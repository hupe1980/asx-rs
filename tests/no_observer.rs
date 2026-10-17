#![cfg(feature = "as4")]
//! A send or receive succeeds with nothing observing it, and an observer that
//! does nothing changes nothing, for AS4 and AS2.

#[path = "common/peers.rs"]
mod peers;
#[allow(unreachable_pub)]
#[path = "common/ported_as4.rs"]
mod ported;

use std::sync::{Arc, Mutex};

use asx::Verified;
use asx::as4::UserMessage;
use asx::testkit::loopback::Loopback;
use peers::Preset;
use tracing_subscriber::layer::SubscriberExt;

/// What an exchange produced, without the per-run randomness (ids, keys).
#[derive(Debug, PartialEq, Eq)]
struct Observed {
    as4_receipt_for: String,
    as4_signed: bool,
    as4_nrr: bool,
    as4_signer: asx::Certificate,
    as4_delivered_payload: Vec<Vec<u8>>,
}

async fn exchanges(preset: Preset) -> Observed {
    // Two clients with no audit sink, through the in-process loopback.
    let ca = preset.ca();
    let (a, b) = preset.parties(&ca);
    let loopback = Loopback::new();
    let to_b = b.partner(peers::B_URL);
    let sender = ported::client(preset.profile(), &ca, &a, to_b.clone(), &loopback, |b| b);
    let receiver = ported::client(
        preset.profile(),
        &ca,
        &b,
        a.partner(peers::A_URL),
        &loopback,
        |b| b,
    );
    let delivered = Arc::new(Mutex::new(Vec::new()));
    let seen = delivered.clone();
    loopback.mount(
        peers::B_URL,
        receiver.inbound(
            asx::MemoryDedup::default(),
            move |m: Verified<UserMessage>| {
                let seen = seen.clone();
                async move {
                    seen.lock()
                        .unwrap()
                        .extend(m.payloads().iter().map(|p| p.bytes().to_vec()));
                    Ok::<(), asx::Reject>(())
                }
            },
        ),
    );

    let receipt = sender
        .send(
            preset
                .message(&to_b, b"nobody is watching")
                .message_id("quiet@asx.test"),
        )
        .await
        .expect("AS4 exchange with no observer");
    let signal =
        String::from_utf8_lossy(receipt.evidence().signal().expect("the receipt")).into_owned();
    let record = serde_json::to_value(receipt.evidence()).unwrap();
    let delivered = delivered.lock().unwrap().clone();
    Observed {
        as4_receipt_for: record["signal"]["ref_to_message_id"]
            .as_str()
            .unwrap()
            .to_owned(),
        as4_signed: signal.contains("SignatureValue"),
        as4_nrr: signal.contains("NonRepudiationInformation"),
        as4_signer: receipt.signer().clone(),
        as4_delivered_payload: delivered,
    }
}

fn run(preset: Preset) -> Observed {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(exchanges(preset))
}

#[test]
fn exchanges_succeed_unobserved_and_an_idle_observer_changes_nothing() {
    for preset in peers::AS4_PRESETS {
        // Nothing installed: no subscriber, no recorder, no audit sink.
        let unobserved = run(preset);
        assert_eq!(unobserved.as4_receipt_for, "quiet@asx.test");
        assert!(unobserved.as4_signed && unobserved.as4_nrr, "{preset:?}");
        assert_eq!(
            unobserved.as4_delivered_payload,
            vec![b"nobody is watching".to_vec()]
        );

        // A subscriber that enables every span and event and does nothing
        // with them, and a recorder that discards every metric. Fresh keys
        // per run, so compare everything but the signer.
        let idle = tracing_subscriber::registry().with(tracing_subscriber::layer::Identity::new());
        let observed = tracing::subscriber::with_default(idle, || {
            metrics::with_local_recorder(&metrics::NoopRecorder, || run(preset))
        });
        assert_eq!(
            Observed {
                as4_signer: unobserved.as4_signer.clone(),
                ..observed
            },
            unobserved,
            "{preset:?}"
        );
    }
}

/// What an AS2 exchange produced, without the per-run randomness.
#[cfg(feature = "as2")]
#[derive(Debug, PartialEq, Eq)]
struct ObservedAs2 {
    mdn_for: String,
    outcome: String,
    signer: asx::Certificate,
    delivered: Vec<(Vec<u8>, String)>,
}

#[cfg(feature = "as2")]
async fn as2_exchange() -> ObservedAs2 {
    use asx::as2::{As2, Received};
    use asx::testkit::pki::{KeyAlg, TestCa};
    const B_URL: &str = "https://b.example/as2";
    // Two clients with no audit sink, through the in-process loopback.
    let ca = TestCa::new("asx-test AS2 root", KeyAlg::Rsa2048);
    let (a, b) = (ca.as2_party("QUIET-A"), ca.as2_party("QUIET-B"));
    let loopback = Loopback::new();
    let build = |local: &asx::testkit::pki::TestParty, partner: asx::Partner| {
        As2::builder(asx::Profile::as2())
            .local(local.local())
            .trust_anchor(ca.anchor())
            .partner(partner)
            .http_client(loopback.clone())
            .build()
            .expect("AS2 client builds")
    };
    let to_b = b.partner(B_URL);
    let sender = build(&a, to_b.clone());
    let receiver = build(&b, a.partner("https://a.example/as2"));
    let delivered = Arc::new(Mutex::new(Vec::new()));
    let seen = delivered.clone();
    loopback.mount(
        B_URL,
        receiver.inbound(asx::MemoryDedup::default(), move |m: Verified<Received>| {
            seen.lock().unwrap().push((
                m.payload().bytes().to_vec(),
                m.payload().mime_type().to_string(),
            ));
            async { Ok::<(), asx::Reject>(()) }
        }),
    );
    let mdn = sender
        .send(
            asx::as2::Message::to(
                &to_b,
                asx::Payload::new(b"ISA*nobody is watching~".to_vec(), "application/edi-x12"),
            )
            .message_id("quiet-as2@asx.test"),
        )
        .await
        .expect("AS2 exchange with no observer");
    let record = serde_json::to_value(mdn.evidence()).unwrap();
    let delivered = delivered.lock().unwrap().clone();
    ObservedAs2 {
        mdn_for: mdn.evidence().message_id().to_owned(),
        outcome: record["outcome"].as_str().unwrap_or_default().to_owned(),
        signer: mdn.signer().clone(),
        delivered,
    }
}

#[cfg(feature = "as2")]
fn run_as2() -> ObservedAs2 {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(as2_exchange())
}

#[cfg(feature = "as2")]
#[test]
fn as2_exchange_succeeds_unobserved_and_an_idle_observer_changes_nothing() {
    let unobserved = run_as2();
    assert_eq!(unobserved.mdn_for, "quiet-as2@asx.test");
    assert_eq!(unobserved.outcome, "delivered");
    assert_eq!(
        unobserved.delivered,
        vec![(
            b"ISA*nobody is watching~".to_vec(),
            "application/edi-x12".to_string()
        )]
    );
    let idle = tracing_subscriber::registry().with(tracing_subscriber::layer::Identity::new());
    let observed = tracing::subscriber::with_default(idle, || {
        metrics::with_local_recorder(&metrics::NoopRecorder, run_as2)
    });
    assert_eq!(
        ObservedAs2 {
            signer: unobserved.signer.clone(),
            ..observed
        },
        unobserved
    );
}
