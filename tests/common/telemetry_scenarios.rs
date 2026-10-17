//! The exchanges both telemetry contract tests observe, through the public API:
//! an AS4 send delivered against a real partner `Inbound` (with an in-flight
//! retransmission while the handler runs and a duplicate afterwards), a send
//! the partner refuses, a send whose receipt does not verify, a tampered
//! (rejected) inbound message, a failing best-effort audit sink, an SMP
//! lookup and a CRL revocation check.

#![allow(dead_code)]

use std::sync::atomic::Ordering;

use asx::AuditDurability;
use asx::testkit::loopback::Loopback;

#[path = "peers.rs"]
mod peers;
#[allow(unreachable_pub)]
#[path = "ported_as4.rs"]
mod ported;

use peers::{HANDLER_ERR, HANDLER_GATED, HANDLER_OK, Preset};

pub(crate) const PAYLOAD_CANARY: &str = "CANARY-PAYLOAD-7f3a19";
pub(crate) const AUTH_CANARY: &str = "CANARY-AUTH-55aa02";
/// Certificates appear only as fingerprints: no field carries an RDN.
pub(crate) const DN_CANARY: &str = "CN=";
/// The sending and receiving parties (BDEW MP-IDs).
pub(crate) const SENDER: &str = "9900000000001";
pub(crate) const PARTNER: &str = "9900000000002";
/// Every partner and message id the scenarios use: never a metric label.
pub(crate) const IDENTIFIERS: &[&str] = &[
    SENDER,
    PARTNER,
    "contract-1@asx.test",
    "contract-2@asx.test",
    "contract-3@asx.test",
    "contract-X@asx.test",
];

fn message(p: &peers::Pair, id: &str) -> asx::as4::Message {
    Preset::Bdew
        .message(&p.to_b, format!("<doc>{PAYLOAD_CANARY}</doc>").as_bytes())
        .message_id(id)
}

pub(crate) async fn run_scenarios() {
    let p = peers::pair(Preset::Bdew);

    // Delivered, with a retransmission arriving while the handler still runs
    // (in flight); the gate opens once that retransmission is answered.
    p.mode.store(HANDLER_GATED, Ordering::SeqCst);
    let first = p.sender.send(message(&p, "contract-1@asx.test"));
    let retransmit = async {
        while p.calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        let request = p.loopback.last_request().expect("the first request");
        let inbound = ported::accepting_inbound(&p.receiver, peers::SharedDedup(p.dedup.clone()));
        let (status, _) = ported::post(&inbound, ported::clone_request(&request)).await;
        assert_eq!(status, http::StatusCode::SERVICE_UNAVAILABLE, "in flight");
        p.gate.notify_one();
        request
    };
    let (delivered, captured) = tokio::join!(first, retransmit);
    delivered.expect("delivered");
    p.mode.store(HANDLER_OK, Ordering::SeqCst);

    // The same message again, after it was accepted: a duplicate. The request
    // carries an Authorization header that must never be recorded.
    let inbound = ported::accepting_inbound(&p.receiver, peers::SharedDedup(p.dedup.clone()));
    let mut duplicate = ported::clone_request(&captured);
    duplicate.headers_mut().insert(
        http::header::AUTHORIZATION,
        format!("Bearer {AUTH_CANARY}").parse().unwrap(),
    );
    let (status, _) = ported::post(&inbound, duplicate).await;
    assert_eq!(status, http::StatusCode::OK, "duplicate receipted");

    // A rejection: the signature does not cover the changed bytes.
    let body = String::from_utf8_lossy(captured.body()).replacen("contract-1", "contract-X", 1);
    let mut tampered = ported::clone_request(&captured);
    *tampered.body_mut() = bytes::Bytes::from(body);
    let (status, _) = ported::post(
        &ported::accepting_inbound(&p.receiver, asx::MemoryDedup::default()),
        tampered,
    )
    .await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "tampered");

    // The partner's application refuses: eb:Error EBMS:0202.
    p.mode.store(HANDLER_ERR, Ordering::SeqCst);
    let err = p
        .sender
        .send(message(&p, "contract-2@asx.test"))
        .await
        .expect_err("refused");
    assert_eq!(err.kind(), asx::ErrorKind::PartnerError, "{err}");
    p.mode.store(HANDLER_OK, Ordering::SeqCst);

    // The receipt is altered on the way back: indeterminate.
    p.loopback.intercept(|resp| {
        let text =
            String::from_utf8_lossy(resp.body()).replacen("RefToMessageId>", "RefToMessageId>x", 1);
        *resp.body_mut() = bytes::Bytes::from(text);
    });
    let err = p
        .sender
        .send(message(&p, "contract-3@asx.test"))
        .await
        .expect_err("unverifiable receipt");
    assert_eq!(err.kind(), asx::ErrorKind::Indeterminate, "{err}");
    p.loopback.clear_intercept();

    // A receiver whose best-effort audit sink fails: the exchange succeeds.
    let failing = ported::client(
        Preset::Bdew.profile(),
        &p.ca,
        &p.b,
        p.a.partner(peers::A_URL),
        &Loopback::new(),
        |b| b.audit(ported::FailingSink(AuditDurability::BestEffort)),
    );
    let (status, _) = ported::post(
        &ported::accepting_inbound(&failing, asx::MemoryDedup::default()),
        ported::clone_request(&captured),
    )
    .await;
    assert_eq!(
        status,
        http::StatusCode::OK,
        "best-effort audit never fails the receive"
    );

    // AS2: a signed, encrypted message answered by a verified signed MDN.
    #[cfg(feature = "as2")]
    as2_round_trip().await;

    // An SMP lookup (refused: the SMP host is a private address).
    #[cfg(feature = "peppol")]
    {
        use asx::__fuzz::smp::{SmpClient, SmpConfig, SmpLookupRequest};
        SmpClient::with_config(SmpConfig::with_static_smp("https://127.0.0.1"))
            .lookup_endpoint(SmpLookupRequest::new(
                "0088:contract",
                "urn:contract:doc",
                "urn:contract:process",
            ))
            .await
            .expect_err("private SMP host");
    }

    // A revocation check: the leaf is on its CA's CRL.
    {
        use asx::testkit::pki::{KeyAlg, TestCa};
        let ca = TestCa::new("contract revocation root", KeyAlg::EcP256);
        let leaf = ca.issue("contract revoked leaf", KeyAlg::EcP256);
        let der = |pem: &[u8]| {
            openssl::x509::X509::from_pem(pem)
                .unwrap()
                .to_der()
                .unwrap()
        };
        asx::__fuzz::revocation::decide(
            &asx::Profile::edelivery_1_15(),
            &[der(&leaf.cert_pem), der(ca.cert_pem())],
            &[],
            vec![(
                ca.crl_url().to_string(),
                ca.crl_builder().revoke(&leaf).build(),
            )],
            std::time::SystemTime::now(),
        )
        .await
        .expect_err("revoked leaf");
    }
}

#[cfg(feature = "as2")]
async fn as2_round_trip() {
    use asx::as2::{As2, Received};
    use asx::testkit::pki::{KeyAlg, TestCa};
    const B_URL: &str = "https://b.example/as2";
    let ca = TestCa::new("asx-test AS2 root", KeyAlg::Rsa2048);
    let (a, b) = (ca.as2_party("CONTRACT-A"), ca.as2_party("CONTRACT-B"));
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
    loopback.mount(
        B_URL,
        receiver.inbound(
            asx::MemoryDedup::default(),
            |_m: asx::Verified<Received>| async { Ok::<(), asx::Reject>(()) },
        ),
    );
    // The outcome is not part of this contract (the AS2 suites own it): the
    // exchange opens asx.send, asx.receive and asx.mdn whatever it settles to.
    let _ = sender
        .send(asx::as2::Message::to(
            &to_b,
            asx::Payload::new(PAYLOAD_CANARY.as_bytes().to_vec(), "application/edi-x12"),
        ))
        .await;
}
