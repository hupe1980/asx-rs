#![cfg(feature = "as4")]
//! `As4::inbound`: verification order, dedup settlement and the response
//! table.

#[path = "common/peers.rs"]
mod peers;

use asx::as4::{As4, Message, UserMessage};
use asx::{MemoryDedup, Payload, Profile, Reject, Verified};
use peers::{
    A_URL, B_URL, HANDLER_ERR, HANDLER_GATED, HANDLER_PANIC, Preset, pair, pair_with, soap_part,
};
use std::sync::atomic::Ordering;
use tower::ServiceExt;

/// Capture a signed, encrypted message from `a` to `b` without delivering it.
async fn captured(p: &peers::Pair, body: &[u8]) -> http::Request<bytes::Bytes> {
    p.sender
        .send(p.preset.message(&p.to_b, body))
        .await
        .expect("first delivery");
    p.loopback.last_request().expect("request")
}

async fn post(
    inbound: &asx::Inbound,
    request: http::Request<bytes::Bytes>,
) -> (http::StatusCode, String) {
    let response = inbound
        .clone()
        .oneshot(request.map(http_body_util::Full::new))
        .await
        .unwrap_or_else(|never| match never {});
    let status = response.status();
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn receiver_inbound(p: &peers::Pair) -> asx::Inbound {
    p.receiver.inbound(
        peers::SharedDedup(p.dedup.clone()),
        |_m: Verified<UserMessage>| async { Ok::<(), Reject>(()) },
    )
}

fn clone_request(r: &http::Request<bytes::Bytes>) -> http::Request<bytes::Bytes> {
    let mut copy = http::Request::new(r.body().clone());
    *copy.uri_mut() = r.uri().clone();
    *copy.headers_mut() = r.headers().clone();
    *copy.method_mut() = http::Method::POST;
    copy
}

#[tokio::test(flavor = "current_thread")]
async fn accepted_message_is_delivered_once_and_receipted() {
    let p = pair(Preset::Bdew);
    let receipt = p
        .sender
        .send(Preset::Bdew.message(&p.to_b, b"payload-1"))
        .await
        .expect("receipt");
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
    let delivered = p.delivered.lock().unwrap().clone();
    assert_eq!(delivered[0].1, "9900000000001");
    assert_eq!(delivered[0].2, vec![b"payload-1".to_vec()]);
    // The receipt is signed and echoes the message's references (NRR).
    let signal = String::from_utf8(receipt.evidence().signal().unwrap().to_vec()).unwrap();
    assert!(signal.contains("ds:SignatureValue"));
    assert!(signal.contains("NonRepudiationInformation"));
    assert!(signal.contains("#as4-messaging"));
    // The receiver recorded the accepted message with the receipt it issued.
    let records = p.receiver_audit.records_json();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["outcome"], "accepted");
    assert!(records[0]["signal"].is_object());
}

#[tokio::test(flavor = "current_thread")]
async fn duplicate_is_receipted_without_handler() {
    let p = pair(Preset::Bdew);
    let request = captured(&p, b"dup").await;
    let (status, body) = post(&receiver_inbound(&p), clone_request(&request)).await;
    assert_eq!(status, http::StatusCode::OK);
    assert!(
        body.contains("eb:Receipt"),
        "W6: a duplicate gets a fresh receipt: {body}"
    );
    assert!(body.contains("ds:SignatureValue"));
    assert_eq!(
        p.calls.load(Ordering::SeqCst),
        1,
        "the handler is not called again"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn handler_err_is_ebms_0202_and_abandons() {
    let p = pair(Preset::Bdew);
    p.mode.store(HANDLER_ERR, Ordering::SeqCst);
    let _ = p.sender.send(Preset::Bdew.message(&p.to_b, b"x")).await;
    let request = p.loopback.last_request().unwrap();
    // The claim was released: the retransmission reaches the handler again.
    p.mode.store(peers::HANDLER_OK, Ordering::SeqCst);
    let (status, body) = post(
        &p.receiver.inbound(
            peers::SharedDedup(p.dedup.clone()),
            |_m: Verified<UserMessage>| async { Ok::<(), Reject>(()) },
        ),
        clone_request(&request),
    )
    .await;
    assert_eq!(status, http::StatusCode::OK);
    assert!(body.contains("eb:Receipt"), "{body}");
}

#[tokio::test(flavor = "current_thread")]
async fn handler_err_answer_is_an_ebms_0202_signal() {
    let p = pair(Preset::Bdew);
    p.mode.store(HANDLER_ERR, Ordering::SeqCst);
    let request = {
        let _ = p.sender.send(Preset::Bdew.message(&p.to_b, b"x")).await;
        p.loopback.last_request().unwrap()
    };
    let (status, body) = post(
        &p.receiver
            .inbound(MemoryDedup::default(), |_m: Verified<UserMessage>| async {
                Err::<(), Reject>(Reject::new(std::io::Error::other("no")))
            }),
        request,
    )
    .await;
    assert_eq!(status, http::StatusCode::OK);
    assert!(body.contains("EBMS:0202"), "W9: {body}");
}

#[tokio::test(flavor = "current_thread")]
async fn handler_panic_is_treated_as_err() {
    let p = pair(Preset::Bdew);
    p.mode.store(HANDLER_PANIC, Ordering::SeqCst);
    let err = p
        .sender
        .send(Preset::Bdew.message(&p.to_b, b"x"))
        .await
        .expect_err("refused");
    assert_eq!(err.ebms_code(), Some("EBMS:0202"));
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn in_flight_is_503_and_a_stale_holder_cannot_settle() {
    let p = pair(Preset::Bdew);
    p.mode.store(HANDLER_GATED, Ordering::SeqCst);
    // Capture the request without letting the gated first delivery finish.
    let sender = p.sender.clone();
    let message = Preset::Bdew.message(&p.to_b, b"slow");
    let first = tokio::spawn(async move { sender.send(message).await });
    while p.calls.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    let request = p.loopback.last_request().unwrap();
    let inbound = receiver_inbound(&p);
    // The first delivery holds the claim.
    let (status, body) = post(&inbound, clone_request(&request)).await;
    assert_eq!(status, http::StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.is_empty());
    // The lease expires; the retransmission re-claims and settles.
    tokio::time::advance(std::time::Duration::from_secs(5 * 60 + 1)).await;
    let (status, body) = post(&inbound, clone_request(&request)).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert!(body.contains("eb:Receipt"));
    // The first holder finishes late: its accept is stale → 500 + EBMS:0004.
    p.gate.notify_one();
    let late = first.await.unwrap().expect_err("stale holder");
    assert_eq!(late.ebms_code(), Some("EBMS:0004"), "{late}");
    assert!(
        late.is_retryable(),
        "a 5xx answer is the receiver's transient failure"
    );
    // The second delivery's settlement stands.
    let (_, body) = post(&inbound, clone_request(&request)).await;
    assert!(
        body.contains("eb:Receipt"),
        "duplicate after the second accept: {body}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn ping_is_receipted_without_a_claim() {
    let p = pair(Preset::Bdew);
    for _ in 0..2 {
        p.sender
            .send(Message::ping(&p.to_b).payload(Payload::new(&b"ping"[..], "text/plain")))
            .await
            .expect("receipted");
    }
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn oversized_body_is_413() {
    let p = pair(Preset::Bdew);
    let small = As4::builder(Profile::bdew().max_message_bytes(1024))
        .local(p.b.local())
        .trust_anchor(p.ca.anchor())
        .http_client(p.loopback.clone())
        .build()
        .unwrap();
    let inbound = small.inbound(MemoryDedup::default(), |_m: Verified<UserMessage>| async {
        Ok::<(), Reject>(())
    });
    let request = http::Request::post(B_URL)
        .header("Content-Type", "multipart/related")
        .body(bytes::Bytes::from(vec![b'x'; 4096]))
        .unwrap();
    let (status, _) = post(&inbound, request).await;
    assert_eq!(status, http::StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test(flavor = "current_thread")]
async fn message_for_another_party_is_refused() {
    let p = pair(Preset::Bdew);
    // a sends to c; the request is posted to b.
    let c = p.ca.bdew_party("9900000000003");
    let to_c = c.partner("https://c.example/as4");
    p.loopback
        .mount("https://c.example/as4", receiver_inbound(&p));
    let err = p
        .sender
        .send(Preset::Bdew.message(&to_c, b"x"))
        .await
        .expect_err("not for b");
    assert_eq!(err.ebms_code(), Some("EBMS:0004"), "{err}");
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn unpinned_signer_of_a_configured_partner_is_refused() {
    let other = asx::testkit::pki::TestCa::sm_pki().bdew_party("9900000000001");
    let p = pair_with(
        Preset::Bdew,
        |b| b.partner(B_URL),
        |a| {
            asx::Partner::new(&a.id)
                .party_type(asx::testkit::pki::BDEW_PARTY_TYPE)
                .endpoint(A_URL)
                .signing_cert(other.signing.certificate())
                .encryption_cert(a.encryption.certificate())
        },
    );
    let err = p
        .sender
        .send(Preset::Bdew.message(&p.to_b, b"x"))
        .await
        .expect_err("unpinned");
    assert_eq!(err.ebms_code(), Some("EBMS:0101"), "{err}");
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
}

/// A receiver that knows no partner but `d`.
fn stranger_receiver(
    p: &peers::Pair,
    profile: Profile,
    d: &asx::testkit::pki::TestParty,
) -> asx::Inbound {
    let receiver = As4::builder(profile)
        .local(p.b.local())
        .trust_anchor(p.ca.anchor())
        .partner(d.partner("https://d.example/as4"))
        .http_client(p.loopback.clone())
        .build()
        .unwrap();
    let calls = p.calls.clone();
    receiver.inbound(MemoryDedup::default(), move |_m: Verified<UserMessage>| {
        let calls = calls.clone();
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok::<(), Reject>(())
        }
    })
}

#[tokio::test(flavor = "current_thread")]
async fn unconfigured_bdew_sender_with_matching_subject_is_accepted() {
    let p = pair(Preset::Bdew);
    let d = p.ca.bdew_party("9900000000004");
    p.loopback
        .mount(B_URL, stranger_receiver(&p, Profile::bdew(), &d));
    p.sender
        .send(Preset::Bdew.message(&p.to_b, b"x"))
        .await
        .expect("BDEW §2.3.2: any sender whose subject carries the MP-ID");
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn unconfigured_edelivery_sender_is_refused() {
    let p = pair(Preset::Edelivery);
    let d = p.ca.rsa_party("party-d");
    p.loopback
        .mount(B_URL, stranger_receiver(&p, Profile::edelivery_1_15(), &d));
    let err = p
        .sender
        .send(Preset::Edelivery.message(&p.to_b, b"x"))
        .await
        .expect_err("configured partners only");
    assert_eq!(err.ebms_code(), Some("EBMS:0101"), "{err}");
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn tampered_payload_is_refused_without_a_claim() {
    let p = pair(Preset::Bdew);
    let request = captured(&p, b"original").await;
    let body = request.body().to_vec();
    // Flip the first ciphertext byte of the encrypted attachment (the body
    // of the last MIME part, `IV ‖ ct ‖ tag`): the GCM tag fails.
    let at = body
        .windows(4)
        .rposition(|w| w == b"\r\n\r\n")
        .expect("last part")
        + 4
        + 12;
    let mut tampered = body.clone();
    tampered[at] ^= 0x01;
    let mut replay = clone_request(&request);
    *replay.body_mut() = bytes::Bytes::from(tampered);
    let fresh = p
        .receiver
        .inbound(MemoryDedup::default(), |_m: Verified<UserMessage>| async {
            Ok::<(), Reject>(())
        });
    let (status, body) = post(&fresh, replay).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("EBMS:01"), "{body}");
    let _ = soap_part(&[]);
}

/// BDEW AS4-Profil 1.2 §2.3.2/§2.3.4.4 with RzÜ AS4 2.6 §5.2: the MP-ID is
/// the subject's OU. A sender whose certificate carries it only in the CN is
/// neither accepted unregistered nor configurable as a partner.
#[tokio::test(flavor = "current_thread")]
async fn bdew_mp_id_must_be_in_the_ou() {
    use asx::testkit::pki::{KeyAlg, Nid, TestParty};
    let p = pair(Preset::Bdew);
    let cn_only = |role: &str| {
        p.ca.issue_named(
            &[(Nid::COMMONNAME, &format!("9900000000005 {role}"))],
            KeyAlg::EcBrainpoolP256r1,
        )
    };
    let e = TestParty {
        id: "9900000000005".into(),
        party_type: Some(asx::testkit::pki::BDEW_PARTY_TYPE.into()),
        signing: cn_only("sig"),
        encryption: cn_only("enc"),
        tls: cn_only("tls"),
        ..p.ca.bdew_party("9900000000005")
    };
    // Not configurable as a partner.
    let err = As4::builder(Profile::bdew())
        .local(p.b.local())
        .trust_anchor(p.ca.anchor())
        .partner(e.partner("https://e.example/as4"))
        .http_client(p.loopback.clone())
        .build()
        .expect_err("V20");
    assert!(err.to_string().contains("§2.3.4.4"), "{err}");
    // Unregistered: refused at signer authorization.
    let sender = As4::builder(Profile::bdew())
        .local(e.local())
        .trust_anchor(p.ca.anchor())
        .partner(p.b.partner(B_URL))
        .http_client(p.loopback.clone())
        .build()
        .unwrap();
    let to_b = p.b.partner(B_URL);
    let err = sender
        .send(Preset::Bdew.message(&to_b, b"x"))
        .await
        .expect_err("CN is not where the MP-ID lives");
    assert_eq!(err.ebms_code(), Some("EBMS:0101"), "{err}");
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
}

/// The handler sees each payload with the media type its signed
/// `eb:PartInfo` declares (`MimeType`), not the opaque wire part type.
#[tokio::test(flavor = "current_thread")]
async fn payloads_surface_the_declared_mime_type() {
    for (preset, mime) in [
        (Preset::Peppol, "application/xml"),
        (Preset::Edelivery, "text/csv"),
        (Preset::Bdew, "application/octet-stream"),
    ] {
        let p = pair(preset);
        let message = match preset {
            Preset::Edelivery => Message::to(&p.to_b)
                .service("urn:example:service")
                .action("urn:example:action")
                .payload(Payload::new(b"a,b".to_vec(), mime).named("doc.csv")),
            _ => p.preset.message(&p.to_b, b"<Invoice/>"),
        };
        p.sender.send(message).await.expect("first delivery");
        let request = p.loopback.last_request().expect("request");
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        let inbound =
            p.receiver
                .inbound(MemoryDedup::default(), move |m: Verified<UserMessage>| {
                    sink.lock()
                        .unwrap()
                        .extend(m.payloads().iter().map(|p| p.mime_type().to_string()));
                    async { Ok::<(), Reject>(()) }
                });
        let (status, body) = post(&inbound, request).await;
        assert_eq!(status, http::StatusCode::OK, "{preset:?}: {body}");
        assert_eq!(*seen.lock().unwrap(), vec![mime.to_string()], "{preset:?}");
    }
}
