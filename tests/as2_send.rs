#![cfg(feature = "as2")]
//! `As2::send`, `send_async_mdn` and `verify_async_mdn` end to end against a
//! real partner `Inbound`.

#[path = "common/as2_peers.rs"]
mod as2_peers;

use as2_peers::{
    B_URL, EDI, FailingSink, HANDLER_ERR, field, pair, pair_with, replace_with, sign_mdn,
    unsigned_mdn,
};
use asx::as2::{As2, Message, PendingMdn};
use asx::{ErrorKind, Payload, Profile, Quirk};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

const PROCESSED: &str = "automatic-action/MDN-sent-automatically; processed";

fn capture(p: &as2_peers::Pair) -> Arc<Mutex<Vec<http::Response<bytes::Bytes>>>> {
    let captured: Arc<Mutex<Vec<http::Response<bytes::Bytes>>>> = Arc::default();
    let sink = captured.clone();
    p.loopback.intercept(move |resp| {
        let mut copy = http::Response::new(resp.body().clone());
        *copy.headers_mut() = resp.headers().clone();
        *copy.status_mut() = resp.status();
        sink.lock().unwrap().push(copy);
    });
    captured
}

#[tokio::test]
async fn sync_processed_mdn_is_verified_and_recorded() {
    let p = pair();
    let captured = capture(&p);
    let mdn = p
        .sender
        .send(p.message(b"ISA*00*~").message_id("m1@test"))
        .await
        .expect("verified MDN");
    let wire = captured.lock().unwrap().pop().expect("a response");
    assert_eq!(mdn.evidence().signal(), Some(wire.body().as_ref()));
    assert_eq!(mdn.evidence().message_id(), "m1@test");
    assert_eq!(mdn.evidence().partner(), as2_peers::B_ID);
    assert_eq!(mdn.signer(), &p.b.signing.certificate());
    let records = p.sender_audit.records();
    assert_eq!(records.len(), 1);
    assert_eq!(&records[0], mdn.evidence());
    let json = serde_json::to_value(mdn.evidence()).unwrap();
    assert_eq!(json["profile"], "as2");
    assert_eq!(json["outcome"], "delivered");
    assert_eq!(json["protocol"], "as2");
    assert_eq!(json["mic"]["algorithm"], "sha-256");
    assert_eq!(json["quirks"], serde_json::json!([]));
    let delivered = p.delivered.lock().unwrap();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].0, "m1@test");
    assert_eq!(delivered[0].1, as2_peers::A_ID);
    assert_eq!(delivered[0].2, b"ISA*00*~");
    assert_eq!(delivered[0].3, EDI);
}

#[tokio::test]
async fn requests_a_signed_sha256_mdn_and_encrypts() {
    let p = pair();
    let plaintext = b"PLAINTEXT-MARKER-0123456789";
    p.sender
        .send(p.message(plaintext).message_id("w5@test"))
        .await
        .expect("verified MDN");
    let request = p.loopback.last_request().expect("request");
    let h = |name: &str| {
        request
            .headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_else(|| panic!("{name} missing"))
    };
    assert_eq!(
        h("Disposition-Notification-Options"),
        "signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, sha-256"
    );
    assert_eq!(h("Disposition-Notification-To"), as2_peers::A_ID);
    assert!(request.headers().get("Receipt-Delivery-Option").is_none());
    assert_eq!(h("AS2-From"), as2_peers::A_ID);
    assert_eq!(h("AS2-To"), as2_peers::B_ID);
    assert_eq!(h("AS2-Version"), "1.2");
    assert_eq!(h("Message-ID"), "<w5@test>");
    assert!(
        h("Content-Type").contains("enveloped-data"),
        "{}",
        h("Content-Type")
    );
    assert!(
        !request
            .body()
            .windows(plaintext.len())
            .any(|w| w == plaintext),
        "plaintext on the wire"
    );
}

#[tokio::test]
async fn partner_decryption_failure_is_a_partner_error() {
    let other = asx::testkit::pki::TestCa::new("other", asx::testkit::pki::KeyAlg::Rsa2048)
        .as2_party("OTHER");
    let p = pair_with(
        |b| {
            b.partner(B_URL)
                .encryption_cert(other.encryption.certificate())
        },
        |a| a.partner(as2_peers::A_URL),
    );
    let err = p
        .sender
        .send(p.message(b"x"))
        .await
        .expect_err("partner refused");
    assert_eq!(err.kind(), ErrorKind::PartnerError, "{err}");
    assert_eq!(
        err.mdn_disposition(),
        Some("processed/error: decryption-failed")
    );
    assert!(!err.is_retryable());
    let evidence = err.evidence().expect("the negative MDN is evidence");
    assert!(evidence.signal().is_some());
    assert_eq!(
        p.sender_audit.records().len(),
        1,
        "a negative MDN is recorded too"
    );
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn handler_refusal_is_a_retryable_partner_error() {
    let p = pair();
    p.mode.store(HANDLER_ERR, Ordering::SeqCst);
    let err = p.sender.send(p.message(b"x")).await.expect_err("refused");
    assert_eq!(err.kind(), ErrorKind::PartnerError, "{err}");
    assert_eq!(
        err.mdn_disposition(),
        Some("processed/error: unexpected-processing-error")
    );
    assert!(err.is_retryable());
}

/// Replace the partner's MDN by `forge(original MDN body)`.
async fn indeterminate_with(
    forge: impl Fn(&as2_peers::Pair, &[u8]) -> Vec<u8> + Send + Sync + 'static,
    quirk: bool,
) -> asx::Error {
    let p = Arc::new(if quirk {
        pair_with(
            |b| b.partner(B_URL).quirk(Quirk::UnsignedMdn),
            |a| a.partner(as2_peers::A_URL),
        )
    } else {
        pair()
    });
    let hook_pair = p.clone();
    let forge = Arc::new(forge);
    p.loopback.intercept(move |resp| {
        let forged = forge(&hook_pair, resp.body());
        replace_with(resp, forged);
    });
    let err = p
        .sender
        .send(p.message(b"x").message_id("forged@test"))
        .await
        .expect_err("refused MDN");
    assert_eq!(err.kind(), ErrorKind::Indeterminate, "{err}");
    assert!(err.is_retryable());
    assert!(
        err.evidence().is_some(),
        "Indeterminate keeps the evidence: {err}"
    );
    err
}

fn mic_of(original: &[u8]) -> String {
    field(original, "Received-Content-MIC").expect("the partner's MDN carries a MIC")
}

#[tokio::test]
async fn wrong_original_message_id_is_indeterminate() {
    indeterminate_with(
        |p, original| p.mdn_signed_by_b("<other@test>", PROCESSED, Some(&mic_of(original))),
        false,
    )
    .await;
}

#[tokio::test]
async fn wrong_mic_is_indeterminate() {
    indeterminate_with(
        |p, _| {
            p.mdn_signed_by_b(
                "<forged@test>",
                PROCESSED,
                Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, sha-256"),
            )
        },
        false,
    )
    .await;
}

#[tokio::test]
async fn processed_mdn_without_mic_is_indeterminate() {
    indeterminate_with(
        |p, _| p.mdn_signed_by_b("<forged@test>", PROCESSED, None),
        false,
    )
    .await;
}

#[tokio::test]
async fn mdn_signed_by_another_certificate_is_indeterminate() {
    indeterminate_with(
        |p, original| {
            // Same CA, same AS2 id, not pinned.
            let impostor = p.ca.as2_party(as2_peers::B_ID);
            sign_mdn(
                &impostor.signing,
                "<forged@test>",
                PROCESSED,
                Some(&mic_of(original)),
            )
        },
        false,
    )
    .await;
}

#[tokio::test]
async fn unsigned_mdn_is_indeterminate_without_the_quirk() {
    indeterminate_with(
        |_, original| unsigned_mdn("<forged@test>", PROCESSED, Some(&mic_of(original))),
        false,
    )
    .await;
}

#[tokio::test]
async fn unsigned_mdn_quirk_accepts_an_absent_signature_and_records_it() {
    let p = Arc::new(pair_with(
        |b| b.partner(B_URL).quirk(Quirk::UnsignedMdn),
        |a| a.partner(as2_peers::A_URL),
    ));
    p.loopback.intercept(|resp| {
        let mic = mic_of(resp.body());
        replace_with(resp, unsigned_mdn("<q@test>", PROCESSED, Some(&mic)));
    });
    let mdn = p
        .sender
        .send(p.message(b"x").message_id("q@test"))
        .await
        .expect("accepted under UnsignedMdn");
    let json = serde_json::to_value(mdn.evidence()).unwrap();
    assert_eq!(json["quirks"], serde_json::json!(["unsigned_mdn"]));
    assert_eq!(json["signer"], serde_json::Value::Null);
    assert_eq!(json["signal"]["signed"], false);
    assert_eq!(p.sender_audit.records()[0], *mdn.evidence());
}

#[tokio::test]
async fn unsigned_mdn_quirk_still_refuses_a_failing_signature() {
    indeterminate_with(
        |p, original| {
            let impostor = p.ca.as2_party(as2_peers::B_ID);
            sign_mdn(
                &impostor.signing,
                "<forged@test>",
                PROCESSED,
                Some(&mic_of(original)),
            )
        },
        true,
    )
    .await;
}

#[tokio::test]
async fn signed_mdn_under_the_quirk_records_no_quirk() {
    let p = pair_with(
        |b| b.partner(B_URL).quirk(Quirk::UnsignedMdn),
        |a| a.partner(as2_peers::A_URL),
    );
    let mdn = p.sender.send(p.message(b"x")).await.expect("verified");
    let json = serde_json::to_value(mdn.evidence()).unwrap();
    assert_eq!(json["quirks"], serde_json::json!([]));
}

#[tokio::test]
async fn audit_failure_after_a_verified_mdn_is_delivered_but_unrecorded() {
    let ca = asx::testkit::pki::TestCa::new("root", asx::testkit::pki::KeyAlg::Rsa2048);
    let (a, b) = (ca.as2_party("A"), ca.as2_party("B"));
    let loopback = asx::testkit::loopback::Loopback::new();
    let to_b = b.partner(B_URL);
    let sender = As2::builder(Profile::as2())
        .local(a.local())
        .trust_anchor(ca.anchor())
        .partner(to_b.clone())
        .http_client(loopback.clone())
        .audit(FailingSink)
        .build()
        .unwrap();
    let receiver = As2::builder(Profile::as2())
        .local(b.local())
        .trust_anchor(ca.anchor())
        .partner(a.partner(as2_peers::A_URL))
        .http_client(loopback.clone())
        .build()
        .unwrap();
    loopback.mount(
        B_URL,
        receiver.inbound(
            asx::MemoryDedup::default(),
            |_m: asx::Verified<asx::as2::Received>| async { Ok(()) },
        ),
    );
    let err = sender
        .send(Message::to(&to_b, Payload::new(&b"x"[..], EDI)))
        .await
        .expect_err("audit failed");
    assert_eq!(err.kind(), ErrorKind::Backend, "{err}");
    assert!(!err.is_retryable(), "delivered: do not resend");
    assert!(err.evidence().and_then(|e| e.signal()).is_some());
}

#[tokio::test]
async fn invalid_messages_are_refused_before_sending() {
    let p = pair();
    for message in [
        Message::to(&p.to_b, Payload::new(&b"x"[..], "not a type")),
        Message::to(&p.to_b, Payload::new(&b"x"[..], "text/plain\r\nX: y")),
        Message::to(&p.to_b, Payload::new(&b""[..], EDI)),
        Message::to(&p.to_b, Payload::new(&b"x"[..], EDI).named("a.txt")),
        p.message(b"x").message_id("<bracketed@test>"),
        p.message(b"x").message_id("no-at-sign"),
    ] {
        let err = p.sender.send(message).await.expect_err("refused");
        assert_eq!(err.kind(), ErrorKind::Config, "{err}");
    }
    let mut big = Profile::as2();
    big = big.max_message_bytes(4);
    let ca = asx::testkit::pki::TestCa::new("root", asx::testkit::pki::KeyAlg::Rsa2048);
    let (a, b) = (ca.as2_party("A"), ca.as2_party("B"));
    let small = As2::builder(big)
        .local(a.local())
        .trust_anchor(ca.anchor())
        .partner(b.partner(B_URL))
        .http_client(p.loopback.clone())
        .build()
        .unwrap();
    let err = small
        .send(Message::to(
            &b.partner(B_URL),
            Payload::new(&b"12345"[..], EDI),
        ))
        .await
        .expect_err("M11");
    assert_eq!(err.kind(), ErrorKind::Config, "{err}");
    assert_eq!(p.loopback.requests(), 0, "nothing was sent");
}

#[tokio::test]
async fn unregistered_partner_without_endpoint_is_config() {
    let p = pair();
    let stranger = asx::Partner::new("STRANGER").encryption_cert(p.b.encryption.certificate());
    let err = p
        .sender
        .send(Message::to(&stranger, Payload::new(&b"x"[..], EDI)))
        .await
        .expect_err("M9");
    assert_eq!(err.kind(), ErrorKind::Config, "{err}");
    assert!(err.to_string().contains("endpoint"), "{err}");
}

// ── Asynchronous MDN ────────────────────────────────────────────────────────

/// The MDN as the partner would POST it to the receipt URL: our `Inbound`
/// answers an async request synchronously, so the captured response is it.
fn as_request(resp: &http::Response<bytes::Bytes>) -> http::Request<bytes::Bytes> {
    let mut request = http::Request::post("https://a.example/mdn")
        .body(resp.body().clone())
        .unwrap();
    *request.headers_mut() = resp.headers().clone();
    request
}

#[tokio::test]
async fn pending_mdn_survives_json_and_is_verified() {
    let p = pair();
    let captured = capture(&p);
    let pending = p
        .sender
        .send_async_mdn(
            p.message(b"async").message_id("async-1@test"),
            "https://a.example/mdn",
        )
        .await
        .expect("acknowledged");
    assert_eq!(pending.message_id(), "async-1@test");
    let request = p.loopback.last_request().unwrap();
    assert_eq!(
        request.headers()["Receipt-Delivery-Option"]
            .to_str()
            .unwrap(),
        "https://a.example/mdn"
    );
    let json = serde_json::to_string(&pending).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["v"], 1);
    assert_eq!(value["mic_alg"], "sha-256");
    assert_eq!(value["signed"], true);
    let restored: PendingMdn = serde_json::from_str(&json).unwrap();
    let mdn_request = as_request(&captured.lock().unwrap().pop().unwrap());
    assert_eq!(
        PendingMdn::lookup_key(&mdn_request).as_deref(),
        Some("async-1@test")
    );
    let verified = p
        .sender
        .verify_async_mdn(mdn_request, &restored)
        .await
        .expect("verified async MDN");
    assert_eq!(verified.evidence().message_id(), "async-1@test");
    assert_eq!(p.sender_audit.records().len(), 1);
}

#[tokio::test]
async fn pending_mdn_of_another_version_does_not_deserialize() {
    let json = r#"{"v":2,"message_id":"a@b","partner":[null,"B"],"mic":"AAAA","mic_alg":"sha-256","signed":true,"sent_at":"2026-01-01T00:00:00Z"}"#;
    assert!(serde_json::from_str::<PendingMdn>(json).is_err());
    let ok = json.replace("\"v\":2", "\"v\":1");
    assert!(serde_json::from_str::<PendingMdn>(&ok).is_ok());
}

#[tokio::test]
async fn another_messages_mdn_is_rejected() {
    let p = pair();
    let captured = capture(&p);
    let first = p
        .sender
        .send_async_mdn(
            p.message(b"one").message_id("one@test"),
            "https://a.example/mdn",
        )
        .await
        .unwrap();
    let mdn_one = as_request(&captured.lock().unwrap().pop().unwrap());
    let second = p
        .sender
        .send_async_mdn(
            p.message(b"two").message_id("two@test"),
            "https://a.example/mdn",
        )
        .await
        .unwrap();
    let err = p
        .sender
        .verify_async_mdn(
            as_request(&http::Response::new(mdn_one.body().clone())),
            &second,
        )
        .await
        .expect_err("not this pending's MDN");
    assert_eq!(err.kind(), ErrorKind::Rejected, "{err}");
    assert!(!err.is_retryable());
    // Not an MDN at all.
    let junk = http::Request::post("https://a.example/mdn")
        .body(bytes::Bytes::from_static(b"hello"))
        .unwrap();
    let err = p
        .sender
        .verify_async_mdn(junk, &first)
        .await
        .expect_err("junk");
    assert_eq!(err.kind(), ErrorKind::Rejected, "{err}");
    // The right MDN still verifies.
    p.sender
        .verify_async_mdn(mdn_one, &first)
        .await
        .expect("its own MDN");
}

#[tokio::test]
async fn matching_async_mdn_failing_verification_is_indeterminate() {
    let p = pair();
    let pending = p
        .sender
        .send_async_mdn(
            p.message(b"x").message_id("bad@test"),
            "https://a.example/mdn",
        )
        .await
        .unwrap();
    let forged = p.mdn_signed_by_b(
        "<bad@test>",
        PROCESSED,
        Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, sha-256"),
    );
    let mut resp = http::Response::new(bytes::Bytes::new());
    replace_with(&mut resp, forged);
    let err = p
        .sender
        .verify_async_mdn(as_request(&resp), &pending)
        .await
        .expect_err("wrong MIC");
    assert_eq!(err.kind(), ErrorKind::Indeterminate, "{err}");
    assert!(err.is_retryable());
}

#[tokio::test]
async fn receipt_url_is_validated() {
    let p = pair();
    let err = p
        .sender
        .send_async_mdn(p.message(b"x"), "not a url\r\n")
        .await
        .expect_err("bad url");
    assert_eq!(err.kind(), ErrorKind::Config);
    assert_eq!(p.loopback.requests(), 0);
}

/// A signer that is not a `KeyPair` (an HSM stand-in).
#[derive(Debug)]
struct External(asx::KeyPair, Vec<asx::Certificate>);

impl asx::Signer for External {
    fn certificate_chain(&self) -> &[asx::Certificate] {
        &self.1
    }
    fn sign<'a>(
        &'a self,
        algorithm: asx::SignatureAlgorithm,
        message: &'a [u8],
    ) -> asx::BoxFuture<'a, Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>> {
        self.0.sign(algorithm, message)
    }
}

/// Any `Signer` and `Decrypter` builds an AS2 client.
#[tokio::test]
async fn an_external_signer_builds_an_as2_client() {
    use asx::Signer as _;
    let ca = asx::testkit::pki::TestCa::new("root", asx::testkit::pki::KeyAlg::Rsa2048);
    let a = ca.as2_party("A");
    let key = a.signing.key_pair();
    let chain = key.certificate_chain().to_vec();
    As2::builder(Profile::as2())
        .local(
            asx::LocalParty::new("A")
                .signer(External(key.clone(), chain))
                .decrypter(asx::testkit::keys::CountingKeys::new(&a.encryption)),
        )
        .trust_anchor(ca.anchor())
        .http_client(asx::testkit::loopback::Loopback::new())
        .build()
        .expect("an external signer and decrypter are accepted");
}
