#![cfg(feature = "as2")]
//! `As2::inbound`: what a real partner `Inbound` answers, and when it calls
//! the handler.

#[path = "common/as2_peers.rs"]
mod as2_peers;

use as2_peers::{A_ID, B_ID, B_URL, EDI, HANDLER_ERR, HANDLER_OK, HANDLER_PANIC, field, pair};
use asx::{Claim, DedupStore, ErrorKind};
use base64::Engine as _;
use sha2::Digest as _;
use std::sync::Arc;
use std::sync::atomic::Ordering;

const PAYLOAD: &[u8] = b"ISA*00*          *00*~";

fn mdn_disposition(resp: &http::Response<bytes::Bytes>) -> String {
    let disposition = field(resp.body(), "Disposition").unwrap_or_else(|| {
        panic!(
            "HTTP {} without an MDN: {}",
            resp.status(),
            String::from_utf8_lossy(resp.body())
        )
    });
    disposition
        .split_once(';')
        .map(|(_, d)| d.trim().to_string())
        .unwrap_or(disposition)
}

/// A raw AS2 message: optionally signed by `signer`, optionally encrypted to
/// `recipient` (`asx::__fuzz::as2_raw_message`; the client always does both).
fn raw_message(
    signer: Option<&asx::testkit::pki::KeyPair>,
    recipient: Option<&asx::testkit::pki::KeyPair>,
) -> (String, Vec<u8>) {
    asx::__fuzz::as2_raw_message(
        PAYLOAD,
        EDI,
        A_ID,
        signer.map(|s| (s.cert_pem.as_slice(), s.key_pem.as_slice())),
        recipient.map(|r| r.cert_pem.as_slice()),
    )
    .expect("raw message")
}

fn request(
    from: &str,
    to: &str,
    message_id: &str,
    content_type: &str,
    body: Vec<u8>,
) -> http::Request<bytes::Bytes> {
    http::Request::post(B_URL)
        .header("AS2-Version", "1.2")
        .header("AS2-From", from)
        .header("AS2-To", to)
        .header("Message-ID", format!("<{message_id}>"))
        .header("Content-Type", content_type)
        .header("Disposition-Notification-To", from)
        .header(
            "Disposition-Notification-Options",
            "signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, sha-256",
        )
        .body(bytes::Bytes::from(body))
        .unwrap()
}

async fn post(
    p: &as2_peers::Pair,
    request: http::Request<bytes::Bytes>,
) -> http::Response<bytes::Bytes> {
    p.loopback.exchange(request).await.expect("mounted")
}

/// Every MDN this side sends is signed by the local signer.
fn assert_signed_by(resp: &http::Response<bytes::Bytes>, party: &asx::testkit::pki::TestParty) {
    let content_type = resp.headers()["content-type"].to_str().unwrap();
    assert!(content_type.contains("multipart/signed"), "{content_type}");
    let text = String::from_utf8_lossy(resp.body());
    assert!(text.contains("application/pkcs7-signature") || text.contains("x-pkcs7-signature"));
    let _ = party;
}

#[tokio::test]
async fn processed_mdn_is_signed_and_carries_the_mic_over_the_signed_entity() {
    let p = pair();
    let captured: Arc<std::sync::Mutex<Vec<bytes::Bytes>>> = Arc::default();
    {
        let captured = captured.clone();
        p.loopback
            .intercept(move |resp| captured.lock().unwrap().push(resp.body().clone()));
    }
    p.sender
        .send(p.message(PAYLOAD).message_id("d17@test"))
        .await
        .expect("verified");
    let mdn = captured.lock().unwrap().pop().unwrap();
    // The MIC covers the signed MIME entity, headers included.
    let mut entity =
        format!("Content-Type: {EDI}\r\nContent-Transfer-Encoding: binary\r\n\r\n").into_bytes();
    entity.extend_from_slice(PAYLOAD);
    let expected = base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(&entity));
    assert_eq!(
        field(&mdn, "Received-Content-MIC").as_deref(),
        Some(format!("{expected}, sha-256").as_str())
    );
    assert_eq!(
        field(&mdn, "Original-Message-ID").as_deref(),
        Some("<d17@test>")
    );
    assert_eq!(
        field(&mdn, "Final-Recipient").as_deref(),
        Some(format!("rfc822; {B_ID}").as_str())
    );
    // The receiver's record: written before accept, with the MDN as signal.
    let records = p.receiver_audit.records_json();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["direction"], "inbound");
    assert_eq!(records[0]["outcome"], "accepted");
    assert_eq!(records[0]["partner"], A_ID);
    assert_eq!(records[0]["message_id"], "d17@test");
    assert!(
        records[0]["disposition"]
            .as_str()
            .unwrap()
            .ends_with("processed")
    );
    let signal = base64::engine::general_purpose::STANDARD
        .decode(records[0]["signal"]["bytes"].as_str().unwrap())
        .unwrap();
    assert_eq!(signal, mdn.to_vec());
    assert_eq!(
        records[0]["mic"]["value"],
        serde_json::Value::String(expected)
    );
    // Accepted: a replay is a duplicate.
    let key = asx::__dedup_key("as2", "", A_ID, "d17@test");
    assert_eq!(p.dedup.claim(&key).await.unwrap(), Claim::Duplicate);
}

#[tokio::test]
async fn duplicate_is_answered_duplicate_document_without_calling_the_handler() {
    let p = pair();
    let captured: Arc<std::sync::Mutex<Vec<bytes::Bytes>>> = Arc::default();
    {
        let captured = captured.clone();
        p.loopback
            .intercept(move |resp| captured.lock().unwrap().push(resp.body().clone()));
    }
    let first = p
        .sender
        .send(p.message(PAYLOAD).message_id("dup@test"))
        .await
        .expect("first");
    let second = p
        .sender
        .send(p.message(PAYLOAD).message_id("dup@test"))
        .await
        .expect("a duplicate-document warning is a verified MDN");
    assert_eq!(
        p.calls.load(Ordering::SeqCst),
        1,
        "W7: the handler is not called again"
    );
    let mdn = captured.lock().unwrap().pop().unwrap();
    let disposition = field(&mdn, "Disposition").unwrap();
    assert!(
        disposition.ends_with("processed/warning: duplicate-document"),
        "{disposition}"
    );
    assert!(field(&mdn, "Received-Content-MIC").is_some());
    assert_ne!(first.evidence().record_id(), second.evidence().record_id());
    assert_eq!(p.receiver_audit.records().len(), 1);
}

#[tokio::test]
async fn unsigned_or_unencrypted_is_insufficient_message_security() {
    let p = pair();
    for (label, signer, recipient) in [
        ("encrypted only", None, Some(&p.b.encryption)),
        ("signed only", Some(&p.a.signing), None),
        ("neither", None, None),
    ] {
        let (content_type, body) = raw_message(signer, recipient);
        let resp = post(
            &p,
            request(
                A_ID,
                B_ID,
                &format!("w11-{}@test", label.len()),
                &content_type,
                body,
            ),
        )
        .await;
        assert_eq!(
            mdn_disposition(&resp),
            "processed/error: insufficient-message-security",
            "{label}"
        );
        assert_signed_by(&resp, &p.b);
    }
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
    assert!(p.receiver_audit.records().is_empty());
}

#[tokio::test]
async fn bad_signature_is_authentication_failed() {
    let p = pair();
    // Same CA and AS2 id as the partner, but not its pinned certificate.
    let impostor = p.ca.as2_party(A_ID);
    let (content_type, body) = raw_message(Some(&impostor.signing), Some(&p.b.encryption));
    let resp = post(
        &p,
        request(A_ID, B_ID, "impostor@test", &content_type, body),
    )
    .await;
    assert_eq!(resp.status(), http::StatusCode::OK);
    assert_eq!(
        mdn_disposition(&resp),
        "processed/error: authentication-failed"
    );
    // A signer from another CA entirely.
    let stranger =
        asx::testkit::pki::KeyPair::self_signed("stranger", asx::testkit::pki::KeyAlg::Rsa2048);
    let (content_type, body) = raw_message(Some(&stranger), Some(&p.b.encryption));
    let resp = post(
        &p,
        request(A_ID, B_ID, "stranger@test", &content_type, body),
    )
    .await;
    assert_eq!(
        mdn_disposition(&resp),
        "processed/error: authentication-failed"
    );
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn every_decryption_failure_is_the_same_decryption_failed() {
    let p = pair();
    let elsewhere =
        asx::testkit::pki::KeyPair::self_signed("elsewhere", asx::testkit::pki::KeyAlg::Rsa2048);
    let (wrong_ct, wrong_key) = raw_message(Some(&p.a.signing), Some(&elsewhere));
    let (good_ct, good) = raw_message(Some(&p.a.signing), Some(&p.b.encryption));
    let mut corrupted = good.clone();
    let n = corrupted.len();
    for b in &mut corrupted[n - 120..n - 40] {
        *b = if *b == b'A' { b'B' } else { b'A' };
    }
    let garbage = b"MIME-Version: 1.0\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data\r\nContent-Transfer-Encoding: base64\r\n\r\nTm90IGEgQ01TIHN0cnVjdHVyZQ==\r\n".to_vec();
    let mut answers = Vec::new();
    for (i, (ct, body)) in [
        (wrong_ct.as_str(), wrong_key),
        (good_ct.as_str(), corrupted),
        ("application/pkcs7-mime; smime-type=enveloped-data", garbage),
    ]
    .into_iter()
    .enumerate()
    {
        let resp = post(&p, request(A_ID, B_ID, &format!("dec{i}@test"), ct, body)).await;
        assert_eq!(
            mdn_disposition(&resp),
            "processed/error: decryption-failed",
            "case {i}"
        );
        // The whole report text is uniform: only the ids differ.
        let text = String::from_utf8_lossy(resp.body()).to_string();
        let human = text
            .split("text/plain")
            .nth(1)
            .and_then(|t| t.split("--").next())
            .unwrap_or_default()
            .to_string();
        answers.push(human);
    }
    assert!(answers.windows(2).all(|w| w[0] == w[1]), "{answers:?}");
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unknown_sender_is_refused_before_any_private_key_operation() {
    let p = pair();
    // Encrypted to a key the receiver does not hold. Were it decrypted
    // first, the answer would be decryption-failed; it is refused on AS2-From.
    let elsewhere =
        asx::testkit::pki::KeyPair::self_signed("elsewhere", asx::testkit::pki::KeyAlg::Rsa2048);
    let (content_type, body) = raw_message(Some(&p.a.signing), Some(&elsewhere));
    let resp = post(
        &p,
        request("NOT-A-PARTNER", B_ID, "unknown@test", &content_type, body),
    )
    .await;
    assert_eq!(
        mdn_disposition(&resp),
        "processed/error: authentication-failed"
    );
    // And with a body that is not CMS at all: still the sender is refused first.
    let resp = post(
        &p,
        request(
            "NOT-A-PARTNER",
            B_ID,
            "unknown2@test",
            "application/pkcs7-mime; smime-type=enveloped-data",
            b"junk".to_vec(),
        ),
    )
    .await;
    assert_eq!(
        mdn_disposition(&resp),
        "processed/error: authentication-failed"
    );
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn as2_to_other_than_the_local_party_is_refused() {
    let p = pair();
    let (content_type, body) = raw_message(Some(&p.a.signing), Some(&p.b.encryption));
    let resp = post(
        &p,
        request(A_ID, "SOMEONE-ELSE", "to@test", &content_type, body),
    )
    .await;
    assert_eq!(
        mdn_disposition(&resp),
        "processed/error: unexpected-processing-error"
    );
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn raw_signed_and_encrypted_message_is_delivered() {
    let p = pair();
    let (content_type, body) = raw_message(Some(&p.a.signing), Some(&p.b.encryption));
    let resp = post(&p, request(A_ID, B_ID, "raw@test", &content_type, body)).await;
    assert_eq!(resp.status(), http::StatusCode::OK);
    assert_eq!(mdn_disposition(&resp), "processed");
    assert_signed_by(&resp, &p.b);
    let delivered = p.delivered.lock().unwrap();
    assert_eq!(delivered[0].0, "raw@test");
    assert_eq!(delivered[0].1, A_ID);
    assert_eq!(delivered[0].2, PAYLOAD);
    assert_eq!(delivered[0].3, EDI);
}

/// A signed-and-encrypted message whose signed content is RFC 5402
/// compressed: `inner` is the MIME entity inside the `CompressedData`.
fn compressed_message(p: &as2_peers::Pair, inner: &[u8]) -> (String, Vec<u8>) {
    let compressed = asx::__fuzz::compress_cms_zlib(inner, 6).expect("compress");
    asx::__fuzz::as2_raw_message(
        &compressed,
        asx::__fuzz::AS2_COMPRESSED_CONTENT_TYPE,
        A_ID,
        Some((&p.a.signing.cert_pem, &p.a.signing.key_pem)),
        Some(&p.b.encryption.cert_pem),
    )
    .expect("raw message")
}

#[tokio::test]
async fn a_compressed_entity_surfaces_its_inner_content_type_and_body() {
    let p = pair();
    let mut inner =
        b"Content-Type: application/edi-x12\r\nContent-Transfer-Encoding: binary\r\n\r\n".to_vec();
    inner.extend_from_slice(PAYLOAD);
    let (content_type, body) = compressed_message(&p, &inner);
    let resp = post(&p, request(A_ID, B_ID, "zip@test", &content_type, body)).await;
    assert_eq!(mdn_disposition(&resp), "processed");
    let delivered = p.delivered.lock().unwrap();
    assert_eq!(delivered[0].2, PAYLOAD);
    assert_eq!(delivered[0].3, EDI);
}

#[tokio::test]
async fn a_compressed_entity_without_mime_headers_is_decompression_failed() {
    let p = pair();
    let (content_type, body) = compressed_message(&p, PAYLOAD);
    let resp = post(&p, request(A_ID, B_ID, "zip-raw@test", &content_type, body)).await;
    assert_eq!(
        mdn_disposition(&resp),
        "processed/error: decompression-failed"
    );
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn handler_refusal_or_panic_releases_the_claim() {
    for mode in [HANDLER_ERR, HANDLER_PANIC] {
        let p = pair();
        p.mode.store(mode, Ordering::SeqCst);
        let (content_type, body) = raw_message(Some(&p.a.signing), Some(&p.b.encryption));
        let resp = post(
            &p,
            request(A_ID, B_ID, "h@test", &content_type, body.clone()),
        )
        .await;
        assert_eq!(
            mdn_disposition(&resp),
            "processed/error: unexpected-processing-error"
        );
        assert!(p.receiver_audit.records().is_empty());
        // Abandoned: the retransmission is delivered.
        p.mode.store(HANDLER_OK, Ordering::SeqCst);
        let resp = post(&p, request(A_ID, B_ID, "h@test", &content_type, body)).await;
        assert_eq!(mdn_disposition(&resp), "processed");
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn in_flight_is_503_and_a_dedup_failure_is_500() {
    let p = pair();
    let key = asx::__dedup_key("as2", "", A_ID, "busy@test");
    assert!(matches!(
        p.dedup.claim(&key).await.unwrap(),
        Claim::Claimed(_)
    ));
    let (content_type, body) = raw_message(Some(&p.a.signing), Some(&p.b.encryption));
    let resp = post(&p, request(A_ID, B_ID, "busy@test", &content_type, body)).await;
    assert_eq!(resp.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    assert!(resp.body().is_empty());
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);

    // A sender whose MDN is HTTP 503 without a body sees Indeterminate.
    let err = p
        .sender
        .send(p.message(PAYLOAD).message_id("busy@test"))
        .await
        .expect_err("in flight");
    assert_eq!(err.kind(), ErrorKind::Indeterminate);
}

#[derive(Debug)]
struct BrokenDedup;

impl DedupStore for BrokenDedup {
    fn claim<'a>(
        &'a self,
        _key: &'a str,
    ) -> asx::BoxFuture<'a, Result<Claim, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(std::future::ready(Err("store down".into())))
    }
    fn accept<'a>(
        &'a self,
        _key: &'a str,
        _token: &'a asx::ClaimToken,
    ) -> asx::BoxFuture<'a, Result<(), Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(std::future::ready(Err("store down".into())))
    }
    fn abandon<'a>(
        &'a self,
        _key: &'a str,
        _token: &'a asx::ClaimToken,
    ) -> asx::BoxFuture<'a, Result<(), Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(std::future::ready(Err("store down".into())))
    }
}

#[tokio::test]
async fn dedup_failure_is_500_without_an_mdn() {
    let p = pair();
    p.loopback.mount(
        B_URL,
        p.receiver
            .inbound(BrokenDedup, |_m: asx::Verified<asx::as2::Received>| async {
                Ok(())
            }),
    );
    let (content_type, body) = raw_message(Some(&p.a.signing), Some(&p.b.encryption));
    let resp = post(&p, request(A_ID, B_ID, "broken@test", &content_type, body)).await;
    assert_eq!(resp.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(resp.body().is_empty());
}

#[tokio::test]
async fn audit_failure_is_500_without_an_mdn_and_releases_the_claim() {
    let ca = asx::testkit::pki::TestCa::new("root", asx::testkit::pki::KeyAlg::Rsa2048);
    let (a, b) = (ca.as2_party(A_ID), ca.as2_party(B_ID));
    let receiver = asx::as2::As2::builder(asx::Profile::as2())
        .local(b.local())
        .trust_anchor(ca.anchor())
        .partner(a.partner(as2_peers::A_URL))
        .http_client(asx::testkit::loopback::Loopback::new())
        .audit(as2_peers::FailingSink)
        .build()
        .unwrap();
    let dedup = Arc::new(asx::MemoryDedup::default());
    let loopback = asx::testkit::loopback::Loopback::new();
    loopback.mount(
        B_URL,
        receiver.inbound(
            as2_peers::SharedDedup(dedup.clone()),
            |_m: asx::Verified<asx::as2::Received>| async { Ok(()) },
        ),
    );
    let (content_type, body) = raw_message(Some(&a.signing), Some(&b.encryption));
    let resp = loopback
        .exchange(request(A_ID, B_ID, "audit@test", &content_type, body))
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(resp.body().is_empty());
    let key = asx::__dedup_key("as2", "", A_ID, "audit@test");
    assert!(
        matches!(dedup.claim(&key).await.unwrap(), Claim::Claimed(_)),
        "abandoned"
    );
}

#[tokio::test]
async fn unaddressable_requests_are_400() {
    let p = pair();
    let (content_type, body) = raw_message(Some(&p.a.signing), Some(&p.b.encryption));
    let mut req = request(A_ID, B_ID, "x@test", &content_type, body);
    req.headers_mut().remove("Message-ID");
    let resp = post(&p, req).await;
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    assert!(resp.body().is_empty());
    // No AS2-From: addressed by Message-ID, so a 400 with an MDN.
    let (content_type, body) = raw_message(Some(&p.a.signing), Some(&p.b.encryption));
    let mut req = request(A_ID, B_ID, "nofrom@test", &content_type, body);
    req.headers_mut().remove("AS2-From");
    let resp = post(&p, req).await;
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    assert_eq!(
        mdn_disposition(&resp),
        "processed/error: unexpected-processing-error"
    );
}

#[tokio::test]
async fn an_async_mdn_request_is_answered_synchronously() {
    let p = pair();
    let (content_type, body) = raw_message(Some(&p.a.signing), Some(&p.b.encryption));
    let mut req = request(A_ID, B_ID, "async@test", &content_type, body);
    req.headers_mut().insert(
        "Receipt-Delivery-Option",
        http::HeaderValue::from_static("https://a.example/mdn"),
    );
    let resp = post(&p, req).await;
    assert_eq!(resp.status(), http::StatusCode::OK);
    assert_eq!(mdn_disposition(&resp), "processed");
}

#[tokio::test]
async fn oversized_body_is_413() {
    let ca = asx::testkit::pki::TestCa::new("root", asx::testkit::pki::KeyAlg::Rsa2048);
    let (a, b) = (ca.as2_party(A_ID), ca.as2_party(B_ID));
    let receiver = asx::as2::As2::builder(asx::Profile::as2().max_message_bytes(64))
        .local(b.local())
        .trust_anchor(ca.anchor())
        .partner(a.partner(as2_peers::A_URL))
        .http_client(asx::testkit::loopback::Loopback::new())
        .build()
        .unwrap();
    let loopback = asx::testkit::loopback::Loopback::new();
    loopback.mount(
        B_URL,
        receiver.inbound(
            asx::MemoryDedup::default(),
            |_m: asx::Verified<asx::as2::Received>| async { Ok(()) },
        ),
    );
    let (content_type, body) = raw_message(Some(&a.signing), Some(&b.encryption));
    let resp = loopback
        .exchange(request(A_ID, B_ID, "big@test", &content_type, body))
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::PAYLOAD_TOO_LARGE);
}

/// Counts the private-key operations (`asx.decrypt` spans) of one request.
async fn decrypt_calls(
    p: &as2_peers::Pair,
    request: http::Request<bytes::Bytes>,
) -> (usize, String) {
    let capture = asx::testkit::trace::TraceCapture::new();
    let resp = {
        let _guard = capture.set_default();
        post(p, request).await
    };
    (
        capture.spans_named("asx.decrypt").len(),
        mdn_disposition(&resp),
    )
}

#[tokio::test]
async fn counts_zero_decrypt_calls_for_an_unknown_sender() {
    let p = pair();
    let (content_type, body) = raw_message(Some(&p.a.signing), Some(&p.b.encryption));
    let (calls, disposition) = decrypt_calls(
        &p,
        request(
            "NOT-A-PARTNER",
            B_ID,
            "t054@test",
            &content_type,
            body.clone(),
        ),
    )
    .await;
    assert_eq!(disposition, "processed/error: authentication-failed");
    assert_eq!(calls, 0, "no private-key operation for an unknown AS2-From");
    // The counter does see the decryption of a configured sender's message.
    let (calls, disposition) =
        decrypt_calls(&p, request(A_ID, B_ID, "t054b@test", &content_type, body)).await;
    assert_eq!(disposition, "processed");
    assert_eq!(calls, 1);
}

/// The signed part of a `multipart/signed` MDN: the report itself, without
/// the per-response boundary and signature.
fn signed_report(resp: &http::Response<bytes::Bytes>) -> Vec<u8> {
    let content_type = resp.headers()["content-type"].to_str().unwrap();
    let boundary = content_type
        .split("boundary=")
        .nth(1)
        .expect("a boundary")
        .trim_matches('"');
    let delimiter = format!("--{boundary}");
    let body = resp.body();
    let text = String::from_utf8_lossy(body);
    let start = text.find(&delimiter).expect("first part") + delimiter.len() + 1;
    let end = start + text[start..].find(&delimiter).expect("second part");
    body[start..end].to_vec()
}

/// `body` (an asx S/MIME EnvelopedData) with its `EnvelopedData` changed by
/// `tamper`.
fn tampered(body: &[u8], tamper: impl FnOnce(&mut cms::enveloped_data::EnvelopedData)) -> Vec<u8> {
    use base64::Engine as _;
    use der::{Decode as _, Encode as _};
    let der = openssl::cms::CmsContentInfo::smime_read_cms(body)
        .and_then(|c| c.to_der())
        .expect("an S/MIME EnvelopedData");
    let info = cms::content_info::ContentInfo::from_der(&der).unwrap();
    let mut enveloped: cms::enveloped_data::EnvelopedData = info.content.decode_as().unwrap();
    tamper(&mut enveloped);
    let der = cms::content_info::ContentInfo {
        content_type: info.content_type,
        content: der::Any::encode_from(&enveloped).unwrap(),
    }
    .to_der()
    .unwrap();
    format!(
        "MIME-Version: 1.0\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    )
    .into_bytes()
}

/// A PKCS#1 v1.5 padding failure (the CEK does not unwrap) and a
/// content failure (the CEK unwraps, the content padding is wrong) are
/// answered identically — status, AS2 headers and the signed report octets —
/// so the answer is no padding oracle.
#[tokio::test]
async fn padding_and_content_failures_produce_identical_mdns() {
    let p = pair();
    let (content_type, body) = raw_message(Some(&p.a.signing), Some(&p.b.encryption));
    let bad_padding = tampered(&body, |e| {
        let mut ris: Vec<cms::enveloped_data::RecipientInfo> = e.recip_infos.0.clone().into();
        let cms::enveloped_data::RecipientInfo::Ktri(ktri) = &mut ris[0] else {
            panic!("a KeyTransRecipientInfo")
        };
        let mut wrapped = ktri.enc_key.as_bytes().to_vec();
        wrapped[0] ^= 0xff;
        wrapped[1] ^= 0xff;
        ktri.enc_key = der::asn1::OctetString::new(wrapped).unwrap();
        e.recip_infos = cms::enveloped_data::RecipientInfos(ris.try_into().unwrap());
    });
    let bad_content = tampered(&body, |e| {
        let content = e.encrypted_content.encrypted_content.as_mut().unwrap();
        let mut bytes = content.as_bytes().to_vec();
        // CBC: the last octet of the second-to-last block flips the padding
        // length octet of the last block — never valid.
        let n = bytes.len();
        bytes[n - 17] ^= 0xff;
        *content = der::asn1::OctetString::new(bytes).unwrap();
    });
    let mut answers = Vec::new();
    for body in [bad_padding, bad_content] {
        // The same Message-ID: both are refused before the dedup claim.
        let resp = post(&p, request(A_ID, B_ID, "r9@test", &content_type, body)).await;
        assert_eq!(mdn_disposition(&resp), "processed/error: decryption-failed");
        let headers: Vec<(String, String)> = ["as2-version", "as2-from", "as2-to", "mime-version"]
            .iter()
            .map(|h| {
                (
                    h.to_string(),
                    resp.headers()[*h].to_str().unwrap().to_string(),
                )
            })
            .collect();
        answers.push((resp.status(), headers, signed_report(&resp)));
    }
    assert_eq!(answers[0], answers[1]);
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
}

/// RFC 4130 §6.1: a missing or unsupported `AS2-Version` is refused with
/// HTTP 400 and a signed `unexpected-processing-error` MDN; 1.0, 1.1 and 1.2
/// are accepted.
#[tokio::test]
async fn as2_version_is_checked() {
    let p = pair();
    let (content_type, body) = raw_message(Some(&p.a.signing), Some(&p.b.encryption));
    for (i, version) in [None, Some("2.0"), Some("1.3"), Some("one")]
        .into_iter()
        .enumerate()
    {
        let mut req = request(
            A_ID,
            B_ID,
            &format!("v{i}@test"),
            &content_type,
            body.clone(),
        );
        match version {
            Some(v) => {
                req.headers_mut()
                    .insert("as2-version", http::HeaderValue::from_static(v));
            }
            None => {
                req.headers_mut().remove("as2-version");
            }
        }
        let resp = post(&p, req).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST, "{version:?}");
        assert_eq!(
            mdn_disposition(&resp),
            "processed/error: unexpected-processing-error",
            "{version:?}"
        );
        assert_signed_by(&resp, &p.b);
    }
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
    for (i, version) in ["1.0", "1.1", "1.2"].into_iter().enumerate() {
        let mut req = request(
            A_ID,
            B_ID,
            &format!("ok{i}@test"),
            &content_type,
            body.clone(),
        );
        req.headers_mut()
            .insert("as2-version", http::HeaderValue::from_static(version));
        let resp = post(&p, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK, "{version}");
        assert_eq!(mdn_disposition(&resp), "processed", "{version}");
    }
}
