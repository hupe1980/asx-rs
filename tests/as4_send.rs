#![cfg(feature = "as4")]
//! `As4::send` end to end against a real partner `Inbound`.

#[path = "common/peers.rs"]
mod peers;

use asx::as4::Message;
use asx::{ErrorKind, Payload, Quirk};
use peers::{AS4_PRESETS, HANDLER_ERR, Preset, pair, pair_with, soap_part};
use std::sync::atomic::Ordering;

#[tokio::test]
async fn bdew_send_returns_verified_receipt_and_records_it() {
    let p = pair(Preset::Bdew);
    let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let captured = captured.clone();
        p.loopback
            .intercept(move |resp| captured.lock().unwrap().push(resp.body().to_vec()));
    }
    let receipt = p
        .sender
        .send(Preset::Bdew.message(&p.to_b, b"UNB+UNOC:3"))
        .await
        .expect("verified receipt");
    let wire = captured.lock().unwrap().pop().expect("a response");
    assert_eq!(receipt.evidence().signal(), Some(wire.as_slice()));
    // The same record was handed to the sink.
    let records = p.sender_audit.records();
    assert_eq!(records.len(), 1);
    assert_eq!(&records[0], receipt.evidence());
    assert_eq!(receipt.signer(), &p.b.signing.certificate());
    let json = serde_json::to_value(receipt.evidence()).unwrap();
    assert_eq!(json["profile"], "bdew-1.2");
    assert_eq!(json["outcome"], "delivered");
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn every_preset_encrypts() {
    for preset in AS4_PRESETS {
        let p = pair(preset);
        let plaintext = b"PLAINTEXT-MARKER-0123456789";
        p.sender
            .send(preset.message(&p.to_b, plaintext))
            .await
            .unwrap_or_else(|e| panic!("{preset:?}: {e}"));
        let request = p.loopback.last_request().expect("request");
        let body = request.body();
        let text = String::from_utf8_lossy(body);
        assert!(
            text.contains("EncryptedData"),
            "{preset:?}: payload not encrypted"
        );
        assert!(
            !body.windows(plaintext.len()).any(|w| w == plaintext),
            "{preset:?}: plaintext on the wire"
        );
        let delivered = p.delivered.lock().unwrap();
        assert_eq!(
            delivered[0].2[0], plaintext,
            "{preset:?}: payload round trip"
        );
    }
}

async fn indeterminate_with(
    hook: impl Fn(&mut http::Response<bytes::Bytes>) + Send + Sync + 'static,
) {
    let p = pair(Preset::Bdew);
    p.loopback.intercept(hook);
    let err = p
        .sender
        .send(Preset::Bdew.message(&p.to_b, b"x"))
        .await
        .expect_err("refused receipt");
    assert_eq!(err.kind(), ErrorKind::Indeterminate, "{err}");
    assert!(err.is_retryable());
    assert!(
        err.evidence().is_some(),
        "an Indeterminate result keeps the evidence: {err}"
    );
}

fn rewrite(resp: &mut http::Response<bytes::Bytes>, f: impl Fn(String) -> String) {
    let text = String::from_utf8(resp.body().to_vec()).unwrap();
    *resp.body_mut() = bytes::Bytes::from(f(text));
}

#[tokio::test]
async fn tampered_receipt_digest_is_indeterminate() {
    indeterminate_with(|resp| {
        rewrite(resp, |text| {
            // Corrupt the first NRI digest the receipt echoes.
            let at = text.find("DigestValue>").unwrap() + "DigestValue>".len();
            let mut bytes = text.into_bytes();
            bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
            String::from_utf8(bytes).unwrap()
        })
    })
    .await;
}

#[tokio::test]
async fn receipt_for_another_message_is_indeterminate() {
    indeterminate_with(|resp| {
        rewrite(resp, |text| {
            let start = text.find("RefToMessageId>").unwrap() + "RefToMessageId>".len();
            let end = start + text[start..].find('<').unwrap();
            format!("{}other@example.org{}", &text[..start], &text[end..])
        })
    })
    .await;
}

#[tokio::test]
async fn unsigned_receipt_is_indeterminate() {
    indeterminate_with(|resp| {
        rewrite(resp, |text| {
            let start = text.find("<wsse:Security").unwrap();
            let end = text.find("</wsse:Security>").unwrap() + "</wsse:Security>".len();
            format!("{}{}", &text[..start], &text[end..])
        })
    })
    .await;
}

#[tokio::test]
async fn receipt_from_an_unpinned_signer_is_indeterminate() {
    // The sender pins a certificate the partner does not sign with.
    let other = asx_testkit::pki::TestCa::sm_pki().bdew_party("9900000000002");
    let p = pair_with(
        Preset::Bdew,
        |b| {
            asx::Partner::new(&b.id)
                .party_type(asx_testkit::pki::BDEW_PARTY_TYPE)
                .endpoint(peers::B_URL)
                .signing_cert(other.signing.certificate())
                .encryption_cert(b.encryption.certificate())
        },
        |a| a.partner(peers::A_URL),
    );
    let err = p
        .sender
        .send(Preset::Bdew.message(&p.to_b, b"x"))
        .await
        .expect_err("unpinned receipt signer");
    assert_eq!(err.kind(), ErrorKind::Indeterminate, "{err}");
    assert!(err.evidence().is_some());
}

#[tokio::test]
async fn partner_refusal_is_partner_error_with_ebms_code() {
    let p = pair(Preset::Bdew);
    p.mode.store(HANDLER_ERR, Ordering::SeqCst);
    let err = p
        .sender
        .send(Preset::Bdew.message(&p.to_b, b"x"))
        .await
        .expect_err("refused");
    assert_eq!(err.kind(), ErrorKind::PartnerError, "{err}");
    assert_eq!(err.ebms_code(), Some("EBMS:0202"));
    assert!(err.is_retryable());
    assert!(err.evidence().is_some());
}

#[tokio::test]
async fn unreachable_partner_is_retryable_and_nothing_is_recorded() {
    let p = pair(Preset::Bdew);
    // An unregistered partner (e.g. from a directory): validated at send,
    // and nothing is mounted at its endpoint.
    let c = p.ca.bdew_party("9900000000003");
    let elsewhere = c.partner("https://nowhere.example/as4");
    let err = p
        .sender
        .send(Preset::Bdew.message(&elsewhere, b"x"))
        .await
        .expect_err("unreachable");
    // A custom HttpClient's error may have been written: Indeterminate.
    // The built-in client's not-written classification is
    // unit-tested in src/http_client.rs.
    assert_eq!(err.kind(), ErrorKind::Indeterminate, "{err}");
    assert!(err.is_retryable());
    assert!(p.sender_audit.records().is_empty());
}

#[tokio::test]
async fn ping_uses_the_test_service_and_is_not_delivered() {
    let p = pair(Preset::Bdew);
    p.sender
        .send(Message::ping(&p.to_b).payload(Payload::new(&b"ping"[..], "text/plain")))
        .await
        .expect("receipted");
    let soap = soap_part(p.loopback.last_request().unwrap().body());
    assert!(soap.contains("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/service"));
    assert!(soap.contains("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/test"));
    assert_eq!(
        p.calls.load(Ordering::SeqCst),
        0,
        "W10: a ping is never delivered"
    );
}

#[tokio::test]
async fn retried_message_keeps_messaging_and_body_digests() {
    // Same message id and timestamp → the same eb:Messaging, Body and `cid:`
    // digests (signing precedes encryption, so the attachment digest covers the deterministic gzip bytes, not ciphertext).
    let p = pair(Preset::Bdew);
    // The first attempt's time, reused (the receiver's freshness window is
    // five minutes, eDelivery 1.15 §5.1.3).
    let at = std::time::SystemTime::now();
    let message = Preset::Bdew
        .message(&p.to_b, b"retry me")
        .message_id("retry-1@asx.test")
        .timestamp(at);
    let digests = |body: &[u8]| -> Vec<String> {
        let soap = soap_part(body);
        let cid = soap
            .match_indices("URI=\"cid:")
            .map(|(i, _)| {
                let rest = &soap[i + 5..];
                rest[..rest.find('"').unwrap()].to_string()
            })
            .next()
            .expect("a cid: reference");
        ["#as4-messaging", "#as4-body", cid.as_str()]
            .iter()
            .map(|uri| {
                let at = soap.find(&format!("URI=\"{uri}\"")).expect(uri);
                let rest = &soap[at..];
                let start = rest.find("DigestValue>").unwrap() + "DigestValue>".len();
                rest[start..start + rest[start..].find('<').unwrap()].to_string()
            })
            .collect()
    };
    p.sender.send(message.clone()).await.expect("first");
    let first = digests(p.loopback.last_request().unwrap().body());
    // The receiver answers the retry as a duplicate with a fresh receipt.
    p.sender.send(message).await.expect("retry receipted");
    let second = digests(p.loopback.last_request().unwrap().body());
    assert_eq!(first, second);
    assert_eq!(
        p.calls.load(Ordering::SeqCst),
        1,
        "the duplicate is not delivered twice"
    );
}

#[tokio::test]
async fn receipt_without_nri_needs_the_quirk() {
    // A partner whose receipts carry an empty NonRepudiationInformation.
    use asx::__fuzz::wssec::WsSecOutboundKeyInfoProfile;
    use asx::__fuzz::{As4ReceiptCredentials, generate_signed_receipt_with_nri};
    for quirk in [false, true] {
        let p = pair_with(
            Preset::Edelivery,
            |b| {
                let partner = b.partner(peers::B_URL);
                if quirk {
                    partner.quirk(Quirk::ReceiptWithoutNonRepudiation)
                } else {
                    partner
                }
            },
            |a| a.partner(peers::A_URL),
        );
        let signing = p.b.signing.clone();
        p.loopback.intercept(move |resp| {
            let session = asx::__fuzz::SessionContextBuilder::new("b", "a")
                .build()
                .unwrap();
            let body = generate_signed_receipt_with_nri(
                &session,
                "receipt-1@asx.test",
                "nri-1@asx.test",
                &[],
                &As4ReceiptCredentials {
                    signing_key_pem: signing.key_pem.clone(),
                    signing_cert_pem: signing.cert_pem.clone(),
                    key_info_profile: WsSecOutboundKeyInfoProfile::BinarySecurityTokenX509v3,
                },
            )
            .unwrap();
            *resp.body_mut() = bytes::Bytes::from(body);
        });
        let result = p
            .sender
            .send(
                Preset::Edelivery
                    .message(&p.to_b, b"x")
                    .message_id("nri-1@asx.test"),
            )
            .await;
        if quirk {
            let receipt = result.expect("accepted under the quirk");
            let json = serde_json::to_value(receipt.evidence()).unwrap();
            assert_eq!(json["quirks"][0], "receipt_without_non_repudiation");
        } else {
            assert_eq!(
                result.expect_err("refused").kind(),
                ErrorKind::Indeterminate
            );
        }
    }
}

#[tokio::test]
async fn invalid_message_is_config_and_nothing_is_sent() {
    let p = pair(Preset::Bdew);
    for message in [
        Message::to(&p.to_b).payload(Payload::new(&b"x"[..], "application/octet-stream")), // no service
        Preset::Bdew.message(&p.to_b, b"x").action("urn:other"), // unknown action
        Preset::Bdew.message(&p.to_b, b"x").conversation_id("c-1"), // BDEW has no conversation id
        Message::to(&p.to_b).service(peers::MP),                 // no payload
        Message::to(&p.to_b)
            .service(peers::MP)
            .payload(Payload::new(&b"x"[..], "text/plain\r\nX-Injected: 1")), // header injection
        Message::to(&p.to_b)
            .service(peers::MP)
            .payload(Payload::new(&b"x"[..], "application/octet-stream").named("../etc/passwd")), // path in file name
        Preset::Bdew
            .message(&p.to_b, b"x")
            .message_id("<bracketed@x>"), // angle brackets
    ] {
        let err = p.sender.send(message).await.expect_err("refused");
        assert_eq!(err.kind(), ErrorKind::Config, "{err}");
    }
    assert_eq!(p.loopback.requests(), 0);
}

#[tokio::test]
async fn peppol_refuses_file_names() {
    let p = pair(Preset::Peppol);
    let message = Preset::Peppol.message(&p.to_b, b"<Invoice/>");
    let named = Message::to(&p.to_b)
        .service("urn:x")
        .action("urn:y")
        .payload(Payload::new(&b"<Invoice/>"[..], "application/xml").named("invoice.xml"));
    assert_eq!(
        p.sender.send(named).await.unwrap_err().kind(),
        ErrorKind::Config
    ); // a named payload
    p.sender
        .send(message)
        .await
        .expect("unnamed payload is fine");
}

#[tokio::test(flavor = "current_thread")]
async fn send_works_on_a_current_thread_runtime() {
    let p = pair(Preset::Edelivery);
    p.sender
        .send(Preset::Edelivery.message(&p.to_b, b"x"))
        .await
        .expect("no block_on, no block_in_place");
}
