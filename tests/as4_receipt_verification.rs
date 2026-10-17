#![cfg(feature = "as4")]
//! Reception Awareness / Non-Repudiation of Receipt on `As4::send` (BDEW
//! AS4-Profil §4.6.3, eDelivery AS4 1.15 §5.1): a receipt is
//! evidence of delivery only when it is signed by the pinned partner, refers
//! to the sent message, and its `MessagePartNRInformation` echoes the
//! digests the sent message was signed over.
//!
//! Receipts are tampered in flight through the `Loopback` intercept. A
//! tampered receipt is re-signed with the partner's own key (doc-hidden
//! `asx::__fuzz::wssec`), so each refusal is about the tampered content and
//! not a broken signature; `resigned_receipt_is_still_accepted` is the
//! control. Unsigned and wrong-`RefToMessageId` receipts and the
//! `ReceiptWithoutNonRepudiation` quirk are covered in `as4_send.rs`.

#[path = "common/inbound_harness.rs"]
mod inbound_harness;
#[path = "common/peers.rs"]
mod peers;

use asx::ErrorKind;
use peers::{Preset, pair, soap_part};

type Hook = Box<dyn Fn(String) -> String + Send + Sync>;

/// Send under `preset` with every receipt rewritten by `tamper` and then
/// re-signed by the partner `b`.
async fn send_with_tampered_receipt(
    preset: Preset,
    tamper: impl Fn(String) -> String + Send + Sync + 'static,
) -> Result<asx::Verified<asx::Receipt>, asx::Error> {
    let p = pair(preset);
    let signer = p.b.signing.clone();
    let tamper: Hook = Box::new(tamper);
    p.loopback.intercept(move |resp| {
        let text = String::from_utf8(resp.body().to_vec()).unwrap();
        let resigned = inbound_harness::resign(&tamper(text), &[], &signer);
        *resp.body_mut() = bytes::Bytes::from(resigned);
    });
    p.sender
        .send(preset.message(&p.to_b, b"UNB+UNOC:3+nrr'"))
        .await
}

/// The `(URI, DigestValue)` pairs of the `ds:Reference`s in `xml`.
fn references(xml: &str) -> Vec<(String, String)> {
    xml.match_indices("<ds:Reference URI=\"")
        .map(|(i, m)| {
            let rest = &xml[i + m.len()..];
            let uri = rest[..rest.find('"').unwrap()].to_string();
            let start = rest.find("DigestValue>").unwrap() + "DigestValue>".len();
            let digest = rest[start..start + rest[start..].find('<').unwrap()].to_string();
            (uri, digest)
        })
        .collect()
}

#[tokio::test]
async fn nrr_round_trip_is_verified_end_to_end() {
    let p = pair(Preset::Edelivery);
    let receipt = p
        .sender
        .send(
            Preset::Edelivery
                .message(&p.to_b, b"nrr")
                .message_id("nrr-round-trip@asx.test"),
        )
        .await
        .expect("a verified receipt");
    let sent = references(&soap_part(p.loopback.last_request().unwrap().body()));
    let signal = String::from_utf8(receipt.evidence().signal().unwrap().to_vec()).unwrap();
    let nri_start = signal.find("NonRepudiationInformation").expect("NRI");
    let echoed = references(&signal[nri_start..]);
    assert_eq!(
        sent.len(),
        3,
        "eb:Messaging, Body and the attachment are signed"
    );
    assert_eq!(
        echoed, sent,
        "the receipt echoes exactly the sent ds:References"
    );
    assert!(signal.contains("RefToMessageId>nrr-round-trip@asx.test<"));
    assert_eq!(receipt.signer(), &p.b.signing.certificate());
}

#[tokio::test]
async fn resigned_receipt_is_still_accepted() {
    send_with_tampered_receipt(Preset::Edelivery, |text| text)
        .await
        .expect("re-signing by the partner's key keeps the receipt valid");
}

/// The receipt is validly signed by the partner but its NRI digest does not
/// match what was sent: no evidence of delivery for this content.
#[tokio::test]
async fn nrr_digest_mismatch_is_indeterminate() {
    let err = send_with_tampered_receipt(Preset::Edelivery, |text| {
        let nri = text.find("MessagePartNRInformation").unwrap();
        let at = nri + text[nri..].find("DigestValue>").unwrap() + "DigestValue>".len();
        let mut bytes = text.into_bytes();
        bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
        String::from_utf8(bytes).unwrap()
    })
    .await
    .expect_err("NRI digest mismatch");
    assert_eq!(err.kind(), ErrorKind::Indeterminate, "{err}");
    assert!(err.evidence().is_some());
}

/// A receipt that drops one of the sent references from its NRI.
#[tokio::test]
async fn nrr_missing_a_reference_is_indeterminate() {
    let err = send_with_tampered_receipt(Preset::Edelivery, |text| {
        let start = text.find("<ebbpsig:MessagePartNRInformation>").unwrap();
        let end = text.find("</ebbpsig:MessagePartNRInformation>").unwrap()
            + "</ebbpsig:MessagePartNRInformation>".len();
        format!("{}{}", &text[..start], &text[end..])
    })
    .await
    .expect_err("incomplete NRI");
    assert_eq!(err.kind(), ErrorKind::Indeterminate, "{err}");
}

/// Namespace confusion: a signed signal whose `Receipt` element is not in the
/// ebMS namespace is not a receipt.
#[tokio::test]
async fn receipt_in_a_foreign_namespace_is_indeterminate() {
    let err = send_with_tampered_receipt(Preset::Edelivery, |text| {
        text.replace("<eb:Receipt>", "<x:Receipt xmlns:x=\"urn:attacker:fake\">")
            .replace("</eb:Receipt>", "</x:Receipt>")
    })
    .await
    .expect_err("fake-namespace receipt");
    assert_eq!(err.kind(), ErrorKind::Indeterminate, "{err}");
}

/// A partner's signed `eb:Error` instead of a receipt is the partner's
/// answer, not delivery evidence.
#[tokio::test]
async fn ebms_error_signal_is_partner_error() {
    let err = send_with_tampered_receipt(Preset::Edelivery, |text| {
        let start = text.find("<eb:Receipt>").unwrap();
        let end = text.find("</eb:Receipt>").unwrap() + "</eb:Receipt>".len();
        format!(
            "{}<eb:Error errorCode=\"EBMS:0202\" severity=\"failure\" \
             shortDescription=\"DeliveryFailure\" category=\"Communication\" origin=\"ebMS\">\
             <eb:Description xml:lang=\"en\">refused</eb:Description></eb:Error>{}",
            &text[..start],
            &text[end..]
        )
    })
    .await
    .expect_err("an error signal is not a receipt");
    assert_eq!(err.kind(), ErrorKind::PartnerError, "{err}");
    assert_eq!(err.ebms_code(), Some("EBMS:0202"));
}

/// BDEW NRR on brainpoolP256r1: the receipt is signed with `ecdsa-sha256` as
/// `r ‖ s` and verifies as evidence; the same `(r, s)` re-encoded as DER is
/// refused.
#[tokio::test]
async fn ecdsa_receipt_verifies_as_nrr_evidence_and_der_is_rejected() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    let p = pair(Preset::Bdew);
    let receipt = p
        .sender
        .send(Preset::Bdew.message(&p.to_b, b"UNB"))
        .await
        .expect("an r ‖ s ECDSA receipt is NRR evidence");
    let body = String::from_utf8(receipt.evidence().signal().unwrap().to_vec()).unwrap();
    assert!(body.contains("xmldsig-more#ecdsa-sha256"), "{body}");
    let open = body.find("SignatureValue>").unwrap() + "SignatureValue>".len();
    let close = open + body[open..].find("</").unwrap();
    let wire = B64
        .decode(body[open..close].split_whitespace().collect::<String>())
        .unwrap();
    assert_eq!(wire.len(), 64, "brainpoolP256r1 r ‖ s");

    p.loopback.intercept(|resp| {
        let body = String::from_utf8(resp.body().to_vec()).unwrap();
        let open = body.find("SignatureValue>").unwrap() + "SignatureValue>".len();
        let close = open + body[open..].find("</").unwrap();
        let wire = B64
            .decode(body[open..close].split_whitespace().collect::<String>())
            .unwrap();
        let (r, s) = wire.split_at(32);
        let der = openssl::ecdsa::EcdsaSig::from_private_components(
            openssl::bn::BigNum::from_slice(r).unwrap(),
            openssl::bn::BigNum::from_slice(s).unwrap(),
        )
        .unwrap()
        .to_der()
        .unwrap();
        let der_receipt = format!("{}{}{}", &body[..open], B64.encode(&der), &body[close..]);
        *resp.body_mut() = bytes::Bytes::from(der_receipt);
    });
    let err = p
        .sender
        .send(Preset::Bdew.message(&p.to_b, b"UNB"))
        .await
        .expect_err("a DER ECDSA SignatureValue is not XMLDSig");
    assert_eq!(err.kind(), ErrorKind::Indeterminate, "{err}");
}

/// A signed receipt whose NRI `ds:DigestValue`s are folded with `&#13;` is
/// consumed with the values its signature covered:
/// character references are part of the text, not events to drop.
#[tokio::test]
async fn receipt_with_character_references_is_consumed_as_verified() {
    let receipt = send_with_tampered_receipt(Preset::Edelivery, |text| {
        let nri = text.find("NonRepudiationInformation").unwrap();
        let (head, tail) = text.split_at(nri);
        let mut folded = String::with_capacity(tail.len() + 64);
        let mut rest = tail;
        while let Some(at) = rest.find("<ds:DigestValue>") {
            let start = at + "<ds:DigestValue>".len();
            let end = start + rest[start..].find('<').unwrap();
            let (a, b) = rest[start..end].split_at(20);
            folded.push_str(&rest[..start]);
            folded.push_str(&format!("{a}&#13;\n{b}"));
            rest = &rest[end..];
        }
        folded.push_str(rest);
        format!("{head}{folded}")
    })
    .await
    .expect("the receipt the signature covered is the receipt consumed");
    let signal = String::from_utf8(receipt.evidence().signal().unwrap().to_vec()).unwrap();
    assert!(
        signal.contains("&#13;"),
        "the evidence keeps the wire bytes"
    );
}

/// The bytes of the last MIME part of a captured request (the encrypted
/// attachment: `IV ‖ ct ‖ tag`).
fn last_part_body(body: &[u8]) -> Vec<u8> {
    let start = body
        .windows(4)
        .rposition(|w| w == b"\r\n\r\n")
        .expect("last part")
        + 4;
    let end = body[start..]
        .windows(4)
        .position(|w| w == b"\r\n--")
        .expect("closing delimiter")
        + start;
    body[start..end].to_vec()
}

/// For an encrypted send, `As4::send` returns a
/// verified receipt whose echoed `cid:` digest is the sent digest — over the
/// part before encryption (the gzip bytes), not the ciphertext on the wire.
#[tokio::test]
async fn encrypted_send_receipt_echoes_plaintext_digests() {
    use base64::Engine;
    use sha2::Digest;
    let p = pair(Preset::Bdew);
    let receipt = p
        .sender
        .send(Preset::Bdew.message(&p.to_b, b"nrr over plaintext"))
        .await
        .expect("a verified receipt");
    let request = p.loopback.last_request().unwrap();
    let sent = references(&soap_part(request.body()));
    let signal = String::from_utf8(receipt.evidence().signal().unwrap().to_vec()).unwrap();
    let echoed = references(&signal[signal.find("NonRepudiationInformation").unwrap()..]);
    let (_, cid_digest) = echoed
        .iter()
        .find(|(uri, _)| uri.starts_with("cid:"))
        .expect("a cid: reference is echoed");
    assert_eq!(echoed, sent);
    let ciphertext = last_part_body(request.body());
    assert_ne!(
        cid_digest,
        &base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(&ciphertext)),
        "the digest covers the pre-encryption bytes"
    );
    // The digest is what the receiver verified over the decrypted part:
    // the message was delivered.
    assert_eq!(
        p.delivered.lock().unwrap()[0].2[0],
        b"nrr over plaintext".to_vec()
    );
}

/// A receipt this crate generates for an inbound encrypted
/// message echoes the sender's references unchanged (what WSS4J computed).
#[tokio::test]
async fn generated_receipt_echoes_sender_references() {
    let p = pair(Preset::Edelivery);
    let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let captured = captured.clone();
        p.loopback
            .intercept(move |resp| captured.lock().unwrap().push(resp.body().to_vec()));
    }
    p.sender
        .send(Preset::Edelivery.message(&p.to_b, b"echo"))
        .await
        .expect("receipted");
    let sent = references(&soap_part(p.loopback.last_request().unwrap().body()));
    let wire = String::from_utf8(captured.lock().unwrap().pop().unwrap()).unwrap();
    let echoed = references(&wire[wire.find("NonRepudiationInformation").unwrap()..]);
    assert_eq!(echoed, sent);
    assert!(echoed.iter().any(|(uri, _)| uri.starts_with("cid:")));
}
