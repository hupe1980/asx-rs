//! Integration-style tests for the AS4 module.
//!
//! Kept out of `mod.rs` so the module file stays what it is — a re-export hub —
//! and matches the `as2/tests.rs` layout.

use super::signals::*;
use super::stream::extract_multipart_related_payload_if_present;
use super::*;
use crate::core::constant_time_eq;
use crate::core::{ErrorCode, SessionContext};
use crate::crypto::wssec::{
    WsSecOutboundKeyInfoProfile, WsSecVerifyOptions, verify_enveloped_signature,
};

#[test]
fn multipart_content_id_matching_accepts_mixed_case_cid_prefix() {
    let session = SessionContext::new("s-multipart-cid", "p1", "strict").expect("session");
    let multipart = concat!(
        "--boundary123\r\n",
        "Content-Type: application/xop+xml; charset=UTF-8; type=\"application/soap+xml\"\r\n",
        "Content-ID: <soap-root@example.com>\r\n",
        "\r\n",
        "<S12:Envelope xmlns:S12=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:xop=\"http://www.w3.org/2004/08/xop/include\"><S12:Body><xop:Include href=\"cid:payload-123@example.com\"/></S12:Body></S12:Envelope>\r\n",
        "--boundary123\r\n",
        "Content-Type: application/octet-stream\r\n",
        "Content-ID: <CID:payload-123@example.com>\r\n",
        "\r\n",
        "payload-bytes\r\n",
        "--boundary123--\r\n"
    )
    .as_bytes();

    let parsed = extract_multipart_related_payload_if_present(
        multipart,
        "multipart/related; boundary=boundary123",
        &session,
        "as4_receive_push",
    )
    .expect("multipart parse");

    let parsed = parsed.expect("multipart payload");
    assert_eq!(
        parsed.payloads.first().map(|p| p.bytes),
        Some(b"payload-bytes".as_slice())
    );
    assert_eq!(
        parsed.payloads.first().map(|p| p.content_id),
        Some("payload-123@example.com")
    );
}

/// RFC 2046 §5.1.1: a multipart body may start with a preamble before the
/// first delimiter; phase4 (Jakarta Mail) always sends a leading CRLF.
#[test]
fn multipart_preamble_before_the_first_boundary_is_skipped() {
    let session = SessionContext::new("s-multipart-preamble", "p1", "strict").expect("session");
    for preamble in ["\r\n", "\r\n\r\n", "This is a MIME message.\r\n"] {
        let multipart = format!(
            "{preamble}--b1\r\nContent-Type: application/soap+xml\r\n\r\n<S12:Envelope/>\r\n\
             --b1\r\nContent-Type: application/octet-stream\r\nContent-ID: <p@x>\r\n\r\n\
             body\r\n--b1--\r\n"
        );
        let parsed = extract_multipart_related_payload_if_present(
            multipart.as_bytes(),
            "multipart/related; boundary=b1",
            &session,
            "as4_receive_push",
        )
        .unwrap_or_else(|e| panic!("{preamble:?}: {e}"))
        .expect("multipart");
        assert_eq!(parsed.soap_xml, b"<S12:Envelope/>");
        assert_eq!(parsed.payloads[0].bytes, b"body");
    }
}

/// ebMS3 allows several `eb:PartInfo` entries per `UserMessage`, and the
/// eDelivery conformance payload profiles exercise four. Every MIME part is
/// kept, in wire order; which are payloads is decided against the signed
/// `eb:PartInfo`, not by the bytes of the envelope.
#[test]
fn multipart_keeps_every_part_in_wire_order() {
    let session = SessionContext::new("s-multipart-multi", "p1", "strict").expect("session");
    let multipart = concat!(
        "--b1\r\n",
        "Content-Type: application/xop+xml; charset=UTF-8; type=\"application/soap+xml\"\r\n",
        "Content-ID: <soap-root@example.com>\r\n",
        "\r\n",
        "<S12:Envelope xmlns:S12=\"http://www.w3.org/2003/05/soap-envelope\" ",
        "xmlns:xop=\"http://www.w3.org/2004/08/xop/include\"><S12:Body>",
        "<xop:Include href=\"cid:xmlpayload@gitb\"/>",
        "<xop:Include href='cid:xmlpayload2@gitb'/>",
        "<xop:Include href=\"cid:custompayload@gitb\"/>",
        "</S12:Body></S12:Envelope>\r\n",
        // Deliberately out of order relative to the references, and with an
        // unreferenced part interleaved.
        "--b1\r\n",
        "Content-Type: application/octet-stream\r\n",
        "Content-ID: <custompayload@gitb>\r\n",
        "\r\n",
        "third\r\n",
        "--b1\r\n",
        "Content-Type: application/octet-stream\r\n",
        "Content-ID: <unreferenced@gitb>\r\n",
        "\r\n",
        "ignored\r\n",
        "--b1\r\n",
        "Content-Type: application/xml\r\n",
        "Content-ID: <xmlpayload@gitb>\r\n",
        "\r\n",
        "first\r\n",
        "--b1\r\n",
        "Content-Type: application/xml\r\n",
        "Content-ID: <xmlpayload2@gitb>\r\n",
        "\r\n",
        "second\r\n",
        "--b1--\r\n"
    )
    .as_bytes();

    let parsed = extract_multipart_related_payload_if_present(
        multipart,
        "multipart/related; boundary=b1",
        &session,
        "as4_receive_push",
    )
    .expect("multipart parse")
    .expect("multipart payload");

    let resolved: Vec<(&str, &[u8])> = parsed
        .payloads
        .iter()
        .map(|p| (p.content_id, p.bytes))
        .collect();
    assert_eq!(
        resolved,
        vec![
            ("custompayload@gitb", b"third".as_slice()),
            ("unreferenced@gitb", b"ignored".as_slice()),
            ("xmlpayload@gitb", b"first".as_slice()),
            ("xmlpayload2@gitb", b"second".as_slice()),
        ]
    );
}

// PayloadFilename validation tests (header injection, empty string,
// over-length) live in `mime_packaging::tests` — that is the type boundary
// where invariants are enforced. The send pipeline never receives an
// already-invalid PayloadFilename; the type system prevents it.

#[test]
fn generate_receipt_is_deterministic() {
    let session = SessionContext::new("s1", "p1", "strict").expect("session");
    let out = generate_receipt(&session, "receipt-msg-1", "msg-1").expect("receipt");
    let xml = match std::str::from_utf8(&out) {
        Ok(xml) => xml,
        Err(err) => panic!("receipt XML must be valid UTF-8: {err}"),
    };
    assert!(
        xml.contains("<eb:MessageId>receipt-msg-1</eb:MessageId>"),
        "receipt must include its own MessageId per ebMS3 §5.2.2.1"
    );
    assert!(
        xml.contains("<eb:RefToMessageId>msg-1</eb:RefToMessageId>"),
        "receipt must reference the original message ID"
    );
    // Receipts are unsigned by default; callers apply signing credentials
    // via generate_xmlsig_signature before transmitting for NRI.
    assert!(
        !xml.contains("<ds:Signature>"),
        "unsigned receipt must not contain a stub signature element"
    );
}

#[test]
fn generate_receipt_rejects_empty_message_id() {
    let session = SessionContext::new("s1", "p1", "strict").expect("session");
    let err = generate_receipt(&session, "", "ref-1").expect_err("must fail");
    assert_eq!(err.code, ErrorCode::InvalidInput);
}

#[test]
fn generate_receipt_rejects_empty_ref() {
    let session = SessionContext::new("s1", "p1", "strict").expect("session");
    let err = generate_receipt(&session, "msg-id", "").expect_err("must fail");
    assert_eq!(err.code, ErrorCode::InvalidInput);
}

#[test]
fn generate_receipt_with_nri_embeds_reference_elements() {
    let session = SessionContext::new("s1", "p1", "strict").expect("session");
    let nri_refs = vec![As4NriReference {
        uri: "#body".to_string(),
        digest_method_uri: "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
        digest_value_b64: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".to_string(),
    }];
    let out = generate_receipt_with_nri(&session, "receipt-nri-1", "msg-1", &nri_refs)
        .expect("receipt with nri");
    let xml = std::str::from_utf8(&out).expect("valid UTF-8");
    assert!(
        xml.contains("<ebbpsig:NonRepudiationInformation>"),
        "NRI element must be non-empty when refs are provided"
    );
    assert!(
        xml.contains("<ebbpsig:MessagePartNRInformation>"),
        "must contain MessagePartNRInformation per ebMS3 §5.2.2.1"
    );
    assert!(
        xml.contains("<ds:Reference URI=\"#body\">"),
        "ds:Reference must echo the original URI"
    );
    assert!(
        xml.contains("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="),
        "digest value must be preserved"
    );
    assert!(
        xml.contains("xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\""),
        "ds namespace must be declared when NRI refs are present"
    );
}

#[test]
fn generate_receipt_with_nri_empty_refs_matches_generate_receipt() {
    let session = SessionContext::new("s1", "p1", "strict").expect("session");
    let plain = generate_receipt(&session, "r1", "ref-1").expect("plain");
    let with_nri =
        generate_receipt_with_nri(&session, "r1", "ref-1", &[]).expect("nri with empty refs");
    // Timestamps make byte-for-byte equality unreliable; compare structure instead.
    let plain_xml = std::str::from_utf8(&plain).expect("utf8");
    let nri_xml = std::str::from_utf8(&with_nri).expect("utf8");
    assert!(
        plain_xml.contains("<ebbpsig:NonRepudiationInformation/>"),
        "empty-refs receipt must contain self-closing NRI element"
    );
    assert!(
        nri_xml.contains("<ebbpsig:NonRepudiationInformation/>"),
        "nri with empty refs must match plain receipt NRI form"
    );
    assert!(
        !nri_xml.contains("xmlns:ds="),
        "ds namespace must not appear when no NRI refs are provided"
    );
}

#[test]
fn generate_receipt_with_nri_xml_injection_is_escaped() {
    let session = SessionContext::new("s1", "p1", "strict").expect("session");
    let nri_refs = vec![As4NriReference {
        uri: "#body\"><script>attack</script>".to_string(),
        digest_method_uri: "http://example.com/?a=1&b=2".to_string(),
        digest_value_b64: "abc123".to_string(),
    }];
    let out = generate_receipt_with_nri(&session, "r1", "ref-1", &nri_refs).expect("receipt");
    let xml = std::str::from_utf8(&out).expect("utf8");
    assert!(!xml.contains("<script>"), "XML injection must be escaped");
    assert!(xml.contains("&amp;"), "ampersand must be entity-escaped");
}

fn test_nri_refs() -> Vec<As4NriReference> {
    vec![As4NriReference {
        uri: "#body".to_string(),
        digest_method_uri: "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
        digest_value_b64: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".to_string(),
    }]
}

fn test_receipt_credentials() -> As4ReceiptCredentials {
    let (cert, key) = crate::test_support::self_signed_rsa("asx-receipt-signer");
    As4ReceiptCredentials {
        signing_key_pem: key,
        signing_cert_pem: cert,
        key_info_profile: WsSecOutboundKeyInfoProfile::default(),
    }
}

#[test]
fn generate_signed_receipt_with_nri_verifies_and_parses_as_signed() {
    let session = SessionContext::new("s1", "p1", "strict").expect("session");
    let creds = test_receipt_credentials();
    let out = generate_signed_receipt_with_nri(
        &session,
        "receipt-signed-1",
        "msg-1",
        &test_nri_refs(),
        &creds,
    )
    .expect("signed receipt");
    let xml = std::str::from_utf8(&out).expect("utf8");

    assert!(
        xml.contains("wsse:Security"),
        "signed receipt must carry a wsse:Security header"
    );
    assert!(
        xml.contains("<ds:Signature"),
        "signed receipt must carry a ds:Signature"
    );
    assert!(
        xml.contains("<ebbpsig:MessagePartNRInformation>"),
        "NRI refs must be echoed"
    );
    assert!(
        xml.contains("<eb:RefToMessageId>msg-1</eb:RefToMessageId>"),
        "receipt must reference the original message ID"
    );

    // The signature must verify with the library's own verifier …
    verify_enveloped_signature(xml, WsSecVerifyOptions::new())
        .expect("library-generated signed receipt must verify");
}

#[test]
fn generate_signed_receipt_tampering_breaks_verification() {
    let session = SessionContext::new("s1", "p1", "strict").expect("session");
    let creds = test_receipt_credentials();
    let out = generate_signed_receipt_with_nri(
        &session,
        "receipt-signed-2",
        "msg-1",
        &test_nri_refs(),
        &creds,
    )
    .expect("signed receipt");
    let xml = std::str::from_utf8(&out).expect("utf8");
    let tampered = xml.replace(
        "<eb:RefToMessageId>msg-1</eb:RefToMessageId>",
        "<eb:RefToMessageId>msg-2</eb:RefToMessageId>",
    );
    assert_ne!(xml, tampered, "tampering must change the envelope");
    verify_enveloped_signature(&tampered, WsSecVerifyOptions::new())
        .expect_err("tampered signed receipt must fail verification");
}

#[test]
fn generate_signed_receipt_rejects_mismatched_credentials() {
    let session = SessionContext::new("s1", "p1", "strict").expect("session");
    let creds_a = test_receipt_credentials();
    let creds_b = test_receipt_credentials();
    let creds = As4ReceiptCredentials {
        signing_key_pem: creds_b.signing_key_pem.clone(),
        signing_cert_pem: creds_a.signing_cert_pem.clone(),
        key_info_profile: WsSecOutboundKeyInfoProfile::default(),
    };
    let err = generate_signed_receipt_with_nri(&session, "receipt-signed-3", "msg-1", &[], &creds)
        .expect_err("mismatched cert/key must fail");
    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert!(err.message.contains("does not match signing_key_pem"));
}

#[test]
fn generate_signed_receipt_rejects_empty_message_id() {
    let session = SessionContext::new("s1", "p1", "strict").expect("session");
    let creds = test_receipt_credentials();
    let err = generate_signed_receipt_with_nri(&session, "", "ref-1", &[], &creds)
        .expect_err("must fail");
    assert_eq!(err.code, ErrorCode::InvalidInput);
}

#[test]
fn constant_time_eq_returns_true_for_equal_slices() {
    assert!(constant_time_eq(b"secret", b"secret"));
    assert!(constant_time_eq(b"", b""));
}

#[test]
fn constant_time_eq_returns_false_for_differing_slices() {
    assert!(!constant_time_eq(b"secret", b"wrong_"));
    assert!(!constant_time_eq(b"secret", b"secre")); // different length
    assert!(!constant_time_eq(b"", b"x"));
}
