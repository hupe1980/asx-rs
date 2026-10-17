use super::mdn::{generate_mdn, generate_signed_mdn};
use super::*;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509NameBuilder};

fn session() -> SessionContext {
    SessionContext::new("s1", "p1", "strict").expect("session")
}

/// `(certificate PEM, private key PEM)` of a fresh self-signed RSA signer.
fn test_as2_credentials() -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(2048).expect("rsa");
    let pkey = PKey::from_rsa(rsa).expect("pkey");

    let mut name = X509NameBuilder::new().expect("name builder");
    name.append_entry_by_nid(Nid::COMMONNAME, "asx-test-signer")
        .expect("cn");
    let name = name.build();

    let mut serial = BigNum::new().expect("serial");
    serial
        .pseudo_rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .expect("serial rand");
    let serial = serial.to_asn1_integer().expect("serial asn1");

    let mut builder = X509::builder().expect("x509 builder");
    builder.set_version(2).expect("version");
    builder.set_serial_number(&serial).expect("serial");
    builder.set_subject_name(&name).expect("subject");
    builder.set_issuer_name(&name).expect("issuer");
    builder.set_pubkey(&pkey).expect("pubkey");
    let not_before = Asn1Time::days_from_now(0).expect("not_before");
    let not_after = Asn1Time::days_from_now(365).expect("not_after");
    builder.set_not_before(&not_before).expect("nb");
    builder.set_not_after(&not_after).expect("na");
    builder
        .sign(&pkey, openssl::hash::MessageDigest::sha256())
        .expect("sign cert");
    let cert = builder.build();

    (
        cert.to_pem().expect("cert pem"),
        pkey.private_key_to_pem_pkcs8().expect("private key pem"),
    )
}

#[test]
fn generate_mdn_is_deterministic() {
    let out = generate_mdn(
        &session(),
        "<msg-1@example.com>",
        "automatic-action/MDN-sent-automatically; processed",
        Some("abc123, sha-256"),
    )
    .expect("mdn generation");

    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains("Content-Type: multipart/report;"));
    assert!(text.contains("report-type=disposition-notification"));
    assert!(text.contains("Content-Type: text/plain; charset=us-ascii"));
    assert!(text.contains("Content-Type: message/disposition-notification"));
    assert!(text.contains("Original-Message-ID: <msg-1@example.com>"));
    assert!(text.contains("Disposition: automatic-action/MDN-sent-automatically; processed"));
    assert!(text.contains("Received-Content-MIC: abc123, sha-256"));
}

#[test]
fn generate_mdn_rejects_empty_message_id() {
    let err = generate_mdn(
        &session(),
        "",
        "automatic-action/MDN-sent-automatically; processed",
        None,
    )
    .expect_err("must fail");
    assert_eq!(err.code, ErrorCode::InvalidInput);
}

#[test]
fn parse_signed_receipt_micalg_is_case_insensitive_and_allows_quotes() {
    assert_eq!(
        ingress::parse_signed_receipt_micalg("signed-receipt-micalg=required,sha-256"),
        Some(As2MicAlgorithm::Sha256)
    );
    assert_eq!(
        ingress::parse_signed_receipt_micalg(
            "Signed-Receipt-Micalg=\"required, sha256\"; signed-receipt-protocol=required,pkcs7-signature"
        ),
        Some(As2MicAlgorithm::Sha256)
    );
    assert_eq!(
        ingress::parse_signed_receipt_micalg("signed-receipt-micalg=required,sha-1"),
        None
    );
    assert_eq!(
        ingress::parse_signed_receipt_micalg("signed-receipt-micalg=required,SHA-384"),
        Some(As2MicAlgorithm::Sha384)
    );
    assert_eq!(
        ingress::parse_signed_receipt_micalg("signed-receipt-micalg=required,sha512"),
        Some(As2MicAlgorithm::Sha512)
    );
    assert_eq!(
        ingress::parse_signed_receipt_micalg("signed-receipt-micalg=required,md5"),
        None
    );
}

// ── MDN generation refuses header injection ─────────────────────────────────

#[test]
fn generate_mdn_rejects_header_injection() {
    let (signing_cert_pem, signing_key_pem) = test_as2_credentials();
    let signing = As2MdnSigningCredentials {
        signing_cert_pem,
        signing_key_pem,
    };
    let good_id = "<msg-1@example.com>";
    let good_disposition = "automatic-action/MDN-sent-automatically; processed";
    let good_mic = "ZXELZG2MstvZ8CzynjCRhlEuxafCsnlFN6wFAV9r8AA=, sha-256";

    for bad in ["\r", "\n", "\0"] {
        let bad_id = format!("<msg-1@example.com>{bad}X-Injected: y");
        let bad_disposition = format!("{good_disposition}{bad}X-Injected: y");
        let bad_mic = format!("{good_mic}{bad}X-Injected: y");
        let cases: [(&str, &str, Option<&str>, &str); 3] = [
            (
                &bad_id,
                good_disposition,
                Some(good_mic),
                "original_message_id",
            ),
            (good_id, &bad_disposition, Some(good_mic), "disposition"),
            (
                good_id,
                good_disposition,
                Some(&bad_mic),
                "received_content_mic",
            ),
        ];
        for (id, disposition, mic, field) in cases {
            let err = generate_mdn(&session(), id, disposition, mic)
                .err()
                .unwrap_or_else(|| panic!("generate_mdn accepted {bad:?} in {field}"));
            assert_eq!(
                err.code,
                ErrorCode::InvalidInput,
                "{field}: {}",
                err.message
            );
            let err = generate_signed_mdn(&session(), id, disposition, mic, &signing)
                .err()
                .unwrap_or_else(|| panic!("generate_signed_mdn accepted {bad:?} in {field}"));
            assert_eq!(
                err.code,
                ErrorCode::InvalidInput,
                "{field}: {}",
                err.message
            );
        }
    }
}
