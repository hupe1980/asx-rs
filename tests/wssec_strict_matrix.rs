#![cfg(feature = "as4")]

use asx::core::ErrorCode;
use asx::crypto::wssec::{
    WsSecCanonicalizationProfile, WsSecVerifyOptions, canonicalize_reference,
    parse_signature_references, verify_enveloped_signature, verify_signature_references_strict,
};

const SHA256_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

fn signed_xml(reference_uri: &str, payload_xml: &str, digest_base64: &str) -> String {
    format!(
        r#"<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns:eb="urn:example:eb">
  <soap:Header>
    <ds:Signature>
      <ds:SignedInfo>
        <ds:Reference URI="{reference_uri}">
          <ds:DigestMethod Algorithm="{SHA256_URI}"/>
          <ds:DigestValue>{digest_base64}</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>stub-signature</ds:SignatureValue>
    </ds:Signature>
  </soap:Header>
  <soap:Body>
{payload_xml}
  </soap:Body>
</soap:Envelope>"#
    )
}

#[test]
fn strict_profile_accepts_spec_compliant_reference() {
    let payload = "    <eb:Payload wsu:Id=\"payload-1\">ABC</eb:Payload>";
    let unsigned = signed_xml("#payload-1", payload, "placeholder");
    let digest = canonicalize_reference(
        &unsigned,
        "#payload-1",
        WsSecCanonicalizationProfile::default(),
    )
    .expect("digest")
    .digest_value_base64;

    let signed = signed_xml("#payload-1", payload, &digest);
    let refs = parse_signature_references(&signed).expect("refs");

    verify_signature_references_strict(&signed, &refs).expect("strict verify");
}

#[test]
fn strict_mode_rejects_whitespace_digest_mismatch() {
    let payload =
        "    <eb:Payload wsu:Id=\"payload-1\">\n      <eb:Value>ABC</eb:Value>\n    </eb:Payload>";
    let unsigned = signed_xml("#payload-1", payload, "placeholder");

    let whitespace_digest = canonicalize_reference(
        &unsigned,
        "#payload-1",
        WsSecCanonicalizationProfile {
            kind: asx::crypto::wssec::WsSecCanonicalizationKind::Exclusive,
            include_comments: false,
            strip_blank_text: false,
            inclusive_ns_prefixes: Vec::new(),
        },
    )
    .expect("digest")
    .digest_value_base64;

    let signed = signed_xml("#payload-1", payload, &whitespace_digest);
    let refs = parse_signature_references(&signed).expect("refs");

    let err = verify_signature_references_strict(&signed, &refs)
        .expect_err("strict mode must reject whitespace digest mismatch");
    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
}

#[test]
fn strict_mode_rejects_wrapped_reference_uri() {
    let payload = "    <eb:Payload wsu:Id=\"payload-1\">ABC</eb:Payload>";
    let unsigned = signed_xml("#payload-1", payload, "placeholder");
    let digest = canonicalize_reference(
        &unsigned,
        "#payload-1",
        WsSecCanonicalizationProfile::default(),
    )
    .expect("digest")
    .digest_value_base64;

    let signed = signed_xml(" #payload-1 ", payload, &digest);
    let err = parse_signature_references(&signed)
        .expect_err("strict mode must reject URI normalization violations during parsing");
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn strict_profile_rejects_tampered_body_digest_mismatch() {
    let original_payload = "    <eb:Payload wsu:Id=\"payload-1\">ORIGINAL</eb:Payload>";
    let unsigned = signed_xml("#payload-1", original_payload, "placeholder");
    let digest = canonicalize_reference(
        &unsigned,
        "#payload-1",
        WsSecCanonicalizationProfile::default(),
    )
    .expect("digest")
    .digest_value_base64;

    let tampered_payload = "    <eb:Payload wsu:Id=\"payload-1\">TAMPERED</eb:Payload>";
    let tampered = signed_xml("#payload-1", tampered_payload, &digest);
    let refs = parse_signature_references(&tampered).expect("refs");

    let err = verify_signature_references_strict(&tampered, &refs)
        .expect_err("strict must reject body tampering");
    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
}

#[test]
fn strict_profile_rejects_malformed_signature_value() {
    let xml = r##"<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
        xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
        xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        xmlns:eb="urn:example:eb">
    <soap:Header>
        <ds:Signature>
            <ds:SignedInfo>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="#payload-1">
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>ZmFrZS1kaWdlc3Q=</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>%%%not-base64%%%</ds:SignatureValue>
            <ds:KeyInfo>
                <ds:KeyValue>
                    <ds:RSAKeyValue>
                        <ds:Modulus>AQ==</ds:Modulus>
                        <ds:Exponent>AQAB</ds:Exponent>
                    </ds:RSAKeyValue>
                </ds:KeyValue>
            </ds:KeyInfo>
        </ds:Signature>
    </soap:Header>
    <soap:Body>
        <eb:Payload wsu:Id="payload-1">ABC</eb:Payload>
    </soap:Body>
</soap:Envelope>"##;

    let err = verify_enveloped_signature(
        xml,
        WsSecVerifyOptions::new()
            .with_expected_fingerprint(None)
            .with_revocation(asx::crypto::wssec::RevocationPolicy {
                trust_anchor_pems: &[],
                revocation_crl_pems: &[],
                ocsp_mode: asx::core::OcspMode::Disabled,
                ocsp_failure_mode: asx::core::OcspFailureMode::HardFail,
                stapled_ocsp_responses_der: &[],
                responder_ocsp_responses_der: &[],
                ocsp_cache_namespace: "strict-matrix-test",
                require_chain_validation: false,
                pre_parsed_trust_anchors: None,
                pre_built_x509_store: None,
            }),
    )
    .expect_err("malformed signature value must fail strict verification");

    assert_eq!(err.code, ErrorCode::ParseFailed);
}

#[test]
fn strict_profile_rejects_with_comments_reference_transform() {
    let xml = r##"<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
        xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
        xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        xmlns:eb="urn:example:eb">
    <soap:Header>
        <ds:Signature>
            <ds:SignedInfo>
                <ds:Reference URI="#payload-1">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>ZmFrZS1kaWdlc3Q=</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>stub-signature</ds:SignatureValue>
        </ds:Signature>
    </soap:Header>
    <soap:Body>
        <eb:Payload wsu:Id="payload-1">ABC</eb:Payload>
    </soap:Body>
</soap:Envelope>"##;

    let err = parse_signature_references(xml)
        .expect_err("with-comments transform must be rejected by strict parser");
    assert_eq!(err.code, ErrorCode::InteropViolation);
}
