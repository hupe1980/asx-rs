#![cfg(all(feature = "as4", feature = "client"))]
//! Enveloped whole-document XML signatures — the shape SMP `ServiceMetadata`
//! responses use (`ds:Reference URI=""` plus an `enveloped-signature`
//! transform).
//!
//! # Cross-validation status
//!
//! Unlike the AS4 signing path, which is checked against xmlsec1 in
//! `tests/interop_xmlsec_oracle.rs`, this path is **not yet cross-validated
//! against an independent implementation**. The tests below exercise ASX's
//! verifier against documents ASX understands; they prove the logic and the
//! tamper-detection, not byte-level agreement with another stack.
//!
//! Closing that gap needs an xmlsec1 *signing* fixture (its `--sign` key
//! templating did not cooperate) or a captured real PEPPOL SMP response.

use asx_rs::core::ErrorCode;
use asx_rs::crypto::wssec::{
    OwnedRevocationPolicy, RevocationPolicy, verify_enveloped_document_signature,
};

/// A `ServiceMetadata` skeleton with a structurally complete but
/// cryptographically meaningless signature.
fn service_metadata(endpoint: &str, reference_uri: &str, transforms: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ServiceMetadata xmlns="http://busdox.org/serviceMetadata/publishing/1.0/">
  <ServiceInformation>
    <ProcessList><Process>
      <ProcessIdentifier scheme="cenbii-procid-ubl">urn:test:process</ProcessIdentifier>
      <ServiceEndpointList><Endpoint transportProfile="peppol-transport-as4-v2_0">
        <EndpointURI>{endpoint}</EndpointURI>
      </Endpoint></ServiceEndpointList>
    </Process></ProcessList>
  </ServiceInformation>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="{reference_uri}">
        <ds:Transforms>{transforms}</ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>AAAA</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>AAAA</ds:SignatureValue>
    <ds:KeyInfo><ds:X509Data><ds:X509Certificate>AAAA</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
  </ds:Signature>
</ServiceMetadata>"#
    )
}

const ENVELOPED: &str =
    r#"<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>"#;
const EXC_C14N: &str = r#"<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#;

fn anchors() -> OwnedRevocationPolicy {
    OwnedRevocationPolicy::production(vec![])
}

fn verify(xml: &str) -> asx_rs::core::Result<()> {
    let owned = anchors();
    verify_enveloped_document_signature(xml, &[], &RevocationPolicy::from(&owned)).map(|_| ())
}

/// A reference that is not whole-document is rejected by name rather than
/// silently treated as one.
#[test]
fn a_non_empty_reference_uri_is_rejected() {
    let xml = service_metadata(
        "https://ap.example.com/as4",
        "#some-id",
        &format!("{ENVELOPED}{EXC_C14N}"),
    );
    let err = verify(&xml).expect_err("only URI=\"\" is supported here");
    assert_eq!(err.code, ErrorCode::InteropViolation);
    assert!(err.message.contains("URI=\"\""), "{}", err.message);
}

/// Without the enveloped-signature transform the signature would have to
/// contain its own digest, which is impossible — so a document claiming that
/// shape is malformed, not merely unverifiable.
#[test]
fn a_whole_document_reference_must_declare_the_enveloped_transform() {
    let xml = service_metadata("https://ap.example.com/as4", "", EXC_C14N);
    let err = verify(&xml).expect_err("the enveloped transform is mandatory");
    assert_eq!(err.code, ErrorCode::InteropViolation);
    assert!(
        err.message.contains("enveloped-signature"),
        "{}",
        err.message
    );
}

#[test]
fn an_unsupported_transform_is_rejected_by_name() {
    let xml = service_metadata(
        "https://ap.example.com/as4",
        "",
        &format!(r#"{ENVELOPED}<ds:Transform Algorithm="urn:made:up"/>"#),
    );
    let err = verify(&xml).expect_err("unknown transforms must not be ignored");
    assert_eq!(err.code, ErrorCode::InteropViolation);
    assert!(err.message.contains("urn:made:up"), "{}", err.message);
}

/// A well-formed enveloped reference gets as far as the digest check and fails
/// there — proving the reference machinery ran rather than short-circuiting.
#[test]
fn a_well_formed_reference_reaches_and_fails_the_digest_check() {
    let xml = service_metadata(
        "https://ap.example.com/as4",
        "",
        &format!("{ENVELOPED}{EXC_C14N}"),
    );
    let err = verify(&xml).expect_err("the placeholder digest must not match");
    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
    assert!(err.message.contains("digest mismatch"), "{}", err.message);
}

#[test]
fn a_document_without_a_signature_is_rejected() {
    let err =
        verify("<ServiceMetadata xmlns=\"http://busdox.org/serviceMetadata/publishing/1.0/\"/>")
            .expect_err("an unsigned document cannot be verified");
    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
    assert!(err.message.contains("no ds:Signature"), "{}", err.message);
}

/// The enveloped canonicalization must exclude the signature element itself
/// and include everything else — so changing the endpoint URL changes the
/// digest, while the (excluded) signature's own bytes do not.
#[test]
fn enveloped_canonicalization_excludes_the_signature_and_covers_the_rest() {
    use asx_rs::crypto::wssec::{WsSecCanonicalizationProfile, canonicalize_enveloped_document};
    use roxmltree::Document;

    let render = |endpoint: &str, sig_digest: &str| {
        let xml = service_metadata(endpoint, "", &format!("{ENVELOPED}{EXC_C14N}")).replace(
            "<ds:DigestValue>AAAA</ds:DigestValue>",
            &format!("<ds:DigestValue>{sig_digest}</ds:DigestValue>"),
        );
        let doc = Document::parse(&xml).expect("parse");
        let signature = doc
            .descendants()
            .find(|n| {
                n.is_element()
                    && n.tag_name().name() == "Signature"
                    && n.tag_name().namespace() == Some("http://www.w3.org/2000/09/xmldsig#")
            })
            .expect("signature");
        canonicalize_enveloped_document(&doc, &WsSecCanonicalizationProfile::default(), signature)
            .expect("canonicalize")
            .digest_value_base64
    };

    let base = render("https://ap.example.com/as4", "AAAA");

    // Content outside the signature is covered.
    assert_ne!(
        base,
        render("https://evil.example/as4", "AAAA"),
        "the endpoint URL must be inside the signed octets"
    );

    // Content inside the signature is excluded.
    assert_eq!(
        base,
        render("https://ap.example.com/as4", "BBBB"),
        "the ds:Signature subtree must be removed before digesting; otherwise the \
         reference could never contain its own digest"
    );
}
