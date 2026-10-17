#![cfg(all(feature = "peppol", feature = "http-client"))]
//! Enveloped whole-document XML signatures — the shape SMP `ServiceMetadata`
//! responses use (`ds:Reference URI=""` plus an `enveloped-signature`
//! transform).
//!
//! The tests below exercise the verifier against documents ASX understands:
//! they prove the logic and the tamper detection. Agreement with a real
//! signer is checked against a captured Peppol SMP response in
//! `tests/interop_peppol_smp_oracle.rs`.

use asx::__fuzz::ErrorCode;
use asx::__fuzz::wssec::{ChainPolicy, OwnedChainPolicy, verify_enveloped_document_signature};

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

fn anchors() -> OwnedChainPolicy {
    OwnedChainPolicy::production(vec![])
}

fn verify(xml: &str) -> asx::__fuzz::Result<()> {
    let owned = anchors();
    verify_enveloped_document_signature(xml, &[], &ChainPolicy::from(&owned)).map(|_| ())
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

/// A well-formed enveloped reference passes the structural checks and then
/// stops at the signer: the whole-document digest is computed only for an
/// authenticated signer (authenticate before expensive work), so a meaningless certificate fails before any digest.
#[test]
fn a_well_formed_reference_with_an_untrusted_signer_fails_before_the_digest() {
    let xml = service_metadata(
        "https://ap.example.com/as4",
        "",
        &format!("{ENVELOPED}{EXC_C14N}"),
    );
    let err = verify(&xml).expect_err("the placeholder signer cannot be trusted");
    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
    assert!(!err.message.contains("digest mismatch"), "{}", err.message);
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
    use asx::__fuzz::wssec::{WsSecCanonicalizationProfile, canonicalize_enveloped_document};
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
