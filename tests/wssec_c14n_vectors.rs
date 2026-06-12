#![cfg(feature = "as4")]

use asx::core::ErrorCode;
use asx::crypto::wssec::{
    WsSecCanonicalizationProfile, WsSecOutboundKeyInfoProfile, WsSecVerifyOptions,
    canonical_vector_diff, canonicalize_reference,
    generate_xmlsig_signature_with_external_references, parse_signature_references,
    verify_enveloped_signature, verify_signature_references_strict,
};

const BASE_XML_FIXTURE: &str = "tests/fixtures/wssec/signed_message.xml.golden";
const PREFIX_VARIANT_XML_FIXTURE: &str =
    "tests/fixtures/wssec/signed_message_prefix_variant.xml.golden";
const C14N_GOLDEN_FIXTURE: &str = "tests/fixtures/wssec/payload-1.c14n.golden";
const SIGNING_KEY_FIXTURE: &str = "tests/fixtures/pki/receipt_signing.key.pem";
const SIGNING_CERT_FIXTURE: &str = "tests/fixtures/pki/receipt_signing.cert.pem";

fn build_multi_reference_unsigned_envelope() -> String {
    r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
        xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
        xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
    <S12:Header>
        <eb:Messaging wsu:Id="msg-1">
            <eb:UserMessage/>
        </eb:Messaging>
    </S12:Header>
    <S12:Body wsu:Id="body-1">
        <eb:Payload id="payload-1">ABC</eb:Payload>
    </S12:Body>
</S12:Envelope>"#
                .to_string()
}

fn build_multi_reference_signed_envelope(detached_bytes: &[u8]) -> String {
    let unsigned = build_multi_reference_unsigned_envelope();
    let signing_key = std::fs::read(SIGNING_KEY_FIXTURE).expect("signing key fixture");
    let signing_cert = std::fs::read(SIGNING_CERT_FIXTURE).expect("signing cert fixture");
    let reference_uris = ["#msg-1", "#body-1", "cid:payload@example.com"];
    let external_refs = [("cid:payload@example.com", detached_bytes)];

    let signature = generate_xmlsig_signature_with_external_references(
        &unsigned,
        &reference_uris,
        &external_refs,
        &signing_key,
        &signing_cert,
        WsSecOutboundKeyInfoProfile::X509DataAndRsaKeyValue,
    )
    .expect("signature generation for mixed references");

    unsigned.replacen("<S12:Header>", &format!("<S12:Header>{signature}"), 1)
}

#[test]
fn canonicalization_matches_golden_vector() {
    let xml_template = std::fs::read_to_string(BASE_XML_FIXTURE).expect("fixture");
    let xml = xml_template.replace("{{DIGEST}}", "placeholder");

    let canonicalized =
        canonicalize_reference(&xml, "#payload-1", WsSecCanonicalizationProfile::default())
            .expect("canonicalization must pass");

    let expected = std::fs::read_to_string(C14N_GOLDEN_FIXTURE).expect("canonical golden");
    let actual = String::from_utf8_lossy(&canonicalized.canonical_bytes);
    assert!(
        actual == expected.trim_end(),
        "canonical vector mismatch\n{}",
        canonical_vector_diff(expected.trim_end(), &actual)
    );
}

#[test]
fn namespace_prefix_variants_produce_prefix_dependent_digests() {
    // Exclusive C14N preserves the original prefix names from the source document,
    // so two documents that use *different* prefix names for the same namespace URIs
    // produce different canonical byte sequences and therefore different digests.
    // This is correct per-spec behaviour for Exc-C14N (W3C 2002-07-18).
    // A sender's digest is computed over their serialized form; the receiver
    // recomputes from the *same* received bytes, so prefix differences never
    // cause a verification mismatch in practice.
    let base_template = std::fs::read_to_string(BASE_XML_FIXTURE).expect("base fixture");
    let variant_template =
        std::fs::read_to_string(PREFIX_VARIANT_XML_FIXTURE).expect("variant fixture");

    let base = base_template.replace("{{DIGEST}}", "placeholder");
    let variant = variant_template.replace("{{DIGEST}}", "placeholder");

    let base_c14n =
        canonicalize_reference(&base, "#payload-1", WsSecCanonicalizationProfile::default())
            .expect("base canonicalization");
    let variant_c14n = canonicalize_reference(
        &variant,
        "#payload-1",
        WsSecCanonicalizationProfile::default(),
    )
    .expect("variant canonicalization");

    // Different prefixes → different canonical bytes → different digests (by design).
    assert_ne!(
        base_c14n.digest_value_base64, variant_c14n.digest_value_base64,
        "Exc-C14N is prefix-dependent; variant prefixes must yield a different digest"
    );
    // Sanity-check: both documents still produce well-formed canonical output.
    assert!(
        String::from_utf8_lossy(&base_c14n.canonical_bytes).contains("xmlns:eb="),
        "base canonical form must contain xmlns:eb declaration"
    );
    assert!(
        String::from_utf8_lossy(&variant_c14n.canonical_bytes).contains("xmlns:x="),
        "variant canonical form must contain xmlns:x declaration"
    );
}

#[test]
fn parsed_references_verify_against_signed_message() {
    let template = std::fs::read_to_string(BASE_XML_FIXTURE).expect("fixture");
    let unsigned_xml = template.replace("{{DIGEST}}", "placeholder");

    let computed = canonicalize_reference(
        &unsigned_xml,
        "#payload-1",
        WsSecCanonicalizationProfile::default(),
    )
    .expect("compute digest");

    let signed_xml = template.replace("{{DIGEST}}", &computed.digest_value_base64);
    let references = parse_signature_references(&signed_xml).expect("parse references");

    verify_signature_references_strict(&signed_xml, &references).expect("reference verification");
}

#[test]
fn tampered_payload_fails_reference_verification() {
    let template = std::fs::read_to_string(BASE_XML_FIXTURE).expect("fixture");
    let unsigned_xml = template.replace("{{DIGEST}}", "placeholder");

    let computed = canonicalize_reference(
        &unsigned_xml,
        "#payload-1",
        WsSecCanonicalizationProfile::default(),
    )
    .expect("compute digest");

    let signed_xml = template.replace("{{DIGEST}}", &computed.digest_value_base64);
    let references = parse_signature_references(&signed_xml).expect("parse references");

    let tampered = signed_xml.replace(">ABC<", ">ABX<");
    let err = verify_signature_references_strict(&tampered, &references)
        .expect_err("tampered payload should fail");

    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
}

#[test]
fn deterministic_vector_diff_is_stable() {
    let expected = "<a>1</a>\n<b>2</b>\n<c>3</c>";
    let actual = "<a>1</a>\n<b>9</b>\n<d>4</d>";

    let diff = canonical_vector_diff(expected, actual);
    assert_eq!(
        diff,
        "L2: -<b>2</b>\nL2: +<b>9</b>\nL3: -<c>3</c>\nL3: +<d>4</d>"
    );
}

#[test]
fn canonicalization_is_stable_across_attribute_order_variants() {
    let xml_a = r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
        xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
    <S12:Body>
        <eb:Payload id="payload-1" alpha="A" beta="B">ABC</eb:Payload>
    </S12:Body>
</S12:Envelope>"#;

    let xml_b = r#"<S12:Envelope xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
        xmlns:S12="http://www.w3.org/2003/05/soap-envelope">
    <S12:Body>
        <eb:Payload beta="B" id="payload-1" alpha="A">ABC</eb:Payload>
    </S12:Body>
</S12:Envelope>"#;

    let c14n_a =
        canonicalize_reference(xml_a, "#payload-1", WsSecCanonicalizationProfile::default())
            .expect("canonicalization for attribute order variant A");
    let c14n_b =
        canonicalize_reference(xml_b, "#payload-1", WsSecCanonicalizationProfile::default())
            .expect("canonicalization for attribute order variant B");

    assert_eq!(
        c14n_a.digest_value_base64, c14n_b.digest_value_base64,
        "attribute and namespace declaration order must not change canonical digest"
    );
}

#[test]
fn default_profile_ignores_comments_for_digest_equivalence() {
    let xml_without_comment = r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
        xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
    <S12:Body>
        <eb:Payload id="payload-1">ABC</eb:Payload>
    </S12:Body>
</S12:Envelope>"#;

    let xml_with_comment = r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
        xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
    <S12:Body>
        <!-- transport intermediary comment that must not alter digest in default profile -->
        <eb:Payload id="payload-1">ABC</eb:Payload>
    </S12:Body>
</S12:Envelope>"#;

    let without_comment = canonicalize_reference(
        xml_without_comment,
        "#payload-1",
        WsSecCanonicalizationProfile::default(),
    )
    .expect("canonicalization without comment");
    let with_comment = canonicalize_reference(
        xml_with_comment,
        "#payload-1",
        WsSecCanonicalizationProfile::default(),
    )
    .expect("canonicalization with comment");

    assert_eq!(
        without_comment.digest_value_base64, with_comment.digest_value_base64,
        "comments must not affect digest under default include_comments=false profile"
    );
}

#[test]
fn inclusive_prefix_list_forces_visibly_unused_namespace_rendering() {
    let xml = r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
        xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
        xmlns:x="urn:partner:unused:prefix">
        <S12:Body>
        <eb:Payload id="payload-1" role="sender">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"#;

    let default_profile = WsSecCanonicalizationProfile::default();
    let inclusive_profile = WsSecCanonicalizationProfile {
        inclusive_ns_prefixes: vec!["x".to_string()],
        ..WsSecCanonicalizationProfile::default()
    };

    let default_c14n = canonicalize_reference(xml, "#payload-1", default_profile)
        .expect("canonicalization with default profile");
    let inclusive_c14n = canonicalize_reference(xml, "#payload-1", inclusive_profile)
        .expect("canonicalization with inclusive prefix list");

    let default_text = String::from_utf8_lossy(&default_c14n.canonical_bytes);
    let inclusive_text = String::from_utf8_lossy(&inclusive_c14n.canonical_bytes);

    assert!(
        !default_text.contains("xmlns:x=\"urn:partner:unused:prefix\""),
        "default exclusive C14N should omit visibly unused namespace declarations"
    );
    assert!(
        inclusive_text.contains("xmlns:x=\"urn:partner:unused:prefix\""),
        "inclusive prefix list must force rendering of in-scope unused namespace declaration"
    );
    assert_ne!(
        default_c14n.digest_value_base64, inclusive_c14n.digest_value_base64,
        "forcing unused namespace rendering must change canonical bytes/digest"
    );
}

#[test]
fn processing_instruction_changes_digest_under_default_profile() {
    let without_pi = r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
        xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Body>
        <eb:Payload id="payload-1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"#;

    let with_pi = r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
        xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Body>
        <eb:Payload id="payload-1"><?partner keep-this?>ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"#;

    let without_pi_c14n = canonicalize_reference(
        without_pi,
        "#payload-1",
        WsSecCanonicalizationProfile::default(),
    )
    .expect("canonicalization without PI");
    let with_pi_c14n = canonicalize_reference(
        with_pi,
        "#payload-1",
        WsSecCanonicalizationProfile::default(),
    )
    .expect("canonicalization with PI");

    assert_ne!(
        without_pi_c14n.digest_value_base64, with_pi_c14n.digest_value_base64,
        "processing instructions are part of canonical output and must influence digest"
    );
}

#[test]
fn strip_blank_text_profile_controls_whitespace_digest_sensitivity() {
    let compact = r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
        xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Body><eb:Payload id="payload-1"><eb:Chunk>A</eb:Chunk><eb:Chunk>B</eb:Chunk></eb:Payload></S12:Body>
    </S12:Envelope>"#;

    let expanded = r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
        xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Body>
        <eb:Payload id="payload-1">
            <eb:Chunk>A</eb:Chunk>
            <eb:Chunk>B</eb:Chunk>
        </eb:Payload>
        </S12:Body>
    </S12:Envelope>"#;

    let strip_profile = WsSecCanonicalizationProfile::default();
    let keep_profile = WsSecCanonicalizationProfile {
        strip_blank_text: false,
        ..WsSecCanonicalizationProfile::default()
    };

    let compact_strip = canonicalize_reference(compact, "#payload-1", strip_profile.clone())
        .expect("compact strip profile canonicalization");
    let expanded_strip = canonicalize_reference(expanded, "#payload-1", strip_profile)
        .expect("expanded strip profile canonicalization");
    assert_eq!(
        compact_strip.digest_value_base64, expanded_strip.digest_value_base64,
        "strip_blank_text=true should normalize ignorable blank text differences"
    );

    let compact_keep = canonicalize_reference(compact, "#payload-1", keep_profile.clone())
        .expect("compact keep profile canonicalization");
    let expanded_keep = canonicalize_reference(expanded, "#payload-1", keep_profile)
        .expect("expanded keep profile canonicalization");
    assert_ne!(
        compact_keep.digest_value_base64, expanded_keep.digest_value_base64,
        "strip_blank_text=false should preserve blank-text differences in digest"
    );
}

#[test]
fn rejects_unsupported_transform_algorithm_in_reference_chain() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Header>
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:Reference URI="#payload-1">
                        <ds:Transforms>
                            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/>
                        </ds:Transforms>
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AA==</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
            </ds:Signature>
        </S12:Header>
        <S12:Body>
            <eb:Payload id="payload-1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    let err = parse_signature_references(xml)
        .expect_err("non-Exclusive-C14N transform algorithms must fail closed");
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_unexpected_transform_child_elements_in_reference_chain() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
            xmlns:ext="urn:partner:unexpected-transform-child">
        <S12:Header>
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:Reference URI="#payload-1">
                        <ds:Transforms>
                            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                                <ext:UnexpectedTransformHint value="drift"/>
                            </ds:Transform>
                        </ds:Transforms>
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AA==</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
            </ds:Signature>
        </S12:Header>
        <S12:Body>
            <eb:Payload id="payload-1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    let err = parse_signature_references(xml)
        .expect_err("unexpected transform child elements must fail closed");
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_cid_reference_when_external_payload_bytes_are_missing() {
    let xml = r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <S12:Header>
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:Reference URI="cid:payload@example.com">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AA==</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
            </ds:Signature>
        </S12:Header>
        <S12:Body/>
    </S12:Envelope>"#;

    let references = parse_signature_references(xml).expect("reference extraction should succeed");
    let err = verify_signature_references_strict(xml, &references)
        .expect_err("cid references without external payload bytes must fail closed");
    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
}

#[test]
fn verifies_mixed_same_document_and_detached_references() {
    let detached_payload = b"detached-attachment-body-v1";
    let signed = build_multi_reference_signed_envelope(detached_payload);
    let external_refs = [("cid:payload@example.com", detached_payload.as_slice())];

    verify_enveloped_signature(
        &signed,
        WsSecVerifyOptions::new().with_external_references(&external_refs),
    )
    .expect("mixed same-document and detached references must verify");
}

#[test]
fn rejects_mixed_reference_signature_when_detached_payload_is_tampered() {
    let detached_payload = b"detached-attachment-body-v1";
    let signed = build_multi_reference_signed_envelope(detached_payload);
    let tampered_external_refs = [(
        "cid:payload@example.com",
        b"tampered-detached-body".as_slice(),
    )];

    let err = verify_enveloped_signature(
        &signed,
        WsSecVerifyOptions::new().with_external_references(&tampered_external_refs),
    )
    .expect_err("tampered detached payload must fail mixed-reference signature verification");
    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
}

#[test]
fn tolerates_multiple_signature_elements_during_reference_parsing() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Header>
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:Reference URI="#payload-1">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AA==</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
            </ds:Signature>
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:Reference URI="#payload-2">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>BB==</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
            </ds:Signature>
        </S12:Header>
        <S12:Body>
            <eb:Payload id="payload-1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    let refs = parse_signature_references(xml)
        .expect("multi-sig envelope should parse references from first ds:Signature");
    // Must pick the first signature's references (#payload-1, not the second's).
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].uri, "#payload-1");
}

#[test]
fn tolerates_multiple_signature_elements_during_strict_verification() {
    // With multiple ds:Signature elements and no wsse:Security parent, the
    // resolver falls back to first-in-document-order. The envelope has a
    // fabricated digest so verification still fails, but now with
    // SecurityVerificationFailed rather than InteropViolation.
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Header>
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                    <ds:Reference URI="#payload-1">
                        <ds:Transforms>
                            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                        </ds:Transforms>
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AA==</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
            </ds:Signature>
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                    <ds:Reference URI="#payload-1">
                        <ds:Transforms>
                            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                        </ds:Transforms>
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AA==</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
            </ds:Signature>
        </S12:Header>
        <S12:Body>
            <eb:Payload wsu:Id="payload-1" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    // Should no longer return InteropViolation; the first signature is selected
    // and proceeds to crypto verification (which fails on bad digest/signature value).
    let err = verify_enveloped_signature(xml, WsSecVerifyOptions::new())
        .expect_err("fabricated digest must still fail verification");
    assert_ne!(
        err.code,
        ErrorCode::InteropViolation,
        "multi-sig should not be an InteropViolation; got: {}",
        err.message
    );
}

#[test]
fn rejects_semantically_duplicate_cid_reference_uris_during_parsing() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <S12:Header>
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:Reference URI="cid:payload@example.com">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AA==</ds:DigestValue>
                    </ds:Reference>
                    <ds:Reference URI="CID:&lt;payload@example.com&gt;">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AA==</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
            </ds:Signature>
        </S12:Header>
        <S12:Body/>
    </S12:Envelope>"##;

    let err = parse_signature_references(xml)
        .expect_err("equivalent cid URI aliases must fail closed in strict parsing");
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_semantically_duplicate_cid_reference_uris_during_verification() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <S12:Header>
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:Reference URI="cid:payload@example.com">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AA==</ds:DigestValue>
                    </ds:Reference>
                    <ds:Reference URI="CID:&lt;payload@example.com&gt;">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AA==</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
            </ds:Signature>
        </S12:Header>
        <S12:Body/>
    </S12:Envelope>"##;

    let err = verify_enveloped_signature(xml, WsSecVerifyOptions::new())
        .expect_err("equivalent cid URI aliases must fail closed in strict verification");
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_same_document_reference_when_target_id_is_ambiguous() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
            xmlns:xml="http://www.w3.org/XML/1998/namespace">
        <S12:Header>
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:Reference URI="#payload-1">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AA==</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
            </ds:Signature>
        </S12:Header>
        <S12:Body>
            <eb:Payload wsu:Id="payload-1">ABC</eb:Payload>
            <eb:Payload xml:id="payload-1">DEF</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    let references = parse_signature_references(xml).expect("reference extraction should succeed");
    let err = verify_signature_references_strict(xml, &references)
        .expect_err("ambiguous same-document target IDs must fail closed");
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn canonicalize_reference_rejects_ambiguous_same_document_target_id() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
            xmlns:xml="http://www.w3.org/XML/1998/namespace">
        <S12:Body>
            <eb:Payload wsu:Id="payload-1">ABC</eb:Payload>
            <eb:Payload xml:id="payload-1">DEF</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    let err = canonicalize_reference(xml, "#payload-1", WsSecCanonicalizationProfile::default())
        .expect_err("ambiguous same-document canonicalization target must fail closed");
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_percent_encoded_same_document_reference_uri_during_parsing() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Header>
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:Reference URI="#payload%2D1">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AA==</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
            </ds:Signature>
        </S12:Header>
        <S12:Body>
            <eb:Payload id="payload-1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    let err = parse_signature_references(xml).expect_err(
        "percent-encoded same-document URI fragments must fail closed in strict parsing",
    );
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_percent_encoded_same_document_reference_uri_during_canonicalization() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Body>
            <eb:Payload id="payload-1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    let err = canonicalize_reference(
        xml,
        "#payload%2D1",
        WsSecCanonicalizationProfile::default(),
    )
    .expect_err("percent-encoded same-document URI fragments must fail closed in strict canonicalization");
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_same_document_reference_uri_with_fragment_whitespace_during_parsing() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Header>
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:Reference URI="#payload 1">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AA==</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
            </ds:Signature>
        </S12:Header>
        <S12:Body>
            <eb:Payload id="payload 1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    let err = parse_signature_references(xml).expect_err(
        "whitespace inside same-document URI fragment must fail closed in strict parsing",
    );
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_same_document_reference_uri_with_nested_fragment_marker_during_parsing() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Header>
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:Reference URI="#payload-1#alt">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AA==</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
            </ds:Signature>
        </S12:Header>
        <S12:Body>
            <eb:Payload id="payload-1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    let err = parse_signature_references(xml)
        .expect_err("nested fragment markers must fail closed in strict parsing");
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_same_document_reference_uri_with_fragment_whitespace_during_canonicalization() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Body>
            <eb:Payload id="payload-1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    let err = canonicalize_reference(
        xml,
        "#payload 1",
        WsSecCanonicalizationProfile::default(),
    )
    .expect_err("whitespace inside same-document URI fragment must fail closed in strict canonicalization");
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_same_document_reference_uri_with_non_ascii_fragment_during_parsing() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Header>
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:Reference URI="#päyload-1">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AA==</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
            </ds:Signature>
        </S12:Header>
        <S12:Body>
            <eb:Payload id="payload-1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    let err = parse_signature_references(xml)
        .expect_err("non-ASCII same-document URI fragments must fail closed in strict parsing");
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_same_document_reference_uri_with_non_ascii_fragment_during_canonicalization() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Body>
            <eb:Payload id="payload-1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    let err = canonicalize_reference(xml, "#päyload-1", WsSecCanonicalizationProfile::default())
        .expect_err(
            "non-ASCII same-document URI fragments must fail closed in strict canonicalization",
        );
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_same_document_reference_uri_with_empty_fragment_during_parsing() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Header>
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:Reference URI="#">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AA==</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
            </ds:Signature>
        </S12:Header>
        <S12:Body>
            <eb:Payload id="payload-1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    let err = parse_signature_references(xml)
        .expect_err("empty same-document URI fragments must fail closed in strict parsing");
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_same_document_reference_uri_with_empty_fragment_during_canonicalization() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Body>
            <eb:Payload id="payload-1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    let err = canonicalize_reference(xml, "#", WsSecCanonicalizationProfile::default()).expect_err(
        "empty same-document URI fragments must fail closed in strict canonicalization",
    );
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_same_document_reference_uri_with_invalid_fragment_character_during_parsing() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Header>
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:Reference URI="#payload/1">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AA==</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
            </ds:Signature>
        </S12:Header>
        <S12:Body>
            <eb:Payload id="payload-1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    let err = parse_signature_references(xml).expect_err(
        "invalid same-document URI fragment characters must fail closed in strict parsing",
    );
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_same_document_reference_uri_with_invalid_fragment_start_during_canonicalization() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Body>
            <eb:Payload id="payload-1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    let err = canonicalize_reference(
        xml,
        "#1payload",
        WsSecCanonicalizationProfile::default(),
    )
    .expect_err("invalid same-document URI fragment start characters must fail closed in strict canonicalization");
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_same_document_reference_uri_with_uppercase_fragment_during_parsing() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Header>
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:Reference URI="#Payload-1">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AA==</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
            </ds:Signature>
        </S12:Header>
        <S12:Body>
            <eb:Payload id="payload-1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    let err = parse_signature_references(xml)
        .expect_err("uppercase same-document URI fragments must fail closed in strict parsing");
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_same_document_reference_uri_with_uppercase_fragment_during_canonicalization() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Body>
            <eb:Payload id="payload-1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    let err = canonicalize_reference(xml, "#Payload-1", WsSecCanonicalizationProfile::default())
        .expect_err(
            "uppercase same-document URI fragments must fail closed in strict canonicalization",
        );
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_same_document_reference_uri_with_namespace_like_fragment_during_parsing() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Header>
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:Reference URI="#ns:payload-1">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AA==</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
            </ds:Signature>
        </S12:Header>
        <S12:Body>
            <eb:Payload id="payload-1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    let err = parse_signature_references(xml).expect_err(
        "namespace-like same-document URI fragments must fail closed in strict parsing",
    );
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_same_document_reference_uri_with_namespace_like_fragment_during_canonicalization() {
    let xml = r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Body>
            <eb:Payload id="payload-1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"##;

    let err = canonicalize_reference(
        xml,
        "#ns:payload-1",
        WsSecCanonicalizationProfile::default(),
    )
    .expect_err(
        "namespace-like same-document URI fragments must fail closed in strict canonicalization",
    );
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

// ── W3C Exc-C14N spec conformance edge cases ──────────────────────────────────

/// W3C Exc-C14N §2.4: special XML characters in text content must be
/// escaped with entity references in the canonical form.
/// `&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`.
#[test]
fn special_xml_chars_in_text_content_are_escaped_in_canonical_form() {
    let xml = r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Body>
            <eb:Payload id="payload-1">AT&amp;T &lt;Corp&gt; &amp; Partners</eb:Payload>
        </S12:Body>
    </S12:Envelope>"#;

    let c14n = canonicalize_reference(xml, "#payload-1", WsSecCanonicalizationProfile::default())
        .expect("canonicalization with special chars");
    let text = String::from_utf8_lossy(&c14n.canonical_bytes);
    // The canonical form must contain the entity-escaped form.
    assert!(
        text.contains("AT&amp;T"),
        "& in text content must render as &amp; in canonical form"
    );
    assert!(
        text.contains("&lt;Corp&gt;"),
        "< and > in text content must render as &lt;/&gt; in canonical form"
    );
}

/// W3C Exc-C14N §2.4: double-quote in attribute values must be escaped as `&quot;`.
#[test]
fn double_quote_in_attribute_value_is_escaped_in_canonical_form() {
    // Encode the double-quote as &quot; in the source XML so the parser sees it.
    let xml = r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Body>
            <eb:Payload id="payload-1" role="&quot;quoted&quot;">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"#;

    let c14n = canonicalize_reference(xml, "#payload-1", WsSecCanonicalizationProfile::default())
        .expect("canonicalization with quoted attr");
    let text = String::from_utf8_lossy(&c14n.canonical_bytes);
    assert!(
        text.contains("&quot;quoted&quot;"),
        "double-quote in attribute values must be rendered as &quot; in canonical form"
    );
}

/// W3C Exc-C14N §2.5: ancestor namespace declarations that are *visibly*
/// utilized by the signed sub-tree must be propagated into the canonical form.
///
/// Here `xmlns:ex="urn:example"` is declared on the root `Envelope` but used
/// only inside the signed `Payload` element.  The C14N output of `Payload` must
/// include the `xmlns:ex` declaration.
#[test]
fn ancestor_utilized_namespace_declarations_propagate_into_canonical_form() {
    let xml = r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:ex="urn:example:ns"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Body>
            <eb:Payload id="payload-1">
                <ex:Item>value</ex:Item>
            </eb:Payload>
        </S12:Body>
    </S12:Envelope>"#;

    let c14n = canonicalize_reference(xml, "#payload-1", WsSecCanonicalizationProfile::default())
        .expect("canonicalization with ancestor namespace");
    let text = String::from_utf8_lossy(&c14n.canonical_bytes);
    assert!(
        text.contains("xmlns:ex=\"urn:example:ns\""),
        "ancestor namespace utilized in signed subtree must appear in canonical form"
    );
}

/// W3C Exc-C14N §2.5: namespace declarations for prefixes that are *not*
/// visibly utilized in the signed sub-tree must be excluded from the canonical
/// form (core of Exclusive C14N vs. Inclusive C14N).
#[test]
fn ancestor_unutilized_namespace_declarations_are_excluded_in_exclusive_canonical_form() {
    let xml = r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:unused="urn:not:used:here"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Body>
            <eb:Payload id="payload-1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"#;

    let c14n = canonicalize_reference(xml, "#payload-1", WsSecCanonicalizationProfile::default())
        .expect("canonicalization without unused namespace");
    let text = String::from_utf8_lossy(&c14n.canonical_bytes);
    assert!(
        !text.contains("xmlns:unused="),
        "exclusive C14N must exclude namespace declarations unused by the signed subtree"
    );
}

/// W3C Exc-C14N §2.5: `xmlns=""` (default namespace undeclaration on an ancestor)
/// is not rendered in canonical form when the signed subtree does not use the
/// default namespace.
#[test]
fn default_namespace_undeclaration_is_excluded_when_not_needed() {
    // Root explicitly kills default namespace with xmlns=""; the payload
    // uses a prefixed namespace.  The canonical form of the payload must
    // not include xmlns="" since no default namespace was ever active.
    let xml = r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
            xmlns="">
        <S12:Body>
            <eb:Payload id="payload-1">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"#;

    let c14n = canonicalize_reference(xml, "#payload-1", WsSecCanonicalizationProfile::default())
        .expect("canonicalization with xmlns='' on ancestor");
    let text = String::from_utf8_lossy(&c14n.canonical_bytes);
    // eb:Payload's canonical form should not have xmlns="" injected
    // since no default namespace was in scope from a positive declaration.
    assert!(
        !text.contains("xmlns=\"\""),
        "spurious empty xmlns= must not be injected into canonical form of payload element"
    );
}

/// W3C Exc-C14N §2.3: namespace declarations and standard attributes must be
/// sorted in lexicographic order in the canonical form.
///
/// The canonical order rule: namespace declarations (`xmlns:*`) precede normal
/// attributes; within each group, lexicographic sort by expanded name.
#[test]
fn namespace_declarations_precede_normal_attributes_in_canonical_form() {
    let xml = r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <S12:Body>
            <eb:Payload id="payload-1" wsu:Id="p1"
                        xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
                        beta="b" alpha="a">ABC</eb:Payload>
        </S12:Body>
    </S12:Envelope>"#;

    let c14n = canonicalize_reference(xml, "#payload-1", WsSecCanonicalizationProfile::default())
        .expect("canonicalization with mixed attrs");
    let text = String::from_utf8_lossy(&c14n.canonical_bytes);
    // Namespace declarations must come before regular attributes.
    // Within namespace declarations, they must be sorted lexicographically by prefix.
    let xmlns_eb_pos = text.find("xmlns:eb=").unwrap_or(usize::MAX);
    let xmlns_wsu_pos = text.find("xmlns:wsu=").unwrap_or(usize::MAX);
    let alpha_pos = text.find(" alpha=").unwrap_or(usize::MAX);
    let beta_pos = text.find(" beta=").unwrap_or(usize::MAX);
    let id_pos = text.find(" id=").unwrap_or(usize::MAX);

    // xmlns:S12 is visibly unused inside eb:Payload, so Exc-C14N must exclude it.
    assert!(
        !text.contains("xmlns:S12="),
        "xmlns:S12 is visibly unused in signed subtree — Exc-C14N must exclude it"
    );
    // xmlns:eb and xmlns:wsu must be present (used by the element and wsu:Id attr).
    assert!(
        xmlns_eb_pos != usize::MAX,
        "xmlns:eb must appear in canonical form"
    );
    assert!(
        xmlns_wsu_pos != usize::MAX,
        "xmlns:wsu must appear in canonical form"
    );

    // All xmlns: declarations must appear before any regular attributes
    // (Exc-C14N §2.3: namespace nodes precede attribute nodes).
    assert!(
        xmlns_eb_pos < alpha_pos && xmlns_wsu_pos < alpha_pos,
        "namespace declarations must precede regular attributes in canonical form"
    );
    // Regular attributes must be sorted: alpha < beta < id
    // (Unicode code-point lexicographic order, §2.3).
    assert!(
        alpha_pos < beta_pos && beta_pos < id_pos,
        "regular attributes must be in Unicode code-point (lexicographic) order"
    );
    // Namespace declarations themselves must be sorted lexicographically:
    // 'e' (0x65) < 'w' (0x77) → xmlns:eb < xmlns:wsu.
    assert!(
        xmlns_eb_pos < xmlns_wsu_pos,
        "namespace declarations must be in lexicographic order: xmlns:eb < xmlns:wsu"
    );
}

// ── Inclusive C14N (W3C Canonical XML 1.0) tests ─────────────────────────────

#[test]
fn inclusive_c14n_renders_all_in_scope_namespace_declarations() {
    use asx::crypto::wssec::WsSecCanonicalizationKind;

    // An element that uses only `eb:` but has `wsu:` in scope from an ancestor.
    // In Exclusive C14N, only `eb:` would be rendered.
    // In Inclusive C14N, both `eb:` and `wsu:` MUST be rendered.
    let xml = r#"<root xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
    <eb:Messaging wsu:Id="m1"/>
</root>"#;

    let exc_profile = WsSecCanonicalizationProfile::default();
    let inc_profile = WsSecCanonicalizationProfile {
        kind: WsSecCanonicalizationKind::Inclusive,
        ..WsSecCanonicalizationProfile::default()
    };

    // For Exclusive C14N on a child element that only uses `eb:`, `wsu:` must NOT
    // appear unless it's also visibly utilized.
    // We canonicalize the root element itself — both profiles should include both
    // namespaces here since both are visibly used at the root (wsu:Id attribute).
    // The key difference would show at a child that only uses one namespace.

    let result_exc = canonicalize_reference(xml, "#m1", exc_profile).unwrap();
    let result_inc = canonicalize_reference(xml, "#m1", inc_profile).unwrap();

    // For the `eb:Messaging` element with `wsu:Id` attribute, both namespaces
    // ARE visibly utilized, so both C14N modes must include both declarations.
    let exc_str = std::str::from_utf8(&result_exc.canonical_bytes).unwrap();
    let inc_str = std::str::from_utf8(&result_inc.canonical_bytes).unwrap();
    assert!(
        exc_str.contains("xmlns:eb="),
        "Exc-C14N must include eb namespace"
    );
    assert!(
        exc_str.contains("xmlns:wsu="),
        "Exc-C14N must include wsu namespace (utilized via wsu:Id)"
    );
    assert!(
        inc_str.contains("xmlns:eb="),
        "Inc-C14N must include eb namespace"
    );
    assert!(
        inc_str.contains("xmlns:wsu="),
        "Inc-C14N must include wsu namespace"
    );
}

#[test]
fn inclusive_c14n_includes_non_utilized_ancestor_namespaces() {
    use asx::crypto::wssec::WsSecCanonicalizationKind;

    // An element that only uses `eb:` but has `wsu:` declared on it from the
    // parent. In Inclusive C14N, wsu: MUST be rendered even if not used.

    let inc_profile = WsSecCanonicalizationProfile {
        kind: WsSecCanonicalizationKind::Inclusive,
        strip_blank_text: false,
        ..WsSecCanonicalizationProfile::default()
    };

    // Canonicalize <eb:child/> — it only utilizes `eb:` but `wsu:` is in scope.
    // Inclusive C14N MUST include wsu: in the canonical form.
    let xml_with_id = r#"<root>
    <inner xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
           xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
        <eb:child wsu:Id="childid"/>
    </inner>
</root>"#;

    let result_inc = canonicalize_reference(xml_with_id, "#childid", inc_profile).unwrap();
    let inc_str = std::str::from_utf8(&result_inc.canonical_bytes).unwrap();

    // In Inclusive C14N, all in-scope namespaces (both eb: and wsu:) must appear.
    assert!(
        inc_str.contains("xmlns:eb="),
        "Inclusive C14N must render utilized eb: namespace; got: {inc_str}"
    );
    assert!(
        inc_str.contains("xmlns:wsu="),
        "Inclusive C14N must render in-scope but non-utilized wsu: namespace; got: {inc_str}"
    );
}

#[test]
fn inclusive_c14n_versus_exclusive_differ_on_non_utilized_namespaces() {
    use asx::crypto::wssec::WsSecCanonicalizationKind;

    // Build a document where an element has extra namespaces in scope but
    // only utilizes one of them. Exclusive and Inclusive C14N must produce
    // different output (different canonical bytes / different digests).
    let xml = r#"<root xmlns:extra="urn:extra:unused">
    <child xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
           wsu:Id="target"
           xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
        <eb:Messaging/>
    </child>
</root>"#;

    let exc_profile = WsSecCanonicalizationProfile::default();
    let inc_profile = WsSecCanonicalizationProfile {
        kind: WsSecCanonicalizationKind::Inclusive,
        strip_blank_text: false,
        ..WsSecCanonicalizationProfile::default()
    };

    let exc_result = canonicalize_reference(xml, "#target", exc_profile).unwrap();
    let inc_result = canonicalize_reference(xml, "#target", inc_profile).unwrap();

    let exc_str = std::str::from_utf8(&exc_result.canonical_bytes).unwrap();
    let inc_str = std::str::from_utf8(&inc_result.canonical_bytes).unwrap();

    // The `extra:` namespace is in scope from the root but not utilized at
    // <child>. Exclusive C14N must NOT include it; Inclusive C14N MUST.
    assert!(
        !exc_str.contains("xmlns:extra="),
        "Exclusive C14N must NOT include non-utilized ancestor namespace; got: {exc_str}"
    );
    assert!(
        inc_str.contains("xmlns:extra="),
        "Inclusive C14N MUST include all in-scope namespace declarations; got: {inc_str}"
    );

    // The two digests must differ because the canonical forms differ.
    assert_ne!(
        exc_result.digest_value_base64, inc_result.digest_value_base64,
        "Exclusive and Inclusive C14N of the same subtree with non-utilized in-scope \
         namespaces must produce different digests"
    );
}

#[test]
fn parse_signature_references_accepts_inclusive_c14n_transform_uri() {
    use asx::crypto::wssec::WsSecCanonicalizationKind;

    // A minimal ds:Signature with an Inclusive C14N Transform URI.
    let xml = r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                       xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#body-1">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>dummysig==</ds:SignatureValue>
  </ds:Signature>
</root>"##;

    let refs = parse_signature_references(xml).expect("Inclusive C14N URI must be accepted");
    assert_eq!(refs.len(), 1);
    assert_eq!(
        refs[0].c14n_kind,
        WsSecCanonicalizationKind::Inclusive,
        "reference with Inclusive C14N transform URI must have c14n_kind=Inclusive"
    );
}

#[test]
fn parse_signature_references_defaults_to_exclusive_c14n_kind() {
    use asx::crypto::wssec::WsSecCanonicalizationKind;

    // A ds:Signature using the standard Exclusive C14N Transform URI.
    let xml = r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#body-1">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>dummysig==</ds:SignatureValue>
  </ds:Signature>
</root>"##;

    let refs = parse_signature_references(xml).expect("Exclusive C14N should succeed");
    assert_eq!(refs[0].c14n_kind, WsSecCanonicalizationKind::Exclusive);
}

#[test]
fn inclusive_c14n_profile_helper_sets_correct_defaults() {
    use asx::crypto::wssec::WsSecCanonicalizationKind;

    let profile = WsSecCanonicalizationProfile::inclusive();
    assert_eq!(profile.kind, WsSecCanonicalizationKind::Inclusive);
    assert!(
        !profile.strip_blank_text,
        "Inclusive C14N must preserve whitespace"
    );
    assert!(!profile.include_comments);
}

#[test]
fn wssec_canonicalization_profile_algorithm_uri_is_correct() {
    use asx::crypto::wssec::WsSecCanonicalizationKind;

    let exc = WsSecCanonicalizationProfile::default();
    assert_eq!(
        exc.algorithm_uri(),
        "http://www.w3.org/2001/10/xml-exc-c14n#"
    );

    let inc = WsSecCanonicalizationProfile {
        kind: WsSecCanonicalizationKind::Inclusive,
        ..Default::default()
    };
    assert_eq!(
        inc.algorithm_uri(),
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    );
}
