//! Tests for WS-Security signature verification.
//!
//! Kept out of `verify.rs` so the implementation reads as one piece.

use super::{
    WsSecCanonicalizationProfile, WsSecDigestMethod, WsSecVerifyOptions,
    build_external_reference_cid_index, parse_signature_material_from_doc,
    parse_signature_references, verify_enveloped_signature,
};
use crate::crypto::wssec::canonicalize::canonicalize_reference_digest_base64_from_doc_with_inclusive_ns;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::x509::X509;
use roxmltree::Document;
use sha2::Digest as _;

fn encode_der_sequence(elements: &[Vec<u8>]) -> Vec<u8> {
    let payload_len = elements.iter().map(Vec::len).sum::<usize>();
    let mut out = Vec::with_capacity(payload_len + 8);
    out.push(0x30);
    if payload_len < 0x80 {
        out.push(payload_len as u8);
    } else {
        let mut len_bytes = Vec::new();
        let mut value = payload_len;
        while value > 0 {
            len_bytes.push((value & 0xFF) as u8);
            value >>= 8;
        }
        len_bytes.reverse();
        out.push(0x80 | (len_bytes.len() as u8));
        out.extend_from_slice(&len_bytes);
    }
    for element in elements {
        out.extend_from_slice(element);
    }
    out
}

fn signed_xml_with_pkipath_token(
    reference_uri: &str,
    payload_xml: &str,
    digest_value_base64: &str,
    signature_value_base64: &str,
    token_id: &str,
    pki_path_der_base64: &str,
) -> String {
    format!(
        r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
    xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
    xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<S12:Header>
    <wsse:Security>
        <ds:Signature>
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="{reference_uri}">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>{digest_value_base64}</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>{signature_value_base64}</ds:SignatureValue>
            <ds:KeyInfo>
                <wsse:SecurityTokenReference>
                    <wsse:Reference URI="#{token_id}" ValueType="http://docs.oasis-open.org/wss/oasis-wss-x509-token-profile-1.1#X509PKIPathv1"/>
                </wsse:SecurityTokenReference>
            </ds:KeyInfo>
        </ds:Signature>
        <wsse:BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#Base64Binary" ValueType="http://docs.oasis-open.org/wss/oasis-wss-x509-token-profile-1.1#X509PKIPathv1" wsu:Id="{token_id}">{pki_path_der_base64}</wsse:BinarySecurityToken>
    </wsse:Security>
</S12:Header>
<S12:Body>
{payload_xml}
</S12:Body>
</S12:Envelope>"##
    )
}

#[cfg(feature = "as4")]
#[test]
fn verify_enveloped_signature_rejects_malformed_xml() {
    let err = verify_enveloped_signature("<not-xml", WsSecVerifyOptions::new())
        .expect_err("malformed XML must be rejected");

    assert_eq!(err.code, crate::core::ErrorCode::ParseFailed);
    assert!(
        err.message
            .contains("failed to parse XML for wssec verification")
    );
}

/// Generate a fresh self-signed RSA-2048 certificate for signature tests.
/// Returns the private key and the certificate DER.
fn generate_test_signing_identity(common_name: &str) -> (PKey<openssl::pkey::Private>, Vec<u8>) {
    let rsa = openssl::rsa::Rsa::generate(2048).expect("rsa");
    let pkey = PKey::from_rsa(rsa).expect("pkey");

    let mut name = openssl::x509::X509NameBuilder::new().expect("name builder");
    name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, common_name)
        .expect("cn");
    let name = name.build();

    let mut serial = openssl::bn::BigNum::new().expect("serial");
    serial
        .pseudo_rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .expect("serial rand");
    let serial = serial.to_asn1_integer().expect("serial asn1");

    let mut cert_builder = X509::builder().expect("x509 builder");
    cert_builder.set_version(2).expect("version");
    cert_builder.set_serial_number(&serial).expect("serial");
    cert_builder.set_subject_name(&name).expect("subject");
    cert_builder.set_issuer_name(&name).expect("issuer");
    cert_builder.set_pubkey(&pkey).expect("pubkey");
    let not_before = Asn1Time::days_from_now(0).expect("not_before");
    let not_after = Asn1Time::days_from_now(365).expect("not_after");
    cert_builder.set_not_before(&not_before).expect("nb");
    cert_builder.set_not_after(&not_after).expect("na");
    cert_builder
        .sign(&pkey, MessageDigest::sha256())
        .expect("cert sign");
    let cert_der = cert_builder.build().to_der().expect("cert der");
    (pkey, cert_der)
}

#[test]
fn verify_enveloped_signature_accepts_x509pkipathv1_binary_security_token() {
    let (pkey, cert_der) = generate_test_signing_identity("asx-wssec-pkipath-test");

    let pki_path_der = encode_der_sequence(&[cert_der]);
    let pki_path_der_b64 = BASE64_STANDARD.encode(pki_path_der);

    let token_id = "bst-pkipath-1";
    let reference_uri = "#payload-1";
    let payload_xml = "    <eb:Payload wsu:Id=\"payload-1\">ABC</eb:Payload>";

    let unsigned = signed_xml_with_pkipath_token(
        reference_uri,
        payload_xml,
        "placeholder",
        "AA==",
        token_id,
        &pki_path_der_b64,
    );
    let unsigned_doc = Document::parse(&unsigned).expect("unsigned doc");
    let digest = canonicalize_reference_digest_base64_from_doc_with_inclusive_ns(
        &unsigned_doc,
        reference_uri,
        &WsSecCanonicalizationProfile::default(),
        None,
        WsSecDigestMethod::Sha256,
    )
    .expect("digest");

    let unsigned_with_digest = signed_xml_with_pkipath_token(
        reference_uri,
        payload_xml,
        &digest,
        "AA==",
        token_id,
        &pki_path_der_b64,
    );
    let material_doc = Document::parse(&unsigned_with_digest).expect("material doc");
    let material =
        parse_signature_material_from_doc(&material_doc, WsSecCanonicalizationProfile::default())
            .expect("signature material");

    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).expect("signer");
    signer
        .update(&material.signed_info_c14n)
        .expect("signer update");
    let signature_base64 = BASE64_STANDARD.encode(signer.sign_to_vec().expect("signature"));

    let signed = signed_xml_with_pkipath_token(
        reference_uri,
        payload_xml,
        &digest,
        &signature_base64,
        token_id,
        &pki_path_der_b64,
    );

    verify_enveloped_signature(&signed, WsSecVerifyOptions::new())
        .expect("verification should pass with X509PKIPathv1 token");
}

/// The default WSS4J/phase4/Domibus KeyInfo shape: a `wsse:BinarySecurityToken`
/// with `ValueType="...#X509v3"` (a single DER certificate), referenced from
/// `ds:KeyInfo` via `wsse:SecurityTokenReference/wsse:Reference`. This is the
/// stock Java-stack shape; demanding `X509PKIPathv1` instead makes
/// those signatures unverifiable.
#[test]
fn verify_enveloped_signature_accepts_x509v3_binary_security_token() {
    let (pkey, cert_der) = generate_test_signing_identity("asx-wssec-x509v3-test");
    let cert_der_b64 = BASE64_STANDARD.encode(&cert_der);

    let token_id = "X509-token-1";
    let reference_uri = "#payload-1";
    let payload_xml = "    <eb:Payload wsu:Id=\"payload-1\">ABC</eb:Payload>";

    let build = |digest: &str, signature: &str| -> String {
        format!(
            r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
    xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
    xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<S12:Header>
    <wsse:Security>
        <wsse:BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#Base64Binary" ValueType="http://docs.oasis-open.org/wss/oasis-wss-x509-token-profile-1.0#X509v3" wsu:Id="{token_id}">{cert_der_b64}</wsse:BinarySecurityToken>
        <ds:Signature>
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="{reference_uri}">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>{digest}</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>{signature}</ds:SignatureValue>
            <ds:KeyInfo>
                <wsse:SecurityTokenReference>
                    <wsse:Reference URI="#{token_id}" ValueType="http://docs.oasis-open.org/wss/oasis-wss-x509-token-profile-1.0#X509v3"/>
                </wsse:SecurityTokenReference>
            </ds:KeyInfo>
        </ds:Signature>
    </wsse:Security>
</S12:Header>
<S12:Body>
{payload_xml}
</S12:Body>
</S12:Envelope>"##
        )
    };

    let unsigned = build("placeholder", "AA==");
    let unsigned_doc = Document::parse(&unsigned).expect("unsigned doc");
    let digest = canonicalize_reference_digest_base64_from_doc_with_inclusive_ns(
        &unsigned_doc,
        reference_uri,
        &WsSecCanonicalizationProfile::default(),
        None,
        WsSecDigestMethod::Sha256,
    )
    .expect("digest");

    let with_digest = build(&digest, "AA==");
    let material_doc = Document::parse(&with_digest).expect("material doc");
    let material =
        parse_signature_material_from_doc(&material_doc, WsSecCanonicalizationProfile::default())
            .expect("signature material");

    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).expect("signer");
    signer
        .update(&material.signed_info_c14n)
        .expect("signer update");
    let signature_base64 = BASE64_STANDARD.encode(signer.sign_to_vec().expect("signature"));

    let signed = build(&digest, &signature_base64);
    verify_enveloped_signature(&signed, WsSecVerifyOptions::new())
        .expect("verification should pass with the standard X509v3 token shape");
}

/// WSS4J-based signers declare their SOAP envelope prefix in an
/// `InclusiveNamespaces PrefixList` on the SignedInfo `CanonicalizationMethod`.
/// Exc-C14N §2.1 requires the listed prefixes to be rendered on the canonical
/// SignedInfo, so ignoring the list changes the signed bytes and fails every
/// such signature with a bare value mismatch.
#[test]
fn verify_enveloped_signature_honors_signed_info_inclusive_namespaces_prefix_list() {
    let (pkey, cert_der) = generate_test_signing_identity("asx-wssec-prefixlist-test");
    let cert_der_b64 = BASE64_STANDARD.encode(&cert_der);

    let reference_uri = "#payload-1";

    let build = |digest: &str, signature: &str| -> String {
        format!(
            r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
    xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
    xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<S12:Header>
    <wsse:Security>
        <ds:Signature>
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                    <ec:InclusiveNamespaces PrefixList="S12" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ds:CanonicalizationMethod>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="{reference_uri}">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>{digest}</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>{signature}</ds:SignatureValue>
            <ds:KeyInfo>
                <ds:X509Data><ds:X509Certificate>{cert_der_b64}</ds:X509Certificate></ds:X509Data>
            </ds:KeyInfo>
        </ds:Signature>
    </wsse:Security>
</S12:Header>
<S12:Body>
    <eb:Payload wsu:Id="payload-1">ABC</eb:Payload>
</S12:Body>
</S12:Envelope>"##
        )
    };

    let unsigned = build("placeholder", "AA==");
    let unsigned_doc = Document::parse(&unsigned).expect("unsigned doc");
    let digest = canonicalize_reference_digest_base64_from_doc_with_inclusive_ns(
        &unsigned_doc,
        reference_uri,
        &WsSecCanonicalizationProfile::default(),
        None,
        WsSecDigestMethod::Sha256,
    )
    .expect("digest");

    let with_digest = build(&digest, "AA==");
    let material_doc = Document::parse(&with_digest).expect("material doc");
    let material =
        parse_signature_material_from_doc(&material_doc, WsSecCanonicalizationProfile::default())
            .expect("signature material");

    // The prefix list must have changed the canonical bytes: the envelope
    // prefix is not visibly utilized inside SignedInfo, so it can only appear
    // because the PrefixList forced it (Exc-C14N §2.1).
    let canonical = String::from_utf8(material.signed_info_c14n.clone()).expect("utf8");
    assert!(
        canonical.contains(r#"xmlns:S12="http://www.w3.org/2003/05/soap-envelope""#),
        "PrefixList must force the S12 declaration onto canonical SignedInfo: {canonical}"
    );

    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).expect("signer");
    signer
        .update(&material.signed_info_c14n)
        .expect("signer update");
    let signature_base64 = BASE64_STANDARD.encode(signer.sign_to_vec().expect("signature"));

    let signed = build(&digest, &signature_base64);
    verify_enveloped_signature(&signed, WsSecVerifyOptions::new())
        .expect("signature over PrefixList-canonicalized SignedInfo must verify");
}

/// The AS4 profile signs payload attachments with the WSS SwA
/// `Attachment-Content-Signature-Transform` on the `cid:` reference. The digest
/// input for binary content equals the raw attachment octets, so declaring the
/// transform must not change the verification outcome — rejecting it would
/// fail every phase4/Domibus attachment signature.
#[test]
fn verify_enveloped_signature_accepts_swa_attachment_content_transform() {
    let (pkey, cert_der) = generate_test_signing_identity("asx-wssec-swa-test");
    let cert_der_b64 = BASE64_STANDARD.encode(&cert_der);

    let attachment: &[u8] = b"attached-business-document-v1";
    let attachment_digest = BASE64_STANDARD.encode(sha2::Sha256::digest(attachment));
    let external_refs = [("cid:payload@example.com", attachment)];

    let build = |signature: &str| -> String {
        format!(
            r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<S12:Header>
    <wsse:Security>
        <ds:Signature>
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="cid:payload@example.com">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>{attachment_digest}</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>{signature}</ds:SignatureValue>
            <ds:KeyInfo>
                <ds:X509Data><ds:X509Certificate>{cert_der_b64}</ds:X509Certificate></ds:X509Data>
            </ds:KeyInfo>
        </ds:Signature>
    </wsse:Security>
</S12:Header>
<S12:Body/>
</S12:Envelope>"##
        )
    };

    let unsigned = build("AA==");
    let material_doc = Document::parse(&unsigned).expect("material doc");
    let material =
        parse_signature_material_from_doc(&material_doc, WsSecCanonicalizationProfile::default())
            .expect("signature material");

    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).expect("signer");
    signer
        .update(&material.signed_info_c14n)
        .expect("signer update");
    let signature_base64 = BASE64_STANDARD.encode(signer.sign_to_vec().expect("signature"));

    let signed = build(&signature_base64);
    verify_enveloped_signature(
        &signed,
        WsSecVerifyOptions::new().with_external_references(&external_refs),
    )
    .expect("cid reference declaring the SwA content transform must verify");

    // The Complete variant folds MIME headers into the digest and is not
    // implemented; it must be rejected by name, not silently treated as
    // content-only.
    let complete = signed.replace(
        "Attachment-Content-Signature-Transform",
        "Attachment-Complete-Signature-Transform",
    );
    let err = verify_enveloped_signature(
        &complete,
        WsSecVerifyOptions::new().with_external_references(&external_refs),
    )
    .expect_err("Attachment-Complete-Signature-Transform is unsupported");
    assert_eq!(err.code, crate::core::ErrorCode::InteropViolation);
    assert!(err.message.contains("Complete"), "{}", err.message);
}

/// An envelope signed over `references` (`(URI, DigestValue)`), the cid one
/// with the SwA content transform; `body_id` puts a `wsu:Id` on the Body.
fn signed_with_references(references: &[(&str, String)]) -> String {
    let (pkey, cert_der) = generate_test_signing_identity("asx-wssec-split-test");
    let cert_der_b64 = BASE64_STANDARD.encode(&cert_der);
    let refs: String = references
        .iter()
        .map(|(uri, digest)| {
            let transform = if uri.starts_with("cid:") {
                "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform"
            } else {
                "http://www.w3.org/2001/10/xml-exc-c14n#"
            };
            format!(
                r#"<ds:Reference URI="{uri}"><ds:Transforms><ds:Transform Algorithm="{transform}"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference>"#
            )
        })
        .collect();
    let build = |signature: &str| -> String {
        format!(
            r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><S12:Header><wsse:Security><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>{refs}</ds:SignedInfo><ds:SignatureValue>{signature}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_der_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></wsse:Security></S12:Header><S12:Body wsu:Id="body"/></S12:Envelope>"##
        )
    };
    let unsigned = build("AA==");
    let material_doc = Document::parse(&unsigned).expect("material doc");
    let material =
        parse_signature_material_from_doc(&material_doc, WsSecCanonicalizationProfile::default())
            .expect("signature material");
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).expect("signer");
    signer.update(&material.signed_info_c14n).expect("update");
    build(&BASE64_STANDARD.encode(signer.sign_to_vec().expect("signature")))
}

/// Same-document references are digested before any `cid:`
/// reference, whatever their order in `SignedInfo` — a forged header stops
/// before attachment-sized work.
#[test]
fn same_document_failure_stops_before_any_cid_digest() {
    let attachment = b"attachment";
    let good = BASE64_STANDARD.encode(sha2::Sha256::digest(attachment));
    let wrong = BASE64_STANDARD.encode([0u8; 32]);
    let xml = signed_with_references(&[("cid:part@asx", good), ("#body", wrong)]);
    let refs = [("cid:part@asx", attachment.as_slice())];
    super::order_probe::reset();
    let err = verify_enveloped_signature(
        &xml,
        WsSecVerifyOptions::new().with_external_references(&refs),
    )
    .expect_err("the Body digest is wrong");
    assert!(err.message.contains("#body"), "{}", err.message);
    assert_eq!(super::order_probe::cid_digests(), 0, "no cid: digest");
}

/// Deferring leaves the `cid:` references to
/// `verify_cid_references`, which digests the bytes it is given.
#[test]
fn deferred_cid_references_are_verified_over_the_supplied_bytes() {
    let attachment = b"pre-encryption bytes";
    let good = BASE64_STANDARD.encode(sha2::Sha256::digest(attachment));
    let xml = signed_with_references(&[("cid:part@asx", good)]);
    let doc = crate::xml::parse(&xml, crate::xml::XmlLimits::ENVELOPE, "test").unwrap();
    super::order_probe::reset();
    let coverage = super::verify_enveloped_signature_optional_with_doc(
        &doc,
        &xml,
        super::SignedDocClass::UserMessage,
        WsSecVerifyOptions::new().deferring_attachments(),
    )
    .expect("verifies without the attachment")
    .expect("signed");
    assert_eq!(super::order_probe::cid_digests(), 0);
    let deferred = coverage.deferred.expect("deferred");
    assert_eq!(deferred.cid_references.len(), 1);
    super::verify_cid_references(&deferred.cid_references, &[("part@asx", attachment)])
        .expect("the right bytes");
    let err = super::verify_cid_references(&deferred.cid_references, &[("part@asx", b"other")])
        .expect_err("other bytes");
    assert_eq!(err.code, crate::core::ErrorCode::SecurityVerificationFailed);
    super::verify_cid_references(&deferred.cid_references, &[])
        .expect_err("a reference without its part fails");
}

#[test]
fn split_x509_pkipath_rejects_inner_length_overrun_without_panicking() {
    // Outer SEQUENCE (len 4) whose single inner element declares a 65535-byte
    // content length with zero bytes present. Without the bounds check this
    // would slice out of range and panic the worker thread on attacker input.
    let malicious = [0x30u8, 0x04, 0x30, 0x82, 0xFF, 0xFF];
    let err = super::split_x509_pkipath_der_certificates(&malicious)
        .expect_err("over-declared inner DER length must be rejected, not panic");
    assert_eq!(err.code, crate::core::ErrorCode::ParseFailed);
}

/// `cid:` reference matching is normalization-insensitive.
///
/// Exercised through `build_external_reference_cid_index` — the function the
/// verification path actually calls, so the normalization asserted here is the
/// normalization that runs.
#[test]
fn external_reference_cid_index_normalizes_cid_wrappers() {
    let alpha = b"alpha";
    let beta = b"beta";
    let refs: [(&str, &[u8]); 2] = [
        ("<payload@example.com>", alpha.as_slice()),
        ("cid:other@example.com", beta.as_slice()),
    ];
    let index = super::build_external_reference_cid_index(&refs).expect("index");

    for uri in ["cid:payload@example.com", "CID:<payload@example.com>"] {
        assert_eq!(
            index.get(super::normalize_cid_uri(uri)).copied(),
            Some(alpha.as_slice()),
            "{uri} must resolve to the angle-bracket-wrapped candidate"
        );
    }
    assert_eq!(
        index
            .get(super::normalize_cid_uri("<other@example.com>"))
            .copied(),
        Some(beta.as_slice()),
        "an angle-bracket URI must match a cid-prefixed candidate"
    );
}

#[test]
fn parse_signature_references_rejects_unsupported_transform_algorithm() {
    let xml = r##"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"> 
<soap:Header>
    <ds:Signature>
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <ds:Reference URI="#body">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>ZmFrZQ==</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>ZmFrZQ==</ds:SignatureValue>
    </ds:Signature>
</soap:Header>
<soap:Body Id="body"/>
</soap:Envelope>"##;

    let err = parse_signature_references(xml)
        .expect_err("unsupported transform algorithm must fail closed");

    assert_eq!(err.code, crate::core::ErrorCode::InteropViolation);
    assert!(err.message.contains("unsupported ds:Transform Algorithm"));
}

#[test]
fn parse_signature_references_rejects_unsupported_transform_child_element() {
    let xml = r##"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"> 
<soap:Header>
    <ds:Signature>
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <ds:Reference URI="#body">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                        <ds:Bogus/>
                    </ds:Transform>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>ZmFrZQ==</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>ZmFrZQ==</ds:SignatureValue>
    </ds:Signature>
</soap:Header>
<soap:Body Id="body"/>
</soap:Envelope>"##;

    let err =
        parse_signature_references(xml).expect_err("unsupported transform child must fail closed");

    assert_eq!(err.code, crate::core::ErrorCode::InteropViolation);
    assert!(err.message.contains("unsupported child element"));
}

#[test]
fn parse_signature_references_rejects_percent_encoded_cid_uri() {
    let xml = r##"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<soap:Header>
    <ds:Signature>
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <ds:Reference URI="cid:payload%40example.com">
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>ZmFrZQ==</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>ZmFrZQ==</ds:SignatureValue>
    </ds:Signature>
</soap:Header>
<soap:Body Id="body"/>
</soap:Envelope>"##;

    let err =
        parse_signature_references(xml).expect_err("percent-encoded cid URI must fail closed");

    assert_eq!(err.code, crate::core::ErrorCode::InteropViolation);
    assert!(err.message.contains("percent-encoded cid reference URIs"));
}

#[test]
fn parse_signature_references_rejects_unsupported_reference_uri_scheme() {
    let xml = r##"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<soap:Header>
    <ds:Signature>
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <ds:Reference URI="https://example.invalid/object.xml">
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>ZmFrZQ==</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>ZmFrZQ==</ds:SignatureValue>
    </ds:Signature>
</soap:Header>
<soap:Body Id="body"/>
</soap:Envelope>"##;

    let err = parse_signature_references(xml).expect_err("unsupported URI scheme must fail closed");

    assert_eq!(err.code, crate::core::ErrorCode::InteropViolation);
    assert!(err.message.contains("unsupported ds:Reference URI scheme"));
}

#[test]
fn build_external_reference_cid_index_rejects_semantically_equivalent_cid_aliases() {
    let alpha = b"alpha";
    let beta = b"beta";
    let refs = [
        ("cid:payload@example.com", alpha.as_slice()),
        ("CID:<payload@example.com>", beta.as_slice()),
    ];

    let err = build_external_reference_cid_index(&refs)
        .expect_err("semantically equivalent cid aliases must fail closed");

    assert_eq!(err.code, crate::core::ErrorCode::InteropViolation);
    assert!(
        err.message
            .contains("duplicate or semantically equivalent external cid reference provided")
    );
}

/// A second `ds:Signature` in the document (e.g. a gateway counter-signature)
/// must not prevent verification of the primary WS-Security signature.
#[test]
fn verify_tolerates_extra_ds_signature_outside_wssec_security_header() {
    use super::super::WsSecOutboundKeyInfoProfile;
    use super::super::sign::generate_xmlsig_signature;
    use openssl::asn1::Asn1Time;

    // Build a self-signed cert/key pair for this test.
    let rsa = openssl::rsa::Rsa::generate(2048).expect("rsa");
    let pkey = PKey::from_rsa(rsa).expect("pkey");
    let mut name = openssl::x509::X509NameBuilder::new().expect("name");
    name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "asx-multisig-test")
        .expect("cn");
    let name = name.build();
    let mut serial = openssl::bn::BigNum::new().expect("bn");
    serial
        .pseudo_rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .expect("rand");
    let serial = serial.to_asn1_integer().expect("asn1 serial");
    let mut builder = X509::builder().expect("x509 builder");
    builder.set_version(2).expect("v2");
    builder.set_serial_number(&serial).expect("serial");
    builder.set_subject_name(&name).expect("subject");
    builder.set_issuer_name(&name).expect("issuer");
    builder.set_pubkey(&pkey).expect("pubkey");
    builder
        .set_not_before(&Asn1Time::days_from_now(0).expect("nb"))
        .expect("nb");
    builder
        .set_not_after(&Asn1Time::days_from_now(365).expect("na"))
        .expect("na");
    builder
        .sign(&pkey, MessageDigest::sha256())
        .expect("sign cert");
    let cert = builder.build();
    let cert_pem = cert.to_pem().expect("cert pem");
    let key_pem = pkey.private_key_to_pem_pkcs8().expect("key pem");

    let body_id = "body-multisig";
    // Build an unsigned SOAP envelope with a wsse:Security placeholder.
    let envelope = format!(
        r##"<?xml version="1.0" encoding="UTF-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><soap:Header><wsse:Security soap:mustUnderstand="1"></wsse:Security></soap:Header><soap:Body wsu:Id="{body_id}"><data>hello</data></soap:Body></soap:Envelope>"##
    );

    // Generate <ds:Signature> referencing the body.
    let sig_xml = generate_xmlsig_signature(
        &envelope,
        &[&format!("#{body_id}")],
        &key_pem,
        &cert_pem,
        WsSecOutboundKeyInfoProfile::X509DataAndRsaKeyValue,
    )
    .expect("sign");

    // Insert signature inside the wsse:Security block.
    let signed_envelope = envelope.replace(
        "<wsse:Security soap:mustUnderstand=\"1\"></wsse:Security>",
        &format!("<wsse:Security soap:mustUnderstand=\"1\">{sig_xml}</wsse:Security>"),
    );
    assert!(
        signed_envelope.contains("<ds:Signature"),
        "signature must be present in assembled envelope"
    );

    // Inject a second irrelevant ds:Signature in the SOAP header (outside
    // wsse:Security) to simulate a gateway or application-layer counter-signer.
    // It must NOT be inside the signed body element or the digest will change.
    let extra_sig = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>"#;
    let dual_signed =
        signed_envelope.replace("</soap:Header>", &format!("{extra_sig}</soap:Header>"));

    // Verification must succeed: resolver prefers the wsse:Security-hosted ds:Signature.
    verify_enveloped_signature(&dual_signed, WsSecVerifyOptions::new())
        .expect("dual-signed SOAP must verify against primary wsse:Security signature");
}

/// `SignedInfo` is canonicalized with the algorithm the signer **declared**.
///
/// Both W3C algorithms are legitimate and the networks disagree: AS4
/// WS-Security profiles require exclusive C14N, Peppol SMP requires inclusive
/// (SMP 1.4.0 §5.5.1, which changed it *from* exclusive in that release).
/// Anything else is rejected where it can be named, rather than failing later
/// as an opaque "signature value mismatch".
mod canonicalization_method {
    use super::super::parse_signed_info_canonicalization_method;
    use crate::core::ErrorCode;

    fn signed_info(inner: &str) -> roxmltree::Document<'_> {
        roxmltree::Document::parse(inner).expect("fixture parses")
    }

    type Parsed = (crate::crypto::wssec::WsSecCanonicalizationKind, Vec<String>);

    fn check(algorithm_attr: &str) -> crate::core::Result<Parsed> {
        let xml = format!(
            r#"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{algorithm_attr}</ds:SignedInfo>"#
        );
        let doc = signed_info(&xml);
        parse_signed_info_canonicalization_method(doc.root_element())
    }

    #[test]
    fn inclusive_namespaces_prefix_list_is_parsed() {
        let (kind, prefixes) = check(
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces PrefixList="soapenv wsu" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:CanonicalizationMethod>"#,
        )
        .expect("exclusive c14n with a PrefixList is the default WSS4J shape");
        assert_eq!(
            kind,
            crate::crypto::wssec::WsSecCanonicalizationKind::Exclusive
        );
        assert_eq!(prefixes, vec!["soapenv".to_string(), "wsu".to_string()]);
    }

    #[test]
    fn unknown_canonicalization_method_child_is_rejected() {
        let err = check(
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><x:Mystery xmlns:x="urn:x"/></ds:CanonicalizationMethod>"#,
        )
        .expect_err("a child that could change the canonical form must not be skipped");
        assert_eq!(err.code, ErrorCode::InteropViolation);
        assert!(err.message.contains("Mystery"), "{}", err.message);
    }

    #[test]
    fn exclusive_c14n_is_accepted() {
        let (kind, _) = check(
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
        )
        .expect("exclusive c14n is the AS4-mandated algorithm");
        assert_eq!(
            kind,
            crate::crypto::wssec::WsSecCanonicalizationKind::Exclusive
        );
    }

    /// Peppol SMP signs with inclusive C14N and **mandates** it (SMP 1.4.0
    /// §5.5.1). Rejecting it would leave no conformant SMP response
    /// verifiable; `tests/interop_peppol_smp_oracle.rs` is the real-world
    /// witness, and this is the unit-level statement of the same rule.
    #[test]
    fn inclusive_c14n_is_accepted() {
        let (kind, prefixes) = check(
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>"#,
        )
        .expect("inclusive c14n is what Peppol SMP mandates");
        assert_eq!(
            kind,
            crate::crypto::wssec::WsSecCanonicalizationKind::Inclusive
        );
        assert!(prefixes.is_empty());
    }

    /// A prefix list is an exclusive-C14N construct; under inclusive
    /// canonicalization the whole in-scope context is emitted, so declaring one
    /// is a contradiction rather than a redundancy.
    #[test]
    fn inclusive_c14n_with_a_prefix_list_is_rejected() {
        let err = check(
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"><ec:InclusiveNamespaces PrefixList="soapenv" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:CanonicalizationMethod>"#,
        )
        .expect_err("a PrefixList under inclusive c14n is meaningless");
        assert_eq!(err.code, ErrorCode::InteropViolation);
        assert!(err.message.contains("PrefixList"), "{}", err.message);
    }

    #[test]
    fn an_unknown_canonicalization_algorithm_is_rejected_by_name() {
        let err = check(r#"<ds:CanonicalizationMethod Algorithm="urn:made:up"/>"#)
            .expect_err("an unknown algorithm must be named, not guessed at");
        assert_eq!(err.code, ErrorCode::InteropViolation);
        assert!(err.message.contains("urn:made:up"), "{}", err.message);
    }

    /// Comment-preserving **inclusive** C14N is rejected for the same reason as
    /// the exclusive variant: the canonicalizer strips comments.
    #[test]
    fn comment_preserving_inclusive_c14n_is_rejected() {
        let err = check(
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/>"#,
        )
        .expect_err("WithComments must be rejected");
        assert_eq!(err.code, ErrorCode::InteropViolation);
        assert!(err.message.contains("comment"), "{}", err.message);
    }

    #[test]
    fn comment_preserving_exclusive_c14n_is_rejected() {
        // The canonicalizer strips comments, so accepting this URI would
        // verify under a different algorithm than the one declared.
        let err = check(
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/>"#,
        )
        .expect_err("WithComments must be rejected");
        assert_eq!(err.code, ErrorCode::InteropViolation);
        assert!(err.message.contains("comment"), "{}", err.message);
    }

    #[test]
    fn missing_or_empty_algorithm_is_rejected() {
        // XMLDSig schema: SignedInfo is (CanonicalizationMethod, SignatureMethod, Reference+).
        assert_eq!(
            check("").expect_err("absent element").code,
            ErrorCode::ParseFailed
        );
        assert_eq!(
            check(r#"<ds:CanonicalizationMethod/>"#)
                .expect_err("absent attribute")
                .code,
            ErrorCode::ParseFailed
        );
    }
}

// ── inbound wsu:Timestamp (WSS 1.1.1 §10) ───────────────────────────────────

/// A correctly signed message whose `wsse:Security` header also carries
/// `security_extra` (unsigned; a timestamp can only cause rejection).
fn signed_with_security_extra(security_extra: &str) -> String {
    let (pkey, cert_der) = generate_test_signing_identity("asx-wssec-wsu-ts-test");
    let cert_der_b64 = BASE64_STANDARD.encode(&cert_der);
    let reference_uri = "#payload-1";

    let build = |digest: &str, signature: &str| -> String {
        format!(
            r##"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
    xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
    xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<S12:Header>
    <wsse:Security>
        {security_extra}
        <wsse:BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#Base64Binary" ValueType="http://docs.oasis-open.org/wss/oasis-wss-x509-token-profile-1.0#X509v3" wsu:Id="X509-token-1">{cert_der_b64}</wsse:BinarySecurityToken>
        <ds:Signature>
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="{reference_uri}">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>{digest}</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>{signature}</ds:SignatureValue>
            <ds:KeyInfo>
                <wsse:SecurityTokenReference>
                    <wsse:Reference URI="#X509-token-1" ValueType="http://docs.oasis-open.org/wss/oasis-wss-x509-token-profile-1.0#X509v3"/>
                </wsse:SecurityTokenReference>
            </ds:KeyInfo>
        </ds:Signature>
    </wsse:Security>
</S12:Header>
<S12:Body>
    <eb:Payload wsu:Id="payload-1">ABC</eb:Payload>
</S12:Body>
</S12:Envelope>"##
        )
    };

    let unsigned = build("placeholder", "AA==");
    let unsigned_doc = Document::parse(&unsigned).expect("unsigned doc");
    let digest = canonicalize_reference_digest_base64_from_doc_with_inclusive_ns(
        &unsigned_doc,
        reference_uri,
        &WsSecCanonicalizationProfile::default(),
        None,
        WsSecDigestMethod::Sha256,
    )
    .expect("digest");
    let with_digest = build(&digest, "AA==");
    let material_doc = Document::parse(&with_digest).expect("material doc");
    let material =
        parse_signature_material_from_doc(&material_doc, WsSecCanonicalizationProfile::default())
            .expect("signature material");
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).expect("signer");
    signer
        .update(&material.signed_info_c14n)
        .expect("signer update");
    let signature_base64 = BASE64_STANDARD.encode(signer.sign_to_vec().expect("signature"));
    build(&digest, &signature_base64)
}

/// `now + offset_secs` as `YYYY-MM-DDTHH:MM:SSZ`.
fn ts(offset_secs: i64) -> String {
    let now = crate::clock::system().now();
    let t = if offset_secs >= 0 {
        now + std::time::Duration::from_secs(offset_secs as u64)
    } else {
        now - std::time::Duration::from_secs(offset_secs.unsigned_abs())
    };
    crate::time_utils::format_rfc3339_secs(t)
}

fn wsu_timestamp(inner: &str) -> String {
    format!("<wsu:Timestamp wsu:Id=\"TS-1\">{inner}</wsu:Timestamp>")
}

fn created_expires(created: &str, expires: &str) -> String {
    format!("<wsu:Created>{created}</wsu:Created><wsu:Expires>{expires}</wsu:Expires>")
}

fn assert_wsu_timestamp_rejected(security_extra: &str, case: &str) {
    let signed = signed_with_security_extra(security_extra);
    let err = verify_enveloped_signature(&signed, WsSecVerifyOptions::new())
        .err()
        .unwrap_or_else(|| panic!("{case}: a bad wsu:Timestamp must be rejected"));
    assert_eq!(
        err.code,
        crate::core::ErrorCode::SecurityVerificationFailed,
        "{case}"
    );
    assert!(
        err.message.contains("wsu:Timestamp"),
        "{case}: error must name wsu:Timestamp, got: {}",
        err.message
    );
}

#[test]
fn wsu_timestamp_two_timestamps_are_rejected() {
    let one = wsu_timestamp(&created_expires(&ts(0), &ts(300)));
    assert_wsu_timestamp_rejected(&format!("{one}{one}").replacen("TS-1", "TS-2", 1), "two");
}

#[test]
fn wsu_timestamp_two_created_are_rejected() {
    let inner = format!(
        "<wsu:Created>{}</wsu:Created>{}",
        ts(0),
        created_expires(&ts(0), &ts(300))
    );
    assert_wsu_timestamp_rejected(&wsu_timestamp(&inner), "two Created");
}

#[test]
fn wsu_timestamp_expired_is_rejected() {
    let extra = wsu_timestamp(&created_expires(&ts(-1200), &ts(-600)));
    assert_wsu_timestamp_rejected(&extra, "Expires 10 min in the past");
}

#[test]
fn wsu_timestamp_created_in_the_future_is_rejected() {
    let extra = wsu_timestamp(&created_expires(&ts(600), &ts(1200)));
    assert_wsu_timestamp_rejected(&extra, "Created 10 min in the future");
}

#[test]
fn wsu_timestamp_expires_before_created_is_rejected() {
    let extra = wsu_timestamp(&created_expires(&ts(60), &ts(0)));
    assert_wsu_timestamp_rejected(&extra, "Expires < Created");
}

#[test]
fn wsu_timestamp_non_utc_value_is_rejected() {
    let created = ts(0).replace('Z', "+02:00");
    let extra = wsu_timestamp(&created_expires(&created, &ts(300)));
    assert_wsu_timestamp_rejected(&extra, "non-UTC Created");
}

#[test]
fn wsu_timestamp_absent_is_accepted() {
    let signed = signed_with_security_extra("");
    verify_enveloped_signature(&signed, WsSecVerifyOptions::new())
        .expect("an absent wsu:Timestamp stays acceptable");
}

#[test]
fn wsu_timestamp_valid_is_accepted() {
    let signed = signed_with_security_extra(&wsu_timestamp(&created_expires(&ts(0), &ts(300))));
    verify_enveloped_signature(&signed, WsSecVerifyOptions::new())
        .expect("a valid wsu:Timestamp is accepted");
}

// ── authenticate before expensive work ──────────────────────────────────────

mod order {
    use super::super::order_probe;
    use super::super::{
        SignedDocClass, verify_enveloped_document_signature_with_doc,
        verify_enveloped_signature_optional_with_doc,
    };
    use crate::core::ErrorCode;
    use crate::crypto::CertFingerprint;
    use crate::crypto::wssec::{
        ChainPolicy, WsSecOutboundKeyInfoProfile, WsSecVerifyOptions, generate_xmlsig_signature,
    };
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::extension::{BasicConstraints, KeyUsage};
    use openssl::x509::{X509, X509NameBuilder};

    fn named(cn: &str) -> openssl::x509::X509Name {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        name.build()
    }

    fn cert(
        cn: &str,
        key: &PKey<Private>,
        issuer: Option<(&X509, &PKey<Private>)>,
        ca: bool,
    ) -> X509 {
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        let mut serial = openssl::bn::BigNum::new().unwrap();
        serial
            .rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
            .unwrap();
        b.set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        b.set_subject_name(&named(cn)).unwrap();
        match issuer {
            Some((issuer_cert, _)) => b.set_issuer_name(issuer_cert.subject_name()).unwrap(),
            None => b.set_issuer_name(&named(cn)).unwrap(),
        }
        b.set_pubkey(key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();
        if ca {
            b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
            b.append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        } else {
            b.append_extension(BasicConstraints::new().critical().build().unwrap())
                .unwrap();
            b.append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        }
        let signer = issuer.map_or(key, |(_, k)| k);
        b.sign(signer, MessageDigest::sha256()).unwrap();
        b.build()
    }

    fn rsa() -> PKey<Private> {
        PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap()
    }

    /// A leaf issued by a CA, and the CA.
    struct Pki {
        ca_pem: String,
        leaf_key_pem: Vec<u8>,
        leaf_pem: Vec<u8>,
    }

    fn pki() -> Pki {
        let ca_key = rsa();
        let ca = cert("asx-order-ca", &ca_key, None, true);
        let leaf_key = rsa();
        let leaf = cert("asx-order-leaf", &leaf_key, Some((&ca, &ca_key)), false);
        Pki {
            ca_pem: String::from_utf8(ca.to_pem().unwrap()).unwrap(),
            leaf_key_pem: leaf_key.private_key_to_pem_pkcs8().unwrap(),
            leaf_pem: leaf.to_pem().unwrap(),
        }
    }

    /// A SOAP envelope with `n` signed `wsu:Id` targets, the signature in
    /// `wsse:Security`.
    fn signed(pki: &Pki, n: usize) -> String {
        let targets: String = (0..n)
            .map(|i| format!("<p:t wsu:Id=\"r{i}\">{i}</p:t>"))
            .collect();
        let envelope = format!(
            "<S:Envelope xmlns:S=\"http://www.w3.org/2003/05/soap-envelope\" \
             xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" \
             xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" \
             xmlns:p=\"urn:asx:order\"><S:Header><wsse:Security></wsse:Security></S:Header>\
             <S:Body>{targets}</S:Body></S:Envelope>"
        );
        let uris: Vec<String> = (0..n).map(|i| format!("#r{i}")).collect();
        let uris: Vec<&str> = uris.iter().map(String::as_str).collect();
        let signature = generate_xmlsig_signature(
            &envelope,
            &uris,
            &pki.leaf_key_pem,
            &pki.leaf_pem,
            WsSecOutboundKeyInfoProfile::X509DataOnly,
        )
        .expect("sign");
        envelope.replacen(
            "<wsse:Security></wsse:Security>",
            &format!("<wsse:Security>{signature}</wsse:Security>"),
            1,
        )
    }

    fn verify(
        xml: &str,
        class: SignedDocClass,
        pins: &[CertFingerprint],
        anchors: &[String],
    ) -> crate::core::Result<()> {
        let doc = crate::xml::parse(xml, crate::xml::XmlLimits::ENVELOPE, "test").unwrap();
        let mut opts = WsSecVerifyOptions::new().with_expected_fingerprints(pins);
        if !anchors.is_empty() {
            opts = opts.with_chain_policy(ChainPolicy {
                trust_anchor_pems: anchors,
                require_chain_validation: true,
                ..ChainPolicy::default()
            });
        }
        verify_enveloped_signature_optional_with_doc(&doc, xml, class, opts).map(|_| ())
    }

    fn verify_path(xml: &str, pins: &[CertFingerprint], anchors: &[String]) -> usize {
        let doc = crate::xml::parse(xml, crate::xml::XmlLimits::ENVELOPE, "test").unwrap();
        let opts = WsSecVerifyOptions::new()
            .with_expected_fingerprints(pins)
            .with_chain_policy(ChainPolicy {
                trust_anchor_pems: anchors,
                require_chain_validation: true,
                ..ChainPolicy::default()
            });
        verify_enveloped_signature_optional_with_doc(&doc, xml, SignedDocClass::UserMessage, opts)
            .expect("verifies")
            .expect("signed")
            .signer_path
            .len()
    }

    fn pin(pki: &Pki) -> Vec<CertFingerprint> {
        vec![CertFingerprint::from_cert_pem(&pki.leaf_pem).unwrap()]
    }

    #[test]
    fn order_unpinned_signer_fails_before_digesting() {
        let pki = pki();
        let other = vec![CertFingerprint::from_cert_pem(pki.ca_pem.as_bytes()).unwrap()];
        let xml = signed(&pki, 2);
        order_probe::reset();
        let err = verify(&xml, SignedDocClass::UserMessage, &other, &[]).unwrap_err();
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
        assert_eq!(order_probe::digests(), 0, "{}", err.message);
    }

    #[test]
    fn order_untrusted_path_fails_before_digesting() {
        let pki = pki();
        let stranger = super::pki_ca_pem_unrelated();
        let xml = signed(&pki, 2);
        order_probe::reset();
        let err = verify(&xml, SignedDocClass::UserMessage, &pin(&pki), &[stranger]).unwrap_err();
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
        assert_eq!(order_probe::digests(), 0, "{}", err.message);
    }

    #[test]
    fn order_wrong_signature_value_fails_before_digesting() {
        let pki = pki();
        let xml = signed(&pki, 2);
        let open = xml.find("<ds:SignatureValue>").unwrap() + "<ds:SignatureValue>".len();
        let flipped = if &xml[open..open + 1] == "A" {
            "B"
        } else {
            "A"
        };
        let tampered = format!("{}{}{}", &xml[..open], flipped, &xml[open + 1..]);
        order_probe::reset();
        let err = verify(&tampered, SignedDocClass::UserMessage, &pin(&pki), &[]).unwrap_err();
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
        assert_eq!(order_probe::digests(), 0, "{}", err.message);
    }

    /// Verification does no revocation (it may fetch); it returns
    /// the validated path — signer and anchor — for the caller to check
    /// after the sender rule.
    #[test]
    fn order_the_validated_path_is_returned_for_the_callers_revocation_check() {
        let pki = pki();
        let xml = signed(&pki, 3);
        order_probe::reset();
        assert_eq!(
            verify_path(&xml, &pin(&pki), std::slice::from_ref(&pki.ca_pem)),
            2,
            "signer and anchor"
        );
        assert_eq!(order_probe::digests(), 3);
    }

    fn assert_cap(xml: &str, class: SignedDocClass, pins: &[CertFingerprint], needle: &str) {
        order_probe::reset();
        let err = verify(xml, class, pins, &[]).expect_err("over the cap");
        assert_eq!(
            err.code,
            ErrorCode::SecurityVerificationFailed,
            "{}",
            err.message
        );
        assert!(err.message.contains(needle), "{}", err.message);
        assert_eq!(order_probe::digests(), 0, "rejected before any digest");
    }

    #[test]
    fn cap_reference_count_user_message() {
        let pki = pki();
        verify(
            &signed(&pki, 19),
            SignedDocClass::UserMessage,
            &pin(&pki),
            &[],
        )
        .expect("19 references are within the user-message cap");
        assert_cap(
            &signed(&pki, 20),
            SignedDocClass::UserMessage,
            &pin(&pki),
            "20 ds:Reference",
        );
    }

    #[test]
    fn cap_reference_count_signal() {
        let pki = pki();
        verify(&signed(&pki, 3), SignedDocClass::Signal, &pin(&pki), &[])
            .expect("3 references are within the signal cap");
        assert_cap(
            &signed(&pki, 4),
            SignedDocClass::Signal,
            &pin(&pki),
            "4 ds:Reference",
        );
    }

    #[test]
    fn cap_reference_count_smp() {
        let (ok, two) = super::smp_documents();
        let pins: [CertFingerprint; 0] = [];
        let doc = crate::xml::parse(&ok.0, crate::xml::XmlLimits::SMP, "t").unwrap();
        verify_enveloped_document_signature_with_doc(&doc, &pins, &ChainPolicy::default())
            .expect("one URI=\"\" reference verifies");
        let doc = crate::xml::parse(&two, crate::xml::XmlLimits::SMP, "t").unwrap();
        order_probe::reset();
        let err =
            verify_enveloped_document_signature_with_doc(&doc, &pins, &ChainPolicy::default())
                .expect_err("two references exceed the SMP cap");
        assert_eq!(
            err.code,
            ErrorCode::SecurityVerificationFailed,
            "{}",
            err.message
        );
        assert!(err.message.contains("2 ds:Reference"), "{}", err.message);
        assert_eq!(order_probe::digests(), 0);
    }

    #[test]
    fn cap_transforms_per_reference() {
        let pki = pki();
        let xml = signed(&pki, 1);
        let one =
            "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:Transform>";
        let three = one.repeat(3);
        let xml = xml.replacen(one, &three, 1);
        assert_cap(
            &xml,
            SignedDocClass::UserMessage,
            &pin(&pki),
            "3 transforms",
        );
    }

    #[test]
    fn signature_outside_wsse_security_rejected() {
        let pki = pki();
        let xml = signed(&pki, 1);
        let start = xml.find("<ds:Signature").unwrap();
        let end = xml.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
        let signature = &xml[start..end];
        let moved = format!("{}{}", &xml[..start], &xml[end..]).replacen(
            "</S:Header>",
            &format!("{signature}</S:Header>"),
            1,
        );
        order_probe::reset();
        let err = verify(&moved, SignedDocClass::UserMessage, &pin(&pki), &[]).unwrap_err();
        assert_eq!(
            err.code,
            ErrorCode::SecurityVerificationFailed,
            "{}",
            err.message
        );
        assert!(err.message.contains("wsse:Security"), "{}", err.message);
        assert_eq!(order_probe::digests(), 0);
    }

    /// Same-document IDs are `wsu:Id`, `Id` and `xml:id` only.
    #[test]
    fn reference_id_must_be_wsu_id_id_or_xml_id() {
        let pki = pki();
        let xml = signed(&pki, 1);
        for renamed in ["ID=\"r0\"", "p:id=\"r0\""] {
            let probe = xml.replacen("wsu:Id=\"r0\"", renamed, 1);
            let err = verify(&probe, SignedDocClass::UserMessage, &pin(&pki), &[]).unwrap_err();
            assert_eq!(err.code, ErrorCode::SecurityVerificationFailed, "{renamed}");
            assert!(
                err.message.contains("#r0") && err.message.contains("no element"),
                "{renamed}: {}",
                err.message
            );
        }
    }
}

/// A CA no test leaf chains to.
fn pki_ca_pem_unrelated() -> String {
    let (pkey, _) = generate_test_signing_identity("asx-order-stranger");
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    let mut name = openssl::x509::X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "asx-order-stranger-ca")
        .unwrap();
    let name = name.build();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&pkey).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(30).unwrap())
        .unwrap();
    b.append_extension(
        openssl::x509::extension::BasicConstraints::new()
            .critical()
            .ca()
            .build()
            .unwrap(),
    )
    .unwrap();
    b.sign(&pkey, MessageDigest::sha256()).unwrap();
    String::from_utf8(b.build().to_pem().unwrap()).unwrap()
}

/// An enveloped whole-document signature (the SMP shape) over a small
/// document, signed by a fresh self-signed key: `(xml, cert_der)`, and the
/// same document with its `ds:Reference` duplicated.
fn smp_documents() -> ((String, Vec<u8>), String) {
    use crate::crypto::wssec::canonicalize::canonicalize_enveloped_document;
    let (pkey, cert_der) = generate_test_signing_identity("asx-order-smp");
    let cert_b64 = BASE64_STANDARD.encode(&cert_der);
    let build = |digest: &str, signature: &str| {
        format!(
            "<smp:SignedServiceMetadata xmlns:smp=\"urn:asx:smp\"><smp:ServiceMetadata>data</smp:ServiceMetadata>\
             <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo>\
             <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\
             <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\
             <ds:Reference URI=\"\"><ds:Transforms>\
             <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\
             </ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\
             <ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>\
             <ds:SignatureValue>{signature}</ds:SignatureValue>\
             <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>\
             </ds:Signature></smp:SignedServiceMetadata>"
        )
    };
    let unsigned = build("AA==", "AA==");
    let doc = Document::parse(&unsigned).unwrap();
    let signature_node = doc
        .descendants()
        .find(|n| n.tag_name().name() == "Signature")
        .unwrap();
    let profile = WsSecCanonicalizationProfile {
        kind: crate::crypto::wssec::WsSecCanonicalizationKind::Inclusive,
        ..WsSecCanonicalizationProfile::default()
    };
    let digest = canonicalize_enveloped_document(&doc, &profile, signature_node)
        .unwrap()
        .digest_value_base64;
    let with_digest = build(&digest, "AA==");
    let doc = Document::parse(&with_digest).unwrap();
    let material = parse_signature_material_from_doc(&doc, WsSecCanonicalizationProfile::default())
        .expect("material");
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
    signer.update(&material.signed_info_c14n).unwrap();
    let signed = build(
        &digest,
        &BASE64_STANDARD.encode(signer.sign_to_vec().unwrap()),
    );
    let reference_start = signed.find("<ds:Reference").unwrap();
    let reference_end = signed.find("</ds:Reference>").unwrap() + "</ds:Reference>".len();
    let reference = &signed[reference_start..reference_end];
    let two = signed.replacen(reference, &format!("{reference}{reference}"), 1);
    ((signed, cert_der), two)
}
