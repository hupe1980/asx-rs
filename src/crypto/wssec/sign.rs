//! XMLDSig signature generation: *prepare* → one key-seam call → *finish*.
//!
//! Every signature the crate produces runs through the same three steps:
//!
//! 1. [`prepare_signed_info`] — pure: digests every reference with the one
//!    reference digest, writes `ds:SignedInfo` with [`XmlOut`] and
//!    canonicalizes it (the bytes that are signed are the canonical form of
//!    the bytes that are emitted, so the two cannot diverge);
//! 2. [`SigningKeyProvider::sign`] — the only private-key operation: RSA
//!    PKCS #1 v1.5 octets, ECDSA as ASN.1 DER;
//! 3. [`finish_signature`] — pure: converts the raw value to its wire form
//!    (ECDSA `r ‖ s`, XMLDSig 1.1 §6.4.3) and writes `ds:Signature` /
//!    `ds:KeyInfo`.
//!
//! The split lets an asynchronous signer (`Signer::sign(alg, data)`) be
//! awaited between *prepare* and *finish*.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use std::collections::{BTreeMap, HashMap};

use super::canonicalize::{
    canonicalize_reference_digest_from_same_document_target_id_with_inclusive_ns,
    normalize_same_document_uri, try_serialize_node,
};
use super::{
    WsSecCanonicalizationKind, WsSecCanonicalizationProfile, WsSecDigestMethod,
    WsSecOutboundKeyInfoProfile,
};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::crypto::alg::{KeyFamily, TransformAlg};
use crate::crypto::signing::{PemSigningKeyProvider, SignatureAlgorithm, SigningKeyProvider};
use crate::xml::{self, XmlFragment, XmlLimits, XmlOut, ns};

const STAGE: &str = "wssec_generate_signature";

/// The digest of every `ds:Reference` — same-document and `cid:` alike —
/// whatever the signature method's hash (eDelivery AS4 1.15 §3.2.6,
/// BDEW AS4-Profil 1.2 §2.2.6.2.1). One value feeds the computation and the
/// declaration, so they cannot disagree.
pub(crate) const REFERENCE_DIGEST: WsSecDigestMethod = WsSecDigestMethod::Sha256;

/// Generate an XML Signature `<ds:Signature>` element for the given
/// same-document `reference_uris` within `envelope_xml`, using the key's
/// default algorithm (`rsa-sha256` or `ecdsa-sha256`) with Exclusive C14N.
///
/// Every `ds:Reference` is digested with, and declares, SHA-256. An ECDSA
/// `ds:SignatureValue` is emitted as XMLDSig 1.1 `r ‖ s` (64 octets on
/// P-256 and brainpoolP256r1, 96 on P-384, 132 on P-521).
///
/// # Cancel Safety
///
/// This function is **synchronous** and not cancel-safe.  When invoked from a
/// `tokio::task::spawn_blocking` closure, cancelling the outer Tokio task does
/// **not** interrupt the blocking thread — OpenSSL signing and C14N serialization
/// run to completion regardless of task cancellation.
///
/// Do not call this function directly from an async context; always dispatch via
/// `tokio::task::spawn_blocking` or an equivalent executor thread.
pub fn generate_xmlsig_signature(
    envelope_xml: &str,
    reference_uris: &[&str],
    signing_key_pem: &[u8],
    signing_cert_pem: &[u8],
    key_info_profile: WsSecOutboundKeyInfoProfile,
) -> Result<String> {
    require_references(reference_uris)?;
    let provider = PemSigningKeyProvider::from_pem(signing_key_pem, signing_cert_pem)?;
    generate_xmlsig_signature_with_provider(
        envelope_xml,
        reference_uris,
        &[],
        &provider,
        key_info_profile,
    )
}

/// Generate XMLDSig with external reference bodies, e.g. MIME `cid:`
/// attachments (`(uri, digest input)` pairs). Encoding and digests as for
/// [`generate_xmlsig_signature`].
pub fn generate_xmlsig_signature_with_external_references(
    envelope_xml: &str,
    reference_uris: &[&str],
    external_references: &[(&str, &[u8])],
    signing_key_pem: &[u8],
    signing_cert_pem: &[u8],
    key_info_profile: WsSecOutboundKeyInfoProfile,
) -> Result<String> {
    let provider = PemSigningKeyProvider::from_pem(signing_key_pem, signing_cert_pem)?;
    generate_xmlsig_signature_with_provider(
        envelope_xml,
        reference_uris,
        external_references,
        &provider,
        key_info_profile,
    )
}

/// [`generate_xmlsig_signature_with_external_references`] for a key and
/// certificate that are already parsed (no PEM parsing on hot paths).
pub fn generate_xmlsig_signature_with_external_references_preparsed(
    envelope_xml: &str,
    reference_uris: &[&str],
    external_references: &[(&str, &[u8])],
    signing_key: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
    signing_cert: &openssl::x509::X509Ref,
    key_info_profile: WsSecOutboundKeyInfoProfile,
) -> Result<String> {
    let provider =
        PemSigningKeyProvider::from_parts(signing_key.to_owned(), signing_cert.to_owned())?;
    generate_xmlsig_signature_with_provider(
        envelope_xml,
        reference_uris,
        external_references,
        &provider,
        key_info_profile,
    )
}

/// Generate XMLDSig through a [`SigningKeyProvider`] (HSM / cloud KMS).
pub(crate) fn generate_xmlsig_signature_with_provider(
    envelope_xml: &str,
    reference_uris: &[&str],
    external_references: &[(&str, &[u8])],
    provider: &dyn SigningKeyProvider,
    key_info_profile: WsSecOutboundKeyInfoProfile,
) -> Result<String> {
    let algorithm = provider.preferred_algorithm();
    let span = tracing::debug_span!(
        target: "asx",
        "asx.sign",
        algorithm = algorithm.algorithm_uri(),
        reference_count = reference_uris.len() + external_references.len(),
    );
    span.in_scope(|| {
        require_references(reference_uris)?;
        let doc = xml::parse(envelope_xml, XmlLimits::ENVELOPE, STAGE)?;
        let prepared = prepare_signed_info(&doc, reference_uris, external_references, algorithm)?;
        let raw_signature = provider.sign(&prepared.canonical_signed_info, algorithm)?;
        let cert_der = provider.certificate_der()?;
        finish_signature(prepared, raw_signature, &cert_der, key_info_profile)
            .map(XmlFragment::into_string)
    })
}

/// Parse the envelope as it will be sent and prepare its `SignedInfo` under
/// an `asx.sign` span: the pure first half of the signing split.
pub(crate) fn prepare_envelope_signature(
    envelope_xml: &str,
    reference_uris: &[&str],
    external_references: &[(&str, &[u8])],
    algorithm: SignatureAlgorithm,
) -> Result<PreparedSignature> {
    let span = tracing::debug_span!(
        target: "asx",
        "asx.sign",
        algorithm = algorithm.algorithm_uri(),
        reference_count = reference_uris.len() + external_references.len(),
    );
    span.in_scope(|| {
        require_references(reference_uris)?;
        let doc = xml::parse(envelope_xml, XmlLimits::ENVELOPE, STAGE)?;
        prepare_signed_info(&doc, reference_uris, external_references, algorithm)
    })
}

fn require_references(reference_uris: &[&str]) -> Result<()> {
    if reference_uris.is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "XMLDSig signature must contain at least one ds:Reference",
            ErrorContext::new(STAGE),
        ));
    }
    Ok(())
}

/// One prepared `ds:Reference`.
#[derive(Debug)]
pub(crate) struct PreparedReference {
    pub(crate) uri: String,
    pub(crate) transform: TransformAlg,
    pub(crate) digest: Vec<u8>,
}

/// Output of [`prepare_signed_info`]: everything but the signature value.
#[derive(Debug)]
pub(crate) struct PreparedSignature {
    pub(crate) algorithm: SignatureAlgorithm,
    /// `ds:SignedInfo` as it is emitted.
    pub(crate) signed_info: XmlFragment,
    /// Its Exclusive C14N: the bytes the key seam signs.
    pub(crate) canonical_signed_info: Vec<u8>,
}

/// Digest every reference of `doc` (the envelope as it will be sent, parsed
/// with the envelope limits) and of `external` (`cid:` digest inputs), and
/// write the canonical `ds:SignedInfo`. Pure: no key is used.
pub(crate) fn prepare_signed_info(
    doc: &roxmltree::Document<'_>,
    reference_uris: &[&str],
    external: &[(&str, &[u8])],
    algorithm: SignatureAlgorithm,
) -> Result<PreparedSignature> {
    require_references(reference_uris)?;
    let ref_digest = REFERENCE_DIGEST;
    let external: HashMap<&str, &[u8]> = external.iter().copied().collect();
    let profile = WsSecCanonicalizationProfile::default();

    let mut references = Vec::with_capacity(reference_uris.len());
    for &uri in reference_uris {
        let (transform, digest) = if uri.starts_with("cid:") {
            let payload = external.get(uri).copied().ok_or_else(|| {
                AsxError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "missing external reference bytes for URI {uri}; \
                         include it in external_references"
                    ),
                    ErrorContext::new(STAGE).with_message_id(uri.to_string()),
                )
            })?;
            let digest = openssl::hash::hash(ref_digest.message_digest(), payload)
                .map_err(|_err| {
                    AsxError::new(
                        ErrorCode::SecurityVerificationFailed,
                        "failed to digest external reference payload",
                        ErrorContext::new(STAGE).with_message_id(uri.to_string()),
                    )
                })?
                .to_vec();
            (TransformAlg::AttachmentContent, digest)
        } else {
            let target_id = normalize_same_document_uri(uri)?;
            let digest =
                canonicalize_reference_digest_from_same_document_target_id_with_inclusive_ns(
                    doc, uri, target_id, &profile, None, ref_digest,
                )?;
            (
                TransformAlg::C14n(WsSecCanonicalizationKind::Exclusive),
                digest,
            )
        };
        references.push(PreparedReference {
            uri: uri.to_string(),
            transform,
            digest,
        });
    }

    let signed_info = write_signed_info(algorithm, ref_digest, &references)?;
    let canonical_signed_info = canonicalize_signed_info(&signed_info)?;
    Ok(PreparedSignature {
        algorithm,
        signed_info,
        canonical_signed_info,
    })
}

/// `ds:SignedInfo` in Canonical XML element form.
///
/// XMLDSig §4.3.3.2: a same-document `#id` reference dereferences to a
/// node-set that, absent a transform, is serialized with *inclusive* C14N; we
/// digest with exclusive C14N, so the transform is declared. A `cid:`
/// reference dereferences to an octet stream and declares the WSS SwA
/// `Attachment-Content-Signature-Transform`, which the AS4 profile mandates and
/// WSS4J-based receivers require. Schema order inside `ds:Reference` is
/// `Transforms?, DigestMethod, DigestValue`.
fn write_signed_info(
    algorithm: SignatureAlgorithm,
    ref_digest: WsSecDigestMethod,
    references: &[PreparedReference],
) -> Result<XmlFragment> {
    let mut out = XmlOut::canonical();
    out.start("ds:SignedInfo")?.ns("ds", ns::DS)?;
    out.start("ds:CanonicalizationMethod")?
        .attr(
            "Algorithm",
            WsSecCanonicalizationKind::Exclusive.uri(),
            "ds:CanonicalizationMethod/@Algorithm",
        )?
        .end()?;
    out.start("ds:SignatureMethod")?
        .attr(
            "Algorithm",
            algorithm.algorithm_uri(),
            "ds:SignatureMethod/@Algorithm",
        )?
        .end()?;
    for reference in references {
        out.start("ds:Reference")?
            .attr("URI", &reference.uri, "ds:Reference/@URI")?;
        out.start("ds:Transforms")?
            .start("ds:Transform")?
            .attr(
                "Algorithm",
                reference.transform.uri(),
                "ds:Transform/@Algorithm",
            )?
            .end()?
            .end()?;
        out.start("ds:DigestMethod")?
            .attr(
                "Algorithm",
                ref_digest.algorithm_uri(),
                "ds:DigestMethod/@Algorithm",
            )?
            .end()?;
        out.leaf(
            "ds:DigestValue",
            &BASE64_STANDARD.encode(&reference.digest),
            "ds:DigestValue",
        )?;
        out.end()?;
    }
    out.end()?;
    out.finish()?.into_fragment()
}

/// Exclusive C14N of the written `ds:SignedInfo`: the signed bytes.
fn canonicalize_signed_info(signed_info: &XmlFragment) -> Result<Vec<u8>> {
    let doc = xml::parse(signed_info.as_str(), XmlLimits::ENVELOPE, STAGE)?;
    let mut canonical = String::with_capacity(signed_info.as_str().len());
    try_serialize_node(
        doc.root_element(),
        &mut canonical,
        &WsSecCanonicalizationProfile::default(),
        &BTreeMap::new(),
    )
    .map_err(|_err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "failed to canonicalize ds:SignedInfo",
            ErrorContext::new(STAGE),
        )
    })?;
    Ok(canonical.into_bytes())
}

/// Assemble `ds:Signature` from a prepared `SignedInfo`, the key seam's raw
/// signature and the signer certificate. Pure: no key is used.
pub(crate) fn finish_signature(
    prepared: PreparedSignature,
    raw_signature: Vec<u8>,
    signer_cert_der: &[u8],
    key_info: WsSecOutboundKeyInfoProfile,
) -> Result<XmlFragment> {
    let signer_cert = openssl::x509::X509::from_der(signer_cert_der).map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("the signing certificate is not DER X.509: {err}"),
            ErrorContext::new(STAGE),
        )
    })?;
    // ECDSA: the seam returns DER; the wire carries `r ‖ s`.
    let signature_value = prepared.algorithm.to_wire(raw_signature, &signer_cert)?;
    let cert_b64 = BASE64_STANDARD.encode(signer_cert_der);

    let mut out = XmlOut::new();
    out.start("ds:Signature")?.ns("ds", ns::DS)?;
    out.fragment(&prepared.signed_info)?;
    out.leaf(
        "ds:SignatureValue",
        &BASE64_STANDARD.encode(&signature_value),
        "ds:SignatureValue",
    )?;
    out.start("ds:KeyInfo")?;
    match key_info {
        // WSS 1.1.1 §7.7: KeyInfo in a WS-Security header carries a
        // SecurityTokenReference to the `wsse:BinarySecurityToken` that
        // `WsSecurityHeaderBuilder` emits; WSS4J-based receivers reject a bare
        // ds:X509Data with UNSUPPORTED_SECURITY_TOKEN.
        WsSecOutboundKeyInfoProfile::BinarySecurityTokenX509v3 => {
            write_token_reference(&mut out, "#X509Token", ns::WSSE_X509V3_VALUE_TYPE)?;
        }
        WsSecOutboundKeyInfoProfile::X509PKIPathv1 => {
            write_token_reference(
                &mut out,
                "#X509PKIPathToken",
                ns::WSSE_X509_PKIPATH_VALUE_TYPE,
            )?;
        }
        WsSecOutboundKeyInfoProfile::X509DataAndRsaKeyValue => {
            write_x509_data(&mut out, &cert_b64)?;
            // RFC 4051 §2.3 has no ECKeyValue variant: an EC key gets
            // X509Data only.
            if prepared.algorithm.key_family() == KeyFamily::Rsa
                && let Some((modulus, exponent)) = rsa_key_value(signer_cert_der)
            {
                out.start("ds:KeyValue")?.start("ds:RSAKeyValue")?;
                out.leaf("ds:Modulus", &modulus, "ds:Modulus")?;
                out.leaf("ds:Exponent", &exponent, "ds:Exponent")?;
                out.end()?.end()?;
            }
        }
        WsSecOutboundKeyInfoProfile::X509DataOnly => write_x509_data(&mut out, &cert_b64)?,
    }
    out.end()?;
    out.end()?;
    out.finish()?.into_fragment()
}

fn write_token_reference(out: &mut XmlOut, uri: &str, value_type: &'static str) -> Result<()> {
    out.start("wsse:SecurityTokenReference")?
        .ns("wsse", ns::WSSE)?;
    // WS-I BSP R5215 / WSS X.509 Token Profile 1.1 §3.4: a reference to a
    // `#X509PKIPathv1` token names its type; WSS4J (phase4) refuses the
    // reference without it.
    if value_type == ns::WSSE_X509_PKIPATH_VALUE_TYPE {
        out.ns("wsse11", ns::WSSE11)?.attr(
            "wsse11:TokenType",
            ns::WSSE_X509_PKIPATH_VALUE_TYPE,
            "wsse11:TokenType",
        )?;
    }
    out.start("wsse:Reference")?
        .attr("URI", uri, "wsse:Reference/@URI")?
        .attr("ValueType", value_type, "wsse:Reference/@ValueType")?
        .end()?;
    out.end()?;
    Ok(())
}

fn write_x509_data(out: &mut XmlOut, cert_b64: &str) -> Result<()> {
    out.start("ds:X509Data")?;
    out.leaf("ds:X509Certificate", cert_b64, "ds:X509Certificate")?;
    out.end()?;
    Ok(())
}

/// Base64 modulus and exponent of an RSA certificate key, for the optional
/// `ds:RSAKeyValue` some partners require alongside X509Data.
fn rsa_key_value(cert_der: &[u8]) -> Option<(String, String)> {
    let rsa = openssl::x509::X509::from_der(cert_der)
        .ok()?
        .public_key()
        .ok()?
        .rsa()
        .ok()?;
    Some((
        BASE64_STANDARD.encode(rsa.n().to_vec()),
        BASE64_STANDARD.encode(rsa.e().to_vec()),
    ))
}

#[cfg(test)]
mod tests {
    use super::super::canonicalize::is_ds_element;
    use super::*;

    fn reference(uri: &str) -> PreparedReference {
        PreparedReference {
            uri: uri.to_string(),
            transform: TransformAlg::C14n(WsSecCanonicalizationKind::Exclusive),
            digest: vec![0u8; 32],
        }
    }

    /// The written `ds:SignedInfo` is already canonical: what is emitted is
    /// what is signed.
    #[test]
    fn signed_info_is_emitted_in_canonical_form() {
        let references = vec![reference("#as4-message-id"), reference("cid:a@b")];
        let signed_info = write_signed_info(
            SignatureAlgorithm::RsaSha256,
            WsSecDigestMethod::Sha256,
            &references,
        )
        .unwrap();
        let canonical = canonicalize_signed_info(&signed_info).unwrap();
        assert_eq!(signed_info.as_str().as_bytes(), canonical.as_slice());
    }

    #[test]
    fn signed_info_contains_all_references() {
        let references = vec![reference("#as4-message-id"), reference("#as4-body")];
        let signed_info = write_signed_info(
            SignatureAlgorithm::RsaSha256,
            WsSecDigestMethod::Sha256,
            &references,
        )
        .unwrap();
        assert!(
            signed_info
                .as_str()
                .contains("<ds:Reference URI=\"#as4-message-id\"")
        );
        assert!(
            signed_info
                .as_str()
                .contains("<ds:Reference URI=\"#as4-body\"")
        );
    }

    #[test]
    fn generate_signature_rejects_empty_reference_list() {
        let err = generate_xmlsig_signature(
            "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"/>",
            &[],
            b"",
            b"",
            WsSecOutboundKeyInfoProfile::X509DataAndRsaKeyValue,
        )
        .expect_err("empty ds:Reference list must be rejected");

        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("at least one ds:Reference"));
    }

    /// A provider whose method hash is SHA-384: the reference digest must not
    /// follow it.
    #[derive(Debug)]
    struct Sha384Provider(PemSigningKeyProvider);

    impl SigningKeyProvider for Sha384Provider {
        fn sign(&self, data: &[u8], algorithm: SignatureAlgorithm) -> Result<Vec<u8>> {
            self.0.sign(data, algorithm)
        }
        fn certificate_der(&self) -> Result<Vec<u8>> {
            self.0.certificate_der()
        }
        fn preferred_algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::RsaSha384
        }
    }

    pub(super) const SECURED_ENVELOPE: &str = concat!(
        r#"<S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope" "#,
        r#"xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" "#,
        r#"xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">"#,
        r#"<S:Header><wsse:Security></wsse:Security></S:Header>"#,
        r#"<S:Body wsu:Id="body"><p xmlns="urn:asx:sign">payload</p></S:Body></S:Envelope>"#
    );

    pub(super) fn splice(signature: &str) -> String {
        SECURED_ENVELOPE.replacen(
            "<wsse:Security></wsse:Security>",
            &format!("<wsse:Security>{signature}</wsse:Security>"),
            1,
        )
    }

    #[test]
    fn cid_digest_matches_declared_method() {
        use crate::crypto::wssec::{WsSecVerifyOptions, verify_enveloped_signature};
        let (cert_pem, key_pem) = crate::test_support::self_signed_rsa("asx-sha384-provider");
        let provider =
            Sha384Provider(PemSigningKeyProvider::from_pem(&key_pem, &cert_pem).unwrap());
        let payload: &[u8] = b"attachment octets";
        let signature = generate_xmlsig_signature_with_provider(
            SECURED_ENVELOPE,
            &["#body", "cid:part@asx.test"],
            &[("cid:part@asx.test", payload)],
            &provider,
            WsSecOutboundKeyInfoProfile::X509DataOnly,
        )
        .unwrap();
        assert!(signature.contains("xmldsig-more#rsa-sha384"));

        let doc = roxmltree::Document::parse(&signature).unwrap();
        for method in doc
            .descendants()
            .filter(|n| n.is_element() && is_ds_element(*n, "DigestMethod"))
        {
            assert_eq!(
                method.attribute("Algorithm"),
                Some(WsSecDigestMethod::Sha256.algorithm_uri())
            );
        }
        let cid_value = doc
            .descendants()
            .find(|n| n.is_element() && n.attribute("URI") == Some("cid:part@asx.test"))
            .and_then(|r| {
                r.children()
                    .find(|c| c.is_element() && is_ds_element(*c, "DigestValue"))
            })
            .and_then(|v| v.text())
            .unwrap();
        assert_eq!(
            cid_value,
            BASE64_STANDARD.encode(openssl::sha::sha256(payload)),
            "the cid: DigestValue must be the SHA-256 it declares"
        );

        let external = [("cid:part@asx.test", payload)];
        verify_enveloped_signature(
            &splice(&signature),
            WsSecVerifyOptions::new().with_external_references(&external),
        )
        .expect("the signature verifies with its attachment");
    }

    /// Counts calls into the key seam and can hand back `r ‖ s` instead of
    /// the DER the provider contract requires.
    #[derive(Debug)]
    struct CountingProvider {
        inner: PemSigningKeyProvider,
        calls: std::sync::atomic::AtomicUsize,
        raw_r_concat_s: bool,
    }

    impl SigningKeyProvider for CountingProvider {
        fn sign(&self, data: &[u8], algorithm: SignatureAlgorithm) -> Result<Vec<u8>> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let der = self.inner.sign(data, algorithm)?;
            if !self.raw_r_concat_s {
                return Ok(der);
            }
            let sig = openssl::ecdsa::EcdsaSig::from_der(&der).unwrap();
            let mut raw = sig.r().to_vec_padded(32).unwrap();
            raw.extend(sig.s().to_vec_padded(32).unwrap());
            Ok(raw)
        }
        fn certificate_der(&self) -> Result<Vec<u8>> {
            self.inner.certificate_der()
        }
        fn preferred_algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::EcdsaSha256
        }
    }

    fn bp256_provider(raw_r_concat_s: bool) -> CountingProvider {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/wssec/ecdsa/");
        let key = std::fs::read(format!("{dir}bp256.key.pem")).unwrap();
        let cert = std::fs::read(format!("{dir}bp256.cert.pem")).unwrap();
        CountingProvider {
            inner: PemSigningKeyProvider::from_pem(&key, &cert).unwrap(),
            calls: std::sync::atomic::AtomicUsize::new(0),
            raw_r_concat_s,
        }
    }

    /// Every signature goes through the provider exactly once, and the DER it
    /// returns reaches the wire as the 64-octet `r ‖ s` of XMLDSig 1.1
    /// §6.4.3 (BrainpoolP256r1, the BDEW curve).
    #[test]
    fn signing_seam_called_once_and_der_converted() {
        let provider = bp256_provider(false);
        let signature = generate_xmlsig_signature_with_provider(
            SECURED_ENVELOPE,
            &["#body"],
            &[],
            &provider,
            WsSecOutboundKeyInfoProfile::X509DataOnly,
        )
        .unwrap();
        assert_eq!(
            provider.calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "one call into the key seam per signature"
        );
        let doc = roxmltree::Document::parse(&signature).unwrap();
        let value = doc
            .descendants()
            .find(|n| n.is_element() && is_ds_element(*n, "SignatureValue"))
            .and_then(|n| n.text())
            .unwrap();
        let bytes = BASE64_STANDARD.decode(value.trim()).unwrap();
        // 2·l octets; the verifier below accepts only r ‖ s.
        assert_eq!(bytes.len(), 64, "r ‖ s, not DER");

        crate::crypto::wssec::verify_enveloped_signature(
            &splice(&signature),
            crate::crypto::wssec::WsSecVerifyOptions::new(),
        )
        .expect("the r ‖ s signature verifies");
    }

    /// The provider contract is DER. A provider that already returns `r ‖ s`
    /// is refused at the seam rather than emitting a value no peer verifies.
    #[test]
    fn provider_returning_raw_r_concat_s_fails_signing() {
        let provider = bp256_provider(true);
        let err = generate_xmlsig_signature_with_provider(
            SECURED_ENVELOPE,
            &["#body"],
            &[],
            &provider,
            WsSecOutboundKeyInfoProfile::X509DataOnly,
        )
        .expect_err("a non-DER provider output must fail signing");
        assert_eq!(provider.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed, "{err:?}");
    }

    /// A caller-chosen reference URI must not break out of the `URI`
    /// attribute: the bytes are inside `ds:SignedInfo`, so an unescaped `"`
    /// would make the sender sign XML it did not intend.
    #[test]
    fn signed_info_reference_uri_is_attribute_escaped() {
        let uri = "cid:a\"b<c&d@x";
        let signed_info = write_signed_info(
            SignatureAlgorithm::RsaSha256,
            WsSecDigestMethod::Sha256,
            &[reference(uri)],
        )
        .unwrap();
        let xml = signed_info.as_str();
        let doc = roxmltree::Document::parse(xml)
            .unwrap_or_else(|e| panic!("SignedInfo must stay well-formed: {e}\n{xml}"));
        let reference = doc
            .descendants()
            .find(|n| n.is_element() && is_ds_element(*n, "Reference"))
            .expect("ds:Reference");
        assert_eq!(reference.attribute("URI"), Some(uri));
    }
}
