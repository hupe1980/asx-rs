use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use std::collections::HashMap;

use super::canonicalize::canonicalize_reference;
use super::{DS_NS, SHA256_URI, XML_EXC_C14N_URI};
use super::{
    WsSecCanonicalizationProfile, WsSecCanonicalizedReference, WsSecOutboundKeyInfoProfile,
};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::crypto::signing::{PemSigningKeyProvider, SignatureAlgorithm, SigningKeyProvider};

/// Generate an XML Signature `<ds:Signature>` element for the given
/// same-document `reference_uris` within `envelope_xml`, using the key
/// provider's preferred algorithm with Exclusive C14N.
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
    if reference_uris.is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "XMLDSig signature must contain at least one ds:Reference",
            ErrorContext::new("wssec_generate_signature"),
        ));
    }
    let provider = PemSigningKeyProvider::from_pem(signing_key_pem, signing_cert_pem)?;
    generate_xmlsig_signature_with_provider(
        envelope_xml,
        reference_uris,
        &[],
        &provider,
        key_info_profile,
    )
}

/// Generate XMLDSig with optional external reference bodies, e.g. MIME `cid:` attachments.
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

/// Generate XMLDSig with optional external reference bodies using a pre-parsed
/// key/certificate pair to avoid repeated PEM parsing on hot paths.
///
/// Prefer [`generate_xmlsig_signature_with_provider`] for new code; this
/// overload exists for callers that already hold an `openssl::pkey::PKey` and
/// `openssl::x509::X509` object (e.g., caches populated by `prepare_for_policy`).
pub fn generate_xmlsig_signature_with_external_references_preparsed(
    envelope_xml: &str,
    reference_uris: &[&str],
    external_references: &[(&str, &[u8])],
    signing_key: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
    signing_cert: &openssl::x509::X509Ref,
    key_info_profile: WsSecOutboundKeyInfoProfile,
) -> Result<String> {
    // Determine algorithm from key type, defaulting to SHA-256 for both RSA/EC.
    let algorithm = match signing_key.id() {
        openssl::pkey::Id::RSA | openssl::pkey::Id::RSA_PSS => SignatureAlgorithm::RsaSha256,
        openssl::pkey::Id::EC => SignatureAlgorithm::EcdsaSha256,
        other => {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!(
                    "XMLDSig signing key type {:?} is not supported; \
                     use an RSA or EC (P-256/P-384/P-521) key",
                    other
                ),
                ErrorContext::new("wssec_generate_signature"),
            ));
        }
    };
    generate_xmlsig_signature_core(
        envelope_xml,
        reference_uris,
        external_references,
        |data| {
            use openssl::sign::Signer;
            let mut signer =
                Signer::new(algorithm.message_digest(), signing_key).map_err(|_err| {
                    AsxError::new(
                        ErrorCode::SecurityVerificationFailed,
                        "failed to initialize XMLDSig signer",
                        ErrorContext::new("wssec_generate_signature"),
                    )
                })?;
            signer.update(data).map_err(|_err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    "failed to feed SignedInfo bytes to signer",
                    ErrorContext::new("wssec_generate_signature"),
                )
            })?;
            signer.sign_to_vec().map_err(|_err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    "XMLDSig signing operation failed",
                    ErrorContext::new("wssec_generate_signature"),
                )
            })
        },
        || {
            signing_cert.to_der().map_err(|_err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    "failed to DER-encode XMLDSig signing certificate",
                    ErrorContext::new("wssec_generate_signature"),
                )
            })
        },
        XmlSigKeyParams {
            algorithm,
            // Provide RSA key value components for RSA-SHA256 interop.
            rsa_key_value: if matches!(
                algorithm,
                SignatureAlgorithm::RsaSha256
                    | SignatureAlgorithm::RsaSha384
                    | SignatureAlgorithm::RsaSha512
            ) {
                signing_key.rsa().ok().map(|rsa| {
                    (
                        BASE64_STANDARD.encode(rsa.n().to_vec()),
                        BASE64_STANDARD.encode(rsa.e().to_vec()),
                    )
                })
            } else {
                None
            },
            key_info_profile,
        },
    )
}

/// Generate XMLDSig using a [`SigningKeyProvider`] for HSM/cloud-KMS integration.
///
/// This is the recommended API for new code. Pass a [`PemSigningKeyProvider`]
/// for in-memory keys, or any custom type implementing [`SigningKeyProvider`]
/// for HSM / cloud KMS backends.
pub fn generate_xmlsig_signature_with_provider(
    envelope_xml: &str,
    reference_uris: &[&str],
    external_references: &[(&str, &[u8])],
    provider: &dyn SigningKeyProvider,
    key_info_profile: WsSecOutboundKeyInfoProfile,
) -> Result<String> {
    // Validate inputs before any crypto operations.
    if reference_uris.is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "XMLDSig signature must contain at least one ds:Reference",
            ErrorContext::new("wssec_generate_signature"),
        ));
    }
    let algorithm = provider.preferred_algorithm();
    let cert_der = provider.certificate_der()?;

    // Extract RSA modulus/exponent from the DER-encoded certificate for
    // `ds:RSAKeyValue` interop (some partners require it alongside X509Data).
    let rsa_key_value = if matches!(
        algorithm,
        SignatureAlgorithm::RsaSha256
            | SignatureAlgorithm::RsaSha384
            | SignatureAlgorithm::RsaSha512
    ) {
        openssl::x509::X509::from_der(&cert_der)
            .ok()
            .and_then(|cert| cert.public_key().ok())
            .and_then(|pk| pk.rsa().ok())
            .map(|rsa| {
                (
                    BASE64_STANDARD.encode(rsa.n().to_vec()),
                    BASE64_STANDARD.encode(rsa.e().to_vec()),
                )
            })
    } else {
        None
    };

    generate_xmlsig_signature_core(
        envelope_xml,
        reference_uris,
        external_references,
        |data| provider.sign(data, algorithm),
        || Ok(cert_der.clone()),
        XmlSigKeyParams {
            algorithm,
            rsa_key_value,
            key_info_profile,
        },
    )
}

/// Core XMLDSig generation with pluggable sign / cert-der callbacks.
///
/// All public variants funnel through here so the formatting logic is written
/// exactly once.
///
/// `key_params` bundles the non-closure key metadata (algorithm, RSA key value
/// components, and KeyInfo profile) so the argument count stays below the
/// `too_many_arguments` threshold while preserving the HRTB flexibility needed
/// for closure `sign_fn` and `cert_der_fn`.
struct XmlSigKeyParams {
    algorithm: SignatureAlgorithm,
    rsa_key_value: Option<(String, String)>,
    key_info_profile: WsSecOutboundKeyInfoProfile,
}

fn generate_xmlsig_signature_core(
    envelope_xml: &str,
    reference_uris: &[&str],
    external_references: &[(&str, &[u8])],
    sign_fn: impl Fn(&[u8]) -> Result<Vec<u8>>,
    cert_der_fn: impl Fn() -> Result<Vec<u8>>,
    key_params: XmlSigKeyParams,
) -> Result<String> {
    let XmlSigKeyParams {
        algorithm,
        rsa_key_value,
        key_info_profile,
    } = key_params;
    if reference_uris.is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "XMLDSig signature must contain at least one ds:Reference",
            ErrorContext::new("wssec_generate_signature"),
        ));
    }

    let external_map: HashMap<&str, &[u8]> = external_references.iter().copied().collect();

    let mut references = Vec::with_capacity(reference_uris.len());
    for reference_uri in reference_uris {
        let reference = if reference_uri.starts_with("cid:") {
            let payload = external_map.get(reference_uri).copied().ok_or_else(|| {
                AsxError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "missing external reference bytes for URI {reference_uri}; \
                         include it in external_references"
                    ),
                    ErrorContext::new("wssec_generate_signature")
                        .with_message_id((*reference_uri).to_string()),
                )
            })?;
            let digest =
                openssl::hash::hash(algorithm.message_digest(), payload).map_err(|_err| {
                    AsxError::new(
                        ErrorCode::SecurityVerificationFailed,
                        "failed to digest external reference payload",
                        ErrorContext::new("wssec_generate_signature")
                            .with_message_id((*reference_uri).to_string()),
                    )
                })?;
            WsSecCanonicalizedReference {
                uri: (*reference_uri).to_string(),
                canonical_bytes: Vec::new(),
                digest_value_base64: BASE64_STANDARD.encode(digest),
            }
        } else {
            canonicalize_reference(
                envelope_xml,
                reference_uri,
                WsSecCanonicalizationProfile::default(),
            )?
        };
        references.push(reference);
    }

    let sig_algo_uri = algorithm.algorithm_uri();
    let signed_info_xml = build_signed_info_xml(&references, sig_algo_uri, XML_EXC_C14N_URI);
    let signed_info_c14n = canonicalize_signed_info_xml(&signed_info_xml)?;

    let signature_value = sign_fn(&signed_info_c14n)?;
    let signature_value_b64 = BASE64_STANDARD.encode(signature_value);

    let cert_der = cert_der_fn()?;
    let cert_der_b64 = BASE64_STANDARD.encode(cert_der);

    let key_info_xml = match key_info_profile {
        WsSecOutboundKeyInfoProfile::X509DataAndRsaKeyValue => {
            if let Some((modulus_b64, exponent_b64)) = rsa_key_value {
                format!(
                    "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>{}</ds:Modulus><ds:Exponent>{}</ds:Exponent></ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo>",
                    cert_der_b64, modulus_b64, exponent_b64
                )
            } else {
                // EC key — X509Data only (RFC 4051 §2.3: no ECKeyValue variant)
                format!(
                    "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
                    cert_der_b64
                )
            }
        }
        WsSecOutboundKeyInfoProfile::X509DataOnly => format!(
            "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
            cert_der_b64
        ),
    };

    Ok(format!(
        "<ds:Signature xmlns:ds=\"{}\">{}<ds:SignatureValue>{}</ds:SignatureValue>{}</ds:Signature>",
        DS_NS, signed_info_xml, signature_value_b64, key_info_xml
    ))
}
fn build_signed_info_xml(
    references: &[WsSecCanonicalizedReference],
    sig_algo_uri: &str,
    c14n_algo_uri: &str,
) -> String {
    // Build the Exclusive-C14N canonical form of ds:SignedInfo directly, without
    // the costly format-string → roxmltree-parse → serialize round-trip that was
    // previously used.
    //
    // The generated SignedInfo has a fixed, fully-determined structure:
    //   - `xmlns:ds` is declared on the root element and NOT re-declared on
    //     children (Exc-C14N §2: emit only when not inherited from a rendered
    //     ancestor).
    //   - Empty elements in Canonical XML use explicit open + close tags, never
    //     the XML shorthand `<elem/>`.
    //   - Attributes are sorted lexicographically by (namespace-uri, local-name);
    //     since every child element here has exactly one attribute (`Algorithm`)
    //     with no namespace, this ordering is trivially satisfied.
    //   - All attribute values used here are algorithm URIs or base64 strings —
    //     they contain no characters (`&`, `<`, `"`, control chars) that require
    //     XML entity escaping.
    //
    // Correctness is verified by the `signed_info_canonical_bytes_match_roundtrip`
    // unit test below, which asserts that the output is byte-for-byte identical to
    // what the old `canonicalize_signed_info_xml` round-trip produced.
    let mut refs_xml = String::new();
    for reference in references {
        refs_xml.push_str(&format!(
            "<ds:Reference URI=\"{uri}\"\
><ds:DigestMethod Algorithm=\"{dig}\"\
></ds:DigestMethod\
><ds:DigestValue>{val}</ds:DigestValue\
></ds:Reference>",
            uri = reference.uri,
            dig = SHA256_URI,
            val = reference.digest_value_base64
        ));
    }

    format!(
        "<ds:SignedInfo xmlns:ds=\"{ns}\"\
><ds:CanonicalizationMethod Algorithm=\"{c14n}\"\
></ds:CanonicalizationMethod\
><ds:SignatureMethod Algorithm=\"{sig}\"\
></ds:SignatureMethod\
>{refs}\
</ds:SignedInfo>",
        ns = DS_NS,
        c14n = c14n_algo_uri,
        sig = sig_algo_uri,
        refs = refs_xml
    )
}

/// Return the Exclusive C14N bytes of the given `signed_info_xml` string.
///
/// The caller (`generate_xmlsig_signature`) already produces a canonical
/// `signed_info_xml` via `build_signed_info_xml`.  This function exists as a
/// named boundary so the call chain is easy to follow and so the unit test can
/// verify correctness independently.
pub(crate) fn canonicalize_signed_info_xml(signed_info_xml: &str) -> Result<Vec<u8>> {
    // `build_signed_info_xml` already produces Exc-C14N bytes — return them
    // directly.  The previous approach (format → roxmltree parse → serialize)
    // was eliminated because the output structure is fully deterministic and
    // the round-trip added one heap allocation and one XML parse per signing
    // operation with no correctness benefit.
    Ok(signed_info_xml.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::super::canonicalize::{is_ds_element, try_serialize_node};
    use super::*;
    use crate::crypto::wssec::RSA_SHA256_URI;
    use std::collections::BTreeMap;

    /// Verify that `build_signed_info_xml` + trivial `.as_bytes()` produces
    /// byte-for-byte identical output to the old `roxmltree`-based round-trip
    /// that was previously inside `canonicalize_signed_info_xml`.
    ///
    /// This test is the correctness guard that justifies the elimination of the
    /// format→parse→serialize round-trip (P-R5 fix).
    #[test]
    fn signed_info_canonical_bytes_match_roundtrip() {
        use roxmltree::Document;

        let digest_b64 = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        let reference = WsSecCanonicalizedReference {
            uri: "#as4-message-id".to_string(),
            canonical_bytes: b"dummy".to_vec(),
            digest_value_base64: digest_b64.to_string(),
        };

        // New direct path.
        let references = vec![reference];
        let direct_xml = build_signed_info_xml(&references, RSA_SHA256_URI, XML_EXC_C14N_URI);
        let direct_bytes = canonicalize_signed_info_xml(&direct_xml).unwrap();

        // Old round-trip path (kept here for comparison only).
        let old_format = format!(
            "<ds:SignedInfo xmlns:ds=\"{ns}\"><ds:CanonicalizationMethod Algorithm=\"{c14n}\"/><ds:SignatureMethod Algorithm=\"{sig}\"/><ds:Reference URI=\"{uri}\"><ds:DigestMethod Algorithm=\"{dig}\"/><ds:DigestValue>{val}</ds:DigestValue></ds:Reference></ds:SignedInfo>",
            ns = DS_NS,
            c14n = XML_EXC_C14N_URI,
            sig = RSA_SHA256_URI,
            uri = "#as4-message-id",
            dig = SHA256_URI,
            val = digest_b64
        );
        let wrapped = format!("<root xmlns:ds=\"{}\">{}</root>", DS_NS, old_format);
        let doc = Document::parse(&wrapped).unwrap();
        let signed_info_node = doc
            .descendants()
            .find(|n| n.is_element() && is_ds_element(*n, "SignedInfo"))
            .unwrap();
        let mut old_c14n = String::new();
        try_serialize_node(
            signed_info_node,
            &mut old_c14n,
            &WsSecCanonicalizationProfile::default(),
            &BTreeMap::new(),
        )
        .expect("serialize signed info");
        let old_bytes = old_c14n.into_bytes();

        assert_eq!(
            direct_bytes,
            old_bytes,
            "direct SignedInfo bytes must be identical to round-trip output;\
             \n  direct: {}\n  roundtrip: {}",
            String::from_utf8_lossy(&direct_bytes),
            String::from_utf8_lossy(&old_bytes),
        );
    }

    #[test]
    fn signed_info_contains_all_references() {
        let references = vec![
            WsSecCanonicalizedReference {
                uri: "#as4-message-id".to_string(),
                canonical_bytes: Vec::new(),
                digest_value_base64: "a".to_string(),
            },
            WsSecCanonicalizedReference {
                uri: "#as4-body".to_string(),
                canonical_bytes: Vec::new(),
                digest_value_base64: "b".to_string(),
            },
        ];

        let signed_info = build_signed_info_xml(&references, RSA_SHA256_URI, XML_EXC_C14N_URI);
        assert!(signed_info.contains("<ds:Reference URI=\"#as4-message-id\""));
        assert!(signed_info.contains("<ds:Reference URI=\"#as4-body\""));
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
}
