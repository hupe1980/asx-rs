use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use openssl::hash::MessageDigest;
use openssl::sign::Verifier as OsslVerifier;
use roxmltree::Document;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};

#[cfg(test)]
#[cfg(all(test, feature = "as4"))]
use super::WsSecSignatureMaterial;
use super::canonicalize::{
    SameDocumentReferenceIndex, canonicalize_reference_digest_from_doc_with_inclusive_ns_and_index,
    canonicalize_reference_digest_from_same_document_target_id_with_inclusive_ns, is_ds_element,
    normalize_same_document_uri, try_serialize_node,
};
use super::x509::{
    extract_rsa_keyvalue_from_cert, normalize_fingerprint, pkey_from_rsa_components,
    sha256_hex_lower, validate_cert_public_key_matches_rsa_keyvalue,
    validate_pkix_chain_and_revocation, validate_x509_certificate,
};
use super::{
    ECDSA_SHA256_URI, ECDSA_SHA384_URI, ECDSA_SHA512_URI, RSA_SHA256_URI, RSA_SHA384_URI,
    RSA_SHA512_URI, SWA_ATTACHMENT_CONTENT_TRANSFORM_URI, XML_EXC_C14N_URI, XML_INC_C14N_URI,
};
use super::{
    RevocationPolicy, WsSecCanonicalizationKind, WsSecCanonicalizationProfile, WsSecDigestMethod,
    WsSecSignatureReference,
};
use crate::core::{AsxError, ErrorCode, ErrorContext, OcspFailureMode, OcspMode, Result};

const WSSE_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
const WSU_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
const WSSE_X509_PKIPATHV1_VALUE_TYPE_SUFFIX: &str = "#X509PKIPathv1";
const WSSE_X509_V3_VALUE_TYPE_SUFFIX: &str = "#X509v3";

struct WsSecSignatureReferenceBorrowed<'a> {
    uri: &'a str,
    parsed_uri: ParsedReferenceUri<'a>,
    digest_method: WsSecDigestMethod,
    digest_value_base64: &'a str,
    /// Whether this reference's `<ds:Transform>` specifies Inclusive or Exclusive C14N.
    c14n_kind: WsSecCanonicalizationKind,
    /// Inclusive namespace prefixes (only applicable when `c14n_kind == Exclusive`).
    inclusive_ns_prefixes: Cow<'a, [String]>,
}

struct ParsedWsSecSignatureMaterialBorrowed<'a> {
    signed_info: roxmltree::Node<'a, 'a>,
    /// `InclusiveNamespaces/@PrefixList` declared on the
    /// `ds:SignedInfo/ds:CanonicalizationMethod`. Exc-C14N of `SignedInfo`
    /// itself must render these prefixes; WSS4J-based stacks (phase4, Domibus,
    /// Oxalis) routinely declare their SOAP envelope prefix here, and ignoring
    /// the list makes every such signature fail with a bare value mismatch.
    signed_info_inclusive_ns_prefixes: Vec<String>,
    signature_value: Vec<u8>,
    signature_method_algorithm: String,
    rsa_modulus: Option<Vec<u8>>,
    rsa_exponent: Option<Vec<u8>>,
    x509_certificates_der: Vec<Vec<u8>>,
}

struct ParsedWsSecSignatureEnvelopeBorrowed<'a> {
    references: Vec<WsSecSignatureReferenceBorrowed<'a>>,
    signature_material: ParsedWsSecSignatureMaterialBorrowed<'a>,
}

#[derive(Clone, Copy)]
enum ParsedReferenceUri<'a> {
    SameDocument { target_id: &'a str },
    Cid { normalized: &'a str },
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum ParsedReferenceDedupKey<'a> {
    SameDocument(&'a str),
    Cid(&'a str),
}

impl<'a> From<&ParsedReferenceUri<'a>> for ParsedReferenceDedupKey<'a> {
    fn from(value: &ParsedReferenceUri<'a>) -> Self {
        match value {
            ParsedReferenceUri::SameDocument { target_id } => Self::SameDocument(target_id),
            ParsedReferenceUri::Cid { normalized } => Self::Cid(normalized),
        }
    }
}

struct OsslVerifierFmtWriter<'a, 'b> {
    verifier: &'a mut OsslVerifier<'b>,
    write_error: Option<String>,
}

impl<'a, 'b> OsslVerifierFmtWriter<'a, 'b> {
    fn new(verifier: &'a mut OsslVerifier<'b>) -> Self {
        Self {
            verifier,
            write_error: None,
        }
    }

    fn write_error_message(self) -> String {
        self.write_error.unwrap_or_else(|| {
            "failed to stream canonicalized SignedInfo into XMLDSig verifier".to_string()
        })
    }
}

impl std::fmt::Write for OsslVerifierFmtWriter<'_, '_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.verifier.update(s.as_bytes()).map_err(|err| {
            self.write_error = Some(err.to_string());
            std::fmt::Error
        })
    }
}

pub fn parse_signature_references(xml: &str) -> Result<Vec<WsSecSignatureReference>> {
    let doc = parse_wssec_document(
        xml,
        "wssec_parse_references",
        "failed to parse XML while reading signature references",
    )?;

    parse_signature_references_from_doc(&doc)
}

fn parse_signature_references_from_doc(doc: &Document<'_>) -> Result<Vec<WsSecSignatureReference>> {
    parse_signature_references_from_doc_optional(doc)?.ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "no ds:Signature elements found",
            ErrorContext::new("wssec_parse_references"),
        )
    })
}

fn parse_signature_references_from_doc_optional(
    doc: &Document<'_>,
) -> Result<Option<Vec<WsSecSignatureReference>>> {
    parse_signature_references_from_doc_optional_borrowed(doc).map(|opt| {
        opt.map(|parsed| {
            parsed
                .into_iter()
                .map(|reference| WsSecSignatureReference {
                    uri: reference.uri.to_string(),
                    digest_method: reference.digest_method,
                    digest_value_base64: reference.digest_value_base64.to_string(),
                    c14n_kind: reference.c14n_kind,
                    inclusive_ns_prefixes: reference.inclusive_ns_prefixes.into_owned(),
                })
                .collect()
        })
    })
}

fn parse_signature_references_from_doc_optional_borrowed<'a>(
    doc: &'a Document<'a>,
) -> Result<Option<Vec<WsSecSignatureReferenceBorrowed<'a>>>> {
    let Some(signature) = find_single_signature_node(doc, "wssec_parse_references")? else {
        return Ok(None);
    };

    let signed_info = signature
        .children()
        .find(|n| n.is_element() && is_ds_element(*n, "SignedInfo"))
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "ds:Signature missing ds:SignedInfo",
                ErrorContext::new("wssec_parse_references"),
            )
        })?;

    signature
        .children()
        .find(|n| n.is_element() && is_ds_element(*n, "SignatureValue"))
        .and_then(|n| n.text())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "ds:Signature missing non-empty ds:SignatureValue",
                ErrorContext::new("wssec_parse_references"),
            )
        })?;

    Ok(Some(parse_signature_references_from_signed_info_borrowed(
        signed_info,
    )?))
}

fn parse_signature_envelope_from_doc_optional_borrowed<'a>(
    doc: &'a Document<'a>,
) -> Result<Option<ParsedWsSecSignatureEnvelopeBorrowed<'a>>> {
    let Some(signature) = find_single_signature_node(doc, "wssec_parse_references")? else {
        return Ok(None);
    };

    let signed_info = signature
        .children()
        .find(|n| n.is_element() && is_ds_element(*n, "SignedInfo"))
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "ds:Signature missing ds:SignedInfo",
                ErrorContext::new("wssec_parse_references"),
            )
        })?;
    let refs = parse_signature_references_from_signed_info_borrowed(signed_info)?;
    let signature_material = parse_signature_material_components_from_signature_with_signed_info(
        doc,
        signature,
        signed_info,
    )?;

    Ok(Some(ParsedWsSecSignatureEnvelopeBorrowed {
        references: refs,
        signature_material,
    }))
}

fn parse_signature_references_from_signed_info_borrowed<'a>(
    signed_info: roxmltree::Node<'a, 'a>,
) -> Result<Vec<WsSecSignatureReferenceBorrowed<'a>>> {
    let mut refs: Vec<WsSecSignatureReferenceBorrowed<'a>> = Vec::new();
    let mut seen_uris: HashSet<ParsedReferenceDedupKey<'a>> = HashSet::new();
    for node in signed_info
        .descendants()
        .filter(|n| n.is_element() && is_ds_element(*n, "Reference"))
    {
        let uri = node.attribute("URI").ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "Reference is missing required URI attribute",
                ErrorContext::new("wssec_parse_references"),
            )
        })?;

        let parsed_uri = parse_reference_uri(uri, "wssec_parse_references")?;
        let dedup_key = ParsedReferenceDedupKey::from(&parsed_uri);
        if !seen_uris.insert(dedup_key) {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                format!("duplicate or semantically equivalent ds:Reference URI found: {uri}"),
                ErrorContext::new("wssec_parse_references").with_message_id(uri.to_string()),
            ));
        }

        let (c14n_kind, inclusive_ns_prefixes) =
            parse_reference_transform_profile(node, uri, &parsed_uri)?;

        let digest_method_uri = node
            .children()
            .find(|n| n.is_element() && is_ds_element(*n, "DigestMethod"))
            .and_then(|n| n.attribute("Algorithm"))
            .ok_or_else(|| {
                AsxError::new(
                    ErrorCode::ParseFailed,
                    "Reference is missing DigestMethod/Algorithm",
                    ErrorContext::new("wssec_parse_references").with_message_id(uri.to_string()),
                )
            })?;

        let digest_value = node
            .children()
            .find(|n| n.is_element() && is_ds_element(*n, "DigestValue"))
            .and_then(|n| n.text())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AsxError::new(
                    ErrorCode::ParseFailed,
                    "Reference is missing non-empty DigestValue",
                    ErrorContext::new("wssec_parse_references").with_message_id(uri.to_string()),
                )
            })?;

        refs.push(WsSecSignatureReferenceBorrowed {
            uri,
            parsed_uri,
            digest_method: WsSecDigestMethod::from_algorithm_uri(digest_method_uri)?,
            digest_value_base64: digest_value,
            c14n_kind,
            inclusive_ns_prefixes: Cow::Owned(inclusive_ns_prefixes),
        });
    }

    if refs.is_empty() {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "no ds:Reference elements found under ds:SignedInfo",
            ErrorContext::new("wssec_parse_references"),
        ));
    }

    Ok(refs)
}

/// Return the single relevant `ds:Signature` node for WS-Security verification.
///
/// Resolution rules (fail-closed — an ambiguous document is rejected rather
/// than resolved by document order):
///
/// 1. Exactly one `ds:Signature` anywhere in the document → use it.
/// 2. Multiple `ds:Signature` elements, of which **exactly one** is a direct
///    child of a `wsse:Security` element → use that one (the AS4/WS-Security
///    primary signature).  This tolerates gateways that add an
///    application-layer counter-signature elsewhere in the document; the
///    counter-signature is not verified.
/// 3. Multiple `ds:Signature` elements directly inside `wsse:Security`, or
///    multiple signatures with none inside `wsse:Security` → error.  Silently
///    picking one by document order would let an attacker prepend a
///    signature-shaped element and steer which signature gets verified.
///
/// Returns `Ok(None)` when no `ds:Signature` is present at all.
fn find_single_signature_node<'a>(
    doc: &'a Document<'a>,
    stage: &'static str,
) -> Result<Option<roxmltree::Node<'a, 'a>>> {
    let all: Vec<_> = doc
        .descendants()
        .filter(|n| n.is_element() && is_ds_element(*n, "Signature"))
        .collect();

    match all.len() {
        0 => Ok(None),
        1 => Ok(Some(all[0])),
        _ => {
            let mut security_children = all.iter().filter(|sig| {
                sig.parent().is_some_and(|p| {
                    p.is_element()
                        && p.tag_name().name() == "Security"
                        && p.tag_name().namespace() == Some(WSSE_NS)
                })
            });
            match (security_children.next(), security_children.next()) {
                (Some(primary), None) => Ok(Some(*primary)),
                (Some(_), Some(_)) => Err(AsxError::new(
                    ErrorCode::InteropViolation,
                    "multiple ds:Signature elements inside wsse:Security; refusing to choose \
                     one — a document must carry exactly one WS-Security primary signature",
                    ErrorContext::new(stage),
                )),
                (None, _) => Err(AsxError::new(
                    ErrorCode::InteropViolation,
                    format!(
                        "{} ds:Signature elements found and none is a direct child of \
                         wsse:Security; refusing to resolve the ambiguity by document order",
                        all.len()
                    ),
                    ErrorContext::new(stage),
                )),
            }
        }
    }
}

/// The canonicalization a reference uses when it declares none.
///
/// XMLDSig §4.3.3.2: converting a node-set to the octet stream that gets
/// digested uses **Canonical XML** — the inclusive algorithm — unless a
/// transform says otherwise. Defaulting to exclusive instead computes a
/// different digest from the signer's whenever an ancestor declares a
/// namespace the subtree does not use, and reports a valid signature as a
/// forgery. (This is the verify-side counterpart of D2, which is why the
/// signing path *states* the exclusive algorithm rather than relying on a
/// default.)
///
/// A `cid:` reference dereferences to an octet stream, not a node-set, so no
/// canonicalization runs on it at all; the value returned for one is inert.
fn default_c14n_kind(parsed_uri: &ParsedReferenceUri<'_>) -> WsSecCanonicalizationKind {
    match parsed_uri {
        ParsedReferenceUri::Cid { .. } => WsSecCanonicalizationKind::Exclusive,
        _ => WsSecCanonicalizationKind::Inclusive,
    }
}

/// SwA transform that additionally covers selected MIME part headers.
/// Not supported — AS4 mandates the content-only transform.
const SWA_ATTACHMENT_COMPLETE_TRANSFORM_URI: &str = "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Complete-Signature-Transform";

/// Parse the `<ds:Transforms>` of a `<ds:Reference>` element.
///
/// For **same-document** (`#id`) references: accepts Exclusive C14N
/// (`http://www.w3.org/2001/10/xml-exc-c14n#`, optionally with an
/// `InclusiveNamespaces/@PrefixList`) and Inclusive C14N
/// (`http://www.w3.org/TR/2001/REC-xml-c14n-20010315`).
///
/// For **`cid:` attachment** references: accepts the WSS SwA profile
/// `Attachment-Content-Signature-Transform` (the digest input is the raw
/// attachment content, which is exactly what the verification path digests) and
/// the absence of any transform.  C14N transforms make no sense on an octet
/// stream and are rejected; the `Attachment-Complete-Signature-Transform`
/// (which folds MIME part headers into the digest) is not implemented and is
/// rejected by name.
///
/// Any other transform algorithm causes an `InteropViolation` error.
///
/// Returns the inclusive prefix list (empty for Inclusive C14N which has no such
/// concept, and the common case of Exclusive C14N without an InclusiveNamespaces element).
fn parse_reference_transform_profile(
    reference: roxmltree::Node<'_, '_>,
    uri: &str,
    parsed_uri: &ParsedReferenceUri<'_>,
) -> Result<(WsSecCanonicalizationKind, Vec<String>)> {
    const EXC_C14N_NS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
    const INCLUSIVE_NS_LOCAL: &str = "InclusiveNamespaces";

    let transforms = reference
        .children()
        .find(|n| n.is_element() && is_ds_element(*n, "Transforms"));

    let Some(transforms) = transforms else {
        // No transforms at all. What that means depends on what the URI
        // dereferences to.
        return Ok((default_c14n_kind(parsed_uri), Vec::new()));
    };

    if matches!(parsed_uri, ParsedReferenceUri::Cid { .. }) {
        // A cid: reference dereferences to an octet stream. The only transform
        // with defined semantics here is the SwA content transform, whose
        // digest input equals the raw attachment bytes we digest anyway.
        for transform in transforms
            .children()
            .filter(|n| n.is_element() && is_ds_element(*n, "Transform"))
        {
            let alg = transform.attribute("Algorithm").unwrap_or("");
            if alg == SWA_ATTACHMENT_CONTENT_TRANSFORM_URI {
                continue;
            }
            let detail = if alg == SWA_ATTACHMENT_COMPLETE_TRANSFORM_URI {
                "the Attachment-Complete-Signature-Transform (MIME headers included in the \
                 digest) is not supported; AS4 mandates the content-only transform"
            } else {
                "the only supported transform for attachment references is the WSS SwA \
                 Attachment-Content-Signature-Transform"
            };
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                format!(
                    "unsupported ds:Transform Algorithm \"{alg}\" on cid: Reference {uri}: {detail}"
                ),
                ErrorContext::new("wssec_parse_references").with_message_id(uri.to_string()),
            ));
        }
        return Ok((WsSecCanonicalizationKind::Exclusive, Vec::new()));
    }

    let mut c14n_kind = default_c14n_kind(parsed_uri);
    let mut inclusive_prefixes = Vec::new();
    for transform in transforms
        .children()
        .filter(|n| n.is_element() && is_ds_element(*n, "Transform"))
    {
        let alg = transform.attribute("Algorithm").unwrap_or("");
        if alg == XML_INC_C14N_URI {
            // Inclusive C14N has no InclusiveNamespaces child — the entire
            // in-scope namespace set is implicitly included.
            c14n_kind = WsSecCanonicalizationKind::Inclusive;
            continue;
        }
        if alg != XML_EXC_C14N_URI {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                format!(
                    "unsupported ds:Transform Algorithm \"{alg}\" in Reference {uri}; \
                     supported algorithms: Exclusive C14N ({XML_EXC_C14N_URI}) and \
                     Inclusive C14N ({XML_INC_C14N_URI})"
                ),
                ErrorContext::new("wssec_parse_references").with_message_id(uri.to_string()),
            ));
        }
        // Stated explicitly rather than left to the initializer: the default
        // for a reference that declares no transform is *inclusive*, so
        // "exclusive" has to be an assignment, not the absence of one.
        c14n_kind = WsSecCanonicalizationKind::Exclusive;
        for child in transform.children() {
            if !child.is_element() {
                continue;
            }
            let child_ns = child.tag_name().namespace().unwrap_or("");
            let child_local = child.tag_name().name();
            if child_ns == EXC_C14N_NS && child_local == INCLUSIVE_NS_LOCAL {
                if let Some(prefix_list) = child.attribute("PrefixList") {
                    for tok in prefix_list.split_ascii_whitespace() {
                        inclusive_prefixes.push(tok.to_string());
                    }
                }
            } else {
                return Err(AsxError::new(
                    ErrorCode::InteropViolation,
                    format!(
                        "unsupported child element {{{child_ns}}}{child_local} inside ds:Transform \
                         for Reference {uri}"
                    ),
                    ErrorContext::new("wssec_parse_references").with_message_id(uri.to_string()),
                ));
            }
        }
    }

    Ok((c14n_kind, inclusive_prefixes))
}

pub fn verify_signature_references_strict(
    xml: &str,
    references: &[WsSecSignatureReference],
) -> Result<()> {
    let profile = WsSecCanonicalizationProfile::default();
    verify_signature_references_with_profile(xml, references, &profile, &[])
}

/// Options for WS-Security signature verification.
///
/// Construct via `WsSecVerifyOptions::new()`, optionally chaining builder
/// methods before passing to [`verify_enveloped_signature`].
#[derive(Debug)]
pub struct WsSecVerifyOptions<'a> {
    pub(crate) expected_cert_fingerprint_sha256: Option<&'a str>,
    pub(crate) revocation_policy: RevocationPolicy<'a>,
    pub(crate) external_references: &'a [(&'a str, &'a [u8])],
}

impl<'a> WsSecVerifyOptions<'a> {
    /// Create options with strict fail-closed defaults.
    ///
    /// Callers should pass an explicit policy via `with_revocation(...)`
    /// sourced from session trust material before using in production receive
    /// paths.
    pub fn new() -> Self {
        Self {
            expected_cert_fingerprint_sha256: None,
            revocation_policy: RevocationPolicy {
                trust_anchor_pems: &[],
                revocation_crl_pems: &[],
                ocsp_mode: OcspMode::Disabled,
                ocsp_failure_mode: OcspFailureMode::HardFail,
                stapled_ocsp_responses_der: &[],
                responder_ocsp_responses_der: &[],
                // OCSP is disabled in the default; the namespace is not used for cache
                // operations.  Use `with_revocation(revocation_policy)` to supply a
                // session-scoped namespace and enable actual revocation checking.
                ocsp_cache_namespace: "default-ocsp-disabled",
                // Default: pure cryptographic verification only.  Callers that need
                // PKIX chain validation must supply trust anchors via `with_revocation`.
                require_chain_validation: false,
                pre_parsed_trust_anchors: None,
                pre_built_x509_store: None,
            },
            external_references: &[],
        }
    }

    /// Require the signing certificate to match this SHA-256 fingerprint.
    pub fn with_expected_fingerprint(mut self, fingerprint: Option<&'a str>) -> Self {
        self.expected_cert_fingerprint_sha256 = fingerprint;
        self
    }

    /// Apply PKIX chain validation and revocation checks.
    pub fn with_revocation(mut self, policy: RevocationPolicy<'a>) -> Self {
        self.revocation_policy = policy;
        self
    }

    /// Supply external MIME attachment bytes for `cid:` reference resolution.
    pub fn with_external_references(mut self, refs: &'a [(&'a str, &'a [u8])]) -> Self {
        self.external_references = refs;
        self
    }
}

impl<'a> Default for WsSecVerifyOptions<'a> {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify an enveloped WS-Security XMLDSig signature.
///
/// Returns `Ok(())` when strict verification passes.
#[cfg_attr(
    feature = "trace",
    tracing::instrument(skip_all, name = "wssec_verify_enveloped_signature")
)]
pub fn verify_enveloped_signature(xml: &str, opts: WsSecVerifyOptions<'_>) -> Result<()> {
    let doc = parse_wssec_document(
        xml,
        "wssec_verify",
        "failed to parse XML for wssec verification",
    )?;

    let parsed = parse_signature_envelope_from_doc_optional_borrowed(&doc)?.ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "no ds:Signature elements found",
            ErrorContext::new("wssec_parse_references"),
        )
    })?;
    verify_enveloped_signature_with_parsed_signature_borrowed(&doc, xml, parsed, opts)
}

/// Outcome of a successful WS-Security signature verification: everything the
/// signature was actually proven to cover.
///
/// The AS4 receive layer uses this twice:
///
/// - **XML Signature Wrapping** — it requires that the `eb:Messaging` element
///   it consumes is one of [`Self::signed_same_document_ids`], so an attacker
///   cannot relocate the signed element and feed the parser an unsigned,
///   injected one.
/// - **Attachment coverage** — it requires that the payload attachment it
///   surfaces is one of [`Self::signed_cid_references`]. Without this, a
///   signature covering only the header and body would let the payload — the
///   actual business document — be swapped in transit while the signature
///   still verified.
#[cfg(feature = "as4")]
#[derive(Debug, Clone)]
pub(crate) struct VerifiedSignatureCoverage {
    /// `Id` values of same-document (`#...`) references that verified.
    pub signed_same_document_ids: Vec<String>,
    /// Normalized Content-IDs of `cid:` references that verified (no `cid:`
    /// scheme prefix, no angle brackets).
    pub signed_cid_references: Vec<String>,
}

#[cfg(feature = "as4")]
pub(crate) fn verify_enveloped_signature_optional_with_doc(
    doc: &Document<'_>,
    xml: &str,
    opts: WsSecVerifyOptions<'_>,
) -> Result<Option<VerifiedSignatureCoverage>> {
    enforce_wssec_document_limits(
        xml,
        doc,
        "wssec_verify",
        "failed to parse XML for wssec verification",
    )?;

    let Some(parsed) = parse_signature_envelope_from_doc_optional_borrowed(doc)? else {
        return Ok(None);
    };

    // Collect the reference targets *before* consuming `parsed`; these are only
    // trustworthy once verification below succeeds.
    let mut signed_same_document_ids = Vec::new();
    let mut signed_cid_references = Vec::new();
    for reference in &parsed.references {
        match reference.parsed_uri {
            ParsedReferenceUri::SameDocument { target_id } => {
                signed_same_document_ids.push(target_id.to_string());
            }
            ParsedReferenceUri::Cid { normalized } => {
                signed_cid_references.push(normalized.to_string());
            }
        }
    }

    verify_enveloped_signature_with_parsed_signature_borrowed(doc, xml, parsed, opts)?;
    Ok(Some(VerifiedSignatureCoverage {
        signed_same_document_ids,
        signed_cid_references,
    }))
}

fn verify_enveloped_signature_with_parsed_signature_borrowed(
    doc: &Document<'_>,
    xml: &str,
    parsed: ParsedWsSecSignatureEnvelopeBorrowed<'_>,
    opts: WsSecVerifyOptions<'_>,
) -> Result<()> {
    let c14n_profile = WsSecCanonicalizationProfile::default();

    verify_signature_references_borrowed_with_profile(
        xml,
        &parsed.references,
        &c14n_profile,
        opts.external_references,
        Some(doc),
    )?;

    verify_signature_value_with_components(
        parsed.signature_material,
        c14n_profile,
        opts.expected_cert_fingerprint_sha256,
        &opts.revocation_policy,
    )
}

/// Maximum byte length accepted for WS-Security DOM parse.
///
/// This is an independent guard on the `roxmltree` DOM stage.  The streaming
/// pre-parse in `parser.rs` already limits to `MAX_XML_ELEMENTS = 10_000` but
/// does not constrain the raw byte size; a deeply nested document with few but
/// very large attribute values can still consume significant heap before the
/// element count is checked.  2 MiB is ≈ 200× a typical Peppol AS4 envelope.
const MAX_WSSEC_DOM_BYTES: usize = 2 * 1024 * 1024;

/// Maximum XML elements allowed in the WS-Security DOM tree.
///
/// Matches `MAX_XML_ELEMENTS` used in the quick-xml streaming pre-parse so
/// that both parse stages enforce a consistent limit.
const MAX_WSSEC_DOM_ELEMENTS: usize = 10_000;

fn parse_wssec_document<'a>(
    xml: &'a str,
    context: &'static str,
    message: &str,
) -> Result<Document<'a>> {
    if xml.len() > MAX_WSSEC_DOM_BYTES {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            format!(
                "{message}: XML input exceeds {} byte limit ({} bytes)",
                MAX_WSSEC_DOM_BYTES,
                xml.len()
            ),
            ErrorContext::new(context),
        ));
    }
    let doc = Document::parse(xml).map_err(|e| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("{message}: {e}"),
            ErrorContext::new(context),
        )
    })?;
    enforce_wssec_document_limits(xml, &doc, context, message)?;
    Ok(doc)
}

fn enforce_wssec_document_limits(
    xml: &str,
    doc: &Document<'_>,
    context: &'static str,
    message: &str,
) -> Result<()> {
    if xml.len() > MAX_WSSEC_DOM_BYTES {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            format!(
                "{message}: XML input exceeds {} byte limit ({} bytes)",
                MAX_WSSEC_DOM_BYTES,
                xml.len()
            ),
            ErrorContext::new(context),
        ));
    }

    // Bound counting to MAX+1 so oversized envelopes fail fast without a full
    // descendant walk just to compute an exact count above the threshold.
    let element_count = doc
        .root()
        .descendants()
        .filter(|n| n.is_element())
        .take(MAX_WSSEC_DOM_ELEMENTS + 1)
        .count();
    if element_count > MAX_WSSEC_DOM_ELEMENTS {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            format!(
                "{message}: XML element count {element_count} exceeds limit {MAX_WSSEC_DOM_ELEMENTS}"
            ),
            ErrorContext::new(context),
        ));
    }

    Ok(())
}

fn verify_signature_references_with_profile(
    xml: &str,
    references: &[WsSecSignatureReference],
    profile: &WsSecCanonicalizationProfile,
    external_references: &[(&str, &[u8])],
) -> Result<()> {
    let borrowed_references: Vec<WsSecSignatureReferenceBorrowed<'_>> = references
        .iter()
        .map(|r| {
            Ok(WsSecSignatureReferenceBorrowed {
                uri: r.uri.as_str(),
                parsed_uri: parse_reference_uri(&r.uri, "wssec_verify_references")?,
                digest_method: r.digest_method,
                digest_value_base64: r.digest_value_base64.as_str(),
                c14n_kind: r.c14n_kind,
                inclusive_ns_prefixes: Cow::Borrowed(&r.inclusive_ns_prefixes),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    verify_signature_references_borrowed_with_profile(
        xml,
        &borrowed_references,
        profile,
        external_references,
        None,
    )
}

fn verify_signature_references_borrowed_with_profile(
    xml: &str,
    references: &[WsSecSignatureReferenceBorrowed<'_>],
    profile: &WsSecCanonicalizationProfile,
    external_references: &[(&str, &[u8])],
    pre_parsed_doc: Option<&Document<'_>>,
) -> Result<()> {
    let external_reference_cid_index = if references
        .iter()
        .any(|r| matches!(r.parsed_uri, ParsedReferenceUri::Cid { .. }))
    {
        Some(build_external_reference_cid_index(external_references)?)
    } else {
        None
    };

    let same_doc_target_ids =
        collect_same_document_target_ids(references.iter().filter_map(|r| match r.parsed_uri {
            ParsedReferenceUri::SameDocument { target_id } => Some(target_id),
            ParsedReferenceUri::Cid { .. } => None,
        }));

    let mut owned_parsed_doc = None;
    if pre_parsed_doc.is_none() && !same_doc_target_ids.is_empty() {
        owned_parsed_doc = Some(parse_wssec_document(
            xml,
            "wssec_verify_references",
            "failed to parse XML for wssec reference verification",
        )?);
    }
    let parsed_doc = pre_parsed_doc.or(owned_parsed_doc.as_ref());
    let parsed_index = parsed_doc.map(|doc| {
        SameDocumentReferenceIndex::build_for_targets(doc, same_doc_target_ids.iter().copied())
    });

    let alternate_profile = references
        .iter()
        .find_map(|r| (r.c14n_kind != profile.kind).then_some(r.c14n_kind))
        .map(|kind| profile_with_c14n_kind(profile, kind));

    for reference in references {
        let per_ref_profile = if reference.c14n_kind == profile.kind {
            profile
        } else {
            alternate_profile.as_ref().ok_or_else(|| {
                AsxError::new(
                    ErrorCode::InteropViolation,
                    "missing alternate canonicalization profile for reference transform",
                    ErrorContext::new("wssec_verify_references"),
                )
            })?
        };

        let digest_ctx = ReferenceDigestCtx {
            profile: per_ref_profile,
            external_reference_cid_index: external_reference_cid_index.as_ref(),
            parsed_doc,
            parsed_index: parsed_index.as_ref(),
        };
        let computed_digest = compute_reference_digest(
            reference.uri,
            &reference.parsed_uri,
            reference.inclusive_ns_prefixes.as_ref(),
            &digest_ctx,
            reference.digest_method,
        )?;
        let expected_digest = decode_reference_digest_value(
            reference.uri,
            reference.digest_method,
            reference.digest_value_base64,
        )?;
        verify_reference_digest_matches(
            reference.uri,
            &expected_digest,
            reference.digest_value_base64,
            &computed_digest,
        )?;
    }

    Ok(())
}

fn profile_with_c14n_kind(
    profile: &WsSecCanonicalizationProfile,
    kind: WsSecCanonicalizationKind,
) -> WsSecCanonicalizationProfile {
    let mut updated = profile.clone();
    updated.kind = kind;
    updated
}

fn collect_same_document_target_ids<'a>(target_ids: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    let mut seen: HashSet<&'a str> = HashSet::new();
    let mut unique = Vec::new();
    for target_id in target_ids {
        if seen.insert(target_id) {
            unique.push(target_id);
        }
    }
    unique
}

/// Shared context passed to [`compute_reference_digest`].
///
/// Bundles the parameters that are constant across all references in one
/// `ds:SignedInfo` so each reference only needs to supply its own URI,
/// `ParsedReferenceUri`, and digest method.
struct ReferenceDigestCtx<'a> {
    profile: &'a WsSecCanonicalizationProfile,
    external_reference_cid_index: Option<&'a HashMap<&'a str, &'a [u8]>>,
    parsed_doc: Option<&'a Document<'a>>,
    parsed_index: Option<&'a SameDocumentReferenceIndex<'a>>,
}

fn compute_reference_digest<'a>(
    uri: &str,
    parsed_uri: &ParsedReferenceUri<'_>,
    inclusive_ns_prefixes: &[String],
    ctx: &ReferenceDigestCtx<'a>,
    digest_method: WsSecDigestMethod,
) -> Result<Vec<u8>> {
    if let ParsedReferenceUri::Cid { normalized } = parsed_uri {
        let payload = ctx
            .external_reference_cid_index
            .and_then(|idx| idx.get(*normalized).copied())
            .ok_or_else(|| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("missing external reference bytes required for URI {uri}"),
                    ErrorContext::new("wssec_verify_references").with_message_id(uri.to_string()),
                )
            })?;
        let md = match digest_method {
            WsSecDigestMethod::Sha256 => MessageDigest::sha256(),
            WsSecDigestMethod::Sha384 => MessageDigest::sha384(),
            WsSecDigestMethod::Sha512 => MessageDigest::sha512(),
        };
        let digest = openssl::hash::hash(md, payload).map_err(|_err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "failed to digest external reference payload",
                ErrorContext::new("wssec_verify_references").with_message_id(uri.to_string()),
            )
        })?;
        return Ok(digest.to_vec());
    }
    let target_id = match parsed_uri {
        ParsedReferenceUri::SameDocument { target_id } => *target_id,
        ParsedReferenceUri::Cid { .. } => {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                format!("unsupported ds:Reference URI scheme in strict mode: {uri}"),
                ErrorContext::new("wssec_verify_references").with_message_id(uri.to_string()),
            ));
        }
    };

    // Per W3C Exc-C14N §2.1: merge any per-reference InclusiveNamespaces
    // prefixes into the canonicalization profile for this reference only.
    let inclusive_override = if inclusive_ns_prefixes.is_empty() {
        None
    } else {
        Some(inclusive_ns_prefixes)
    };
    if let Some(index) = ctx.parsed_index {
        canonicalize_reference_digest_from_doc_with_inclusive_ns_and_index(
            index,
            uri,
            ctx.profile,
            inclusive_override,
            digest_method,
        )
    } else if let Some(doc) = ctx.parsed_doc {
        canonicalize_reference_digest_from_same_document_target_id_with_inclusive_ns(
            doc,
            uri,
            target_id,
            ctx.profile,
            inclusive_override,
            digest_method,
        )
    } else {
        Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!("same-document reference {uri} requires pre-parsed document/index"),
            ErrorContext::new("wssec_verify_references").with_message_id(uri.to_string()),
        ))
    }
}

fn build_external_reference_cid_index<'a>(
    external_references: &'a [(&'a str, &'a [u8])],
) -> Result<HashMap<&'a str, &'a [u8]>> {
    let mut by_normalized_cid: HashMap<&'a str, &'a [u8]> =
        HashMap::with_capacity(external_references.len());
    for (uri, payload) in external_references {
        let normalized = normalize_cid_uri(uri);
        if by_normalized_cid.insert(normalized, *payload).is_some() {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                format!(
                    "duplicate or semantically equivalent external cid reference provided: {uri}"
                ),
                ErrorContext::new("wssec_verify_references")
                    .with_message_id(normalized.to_string()),
            ));
        }
    }
    Ok(by_normalized_cid)
}

fn decode_reference_digest_value(
    uri: &str,
    digest_method: WsSecDigestMethod,
    expected: &str,
) -> Result<Vec<u8>> {
    let decoded = crate::core::decode_xml_base64(
        expected,
        &format!("DigestValue for reference {uri}"),
        "wssec_verify_references",
    )
    .map_err(|err| err.with_message_id(uri.to_string()))?;
    let expected_len = digest_method.output_len();
    if decoded.len() != expected_len {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            format!(
                "invalid DigestValue length for reference {uri}: expected {} bytes ({digest_method:?}), got {}",
                expected_len,
                decoded.len()
            ),
            ErrorContext::new("wssec_verify_references").with_message_id(uri.to_string()),
        ));
    }
    Ok(decoded)
}

fn verify_reference_digest_matches(
    uri: &str,
    expected: &[u8],
    expected_b64: &str,
    computed: &[u8],
) -> Result<()> {
    if secure_eq(computed, expected) {
        return Ok(());
    }

    let computed_b64 = BASE64_STANDARD.encode(computed);

    Err(AsxError::new(
        ErrorCode::SecurityVerificationFailed,
        format!(
            "digest mismatch for reference {uri} (expected {expected_b64}, computed {computed_b64})"
        ),
        ErrorContext::new("wssec_verify_references").with_message_id(uri.to_string()),
    ))
}

fn normalize_cid_uri(uri: &str) -> &str {
    uri.trim()
        .trim_start_matches("cid:")
        .trim_start_matches("CID:")
        .trim_start_matches('<')
        .trim_end_matches('>')
}

fn parse_reference_uri<'a>(uri: &'a str, stage: &'static str) -> Result<ParsedReferenceUri<'a>> {
    if uri.trim() != uri {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!("non-canonical ds:Reference URI with surrounding whitespace: {uri}"),
            ErrorContext::new(stage).with_message_id(uri.to_string()),
        ));
    }

    if is_cid_reference_uri(uri) {
        return Ok(ParsedReferenceUri::Cid {
            normalized: validate_cid_reference_uri(uri)?,
        });
    }

    if uri.starts_with('#') {
        let target_id = normalize_same_document_uri(uri).map_err(|_err| {
            AsxError::new(
                ErrorCode::InteropViolation,
                format!("invalid same-document reference URI in ds:Reference: {uri}"),
                ErrorContext::new(stage).with_message_id(uri.to_string()),
            )
        })?;
        return Ok(ParsedReferenceUri::SameDocument { target_id });
    }

    Err(AsxError::new(
        ErrorCode::InteropViolation,
        format!(
            "unsupported ds:Reference URI scheme in strict mode: {uri} (supported: same-document '#...' and cid:...)"
        ),
        ErrorContext::new(stage).with_message_id(uri.to_string()),
    ))
}

fn is_cid_reference_uri(uri: &str) -> bool {
    uri.starts_with("cid:") || uri.starts_with("CID:")
}

fn validate_cid_reference_uri(uri: &str) -> Result<&str> {
    let normalized = normalize_cid_uri(uri);
    if normalized.is_empty() {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!("empty cid reference URI is not allowed in strict mode: {uri}"),
            ErrorContext::new("wssec_parse_references").with_message_id(uri.to_string()),
        ));
    }
    if normalized.contains('%') {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!("percent-encoded cid reference URIs are not supported in strict mode: {uri}"),
            ErrorContext::new("wssec_parse_references").with_message_id(uri.to_string()),
        ));
    }
    if normalized.chars().any(char::is_whitespace) || normalized.chars().any(char::is_control) {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!("invalid whitespace/control characters in cid reference URI: {uri}"),
            ErrorContext::new("wssec_parse_references").with_message_id(uri.to_string()),
        ));
    }

    Ok(normalized)
}

fn verify_signature_value_with_components(
    mat: ParsedWsSecSignatureMaterialBorrowed<'_>,
    profile: WsSecCanonicalizationProfile,
    expected_cert_fingerprint_sha256: Option<&str>,
    revocation_policy: &RevocationPolicy<'_>,
) -> Result<()> {
    let ParsedWsSecSignatureMaterialBorrowed {
        signed_info,
        signed_info_inclusive_ns_prefixes,
        signature_value,
        signature_method_algorithm,
        rsa_modulus,
        rsa_exponent,
        x509_certificates_der,
    } = mat;
    // Exc-C14N of SignedInfo must honor the InclusiveNamespaces PrefixList the
    // signer declared on ds:CanonicalizationMethod — the listed prefixes are
    // part of the canonical bytes the signature was computed over.
    let mut profile = profile;
    profile.inclusive_ns_prefixes = signed_info_inclusive_ns_prefixes;
    let profile = profile;
    let is_rsa = signature_method_algorithm == RSA_SHA256_URI
        || signature_method_algorithm == RSA_SHA384_URI
        || signature_method_algorithm == RSA_SHA512_URI;
    let is_ecdsa = signature_method_algorithm == ECDSA_SHA256_URI
        || signature_method_algorithm == ECDSA_SHA384_URI
        || signature_method_algorithm == ECDSA_SHA512_URI;

    if !is_rsa && !is_ecdsa {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!(
                "unsupported SignatureMethod algorithm: {} \
                 (supported: RSA-SHA256/384/512, ECDSA-SHA256/384/512)",
                signature_method_algorithm
            ),
            ErrorContext::new("wssec_verify_signature_value"),
        ));
    }

    // A signature is only evidence of *identity* if the verifying key is bound
    // to a certificate. A bare `ds:KeyValue/ds:RSAKeyValue` is attacker-supplied
    // material: anyone can mint a key pair, sign the envelope, and inline the
    // public half, and the signature verifies while proving nothing. WS-Security
    // and the AS4 profile both carry the signer as an X.509 token, so require
    // one unconditionally rather than leaving it to caller policy.
    let signer_cert_der = x509_certificates_der
        .first()
        .map(Vec::as_slice)
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "ds:KeyInfo carries no X.509 certificate; a signature verified against an inline \
             ds:RSAKeyValue authenticates nobody. The signer must be identified by a \
             wsse:BinarySecurityToken or ds:X509Data/ds:X509Certificate",
                ErrorContext::new("wssec_verify_signature_value"),
            )
        })?;

    validate_x509_certificate(signer_cert_der)?;

    if let Some(expected) = expected_cert_fingerprint_sha256 {
        let expected = normalize_fingerprint(expected).ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "expected certificate fingerprint is empty or invalid",
                ErrorContext::new("wssec_verify_signature_value"),
            )
        })?;
        let actual = sha256_hex_lower(signer_cert_der);
        if actual != expected {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "signer certificate fingerprint does not match expected fingerprint",
                ErrorContext::new("wssec_verify_signature_value"),
            ));
        }
    }

    // An inline ds:RSAKeyValue is redundant with the certificate. It is not
    // trusted as a key source, but if a partner sends one it must agree with the
    // certificate — a mismatch means the two halves of KeyInfo disagree about
    // who signed, which is never benign.
    if is_rsa
        && let (Some(modulus), Some(exponent)) = (rsa_modulus.as_deref(), rsa_exponent.as_deref())
    {
        validate_cert_public_key_matches_rsa_keyvalue(signer_cert_der, modulus, exponent)?;
    }

    if revocation_policy.require_chain_validation {
        validate_pkix_chain_and_revocation(&x509_certificates_der, revocation_policy)?;
    }

    // The verifying key always comes from the certificate — the same object the
    // fingerprint pin and PKIX chain validation above were applied to. Deriving
    // it from anywhere else would let those checks and the actual verification
    // disagree about which key mattered.
    let pkey = if is_ecdsa {
        let cert = openssl::x509::X509::from_der(signer_cert_der).map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("failed to parse X509 certificate for ECDSA verification: {err}"),
                ErrorContext::new("wssec_verify_signature_value"),
            )
        })?;
        cert.public_key().map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!(
                    "failed to extract public key from certificate for ECDSA verification: {err}"
                ),
                ErrorContext::new("wssec_verify_signature_value"),
            )
        })?
    } else {
        let (modulus, exponent) = extract_rsa_keyvalue_from_cert(signer_cert_der)?;
        pkey_from_rsa_components(&modulus, &exponent)?
    };

    let digest = match signature_method_algorithm.as_str() {
        s if s == RSA_SHA384_URI || s == ECDSA_SHA384_URI => MessageDigest::sha384(),
        s if s == RSA_SHA512_URI || s == ECDSA_SHA512_URI => MessageDigest::sha512(),
        _ => MessageDigest::sha256(),
    };
    let mut verifier = OsslVerifier::new(digest, &pkey).map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to initialize XMLDSig verifier: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })?;

    {
        let mut verifier_out = OsslVerifierFmtWriter::new(&mut verifier);
        if try_serialize_node(signed_info, &mut verifier_out, &profile, &BTreeMap::new()).is_err() {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!(
                    "failed to feed SignedInfo into XMLDSig verifier: {}",
                    verifier_out.write_error_message()
                ),
                ErrorContext::new("wssec_verify_signature_value"),
            ));
        }
    }

    let verified = verifier.verify(&signature_value).map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("XMLDSig signature verification failed: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })?;

    if !verified {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "XMLDSig signature value did not verify",
            ErrorContext::new("wssec_verify_signature_value"),
        ));
    }

    Ok(())
}

#[cfg(all(test, feature = "as4"))]
pub(crate) fn parse_signature_material(
    xml: &str,
    profile: WsSecCanonicalizationProfile,
) -> Result<WsSecSignatureMaterial> {
    let doc = Document::parse(xml).map_err(|e| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("failed to parse XML for signature material: {e}"),
            ErrorContext::new("wssec_signature_material"),
        )
    })?;

    parse_signature_material_from_doc(&doc, profile)
}

#[cfg(test)]
fn parse_signature_material_from_doc(
    doc: &Document<'_>,
    profile: WsSecCanonicalizationProfile,
) -> Result<WsSecSignatureMaterial> {
    let signature = doc
        .descendants()
        .find(|n| n.is_element() && is_ds_element(*n, "Signature"))
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "no ds:Signature element found",
                ErrorContext::new("wssec_signature_material"),
            )
        })?;

    let ParsedWsSecSignatureMaterialBorrowed {
        signed_info,
        signed_info_inclusive_ns_prefixes,
        signature_value,
        signature_method_algorithm,
        rsa_modulus,
        rsa_exponent,
        x509_certificates_der,
    } = parse_signature_material_components_from_signature(doc, signature)?;

    let mut profile = profile;
    profile.inclusive_ns_prefixes = signed_info_inclusive_ns_prefixes;
    let mut signed_info_xml = String::new();
    try_serialize_node(
        signed_info,
        &mut signed_info_xml,
        &profile,
        &BTreeMap::new(),
    )
    .map_err(|_err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "failed to canonicalize SignedInfo for signature material",
            ErrorContext::new("wssec_signature_material"),
        )
    })?;

    Ok(WsSecSignatureMaterial {
        signed_info_c14n: signed_info_xml.into_bytes(),
        signature_value,
        signature_method_algorithm,
        rsa_modulus,
        rsa_exponent,
        x509_certificates_der,
    })
}

#[cfg(test)]
fn parse_signature_material_components_from_signature<'a>(
    doc: &'a Document<'a>,
    signature: roxmltree::Node<'a, 'a>,
) -> Result<ParsedWsSecSignatureMaterialBorrowed<'a>> {
    let signed_info = signature
        .children()
        .find(|n| n.is_element() && is_ds_element(*n, "SignedInfo"))
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "ds:Signature missing ds:SignedInfo",
                ErrorContext::new("wssec_signature_material"),
            )
        })?;

    parse_signature_material_components_from_signature_with_signed_info(doc, signature, signed_info)
}

/// Exclusive XML Canonicalization 1.0, with and without comments.
const EXC_C14N_URI: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const EXC_C14N_WITH_COMMENTS_URI: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

/// Require `ds:SignedInfo/ds:CanonicalizationMethod` to declare Exclusive C14N,
/// and return the `InclusiveNamespaces/@PrefixList` it carries (if any).
///
/// Verification canonicalizes `SignedInfo` with the exclusive profile, which
/// every AS4 profile (PEPPOL, CEF eDelivery, BDEW) mandates. The declared
/// algorithm is checked so a signature declaring Inclusive C14N is rejected at
/// the place that can name the mismatch, instead of failing later with an
/// opaque "signature value mismatch" that sends the operator hunting for a key
/// problem that does not exist.
///
/// The `InclusiveNamespaces/@PrefixList` child is **honored**, not ignored:
/// Exc-C14N §2.1 requires the listed prefixes to be rendered on the canonical
/// `SignedInfo` even when not visibly utilized, and WSS4J-based signers
/// (phase4, Domibus, Oxalis) declare their SOAP envelope prefix here by
/// default. Any other child element of `ds:CanonicalizationMethod` is rejected
/// — silently skipping a child that changes the canonical form would verify
/// under a different algorithm than the one declared.
///
/// Comment-preserving exclusive C14N is rejected for the same reason: the
/// canonicalizer strips comments, so accepting the `WithComments` URI would
/// mean verifying under a different algorithm than the one declared.
fn parse_signed_info_canonicalization_method(
    signed_info: roxmltree::Node<'_, '_>,
) -> Result<Vec<String>> {
    const EXC_C14N_NS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

    let method = signed_info
        .children()
        .find(|n| n.is_element() && is_ds_element(*n, "CanonicalizationMethod"))
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "ds:SignedInfo missing ds:CanonicalizationMethod",
                ErrorContext::new("wssec_signature_material"),
            )
        })?;

    let algorithm = method
        .attribute("Algorithm")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "ds:CanonicalizationMethod missing Algorithm attribute",
                ErrorContext::new("wssec_signature_material"),
            )
        })?;

    if algorithm != EXC_C14N_URI {
        let detail = if algorithm == EXC_C14N_WITH_COMMENTS_URI {
            "comment-preserving canonicalization is not supported"
        } else {
            "only Exclusive XML Canonicalization 1.0 is supported"
        };

        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!(
                "unsupported ds:CanonicalizationMethod Algorithm \"{algorithm}\": {detail} \
                 (expected \"{EXC_C14N_URI}\", as required by the AS4 profiles)"
            ),
            ErrorContext::new("wssec_signature_material").with_message_id(algorithm.to_string()),
        ));
    }

    let mut inclusive_prefixes = Vec::new();
    for child in method.children().filter(roxmltree::Node::is_element) {
        let child_ns = child.tag_name().namespace().unwrap_or("");
        let child_local = child.tag_name().name();
        if child_ns == EXC_C14N_NS && child_local == "InclusiveNamespaces" {
            if let Some(prefix_list) = child.attribute("PrefixList") {
                for tok in prefix_list.split_ascii_whitespace() {
                    inclusive_prefixes.push(tok.to_string());
                }
            }
        } else {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                format!(
                    "unsupported child element {{{child_ns}}}{child_local} inside \
                     ds:CanonicalizationMethod"
                ),
                ErrorContext::new("wssec_signature_material"),
            ));
        }
    }

    Ok(inclusive_prefixes)
}

fn parse_signature_material_components_from_signature_with_signed_info<'a>(
    doc: &'a Document<'a>,
    signature: roxmltree::Node<'a, 'a>,
    signed_info: roxmltree::Node<'a, 'a>,
) -> Result<ParsedWsSecSignatureMaterialBorrowed<'a>> {
    let signed_info_inclusive_ns_prefixes = parse_signed_info_canonicalization_method(signed_info)?;

    let signature_method_algorithm = signed_info
        .children()
        .find(|n| n.is_element() && is_ds_element(*n, "SignatureMethod"))
        .and_then(|n| n.attribute("Algorithm"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "ds:SignedInfo missing SignatureMethod/Algorithm",
                ErrorContext::new("wssec_signature_material"),
            )
        })?;

    let signature_value_b64 = signature
        .children()
        .find(|n| n.is_element() && is_ds_element(*n, "SignatureValue"))
        .and_then(|n| n.text())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "ds:Signature missing non-empty SignatureValue",
                ErrorContext::new("wssec_signature_material"),
            )
        })?;

    let key_info = signature
        .children()
        .find(|n| n.is_element() && is_ds_element(*n, "KeyInfo"))
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "ds:Signature missing ds:KeyInfo",
                ErrorContext::new("wssec_signature_material"),
            )
        })?;

    let key_value = key_info
        .descendants()
        .find(|n| n.is_element() && is_ds_element(*n, "RSAKeyValue"));

    let modulus_b64 = key_value
        .and_then(|n| {
            n.children()
                .find(|c| c.is_element() && is_ds_element(*c, "Modulus"))
                .and_then(|c| c.text())
        })
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let exponent_b64 = key_value
        .and_then(|n| {
            n.children()
                .find(|c| c.is_element() && is_ds_element(*c, "Exponent"))
                .and_then(|c| c.text())
        })
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let mut x509_certificates_der = Vec::new();
    for node in key_info
        .descendants()
        .filter(|n| n.is_element() && is_ds_element(*n, "X509Certificate"))
    {
        let b64 = node
            .text()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AsxError::new(
                    ErrorCode::ParseFailed,
                    "ds:X509Certificate must not be empty when present",
                    ErrorContext::new("wssec_signature_material"),
                )
            })?;
        let der =
            crate::core::decode_xml_base64(b64, "X509Certificate", "wssec_signature_material")?;
        x509_certificates_der.push(der);
    }

    if x509_certificates_der.is_empty()
        && let Some(token_certs_der) =
            extract_x509_certificates_from_security_token_reference(doc, key_info)?
    {
        x509_certificates_der = token_certs_der;
    }

    let signature_value = crate::core::decode_xml_base64(
        signature_value_b64,
        "SignatureValue",
        "wssec_signature_material",
    )?;
    let rsa_modulus = match (modulus_b64, key_value) {
        (Some(v), _) => Some(crate::core::decode_xml_base64(
            v,
            "RSA modulus",
            "wssec_signature_material",
        )?),
        (None, Some(_)) => {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                "ds:RSAKeyValue missing Modulus",
                ErrorContext::new("wssec_signature_material"),
            ));
        }
        (None, None) => None,
    };

    let rsa_exponent = match (exponent_b64, key_value) {
        (Some(v), _) => Some(crate::core::decode_xml_base64(
            v,
            "RSA exponent",
            "wssec_signature_material",
        )?),
        (None, Some(_)) => {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                "ds:RSAKeyValue missing Exponent",
                ErrorContext::new("wssec_signature_material"),
            ));
        }
        (None, None) => None,
    };

    Ok(ParsedWsSecSignatureMaterialBorrowed {
        signed_info,
        signed_info_inclusive_ns_prefixes,
        signature_value,
        signature_method_algorithm,
        rsa_modulus,
        rsa_exponent,
        x509_certificates_der,
    })
}

/// Resolve `ds:KeyInfo/wsse:SecurityTokenReference/wsse:Reference` to the
/// certificate(s) of the in-document `wsse:BinarySecurityToken` it points at.
///
/// Two token shapes are supported:
///
/// - **`#X509v3`** — a single DER certificate. This is the default KeyInfo
///   shape of WSS4J-based stacks (phase4, Domibus, Oxalis).
/// - **`#X509PKIPathv1`** — a DER `SEQUENCE` of certificates (leaf first).
///
/// Key-identifier styles that require out-of-document lookup
/// (`wsse:KeyIdentifier` with SKI/thumbprint, `ds:X509IssuerSerial`) are not
/// resolvable from the message alone and surface as errors upstream when no
/// certificate can be found.
fn extract_x509_certificates_from_security_token_reference(
    doc: &Document<'_>,
    key_info: roxmltree::Node<'_, '_>,
) -> Result<Option<Vec<Vec<u8>>>> {
    let Some(token_reference) = key_info.descendants().find(|node| {
        node.is_element()
            && node.tag_name().namespace() == Some(WSSE_NS)
            && node.tag_name().name() == "SecurityTokenReference"
    }) else {
        return Ok(None);
    };

    let token_ptr = token_reference
        .descendants()
        .find(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(WSSE_NS)
                && node.tag_name().name() == "Reference"
        })
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "wsse:SecurityTokenReference is missing wsse:Reference",
                ErrorContext::new("wssec_signature_material"),
            )
        })?;

    let uri = token_ptr.attribute("URI").ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "wsse:Reference is missing required URI attribute",
            ErrorContext::new("wssec_signature_material"),
        )
    })?;

    let referenced_value_type = token_ptr.attribute("ValueType").unwrap_or("");
    if !referenced_value_type.is_empty()
        && !referenced_value_type.ends_with(WSSE_X509_PKIPATHV1_VALUE_TYPE_SUFFIX)
        && !referenced_value_type.ends_with(WSSE_X509_V3_VALUE_TYPE_SUFFIX)
    {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            format!(
                "unsupported wsse:Reference ValueType \"{referenced_value_type}\" \
                 (supported: X509v3 and X509PKIPathv1)"
            ),
            ErrorContext::new("wssec_signature_material"),
        ));
    }

    let token_id = uri.strip_prefix('#').ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "wsse:Reference URI must be a same-document #token-id reference",
            ErrorContext::new("wssec_signature_material"),
        )
    })?;
    if token_id.is_empty() {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "wsse:Reference URI token-id must not be empty",
            ErrorContext::new("wssec_signature_material"),
        ));
    }

    let binary_token = doc
        .descendants()
        .find(|node| {
            if !(node.is_element()
                && node.tag_name().namespace() == Some(WSSE_NS)
                && node.tag_name().name() == "BinarySecurityToken")
            {
                return false;
            }
            node.attribute((WSU_NS, "Id"))
                .or_else(|| node.attribute("Id"))
                == Some(token_id)
        })
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "wsse:Reference points to missing wsse:BinarySecurityToken",
                ErrorContext::new("wssec_signature_material"),
            )
        })?;

    let token_value_type = binary_token.attribute("ValueType").unwrap_or("");
    let token_is_pkipath = token_value_type.ends_with(WSSE_X509_PKIPATHV1_VALUE_TYPE_SUFFIX);
    let token_is_x509v3 = token_value_type.ends_with(WSSE_X509_V3_VALUE_TYPE_SUFFIX);
    if !token_is_pkipath && !token_is_x509v3 {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            format!(
                "unsupported wsse:BinarySecurityToken ValueType \"{token_value_type}\" \
                 (supported: X509v3 and X509PKIPathv1)"
            ),
            ErrorContext::new("wssec_signature_material"),
        ));
    }

    let token_b64 = binary_token
        .text()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "wsse:BinarySecurityToken must not be empty",
                ErrorContext::new("wssec_signature_material"),
            )
        })?;

    let token_der = crate::core::decode_xml_base64(
        token_b64,
        "wsse:BinarySecurityToken",
        "wssec_signature_material",
    )?;

    if token_is_x509v3 {
        // Single DER certificate — the standard WSS4J/phase4/Domibus token
        // shape (`ValueType="...#X509v3"`). The chain, if any, must come from
        // configured trust material.
        return Ok(Some(vec![token_der]));
    }

    split_x509_pkipath_der_certificates(&token_der).map(Some)
}

fn split_x509_pkipath_der_certificates(pkipath_der: &[u8]) -> Result<Vec<Vec<u8>>> {
    let (seq_header_len, seq_content_len) =
        parse_der_header(pkipath_der, "wssec_signature_material")?;

    if pkipath_der[0] != 0x30 {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "X509PKIPathv1 token is not a DER SEQUENCE",
            ErrorContext::new("wssec_signature_material"),
        ));
    }

    if seq_header_len + seq_content_len != pkipath_der.len() {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "X509PKIPathv1 token has trailing bytes after DER SEQUENCE",
            ErrorContext::new("wssec_signature_material"),
        ));
    }

    let content = &pkipath_der[seq_header_len..];
    let mut cursor = 0usize;
    let mut certs = Vec::new();
    while cursor < content.len() {
        if content[cursor] != 0x30 {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                "X509PKIPathv1 contains a non-certificate DER element",
                ErrorContext::new("wssec_signature_material"),
            ));
        }
        let (header_len, value_len) =
            parse_der_header(&content[cursor..], "wssec_signature_material")?;
        let total_len = header_len + value_len;
        certs.push(content[cursor..cursor + total_len].to_vec());
        cursor += total_len;
    }

    if certs.is_empty() {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "X509PKIPathv1 token does not contain any certificates",
            ErrorContext::new("wssec_signature_material"),
        ));
    }

    Ok(certs)
}

fn parse_der_header(input: &[u8], stage: &'static str) -> Result<(usize, usize)> {
    if input.len() < 2 {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "invalid DER: missing tag/length",
            ErrorContext::new(stage),
        ));
    }

    let first_len = input[1];
    if first_len & 0x80 == 0 {
        return Ok((2, first_len as usize));
    }

    let len_octets = (first_len & 0x7F) as usize;
    if len_octets == 0 {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "invalid DER: indefinite length is not supported",
            ErrorContext::new(stage),
        ));
    }
    if len_octets > std::mem::size_of::<usize>() {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "invalid DER: length field is too large",
            ErrorContext::new(stage),
        ));
    }
    if input.len() < 2 + len_octets {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "invalid DER: truncated length field",
            ErrorContext::new(stage),
        ));
    }

    let mut value_len = 0usize;
    for byte in &input[2..2 + len_octets] {
        value_len = value_len
            .checked_mul(256)
            .and_then(|acc| acc.checked_add(*byte as usize))
            .ok_or_else(|| {
                AsxError::new(
                    ErrorCode::ParseFailed,
                    "invalid DER: overflow while reading length",
                    ErrorContext::new(stage),
                )
            })?;
    }

    let header_len = 2 + len_octets;
    // Reject a declared content length that does not fit within the remaining
    // buffer. Without this check a caller slicing `input[..header_len + value_len]`
    // (e.g. `split_x509_pkipath_der_certificates`) would index out of bounds and
    // panic on an attacker-supplied `wsse:BinarySecurityToken`, crashing the
    // worker thread before any trust decision is made.
    if value_len > input.len() - header_len {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "invalid DER: declared length exceeds available bytes",
            ErrorContext::new(stage),
        ));
    }
    Ok((header_len, value_len))
}

pub(crate) use crate::core::constant_time_eq as secure_eq;

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;

// ---------------------------------------------------------------------------
// Enveloped whole-document signatures (SMP `ServiceMetadata`)
// ---------------------------------------------------------------------------

/// XMLDSig enveloped-signature transform.
pub const ENVELOPED_SIGNATURE_URI: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// Outcome of a successful [`verify_enveloped_document_signature`].
#[derive(Debug, Clone)]
pub struct VerifiedEnvelopedSignature {
    /// SHA-256 fingerprint (lowercase hex) of the signing certificate.
    pub signer_fingerprint_sha256: String,
    /// DER of the signing certificate, as carried in `ds:KeyInfo/ds:X509Data`.
    pub signer_certificate_der: Vec<u8>,
}

/// Verify an **enveloped, whole-document** XML signature.
///
/// This is the shape used by SMP `ServiceMetadata` responses (and XML documents
/// generally): a single `ds:Signature` inside the document it signs, with one
/// `ds:Reference URI=""` covering the whole document and an
/// `enveloped-signature` transform removing the signature element itself.
///
/// AS4/WS-Security never uses this form — it references specific elements by
/// `wsu:Id` — which is why it lives beside, rather than inside,
/// [`verify_enveloped_signature`].
///
/// The signing certificate is chain-validated against `revocation_policy`, so
/// callers must supply the network's SMP CA as a trust anchor. Passing an empty
/// anchor set with `require_chain_validation` fails closed.
///
/// # Errors
///
/// - [`ErrorCode::SecurityVerificationFailed`] — no signature, digest
///   mismatch, bad signature value, or an untrusted certificate.
/// - [`ErrorCode::InteropViolation`] — a reference shape this function does not
///   implement (non-empty `URI`, missing enveloped-signature transform).
pub fn verify_enveloped_document_signature(
    xml: &str,
    expected_cert_fingerprint_sha256: Option<&str>,
    revocation_policy: &RevocationPolicy<'_>,
) -> Result<VerifiedEnvelopedSignature> {
    let doc = parse_wssec_document(
        xml,
        "wssec_verify_enveloped",
        "failed to parse XML for enveloped signature verification",
    )?;
    enforce_wssec_document_limits(
        xml,
        &doc,
        "wssec_verify_enveloped",
        "failed to parse XML for enveloped signature verification",
    )?;

    let signature =
        find_single_signature_node(&doc, "wssec_verify_enveloped")?.ok_or_else(|| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "document carries no ds:Signature",
                ErrorContext::new("wssec_verify_enveloped"),
            )
        })?;

    let signed_info = signature
        .children()
        .find(|n| n.is_element() && is_ds_element(*n, "SignedInfo"))
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "ds:Signature missing ds:SignedInfo",
                ErrorContext::new("wssec_verify_enveloped"),
            )
        })?;

    let material = parse_signature_material_components_from_signature_with_signed_info(
        &doc,
        signature,
        signed_info,
    )?;

    // Digest every reference before touching the signature value.
    let mut reference_count = 0usize;
    for reference in signed_info
        .children()
        .filter(|n| n.is_element() && is_ds_element(*n, "Reference"))
    {
        reference_count += 1;
        verify_enveloped_reference(&doc, signature, reference)?;
    }

    if reference_count == 0 {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "ds:SignedInfo contains no ds:Reference",
            ErrorContext::new("wssec_verify_enveloped"),
        ));
    }

    let signer_certificate_der =
        material
            .x509_certificates_der
            .first()
            .cloned()
            .ok_or_else(|| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    "ds:KeyInfo must carry ds:X509Data/ds:X509Certificate so the signer can be \
                 chained to a trust anchor",
                    ErrorContext::new("wssec_verify_enveloped"),
                )
            })?;

    verify_signature_value_with_components(
        material,
        WsSecCanonicalizationProfile::default(),
        expected_cert_fingerprint_sha256,
        revocation_policy,
    )?;

    Ok(VerifiedEnvelopedSignature {
        signer_fingerprint_sha256: super::x509::sha256_hex_lower(&signer_certificate_der),
        signer_certificate_der,
    })
}

/// Check one `URI=""` + enveloped-signature reference.
fn verify_enveloped_reference(
    doc: &Document<'_>,
    signature: roxmltree::Node<'_, '_>,
    reference: roxmltree::Node<'_, '_>,
) -> Result<()> {
    let uri = reference.attribute("URI").unwrap_or("");
    if !uri.is_empty() {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!(
                "enveloped document signatures support only the whole-document \
                 reference URI=\"\", got \"{uri}\""
            ),
            ErrorContext::new("wssec_verify_enveloped").with_message_id(uri.to_string()),
        ));
    }

    let mut saw_enveloped = false;
    // XMLDSig §4.3.3.2 again: the enveloped-signature transform yields a
    // node-set, and turning that into octets uses inclusive Canonical XML
    // unless a further transform names another algorithm.
    let mut c14n_kind = WsSecCanonicalizationKind::Inclusive;
    if let Some(transforms) = reference
        .children()
        .find(|n| n.is_element() && is_ds_element(*n, "Transforms"))
    {
        for transform in transforms
            .children()
            .filter(|n| n.is_element() && is_ds_element(*n, "Transform"))
        {
            match transform.attribute("Algorithm").unwrap_or("") {
                ENVELOPED_SIGNATURE_URI => saw_enveloped = true,
                XML_EXC_C14N_URI => c14n_kind = WsSecCanonicalizationKind::Exclusive,
                XML_INC_C14N_URI => c14n_kind = WsSecCanonicalizationKind::Inclusive,
                other => {
                    return Err(AsxError::new(
                        ErrorCode::InteropViolation,
                        format!(
                            "unsupported ds:Transform Algorithm \"{other}\" on a URI=\"\" reference"
                        ),
                        ErrorContext::new("wssec_verify_enveloped"),
                    ));
                }
            }
        }
    }

    if !saw_enveloped {
        // Without it the signature would have to contain its own digest.
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!("a URI=\"\" reference must declare the {ENVELOPED_SIGNATURE_URI} transform"),
            ErrorContext::new("wssec_verify_enveloped"),
        ));
    }

    let expected = reference
        .children()
        .find(|n| n.is_element() && is_ds_element(*n, "DigestValue"))
        .and_then(|n| n.text())
        .map(str::trim)
        .unwrap_or_default();

    let profile = WsSecCanonicalizationProfile {
        kind: c14n_kind,
        ..WsSecCanonicalizationProfile::default()
    };
    let actual = super::canonicalize::canonicalize_enveloped_document(doc, &profile, signature)?;

    if !super::x509::secure_eq(actual.digest_value_base64.as_bytes(), expected.as_bytes()) {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "enveloped document digest mismatch: the document was modified after signing",
            ErrorContext::new("wssec_verify_enveloped"),
        ));
    }

    Ok(())
}
