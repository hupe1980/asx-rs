use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use openssl::hash::MessageDigest;
use openssl::sign::Verifier as OsslVerifier;
use roxmltree::Document;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};

#[cfg(test)]
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
    RSA_SHA512_URI, XML_EXC_C14N_URI, XML_INC_C14N_URI,
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

        let (c14n_kind, inclusive_ns_prefixes) = parse_reference_transform_profile(node, uri)?;

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
/// Resolution order:
/// 1. If exactly one `ds:Signature` is present anywhere in the document → use it.
/// 2. If multiple `ds:Signature` elements are present, prefer the first one that
///    is a direct child of a `wsse:Security` element (the AS4/WS-Security primary
///    signature).  This gracefully handles gateways that produce dual-signing
///    (e.g. an application-layer counter-signature alongside the transport signature).
/// 3. If none of the above resolves to a single candidate, fall back to the first
///    `ds:Signature` found in document order.
///
/// Returns `Ok(None)` when no `ds:Signature` is present at all.
fn find_single_signature_node<'a>(
    doc: &'a Document<'a>,
    _stage: &'static str,
) -> Result<Option<roxmltree::Node<'a, 'a>>> {
    let all: Vec<_> = doc
        .descendants()
        .filter(|n| n.is_element() && is_ds_element(*n, "Signature"))
        .collect();

    match all.len() {
        0 => Ok(None),
        1 => Ok(Some(all[0])),
        _ => {
            // Prefer the first ds:Signature that is a direct child of wsse:Security.
            let preferred = all.iter().find(|sig| {
                sig.parent().is_some_and(|p| {
                    p.is_element()
                        && p.tag_name().name() == "Security"
                        && p.tag_name().namespace() == Some(WSSE_NS)
                })
            });
            Ok(Some(*preferred.unwrap_or(&all[0])))
        }
    }
}

/// Parse the `exc-c14n:InclusiveNamespaces/@PrefixList` from the `<ds:Transforms>`
/// of a `<ds:Reference>` element.
///
/// Accepts both the Exclusive C14N (`http://www.w3.org/2001/10/xml-exc-c14n#`) and
/// the Inclusive C14N (`http://www.w3.org/TR/2001/REC-xml-c14n-20010315`) transform
/// algorithms.  Any other transform algorithm causes an `InteropViolation` error.
///
/// Returns the inclusive prefix list (empty for Inclusive C14N which has no such
/// concept, and the common case of Exclusive C14N without an InclusiveNamespaces element).
fn parse_reference_transform_profile(
    reference: roxmltree::Node<'_, '_>,
    uri: &str,
) -> Result<(WsSecCanonicalizationKind, Vec<String>)> {
    const EXC_C14N_NS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
    const INCLUSIVE_NS_LOCAL: &str = "InclusiveNamespaces";

    let transforms = reference
        .children()
        .find(|n| n.is_element() && is_ds_element(*n, "Transforms"));

    let Some(transforms) = transforms else {
        return Ok((WsSecCanonicalizationKind::Exclusive, Vec::new()));
    };

    let mut c14n_kind = WsSecCanonicalizationKind::Exclusive;
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

/// Outcome of a successful WS-Security signature verification: the set of
/// same-document element `Id`s (`wsu:Id`/`xml:id`) whose digests were verified.
///
/// The AS4 receive layer uses this to defend against XML Signature Wrapping:
/// it requires that the `eb:Messaging` element it actually consumes is one of
/// these signed ids, so an attacker cannot relocate the signed element and feed
/// the parser an unsigned, injected one.
#[cfg(feature = "as4")]
#[derive(Debug, Clone)]
pub(crate) struct VerifiedSignatureCoverage {
    /// `Id` values of same-document (`#...`) references that verified.
    pub signed_same_document_ids: Vec<String>,
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

    // Collect the same-document reference ids *before* consuming `parsed`; these
    // are only trustworthy once verification below succeeds.
    let signed_same_document_ids: Vec<String> = parsed
        .references
        .iter()
        .filter_map(|r| match r.parsed_uri {
            ParsedReferenceUri::SameDocument { target_id } => Some(target_id.to_string()),
            ParsedReferenceUri::Cid { .. } => None,
        })
        .collect();

    verify_enveloped_signature_with_parsed_signature_borrowed(doc, xml, parsed, opts)?;
    Ok(Some(VerifiedSignatureCoverage {
        signed_same_document_ids,
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
    if kind == WsSecCanonicalizationKind::Inclusive {
        updated.strip_blank_text = false;
    }
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
    let decoded = BASE64_STANDARD.decode(expected).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("invalid base64 DigestValue for reference {uri}: {err}"),
            ErrorContext::new("wssec_verify_references").with_message_id(uri.to_string()),
        )
    })?;
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

#[cfg(test)]
fn resolve_external_reference_bytes<'a>(
    uri: &str,
    external_references: &'a [(&str, &'a [u8])],
) -> Option<&'a [u8]> {
    let wanted_normalized_cid = normalize_cid_uri(uri);
    external_references
        .iter()
        .find(|(candidate_uri, _)| normalize_cid_uri(candidate_uri) == wanted_normalized_cid)
        .map(|(_, bytes)| *bytes)
}

fn verify_signature_value_with_components(
    mat: ParsedWsSecSignatureMaterialBorrowed<'_>,
    profile: WsSecCanonicalizationProfile,
    expected_cert_fingerprint_sha256: Option<&str>,
    revocation_policy: &RevocationPolicy<'_>,
) -> Result<()> {
    let ParsedWsSecSignatureMaterialBorrowed {
        signed_info,
        signature_value,
        signature_method_algorithm,
        rsa_modulus,
        rsa_exponent,
        x509_certificates_der,
    } = mat;
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

    let signer_cert_der = x509_certificates_der.first().map(Vec::as_slice);
    if let Some(cert_der) = signer_cert_der {
        validate_x509_certificate(cert_der)?;

        if let Some(expected) = expected_cert_fingerprint_sha256 {
            let expected = normalize_fingerprint(expected).ok_or_else(|| {
                AsxError::new(
                    ErrorCode::ParseFailed,
                    "expected certificate fingerprint is empty or invalid",
                    ErrorContext::new("wssec_verify_signature_value"),
                )
            })?;
            let actual = sha256_hex_lower(cert_der);
            if actual != expected {
                return Err(AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    "signer certificate fingerprint does not match expected fingerprint",
                    ErrorContext::new("wssec_verify_signature_value"),
                ));
            }
        }

        // RSA-only: validate that the inline ds:RSAKeyValue matches the certificate
        if is_rsa
            && let (Some(modulus), Some(exponent)) =
                (rsa_modulus.as_deref(), rsa_exponent.as_deref())
        {
            validate_cert_public_key_matches_rsa_keyvalue(cert_der, modulus, exponent)?;
        }

        if revocation_policy.require_chain_validation {
            validate_pkix_chain_and_revocation(&x509_certificates_der, revocation_policy)?;
        }
    } else if expected_cert_fingerprint_sha256.is_some()
        || revocation_policy.require_chain_validation
    {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "ds:Signature does not include an X509 certificate required for verification policy",
            ErrorContext::new("wssec_verify_signature_value"),
        ));
    }

    // Build a PKey from available material:
    // - ECDSA: always from certificate (no inline key value in XML)
    // - RSA: prefer inline ds:RSAKeyValue; fall back to certificate
    let pkey = if is_ecdsa {
        let cert_der = signer_cert_der.ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "ECDSA-SHA256 ds:Signature requires an X509 certificate in ds:KeyInfo",
                ErrorContext::new("wssec_verify_signature_value"),
            )
        })?;
        let cert = openssl::x509::X509::from_der(cert_der).map_err(|err| {
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
    } else if let (Some(modulus), Some(exponent)) =
        (rsa_modulus.as_deref(), rsa_exponent.as_deref())
    {
        pkey_from_rsa_components(modulus, exponent)?
    } else if let Some(cert_der) = signer_cert_der {
        let (modulus, exponent) = extract_rsa_keyvalue_from_cert(cert_der)?;
        pkey_from_rsa_components(&modulus, &exponent)?
    } else {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "ds:Signature missing both ds:RSAKeyValue and signer certificate",
            ErrorContext::new("wssec_verify_signature_value"),
        ));
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

#[cfg(test)]
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
        signature_value,
        signature_method_algorithm,
        rsa_modulus,
        rsa_exponent,
        x509_certificates_der,
    } = parse_signature_material_components_from_signature(doc, signature)?;

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

fn parse_signature_material_components_from_signature_with_signed_info<'a>(
    doc: &'a Document<'a>,
    signature: roxmltree::Node<'a, 'a>,
    signed_info: roxmltree::Node<'a, 'a>,
) -> Result<ParsedWsSecSignatureMaterialBorrowed<'a>> {
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
        let der = BASE64_STANDARD.decode(b64).map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("invalid base64 X509Certificate: {err}"),
                ErrorContext::new("wssec_signature_material"),
            )
        })?;
        x509_certificates_der.push(der);
    }

    if x509_certificates_der.is_empty()
        && let Some(pkipath_certs_der) =
            extract_x509_pkipath_certificates_from_security_token_reference(doc, key_info)?
    {
        x509_certificates_der = pkipath_certs_der;
    }

    let signature_value = BASE64_STANDARD.decode(signature_value_b64).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("invalid base64 SignatureValue: {err}"),
            ErrorContext::new("wssec_signature_material"),
        )
    })?;
    let rsa_modulus = match (modulus_b64, key_value) {
        (Some(v), _) => Some(BASE64_STANDARD.decode(v).map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("invalid base64 RSA modulus: {err}"),
                ErrorContext::new("wssec_signature_material"),
            )
        })?),
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
        (Some(v), _) => Some(BASE64_STANDARD.decode(v).map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("invalid base64 RSA exponent: {err}"),
                ErrorContext::new("wssec_signature_material"),
            )
        })?),
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
        signature_value,
        signature_method_algorithm,
        rsa_modulus,
        rsa_exponent,
        x509_certificates_der,
    })
}

fn extract_x509_pkipath_certificates_from_security_token_reference(
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
    if !referenced_value_type.ends_with(WSSE_X509_PKIPATHV1_VALUE_TYPE_SUFFIX) {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "wsse:SecurityTokenReference ValueType must be X509PKIPathv1",
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
    if !token_value_type.ends_with(WSSE_X509_PKIPATHV1_VALUE_TYPE_SUFFIX) {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "wsse:BinarySecurityToken ValueType must be X509PKIPathv1",
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

    let token_der = BASE64_STANDARD.decode(token_b64).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("invalid base64 wsse:BinarySecurityToken: {err}"),
            ErrorContext::new("wssec_signature_material"),
        )
    })?;

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

pub(crate) fn secure_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (lhs, rhs) in a.iter().zip(b.iter()) {
        diff |= lhs ^ rhs;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::{
        WsSecCanonicalizationProfile, WsSecDigestMethod, WsSecVerifyOptions,
        build_external_reference_cid_index, parse_signature_material_from_doc,
        parse_signature_references, resolve_external_reference_bytes, verify_enveloped_signature,
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

    #[test]
    fn verify_enveloped_signature_accepts_x509pkipathv1_binary_security_token() {
        let rsa = openssl::rsa::Rsa::generate(2048).expect("rsa");
        let pkey = PKey::from_rsa(rsa).expect("pkey");

        let mut name = openssl::x509::X509NameBuilder::new().expect("name builder");
        name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "asx-wssec-pkipath-test")
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
        let material = parse_signature_material_from_doc(
            &material_doc,
            WsSecCanonicalizationProfile::default(),
        )
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

    #[test]
    fn split_x509_pkipath_rejects_inner_length_overrun_without_panicking() {
        // Outer SEQUENCE (len 4) whose single inner element declares a 65535-byte
        // content length with zero bytes present. Before the bounds check this
        // sliced out of range and panicked the worker thread on attacker input.
        let malicious = [0x30u8, 0x04, 0x30, 0x82, 0xFF, 0xFF];
        let err = super::split_x509_pkipath_der_certificates(&malicious)
            .expect_err("over-declared inner DER length must be rejected, not panic");
        assert_eq!(err.code, crate::core::ErrorCode::ParseFailed);
    }

    #[test]
    fn resolve_external_reference_bytes_normalizes_cid_wrappers() {
        let alpha = b"alpha";
        let beta = b"beta";
        let refs: [(&str, &[u8]); 2] = [
            ("<payload@example.com>", alpha.as_slice()),
            ("cid:other@example.com", beta.as_slice()),
        ];

        let resolved = resolve_external_reference_bytes("cid:payload@example.com", &refs)
            .expect("cid URI should match angle-bracket wrapped candidate");
        assert_eq!(resolved, alpha.as_slice());

        let resolved = resolve_external_reference_bytes("CID:<payload@example.com>", &refs)
            .expect("CID + angle-bracket wrapped URI should normalize");
        assert_eq!(resolved, alpha.as_slice());

        let resolved = resolve_external_reference_bytes("<other@example.com>", &refs)
            .expect("angle-bracket URI should match cid-prefixed candidate");
        assert_eq!(resolved, beta.as_slice());
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

        let err = parse_signature_references(xml)
            .expect_err("unsupported transform child must fail closed");

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

        let err =
            parse_signature_references(xml).expect_err("unsupported URI scheme must fail closed");

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
}
