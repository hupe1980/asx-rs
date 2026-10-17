use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
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
    ValidatedChain, extract_rsa_keyvalue_from_cert, pkey_from_rsa_components,
    validate_cert_public_key_matches_rsa_keyvalue, validate_chain_offline,
    validate_x509_certificate,
};
use super::{
    ChainPolicy, WsSecCanonicalizationKind, WsSecCanonicalizationProfile, WsSecDigestMethod,
    WsSecSignatureReference,
};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::crypto::alg::{KeyFamily, TransformAlg};
use crate::crypto::signing::SignatureAlgorithm;

const WSSE_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
const WSU_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
/// Namespace of `ec:InclusiveNamespaces` (Exc-C14N §3).
const EXC_C14N_NS: &str = crate::xml::ns::EXC_C14N;
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
    signed_info_c14n_kind: WsSecCanonicalizationKind,
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
    /// The `wsse:Security` header that contains the primary `ds:Signature`,
    /// when the signature sits directly inside one.
    security_header: Option<roxmltree::Node<'a, 'a>>,
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
        crate::xml::XmlLimits::ENVELOPE,
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
        SignedDocClass::UserMessage,
    )?))
}

fn parse_signature_envelope_from_doc_optional_borrowed<'a>(
    doc: &'a Document<'a>,
    class: SignedDocClass,
) -> Result<Option<ParsedWsSecSignatureEnvelopeBorrowed<'a>>> {
    let Some(signature) = find_single_signature_node(doc, "wssec_parse_references")? else {
        return Ok(None);
    };

    // In a SOAP envelope the primary signature is a
    // WS-Security header entry — a direct child of wsse:Security — and
    // nowhere else.
    let root = doc.root_element();
    let soap = matches!(
        root.tag_name().namespace(),
        Some(crate::xml::ns::SOAP12 | crate::xml::ns::SOAP11)
    ) && root.tag_name().name() == "Envelope";
    let in_security = signature.parent().is_some_and(|p| {
        p.is_element()
            && p.tag_name().name() == "Security"
            && p.tag_name().namespace() == Some(WSSE_NS)
    });
    if soap && !in_security {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "the ds:Signature of a SOAP envelope must be a direct child of a wsse:Security \
             header block; a signature elsewhere is not a WS-Security signature",
            ErrorContext::new("wssec_parse_references"),
        ));
    }

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
    let refs = parse_signature_references_from_signed_info_borrowed(signed_info, class)?;
    let signature_material = parse_signature_material_components_from_signature_with_signed_info(
        doc,
        signature,
        signed_info,
    )?;

    let security_header = signature.parent().filter(|p| {
        p.is_element()
            && p.tag_name().name() == "Security"
            && p.tag_name().namespace() == Some(WSSE_NS)
    });

    Ok(Some(ParsedWsSecSignatureEnvelopeBorrowed {
        references: refs,
        signature_material,
        security_header,
    }))
}

fn parse_signature_references_from_signed_info_borrowed<'a>(
    signed_info: roxmltree::Node<'a, 'a>,
    class: SignedDocClass,
) -> Result<Vec<WsSecSignatureReferenceBorrowed<'a>>> {
    enforce_reference_cap(signed_info, class)?;
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

        enforce_transform_cap(node, uri)?;
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

/// At most `class.max_references()` `ds:Reference`s, counted
/// before any is parsed, digested or trusted (W3C XMLDSig Best Practices BP 9).
fn enforce_reference_cap(
    signed_info: roxmltree::Node<'_, '_>,
    class: SignedDocClass,
) -> Result<()> {
    let count = signed_info
        .descendants()
        .filter(|n| n.is_element() && is_ds_element(*n, "Reference"))
        .count();
    if count > class.max_references() {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!(
                "{count} ds:Reference elements exceed the cap of {} for a {class:?} document",
                class.max_references()
            ),
            ErrorContext::new("wssec_parse_references"),
        ));
    }
    Ok(())
}

/// At most `SignedDocClass::MAX_TRANSFORMS` transforms per
/// reference.
fn enforce_transform_cap(reference: roxmltree::Node<'_, '_>, uri: &str) -> Result<()> {
    let count = reference
        .children()
        .filter(|n| n.is_element() && is_ds_element(*n, "Transforms"))
        .flat_map(|t| t.children())
        .filter(|n| n.is_element() && is_ds_element(*n, "Transform"))
        .count();
    if count > SignedDocClass::MAX_TRANSFORMS {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!(
                "ds:Reference {uri} carries {count} transforms; at most {} are allowed",
                SignedDocClass::MAX_TRANSFORMS
            ),
            ErrorContext::new("wssec_parse_references").with_message_id(uri.to_string()),
        ));
    }
    Ok(())
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
/// forgery. (This is also why the signing path *states* the exclusive
/// algorithm rather than relying on a default.)
///
/// A `cid:` reference dereferences to an octet stream, not a node-set, so no
/// canonicalization runs on it at all; the value returned for one is inert.
fn default_c14n_kind(parsed_uri: &ParsedReferenceUri<'_>) -> WsSecCanonicalizationKind {
    match parsed_uri {
        ParsedReferenceUri::Cid { .. } => WsSecCanonicalizationKind::Exclusive,
        _ => WsSecCanonicalizationKind::Inclusive,
    }
}

/// Fragment of the SwA transform that additionally covers selected MIME part
/// headers. It has no registry row (AS4 mandates the content-only transform);
/// the suffix only selects a more specific rejection message.
const SWA_ATTACHMENT_COMPLETE_TRANSFORM_SUFFIX: &str = "#Attachment-Complete-Signature-Transform";

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
            if matches!(
                TransformAlg::from_uri(alg),
                Ok(TransformAlg::AttachmentContent)
            ) {
                continue;
            }
            let detail = if alg.ends_with(SWA_ATTACHMENT_COMPLETE_TRANSFORM_SUFFIX) {
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
        match TransformAlg::from_uri(alg) {
            Ok(TransformAlg::C14n(WsSecCanonicalizationKind::Inclusive)) => {
                // Inclusive C14N has no InclusiveNamespaces child — the entire
                // in-scope namespace set is implicitly included.
                c14n_kind = WsSecCanonicalizationKind::Inclusive;
                continue;
            }
            Ok(TransformAlg::C14n(WsSecCanonicalizationKind::Exclusive)) => {}
            _ => {
                return Err(AsxError::new(
                    ErrorCode::InteropViolation,
                    format!(
                        "unsupported ds:Transform Algorithm \"{alg}\" in Reference {uri}; \
                         supported algorithms: Exclusive C14N ({}) and Inclusive C14N ({})",
                        WsSecCanonicalizationKind::Exclusive.uri(),
                        WsSecCanonicalizationKind::Inclusive.uri()
                    ),
                    ErrorContext::new("wssec_parse_references").with_message_id(uri.to_string()),
                ));
            }
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

/// A sender rule over the signer certificate (DER).
pub(crate) type SignerCheck = dyn Fn(&[u8]) -> Result<()> + Send + Sync;

/// Options for WS-Security signature verification.
///
/// Construct via `WsSecVerifyOptions::new()`, optionally chaining builder
/// methods before passing to [`verify_enveloped_signature`].
pub struct WsSecVerifyOptions<'a> {
    /// Permitted signer fingerprints. Empty means "no pin configured";
    /// the AS4 receive path refuses before reaching here in that case.
    pub(crate) expected_cert_fingerprints: &'a [crate::crypto::CertFingerprint],
    /// A profile's sender rule over the signer certificate (DER), checked
    /// with the pins — before the signature value (the
    /// caller's revocation check comes after, so an unauthorized signer
    /// triggers no fetch).
    pub(crate) signer_check: Option<&'a SignerCheck>,
    pub(crate) chain_policy: ChainPolicy<'a>,
    pub(crate) external_references: &'a [(&'a str, &'a [u8])],
    /// When the verification happens (`wsu:Timestamp`): the session clock's
    /// reading, the system clock by default.
    pub(crate) now: std::time::SystemTime,
    /// Leave the `cid:` references to the caller (returned in
    /// [`VerifiedSignatureCoverage::deferred`]): the attachment bytes they
    /// cover exist only after decryption.
    pub(crate) defer_attachments: bool,
}

impl std::fmt::Debug for WsSecVerifyOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsSecVerifyOptions")
            .field(
                "expected_cert_fingerprints",
                &self.expected_cert_fingerprints,
            )
            .field("signer_check", &self.signer_check.is_some())
            .field("chain_policy", &self.chain_policy)
            .field("external_references", &self.external_references.len())
            .finish()
    }
}

impl<'a> WsSecVerifyOptions<'a> {
    /// Create options with strict fail-closed defaults.
    ///
    /// Callers should pass an explicit policy via `with_chain_policy(...)`
    /// sourced from session trust material before using in production receive
    /// paths.
    pub fn new() -> Self {
        Self {
            expected_cert_fingerprints: &[],
            signer_check: None,
            // Pure cryptographic verification by default: callers that need
            // PKIX chain validation supply anchors via `with_chain_policy`.
            chain_policy: ChainPolicy::default(),
            external_references: &[],
            now: crate::clock::system().now(),
            defer_attachments: false,
        }
    }

    /// Verify `SignatureValue`, signer and the same-document references only;
    /// the `cid:` references are returned for the caller.
    #[cfg(feature = "as4")]
    pub(crate) fn deferring_attachments(mut self) -> Self {
        self.defer_attachments = true;
        self
    }

    /// Judge every time-dependent check at `now` (the session clock).
    pub(crate) fn at(mut self, now: std::time::SystemTime) -> Self {
        self.now = now;
        self
    }

    /// Apply a sender rule to the signing certificate (DER).
    pub(crate) fn with_signer_check(mut self, check: Option<&'a SignerCheck>) -> Self {
        self.signer_check = check;
        self
    }

    /// Require the signing certificate to match one of these fingerprints.
    ///
    /// An empty slice applies no pin. On the AS4 receive path that state is
    /// refused earlier, by the signer-pin resolver.
    pub fn with_expected_fingerprints(
        mut self,
        fingerprints: &'a [crate::crypto::CertFingerprint],
    ) -> Self {
        self.expected_cert_fingerprints = fingerprints;
        self
    }

    /// Validate the signer's certification path against `policy` (offline;
    /// revocation is the caller's).
    pub fn with_chain_policy(mut self, policy: ChainPolicy<'a>) -> Self {
        self.chain_policy = policy;
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
pub fn verify_enveloped_signature(xml: &str, opts: WsSecVerifyOptions<'_>) -> Result<()> {
    let doc = parse_wssec_document(
        xml,
        crate::xml::XmlLimits::ENVELOPE,
        "wssec_verify",
        "failed to parse XML for wssec verification",
    )?;

    let parsed =
        parse_signature_envelope_from_doc_optional_borrowed(&doc, SignedDocClass::UserMessage)?
            .ok_or_else(|| {
                AsxError::new(
                    ErrorCode::ParseFailed,
                    "no ds:Signature elements found",
                    ErrorContext::new("wssec_parse_references"),
                )
            })?;
    verify_enveloped_signature_with_parsed_signature_borrowed(&doc, xml, parsed, opts).map(|_| ())
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
    /// The signer certificate the signature verified against (audit evidence).
    pub signer_certificate_der: Option<Vec<u8>>,
    /// `(URI, DigestMethod URI, base64 DigestValue)` of every verified
    /// `ds:Reference`, in document order (audit evidence).
    pub references: Vec<(String, String, String)>,
    /// What [`WsSecVerifyOptions::deferring_attachments`] left to the caller.
    pub deferred: Option<std::sync::Arc<Deferred>>,
    /// The validated certification path, signer first, trust anchor last
    /// (empty without chain validation): what the caller checks for
    /// revocation.
    pub(crate) signer_path: Vec<openssl::x509::X509>,
}

/// The verification step left open by
/// [`WsSecVerifyOptions::deferring_attachments`]: the `cid:` references, to
/// be digested over the decrypted parts ([`verify_cid_references`]).
#[cfg(feature = "as4")]
#[derive(Debug)]
pub(crate) struct Deferred {
    pub(crate) cid_references: Vec<PendingCidReference>,
}

/// One `cid:` `ds:Reference` whose digest is still to be checked.
#[cfg(feature = "as4")]
#[derive(Debug, Clone)]
pub(crate) struct PendingCidReference {
    pub(crate) uri: String,
    /// The Content-ID, normalized.
    pub(crate) cid: String,
    pub(crate) digest_method: WsSecDigestMethod,
    pub(crate) digest_value_base64: String,
}

/// The second half of verification step 4: every pending `cid:`
/// reference digested over its part's digest input (`parts`: normalized
/// Content-ID, bytes after the SwA content transform). A reference without
/// its part fails.
#[cfg(feature = "as4")]
pub(crate) fn verify_cid_references(
    pending: &[PendingCidReference],
    parts: &[(&str, &[u8])],
) -> Result<()> {
    for reference in pending {
        #[cfg(test)]
        order_probe::cid_digested();
        let payload = parts
            .iter()
            .find(|(cid, _)| normalize_cid_uri(cid) == reference.cid)
            .map(|(_, bytes)| *bytes)
            .ok_or_else(|| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!(
                        "missing external reference bytes required for URI {}",
                        reference.uri
                    ),
                    ErrorContext::new("wssec_verify_references")
                        .with_message_id(reference.uri.clone()),
                )
            })?;
        let computed = openssl::hash::hash(reference.digest_method.message_digest(), payload)
            .map_err(|_| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    "failed to digest external reference payload",
                    ErrorContext::new("wssec_verify_references")
                        .with_message_id(reference.uri.clone()),
                )
            })?;
        let expected = decode_reference_digest_value(
            &reference.uri,
            reference.digest_method,
            &reference.digest_value_base64,
        )?;
        verify_reference_digest_matches(
            &reference.uri,
            &expected,
            &reference.digest_value_base64,
            &computed,
        )?;
    }
    Ok(())
}

/// What a signed document is, for the reference caps: a user
/// message signs `eb:Messaging`, the Body, an optional `wsu:Timestamp` and one
/// reference per attachment; a signal or pull request signs its header block,
/// the Body and an optional timestamp; an SMP document signs itself once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignedDocClass {
    UserMessage,
    Signal,
    Smp,
}

impl SignedDocClass {
    /// At most this many `ds:Reference`s.
    pub(crate) const fn max_references(self) -> usize {
        match self {
            // eb:Messaging, soap:Body, wsu:Timestamp, MAX_INBOUND_PAYLOADS (16).
            Self::UserMessage => 3 + 16,
            Self::Signal => 3,
            Self::Smp => 1,
        }
    }

    /// At most this many transforms per reference.
    pub(crate) const MAX_TRANSFORMS: usize = 2;
}

#[cfg(feature = "as4")]
pub(crate) fn verify_enveloped_signature_optional_with_doc(
    doc: &Document<'_>,
    xml: &str,
    class: SignedDocClass,
    opts: WsSecVerifyOptions<'_>,
) -> Result<Option<VerifiedSignatureCoverage>> {
    let Some(parsed) = parse_signature_envelope_from_doc_optional_borrowed(doc, class)? else {
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

    let signer_certificate_der = parsed
        .signature_material
        .x509_certificates_der
        .first()
        .cloned();
    let span = crate::telemetry::verify_span(
        &parsed.signature_material.signature_method_algorithm,
        signer_certificate_der.as_deref(),
    );
    let references = parsed
        .references
        .iter()
        .map(|r| {
            (
                r.uri.to_owned(),
                r.digest_method.algorithm_uri().to_owned(),
                r.digest_value_base64.to_owned(),
            )
        })
        .collect();

    let pending: Vec<PendingCidReference> = if opts.defer_attachments {
        parsed
            .references
            .iter()
            .filter_map(|r| match r.parsed_uri {
                ParsedReferenceUri::Cid { normalized } => Some(PendingCidReference {
                    uri: r.uri.to_owned(),
                    cid: normalized.to_owned(),
                    digest_method: r.digest_method,
                    digest_value_base64: r.digest_value_base64.to_owned(),
                }),
                ParsedReferenceUri::SameDocument { .. } => None,
            })
            .collect()
    } else {
        Vec::new()
    };
    let defer = opts.defer_attachments;
    let verified = span.in_scope(|| {
        verify_enveloped_signature_with_parsed_signature_borrowed(doc, xml, parsed, opts)
    });
    crate::telemetry::child_outcome(&span, &verified);
    let chain = verified?;
    Ok(Some(VerifiedSignatureCoverage {
        signed_same_document_ids,
        signed_cid_references,
        signer_certificate_der,
        references,
        deferred: defer.then(|| {
            std::sync::Arc::new(Deferred {
                cid_references: pending,
            })
        }),
        signer_path: chain.map(|c| c.path).unwrap_or_default(),
    }))
}

/// The one verification pipeline — each step only after the
/// previous succeeded (W3C XMLDSig Best Practices BP 1, 2):
///
/// 1. `SignedInfo`/`KeyInfo` parsed, reference and transform caps and the
///    signature location enforced (done while parsing `parsed`);
/// 2. signer identity: the pin, then the offline certification path;
/// 3. key family, then the `SignatureValue` over the canonical `SignedInfo`;
/// 4. reference digests — the expensive, attacker-sized work: same-document
///    references first, then `cid:` references (when deferring, the `cid:`
///    ones are the caller's, after decryption);
/// 5. the `wsu:Timestamp`.
///
/// The validated path is returned: revocation (which may fetch) is the
/// caller's, after the sender rule.
fn verify_enveloped_signature_with_parsed_signature_borrowed(
    doc: &Document<'_>,
    xml: &str,
    parsed: ParsedWsSecSignatureEnvelopeBorrowed<'_>,
    opts: WsSecVerifyOptions<'_>,
) -> Result<Option<ValidatedChain>> {
    let c14n_profile = WsSecCanonicalizationProfile::default();
    let ParsedWsSecSignatureEnvelopeBorrowed {
        references,
        signature_material,
        security_header,
    } = parsed;

    let chain = verify_signature_value_with_components(
        signature_material,
        c14n_profile.clone(),
        opts.expected_cert_fingerprints,
        opts.signer_check,
        &opts.chain_policy,
    )?;

    let references: Vec<WsSecSignatureReferenceBorrowed<'_>> = if opts.defer_attachments {
        references
            .into_iter()
            .filter(|r| matches!(r.parsed_uri, ParsedReferenceUri::SameDocument { .. }))
            .collect()
    } else {
        references
    };
    verify_signature_references_borrowed_with_profile(
        xml,
        &references,
        &c14n_profile,
        opts.external_references,
        Some(doc),
    )?;

    if let Some(security) = security_header {
        check_wsu_timestamp(security, opts.now)?;
    }

    Ok(chain)
}

/// Clock skew tolerated on an inbound `wsu:Timestamp` (WSS 1.1.1 §10).
const WSU_TIMESTAMP_SKEW: std::time::Duration = std::time::Duration::from_secs(300);

/// Validate a present `wsu:Timestamp` in the processed `wsse:Security` header
/// (WSS SOAP Message Security 1.1.1 §10).
///
/// An absent timestamp is accepted: WSS makes the element optional and the
/// AS4 peers this crate interoperates with send none. A present one must be
/// unambiguous and current — at most one `wsu:Timestamp`, at most one
/// `wsu:Created` and `wsu:Expires`, both UTC `xsd:dateTime` values, `Expires`
/// not before `Created`, `Expires ≥ now − skew` and `Created ≤ now + skew`.
/// Whether the timestamp is signed does not matter: it can only cause
/// rejection.
fn check_wsu_timestamp(
    security: roxmltree::Node<'_, '_>,
    now: std::time::SystemTime,
) -> Result<()> {
    let reject = |detail: String| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("wsu:Timestamp rejected: {detail}"),
            ErrorContext::new("wssec_verify_timestamp"),
        )
    };
    let is_wsu = |n: &roxmltree::Node<'_, '_>, local: &str| {
        n.is_element() && n.tag_name().namespace() == Some(WSU_NS) && n.tag_name().name() == local
    };

    let mut timestamps = security.children().filter(|n| is_wsu(n, "Timestamp"));
    let Some(timestamp) = timestamps.next() else {
        return Ok(());
    };
    if timestamps.next().is_some() {
        return Err(reject(
            "more than one wsu:Timestamp in the wsse:Security header".to_string(),
        ));
    }

    let single = |local: &str| -> Result<Option<i64>> {
        let mut values = timestamp.children().filter(|n| is_wsu(n, local));
        let Some(node) = values.next() else {
            return Ok(None);
        };
        if values.next().is_some() {
            return Err(reject(format!("more than one wsu:{local}")));
        }
        let text = node.text().unwrap_or("").trim();
        let secs = text
            .ends_with('Z')
            .then(|| crate::time_utils::parse_rfc3339_to_unix_secs(text))
            .flatten()
            .ok_or_else(|| reject(format!("wsu:{local} '{text}' is not a UTC xsd:dateTime")))?;
        Ok(Some(secs))
    };
    let created = single("Created")?;
    let expires = single("Expires")?;

    let now_secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let skew = WSU_TIMESTAMP_SKEW.as_secs() as i64;

    if let (Some(created), Some(expires)) = (created, expires)
        && expires < created
    {
        return Err(reject(
            "wsu:Expires is earlier than wsu:Created".to_string(),
        ));
    }
    if let Some(expires) = expires
        && expires < now_secs - skew
    {
        return Err(reject(format!(
            "message expired {} s ago (skew {skew} s)",
            now_secs - expires
        )));
    }
    if let Some(created) = created
        && created > now_secs + skew
    {
        return Err(reject(format!(
            "wsu:Created is {} s in the future (skew {skew} s)",
            created - now_secs
        )));
    }
    Ok(())
}

/// Parse a WS-Security document with the envelope limits (`xml::parse`),
/// prefixing a failure with what was being parsed.
fn parse_wssec_document<'a>(
    xml: &'a str,
    limits: crate::xml::XmlLimits,
    context: &'static str,
    message: &str,
) -> Result<Document<'a>> {
    crate::xml::parse(xml, limits, context).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("{message}: {}", err.message),
            ErrorContext::new(context),
        )
    })
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
            crate::xml::XmlLimits::ENVELOPE,
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

    // Same-document references first: a forged header stops before any
    // attachment-sized digest.
    let ordered = references
        .iter()
        .filter(|r| matches!(r.parsed_uri, ParsedReferenceUri::SameDocument { .. }))
        .chain(
            references
                .iter()
                .filter(|r| matches!(r.parsed_uri, ParsedReferenceUri::Cid { .. })),
        );
    for reference in ordered {
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
    #[cfg(test)]
    order_probe::digested();
    if let ParsedReferenceUri::Cid { normalized } = parsed_uri {
        #[cfg(test)]
        order_probe::cid_digested();
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
        let digest =
            openssl::hash::hash(digest_method.message_digest(), payload).map_err(|_err| {
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
    // An unresolvable target is a verification failure here,
    // whatever the shared resolver calls it for a signer.
    let unresolved = |err: AsxError| {
        if err.code == ErrorCode::InvalidInput {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                err.message,
                ErrorContext::new("wssec_verify_references").with_message_id(uri.to_string()),
            )
        } else {
            err
        }
    };
    if let Some(index) = ctx.parsed_index {
        canonicalize_reference_digest_from_doc_with_inclusive_ns_and_index(
            index,
            uri,
            ctx.profile,
            inclusive_override,
            digest_method,
        )
        .map_err(unresolved)
    } else if let Some(doc) = ctx.parsed_doc {
        canonicalize_reference_digest_from_same_document_target_id_with_inclusive_ns(
            doc,
            uri,
            target_id,
            ctx.profile,
            inclusive_override,
            digest_method,
        )
        .map_err(unresolved)
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

/// The signature method's key family must match the signer certificate's
/// key, named in the error.
fn check_key_family(
    algorithm: SignatureAlgorithm,
    signer_cert: &openssl::x509::X509Ref,
) -> Result<()> {
    let key_id = signer_cert.public_key().map(|k| k.id()).map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("signer certificate does not contain a usable public key: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })?;
    let cert_family = match key_id {
        openssl::pkey::Id::RSA | openssl::pkey::Id::RSA_PSS => Some(KeyFamily::Rsa),
        openssl::pkey::Id::EC => Some(KeyFamily::Ec),
        _ => None,
    };
    if cert_family == Some(algorithm.key_family()) {
        return Ok(());
    }
    let key_type = match cert_family {
        Some(KeyFamily::Rsa) => "an RSA".to_string(),
        Some(KeyFamily::Ec) => "an EC".to_string(),
        None => format!("a {key_id:?}"),
    };
    Err(AsxError::new(
        ErrorCode::SecurityVerificationFailed,
        format!(
            "SignatureMethod {} does not match the signer certificate, which carries {key_type} key",
            algorithm.algorithm_uri()
        ),
        ErrorContext::new("wssec_verify_signature_value"),
    ))
}

fn verify_signature_value_with_components(
    mat: ParsedWsSecSignatureMaterialBorrowed<'_>,
    profile: WsSecCanonicalizationProfile,
    expected_cert_fingerprints: &[crate::crypto::CertFingerprint],
    signer_check: Option<&SignerCheck>,
    chain_policy: &ChainPolicy<'_>,
) -> Result<Option<ValidatedChain>> {
    let ParsedWsSecSignatureMaterialBorrowed {
        signed_info,
        signed_info_c14n_kind,
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
    // The signer's declared algorithm wins over the caller's default: the
    // signature was computed over whatever `ds:CanonicalizationMethod` names.
    profile.kind = signed_info_c14n_kind;
    profile.inclusive_ns_prefixes = signed_info_inclusive_ns_prefixes;
    let profile = profile;
    let algorithm = SignatureAlgorithm::from_uri(&signature_method_algorithm).map_err(|_| {
        AsxError::new(
            ErrorCode::InteropViolation,
            format!(
                "unsupported SignatureMethod algorithm: {} \
                 (supported: RSA-SHA256/384/512, ECDSA-SHA256/384/512)",
                signature_method_algorithm
            ),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })?;
    let is_rsa = algorithm.key_family() == KeyFamily::Rsa;
    let is_ecdsa = algorithm.key_family() == KeyFamily::Ec;

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

    if !expected_cert_fingerprints.is_empty() {
        let actual = crate::crypto::CertFingerprint::from_cert_der(signer_cert_der);
        if !expected_cert_fingerprints.contains(&actual) {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "signer certificate fingerprint does not match any pinned fingerprint \
                 for the claimed sender",
                ErrorContext::new("wssec_verify_signature_value"),
            ));
        }
    }
    if let Some(check) = signer_check {
        check(signer_cert_der)?;
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

    // Trust in the key before any expensive work: the offline path only.
    // Revocation (which may fetch) is the caller's, after the sender rule.
    let chain = if chain_policy.require_chain_validation {
        Some(validate_chain_offline(
            &x509_certificates_der,
            chain_policy,
        )?)
    } else {
        None
    };

    // The method's key family must be the certificate's,
    // before any signature operation.
    let signer_cert = openssl::x509::X509::from_der(signer_cert_der).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("failed to parse X509 certificate for signature verification: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })?;
    check_key_family(algorithm, &signer_cert)?;
    // An ECDSA value is exactly `2·l` octets (`r ‖ s`); any other
    // length is refused here, naming both lengths. DER is never parsed.
    let signature_value = algorithm.from_wire(&signature_value, &signer_cert)?;

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

    let mut verifier = OsslVerifier::new(algorithm.message_digest(), &pkey).map_err(|err| {
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

    Ok(chain)
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
        signed_info_c14n_kind,
        signed_info_inclusive_ns_prefixes,
        signature_value,
        signature_method_algorithm,
        rsa_modulus,
        rsa_exponent,
        x509_certificates_der,
    } = parse_signature_material_components_from_signature(doc, signature)?;

    let mut profile = profile;
    // As in `verify_signature_value_with_components`: the signature was
    // computed over whatever `ds:CanonicalizationMethod` declares, so that is
    // what SignedInfo must be serialized with.
    profile.kind = signed_info_c14n_kind;
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
) -> Result<(WsSecCanonicalizationKind, Vec<String>)> {
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

    // Which canonicalization the signer declared decides how SignedInfo is
    // serialized before the signature is checked. Both W3C algorithms are
    // legitimate here and the networks disagree: AS4 WS-Security profiles
    // require exclusive, Peppol SMP requires inclusive. Forcing one would
    // reject every conformant SMP response.
    // Inclusive Canonical XML 1.0 is mandated for Peppol SMP `ds:Signature`
    // (SMP 1.4.0 §5.5.1, which changed it *from* exclusive in that release),
    // and is the XMLDSig default for a reference that declares no transform.
    let kind = match WsSecCanonicalizationKind::from_uri(algorithm) {
        Ok(kind) => kind,
        Err(_) => {
            let detail = if algorithm.ends_with("#WithComments") {
                "comment-preserving canonicalization is not supported"
            } else {
                "only Canonical XML 1.0 (inclusive) and Exclusive XML Canonicalization 1.0 \
                 are supported"
            };

            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                format!(
                    "unsupported ds:CanonicalizationMethod Algorithm \"{algorithm}\": {detail} \
                     (expected \"{}\" for AS4 WS-Security, or \"{}\" for Peppol SMP)",
                    WsSecCanonicalizationKind::Exclusive.uri(),
                    WsSecCanonicalizationKind::Inclusive.uri()
                ),
                ErrorContext::new("wssec_signature_material")
                    .with_message_id(algorithm.to_string()),
            ));
        }
    };

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

    // `InclusiveNamespaces/@PrefixList` is an exclusive-C14N construct; under
    // inclusive canonicalization the whole in-scope context is emitted anyway,
    // so a prefix list would be meaningless rather than merely redundant.
    if kind == WsSecCanonicalizationKind::Inclusive && !inclusive_prefixes.is_empty() {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            "ds:CanonicalizationMethod declares inclusive Canonical XML 1.0 but carries an \
             exc-c14n InclusiveNamespaces PrefixList, which applies only to exclusive \
             canonicalization",
            ErrorContext::new("wssec_signature_material"),
        ));
    }

    Ok((kind, inclusive_prefixes))
}

fn parse_signature_material_components_from_signature_with_signed_info<'a>(
    doc: &'a Document<'a>,
    signature: roxmltree::Node<'a, 'a>,
    signed_info: roxmltree::Node<'a, 'a>,
) -> Result<ParsedWsSecSignatureMaterialBorrowed<'a>> {
    let (signed_info_c14n_kind, signed_info_inclusive_ns_prefixes) =
        parse_signed_info_canonicalization_method(signed_info)?;

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
        signed_info_c14n_kind,
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
/// - **`#X509PKIPathv1`** — a DER `SEQUENCE` of certificates, issuer first
///   and the signer last (WSS X.509 Token Profile 1.1 §3.1); returned signer
///   first.
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

    // WSS X.509 Token Profile 1.1 §3.1: a PkiPath is ordered from the trust
    // anchor side to the end entity, so the signer is the *last* certificate.
    // Everything downstream (pin, path validation, SignatureValue) takes the
    // signer first and the rest as the chain, so reverse once here.
    let mut path = split_x509_pkipath_der_certificates(&token_der)?;
    path.reverse();
    Ok(Some(path))
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

/// Instrumentation for the verification-order tests: how many
/// reference digests ran on this thread.
#[cfg(test)]
pub(crate) mod order_probe {
    use std::cell::Cell;

    thread_local! {
        pub(crate) static DIGESTS: Cell<usize> = const { Cell::new(0) };
        pub(crate) static CID_DIGESTS: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) fn cid_digested() {
        CID_DIGESTS.with(|c| c.set(c.get() + 1));
    }

    pub(crate) fn cid_digests() -> usize {
        CID_DIGESTS.with(Cell::get)
    }

    pub(crate) fn reset() {
        CID_DIGESTS.with(|c| c.set(0));
        DIGESTS.with(|c| c.set(0));
    }

    pub(crate) fn digested() {
        DIGESTS.with(|c| c.set(c.get() + 1));
    }

    pub(crate) fn digests() -> usize {
        DIGESTS.with(Cell::get)
    }
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;

// ---------------------------------------------------------------------------
// Enveloped whole-document signatures (SMP `ServiceMetadata`)
// ---------------------------------------------------------------------------

/// XMLDSig enveloped-signature transform.
pub const ENVELOPED_SIGNATURE_URI: &str = crate::crypto::alg::ENVELOPED_SIGNATURE;

/// Outcome of a successful [`verify_enveloped_document_signature`].
#[derive(Debug, Clone)]
pub struct VerifiedEnvelopedSignature {
    /// SHA-256 fingerprint (lowercase hex) of the signing certificate.
    pub signer_fingerprint_sha256: String,
    /// DER of the signing certificate, as carried in `ds:KeyInfo/ds:X509Data`.
    pub signer_certificate_der: Vec<u8>,
    /// The validated certification path, signer first (the caller checks
    /// its revocation; the SMP client, feature `peppol`).
    #[cfg_attr(not(feature = "peppol"), allow(dead_code))]
    pub(crate) signer_path: Vec<openssl::x509::X509>,
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
/// The signing certificate is chain-validated against `chain_policy`, so
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
    expected_cert_fingerprints: &[crate::crypto::CertFingerprint],
    chain_policy: &ChainPolicy<'_>,
) -> Result<VerifiedEnvelopedSignature> {
    let doc = parse_wssec_document(
        xml,
        crate::xml::XmlLimits::SMP,
        "wssec_verify_enveloped",
        "failed to parse XML for enveloped signature verification",
    )?;
    verify_enveloped_document_signature_with_doc(&doc, expected_cert_fingerprints, chain_policy)
}

/// [`verify_enveloped_document_signature`] on a document already parsed with
/// `xml::parse(XmlLimits::SMP)` — the SMP client verifies and consumes one DOM.
pub(crate) fn verify_enveloped_document_signature_with_doc(
    doc: &Document<'_>,
    expected_cert_fingerprints: &[crate::crypto::CertFingerprint],
    chain_policy: &ChainPolicy<'_>,
) -> Result<VerifiedEnvelopedSignature> {
    let span = crate::telemetry::verify_span("xmldsig-enveloped-document", None);
    let result = span.in_scope(|| {
        verify_enveloped_document_signature_inner(doc, expected_cert_fingerprints, chain_policy)
    });
    if let Ok(verified) = &result {
        span.record(
            "signer.fingerprint",
            verified.signer_fingerprint_sha256.as_str(),
        );
    }
    crate::telemetry::child_outcome(&span, &result);
    result
}

fn verify_enveloped_document_signature_inner(
    doc: &Document<'_>,
    expected_cert_fingerprints: &[crate::crypto::CertFingerprint],
    chain_policy: &ChainPolicy<'_>,
) -> Result<VerifiedEnvelopedSignature> {
    let signature =
        find_single_signature_node(doc, "wssec_verify_enveloped")?.ok_or_else(|| {
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

    // Verification step 1: the cap (one URI="" reference) and at most two
    // transforms, before anything is trusted or digested.
    enforce_reference_cap(signed_info, SignedDocClass::Smp)?;
    let references: Vec<_> = signed_info
        .children()
        .filter(|n| n.is_element() && is_ds_element(*n, "Reference"))
        .collect();
    if references.is_empty() {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "ds:SignedInfo contains no ds:Reference",
            ErrorContext::new("wssec_verify_enveloped"),
        ));
    }
    let references = references
        .into_iter()
        .map(|reference| {
            enforce_transform_cap(reference, reference.attribute("URI").unwrap_or(""))?;
            parse_enveloped_reference(reference)
        })
        .collect::<Result<Vec<_>>>()?;

    let material = parse_signature_material_components_from_signature_with_signed_info(
        doc,
        signature,
        signed_info,
    )?;
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

    // Steps 2–3: signer identity (pin, offline path), then the SignatureValue.
    let chain = verify_signature_value_with_components(
        material,
        WsSecCanonicalizationProfile::default(),
        expected_cert_fingerprints,
        None,
        chain_policy,
    )?;

    // Step 4: the whole-document digest, only for an authenticated signer.
    for reference in &references {
        digest_enveloped_reference(doc, signature, reference)?;
    }

    // Revocation (may fetch) is the caller's, on the returned path.
    Ok(VerifiedEnvelopedSignature {
        signer_fingerprint_sha256: super::x509::sha256_hex_lower(&signer_certificate_der),
        signer_certificate_der,
        signer_path: chain.map(|c| c.path).unwrap_or_default(),
    })
}

/// A structurally valid `URI=""` + enveloped-signature reference: its
/// canonicalization and declared digest. Decided from the document alone
/// (verification step 1), before the signer is trusted.
struct EnvelopedReference<'a> {
    c14n_kind: WsSecCanonicalizationKind,
    expected_digest: &'a str,
}

/// Check one `URI=""` + enveloped-signature reference's shape.
fn parse_enveloped_reference<'a>(
    reference: roxmltree::Node<'a, '_>,
) -> Result<EnvelopedReference<'a>> {
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
            let algorithm = transform.attribute("Algorithm").unwrap_or("");
            match TransformAlg::from_uri(algorithm) {
                Ok(TransformAlg::EnvelopedSignature) => saw_enveloped = true,
                Ok(TransformAlg::C14n(kind)) => c14n_kind = kind,
                _ => {
                    let other = algorithm;
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

    let expected_digest = reference
        .children()
        .find(|n| n.is_element() && is_ds_element(*n, "DigestValue"))
        .and_then(|n| n.text())
        .map(str::trim)
        .unwrap_or_default();
    Ok(EnvelopedReference {
        c14n_kind,
        expected_digest,
    })
}

/// The whole-document digest of a parsed enveloped reference (verification
/// step 4).
fn digest_enveloped_reference(
    doc: &Document<'_>,
    signature: roxmltree::Node<'_, '_>,
    reference: &EnvelopedReference<'_>,
) -> Result<()> {
    #[cfg(test)]
    order_probe::digested();
    let expected = reference.expected_digest;
    let profile = WsSecCanonicalizationProfile {
        kind: reference.c14n_kind,
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
