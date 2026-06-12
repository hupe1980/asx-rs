use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use roxmltree::{Document, Node, NodeType};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::LazyLock;

use super::{DS_NS, WsSecCanonicalizationKind, WsSecDigestMethod, XML_NS};
use super::{WsSecCanonicalizationProfile, WsSecCanonicalizedReference};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

/// Shared empty namespace map; avoids a per-call heap allocation for the common case
/// where no inherited parent namespaces are in scope at the canonicalization root.
static EMPTY_NS_MAP: LazyLock<BTreeMap<String, String>> = LazyLock::new(BTreeMap::new);

// ---- Public canonicalization API ----

pub fn canonicalize_reference(
    xml: &str,
    uri: &str,
    profile: WsSecCanonicalizationProfile,
) -> Result<WsSecCanonicalizedReference> {
    let doc = Document::parse(xml).map_err(|e| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("failed to parse XML for canonicalization: {e}"),
            ErrorContext::new("wssec_canonicalize").with_message_id(uri.to_string()),
        )
    })?;

    canonicalize_reference_from_doc(&doc, uri, &profile)
}

pub fn canonicalize_reference_from_doc(
    doc: &Document<'_>,
    uri: &str,
    profile: &WsSecCanonicalizationProfile,
) -> Result<WsSecCanonicalizedReference> {
    canonicalize_reference_from_doc_with_inclusive_ns(doc, uri, profile, None)
}

pub fn canonicalize_reference_from_doc_with_inclusive_ns(
    doc: &Document<'_>,
    uri: &str,
    profile: &WsSecCanonicalizationProfile,
    inclusive_ns_prefixes_override: Option<&[String]>,
) -> Result<WsSecCanonicalizedReference> {
    let target_id = normalize_same_document_uri(uri)?;

    let target = resolve_same_document_reference_target(doc, uri, target_id)?;

    let mut out = String::new();
    try_serialize_node_with_inclusive_ns(
        target,
        &mut out,
        profile,
        &EMPTY_NS_MAP,
        inclusive_ns_prefixes_override,
    )
    .map_err(|_err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "failed to canonicalize XML reference subtree",
            ErrorContext::new("wssec_canonicalize").with_message_id(uri.to_string()),
        )
    })?;

    let digest = Sha256::digest(out.as_bytes());
    let digest_b64 = BASE64_STANDARD.encode(digest);

    Ok(WsSecCanonicalizedReference {
        uri: uri.to_string(),
        canonical_bytes: out.into_bytes(),
        digest_value_base64: digest_b64,
    })
}

#[cfg(test)]
pub(crate) fn canonicalize_reference_digest_base64_from_doc_with_inclusive_ns(
    doc: &Document<'_>,
    uri: &str,
    profile: &WsSecCanonicalizationProfile,
    inclusive_ns_prefixes_override: Option<&[String]>,
    digest_method: WsSecDigestMethod,
) -> Result<String> {
    let target_id = normalize_same_document_uri(uri)?;
    let digest = canonicalize_reference_digest_from_same_document_target_id_with_inclusive_ns(
        doc,
        uri,
        target_id,
        profile,
        inclusive_ns_prefixes_override,
        digest_method,
    )?;
    Ok(BASE64_STANDARD.encode(digest))
}

pub(crate) fn canonicalize_reference_digest_from_same_document_target_id_with_inclusive_ns(
    doc: &Document<'_>,
    uri: &str,
    target_id: &str,
    profile: &WsSecCanonicalizationProfile,
    inclusive_ns_prefixes_override: Option<&[String]>,
    digest_method: WsSecDigestMethod,
) -> Result<Vec<u8>> {
    let target = resolve_same_document_reference_target(doc, uri, target_id)?;

    canonicalize_reference_digest_from_target_with_inclusive_ns(
        target,
        profile,
        inclusive_ns_prefixes_override,
        digest_method,
    )
}

pub fn canonicalize_reference_digest_from_doc_with_inclusive_ns_and_index(
    index: &SameDocumentReferenceIndex<'_>,
    uri: &str,
    profile: &WsSecCanonicalizationProfile,
    inclusive_ns_prefixes_override: Option<&[String]>,
    digest_method: WsSecDigestMethod,
) -> Result<Vec<u8>> {
    let target_id = normalize_same_document_uri(uri)?;

    let target = resolve_same_document_reference_target_with_index(index, uri, target_id)?;

    canonicalize_reference_digest_from_target_with_inclusive_ns(
        target,
        profile,
        inclusive_ns_prefixes_override,
        digest_method,
    )
}

fn canonicalize_reference_digest_from_target_with_inclusive_ns(
    target: Node<'_, '_>,
    profile: &WsSecCanonicalizationProfile,
    inclusive_ns_prefixes_override: Option<&[String]>,
    digest_method: WsSecDigestMethod,
) -> Result<Vec<u8>> {
    let mut hasher_out = DigestFmtWriter::new(digest_method);
    try_serialize_node_with_inclusive_ns(
        target,
        &mut hasher_out,
        profile,
        &EMPTY_NS_MAP,
        inclusive_ns_prefixes_override,
    )
    .map_err(|_err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "failed to canonicalize XML reference subtree",
            ErrorContext::new("wssec_canonicalize"),
        )
    })?;

    Ok(hasher_out.finalize())
}

/// Multi-algorithm streaming digest writer for XML canonicalization.
///
/// Wraps sha2 hashers behind a common `fmt::Write` interface so that
/// `try_serialize_node_with_inclusive_ns` can drive any digest algorithm
/// without buffering the full canonical form.
enum DigestFmtWriter {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl DigestFmtWriter {
    fn new(method: WsSecDigestMethod) -> Self {
        match method {
            WsSecDigestMethod::Sha256 => Self::Sha256(Sha256::new()),
            WsSecDigestMethod::Sha384 => Self::Sha384(Sha384::new()),
            WsSecDigestMethod::Sha512 => Self::Sha512(Sha512::new()),
        }
    }

    fn finalize(self) -> Vec<u8> {
        match self {
            Self::Sha256(h) => h.finalize().to_vec(),
            Self::Sha384(h) => h.finalize().to_vec(),
            Self::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

impl std::fmt::Write for DigestFmtWriter {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        match self {
            Self::Sha256(h) => h.update(s.as_bytes()),
            Self::Sha384(h) => h.update(s.as_bytes()),
            Self::Sha512(h) => h.update(s.as_bytes()),
        }
        Ok(())
    }
}

enum SameDocumentReferenceEntry<'a> {
    Unique(Node<'a, 'a>),
    Ambiguous,
}

pub struct SameDocumentReferenceIndex<'a> {
    entries: HashMap<&'a str, SameDocumentReferenceEntry<'a>>,
}

impl<'a> SameDocumentReferenceIndex<'a> {
    pub(crate) fn build(doc: &'a Document<'a>) -> Self {
        Self::build_impl(doc, None)
    }

    pub(crate) fn build_for_targets<'t>(
        doc: &'a Document<'a>,
        target_ids: impl IntoIterator<Item = &'t str>,
    ) -> Self {
        let wanted: HashSet<&str> = target_ids.into_iter().collect();
        if wanted.is_empty() {
            return Self {
                entries: HashMap::new(),
            };
        }
        Self::build_impl(doc, Some(&wanted))
    }

    fn build_impl(doc: &'a Document<'a>, wanted: Option<&HashSet<&str>>) -> Self {
        let mut entries: HashMap<&'a str, SameDocumentReferenceEntry<'a>> = HashMap::new();

        for node in doc.descendants().filter(Node::is_element) {
            let mut node_ids: Vec<&str> = Vec::new();
            for attr in node.attributes() {
                if is_reference_id_attr(attr.namespace(), attr.name()) {
                    let value = attr.value();
                    if wanted.is_some_and(|ids| !ids.contains(value)) {
                        continue;
                    }
                    if !node_ids.contains(&value) {
                        node_ids.push(value);
                    }
                }
            }

            for value in node_ids {
                use std::collections::hash_map::Entry;
                match entries.entry(value) {
                    Entry::Vacant(slot) => {
                        slot.insert(SameDocumentReferenceEntry::Unique(node));
                    }
                    Entry::Occupied(mut slot) => {
                        let new_entry = match slot.get() {
                            SameDocumentReferenceEntry::Unique(existing)
                                if existing.id() == node.id() =>
                            {
                                None
                            }
                            _ => Some(SameDocumentReferenceEntry::Ambiguous),
                        };
                        if let Some(entry) = new_entry {
                            slot.insert(entry);
                        }
                    }
                }
            }
        }

        Self { entries }
    }
}

pub(crate) fn normalize_same_document_uri(uri: &str) -> Result<&str> {
    if uri.trim() != uri {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!("non-canonical reference URI with surrounding whitespace: {uri}"),
            ErrorContext::new("wssec_reference_uri"),
        ));
    }

    if !uri.starts_with('#') {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!("unsupported reference URI: {uri}"),
            ErrorContext::new("wssec_reference_uri"),
        ));
    }
    if uri.len() == 1 {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!("empty same-document URI fragment is not supported in strict mode: {uri}"),
            ErrorContext::new("wssec_reference_uri"),
        ));
    }

    let fragment = &uri[1..];
    if fragment.contains('%') {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!(
                "percent-encoded same-document URI fragments are not supported in strict mode: {uri}"
            ),
            ErrorContext::new("wssec_reference_uri"),
        ));
    }
    if !fragment.is_ascii() {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!(
                "non-ASCII same-document URI fragments are not supported in strict mode: {uri}"
            ),
            ErrorContext::new("wssec_reference_uri"),
        ));
    }
    if fragment.contains('#') {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!(
                "nested fragment markers are not supported in strict same-document URIs: {uri}"
            ),
            ErrorContext::new("wssec_reference_uri"),
        ));
    }
    if fragment.chars().any(char::is_whitespace) {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!("whitespace is not allowed inside strict same-document URI fragments: {uri}"),
            ErrorContext::new("wssec_reference_uri"),
        ));
    }
    if fragment.chars().any(char::is_control) {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!(
                "control characters are not allowed in strict same-document URI fragments: {uri}"
            ),
            ErrorContext::new("wssec_reference_uri"),
        ));
    }
    let mut chars = fragment.chars();
    let first = chars.next().expect("fragment is non-empty");
    let first_is_valid = first.is_ascii_alphabetic() || first == '_';
    let rest_is_valid =
        chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ':'));
    if !first_is_valid || !rest_is_valid {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!(
                "non-canonical same-document URI fragment characters are not supported in strict mode: {uri}"
            ),
            ErrorContext::new("wssec_reference_uri"),
        ));
    }
    if fragment.chars().any(|ch| ch.is_ascii_uppercase()) {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!(
                "uppercase same-document URI fragments are not supported in strict mode: {uri}"
            ),
            ErrorContext::new("wssec_reference_uri"),
        ));
    }
    if fragment.contains(':') {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!(
                "namespace-like delimiters are not supported in strict same-document URI fragments: {uri}"
            ),
            ErrorContext::new("wssec_reference_uri"),
        ));
    }

    Ok(fragment)
}

fn resolve_same_document_reference_target<'a>(
    doc: &'a Document<'a>,
    uri: &str,
    target_id: &str,
) -> Result<Node<'a, 'a>> {
    let index = SameDocumentReferenceIndex::build(doc);
    resolve_same_document_reference_target_with_index(&index, uri, target_id)
}

pub(crate) fn resolve_same_document_reference_target_with_index<'a>(
    index: &SameDocumentReferenceIndex<'a>,
    uri: &str,
    target_id: &str,
) -> Result<Node<'a, 'a>> {
    match index.entries.get(target_id) {
        Some(SameDocumentReferenceEntry::Unique(node)) => Ok(*node),
        Some(SameDocumentReferenceEntry::Ambiguous) => Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!(
                "ambiguous same-document reference target for URI {uri}: multiple elements share ID {target_id}"
            ),
            ErrorContext::new("wssec_canonicalize").with_message_id(uri.to_string()),
        )),
        None => Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!("could not resolve same-document reference target for URI {uri}"),
            ErrorContext::new("wssec_canonicalize").with_message_id(uri.to_string()),
        )),
    }
}

fn is_reference_id_attr(namespace: Option<&str>, name: &str) -> bool {
    if namespace == Some(XML_NS) && name == "id" {
        return true;
    }

    name.eq_ignore_ascii_case("id")
}

pub(crate) fn is_ds_element(node: Node<'_, '_>, local_name: &str) -> bool {
    node.tag_name().namespace() == Some(DS_NS) && node.tag_name().name() == local_name
}

// ---- Canonical diff helper (pub for test use) ----

/// Produce a human-readable diff of two C14N strings, line by line.
/// Returns "no diff" when the strings are identical.
pub fn canonical_vector_diff(expected: &str, actual: &str) -> String {
    let expected_lines: Vec<&str> = expected.lines().collect();
    let actual_lines: Vec<&str> = actual.lines().collect();
    let max_len = expected_lines.len().max(actual_lines.len());
    let mut out = Vec::new();

    for idx in 0..max_len {
        let line_no = idx + 1;
        let expected_line = expected_lines.get(idx).copied().unwrap_or("<missing>");
        let actual_line = actual_lines.get(idx).copied().unwrap_or("<missing>");
        if expected_line != actual_line {
            out.push(format!("L{line_no}: -{expected_line}"));
            out.push(format!("L{line_no}: +{actual_line}"));
        }
    }

    if out.is_empty() {
        "no diff".to_string()
    } else {
        out.join("\n")
    }
}

/// Canonicalize an entire well-formed XML document (the root node and all its
/// descendants).  This is the operation described in W3C Canonical XML 1.0
/// §2.3 when the input is an octet stream (not a document subset).
///
/// PI and comment children of the root node receive leading/trailing `\n`
/// per C14N §2.3.
#[cfg(test)]
pub(crate) fn canonicalize_document(
    xml: &str,
    profile: &WsSecCanonicalizationProfile,
) -> Result<String> {
    let doc = Document::parse(xml).map_err(|e| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("failed to parse XML for whole-document canonicalization: {e}"),
            ErrorContext::new("wssec_canonicalize_document"),
        )
    })?;

    let mut out = String::new();
    serialize_root_node(&doc, &mut out, profile)?;
    Ok(out)
}

/// Serialize the root node of a document for whole-document canonicalization.
///
/// Per W3C Canonical XML 1.0 §2.3, PI and comment children of the root node
/// receive a leading `\n` (if they come after the document element) or a
/// trailing `\n` (if they come before the document element).
#[cfg(test)]
fn serialize_root_node(
    doc: &Document<'_>,
    out: &mut String,
    profile: &WsSecCanonicalizationProfile,
) -> Result<()> {
    use roxmltree::NodeType as NT;
    let root = doc.root();

    // Identify the document element position.
    let doc_elem_idx = root
        .children()
        .enumerate()
        .find(|(_, n)| n.is_element())
        .map(|(i, _)| i);

    for (i, child) in root.children().enumerate() {
        let is_after_doc_elem = doc_elem_idx.is_some_and(|di| i > di);
        let is_before_doc_elem = doc_elem_idx.is_some_and(|di| i < di);

        match child.node_type() {
            NT::Element => {
                try_serialize_node_with_inclusive_ns(child, out, profile, &EMPTY_NS_MAP, None)
                    .map_err(|_| {
                        AsxError::new(
                            ErrorCode::SecurityVerificationFailed,
                            "failed to canonicalize document element",
                            ErrorContext::new("wssec_canonicalize_document"),
                        )
                    })?;
            }
            NT::PI => {
                if let Some(pi) = child.pi() {
                    // PI before document element → trailing \n
                    // PI after document element → leading \n
                    if is_after_doc_elem {
                        out.push('\n');
                    }
                    out.push_str("<?");
                    out.push_str(pi.target);
                    if let Some(data) = pi.value {
                        let data = data.trim_end();
                        if !data.is_empty() {
                            out.push(' ');
                            out.push_str(data);
                        }
                    }
                    out.push_str("?>");
                    if is_before_doc_elem {
                        out.push('\n');
                    }
                }
            }
            NT::Comment if profile.include_comments => {
                if is_after_doc_elem {
                    out.push('\n');
                }
                out.push_str("<!--");
                out.push_str(child.text().unwrap_or_default());
                out.push_str("-->");
                if is_before_doc_elem {
                    out.push('\n');
                }
            }
            _ => {
                // Text nodes at root are whitespace-only and discarded per C14N.
            }
        }
    }
    Ok(())
}

// ---- DOM serializer (Exc-C14N) ----

/// Serialize a node subtree using Exclusive XML Canonicalization (Exc-C14N,
/// https://www.w3.org/TR/xml-exc-c14n/).  Namespace declarations are emitted
/// only for namespaces "visibly utilized" at each element (the element's own
/// namespace plus each attribute's namespace), and only when the binding
/// differs from the inherited parent context.  Original document prefixes are
/// preserved; the output is therefore prefix-dependent — two documents with
/// different prefix names for the same namespace URIs produce different
/// canonical bytes.  This is correct per-spec behavior for Exc-C14N.
///
/// `parent_ns` carries `prefix → uri` bindings already present in the
/// canonical output of ancestor elements.  Pass an empty `BTreeMap` at the
/// serialization root.
pub(crate) fn try_serialize_node(
    node: Node<'_, '_>,
    out: &mut impl std::fmt::Write,
    profile: &WsSecCanonicalizationProfile,
    parent_ns: &BTreeMap<String, String>,
) -> std::fmt::Result {
    try_serialize_node_with_inclusive_ns(node, out, profile, parent_ns, None)
}

pub(crate) fn try_serialize_node_with_inclusive_ns(
    node: Node<'_, '_>,
    out: &mut impl std::fmt::Write,
    profile: &WsSecCanonicalizationProfile,
    parent_ns: &BTreeMap<String, String>,
    inclusive_ns_prefixes_override: Option<&[String]>,
) -> std::fmt::Result {
    match node.node_type() {
        NodeType::Element => serialize_element(
            node,
            out,
            profile,
            parent_ns,
            inclusive_ns_prefixes_override,
        ),
        NodeType::Text => {
            if let Some(text) = node.text() {
                if profile.strip_blank_text && text.trim().is_empty() {
                    return Ok(());
                }
                escape_text(text, out)?;
            }
            Ok(())
        }
        NodeType::Comment => {
            if profile.include_comments {
                out.write_str("<!--")?;
                out.write_str(node.text().unwrap_or_default())?;
                out.write_str("-->")?;
            }
            Ok(())
        }
        // Per XML C14N §2.2 and Exclusive C14N §1: processing instructions
        // are always included in the canonical form (they are not stripped
        // unless the document subset explicitly excludes them).
        // roxmltree exposes PI data via `node.pi()` → PI { target, value }.
        NodeType::PI => {
            if let Some(pi) = node.pi() {
                out.write_str("<?")?;
                out.write_str(pi.target)?;
                if let Some(data) = pi.value {
                    let data = data.trim_end();
                    if !data.is_empty() {
                        out.write_char(' ')?;
                        out.write_str(data)?;
                    }
                }
                out.write_str("?>")?;
            }
            Ok(())
        }
        NodeType::Root => {
            for child in node.children() {
                try_serialize_node_with_inclusive_ns(
                    child,
                    out,
                    profile,
                    parent_ns,
                    inclusive_ns_prefixes_override,
                )?;
            }
            Ok(())
        }
    }
}

fn serialize_element(
    node: Node<'_, '_>,
    out: &mut impl std::fmt::Write,
    profile: &WsSecCanonicalizationProfile,
    parent_ns: &BTreeMap<String, String>,
    inclusive_ns_prefixes_override: Option<&[String]>,
) -> std::fmt::Result {
    // Build URI → prefix map from all in-scope namespace declarations at this
    // node.  When multiple prefixes are bound to the same URI, one is kept
    // arbitrarily; well-formed AS4/SOAP documents do not rebind URIs so this
    // does not cause non-determinism in practice.
    let uri_to_prefix: HashMap<&str, &str> = node
        .namespaces()
        .filter_map(|ns| ns.name().map(|prefix| (ns.uri(), prefix)))
        .collect();

    let tag_ns = node.tag_name().namespace();
    let tag_local = node.tag_name().name();
    let tag_qname = build_qname(tag_ns, tag_local, &uri_to_prefix);

    // Collect namespaces visibly utilized at this element: the element's own
    // namespace plus every attribute namespace.  Exclude the pre-defined `xml:`
    // binding (http://www.w3.org/XML/1998/namespace) — it must never be
    // explicitly declared per the XML spec.
    let mut utilized: BTreeMap<&str, &str> = BTreeMap::new();

    if matches!(profile.kind, WsSecCanonicalizationKind::Inclusive) {
        // Inclusive C14N (W3C Canonical XML 1.0 §2.3): ALL in-scope namespace
        // declarations are rendered, regardless of whether the prefix is
        // visibly utilized at this element.  The `xml:` binding is excluded.
        //
        // For the default namespace prefix (""), an empty URI means `xmlns=""`
        // (undeclaration).  We include it here so the emit loop below can
        // detect that it differs from a non-empty parent default namespace and
        // emit the xmlns="" undeclaration.  For non-default prefixes, an empty
        // URI would be illegal XML and is never emitted.
        for ns in node.namespaces() {
            let prefix = ns.name().unwrap_or("");
            let uri = ns.uri();
            if uri == XML_NS {
                continue;
            }
            // Only include the empty-URI binding for the default prefix ("").
            // Named prefixes with empty URIs are illegal and skipped.
            if uri.is_empty() && !prefix.is_empty() {
                continue;
            }
            utilized.insert(prefix, uri);
        }
    } else {
        // Exclusive C14N (W3C Exc-C14N §2.1): only visibly-utilized namespace
        // declarations are rendered.
        if let Some(ns_uri) = tag_ns
            && ns_uri != XML_NS
        {
            let prefix = uri_to_prefix.get(ns_uri).copied().unwrap_or("");
            utilized.insert(prefix, ns_uri);
        }
        for a in node.attributes() {
            if let Some(ns_uri) = a.namespace()
                && ns_uri != XML_NS
            {
                let prefix = uri_to_prefix.get(ns_uri).copied().unwrap_or("");
                utilized.insert(prefix, ns_uri);
            }
        }
    }

    // Emit namespace declarations for utilized namespaces that differ from the
    // inherited parent context.  BTreeMap iteration is sorted by key (prefix),
    // which satisfies the C14N requirement of lexicographic namespace ordering.
    //
    // Additionally, for each prefix in `profile.inclusive_ns_prefixes`, if a
    // binding is in scope at this element, the declaration MUST be rendered
    // even if the prefix is not visibly utilized — per W3C Exc-C14N §2.1.
    // The special token "#default" represents the default (empty-string) prefix.

    // Build prefix → URI map for in-scope namespaces (the inverse of uri_to_prefix).
    let prefix_to_uri: HashMap<&str, &str> = node
        .namespaces()
        .map(|ns| {
            let prefix = ns.name().unwrap_or("");
            (prefix, ns.uri())
        })
        .collect();

    // Merge inclusive prefixes into the utilized set.
    // This only applies to Exclusive C14N — for Inclusive C14N the entire
    // in-scope namespace set is already captured above.
    if matches!(profile.kind, WsSecCanonicalizationKind::Exclusive) {
        let effective_inclusive_ns_prefixes =
            inclusive_ns_prefixes_override.unwrap_or(&profile.inclusive_ns_prefixes);
        for token in effective_inclusive_ns_prefixes {
            let prefix: &str = if token == "#default" {
                ""
            } else {
                token.as_str()
            };
            if let Some(&uri) = prefix_to_uri.get(prefix)
                && uri != XML_NS
            {
                utilized.entry(prefix).or_insert(uri);
            }
        }
    }

    let mut ns_emitted: BTreeMap<String, String> = BTreeMap::new();
    out.write_char('<')?;
    out.write_str(&tag_qname)?;
    for (&prefix, &uri) in &utilized {
        let parent_uri = parent_ns.get(prefix).map(String::as_str);
        // Emit a namespace declaration when the binding differs from what the
        // parent context already has in scope.
        //
        // Special case: xmlns="" (empty URI on empty prefix) must only be
        // emitted when the parent context had a *non-empty* default namespace.
        // If the parent had no default namespace at all, emitting xmlns="" would
        // be incorrect (and the W3C spec omits it in that case).
        let should_emit = if uri.is_empty() && prefix.is_empty() {
            // Emit xmlns="" only when a non-empty default ns is being "undeclared".
            parent_uri.is_some_and(|p| !p.is_empty())
        } else {
            parent_uri != Some(uri)
        };
        if should_emit {
            if prefix.is_empty() {
                out.write_str(" xmlns=\"")?;
            } else {
                out.write_str(" xmlns:")?;
                out.write_str(prefix)?;
                out.write_str("=\"")?;
            }
            escape_attr_value(uri, out)?;
            out.write_char('"')?;
            ns_emitted.insert(prefix.to_string(), uri.to_string());
        }
    }

    // Regular attributes sorted by (namespace URI, local name) per C14N spec.
    // No-namespace attributes (empty URI string) sort before namespaced ones.
    let mut attrs: Vec<(Option<&str>, &str, String, &str)> = node
        .attributes()
        .map(|a| {
            let qname = build_qname(a.namespace(), a.name(), &uri_to_prefix);
            (a.namespace(), a.name(), qname, a.value())
        })
        .collect();
    attrs.sort_unstable_by(|a, b| {
        let a_ns = a.0.unwrap_or("");
        let b_ns = b.0.unwrap_or("");
        match a_ns.cmp(b_ns) {
            std::cmp::Ordering::Equal => a.1.cmp(b.1),
            other => other,
        }
    });
    for (_, _, qname, value) in attrs {
        out.write_char(' ')?;
        out.write_str(&qname)?;
        out.write_str("=\"")?;
        escape_attr_value(value, out)?;
        out.write_char('"')?;
    }

    out.write_char('>')?;

    // Build child namespace context: when no declarations were emitted at this
    // element, pass the parent context through without cloning.
    let child_ns: Cow<'_, BTreeMap<String, String>> = if ns_emitted.is_empty() {
        Cow::Borrowed(parent_ns)
    } else {
        let mut owned = parent_ns.clone();
        owned.extend(ns_emitted);
        Cow::Owned(owned)
    };

    for child in node.children() {
        try_serialize_node_with_inclusive_ns(
            child,
            out,
            profile,
            child_ns.as_ref(),
            inclusive_ns_prefixes_override,
        )?;
    }

    out.write_str("</")?;
    out.write_str(&tag_qname)?;
    out.write_char('>')?;
    Ok(())
}

/// Resolve a namespace URI and local name to a prefixed qualified name using
/// the URI → prefix map built from in-scope namespace declarations.
/// Returns `local_name` unchanged when the namespace is absent or maps to
/// the default (empty-string) prefix.
fn build_qname(
    ns_uri: Option<&str>,
    local_name: &str,
    uri_to_prefix: &HashMap<&str, &str>,
) -> String {
    match ns_uri {
        Some(uri) => match uri_to_prefix.get(uri).copied() {
            Some(prefix) if !prefix.is_empty() => format!("{prefix}:{local_name}"),
            _ => local_name.to_string(),
        },
        None => local_name.to_string(),
    }
}

/// Escape text node content per Canonical XML 1.0 §2.2:
/// `&`, `<`, `>` are entity-escaped; CR (`\r`) is escaped to `&#xD;`.
pub(crate) fn escape_text(input: &str, out: &mut impl std::fmt::Write) -> std::fmt::Result {
    for ch in input.chars() {
        match ch {
            '<' => {
                out.write_str("&lt;")?;
            }
            '>' => {
                out.write_str("&gt;")?;
            }
            '&' => {
                out.write_str("&amp;")?;
            }
            '\r' => {
                out.write_str("&#xD;")?;
            }
            _ => {
                out.write_char(ch)?;
            }
        }
    }
    Ok(())
}

/// Escape attribute values per Canonical XML 1.0 §2.3:
/// attributes are always double-quoted; `&`, `<`, `"` are entity-escaped;
/// whitespace control characters (`\t`, `\n`, `\r`) are escaped numerically.
/// Single quote does NOT need escaping inside double-quoted attributes.
pub(crate) fn escape_attr_value(input: &str, out: &mut impl std::fmt::Write) -> std::fmt::Result {
    for ch in input.chars() {
        match ch {
            '&' => {
                out.write_str("&amp;")?;
            }
            '<' => {
                out.write_str("&lt;")?;
            }
            '"' => {
                out.write_str("&quot;")?;
            }
            '\t' => {
                out.write_str("&#x9;")?;
            }
            '\n' => {
                out.write_str("&#xA;")?;
            }
            '\r' => {
                out.write_str("&#xD;")?;
            }
            _ => {
                out.write_char(ch)?;
            }
        }
    }
    Ok(())
}

// ── W3C C14N conformance tests ────────────────────────────────────────────────
//
// Source specifications:
//   Canonical XML 1.0 — https://www.w3.org/TR/2001/REC-xml-c14n-20010315 §3
//   Exclusive C14N 1.0 — https://www.w3.org/TR/xml-exc-c14n/ §2
//
// Constraint: roxmltree is a non-validating parser.  Tests that require ATTLIST
// default-attribute expansion (W3C §3.3 e9) or internal entity substitution
// (§3.4) are either omitted or adapted to use pre-expanded input.
#[cfg(test)]
mod w3c_c14n_vectors {
    use super::{
        EMPTY_NS_MAP, canonical_vector_diff, canonicalize_document, escape_attr_value, escape_text,
        try_serialize_node_with_inclusive_ns,
    };
    use crate::crypto::wssec::{WsSecCanonicalizationKind, WsSecCanonicalizationProfile};
    use roxmltree::Document;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn inc_profile() -> WsSecCanonicalizationProfile {
        WsSecCanonicalizationProfile {
            kind: WsSecCanonicalizationKind::Inclusive,
            include_comments: false,
            strip_blank_text: false,
            inclusive_ns_prefixes: Vec::new(),
        }
    }

    fn inc_with_comments() -> WsSecCanonicalizationProfile {
        WsSecCanonicalizationProfile {
            kind: WsSecCanonicalizationKind::Inclusive,
            include_comments: true,
            strip_blank_text: false,
            inclusive_ns_prefixes: Vec::new(),
        }
    }

    fn exc_profile() -> WsSecCanonicalizationProfile {
        WsSecCanonicalizationProfile {
            kind: WsSecCanonicalizationKind::Exclusive,
            include_comments: false,
            strip_blank_text: false,
            inclusive_ns_prefixes: Vec::new(),
        }
    }

    /// Serialize the element whose `id` attribute (case-insensitive) equals
    /// `id_value` using `try_serialize_node_with_inclusive_ns` with an empty
    /// parent namespace context.
    fn canonicalize_element_by_id(
        xml: &str,
        id_value: &str,
        profile: &WsSecCanonicalizationProfile,
    ) -> String {
        let doc = Document::parse(xml).expect("parse");
        let target = doc
            .descendants()
            .find(|n| {
                n.is_element()
                    && n.attributes()
                        .any(|a| a.name().eq_ignore_ascii_case("id") && a.value() == id_value)
            })
            .unwrap_or_else(|| panic!("element with id={id_value} not found"));
        let mut out = String::new();
        try_serialize_node_with_inclusive_ns(target, &mut out, profile, &EMPTY_NS_MAP, None)
            .expect("serialize");
        out
    }

    /// Like `canonicalize_element_by_id` but passes an explicit inclusive
    /// namespace prefix list (for Exc-C14N InclusiveNamespaces tests).
    fn canonicalize_element_by_id_with_inc_list(
        xml: &str,
        id_value: &str,
        profile: &WsSecCanonicalizationProfile,
        inc_prefixes: &[String],
    ) -> String {
        let doc = Document::parse(xml).expect("parse");
        let target = doc
            .descendants()
            .find(|n| {
                n.is_element()
                    && n.attributes()
                        .any(|a| a.name().eq_ignore_ascii_case("id") && a.value() == id_value)
            })
            .unwrap_or_else(|| panic!("element with id={id_value} not found"));
        let mut out = String::new();
        try_serialize_node_with_inclusive_ns(
            target,
            &mut out,
            profile,
            &EMPTY_NS_MAP,
            Some(inc_prefixes),
        )
        .expect("serialize");
        out
    }

    // ── W3C Canonical XML 1.0 §3.1 — PIs, Comments, Outside Document Element ─

    /// PI before the document element receives a trailing `\n`; PI after
    /// receives a leading `\n`.  Comments are stripped in the uncommented form.
    #[test]
    fn w3c_3_1_pis_outside_doc_elem_uncommented() {
        // roxmltree does not accept DOCTYPE; test the PI placement rule only.
        let xml = r#"<?xml-stylesheet href="doc.xsl" type="text/xsl"?><doc>Hello, world!</doc><?pi-without-data?>"#;
        let expected = concat!(
            "<?xml-stylesheet href=\"doc.xsl\" type=\"text/xsl\"?>\n",
            "<doc>Hello, world!</doc>\n",
            "<?pi-without-data?>"
        );
        let result = canonicalize_document(xml, &inc_profile()).expect("c14n");
        assert_eq!(
            result,
            expected,
            "W3C §3.1 PI placement diff:\n{}",
            canonical_vector_diff(expected, &result)
        );
    }

    /// PI after document element, comments at root level: retained in commented
    /// form with correct `\n` separators.
    #[test]
    fn w3c_3_1_pis_and_comments_commented_form() {
        let xml = r#"<?xml-stylesheet href="doc.xsl" type="text/xsl"?><doc>Hello, world!<!-- Comment 1 --></doc><?pi-without-data?><!-- Comment 2 --><!-- Comment 3 -->"#;
        let expected = concat!(
            "<?xml-stylesheet href=\"doc.xsl\" type=\"text/xsl\"?>\n",
            "<doc>Hello, world!<!-- Comment 1 --></doc>\n",
            "<?pi-without-data?>\n",
            "<!-- Comment 2 -->\n",
            "<!-- Comment 3 -->"
        );
        let result = canonicalize_document(xml, &inc_with_comments()).expect("c14n");
        assert_eq!(
            result,
            expected,
            "W3C §3.1 commented form diff:\n{}",
            canonical_vector_diff(expected, &result)
        );
    }

    // ── W3C Canonical XML 1.0 §3.2 — Whitespace in Document Content ──────────

    /// All whitespace in element content is preserved unchanged.
    #[test]
    fn w3c_3_2_whitespace_in_document_content_preserved() {
        let xml = "<doc>   <clean>   </clean>   <dirty>   A   B   </dirty>   </doc>";
        let result = canonicalize_document(xml, &inc_profile()).expect("c14n");
        assert!(
            result.contains("   A   B   "),
            "W3C §3.2: whitespace in content not preserved: {result}"
        );
        assert!(
            result.contains(">   </clean>"),
            "W3C §3.2: whitespace before close tag stripped: {result}"
        );
    }

    // ── W3C Canonical XML 1.0 §3.3 — Start and End Tags ─────────────────────

    /// Self-closing empty elements must become start+end tag pairs.
    #[test]
    fn w3c_3_3_empty_elements_expanded_to_start_end_tags() {
        let xml = r#"<doc><e1/><e2></e2></doc>"#;
        let expected = "<doc><e1></e1><e2></e2></doc>";
        let result = canonicalize_document(xml, &inc_profile()).expect("c14n");
        assert_eq!(
            result,
            expected,
            "W3C §3.3 empty element expansion diff:\n{}",
            canonical_vector_diff(expected, &result)
        );
    }

    /// Attribute ordering per C14N §3.3: namespace URI is the primary sort key,
    /// local name is secondary.  Unqualified attributes sort before any
    /// namespaced attribute (empty URI "" < any non-empty URI).
    ///
    /// W3C example element e5:
    ///   Original: a:attr, b:attr, attr2, attr, xmlns:b=ietf, xmlns:a=w3c, xmlns=example
    ///   Canonical attr order: attr(no-ns) attr2(no-ns) b:attr(ietf) a:attr(w3c)
    ///   because ietf < w3c lexicographically.
    #[test]
    fn w3c_3_3_attribute_namespace_uri_sort_order() {
        let xml = r##"<e5 a:attr="out" b:attr="sorted" attr2="all" attr="I'm"
               xmlns:b="http://www.ietf.org"
               xmlns:a="http://www.w3.org"
               xmlns="http://example.org"></e5>"##;

        let expected = r##"<e5 xmlns="http://example.org" xmlns:a="http://www.w3.org" xmlns:b="http://www.ietf.org" attr="I'm" attr2="all" b:attr="sorted" a:attr="out"></e5>"##;

        let result = canonicalize_document(xml, &inc_profile()).expect("c14n");
        assert_eq!(
            result,
            expected,
            "W3C §3.3 attribute sort order diff:\n{}",
            canonical_vector_diff(expected, &result)
        );
    }

    /// Namespace declarations are sorted lexicographically by prefix.
    #[test]
    fn w3c_3_3_namespace_declarations_sorted_by_prefix() {
        let xml = r#"<e xmlns:z="urn:z" xmlns:a="urn:a" xmlns:m="urn:m" z:x="1"></e>"#;
        // Inclusive C14N: all declared → xmlns:a, xmlns:m, xmlns:z (sorted by prefix)
        let expected_inc = r#"<e xmlns:a="urn:a" xmlns:m="urn:m" xmlns:z="urn:z" z:x="1"></e>"#;
        let result = canonicalize_document(xml, &inc_profile()).expect("c14n");
        assert_eq!(
            result,
            expected_inc,
            "§3.3 namespace sort (Inclusive):\n{}",
            canonical_vector_diff(expected_inc, &result)
        );
    }

    /// Superfluous namespace declarations in descendants must not be re-emitted.
    /// When a namespace is already in scope from an ancestor, the child element
    /// must NOT re-declare it.
    #[test]
    fn w3c_3_3_superfluous_namespace_suppression() {
        let xml = r#"<e6 xmlns="http://example.org" xmlns:a="http://www.w3.org">
  <e7>
    <e8 xmlns="">
      <e9></e9>
    </e8>
  </e7>
</e6>"#;
        let result = canonicalize_document(xml, &inc_profile()).expect("c14n");
        // e6: declares both namespaces
        assert!(
            result.contains(r#"<e6 xmlns="http://example.org" xmlns:a="http://www.w3.org">"#),
            "e6 must declare both namespaces: {result}"
        );
        // e7: inherits — no xmlns* re-declaration
        assert!(
            !result.contains(r#"<e7 xmlns"#),
            "e7 must not re-declare inherited namespaces: {result}"
        );
        // e8: undeclares default namespace → xmlns=""
        assert!(
            result.contains(r#"<e8 xmlns="">"#),
            "e8 must emit xmlns=\"\" to undeclare default ns: {result}"
        );
        // e9: inside e8 (which has xmlns=""), no re-declaration needed
        let e9_start = result.find("<e9").expect("e9 missing");
        let e9_end = result[e9_start..].find('>').unwrap();
        let e9_open = &result[e9_start..e9_start + e9_end + 1];
        assert!(
            !e9_open.contains("xmlns"),
            "e9 must not re-declare xmlns=\"\" (already inherited from e8): {e9_open}"
        );
    }

    // ── W3C Canonical XML 1.0 §3.4 — Character Modifications ────────────────

    /// CR in text content is escaped to `&#xD;` — but XML parsers normalize
    /// standalone `\r` to `\n` per XML §2.11 before we see it.
    /// To get a literal CR through to C14N, use the `&#xD;` numeric reference in
    /// the input (which roxmltree passes through as the character U+000D).
    #[test]
    fn w3c_3_4_cr_in_text_becomes_num_ref() {
        // Using &#xD; in the source XML → the parser gives us the literal \r character,
        // which our escape_text then converts to &#xD; in the output.
        let xml = "<doc><t>line1&#xD;line2</t></doc>";
        let result = canonicalize_document(xml, &inc_profile()).expect("c14n");
        assert!(
            result.contains("line1&#xD;line2"),
            "CR (from &#xD; numeric ref) must become &#xD; in text content: {result}"
        );
    }

    /// `<`, `>`, `&` in text content are entity-escaped.
    #[test]
    fn w3c_3_4_text_entity_escaping() {
        let xml = "<doc><t>&lt;tag&gt; &amp; rest</t></doc>";
        let result = canonicalize_document(xml, &inc_profile()).expect("c14n");
        assert!(
            result.contains("&lt;tag&gt; &amp; rest"),
            "text entity escaping failed: {result}"
        );
    }

    /// CDATA sections are replaced by their character data with standard escaping.
    #[test]
    fn w3c_3_4_cdata_expanded_and_escaped() {
        let xml = r#"<doc><![CDATA[value>"0" && value<"10"]]></doc>"#;
        let result = canonicalize_document(xml, &inc_profile()).expect("c14n");
        assert!(
            result.contains("value&gt;"),
            "CDATA > must become &gt;: {result}"
        );
        assert!(
            result.contains("value&lt;"),
            "CDATA < must become &lt;: {result}"
        );
        assert!(
            result.contains("&amp;&amp;"),
            "CDATA && must become &amp;&amp;: {result}"
        );
    }

    /// Attribute values: tab (#x9), LF (#xA), CR (#xD) are escaped numerically.
    #[test]
    fn w3c_3_4_attribute_whitespace_escaping() {
        let xml = "<doc><e attr=\"tab&#x9;lf&#xA;cr&#xD;end\"></e></doc>";
        let result = canonicalize_document(xml, &inc_profile()).expect("c14n");
        assert!(
            result.contains(r#"attr="tab&#x9;lf&#xA;cr&#xD;end""#),
            "attribute whitespace chars must be escaped: {result}"
        );
    }

    /// Double quotes inside attribute values must be `&quot;`.
    #[test]
    fn w3c_3_4_double_quote_escaped_in_attribute() {
        let xml = r#"<doc><e attr='say "hello"'></e></doc>"#;
        let result = canonicalize_document(xml, &inc_profile()).expect("c14n");
        assert!(
            result.contains(r#"attr="say &quot;hello&quot;""#),
            "inner \" in attribute must become &quot;: {result}"
        );
    }

    // ── W3C Canonical XML 1.0 §3.6 — UTF-8 output ───────────────────────────

    /// Non-ASCII characters must be emitted as UTF-8, not as numeric refs.
    #[test]
    fn w3c_3_6_non_ascii_emitted_as_utf8() {
        let xml = "<doc>\u{00A9}\u{20AC}</doc>";
        let result = canonicalize_document(xml, &inc_profile()).expect("c14n");
        assert!(
            result.contains('\u{00A9}'),
            "© must be UTF-8 in output: {result}"
        );
        assert!(
            result.contains('\u{20AC}'),
            "€ must be UTF-8 in output: {result}"
        );
        assert!(
            !result.contains("&#xA9;") && !result.contains("&#x20AC;"),
            "no numeric escapes for non-ASCII: {result}"
        );
    }

    // ── Escape helper unit tests ──────────────────────────────────────────────

    #[test]
    fn escape_text_helper_covers_required_chars() {
        let mut out = String::new();
        escape_text("<>&\r\t\n", &mut out).unwrap();
        // < → &lt;, > → &gt;, & → &amp;, CR → &#xD;, TAB kept, LF kept
        assert_eq!(out, "&lt;&gt;&amp;&#xD;\t\n");
    }

    #[test]
    fn escape_attr_value_helper_covers_required_chars() {
        let mut out = String::new();
        // C14N §2.3: in attribute values, escape &, <, ", and whitespace chars.
        // Note: > is NOT escaped in attribute values (only in text content).
        escape_attr_value("<>&\"\t\n\r", &mut out).unwrap();
        assert_eq!(out, "&lt;>&amp;&quot;&#x9;&#xA;&#xD;");
    }

    #[test]
    fn escape_attr_value_single_quote_not_escaped() {
        let mut out = String::new();
        escape_attr_value("I'm here", &mut out).unwrap();
        assert_eq!(out, "I'm here");
    }

    // ── W3C Exclusive C14N §2.1 — Simple re-enveloping ───────────────────────

    /// elem1 in Exc-C14N must be invariant regardless of enveloping context:
    /// the outer `n0` namespace must NOT appear on the canonical form of elem1.
    #[test]
    fn w3c_exc_c14n_2_1_enveloping_does_not_pollute() {
        let xml_standalone = r#"<n1:elem1 id="e1" xmlns:n1="http://b.example">content</n1:elem1>"#;
        let xml_enveloped = r#"<n0:pdu xmlns:n0="http://a.example">
          <n1:elem1 id="e1" xmlns:n1="http://b.example">content</n1:elem1>
        </n0:pdu>"#;

        let c14n_standalone = canonicalize_element_by_id(xml_standalone, "e1", &exc_profile());
        let c14n_enveloped = canonicalize_element_by_id(xml_enveloped, "e1", &exc_profile());

        assert_eq!(
            c14n_standalone, c14n_enveloped,
            "Exc-C14N §2.1: elem1 must be invariant across enveloping contexts.\nStandalone: {c14n_standalone}\nEnveloped:  {c14n_enveloped}"
        );
        assert!(
            !c14n_enveloped.contains("n0"),
            "Exc-C14N §2.1: n0 namespace must not appear: {c14n_enveloped}"
        );
        assert!(
            c14n_enveloped.contains(r#"xmlns:n1="http://b.example""#),
            "Exc-C14N §2.1: n1 namespace must appear: {c14n_enveloped}"
        );
    }

    // ── W3C Exclusive C14N §2.2 — Re-enveloping invariance ───────────────────

    /// elem2 under Exc-C14N must produce the same canonical form regardless of
    /// which outer element envelopes it, even when the outer elements declare
    /// different namespace prefixes.
    ///
    /// W3C Exc-C14N §2.2 expected form:
    /// ```xml
    /// <n1:elem2 xmlns:n1="http://example.net" xml:lang="en">
    ///   <n3:stuff xmlns:n3="ftp://example.org"></n3:stuff>
    /// </n1:elem2>
    /// ```
    #[test]
    fn w3c_exc_c14n_2_2_elem2_invariant_across_contexts() {
        let xml_ctx1 = r#"<n0:local xmlns:n0="foo:bar" xmlns:n3="ftp://example.org">
  <n1:elem2 id="elem2" xmlns:n1="http://example.net" xml:lang="en">
    <n3:stuff xmlns:n3="ftp://example.org"></n3:stuff>
  </n1:elem2>
</n0:local>"#;

        let xml_ctx2 = r#"<n2:pdu xmlns:n1="http://example.com"
        xmlns:n2="http://foo.example"
        xml:lang="fr"
        xml:space="retain">
  <n1:elem2 id="elem2" xmlns:n1="http://example.net" xml:lang="en">
    <n3:stuff xmlns:n3="ftp://example.org"></n3:stuff>
  </n1:elem2>
</n2:pdu>"#;

        let c14n1 = canonicalize_element_by_id(xml_ctx1, "elem2", &exc_profile());
        let c14n2 = canonicalize_element_by_id(xml_ctx2, "elem2", &exc_profile());

        assert_eq!(
            c14n1, c14n2,
            "Exc-C14N §2.2: elem2 must be invariant.\nCtx1: {c14n1}\nCtx2: {c14n2}"
        );
        // n0 and n2 are enveloping-context namespaces — must not appear.
        assert!(
            !c14n1.contains("n0"),
            "n0 must not appear in Exc-C14N elem2: {c14n1}"
        );
        assert!(
            !c14n1.contains("n2"),
            "n2 must not appear in Exc-C14N elem2: {c14n1}"
        );
        // n1 is visibly utilized (the element's own namespace).
        assert!(
            c14n1.contains(r#"xmlns:n1="http://example.net""#),
            "n1 namespace must appear: {c14n1}"
        );
        // n3 is visibly utilized by n3:stuff.
        assert!(
            c14n1.contains(r#"xmlns:n3="ftp://example.org""#),
            "n3 namespace must appear on n3:stuff: {c14n1}"
        );
    }

    // ── Exc-C14N InclusiveNamespaces PrefixList ───────────────────────────────

    /// When a prefix is in the InclusiveNamespaces PrefixList, its namespace
    /// declaration must appear on the apex element even if not visibly utilized.
    #[test]
    fn exc_c14n_inclusive_ns_prefix_list_forces_declaration() {
        let xml = r#"<root xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"
                           xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
          <child id="c1">content</child>
        </root>"#;

        // Without prefix list: child uses no namespaces → no xmlns* emitted.
        let c14n_no_list = canonicalize_element_by_id(xml, "c1", &exc_profile());
        assert!(
            !c14n_no_list.contains("dsig"),
            "Without prefix list, dsig must not appear: {c14n_no_list}"
        );

        // With PrefixList="dsig": dsig must appear even though child doesn't use it.
        let inc_prefixes = vec!["dsig".to_string()];
        let c14n_with_list =
            canonicalize_element_by_id_with_inc_list(xml, "c1", &exc_profile(), &inc_prefixes);
        assert!(
            c14n_with_list.contains(r#"xmlns:dsig="http://www.w3.org/2000/09/xmldsig#""#),
            "With PrefixList=dsig, dsig namespace must appear: {c14n_with_list}"
        );
        // soap was NOT in the list → must not appear.
        assert!(
            !c14n_with_list.contains("soap"),
            "soap not in prefix list, must not appear: {c14n_with_list}"
        );
    }

    // ── Inclusive C14N: default namespace undeclaration ──────────────────────

    /// When an element resets the default namespace to empty (xmlns=""), its
    /// descendants must NOT repeat the undeclaration.
    #[test]
    fn inc_c14n_default_namespace_undeclaration_not_repeated_in_descendants() {
        let xml = r#"<root xmlns="urn:default">
  <child xmlns="">
    <inner></inner>
  </child>
</root>"#;
        let result = canonicalize_document(xml, &inc_profile()).expect("c14n");
        // child must emit xmlns="" to undeclare the inherited default namespace.
        assert!(
            result.contains(r#"<child xmlns="">"#),
            "child must emit xmlns=\"\": {result}"
        );
        // inner is inside child (xmlns="") — no re-declaration.
        let inner_start = result.find("<inner").expect("inner missing");
        let inner_tag_end = result[inner_start..].find('>').unwrap();
        let inner_open = &result[inner_start..inner_start + inner_tag_end + 1];
        assert!(
            !inner_open.contains("xmlns"),
            "inner must not re-declare xmlns=\"\": {inner_open}"
        );
    }

    // ── Inclusive vs Exclusive C14N namespace accumulation ───────────────────

    /// Inclusive C14N accumulates ALL in-scope namespace declarations;
    /// Exclusive C14N emits only visibly-utilized ones.
    #[test]
    fn inclusive_vs_exclusive_namespace_accumulation() {
        let xml = r#"<root xmlns:a="urn:a" xmlns:b="urn:b">
  <child id="c1" a:x="1">text</child>
</root>"#;

        let inc = canonicalize_element_by_id(xml, "c1", &inc_profile());
        let exc = canonicalize_element_by_id(xml, "c1", &exc_profile());

        // Inclusive: both xmlns:a and xmlns:b must appear.
        assert!(
            inc.contains(r#"xmlns:a="urn:a""#),
            "Inclusive: xmlns:a must appear: {inc}"
        );
        assert!(
            inc.contains(r#"xmlns:b="urn:b""#),
            "Inclusive: xmlns:b must appear: {inc}"
        );

        // Exclusive: only xmlns:a (used by a:x); xmlns:b absent.
        assert!(
            exc.contains(r#"xmlns:a="urn:a""#),
            "Exclusive: xmlns:a must appear (used by a:x): {exc}"
        );
        assert!(
            !exc.contains(r#"xmlns:b"#),
            "Exclusive: xmlns:b must NOT appear (not visibly utilized): {exc}"
        );
    }

    // ── Exc-C14N: xml:* attrs from ancestors not propagated ──────────────────

    /// Per W3C Exc-C14N §3: xml:lang and xml:space from ancestor elements are
    /// NOT copied into the apex element's canonical form.
    #[test]
    fn exc_c14n_xml_ns_attrs_not_propagated_from_ancestors() {
        let xml = r#"<outer xml:lang="fr" xml:space="preserve">
  <inner id="inner">content</inner>
</outer>"#;
        let result = canonicalize_element_by_id(xml, "inner", &exc_profile());
        assert!(
            !result.contains("xml:lang"),
            "Exc-C14N: xml:lang from ancestor must not appear: {result}"
        );
        assert!(
            !result.contains("xml:space"),
            "Exc-C14N: xml:space from ancestor must not appear: {result}"
        );
    }

    // ── AS4/SOAP: WS-Security SignedInfo Exc-C14N + InclusiveNamespaces ───────

    /// Real-world OASIS WS-Security SignedInfo element: Exc-C14N with
    /// PrefixList="wsse" ensures wsse namespace propagates into the canonical
    /// SignedInfo even though SignedInfo itself is in the ds: namespace.
    #[test]
    fn wssec_signed_info_exc_c14n_with_wsse_inclusive_ns() {
        let xml = r#"<S12:Envelope
            xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <S12:Header>
            <wsse:Security>
              <ds:Signature>
                <ds:SignedInfo id="siginfo">
                  <ds:CanonicalizationMethod
                    Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                    <ec:InclusiveNamespaces PrefixList="wsse"
                      xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                  </ds:CanonicalizationMethod>
                </ds:SignedInfo>
              </ds:Signature>
            </wsse:Security>
          </S12:Header>
          <S12:Body/>
        </S12:Envelope>"#;

        let inc_prefixes = vec!["wsse".to_string()];
        let result =
            canonicalize_element_by_id_with_inc_list(xml, "siginfo", &exc_profile(), &inc_prefixes);

        // ds: namespace must appear (SignedInfo is in ds: namespace).
        assert!(
            result.contains(r#"xmlns:ds="http://www.w3.org/2000/09/xmldsig#""#),
            "ds namespace must appear: {result}"
        );
        // wsse must appear (in InclusiveNamespaces PrefixList).
        assert!(
            result.contains(r#"xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd""#),
            "wsse namespace must appear (in PrefixList): {result}"
        );
        // S12/S12 envelope namespace must NOT appear (not visibly utilized).
        assert!(
            !result.contains("S12"),
            "S12 namespace must not appear in SignedInfo: {result}"
        );
    }
}
