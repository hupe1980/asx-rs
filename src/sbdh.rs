//! Standard Business Document Header (SBDH) — UN/CEFACT SBDH 1.3.
//!
//! SBDH is a standardised envelope used by Peppol, CEF eDelivery, and other
//! European e-invoicing networks to wrap business documents (e.g., UBL invoices
//! or CII credit notes) with routing and identification metadata.
//!
//! This module implements [`StandardBusinessDocument::wrap`] (serialize to XML)
//! and [`StandardBusinessDocument::unwrap`] (parse from XML), covering the
//! mandatory SBDH elements used in production Peppol / EESSI message exchanges.
//!
//! ## Wire format
//!
//! ```xml
//! <StandardBusinessDocument
//!     xmlns="http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader">
//!   <StandardBusinessDocumentHeader>
//!     <HeaderVersion>1.0</HeaderVersion>
//!     <Sender>
//!       <Identifier Authority="iso6523-actorid-upis">0007:9876543210987</Identifier>
//!     </Sender>
//!     <Receiver>
//!       <Identifier Authority="iso6523-actorid-upis">0007:1234567890123</Identifier>
//!     </Receiver>
//!     <DocumentIdentification>
//!       <Standard>urn:oasis:names:specification:ubl:schema:xsd:Invoice-2</Standard>
//!       <TypeVersion>2.1</TypeVersion>
//!       <InstanceIdentifier>urn:uuid:550e8400-e29b-41d4-a716-446655440000</InstanceIdentifier>
//!       <Type>Invoice</Type>
//!       <MultipleType>false</MultipleType>
//!       <CreationDateAndTime>2026-01-01T12:00:00+00:00</CreationDateAndTime>
//!     </DocumentIdentification>
//!   </StandardBusinessDocumentHeader>
//!   <!-- business document payload (XML) embedded directly -->
//! </StandardBusinessDocument>
//! ```
//!
//! ## Usage
//!
//! ```text
//! # use asx::sbdh::{
//! #     StandardBusinessDocument, SbdhHeader, SbdhParty, SbdhDocumentIdentification,
//! #     SbdhScope, peppol_scope,
//! # };
//! let doc = StandardBusinessDocument {
//!     header: SbdhHeader {
//!         header_version: "1.0".into(),
//!         sender: SbdhParty { identifier: "0007:1234567890".into(), authority: "iso6523-actorid-upis".into() },
//!         receiver: SbdhParty { identifier: "0007:9876543210".into(), authority: "iso6523-actorid-upis".into() },
//!         business_scope: vec![
//!             // Peppol requires at least these two.
//!             SbdhScope::with_scheme(
//!                 peppol_scope::DOCUMENT_ID,
//!                 "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1",
//!                 "busdox-docid-qns",
//!             ),
//!             SbdhScope::with_scheme(
//!                 peppol_scope::PROCESS_ID,
//!                 "urn:fdc:peppol.eu:2017:poacc:billing:01:1.0",
//!                 "cenbii-procid-ubl",
//!             ),
//!             SbdhScope::new(peppol_scope::COUNTRY_C1, "BE"),
//!         ],
//!         document_identification: SbdhDocumentIdentification {
//!             standard: "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2".into(),
//!             type_version: "2.1".into(),
//!             instance_identifier: "urn:uuid:abc123".into(),
//!             r#type: "Invoice".into(),
//!             multiple_type: false,
//!             creation_date_and_time: "2026-01-01T12:00:00+00:00".into(),
//!         },
//!     },
//!     payload: b"<Invoice/>".to_vec(),
//! };
//!
//! let wrapped = doc.wrap().unwrap();
//! let parsed = StandardBusinessDocument::unwrap(&wrapped).unwrap();
//! assert_eq!(parsed.header.sender.identifier, "0007:1234567890");
//! assert_eq!(parsed.payload, b"<Invoice/>");
//! ```

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

/// XML namespace for SBDH 1.3 documents.
pub const SBDH_NAMESPACE: &str = crate::xml::ns::SBDH;

// ── Public types ──────────────────────────────────────────────────────────────

/// Sender or receiver party in an SBDH envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbdhParty {
    /// Party identifier value.
    ///
    /// For Peppol, this is `<scheme>:<participant-id>` (e.g., `"0007:9876543210987"`
    /// for a German VAT-registered participant).
    pub identifier: String,
    /// Identifier scheme authority.
    ///
    /// Peppol uses `"iso6523-actorid-upis"`.  Other networks may use scheme-specific
    /// authority strings defined in their interoperability agreements.
    pub authority: String,
}

/// Document identification metadata embedded in an SBDH envelope.
///
/// These fields identify the enclosed business document and are used for routing,
/// duplicate detection, and tracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbdhDocumentIdentification {
    /// Document type standard namespace URI.
    ///
    /// Example: `"urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"`.
    pub standard: String,
    /// Schema version string (e.g., `"2.1"`, `"D16B"`).
    pub type_version: String,
    /// Globally unique instance identifier.
    ///
    /// Should be a UUID URN (e.g., `"urn:uuid:550e8400-e29b-41d4-a716-446655440000"`)
    /// or another scheme-scoped unique string.
    pub instance_identifier: String,
    /// Human-readable document type (e.g., `"Invoice"`, `"Order"`, `"Despatch Advice"`).
    pub r#type: String,
    /// Whether the document carries multiple document types.  Typically `false`.
    pub multiple_type: bool,
    /// ISO 8601 creation timestamp (e.g., `"2026-05-18T12:00:00+00:00"`).
    pub creation_date_and_time: String,
}

// ── Business scope ───────────────────────────────────────────────────────────

/// Peppol's namespace for the non-XML payload wrappers.
pub const PEPPOL_ENVELOPE_NAMESPACE: &str = crate::xml::ns::PEPPOL_ENVELOPE;

/// Well-known `Scope/Type` values reserved by the Peppol network.
///
/// Peppol's Business Message Envelope carries every one of its parameters as a
/// `<Scope>` entry keyed by `Type`, so these are the keys — not a separate
/// mechanism. They are reserved network-wide and
/// [MUST NOT be used for other purposes][bme] (BME 2.0.2 §2.7.1).
///
/// [bme]: https://docs.peppol.eu/edelivery/envelope/
pub mod peppol_scope {
    /// The Peppol Document Type Identifier (BME §2.4). **Required.**
    pub const DOCUMENT_ID: &str = "DOCUMENTID";
    /// The Peppol Process Identifier (BME §2.4). **Required.**
    pub const PROCESS_ID: &str = "PROCESSID";
    /// Country code of the original sender, corner 1 (BME §2.5).
    pub const COUNTRY_C1: &str = "COUNTRY_C1";
    /// Reserved for future use by the network.
    pub const COUNTRY_C4: &str = "COUNTRY_C4";
    /// A specific Message Level Status receiver (BME §2.6.1).
    pub const MLS_TO: &str = "MLS_TO";
    /// A specific Message Level Status usage type (BME §2.6.2).
    ///
    /// Absent means `FAILURE_ONLY` — Peppol Network Policy 1.0.0 rule MLS-3
    /// says a positive MLS is sent only when the sender opted in.
    pub const MLS_TYPE: &str = "MLS_TYPE";
}

/// One `<Scope>` entry: a key, a value, and optionally the scheme the value is
/// expressed in.
///
/// This is the whole extensibility mechanism of the Peppol envelope. A scope
/// may also carry **no** value — an indicator attribute — which is why
/// `instance_identifier` is a `String` that is allowed to be empty rather than
/// an `Option`: the element is present either way, and absence of the element
/// means absence of the scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbdhScope {
    /// `<Type>` — the key. Use a [`peppol_scope`] constant for a reserved one.
    pub scope_type: String,
    /// `<InstanceIdentifier>` — the value. Empty for an indicator attribute.
    pub instance_identifier: String,
    /// `<Identifier>` — the scheme the value is expressed in, e.g.
    /// `busdox-docid-qns` for a document type or `iso6523-actorid-upis` for a
    /// participant.
    ///
    /// New in Business Message Envelope 2.0; older receivers read the scheme
    /// from a prefix on the value instead, so emitting it is additive.
    pub identifier: Option<String>,
}

impl SbdhScope {
    /// A scope with a value and no scheme.
    pub fn new(scope_type: impl Into<String>, instance_identifier: impl Into<String>) -> Self {
        Self {
            scope_type: scope_type.into(),
            instance_identifier: instance_identifier.into(),
            identifier: None,
        }
    }

    /// A scope whose value is expressed in a named identifier scheme.
    pub fn with_scheme(
        scope_type: impl Into<String>,
        instance_identifier: impl Into<String>,
        identifier: impl Into<String>,
    ) -> Self {
        Self {
            scope_type: scope_type.into(),
            instance_identifier: instance_identifier.into(),
            identifier: Some(identifier.into()),
        }
    }

    /// An indicator attribute — present, with no value.
    pub fn indicator(scope_type: impl Into<String>) -> Self {
        Self {
            scope_type: scope_type.into(),
            instance_identifier: String::new(),
            identifier: None,
        }
    }
}

/// Standard Business Document Header metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbdhHeader {
    /// SBDH schema version.  Always `"1.0"` per UN/CEFACT SBDH 1.3.
    pub header_version: String,
    /// Sending party.
    pub sender: SbdhParty,
    /// Receiving party.
    pub receiver: SbdhParty,
    /// Document identification.
    pub document_identification: SbdhDocumentIdentification,
    /// `<BusinessScope>` — the envelope's parameters, as `<Scope>` entries.
    ///
    /// Empty emits no `<BusinessScope>` element at all, which is what a bare
    /// UN/CEFACT SBDH looks like. **Peppol requires it**: a Business Message
    /// Envelope carries at least `DOCUMENTID` and `PROCESSID`
    /// ([`peppol_scope`]), and an access point rejects an envelope without
    /// them. Use [`SbdhHeader::scope`] to read one back.
    pub business_scope: Vec<SbdhScope>,
}

impl SbdhHeader {
    /// The first scope with this `Type`, if present.
    ///
    /// ```text
    /// # use asx::sbdh::{SbdhHeader, SbdhScope, peppol_scope};
    /// # fn example(header: &SbdhHeader) {
    /// let doc_type = header.scope(peppol_scope::DOCUMENT_ID);
    /// # let _ = doc_type;
    /// # }
    /// ```
    pub fn scope(&self, scope_type: &str) -> Option<&SbdhScope> {
        self.business_scope
            .iter()
            .find(|s| s.scope_type == scope_type)
    }

    /// The value of the first scope with this `Type`.
    pub fn scope_value(&self, scope_type: &str) -> Option<&str> {
        self.scope(scope_type)
            .map(|s| s.instance_identifier.as_str())
    }
}

/// A business document wrapped with an SBDH envelope.
///
/// Use [`wrap`](Self::wrap) to serialize to XML and [`unwrap`](Self::unwrap)
/// to parse from XML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandardBusinessDocument {
    /// SBDH envelope metadata.
    pub header: SbdhHeader,
    /// Raw business document bytes (typically XML).
    pub payload: Vec<u8>,
}

// ── Serialization ─────────────────────────────────────────────────────────────

impl StandardBusinessDocument {
    /// Serialize this document to UTF-8 XML bytes conforming to SBDH 1.3.
    ///
    /// The payload bytes are embedded verbatim as a child element of
    /// `<StandardBusinessDocument>`.  The caller is responsible for ensuring
    /// the payload is valid XML and that its root element does not conflict
    /// with the SBDH namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if any header field contains XML-unsafe content that
    /// cannot be safely escaped (e.g., invalid UTF-8 in fields derived from
    /// untrusted input).
    pub fn wrap(&self) -> Result<Vec<u8>> {
        use crate::xml::{XmlLimits, XmlOut, ns};
        let h = &self.header;
        let di = &h.document_identification;
        let payload = std::str::from_utf8(&self.payload).map_err(|_| {
            AsxError::new(
                ErrorCode::InvalidInput,
                "SBDH payload is not valid UTF-8",
                ErrorContext::new("sbdh_wrap"),
            )
        })?;

        // The envelope uses the `sh:` prefix (as phase4 writes it), so an
        // unprefixed payload keeps its own namespace instead of inheriting the
        // SBDH default namespace.
        let mut out = XmlOut::new();
        out.declaration();
        out.start("sh:StandardBusinessDocument")?
            .ns("sh", ns::SBDH)?;
        out.start("sh:StandardBusinessDocumentHeader")?;
        out.leaf(
            "sh:HeaderVersion",
            &h.header_version,
            "SbdhHeader::header_version",
        )?;
        for (element, party, field) in [
            ("sh:Sender", &h.sender, "SbdhHeader::sender"),
            ("sh:Receiver", &h.receiver, "SbdhHeader::receiver"),
        ] {
            out.start(element)?
                .start("sh:Identifier")?
                .attr("Authority", &party.authority, field)?
                .text(&party.identifier, field)?
                .end()?
                .end()?;
        }
        out.start("sh:DocumentIdentification")?;
        out.leaf(
            "sh:Standard",
            &di.standard,
            "SbdhDocumentIdentification::standard",
        )?;
        out.leaf(
            "sh:TypeVersion",
            &di.type_version,
            "SbdhDocumentIdentification::type_version",
        )?;
        out.leaf(
            "sh:InstanceIdentifier",
            &di.instance_identifier,
            "SbdhDocumentIdentification::instance_identifier",
        )?;
        out.leaf("sh:Type", &di.r#type, "SbdhDocumentIdentification::type")?;
        out.leaf(
            "sh:MultipleType",
            if di.multiple_type { "true" } else { "false" },
            "SbdhDocumentIdentification::multiple_type",
        )?;
        out.leaf(
            "sh:CreationDateAndTime",
            &di.creation_date_and_time,
            "SbdhDocumentIdentification::creation_date_and_time",
        )?;
        out.end()?;
        write_business_scope(&mut out, &h.business_scope)?;
        out.end()?;
        out.document_element(
            payload,
            XmlLimits::payload(crate::core::DEFAULT_MAX_BODY_BYTES),
            "StandardBusinessDocument::payload",
        )?;
        out.end()?;
        Ok(out.finish()?.into_string()?.into_bytes())
    }

    // ── Parsing ───────────────────────────────────────────────────────────────

    /// Parse an SBDH-wrapped document from UTF-8 XML bytes.
    ///
    /// The parser extracts the `<StandardBusinessDocumentHeader>` fields and
    /// the raw payload bytes that appear after the closing header tag.
    ///
    /// The payload is returned as the byte slice between the end of
    /// `</StandardBusinessDocumentHeader>` and the start of
    /// `</StandardBusinessDocument>`, trimmed of leading/trailing ASCII whitespace.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::ParseFailed`] when the input is malformed, missing
    /// required SBDH elements, or not valid UTF-8.
    pub fn unwrap(bytes: &[u8]) -> Result<Self> {
        let ctx = || ErrorContext::new("sbdh_unwrap");
        let doc = crate::xml::parse_bytes(
            bytes,
            crate::xml::XmlLimits::payload(crate::core::DEFAULT_MAX_BODY_BYTES),
            "sbdh_unwrap",
        )
        .map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("SBDH XML is malformed: {}", err.message),
                ctx(),
            )
        })?;
        let root = doc.root_element();
        if !is_sbdh(root, "StandardBusinessDocument") {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                "SBDH root element is not {http://www.unece.org/cefact/namespaces/\
                 StandardBusinessDocumentHeader}StandardBusinessDocument",
                ctx(),
            ));
        }
        let mut children = root.children().filter(roxmltree::Node::is_element);
        let header_node = children
            .next()
            .filter(|n| is_sbdh(*n, "StandardBusinessDocumentHeader"))
            .ok_or_else(|| {
                AsxError::new(
                    ErrorCode::ParseFailed,
                    "SBDH missing StandardBusinessDocumentHeader as the first child",
                    ctx(),
                )
            })?;
        let header = parse_sbdh_header(header_node, ctx)?;
        let payload_node = children.next().ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "SBDH carries no payload element after its header",
                ctx(),
            )
        })?;
        if children.next().is_some() {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                "SBDH carries more than one payload element",
                ctx(),
            ));
        }
        let payload = payload_with_inherited_namespaces(doc.input_text(), payload_node)?;
        Ok(Self {
            header,
            payload: payload.into_bytes(),
        })
    }
}

fn is_sbdh(node: roxmltree::Node<'_, '_>, local: &str) -> bool {
    node.is_element()
        && node.tag_name().namespace() == Some(SBDH_NAMESPACE)
        && node.tag_name().name() == local
}

/// The payload element's source bytes, with every namespace it uses but
/// inherits from the envelope re-declared on its start tag, so the payload is
/// a well-formed document on its own (an SBDH may declare a prefix the
/// payload uses).
fn payload_with_inherited_namespaces(
    text: &str,
    payload: roxmltree::Node<'_, '_>,
) -> Result<String> {
    let element = &text[payload.range()];
    let start_tag_end = start_tag_end(element);
    let own = own_namespace_declarations(&element[..start_tag_end]);
    // Prefixes the payload subtree uses: element prefixes as written, and the
    // in-scope prefix of every namespaced attribute.
    let mut used: Vec<Option<&str>> = Vec::new();
    for node in payload.descendants().filter(roxmltree::Node::is_element) {
        let source = &text[node.range()];
        let qname_end = source[1..]
            .find(|c: char| c.is_whitespace() || c == '/' || c == '>')
            .map_or(source.len(), |i| i + 1);
        let prefix = source[1..qname_end].split_once(':').map(|(p, _)| p);
        if !used.contains(&prefix) {
            used.push(prefix);
        }
        for attr in node.attributes() {
            if let Some(uri) = attr.namespace() {
                let prefix = node.lookup_prefix(uri);
                if prefix.is_some() && !used.contains(&prefix) {
                    used.push(prefix);
                }
            }
        }
    }
    let mut extra = String::new();
    for ns in payload.namespaces() {
        let prefix = ns.name();
        if prefix == Some("xml") || own.contains(&prefix) || !used.contains(&prefix) {
            continue;
        }
        match prefix {
            Some(p) => {
                extra.push_str(" xmlns:");
                extra.push_str(p);
            }
            None => extra.push_str(" xmlns"),
        }
        extra.push_str("=\"");
        crate::crypto::wssec::canonicalize::escape_attr_value(ns.uri(), &mut extra).map_err(
            |_| {
                AsxError::new(
                    ErrorCode::ParseFailed,
                    "SBDH payload namespace could not be re-declared",
                    ErrorContext::new("sbdh_unwrap"),
                )
            },
        )?;
        extra.push('"');
    }
    if extra.is_empty() {
        return Ok(element.to_string());
    }
    let name_end = element[1..]
        .find(|c: char| c.is_whitespace() || c == '/' || c == '>')
        .map_or(element.len(), |i| i + 1);
    Ok(format!(
        "{}{}{}",
        &element[..name_end],
        extra,
        &element[name_end..]
    ))
}

/// Index of the unquoted `>` that ends the start tag at the beginning of
/// `element`.
fn start_tag_end(element: &str) -> usize {
    let mut quote = None;
    for (i, b) in element.bytes().enumerate() {
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'>' => return i,
            None => {}
        }
    }
    element.len()
}

/// Prefixes (`None` = default namespace) declared on a start tag.
fn own_namespace_declarations(start_tag: &str) -> Vec<Option<&str>> {
    let mut own = Vec::new();
    let mut rest = start_tag;
    while let Some(at) = rest.find("xmlns") {
        let before = rest[..at].chars().last();
        let after = &rest[at + 5..];
        if before.is_some_and(char::is_whitespace) {
            if let Some(tail) = after.strip_prefix(':') {
                let end = tail
                    .find(|c: char| c == '=' || c.is_whitespace())
                    .unwrap_or(tail.len());
                own.push(Some(&tail[..end]));
            } else if after.trim_start().starts_with('=') {
                own.push(None);
            }
        }
        rest = after;
    }
    own
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Write `<BusinessScope>`, or nothing when there are no scopes.
///
/// An empty `<BusinessScope/>` is not the same as an absent one: the Peppol
/// schema gives `Scope` a lower bound of 1 (BME 2.0.1 fixed exactly this), so
/// emitting an empty container would produce an envelope that fails schema
/// validation at the receiving access point.
fn write_business_scope(out: &mut crate::xml::XmlOut, scopes: &[SbdhScope]) -> Result<()> {
    if scopes.is_empty() {
        return Ok(());
    }
    out.start("sh:BusinessScope")?;
    for scope in scopes {
        out.start("sh:Scope")?;
        out.leaf("sh:Type", &scope.scope_type, "SbdhScope::scope_type")?;
        // Always emitted, even when empty: an indicator attribute is a present
        // element with no value.
        out.leaf(
            "sh:InstanceIdentifier",
            &scope.instance_identifier,
            "SbdhScope::instance_identifier",
        )?;
        if let Some(identifier) = &scope.identifier {
            out.leaf("sh:Identifier", identifier, "SbdhScope::identifier")?;
        }
        out.end()?;
    }
    out.end()?;
    Ok(())
}

/// Read the header fields from the `StandardBusinessDocumentHeader` node.
fn parse_sbdh_header(
    sbdh: roxmltree::Node<'_, '_>,
    ctx: impl Fn() -> ErrorContext,
) -> Result<SbdhHeader> {
    // Helper: find a direct child element by local name and return its trimmed text.
    let find_text = |parent: roxmltree::Node<'_, '_>, name: &str| -> Option<String> {
        parent
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == name)
            .and_then(|n| n.text())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };

    let header_version = find_text(sbdh, "HeaderVersion").ok_or_else(|| {
        AsxError::new(ErrorCode::ParseFailed, "SBDH missing HeaderVersion", ctx())
    })?;

    // ── Sender ────────────────────────────────────────────────────────────────
    let sender_node = sbdh
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "Sender")
        .ok_or_else(|| AsxError::new(ErrorCode::ParseFailed, "SBDH missing Sender", ctx()))?;
    let sender_id_node = sender_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "Identifier")
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "SBDH missing Sender/Identifier",
                ctx(),
            )
        })?;
    let sender_identifier = sender_id_node
        .text()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "SBDH Sender/Identifier is empty",
                ctx(),
            )
        })?;
    let sender_authority = sender_id_node
        .attribute("Authority")
        .unwrap_or("")
        .to_string();

    // ── Receiver ──────────────────────────────────────────────────────────────
    let receiver_node = sbdh
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "Receiver")
        .ok_or_else(|| AsxError::new(ErrorCode::ParseFailed, "SBDH missing Receiver", ctx()))?;
    let receiver_id_node = receiver_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "Identifier")
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "SBDH missing Receiver/Identifier",
                ctx(),
            )
        })?;
    let receiver_identifier = receiver_id_node
        .text()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "SBDH Receiver/Identifier is empty",
                ctx(),
            )
        })?;
    let receiver_authority = receiver_id_node
        .attribute("Authority")
        .unwrap_or("")
        .to_string();

    // ── DocumentIdentification ────────────────────────────────────────────────
    let doc_id = sbdh
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "DocumentIdentification")
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "SBDH missing DocumentIdentification",
                ctx(),
            )
        })?;

    let standard = find_text(doc_id, "Standard").ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "SBDH missing DocumentIdentification/Standard",
            ctx(),
        )
    })?;
    let type_version = find_text(doc_id, "TypeVersion").ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "SBDH missing DocumentIdentification/TypeVersion",
            ctx(),
        )
    })?;
    let instance_identifier = find_text(doc_id, "InstanceIdentifier").ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "SBDH missing DocumentIdentification/InstanceIdentifier",
            ctx(),
        )
    })?;
    let doc_type = find_text(doc_id, "Type").ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "SBDH missing DocumentIdentification/Type",
            ctx(),
        )
    })?;
    let multiple_type = find_text(doc_id, "MultipleType")
        .map(|t| matches!(t.to_ascii_lowercase().as_str(), "true" | "1"))
        .unwrap_or(false);
    let creation_date_and_time = find_text(doc_id, "CreationDateAndTime").ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "SBDH missing DocumentIdentification/CreationDateAndTime",
            ctx(),
        )
    })?;

    // ── BusinessScope ─────────────────────────────────────────────────────────
    //
    // Optional in UN/CEFACT SBDH, required by Peppol. Parsed positionally
    // within each <Scope> by element name, never by document order across
    // scopes: order is not significant and two scopes may share a Type.
    let business_scope = sbdh
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "BusinessScope")
        .map(|node| {
            node.children()
                .filter(|n| n.is_element() && n.tag_name().name() == "Scope")
                .map(|scope| {
                    // `InstanceIdentifier` may be legitimately empty (an
                    // indicator attribute), so unlike every other field here it
                    // is not filtered out when blank.
                    let value = scope
                        .children()
                        .find(|n| n.is_element() && n.tag_name().name() == "InstanceIdentifier")
                        .map(|n| n.text().unwrap_or("").trim().to_string())
                        .unwrap_or_default();
                    SbdhScope {
                        scope_type: find_text(scope, "Type").unwrap_or_default(),
                        instance_identifier: value,
                        identifier: find_text(scope, "Identifier"),
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(SbdhHeader {
        header_version,
        sender: SbdhParty {
            identifier: sender_identifier,
            authority: sender_authority,
        },
        receiver: SbdhParty {
            identifier: receiver_identifier,
            authority: receiver_authority,
        },
        business_scope,
        document_identification: SbdhDocumentIdentification {
            standard,
            type_version,
            instance_identifier,
            r#type: doc_type,
            multiple_type,
            creation_date_and_time,
        },
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_doc() -> StandardBusinessDocument {
        StandardBusinessDocument {
            header: SbdhHeader {
                header_version: "1.0".into(),
                sender: SbdhParty {
                    identifier: "0007:1234567890".into(),
                    authority: "iso6523-actorid-upis".into(),
                },
                receiver: SbdhParty {
                    identifier: "0007:9876543210".into(),
                    authority: "iso6523-actorid-upis".into(),
                },
                business_scope: Vec::new(),
                document_identification: SbdhDocumentIdentification {
                    standard: "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2".into(),
                    type_version: "2.1".into(),
                    instance_identifier: "urn:uuid:550e8400-e29b-41d4-a716-446655440000".into(),
                    r#type: "Invoice".into(),
                    multiple_type: false,
                    creation_date_and_time: "2026-01-01T12:00:00+00:00".into(),
                },
            },
            payload: b"<Invoice xmlns=\"urn:oasis:names:specification:ubl:schema:xsd:Invoice-2\"/>"
                .to_vec(),
        }
    }

    #[test]
    fn wrap_produces_well_formed_xml() {
        let doc = sample_doc();
        let bytes = doc.wrap().expect("wrap");
        let xml = std::str::from_utf8(&bytes).expect("utf8");
        assert!(
            xml.contains("<sh:StandardBusinessDocument"),
            "outer element present"
        );
        assert!(
            xml.contains("<sh:StandardBusinessDocumentHeader>"),
            "header element present"
        );
        assert!(
            xml.contains("<sh:HeaderVersion>1.0</sh:HeaderVersion>"),
            "header version"
        );
        assert!(xml.contains("0007:1234567890"), "sender id");
        assert!(xml.contains("0007:9876543210"), "receiver id");
        assert!(xml.contains("Invoice"), "doc type");
        assert!(xml.contains("<Invoice"), "payload embedded");
    }

    #[test]
    fn unwrap_recovers_header_and_payload() {
        let doc = sample_doc();
        let bytes = doc.wrap().expect("wrap");
        let parsed = StandardBusinessDocument::unwrap(&bytes).expect("unwrap");

        assert_eq!(parsed.header.header_version, "1.0");
        assert_eq!(parsed.header.sender.identifier, "0007:1234567890");
        assert_eq!(parsed.header.sender.authority, "iso6523-actorid-upis");
        assert_eq!(parsed.header.receiver.identifier, "0007:9876543210");
        assert_eq!(parsed.header.document_identification.r#type, "Invoice");
        assert_eq!(parsed.header.document_identification.type_version, "2.1");
        assert!(!parsed.header.document_identification.multiple_type);
        assert_eq!(parsed.payload, doc.payload);
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        let doc = sample_doc();
        let parsed = StandardBusinessDocument::unwrap(&doc.wrap().expect("wrap")).expect("unwrap");
        assert_eq!(parsed, doc);
    }

    #[test]
    fn unwrap_returns_error_on_missing_header_close_tag() {
        let bad = b"<StandardBusinessDocument><StandardBusinessDocumentHeader>";
        let result = StandardBusinessDocument::unwrap(bad);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("StandardBusinessDocumentHeader")
                || err.code == ErrorCode::ParseFailed
        );
    }

    #[test]
    fn unwrap_returns_error_on_missing_document_close_tag() {
        let bad = b"<x/></StandardBusinessDocumentHeader>";
        let result = StandardBusinessDocument::unwrap(bad);
        assert!(result.is_err());
    }

    const HEADER_BODY: &str = "<sh:HeaderVersion>1.0</sh:HeaderVersion>\
        <sh:Sender><sh:Identifier Authority=\"iso6523-actorid-upis\">0088:s</sh:Identifier></sh:Sender>\
        <sh:Receiver><sh:Identifier Authority=\"iso6523-actorid-upis\">0088:r</sh:Identifier></sh:Receiver>\
        <sh:DocumentIdentification><sh:Standard>urn:x</sh:Standard><sh:TypeVersion>2.1</sh:TypeVersion>\
        <sh:InstanceIdentifier>i</sh:InstanceIdentifier><sh:Type>Invoice</sh:Type>\
        <sh:CreationDateAndTime>2026-10-16T12:00:00Z</sh:CreationDateAndTime></sh:DocumentIdentification>";

    /// phase4 writes the SBDH with an `sh:` prefix; the header and the
    /// payload come from the DOM, not from a byte search for unprefixed tags.
    #[test]
    fn prefixed_sbdh_unwraps() {
        let xml = format!(
            "<sh:StandardBusinessDocument xmlns:sh=\"{SBDH_NAMESPACE}\">\
             <sh:StandardBusinessDocumentHeader>{HEADER_BODY}</sh:StandardBusinessDocumentHeader>\
             <Invoice xmlns=\"urn:inv\"><ID>1</ID></Invoice></sh:StandardBusinessDocument>"
        );
        let parsed = StandardBusinessDocument::unwrap(xml.as_bytes()).expect("unwrap");
        assert_eq!(parsed.header.sender.identifier, "0088:s");
        assert_eq!(
            parsed.payload,
            b"<Invoice xmlns=\"urn:inv\"><ID>1</ID></Invoice>".to_vec()
        );
    }

    #[test]
    fn comment_with_close_tag_does_not_split_payload() {
        let payload =
            "<Invoice xmlns=\"urn:inv\"><!-- </StandardBusinessDocument> --><ID>1</ID></Invoice>";
        let xml = format!(
            "<sh:StandardBusinessDocument xmlns:sh=\"{SBDH_NAMESPACE}\">\
             <sh:StandardBusinessDocumentHeader>{HEADER_BODY}</sh:StandardBusinessDocumentHeader>\
             {payload}</sh:StandardBusinessDocument>"
        );
        let parsed = StandardBusinessDocument::unwrap(xml.as_bytes()).expect("unwrap");
        assert_eq!(parsed.payload, payload.as_bytes().to_vec());
    }

    /// A payload that uses a prefix declared on the SBDH root must stay a
    /// well-formed document on its own: the inherited declaration is
    /// re-declared on the payload root.
    #[test]
    fn payload_redeclares_inherited_namespaces() {
        let xml = format!(
            "<sh:StandardBusinessDocument xmlns:sh=\"{SBDH_NAMESPACE}\" xmlns:cbc=\"urn:cbc\">\
             <sh:StandardBusinessDocumentHeader>{HEADER_BODY}</sh:StandardBusinessDocumentHeader>\
             <Invoice xmlns=\"urn:inv\"><cbc:ID>1</cbc:ID></Invoice></sh:StandardBusinessDocument>"
        );
        let parsed = StandardBusinessDocument::unwrap(xml.as_bytes()).expect("unwrap");
        let payload = String::from_utf8(parsed.payload).unwrap();
        let doc = roxmltree::Document::parse(&payload)
            .unwrap_or_else(|e| panic!("the payload must stand alone: {e}\n{payload}"));
        let id = doc
            .descendants()
            .find(|n| n.tag_name().name() == "ID")
            .expect("cbc:ID");
        assert_eq!(id.tag_name().namespace(), Some("urn:cbc"));
        assert_eq!(doc.root_element().tag_name().namespace(), Some("urn:inv"));
    }
}

// ── Non-XML payloads (Peppol BME §2.3.1–2.3.2) ───────────────────────────────

/// Wrap a **binary** payload for transport inside an SBDH.
///
/// Peppol's envelope carries the business document as XML. A payload that is
/// not XML — a PDF, an ASiC-E container — needs a wrapper, and BME §2.3.1
/// defines this one: base64 inside `<BinaryContent>`, with the media type as an
/// attribute.
///
/// `encoding` is for *text-based* payloads whose source encoding differs from
/// the surrounding document; leave it `None` for genuinely binary content.
///
/// **Not for XML.** The specification says this wrapper MUST NOT be used for a
/// plain XML payload — that goes in directly.
///
/// ```text
/// use asx::sbdh::wrap_binary_payload;
///
/// let xml = wrap_binary_payload(b"%PDF-1.7", "application/pdf", None)?;
/// assert!(xml.starts_with("<BinaryContent"));
/// assert!(xml.contains(r#"mimeType="application/pdf""#));
/// # Ok::<(), asx::core::AsxError>(())
/// ```
pub fn wrap_binary_payload(
    payload: &[u8],
    mime_type: &str,
    encoding: Option<&str>,
) -> Result<String> {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
    let mut out = crate::xml::XmlOut::new();
    out.start("BinaryContent")?
        .ns("", PEPPOL_ENVELOPE_NAMESPACE)?
        .attr("mimeType", mime_type, "mime_type")?;
    if let Some(encoding) = encoding {
        out.attr("encoding", encoding, "encoding")?;
    }
    out.text(&encoded, "payload")?.end()?;
    out.finish()?.into_string()
}

/// Wrap a **text** payload for transport inside an SBDH (BME §2.3.2).
///
/// The text is XML-escaped, so a payload containing `<` or `&` stays
/// well-formed. It must use the same character encoding as the surrounding
/// document — if it does not, use [`wrap_binary_payload`] instead, which is
/// what the specification says.
///
/// **Not for XML.**
///
/// ```text
/// use asx::sbdh::wrap_text_payload;
///
/// let xml = wrap_text_payload("UNB+UNOA:2+...", "Application/EDIFACT")?;
/// assert!(xml.contains("UNB+UNOA:2+..."));
/// # Ok::<(), asx::core::AsxError>(())
/// ```
pub fn wrap_text_payload(payload: &str, mime_type: &str) -> Result<String> {
    let mut out = crate::xml::XmlOut::new();
    out.start("TextContent")?
        .ns("", PEPPOL_ENVELOPE_NAMESPACE)?
        .attr("mimeType", mime_type, "mime_type")?
        .text(payload, "payload")?
        .end()?;
    out.finish()?.into_string()
}

#[cfg(test)]
mod business_scope_tests {
    use super::*;

    fn header_with(scopes: Vec<SbdhScope>) -> SbdhHeader {
        SbdhHeader {
            header_version: "1.0".into(),
            sender: SbdhParty {
                identifier: "0088:7315458756324".into(),
                authority: "iso6523-actorid-upis".into(),
            },
            receiver: SbdhParty {
                identifier: "0088:4562458856624".into(),
                authority: "iso6523-actorid-upis".into(),
            },
            business_scope: scopes,
            document_identification: SbdhDocumentIdentification {
                standard: "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2".into(),
                type_version: "2.1".into(),
                instance_identifier: "123123".into(),
                r#type: "Invoice".into(),
                multiple_type: false,
                creation_date_and_time: "2026-01-01T12:00:00+00:00".into(),
            },
        }
    }

    fn roundtrip(scopes: Vec<SbdhScope>) -> Vec<SbdhScope> {
        let doc = StandardBusinessDocument {
            header: header_with(scopes),
            payload: b"<Invoice/>".to_vec(),
        };
        let wrapped = doc.wrap().expect("wrap");
        StandardBusinessDocument::unwrap(&wrapped)
            .expect("unwrap")
            .header
            .business_scope
    }

    /// The minimum a Peppol access point accepts.
    #[test]
    fn peppol_mandatory_scopes_round_trip_with_their_schemes() {
        let scopes = vec![
            SbdhScope::with_scheme(
                peppol_scope::DOCUMENT_ID,
                "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1",
                "busdox-docid-qns",
            ),
            SbdhScope::with_scheme(
                peppol_scope::PROCESS_ID,
                "urn:fdc:peppol.eu:2017:poacc:billing:01:1.0",
                "cenbii-procid-ubl",
            ),
            SbdhScope::new(peppol_scope::COUNTRY_C1, "BE"),
        ];
        assert_eq!(roundtrip(scopes.clone()), scopes);
    }

    /// The MLS customisations from Network Policy 1.0.0.
    #[test]
    fn mls_scopes_round_trip() {
        let scopes = vec![
            SbdhScope::with_scheme(
                peppol_scope::MLS_TO,
                "0242:987654-TEST",
                "iso6523-actorid-upis",
            ),
            SbdhScope::new(peppol_scope::MLS_TYPE, "FAILURE_ONLY"),
        ];
        assert_eq!(roundtrip(scopes.clone()), scopes);
    }

    /// An indicator attribute is a present element with no value — distinct
    /// from an absent scope, and the case BME 1.1.1 had to correct.
    #[test]
    fn an_indicator_attribute_survives_the_round_trip() {
        let scopes = vec![SbdhScope::indicator("IndicatorAttribute")];
        let back = roundtrip(scopes);
        assert_eq!(back.len(), 1, "the scope must not vanish");
        assert_eq!(back[0].scope_type, "IndicatorAttribute");
        assert!(back[0].instance_identifier.is_empty());
        assert!(back[0].identifier.is_none());
    }

    /// No scopes emits **no** `<BusinessScope>` element.
    ///
    /// An empty container would fail the Peppol schema, whose `Scope` has a
    /// lower bound of 1 — the cardinality BME 2.0.1 fixed.
    #[test]
    fn an_empty_scope_list_emits_no_container() {
        let doc = StandardBusinessDocument {
            header: header_with(Vec::new()),
            payload: b"<Invoice/>".to_vec(),
        };
        let wrapped = doc.wrap().expect("wrap");
        let xml = String::from_utf8(wrapped).expect("utf8");
        assert!(
            !xml.contains("BusinessScope"),
            "an empty BusinessScope must not be emitted: {xml}"
        );
    }

    #[test]
    fn scope_lookup_finds_by_type() {
        let header = header_with(vec![
            SbdhScope::new(peppol_scope::DOCUMENT_ID, "doc"),
            SbdhScope::new(peppol_scope::PROCESS_ID, "proc"),
        ]);
        assert_eq!(header.scope_value(peppol_scope::PROCESS_ID), Some("proc"));
        assert!(header.scope("NOT_PRESENT").is_none());
    }

    /// Two scopes may share a `Type` (a rollover of MLS receivers, say), so the
    /// parser must keep both rather than collapsing them.
    #[test]
    fn repeated_scope_types_are_all_retained() {
        let scopes = vec![
            SbdhScope::new(peppol_scope::MLS_TO, "0242:a"),
            SbdhScope::new(peppol_scope::MLS_TO, "0242:b"),
        ];
        assert_eq!(roundtrip(scopes).len(), 2);
    }

    #[test]
    fn scope_values_are_xml_escaped() {
        let scopes = vec![SbdhScope::new("CUSTOM", "a<b&c\"d")];
        assert_eq!(roundtrip(scopes.clone()), scopes);
    }

    #[test]
    fn binary_payload_wrapper_matches_the_specification_shape() {
        let xml = wrap_binary_payload(
            b"hello",
            "application/vnd.etsi.asic-e+zip",
            Some("iso-8859-1"),
        )
        .expect("wrap");
        assert!(xml.contains(r#"xmlns="http://peppol.eu/xsd/ticc/envelope/1.0""#));
        assert!(xml.contains(r#"mimeType="application/vnd.etsi.asic-e+zip""#));
        assert!(xml.contains(r#"encoding="iso-8859-1""#));
        assert!(xml.contains("aGVsbG8="), "payload must be base64: {xml}");
    }

    #[test]
    fn text_payload_wrapper_escapes_xml_special_characters() {
        let xml = wrap_text_payload("a<b&c", "Application/EDIFACT").expect("wrap");
        assert!(xml.contains("a&lt;b&amp;c"), "must stay well-formed: {xml}");
        assert!(!xml.contains("a<b"), "raw '<' must not survive: {xml}");
    }
}

#[cfg(test)]
mod peppol_example_conformance {
    use super::*;

    /// The specification's own example instance, parsed.
    ///
    /// Copied from Peppol Business Message Envelope 2.0.2 §3.1 (non-normative
    /// example): a foreign witness, unlike a round trip through our own
    /// serializer and parser.
    const BME_EXAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<StandardBusinessDocument xmlns="http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader">
  <StandardBusinessDocumentHeader>
    <HeaderVersion>1.0</HeaderVersion>
    <Sender>
      <Identifier Authority="iso6523-actorid-upis">0088:7315458756324</Identifier>
    </Sender>
    <Receiver>
      <Identifier Authority="iso6523-actorid-upis">0088:4562458856624</Identifier>
    </Receiver>
    <DocumentIdentification>
      <Standard>urn:oasis:names:specification:ubl:schema:xsd:Invoice2</Standard>
      <TypeVersion>2.1</TypeVersion>
      <InstanceIdentifier>123123</InstanceIdentifier>
      <Type>Invoice</Type>
      <CreationDateAndTime>2019-02-01T15:42:10Z</CreationDateAndTime>
    </DocumentIdentification>
    <BusinessScope>
      <Scope>
        <Type>DOCUMENTID</Type>
        <InstanceIdentifier>urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1</InstanceIdentifier>
        <Identifier>busdox-docid-qns</Identifier>
      </Scope>
      <Scope>
        <Type>PROCESSID</Type>
        <InstanceIdentifier>urn:fdc:peppol.eu:2017:poacc:billing:01:1.0</InstanceIdentifier>
        <Identifier>cenbii-procid-ubl</Identifier>
      </Scope>
      <Scope>
        <Type>COUNTRY_C1</Type>
        <InstanceIdentifier>BE</InstanceIdentifier>
      </Scope>
    </BusinessScope>
  </StandardBusinessDocumentHeader>
  <Invoice/>
</StandardBusinessDocument>"#;

    #[test]
    fn the_specifications_own_example_parses_to_the_values_it_prints() {
        let parsed = StandardBusinessDocument::unwrap(BME_EXAMPLE.as_bytes()).expect("unwrap");
        let header = &parsed.header;

        assert_eq!(header.sender.identifier, "0088:7315458756324");
        assert_eq!(header.sender.authority, "iso6523-actorid-upis");

        assert_eq!(header.business_scope.len(), 3);

        let doc_id = header.scope(peppol_scope::DOCUMENT_ID).expect("DOCUMENTID");
        assert!(
            doc_id.instance_identifier.ends_with("billing:3.0::2.1"),
            "value: {}",
            doc_id.instance_identifier
        );
        assert_eq!(doc_id.identifier.as_deref(), Some("busdox-docid-qns"));

        let process = header.scope(peppol_scope::PROCESS_ID).expect("PROCESSID");
        assert_eq!(
            process.instance_identifier,
            "urn:fdc:peppol.eu:2017:poacc:billing:01:1.0"
        );
        assert_eq!(process.identifier.as_deref(), Some("cenbii-procid-ubl"));

        // COUNTRY_C1 carries no scheme — the element is genuinely absent, not
        // present-and-empty.
        let country = header.scope(peppol_scope::COUNTRY_C1).expect("COUNTRY_C1");
        assert_eq!(country.instance_identifier, "BE");
        assert_eq!(country.identifier, None);
    }

    /// Re-emitting what we parsed must preserve every scope, so a message
    /// forwarded through this crate stays acceptable to the next access point.
    #[test]
    fn re_emitting_the_specification_example_preserves_its_scopes() {
        let parsed = StandardBusinessDocument::unwrap(BME_EXAMPLE.as_bytes()).expect("unwrap");
        let original = parsed.header.business_scope.clone();

        let rewrapped = StandardBusinessDocument {
            header: parsed.header,
            payload: parsed.payload,
        }
        .wrap()
        .expect("wrap");

        let again = StandardBusinessDocument::unwrap(&rewrapped).expect("unwrap");
        assert_eq!(again.header.business_scope, original);
    }
}
