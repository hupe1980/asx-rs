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
//! ```rust
//! # use asx::sbdh::{StandardBusinessDocument, SbdhHeader, SbdhParty, SbdhDocumentIdentification};
//! let doc = StandardBusinessDocument {
//!     header: SbdhHeader {
//!         header_version: "1.0".into(),
//!         sender: SbdhParty { identifier: "0007:1234567890".into(), authority: "iso6523-actorid-upis".into() },
//!         receiver: SbdhParty { identifier: "0007:9876543210".into(), authority: "iso6523-actorid-upis".into() },
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

use crate::core::{AsxError, ErrorCode, ErrorContext, Result, escape_xml};
use roxmltree::Document;

/// XML namespace for SBDH 1.3 documents.
pub const SBDH_NAMESPACE: &str =
    "http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader";

/// Closing tag used to locate the end of the header block during parsing.
const HEADER_CLOSE_TAG: &[u8] = b"</StandardBusinessDocumentHeader>";

/// Closing tag used to locate the end of the document envelope during parsing.
const DOCUMENT_CLOSE_TAG: &[u8] = b"</StandardBusinessDocument>";

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
        let h = &self.header;
        let di = &h.document_identification;
        let multiple_type = if di.multiple_type { "true" } else { "false" };

        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<StandardBusinessDocument xmlns="{ns}">
  <StandardBusinessDocumentHeader>
    <HeaderVersion>{hv}</HeaderVersion>
    <Sender>
      <Identifier Authority="{sender_auth}">{sender_id}</Identifier>
    </Sender>
    <Receiver>
      <Identifier Authority="{receiver_auth}">{receiver_id}</Identifier>
    </Receiver>
    <DocumentIdentification>
      <Standard>{standard}</Standard>
      <TypeVersion>{type_version}</TypeVersion>
      <InstanceIdentifier>{instance_id}</InstanceIdentifier>
      <Type>{doc_type}</Type>
      <MultipleType>{multiple_type}</MultipleType>
      <CreationDateAndTime>{created_at}</CreationDateAndTime>
    </DocumentIdentification>
  </StandardBusinessDocumentHeader>
  {payload}
</StandardBusinessDocument>"#,
            ns = SBDH_NAMESPACE,
            hv = escape_xml(&h.header_version),
            sender_auth = escape_xml(&h.sender.authority),
            sender_id = escape_xml(&h.sender.identifier),
            receiver_auth = escape_xml(&h.receiver.authority),
            receiver_id = escape_xml(&h.receiver.identifier),
            standard = escape_xml(&di.standard),
            type_version = escape_xml(&di.type_version),
            instance_id = escape_xml(&di.instance_identifier),
            doc_type = escape_xml(&di.r#type),
            multiple_type = multiple_type,
            created_at = escape_xml(&di.creation_date_and_time),
            payload = std::str::from_utf8(&self.payload).map_err(|_| {
                AsxError::new(
                    ErrorCode::InvalidInput,
                    "SBDH payload is not valid UTF-8",
                    ErrorContext::new("sbdh_wrap"),
                )
            })?,
        );
        Ok(xml.into_bytes())
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

        // Locate the end of <StandardBusinessDocumentHeader>.
        let header_end_pos = find_subsequence(bytes, HEADER_CLOSE_TAG).ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "SBDH missing </StandardBusinessDocumentHeader>",
                ctx(),
            )
        })?;

        let header = parse_sbdh_header(bytes, ctx)?;

        // Extract payload: everything after </StandardBusinessDocumentHeader>
        // and before </StandardBusinessDocument>.
        let after_header = &bytes[header_end_pos + HEADER_CLOSE_TAG.len()..];
        let payload_end = find_subsequence(after_header, DOCUMENT_CLOSE_TAG).ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "SBDH missing </StandardBusinessDocument>",
                ctx(),
            )
        })?;

        let payload_slice = &after_header[..payload_end];
        let payload = trim_ascii(payload_slice).to_vec();

        Ok(Self { header, payload })
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Returns the byte offset of the first occurrence of `needle` in `haystack`,
/// or `None` if not found.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Trim leading and trailing ASCII whitespace from a byte slice.
fn trim_ascii(s: &[u8]) -> &[u8] {
    let start = s
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(0);
    if start >= end { &[] } else { &s[start..end] }
}

/// Parse the SBDH header from a full SBDH-wrapped document using roxmltree.
///
/// Navigates the DOM to `StandardBusinessDocumentHeader` and extracts all
/// required fields.  Requires the full document bytes (valid XML including the
/// outer `<StandardBusinessDocument>` element and its payload child).
fn parse_sbdh_header(bytes: &[u8], ctx: impl Fn() -> ErrorContext) -> Result<SbdhHeader> {
    let xml_str = std::str::from_utf8(bytes).map_err(|_| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "SBDH document is not valid UTF-8",
            ctx(),
        )
    })?;

    let doc = Document::parse(xml_str).map_err(|e| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("SBDH XML is malformed: {e}"),
            ctx(),
        )
    })?;

    // Locate <StandardBusinessDocumentHeader>
    let sbdh = doc
        .root_element()
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "StandardBusinessDocumentHeader")
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "SBDH missing StandardBusinessDocumentHeader",
                ctx(),
            )
        })?;

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
            xml.contains("<StandardBusinessDocument"),
            "outer element present"
        );
        assert!(
            xml.contains("<StandardBusinessDocumentHeader>"),
            "header element present"
        );
        assert!(
            xml.contains("<HeaderVersion>1.0</HeaderVersion>"),
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

    #[test]
    fn find_subsequence_works() {
        assert_eq!(find_subsequence(b"hello world", b"world"), Some(6));
        assert_eq!(find_subsequence(b"hello", b"xyz"), None);
        assert_eq!(find_subsequence(b"abc", b""), None);
    }

    #[test]
    fn trim_ascii_removes_whitespace() {
        assert_eq!(trim_ascii(b"  hello  "), b"hello");
        assert_eq!(trim_ascii(b"\n\t<Tag/>\n"), b"<Tag/>");
        assert_eq!(trim_ascii(b"   "), b"");
    }
}
