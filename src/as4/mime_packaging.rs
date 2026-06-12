//! MIME multipart/related attachment support for AS4 messages.
//!
//! This module provides utilities for packaging AS4 payloads as MIME multipart/related
//! attachments with Content-ID references, conforming to the **OpenPeppol AS4 Profile v2.0**
//! and **CEF eDelivery AS4 profile**.
//!
//! ## Background
//!
//! In strict profiles (PEPPOL, CEF), AS4 payloads are transmitted as MIME multipart/related
//! message bodies rather than embedded in the SOAP `<Body>`. The SOAP envelope contains
//! Content-ID references to the attachments using WS-Addressing properties.
//!
//! ### Example MIME Structure
//!
//! ```text
//! Content-Type: multipart/related; boundary="----boundary123"; type="application/xop+xml"
//!
//! ------boundary123
//! Content-Type: application/xop+xml; charset=UTF-8
//! Content-Transfer-Encoding: 8bit
//! Content-ID: <soap-body@example.com>
//!
//! <?xml version="1.0"?>
//! <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
//!   <soap:Body>
//!     <eb:UserMessage xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/">
//!       <!-- payload references via xop:Include -->
//!       <xop:Include href="cid:payload-001@example.com"/>
//!     </eb:UserMessage>
//!   </soap:Body>
//! </soap:Envelope>
//!
//! ------boundary123
//! Content-Type: application/octet-stream
//! Content-Transfer-Encoding: binary
//! Content-ID: <payload-001@example.com>
//! Content-Disposition: attachment; name="payload"
//!
//! [binary payload data]
//! ------boundary123--
//! ```
//!
//! ## Architecture
//!
//! The module provides:
//! - `MimePackage`: A builder for constructing MIME multipart/related messages
//! - `MimeAttachment`: Represents a single attachment within the package
//! - Helpers for generating stable Content-ID values from payloads

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use std::io::Write;

/// MIME boundary marker for multipart/related messages.
///
/// Chosen to be unlikely to appear in any embedded payload data.
/// Format: `----boundary-{random hex}`
pub const MIME_BOUNDARY_PREFIX: &str = "----boundary-asx-";

/// MIME attachment representing a single part within a multipart/related message.
#[derive(Debug, Clone)]
pub struct MimeAttachment {
    /// Content-ID for this attachment (e.g., `payload-001@example.com`).
    /// Used in xop:Include href references within the SOAP envelope.
    pub content_id: String,

    /// MIME type of the attachment (e.g., `application/octet-stream`).
    pub content_type: String,

    /// Content-Transfer-Encoding (typically `binary` for payloads, `8bit` for SOAP).
    pub transfer_encoding: String,

    /// Attachment body (binary or XML).
    pub body: Vec<u8>,

    /// Optional Content-Disposition header value.
    pub disposition: Option<String>,
}

impl MimeAttachment {
    /// Create a new MIME attachment.
    ///
    /// # Parameters
    /// - `content_id`: Unique identifier (will be wrapped in `<...>` when serialized)
    /// - `content_type`: RFC 2045 media type
    /// - `body`: Attachment body (binary or text)
    /// - `transfer_encoding`: Encoding scheme (e.g., `binary`, `8bit`)
    pub fn new(
        content_id: impl Into<String>,
        content_type: impl Into<String>,
        body: impl Into<Vec<u8>>,
        transfer_encoding: impl Into<String>,
    ) -> Self {
        Self {
            content_id: content_id.into(),
            content_type: content_type.into(),
            transfer_encoding: transfer_encoding.into(),
            body: body.into(),
            disposition: None,
        }
    }

    /// Add a Content-Disposition header (e.g., `attachment; name="payload"`).
    pub fn with_disposition(mut self, disposition: impl Into<String>) -> Self {
        self.disposition = Some(disposition.into());
        self
    }

    /// Generate a stable Content-ID from payload digest.
    ///
    /// Computes SHA-256 of the payload and formats as `payload-{first 16 hex chars}@example.com`.
    pub fn content_id_from_digest(payload: &[u8]) -> String {
        // Use OpenSSL to compute SHA-256 digest
        use openssl::hash::MessageDigest;

        // Compute SHA-256
        let digest =
            openssl::hash::hash(MessageDigest::sha256(), payload).expect("SHA-256 should not fail");

        // Convert first 8 bytes to hex string (16 hex characters)
        let hex_str = digest
            .iter()
            .take(8)
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        format!("payload-{}@example.com", hex_str)
    }
}

/// Builder for constructing MIME multipart/related messages.
///
/// Handles serialization of SOAP envelope and attachments into properly-formatted
/// multipart MIME structure with correct boundary markers and headers.
pub struct MimePackageBuilder {
    boundary: String,
    root_soap_content_type: String,
    soap_attachment: Option<MimeAttachment>,
    attachments: Vec<MimeAttachment>,
}

impl MimePackageBuilder {
    fn write_crlf_line(body: &mut Vec<u8>, line: &str, stage: &'static str) -> Result<()> {
        body.write_all(line.as_bytes()).map_err(|_| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                "Failed to write MIME line",
                ErrorContext::new(stage),
            )
        })?;
        body.write_all(b"\r\n").map_err(|_| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                "Failed to write MIME CRLF",
                ErrorContext::new(stage),
            )
        })
    }

    /// Create a new MIME package builder.
    ///
    /// Generates a unique boundary marker automatically.
    pub fn new() -> Self {
        // Generate boundary using current nanosecond timestamp and incrementing counter
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let combined = nanos.wrapping_add(counter);

        let boundary = format!("{}{:016x}", MIME_BOUNDARY_PREFIX, combined);

        Self {
            boundary,
            root_soap_content_type: "application/soap+xml".to_string(),
            soap_attachment: None,
            attachments: Vec::new(),
        }
    }

    /// Set SOAP media type advertised for the root XOP part.
    ///
    /// Example:
    /// - SOAP 1.2: `application/soap+xml`
    pub fn with_root_soap_content_type(mut self, soap_content_type: impl Into<String>) -> Self {
        self.root_soap_content_type = soap_content_type.into();
        self
    }

    /// Set the SOAP envelope as the root attachment (Content-ID: `<soap-body@example.com>`).
    ///
    /// This is typically the first attachment in a MIME package.
    pub fn with_soap_body(mut self, soap_xml: Vec<u8>) -> Self {
        let content_type = format!(
            "application/xop+xml; charset=UTF-8; type=\"{}\"",
            self.root_soap_content_type
        );
        self.soap_attachment = Some(MimeAttachment::new(
            "soap-body@example.com",
            content_type,
            soap_xml,
            "8bit",
        ));
        self
    }

    /// Add a binary attachment (e.g., encrypted payload).
    pub fn add_attachment(mut self, attachment: MimeAttachment) -> Self {
        self.attachments.push(attachment);
        self
    }

    /// Add multiple attachments.
    pub fn add_attachments(mut self, attachments: Vec<MimeAttachment>) -> Self {
        self.attachments.extend(attachments);
        self
    }

    /// Build the final MIME multipart/related message as bytes.
    ///
    /// Returns the complete HTTP message body with proper boundary markers
    /// and headers for each part.
    pub fn build(self) -> Result<Vec<u8>> {
        if self.soap_attachment.is_none() {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                "MIME package requires at least a SOAP body attachment",
                ErrorContext::new("mime_packaging"),
            ));
        }

        let mut body = Vec::new();

        // Write root MIME boundaries and SOAP part
        if let Some(ref soap) = self.soap_attachment {
            Self::write_crlf_line(&mut body, &format!("--{}", self.boundary), "mime_packaging")?;

            Self::write_attachment(&mut body, soap)?;
        }

        // Write additional attachments
        for attachment in &self.attachments {
            Self::write_crlf_line(&mut body, &format!("--{}", self.boundary), "mime_packaging")?;

            Self::write_attachment(&mut body, attachment)?;
        }

        // Write closing boundary
        Self::write_crlf_line(
            &mut body,
            &format!("--{}--", self.boundary),
            "mime_packaging",
        )?;

        Ok(body)
    }

    /// Get the Content-Type header value for this package.
    ///
    /// Returns the multipart/related Content-Type with boundary parameter.
    pub fn content_type(&self) -> String {
        format!(
            "multipart/related; boundary=\"{}\"; type=\"application/xop+xml\"",
            self.boundary
        )
    }

    /// Get the boundary marker for this package.
    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    fn write_attachment(body: &mut Vec<u8>, attachment: &MimeAttachment) -> Result<()> {
        // Write headers
        Self::write_crlf_line(
            body,
            &format!("Content-Type: {}", attachment.content_type),
            "mime_packaging",
        )?;

        Self::write_crlf_line(
            body,
            &format!(
                "Content-Transfer-Encoding: {}",
                attachment.transfer_encoding
            ),
            "mime_packaging",
        )?;

        Self::write_crlf_line(
            body,
            &format!("Content-ID: <{}>", attachment.content_id),
            "mime_packaging",
        )?;

        if let Some(ref disposition) = attachment.disposition {
            Self::write_crlf_line(
                body,
                &format!("Content-Disposition: {}", disposition),
                "mime_packaging",
            )?;
        }

        // Empty line before body
        body.write_all(b"\r\n").map_err(|_| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                "Failed to write empty line before attachment body",
                ErrorContext::new("mime_packaging"),
            )
        })?;

        // Write body
        body.extend_from_slice(&attachment.body);

        // Separate the part body from the next boundary marker.
        body.write_all(b"\r\n").map_err(|_| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                "Failed to write CRLF after attachment body",
                ErrorContext::new("mime_packaging"),
            )
        })?;

        Ok(())
    }
}

impl Default for MimePackageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mime_attachment_with_digest_generates_stable_content_id() {
        let payload = b"test payload data";
        let cid_1 = MimeAttachment::content_id_from_digest(payload);
        let cid_2 = MimeAttachment::content_id_from_digest(payload);

        // Same payload → same Content-ID
        assert_eq!(cid_1, cid_2);

        // Format check: should be payload-{hex}@example.com
        assert!(cid_1.starts_with("payload-"));
        assert!(cid_1.ends_with("@example.com"));
    }

    #[test]
    fn mime_attachment_different_payloads_different_content_ids() {
        let payload_a = b"payload A";
        let payload_b = b"payload B";

        let cid_a = MimeAttachment::content_id_from_digest(payload_a);
        let cid_b = MimeAttachment::content_id_from_digest(payload_b);

        // Different payloads → different Content-IDs
        assert_ne!(cid_a, cid_b);
    }

    #[test]
    fn mime_package_builder_generates_boundary() {
        let builder_1 = MimePackageBuilder::new();
        let builder_2 = MimePackageBuilder::new();

        let boundary_1 = builder_1.boundary();
        let boundary_2 = builder_2.boundary();

        // Each builder gets a unique boundary
        assert_ne!(boundary_1, boundary_2);

        // Boundary matches prefix pattern
        assert!(boundary_1.starts_with(MIME_BOUNDARY_PREFIX));
        assert!(boundary_2.starts_with(MIME_BOUNDARY_PREFIX));
    }

    #[test]
    fn mime_package_content_type_header() {
        let builder = MimePackageBuilder::new();
        let content_type = builder.content_type();

        assert!(content_type.starts_with("multipart/related"));
        assert!(content_type.contains("boundary="));
        assert!(content_type.contains("type=\"application/xop+xml\""));
    }

    #[test]
    fn mime_package_builder_requires_soap_body() {
        let builder = MimePackageBuilder::new();
        let result = builder.build();

        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.code, ErrorCode::PolicyViolation);
        }
    }

    #[test]
    fn mime_package_builder_with_soap_and_attachment() {
        let soap_body = b"<soap:Envelope>...</soap:Envelope>".to_vec();
        let payload = b"binary payload".to_vec();

        let attachment = MimeAttachment::new(
            "payload-001@example.com",
            "application/octet-stream",
            payload,
            "binary",
        );

        let builder = MimePackageBuilder::new()
            .with_soap_body(soap_body)
            .add_attachment(attachment);

        let result = builder.build();
        assert!(result.is_ok());

        let mime_body = result.unwrap();
        // Should contain boundary markers
        assert!(String::from_utf8_lossy(&mime_body).contains("--"));
        // Should contain Content-ID headers
        assert!(String::from_utf8_lossy(&mime_body).contains("Content-ID:"));
    }
}
