//! MIME multipart/related attachment support for AS4 messages.
//!
//! This module provides utilities for packaging AS4 payloads as MIME multipart/related
//! attachments with Content-ID references, conforming to the **OpenPeppol AS4 Profile v2.0**
//! and **CEF eDelivery AS4 profile**.
//!
//! ## Background
//!
//! AS4 payloads are transmitted as MIME multipart/related parts (SwA
//! packaging): the root part carries the SOAP envelope with an **empty**
//! `<soap:Body>`, and each payload part is referenced from the signed
//! `eb:PartInfo href="cid:…"` entries in the `eb:Messaging` header.
//!
//! ### Example MIME Structure
//!
//! ```text
//! Content-Type: multipart/related; boundary="----boundary123"; type="application/soap+xml"
//!
//! ------boundary123
//! Content-Type: application/soap+xml; charset=UTF-8
//! Content-Transfer-Encoding: 8bit
//! Content-ID: <soap-body@example.com>
//!
//! <?xml version="1.0"?>
//! <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
//!   <soap:Header>
//!     <!-- eb:Messaging with eb:PartInfo href="cid:payload-001@example.com" -->
//!     <!-- wsse:Security signing eb:Messaging, the Body and the attachment -->
//!   </soap:Header>
//!   <soap:Body/>
//! </soap:Envelope>
//!
//! ------boundary123
//! Content-Type: application/octet-stream
//! Content-Transfer-Encoding: binary
//! Content-ID: <payload-001@example.com>
//! Content-Disposition: attachment; filename="MSCONS_..._260705_1230_REF.txt"
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
use std::fmt;
use std::io::Write;

// ──────────────────────────────────────────────────────────────────────────────
// PayloadFilename newtype
// ──────────────────────────────────────────────────────────────────────────────

/// A validated MIME `Content-Disposition` filename safe for embedding in
/// AS4 payload part headers.
///
/// ## Invariants (enforced once, at construction)
///
/// * 1–255 printable US-ASCII bytes (range `0x20`–`0x7E`)
/// * No double-quote (`"`) or backslash (`\`) — RFC 2183 `quoted-string` specials
/// * No control characters including CR/LF — no header injection
///
/// Using a newtype instead of a raw `String` moves validation to the API
/// boundary ("parse, don't validate"): once a `PayloadFilename` exists, the
/// send pipeline can embed it in a MIME header without any further checks.
///
/// Applications set it with `Payload::named("invoice.xml")`; `send` builds
/// and validates it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PayloadFilename(String);

/// Error returned when a string violates [`PayloadFilename`] invariants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PayloadFilenameError(String);

impl fmt::Display for PayloadFilenameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PayloadFilenameError {}

impl PayloadFilename {
    const MAX_LEN: usize = 255;

    /// Create a `PayloadFilename` from a string slice.
    ///
    /// Validates first, then allocates — the `&str` is only copied into an
    /// owned `String` when the value is known to be valid.
    ///
    /// An owned `String` converts without a copy through `TryFrom<String>`.
    ///
    /// Returns `Err` when the string is empty, exceeds 255 bytes, or contains
    /// any character outside `0x20`–`0x7E` or the forbidden `"` and `\`.
    pub(crate) fn new(s: &str) -> std::result::Result<Self, PayloadFilenameError> {
        Self::validate_bytes(s.as_bytes())?;
        Ok(Self(s.to_owned()))
    }

    /// Return the filename as a string slice.
    #[inline]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    fn validate_bytes(bytes: &[u8]) -> std::result::Result<(), PayloadFilenameError> {
        if bytes.is_empty() {
            return Err(PayloadFilenameError(
                "payload filename must not be empty \
                 (use None to omit the Content-Disposition filename parameter)"
                    .into(),
            ));
        }
        if bytes.len() > Self::MAX_LEN {
            return Err(PayloadFilenameError(format!(
                "payload filename exceeds maximum length ({} bytes, limit is {})",
                bytes.len(),
                Self::MAX_LEN,
            )));
        }
        if let Some(bad) = bytes
            .iter()
            .copied()
            .find(|&b| !(0x20..=0x7E).contains(&b) || b == b'"' || b == b'\\')
        {
            return Err(PayloadFilenameError(format!(
                "payload filename contains character 0x{bad:02X} not allowed in a \
                 Content-Disposition header value (must be printable ASCII, \
                 no double-quote or backslash)"
            )));
        }
        Ok(())
    }
}

impl fmt::Display for PayloadFilename {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for PayloadFilename {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for PayloadFilename {
    type Err = PayloadFilenameError;
    /// Parse a `PayloadFilename` from a string slice. Enables the `.parse()` idiom:
    /// ```text
    /// use asx::as4::mime_packaging::PayloadFilename;
    /// let name: PayloadFilename = "invoice.xml".parse().unwrap();
    /// ```
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<String> for PayloadFilename {
    type Error = PayloadFilenameError;
    /// Validate and wrap an owned `String` without re-allocating.
    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        Self::validate_bytes(s.as_bytes())?;
        Ok(Self(s))
    }
}

impl TryFrom<&str> for PayloadFilename {
    type Error = PayloadFilenameError;
    fn try_from(s: &str) -> std::result::Result<Self, Self::Error> {
        Self::new(s)
    }
}

/// MIME boundary marker for multipart/related messages.
///
/// Chosen to be unlikely to appear in any embedded payload data.
/// Format: `----boundary-{random hex}`
pub(crate) const MIME_BOUNDARY_PREFIX: &str = "----boundary-asx-";

/// MIME attachment representing a single part within a multipart/related message.
#[derive(Debug, Clone)]
pub(crate) struct MimeAttachment {
    /// Content-ID for this attachment (e.g., `payload-001@example.com`).
    /// Referenced from `eb:PartInfo href="cid:…"` in the SOAP envelope.
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
    pub(crate) fn new(
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
    pub(crate) fn with_disposition(mut self, disposition: impl Into<String>) -> Self {
        self.disposition = Some(disposition.into());
        self
    }
}

/// Validate a caller-supplied payload Content-ID (bare, no brackets or
/// `cid:` scheme).
///
/// RFC 2392 `cid` restricted to an unquoted `addr-spec`: 1–255 octets of
/// printable ASCII without space, `"`, `<`, `>` or `\`. The value is written
/// as `Content-ID: <…>` and as `cid:…` inside signed XML, so anything outside
/// this set could break out of the header or the attribute.
pub(crate) fn validate_content_id(value: &str, field: &str) -> Result<()> {
    let reject = |reason: String| {
        Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!("{field} {reason}"),
            ErrorContext::new("as4_send_validate"),
        ))
    };
    if value.is_empty() || value.len() > 255 {
        return reject(format!("must be 1-255 bytes, got {} bytes", value.len()));
    }
    if let Some(bad) = value
        .bytes()
        .find(|&b| !(0x21..=0x7E).contains(&b) || matches!(b, b'"' | b'<' | b'>' | b'\\'))
    {
        return reject(format!(
            "contains byte 0x{bad:02X}; a Content-ID is printable ASCII without \
             space, '\"', '<', '>' or '\\'"
        ));
    }
    Ok(())
}

/// Validate a caller-supplied media type: `type "/" subtype *( OWS ";" OWS
/// name "=" ( token / quoted-string ) )` per RFC 6838 §4.2 and RFC 9110
/// §8.3.1, ASCII only, with no control characters anywhere.
pub(crate) fn validate_media_type(value: &str, field: &str) -> Result<()> {
    fn is_tchar(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
    }
    fn token(bytes: &[u8], mut i: usize) -> Option<usize> {
        let start = i;
        while i < bytes.len() && is_tchar(bytes[i]) {
            i += 1;
        }
        (i > start).then_some(i)
    }
    fn quoted_string(bytes: &[u8], mut i: usize) -> Option<usize> {
        if bytes.get(i) != Some(&b'"') {
            return None;
        }
        i += 1;
        while i < bytes.len() {
            match bytes[i] {
                b'"' => return Some(i + 1),
                b'\\' => i += 2,
                _ => i += 1,
            }
        }
        None
    }
    fn skip_spaces(bytes: &[u8], mut i: usize) -> usize {
        while bytes.get(i) == Some(&b' ') {
            i += 1;
        }
        i
    }
    fn parse(bytes: &[u8]) -> Option<()> {
        let mut i = token(bytes, 0)?;
        if bytes.get(i) != Some(&b'/') {
            return None;
        }
        i = token(bytes, i + 1)?;
        loop {
            let j = skip_spaces(bytes, i);
            if j == bytes.len() {
                return (j == i).then_some(());
            }
            if bytes[j] != b';' {
                return None;
            }
            i = token(bytes, skip_spaces(bytes, j + 1))?;
            if bytes.get(i) != Some(&b'=') {
                return None;
            }
            i = token(bytes, i + 1).or_else(|| quoted_string(bytes, i + 1))?;
        }
    }

    let bytes = value.as_bytes();
    if let Some(bad) = bytes.iter().copied().find(|&b| !(0x20..0x7F).contains(&b)) {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!("{field} contains byte 0x{bad:02X}; a media type is printable ASCII"),
            ErrorContext::new("as4_send_validate"),
        ));
    }
    parse(bytes).ok_or_else(|| {
        AsxError::new(
            ErrorCode::InvalidInput,
            format!(
                "{field} {value:?} is not a media type (type/subtype with optional \
                 ; name=value parameters)"
            ),
            ErrorContext::new("as4_send_validate"),
        )
    })
}

/// Builder for constructing MIME multipart/related messages.
///
/// Handles serialization of SOAP envelope and attachments into properly-formatted
/// multipart MIME structure with correct boundary markers and headers.
#[derive(Debug)]
pub(crate) struct MimePackageBuilder {
    boundary: String,
    root_soap_content_type: String,
    soap_attachment: Option<MimeAttachment>,
    attachments: Vec<MimeAttachment>,
}

impl MimePackageBuilder {
    fn write_crlf_line(body: &mut Vec<u8>, line: &str, stage: &'static str) -> Result<()> {
        // Every header source passes here: a CR, LF or other control octet in
        // a line would end the header early or inject another one.
        if let Some(bad) = line.bytes().find(|&b| b < 0x20 || b == 0x7F) {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                format!("MIME header line contains control character 0x{bad:02X}"),
                ErrorContext::new(stage),
            ));
        }
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
    pub(crate) fn new() -> Self {
        // A random boundary plus a process counter: unique without reading
        // the wall clock.
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let mut random = [0u8; 8];
        // On a getrandom failure the counter alone still separates boundaries
        // within the process.
        let _ = getrandom::fill(&mut random);
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let combined = u64::from_le_bytes(random).wrapping_add(counter);

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
    pub(crate) fn with_root_soap_content_type(
        mut self,
        soap_content_type: impl Into<String>,
    ) -> Self {
        self.root_soap_content_type = soap_content_type.into();
        self
    }

    /// Set the SOAP envelope as the root attachment (Content-ID: `<soap-body@example.com>`).
    ///
    /// The root part is `application/soap+xml` — AS4 SwA packaging. (MTOM's
    /// `application/xop+xml` root makes WSS4J-based receivers fail the security-header DOM conversion.)
    pub(crate) fn with_soap_body(mut self, soap_xml: Vec<u8>) -> Self {
        let content_type = format!("{}; charset=UTF-8", self.root_soap_content_type);
        self.soap_attachment = Some(MimeAttachment::new(
            "soap-body@example.com",
            content_type,
            soap_xml,
            "8bit",
        ));
        self
    }

    /// Add multiple attachments.
    pub(crate) fn add_attachments(mut self, attachments: Vec<MimeAttachment>) -> Self {
        self.attachments.extend(attachments);
        self
    }

    /// Build the final MIME multipart/related message as bytes.
    ///
    /// Returns the complete HTTP message body with proper boundary markers
    /// and headers for each part.
    pub(crate) fn build(self) -> Result<Vec<u8>> {
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
    /// The `type` parameter names the root part's media type per RFC 2387 —
    /// `application/soap+xml` for AS4 SwA packaging.
    pub(crate) fn content_type(&self) -> String {
        format!(
            "multipart/related; boundary=\"{}\"; type=\"{}\"",
            self.boundary, self.root_soap_content_type
        )
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
    fn mime_package_content_type_header() {
        let builder = MimePackageBuilder::new();
        let content_type = builder.content_type();

        assert!(content_type.starts_with("multipart/related"));
        assert!(content_type.contains("boundary="));
        assert!(content_type.contains("type=\"application/soap+xml\""));
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

    // ── PayloadFilename tests ─────────────────────────────────────────────────

    #[test]
    fn payload_filename_accepts_printable_ascii() {
        assert!(PayloadFilename::new("invoice.xml").is_ok());
        assert!(
            PayloadFilename::new("MSCONS_4011234000000_4011234000001_260705_1230_REF.txt").is_ok()
        );
        assert!(PayloadFilename::new("file with spaces.txt").is_ok());
        // full printable range: 0x20 and 0x7E
        assert!(PayloadFilename::new(" ~").is_ok());
    }

    #[test]
    fn payload_filename_rejects_empty() {
        let err = PayloadFilename::new("").unwrap_err();
        assert!(err.to_string().contains("empty"), "{err}");
    }

    #[test]
    fn payload_filename_rejects_over_length() {
        let long = "a".repeat(256);
        let err = PayloadFilename::new(&long).unwrap_err();
        assert!(err.to_string().contains("maximum length"), "{err}");
    }

    #[test]
    fn payload_filename_rejects_control_characters() {
        // Header-injection: CR, LF
        assert!(PayloadFilename::new("evil\r\nX-Injected: hdr").is_err());
        assert!(PayloadFilename::new("evil\n").is_err());
        // Null byte
        assert!(PayloadFilename::new("evil\x00null").is_err());
        // DEL (0x7F is outside the 0x20–0x7E printable range)
        assert!(PayloadFilename::new("evil\x7f").is_err());
        // Non-ASCII: U+00E9 é (UTF-8: 0xC3 0xA9 — both bytes > 0x7E)
        assert!(PayloadFilename::new("caf\u{00e9}").is_err());
    }

    #[test]
    fn payload_filename_rejects_quoted_string_specials() {
        // Double-quote would break `filename="..."` encoding
        assert!(PayloadFilename::new("evil\"quote").is_err());
        // Backslash is the RFC 2183 escape character in quoted-string
        assert!(PayloadFilename::new("evil\\backslash").is_err());
    }

    #[test]
    fn payload_filename_tryfrom_conversions_work() {
        let from_str: PayloadFilename = "invoice.xml".try_into().unwrap();
        let from_string: PayloadFilename = "invoice.xml".to_string().try_into().unwrap();
        let from_parse: PayloadFilename = "invoice.xml".parse().unwrap();
        assert_eq!(from_str, from_string);
        assert_eq!(from_str, from_parse);
        assert_eq!(from_str.as_str(), "invoice.xml");
    }

    #[test]
    fn payload_filename_display_and_asref() {
        let name = PayloadFilename::new("report.pdf").unwrap();
        assert_eq!(name.to_string(), "report.pdf");
        assert_eq!(AsRef::<str>::as_ref(&name), "report.pdf");
    }
}
