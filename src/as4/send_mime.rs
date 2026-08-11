//! MIME attachment support for AS4 outbound messages.
//!
//! This module provides helper functions to package AS4 messages with MIME multipart/related
//! structure for strict profile (PEPPOL/CEF) conformance.
//!
//! When `PayloadPackagingMode::MimeAttachment` is selected, AS4 messages are transmitted
//! as MIME multipart/related instead of embedded in SOAP `<asx:Base64>` elements.

use crate::as4::mime_packaging::{MimeAttachment, MimePackageBuilder, PayloadFilename};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

/// Package an AS4 SOAP envelope + payload as MIME multipart/related.
///
/// AS4 SwA packaging: the multipart/related message carries
/// - Part 1: the SOAP envelope (`application/soap+xml`, empty Body), and
/// - Part 2+: payload attachment(s), referenced from the signed
///   `eb:PartInfo href="cid:…"` header entries.
///
/// # Parameters
/// - `soap_envelope`: The unsigned SOAP envelope (will be signed before MIME packaging in real flows)
/// - `payload`: The binary payload to attach
/// - `payload_content_id`: Content-ID for the payload (e.g., from `MimeAttachment::content_id_from_digest`)
/// - `payload_content_type`: MIME type of the payload (e.g., "application/octet-stream")
///
/// # Returns
/// - MIME multipart/related message bytes
/// - Content-Type header for the HTTP response
///
/// # Errors
/// - `PolicyViolation` if MIME packaging fails
pub fn package_as_mime(
    soap_body: Vec<u8>,
    payload: Vec<u8>,
    payload_content_id: &str,
    payload_content_type: &str,
    soap_content_type: &str,
    payload_filename: Option<&PayloadFilename>,
) -> Result<(Vec<u8>, String)> {
    package_as_mime_with_extra_attachments(
        soap_body,
        payload,
        payload_content_id,
        payload_content_type,
        soap_content_type,
        payload_filename,
        Vec::new(),
    )
}

/// [`package_as_mime`] with additional payload parts appended after the
/// primary, in order — the multi-payload UserMessage packaging.
#[allow(clippy::too_many_arguments)]
pub fn package_as_mime_with_extra_attachments(
    soap_body: Vec<u8>,
    payload: Vec<u8>,
    payload_content_id: &str,
    payload_content_type: &str,
    soap_content_type: &str,
    payload_filename: Option<&PayloadFilename>,
    extra_attachments: Vec<MimeAttachment>,
) -> Result<(Vec<u8>, String)> {
    // Build the Content-Disposition value. BDEW §AF §2.12 requires a filename
    // on every payload part. When no filename is supplied we still emit
    // `Content-Disposition: attachment` for PEPPOL AS4 profile conformance
    // (receivers validate the header's presence; omitting it is incorrect).
    let disposition = match payload_filename {
        Some(name) => format!("attachment; filename=\"{}\"", name.as_str()),
        None => "attachment".to_string(),
    };
    let payload_attachment =
        MimeAttachment::new(payload_content_id, payload_content_type, payload, "binary")
            .with_disposition(disposition);

    // Build MIME package
    let builder = MimePackageBuilder::new()
        .with_root_soap_content_type(soap_content_type)
        .with_soap_body(soap_body)
        .add_attachment(payload_attachment)
        .add_attachments(extra_attachments);

    // Include the start parameter for strict multipart/related parsers.
    let content_type = format!(
        "{}; start=\"<soap-body@example.com>\"",
        builder.content_type(),
    );

    let mime_body = builder.build().map_err(|e| {
        AsxError::new(
            ErrorCode::PolicyViolation,
            format!("MIME packaging failed: {}", e),
            ErrorContext::new("send_mime_package"),
        )
    })?;

    Ok((mime_body, content_type))
}
