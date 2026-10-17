//! MIME attachment support for AS4 outbound messages.
//!
//! This module provides helper functions to package AS4 messages with MIME multipart/related
//! structure for strict profile (PEPPOL/CEF) conformance.
//!
//! AS4 messages are transmitted
//! as MIME multipart/related instead of embedded in SOAP `<asx:Base64>` elements.

use crate::as4::mime_packaging::{MimeAttachment, MimePackageBuilder};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

/// The SOAP part followed by `attachments`, in order.
pub(crate) fn package_attachments(
    soap_body: Vec<u8>,
    soap_content_type: &str,
    attachments: Vec<MimeAttachment>,
) -> Result<(Vec<u8>, String)> {
    let builder = MimePackageBuilder::new()
        .with_root_soap_content_type(soap_content_type)
        .with_soap_body(soap_body)
        .add_attachments(attachments);

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
