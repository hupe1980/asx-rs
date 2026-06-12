//! MIME attachment support for AS4 outbound messages.
//!
//! This module provides helper functions to package AS4 messages with MIME multipart/related
//! structure for strict profile (PEPPOL/CEF) conformance.
//!
//! When `PayloadPackagingMode::MimeAttachment` is selected, AS4 messages are transmitted
//! as MIME multipart/related instead of embedded in SOAP `<asx:Base64>` elements.

use crate::as4::mime_packaging::{MimeAttachment, MimePackageBuilder};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, Writer};

const XOP_NAMESPACE: &str = "http://www.w3.org/2004/08/xop/include";

#[inline]
fn generated_xml_bytes_to_string(bytes: Vec<u8>) -> String {
    debug_assert!(
        std::str::from_utf8(&bytes).is_ok(),
        "generated XML must be UTF-8"
    );
    // quick-xml writer re-emits UTF-8 XML; still validate in release builds.
    String::from_utf8(bytes).expect("generated XML must be UTF-8")
}

/// Package an AS4 SOAP envelope + payload as MIME multipart/related.
///
/// This function creates a multipart/related message with:
/// - Part 1: SOAP envelope (Content-Type: application/xop+xml)
/// - Part 2+: Payload attachment(s) (Content-Type: application/octet-stream or as configured)
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
) -> Result<(Vec<u8>, String)> {
    // Create payload attachment. Content-Disposition is intentionally omitted
    // for strict-profile interoperability.
    let payload_attachment =
        MimeAttachment::new(payload_content_id, payload_content_type, payload, "binary");

    // Build MIME package
    let builder = MimePackageBuilder::new()
        .with_root_soap_content_type(soap_content_type)
        .with_soap_body(soap_body)
        .add_attachment(payload_attachment);

    // Include start/start-info parameters for strict multipart/related parsers.
    let content_type = format!(
        "{}; start=\"<soap-body@example.com>\"; start-info=\"{}\"",
        builder.content_type(),
        soap_content_type,
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

/// Inject xop:Include reference into SOAP body for MIME mode.
///
/// Replaces the embedded `<asx:Base64>` payload with `<xop:Include>` reference.
/// This is used when generating SOAP envelopes for MIME multipart/related transmission.
///
/// # Returns
/// Modified SOAP body XML with xop:Include instead of embedded payload
pub fn inject_xop_include(soap_xml: &str, payload_content_id: &str) -> Result<String> {
    let mut reader = Reader::from_str(soap_xml);
    reader.config_mut().trim_text(false);

    let mut writer = Writer::new(Vec::new());
    let mut buf = Vec::new();

    let mut depth: usize = 0;
    let mut payload_depth: Option<usize> = None;
    let mut skipping_base64 = false;
    let mut base64_skip_depth = 0usize;
    let mut replaced = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(start)) => {
                depth = depth.saturating_add(1);

                if skipping_base64 {
                    base64_skip_depth = base64_skip_depth.saturating_add(1);
                    buf.clear();
                    continue;
                }

                let local = local_name(start.name().as_ref()).to_vec();
                if local.as_slice() == b"Payload" {
                    payload_depth = Some(depth);
                    let start = ensure_xop_namespace(start);
                    writer.write_event(Event::Start(start)).map_err(|e| {
                        AsxError::new(
                            ErrorCode::ParseFailed,
                            format!("failed to write Payload start event: {e}"),
                            ErrorContext::new("inject_xop_include"),
                        )
                    })?;
                } else if local.as_slice() == b"Base64" && payload_depth.is_some() {
                    let include = make_xop_include(payload_content_id);
                    writer.write_event(Event::Empty(include)).map_err(|e| {
                        AsxError::new(
                            ErrorCode::ParseFailed,
                            format!("failed to write xop:Include event: {e}"),
                            ErrorContext::new("inject_xop_include"),
                        )
                    })?;
                    skipping_base64 = true;
                    base64_skip_depth = 1;
                    replaced = true;
                } else {
                    writer
                        .write_event(Event::Start(start.into_owned()))
                        .map_err(|e| {
                            AsxError::new(
                                ErrorCode::ParseFailed,
                                format!("failed to write XML start event: {e}"),
                                ErrorContext::new("inject_xop_include"),
                            )
                        })?;
                }
            }
            Ok(Event::Empty(empty)) => {
                let local = local_name(empty.name().as_ref()).to_vec();
                if local.as_slice() == b"Base64" && payload_depth.is_some() {
                    let include = make_xop_include(payload_content_id);
                    writer.write_event(Event::Empty(include)).map_err(|e| {
                        AsxError::new(
                            ErrorCode::ParseFailed,
                            format!("failed to write xop:Include empty event: {e}"),
                            ErrorContext::new("inject_xop_include"),
                        )
                    })?;
                    replaced = true;
                } else if local.as_slice() == b"Payload" {
                    let payload = ensure_xop_namespace(empty);
                    writer.write_event(Event::Empty(payload)).map_err(|e| {
                        AsxError::new(
                            ErrorCode::ParseFailed,
                            format!("failed to write Payload empty event: {e}"),
                            ErrorContext::new("inject_xop_include"),
                        )
                    })?;
                } else {
                    writer
                        .write_event(Event::Empty(empty.into_owned()))
                        .map_err(|e| {
                            AsxError::new(
                                ErrorCode::ParseFailed,
                                format!("failed to write XML empty event: {e}"),
                                ErrorContext::new("inject_xop_include"),
                            )
                        })?;
                }
            }
            Ok(Event::End(end)) => {
                if skipping_base64 {
                    base64_skip_depth = base64_skip_depth.saturating_sub(1);
                    if base64_skip_depth == 0 {
                        skipping_base64 = false;
                    }
                    depth = depth.saturating_sub(1);
                    buf.clear();
                    continue;
                }

                let local = local_name(end.name().as_ref()).to_vec();
                writer
                    .write_event(Event::End(end.into_owned()))
                    .map_err(|e| {
                        AsxError::new(
                            ErrorCode::ParseFailed,
                            format!("failed to write XML end event: {e}"),
                            ErrorContext::new("inject_xop_include"),
                        )
                    })?;

                if local.as_slice() == b"Payload" {
                    payload_depth = None;
                }
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Text(text)) => {
                if !skipping_base64 {
                    writer
                        .write_event(Event::Text(text.into_owned()))
                        .map_err(|e| {
                            AsxError::new(
                                ErrorCode::ParseFailed,
                                format!("failed to write XML text event: {e}"),
                                ErrorContext::new("inject_xop_include"),
                            )
                        })?;
                }
            }
            Ok(Event::CData(cdata)) => {
                if !skipping_base64 {
                    writer
                        .write_event(Event::CData(cdata.into_owned()))
                        .map_err(|e| {
                            AsxError::new(
                                ErrorCode::ParseFailed,
                                format!("failed to write XML cdata event: {e}"),
                                ErrorContext::new("inject_xop_include"),
                            )
                        })?;
                }
            }
            Ok(Event::Comment(comment)) => {
                if !skipping_base64 {
                    writer
                        .write_event(Event::Comment(comment.into_owned()))
                        .map_err(|e| {
                            AsxError::new(
                                ErrorCode::ParseFailed,
                                format!("failed to write XML comment event: {e}"),
                                ErrorContext::new("inject_xop_include"),
                            )
                        })?;
                }
            }
            Ok(Event::Decl(decl)) => {
                writer
                    .write_event(Event::Decl(decl.into_owned()))
                    .map_err(|e| {
                        AsxError::new(
                            ErrorCode::ParseFailed,
                            format!("failed to write XML declaration event: {e}"),
                            ErrorContext::new("inject_xop_include"),
                        )
                    })?;
            }
            Ok(Event::PI(pi)) => {
                writer
                    .write_event(Event::PI(pi.into_owned()))
                    .map_err(|e| {
                        AsxError::new(
                            ErrorCode::ParseFailed,
                            format!("failed to write XML PI event: {e}"),
                            ErrorContext::new("inject_xop_include"),
                        )
                    })?;
            }
            Ok(Event::DocType(doctype)) => {
                writer
                    .write_event(Event::DocType(doctype.into_owned()))
                    .map_err(|e| {
                        AsxError::new(
                            ErrorCode::ParseFailed,
                            format!("failed to write XML doctype event: {e}"),
                            ErrorContext::new("inject_xop_include"),
                        )
                    })?;
            }
            Ok(Event::GeneralRef(reference)) => {
                if !skipping_base64 {
                    writer
                        .write_event(Event::GeneralRef(reference.into_owned()))
                        .map_err(|e| {
                            AsxError::new(
                                ErrorCode::ParseFailed,
                                format!("failed to write XML entity reference event: {e}"),
                                ErrorContext::new("inject_xop_include"),
                            )
                        })?;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(AsxError::new(
                    ErrorCode::ParseFailed,
                    format!("failed to parse XML for xop:Include injection: {e}"),
                    ErrorContext::new("inject_xop_include"),
                ));
            }
        }
        buf.clear();
    }

    if !replaced {
        // Keep exact formatting when no Base64 node was present.
        return Ok(soap_xml.to_string());
    }

    Ok(generated_xml_bytes_to_string(writer.into_inner()))
}

fn ensure_xop_namespace(start: BytesStart<'_>) -> BytesStart<'static> {
    let mut owned = start.into_owned();
    let has_xop = owned
        .attributes()
        .with_checks(false)
        .flatten()
        .any(|attr| attr.key.as_ref() == b"xmlns:xop");
    if !has_xop {
        owned.push_attribute(("xmlns:xop", XOP_NAMESPACE));
    }
    owned
}

fn make_xop_include(payload_content_id: &str) -> BytesStart<'static> {
    let mut include = BytesStart::new("xop:Include");
    let href = format!("cid:{payload_content_id}");
    include.push_attribute(("href", href.as_str()));
    include
}

fn local_name(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|b| *b == b':') {
        Some(idx) => &name[idx + 1..],
        None => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_xop_include_replaces_base64() {
        let soap_with_base64 = r#"  <soap:Body wsu:Id="as4-body">
    <asx:Payload xmlns:asx="urn:asx:payload">
      <asx:MimeType>application/octet-stream</asx:MimeType>
      <asx:Base64>YWJjZA==</asx:Base64>
    </asx:Payload>
  </soap:Body>"#;

        let result = inject_xop_include(soap_with_base64, "payload-001@example.com")
            .expect("should inject xop:Include");

        assert!(
            result.contains("<xop:Include"),
            "should contain xop:Include"
        );
        assert!(
            result.contains("href=\"cid:payload-001@example.com\""),
            "should reference correct Content-ID"
        );
        assert!(
            !result.contains("Base64"),
            "should not contain Base64 element"
        );
        assert!(
            result.contains("xmlns:xop="),
            "should declare xop namespace"
        );
    }

    #[test]
    fn inject_xop_include_no_payload_is_safe() {
        let soap_no_payload = r#"  <soap:Body wsu:Id="as4-body">
  </soap:Body>"#;

        let result = inject_xop_include(soap_no_payload, "payload-001@example.com")
            .expect("should not error");

        assert_eq!(
            result, soap_no_payload,
            "should return unchanged when no payload"
        );
    }
}
