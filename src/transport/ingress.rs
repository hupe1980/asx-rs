//! Server-side HTTP ingress adapters for AS2 and AS4.
//!
//! These conversion functions extract protocol-level message data from
//! incoming [`crate::http::HttpRequest`] objects, validating required
//! headers per RFC 4130 §6 (AS2) and the eDelivery AS4 HTTP binding.
//! They impose no dependency on an HTTP framework — integrate them with
//! actix-web, axum, or any adapter that can produce an `HttpRequest`.

use crate::core::{AsxError, DEFAULT_MAX_BODY_BYTES, ErrorCode, ErrorContext, Result};
use crate::http::{HttpHeaders, HttpRequest};
use crate::transport::trace_context::normalize_traceparent;
use std::collections::HashSet;
use std::sync::Arc;

// ── Helpers ────────────────────────────────────────────────────────────────

/// Find the first header value for `name` (case-insensitive).
fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Require header `name`, returning a trimmed owned copy or an `InvalidInput` error.
fn require_header(headers: &[(String, String)], name: &str, ctx: &'static str) -> Result<String> {
    match find_header(headers, name) {
        Some(v) if !v.trim().is_empty() => Ok(v.trim().to_string()),
        _ => Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!("required AS2 HTTP header '{name}' is missing or empty"),
            ErrorContext::new(ctx),
        )),
    }
}

// ── AS2 ingress ────────────────────────────────────────────────────────────

/// Data extracted from an HTTP POST carrying an AS2 message (RFC 4130 §6).
///
/// Pass `body` bytes into `crate::as2::receive_from_ingress` for
/// fully automatic MDN generation, or `crate::as2::receive_sync` for
/// manual control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As2HttpIngress {
    /// Raw MIME body bytes (the payload after all HTTP framing is stripped).
    pub body: Arc<[u8]>,
    /// Value of the HTTP `Content-Type` header.
    pub content_type: String,
    /// Value of the `AS2-From` header (sender's AS2 ID).
    pub as2_from: String,
    /// Value of the `AS2-To` header (recipient's AS2 ID).
    pub as2_to: String,
    /// Value of the `Message-ID` header, if present.
    pub message_id: Option<String>,
    /// Value of the `AS2-Version` header, if present.
    pub as2_version: Option<String>,
    /// Value of the `MIME-Version` header, if present.
    pub mime_version: Option<String>,
    /// `Disposition-Notification-To` header value, if present (RFC 4130 §6).
    ///
    /// When set, the sender is requesting an MDN.  An HTTP URL means a
    /// synchronous MDN is expected in the HTTP response; a `mailto:` address
    /// means an asynchronous MDN should be delivered separately.
    ///
    /// Pass this struct to `crate::as2::receive_from_ingress` to
    /// have the library generate the MDN automatically.
    pub disposition_notification_to: Option<String>,
    /// `Disposition-Notification-Options` header value, if present (RFC 4130 §6).
    ///
    /// Contains the sender's preferred MIC algorithm, e.g.:
    /// `signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, sha-256`
    pub disposition_notification_options: Option<String>,
    /// W3C Trace Context parent value from inbound HTTP headers, when valid.
    pub traceparent: Option<String>,
    /// Raw HTTP headers (all of them) for downstream inspection.
    pub raw_headers: HttpHeaders,
}

/// Extract AS2 ingress data from an HTTP `POST` request.
///
/// Validates:
/// - Method is `POST` (RFC 4130 §6 requires POST).
/// - `AS2-From` header is present and non-empty.
/// - `AS2-To` header is present and non-empty.
/// - `Content-Type` header is present and non-empty.
///
/// The request body is **moved** into the returned struct without copying.
///
/// # Errors
/// Returns [`ErrorCode::InvalidInput`] if the method is wrong or any required
/// header is missing.
pub fn as2_ingress_from_http(request: HttpRequest) -> Result<As2HttpIngress> {
    if !request.method.eq_ignore_ascii_case("POST") {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!(
                "AS2 HTTP binding requires POST; received '{}'",
                request.method
            ),
            ErrorContext::new("as2_ingress"),
        ));
    }

    let as2_from = require_header(&request.headers, "AS2-From", "as2_ingress")?;
    let as2_to = require_header(&request.headers, "AS2-To", "as2_ingress")?;
    let content_type = require_header(&request.headers, "Content-Type", "as2_ingress")?;

    // Enforce body size limit before allocating/processing the body.
    let body_len = request.body.len();
    if body_len > DEFAULT_MAX_BODY_BYTES {
        return Err(AsxError::new(
            ErrorCode::PayloadTooLarge,
            format!(
                "AS2 request body size {body_len} exceeds limit {DEFAULT_MAX_BODY_BYTES}; \
                 respond with HTTP 413 Content Too Large"
            ),
            ErrorContext::new("as2_ingress"),
        ));
    }

    let message_id = find_header(&request.headers, "Message-ID")
        .filter(|v| !v.trim().is_empty())
        .map(|v| v.trim().to_string());

    let as2_version = find_header(&request.headers, "AS2-Version")
        .filter(|v| !v.trim().is_empty())
        .map(|v| v.trim().to_string());

    let mime_version = find_header(&request.headers, "MIME-Version")
        .filter(|v| !v.trim().is_empty())
        .map(|v| v.trim().to_string());

    let disposition_notification_to = find_header(&request.headers, "Disposition-Notification-To")
        .filter(|v| !v.trim().is_empty())
        .map(|v| v.trim().to_string());

    let disposition_notification_options =
        find_header(&request.headers, "Disposition-Notification-Options")
            .filter(|v| !v.trim().is_empty())
            .map(|v| v.trim().to_string());
    let traceparent = find_header(&request.headers, "traceparent").and_then(normalize_traceparent);

    Ok(As2HttpIngress {
        body: request.body,
        content_type,
        as2_from,
        as2_to,
        message_id,
        as2_version,
        mime_version,
        disposition_notification_to,
        disposition_notification_options,
        traceparent,
        raw_headers: request.headers,
    })
}

#[cfg(feature = "as2")]
impl As2HttpIngress {
    /// Verify the inbound AS2 message and automatically generate a synchronous MDN
    /// when the sender requests one via `Disposition-Notification-To` (RFC 4130 §7.4).
    ///
    /// This is the ergonomic entry point for AS2 server handlers:
    ///
    /// ```rust,ignore
    /// let ingress = as2_ingress_from_http(http_request)?;
    /// let result  = ingress.receive_and_generate_mdn(session, verifier)?;
    /// if let Some(mdn) = result.sync_mdn.as_ref() {
    ///     // return mdn.bytes as HTTP 200 with Content-Type: mdn.content_type
    /// }
    /// ```
    ///
    /// See `crate::as2::receive_from_ingress` for the lower-level equivalent.
    pub fn receive_and_generate_mdn(
        &self,
        session: &crate::core::SessionContext,
        verifier: &dyn crate::as2::As2TrustVerifier,
    ) -> crate::core::Result<crate::as2::As2InboundResult> {
        self.receive_and_generate_mdn_with_signing(session, verifier, None)
    }

    /// Same as `receive_and_generate_mdn`, but allows configuring MDN signing
    /// credentials for partners that request signed synchronous receipts.
    pub fn receive_and_generate_mdn_with_signing(
        &self,
        session: &crate::core::SessionContext,
        verifier: &dyn crate::as2::As2TrustVerifier,
        mdn_signing_credentials: Option<&crate::as2::As2MdnSigningCredentials>,
    ) -> crate::core::Result<crate::as2::As2InboundResult> {
        // RFC 4130 §6 mandates a valid AS2-Version header.  Validate before
        // processing the payload so callers get a clear rejection reason.
        crate::as2::validate_as2_version_header(
            &self.raw_headers,
            &crate::as2::As2ReceivePolicy::default(),
        )
        .map_err(|e| e.with_partner_id(session.partner_id()))?;

        crate::as2::receive_from_ingress(crate::as2::As2IngressReceiveRequest {
            session,
            payload: &self.body,
            content_type: &self.content_type,
            original_message_id: self.message_id.as_deref(),
            as2_from_header: &self.as2_from,
            disposition_notification_to: self.disposition_notification_to.as_deref(),
            disposition_notification_options: self.disposition_notification_options.as_deref(),
            mdn_signing_credentials,
            verifier,
        })
    }
}

/// Data extracted from an HTTP `POST` carrying an AS4 SOAP message.
///
/// Feed `body` into [`crate::as4::receive_push_with_dedup_sync`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As4HttpIngress {
    /// Raw SOAP envelope bytes.
    pub body: Arc<[u8]>,
    /// Value of the HTTP `Content-Type` header.
    pub content_type: String,
    /// SOAP 1.2 action value, if present.
    ///
    /// This is extracted from the `action` parameter of `Content-Type`.
    pub action: Option<String>,
    /// W3C Trace Context parent value from inbound HTTP headers, when valid.
    pub traceparent: Option<String>,
    /// Raw HTTP headers for downstream inspection.
    pub raw_headers: HttpHeaders,
}

#[cfg(feature = "as4")]
pub struct As4IngressReceivePushSyncRequest<'a> {
    pub session: &'a crate::core::SessionContext,
    pub event_bus: &'a crate::observability::EventBus,
    pub policy: crate::as4::As4PushPolicy,
    pub dedup_backend: &'a dyn crate::storage::DedupStorage,
    pub receipt_payload: Option<Vec<u8>>,
}

/// Extract AS4 SOAP ingress data from an HTTP `POST` request.
///
/// Validates:
/// - Method is `POST`.
/// - `Content-Type` is present and is either:
///   - `application/soap+xml`, or
///   - `multipart/related` carrying SOAP/XOP (`application/soap+xml` or
///     `application/xop+xml`).
///
/// The SOAP 1.2 action is extracted from the `action` parameter inside
/// `Content-Type`.
///
/// # Errors
/// Returns [`ErrorCode::InvalidInput`] if the method is wrong, `Content-Type`
/// is missing, or the content type is not a recognisable SOAP variant.
pub fn as4_ingress_from_http(request: HttpRequest) -> Result<As4HttpIngress> {
    if !request.method.eq_ignore_ascii_case("POST") {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!(
                "AS4 HTTP binding requires POST; received '{}'",
                request.method
            ),
            ErrorContext::new("as4_ingress"),
        ));
    }

    let content_type = require_header(&request.headers, "Content-Type", "as4_ingress")?;

    let is_direct_soap = content_type
        .split(';')
        .next()
        .map(|v| v.trim().eq_ignore_ascii_case("application/soap+xml"))
        .unwrap_or(false);
    let is_multipart_soap = is_as4_multipart_soap_content_type(&content_type);

    if !(is_direct_soap || is_multipart_soap) {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!(
                "AS4 HTTP binding requires SOAP-aware Content-Type \
                 (application/soap+xml or multipart/related with SOAP/XOP root); got '{content_type}'"
            ),
            ErrorContext::new("as4_ingress"),
        ));
    }

    let action = extract_action_param(&content_type);
    let traceparent = find_header(&request.headers, "traceparent").and_then(normalize_traceparent);

    // Enforce body size limit before processing the SOAP payload.
    let body_len = request.body.len();
    if body_len > DEFAULT_MAX_BODY_BYTES {
        return Err(AsxError::new(
            ErrorCode::PayloadTooLarge,
            format!(
                "AS4 request body size {body_len} exceeds limit {DEFAULT_MAX_BODY_BYTES}; \
                 respond with HTTP 413 Content Too Large"
            ),
            ErrorContext::new("as4_ingress"),
        ));
    }

    Ok(As4HttpIngress {
        body: request.body,
        content_type,
        action,
        traceparent,
        raw_headers: request.headers,
    })
}

#[cfg(feature = "as4")]
impl As4HttpIngress {
    fn make_receive_push_request(
        &self,
        policy: crate::as4::As4PushPolicy,
        receipt_payload: Option<Vec<u8>>,
    ) -> crate::as4::As4ReceivePushRequest {
        crate::as4::As4ReceivePushRequest {
            http_content_type: self.content_type.clone(),
            payload: Arc::clone(&self.body),
            receipt_payload,
            policy,
            authenticated_sender_scope: None,
        }
    }

    /// Verify/process an inbound AS4 push message with dedup using this ingress payload.
    ///
    /// `receipt_payload` is optional and can be supplied when the caller has an
    /// associated receipt envelope to correlate with this push processing step.
    pub fn receive_push_with_dedup_sync(
        &self,
        request: As4IngressReceivePushSyncRequest<'_>,
    ) -> crate::core::Result<crate::as4::As4ReceiveOutcome> {
        crate::as4::receive_push_with_dedup_sync(
            request.session,
            request.event_bus,
            crate::as4::As4ReceivePushSyncRequest {
                request: self.make_receive_push_request(request.policy, request.receipt_payload),
                dedup_backend: request.dedup_backend,
            },
        )
    }
}

fn strip_optional_quotes(value: &str) -> &str {
    let trimmed = value.trim();
    if trimmed.len() >= 2 {
        let bytes = trimmed.as_bytes();
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &trimmed[1..trimmed.len() - 1];
        }
    }
    trimmed
}

fn has_mismatched_wrapping_quote(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() < 2 {
        return false;
    }
    let bytes = trimmed.as_bytes();
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    (first == b'"' || first == b'\'') && first != last
}

fn is_as4_multipart_soap_content_type(content_type: &str) -> bool {
    let mut parts = content_type.split(';');
    let Some(media_type) = parts.next() else {
        return false;
    };
    if !media_type.trim().eq_ignore_ascii_case("multipart/related") {
        return false;
    }

    let mut root_type: Option<String> = None;
    let mut start_info: Option<String> = None;
    let mut seen_params: HashSet<String> = HashSet::new();
    for part in parts {
        let trimmed_part = part.trim();
        if trimmed_part.is_empty() {
            continue;
        }

        let Some((key, value)) = trimmed_part.split_once('=') else {
            if trimmed_part.eq_ignore_ascii_case("type")
                || trimmed_part.eq_ignore_ascii_case("start-info")
            {
                return false;
            }
            continue;
        };
        let key = key.trim();
        let normalized_key = key.to_ascii_lowercase();
        if !seen_params.insert(normalized_key) {
            return false;
        }
        if has_mismatched_wrapping_quote(value) {
            return false;
        }
        let value = strip_optional_quotes(value).to_ascii_lowercase();
        if key.eq_ignore_ascii_case("type") {
            root_type = Some(value);
        } else if key.eq_ignore_ascii_case("start-info") {
            start_info = Some(value);
        }
    }

    match root_type.as_deref() {
        Some("application/soap+xml") => true,
        Some("application/xop+xml") => {
            matches!(start_info.as_deref(), Some("application/soap+xml"))
        }
        _ => false,
    }
}

/// Extract the `action="..."` parameter from a SOAP 1.2 `Content-Type` value.
fn extract_action_param(content_type: &str) -> Option<String> {
    for part in content_type.split(';') {
        let trimmed = part.trim();
        if let Some(rest) = trimmed.strip_prefix("action=") {
            let value = rest.trim();
            // Strip surrounding quotes.
            if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
                return Some(value[1..value.len() - 1].to_string());
            }
            return Some(value.to_string());
        }
    }
    None
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![cfg_attr(not(feature = "interop-relaxed"), allow(unused_imports, dead_code))]
    use super::*;
    #[cfg(feature = "as4")]
    use crate::as4::As4TopologyCoordination;
    #[cfg(feature = "as4")]
    use crate::core::InteropMode;
    #[cfg(all(feature = "as4", feature = "testing"))]
    use crate::core::OcspMode;
    #[cfg(feature = "as4")]
    use crate::observability::audit_sink::{
        AuditEvent, AuditSinkDurability, DurableAuditSink, InMemoryAuditSink, ReplayCursor,
    };
    #[cfg(feature = "as4")]
    use crate::presets::{
        DeploymentTopology, issue_strict_runtime_bootstrap_token_with_as4_topology,
    };
    #[cfg(feature = "as4")]
    use crate::reliability::ReconciliationRequest;
    #[cfg(feature = "as4")]
    use crate::storage::{BoxFuture, DedupStorage, ReconciliationStorage};
    #[cfg(all(feature = "as4", feature = "testing"))]
    use sha2::{Digest, Sha256};
    #[cfg(feature = "as4")]
    use std::sync::Arc;

    fn as2_post(headers: Vec<(&str, &str)>, body: Vec<u8>) -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            uri: "/as2/inbox".into(),
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.into(),
        }
    }

    fn as4_post(headers: Vec<(&str, &str)>, body: Vec<u8>) -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            uri: "/as4/inbox".into(),
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.into(),
        }
    }

    #[test]
    fn as2_ingress_extracts_required_headers() {
        let req = as2_post(
            vec![
                ("AS2-From", "sender-id"),
                ("AS2-To", "receiver-id"),
                (
                    "Content-Type",
                    "application/pkcs7-mime; smime-type=enveloped-data",
                ),
                ("Message-ID", "<msg-001@example.com>"),
                ("AS2-Version", "1.2"),
            ],
            b"payload bytes".to_vec(),
        );

        let ingress = as2_ingress_from_http(req).expect("should parse AS2 ingress");
        assert_eq!(ingress.as2_from, "sender-id");
        assert_eq!(ingress.as2_to, "receiver-id");
        assert_eq!(ingress.message_id.as_deref(), Some("<msg-001@example.com>"));
        assert_eq!(ingress.as2_version.as_deref(), Some("1.2"));
        assert_eq!(ingress.body.as_ref(), b"payload bytes");
        assert!(ingress.traceparent.is_none());
    }

    #[test]
    fn as2_ingress_extracts_valid_traceparent() {
        let req = as2_post(
            vec![
                ("AS2-From", "sender-id"),
                ("AS2-To", "receiver-id"),
                ("Content-Type", "application/octet-stream"),
                (
                    "traceparent",
                    "00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01",
                ),
            ],
            b"payload bytes".to_vec(),
        );

        let ingress = as2_ingress_from_http(req).expect("should parse AS2 ingress");
        assert_eq!(
            ingress.traceparent.as_deref(),
            Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
        );
    }

    #[test]
    fn as2_ingress_rejects_non_post() {
        let mut req = as2_post(
            vec![
                ("AS2-From", "s"),
                ("AS2-To", "r"),
                ("Content-Type", "application/octet-stream"),
            ],
            vec![],
        );
        req.method = "GET".into();
        let err = as2_ingress_from_http(req).expect_err("GET should be rejected");
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn as2_ingress_rejects_missing_as2_from() {
        let req = as2_post(
            vec![
                ("AS2-To", "receiver-id"),
                ("Content-Type", "application/octet-stream"),
            ],
            vec![],
        );
        let err = as2_ingress_from_http(req).expect_err("missing AS2-From must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("AS2-From"));
    }

    #[test]
    fn as2_ingress_header_matching_is_case_insensitive() {
        let req = as2_post(
            vec![
                ("as2-from", "sender"),
                ("AS2-TO", "receiver"),
                ("content-type", "application/octet-stream"),
            ],
            b"body".to_vec(),
        );
        let ingress = as2_ingress_from_http(req).expect("case-insensitive headers must match");
        assert_eq!(ingress.as2_from, "sender");
        assert_eq!(ingress.as2_to, "receiver");
    }

    #[test]
    fn as4_ingress_rejects_text_xml_soap11_content_type() {
        let body = b"<soapenv:Envelope/>".to_vec();
        let req = as4_post(
            vec![("Content-Type", "text/xml; charset=UTF-8")],
            body.clone(),
        );

        let err = as4_ingress_from_http(req).expect_err("SOAP 1.1 content-type must be rejected");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("application/soap+xml"));
    }

    #[test]
    fn as4_ingress_ignores_invalid_traceparent() {
        let req = as4_post(
            vec![
                ("Content-Type", "application/soap+xml"),
                ("traceparent", "invalid-value"),
            ],
            b"<soap/>".to_vec(),
        );

        let ingress = as4_ingress_from_http(req).expect("should parse AS4 ingress");
        assert!(
            ingress.traceparent.is_none(),
            "invalid traceparent must be ignored"
        );
    }

    #[test]
    fn as4_ingress_extracts_action_from_content_type() {
        let req = as4_post(
            vec![(
                "Content-Type",
                "application/soap+xml; charset=UTF-8; action=\"urn:ebms:push\"",
            )],
            b"<soap/>".to_vec(),
        );

        let ingress = as4_ingress_from_http(req).expect("SOAP 1.2 action param should parse");
        assert_eq!(ingress.action.as_deref(), Some("urn:ebms:push"));
    }

    #[test]
    fn as4_ingress_accepts_multipart_with_soap_root_type() {
        let req = as4_post(
            vec![(
                "Content-Type",
                "multipart/related; boundary=abc; type=\"application/soap+xml\"",
            )],
            b"--abc--\r\n".to_vec(),
        );

        let ingress = as4_ingress_from_http(req).expect("multipart SOAP root must be accepted");
        assert_eq!(
            ingress.content_type,
            "multipart/related; boundary=abc; type=\"application/soap+xml\""
        );
    }

    #[test]
    fn as4_ingress_accepts_multipart_xop_with_start_info_soap() {
        let req = as4_post(
            vec![(
                "Content-Type",
                "multipart/related; boundary=abc; type=\"application/xop+xml\"; start-info=\"application/soap+xml\"",
            )],
            b"--abc--\r\n".to_vec(),
        );

        let ingress = as4_ingress_from_http(req)
            .expect("multipart XOP with SOAP start-info must be accepted");
        assert!(ingress.content_type.contains("application/xop+xml"));
    }

    #[test]
    fn as4_ingress_accepts_multipart_with_mixed_case_params() {
        let req = as4_post(
            vec![(
                "Content-Type",
                "MuLtIpArT/ReLaTeD; BOUNDARY=abc; TYPE=\"Application/SoAp+XmL\"",
            )],
            b"--abc--\r\n".to_vec(),
        );

        let ingress = as4_ingress_from_http(req)
            .expect("multipart params should be matched case-insensitively");
        assert!(
            ingress
                .content_type
                .contains("TYPE=\"Application/SoAp+XmL\"")
        );
    }

    #[test]
    fn as4_ingress_accepts_multipart_xop_with_single_quoted_params() {
        let req = as4_post(
            vec![(
                "Content-Type",
                "multipart/related; boundary=abc; type='application/xop+xml'; start-info='application/soap+xml'",
            )],
            b"--abc--\r\n".to_vec(),
        );

        let ingress = as4_ingress_from_http(req)
            .expect("single-quoted multipart params should be normalized");
        assert!(ingress.content_type.contains("application/xop+xml"));
    }

    #[test]
    fn as4_ingress_rejects_multipart_missing_root_type_param() {
        let req = as4_post(
            vec![("Content-Type", "multipart/related; boundary=abc")],
            b"--abc--\r\n".to_vec(),
        );

        let err =
            as4_ingress_from_http(req).expect_err("multipart without root type must fail closed");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("SOAP-aware"));
    }

    #[test]
    fn as4_ingress_rejects_multipart_xop_without_start_info_soap() {
        let req = as4_post(
            vec![(
                "Content-Type",
                "multipart/related; boundary=abc; type=\"application/xop+xml\"",
            )],
            b"--abc--\r\n".to_vec(),
        );

        let err = as4_ingress_from_http(req)
            .expect_err("multipart XOP without SOAP start-info must fail closed");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("SOAP-aware"));
    }

    #[test]
    fn as4_ingress_rejects_multipart_with_mismatched_quote_delimiter() {
        let req = as4_post(
            vec![(
                "Content-Type",
                "multipart/related; boundary=abc; type=\"application/xop+xml'; start-info=\"application/soap+xml\"",
            )],
            b"--abc--\r\n".to_vec(),
        );

        let err = as4_ingress_from_http(req)
            .expect_err("mismatched multipart quote delimiters must fail closed");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("SOAP-aware"));
    }

    #[test]
    fn as4_ingress_rejects_multipart_with_duplicate_type_param() {
        let req = as4_post(
            vec![(
                "Content-Type",
                "multipart/related; boundary=abc; type=\"application/soap+xml\"; type=\"application/xop+xml\"; start-info=\"application/soap+xml\"",
            )],
            b"--abc--\r\n".to_vec(),
        );

        let err =
            as4_ingress_from_http(req).expect_err("duplicate type parameter must fail closed");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("SOAP-aware"));
    }

    #[test]
    fn as4_ingress_rejects_multipart_with_duplicate_start_info_param() {
        let req = as4_post(
            vec![(
                "Content-Type",
                "multipart/related; boundary=abc; type=\"application/xop+xml\"; start-info=\"application/soap+xml\"; start-info=\"application/soap+xml\"",
            )],
            b"--abc--\r\n".to_vec(),
        );

        let err = as4_ingress_from_http(req)
            .expect_err("duplicate start-info parameter must fail closed");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("SOAP-aware"));
    }

    #[test]
    fn as4_ingress_rejects_multipart_with_bare_type_token_without_equals() {
        let req = as4_post(
            vec![(
                "Content-Type",
                "multipart/related; boundary=abc; type; start-info=\"application/soap+xml\"",
            )],
            b"--abc--\r\n".to_vec(),
        );

        let err =
            as4_ingress_from_http(req).expect_err("bare type token without '=' must fail closed");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("SOAP-aware"));
    }

    #[test]
    fn as4_ingress_accepts_multipart_with_whitespace_padded_parameter_names() {
        let req = as4_post(
            vec![(
                "Content-Type",
                "multipart/related; boundary=abc;  type = \"application/xop+xml\";  start-info = \"application/soap+xml\"",
            )],
            b"--abc--\r\n".to_vec(),
        );

        let ingress = as4_ingress_from_http(req)
            .expect("whitespace-padded multipart parameter names should be normalized");
        assert!(
            ingress
                .content_type
                .contains("type = \"application/xop+xml\"")
        );
    }

    #[test]
    fn as4_ingress_rejects_multipart_with_duplicate_noncritical_param() {
        let req = as4_post(
            vec![(
                "Content-Type",
                "multipart/related; boundary=abc; boundary=def; type=\"application/soap+xml\"",
            )],
            b"--abc--\r\n".to_vec(),
        );

        let err = as4_ingress_from_http(req)
            .expect_err("duplicate non-critical parameters must fail closed");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("SOAP-aware"));
    }

    #[test]
    fn as4_ingress_rejects_multipart_with_empty_type_value() {
        let req = as4_post(
            vec![(
                "Content-Type",
                "multipart/related; boundary=abc; type=; start-info=\"application/soap+xml\"",
            )],
            b"--abc--\r\n".to_vec(),
        );

        let err = as4_ingress_from_http(req).expect_err("empty type value must fail closed");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("SOAP-aware"));
    }

    #[test]
    fn as4_ingress_rejects_multipart_with_empty_start_info_value() {
        let req = as4_post(
            vec![(
                "Content-Type",
                "multipart/related; boundary=abc; type=\"application/xop+xml\"; start-info=",
            )],
            b"--abc--\r\n".to_vec(),
        );

        let err = as4_ingress_from_http(req).expect_err("empty start-info value must fail closed");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("SOAP-aware"));
    }

    #[test]
    fn as4_ingress_rejects_non_soap_content_type() {
        let req = as4_post(vec![("Content-Type", "application/json")], b"{}".to_vec());
        let err = as4_ingress_from_http(req).expect_err("non-SOAP content-type must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("application/soap+xml"));
    }

    #[test]
    fn as4_ingress_rejects_non_post() {
        let mut req = as4_post(vec![("Content-Type", "application/soap+xml")], vec![]);
        req.method = "PUT".into();
        let err = as4_ingress_from_http(req).expect_err("PUT should be rejected");
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[cfg(all(feature = "as4", feature = "testing"))]
    const PUSH_FLOW_BOUNDARY: &str = "asx-push-flow-boundary";

    #[cfg(all(feature = "as4", feature = "testing"))]
    fn multipart_content_type() -> String {
        format!(
            "multipart/related; boundary=\"{PUSH_FLOW_BOUNDARY}\"; type=\"application/soap+xml\""
        )
    }

    #[cfg(all(feature = "as4", feature = "testing"))]
    fn fixture(name: &str) -> Vec<u8> {
        let path = format!("tests/fixtures/{name}");
        std::fs::read(&path).unwrap_or_else(|_| panic!("failed to read fixture: {path}"))
    }

    #[cfg(all(feature = "as4", feature = "testing"))]
    fn pki_fixture(name: &str) -> Vec<u8> {
        let path = format!("tests/fixtures/pki/{name}");
        std::fs::read(&path).unwrap_or_else(|_| panic!("failed to read pki fixture: {path}"))
    }

    #[cfg(all(feature = "as4", feature = "testing"))]
    fn cert_fingerprint_sha256_hex(cert_pem: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let cert = openssl::x509::X509::from_pem(cert_pem).expect("valid certificate PEM");
        let der = cert.to_der().expect("valid certificate DER");
        let digest = Sha256::digest(&der);
        let mut out = String::with_capacity(digest.len() * 2);
        for &byte in &digest {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    #[cfg(all(feature = "as4", feature = "testing"))]
    fn session_with_trust_anchor_and_fingerprint_pin(
        anchor_pem: &[u8],
    ) -> crate::core::SessionContext {
        let mut cert_handle = crate::core::CertHandle::new("as4-receipt-signing-anchor-with-pin");
        cert_handle.trust_anchor_pems =
            vec![String::from_utf8(anchor_pem.to_vec()).expect("trust-anchor PEM must be UTF-8")];
        cert_handle.ocsp_mode = OcspMode::Disabled;
        cert_handle.fingerprint_sha256 = cert_fingerprint_sha256_hex(anchor_pem);

        crate::core::SessionContext::new("as4-session-1", "partner-a", "strict")
            .expect("session")
            .with_cert_handle(cert_handle)
            .expect("session trust configuration with pin")
    }

    #[cfg(all(feature = "as4", feature = "testing"))]
    fn signed_receipt_fixture(ref_to_message_id: &str) -> Vec<u8> {
        const SIGNAL_WSU_ID: &str = "as4-receipt-signal";

        let unsigned = format!(
            r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
        xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
        xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
        xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <S12:Header>
        <eb:Messaging>
            <eb:SignalMessage wsu:Id="{signal_wsu_id}">
                <eb:MessageInfo>
                    <eb:RefToMessageId>{ref_to_message_id}</eb:RefToMessageId>
                </eb:MessageInfo>
                <eb:Receipt>
                    <eb:NonRepudiationInformation/>
                </eb:Receipt>
            </eb:SignalMessage>
        </eb:Messaging>
        <!-- signature-placeholder -->
    </S12:Header>
    <S12:Body/>
</S12:Envelope>"#,
            signal_wsu_id = SIGNAL_WSU_ID,
            ref_to_message_id = ref_to_message_id,
        );

        let signing_key_pem = pki_fixture("receipt_signing.key.pem");
        let signing_cert_pem = pki_fixture("receipt_signing.cert.pem");
        let reference_uri = format!("#{SIGNAL_WSU_ID}");
        let reference_uris = [reference_uri.as_str()];
        let signature_xml = crate::crypto::wssec::generate_xmlsig_signature(
            &unsigned,
            &reference_uris,
            &signing_key_pem,
            &signing_cert_pem,
            crate::crypto::wssec::WsSecOutboundKeyInfoProfile::X509DataAndRsaKeyValue,
        )
        .expect("valid receipt signature");

        unsigned
            .replace("<!-- signature-placeholder -->", &signature_xml)
            .into_bytes()
    }

    #[cfg(all(feature = "as4", feature = "testing"))]
    fn ensure_required_strict_properties_in_xml(xml: &str) -> String {
        let has_original_sender = xml.contains("name=\"originalSender\"");
        let has_final_recipient = xml.contains("name=\"finalRecipient\"");
        let has_tracking_identifier = xml.contains("name=\"trackingIdentifier\"");

        if has_original_sender && has_final_recipient && has_tracking_identifier {
            return xml.to_string();
        }

        let Some(user_message_close) = xml.find("</eb:UserMessage>") else {
            return xml.to_string();
        };

        let mut out = String::with_capacity(xml.len() + 256);
        out.push_str(&xml[..user_message_close]);
        out.push_str(
            "<eb:MessageProperties>\
                <eb:Property name=\"originalSender\">urn:test:sender</eb:Property>\
                <eb:Property name=\"finalRecipient\">urn:test:recipient</eb:Property>\
                <eb:Property name=\"trackingIdentifier\">urn:test:tracking</eb:Property>\
            </eb:MessageProperties>",
        );
        out.push_str(&xml[user_message_close..]);
        out
    }

    #[cfg(all(feature = "as4", feature = "testing"))]
    fn multipart_push_payload() -> Vec<u8> {
        let payload_cid = "push-flow-body@example.com";
        let mut soap =
            String::from_utf8(fixture("as4_push_user_message.golden")).expect("utf8 fixture");
        soap = ensure_required_strict_properties_in_xml(&soap);

        if !soap.contains("xmlns:xop=\"http://www.w3.org/2004/08/xop/include\"") {
            soap = soap.replacen(
                "<S12:Envelope ",
                "<S12:Envelope xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" ",
                1,
            );
        }
        if soap.contains("<S12:Body/>") {
            soap = soap.replacen(
                "<S12:Body/>",
                &format!("<S12:Body><xop:Include href=\"cid:{payload_cid}\"/></S12:Body>"),
                1,
            );
        }

        let mut out = Vec::new();
        out.extend_from_slice(format!("--{PUSH_FLOW_BOUNDARY}\r\n").as_bytes());
        out.extend_from_slice(
            b"Content-Type: application/xop+xml; charset=UTF-8; type=\"application/soap+xml\"\r\n",
        );
        out.extend_from_slice(b"Content-ID: <soap-root@example.com>\r\n\r\n");
        out.extend_from_slice(soap.as_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(format!("--{PUSH_FLOW_BOUNDARY}\r\n").as_bytes());
        out.extend_from_slice(
            format!(
                "Content-Type: application/octet-stream\r\nContent-ID: <{payload_cid}>\r\n\r\n"
            )
            .as_bytes(),
        );
        out.extend_from_slice(b"push-flow-detached-payload\r\n");
        out.extend_from_slice(format!("--{PUSH_FLOW_BOUNDARY}--\r\n").as_bytes());
        out
    }

    #[cfg(feature = "as4")]
    struct DurableTestAuditSink {
        inner: InMemoryAuditSink,
    }

    #[cfg(feature = "as4")]
    impl DurableTestAuditSink {
        fn new() -> Self {
            Self {
                inner: InMemoryAuditSink::new(),
            }
        }
    }

    #[cfg(feature = "as4")]
    impl DurableAuditSink for DurableTestAuditSink {
        fn durability(&self) -> AuditSinkDurability {
            AuditSinkDurability::Durable
        }

        fn has_replay_cursor_integrity_protection(&self) -> bool {
            self.inner.has_replay_cursor_integrity_protection()
        }

        fn store_event(&self, event: &AuditEvent) -> Result<()> {
            self.inner.store_event(event)
        }

        fn retrieve_events_from(
            &self,
            cursor: &ReplayCursor,
            limit: usize,
        ) -> Result<Vec<AuditEvent>> {
            self.inner.retrieve_events_from(cursor, limit)
        }

        fn current_cursor(&self) -> Result<ReplayCursor> {
            self.inner.current_cursor()
        }

        fn verify_replay_cursor_integrity(&self, cursor: &ReplayCursor) -> Result<()> {
            self.inner.verify_replay_cursor_integrity(cursor)
        }

        fn acknowledge_cursor(&self, cursor: &ReplayCursor) -> Result<()> {
            self.inner.acknowledge_cursor(cursor)
        }

        fn clear(&self) -> Result<()> {
            self.inner.clear()
        }
    }

    #[cfg(feature = "as4")]
    struct DurableClusterSafeDedup;

    #[cfg(feature = "as4")]
    impl DedupStorage for DurableClusterSafeDedup {
        fn is_durable(&self) -> bool {
            true
        }

        fn cluster_safe(&self) -> bool {
            true
        }

        fn first_seen<'a>(
            &'a self,
            _idempotency_key: &'a str,
        ) -> BoxFuture<'a, crate::core::Result<bool>> {
            Box::pin(async move { Ok(true) })
        }
    }

    #[cfg(feature = "as4")]
    struct DurableClusterSafeReconciliation;

    #[cfg(feature = "as4")]
    impl ReconciliationStorage for DurableClusterSafeReconciliation {
        fn is_durable(&self) -> bool {
            true
        }

        fn cluster_safe(&self) -> bool {
            true
        }

        fn enqueue<'a>(&'a self, _request: ReconciliationRequest) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async move { Ok(false) })
        }

        fn queued_requests(&self) -> BoxFuture<'_, Result<Vec<ReconciliationRequest>>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn resolve<'a>(&'a self, _idempotency_key: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async move { Ok(false) })
        }
    }

    #[cfg(feature = "as4")]
    fn strict_event_bus() -> crate::observability::EventBus {
        crate::presets::strict_production_event_bus(16, Arc::new(DurableTestAuditSink::new()))
            .expect("strict production event bus")
    }

    #[cfg(feature = "as4")]
    fn strict_runtime_token() -> crate::presets::StrictRuntimeBootstrapToken {
        struct StrictTestCoordination(&'static str);

        impl As4TopologyCoordination for StrictTestCoordination {
            fn cluster_safe(&self) -> bool {
                true
            }

            fn topology_component(&self) -> &'static str {
                self.0
            }
        }

        let pull_store = StrictTestCoordination("pull-store");
        let conversation_gate = StrictTestCoordination("conversation-order-gate");
        issue_strict_runtime_bootstrap_token_with_as4_topology(
            "transport_as4_ingress_helper",
            &strict_event_bus(),
            &DurableClusterSafeReconciliation,
            &DurableClusterSafeDedup,
            DeploymentTopology::Clustered,
            Some(&pull_store),
            Some(&conversation_gate),
        )
        .expect("strict runtime token")
    }

    #[cfg(feature = "as4")]
    fn strict_session() -> crate::core::SessionContext {
        crate::core::SessionContext::new("sess-as4-ingress", "partner-a", "strict")
            .expect("session")
    }

    #[cfg(all(feature = "as4", not(feature = "testing")))]
    #[test]
    fn as4_ingress_helper_without_token_fails_closed_for_strict_interop() {
        let req = as4_post(
            vec![("Content-Type", "application/soap+xml")],
            b"not-soap".to_vec(),
        );
        let ingress = as4_ingress_from_http(req).expect("as4 ingress");

        let err = ingress
            .receive_push_with_dedup_sync(As4IngressReceivePushSyncRequest {
                session: &strict_session(),
                event_bus: &crate::observability::EventBus::new(16).expect("bus"),
                policy: crate::as4::As4PushPolicy {
                    interop: InteropMode::Strict,
                    ..crate::as4::As4PushPolicy::default()
                },
                dedup_backend: &crate::reliability::InMemoryDedupBackend::default(),
                receipt_payload: None,
            })
            .expect_err("strict helper without token must fail closed");

        assert_eq!(err.code, ErrorCode::PolicyViolation);
        assert!(
            err.message
                .contains("strict-runtime bootstrap token binding")
        );
    }

    #[cfg(feature = "as4")]
    #[test]
    fn as4_ingress_helper_with_token_reaches_protocol_validation() {
        let req = as4_post(
            vec![("Content-Type", "application/soap+xml")],
            b"not-soap".to_vec(),
        );
        let ingress = as4_ingress_from_http(req).expect("as4 ingress");
        let token = strict_runtime_token();
        let strict_session = crate::presets::session_with_strict_runtime_bootstrap_token(
            "transport_as4_ingress_helper",
            &token,
            &strict_session(),
        )
        .expect("strict session");

        let err = ingress
            .receive_push_with_dedup_sync(As4IngressReceivePushSyncRequest {
                session: &strict_session,
                event_bus: &crate::observability::EventBus::new(16).expect("bus"),
                policy: crate::as4::As4PushPolicy {
                    interop: InteropMode::Strict,
                    ..crate::as4::As4PushPolicy::default()
                },
                dedup_backend: &crate::reliability::InMemoryDedupBackend::default(),
                receipt_payload: None,
            })
            .expect_err("invalid payload should fail after runtime token validation");

        assert_ne!(err.code, ErrorCode::PolicyViolation);
    }

    #[cfg(feature = "interop-relaxed")]
    #[cfg(all(feature = "as4", feature = "testing"))]
    #[test]
    fn as4_ingress_helper_processes_valid_push_payload() {
        let req = as4_post(
            vec![("Content-Type", &multipart_content_type())],
            multipart_push_payload(),
        );
        let ingress = as4_ingress_from_http(req).expect("as4 ingress");
        let bus = crate::observability::EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();

        let out = ingress
            .receive_push_with_dedup_sync(As4IngressReceivePushSyncRequest {
                session: &strict_session(),
                event_bus: &bus,
                policy: crate::as4::As4PushPolicyBuilder::new()
                    .interop(crate::core::InteropMode::Relaxed)
                    .allow_unsigned_push(true)
                    .fail_closed_audit_events(false)
                    .build()
                    .expect("policy"),
                dedup_backend: &crate::reliability::InMemoryDedupBackend::default(),
                receipt_payload: None,
            })
            .expect("valid multipart push payload must succeed")
            .unwrap_output();

        assert_eq!(out.user_message.message_id, "msg-push-1");
        assert_eq!(out.user_message.action, "SubmitOrder");
    }

    #[cfg(feature = "interop-relaxed")]
    #[cfg(all(feature = "as4", feature = "testing"))]
    #[test]
    fn as4_ingress_token_helper_processes_valid_push_and_signed_receipt() {
        let req = as4_post(
            vec![("Content-Type", &multipart_content_type())],
            multipart_push_payload(),
        );
        let ingress = as4_ingress_from_http(req).expect("as4 ingress");
        let signing_cert_pem = pki_fixture("receipt_signing.cert.pem");
        let token = strict_runtime_token();
        let strict_session = crate::presets::session_with_strict_runtime_bootstrap_token(
            "transport_as4_ingress_helper",
            &token,
            &session_with_trust_anchor_and_fingerprint_pin(&signing_cert_pem),
        )
        .expect("strict session");
        let bus = crate::observability::EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();

        let out = ingress
            .receive_push_with_dedup_sync(As4IngressReceivePushSyncRequest {
                session: &strict_session,
                event_bus: &bus,
                policy: crate::as4::As4PushPolicyBuilder::new()
                    .interop(crate::core::InteropMode::Relaxed)
                    .allow_unsigned_push(true)
                    .fail_closed_audit_events(false)
                    .build()
                    .expect("policy"),
                dedup_backend: &crate::reliability::InMemoryDedupBackend::default(),
                receipt_payload: Some(signed_receipt_fixture("msg-push-1")),
            })
            .expect("valid multipart push + signed receipt must succeed")
            .unwrap_output();

        let receipt = out.receipt.expect("receipt");
        assert!(receipt.is_signed);
        assert_eq!(receipt.ref_to_message_id, "msg-push-1");
    }
}
