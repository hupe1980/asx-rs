use std::sync::Arc;

use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};

use super::{
    As2GeneratedMdn, As2InboundResult, As2MdnSigningCredentials, As2MicAlgorithm, As2TrustVerifier,
    extract_content_type_header, generate_mdn, generate_signed_mdn, mic::compute_rfc4130_mic,
    receive_payload,
};

/// Receive an inbound AS2 message and automatically generate a synchronous MDN
/// when the sender requests one via the `Disposition-Notification-To` header
/// (RFC 4130 section 7.4).
///
/// This is the preferred entry point for AS2 server implementations:
///
/// - **Validates the `AS2-From` header** against the session partner identity
///   (RFC 4130 §6.2) — supply the raw `AS2-From` header value in
///   [`as2_from_header`](Self::as2_from_header).
/// - Verifies/decrypts the payload via `verifier`.
/// - Computes the RFC 4130 section 7.3.1 MIC over the received MIME body.
/// - Generates a synchronous MDN and returns it in `As2InboundResult::sync_mdn`
///   when `disposition_notification_to` contains an HTTP/HTTPS URL.
/// - Skips MDN generation when `disposition_notification_to` is absent or is a
///   `mailto:` address (see below).
///
/// The MIC algorithm is negotiated from the `Disposition-Notification-Options`
/// header (`signed-receipt-micalg=required,sha-256` etc.). SHA-256 is used when
/// the header is absent or unrecognized.
///
/// # ⚠ Asynchronous MDN via `mailto:` is not dispatched automatically
///
/// RFC 4130 §7.3 defines asynchronous MDN delivery over both HTTP and SMTP.
/// When `disposition_notification_to` contains a `mailto:` address, the
/// library **extracts the address** (it is accessible in
/// [`As2InboundResult`]) but does **not** send an email.  SMTP dispatch is
/// outside the scope of an HTTP transport library.
///
/// **Embedder responsibility**: inspect `disposition_notification_to` after
/// `receive_from_ingress` returns.  If it contains a `mailto:` URI, construct
/// the MDN body using [`crate::as2::generate_mdn`] (or the signed variant) and
/// dispatch it via an SMTP client of your choice.
///
/// Silently ignoring async MDN requests violates RFC 4130 §7.3 and will cause
/// partners that require async MDN confirmation to mark messages as
/// unacknowledged.  Consider logging a warning when `mailto:` is detected.
#[derive(Clone, Copy)]
pub struct As2IngressReceiveRequest<'a> {
    pub session: &'a SessionContext,
    pub payload: &'a [u8],
    pub content_type: &'a str,
    pub original_message_id: Option<&'a str>,
    /// Raw value of the inbound `AS2-From` MIME header.
    ///
    /// RFC 4130 §6.2 requires that this value is validated against the sender
    /// identity configured in the session.  Provide the exact header value as
    /// received; the library normalises whitespace and angle-bracket quoting
    /// before comparison.
    ///
    /// ASX now enforces this as mandatory input; callers must pass the
    /// received header value and cannot skip identity validation.
    pub as2_from_header: &'a str,
    pub disposition_notification_to: Option<&'a str>,
    pub disposition_notification_options: Option<&'a str>,
    pub mdn_signing_credentials: Option<&'a As2MdnSigningCredentials>,
    pub verifier: &'a dyn As2TrustVerifier,
}

#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %request.session.partner_id(), message_id = ?request.original_message_id)))]
pub fn receive_from_ingress(request: As2IngressReceiveRequest<'_>) -> Result<As2InboundResult> {
    let As2IngressReceiveRequest {
        session,
        payload,
        content_type,
        original_message_id,
        as2_from_header,
        disposition_notification_to,
        disposition_notification_options,
        mdn_signing_credentials,
        verifier,
    } = request;

    crate::presets::enforce_strict_runtime_bootstrap_for_strict_interop(
        "as2_receive_from_ingress",
        session,
        crate::core::InteropMode::Strict,
    )?;

    // RFC 4130 §6.2: validate AS2-From against the configured partner identity.
    // Strip angle brackets and whitespace before comparison (e.g. <partner-id>).
    let claimed = as2_from_header
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim();
    let expected = session.partner_id();
    if claimed.is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "AS2-From header must not be empty",
            ErrorContext::for_session("as2_receive_from_ingress", session),
        ));
    }
    // RFC 4130 §4: AS2 identifiers must be 1..=128 US-ASCII printable chars.
    if claimed.len() > 128 {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!(
                "AS2-From identifier exceeds RFC 4130 maximum length \
                 ({} bytes, limit is 128)",
                claimed.len()
            ),
            ErrorContext::for_session("as2_receive_from_ingress", session),
        ));
    }
    if let Some(bad) = claimed.bytes().find(|&b| !(0x20u8..=0x7E).contains(&b)) {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!(
                "AS2-From identifier contains character 0x{bad:02X} \
                 not allowed by RFC 4130 §4 (US-ASCII printable only)"
            ),
            ErrorContext::for_session("as2_receive_from_ingress", session),
        ));
    }
    if !claimed.eq_ignore_ascii_case(expected) {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!(
                "AS2-From identity mismatch: header claims '{claimed}' \
                 but session partner_id is '{expected}' (RFC 4130 §6.2)"
            ),
            ErrorContext::for_session("as2_receive_from_ingress", session),
        ));
    }

    let content = receive_payload(
        session,
        crate::core::PayloadInput::Borrowed(payload),
        verifier,
    )?;

    let Some(notify_to) = disposition_notification_to.filter(|s| !s.trim().is_empty()) else {
        return Ok(As2InboundResult {
            content,
            sync_mdn: None,
            received_content_mic: None,
            mic_algorithm: As2MicAlgorithm::Sha256,
            async_mdn_address: None,
        });
    };

    let mic_algorithm = disposition_notification_options
        .and_then(parse_signed_receipt_micalg)
        .unwrap_or(As2MicAlgorithm::Sha256);

    let (mic_base64, mic_alg_str) = compute_rfc4130_mic(payload, content_type, mic_algorithm);
    let mic_header_value = format!("{}, {mic_alg_str}", mic_base64);

    // Detect mailto: async MDN request — extract the address for the embedder to dispatch.
    let is_mailto = notify_to.split_ascii_whitespace().any(|tok| {
        let inner = tok.trim_start_matches('<').trim_end_matches('>');
        inner.starts_with("mailto:")
    }) || notify_to.starts_with("mailto:");
    let async_mdn_address = if is_mailto {
        let raw_addr = notify_to
            .trim()
            .trim_start_matches('<')
            .trim_end_matches('>')
            .trim_start_matches("mailto:")
            .to_string();
        // RFC 4130 §7.3: async MDN must be dispatched by the embedder via
        // SMTP — this library does not send email. Warn so that observability
        // subscribers can detect this condition even if the embedder forgets to
        // check `async_mdn_address` in the returned `As2InboundResult`.
        tracing::warn!(
            session_id = %session.session_id(),
            partner_id = %session.partner_id(),
            mailto_address = %raw_addr,
            "AS2 sender requested async MDN delivery to a mailto: address (RFC 4130 §7.3); \
             the embedder must dispatch this MDN via SMTP — check \
             `As2InboundResult::async_mdn_address` and emit \
             `AsxEvent::As2AsyncMdnRequested` on your EventBus",
        );
        Some(raw_addr)
    } else {
        None
    };

    let is_sync = notify_to.split_ascii_whitespace().any(|tok| {
        tok.starts_with('<') && {
            let inner = tok.trim_start_matches('<').trim_end_matches('>');
            inner.starts_with("http://") || inner.starts_with("https://")
        }
    }) || notify_to.starts_with("http://")
        || notify_to.starts_with("https://");

    let signed_receipt_requested =
        disposition_notification_options.is_some_and(parse_signed_receipt_protocol_pkcs7);

    let sync_mdn = if is_sync {
        let msg_id = original_message_id.unwrap_or_default();
        if msg_id.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "original_message_id is required when generating a synchronous MDN",
                ErrorContext::for_session("as2_receive_from_ingress", session),
            ));
        }

        let mdn_bytes = if signed_receipt_requested {
            let creds = mdn_signing_credentials.ok_or_else(|| {
                AsxError::new(
                    ErrorCode::PolicyViolation,
                    "signed AS2 receipt was requested but mdn_signing_credentials are not configured",
                    ErrorContext::for_session("as2_receive_from_ingress", session),
                )
            })?;
            generate_signed_mdn(
                session,
                msg_id,
                "automatic-action/MDN-sent-automatically; processed",
                Some(&mic_header_value),
                creds,
            )?
        } else {
            generate_mdn(
                session,
                msg_id,
                "automatic-action/MDN-sent-automatically; processed",
                Some(&mic_header_value),
            )?
        };

        let fallback_ct = if signed_receipt_requested {
            "multipart/signed"
        } else {
            "multipart/report; report-type=disposition-notification"
        };
        let content_type =
            extract_content_type_header(&mdn_bytes).unwrap_or_else(|| fallback_ct.to_string());

        Some(As2GeneratedMdn {
            bytes: Arc::from(mdn_bytes),
            content_type,
            is_signed: signed_receipt_requested,
        })
    } else {
        None
    };

    Ok(As2InboundResult {
        content,
        sync_mdn,
        received_content_mic: Some(mic_base64),
        mic_algorithm,
        async_mdn_address,
    })
}

/// Parse the `signed-receipt-micalg` value from a Disposition-Notification-Options header.
pub(crate) fn parse_signed_receipt_micalg(options: &str) -> Option<As2MicAlgorithm> {
    for param in options.split(';') {
        let mut parts = param.splitn(2, '=');
        let key = parts.next().map(str::trim).unwrap_or_default();
        if !key.eq_ignore_ascii_case("signed-receipt-micalg") {
            continue;
        }

        let value = parts
            .next()
            .map(str::trim)
            .unwrap_or_default()
            .trim_matches('"');

        for token in value.split(',') {
            let token = token.trim();
            if token.eq_ignore_ascii_case("sha-256") || token.eq_ignore_ascii_case("sha256") {
                return Some(As2MicAlgorithm::Sha256);
            }
            if token.eq_ignore_ascii_case("sha-384") || token.eq_ignore_ascii_case("sha384") {
                return Some(As2MicAlgorithm::Sha384);
            }
            if token.eq_ignore_ascii_case("sha-512") || token.eq_ignore_ascii_case("sha512") {
                return Some(As2MicAlgorithm::Sha512);
            }
        }
    }
    None
}

pub(crate) fn parse_signed_receipt_protocol_pkcs7(options: &str) -> bool {
    options.split(';').any(|param| {
        let mut parts = param.splitn(2, '=');
        let key = parts.next().map(str::trim).unwrap_or_default();
        if !key.eq_ignore_ascii_case("signed-receipt-protocol") {
            return false;
        }

        let value = parts
            .next()
            .map(str::trim)
            .unwrap_or_default()
            .trim_matches('"')
            .to_ascii_lowercase();

        value.contains("pkcs7-signature") || value.contains("application/pkcs7-signature")
    })
}
