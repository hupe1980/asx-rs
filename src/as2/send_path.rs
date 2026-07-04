use std::sync::Arc;

use super::{
    As2PreparedSendCredentials, As2SendCredentials, As2SendOutput, As2SendPolicy, AsxError,
    AsxEvent, ErrorCode, ErrorContext, EventBus, InteropMode, MimeEnvelope, Result, SessionContext,
    emit_protocol_event, extract_content_type_header, mic::compute_rfc4130_mic, pipeline,
};
use crate::http::HttpHeaders;
use crate::reliability::{RetryConfig, RetryScheduler};
use crate::transport::trace_context::generate_traceparent;

#[derive(Clone)]
pub struct As2SendRequest {
    pub message_id: String,
    pub payload: Vec<u8>,
    pub policy: As2SendPolicy,
    /// Per-request signing / encryption credentials.
    ///
    /// - `None` — use the signing cert, signing key, and recipient cert stored
    ///   in the session's `CertHandle` (set via
    ///   `SessionContextBuilder::with_signing_cert_pem` /
    ///   `with_signing_key_pem` / `with_recipient_cert_pem`).
    /// - `Some(creds)` — use `creds` exactly, ignoring session-level
    ///   credential material.  Use this for per-message overrides.
    pub credentials: Option<As2SendCredentials>,
}

#[derive(Clone)]
pub struct As2SendPreparedRequest {
    pub message_id: String,
    pub payload: Vec<u8>,
    pub policy: As2SendPolicy,
    pub prepared: As2PreparedSendCredentials,
}

/// Validate an AS2 identifier value against RFC 4130 §4 grammar.
///
/// RFC 4130 §4 defines `as2-id` as a printable-string or quoted-string of
/// 1..=128 US-ASCII printable characters:
///
/// - **printable-string**: visible US-ASCII only (0x21..=0x7E, no space).
/// - **quoted-string**: `"` + (0x20..=0x7E)* + `"` — space allowed inside
///   the quotes.
///
/// The function also rejects control characters and non-US-ASCII bytes so the
/// identifier is always safe to embed in HTTP headers.
fn validate_as2_from_identifier(
    stage: &'static str,
    session: &SessionContext,
    value: &str,
) -> Result<()> {
    // RFC 4130 §4: max length is 128 characters.
    const AS2_ID_MAX_LEN: usize = 128;

    // Determine whether this is a quoted-string and find the inner content
    // that must meet the printable-ASCII constraint.
    let (inner, allow_space) = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2
    {
        (&value[1..value.len() - 1], true)
    } else {
        (value, false)
    };

    if inner.is_empty() {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "AS2-From identifier must not be empty",
            ErrorContext::for_session(stage, session),
        ));
    }

    if inner.len() > AS2_ID_MAX_LEN {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            format!(
                "AS2-From identifier exceeds maximum length \
                 ({} bytes, limit is {AS2_ID_MAX_LEN})",
                inner.len()
            ),
            ErrorContext::for_session(stage, session),
        ));
    }

    let min_char: u8 = if allow_space { 0x20 } else { 0x21 };
    if let Some(bad) = inner.bytes().find(|&b| !(min_char..=0x7E).contains(&b)) {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            format!(
                "AS2-From identifier contains character 0x{bad:02X} \
                 not allowed by RFC 4130 §4 (US-ASCII printable only)"
            ),
            ErrorContext::for_session(stage, session),
        ));
    }

    Ok(())
}

fn validate_as2_send_runtime_inputs(
    session: &SessionContext,
    policy: &As2SendPolicy,
    prepared: &As2PreparedSendCredentials,
) -> Result<()> {
    let stage = "as2_send_validate";

    if !policy.as2_from_id.trim().is_empty() {
        validate_as2_from_identifier(stage, session, policy.as2_from_id.as_str())?;
    }

    if policy.sign {
        let signing_cert = prepared.signing_cert.as_ref().ok_or_else(|| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                "AS2 signing certificate is missing",
                ErrorContext::for_session(stage, session),
            )
        })?;
        let signing_key = prepared.signing_key.as_ref().ok_or_else(|| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                "AS2 signing key is missing",
                ErrorContext::for_session(stage, session),
            )
        })?;

        let _ = signing_cert;
        let _ = signing_key;
    }

    if policy.encrypt {
        let recipient_cert = prepared.recipient_cert.as_ref().ok_or_else(|| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                "AS2 recipient certificate is missing",
                ErrorContext::for_session(stage, session),
            )
        })?;

        let _ = recipient_cert;
    }

    Ok(())
}

#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %session.partner_id())))]
pub fn send_sync(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As2SendRequest,
) -> Result<As2SendOutput> {
    let As2SendRequest {
        message_id,
        payload,
        policy,
        credentials: credentials_opt,
    } = request;

    // Resolve effective credentials: per-request `Some(c)` wins; `None` falls
    // back to the signing material stored in the session's CertHandle.
    let session_creds;
    let credentials = match credentials_opt {
        Some(c) => c,
        None => {
            let ch = session.cert_handle();
            session_creds = As2SendCredentials {
                signing_cert_pem: ch
                    .signing_cert_pem
                    .as_ref()
                    .map(|s| Arc::from(s.as_bytes())),
                signing_key_pem: ch.signing_key_pem.as_ref().map(|s| s.as_bytes().to_vec()),
                recipient_cert_pem: ch
                    .recipient_cert_pem
                    .as_ref()
                    .map(|s| Arc::from(s.as_bytes())),
            };
            session_creds
        }
    };

    let prepared =
        credentials.prepare_for_policy(&policy, "as2_send_validate", ErrorCode::PolicyViolation)?;
    send_sync_prepared(
        session,
        event_bus,
        As2SendPreparedRequest {
            message_id,
            payload,
            policy,
            prepared,
        },
    )
}

#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %session.partner_id())))]
pub fn send_sync_prepared(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As2SendPreparedRequest,
) -> Result<As2SendOutput> {
    let As2SendPreparedRequest {
        message_id,
        payload,
        policy,
        prepared,
    } = request;
    send_sync_prepared_ref(session, event_bus, message_id, payload, policy, &prepared)
}

fn send_sync_prepared_ref(
    session: &SessionContext,
    event_bus: &EventBus,
    message_id: String,
    payload: Vec<u8>,
    policy: As2SendPolicy,
    prepared: &As2PreparedSendCredentials,
) -> Result<As2SendOutput> {
    #[cfg(feature = "interop-relaxed")]
    let mut message_id = message_id;
    #[cfg(not(feature = "interop-relaxed"))]
    let message_id = message_id;
    #[cfg(feature = "interop-relaxed")]
    let mut payload = payload;
    #[cfg(not(feature = "interop-relaxed"))]
    let payload = payload;
    pipeline::validate_message_id(&message_id, "as2_send_validate", session)?;
    crate::presets::enforce_strict_runtime_bootstrap_for_strict_interop(
        "as2_send_validate",
        session,
        policy.interop_mode,
    )?;
    tracing::debug!(
        session_id = %session.session_id(),
        partner_id = %session.partner_id(),
        message_id = %message_id,
        sign = policy.sign,
        encrypt = policy.encrypt,
        "AS2 send: building outbound message",
    );

    if policy.interop_mode == InteropMode::Strict && payload.is_empty() {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "strict interop mode rejects empty AS2 payload",
            ErrorContext::for_session("as2_send_strict_policy", session),
        ));
    }

    #[cfg(feature = "interop-relaxed")]
    if policy.interop_mode == InteropMode::Relaxed {
        message_id = message_id.trim().to_string();
        if payload.is_empty() {
            payload = b"\n".to_vec();
        }
    }

    validate_as2_send_runtime_inputs(session, &policy, prepared)?;
    pipeline::validate_signing_credentials(
        policy.sign,
        prepared.signing_key.is_some(),
        prepared.signing_cert.is_some(),
        "as2_send_validate",
        "AS2",
        session,
    )?;
    pipeline::validate_encryption_credentials(
        policy.encrypt,
        prepared.recipient_cert.is_some(),
        "as2_send_validate",
        "AS2",
        session,
    )?;
    pipeline::emit_outbound_prepared(
        event_bus,
        session,
        &message_id,
        super::AsxProtocol::As2,
        policy.fail_closed_audit_events,
    )?;

    let (mic_base64, digest_alg_str) = compute_mic(&payload, &policy);
    emit_protocol_event(
        event_bus,
        session,
        AsxEvent::MicComputed {
            message_id: message_id.clone().into(),
            digest_alg: digest_alg_str,
            mic_base64: mic_base64.clone(),
        },
        policy.fail_closed_audit_events,
        "as2_send_mic_computed",
    )?;

    let mut payload_to_send = payload;
    #[cfg(feature = "compression")]
    if policy.compress {
        payload_to_send = compress_payload(&payload_to_send)?;
    }

    if policy.sign {
        let key = prepared.signing_key.as_ref().ok_or_else(|| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                "AS2 signing key is missing",
                ErrorContext::for_session("as2_send_sign", session),
            )
        })?;
        let cert = prepared.signing_cert.as_ref().ok_or_else(|| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                "AS2 signing certificate is missing",
                ErrorContext::for_session("as2_send_sign", session),
            )
        })?;
        payload_to_send = sign_payload(&payload_to_send, key, cert)?;
        pipeline::emit_message_signed(
            event_bus,
            session,
            &message_id,
            policy.fail_closed_audit_events,
        )?;
    }

    if policy.encrypt {
        let recipient_cert = prepared.recipient_cert.as_ref().ok_or_else(|| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                "AS2 recipient certificate is missing",
                ErrorContext::for_session("as2_send_encrypt", session),
            )
        })?;
        payload_to_send = encrypt_payload(&payload_to_send, recipient_cert, &policy)?;
        pipeline::emit_message_encrypted(
            event_bus,
            session,
            &message_id,
            policy.fail_closed_audit_events,
        )?;
    }

    let mime = build_mime_envelope(&message_id, payload_to_send, &policy);
    let http_headers = build_as2_http_headers(session, &policy, &message_id, &mime);

    let traceparent = generate_traceparent(&session.correlation_scope().root_id, &message_id);

    Ok(As2SendOutput {
        message_id,
        mime,
        mic_base64,
        digest_alg: digest_alg_str,
        traceparent: Some(traceparent),
        http_headers,
    })
}

pub async fn send_async(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As2SendRequest,
) -> Result<As2SendOutput> {
    let scheduler = RetryScheduler::new(RetryConfig::default());
    let request = request;

    scheduler
        .retry_with_decider(
            || {
                let blocking_session = session.clone();
                let blocking_bus = event_bus.clone();
                let error_session = session.clone();
                let request = request.clone();
                async move {
                    let permit = crate::core::CryptoAdmissionControl::process_global()
                        .acquire("as2_send_async_admission", &blocking_session)
                        .await?;
                    tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        send_sync(&blocking_session, &blocking_bus, request)
                    })
                    .await
                    .map_err(|err| {
                        AsxError::new(
                            ErrorCode::TransportFailure,
                            format!("AS2 send blocking task failed: {err}"),
                            ErrorContext::for_session("as2_send_async_join", &error_session),
                        )
                    })?
                }
            },
            |err| pipeline::classify_send_retry(err).should_retry,
        )
        .await
}

pub async fn send_async_prepared(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As2SendPreparedRequest,
) -> Result<As2SendOutput> {
    let scheduler = RetryScheduler::new(RetryConfig::default());
    let request = Arc::new(request);

    scheduler
        .retry_with_decider(
            || {
                let blocking_session = session.clone();
                let blocking_bus = event_bus.clone();
                let error_session = session.clone();
                let request = Arc::clone(&request);
                async move {
                    let permit = crate::core::CryptoAdmissionControl::process_global()
                        .acquire("as2_send_async_admission", &blocking_session)
                        .await?;
                    tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        let request = request.as_ref();
                        send_sync_prepared_ref(
                            &blocking_session,
                            &blocking_bus,
                            request.message_id.clone(),
                            request.payload.clone(),
                            request.policy.clone(),
                            &request.prepared,
                        )
                    })
                    .await
                    .map_err(|err| {
                        AsxError::new(
                            ErrorCode::TransportFailure,
                            format!("AS2 send blocking task failed: {err}"),
                            ErrorContext::for_session("as2_send_async_join", &error_session),
                        )
                    })?
                }
            },
            |err| pipeline::classify_send_retry(err).should_retry,
        )
        .await
}

fn compute_mic(payload: &[u8], policy: &As2SendPolicy) -> (String, &'static str) {
    let mic_content_type = policy
        .payload_content_type
        .unwrap_or("application/octet-stream");

    compute_rfc4130_mic(payload, mic_content_type, policy.mic_algorithm)
}

fn build_mime_envelope(
    message_id: &str,
    payload_to_send: Vec<u8>,
    policy: &As2SendPolicy,
) -> MimeEnvelope {
    if policy.encrypt {
        return MimeEnvelope {
            content_type: "application/pkcs7-mime; smime-type=enveloped-data".to_string(),
            body: payload_to_send.into(),
        };
    }

    if policy.sign {
        let content_type = extract_content_type_header(&payload_to_send)
            .unwrap_or_else(|| "multipart/signed".to_string());
        return MimeEnvelope {
            content_type,
            body: payload_to_send.into(),
        };
    }

    let boundary = format!("asx-{message_id}");
    let mut mime_body = Vec::with_capacity(boundary.len() * 2 + payload_to_send.len() + 64);
    mime_body.extend_from_slice(
        format!("--{boundary}\r\nContent-Type: application/edi-x12\r\n\r\n").as_bytes(),
    );
    mime_body.extend_from_slice(&payload_to_send);
    mime_body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    MimeEnvelope {
        content_type: format!("multipart/mixed; boundary=\"{boundary}\""),
        body: Arc::from(mime_body),
    }
}

fn build_as2_http_headers(
    session: &SessionContext,
    policy: &As2SendPolicy,
    message_id: &str,
    mime: &MimeEnvelope,
) -> HttpHeaders {
    let as2_from = if policy.as2_from_id.trim().is_empty() {
        session.session_id().to_string()
    } else {
        policy.as2_from_id.clone()
    };

    HttpHeaders::from_vec(vec![
        ("AS2-Version".to_string(), "1.2".to_string()),
        ("AS2-From".to_string(), as2_from),
        ("AS2-To".to_string(), session.partner_id().to_string()),
        ("Message-ID".to_string(), format!("<{message_id}@asx>")),
        ("MIME-Version".to_string(), "1.0".to_string()),
        ("Content-Type".to_string(), mime.content_type.clone()),
    ])
}

fn sign_payload(
    payload: &[u8],
    signing_key: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
    signing_cert: &openssl::x509::X509Ref,
) -> Result<Vec<u8>> {
    crate::crypto::as2_smime::sign_smime_message_preparsed(payload, signing_key, signing_cert)
}

fn encrypt_payload(
    payload: &[u8],
    recipient_cert: &openssl::x509::X509Ref,
    policy: &As2SendPolicy,
) -> Result<Vec<u8>> {
    crate::crypto::as2_smime::encrypt_smime_message_preparsed(
        payload,
        recipient_cert,
        policy.encryption_cipher,
    )
}

#[cfg(feature = "compression")]
fn compress_payload(payload: &[u8]) -> Result<Vec<u8>> {
    crate::crypto::compression::compress_gzip(payload, 6)
}
