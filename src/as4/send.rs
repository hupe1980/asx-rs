//! AS4 outbound send pipeline.

use std::sync::Arc;

use super::send_mime::{inject_xop_include, package_as_mime};
use super::services::enforce_strict_as4_send_runtime_policy_consistency;
use super::types::{
    As4PreparedSendCredentials, As4SendCredentials, As4SendOutput, As4SendPolicy, SoapEnvelope,
    validate_as4_send_policy_and_credentials_consistency,
};
use crate::as4::mime_packaging::MimeAttachment;
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
#[cfg(feature = "as4")]
use crate::crypto::soap_builder::{SoapEnvelopeBuilder, WsSecurityHeaderBuilder};
use crate::crypto::wssec::{
    encrypt_payload_xmlenc_preparsed, generate_xmlsig_signature_with_external_references_preparsed,
};
use crate::observability::{AsxProtocol, EventBus};
use crate::reliability::{RetryConfig, RetryScheduler};
use crate::sbdh::StandardBusinessDocument;
use crate::send_pipeline as pipeline;
use crate::transport::trace_context::generate_traceparent;

const SOAP12_NAMESPACE: &str = "http://www.w3.org/2003/05/soap-envelope";
const SOAP12_HTTP_CONTENT_TYPE: &str = "application/soap+xml";
const SOAP12_MUST_UNDERSTAND_TOKEN: &str = "true";

#[derive(Clone)]
pub struct As4SendRequest {
    pub message_id: String,
    pub payload: Vec<u8>,
    pub policy: As4SendPolicy,
    /// Per-request signing / encryption credentials.
    ///
    /// - `None` — use the signing cert, signing key, and recipient cert stored
    ///   in the session's `CertHandle` (set via
    ///   `SessionContextBuilder::with_signing_cert_pem` /
    ///   `with_signing_key_pem` / `with_recipient_cert_pem`).
    /// - `Some(creds)` — use `creds` exactly, ignoring any session-level
    ///   credential material.  Use this for per-message credential overrides
    ///   (e.g. partner-specific encryption certs in a hub/spoke topology).
    pub credentials: Option<As4SendCredentials>,
}

#[derive(Clone)]
pub struct As4SendPreparedRequest {
    pub message_id: String,
    pub payload: Vec<u8>,
    pub policy: As4SendPolicy,
    pub prepared: As4PreparedSendCredentials,
}

#[inline]
fn generated_xml_bytes_to_string(bytes: Vec<u8>) -> String {
    debug_assert!(
        std::str::from_utf8(&bytes).is_ok(),
        "generated XML must be UTF-8"
    );
    // Generated XML must be valid UTF-8; in release builds we still fail fast
    // with a clear panic message if this invariant is violated.
    String::from_utf8(bytes).expect("generated XML must be UTF-8")
}

fn encrypt_soap_header_block(
    soap_xml: &str,
    recipient_cert: &openssl::x509::X509Ref,
    payload_algorithm: crate::crypto::wssec::XmlEncPayloadAlgorithm,
    soap_namespace: &'static str,
    must_understand_token: &'static str,
) -> Result<String> {
    let start = soap_xml.find("<ebms:Messaging").ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 SOAP envelope is missing eb:Messaging header block",
            ErrorContext::new("as4_send_encrypt_soap_header"),
        )
    })?;
    let end_rel = soap_xml[start..].find("</ebms:Messaging>").ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 SOAP envelope is missing closing eb:Messaging header block",
            ErrorContext::new("as4_send_encrypt_soap_header"),
        )
    })?;
    let end = start + end_rel + "</ebms:Messaging>".len();

    let encrypted_header = crate::crypto::wssec::encrypt_soap_header_xmlenc_preparsed(
        &soap_xml.as_bytes()[start..end],
        recipient_cert,
        payload_algorithm,
        soap_namespace,
        must_understand_token,
    )?;
    let encrypted_header = String::from_utf8(encrypted_header).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("generated XML Encryption header is not valid UTF-8: {err}"),
            ErrorContext::new("as4_send_encrypt_soap_header"),
        )
    })?;

    let mut rewritten = String::with_capacity(soap_xml.len() + encrypted_header.len());
    rewritten.push_str(&soap_xml[..start]);
    rewritten.push_str(&encrypted_header);
    rewritten.push_str(&soap_xml[end..]);
    Ok(rewritten)
}

/// Send an AS4 message with explicit credentials for signing/encryption.
#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %session.partner_id())))]
pub fn send_sync(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4SendRequest,
) -> Result<As4SendOutput> {
    let As4SendRequest {
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
            session_creds = As4SendCredentials {
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

    pipeline::validate_message_id(&message_id, "as4_send_validate", session)?;

    enforce_strict_as4_send_runtime_policy_consistency(session, "as4_send_validate", &policy)?;

    validate_as4_send_policy_and_credentials_consistency(
        "as4_send_validate",
        &policy,
        &credentials,
        ErrorCode::PolicyViolation,
    )
    .map_err(|err| {
        AsxError::new(
            err.code,
            err.message,
            ErrorContext::for_session("as4_send_validate", session),
        )
    })?;

    if payload.is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "AS4 payload must not be empty",
            ErrorContext::for_session("as4_send_validate", session),
        ));
    }

    let prepared = credentials
        .prepare_for_policy(&policy, "as4_send_validate", ErrorCode::PolicyViolation)
        .map_err(|err| {
            AsxError::new(
                err.code,
                err.message,
                ErrorContext::for_session("as4_send_validate", session),
            )
        })?;

    send_sync_prepared(
        session,
        event_bus,
        As4SendPreparedRequest {
            message_id,
            payload,
            policy,
            prepared,
        },
    )
}

/// Send an AS4 message with pre-parsed credentials.
#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %session.partner_id())))]
pub fn send_sync_prepared(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4SendPreparedRequest,
) -> Result<As4SendOutput> {
    let As4SendPreparedRequest {
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
    policy: As4SendPolicy,
    prepared: &As4PreparedSendCredentials,
) -> Result<As4SendOutput> {
    pipeline::validate_message_id(&message_id, "as4_send_validate", session)?;

    crate::presets::enforce_strict_runtime_bootstrap_for_strict_interop(
        "as4_send_validate",
        session,
        policy.interop,
    )?;

    enforce_strict_as4_send_runtime_policy_consistency(session, "as4_send_validate", &policy)?;

    if payload.is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "AS4 payload must not be empty",
            ErrorContext::for_session("as4_send_validate", session),
        ));
    }

    let signing_cert = prepared.signing_cert.as_ref().map(|cert| cert.as_ref());
    let signing_key = prepared.signing_key.as_ref().map(|key| key.as_ref());
    let recipient_cert = prepared.recipient_cert.as_ref().map(|cert| cert.as_ref());
    pipeline::validate_signing_credentials(
        policy.sign,
        signing_key.is_some(),
        signing_cert.is_some(),
        "as4_send_validate",
        "AS4",
        session,
    )?;
    pipeline::validate_encryption_credentials(
        policy.encrypt,
        recipient_cert.is_some(),
        "as4_send_validate",
        "AS4",
        session,
    )?;
    pipeline::emit_outbound_prepared(
        event_bus,
        session,
        &message_id,
        AsxProtocol::As4,
        policy.fail_closed_audit_events,
    )?;

    let payload = if let Some(header) = policy.sbdh_header.as_ref() {
        StandardBusinessDocument {
            header: header.clone(),
            payload,
        }
        .wrap()
        .map_err(|err| {
            AsxError::new(
                err.code,
                format!("failed to wrap AS4 payload with SBDH: {}", err.message),
                ErrorContext::for_session("as4_send_sbdh_wrap", session),
            )
        })?
    } else {
        payload
    };

    let mut payload_to_send = if policy.compress {
        #[cfg(feature = "compression")]
        {
            crate::crypto::compression::compress_gzip(&payload, 6)?
        }
        #[cfg(not(feature = "compression"))]
        {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                "AS4 compression requested but 'compression' feature is disabled",
                ErrorContext::for_session("as4_send_compress", session),
            ));
        }
    } else {
        payload
    };

    if policy.encrypt {
        let recipient_cert = recipient_cert.ok_or_else(|| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                "AS4 recipient certificate is missing",
                ErrorContext::for_session("as4_send_encrypt", session),
            )
        })?;
        payload_to_send = encrypt_payload_xmlenc_preparsed(
            &payload_to_send,
            recipient_cert,
            policy.outbound_xmlenc_payload_algorithm,
        )?;
    }

    let payload_mime_type = if policy.encrypt {
        "application/xml"
    } else if policy.compress {
        "application/gzip"
    } else {
        "application/octet-stream"
    };

    let payload_content_id = MimeAttachment::content_id_from_digest(&payload_to_send);
    let original_sender = policy
        .original_sender
        .clone()
        .unwrap_or_else(|| session.session_id().to_string());
    let final_recipient = policy
        .final_recipient
        .clone()
        .unwrap_or_else(|| session.partner_id().to_string());
    let tracking_identifier = policy
        .tracking_identifier
        .clone()
        .unwrap_or_else(|| message_id.clone());
    let conversation_id = policy.conversation_id.clone();

    let build_soap_xml = |payload: Vec<u8>, ws_header: Option<String>| -> Result<String> {
        let mut builder =
            SoapEnvelopeBuilder::new(&message_id, session.session_id(), session.partner_id())
                .with_action(&policy.action)
                .with_service(&policy.service, &policy.service_type)
                .with_four_corner_properties(
                    &original_sender,
                    &final_recipient,
                    &tracking_identifier,
                )
                .with_payload_content_id(&payload_content_id)
                .with_payload_mime_type(payload_mime_type)
                .with_payload(payload);
        if let Some(ref_id) = &policy.ref_to_message_id {
            builder = builder.with_ref_to_message_id(ref_id);
        }
        if let Some(conv_id) = &conversation_id {
            builder = builder.with_conversation_id(conv_id);
        }
        if let Some(wsa) = &policy.ws_addressing {
            builder = builder.with_ws_addressing(wsa.clone());
        }
        if let Some(header) = ws_header {
            builder = builder.with_ws_security_header(header);
        }
        let built = builder.build().map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("failed to build SOAP envelope: {err:?}"),
                ErrorContext::for_session("as4_soap_builder", session),
            )
        })?;
        Ok(generated_xml_bytes_to_string(built))
    };

    let adapt_soap_for_mime = |soap_xml: &str, payload_content_id: &str| -> Result<String> {
        inject_xop_include(soap_xml, payload_content_id)
    };

    // MIME mode rewrites `<asx:Base64>` to `<xop:Include>` and carries
    // bytes in the MIME attachment. Use a tiny placeholder payload to
    // avoid cloning and base64-encoding the full payload into SOAP first.
    let payload_for_soap = vec![0u8];
    let unsigned_xml = build_soap_xml(payload_for_soap.clone(), None)?;
    let unsigned_xml = adapt_soap_for_mime(&unsigned_xml, &payload_content_id)?;

    let mut soap_xml = if policy.sign {
        let signing_key = signing_key.ok_or_else(|| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                "AS4 signing key is missing",
                ErrorContext::for_session("as4_send_sign", session),
            )
        })?;
        let signing_cert_ref = signing_cert.ok_or_else(|| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                "AS4 signing certificate is missing",
                ErrorContext::for_session("as4_send_sign", session),
            )
        })?;
        let signing_cert_pem_bytes = signing_cert_ref.to_pem().map_err(|_err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "failed to serialize AS4 signing certificate to PEM",
                ErrorContext::for_session("as4_send_sign", session),
            )
        })?;

        let message_id_reference = format!("#{}", crate::crypto::soap_builder::MESSAGE_ID_WSU_ID);
        let body_reference = format!("#{}", crate::crypto::soap_builder::SOAP_BODY_WSU_ID);
        let payload_reference = format!("cid:{payload_content_id}");
        let reference_uris = [
            message_id_reference.as_str(),
            body_reference.as_str(),
            payload_reference.as_str(),
        ];
        let external_refs = [(payload_reference.as_str(), payload_to_send.as_slice())];
        let signature_xml = generate_xmlsig_signature_with_external_references_preparsed(
            &unsigned_xml,
            &reference_uris,
            &external_refs,
            signing_key,
            signing_cert_ref,
            policy.outbound_key_info_profile,
        )?;

        let wsse_header = WsSecurityHeaderBuilder::new()
            .with_signing_cert(signing_cert_pem_bytes)
            .with_signature_xml(signature_xml)
            .build()
            .map_err(|err| {
                AsxError::new(
                    ErrorCode::ParseFailed,
                    format!("failed to build WS-Security header: {err:?}"),
                    ErrorContext::for_session("as4_send_sign", session),
                )
            })?;
        let wsse_header = generated_xml_bytes_to_string(wsse_header);

        // Rebuild the SOAP envelope with the structured WS-Security header,
        // then apply MIME adaptation. This avoids brittle string-marker
        // insertion into generated XML.
        let signed_xml = build_soap_xml(payload_for_soap, Some(wsse_header))?;
        adapt_soap_for_mime(&signed_xml, &payload_content_id)?
    } else {
        unsigned_xml
    };

    if policy.encrypt_soap_headers {
        let recipient_cert = recipient_cert.ok_or_else(|| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                "AS4 recipient certificate is missing for SOAP header encryption",
                ErrorContext::for_session("as4_send_encrypt_soap_header", session),
            )
        })?;
        soap_xml = encrypt_soap_header_block(
            &soap_xml,
            recipient_cert,
            policy.outbound_xmlenc_payload_algorithm,
            SOAP12_NAMESPACE,
            SOAP12_MUST_UNDERSTAND_TOKEN,
        )?;
    }

    let soap_body = soap_xml.into_bytes();

    let (outbound_body, http_content_type) = package_as_mime(
        soap_body,
        payload_to_send,
        &payload_content_id,
        payload_mime_type,
        SOAP12_HTTP_CONTENT_TYPE,
    )?;

    if policy.sign {
        pipeline::emit_message_signed(
            event_bus,
            session,
            &message_id,
            policy.fail_closed_audit_events,
        )?;
    }
    if policy.encrypt {
        pipeline::emit_message_encrypted(
            event_bus,
            session,
            &message_id,
            policy.fail_closed_audit_events,
        )?;
    }

    let traceparent = generate_traceparent(&session.correlation_scope().root_id, &message_id);

    Ok(As4SendOutput {
        message_id,
        action: policy.action,
        traceparent: Some(traceparent),
        http_content_type,
        soap_envelope: SoapEnvelope {
            action: "ebms:user-message".into(),
            body: outbound_body.into(),
        },
        ref_to_message_id: policy.ref_to_message_id,
    })
}

/// Async-safe wrapper around [`send_sync`] that isolates synchronous SOAP/XMLDSig
/// and MIME assembly work onto Tokio's blocking thread pool.
pub async fn send_async(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4SendRequest,
) -> Result<As4SendOutput> {
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
                        .acquire("as4_send_async_admission", &blocking_session)
                        .await?;
                    tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        send_sync(&blocking_session, &blocking_bus, request)
                    })
                    .await
                    .map_err(|err| {
                        AsxError::new(
                            ErrorCode::TransportFailure,
                            format!("AS4 send blocking task failed: {err}"),
                            ErrorContext::for_session("as4_send_async_join", &error_session),
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
    request: As4SendPreparedRequest,
) -> Result<As4SendOutput> {
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
                        .acquire("as4_send_async_admission", &blocking_session)
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
                            format!("AS4 send blocking task failed: {err}"),
                            ErrorContext::for_session("as4_send_async_join", &error_session),
                        )
                    })?
                }
            },
            |err| pipeline::classify_send_retry(err).should_retry,
        )
        .await
}
