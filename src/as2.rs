use crate::core::{
    AsxError, ErrorCode, ErrorContext, InteropMode, ReceivedBodyHandle, Result, SessionContext,
    SpoolEncryption, SpoolLifecyclePolicy,
};
#[cfg(feature = "as2")]
pub use crate::crypto::as2_smime::SmimeCipher;
#[cfg(feature = "as2")]
use crate::crypto::as2_smime::sign_smime_message;
#[cfg(test)]
use crate::interop::InteropExceptionPolicy;
use crate::interop::{
    InteropDecision, InteropExceptionCode, enforce_exception, evaluate_exception_guardrail,
};
#[cfg(test)]
use crate::lifecycle::TrustEvidence;
use crate::lifecycle::{DomainReady, UntrustedBytes};
use crate::observability::{
    AsxEvent, AsxIngressStage, AsxProtocol, EventBus, emit_audit_event, emit_protocol_event,
};
use crate::reliability::{
    DeliveryOutcome, ReconciliationReason, ReconciliationRequest, RetryDecision,
    derive_ingress_idempotency_key, derive_reconciliation_idempotency_key,
};
use crate::send_pipeline as pipeline;
use crate::storage::{
    DedupStorage, ReconciliationStorage, drive_dedup_future, drive_reconciliation_future,
};
use crate::wire::{
    DEFAULT_MAX_BODY_BYTES, StreamBodyPolicy, StreamLimits, StreamReadMetrics,
    enforce_payload_limit,
};
use std::sync::Arc;

mod auth_telemetry;
mod ingress;
mod mdn;
mod mic;
mod send_path;
mod spool_http_helpers;
mod spool_key_provider;
mod spool_policy;
mod spool_provider_backends;
mod spool_runtime_utils;
mod stream_receive;
mod trust;
mod types;
#[cfg(feature = "client")]
pub use auth_telemetry::compute_http_spool_key_auth_telemetry_labels;
pub use ingress::{As2IngressReceiveRequest, receive_from_ingress};
pub use send_path::{
    As2SendPreparedRequest, As2SendRequest, send_async, send_async_prepared, send_sync,
    send_sync_prepared,
};
pub use spool_key_provider::As2RegulatedSpoolKeyProvider;
pub use stream_receive::{
    receive_stream, receive_stream_with_metrics, receive_stream_with_metrics_and_audit,
};

// Types extracted into sub-modules.
#[cfg(test)]
use spool_policy::regulated_stream_body_policy_build_with_provider;
pub(crate) use spool_policy::{StreamBodyPolicyBuildOutcome, as2_stream_body_policy_build};
#[cfg(test)]
pub use trust::InsecureBypassTrustVerifier;
#[cfg(feature = "testing")]
pub use trust::TrustVerifierSeal;
#[cfg(feature = "testing")]
pub(crate) use trust::private;
pub use trust::{
    As2TrustVerifier, AsyncAs2TrustVerifier, CmsSmimeTrustVerifier, SyncToAsyncTrustVerifier,
    TrustResult,
};
#[cfg(feature = "as2")]
pub use types::validate_as2_version_header;
pub use types::{
    As2GeneratedMdn, As2InboundResult, As2MdnMode, As2MdnSigningCredentials, As2MicAlgorithm,
    As2PreparedSendCredentials, As2ReceiveMdnOutput, As2ReceiveMdnRequest, As2ReceivePolicy,
    As2ReceivePolicyBuilder, As2SendCredentials, As2SendOutput, As2SendPolicy, MimeEnvelope,
    ParsedMdn, payload_content_type,
};

use mdn::{classify_mdn_outcome, extract_content_type_header, parse_mdn};
use spool_http_helpers::fetch_spool_key_hex_over_http;
#[cfg(all(feature = "client", test))]
use spool_http_helpers::{
    ensure_http_key_provider_circuit_allows_request, http_key_provider_backoff_for_attempt,
    key_response_signing_input, note_http_key_provider_circuit_failure,
    note_http_key_provider_circuit_success, resolve_http_key_provider_client_identity_pem,
    validate_http_key_provider_mtls_policy,
};
#[cfg(test)]
use spool_provider_backends::HttpJsonSpoolEncryptionKeyProvider;
#[cfg(all(feature = "client", test))]
use spool_provider_backends::HttpKeyProviderResilienceConfig;
#[cfg(all(feature = "client", test))]
use spool_provider_backends::HttpKeyProviderTlsConfig;
use spool_provider_backends::{SpoolEncryptionKeyProvider, regulated_spool_key_provider};
use spool_runtime_utils::{
    as2_spool_threshold_for_profile, parse_spool_encryption_key_hex,
    profile_requires_encrypted_spool, validate_spool_encryption_key_startup_self_test,
};
#[cfg(test)]
use stream_receive::{
    emit_stream_ingest_observations, maybe_emit_provider_health_state_transition,
};

const MAX_AS2_PAYLOAD_BYTES: usize = DEFAULT_MAX_BODY_BYTES;
const MAX_AS2_MDN_BYTES: usize = 256 * 1024;

#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %session.partner_id())))]
pub fn receive_sync(
    session: &SessionContext,
    payload: Vec<u8>,
    verifier: &dyn As2TrustVerifier,
) -> Result<DomainReady<Arc<[u8]>>> {
    crate::presets::enforce_strict_runtime_bootstrap_for_strict_interop(
        "as2_receive_sync",
        session,
        InteropMode::Strict,
    )?;
    receive_payload(session, crate::core::PayloadInput::Owned(payload), verifier)
}

/// Async-safe wrapper around [`receive_sync`] that isolates synchronous verification
/// and parse work onto Tokio's blocking thread pool.
pub async fn receive_async(
    session: &SessionContext,
    payload: Vec<u8>,
    verifier: Arc<dyn As2TrustVerifier + Send + Sync>,
) -> Result<DomainReady<Arc<[u8]>>> {
    let permit = crate::core::CryptoAdmissionControl::process_global()
        .acquire("as2_receive_async_admission", session)
        .await?;
    let blocking_session = session.clone();
    let error_session = session.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        receive_sync(&blocking_session, payload, verifier.as_ref())
    })
    .await
    .map_err(|err| {
        AsxError::new(
            ErrorCode::TransportFailure,
            format!("AS2 receive blocking task failed: {err}"),
            ErrorContext::for_session("as2_receive_async_join", &error_session),
        )
    })?
}

fn receive_payload(
    session: &SessionContext,
    payload_input: crate::core::PayloadInput<'_>,
    verifier: &dyn As2TrustVerifier,
) -> Result<DomainReady<Arc<[u8]>>> {
    let body = ReceivedBodyHandle::from_payload_input(payload_input);
    let payload_len = body.payload_len("as2_receive_parse", session)?;
    enforce_payload_limit("as2_receive_parse", payload_len, MAX_AS2_PAYLOAD_BYTES)?;
    if payload_len == 0 {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "as2 payload is empty",
            ErrorContext::new("as2_receive_parse")
                .with_session_and_partner(session.session_id(), session.partner_id()),
        ));
    }
    tracing::debug!(
        session_id = %session.session_id(),
        partner_id = %session.partner_id(),
        bytes = payload_len,
        "AS2 receive: verifying payload",
    );

    let trust = verifier.verify_and_decrypt(session, &body)?;

    // When the verifier performed EnvelopedData decryption it returns the
    // plaintext bytes directly.  For sign-only payloads the original bytes
    // are used unchanged.
    let domain_bytes: Arc<[u8]> = trust
        .decrypted_payload
        .unwrap_or(body.into_arc("as2_receive_parse", session)?);

    // SAFETY: structural validation (size, encoding) was performed by the
    // S/MIME verifier before this point; advancing unchecked is deliberate.
    let trusted = UntrustedBytes::new(domain_bytes)
        .into_parsed_unchecked()
        .verify(trust.signature)?
        .decrypt(trust.decryption)?
        .into_domain_ready();

    Ok(trusted)
}

#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %session.partner_id(), original_message_id = ?request.original_message_id)))]
pub fn receive_with_mdn_with_reliability(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As2ReceiveMdnRequest,
    reconciliation_hook: &dyn ReconciliationStorage,
    dedup_backend: &dyn DedupStorage,
    verifier: &dyn As2TrustVerifier,
) -> Result<As2ReceiveMdnOutput> {
    crate::presets::enforce_strict_runtime_bootstrap_for_strict_interop(
        "as2_receive_with_mdn",
        session,
        request.policy.interop_mode,
    )?;

    if request.policy.interop_mode == InteropMode::Strict
        && (request
            .policy
            .interop_exceptions
            .scoped_profile_name
            .is_some()
            || !request.policy.interop_exceptions.allowed.is_empty())
    {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "strict AS2 runtime policy forbids configured interop exception overrides",
            ErrorContext::for_session("as2_receive_with_mdn", session),
        ));
    }

    crate::presets::enforce_strict_production_runtime_receive_guards(
        "as2_receive_with_mdn",
        session,
        event_bus,
        request.policy.fail_closed_audit_events,
        Some(reconciliation_hook),
        Some(dedup_backend),
    )?;

    // Extract before policy is moved into parse_mdn.
    let fail_closed = request.policy.fail_closed_audit_events;

    let payload = receive_payload(
        session,
        crate::core::PayloadInput::Shared(Arc::clone(&request.payload)),
        verifier,
    )?;

    let (mdn, interop_reason_codes) = match parse_mdn(
        request.mdn_payload.as_ref(),
        request.policy,
        request.require_signed_mdn,
        session,
        event_bus,
        verifier,
    ) {
        Ok(result) => result,
        Err(err) => {
            // R2: parse_mdn failed before we could extract a message ID from the MDN.
            // If the caller supplied an original_message_id, queue it for reconciliation
            // with PendingVerification so it is not silently stranded.
            if let Some(original_id) = request.original_message_id.as_deref() {
                tracing::warn!(
                    session_id = %session.session_id(),
                    partner_id = %session.partner_id(),
                    original_message_id = %original_id,
                    error = %err,
                    "AS2 parse_mdn failed; queuing reconciliation for original message",
                );
                if let Some(req) = ReconciliationRequest::for_outcome(
                    original_id,
                    session.partner_id().to_string(),
                    DeliveryOutcome::Indeterminate,
                ) {
                    drive_reconciliation_future(reconciliation_hook.enqueue(req)).map_err(|enqueue_err| {
                        AsxError::new(
                            ErrorCode::ReliabilityFailure,
                            format!(
                                "AS2 MDN parse failed and reconciliation enqueue failed: parse={err}; enqueue={enqueue_err}"
                            ),
                            ErrorContext::for_session("as2_receive_with_mdn", session),
                        )
                    })?;
                }
            }
            return Err(err);
        }
    };
    let outcome = classify_mdn_outcome(&mdn, request.mdn_mode, request.expected_mic.as_deref());
    let retry_decision = RetryDecision::from_outcome(outcome);
    // Hoist to Arc<str> once so all event-emission clones are O(1) atomic
    // refcount increments rather than String heap allocations.
    let reconciliation_message_id: Arc<str> = Arc::from(
        mdn.original_message_id
            .as_deref()
            .unwrap_or("unknown")
            .to_string(),
    );

    let dedup_key = derive_ingress_idempotency_key(
        session.partner_id(),
        "as2_mdn_receive",
        &reconciliation_message_id,
    );
    if !drive_dedup_future(dedup_backend.first_seen(&dedup_key))? {
        tracing::warn!(
            session_id = %session.session_id(),
            partner_id = %session.partner_id(),
            message_id = %reconciliation_message_id,
            "AS2 duplicate MDN detected, ignoring",
        );
        emit_audit_event(
            event_bus,
            session,
            AsxEvent::DuplicateDetected {
                message_id: reconciliation_message_id.clone(),
                key: dedup_key,
                ingress: AsxIngressStage::As2ReceiveWithMdn,
            },
            fail_closed,
            "as2_mdn_dedup",
        )?;

        // Duplicate MDN ingress should not trigger downstream side effects.
        return Ok(As2ReceiveMdnOutput {
            payload,
            mdn,
            outcome,
            retry_decision,
            interop_reason_codes,
        });
    }

    for reason in &interop_reason_codes {
        emit_protocol_event(
            event_bus,
            session,
            AsxEvent::InteropRelaxationApplied {
                message_id: reconciliation_message_id.clone(),
                rule: "as2_interop_exception",
                detail: reason,
            },
            fail_closed,
            "as2_mdn_interop_relaxation",
        )?;
    }

    emit_protocol_event(
        event_bus,
        session,
        AsxEvent::MdnReceived {
            message_id: reconciliation_message_id.clone(),
            disposition: mdn.disposition.clone(),
        },
        fail_closed,
        "as2_mdn_received",
    )?;

    if retry_decision.should_retry {
        emit_protocol_event(
            event_bus,
            session,
            AsxEvent::RetryScheduled {
                message_id: reconciliation_message_id.clone(),
                attempt: 1,
                reason: "indeterminate_mdn",
            },
            fail_closed,
            "as2_mdn_retry_scheduled",
        )?;
    }

    if let Some(recon_req) = ReconciliationRequest::for_outcome(
        reconciliation_message_id.as_ref(),
        session.partner_id().to_string(),
        outcome,
    ) {
        let reason = match recon_req.reason {
            ReconciliationReason::Indeterminate => "indeterminate",
            ReconciliationReason::PendingVerification => "pending_verification",
        };
        if drive_reconciliation_future(reconciliation_hook.enqueue(recon_req))? {
            emit_protocol_event(
                event_bus,
                session,
                AsxEvent::ReconciliationQueued {
                    message_id: reconciliation_message_id.clone(),
                    reason,
                },
                fail_closed,
                "as2_mdn_reconciliation_queued",
            )?;
        }
    }

    Ok(As2ReceiveMdnOutput {
        payload,
        mdn,
        outcome,
        retry_decision,
        interop_reason_codes,
    })
}

#[cfg(feature = "as2")]
pub fn generate_signed_mdn(
    session: &SessionContext,
    original_message_id: &str,
    disposition: &str,
    received_content_mic: Option<&str>,
    signing: &As2MdnSigningCredentials,
) -> Result<Vec<u8>> {
    let report = generate_mdn(
        session,
        original_message_id,
        disposition,
        received_content_mic,
    )?;

    sign_smime_message(
        &report,
        signing.signing_key_pem.as_slice(),
        signing.signing_cert_pem.as_slice(),
    )
}

pub fn generate_mdn(
    session: &SessionContext,
    original_message_id: &str,
    disposition: &str,
    received_content_mic: Option<&str>,
) -> Result<Vec<u8>> {
    if original_message_id.trim().is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "original_message_id must not be empty",
            ErrorContext::for_session("as2_generate_mdn", session),
        ));
    }
    if disposition.trim().is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "disposition must not be empty",
            ErrorContext::for_session("as2_generate_mdn", session),
        ));
    }

    let boundary = mdn_boundary_from_message_id(original_message_id);

    let mut notification_part = format!(
        "Final-Recipient: rfc822; {}\r\nOriginal-Message-ID: {}\r\nDisposition: {}\r\n",
        session.partner_id(),
        original_message_id,
        disposition
    );
    if let Some(mic) = received_content_mic {
        notification_part.push_str(&format!("Received-Content-MIC: {}\r\n", mic.trim()));
    }

    // RFC 3798 MDN wire shape: multipart/report with human-readable + machine-readable parts.
    let mdn = format!(
        "Content-Type: multipart/report; report-type=disposition-notification; boundary=\"{boundary}\"\r\n\
MIME-Version: 1.0\r\n\
\r\n\
--{boundary}\r\n\
Content-Type: text/plain; charset=us-ascii\r\n\
\r\n\
The message has been received and processed by ASX.\r\n\
\r\n\
--{boundary}\r\n\
Content-Type: message/disposition-notification\r\n\
\r\n\
{notification_part}\
\r\n\
--{boundary}--\r\n"
    );

    Ok(mdn.into_bytes())
}

fn mdn_boundary_from_message_id(original_message_id: &str) -> String {
    // FNV-1a: fast non-cryptographic hash sufficient for MIME boundary uniqueness.
    const OFFSET: u64 = 14_695_981_039_346_656_037;
    const PRIME: u64 = 1_099_511_628_211;
    let mut h: u64 = OFFSET;
    for &b in original_message_id.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(PRIME);
    }
    format!("asx-mdn-{h:016x}")
}

/// Outcome of [`correlate_async_mdn`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsyncMdnCorrelationOutcome {
    /// The async MDN was successfully correlated and its reconciliation entry resolved.
    ///
    /// `original_message_id` is the `Original-Message-ID` field from the MDN.
    Resolved { original_message_id: String },
    /// The async MDN carried an `Original-Message-ID` but no matching reconciliation
    /// entry was found (already resolved, never enqueued, or a duplicate delivery).
    NotPending { original_message_id: String },
    /// The async MDN did not carry an `Original-Message-ID` field; correlation is impossible.
    NoOriginalMessageId,
}

/// Correlate an async MDN with a pending reconciliation entry.
///
/// Call this when your AS2 server receives an asynchronous MDN at the callback URL
/// previously supplied in `Disposition-Notification-To`.  The function extracts the
/// `Original-Message-ID` from the MDN, builds the corresponding reconciliation
/// idempotency keys, and calls [`ReconciliationStorage::resolve`] for the matching entry.
///
/// # Parameters
/// - `mdn_bytes` — raw bytes of the inbound async MDN (the HTTP request body).
/// - `partner_id` — AS2-ID of the trading partner that sent the MDN.
/// - `reconciliation` — reconciliation storage holding pending entries from the original send.
///
/// # Errors
/// Returns [`ErrorCode::ParseFailed`] if the MDN bytes cannot be decoded as a MIME message.
/// Storage errors from `reconciliation.resolve` are propagated directly.
pub fn correlate_async_mdn(
    mdn_bytes: &[u8],
    partner_id: &str,
    reconciliation: &dyn ReconciliationStorage,
) -> Result<AsyncMdnCorrelationOutcome> {
    // This is a public entry point for the async-MDN callback endpoint and runs
    // on an unauthenticated request body. Bound it before the MIME parse so a
    // large or deeply-nested body cannot drive unbounded allocation/recursion,
    // matching the cap `parse_mdn` already enforces.
    enforce_payload_limit(
        "as2_correlate_async_mdn",
        mdn_bytes.len(),
        MAX_AS2_MDN_BYTES,
    )?;

    let original_message_id = match mdn::extract_original_message_id(mdn_bytes) {
        Some(id) => id,
        None => return Ok(AsyncMdnCorrelationOutcome::NoOriginalMessageId),
    };

    // Both possible reconciliation reason variants share the same message ID.
    for reason in [
        ReconciliationReason::Indeterminate,
        ReconciliationReason::PendingVerification,
    ] {
        let key = derive_reconciliation_idempotency_key(partner_id, &original_message_id, reason);
        if drive_reconciliation_future(reconciliation.resolve(&key))? {
            return Ok(AsyncMdnCorrelationOutcome::Resolved {
                original_message_id,
            });
        }
    }

    Ok(AsyncMdnCorrelationOutcome::NotPending {
        original_message_id,
    })
}

#[cfg(test)]
mod tests;
