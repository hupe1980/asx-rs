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
    DedupClaim, DedupStorage, DedupVerdict, ReconciliationStorage, drive_dedup_future,
    drive_reconciliation_future,
};
use crate::wire::{
    DEFAULT_MAX_BODY_BYTES, StreamBodyPolicy, StreamLimits, StreamReadMetrics,
    enforce_payload_limit,
};
use std::sync::Arc;

mod ingress;
mod mdn;
mod mic;
mod send_path;
mod spool_key;
mod spool_policy;
mod spool_runtime_utils;
mod stream_receive;
mod trust;
mod types;
pub use ingress::{As2IngressReceiveRequest, receive_from_ingress};
pub use send_path::{
    As2SendPreparedRequest, As2SendRequest, send_async, send_async_prepared, send_sync,
    send_sync_prepared,
};
pub use spool_key::{SpoolEncryptionKeyProvider, StaticSpoolKey};
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
    As2SignaturePolicy, As2TrustVerifier, AsyncAs2TrustVerifier, CmsSmimeTrustVerifier,
    SyncToAsyncTrustVerifier, TrustResult,
};
#[cfg(feature = "as2")]
pub use types::validate_as2_version_header;
pub use types::{
    As2GeneratedMdn, As2InboundResult, As2MdnDedup, As2MdnMode, As2MdnSigningCredentials,
    As2MicAlgorithm, As2PreparedSendCredentials, As2ReceiveMdnOutput, As2ReceiveMdnRequest,
    As2ReceivePolicy, As2ReceivePolicyBuilder, As2SendCredentials, As2SendOutput, As2SendPolicy,
    MimeEnvelope, ParsedMdn, payload_content_type,
};

use mdn::{classify_mdn_outcome, extract_content_type_header, parse_mdn};
use spool_runtime_utils::{as2_spool_threshold_for_profile, profile_requires_encrypted_spool};
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
    Ok(receive_payload(
        session,
        crate::core::PayloadInput::Owned(payload),
        None,
        verifier,
    )?
    .content)
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

/// What the AS2 receive path recovered from an inbound message.
///
/// `content` is the business document. `mic_input` is the exact octet sequence
/// RFC 4130 §7.3.1 says to digest for the MDN's `Received-Content-MIC` — the
/// protected MIME entity for signed/encrypted messages, or the bare content for
/// unprotected ones. They differ, and using one where the other belongs is why
/// MIC mismatches are the classic AS2 interop failure.
pub(crate) struct ReceivedAs2Payload {
    pub content: DomainReady<Arc<[u8]>>,
    pub mic_input: Arc<[u8]>,
}

/// Whether the body's first line is a plausible MIME header field
/// (`token ":" …`). Distinguishes bodies that repeat the outer MIME headers
/// (OpenSSL `SMIME_write_*` output, asx's own emission) from bodies that start
/// directly with content — a `multipart/signed` preamble or boundary, raw
/// PKCS#7 DER under a binary content-transfer-encoding, or a bare payload.
fn body_starts_with_mime_header(bytes: &[u8]) -> bool {
    let line_end = bytes
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(bytes.len())
        .min(998);
    let line = &bytes[..line_end];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return false;
    };
    let name = &line[..colon];
    !name.is_empty()
        && name.iter().all(|&b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'!' | b'#'..=b'\'' | b'-' | b'^'..=b'`' | b'|' | b'~' | b'+' | b'.')
        })
}

/// RFC 4130 partners differ in whether the HTTP entity body repeats the outer
/// MIME headers. S/MIME processing needs the self-describing form, so when the
/// body starts directly with content, synthesize the headers from the
/// transport `Content-Type`. Without this, a conformant partner that sends
/// `multipart/signed` content (or raw PKCS#7 DER under a binary
/// content-transfer-encoding) with the media type only in the HTTP header is
/// misdetected as carrying no S/MIME layer at all.
fn body_with_mime_headers(
    _session: &SessionContext,
    bytes: &Arc<[u8]>,
    body_content_type: Option<&str>,
) -> ReceivedBodyHandle {
    let Some(content_type) = body_content_type else {
        return ReceivedBodyHandle::InMemory(Arc::clone(bytes));
    };
    if body_starts_with_mime_header(bytes) {
        return ReceivedBodyHandle::InMemory(Arc::clone(bytes));
    }
    // Raw DER (a PKCS#7 ContentInfo starts with SEQUENCE, 0x30) travels under
    // a binary content-transfer-encoding; everything else is already
    // line-oriented MIME content.
    let cte: &str = if bytes.first() == Some(&0x30) {
        "Content-Transfer-Encoding: binary\r\n"
    } else {
        ""
    };
    let mut synthesized =
        format!("MIME-Version: 1.0\r\nContent-Type: {content_type}\r\n{cte}\r\n").into_bytes();
    synthesized.extend_from_slice(bytes);
    ReceivedBodyHandle::InMemory(synthesized.into())
}

/// `body_content_type` is the inbound `Content-Type` header, when the caller
/// has it. It selects the S/MIME processing shape when the body does not
/// repeat the outer MIME headers, and — for messages carrying no
/// message-level security — is the sole signal that the body is an RFC 5402
/// compressed entity.
fn receive_payload(
    session: &SessionContext,
    payload_input: crate::core::PayloadInput<'_>,
    body_content_type: Option<&str>,
    verifier: &dyn As2TrustVerifier,
) -> Result<ReceivedAs2Payload> {
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

    // Keep the original body octets: for unprotected messages they are both
    // the delivered content and, per RFC 4130 §7.3.1, the MIC input — the
    // synthesized headers below exist only for S/MIME processing.
    let original = body.into_arc("as2_receive_parse", session)?;
    let body = body_with_mime_headers(session, &original, body_content_type);
    let trust = verifier.verify_and_decrypt(session, &body)?;

    // The application wants the business document, not the S/MIME envelope it
    // arrived in — so unwrap the protected entity down to its content. The
    // entity's own octets are kept separately as the MIC input.
    let (domain_bytes, mic_input): (Arc<[u8]>, Arc<[u8]>) = match trust.protected_entity {
        Some(entity) => {
            let content: Arc<[u8]> = decode_entity_content(session, &entity)?;
            (content, Arc::from(entity.entity()))
        }
        None => {
            // No message-level security: the original body is both the content
            // and, per RFC 4130 §7.3.1, the MIC input (headers excluded). It
            // may still be compressed — only the transport header says so.
            let compressed = body_content_type
                .is_some_and(crate::crypto::compression::is_as2_compressed_content_type);
            let content = if compressed {
                decompress_as2_entity(session, &original)?
            } else {
                Arc::clone(&original)
            };
            (content, original)
        }
    };

    // SAFETY: structural validation (size, encoding) was performed by the
    // S/MIME verifier before this point; advancing unchecked is deliberate.
    let trusted = UntrustedBytes::new(domain_bytes)
        .into_parsed_unchecked()
        .verify(trust.signature)?
        .decrypt(trust.decryption)?
        .into_domain_ready();

    Ok(ReceivedAs2Payload {
        content: trusted,
        mic_input,
    })
}

/// Recover the business document from a verified MIME entity, reversing RFC
/// 5402 compression when the entity advertises it.
fn decode_entity_content(
    session: &SessionContext,
    entity: &crate::crypto::as2_smime::VerifiedSmimeEntity,
) -> Result<Arc<[u8]>> {
    let content_type = entity.content_type().unwrap_or_default();
    let decoded = entity.decoded_content()?;
    if crate::crypto::compression::is_as2_compressed_content_type(&content_type) {
        return decompress_as2_entity(session, &decoded);
    }
    Ok(Arc::from(decoded.as_ref()))
}

/// Unwrap an RFC 5402 CMS `CompressedData` body.
fn decompress_as2_entity(session: &SessionContext, compressed: &[u8]) -> Result<Arc<[u8]>> {
    #[cfg(feature = "compression")]
    {
        let plain = crate::crypto::compression::decompress_cms_zlib(compressed).map_err(|err| {
            AsxError::new(
                err.code,
                format!(
                    "failed to decompress AS2 payload (RFC 5402): {}",
                    err.message
                ),
                ErrorContext::for_session("as2_receive_decompress", session),
            )
        })?;
        Ok(Arc::from(plain))
    }
    #[cfg(not(feature = "compression"))]
    {
        let _ = compressed;
        Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "partner sent an RFC 5402 compressed AS2 payload but the 'compression' \
             feature is disabled",
            ErrorContext::for_session("as2_receive_decompress", session),
        ))
    }
}

#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %session.partner_id(), original_message_id = ?request.original_message_id)))]
pub fn receive_with_mdn_with_reliability(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As2ReceiveMdnRequest,
    reconciliation_hook: &dyn ReconciliationStorage,
    dedup_backend: Arc<dyn DedupStorage>,
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
        Some(dedup_backend.as_ref()),
    )?;

    // Extract before policy is moved into parse_mdn.
    let fail_closed = request.policy.fail_closed_audit_events;

    let payload = receive_payload(
        session,
        crate::core::PayloadInput::Shared(Arc::clone(&request.payload)),
        None,
        verifier,
    )?
    .content;

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
    // Claimed, not consumed: everything below can still fail, and a failure
    // here means the MDN's outcome was never recorded. Releasing the claim on
    // the way out is what lets the partner's retransmission be processed
    // instead of being swallowed as a duplicate (D59).
    let claim = match drive_dedup_future(dedup_backend.claim(&dedup_key))? {
        DedupVerdict::Claimed => {
            DedupClaim::new(Arc::from(dedup_key.as_str()), Arc::clone(&dedup_backend))
        }
        DedupVerdict::Duplicate => {
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
                dedup: As2MdnDedup::Duplicate,
            });
        }
        DedupVerdict::InFlight => {
            emit_audit_event(
                event_bus,
                session,
                AsxEvent::DuplicateInFlight {
                    message_id: reconciliation_message_id.clone(),
                    key: dedup_key,
                    ingress: AsxIngressStage::As2ReceiveWithMdn,
                },
                fail_closed,
                "as2_mdn_dedup",
            )?;

            return Ok(As2ReceiveMdnOutput {
                payload,
                mdn,
                outcome,
                retry_decision,
                interop_reason_codes,
                dedup: As2MdnDedup::InFlight,
            });
        }
    };

    // From here the claim is live. `mdn_side_effects` owns every remaining
    // fallible step so exactly one place decides whether to release it.
    let mut claim = claim;
    if let Err(err) = mdn_side_effects(MdnSideEffects {
        session,
        event_bus,
        reconciliation_hook,
        fail_closed,
        outcome,
        retry_decision: retry_decision.clone(),
        message_id: &reconciliation_message_id,
        mdn: &mdn,
        interop_reason_codes: &interop_reason_codes,
    }) {
        if let Err(release_err) = claim.abandon_in_place() {
            tracing::error!(
                error = %release_err,
                "failed to release AS2 MDN dedup claim after a failed receive; \
                 the key stays claimed until its lease expires"
            );
        }
        return Err(err);
    }

    Ok(As2ReceiveMdnOutput {
        payload,
        mdn,
        outcome,
        retry_decision,
        interop_reason_codes,
        dedup: As2MdnDedup::FirstSeen(claim),
    })
}

/// Invariant context for the post-dedup side effects of a received MDN.
struct MdnSideEffects<'a> {
    session: &'a SessionContext,
    event_bus: &'a EventBus,
    reconciliation_hook: &'a dyn ReconciliationStorage,
    fail_closed: bool,
    outcome: DeliveryOutcome,
    retry_decision: RetryDecision,
    message_id: &'a Arc<str>,
    mdn: &'a ParsedMdn,
    interop_reason_codes: &'a [&'static str],
}

/// Emit every event and reconciliation entry a first-seen MDN implies.
///
/// Split out so the claim has exactly one release point: each step below is
/// fallible under `fail_closed_audit_events`, and any of them failing means the
/// MDN's outcome was not durably recorded.
fn mdn_side_effects(ctx: MdnSideEffects<'_>) -> Result<()> {
    let MdnSideEffects {
        session,
        event_bus,
        reconciliation_hook,
        fail_closed,
        outcome,
        retry_decision,
        message_id,
        mdn,
        interop_reason_codes,
    } = ctx;

    for reason in interop_reason_codes {
        emit_protocol_event(
            event_bus,
            session,
            AsxEvent::InteropRelaxationApplied {
                message_id: Arc::clone(message_id),
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
            message_id: Arc::clone(message_id),
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
                message_id: Arc::clone(message_id),
                attempt: 1,
                reason: "indeterminate_mdn",
            },
            fail_closed,
            "as2_mdn_retry_scheduled",
        )?;
    }

    if let Some(recon_req) = ReconciliationRequest::for_outcome(
        message_id.as_ref(),
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
                    message_id: Arc::clone(message_id),
                    reason,
                },
                fail_closed,
                "as2_mdn_reconciliation_queued",
            )?;
        }
    }

    Ok(())
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
