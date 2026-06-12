#[cfg(not(feature = "testing"))]
use crate::as4::pmode::PayloadPackagingMode;
use crate::as4::types::As4SendPolicy;
use crate::core::InteropMode;
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
use crate::crypto::wssec::RevocationPolicy;
use crate::interop::InteropExceptionPolicy;
use crate::observability::{
    AsxEvent, AsxIngressStage, EventBus, emit_audit_event, emit_protocol_event,
};
use crate::reliability::{
    DeliveryOutcome, ReconciliationReason, ReconciliationRequest, RetryDecision,
    derive_ingress_idempotency_key,
};
use crate::storage::{DedupStorage, ReconciliationStorage};
use std::sync::Arc;

pub(crate) fn expected_fingerprint_from_session(session: &SessionContext) -> Option<&str> {
    let fp = session.cert_handle().fingerprint_sha256.trim();
    if fp.is_empty() { None } else { Some(fp) }
}

pub(crate) fn wssec_revocation_policy_from_session<'a>(
    session: &'a SessionContext,
) -> Result<RevocationPolicy<'a>> {
    Ok(RevocationPolicy {
        trust_anchor_pems: &session.cert_handle().trust_anchor_pems,
        revocation_crl_pems: &session.cert_handle().revocation_crl_pems,
        ocsp_mode: session.cert_handle().ocsp_mode,
        ocsp_failure_mode: session.cert_handle().ocsp_failure_mode,
        stapled_ocsp_responses_der: &session.cert_handle().stapled_ocsp_responses_der,
        responder_ocsp_responses_der: &session.cert_handle().responder_ocsp_responses_der,
        ocsp_cache_namespace: session.partner_id(),
        require_chain_validation: true,
        pre_parsed_trust_anchors: Some(session.cert_handle().trust_anchors_x509()?),
        pre_built_x509_store: Some(session.cert_handle().trust_anchor_x509_store()?),
    })
}

pub(crate) fn enforce_strict_as4_runtime_policy_consistency(
    session: &SessionContext,
    stage: &'static str,
    interop_mode: InteropMode,
    interop_exceptions: &InteropExceptionPolicy,
    _require_signed_push: bool,
    _require_signed_receipt: bool,
    _fail_closed_audit_events: bool,
) -> Result<()> {
    // Guard: the `testing` feature disables enforcement gates, which is safe
    // only inside automated tests.  Emit a hard compile-time error when
    // `testing` is enabled together with `--release` optimisations so that
    // a misconfigured production build is caught at compile time, not at
    // runtime.
    //
    // The `cfg` combination `feature="testing" + not(debug_assertions)` means
    // the crate was compiled in release mode with the testing feature active —
    // i.e., production artefacts with security removed.
    #[cfg(all(feature = "testing", not(debug_assertions)))]
    compile_error!(
        "The `testing` feature must NOT be enabled in release builds.  \
         It disables critical WS-Security enforcement gates.  \
         Remove `features = [\"testing\"]` from your release dependency."
    );

    #[cfg(feature = "testing")]
    let _ = (
        session,
        stage,
        _require_signed_push,
        _require_signed_receipt,
        _fail_closed_audit_events,
    );

    #[cfg(not(feature = "testing"))]
    {
        if !_require_signed_push {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                "AS4 receive runtime policy forbids require_signed_push=false in non-testing builds",
                ErrorContext::for_session(stage, session),
            ));
        }

        if interop_mode == InteropMode::Strict {
            if !_require_signed_receipt {
                return Err(AsxError::new(
                    ErrorCode::PolicyViolation,
                    "strict AS4 receive runtime policy requires require_signed_receipt=true in non-testing builds",
                    ErrorContext::for_session(stage, session),
                ));
            }
        }
    }

    if interop_mode == InteropMode::Strict
        && (interop_exceptions.scoped_profile_name.is_some()
            || !interop_exceptions.allowed.is_empty())
    {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "strict AS4 runtime policy forbids configured interop exception overrides",
            ErrorContext::for_session(stage, session),
        ));
    }

    Ok(())
}

pub(crate) fn enforce_strict_as4_send_runtime_policy_consistency(
    session: &SessionContext,
    stage: &'static str,
    policy: &As4SendPolicy,
) -> Result<()> {
    #[cfg(feature = "testing")]
    let _ = (session, stage, policy);

    #[cfg(not(feature = "testing"))]
    if policy.interop == InteropMode::Strict {
        if !policy.sign {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                "strict AS4 send policy forbids sign=false in non-testing builds",
                ErrorContext::for_session(stage, session),
            ));
        }
        if !policy.fail_closed_audit_events {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                "strict AS4 send policy requires fail_closed_audit_events=true in non-testing builds",
                ErrorContext::for_session(stage, session),
            ));
        }
        if policy.payload_packaging_mode != PayloadPackagingMode::MimeAttachment {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                "strict AS4 send policy requires MIME attachment payload packaging",
                ErrorContext::for_session(stage, session),
            ));
        }
    }

    Ok(())
}

pub(crate) fn emit_duplicate_if_seen(
    session: &SessionContext,
    event_bus: &EventBus,
    dedup_backend: &dyn DedupStorage,
    message_id: &str,
    ingress: AsxIngressStage,
    fail_closed_audit_events: bool,
) -> crate::core::Result<()> {
    let dedup_key =
        derive_ingress_idempotency_key(session.partner_id(), "as4_push_receive", message_id);
    if !dedup_backend.first_seen(&dedup_key)? {
        emit_audit_event(
            event_bus,
            session,
            AsxEvent::DuplicateDetected {
                message_id: Arc::from(message_id),
                key: dedup_key,
                ingress,
            },
            fail_closed_audit_events,
            "as4_dedup",
        )?;
    }
    Ok(())
}

pub(crate) fn emit_receive_push_signed_encrypted(
    session: &SessionContext,
    event_bus: &EventBus,
    message_id: &str,
    fail_closed_audit_events: bool,
) -> crate::core::Result<()> {
    let message_id = Arc::<str>::from(message_id);

    emit_protocol_event(
        event_bus,
        session,
        AsxEvent::MessageSigned {
            message_id: Arc::clone(&message_id),
        },
        fail_closed_audit_events,
        "as4_receive_push_signed",
    )?;

    emit_protocol_event(
        event_bus,
        session,
        AsxEvent::MessageEncrypted { message_id },
        fail_closed_audit_events,
        "as4_receive_push_encrypted",
    )?;

    Ok(())
}

pub(crate) fn emit_receive_push_receipt_received(
    session: &SessionContext,
    event_bus: &EventBus,
    message_id: &Arc<str>,
) -> crate::core::Result<()> {
    emit_protocol_event(
        event_bus,
        session,
        AsxEvent::ReceiptReceived {
            message_id: Arc::clone(message_id),
            signal: "as4",
        },
        true,
        "as4_receive_push_receipt",
    )?;

    Ok(())
}

pub(crate) fn emit_receive_push_receipt_taxonomy_outcome(
    session: &SessionContext,
    event_bus: &EventBus,
    message_id: &Arc<str>,
    outcome: &'static str,
    detail: &'static str,
    fail_closed: bool,
) -> crate::core::Result<()> {
    emit_protocol_event(
        event_bus,
        session,
        AsxEvent::ReceiptTaxonomyOutcome {
            message_id: Arc::clone(message_id),
            signal: "as4",
            outcome,
            detail,
        },
        fail_closed,
        "as4_receive_push_receipt_taxonomy",
    )?;

    Ok(())
}

pub(crate) fn emit_pull_duplicate_if_seen(
    session: &SessionContext,
    event_bus: &EventBus,
    dedup_backend: &dyn DedupStorage,
    pull_message_id: &Arc<str>,
    fail_closed_audit_events: bool,
) -> crate::core::Result<()> {
    let dedup_key = derive_ingress_idempotency_key(
        session.partner_id(),
        "as4_pull_receive",
        pull_message_id.as_ref(),
    );
    if !dedup_backend.first_seen(&dedup_key)? {
        emit_audit_event(
            event_bus,
            session,
            AsxEvent::DuplicateDetected {
                message_id: Arc::clone(pull_message_id),
                key: dedup_key,
                ingress: AsxIngressStage::As4ReceivePull,
            },
            fail_closed_audit_events,
            "as4_pull_dedup",
        )?;
    }
    Ok(())
}

pub(crate) fn handle_empty_pull_partition(
    session: &SessionContext,
    event_bus: &EventBus,
    reconciliation_hook: &dyn ReconciliationStorage,
    pull_message_id: &Arc<str>,
    fail_closed_audit_events: bool,
) -> crate::core::Result<(DeliveryOutcome, RetryDecision)> {
    let outcome = DeliveryOutcome::Indeterminate;
    let retry = RetryDecision::from_outcome(outcome);

    if let Some(reconciliation_request) = ReconciliationRequest::for_outcome(
        pull_message_id.as_ref(),
        session.partner_id().to_string(),
        outcome,
    ) {
        let reason = match reconciliation_request.reason {
            ReconciliationReason::Indeterminate => "indeterminate",
            ReconciliationReason::PendingVerification => "pending_verification",
        };
        if reconciliation_hook.enqueue(reconciliation_request)? {
            emit_protocol_event(
                event_bus,
                session,
                AsxEvent::ReconciliationQueued {
                    message_id: Arc::clone(pull_message_id),
                    reason,
                },
                fail_closed_audit_events,
                "as4_pull_reconciliation_queued",
            )?;
        }
    }

    emit_protocol_event(
        event_bus,
        session,
        AsxEvent::RetryScheduled {
            message_id: Arc::clone(pull_message_id),
            attempt: 1,
            reason: "empty_message_partition_channel",
        },
        fail_closed_audit_events,
        "as4_pull_retry_scheduled",
    )?;

    Ok((outcome, retry))
}

pub(crate) fn ensure_pull_mpc_matches(
    session: &SessionContext,
    expected_mpc: &str,
    pulled_mpc: &str,
    message_id: &str,
) -> Result<()> {
    if expected_mpc != pulled_mpc {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            "pulled AS4 UserMessage MPC does not match PullRequest MPC",
            ErrorContext::for_session_with_message("as4_receive_pull", session, message_id),
        ));
    }

    Ok(())
}
