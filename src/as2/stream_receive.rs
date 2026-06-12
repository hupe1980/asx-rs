use crate::wire::read_bounded_stream_into_handle_async;

use super::{
    As2ReceivePolicy, AsxError, AsxEvent, AsyncAs2TrustVerifier, DomainReady, ErrorCode,
    ErrorContext, EventBus, ReceivedBodyHandle, Result, SessionContext, StreamBodyPolicy,
    StreamBodyPolicyBuildOutcome, StreamLimits, StreamReadMetrics, UntrustedBytes,
    as2_stream_body_policy_build, emit_audit_event, emit_protocol_event,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};

static PROVIDER_HEALTH_STATE_BY_PARTNER: OnceLock<Mutex<HashMap<String, &'static str>>> =
    OnceLock::new();

#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %session.partner_id())))]
pub async fn receive_stream<R: tokio::io::AsyncRead + Unpin>(
    session: &SessionContext,
    policy: &As2ReceivePolicy,
    reader: R,
    verifier: &dyn AsyncAs2TrustVerifier,
    limits: StreamLimits,
) -> Result<DomainReady<Arc<[u8]>>> {
    let (trusted, _) =
        receive_stream_with_metrics(session, policy, reader, verifier, limits).await?;
    Ok(trusted)
}

#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %session.partner_id())))]
pub async fn receive_stream_with_metrics_and_audit<R: tokio::io::AsyncRead + Unpin>(
    session: &SessionContext,
    policy: &As2ReceivePolicy,
    event_bus: &EventBus,
    fail_closed_audit_events: bool,
    reader: R,
    verifier: &dyn AsyncAs2TrustVerifier,
    limits: StreamLimits,
) -> Result<(DomainReady<Arc<[u8]>>, StreamReadMetrics)> {
    crate::presets::enforce_strict_runtime_bootstrap_for_strict_interop(
        "as2_receive_stream",
        session,
        policy.interop_mode,
    )?;

    let (body_policy, provider_observation) = match as2_stream_body_policy_build(session, policy) {
        StreamBodyPolicyBuildOutcome::Ready {
            body_policy,
            provider_observation,
        } => (body_policy, provider_observation),
        StreamBodyPolicyBuildOutcome::ProviderFailure { error, observation } => {
            maybe_emit_provider_health_state_transition(
                session,
                event_bus,
                fail_closed_audit_events,
                observation.provider,
                observation.backend,
                observation.health_state,
                observation.phase,
            )?;
            emit_audit_event(
                event_bus,
                session,
                AsxEvent::SpoolKeyProviderHealthCheckFailed {
                    provider: observation.provider,
                    backend: observation.backend,
                    auth_mode: observation.auth_mode,
                    auth_fingerprint_label: observation.auth_fingerprint_label.into(),
                    auth_rotation_hint: observation.auth_rotation_hint,
                    health_state: observation.health_state,
                    phase: observation.phase,
                    error_code: observation.error_code,
                },
                fail_closed_audit_events,
                "as2_receive_stream_provider_health_failure",
            )?;
            return Err(error);
        }
    };

    let (trusted, metrics) =
        receive_stream_with_metrics_internal(session, reader, verifier, limits, &body_policy)
            .await?;

    if let Some(observation) = provider_observation {
        maybe_emit_provider_health_state_transition(
            session,
            event_bus,
            fail_closed_audit_events,
            observation.provider,
            observation.backend,
            observation.health_state,
            "policy_ready",
        )?;
        emit_protocol_event(
            event_bus,
            session,
            AsxEvent::SpoolKeyProviderHealthChecked {
                provider: observation.provider,
                backend: observation.backend,
                auth_mode: observation.auth_mode,
                auth_fingerprint_label: observation.auth_fingerprint_label.into(),
                auth_rotation_hint: observation.auth_rotation_hint,
                health_state: observation.health_state,
                startup_self_test_ms: observation.startup_self_test_ms,
                resolve_key_ms: observation.resolve_key_ms,
            },
            fail_closed_audit_events,
            "as2_receive_stream_provider_health",
        )?;
    }
    emit_stream_ingest_observations(session, event_bus, fail_closed_audit_events, &metrics)?;
    Ok((trusted, metrics))
}

pub(super) fn maybe_emit_provider_health_state_transition(
    session: &SessionContext,
    event_bus: &EventBus,
    fail_closed_audit_events: bool,
    provider: &'static str,
    backend: &'static str,
    health_state: &'static str,
    reason: &'static str,
) -> Result<()> {
    let key = format!("{}:{provider}:{backend}", session.partner_id());
    let states = PROVIDER_HEALTH_STATE_BY_PARTNER.get_or_init(|| Mutex::new(HashMap::new()));
    let previous_state = {
        let mut guard = states.lock().map_err(|_| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                "provider health state cache lock is poisoned",
                ErrorContext::for_session("as2_receive_stream_provider_health_transition", session),
            )
        })?;
        guard.insert(key, health_state)
    };

    let previous_state = previous_state.unwrap_or("unknown");
    if previous_state == health_state {
        return Ok(());
    }

    emit_protocol_event(
        event_bus,
        session,
        AsxEvent::SpoolKeyProviderHealthStateChanged {
            provider,
            backend,
            previous_state,
            current_state: health_state,
            reason,
        },
        fail_closed_audit_events,
        "as2_receive_stream_provider_health_transition",
    )
}

pub(super) fn emit_stream_ingest_observations(
    session: &SessionContext,
    event_bus: &EventBus,
    fail_closed_audit_events: bool,
    metrics: &StreamReadMetrics,
) -> Result<()> {
    if metrics.startup_hygiene_checked
        && let (Some(free_bytes), Some(min_required_bytes)) =
            (metrics.spool_free_bytes, metrics.spool_min_free_bytes)
    {
        emit_protocol_event(
            event_bus,
            session,
            AsxEvent::SpoolHeadroomChecked {
                stage: "as2_receive_stream",
                free_bytes,
                min_required_bytes,
            },
            fail_closed_audit_events,
            "as2_receive_stream_spool_headroom",
        )?;
    }

    if metrics.materialized_from_spool {
        emit_audit_event(
            event_bus,
            session,
            AsxEvent::MaterializationApplied {
                message_id: Arc::from("unknown"),
                stage: "as2_receive_stream",
                reason: "spooled_payload_to_contiguous_bytes",
                bytes: metrics.total_bytes,
                source: "spool",
            },
            fail_closed_audit_events,
            "as2_receive_stream_materialize",
        )?;
    }

    Ok(())
}

#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %session.partner_id())))]
pub async fn receive_stream_with_metrics<R: tokio::io::AsyncRead + Unpin>(
    session: &SessionContext,
    policy: &As2ReceivePolicy,
    reader: R,
    verifier: &dyn AsyncAs2TrustVerifier,
    limits: StreamLimits,
) -> Result<(DomainReady<Arc<[u8]>>, StreamReadMetrics)> {
    crate::presets::enforce_strict_runtime_bootstrap_for_strict_interop(
        "as2_receive_stream",
        session,
        policy.interop_mode,
    )?;

    let body_policy = match as2_stream_body_policy_build(session, policy) {
        StreamBodyPolicyBuildOutcome::Ready { body_policy, .. } => body_policy,
        StreamBodyPolicyBuildOutcome::ProviderFailure { error, .. } => return Err(error),
    };
    let (trusted, metrics) =
        receive_stream_with_metrics_internal(session, reader, verifier, limits, &body_policy)
            .await?;
    Ok((trusted, metrics))
}

async fn receive_stream_with_metrics_internal<R: tokio::io::AsyncRead + Unpin>(
    session: &SessionContext,
    reader: R,
    verifier: &dyn AsyncAs2TrustVerifier,
    limits: StreamLimits,
    body_policy: &StreamBodyPolicy,
) -> Result<(DomainReady<Arc<[u8]>>, StreamReadMetrics)> {
    let (handle, mut metrics) =
        read_bounded_stream_into_handle_async(reader, limits, body_policy, "as2_receive_stream")
            .await?;
    let trust = verifier.verify_and_decrypt(session, &handle).await?;
    let domain_bytes = match trust.decrypted_payload {
        Some(bytes) => {
            if matches!(handle, ReceivedBodyHandle::Spooled { .. }) {
                handle.dispose("as2_receive_stream_cleanup", session)?;
            }
            bytes
        }
        None => {
            if matches!(handle, ReceivedBodyHandle::Spooled { .. }) {
                metrics.materialized_from_spool = true;
            }
            handle.into_arc("as2_receive_stream", session)?
        }
    };
    // SAFETY: structural validation was performed by the async S/MIME verifier
    // before this point; advancing unchecked is deliberate.
    let trusted = UntrustedBytes::new(domain_bytes)
        .into_parsed_unchecked()
        .verify(trust.signature)?
        .decrypt(trust.decryption)?
        .into_domain_ready();
    Ok((trusted, metrics))
}
