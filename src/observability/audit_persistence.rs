use std::cell::Cell;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    AsxError, AsxEvent, AuditEvent, AuditMetadata, AuditSeverity, ErrorCode, ErrorContext,
    EventBus, ReplayCursor, Result, SessionContext,
};

thread_local! {
    static AUDIT_SINK_STORE_EVENT_ACTIVE: Cell<bool> = const { Cell::new(false) };
}

struct AuditSinkStoreEventGuard;

impl AuditSinkStoreEventGuard {
    fn enter(session: &SessionContext, stage: &'static str) -> Result<Self> {
        let already_active = AUDIT_SINK_STORE_EVENT_ACTIVE.with(|active| {
            let currently_active = active.get();
            if !currently_active {
                active.set(true);
            }
            currently_active
        });

        if already_active {
            return Err(AsxError::new(
                ErrorCode::ReliabilityFailure,
                "durable audit sink re-entrant store_event call detected",
                ErrorContext::for_session(stage, session),
            ));
        }

        Ok(Self)
    }
}

impl Drop for AuditSinkStoreEventGuard {
    fn drop(&mut self) {
        AUDIT_SINK_STORE_EVENT_ACTIVE.with(|active| active.set(false));
    }
}

pub(super) fn replay_audit_events_from(
    bus: &EventBus,
    cursor: &ReplayCursor,
    limit: usize,
) -> Result<Vec<AuditEvent>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let sink = bus.audit_sink.as_ref().ok_or_else(|| {
        AsxError::new(
            ErrorCode::InvalidInput,
            "durable audit sink is not configured",
            ErrorContext::new("event_bus_audit_replay"),
        )
    })?;
    sink.verify_replay_cursor_integrity(cursor)?;
    sink.retrieve_events_from(cursor, limit)
}

pub(super) fn current_audit_cursor(bus: &EventBus) -> Result<ReplayCursor> {
    let sink = bus.audit_sink.as_ref().ok_or_else(|| {
        AsxError::new(
            ErrorCode::InvalidInput,
            "durable audit sink is not configured",
            ErrorContext::new("event_bus_audit_cursor"),
        )
    })?;
    let cursor = sink.current_cursor()?;
    sink.verify_replay_cursor_integrity(&cursor)?;
    Ok(cursor)
}

pub(super) fn acknowledge_audit_cursor(bus: &EventBus, cursor: &ReplayCursor) -> Result<()> {
    let sink = bus.audit_sink.as_ref().ok_or_else(|| {
        AsxError::new(
            ErrorCode::InvalidInput,
            "durable audit sink is not configured",
            ErrorContext::new("event_bus_audit_ack"),
        )
    })?;
    sink.verify_replay_cursor_integrity(cursor)?;
    sink.acknowledge_cursor(cursor)
}

pub(super) fn persist_audit_event(
    bus: &EventBus,
    session: &SessionContext,
    event: &AsxEvent,
    stage: &'static str,
) -> Result<()> {
    let Some(sink) = &bus.audit_sink else {
        return Ok(());
    };

    let _guard = AuditSinkStoreEventGuard::enter(session, stage)?;

    let sequence = bus.audit_sequence.fetch_add(1, Ordering::Relaxed) + 1;
    let timestamp_secs = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    };

    let audit_event = AuditEvent {
        event_id: format!("evt-{sequence}"),
        session_id: Some(session.session_id().to_string()),
        partner_id: Some(session.partner_id().to_string()),
        code: event_code(event).into(),
        timestamp: timestamp_secs,
        message: event_message(event).into(),
        metadata: AuditMetadata {
            stage: Some(stage.to_string()),
            severity: AuditSeverity::High,
            action: Some("emit_audit_event".into()),
            result: Some("attempted".into()),
        },
    };

    sink.store_event(&audit_event).map_err(|_| {
        AsxError::new(
            ErrorCode::ReliabilityFailure,
            "durable audit sink write failed",
            ErrorContext::for_session(stage, session),
        )
    })
}

pub(super) fn event_code(event: &AsxEvent) -> &'static str {
    match event {
        AsxEvent::OutboundPrepared { .. } => "outbound_prepared",
        AsxEvent::MicComputed { .. } => "mic_computed",
        AsxEvent::MessageSigned { .. } => "message_signed",
        AsxEvent::MessageEncrypted { .. } => "message_encrypted",
        AsxEvent::MdnReceived { .. } => "mdn_received",
        AsxEvent::ReceiptReceived { .. } => "receipt_received",
        AsxEvent::ReceiptTaxonomyOutcome { .. } => "receipt_taxonomy_outcome",
        AsxEvent::ReceiptTaxonomyAlertRaised { .. } => "receipt_taxonomy_alert_raised",
        AsxEvent::RetryScheduled { .. } => "retry_scheduled",
        AsxEvent::ReconciliationQueued { .. } => "reconciliation_queued",
        AsxEvent::DuplicateDetected { .. } => "duplicate_detected",
        AsxEvent::InteropRelaxationApplied { .. } => "interop_relaxation_applied",
        AsxEvent::InteropGuardrailEvaluated { .. } => "interop_guardrail_evaluated",
        AsxEvent::MaterializationApplied { .. } => "materialization_applied",
        AsxEvent::SpoolKeyProviderHealthChecked { .. } => "spool_key_provider_health_checked",
        AsxEvent::SpoolKeyProviderHealthCheckFailed { .. } => {
            "spool_key_provider_health_check_failed"
        }
        AsxEvent::SpoolKeyProviderHealthStateChanged { .. } => {
            "spool_key_provider_health_state_changed"
        }
        AsxEvent::SpoolProviderHealthAlertRaised { .. } => "spool_provider_health_alert_raised",
        AsxEvent::SpoolHeadroomChecked { .. } => "spool_headroom_checked",
        AsxEvent::PullQueueOverflow { .. } => "pull_queue_overflow",
        AsxEvent::CertOcspRevoked { .. } => "cert_ocsp_revoked",
        AsxEvent::CertOcspUnknown { .. } => "cert_ocsp_unknown",
        AsxEvent::CertNearExpiry { .. } => "cert_near_expiry",
        AsxEvent::As2AsyncMdnRequested { .. } => "as2_async_mdn_requested",
        AsxEvent::MessageSent { .. } => "message_sent",
        AsxEvent::MessageSendFailed { .. } => "message_send_failed",
        AsxEvent::FragmentIngested { .. } => "fragment_ingested",
        AsxEvent::FragmentGroupComplete { .. } => "fragment_group_complete",
        AsxEvent::FragmentGroupEvicted { .. } => "fragment_group_evicted",
    }
}

pub(super) fn event_message(event: &AsxEvent) -> &'static str {
    match event {
        AsxEvent::OutboundPrepared { .. } => "Outbound message prepared",
        AsxEvent::MicComputed { .. } => "MIC computed",
        AsxEvent::MessageSigned { .. } => "Message signed",
        AsxEvent::MessageEncrypted { .. } => "Message encrypted",
        AsxEvent::MdnReceived { .. } => "MDN received",
        AsxEvent::ReceiptReceived { .. } => "Receipt received",
        AsxEvent::ReceiptTaxonomyOutcome { .. } => "Receipt taxonomy outcome recorded",
        AsxEvent::ReceiptTaxonomyAlertRaised { .. } => "Receipt taxonomy alert raised",
        AsxEvent::RetryScheduled { .. } => "Retry scheduled",
        AsxEvent::ReconciliationQueued { .. } => "Reconciliation queued",
        AsxEvent::DuplicateDetected { .. } => "Duplicate detected",
        AsxEvent::InteropRelaxationApplied { .. } => "Interop relaxation applied",
        AsxEvent::InteropGuardrailEvaluated { .. } => "Interop guardrail evaluated",
        AsxEvent::MaterializationApplied { .. } => "Body materialization applied",
        AsxEvent::SpoolKeyProviderHealthChecked { .. } => "Spool key provider health checked",
        AsxEvent::SpoolKeyProviderHealthCheckFailed { .. } => {
            "Spool key provider health check failed"
        }
        AsxEvent::SpoolKeyProviderHealthStateChanged { .. } => {
            "Spool key provider health state changed"
        }
        AsxEvent::SpoolProviderHealthAlertRaised { .. } => "Spool provider health alert raised",
        AsxEvent::SpoolHeadroomChecked { .. } => "Spool headroom checked",
        AsxEvent::PullQueueOverflow { .. } => "Pull queue overflow",
        AsxEvent::CertOcspRevoked { .. } => "Certificate OCSP revoked",
        AsxEvent::CertOcspUnknown { .. } => "Certificate OCSP status unknown",
        AsxEvent::CertNearExpiry { .. } => "Certificate approaching expiry",
        AsxEvent::As2AsyncMdnRequested { .. } => "Async MDN delivery requested via mailto:",
        AsxEvent::MessageSent { .. } => "Outbound message sent successfully",
        AsxEvent::MessageSendFailed { .. } => "Outbound message delivery failed permanently",
        AsxEvent::FragmentIngested { .. } => "Large-message fragment ingested",
        AsxEvent::FragmentGroupComplete { .. } => "Large-message fragment group complete",
        AsxEvent::FragmentGroupEvicted { .. } => "Large-message fragment group evicted",
    }
}
