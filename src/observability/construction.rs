use std::sync::{Arc, atomic::AtomicU64};

use dashmap::DashMap;

use super::{
    AsxError, AuditSinkDurability, BackpressurePolicy, DurableAuditSink, ErrorCode, ErrorContext,
    EventBus, EventBusMetrics, EventEmissionMode, MetricsSink, NoopMetricsSink, Result,
};

pub(super) fn new_with_config_and_mode_and_metrics(
    capacity: usize,
    audit_sink: Option<Arc<dyn DurableAuditSink>>,
    backpressure: BackpressurePolicy,
    emission_mode: EventEmissionMode,
    metrics_sink: Arc<dyn MetricsSink>,
) -> Result<EventBus> {
    if capacity == 0 {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "event bus capacity must be > 0",
            ErrorContext::new("event_bus_init"),
        ));
    }
    if backpressure.session_channel_capacity == 0 {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "session channel capacity must be > 0",
            ErrorContext::new("event_bus_init"),
        ));
    }
    if backpressure.window_secs == 0 {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "backpressure window_secs must be > 0",
            ErrorContext::new("event_bus_init"),
        ));
    }
    if emission_mode == EventEmissionMode::StrictWithAuditFallback {
        let Some(sink) = audit_sink.as_ref() else {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "StrictWithAuditFallback requires a configured durable audit sink",
                ErrorContext::new("event_bus_init"),
            ));
        };
        if sink.durability() != AuditSinkDurability::Durable {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "StrictWithAuditFallback requires a production-durable audit sink",
                ErrorContext::new("event_bus_init"),
            ));
        }
    }

    // ⚠ OBS-1: BestEffort emission silently drops events when the channel is full.
    // This is incompatible with `fail_closed_audit_events = true` in any policy struct
    // (As2ReceivePolicy, As4PushPolicy, etc.) because the event bus may drop the very
    // audit event the policy requires to be durable before the message is processed.
    // In regulated deployments use StrictTransactional or StrictWithAuditFallback.
    if emission_mode == EventEmissionMode::BestEffort {
        tracing::warn!(
            emission_mode = ?emission_mode,
            "EventBus constructed with BestEffort emission; this mode silently drops events \
             when the channel is full and is incompatible with fail_closed_audit_events = true. \
             Use EventEmissionMode::StrictTransactional or StrictWithAuditFallback for regulated \
             or fail-closed deployments."
        );
    }

    let window_secs = backpressure.window_secs;
    let session_channel_capacity = backpressure.session_channel_capacity;
    Ok(EventBus {
        scoped_senders: Arc::new(DashMap::new()),
        next_scoped_subscription_id: Arc::new(AtomicU64::new(0)),
        session_senders: Arc::new(DashMap::new()),
        next_session_subscription_id: Arc::new(AtomicU64::new(0)),
        metrics: Arc::new(EventBusMetrics {
            window_secs,
            ..Default::default()
        }),
        metrics_sink,
        audit_sink,
        audit_sequence: Arc::new(AtomicU64::new(0)),
        taxonomy_alert_dedup_epoch_secs: Arc::new(DashMap::new()),
        emission_mode,
        backpressure,
        scoped_channel_capacity: capacity,
        session_channel_capacity,
    })
}

pub(super) fn new_with_config_and_mode(
    capacity: usize,
    audit_sink: Option<Arc<dyn DurableAuditSink>>,
    backpressure: BackpressurePolicy,
    emission_mode: EventEmissionMode,
) -> Result<EventBus> {
    new_with_config_and_mode_and_metrics(
        capacity,
        audit_sink,
        backpressure,
        emission_mode,
        Arc::new(NoopMetricsSink),
    )
}

pub(super) fn validate_regulated_audit_sink(audit_sink: &Arc<dyn DurableAuditSink>) -> Result<()> {
    if audit_sink.durability() != AuditSinkDurability::Durable {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "regulated event bus requires a production-durable audit sink",
            ErrorContext::new("event_bus_init"),
        ));
    }
    if !audit_sink.has_replay_cursor_integrity_protection() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "regulated event bus requires integrity-protected replay cursors",
            ErrorContext::new("event_bus_init"),
        ));
    }
    Ok(())
}
