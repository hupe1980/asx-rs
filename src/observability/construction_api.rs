use std::sync::Arc;

use super::{
    BackpressurePolicy, DurableAuditSink, EventBus, EventEmissionMode, MetricsSink, Result,
    new_with_config_and_mode_and_metrics_impl, new_with_config_and_mode_impl,
    validate_regulated_audit_sink,
};

impl EventBus {
    /// Strict constructor.
    ///
    /// By default, strict emission is transactional:
    /// - fail closed when no broadcast subscribers are active
    /// - pre-reserve per-session capacity before broadcast send
    /// - avoid partial side effects when strict preconditions fail
    pub fn new(capacity: usize) -> Result<Self> {
        Self::new_with_config_and_mode(
            capacity,
            None,
            BackpressurePolicy::default(),
            EventEmissionMode::StrictTransactional,
        )
    }

    /// Regulated profile: durable audit is mandatory, emission is strict,
    /// and backpressure thresholds fail closed.
    pub fn new_regulated(capacity: usize, audit_sink: Arc<dyn DurableAuditSink>) -> Result<Self> {
        validate_regulated_audit_sink(&audit_sink)?;
        new_with_config_and_mode_impl(
            capacity,
            Some(audit_sink),
            BackpressurePolicy::regulated(),
            EventEmissionMode::StrictTransactional,
        )
    }

    /// Audit-fallback strict mode.
    ///
    /// When no broadcast subscriber is active, protocol events are written
    /// directly to audit_sink instead of failing with ReliabilityFailure.
    /// This breaks the strict liveness coupling between the EventBus and
    /// broadcast subscribers while keeping the audit log durable.
    ///
    /// Use this in regulated deployments where subscriber uptime guarantees
    /// are operationally difficult (for example rolling deploys or maintenance windows).
    pub fn new_strict_with_audit_fallback(
        capacity: usize,
        audit_sink: Arc<dyn DurableAuditSink>,
    ) -> Result<Self> {
        new_with_config_and_mode_impl(
            capacity,
            Some(audit_sink),
            BackpressurePolicy::default(),
            EventEmissionMode::StrictWithAuditFallback,
        )
    }

    pub fn new_with_config_and_mode(
        capacity: usize,
        audit_sink: Option<Arc<dyn DurableAuditSink>>,
        backpressure: BackpressurePolicy,
        emission_mode: EventEmissionMode,
    ) -> Result<Self> {
        new_with_config_and_mode_impl(capacity, audit_sink, backpressure, emission_mode)
    }

    pub fn new_with_config_and_mode_and_metrics(
        capacity: usize,
        audit_sink: Option<Arc<dyn DurableAuditSink>>,
        backpressure: BackpressurePolicy,
        emission_mode: EventEmissionMode,
        metrics_sink: Arc<dyn MetricsSink>,
    ) -> Result<Self> {
        new_with_config_and_mode_and_metrics_impl(
            capacity,
            audit_sink,
            backpressure,
            emission_mode,
            metrics_sink,
        )
    }

    /// Zero-config best-effort event bus for unit and integration tests.
    ///
    /// Uses [`EventEmissionMode::BestEffort`]: events are silently dropped when
    /// no broadcast subscriber is active, so tests that do not assert on
    /// protocol events never fail with `ReliabilityFailure`.
    ///
    /// **Never use this in production** — it silently discards all protocol
    /// events and audit records.  For production use, see [`EventBus::new`],
    /// [`EventBus::new_regulated`], or [`EventBus::new_strict_with_audit_fallback`].
    #[cfg(feature = "testing")]
    pub fn new_for_testing() -> Self {
        Self::new_with_config_and_mode(
            256,
            None,
            BackpressurePolicy::default(),
            EventEmissionMode::BestEffort,
        )
        .expect("EventBus::new_for_testing: infallible BestEffort construction")
    }
}
