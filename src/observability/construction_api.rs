use std::sync::Arc;

use super::{
    BackpressurePolicy, DurableAuditSink, EventBus, EventEmissionMode, MetricsSink, Result,
    new_with_config_and_mode_and_metrics_impl, new_with_config_and_mode_impl,
    validate_regulated_audit_sink,
};

/// Fluent constructor for [`EventBus`].
///
/// Every field has a safe default, so only the ones a deployment actually cares
/// about need naming:
///
/// | Field | Default |
/// |---|---|
/// | `capacity` | 256 scoped-subscription slots |
/// | `emission_mode` | [`EventEmissionMode::StrictTransactional`] |
/// | `backpressure` | [`BackpressurePolicy::default`] |
/// | `audit_sink` | none |
/// | `metrics_sink` | a no-op sink |
///
/// ```
/// use asx_rs::observability::{BackpressurePolicy, EventBus, EventEmissionMode};
///
/// # fn main() -> asx_rs::Result<()> {
/// let bus = EventBus::builder()
///     .capacity(64)
///     .emission_mode(EventEmissionMode::BestEffort)
///     .backpressure(BackpressurePolicy::regulated())
///     .build()?;
/// # let _ = bus;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct EventBusBuilder {
    capacity: usize,
    audit_sink: Option<Arc<dyn DurableAuditSink>>,
    backpressure: BackpressurePolicy,
    emission_mode: EventEmissionMode,
    metrics_sink: Option<Arc<dyn MetricsSink>>,
}

impl std::fmt::Debug for EventBusBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBusBuilder")
            .field("capacity", &self.capacity)
            .field("audit_sink", &self.audit_sink.is_some())
            .field("backpressure", &self.backpressure)
            .field("emission_mode", &self.emission_mode)
            .field("metrics_sink", &self.metrics_sink.is_some())
            .finish()
    }
}

impl Default for EventBusBuilder {
    fn default() -> Self {
        Self {
            capacity: 256,
            audit_sink: None,
            backpressure: BackpressurePolicy::default(),
            emission_mode: EventEmissionMode::StrictTransactional,
            metrics_sink: None,
        }
    }
}

impl EventBusBuilder {
    /// Per-subscription channel depth. Must be greater than zero.
    #[must_use]
    pub fn capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }

    /// Attach a durable audit sink. Every event is persisted through it
    /// **before** fan-out, so an event a subscriber saw is an event the store
    /// has.
    #[must_use]
    pub fn audit_sink(mut self, sink: Arc<dyn DurableAuditSink>) -> Self {
        self.audit_sink = Some(sink);
        self
    }

    /// Saturation thresholds and what to do when they are exceeded.
    #[must_use]
    pub fn backpressure(mut self, backpressure: BackpressurePolicy) -> Self {
        self.backpressure = backpressure;
        self
    }

    /// Whether emission is transactional with respect to its preconditions.
    #[must_use]
    pub fn emission_mode(mut self, mode: EventEmissionMode) -> Self {
        self.emission_mode = mode;
        self
    }

    /// Where counters and gauges go. Defaults to a no-op sink.
    #[must_use]
    pub fn metrics_sink(mut self, sink: Arc<dyn MetricsSink>) -> Self {
        self.metrics_sink = Some(sink);
        self
    }

    /// Validate the combination and construct the bus.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::InvalidInput`](crate::ErrorCode::InvalidInput) when
    /// `capacity`, `session_channel_capacity` or `window_secs` is zero, or when
    /// [`EventEmissionMode::StrictWithAuditFallback`] is selected without a
    /// production-durable audit sink to fall back to.
    pub fn build(self) -> Result<EventBus> {
        match self.metrics_sink {
            Some(metrics) => new_with_config_and_mode_and_metrics_impl(
                self.capacity,
                self.audit_sink,
                self.backpressure,
                self.emission_mode,
                metrics,
            ),
            None => new_with_config_and_mode_impl(
                self.capacity,
                self.audit_sink,
                self.backpressure,
                self.emission_mode,
            ),
        }
    }
}

impl EventBus {
    /// Start building a bus. See [`EventBusBuilder`] for the defaults.
    #[must_use]
    pub fn builder() -> EventBusBuilder {
        EventBusBuilder::default()
    }

    /// Strict transactional bus with no audit sink — the ordinary choice.
    ///
    /// Strict emission is transactional with respect to its preconditions: it
    /// fails closed when no subscriber is active, pre-reserves per-session
    /// capacity before sending, and leaves no partial side effects when a
    /// precondition fails.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::InvalidInput`](crate::ErrorCode::InvalidInput) if
    /// `capacity` is zero.
    pub fn new(capacity: usize) -> Result<Self> {
        Self::builder().capacity(capacity).build()
    }

    /// Regulated profile: a durable, integrity-protected audit sink is
    /// mandatory, emission is strict, and backpressure fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::InvalidInput`](crate::ErrorCode::InvalidInput) if
    /// the sink is not production-durable or does not integrity-protect its
    /// replay cursor, or if `capacity` is zero.
    pub fn new_regulated(capacity: usize, audit_sink: Arc<dyn DurableAuditSink>) -> Result<Self> {
        validate_regulated_audit_sink(&audit_sink)?;
        Self::builder()
            .capacity(capacity)
            .audit_sink(audit_sink)
            .backpressure(BackpressurePolicy::regulated())
            .build()
    }

    /// Zero-config best-effort bus for unit and integration tests.
    ///
    /// Uses [`EventEmissionMode::BestEffort`]: events are silently dropped when
    /// no subscriber is active, so tests that do not assert on protocol events
    /// never fail with `ReliabilityFailure`.
    ///
    /// **Never use this in production** — it silently discards protocol events
    /// and audit records. See [`EventBus::new`] or [`EventBus::new_regulated`].
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn new_for_testing() -> Self {
        Self::builder()
            .emission_mode(EventEmissionMode::BestEffort)
            .build()
            .expect("EventBus::new_for_testing: infallible BestEffort construction")
    }

    #[cfg(test)]
    pub(crate) fn new_with_config_and_mode(
        capacity: usize,
        audit_sink: Option<Arc<dyn DurableAuditSink>>,
        backpressure: BackpressurePolicy,
        emission_mode: EventEmissionMode,
    ) -> Result<Self> {
        new_with_config_and_mode_impl(capacity, audit_sink, backpressure, emission_mode)
    }

    #[cfg(test)]
    pub(crate) fn new_with_config_and_mode_and_metrics(
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

    #[cfg(test)]
    pub(crate) fn new_strict_with_audit_fallback(
        capacity: usize,
        audit_sink: Arc<dyn DurableAuditSink>,
    ) -> Result<Self> {
        Self::builder()
            .capacity(capacity)
            .audit_sink(audit_sink)
            .emission_mode(EventEmissionMode::StrictWithAuditFallback)
            .build()
    }
}
