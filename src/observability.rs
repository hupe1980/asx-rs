use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use tokio::sync::mpsc;
#[cfg(test)]
use tokio::sync::watch;

use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
use crate::observability::audit_sink::{
    AuditEvent, AuditMetadata, AuditSeverity, AuditSinkDurability, DurableAuditSink, ReplayCursor,
};

mod alerts;
mod audit_persistence;
mod audit_runtime;
pub mod audit_sink;
mod construction;
mod construction_api;
mod emission_policy;
mod emission_runtime;
mod event_taxonomy;
pub mod metric_names;
mod metrics_analysis;
mod metrics_observation;
#[cfg(feature = "opentelemetry")]
pub mod opentelemetry;
#[cfg(feature = "prometheus")]
pub mod prometheus;
mod scoped_subscriptions;
mod session_subscriptions;
mod sink_forwarding;
pub use crate::alerting::{
    As2ProviderHealthAlert, As2ProviderHealthAlertCategory, As2ProviderHealthAlertDispatchPolicy,
    As2ProviderHealthAlertIncident, As2ProviderHealthAlertPolicy, As2ProviderHealthAlertSeverity,
    As2ProviderHealthIncidentChannel, As2ProviderHealthSnapshot, As4ReceiptTaxonomyAlert,
    As4ReceiptTaxonomyAlertCategory, As4ReceiptTaxonomyAlertDispatchPolicy,
    As4ReceiptTaxonomyAlertIncident, As4ReceiptTaxonomyAlertPolicy,
    As4ReceiptTaxonomyAlertSeverity, As4ReceiptTaxonomyIncidentChannel, As4ReceiptTaxonomySnapshot,
};
pub use crate::alerting::{
    As2ProviderHealthAlertSchedulerRequest, As4ReceiptTaxonomyAlertSchedulerRequest,
};
#[cfg(test)]
use audit_persistence::{event_code, event_message};
use construction::{
    new_with_config_and_mode as new_with_config_and_mode_impl,
    new_with_config_and_mode_and_metrics as new_with_config_and_mode_and_metrics_impl,
    validate_regulated_audit_sink,
};
pub use emission_runtime::emit_audit_event;
#[cfg(any(feature = "as2", feature = "as4"))]
pub(crate) use emission_runtime::{emit_protocol_event, require_durable_audit_sink};
pub use event_taxonomy::{AsxEvent, AsxIngressStage, AsxProtocol, ScopedAsxEvent, SharedAsxEvent};
#[cfg(feature = "opentelemetry")]
pub use opentelemetry::OtelMetricsSink;
#[cfg(feature = "prometheus")]
pub use prometheus::PrometheusMetricsSink;
use scoped_subscriptions::subscribe_scoped_events_impl;
pub use scoped_subscriptions::{ScopedEventSubscription, ScopedEventTryRecvError};
pub use session_subscriptions::SessionEventSubscription;
use session_subscriptions::{SessionSenderEntry, subscribe_session_events_impl};
pub use sink_forwarding::{EventSink, forward_to_sink};

// ── MetricsSink ───────────────────────────────────────────────────────────────

/// Prometheus-agnostic metrics surface.
///
/// Implementations may bridge to any metrics backend (Prometheus, StatsD,
/// OpenTelemetry, etc.).  The default no-op implementation discards all
/// observations so that crate users who do not need metrics incur zero overhead.
///
/// All methods take `&self` and must be cheaply callable from hot paths.
/// Implementations are expected to be `Send + Sync`.
pub trait MetricsSink: Send + Sync + std::fmt::Debug {
    /// Increment a counter by `value`.
    ///
    /// `name` follows the convention `asx_<subsystem>_<event>_total` (no suffix
    /// is added by the framework; the caller supplies the full name).
    fn increment_counter(&self, name: &'static str, value: u64, labels: &[(&'static str, &str)]);

    /// Record a single histogram observation (duration in seconds, size in bytes, etc.).
    fn record_histogram(&self, name: &'static str, value: f64, labels: &[(&'static str, &str)]);

    /// Set a gauge to an absolute value.
    fn set_gauge(&self, name: &'static str, value: f64, labels: &[(&'static str, &str)]);
}

const AS4_RECEIPT_TAXONOMY_OUTCOME_TOTAL: &str = "asx_as4_receipt_taxonomy_outcome_total";
const AS4_RECEIPT_TAXONOMY_ALERT_TOTAL: &str = "asx_as4_receipt_taxonomy_alert_total";
const AS4_RECEIPT_TAXONOMY_INCIDENT_FORWARD_TOTAL: &str =
    "asx_as4_receipt_taxonomy_incident_forward_total";
const AS2_PROVIDER_HEALTH_ALERT_TOTAL: &str = "asx_as2_provider_health_alert_total";
const AS2_PROVIDER_HEALTH_INCIDENT_FORWARD_TOTAL: &str =
    "asx_as2_provider_health_incident_forward_total";

/// No-op [`MetricsSink`] that discards all observations.
///
/// Used as the default sink when no metrics backend is configured.
#[derive(Debug, Clone, Default)]
pub struct NoopMetricsSink;

impl MetricsSink for NoopMetricsSink {
    #[inline]
    fn increment_counter(
        &self,
        _name: &'static str,
        _value: u64,
        _labels: &[(&'static str, &str)],
    ) {
    }
    #[inline]
    fn record_histogram(&self, _name: &'static str, _value: f64, _labels: &[(&'static str, &str)]) {
    }
    #[inline]
    fn set_gauge(&self, _name: &'static str, _value: f64, _labels: &[(&'static str, &str)]) {}
}

#[derive(Debug, Default)]
pub struct EventBusMetrics {
    emitted: AtomicU64,
    dropped: AtomicU64,
    lagged: AtomicU64,
    receipt_taxonomy_total: AtomicU64,
    receipt_taxonomy_security_verification_failed: AtomicU64,
    receipt_taxonomy_semantic_interop_failure: AtomicU64,
    provider_health_transition_total: AtomicU64,
    provider_health_transition_to_failing: AtomicU64,
    // Sliding-window counters for backpressure enforcement.
    // `window_epoch` holds the start of the current window as seconds since
    // UNIX_EPOCH.  When the current time advances past `window_epoch + window_secs`,
    // the window resets and `window_dropped`/`window_lagged` restart from zero.
    window_epoch: AtomicU64,
    window_dropped: AtomicU64,
    window_lagged: AtomicU64,
    /// Window width in seconds, copied from `BackpressurePolicy` at bus creation.
    window_secs: u64,
}

impl EventBusMetrics {
    pub fn emitted(&self) -> u64 {
        self.emitted.load(Ordering::Relaxed)
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn lagged(&self) -> u64 {
        self.lagged.load(Ordering::Relaxed)
    }

    fn observe_event(&self, event: &AsxEvent, sink: &dyn MetricsSink) {
        metrics_observation::observe_event(self, event, sink);
    }

    /// Increment `dropped` and return the new per-window count.
    /// When the window boundary has passed, window counters reset before incrementing.
    fn inc_dropped(&self) -> u64 {
        let window_secs = self.window_secs;
        self.dropped.fetch_add(1, Ordering::Relaxed);
        self.window_count_inc(&self.window_dropped, window_secs)
    }

    /// Increment `lagged` (channel-full events) and return the new per-window count.
    fn inc_lagged(&self, n: u64) -> u64 {
        let window_secs = self.window_secs;
        self.lagged.fetch_add(n, Ordering::Relaxed);
        self.window_count_add(&self.window_lagged, n, window_secs)
    }

    /// Advance the window epoch if needed and increment a window counter by 1.
    fn window_count_inc(&self, counter: &AtomicU64, window_secs: u64) -> u64 {
        self.window_count_add(counter, 1, window_secs)
    }

    /// Advance the window epoch if needed and increment a window counter by `n`.
    ///
    /// Memory ordering:
    /// - `window_epoch` CAS uses `AcqRel`/`Acquire`: the winning thread's
    ///   counter resets (Release stores below) synchronise-with subsequent
    ///   `Acquire` reads in losing threads, so they see 0 before their own
    ///   `fetch_add`.
    /// - Counter stores use `Release` so they are visible before any
    ///   `fetch_add` that observes the new epoch.
    /// - Counter `fetch_add` uses `AcqRel` to ensure that losing threads
    ///   observe the epoch-reset `store(0, Release)` before incrementing.
    ///   Using `Relaxed` here would allow a loser's increment to be reordered
    ///   before the epoch-change Release stores, producing window-boundary
    ///   counts that mix old and new windows.
    ///
    /// Residual caveat: increments that were *already executing* in a
    /// different call stack when the window reset fires can be overwritten.
    /// Under burst conditions this bounds the error to at most `O(thread_count)`
    /// counts per window boundary — documented in FINDINGS §4 as acceptable
    /// for backpressure metrics.
    fn window_count_add(&self, counter: &AtomicU64, n: u64, window_secs: u64) -> u64 {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let epoch = self.window_epoch.load(Ordering::Acquire);
        if epoch == 0 {
            // First call — initialise the epoch.
            let _ = self.window_epoch.compare_exchange(
                0,
                now_secs,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        } else if now_secs >= epoch + window_secs {
            // Window expired — try to reset.  Only one winner resets; the rest
            // will land in the freshly-zeroed window once they observe the
            // Release stores from the winner.
            if self
                .window_epoch
                .compare_exchange(epoch, now_secs, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.window_dropped.store(0, Ordering::Release);
                self.window_lagged.store(0, Ordering::Release);
            }
        }
        // AcqRel: the Acquire half synchronises with the winner's Release stores
        // above so this thread sees the zeroed counter before incrementing.
        counter.fetch_add(n, Ordering::AcqRel) + n
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventEmissionMode {
    /// Best-effort emission: dropped broadcast events are tracked in metrics,
    /// but do not fail protocol execution unless backpressure fail-closed
    /// thresholds are exceeded.
    BestEffort,

    /// Transactional strict emission:
    /// - requires at least one active broadcast subscriber
    /// - requires reservable capacity on all per-session subscribers before send
    /// - performs no side effects when preconditions fail
    StrictTransactional,

    /// Audit-fallback strict mode.
    ///
    /// When no broadcast subscriber is present, the event is persisted to the
    /// durable audit sink (if configured) and the call succeeds instead of
    /// failing. This breaks the liveness coupling between the EventBus and
    /// running broadcast subscribers, while preserving full audit durability.
    ///
    /// `StrictWithAuditFallback` requires a configured production-durable audit sink.
    /// Construction fails when no sink is provided.
    ///
    /// Use this mode in regulated deployments where the audit log is the
    /// primary compliance record and subscriber uptime guarantees are
    /// operationally difficult.
    StrictWithAuditFallback,
}

/// What to do when a backpressure threshold is exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackpressureAction {
    /// Increment metrics and continue (default).
    Track,
    /// Return `Err(ReliabilityFailure)` once the threshold is reached.
    FailClosed,
}

/// Policy governing automatic escalation when event-bus saturation is detected.
///
/// `max_dropped` and `max_lagged` are evaluated against a sliding window of
/// `window_secs` seconds.  When the wall clock advances past the current window
/// boundary, the per-window counters reset automatically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackpressurePolicy {
    /// Fail (or track) once this many dropped events occur in the current window.
    pub max_dropped: Option<u64>,
    /// Fail (or track) once this many lagged events occur in the current window.
    pub max_lagged: Option<u64>,
    /// What to do when a threshold is exceeded.
    pub action: BackpressureAction,
    /// Width of the sliding epoch window in seconds. Must be > 0.
    pub window_secs: u64,
    /// Capacity for per-session mpsc queues used by `subscribe_session_events`.
    pub session_channel_capacity: usize,
}

impl Default for BackpressurePolicy {
    fn default() -> Self {
        Self {
            max_dropped: None,
            max_lagged: None,
            action: BackpressureAction::Track,
            window_secs: 60,
            session_channel_capacity: 64,
        }
    }
}

impl BackpressurePolicy {
    /// Conservative defaults for regulated deployments.
    ///
    /// - Any dropped event in a window is treated as reliability failure.
    /// - Lagging is tolerated up to a bounded threshold before failing closed.
    #[must_use]
    pub fn regulated() -> Self {
        Self {
            max_dropped: Some(1),
            max_lagged: Some(64),
            action: BackpressureAction::FailClosed,
            window_secs: 60,
            session_channel_capacity: 128,
        }
    }
}

/// Input parameters for sizing `EventBus` channel capacities.
///
/// The recommendation models a bounded burst backlog during subscriber pauses:
///
/// `required_backlog = ceil(peak_events_per_sec * max_subscriber_pause_ms / 1000)`
///
/// A caller-controlled burst multiplier and fixed headroom are then applied to
/// reduce the risk of transient lag in real deployments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventBusCapacitySizingInput {
    /// Peak sustained events emitted per second.
    pub peak_events_per_sec: u64,
    /// Longest tolerated subscriber pause (GC, scheduler stall, I/O blip), in milliseconds.
    pub max_subscriber_pause_ms: u64,
    /// Extra burst multiplier applied after pause-derived backlog (minimum effective value is 1).
    pub burst_multiplier: u64,
}

/// Recommended capacities for constructing `EventBus` and `BackpressurePolicy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventBusCapacityRecommendation {
    /// Recommended `EventBus::new(capacity)` broadcast ring size.
    pub broadcast_capacity: usize,
    /// Recommended `BackpressurePolicy::session_channel_capacity` value.
    pub session_channel_capacity: usize,
}

#[inline]
fn ceil_div_u128(numerator: u128, denominator: u128) -> u128 {
    numerator.div_ceil(denominator)
}

/// Recommend channel capacities for deployment-specific event rates.
///
/// This helper is intentionally conservative and deterministic:
/// - computes a pause backlog from peak rate and tolerated pause
/// - multiplies by `burst_multiplier` (min 1)
/// - adds 25% headroom
/// - enforces minimum floors (`16` broadcast, `64` per-session)
///
/// Example:
///
/// ```
/// # use asx::observability::{
/// #   BackpressurePolicy, EventBusCapacitySizingInput, recommend_event_bus_capacity,
/// # };
/// let sizing = recommend_event_bus_capacity(EventBusCapacitySizingInput {
///     peak_events_per_sec: 2_000,
///     max_subscriber_pause_ms: 100,
///     burst_multiplier: 2,
/// });
/// let backpressure = BackpressurePolicy {
///     session_channel_capacity: sizing.session_channel_capacity,
///     ..BackpressurePolicy::regulated()
/// };
/// let _ = (sizing.broadcast_capacity, backpressure.session_channel_capacity);
/// ```
#[must_use]
pub fn recommend_event_bus_capacity(
    input: EventBusCapacitySizingInput,
) -> EventBusCapacityRecommendation {
    let peak = u128::from(input.peak_events_per_sec.max(1));
    let pause_ms = u128::from(input.max_subscriber_pause_ms.max(1));
    let burst = u128::from(input.burst_multiplier.max(1));

    let pause_backlog = ceil_div_u128(peak.saturating_mul(pause_ms), 1_000);
    let burst_backlog = pause_backlog.saturating_mul(burst);
    // Add 25% headroom: ceil(burst_backlog * 1.25)
    let with_headroom = ceil_div_u128(burst_backlog.saturating_mul(5), 4);

    let bounded = with_headroom.min(usize::MAX as u128) as usize;
    EventBusCapacityRecommendation {
        broadcast_capacity: bounded.max(16),
        session_channel_capacity: bounded.max(64),
    }
}

#[derive(Clone)]
pub struct EventBus {
    scoped_senders: Arc<DashMap<u64, mpsc::Sender<ScopedAsxEvent>>>,
    next_scoped_subscription_id: Arc<AtomicU64>,
    /// Per-session mpsc senders.  `emit` routes directly to a session's senders
    /// (O(1) lookup) rather than relying on every subscriber to filter a broadcast
    /// (O(N) fan-out).  Dead (closed) senders are pruned lazily on next emit.
    session_senders: Arc<DashMap<String, Vec<SessionSenderEntry>>>,
    next_session_subscription_id: Arc<AtomicU64>,
    metrics: Arc<EventBusMetrics>,
    metrics_sink: Arc<dyn MetricsSink>,
    audit_sink: Option<Arc<dyn DurableAuditSink>>,
    audit_sequence: Arc<AtomicU64>,
    taxonomy_alert_dedup_epoch_secs: Arc<DashMap<String, u64>>,
    emission_mode: EventEmissionMode,
    backpressure: BackpressurePolicy,
    scoped_channel_capacity: usize,
    session_channel_capacity: usize,
}

impl EventBus {
    pub fn metrics(&self) -> Arc<EventBusMetrics> {
        Arc::clone(&self.metrics)
    }

    pub fn emission_mode(&self) -> EventEmissionMode {
        self.emission_mode
    }

    pub fn has_durable_audit_sink(&self) -> bool {
        self.audit_sink.is_some()
    }

    pub fn has_production_durable_audit_sink(&self) -> bool {
        self.audit_sink
            .as_ref()
            .map(|sink| sink.durability() == AuditSinkDurability::Durable)
            .unwrap_or(false)
    }

    /// Returns `true` when this bus is safe to use with `fail_closed_audit_events = true`.
    ///
    /// [`EventEmissionMode::BestEffort`] silently drops events when the broadcast channel is
    /// full. Using it alongside `fail_closed_audit_events = true` (in any `As2ReceivePolicy`
    /// or `As4PushPolicy`) creates a contradiction: the policy requires that audit events are
    /// durable, but the bus may discard them under load without returning an error.
    ///
    /// A bus is **compatible** with fail-closed policies when it uses
    /// [`EventEmissionMode::StrictTransactional`] or
    /// [`EventEmissionMode::StrictWithAuditFallback`].
    ///
    /// # Example
    /// ```
    /// use asx::observability::EventBus;
    ///
    /// let bus = EventBus::new(16).expect("bus");
    /// assert!(bus.is_compatible_with_fail_closed(), "strict mode is fail-closed safe");
    /// ```
    pub fn is_compatible_with_fail_closed(&self) -> bool {
        self.emission_mode != EventEmissionMode::BestEffort
    }

    pub fn subscribe_scoped_events(&self) -> ScopedEventSubscription {
        subscribe_scoped_events_impl(self)
    }

    pub fn subscribe_session_events(
        &self,
        session_id: impl Into<String>,
    ) -> Result<SessionEventSubscription> {
        subscribe_session_events_impl(self, session_id.into())
    }

    /// Close all active sender channels to signal subscribers that no more events
    /// will be emitted.
    ///
    /// # Shutdown sequence
    ///
    /// For a graceful shutdown that ensures all in-flight events are persisted to a
    /// durable audit sink before the process exits, follow these steps:
    ///
    /// 1. Stop accepting new work (refuse new AS2/AS4 connections / messages).
    /// 2. Allow in-flight message processing to complete (wait for active tasks).
    /// 3. Call `event_bus.shutdown()` — this drops all MPSC sender handles, causing
    ///    subscriber `recv()` loops to return `None` once the queue is drained.
    /// 4. Join all subscriber tasks; each subscriber should drain its channel to
    ///    `None` before returning.  If a [`DurableAuditSink`] is configured, all
    ///    events will have been persisted by the time the subscriber exits.
    ///
    /// Dropping the `EventBus` without calling `shutdown()` first is safe — Rust's
    /// drop order ensures the MPSC senders close before the struct is freed — but the
    /// explicit call makes the intent clear and allows structured logging at shutdown
    /// boundaries.
    ///
    /// # No-op idempotency
    ///
    /// Calling `shutdown()` more than once is safe; subsequent calls are no-ops because
    /// the sender maps will already be empty.
    pub fn shutdown(&self) {
        self.scoped_senders.clear();
        self.session_senders.clear();
    }
}

#[cfg(test)]
mod tests;
