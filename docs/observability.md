# Observability

The `observability` module provides structured audit event emission, per-session event routing, configurable backpressure, and a durable audit sink trait for external persistence.

---

## EventBus

`EventBus` is the central fan-out hub for all protocol audit events. Core `as2` and `as4` operations take an `&EventBus` and emit typed `AuditEvent` records as processing proceeds.

```rust
use asx::observability::{BackpressurePolicy, EventBus, EventEmissionMode};

// Strict transactional-by-default bus with 64-event channel depth:
let bus = EventBus::new(64)?;

// Optional explicit best-effort mode for loss-tolerant flows:
let best_effort_bus = EventBus::new_with_config_and_mode(
    64,
    None,
    BackpressurePolicy::default(),
    EventEmissionMode::BestEffort,
)?;
```

Pass the same `EventBus` instance across concurrent sessions so all events flow through a single fan-out point. The bus is clone-safe (`Arc`-backed internally).

In strict default mode, emits are transactional with respect to strict preconditions: the bus requires at least one active scoped or per-session subscriber and pre-reservable capacity for all scoped/per-session queues before send.

---

## Backpressure

Configure backpressure limits with `EventBus::new_with_config_and_mode`:

```rust
use asx::observability::{
    BackpressureAction, BackpressurePolicy, EventBus, EventEmissionMode,
};

let bus = EventBus::new_with_config_and_mode(
    64,
    None,
    BackpressurePolicy {
        max_dropped: Some(100),
        max_lagged: Some(50),
        action: BackpressureAction::FailClosed,
        window_secs: 60,  // sliding window (must be > 0)
        session_channel_capacity: 64,
    },
    EventEmissionMode::StrictTransactional,
)?;
```

| `BackpressureAction` | Behaviour |
|---|---|
| `FailClosed` | `emit_audit_event` returns `Err` when thresholds are exceeded; the error propagates up the receive path |
| `Track` | Saturation is counted but not escalated to a reliability failure |

### Windowed counters

Dropped and lagged counters reset automatically after `window_secs` seconds. This prevents an early burst from permanently latching `FailClosed` in a long-running process.

### High-cardinality incident sizing advisor

For incident webhook/paging channels, use the built-in sizing advisor to derive deterministic queue/timeout/backpressure settings from measured workload signals:

```rust
use asx::{
    IncidentDeliverySizingInput, recommend_incident_delivery_config,
};

let config = recommend_incident_delivery_config(IncidentDeliverySizingInput {
    peak_incidents_per_sec: 300,
    sustained_burst_secs: 4,
    delivery_p99_millis: 180,
    regulated: true,
})?;

assert_eq!(config.queue_capacity, 2048);
assert_eq!(config.request_timeout_secs, 2);
```

Sizing semantics:
1. Queue capacity is projected backlog (`peak_incidents_per_sec * sustained_burst_secs`) rounded up to next power-of-two, with profile bounds.
2. `request_timeout_secs` is derived from `4 * delivery_p99_millis` and clamped to operational limits.
3. Regulated mode uses fail-closed overflow and non-zero wait budget; non-regulated mode uses best-effort drop with zero wait.

---

## Audit Sink Integration

`EventBus::new_with_config_and_mode` can attach a durable sink that persists every event before fan-out:

```rust
use asx::observability::{
    BackpressurePolicy, DurableAuditSink, EventBus, EventEmissionMode,
};
use asx::Result;
use std::sync::Arc;

struct PostgresAuditSink { /* pool */ }

impl DurableAuditSink for PostgresAuditSink {
    fn store_event(&self, event: &asx::observability::AuditEvent) -> Result<()> {
        // INSERT INTO audit_events ...
        todo!()
    }

    fn retrieve_events_from(
        &self,
        cursor: &asx::observability::ReplayCursor,
        limit: usize,
    ) -> Result<Vec<asx::observability::AuditEvent>> {
        // SELECT ... WHERE sequence > cursor.position LIMIT ?
        let _ = (cursor, limit);
        todo!()
    }

    fn acknowledge_cursor(&self, cursor: &asx::observability::ReplayCursor) -> Result<()> {
        let _ = cursor;
        Ok(())
    }

    fn current_cursor(&self) -> Result<asx::observability::ReplayCursor> {
        todo!()
    }

    fn durability(&self) -> asx::observability::AuditSinkDurability {
        asx::observability::AuditSinkDurability::Durable
    }
}

let bus = EventBus::new_with_config_and_mode(
    64,
    Some(Arc::new(PostgresAuditSink { /* ... */ })),
    BackpressurePolicy::default(),
    EventEmissionMode::StrictTransactional,
)?;
```

The sink's `store_event` is called synchronously in the emit hot-path. Keep it fast; delegate to a background writer via an internal channel if latency matters.

`AuditEvent::timestamp` is a `u64` Unix seconds epoch value.

---

## Per-Session Event Routing

Subscribe to events for a single session using `subscribe_session_events`. This uses an `mpsc` channel keyed by `session_id`, giving O(1) delivery to the interested subscriber without broadcasting to all listeners:

```rust
let subscription = bus.subscribe_session_events("sess-acme-001")?;

tokio::spawn(async move {
    while let Some(event) = subscription.recv().await {
        // Only events emitted for session "sess-acme-001"
        println!("{:?}", event);
    }
});
```

Dead subscribers are pruned lazily on the next emit for that session — no explicit teardown needed.

For global fan-out across all sessions (e.g., a metrics collector), use `subscribe_scoped_events`:

```rust
let mut rx = bus.subscribe_scoped_events();

tokio::spawn(async move {
    while let Some(event) = rx.recv().await {
        // all events
        println!("{}", event.event.kind());
    }
});
```

---

## Emit Semantics

| Function | Error behaviour |
|---|---|
| `emit_audit_event` | Fail-closed — returns `Err` if the sink or backpressure policy rejects the event |

Protocol operations use `emit_audit_event` for security-critical events (signature verification, deduplication). Best-effort behavior is available by configuring `EventBus` with `EventEmissionMode::BestEffort` and `BackpressureAction::Track`.

High-level APIs now default to strict subscriber requirements. Use explicit mode constructors (`new_with_config_and_mode`, `new_with_config_and_mode_and_metrics`) with `EventEmissionMode::BestEffort` when subscriber liveness must not gate protocol progress.

---

## AuditEvent Reference

All protocol operations emit a subset of the following events. See [AS2 Protocol Reference](as2.md#audit-events) and [AS4 Protocol Reference](as4.md#audit-events) for per-protocol tables.

```rust
pub struct AuditEvent {
    pub event_type: AuditEventType,
    pub session_id: String,
    pub partner_id: Option<String>,
    pub message_id: Option<String>,
    pub timestamp: u64,             // Unix seconds
    pub details: Option<String>,    // Freeform context (error messages, algorithm names, etc.)
}
```

Common event types:

| Event | Description |
|---|---|
| `OutboundPrepared` | Send path entered |
| `MessageSigned` | Signature applied |
| `MessageEncrypted` | Encryption applied |
| `InboundReceived` | Receive path entered |
| `DuplicateDetected` | Message ID already seen in dedup store |
| `SignatureVerified` | Cryptographic signature check passed |
| `SignatureFailed` | Cryptographic signature check failed |
| `MdnGenerated` | AS2 MDN constructed |
| `MdnReceived` | AS2 MDN parsed from partner |
| `ReceiptGenerated` | AS4 ebMS3 Receipt signal constructed |
| `ReceiptReceived` | AS4 Receipt parsed from partner |
| `PullRequestGenerated` | AS4 Pull request signal constructed |

---

## Metrics

`EventBus` exposes atomic counters via `EventBusMetrics`:

```rust
let metrics = bus.metrics();
println!("emitted: {}", metrics.emitted());
println!("dropped: {}", metrics.dropped());
println!("lagged:  {}", metrics.lagged());
```

These are `AtomicU64` values — safe to read from any thread without acquiring a lock. Expose them to Prometheus or your metrics sink by polling on a background task.

### AS4 receipt taxonomy alert thresholds

Use the built-in evaluator to convert receipt taxonomy counters into SLO-friendly alerts:

```rust
use asx::observability::As4ReceiptTaxonomyAlertPolicy;

let metrics = bus.metrics();
let alerts = metrics.evaluate_as4_receipt_taxonomy_alerts(
    &As4ReceiptTaxonomyAlertPolicy::default(),
);

for alert in alerts {
    println!(
        "{:?} {:?}: {} ppm over {} samples; runbook={} ",
        alert.severity,
        alert.category,
        alert.observed_rate_ppm,
        alert.sample_size,
        alert.runbook_hint,
    );
}
```

Default thresholds:
1. Minimum sample size: 100 receipt taxonomy outcomes.
2. security_verification_failed: warning at 1 percent (10,000 ppm), critical at 5 percent (50,000 ppm).
3. semantic_interop_failure: warning at 0.5 percent (5,000 ppm), critical at 2 percent (20,000 ppm).

Operational runbook mapping:
1. Security verification failures: verify signer trust chain, signature transform parity, and certificate rotation state.
2. Semantic interop failures: verify RefToMessageId correlation rules, parser namespace handling, and partner profile drift.

### Periodic alert export

Convert threshold breaches into exported events and metrics on a periodic loop:

```rust
use asx::core::SessionContext;
use asx::observability::As4ReceiptTaxonomyAlertPolicy;

let sess = SessionContext::new("ops-taxonomy", "ops", "strict")?;
let policy = As4ReceiptTaxonomyAlertPolicy::default();

let alerts = bus.export_as4_receipt_taxonomy_alerts(&sess, &policy, false)?;
for alert in alerts {
    println!(
        "raised {:?} {:?} at {} ppm (n={})",
        alert.severity,
        alert.category,
        alert.observed_rate_ppm,
        alert.sample_size,
    );
}
```

Export side effects:
1. Emits `AsxEvent::ReceiptTaxonomyAlertRaised` for each threshold breach.
2. Increments `asx_as4_receipt_taxonomy_alert_total` with labels `protocol`, `signal`, `severity`, `category`.

### Incident forwarding with dedup keys

Use the forwarding API to send threshold breaches to incident channels with stable dedup keys:

```rust
use asx::observability::{
    As4ReceiptTaxonomyAlertDispatchPolicy, As4ReceiptTaxonomyAlertIncident,
    As4ReceiptTaxonomyAlertPolicy, As4ReceiptTaxonomyIncidentChannel,
};
use asx::core::Result;

#[derive(Debug)]
struct IncidentBackendChannel;

impl As4ReceiptTaxonomyIncidentChannel for IncidentBackendChannel {
    fn send_incident(&self, incident: &As4ReceiptTaxonomyAlertIncident) -> Result<()> {
        // Forward to your incident backend with incident.dedup_key
        let _ = incident;
        Ok(())
    }
}

let incidents = bus.forward_as4_receipt_taxonomy_alerts(
    &sess,
    &As4ReceiptTaxonomyAlertPolicy::default(),
    &As4ReceiptTaxonomyAlertDispatchPolicy {
        interval_secs: 60,
        dedup_cooldown_secs: 300,
    },
    "incident-backend",
    &IncidentBackendChannel,
    true,
)?;

for incident in incidents {
    println!("dedup={} severity={:?}", incident.dedup_key, incident.severity);
}
```

Forwarding side effects:
1. Increments `asx_as4_receipt_taxonomy_incident_forward_total` with labels `protocol`, `channel`, `severity`, `category`, `result`.
2. Uses stable dedup keys such as `as4:receipt-taxonomy:critical:security_verification_failed`.

For fixed cadence operation, run `run_as4_receipt_taxonomy_alert_scheduler(...)` with a shutdown watch channel.

Library scope note:
1. Keep provider-specific adapters in downstream crates or service code.
2. Keep this crate focused on trait contracts, dedup policy, and scheduler orchestration.

### Companion adapter guidance

Use [incident-channel-companion-guidance.md](incident-channel-companion-guidance.md) when building vendor-specific paging/webhook adapters in a companion crate.

It includes:
1. Trait-first adapter patterns for `As4ReceiptTaxonomyIncidentChannel` and `As2ProviderHealthIncidentChannel`.
2. Stable dedup-key templates for AS4 receipt taxonomy and AS2 provider health incidents.
3. Operational guardrails (bounded queueing, best-effort transport, and secret-safe payload mapping).
