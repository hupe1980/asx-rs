+++
title = "Observability"
description = "The event bus, emission modes and backpressure, durable audit sinks, metrics, and how to wire asx-rs into your telemetry stack."
+++

The `observability` module provides structured audit event emission, per-session event routing, configurable backpressure, and a durable audit sink trait for external persistence.

---

## EventBus

`EventBus` is the central fan-out hub for all protocol audit events. Core `as2` and `as4` operations take an `&EventBus` and emit typed `AuditEvent` records as processing proceeds.

```rust
use asx_rs::observability::{BackpressurePolicy, EventBus, EventEmissionMode};

// Strict transactional-by-default bus with 64-event channel depth:
let bus = EventBus::new(64)?;

// Optional explicit best-effort mode for loss-tolerant flows:
let best_effort_bus = EventBus::builder()
    .capacity(64)
    .emission_mode(EventEmissionMode::BestEffort)
    .build()?;
```

Pass the same `EventBus` instance across concurrent sessions so all events flow through a single fan-out point. The bus is clone-safe (`Arc`-backed internally).

In strict default mode, emits are transactional with respect to strict preconditions: the bus requires at least one active scoped or per-session subscriber and pre-reservable capacity for all scoped/per-session queues before send.

---

## Backpressure

Configure backpressure limits on the builder:

```rust
use asx_rs::observability::{BackpressureAction, BackpressurePolicy, EventBus};

let bus = EventBus::builder()
    .capacity(64)
    .backpressure(BackpressurePolicy {
        max_dropped: Some(100),
        max_lagged: Some(50),
        action: BackpressureAction::FailClosed,
        window_secs: 60,  // sliding window (must be > 0)
        session_channel_capacity: 64,
    })
    .build()?;
```

| `BackpressureAction` | Behaviour |
|---|---|
| `FailClosed` | `emit_audit_event` returns `Err` when thresholds are exceeded; the error propagates up the receive path |
| `Track` | Saturation is counted but not escalated to a reliability failure |

### Windowed counters

Dropped and lagged counters reset automatically after `window_secs` seconds. This prevents an early burst from permanently latching `FailClosed` in a long-running process.

---

## Audit Sink Integration

`EventBusBuilder::audit_sink` attaches a durable sink that persists every event before fan-out:

```rust
use asx_rs::observability::{
    BackpressurePolicy, DurableAuditSink, EventBus, EventEmissionMode,
};
use asx_rs::Result;
use std::sync::Arc;

struct PostgresAuditSink { /* pool */ }

impl DurableAuditSink for PostgresAuditSink {
    fn store_event(&self, event: &asx_rs::observability::AuditEvent) -> Result<()> {
        // INSERT INTO audit_events ...
        todo!()
    }

    fn retrieve_events_from(
        &self,
        cursor: &asx_rs::observability::ReplayCursor,
        limit: usize,
    ) -> Result<Vec<asx_rs::observability::AuditEvent>> {
        // SELECT ... WHERE sequence > cursor.position LIMIT ?
        let _ = (cursor, limit);
        todo!()
    }

    fn acknowledge_cursor(&self, cursor: &asx_rs::observability::ReplayCursor) -> Result<()> {
        let _ = cursor;
        Ok(())
    }

    fn current_cursor(&self) -> Result<asx_rs::observability::ReplayCursor> {
        todo!()
    }

    fn durability(&self) -> asx_rs::observability::AuditSinkDurability {
        asx_rs::observability::AuditSinkDurability::Durable
    }
}

let bus = EventBus::builder()
    .capacity(64)
    .audit_sink(Arc::new(PostgresAuditSink { /* ... */ }))
    .build()?;

// Or, for a regulated deployment — this additionally rejects a sink that is not
// production-durable or does not integrity-protect its replay cursor:
let bus = EventBus::new_regulated(64, Arc::new(PostgresAuditSink { /* ... */ }))?;
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

Emission is strict by default. Select `EventEmissionMode::BestEffort` on the
builder when subscriber liveness must not gate protocol progress, or
`StrictWithAuditFallback` — which keeps strictness but persists to the durable
sink instead of failing when no subscriber is live, and is accepted by the
[regulated startup gate](@/docs/getting-started.md#regulated-startup-gate-strict-production).

---

## AuditEvent Reference

All protocol operations emit a subset of the following events. The list below is canonical; [the AS2 reference](@/docs/as2.md#audit-events) additionally maps them to AS2 send and receive stages.

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

### Receipt-taxonomy and provider-health counters

Two counter readouts summarise what the protocol paths classified:

```rust
let metrics = bus.metrics();

let receipts = metrics.as4_receipt_taxonomy_snapshot();
println!(
    "receipts: {} classified, {} security failures, {} interop failures",
    receipts.total,
    receipts.security_verification_failed,
    receipts.semantic_interop_failure,
);

let providers = metrics.as2_provider_health_snapshot();
println!(
    "spool key provider: {} of {} transitions were into `failing`",
    providers.transition_to_failing,
    providers.total_transitions,
);
```

Numbers, not verdicts.

### Where the thresholds live

`asx-rs` ships no alerting engine: no thresholds, no severity grading, no
incident types, no scheduler. Whether a 1 % receipt-verification failure rate is
normal or an incident is a partner-SLA and topology question, and the monitoring
stack you already run answers it better than a library can.

Scrape the counters, or consume `AsxEvent::ReceiptTaxonomyOutcome`, and write
the rule where your other rules live:

```promql
# Page when more than 1% of classified receipts fail verification over 15
# minutes, with a meaningful sample.
(
  sum(rate(asx_as4_receipt_taxonomy_outcome_total{outcome="security_verification_failed"}[15m]))
  /
  sum(rate(asx_as4_receipt_taxonomy_outcome_total[15m]))
) > 0.01
and
sum(increase(asx_as4_receipt_taxonomy_outcome_total[15m])) > 100
```

Metric names are API: renaming one breaks dashboards and alert rules this
repository cannot see.
