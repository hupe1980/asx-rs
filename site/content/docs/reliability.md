+++
title = "Reliability"
description = "Delivery outcome classification, retry decisions, deduplication and replay windows, and reconciliation after partial failure."
+++

## Overview

The `reliability` and `storage` modules provide the infrastructure for exactly-once delivery, retry classification, and reconciliation tracking.

---

## Deduplication

Deduplication is **two-phase**. A key is *claimed* before the message is
processed and *settled* once its fate is known, because a single call that both
records the key and answers cannot express the state that matters: seen, but not
yet known to be handled.

### `DedupStorage` trait

```rust
pub enum DedupVerdict {
    /// First sight. The caller owns an unsettled claim and must settle it.
    Claimed,
    /// A previous attempt was accepted — a genuine replay.
    Duplicate,
    /// Another attempt holds an unsettled claim (a concurrent delivery).
    InFlight,
}

pub trait DedupStorage: Send + Sync {
    fn is_durable(&self) -> bool;
    fn cluster_safe(&self) -> bool { false }

    /// Phase 1: atomically claim the key, or report what already holds it.
    fn claim(&self, key: &str) -> Result<DedupVerdict>;

    /// Phase 2a: the message is durably handled. Replays are now rejected.
    fn accept(&self, key: &str) -> Result<()>;

    /// Phase 2b: the message was NOT handled. Release the key so the sender's
    /// retransmission is processed.
    fn abandon(&self, key: &str) -> Result<()>;
}
```

Protocol functions accept `Arc<dyn DedupStorage>`. Pass the same instance across
all concurrent receive calls for a given session.

`Err` from any method must **fail closed** — a backend that cannot answer must
never be read as "not seen".

### Settling the claim

A first-seen message arrives with an unsettled `DedupClaim`:

```rust
use asx_rs::as4::As4ReceiveOutcome;

match receive_push(&session, &bus, push).await?.into_inner() {
    As4ReceiveOutcome::FirstSeen { output, claim } => {
        match persist_and_dispatch(&output).await {
            // Handled, or durably dead-lettered: it is ours now, and a
            // retransmission must not deliver it a second time.
            Ok(()) => claim.accept().await?,
            // We could not take responsibility for it. Release the key so the
            // sender's retransmission is processed instead of swallowed.
            Err(e) => {
                claim.abandon().await?;
                return Err(e);
            }
        }
        // ... return an AS4 receipt
    }
    As4ReceiveOutcome::Duplicate { .. } => {
        // Already accepted. Return a receipt without re-dispatching — the
        // sender may not have received the first one.
    }
    As4ReceiveOutcome::InFlight { .. } => {
        // A concurrent delivery still holds the claim. Do NOT acknowledge:
        // answer 503 and let ReceptionAwareness retransmit.
    }
    _ => {}
}
```

The caller settles because only the caller knows whether the message was
*handled* — committed with your business transaction, queued, or dead-lettered.
`asx-rs` knows only that it parsed, verified and decrypted.

> **The claim is `#[must_use]`.** Dropping one without settling it holds the
> `eb:MessageId` until the backend's claim lease expires, and every
> retransmission in that window is answered `InFlight`. That is a delay rather
> than a loss, but it is still a bug.

### Claim leases

An unsettled claim must expire, or a process that dies between `claim` and
`accept` wedges that message forever. Size the lease **above** the longest
plausible processing time and **below** the sender's retransmission interval.
The in-tree backends default to 5 minutes:

```rust
use asx_rs::storage::TtlDedupStorage;
use std::time::Duration;

let dedup = Arc::new(
    TtlDedupStorage::new(Duration::from_secs(48 * 3600))
        .with_claim_lease(Duration::from_secs(120)),
);
```

### In-memory backends

```rust
use asx_rs::storage::TtlDedupStorage;
use std::time::Duration;

// The TTL *is* the replay window.
let dedup = Arc::new(TtlDedupStorage::new(Duration::from_secs(48 * 3600)));
```

`TtlDedupStorage` is the only in-tree backend. Memory is bounded by the replay
window rather than by a key count, and expiry is lazy — entries are checked on
access and swept periodically, not on a background thread.

It is in-memory, so the window resets on restart. RFC 4130 §5.2.1 recommends
**48 hours**; for production, implement `DedupStorage` against a persistent
store.

### Implementing a custom backend

The whole `claim` decision — inspect, expire, insert — must be **one atomic
step**. A read followed by a separate write lets two concurrent deliveries of
the same message both claim it.

```rust
use asx_rs::storage::{DedupStorage, DedupVerdict};
use asx_rs::Result;

struct RedisDedupStorage { /* ... */ }

impl DedupStorage for RedisDedupStorage {
    fn is_durable(&self) -> bool { true }
    fn cluster_safe(&self) -> bool { true }

    fn claim(&self, key: &str) -> Result<DedupVerdict> {
        // SET key "inflight" NX EX <lease>  -> Claimed when created.
        // Otherwise GET decides Duplicate ("accepted") vs InFlight.
        todo!()
    }

    fn accept(&self, key: &str) -> Result<()> {
        // SET key "accepted" EX <ttl>   (overwrites our own claim)
        todo!()
    }

    fn abandon(&self, key: &str) -> Result<()> {
        // DEL key, but only while it is still "inflight" — an accepted key
        // must survive a late abandon.
        todo!()
    }
}
```

Verify it with `asx_rs::storage::conformance::DedupConformance`, which races
concurrent claims and checks each settlement rule. See
[Testing](@/docs/testing.md).

---

## Reconciliation

### `ReconciliationStorage` trait

```rust
pub trait ReconciliationStorage: Send + Sync {
    fn enqueue(&self, request: ReconciliationRequest) -> Result<bool>;
    fn queued_requests(&self) -> Result<Vec<ReconciliationRequest>>;
    fn resolve(&self, idempotency_key: &str) -> Result<bool>;
}
```

`ReconciliationRequest` records an outbound message that has not yet received a confirmed delivery outcome:

```rust
pub struct ReconciliationRequest {
    pub idempotency_key: String,
    pub message_id: String,
    pub partner_id: String,
    pub reason: ReconciliationReason,
}

pub enum ReconciliationReason {
    Indeterminate,
    PendingVerification,
}
```

### In-memory reconciliation storage

```rust
use asx_rs::storage::InMemoryReconciliationStorage;

// Unbounded:
let reconciliation = Arc::new(InMemoryReconciliationStorage::default());

// With a hard cap to prevent unbounded growth:
let reconciliation = Arc::new(InMemoryReconciliationStorage::with_capacity(10_000));
```

`with_capacity` enforces a maximum queue size. `enqueue` fails closed when the cap is reached, returning `Err(AsxError)`.

`resolve(key)` removes the entry from the queue and returns `Ok(true)` if the key was found, `Ok(false)` if not. Resolved keys are retained in a separate `seen` set to prevent re-queueing of already-processed messages.

---

## Retry Orchestration

### ⚠ Retry orchestration is the embedder's responsibility

ASX classifies delivery outcomes and provides the primitives for safe retry orchestration, but it **does not run a retry scheduler, circuit breaker, or backoff loop internally**. This is an intentional design decision: retry policy varies widely across regulated industries, partner SLAs, and deployment topologies (single-node vs. multi-replica), and a built-in scheduler would impose unsuitable defaults.

The library's contract is:
1. Return a `DeliveryOutcome` from every send attempt.
2. Provide `RetryDecision` for structured retry classification.
3. Provide `ReconciliationStorage` to persist in-flight messages that require outcome follow-up.
4. Emit `AsxEvent` entries for every state transition (sent, accepted, failed, reconciled) to the `EventBus`.

**The embedder is responsible for:**
- Scheduling retry attempts (backoff timer, delay queue, job scheduler).
- Enforcing a retry budget (maximum attempt count or total elapsed time).
- Implementing a circuit breaker for partners with sustained failure.
- Correlating async MDNs or AS4 receipts to pending `AcceptedPendingVerification` entries.

### Reference retry loop pattern

```rust
use asx_rs::reliability::{DeliveryOutcome, RetryDecision, RetryClass};
use std::time::Duration;
use tokio::time::sleep;

const MAX_ATTEMPTS: u32 = 5;
// Exponential backoff: 1s, 2s, 4s, 8s, 16s
const BASE_DELAY: Duration = Duration::from_secs(1);

async fn send_with_retry(
    ctx: &MyAppContext,
    message: MyMessage,
) -> Result<DeliveryOutcome, MyAppError> {
    let mut attempt = 0u32;
    loop {
        let outcome = ctx.asx_client.send(&message).await?;
        let decision = RetryDecision::from_outcome(&outcome);

        if !decision.should_retry || attempt >= MAX_ATTEMPTS {
            return Ok(outcome);
        }

        attempt += 1;
        // Exponential backoff with jitter (add random 0–500 ms in production).
        let delay = BASE_DELAY * 2u32.saturating_pow(attempt - 1);
        tracing::warn!(
            attempt,
            max = MAX_ATTEMPTS,
            ?delay,
            "Transient delivery failure; retrying"
        );
        sleep(delay).await;
    }
}
```

### Circuit breaker pattern

For high-volume partners, wrap the retry loop in a circuit breaker that opens after N consecutive `Indeterminate` outcomes:

```rust
// Use a crate such as `failsafe` or implement a simple token-bucket yourself.
// The circuit breaker should:
// 1. Open after N consecutive Indeterminate/Transient outcomes.
// 2. Allow a probe attempt after a configurable cool-down (e.g. 30s).
// 3. Close again on a successful SuccessConfirmed outcome.
// 4. Emit an AsxEvent::IncidentOpened / IncidentClosed via your EventBus.
```

### Reconciliation integration

Messages that return `AcceptedPendingVerification` have been accepted by the remote AS2/AS4 endpoint but no synchronous delivery confirmation is available yet. Track them in `ReconciliationStorage`:

```rust
use asx_rs::storage::InMemoryReconciliationStorage;
use asx_rs::reliability::ReconciliationRequest;

let reconciliation = Arc::new(InMemoryReconciliationStorage::with_capacity(50_000));

// After a send that returns AcceptedPendingVerification:
if let Some(request) = ReconciliationRequest::for_outcome(&outcome, &message_id, &partner_id) {
    reconciliation.enqueue(request)?;
}

// When an async MDN or AS4 receipt arrives — correlate and resolve:
reconciliation.resolve(&idempotency_key)?;

// Periodically escalate stale PendingVerification entries:
// (call from a background task every few minutes)
asx_rs::reliability::escalate_stale_pending_reconciliation_requests(
    &*reconciliation,
    Duration::from_secs(300),  // max pending age before escalation to Indeterminate
)?;
```

> **Multi-replica deployments**: `InMemoryReconciliationStorage` is single-process only. For horizontally scaled deployments, implement `ReconciliationStorage` against a persistent, consistent store (Redis with Lua atomics, DynamoDB conditional writes, PostgreSQL advisory locks). See [Persistence How-To](@/docs/persistence.md).

---

## Retry Classification

`RetryDecision::from_outcome` maps a `DeliveryOutcome` to a structured retry decision:

```rust
pub struct RetryDecision {
    pub class: RetryClass,
    pub should_retry: bool,
}

pub enum RetryClass {
    Permanent,
    Indeterminate,
    PendingVerification,
}
```

| `DeliveryOutcome` | `class` | `should_retry` |
|---|---|---|
| `SuccessConfirmed` | `Permanent` | `false` |
| `FailureConfirmed` | `Permanent` | `false` |
| `Indeterminate` | `Indeterminate` | `true` |
| `AcceptedPendingVerification` | `PendingVerification` | `false` |

`AcceptedPendingVerification` means the message was accepted by the transport but an async MDN or receipt has not yet arrived. The caller should track the message ID and correlate against incoming MDNs/receipts before concluding delivery.

---

## Delivery Outcomes

```rust
pub enum DeliveryOutcome {
    SuccessConfirmed,               // Delivery confirmed with matching MIC or disposition
    FailureConfirmed,               // Delivery failed with error disposition or MIC mismatch
    Indeterminate,                  // Outcome unknown; re-reconciliation required
    AcceptedPendingVerification,    // Accepted; awaiting async MDN/receipt
}
```

`ReconciliationRequest::for_outcome` returns `None` for finalized outcomes (`SuccessConfirmed`, `FailureConfirmed`) and `Some(request)` for states requiring follow-up.

---

> **See also:** [Persistence How-To](@/docs/persistence.md) — library-first production persistence pattern with a runnable SQLite adapter skeleton.
>
> **See also:** [Observability](@/docs/observability.md) — `EventBus`, backpressure, per-session event routing, and durable audit sinks.
