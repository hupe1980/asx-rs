# Reliability

## Overview

The `reliability` and `storage` modules provide the infrastructure for exactly-once delivery, retry classification, and reconciliation tracking.

---

## Deduplication

### `DedupStorage` trait

```rust
pub trait DedupStorage: Send + Sync {
    /// Attempt to record the key as seen. Returns Ok(true) if first time seen,
    /// Ok(false) if duplicate. Implementations must be safe for concurrent use.
    fn first_seen(&self, key: &str) -> Result<bool>;
}
```

Protocol functions accept `Arc<dyn DedupStorage>`. Pass the same instance across all concurrent receive calls for a given session to enforce deduplication correctly.

### In-memory dedup

```rust
use asx::storage::InMemoryDedupStorage;

let dedup = Arc::new(InMemoryDedupStorage::default());
```

`InMemoryDedupStorage` uses a `Mutex<HashSet<String>>`. It is correct under concurrent access but does **not** persist across process restarts. All previously-seen message IDs are forgotten on restart. For production deployments requiring replay protection across restarts, implement `DedupStorage` against a persistent store (Redis, DynamoDB, PostgreSQL).

### TTL-aware dedup

```rust
use asx::storage::TtlDedupStorage;
use std::time::Duration;

// Expire entries after 48 hours (RFC 4130 §5.2.1 recommended window):
let dedup = Arc::new(TtlDedupStorage::new(Duration::from_secs(48 * 3600)));
```

`TtlDedupStorage` wraps `InMemoryDedupStorage` with lazy per-entry expiry based on `first_seen` timestamp. Entries older than the TTL are treated as unseen (first occurrence accepted again). Expiry is lazy — entries are not evicted on a background thread; they are checked on next access.

> **Production note:** `TtlDedupStorage` is still in-memory. For replay protection across process restarts, plug in a persistent backend. The minimum recommended window is 48 hours per RFC 4130 §5.2.1.

### Implementing a custom backend

```rust
use asx::storage::DedupStorage;
use asx::Result;

struct RedisDedupStorage { /* ... */ }

impl DedupStorage for RedisDedupStorage {
    fn first_seen(&self, key: &str) -> Result<bool> {
        // SET NX + EXPIRE in Redis
        todo!()
    }
}
```

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
use asx::storage::InMemoryReconciliationStorage;

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
use asx::reliability::{DeliveryOutcome, RetryDecision, RetryClass};
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
use asx::storage::InMemoryReconciliationStorage;
use asx::reliability::ReconciliationRequest;

let reconciliation = Arc::new(InMemoryReconciliationStorage::with_capacity(50_000));

// After a send that returns AcceptedPendingVerification:
if let Some(request) = ReconciliationRequest::for_outcome(&outcome, &message_id, &partner_id) {
    reconciliation.enqueue(request)?;
}

// When an async MDN or AS4 receipt arrives — correlate and resolve:
reconciliation.resolve(&idempotency_key)?;

// Periodically escalate stale PendingVerification entries:
// (call from a background task every few minutes)
asx::reliability::escalate_stale_pending_reconciliation_requests(
    &*reconciliation,
    Duration::from_secs(300),  // max pending age before escalation to Indeterminate
)?;
```

> **Multi-replica deployments**: `InMemoryReconciliationStorage` is single-process only. For horizontally scaled deployments, implement `ReconciliationStorage` against a persistent, consistent store (Redis with Lua atomics, DynamoDB conditional writes, PostgreSQL advisory locks). See [Persistence How-To](persistence-howto.md).

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

> **See also:** [Persistence How-To](persistence-howto.md) — library-first production persistence pattern with a runnable SQLite adapter skeleton.
>
> **See also:** [Observability](observability.md) — `EventBus`, backpressure, per-session event routing, and durable audit sinks.
