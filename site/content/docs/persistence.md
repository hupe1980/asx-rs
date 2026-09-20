+++
title = "Persistence"
description = "Implementing the storage traits — dedup, reconciliation, durable audit, and spool encryption keys — against PostgreSQL, Redis, or your own key manager."
+++

This guide shows how to add production-grade persistence for:

- dedup (`DedupStorage`)
- reconciliation (`ReconciliationStorage`)
- durable audit (`DurableAuditSink`)

without coupling `asx-rs` to a gateway product.

## Why This Is a Library Concern

`asx-rs` is storage-agnostic by design. The core crate defines traits and default in-memory implementations. For production reliability, integrators should provide persistent backends and run restart-safety tests.

This keeps the library modular while still enabling strong delivery guarantees.

## Recommended Near-Term Pattern

1. Implement traits in a dedicated adapter crate or internal module.
2. Use a durable local store first (SQLite) for a zero-infra baseline.
3. Add restart/crash tests before promoting to production.
4. Move to Redis/Postgres if horizontal scale is required.

## Trait Contracts (Current API)

### Dedup

Deduplication is **two-phase**: claim the key before processing, settle it once
the message's fate is durable.

```rust
pub enum DedupVerdict { Claimed, Duplicate, InFlight }

pub trait DedupStorage: Send + Sync {
    fn is_durable(&self) -> bool;
    fn cluster_safe(&self) -> bool { false }
    fn claim(&self, idempotency_key: &str) -> asx_rs::core::Result<DedupVerdict>;
    fn accept(&self, idempotency_key: &str) -> asx_rs::core::Result<()>;
    fn abandon(&self, idempotency_key: &str) -> asx_rs::core::Result<()>;
}
```

Semantics:

- `claim` → `Claimed`: first sight; the caller owns an unsettled claim
- `claim` → `Duplicate`: a previous attempt was **accepted** — a genuine replay
- `claim` → `InFlight`: another attempt holds an unsettled claim
- `accept`: the message is durably handled; replays rejected for the TTL window
- `abandon`: the message was **not** handled; release the key
- `Err(..)`: backend error, fail closed

Four rules a backend must satisfy, all of them checked by `DedupConformance`:

1. **`claim` is one atomic step.** Inspect, expire and insert in a single
   conditional write (`INSERT … ON CONFLICT DO NOTHING`, `SET NX`). A
   `SELECT`-then-`INSERT` admits duplicates the moment two replicas race.
2. **An unsettled claim reports `InFlight`, never `Duplicate`.** Collapsing them
   acknowledges a concurrent delivery as handled while the first attempt can
   still fail.
3. **`abandon` releases only an unsettled claim.** An already-accepted key must
   survive a late abandon, or a processed message is delivered twice.
4. **An unsettled claim expires.** Record a lease; treat an expired claim as
   absent. Without it, a process that dies mid-handling wedges that
   `eb:MessageId` forever.

### Reconciliation

```rust
pub trait ReconciliationStorage: Send + Sync {
    fn is_durable(&self) -> bool;
    fn cluster_safe(&self) -> bool { false }
    fn enqueue(&self, request: ReconciliationRequest) -> asx_rs::core::Result<bool>;
    fn queued_requests(&self) -> asx_rs::core::Result<Vec<ReconciliationRequest>>;
    fn resolve(&self, idempotency_key: &str) -> asx_rs::core::Result<bool>;
}
```

## Durable, cluster-safe backends are consumer-supplied

`asx-rs` deliberately ships **no** database-backed storage. `DedupStorage`,
`ReconciliationStorage`, `DurableAuditSink`, and `SpoolEncryptionKeyProvider`
are the integration boundary — you implement them against your own store
(PostgreSQL, Redis, DynamoDB, SQLite, …) or key manager. The only in-tree
implementations are the in-memory / static ones, which are for testing and
single-process use.

### Spool encryption keys

Profiles that mandate an encrypted payload spool (PEPPOL, CEF, BDEW) need a key.
`As2ReceivePolicy::spool_key_provider` supplies it, and those receives **fail
closed** when it is unset rather than spooling in the clear.

Through 0.12.0 this crate shipped its own KMS/HSM HTTP client — twenty-eight
environment variables, mTLS, retry/backoff, a circuit breaker — that spoke a
JSON contract (`{"key_hex","key_hmac_b64"}`) no real key manager implements. It
only ever worked against a bespoke shim, and the trait that would have let you
skip the shim was private. All of it is gone.

Implement the trait against your own SDK:

```rust
use asx_rs::as2::SpoolEncryptionKeyProvider;

#[derive(Debug)]
struct KmsSpoolKey { client: aws_sdk_kms::Client, key_id: String }

impl SpoolEncryptionKeyProvider for KmsSpoolKey {
    fn label(&self) -> &'static str { "aws-kms" }

    fn resolve_key(&self, _session: &SessionContext) -> Result<Arc<[u8; 32]>> {
        // Cache this — resolve_key is called whenever a receive decides to spool.
        Ok(Arc::clone(&self.cached))
    }
}
```

For development, or when an orchestrator injects the key as a secret:

```rust
use asx_rs::as2::StaticSpoolKey;

let policy = As2ReceivePolicyBuilder::new()
    .spool_key_provider(Arc::new(StaticSpoolKey::from_env("MY_APP_SPOOL_KEY")?))
    .build();
```

`StaticSpoolKey` resolves eagerly, so a missing or malformed key fails at
startup rather than on the first large inbound message. An all-zero key is
rejected outright: that is what an unset or truncated secret looks like, and it
would "encrypt" a regulated spool while protecting nothing.

A durable backend must return `true` from both `is_durable()` and
`cluster_safe()` so it passes the [strict production startup
gate](@/docs/getting-started.md#regulated-startup-gate-strict-production).

Those two methods are **self-declarations**: the gate checks that you made a
claim, not that the claim is true. What actually establishes it is the
[test checklist](#minimum-test-checklist) below — run it against your backend.

A minimal PostgreSQL implementation wraps a connection pool and satisfies the
trait as follows:

```rust,ignore
struct PostgresDedupStorage { /* pool, namespace */ }

impl asx_rs::storage::DedupStorage for PostgresDedupStorage {
    fn is_durable(&self) -> bool { true }
    fn cluster_safe(&self) -> bool { true }

    fn claim<'a>(&'a self, key: &'a str)
        -> futures::future::BoxFuture<'a, asx_rs::core::Result<DedupVerdict>>
    {
        Box::pin(async move {
            // One statement, so two replicas cannot both claim:
            //
            //   INSERT INTO dedup_keys (idempotency_key, state, expires_at)
            //   VALUES ($1, 'inflight', now() + $2)
            //   ON CONFLICT (idempotency_key) DO UPDATE
            //     SET state = 'inflight', expires_at = now() + $2
            //     WHERE dedup_keys.expires_at <= now()   -- only a dead lease
            //   RETURNING state;
            //
            // A row back => Claimed. No row => SELECT state to tell
            // Duplicate ('accepted') from InFlight ('inflight').
            todo!("run against your pool")
        })
    }

    fn accept<'a>(&'a self, key: &'a str)
        -> futures::future::BoxFuture<'a, asx_rs::core::Result<()>>
    {
        Box::pin(async move {
            //   INSERT INTO dedup_keys (idempotency_key, state, expires_at)
            //   VALUES ($1, 'accepted', now() + $2)
            //   ON CONFLICT (idempotency_key) DO UPDATE
            //     SET state = 'accepted', expires_at = now() + $2;
            //
            // Unconditional, so settlement stays idempotent under retry.
            todo!()
        })
    }

    fn abandon<'a>(&'a self, key: &'a str)
        -> futures::future::BoxFuture<'a, asx_rs::core::Result<()>>
    {
        Box::pin(async move {
            //   DELETE FROM dedup_keys
            //   WHERE idempotency_key = $1 AND state = 'inflight';
            //
            // The state predicate is load-bearing: without it a late abandon
            // reopens a message that really was processed.
            todo!()
        })
    }
}
```

**Commit the accept with your business transaction.** That is the whole reason
this trait is yours rather than ours: a message that is business-committed and
dedup-accepted in *different* transactions has a window where a crash loses one
of them.

The reference SQL schema below is a starting point for such an implementation.

### Durable Audit

```rust
pub trait DurableAuditSink: Send + Sync {
    fn store_event(&self, event: &AuditEvent) -> Result<()>;
    fn retrieve_events_from(&self, cursor: &ReplayCursor, limit: usize) -> Result<Vec<AuditEvent>>;
    fn current_cursor(&self) -> Result<ReplayCursor>;
    fn acknowledge_cursor(&self, cursor: &ReplayCursor) -> Result<()>;
    fn clear(&self) -> Result<()>;
}
```

## SQLite Schema (Reference)

```sql
-- `state` is what makes the protocol two-phase: 'inflight' is a claim nobody
-- has settled yet, 'accepted' is a message someone took responsibility for.
-- `expires_at` is the claim lease for 'inflight' and the replay window for
-- 'accepted' — an expired row of either kind is treated as absent.
CREATE TABLE IF NOT EXISTS dedup_keys (
  idempotency_key TEXT PRIMARY KEY,
  state           TEXT NOT NULL CHECK (state IN ('inflight','accepted')),
  claimed_at_unix INTEGER NOT NULL,
  expires_at_unix INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS dedup_keys_expiry ON dedup_keys (expires_at_unix);

CREATE TABLE IF NOT EXISTS reconciliation_queue (
  idempotency_key TEXT PRIMARY KEY,
  message_id TEXT NOT NULL,
  partner_id TEXT NOT NULL,
  queued_at INTEGER NOT NULL,
  retry_count INTEGER NOT NULL,
  last_attempt INTEGER
);

CREATE TABLE IF NOT EXISTS audit_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  session_id TEXT,
  partner_id TEXT,
  code TEXT NOT NULL,
  timestamp INTEGER NOT NULL,
  message TEXT NOT NULL,
  metadata_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_ack (
  singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
  last_event_id TEXT NOT NULL,
  position INTEGER NOT NULL,
  last_timestamp INTEGER NOT NULL
);

INSERT OR IGNORE INTO audit_ack (singleton_id, last_event_id, position, last_timestamp)
VALUES (1, '0', 0, 0);
```

## Running Example Skeleton (SQLite + rusqlite)

```rust,ignore
use asx_rs::core::{AsxError, ErrorCode, ErrorContext, Result};
use asx_rs::observability::audit_sink::{AuditEvent, DurableAuditSink, ReplayCursor};
use asx_rs::reliability::ReconciliationRequest;
use asx_rs::storage::{DedupStorage, DedupVerdict, ReconciliationStorage};
use rusqlite::{params, Connection};
use std::sync::Mutex;

pub struct SqliteReliabilityStore {
    conn: Mutex<Connection>,
}

impl SqliteReliabilityStore {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path).map_err(|e| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!("sqlite open failed: {e}"),
                ErrorContext::new("sqlite_open"),
            )
        })?;

        // execute schema here
        Ok(Self { conn: Mutex::new(conn) })
    }
}

impl DedupStorage for SqliteReliabilityStore {
    fn is_durable(&self) -> bool { true }

    fn claim(&self, key: &str) -> Result<DedupVerdict> {
        let conn = self.lock("sqlite_dedup_claim")?;

        // One statement: take the key when it is absent, or when the row that
        // is there has expired (a dead claim lease, or a replay window that
        // has run out). `WHERE excluded...` is how SQLite expresses the
        // conditional part of the upsert.
        let claimed = conn.execute(
            "INSERT INTO dedup_keys
                 (idempotency_key, state, claimed_at_unix, expires_at_unix)
             VALUES (?1, 'inflight', strftime('%s','now'), strftime('%s','now') + ?2)
             ON CONFLICT (idempotency_key) DO UPDATE SET
                 state           = 'inflight',
                 claimed_at_unix = strftime('%s','now'),
                 expires_at_unix = strftime('%s','now') + ?2
             WHERE dedup_keys.expires_at_unix <= strftime('%s','now')",
            params![key, self.claim_lease_secs],
        ).map_err(|e| self.err("sqlite_dedup_claim", e))?;

        if claimed > 0 {
            return Ok(DedupVerdict::Claimed);
        }

        // Not claimed: a live row is already there. Which kind decides whether
        // this is a replay or a race, and the two get opposite answers.
        let state: String = conn.query_row(
            "SELECT state FROM dedup_keys WHERE idempotency_key = ?1",
            params![key],
            |row| row.get(0),
        ).map_err(|e| self.err("sqlite_dedup_claim", e))?;

        Ok(match state.as_str() {
            "accepted" => DedupVerdict::Duplicate,
            _ => DedupVerdict::InFlight,
        })
    }

    fn accept(&self, key: &str) -> Result<()> {
        let conn = self.lock("sqlite_dedup_accept")?;
        // Unconditional, so a retried settlement is not an error.
        conn.execute(
            "INSERT INTO dedup_keys
                 (idempotency_key, state, claimed_at_unix, expires_at_unix)
             VALUES (?1, 'accepted', strftime('%s','now'), strftime('%s','now') + ?2)
             ON CONFLICT (idempotency_key) DO UPDATE SET
                 state           = 'accepted',
                 expires_at_unix = strftime('%s','now') + ?2",
            params![key, self.replay_window_secs],
        ).map_err(|e| self.err("sqlite_dedup_accept", e))?;
        Ok(())
    }

    fn abandon(&self, key: &str) -> Result<()> {
        let conn = self.lock("sqlite_dedup_abandon")?;
        // `AND state = 'inflight'` is load-bearing: a late abandon must not
        // reopen a message that was genuinely accepted.
        conn.execute(
            "DELETE FROM dedup_keys
             WHERE idempotency_key = ?1 AND state = 'inflight'",
            params![key],
        ).map_err(|e| self.err("sqlite_dedup_abandon", e))?;
        Ok(())
    }
}

impl ReconciliationStorage for SqliteReliabilityStore {
    fn enqueue(&self, req: ReconciliationRequest) -> Result<bool> {
        let conn = self.conn.lock().map_err(|_| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                "sqlite mutex poisoned",
                ErrorContext::new("sqlite_reconciliation_enqueue"),
            )
        })?;

        let changed = conn.execute(
            "INSERT OR IGNORE INTO reconciliation_queue
             (idempotency_key, message_id, partner_id, queued_at, retry_count, last_attempt)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                req.idempotency_key,
                req.message_id,
                req.partner_id,
                req.queued_at,
                req.retry_count,
                req.last_attempt,
            ],
        ).map_err(|e| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!("reconciliation enqueue failed: {e}"),
                ErrorContext::new("sqlite_reconciliation_enqueue"),
            )
        })?;

        Ok(changed > 0)
    }

    fn queued_requests(&self) -> Result<Vec<ReconciliationRequest>> {
        // SELECT and map rows -> ReconciliationRequest
        todo!()
    }

    fn resolve(&self, key: &str) -> Result<bool> {
        let conn = self.conn.lock().map_err(|_| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                "sqlite mutex poisoned",
                ErrorContext::new("sqlite_reconciliation_resolve"),
            )
        })?;

        let changed = conn.execute(
            "DELETE FROM reconciliation_queue WHERE idempotency_key = ?1",
            params![key],
        ).map_err(|e| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!("reconciliation resolve failed: {e}"),
                ErrorContext::new("sqlite_reconciliation_resolve"),
            )
        })?;

        Ok(changed > 0)
    }
}

impl DurableAuditSink for SqliteReliabilityStore {
    fn store_event(&self, event: &AuditEvent) -> Result<()> {
        // INSERT event row, fail closed on error
        todo!()
    }

    fn retrieve_events_from(&self, cursor: &ReplayCursor, limit: usize) -> Result<Vec<AuditEvent>> {
        // Use last_event_id anchor semantics, not raw index-only replay
        todo!()
    }

    fn current_cursor(&self) -> Result<ReplayCursor> {
        todo!()
    }

    fn acknowledge_cursor(&self, cursor: &ReplayCursor) -> Result<()> {
        // UPSERT audit_ack singleton row
        todo!()
    }

    fn clear(&self) -> Result<()> {
        todo!()
    }
}
```

## Wiring Into ASX Flows

- Pass your `SqliteReliabilityStore` as `&dyn DedupStorage` and `&dyn ReconciliationStorage` to receive/reconcile paths.
- Configure `EventBus::new_with_audit_sink` with `Some(Arc<dyn DurableAuditSink>)`.
- Keep one shared store instance per process.

## Conformance kit (run this against your backend)

`is_durable()` and `cluster_safe()` are self-declarations: the startup gate can
only check that you made a claim. `asx_rs::storage::conformance` (behind the
`testing` feature) is what establishes it. Implement one trait — a factory that
hands out a **fresh handle onto the same store** — and run the suite:

```rust
use asx_rs::storage::conformance::{DedupConformance, StorageFactory};
use asx_rs::storage::DedupStorage;
use std::sync::Arc;

struct PostgresDedupFactory { pool: PgPool }

impl StorageFactory<dyn DedupStorage> for PostgresDedupFactory {
    // A new connection, not a clone of one in-memory map — the reconnect
    // checks are vacuous otherwise.
    fn connect(&self) -> Arc<dyn DedupStorage> {
        Arc::new(PostgresDedupStorage::new(self.pool.clone()))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn our_dedup_backend_conforms() {
    let report = DedupConformance::new(&PostgresDedupFactory { pool }).run().await;
    assert!(report.passed(), "{report}");
}
```

What it establishes:

| Check | Why it is in the suite |
|---|---|
| Claimable once, `Duplicate` after `accept` | The basic replay guarantee |
| Distinct keys are independent | Catches key-namespace collisions |
| **An unsettled claim reports `InFlight`, not `Duplicate`** | The failure that loses messages. A backend that collapses the two acknowledges a concurrent delivery as already handled while the first attempt can still fail |
| **`abandon` releases the key** | Without it, every failed dispatch becomes a permanently unreceivable message — the recovery path silently absent |
| **`abandon` never reopens an accepted key** | The mirror image: a late abandon that reopens a processed message hands the business document to the application twice |
| `accept` is idempotent | Settlement is retried after a transient failure, so applying it twice must not error or reopen the key |
| **The backend answers from a blocking context** | The AS4 receive pipeline runs inside `spawn_blocking`. A network-backed store yields, and must be driven to completion there |
| **`claim` is atomic under concurrency** | The one that matters. A `SELECT`-then-`INSERT` backend passes every serial test and admits duplicate business documents the moment two replicas process one message. The suite races 16 tasks for one key and requires exactly one `Claimed` |
| **State survives a reconnect** | A durable backend must answer the same through a fresh handle. Skipped, not failed, when the backend declares `is_durable() == false` — losing state is then correct |
| `cluster_safe()` implies `is_durable()` | A store shared across replicas is out of process by definition |

`AuditSinkConformance` covers the audit trail the same way:

```rust
use asx_rs::storage::conformance::AuditSinkConformance;

#[tokio::test]
async fn our_audit_sink_conforms() {
    let report = AuditSinkConformance::new(&PostgresAuditFactory { pool }).run().await;
    assert!(report.passed(), "{report}");
}
```

| Audit-sink check | Why it is in the suite |
|---|---|
| A stored event is readable | A trail that accepts writes it cannot produce as evidence |
| **Replay resumes from the cursor** | A sink that re-delivers the whole log on reconnect makes a consumer process the trail twice after a restart |
| The cursor advances as events are stored | Otherwise a consumer cannot tell that new evidence exists |
| **State survives a reconnect** | A sink declared `Durable` that keeps the trail in process memory |
| **A tampered cursor is refused** | A cursor is a claim about how far a consumer has read. If it can be forged, so can that claim. Skipped when the sink declares no integrity protection |

`ReconciliationConformance` covers the queue: enqueue is visible, `resolve`
removes exactly one record and leaves the others, an unknown key returns
`Ok(false)` rather than an error, and the queue survives a reconnect.

Each suite's own tests require the broken cases to fail — a backend that lies
about durability, one that races `claim`, one that forgets on reconnect,
one that accepts a forged cursor.

The report is a value, not a panic — print it and every check appears with its
id and, on failure, what went wrong and usually how to fix it.

**What it cannot prove:** durability across a real crash or a power loss. A
fresh handle is as close as a library can get, and the module says so rather
than implying otherwise.

## Minimum test checklist

The suite covers 1–2 and the atomicity property. The audit-sink items are still
yours to check:

1. Dedup survives restart (same idempotency key after restart returns duplicate).
2. Reconciliation queue survives restart and `resolve` removes exactly one key.
3. Audit replay resumes correctly from `ReplayCursor.last_event_id`.
4. Acknowledged cursor is durable across restart.
5. Backend errors fail closed (no implicit `Ok(true)` on uncertainty).

## What This Gives You Today

- A library-first path that does not force gateway coupling.
- A concrete persistence blueprint you can run now.
- Clear migration path to Redis/Postgres once scale requires it.
