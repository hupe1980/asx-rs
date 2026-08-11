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

```rust
pub trait DedupStorage: Send + Sync {
    fn is_durable(&self) -> bool;
    fn cluster_safe(&self) -> bool { false }
    fn first_seen(&self, idempotency_key: &str) -> asx_rs::core::Result<bool>;
}
```

Semantics:

- `Ok(true)`: first occurrence
- `Ok(false)`: duplicate
- `Err(..)`: backend error, fail closed

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
`cluster_safe()` so it passes the strict production startup gate
(`issue_strict_runtime_bootstrap_token`). A minimal PostgreSQL implementation
wraps a connection pool and satisfies the trait as follows:

```rust,ignore
struct PostgresDedupStorage { /* pool, namespace */ }

impl asx_rs::storage::DedupStorage for PostgresDedupStorage {
    fn first_seen<'a>(&'a self, key: &'a str)
        -> futures::future::BoxFuture<'a, asx_rs::core::Result<bool>>
    {
        Box::pin(async move {
            // INSERT ... ON CONFLICT DO NOTHING; RETURNING true-if-inserted
            todo!("run against your pool")
        })
    }
    fn is_durable(&self) -> bool { true }
    fn cluster_safe(&self) -> bool { true }
}
```

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
CREATE TABLE IF NOT EXISTS dedup_keys (
  idempotency_key TEXT PRIMARY KEY,
  first_seen_unix INTEGER NOT NULL
);

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
use asx_rs::storage::{DedupStorage, ReconciliationStorage};
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
    fn first_seen(&self, key: &str) -> Result<bool> {
        let conn = self.conn.lock().map_err(|_| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                "sqlite mutex poisoned",
                ErrorContext::new("sqlite_dedup_first_seen"),
            )
        })?;

        let changed = conn.execute(
            "INSERT OR IGNORE INTO dedup_keys (idempotency_key, first_seen_unix)
             VALUES (?1, strftime('%s','now'))",
            params![key],
        ).map_err(|e| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!("dedup insert failed: {e}"),
                ErrorContext::new("sqlite_dedup_first_seen"),
            )
        })?;

        Ok(changed > 0)
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

## Minimum Test Checklist

1. Dedup survives restart (same idempotency key after restart returns duplicate).
2. Reconciliation queue survives restart and `resolve` removes exactly one key.
3. Audit replay resumes correctly from `ReplayCursor.last_event_id`.
4. Acknowledged cursor is durable across restart.
5. Backend errors fail closed (no implicit `Ok(true)` on uncertainty).

## What This Gives You Today

- A library-first path that does not force gateway coupling.
- A concrete persistence blueprint you can run now.
- Clear migration path to Redis/Postgres once scale requires it.
