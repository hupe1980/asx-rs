+++
title = "Persistence"
description = "Implementing a durable DedupStore and AuditSink, and checking them with the testkit conformance suites."
+++

The library keeps no state between requests. Two stores are yours, each a
trait with a conformance suite in `asx::testkit`:

- **[`DedupStore`](https://docs.rs/asx-rs/latest/asx/trait.DedupStore.html)**
  decides whether an inbound message is new;
- **[`AuditSink`](https://docs.rs/asx-rs/latest/asx/trait.AuditSink.html)**
  keeps the evidence of every exchange leg.

## Duplicate detection: claim, then accept or abandon

Every target profile requires duplicate detection (AS4 §3.2, eDelivery 1.15
§3.3.2, BDEW §2.2.5, RFC 4130 §9.3). After a message verified and decrypted,
the `Inbound` calls:

1. `claim(key)`, which returns one of
   - `Claim::Claimed(token)`: the handler runs;
   - `Claim::Duplicate`: already accepted, answered with a fresh receipt or a
     `duplicate-document` MDN;
   - `Claim::InFlight`: another delivery holds an unexpired lease, answered 503.
2. then exactly one of `accept(key, &token)` (handler `Ok`, audit record
   written) or `abandon(key, &token)` (handler `Err` or panic, audit failure).

The contract, as the testkit checks it:

| Rule | Why |
|---|---|
| `claim` is atomic: of concurrent claims for one key, exactly one wins | `SELECT`-then-`INSERT` admits duplicates under load |
| each successful claim carries a fresh token, never reused for the key | a token must never match a later lease |
| an unsettled claim expires (a lease), then the key can be claimed again | a crashed handler must not block the message forever |
| `accept` and `abandon` succeed only if the token is the key's current lease (compare-and-set), else `Err` | a slow handler whose lease was re-claimed must not settle |
| `abandon` never reopens an accepted key | a late refusal must not admit a replay |
| an accepted key is remembered for at least 24 hours | inbound `eb:Timestamp` is accepted up to 24 hours back |
| infrastructure failure returns `Err` | fail closed: HTTP 500, no receipt, the sender retries |

Keys are opaque 64-character lowercase hex digests of
`("asx-dedup-v1", protocol, sender type, sender id, message id)`, stable
across releases.

### `MemoryDedup` is not durable

`MemoryDedup::default()` keeps claims in process memory (lease 5 minutes,
retention 24 hours). After a restart, or behind a load balancer, a
retransmission is delivered again. Use it for tests, examples and
single-process deployments with idempotent handlers.

### Implementing a durable store

One table and four statements:

```text
CREATE TABLE asx_dedup (
  key         TEXT PRIMARY KEY,
  token       TEXT,          -- the current lease, NULL once accepted
  state       TEXT NOT NULL, -- 'claimed' | 'accepted'
  lease_until TIMESTAMP,
  accepted_at TIMESTAMP
);

claim:   INSERT … ON CONFLICT (key) DO UPDATE SET token = :new, lease_until = :lease
           WHERE asx_dedup.state = 'claimed' AND asx_dedup.lease_until < now()
         -- 1 row: Claimed(new); else read the row: 'accepted' → Duplicate, 'claimed' → InFlight
accept:  UPDATE asx_dedup SET state = 'accepted', token = NULL, accepted_at = now()
           WHERE key = :key AND state = 'claimed' AND token = :token   -- 0 rows → Err
abandon: DELETE FROM asx_dedup WHERE key = :key AND state = 'claimed' AND token = :token  -- 0 rows → Err
expire:  DELETE FROM asx_dedup WHERE state = 'accepted' AND accepted_at < now() - interval '24 hours'
```

The same logic over a `Mutex<HashMap>`, compiled so the trait shape is exact
(a real store also expires accepted rows and reads time from the database):

```rust
use asx::{BoxFuture, Claim, ClaimToken, DedupStore};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
enum Row {
    Claimed { token: String, lease_until: Instant },
    Accepted,
}

#[derive(Debug, Default)]
struct TableDedup {
    rows: Mutex<HashMap<String, Row>>,
}

const LEASE: Duration = Duration::from_secs(300);

impl DedupStore for TableDedup {
    fn claim<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Claim, BoxError>> {
        Box::pin(async move {
            let mut rows = self.rows.lock().map_err(|_| "poisoned")?;
            let now = Instant::now();
            match rows.get(key) {
                Some(Row::Accepted) => return Ok(Claim::Duplicate),
                Some(Row::Claimed { lease_until, .. }) if *lease_until > now => return Ok(Claim::InFlight),
                _ => {}
            }
            let token = uuid::Uuid::new_v4().to_string(); // fresh per claim
            rows.insert(key.to_owned(), Row::Claimed { token: token.clone(), lease_until: now + LEASE });
            Ok(Claim::Claimed(ClaimToken::new(token)))
        })
    }

    fn accept<'a>(&'a self, key: &'a str, token: &'a ClaimToken) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move {
            let mut rows = self.rows.lock().map_err(|_| "poisoned")?;
            match rows.get(key) {
                Some(Row::Claimed { token: t, .. }) if t == token.as_str() => {
                    rows.insert(key.to_owned(), Row::Accepted);
                    Ok(())
                }
                _ => Err("stale or unknown claim".into()),
            }
        })
    }

    fn abandon<'a>(&'a self, key: &'a str, token: &'a ClaimToken) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move {
            let mut rows = self.rows.lock().map_err(|_| "poisoned")?;
            match rows.get(key) {
                Some(Row::Claimed { token: t, .. }) if t == token.as_str() => {
                    rows.remove(key);
                    Ok(())
                }
                _ => Err("stale or unknown claim".into()),
            }
        })
    }
}
```

### Check your store before production

`asx::testkit::dedup::conformance` drives a store through every rule above,
including the concurrent claim race and stale-holder fencing, and returns the
failed checks. Each check is itself tested against a deliberately broken store
in `asx::testkit::dedup::broken`.

```rust,no_run
use asx::testkit::dedup::{conformance, DedupHarness};
use std::time::Duration;

struct Harness;

impl DedupHarness for Harness {
    type Store = asx::MemoryDedup; // your store: open an empty table per call
    fn open(&self) -> asx::MemoryDedup {
        asx::MemoryDedup::default()
    }
    fn lease(&self) -> Duration {
        Duration::from_secs(5 * 60)
    }
}

#[tokio::main(flavor = "current_thread", start_paused = true)]
async fn main() {
    let failures = conformance(&Harness).await;
    assert!(failures.is_empty(), "{failures:#?}");
}
```

In a test suite use `#[tokio::test(start_paused = true)]`: lease waits finish
instantly for a store that reads time through `tokio::time::Instant`, as
`MemoryDedup` does. For a store on the database clock, give the harness a lease
of a few seconds and run unpaused.

## The audit sink

`Builder::audit(sink)` installs one `AuditSink` per client; it receives one
`AuditRecord` per exchange leg. When a record is written and what it contains
are on the [observability page](@/docs/observability.md#audit-records).

```rust
use asx::{AuditDurability, AuditRecord, AuditSink, BoxFuture};
use std::sync::Mutex;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Appends records as JSON lines. A database sink would `INSERT … ON CONFLICT
/// (record_id) DO NOTHING`: the record id is the idempotency key.
#[derive(Debug, Default)]
struct JsonLines(Mutex<Vec<String>>);

impl AuditSink for JsonLines {
    fn durability(&self) -> AuditDurability {
        AuditDurability::Durable
    }

    fn record<'a>(&'a self, r: &'a AuditRecord) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move {
            let line = serde_json::to_string(r)?;
            self.0.lock().map_err(|_| "poisoned")?.push(line);
            Ok(())
        })
    }
}

fn with_audit(builder: asx::Builder<asx::as4::As4>) -> asx::Builder<asx::as4::As4> {
    builder.audit(JsonLines::default())
}
```

`durability()` decides what a failure means:

- `Durable`: the error fails the exchange. On receive no receipt goes out and
  the claim is released, so the retransmission is processed again; on send you
  get `ErrorKind::Backend` with the verified receipt as `evidence()` (the
  message was delivered: do not resend it).
- `BestEffort`: an `ERROR` event and a counted metric; the exchange proceeds.

`asx::testkit::audit::conformance` checks the durability claim; see
[check your sink](@/docs/observability.md#check-your-sink-before-production).
