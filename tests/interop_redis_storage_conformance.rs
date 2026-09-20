#![cfg(all(feature = "as4", feature = "testing"))]
//! The storage seam, against a **real** network-backed store.
//!
//! # Why this exists
//!
//! `DedupStorage` returns `BoxFuture` so that Redis/PostgreSQL/DynamoDB
//! backends can implement it natively, and `cluster_safe()` — which the strict
//! production startup gate *requires* — means an out-of-process store by
//! definition. Every in-tree implementation is in-memory and resolves on the
//! first poll, so that half of the trait had never been driven by anything. A
//! single poll followed by a panic survived every gate the crate has, and the
//! backend the gate demands would have panicked on the first inbound message
//! (D61, R18).
//!
//! `DedupConformance` now includes a yielding backend and a blocking-context
//! check, which closes the class in-tree. This closes it out of tree: the same
//! argument that makes Holodeck worth more than a mock applies to a database.
//!
//! What a real store adds over the in-tree doubles:
//!
//! - **Genuine network latency** on every call, so the future really suspends.
//! - **Real atomicity**, or its absence. The suite races concurrent claims;
//!   here they race through a socket against a single-threaded server, which is
//!   where a `GET`-then-`SET` implementation actually loses.
//! - **A real reconnect.** The conformance factory hands out a *fresh
//!   connection*, so "state survives a reconnect" means what it says.
//!
//! # Running
//!
//! `#[ignore]`d so the default `cargo test` stays hermetic and offline:
//!
//! ```text
//! cargo test --all-features --test interop_redis_storage_conformance -- --ignored --nocapture
//! ```

use std::sync::Arc;

use asx_rs::storage::conformance::{DedupConformance, StorageFactory};
use asx_rs::storage::{BoxFuture, DedupStorage, DedupVerdict};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage};

const REDIS_IMAGE: &str = "redis";
const REDIS_TAG: &str = "7-alpine";

/// How long an unsettled claim is held before the lease expires.
const CLAIM_LEASE_SECS: u64 = 300;
/// How long an accepted key suppresses replays. RFC 4130 §5.2.1 wants 48h.
const REPLAY_WINDOW_SECS: u64 = 48 * 3600;

/// A `DedupStorage` on Redis, written the way the persistence guide says to.
///
/// Both state transitions that must not race are single `EVAL`s, because Redis
/// executes a script atomically. The alternative — `SET NX`, then `GET` to find
/// out why it failed — has a window in which the other attempt settles, and the
/// conformance suite's concurrency check is built to find exactly that.
#[derive(Debug)]
struct RedisDedup {
    client: redis::Client,
}

impl RedisDedup {
    fn new(url: &str) -> Self {
        Self {
            client: redis::Client::open(url).expect("redis url"),
        }
    }

    async fn conn(&self) -> asx_rs::Result<redis::aio::MultiplexedConnection> {
        self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(storage_err)
    }
}

fn storage_err(e: impl std::fmt::Display) -> asx_rs::AsxError {
    // Fail closed: a backend that cannot answer must never read as "not seen".
    asx_rs::AsxError::new(
        asx_rs::ErrorCode::ReliabilityFailure,
        format!("redis dedup backend failure: {e}"),
        asx_rs::ErrorContext::new("redis_dedup"),
    )
}

/// Take the key, or report what already holds it — in one atomic step.
const CLAIM_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if current == 'accepted' then return 'duplicate' end
if current == 'inflight' then return 'inflight' end
redis.call('SET', KEYS[1], 'inflight', 'EX', ARGV[1])
return 'claimed'
"#;

/// Release the key, but only while it is still unsettled: an already-accepted
/// key must survive a late abandon, or a processed message is delivered twice.
const ABANDON_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) == 'inflight' then
  redis.call('DEL', KEYS[1])
end
return 1
"#;

impl DedupStorage for RedisDedup {
    fn is_durable(&self) -> bool {
        true
    }

    fn cluster_safe(&self) -> bool {
        true
    }

    fn claim<'a>(&'a self, key: &'a str) -> BoxFuture<'a, asx_rs::Result<DedupVerdict>> {
        Box::pin(async move {
            let mut conn = self.conn().await?;
            let verdict: String = redis::Script::new(CLAIM_SCRIPT)
                .key(key)
                .arg(CLAIM_LEASE_SECS)
                .invoke_async(&mut conn)
                .await
                .map_err(storage_err)?;
            Ok(match verdict.as_str() {
                "claimed" => DedupVerdict::Claimed,
                "duplicate" => DedupVerdict::Duplicate,
                _ => DedupVerdict::InFlight,
            })
        })
    }

    fn accept<'a>(&'a self, key: &'a str) -> BoxFuture<'a, asx_rs::Result<()>> {
        Box::pin(async move {
            let mut conn = self.conn().await?;
            // Unconditional, so a retried settlement is not an error.
            let _: () = redis::cmd("SET")
                .arg(key)
                .arg("accepted")
                .arg("EX")
                .arg(REPLAY_WINDOW_SECS)
                .query_async(&mut conn)
                .await
                .map_err(storage_err)?;
            Ok(())
        })
    }

    fn abandon<'a>(&'a self, key: &'a str) -> BoxFuture<'a, asx_rs::Result<()>> {
        Box::pin(async move {
            let mut conn = self.conn().await?;
            let _: i64 = redis::Script::new(ABANDON_SCRIPT)
                .key(key)
                .invoke_async(&mut conn)
                .await
                .map_err(storage_err)?;
            Ok(())
        })
    }
}

/// Hands out a **fresh connection** each time, which is what makes the
/// suite's reconnect check meaningful.
struct RedisFactory {
    url: String,
}

impl StorageFactory<dyn DedupStorage> for RedisFactory {
    fn connect(&self) -> Arc<dyn DedupStorage> {
        Arc::new(RedisDedup::new(&self.url))
    }
}

async fn start_redis() -> (ContainerAsync<GenericImage>, String) {
    let container = GenericImage::new(REDIS_IMAGE, REDIS_TAG)
        .with_exposed_port(6379.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
        .start()
        .await
        .expect("start redis (is the Docker daemon running?)");

    let port = container
        .get_host_port_ipv4(6379.tcp())
        .await
        .expect("mapped redis port");
    let url = format!("redis://127.0.0.1:{port}");
    (container, url)
}

/// **The oracle.** The whole dedup contract, against a real store.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker"]
async fn redis_dedup_backend_conforms() {
    let (_container, url) = start_redis().await;

    let report = DedupConformance::new(&RedisFactory { url })
        .key_prefix("asx-redis-conformance")
        .concurrency(16)
        .run()
        .await;

    assert!(
        report.passed(),
        "a Redis-backed DedupStorage must satisfy the contract the protocol \
         paths depend on:\n{report}"
    );
}

/// The check the in-tree doubles cannot make: a backend that really yields,
/// driven from the blocking context the AS4 receive pipeline runs in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker"]
async fn redis_dedup_survives_the_blocking_receive_context() {
    let (_container, url) = start_redis().await;
    let backend: Arc<dyn DedupStorage> = Arc::new(RedisDedup::new(&url));

    let key = "asx-redis-blocking-context";
    let verdict = tokio::task::spawn_blocking({
        let backend = Arc::clone(&backend);
        let key = key.to_string();
        move || asx_rs::storage::drive_dedup_future(backend.claim(&key))
    })
    .await
    .expect("join")
    .expect("a network-backed claim must be driven to completion, not polled once");

    assert_eq!(verdict, DedupVerdict::Claimed);
}

/// A deliberately non-atomic implementation must **fail** the suite.
///
/// Without this, `redis_dedup_backend_conforms` would also pass against a
/// suite that reported success unconditionally — and the race it is meant to
/// catch is the one that only appears against a real server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker"]
async fn a_get_then_set_redis_backend_fails_the_race_check() {
    #[derive(Debug)]
    struct GetThenSet(RedisDedup);

    impl DedupStorage for GetThenSet {
        fn is_durable(&self) -> bool {
            true
        }
        fn cluster_safe(&self) -> bool {
            true
        }
        fn claim<'a>(&'a self, key: &'a str) -> BoxFuture<'a, asx_rs::Result<DedupVerdict>> {
            Box::pin(async move {
                let mut conn = self.0.conn().await?;
                // Two round trips: the classic mistake. Another caller can
                // claim between the GET and the SET.
                let current: Option<String> = redis::cmd("GET")
                    .arg(key)
                    .query_async(&mut conn)
                    .await
                    .map_err(storage_err)?;
                match current.as_deref() {
                    Some("accepted") => return Ok(DedupVerdict::Duplicate),
                    Some(_) => return Ok(DedupVerdict::InFlight),
                    None => {}
                }
                let _: () = redis::cmd("SET")
                    .arg(key)
                    .arg("inflight")
                    .arg("EX")
                    .arg(CLAIM_LEASE_SECS)
                    .query_async(&mut conn)
                    .await
                    .map_err(storage_err)?;
                Ok(DedupVerdict::Claimed)
            })
        }
        fn accept<'a>(&'a self, key: &'a str) -> BoxFuture<'a, asx_rs::Result<()>> {
            self.0.accept(key)
        }
        fn abandon<'a>(&'a self, key: &'a str) -> BoxFuture<'a, asx_rs::Result<()>> {
            self.0.abandon(key)
        }
    }

    struct Factory {
        url: String,
    }
    impl StorageFactory<dyn DedupStorage> for Factory {
        fn connect(&self) -> Arc<dyn DedupStorage> {
            Arc::new(GetThenSet(RedisDedup::new(&self.url)))
        }
    }

    let (_container, url) = start_redis().await;
    let report = DedupConformance::new(&Factory { url })
        .key_prefix("asx-redis-racy")
        .concurrency(32)
        .run()
        .await;

    let failed: Vec<_> = report.failures().iter().map(|c| c.id).collect();
    assert!(
        failed.contains(&"dedup.concurrent_claim_admits_exactly_one"),
        "a GET-then-SET backend must fail the race check, or the suite is not \
         checking what it claims to:\n{report}"
    );
}
