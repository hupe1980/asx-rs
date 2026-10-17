#![cfg(feature = "as4")]
//! The dedup seam, against a **real** network-backed store.
//!
//! # Why this exists
//!
//! `DedupStore` returns `BoxFuture` so that Redis/PostgreSQL/DynamoDB backends
//! can implement it natively. Every in-tree implementation is in-memory and
//! resolves on the first poll, so that half of the trait is never driven by
//! anything in-tree except a simulated yield. This drives it against a real
//! Redis.
//!
//! What a real store adds over the in-tree doubles:
//!
//! - **Genuine network latency** on every call, so the future really suspends.
//! - **Real atomicity**, or its absence. The suite races concurrent claims;
//!   here they race through a socket against a single-threaded server, which
//!   is where a `GET`-then-`SET` implementation actually loses.
//! - **A real lease** on the server's clock, and fencing by lease token: a
//!   stale holder must not settle a key that was re-claimed.
//!
//! # Running
//!
//! `#[ignore]`d so the default `cargo test` stays hermetic and offline:
//!
//! ```text
//! cargo test --all-features --test interop_redis_storage_conformance -- --ignored --nocapture
//! ```

#[path = "common/peers.rs"]
mod peers;
#[allow(unreachable_pub)]
#[path = "common/ported_as4.rs"]
mod ported;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use asx::testkit::dedup::{self, DedupHarness, conformance};
use asx::{BoxFuture, Claim, ClaimToken, DedupStore};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage};

const REDIS_IMAGE: &str = "redis";
const REDIS_TAG: &str = "7-alpine";

/// How long an unsettled claim is held before the lease expires. Short, so
/// the suite can wait it out on the server's clock (it cannot be paused).
const CLAIM_LEASE: Duration = Duration::from_secs(4);
/// How long an accepted key suppresses replays. RFC 4130 §5.2.1 wants 48h.
const REPLAY_WINDOW_SECS: u64 = 48 * 3600;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A `DedupStore` on Redis, written the way the persistence guide says to.
///
/// Every state transition that must not race is a single `EVAL`, because
/// Redis executes a script atomically. A claim stores `held:<token>` with a
/// fencing token from `INCR`; `accept` and `abandon` compare it.
#[derive(Debug)]
struct RedisDedup {
    client: redis::Client,
    /// Isolates one store from another on the same server.
    namespace: String,
}

impl RedisDedup {
    fn new(url: &str, namespace: impl Into<String>) -> Self {
        Self {
            client: redis::Client::open(url).expect("redis url"),
            namespace: namespace.into(),
        }
    }

    fn key(&self, key: &str) -> String {
        format!("{}:{key}", self.namespace)
    }

    async fn conn(&self) -> Result<redis::aio::MultiplexedConnection, BoxError> {
        // Fail closed: a backend that cannot answer must never read as "not seen".
        Ok(self.client.get_multiplexed_async_connection().await?)
    }
}

/// Take the key under a fresh fencing token, or report what holds it — in
/// one atomic step.
const CLAIM_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if current == 'accepted' then return 'duplicate' end
if current then return 'inflight' end
local token = tostring(redis.call('INCR', KEYS[2]))
redis.call('SET', KEYS[1], 'held:' .. token, 'PX', ARGV[1])
return 'claimed:' .. token
"#;

/// Settle the key, but only for its current holder.
const ACCEPT_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) ~= 'held:' .. ARGV[1] then
  return redis.error_reply('stale or unknown claim token')
end
redis.call('SET', KEYS[1], 'accepted', 'EX', ARGV[2])
return 1
"#;

/// Release the key, but only while the token still holds it: an accepted or
/// re-claimed key must survive a late abandon.
const ABANDON_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) ~= 'held:' .. ARGV[1] then
  return redis.error_reply('stale or unknown claim token')
end
redis.call('DEL', KEYS[1])
return 1
"#;

fn verdict(answer: &str) -> Claim {
    match answer.strip_prefix("claimed:") {
        Some(token) => Claim::Claimed(ClaimToken::new(token)),
        None if answer == "duplicate" => Claim::Duplicate,
        None => Claim::InFlight,
    }
}

impl DedupStore for RedisDedup {
    fn claim<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Claim, BoxError>> {
        Box::pin(async move {
            let mut conn = self.conn().await?;
            let answer: String = redis::Script::new(CLAIM_SCRIPT)
                .key(self.key(key))
                .key(format!("{}:fence", self.namespace))
                .arg(CLAIM_LEASE.as_millis() as u64)
                .invoke_async(&mut conn)
                .await?;
            Ok(verdict(&answer))
        })
    }

    fn accept<'a>(
        &'a self,
        key: &'a str,
        token: &'a ClaimToken,
    ) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move {
            let mut conn = self.conn().await?;
            let _: i64 = redis::Script::new(ACCEPT_SCRIPT)
                .key(self.key(key))
                .arg(token.as_str())
                .arg(REPLAY_WINDOW_SECS)
                .invoke_async(&mut conn)
                .await?;
            Ok(())
        })
    }

    fn abandon<'a>(
        &'a self,
        key: &'a str,
        token: &'a ClaimToken,
    ) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move {
            let mut conn = self.conn().await?;
            let _: i64 = redis::Script::new(ABANDON_SCRIPT)
                .key(self.key(key))
                .arg(token.as_str())
                .invoke_async(&mut conn)
                .await?;
            Ok(())
        })
    }
}

/// Hands out a store in a fresh namespace each time (an empty store), each
/// with its own client, so every check also crosses a fresh connection.
struct RedisHarness {
    url: String,
    prefix: &'static str,
    opened: AtomicU64,
}

impl RedisHarness {
    fn new(url: String, prefix: &'static str) -> Self {
        Self {
            url,
            prefix,
            opened: AtomicU64::new(0),
        }
    }
    fn namespace(&self) -> String {
        format!(
            "{}-{}",
            self.prefix,
            self.opened.fetch_add(1, Ordering::SeqCst)
        )
    }
}

impl DedupHarness for RedisHarness {
    type Store = RedisDedup;
    fn open(&self) -> RedisDedup {
        RedisDedup::new(&self.url, self.namespace())
    }
    fn lease(&self) -> Duration {
        CLAIM_LEASE
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

/// **The oracle.** The whole dedup contract, against a real store. Unpaused:
/// the lease runs on the server's clock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker"]
async fn redis_dedup_backend_conforms() {
    let (_container, url) = start_redis().await;
    let failures = conformance(&RedisHarness::new(url, "asx-redis-conformance")).await;
    assert!(
        failures.is_empty(),
        "a Redis-backed DedupStore must satisfy the contract the receive path \
         depends on:\n{failures:#?}"
    );
}

/// The check the in-tree doubles cannot make: a store that really suspends,
/// behind a real `Inbound` — claimed, accepted, then answered as a duplicate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker"]
async fn redis_dedup_backs_a_real_inbound() {
    use peers::Preset;
    let (_container, url) = start_redis().await;
    let p = peers::pair(Preset::Edelivery);
    p.sender
        .send(Preset::Edelivery.message(&p.to_b, b"x"))
        .await
        .expect("delivered");
    let request = p.loopback.last_request().unwrap();
    let inbound =
        ported::accepting_inbound(&p.receiver, RedisDedup::new(&url, "asx-redis-inbound"));
    let (status, body) = ported::post(&inbound, ported::clone_request(&request)).await;
    assert_eq!(
        status,
        http::StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let (status, _) = ported::post(&inbound, request).await;
    assert_eq!(status, http::StatusCode::OK, "duplicate receipted");

    let store = RedisDedup::new(&url, "asx-redis-inbound");
    let mut conn = store.conn().await.expect("connection");
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("asx-redis-inbound:*")
        .query_async(&mut conn)
        .await
        .expect("keys");
    let settled: Vec<String> = {
        let mut values = Vec::new();
        for key in keys.iter().filter(|k| !k.ends_with(":fence")) {
            let value: String = redis::cmd("GET")
                .arg(key)
                .query_async(&mut conn)
                .await
                .expect("get");
            values.push(value);
        }
        values
    };
    assert_eq!(settled, ["accepted"], "one key, accepted");
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

    impl DedupStore for GetThenSet {
        fn claim<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Claim, BoxError>> {
            Box::pin(async move {
                let mut conn = self.0.conn().await?;
                // Two round trips: the classic mistake. Another caller can
                // claim between the GET and the SET.
                let current: Option<String> = redis::cmd("GET")
                    .arg(self.0.key(key))
                    .query_async(&mut conn)
                    .await?;
                match current.as_deref() {
                    Some("accepted") => return Ok(Claim::Duplicate),
                    Some(_) => return Ok(Claim::InFlight),
                    None => {}
                }
                // Widen the window so every concurrent claimer reads the key
                // as absent: the race must happen on every run, or the
                // conformance check could pass this broken store by luck.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                let token: u64 = redis::cmd("INCR")
                    .arg(format!("{}:fence", self.0.namespace))
                    .query_async(&mut conn)
                    .await?;
                let _: () = redis::cmd("SET")
                    .arg(self.0.key(key))
                    .arg(format!("held:{token}"))
                    .arg("PX")
                    .arg(CLAIM_LEASE.as_millis() as u64)
                    .query_async(&mut conn)
                    .await?;
                Ok(Claim::Claimed(ClaimToken::new(token.to_string())))
            })
        }
        fn accept<'a>(
            &'a self,
            key: &'a str,
            token: &'a ClaimToken,
        ) -> BoxFuture<'a, Result<(), BoxError>> {
            self.0.accept(key, token)
        }
        fn abandon<'a>(
            &'a self,
            key: &'a str,
            token: &'a ClaimToken,
        ) -> BoxFuture<'a, Result<(), BoxError>> {
            self.0.abandon(key, token)
        }
    }

    struct Racy(RedisHarness);
    impl DedupHarness for Racy {
        type Store = GetThenSet;
        fn open(&self) -> GetThenSet {
            GetThenSet(self.0.open())
        }
        fn lease(&self) -> Duration {
            CLAIM_LEASE
        }
    }

    let (_container, url) = start_redis().await;
    let failures = conformance(&Racy(RedisHarness::new(url, "asx-redis-racy"))).await;
    let failed: Vec<_> = failures.iter().map(|f| f.check).collect();
    assert!(
        failed.contains(&dedup::CONCURRENT_CLAIM_ADMITS_EXACTLY_ONE),
        "a GET-then-SET backend must fail the race check, or the suite is not \
         checking what it claims to:\n{failures:#?}"
    );
}
