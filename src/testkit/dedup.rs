//! A conformance suite for [`asx::DedupStore`] backends.
//!
//! The library trusts its replay store with the most load-bearing decision on
//! the receive path: whether a message is new. Nothing at runtime can verify
//! that a backend keeps its promises, so this suite drives one through the
//! properties the pipeline depends on, including the ones a single-threaded
//! smoke test never notices:
//!
//! - **`claim` is atomic.** Under concurrent calls for one key exactly one
//!   caller is handed the claim. A `SELECT`-then-`INSERT` backend passes every
//!   serial test and admits duplicate business documents under load.
//! - **Settlement is fenced by the lease token.** After a lease expires and a
//!   second delivery re-claims the key, the first (slow) holder's `accept` and
//!   `abandon` must fail and change nothing. A backend that settles
//!   by key alone lets a stale handler release or settle a claim it no longer
//!   holds.
//! - **Tokens are fresh per claim**, so a token can never match a later lease.
//!
//! Every check has a deliberately broken store in [`broken`] that fails it,
//! so the suite itself is tested against false passes.
//!
//! # Paused time
//!
//! The lease checks wait out the store's lease with [`tokio::time::sleep`].
//! Run the suite under a **paused clock**, i.e. from a
//! `#[tokio::test(start_paused = true)]` test: the runtime then auto-advances
//! the clock past the lease instantly (the same effect as
//! `tokio::time::advance`), and a store that reads time through
//! [`tokio::time::Instant`] — as [`asx::MemoryDedup`] does — sees its lease
//! expire. A wait that has not finished after [`REAL_TIME_GUARD`] of wall-clock
//! time is reported as a failure instead of hanging for the whole lease.
//!
//! A backend whose lease runs on its own clock (a database `now()`) cannot be
//! fast-forwarded: give it a short lease in the harness (a few seconds at
//! most, below [`REAL_TIME_GUARD`]) and run the test unpaused.
//!
//! # Using it
//!
//! ```no_run
//! use asx::testkit::dedup::{conformance, DedupHarness};
//! use std::time::Duration;
//!
//! #[derive(Debug)]
//! struct Memory;
//!
//! impl DedupHarness for Memory {
//!     type Store = asx::MemoryDedup;
//!     fn open(&self) -> asx::MemoryDedup {
//!         asx::MemoryDedup::default()
//!     }
//!     fn lease(&self) -> Duration {
//!         Duration::from_secs(5 * 60)
//!     }
//! }
//!
//! // In the test: #[tokio::test(start_paused = true)]
//! async fn memory_dedup_conforms() {
//!     let failures = conformance(&Memory).await;
//!     assert!(failures.is_empty(), "{failures:#?}");
//! }
//! ```

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use asx::{Claim, ClaimToken, DedupStore};

/// A claimed key is reported once, and as a duplicate after `accept`.
pub const ACCEPTED_KEY_IS_CLAIMED_ONCE: &str = "dedup.accepted_key_is_claimed_once";
/// Settling one key does not mark another as seen.
pub const DISTINCT_KEYS_ARE_INDEPENDENT: &str = "dedup.distinct_keys_are_independent";
/// A claimed but unsettled key reports `InFlight`, never `Duplicate` or a
/// second `Claimed`.
pub const UNSETTLED_CLAIM_REPORTS_IN_FLIGHT: &str = "dedup.unsettled_claim_reports_in_flight";
/// `abandon` by the holder lets the key be claimed again.
pub const ABANDON_RELEASES_THE_KEY: &str = "dedup.abandon_releases_the_key";
/// A late `abandon` after `accept` fails and leaves the key a duplicate.
pub const ABANDON_NEVER_REOPENS_AN_ACCEPTED_KEY: &str =
    "dedup.abandon_never_reopens_an_accepted_key";
/// A token is spent once settled: a second `accept`, or an `accept` after
/// `abandon`, fails and changes nothing.
pub const SETTLED_TOKEN_IS_SPENT: &str = "dedup.settled_token_is_spent";
/// Under concurrent `claim` calls for one key exactly one caller wins.
pub const CONCURRENT_CLAIM_ADMITS_EXACTLY_ONE: &str = "dedup.concurrent_claim_admits_exactly_one";
/// An unsettled claim holds until its lease expires, and only then can the
/// key be claimed again.
pub const LEASE_EXPIRY_ALLOWS_RECLAIM: &str = "dedup.lease_expiry_allows_reclaim";
/// After lease expiry and a re-claim, the first token's `accept` fails and the
/// key stays held by the second claim.
pub const STALE_HOLDER_CANNOT_ACCEPT: &str = "dedup.stale_holder_cannot_accept";
/// After lease expiry and a re-claim, the first token's `abandon` fails and
/// the key stays held by the second claim.
pub const STALE_HOLDER_CANNOT_ABANDON: &str = "dedup.stale_holder_cannot_abandon";
/// Every successful claim carries a new token, also for the same key.
pub const TOKENS_ARE_FRESH_PER_CLAIM: &str = "dedup.tokens_are_fresh_per_claim";

/// Every check, in execution order.
pub const CHECKS: &[&str] = &[
    ACCEPTED_KEY_IS_CLAIMED_ONCE,
    DISTINCT_KEYS_ARE_INDEPENDENT,
    UNSETTLED_CLAIM_REPORTS_IN_FLIGHT,
    ABANDON_RELEASES_THE_KEY,
    ABANDON_NEVER_REOPENS_AN_ACCEPTED_KEY,
    SETTLED_TOKEN_IS_SPENT,
    CONCURRENT_CLAIM_ADMITS_EXACTLY_ONE,
    LEASE_EXPIRY_ALLOWS_RECLAIM,
    STALE_HOLDER_CANNOT_ACCEPT,
    STALE_HOLDER_CANNOT_ABANDON,
    TOKENS_ARE_FRESH_PER_CLAIM,
];

/// How many tasks race for one key in [`CONCURRENT_CLAIM_ADMITS_EXACTLY_ONE`].
pub const CONCURRENCY: usize = 16;

/// Wall-clock limit for one lease wait. Under a paused clock a wait finishes
/// immediately; one still running after this long means the clock is not
/// paused and the lease is too long to wait out for real.
pub const REAL_TIME_GUARD: Duration = Duration::from_secs(10);

/// How the suite obtains stores of the backend under test.
pub trait DedupHarness {
    /// The backend under test.
    type Store: DedupStore + 'static;

    /// A fresh, **empty** store. Every check opens its own, so state never
    /// leaks between checks. For a database, an isolated schema or table.
    fn open(&self) -> Self::Store;

    /// The lease the store applies to an unsettled claim. The lease checks
    /// wait just under and just over it (see the module docs on paused time).
    fn lease(&self) -> Duration;
}

/// One failed check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceFailure {
    /// The check's stable name, one of [`CHECKS`].
    pub check: &'static str,
    /// What went wrong.
    pub detail: String,
}

impl fmt::Display for ConformanceFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.check, self.detail)
    }
}

/// Run every check against stores from `harness`. Never panics; returns the
/// failed checks (empty when the backend conforms).
///
/// Run it under `#[tokio::test(start_paused = true)]` (see the module docs).
pub async fn conformance<H: DedupHarness>(harness: &H) -> Vec<ConformanceFailure> {
    let lease = harness.lease();
    let mut failures = Vec::new();
    let mut record = |check: &'static str, outcome: Outcome| {
        if let Err(detail) = outcome {
            failures.push(ConformanceFailure { check, detail });
        }
    };
    record(
        ACCEPTED_KEY_IS_CLAIMED_ONCE,
        accepted_key_is_claimed_once(&harness.open()).await,
    );
    record(
        DISTINCT_KEYS_ARE_INDEPENDENT,
        distinct_keys_are_independent(&harness.open()).await,
    );
    record(
        UNSETTLED_CLAIM_REPORTS_IN_FLIGHT,
        unsettled_claim_reports_in_flight(&harness.open()).await,
    );
    record(
        ABANDON_RELEASES_THE_KEY,
        abandon_releases_the_key(&harness.open()).await,
    );
    record(
        ABANDON_NEVER_REOPENS_AN_ACCEPTED_KEY,
        abandon_never_reopens_an_accepted_key(&harness.open()).await,
    );
    record(
        SETTLED_TOKEN_IS_SPENT,
        settled_token_is_spent(&harness.open()).await,
    );
    record(
        CONCURRENT_CLAIM_ADMITS_EXACTLY_ONE,
        concurrent_claim_admits_exactly_one(Arc::new(harness.open())).await,
    );
    record(
        LEASE_EXPIRY_ALLOWS_RECLAIM,
        lease_expiry_allows_reclaim(&harness.open(), lease).await,
    );
    record(
        STALE_HOLDER_CANNOT_ACCEPT,
        stale_holder_cannot_settle(&harness.open(), lease, Settle::Accept).await,
    );
    record(
        STALE_HOLDER_CANNOT_ABANDON,
        stale_holder_cannot_settle(&harness.open(), lease, Settle::Abandon).await,
    );
    record(
        TOKENS_ARE_FRESH_PER_CLAIM,
        tokens_are_fresh_per_claim(&harness.open()).await,
    );
    failures
}

type Outcome = Result<(), String>;

/// A production-shaped key: 64 lowercase hex characters.
fn key(name: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(format!("asx-testkit-dedup-conformance\0{name}").as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

async fn claim<S: DedupStore>(store: &S, key: &str, step: &str) -> Result<Claim, String> {
    store
        .claim(key)
        .await
        .map_err(|err| format!("{step}: claim errored: {err}"))
}

async fn claimed<S: DedupStore>(store: &S, key: &str, step: &str) -> Result<ClaimToken, String> {
    match claim(store, key, step).await? {
        Claim::Claimed(token) => Ok(token),
        other => Err(format!("{step}: expected Claimed, got {other:?}")),
    }
}

async fn expect<S: DedupStore>(store: &S, key: &str, want: Claim, step: &str) -> Outcome {
    let got = claim(store, key, step).await?;
    if got == want {
        Ok(())
    } else {
        Err(format!("{step}: expected {want:?}, got {got:?}"))
    }
}

async fn accept<S: DedupStore>(store: &S, key: &str, token: &ClaimToken, step: &str) -> Outcome {
    store
        .accept(key, token)
        .await
        .map_err(|err| format!("{step}: accept errored: {err}"))
}

async fn abandon<S: DedupStore>(store: &S, key: &str, token: &ClaimToken, step: &str) -> Outcome {
    store
        .abandon(key, token)
        .await
        .map_err(|err| format!("{step}: abandon errored: {err}"))
}

/// Advance the (paused) tokio clock by `by`, failing instead of hanging when
/// the clock is not paused and `by` is long.
async fn wait(by: Duration) -> Outcome {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        std::thread::sleep(REAL_TIME_GUARD);
        let _ = tx.send(());
    });
    tokio::select! {
        () = tokio::time::sleep(by) => Ok(()),
        _ = rx => Err(format!(
            "waiting {by:?} for the lease took longer than {REAL_TIME_GUARD:?} of real time: \
             run the suite under #[tokio::test(start_paused = true)] or give the harness a \
             short lease"
        )),
    }
}

/// A margin around the lease boundary: one second, or a quarter of a short
/// lease.
fn margin(lease: Duration) -> Duration {
    (lease / 4).min(Duration::from_secs(1))
}

async fn accepted_key_is_claimed_once<S: DedupStore>(store: &S) -> Outcome {
    let key = key("once");
    let token = claimed(store, &key, "a fresh key").await?;
    accept(store, &key, &token, "the holder").await?;
    expect(
        store,
        &key,
        Claim::Duplicate,
        "an accepted key (replay protection)",
    )
    .await
}

async fn distinct_keys_are_independent<S: DedupStore>(store: &S) -> Outcome {
    let a = key("independent-a");
    let b = key("independent-b");
    let token = claimed(store, &a, "key a").await?;
    claimed(store, &b, "key b while a is held (keys collide)").await?;
    accept(store, &a, &token, "key a's holder").await?;
    expect(store, &b, Claim::InFlight, "key b after a was accepted").await
}

/// Reporting `Duplicate` here loses messages: the second delivery is
/// acknowledged as handled while the first attempt may still fail.
async fn unsettled_claim_reports_in_flight<S: DedupStore>(store: &S) -> Outcome {
    let key = key("inflight");
    claimed(store, &key, "a fresh key").await?;
    expect(store, &key, Claim::InFlight, "an unsettled claim").await
}

async fn abandon_releases_the_key<S: DedupStore>(store: &S) -> Outcome {
    let key = key("abandon");
    let token = claimed(store, &key, "a fresh key").await?;
    abandon(store, &key, &token, "the holder").await?;
    claimed(
        store,
        &key,
        "an abandoned key (a failed message must be redeliverable)",
    )
    .await
    .map(drop)
}

async fn abandon_never_reopens_an_accepted_key<S: DedupStore>(store: &S) -> Outcome {
    let key = key("late-abandon");
    let token = claimed(store, &key, "a fresh key").await?;
    accept(store, &key, &token, "the holder").await?;
    if store.abandon(&key, &token).await.is_ok() {
        return Err("abandon after accept returned Ok; a settled token must be refused".into());
    }
    expect(
        store,
        &key,
        Claim::Duplicate,
        "an accepted key after a late abandon (a replay would be processed twice)",
    )
    .await
}

async fn settled_token_is_spent<S: DedupStore>(store: &S) -> Outcome {
    let accepted = key("accept-twice");
    let token = claimed(store, &accepted, "a fresh key").await?;
    accept(store, &accepted, &token, "the holder").await?;
    if store.accept(&accepted, &token).await.is_ok() {
        return Err("a second accept with the same token returned Ok".into());
    }
    expect(store, &accepted, Claim::Duplicate, "after a second accept").await?;

    let abandoned = key("accept-after-abandon");
    let token = claimed(store, &abandoned, "a fresh key").await?;
    abandon(store, &abandoned, &token, "the holder").await?;
    if store.accept(&abandoned, &token).await.is_ok() {
        return Err("accept after abandon with the same token returned Ok".into());
    }
    claimed(
        store,
        &abandoned,
        "an abandoned key after a stale accept (the accept must change nothing)",
    )
    .await
    .map(drop)
}

/// The check that separates a correct backend from a plausible one. The
/// atomic forms are `INSERT … ON CONFLICT DO NOTHING`, `SET NX`, or a
/// conditional write.
async fn concurrent_claim_admits_exactly_one<S: DedupStore>(store: Arc<S>) -> Outcome {
    let key = key("race");
    let mut handles = Vec::with_capacity(CONCURRENCY);
    for _ in 0..CONCURRENCY {
        let store = Arc::clone(&store);
        let key = key.clone();
        handles.push(tokio::spawn(async move { store.claim(&key).await }));
    }
    let mut winners = 0usize;
    for handle in handles {
        match handle.await {
            Ok(Ok(Claim::Claimed(_))) => winners += 1,
            Ok(Ok(_)) => {}
            Ok(Err(err)) => return Err(format!("a racing claim errored: {err}")),
            Err(err) => return Err(format!("a racing task failed: {err}")),
        }
    }
    match winners {
        1 => Ok(()),
        0 => Err("no concurrent caller claimed the key".into()),
        n => Err(format!(
            "{n} of {CONCURRENCY} concurrent callers claimed the key; claim is not atomic, so \
             {} duplicate messages would be processed under load",
            n - 1
        )),
    }
}

async fn lease_expiry_allows_reclaim<S: DedupStore>(store: &S, lease: Duration) -> Outcome {
    let key = key("lease");
    let margin = margin(lease);
    claimed(store, &key, "a fresh key").await?;
    wait(lease.saturating_sub(margin)).await?;
    expect(
        store,
        &key,
        Claim::InFlight,
        "just before the lease expires",
    )
    .await?;
    wait(margin * 2).await?;
    claimed(
        store,
        &key,
        "after the lease expired (an unsettled claim must not hold forever)",
    )
    .await
    .map(drop)
}

#[derive(Debug, Clone, Copy)]
enum Settle {
    Accept,
    Abandon,
}

/// A slow handler whose lease expired must neither settle nor
/// release the claim the next delivery now holds.
async fn stale_holder_cannot_settle<S: DedupStore>(
    store: &S,
    lease: Duration,
    settle: Settle,
) -> Outcome {
    let key = key(match settle {
        Settle::Accept => "stale-accept",
        Settle::Abandon => "stale-abandon",
    });
    let first = claimed(store, &key, "a fresh key").await?;
    wait(lease + margin(lease)).await?;
    let second = claimed(store, &key, "a re-claim after the lease expired").await?;
    let stale = match settle {
        Settle::Accept => store.accept(&key, &first).await,
        Settle::Abandon => store.abandon(&key, &first).await,
    };
    if stale.is_ok() {
        return Err(format!(
            "the expired first holder's {settle:?} returned Ok while a second claim holds the \
             key; settlement is not fenced by the lease token"
        ));
    }
    expect(
        store,
        &key,
        Claim::InFlight,
        "the key after the stale settlement (it must stay held by the second claim)",
    )
    .await?;
    accept(store, &key, &second, "the second holder").await?;
    expect(
        store,
        &key,
        Claim::Duplicate,
        "after the second holder accepted",
    )
    .await
}

async fn tokens_are_fresh_per_claim<S: DedupStore>(store: &S) -> Outcome {
    let a = key("fresh-a");
    let b = key("fresh-b");
    let first = claimed(store, &a, "a fresh key").await?;
    abandon(store, &a, &first, "the first holder").await?;
    let second = claimed(store, &a, "the abandoned key").await?;
    let other = claimed(store, &b, "another key").await?;
    let tokens = [&first, &second, &other];
    if tokens.iter().any(|t| t.as_str().is_empty()) {
        return Err("a claim returned an empty token".into());
    }
    let distinct: HashSet<&str> = tokens.iter().map(|t| t.as_str()).collect();
    if distinct.len() != tokens.len() {
        return Err(format!(
            "tokens repeat across claims ({first:?}, {second:?}, {other:?}); a reused token \
             lets an earlier holder settle a later lease"
        ));
    }
    Ok(())
}

/// Deliberately broken stores, the negative controls of the suite: each one
/// must fail the checks it is built to violate, which proves those checks can
/// fail. Never use them outside tests.
///
/// All of them read time through [`tokio::time::Instant`] and use
/// [`LEASE`](broken::LEASE).
pub mod broken {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use asx::{BoxFuture, Claim, ClaimToken, DedupStore};
    use tokio::time::Instant;

    type BoxError = Box<dyn std::error::Error + Send + Sync>;

    /// The lease of every broken store (the same as `MemoryDedup`'s).
    pub const LEASE: Duration = Duration::from_secs(5 * 60);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Flaw {
        KeyOnly,
        NonAtomic,
        DuplicateWhileInFlight,
        AbandonReopens,
        NoLease,
        Failing,
    }

    #[derive(Debug)]
    enum Entry {
        Held { token: ClaimToken, until: Instant },
        Accepted,
    }

    enum Decision {
        Done(Claim),
        Free,
    }

    #[derive(Debug)]
    struct Model {
        flaw: Flaw,
        entries: Mutex<HashMap<String, Entry>>,
        counter: AtomicU64,
    }

    impl Model {
        fn new(flaw: Flaw) -> Model {
            Model {
                flaw,
                entries: Mutex::new(HashMap::new()),
                counter: AtomicU64::new(0),
            }
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
            self.entries.lock().unwrap_or_else(|e| e.into_inner())
        }

        fn failing(&self) -> Result<(), BoxError> {
            if self.flaw == Flaw::Failing {
                Err("backend unavailable".into())
            } else {
                Ok(())
            }
        }

        fn live(&self, until: Instant, now: Instant) -> bool {
            self.flaw == Flaw::NoLease || until > now
        }

        fn decide(&self, entries: &HashMap<String, Entry>, key: &str, now: Instant) -> Decision {
            match entries.get(key) {
                Some(Entry::Accepted) => Decision::Done(Claim::Duplicate),
                Some(Entry::Held { until, .. }) if self.live(*until, now) => {
                    Decision::Done(if self.flaw == Flaw::DuplicateWhileInFlight {
                        Claim::Duplicate
                    } else {
                        Claim::InFlight
                    })
                }
                _ => Decision::Free,
            }
        }

        fn take(&self, entries: &mut HashMap<String, Entry>, key: &str, now: Instant) -> Claim {
            let token = if self.flaw == Flaw::KeyOnly {
                // The same "token" for every claim of the key.
                ClaimToken::new(key)
            } else {
                ClaimToken::new(format!(
                    "lease-{}",
                    self.counter.fetch_add(1, Ordering::Relaxed)
                ))
            };
            entries.insert(
                key.to_string(),
                Entry::Held {
                    token: token.clone(),
                    until: now + LEASE,
                },
            );
            Claim::Claimed(token)
        }

        fn claim_atomic(&self, key: &str) -> Result<Option<Claim>, BoxError> {
            self.failing()?;
            let now = Instant::now();
            let mut entries = self.lock();
            match self.decide(&entries, key, now) {
                Decision::Done(claim) => Ok(Some(claim)),
                Decision::Free if self.flaw == Flaw::NonAtomic => Ok(None),
                Decision::Free => Ok(Some(self.take(&mut entries, key, now))),
            }
        }

        async fn claim(&self, key: &str) -> Result<Claim, BoxError> {
            if let Some(claim) = self.claim_atomic(key)? {
                return Ok(claim);
            }
            // SELECT, then INSERT in a separate step: racing callers all saw
            // the key free and all take it.
            tokio::task::yield_now().await;
            let now = Instant::now();
            Ok(self.take(&mut self.lock(), key, now))
        }

        fn settle(&self, key: &str, token: &ClaimToken, accept: bool) -> Result<(), BoxError> {
            self.failing()?;
            let now = Instant::now();
            let mut entries = self.lock();
            match entries.get(key) {
                Some(Entry::Accepted) if !accept && self.flaw == Flaw::AbandonReopens => {
                    entries.remove(key);
                    Ok(())
                }
                Some(Entry::Held { token: held, until })
                    if self.live(*until, now) && (self.flaw == Flaw::KeyOnly || held == token) =>
                {
                    if accept {
                        entries.insert(key.to_string(), Entry::Accepted);
                    } else {
                        entries.remove(key);
                    }
                    Ok(())
                }
                _ => Err("the key is not held under this token".into()),
            }
        }
    }

    macro_rules! broken_store {
        ($(#[$doc:meta])* $name:ident, $flaw:expr) => {
            $(#[$doc])*
            #[derive(Debug)]
            pub struct $name(Model);

            impl Default for $name {
                fn default() -> Self {
                    Self(Model::new($flaw))
                }
            }

            impl DedupStore for $name {
                fn claim<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Claim, BoxError>> {
                    Box::pin(self.0.claim(key))
                }

                fn accept<'a>(
                    &'a self,
                    key: &'a str,
                    token: &'a ClaimToken,
                ) -> BoxFuture<'a, Result<(), BoxError>> {
                    Box::pin(std::future::ready(self.0.settle(key, token, true)))
                }

                fn abandon<'a>(
                    &'a self,
                    key: &'a str,
                    token: &'a ClaimToken,
                ) -> BoxFuture<'a, Result<(), BoxError>> {
                    Box::pin(std::future::ready(self.0.settle(key, token, false)))
                }
            }
        };
    }

    broken_store!(
        /// Settles by key alone and hands out the key itself as the token:
        /// any holder, stale or current, can accept or abandon. Fails exactly
        /// `stale_holder_cannot_accept`, `stale_holder_cannot_abandon` and
        /// `tokens_are_fresh_per_claim`.
        KeyOnlyDedup,
        Flaw::KeyOnly
    );

    broken_store!(
        /// Checks the key and takes it in two steps with a yield between them
        /// (`SELECT` then `INSERT`). Fails `concurrent_claim_admits_exactly_one`.
        NonAtomicDedup,
        Flaw::NonAtomic
    );

    broken_store!(
        /// Reports an unsettled claim as `Duplicate` instead of `InFlight`.
        /// Fails `unsettled_claim_reports_in_flight`, and every check that
        /// expects `InFlight` while a lease is held.
        DuplicateWhileInFlightDedup,
        Flaw::DuplicateWhileInFlight
    );

    broken_store!(
        /// Lets `abandon` delete an accepted key. Fails
        /// `abandon_never_reopens_an_accepted_key`.
        AbandonReopensDedup,
        Flaw::AbandonReopens
    );

    broken_store!(
        /// Leases never expire, so a crashed handler blocks its key forever.
        /// Fails `lease_expiry_allows_reclaim` and both stale-holder checks.
        NoLeaseDedup,
        Flaw::NoLease
    );

    broken_store!(
        /// Every call returns `Err`. Fails every check: an erroring backend
        /// is never a pass (fail closed).
        FailingDedup,
        Flaw::Failing
    );
}
