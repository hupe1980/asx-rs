//! Pluggable storage backends for dedup and reconciliation.
//!
//! This module provides trait-based abstractions for idempotency key tracking
//! and reconciliation request queuing, enabling production deployments to use
//! distributed backends (Redis, PostgreSQL, etc.) while maintaining simple
//! in-memory implementations for development and testing.
//!
pub mod memory;

use crate::reliability::ReconciliationRequest;
use std::future::Future;
use std::pin::Pin;
use std::task::Poll;

/// A conformance suite an embedder runs against its own backend, to establish
/// the durability and atomicity that `is_durable()`, `cluster_safe()` and
/// `DurableAuditSink::durability()` only *declare*.
///
/// Covers all three storage traits: [`DedupStorage`], [`ReconciliationStorage`]
/// and [`crate::observability::audit_sink::DurableAuditSink`].
#[cfg(feature = "testing")]
pub mod conformance;

/// `dyn`-safe boxed async future for storage trait methods.
///
/// This is the return type of every [`DedupStorage`] and
/// [`ReconciliationStorage`] method.  Implementations box their async body
/// with `Box::pin(async move { ... })`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Core implementation of the drive-a-future-from-sync-code pattern.
///
/// Both [`drive_dedup_future`] and [`drive_reconciliation_future`] delegate here,
/// so the two-step logic below is maintained in one place while each keeps its
/// own diagnostic.
///
/// Two steps, in this order:
///
/// 1. **Poll once with a no-op waker.** Every in-tree backend is in-memory and
///    resolves immediately, so the common case never touches the runtime and
///    costs nothing. It also means the pure-sync entry points keep working with
///    no Tokio runtime present at all.
/// 2. **If it is genuinely pending, hand it to the runtime.** A network-backed
///    store — Redis, PostgreSQL, DynamoDB — yields at least once, which is
///    exactly what `cluster_safe()` implies and what the strict production gate
///    requires. Polling such a future once and giving up turned the trait's own
///    recommended backends into a panic on the first inbound message. This is
///    the same bridge `fetch_ocsp_responses_with_cache_provider_scoped` uses.
///
/// Re-polling a future that returned `Pending` is part of the `Future`
/// contract — an executor may poll with a different waker, and implementations
/// re-register on each poll.
#[inline]
fn drive_sync_future<T>(future: impl Future<Output = T>, context: &'static str) -> T {
    let mut future = Box::pin(future);

    {
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        if let Poll::Ready(val) = future.as_mut().poll(&mut cx) {
            return val;
        }
    }

    // Pending: this is an async-backed store. Drive it properly if we are
    // inside a runtime.
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            if matches!(
                handle.runtime_flavor(),
                tokio::runtime::RuntimeFlavor::MultiThread
            ) {
                // Tell the scheduler this worker is about to block, so the
                // other tasks on it are not stalled for the round trip.
                tokio::task::block_in_place(|| handle.block_on(future))
            } else {
                // A current-thread runtime has no other worker to hand work to.
                // This is reachable from `spawn_blocking` (not an async
                // context, so `block_on` is allowed); calling a *_sync receive
                // directly from a current-thread async task is not, and Tokio
                // panics with its own message saying so.
                handle.block_on(future)
            }
        }
        Err(_) => panic!("{context}"),
    }
}

/// Drive a `BoxFuture` to completion synchronously.
///
/// This is provided for **sync receive paths** that cannot `.await` a future:
/// - `receive_push_sync` (dedup)
/// - `receive_with_mdn_with_reliability` and internal AS4 helpers (reconciliation)
///
/// All in-memory storage implementations return a `Poll::Ready` future immediately
/// and this function resolves them in O(1).
///
/// # Panics
/// Panics with a clear message if the future returns `Poll::Pending`, which
/// indicates an async backend being called from the sync path.  For dedup, switch
/// to `receive_push`.  For reconciliation sync callers, ensure
/// only in-memory backends are used on sync paths.
#[allow(dead_code)]
#[inline]
pub fn drive_dedup_future<T>(future: impl Future<Output = T>) -> T {
    drive_sync_future(
        future,
        "DedupStorage returned Poll::Pending with no Tokio runtime available. \
         An async-backed dedup store needs a runtime to drive it: call the \
         receive path from within one, or use an in-memory backend.",
    )
}

/// Drive a [`ReconciliationStorage`] `BoxFuture` to completion synchronously.
///
/// Provided for sync receive paths (`receive_with_mdn_with_reliability`, internal
/// AS4 pull/push helpers) that hold a `&dyn ReconciliationStorage` and cannot `.await`.
/// In-memory backends resolve immediately (`Poll::Ready`); network-backed backends must
/// not be used from sync paths — this function will panic with a diagnostic if they do.
///
/// # Panics
/// Panics if the future returns `Poll::Pending` (async backend on a sync path).
#[inline]
pub(crate) fn drive_reconciliation_future<T>(future: impl Future<Output = T>) -> T {
    drive_sync_future(
        future,
        "ReconciliationStorage returned Poll::Pending with no Tokio runtime available. \
         An async-backed reconciliation store needs a runtime to drive it: call \
         the receive path from within one, or use an in-memory backend.",
    )
}

/// Verdict returned by [`DedupStorage::claim`].
///
/// Deduplication is **two-phase**: a claim is taken before the message is
/// processed and settled once its fate is known. The single-call
/// check-and-record shape this replaces could not express "seen, but not yet
/// known to be handled", so a message that failed after the check had already
/// spent its replay protection — the retransmission was answered as a
/// duplicate and the message was lost (D59).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupVerdict {
    /// First occurrence. The caller now **owns an unsettled claim** and must
    /// resolve it with [`DedupStorage::accept`] or [`DedupStorage::abandon`].
    Claimed,
    /// A previous attempt was settled with [`accept`](DedupStorage::accept):
    /// this is a genuine replay and must not be processed again.
    Duplicate,
    /// Another attempt holds an unexpired claim on this key and has not
    /// settled it yet — a concurrent delivery of the same message.
    ///
    /// The message is neither accepted nor rejected. Do **not** acknowledge it:
    /// leave it unanswered (or answer 503) so the sender retransmits under
    /// `ReceptionAwareness` once the in-flight attempt has settled.
    InFlight,
}

/// Trait for distributed dedup state storage.
///
/// # Two-phase protocol
///
/// | Step | Method | Meaning |
/// |---|---|---|
/// | 1 | [`claim`](Self::claim) | Atomically take the key, or report `Duplicate` / `InFlight` |
/// | 2a | [`accept`](Self::accept) | The message was handled durably — settle the key so replays are rejected for the TTL window |
/// | 2b | [`abandon`](Self::abandon) | The message was **not** handled — release the key so a retransmission is processed |
///
/// Splitting the two is what makes replay protection safe to spend: nothing is
/// permanently deduplicated until someone has taken durable responsibility for
/// it.
///
/// # Claim leases
///
/// An unsettled claim must **expire**. A process that crashes between `claim`
/// and `accept` would otherwise wedge that `eb:MessageId` forever, and no
/// retransmission could ever be processed. Implementations therefore record a
/// claim with a lease and treat an expired claim as absent, so a later
/// [`claim`](Self::claim) on the same key returns
/// [`Claimed`](DedupVerdict::Claimed) rather than
/// [`InFlight`](DedupVerdict::InFlight).
///
/// Size the lease above the longest plausible processing time and below the
/// sender's retransmission interval. [`TtlDedupStorage`] defaults to 5 minutes
/// ([`TtlDedupStorage::with_claim_lease`] overrides it).
///
/// # Async by default
///
/// Every method is **async** via a `BoxFuture` return so that production
/// backends on Redis, PostgreSQL, DynamoDB or SlateDB implement them natively
/// without `block_in_place` / `Handle::current().block_on(…)` boilerplate.
/// In-memory implementations wrap synchronous logic in
/// `Box::pin(async move { … })` and resolve on the first `.await`.
///
/// Infrastructure failures must **fail closed** — return `Err`, never a verdict
/// that lets an unverified message through.
///
/// # Implementing it
///
/// A process-local backend wraps synchronous logic; the future resolves on the
/// first `.await`.
///
/// ```
/// use asx_rs::storage::{BoxFuture, DedupStorage, DedupVerdict};
/// use std::collections::HashMap;
/// use std::sync::Mutex;
/// use std::time::{Duration, Instant};
///
/// #[derive(Debug, PartialEq)]
/// enum State {
///     /// Claimed but not settled; the lease expires at this instant.
///     InFlight(Instant),
///     Accepted,
/// }
///
/// #[derive(Debug, Default)]
/// struct MyMemoryStore {
///     entries: Mutex<HashMap<String, State>>,
/// }
///
/// impl DedupStorage for MyMemoryStore {
///     fn is_durable(&self) -> bool {
///         false // forgets everything on restart
///     }
///
///     fn claim<'a>(&'a self, key: &'a str) -> BoxFuture<'a, asx_rs::Result<DedupVerdict>> {
///         Box::pin(async move {
///             // A poisoned lock must fail closed, never report "not seen".
///             let mut entries = self.entries.lock().map_err(|_| {
///                 asx_rs::AsxError::new(
///                     asx_rs::ErrorCode::ReliabilityFailure,
///                     "dedup mutex poisoned",
///                     asx_rs::ErrorContext::new("my_memory_store"),
///                 )
///             })?;
///             let now = Instant::now();
///             match entries.get(key) {
///                 Some(State::Accepted) => return Ok(DedupVerdict::Duplicate),
///                 // An unexpired claim is held by a concurrent attempt.
///                 Some(State::InFlight(until)) if now < *until => {
///                     return Ok(DedupVerdict::InFlight);
///                 }
///                 // Absent, or an expired lease we are free to take over.
///                 _ => {}
///             }
///             entries.insert(key.to_string(), State::InFlight(now + Duration::from_secs(300)));
///             Ok(DedupVerdict::Claimed)
///         })
///     }
///
///     fn accept<'a>(&'a self, key: &'a str) -> BoxFuture<'a, asx_rs::Result<()>> {
///         Box::pin(async move {
///             let mut entries = self.entries.lock().unwrap();
///             entries.insert(key.to_string(), State::Accepted);
///             Ok(())
///         })
///     }
///
///     fn abandon<'a>(&'a self, key: &'a str) -> BoxFuture<'a, asx_rs::Result<()>> {
///         Box::pin(async move {
///             let mut entries = self.entries.lock().unwrap();
///             // Only drop our own unsettled claim — never an accepted key.
///             if matches!(entries.get(key), Some(State::InFlight(_))) {
///                 entries.remove(key);
///             }
///             Ok(())
///         })
///     }
/// }
///
/// # fn main() {
/// # let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
/// let store = MyMemoryStore::default();
/// rt.block_on(async {
///     assert_eq!(store.claim("msg-1").await.unwrap(), DedupVerdict::Claimed);
///     assert_eq!(store.claim("msg-1").await.unwrap(), DedupVerdict::InFlight);
///     // Processing failed: release the key so the retransmission is processed.
///     store.abandon("msg-1").await.unwrap();
///     assert_eq!(store.claim("msg-1").await.unwrap(), DedupVerdict::Claimed);
///     store.accept("msg-1").await.unwrap();
///     assert_eq!(store.claim("msg-1").await.unwrap(), DedupVerdict::Duplicate);
/// });
/// # }
/// ```
///
/// A durable, cluster-safe backend declares both properties and does the work
/// in the returned future — one round trip, no `block_on`. The
/// [persistence guide](https://hupe1980.github.io/asx-rs/docs/persistence/)
/// has a Redis implementation, and `tests/interop_redis_storage_conformance.rs`
/// runs it against a real server.
pub trait DedupStorage: Send + Sync + std::fmt::Debug {
    /// Return whether this backend persists dedup state durably.
    ///
    /// Implementations that keep replay-protection keys only in process memory
    /// must return `false`. Durable/network-backed implementations should
    /// return `true` once restart-safe persistence semantics are guaranteed.
    fn is_durable(&self) -> bool;

    /// Return whether this backend is safe for multi-node cluster deployments.
    ///
    /// Implementations backed by distributed stores (Redis, PostgreSQL, etc.)
    /// that provide atomic compare-and-swap semantics should return `true`.
    /// In-memory backends must return `false` — they only provide single-node
    /// idempotency guarantees and will silently permit duplicates when traffic
    /// is spread across multiple instances.
    fn cluster_safe(&self) -> bool {
        false
    }

    /// Phase 1: atomically claim an idempotency key.
    ///
    /// See [`DedupVerdict`] for the three outcomes and **Claim leases** on the
    /// trait for why an unsettled claim must expire.
    ///
    /// The whole decision — inspect, expire, insert — must be **one atomic
    /// step**. A read followed by a separate write lets two concurrent
    /// deliveries of the same message both observe "absent" and both claim it.
    ///
    /// Returns `Err(_)` on a storage backend failure (fail-closed).
    fn claim<'a>(
        &'a self,
        idempotency_key: &'a str,
    ) -> BoxFuture<'a, crate::core::Result<DedupVerdict>>;

    /// Phase 2a: settle a claim as **accepted**.
    ///
    /// Call this only once the message is durably handled — persisted, queued,
    /// or dead-lettered — because from here on every retransmission of it is
    /// answered [`Duplicate`](DedupVerdict::Duplicate) for the TTL window.
    ///
    /// Accepting a key that is not currently claimed is a no-op, not an error:
    /// settlement must stay idempotent under retry.
    fn accept<'a>(&'a self, idempotency_key: &'a str) -> BoxFuture<'a, crate::core::Result<()>>;

    /// Phase 2b: settle a claim as **abandoned**, releasing the key.
    ///
    /// Call this when the message was *not* handled. The next delivery of the
    /// same `eb:MessageId` is then treated as first-seen and processed, which
    /// is what makes a `ReceptionAwareness` retransmission a recovery path
    /// instead of a silent drop.
    ///
    /// Implementations must only release a key that is still unsettled — an
    /// already-[`accept`](Self::accept)ed key must survive, or a late abandon
    /// would reopen a message that was genuinely processed.
    fn abandon<'a>(&'a self, idempotency_key: &'a str) -> BoxFuture<'a, crate::core::Result<()>>;
}

/// Trait for distributed reconciliation request queuing.
/// Implementations must preserve order and prevent duplicate reconciliation attempts.
///
/// # Stability
///
/// `ReconciliationStorage` is part of the public API and is accepted by
/// several functions in [`crate::presets`] and [`crate::reliability`], but its
/// **trait shape — method signatures, return types, and error variants — is
/// subject to breaking change** while this crate is at `0.x`.
///
/// If you implement this trait in downstream code, pin to an exact `asx-rs`
/// version in your `Cargo.toml` to avoid unexpected breakage:
///
/// ```toml
/// [dependencies]
/// asx-rs = "=0.13.0"  # exact-version pin — ReconciliationStorage is not yet stable
/// ```
///
/// The sealed-trait pattern is intentionally not used here so that downstream
/// crates can provide production-grade backends (PostgreSQL, Redis, etc.) before
/// this crate reaches `1.0`.  Once the trait stabilises the exact-pin
/// requirement will be lifted and a crate-level migration notice will be
/// published.
pub trait ReconciliationStorage: Send + Sync + std::fmt::Debug {
    /// Return whether this backend persists reconciliation state durably.
    ///
    /// Implementations that keep state only in process memory must return `false`.
    /// Durable/network-backed implementations (e.g. PostgreSQL/Redis) should
    /// return `true` once persistence semantics are guaranteed.
    fn is_durable(&self) -> bool;

    /// Return whether this backend is safe for multi-node cluster deployments.
    ///
    /// Implementations backed by distributed stores (Redis, PostgreSQL, etc.)
    /// that provide atomic compare-and-swap semantics should return `true`.
    /// In-memory backends must return `false` — they only provide single-node
    /// reconciliation guarantees and will silently permit duplicate reconciliation
    /// attempts when traffic is spread across multiple instances.
    fn cluster_safe(&self) -> bool {
        false
    }

    /// Enqueue a reconciliation request.
    ///
    /// Returns a future that resolves to:
    /// - `Ok(true)` — enqueued successfully (not a duplicate).
    /// - `Ok(false)` — duplicate (already in queue by idempotency key).
    /// - `Err(_)` — storage backend failure (fail-closed for correctness).
    ///
    /// The future is `Send` so it can be driven from async tasks on any executor.
    /// In-memory implementations resolve immediately (`Poll::Ready`).
    fn enqueue<'a>(
        &'a self,
        request: ReconciliationRequest,
    ) -> BoxFuture<'a, crate::core::Result<bool>>;

    /// Retrieve all queued reconciliation requests.
    ///
    /// Returns a snapshot of the current queue. Callers should process the
    /// returned `Vec` outside the storage lock; do not call back into this
    /// storage from within any callback derived from the snapshot.
    ///
    /// The future is `Send` and resolves immediately for in-memory backends.
    fn queued_requests(&self) -> BoxFuture<'_, crate::core::Result<Vec<ReconciliationRequest>>>;

    /// Mark a reconciliation request as resolved and remove it from the queue.
    ///
    /// `idempotency_key` must match the key used during `enqueue`.
    /// Returns `Ok(true)` if the request was found and removed, `Ok(false)` if not found.
    /// Returns `Err` if storage backend fails (fail-closed).
    ///
    /// The future is `Send` and resolves immediately for in-memory backends.
    fn resolve<'a>(&'a self, idempotency_key: &'a str) -> BoxFuture<'a, crate::core::Result<bool>>;
}

/// An unsettled deduplication claim, handed to the caller with a first-seen
/// message.
///
/// Holding one means the key is **spent but not committed**: replays are held
/// off, and nothing is permanently deduplicated yet. Settle it once the
/// message's fate is durable —
///
/// * [`accept`](Self::accept) — persisted, queued or dead-lettered. Later
///   retransmissions of this `eb:MessageId` are answered as duplicates.
/// * [`abandon`](Self::abandon) — not handled. The next retransmission is
///   processed as first-seen, which is what turns `ReceptionAwareness` into a
///   recovery path.
///
/// Dropping a claim without settling it is not corruption, only a delay: the
/// backend's claim lease expires and a retransmission re-claims the key. It is
/// still a bug, so the drop is logged and the type is `#[must_use]`.
///
/// # Example
///
/// ```no_run
/// use asx_rs::storage::{DedupClaim, DedupStorage, DedupVerdict};
/// use std::sync::Arc;
///
/// # async fn example(
/// #     backend: Arc<dyn DedupStorage>,
/// #     key: &str,
/// # ) -> asx_rs::Result<()> {
/// # fn persist_and_dispatch() -> asx_rs::Result<()> { Ok(()) }
/// # fn dead_lettered(_: &asx_rs::AsxError) -> bool { false }
/// # let claim: DedupClaim = match backend.claim(key).await? {
/// #     DedupVerdict::Claimed => unimplemented!("the receive pipeline mints this"),
/// #     _ => return Ok(()),
/// # };
/// match persist_and_dispatch() {
///     Ok(()) => claim.accept().await?,
///     // The message is ours now — a duplicate must not replay it.
///     Err(e) if dead_lettered(&e) => claim.accept().await?,
///     // We could not take responsibility: let the sender retransmit.
///     Err(e) => {
///         claim.abandon().await?;
///         return Err(e);
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[must_use = "an unsettled dedup claim holds the key until its lease expires; \
              call accept() or abandon()"]
pub struct DedupClaim {
    key: std::sync::Arc<str>,
    backend: std::sync::Arc<dyn DedupStorage>,
    settled: bool,
}

impl std::fmt::Debug for DedupClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DedupClaim")
            .field("key", &self.key)
            .field("settled", &self.settled)
            .finish_non_exhaustive()
    }
}

impl DedupClaim {
    /// Construct a claim over an already-claimed key.
    ///
    /// Only the receive pipeline calls this, immediately after
    /// [`DedupStorage::claim`] returned [`DedupVerdict::Claimed`] — the type is
    /// evidence that the claim was taken, so minting one without that call
    /// would be a lie.
    pub(crate) fn new(key: std::sync::Arc<str>, backend: std::sync::Arc<dyn DedupStorage>) -> Self {
        Self {
            key,
            backend,
            settled: false,
        }
    }

    /// The derived idempotency key this claim holds.
    ///
    /// Use it to record the message's own outcome under the same key, so a
    /// later duplicate can be answered from the stored result.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Settle as accepted: the message is durably handled and replays of it
    /// must be rejected for the backend's TTL window.
    pub async fn accept(mut self) -> crate::core::Result<()> {
        self.settled = true;
        self.backend.accept(&self.key).await
    }

    /// Settle as abandoned: the message was **not** handled, so release the key
    /// and let a retransmission be processed as first-seen.
    pub async fn abandon(mut self) -> crate::core::Result<()> {
        self.settled = true;
        self.backend.abandon(&self.key).await
    }

    /// [`accept`](Self::accept) from a synchronous context.
    ///
    /// # Panics
    /// Panics if the backend's future is not immediately ready — an async
    /// backend settled from a sync receive path. Use the async receive
    /// entrypoints with such a backend.
    pub fn accept_blocking(mut self) -> crate::core::Result<()> {
        self.settled = true;
        drive_dedup_future(self.backend.accept(&self.key))
    }

    /// [`abandon`](Self::abandon) from a synchronous context.
    ///
    /// # Panics
    /// See [`accept_blocking`](Self::accept_blocking).
    pub fn abandon_blocking(mut self) -> crate::core::Result<()> {
        self.settled = true;
        drive_dedup_future(self.backend.abandon(&self.key))
    }

    /// Settle from inside the pipeline without consuming the value.
    pub(crate) fn abandon_in_place(&mut self) -> crate::core::Result<()> {
        if self.settled {
            return Ok(());
        }
        self.settled = true;
        drive_dedup_future(self.backend.abandon(&self.key))
    }
}

impl Drop for DedupClaim {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        // Settling needs to await, and a Drop that blocks on a network backend
        // would deadlock or abort. The claim lease is the safety net: it
        // expires and the retransmission re-claims the key. Say so loudly —
        // until then this message cannot be redelivered.
        // `tracing` is an unconditional dependency, and a dropped claim is a
        // correctness bug — not something to hide behind a feature flag.
        tracing::error!(
            dedup_key = %self.key,
            "DedupClaim dropped without accept()/abandon(); the key stays claimed \
             until its lease expires and retransmissions are answered InFlight"
        );
    }
}

pub use memory::{DEFAULT_CLAIM_LEASE, InMemoryReconciliationStorage, TtlDedupStorage};

#[cfg(feature = "testing")]
pub use memory::DurableInMemoryDedupBackend;
