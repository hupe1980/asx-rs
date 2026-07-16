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

/// `dyn`-safe boxed async future for storage trait methods.
///
/// This is the return type of [`DedupStorage::first_seen`].  Implementations
/// box their async body with `Box::pin(async move { ... })`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Core implementation of the synchronous-poll drive pattern.
///
/// Both [`drive_dedup_future`] and [`drive_reconciliation_future`] delegate here.
/// Having one code path ensures the noop-waker poll logic is maintained in a
/// single place while preserving the distinct diagnostic messages.
#[inline]
fn drive_sync_future<T>(future: impl Future<Output = T>, context: &'static str) -> T {
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    match std::pin::pin!(future).poll(&mut cx) {
        Poll::Ready(val) => val,
        Poll::Pending => panic!("{context}"),
    }
}

/// Drive a `BoxFuture` to completion synchronously.
///
/// This is provided for **sync receive paths** that cannot `.await` a future:
/// - `receive_push_with_dedup_sync` (dedup)
/// - `receive_with_mdn_with_reliability` and internal AS4 helpers (reconciliation)
///
/// All in-memory storage implementations return a `Poll::Ready` future immediately
/// and this function resolves them in O(1).
///
/// # Panics
/// Panics with a clear message if the future returns `Poll::Pending`, which
/// indicates an async backend being called from the sync path.  For dedup, switch
/// to `receive_push_with_dedup_async`.  For reconciliation sync callers, ensure
/// only in-memory backends are used on sync paths.
#[allow(dead_code)]
#[inline]
pub(crate) fn drive_dedup_future<T>(future: impl Future<Output = T>) -> T {
    drive_sync_future(
        future,
        "DedupStorage::first_seen returned Poll::Pending from a sync receive context. \
         Use `receive_push_with_dedup_async` for async-backed dedup stores.",
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
        "ReconciliationStorage method returned Poll::Pending from a sync receive context. \
         Only in-memory ReconciliationStorage backends can be used from sync paths.",
    )
}

/// Trait for distributed dedup state storage.
///
/// The single required method [`first_seen`](Self::first_seen) is **async** via
/// a `BoxFuture` return so that production backends backed by Redis, PostgreSQL,
/// DynamoDB, or SlateDB can implement it natively without
/// `block_in_place` / `Handle::current().block_on(…)` boilerplate.
///
/// In-memory implementations simply wrap synchronous logic in `Box::pin(async move { … })` —
/// the future resolves immediately on the first `.await`.
///
/// Implementations must provide strict idempotency guarantees: each idempotency key
/// is seen exactly once, and lock poison/infrastructure failures must fail-closed.
///
/// # Example implementation (in-memory, sync-wrapped)
/// ```rust,ignore
/// impl DedupStorage for MyMemoryStore {
///     fn is_durable(&self) -> bool { false }
///     fn first_seen<'a>(&'a self, key: &'a str) -> BoxFuture<'a, asx_rs::core::Result<bool>> {
///         Box::pin(async move { self.inner_first_seen_sync(key) })
///     }
/// }
/// ```
///
/// # Example implementation (async backend)
/// ```rust,ignore
/// impl DedupStorage for RedisDedup {
///     fn is_durable(&self) -> bool { true }
///     fn first_seen<'a>(&'a self, key: &'a str) -> BoxFuture<'a, asx_rs::core::Result<bool>> {
///         Box::pin(async move {
///             self.redis.set_nx(key).await.map_err(|e| storage_err(e))
///         })
///     }
/// }
/// ```
pub trait DedupStorage: Send + Sync {
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

    /// Check if an idempotency key has been seen before.
    ///
    /// Returns a future that resolves to:
    /// - `Ok(true)` — first occurrence (not a duplicate); the key has been recorded.
    /// - `Ok(false)` — already seen (duplicate); the key was already present.
    /// - `Err(_)` — storage backend failure (fail-closed for correctness).
    ///
    /// The future is `Send` so that it can be driven from async tasks on any executor.
    fn first_seen<'a>(
        &'a self,
        idempotency_key: &'a str,
    ) -> BoxFuture<'a, crate::core::Result<bool>>;
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
/// asx-rs = "=0.5.0"  # exact-version pin — ReconciliationStorage is not yet stable
/// ```
///
/// The sealed-trait pattern is intentionally not used here so that downstream
/// crates can provide production-grade backends (PostgreSQL, Redis, etc.) before
/// this crate reaches `1.0`.  Once the trait stabilises the exact-pin
/// requirement will be lifted and a crate-level migration notice will be
/// published.
pub trait ReconciliationStorage: Send + Sync {
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

pub use memory::{
    BoundedFifoDedupStorage, InMemoryDedupStorage, InMemoryReconciliationStorage, TtlDedupStorage,
};

#[cfg(feature = "testing")]
pub use memory::DurableInMemoryDedupBackend;
