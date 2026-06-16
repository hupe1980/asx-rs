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

/// Drive a `BoxFuture` to completion synchronously.
///
/// This is provided for the **sync receive path** (`receive_push_with_dedup_sync`),
/// which runs inside `tokio::task::spawn_blocking` and cannot `.await` a future.
/// All in-memory [`DedupStorage`] implementations return a `Poll::Ready` future
/// immediately and this function resolves them in O(1).
///
/// # Panics
/// Panics with a clear message if the future returns `Poll::Pending`, which
/// indicates an async backend being called from the sync path.  In that case,
/// switch to `receive_push_with_dedup_async` which properly `.await`s the dedup call.
#[inline]
pub(crate) fn drive_dedup_future<T>(future: impl Future<Output = T>) -> T {
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    match std::pin::pin!(future).poll(&mut cx) {
        Poll::Ready(val) => val,
        Poll::Pending => panic!(
            "DedupStorage::first_seen returned Poll::Pending from a sync receive context. \
             Use `receive_push_with_dedup_async` for async-backed dedup stores."
        ),
    }
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
/// **Stability notice — forward declaration only.**
/// This trait is exported as public API, but no public function in `asx-rs 0.1`
/// accepts a `dyn ReconciliationStorage` parameter.  It is provided so that
/// downstream crates can implement it against a future stable integration surface
/// without a dependency version bump.  The trait shape (method signatures, return
/// types, error variants) is subject to breaking change while the crate is at
/// `0.x`.  Pin to an exact `asx-rs` patch version if you implement this trait.
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
    /// Returns Ok(true) if enqueued (not previously seen by idempotency key).
    /// Returns Ok(false) if duplicate (already in queue).
    /// Returns Err if storage backend fails (fail-closed for correctness).
    fn enqueue(&self, request: ReconciliationRequest) -> crate::core::Result<bool>;

    /// Retrieve all queued reconciliation requests.
    ///
    /// Returns a snapshot of the current queue.  Callers should process the
    /// returned `Vec` outside the storage lock; do not call back into this
    /// storage from within any callback derived from the snapshot.
    fn queued_requests(&self) -> crate::core::Result<Vec<ReconciliationRequest>>;

    /// Mark a reconciliation request as resolved and remove it from the queue.
    /// `idempotency_key` must match the key used during `enqueue`.
    /// Returns Ok(true) if the request was found and removed, Ok(false) if not found.
    /// Returns Err if storage backend fails (fail-closed).
    fn resolve(&self, idempotency_key: &str) -> crate::core::Result<bool>;
}

pub use memory::{
    BoundedFifoDedupStorage, InMemoryDedupStorage, InMemoryReconciliationStorage, TtlDedupStorage,
};
