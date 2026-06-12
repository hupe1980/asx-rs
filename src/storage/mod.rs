//! Pluggable storage backends for dedup and reconciliation.
//!
//! This module provides trait-based abstractions for idempotency key tracking
//! and reconciliation request queuing, enabling production deployments to use
//! distributed backends (Redis, PostgreSQL, etc.) while maintaining simple
//! in-memory implementations for development and testing.
//!
pub mod memory;

use crate::reliability::ReconciliationRequest;

/// Trait for distributed dedup state storage.
/// Implementations must provide strict idempotency guarantees: each idempotency key
/// is seen exactly once, and lock poison/infrastructure failures must fail-closed.
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
    /// Returns Ok(true) if this is the first occurrence (not a duplicate).
    /// Returns Ok(false) if this key has been seen before (duplicate).
    /// Returns Err if storage backend fails (fail-closed for correctness).
    fn first_seen(&self, idempotency_key: &str) -> crate::core::Result<bool>;
}

/// Trait for distributed reconciliation request queuing.
/// Implementations must preserve order and prevent duplicate reconciliation attempts.
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
