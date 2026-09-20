#![cfg(feature = "testing")]
//! An async-backed `DedupStorage` must work on the receive paths.
//!
//! The trait returns `BoxFuture` precisely so Redis/PostgreSQL/DynamoDB
//! backends can implement it natively — and `cluster_safe()`, which the strict
//! production startup gate requires, implies exactly such a store. A backend
//! that yields must therefore be driven to completion, not polled once.

use asx_rs::storage::{BoxFuture, DedupStorage, DedupVerdict, drive_dedup_future};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Yields before answering, like any network round trip.
#[derive(Debug, Default)]
struct AsyncBackedDedup {
    claims: AtomicUsize,
}

impl DedupStorage for AsyncBackedDedup {
    fn is_durable(&self) -> bool {
        true
    }
    fn cluster_safe(&self) -> bool {
        true
    }

    fn claim<'a>(&'a self, _key: &'a str) -> BoxFuture<'a, asx_rs::Result<DedupVerdict>> {
        Box::pin(async move {
            // Several yields: a single extra poll must not be enough.
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
            self.claims.fetch_add(1, Ordering::SeqCst);
            Ok(DedupVerdict::Claimed)
        })
    }

    fn accept<'a>(&'a self, _key: &'a str) -> BoxFuture<'a, asx_rs::Result<()>> {
        Box::pin(async move {
            tokio::task::yield_now().await;
            Ok(())
        })
    }

    fn abandon<'a>(&'a self, _key: &'a str) -> BoxFuture<'a, asx_rs::Result<()>> {
        Box::pin(async move {
            tokio::task::yield_now().await;
            Ok(())
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_backend_is_driven_on_a_multi_thread_runtime() {
    let backend = AsyncBackedDedup::default();
    // `block_in_place` requires a multi-thread runtime; this is the shape a
    // real deployment uses.
    let verdict = tokio::task::spawn_blocking(move || {
        let v = drive_dedup_future(backend.claim("k")).expect("claim");
        assert_eq!(backend.claims.load(Ordering::SeqCst), 1);
        v
    })
    .await
    .expect("join");
    assert_eq!(verdict, DedupVerdict::Claimed);
}

#[tokio::test(flavor = "current_thread")]
async fn async_backend_is_driven_from_spawn_blocking_on_a_current_thread_runtime() {
    let backend = AsyncBackedDedup::default();
    let verdict = tokio::task::spawn_blocking(move || drive_dedup_future(backend.claim("k")))
        .await
        .expect("join")
        .expect("claim");
    assert_eq!(verdict, DedupVerdict::Claimed);
}

#[test]
fn in_memory_backend_still_works_with_no_runtime_at_all() {
    // The fast path: an immediately-ready future must not need a runtime, so
    // the pure-sync entry points keep working outside Tokio entirely.
    let backend = asx_rs::storage::TtlDedupStorage::default();
    let verdict = drive_dedup_future(backend.claim("k")).expect("claim");
    assert_eq!(verdict, DedupVerdict::Claimed);
    drive_dedup_future(backend.accept("k")).expect("accept");
    assert_eq!(
        drive_dedup_future(backend.claim("k")).expect("claim"),
        DedupVerdict::Duplicate
    );
}

#[test]
#[should_panic(expected = "no Tokio runtime available")]
fn async_backend_with_no_runtime_says_so() {
    let backend = AsyncBackedDedup::default();
    let _ = drive_dedup_future(backend.claim("k"));
}
