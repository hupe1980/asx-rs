//! An async-backed `DedupStore` must work on the receive path.
//!
//! The trait returns `BoxFuture` precisely so Redis/PostgreSQL/DynamoDB
//! backends can implement it natively. Every in-tree store resolves on the
//! first poll, so a store that really suspends is the case that proves the
//! library drives the future to completion instead of polling it once.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use asx::{BoxFuture, Claim, ClaimToken, DedupStore, MemoryDedup};
use asx_testkit::dedup::{DedupHarness, conformance};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Yields several times before answering, like any network round trip, and
/// counts the calls that completed.
#[derive(Debug, Default, Clone)]
struct AsyncBackedDedup {
    inner: Arc<MemoryDedup>,
    completed: Arc<AtomicUsize>,
}

impl AsyncBackedDedup {
    async fn round_trip(&self) {
        // Several yields: a single extra poll must not be enough.
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        self.completed.fetch_add(1, Ordering::SeqCst);
    }
}

impl DedupStore for AsyncBackedDedup {
    fn claim<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Claim, BoxError>> {
        Box::pin(async move {
            self.round_trip().await;
            self.inner.claim(key).await
        })
    }
    fn accept<'a>(
        &'a self,
        key: &'a str,
        token: &'a ClaimToken,
    ) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move {
            self.round_trip().await;
            self.inner.accept(key, token).await
        })
    }
    fn abandon<'a>(
        &'a self,
        key: &'a str,
        token: &'a ClaimToken,
    ) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move {
            self.round_trip().await;
            self.inner.abandon(key, token).await
        })
    }
}

#[derive(Debug)]
struct Harness;

impl DedupHarness for Harness {
    type Store = AsyncBackedDedup;
    fn open(&self) -> AsyncBackedDedup {
        AsyncBackedDedup::default()
    }
    fn lease(&self) -> Duration {
        Duration::from_secs(5 * 60)
    }
}

#[tokio::test(start_paused = true)]
async fn a_yielding_store_conforms() {
    let failures = conformance(&Harness).await;
    assert!(failures.is_empty(), "{failures:#?}");
}

#[cfg(feature = "as4")]
#[path = "common/peers.rs"]
mod peers;
#[cfg(feature = "as4")]
#[allow(unreachable_pub)]
#[path = "common/ported_as4.rs"]
mod ported;

/// A message and its retransmission through an `Inbound` over the yielding
/// store: claimed, accepted, then answered as a duplicate.
#[cfg(feature = "as4")]
async fn receive_through_a_yielding_store() {
    use peers::Preset;
    let p = peers::pair(Preset::Edelivery);
    p.sender
        .send(Preset::Edelivery.message(&p.to_b, b"x"))
        .await
        .expect("delivered");
    let request = p.loopback.last_request().unwrap();
    let store = AsyncBackedDedup::default();
    let inbound = ported::accepting_inbound(&p.receiver, store.clone());
    let (status, body) = ported::post(&inbound, ported::clone_request(&request)).await;
    assert_eq!(status, http::StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("Receipt"));
    assert_eq!(
        store.completed.load(Ordering::SeqCst),
        2,
        "claim and accept ran to completion"
    );
    let (status, _) = ported::post(&inbound, request).await;
    assert_eq!(status, http::StatusCode::OK, "duplicate receipted");
    assert_eq!(
        store.completed.load(Ordering::SeqCst),
        3,
        "the duplicate's claim"
    );
}

#[cfg(feature = "as4")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_store_is_driven_on_a_multi_thread_runtime() {
    receive_through_a_yielding_store().await;
}

#[cfg(feature = "as4")]
#[tokio::test(flavor = "current_thread")]
async fn async_store_is_driven_on_a_current_thread_runtime() {
    receive_through_a_yielding_store().await;
}
