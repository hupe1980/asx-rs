//! The one bridge from async code onto Tokio's blocking pool.
//!
//! Signing, verification, decryption and MIME/SOAP assembly are CPU-bound and
//! synchronous. Every async entry point runs them through [`spawn_crypto`],
//! which bounds how many run at once with a process-wide semaphore so a burst
//! of inbound traffic cannot occupy every blocking thread.

use std::sync::{Arc, OnceLock};

use tokio::sync::Semaphore;

use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};

/// Permits in the process-wide crypto semaphore: twice the available
/// parallelism, clamped to `4..=128`. Slightly above core count keeps
/// throughput stable while bounding queueing.
fn crypto_concurrency() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().saturating_mul(2))
        .unwrap_or(8)
        .clamp(4, 128)
}

fn crypto_semaphore() -> Arc<Semaphore> {
    static SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();
    Arc::clone(SEMAPHORE.get_or_init(|| Arc::new(Semaphore::new(crypto_concurrency()))))
}

/// Run `f` once on the blocking pool after acquiring a crypto permit.
///
/// `stage` labels the error if the blocking task panics or is cancelled.
pub(crate) async fn spawn_crypto<T: Send + 'static>(
    stage: &'static str,
    session: &SessionContext,
    f: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let permit = crypto_semaphore()
        .acquire_owned()
        .await
        .expect("the process-wide crypto semaphore is never closed");
    // The work keeps its place in the caller's trace: the current span is its
    // parent and the caller's subscriber (thread-local or global) sees it.
    let span = tracing::Span::current();
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        tracing::dispatcher::with_default(&dispatch, || span.in_scope(f))
    })
    .await
    .map_err(|err| {
        AsxError::new(
            ErrorCode::TransportFailure,
            format!("blocking task failed: {err}"),
            ErrorContext::for_session(stage, session),
        )
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_concurrency_is_bounded() {
        let n = crypto_concurrency();
        assert!((4..=128).contains(&n), "{n}");
    }

    #[tokio::test]
    async fn spawn_crypto_returns_the_closure_result() {
        let session = SessionContext::new("s", "p", "strict").expect("session");
        let value = spawn_crypto("runtime_test", &session, || Ok(7)).await;
        assert_eq!(value.expect("ok"), 7);
    }

    #[tokio::test]
    async fn a_panicking_task_becomes_a_transport_failure() {
        let session = SessionContext::new("s", "p", "strict").expect("session");
        let err = spawn_crypto::<()>("runtime_test_panic", &session, || panic!("boom"))
            .await
            .expect_err("panic must surface as an error");
        assert_eq!(err.code, ErrorCode::TransportFailure);
        assert_eq!(err.context.stage, "runtime_test_panic");
    }
}
