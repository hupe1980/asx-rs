use super::super::large_message::As4FragmentJoiner;
use super::super::types::{As4ReceivePushProgress, As4ReceivePushRequest};
use super::{As4Verifier, EventBus, SessionContext, sync_core};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::storage::DedupStorage;
use std::sync::Arc;

pub(super) async fn receive_push_with_dedup_async_fragment_aware_with_shared_verifier(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushRequest,
    dedup_backend: Arc<dyn DedupStorage>,
    verifier: Arc<dyn As4Verifier + Send + Sync>,
    fragment_joiner: Arc<std::sync::Mutex<As4FragmentJoiner>>,
) -> Result<As4ReceivePushProgress> {
    let permit = crate::core::CryptoAdmissionControl::process_global()
        .acquire("as4_receive_push_async_admission", session)
        .await?;
    let blocking_session = session.clone();
    let blocking_bus = event_bus.clone();
    let error_session = session.clone();
    let blocking_verifier = Arc::clone(&verifier);
    let blocking_joiner = Arc::clone(&fragment_joiner);

    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut guard = blocking_joiner.lock().map_err(|_| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                "AS4 fragment joiner mutex poisoned",
                ErrorContext::for_session("as4_receive_push", &blocking_session),
            )
        })?;
        sync_core::receive_push_with_dedup_sync_fragment_aware_with_verifier(
            &blocking_session,
            &blocking_bus,
            request,
            dedup_backend.as_ref(),
            blocking_verifier.as_ref(),
            Some(&mut guard),
        )
    })
    .await
    .map_err(|err| {
        AsxError::new(
            ErrorCode::TransportFailure,
            format!("AS4 receive blocking task failed: {err}"),
            ErrorContext::for_session("as4_receive_push_async_join", &error_session),
        )
    })?
}
