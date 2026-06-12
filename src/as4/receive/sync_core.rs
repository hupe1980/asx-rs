use super::super::large_message::As4FragmentJoiner;
use super::super::types::{As4ReceivePushProgress, As4ReceivePushRequest};
use super::{
    As4PushReceiveCtx, As4Verifier, DedupStorage, EventBus, PayloadInput, Result, SessionContext,
};
#[cfg(not(feature = "testing"))]
use crate::core::{AsxError, ErrorCode, ErrorContext};

pub(super) fn receive_push_with_dedup_sync_fragment_aware_with_verifier(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushRequest,
    dedup_backend: &dyn DedupStorage,
    verifier: &(dyn As4Verifier + Send + Sync),
    fragment_joiner: Option<&mut As4FragmentJoiner>,
) -> Result<As4ReceivePushProgress> {
    crate::presets::enforce_strict_runtime_bootstrap_for_strict_interop(
        "as4_receive_push",
        session,
        request.policy.interop,
    )?;

    // Safety check: if freshness-window enforcement is disabled AND the dedup
    // backend is non-durable (e.g. in-process memory), there is effectively no
    // replay protection at all — a replayed message from hours earlier will
    // always pass once evicted from the in-memory store.  Require at least one
    // of the two controls to be active.  Tests may opt out via test_relaxed()
    // which sets both fields explicitly.
    #[cfg(not(feature = "testing"))]
    if request.policy.timestamp_freshness_window.is_none() && !dedup_backend.is_durable() {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "insecure receive configuration: timestamp_freshness_window is None and the \
             dedup backend is non-durable; at least one replay protection mechanism must be active. \
             Set timestamp_freshness_window or use a durable backend.",
            ErrorContext::for_session("as4_receive_push_startup_check", session),
        ));
    }

    let As4ReceivePushRequest {
        payload,
        receipt_payload,
        policy,
        http_content_type,
        authenticated_sender_scope,
    } = request;

    let scope_ref = authenticated_sender_scope.as_deref();
    let ctx = As4PushReceiveCtx {
        session,
        event_bus,
        policy: &policy,
        dedup_backend,
        verifier,
    };

    super::receive_push_with_dedup_inner(
        &ctx,
        PayloadInput::Shared(payload),
        receipt_payload.as_deref(),
        &http_content_type,
        fragment_joiner,
        scope_ref,
    )
}
