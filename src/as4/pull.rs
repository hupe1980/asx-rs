//! AS4 pull receive with reliability.

use super::pull_store::{As4PullEnqueueOutcome, As4PullStore};
use super::pull_store::{PullQueueKey, PullRequestKey};
use super::receive::receive_push_with_dedup_async;
use super::services::{
    check_duplicate_pull, enforce_strict_as4_runtime_policy_consistency, ensure_pull_mpc_matches,
    handle_empty_pull_partition,
};
use super::stream::{constant_time_eq, normalize_mpc};
use super::types::{
    As4PushPolicy, As4QueuedPullMessage, As4ReceiveOutcome, As4ReceivePullOutput,
    As4ReceivePullRequest, As4ReceivePushOutput, As4ReceivePushRequest,
    FragmentScopePolicy as As4FragmentScopePolicy,
};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
use crate::observability::{AsxEvent, EventBus, emit_audit_event, emit_protocol_event};
use crate::reliability::{DeliveryOutcome, ReconciliationRequest, RetryDecision};
use crate::storage::{DedupStorage, ReconciliationStorage};
use std::sync::Arc;

/// Default MPC used when none is specified in the queued message.
const DEFAULT_MPC: &str =
    "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/defaultMPC";

pub struct As4EnqueuePullWithReliabilityRequest<'a> {
    pub store: &'a As4PullStore,
    pub mpc: String,
    pub message: As4QueuedPullMessage,
    pub reconciliation_hook: &'a dyn ReconciliationStorage,
    pub fail_closed_audit_events: bool,
}

pub struct As4ReceivePullWithReliabilityRequest<'a> {
    pub store: &'a As4PullStore,
    pub request: As4ReceivePullRequest,
    pub reconciliation_hook: &'a dyn ReconciliationStorage,
    pub dedup_backend: Arc<dyn DedupStorage>,
}

/// Static label set passed to [`emit_pull_overflow_with_reconciliation`].
struct PullOverflowSpec {
    overflow_action: &'static str,
    overflow_policy: &'static str,
    reconciliation_reason: &'static str,
}

fn emit_pull_overflow_with_reconciliation(
    session: &SessionContext,
    event_bus: &EventBus,
    reconciliation_hook: &dyn ReconciliationStorage,
    message_id: &Arc<str>,
    spec: PullOverflowSpec,
    fail_closed_audit_events: bool,
) -> Result<()> {
    emit_audit_event(
        event_bus,
        session,
        AsxEvent::PullQueueOverflow {
            message_id: Arc::clone(message_id),
            action: spec.overflow_action,
            policy: spec.overflow_policy,
        },
        fail_closed_audit_events,
        "as4_pull_enqueue_overflow",
    )?;

    if let Some(reconciliation_request) = ReconciliationRequest::for_outcome(
        message_id.to_string(),
        session.partner_id().to_string(),
        DeliveryOutcome::Indeterminate,
    ) && reconciliation_hook.enqueue(reconciliation_request)?
    {
        emit_protocol_event(
            event_bus,
            session,
            AsxEvent::ReconciliationQueued {
                message_id: Arc::clone(message_id),
                reason: spec.reconciliation_reason,
            },
            fail_closed_audit_events,
            "as4_pull_enqueue_reconciliation_queued",
        )?;
    }

    Ok(())
}

fn validate_pull_request_inputs(
    session: &SessionContext,
    pull_message_id: &str,
    requested_mpc: &str,
) -> Result<(Arc<str>, Arc<str>)> {
    if pull_message_id.trim().is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "AS4 PullRequest MessageId must not be empty",
            ErrorContext::for_session("as4_receive_pull", session),
        ));
    }

    let mpc = normalize_mpc(requested_mpc);
    if mpc.is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "AS4 PullRequest MPC must not be empty",
            ErrorContext::for_session("as4_receive_pull", session),
        ));
    }

    Ok((Arc::from(pull_message_id), Arc::from(mpc)))
}

fn validate_pull_authorization_info(
    session: &SessionContext,
    expected_authorization_info: Option<&str>,
    provided_authorization_info: Option<&str>,
) -> Result<()> {
    // OASIS-4: AuthorizationInfo enforcement (ebMS3 section 5.2.3.1).
    if let Some(expected) = expected_authorization_info {
        let provided = provided_authorization_info.unwrap_or("");
        if !constant_time_eq(expected.as_bytes(), provided.as_bytes()) {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "AS4 PullRequest AuthorizationInfo does not match expected value",
                ErrorContext::for_session("as4_receive_pull_auth", session),
            ));
        }
    }

    Ok(())
}

fn build_pull_output(
    pull_message_id: Arc<str>,
    mpc: Arc<str>,
    correlation_message_id: Option<Arc<str>>,
    duplicate_retrieval: bool,
    pulled: Option<Arc<As4ReceivePushOutput>>,
    outcome: DeliveryOutcome,
    retry: RetryDecision,
) -> As4ReceivePullOutput {
    As4ReceivePullOutput {
        pull_message_id,
        correlation_message_id,
        mpc,
        duplicate_retrieval,
        pulled,
        outcome,
        retry,
    }
}

fn build_pull_push_policy(
    interop: crate::core::InteropMode,
    interop_exceptions: crate::interop::InteropExceptionPolicy,
    require_signed_receipt: bool,
    require_signed_push: bool,
    fail_closed_audit_events: bool,
) -> As4PushPolicy {
    As4PushPolicy {
        interop,
        interop_exceptions,
        require_signed_receipt,
        require_signed_push,
        fail_closed_audit_events,
        inbound_decryption_key_pem: None,
        timestamp_freshness_window: Some(std::time::Duration::from_secs(300)),
        fragment_scope_policy: As4FragmentScopePolicy::RequireAuthenticatedScope,
    }
}

/// Bundled parameters for delivering a queued pull message.
struct QueuedPullDelivery<'a> {
    store: &'a As4PullStore,
    queue_key: &'a PullQueueKey,
    queued: As4QueuedPullMessage,
    receipt_payload: Option<Vec<u8>>,
    push_policy: As4PushPolicy,
    dedup_backend: Arc<dyn DedupStorage>,
}

async fn receive_queued_pull_message(
    session: &SessionContext,
    event_bus: &EventBus,
    delivery: QueuedPullDelivery<'_>,
) -> Result<Arc<As4ReceivePushOutput>> {
    let QueuedPullDelivery {
        store,
        queue_key,
        queued,
        receipt_payload,
        push_policy,
        dedup_backend,
    } = delivery;
    let payload = Arc::clone(&queued.payload);
    let http_content_type = Arc::clone(&queued.http_content_type);

    let push_out = match receive_push_with_dedup_async(
        session,
        event_bus,
        As4ReceivePushRequest {
            http_content_type: http_content_type.to_string(),
            payload,
            receipt_payload,
            policy: push_policy,
            authenticated_sender_scope: None, // pull messages are pre-authorized by the pull store
        },
        dedup_backend,
    )
    .await
    {
        Ok(As4ReceiveOutcome::FirstSeen(output)) => *output,
        Ok(As4ReceiveOutcome::Duplicate { .. }) => {
            // Pull messages replayed through the same pull store entry are
            // idempotent by construction — the push was already processed.
            store.requeue_front(queue_key, queued).await?;
            return Err(crate::core::AsxError::new(
                ErrorCode::ReliabilityFailure,
                "pull message replay: already processed",
                crate::core::ErrorContext::for_session("as4_pull_receive", session),
            ));
        }
        Err(err) => {
            store.requeue_front(queue_key, queued).await?;
            return Err(err);
        }
    };

    Ok(Arc::new(push_out))
}

#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %session.partner_id())))]
pub async fn enqueue_pull_with_reliability(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4EnqueuePullWithReliabilityRequest<'_>,
) -> Result<As4PullEnqueueOutcome> {
    let As4EnqueuePullWithReliabilityRequest {
        store,
        mpc,
        message,
        reconciliation_hook,
        fail_closed_audit_events,
    } = request;

    crate::presets::enforce_strict_production_runtime_receive_guards(
        "as4_enqueue_pull",
        session,
        event_bus,
        fail_closed_audit_events,
        Some(reconciliation_hook),
        None,
    )?;

    let incoming_message_id = Arc::clone(&message.message_id);
    match store.enqueue(session, mpc, message).await {
        Ok(As4PullEnqueueOutcome::Enqueued) => Ok(As4PullEnqueueOutcome::Enqueued),
        Ok(As4PullEnqueueOutcome::EvictedOldestAndEnqueued { dropped }) => {
            emit_pull_overflow_with_reconciliation(
                session,
                event_bus,
                reconciliation_hook,
                &dropped.message_id,
                PullOverflowSpec {
                    overflow_action: "evicted_oldest",
                    overflow_policy: "evict_oldest",
                    reconciliation_reason: "queue_overflow_evict_oldest",
                },
                fail_closed_audit_events,
            )?;

            Ok(As4PullEnqueueOutcome::EvictedOldestAndEnqueued { dropped })
        }
        Err(err) if err.code == ErrorCode::CapacityExhausted => {
            emit_pull_overflow_with_reconciliation(
                session,
                event_bus,
                reconciliation_hook,
                &incoming_message_id,
                PullOverflowSpec {
                    overflow_action: "rejected_new",
                    overflow_policy: "reject_new",
                    reconciliation_reason: "queue_overflow_rejected_new",
                },
                fail_closed_audit_events,
            )?;

            Err(err)
        }
        Err(err) => Err(err),
    }
}

#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %session.partner_id())))]
pub async fn receive_pull_with_reliability(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePullWithReliabilityRequest<'_>,
) -> Result<As4ReceivePullOutput> {
    let As4ReceivePullWithReliabilityRequest {
        store,
        request,
        reconciliation_hook,
        dedup_backend,
    } = request;

    let As4ReceivePullRequest {
        pull_message_id,
        policy,
        receipt_payload,
        authorization_info,
    } = request;
    let super::types::As4PullPolicy {
        interop,
        mpc: requested_mpc,
        interop_exceptions,
        require_signed_receipt,
        require_signed_push,
        fail_closed_audit_events,
        expected_authorization_info,
    } = policy;

    crate::presets::enforce_strict_runtime_bootstrap_for_strict_interop(
        "as4_receive_pull",
        session,
        interop,
    )?;

    crate::presets::enforce_strict_production_runtime_receive_guards(
        "as4_receive_pull",
        session,
        event_bus,
        fail_closed_audit_events,
        Some(reconciliation_hook),
        Some(dedup_backend.as_ref()),
    )?;

    enforce_strict_as4_runtime_policy_consistency(
        session,
        "as4_receive_pull",
        interop,
        &interop_exceptions,
        require_signed_push,
        require_signed_receipt,
        fail_closed_audit_events,
    )?;

    let (pull_message_id, mpc) =
        validate_pull_request_inputs(session, &pull_message_id, &requested_mpc)?;

    let session_id = Arc::from(session.session_id());

    let pull_key = PullRequestKey {
        session_id: Arc::clone(&session_id),
        mpc: Arc::clone(&mpc),
        pull_message_id: Arc::clone(&pull_message_id),
    };
    let queue_key = PullQueueKey {
        session_id: Arc::clone(&session_id),
        mpc: Arc::clone(&mpc),
    };

    check_duplicate_pull(
        session,
        event_bus,
        dedup_backend.as_ref(),
        &pull_message_id,
        fail_closed_audit_events,
    )
    .await?;

    validate_pull_authorization_info(
        session,
        expected_authorization_info.as_deref(),
        authorization_info.as_deref(),
    )?;

    let (cached_pulled, queued) = store.atomic_take(&pull_key, &queue_key).await?;

    if let Some(push_out) = cached_pulled {
        let pulled_mpc = push_out.user_message.mpc.as_deref().unwrap_or(DEFAULT_MPC);
        ensure_pull_mpc_matches(
            session,
            &mpc,
            normalize_mpc(pulled_mpc),
            &push_out.user_message.message_id,
        )?;

        let outcome = DeliveryOutcome::SuccessConfirmed;
        return Ok(build_pull_output(
            Arc::clone(&pull_message_id),
            Arc::clone(&mpc),
            Some(Arc::from(push_out.user_message.message_id.as_str())),
            true,
            Some(push_out),
            outcome,
            RetryDecision::from_outcome(outcome),
        ));
    }

    let Some(queued) = queued else {
        let (outcome, retry) = handle_empty_pull_partition(
            session,
            event_bus,
            reconciliation_hook,
            &pull_message_id,
            fail_closed_audit_events,
        )?;
        return Ok(build_pull_output(
            Arc::clone(&pull_message_id),
            Arc::clone(&mpc),
            None,
            false,
            None,
            outcome,
            retry,
        ));
    };

    let push_policy = build_pull_push_policy(
        interop,
        interop_exceptions,
        require_signed_receipt,
        require_signed_push,
        fail_closed_audit_events,
    );
    let push_out = receive_queued_pull_message(
        session,
        event_bus,
        QueuedPullDelivery {
            store,
            queue_key: &queue_key,
            queued,
            receipt_payload,
            push_policy,
            dedup_backend: Arc::clone(&dedup_backend),
        },
    )
    .await?;

    let pulled_mpc = push_out.user_message.mpc.as_deref().unwrap_or(DEFAULT_MPC);
    ensure_pull_mpc_matches(
        session,
        &mpc,
        normalize_mpc(pulled_mpc),
        &push_out.user_message.message_id,
    )?;

    let correlation_message_id = Some(Arc::from(push_out.user_message.message_id.as_str()));

    store.cache_pulled(pull_key, Arc::clone(&push_out)).await;

    Ok(build_pull_output(
        Arc::clone(&pull_message_id),
        Arc::clone(&mpc),
        correlation_message_id,
        false,
        Some(push_out),
        DeliveryOutcome::SuccessConfirmed,
        RetryDecision::from_outcome(DeliveryOutcome::SuccessConfirmed),
    ))
}
