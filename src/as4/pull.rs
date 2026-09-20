//! AS4 pull receive with reliability.

use super::pull_store::{As4PullEnqueueOutcome, As4PullStore};
use super::pull_store::{PullQueueKey, PullRequestKey};
use super::receive::{As4Ordered, As4ReceivePush, receive_push};
use super::services::{
    DedupDecision, claim_pull, enforce_strict_as4_runtime_policy_consistency,
    ensure_pull_mpc_matches, handle_empty_pull_partition,
};
use super::stream::{constant_time_eq, normalize_mpc};
use super::types::{
    As4PullAuthorization, As4PushPolicy, As4QueuedPullMessage, As4ReceiveOutcome,
    As4ReceivePullOutput, As4ReceivePullRequest, As4ReceivePushOutput, As4ReceivePushRequest,
    FragmentScopePolicy as As4FragmentScopePolicy,
};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
use crate::observability::{AsxEvent, EventBus, emit_audit_event, emit_protocol_event};
use crate::reliability::{DeliveryOutcome, ReconciliationRequest, RetryDecision};
use crate::storage::{
    DedupClaim, DedupStorage, ReconciliationStorage, drive_reconciliation_future,
};
use std::sync::Arc;

/// Default MPC used when none is specified in the queued message.
const DEFAULT_MPC: &str =
    "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/defaultMPC";

#[derive(Debug)]
pub struct As4EnqueuePullWithReliabilityRequest<'a> {
    pub store: &'a As4PullStore,
    pub mpc: String,
    pub message: As4QueuedPullMessage,
    pub reconciliation_hook: &'a dyn ReconciliationStorage,
    pub fail_closed_audit_events: bool,
}

#[derive(Debug)]
pub struct As4ReceivePullWithReliabilityRequest<'a> {
    pub store: &'a As4PullStore,
    pub request: As4ReceivePullRequest,
    pub reconciliation_hook: &'a dyn ReconciliationStorage,
    pub dedup_backend: Arc<dyn DedupStorage>,
    /// Permitted signers for the claimed `eb:From` of the **pulled**
    /// `UserMessage`. See [`As4ReceivePush::signer_pins`].
    ///
    /// [`As4ReceivePush::signer_pins`]: crate::as4::As4ReceivePush::signer_pins
    pub signer_pins: Option<Arc<dyn crate::as4::As4SignerPins>>,
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
    ) && drive_reconciliation_future(reconciliation_hook.enqueue(reconciliation_request))?
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

/// Authorize a `PullRequest` to drain an MPC (ebMS3 §5.2.3.1).
///
/// A `PullRequest` is unsigned and an MPC URI is not secret, so this check is
/// the only thing between a caller and another party's queued documents.
fn validate_pull_authorization_info(
    session: &SessionContext,
    authorization: &As4PullAuthorization,
    provided_authorization_info: Option<&str>,
) -> Result<()> {
    match authorization {
        As4PullAuthorization::Deny => Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "AS4 pull is not authorized for this MPC: As4PullPolicy::authorization is \
             As4PullAuthorization::Deny (the default). Set \
             As4PullAuthorization::SharedSecret(secret) to check eb:AuthorizationInfo, or \
             As4PullAuthorization::EnforcedByTransport if mTLS or an API gateway already \
             authorizes the caller for this MPC",
            ErrorContext::for_session("as4_receive_pull_auth", session),
        )),

        As4PullAuthorization::SharedSecret(expected) => {
            let provided = provided_authorization_info.unwrap_or("");
            if constant_time_eq(expected.as_bytes(), provided.as_bytes()) {
                Ok(())
            } else {
                Err(AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    "AS4 PullRequest AuthorizationInfo does not match expected value",
                    ErrorContext::for_session("as4_receive_pull_auth", session),
                ))
            }
        }

        // The embedder asserted that an upstream control already authorized this
        // caller for this MPC.
        As4PullAuthorization::EnforcedByTransport => Ok(()),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_pull_output(
    pull_message_id: Arc<str>,
    mpc: Arc<str>,
    correlation_message_id: Option<Arc<str>>,
    duplicate_retrieval: bool,
    pulled: Option<Arc<As4ReceivePushOutput>>,
    claim: Option<DedupClaim>,
    outcome: DeliveryOutcome,
    retry: RetryDecision,
) -> As4ReceivePullOutput {
    As4ReceivePullOutput {
        pull_message_id,
        correlation_message_id,
        mpc,
        duplicate_retrieval,
        pulled,
        claim,
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
        require_encrypted_inbound: false,
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
    signer_pins: Option<Arc<dyn crate::as4::As4SignerPins>>,
}

async fn receive_queued_pull_message(
    session: &SessionContext,
    event_bus: &EventBus,
    delivery: QueuedPullDelivery<'_>,
) -> Result<(Arc<As4ReceivePushOutput>, DedupClaim)> {
    let QueuedPullDelivery {
        store,
        queue_key,
        queued,
        receipt_payload,
        push_policy,
        dedup_backend,
        signer_pins,
    } = delivery;
    let payload = Arc::clone(&queued.payload);
    let http_content_type = Arc::clone(&queued.http_content_type);

    let delivered = receive_push(
        session,
        event_bus,
        As4ReceivePush {
            request: As4ReceivePushRequest {
                http_content_type: http_content_type.to_string(),
                payload,
                receipt_payload,
                policy: push_policy,
                // Pull messages are pre-authorized by the pull store.
                authenticated_sender_scope: None,
            },
            dedup: dedup_backend,
            // A pulled message is delivered to the initiator that asked for it;
            // the conversation gate serializes *push* arrivals.
            ordering: None,
            signer_pins,
        },
    )
    .await
    .map(As4Ordered::into_inner);

    let (push_out, claim) = match delivered {
        Ok(As4ReceiveOutcome::FirstSeen { output, claim }) => (*output, claim),
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
        Ok(As4ReceiveOutcome::InFlight { .. }) => {
            // Another delivery of this UserMessage is still unsettled. Put it
            // back and let the initiator pull again once that one resolves.
            store.requeue_front(queue_key, queued).await?;
            return Err(crate::core::AsxError::new(
                ErrorCode::ReliabilityFailure,
                "pull message delivery already in flight; retry with a fresh PullRequest",
                crate::core::ErrorContext::for_session("as4_pull_receive", session),
            ));
        }
        Err(err) => {
            store.requeue_front(queue_key, queued).await?;
            return Err(err);
        }
    };

    Ok((Arc::new(push_out), claim))
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
        signer_pins,
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
        authorization,
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

    // Authorization first: `check_duplicate_pull` *writes* the MessageId into
    // the dedup backend, so running it before this check would let an
    // unauthorized peer insert arbitrary keys into a durable, shared store.
    validate_pull_authorization_info(session, &authorization, authorization_info.as_deref())?;

    let pull_decision = claim_pull(
        session,
        event_bus,
        &dedup_backend,
        &pull_message_id,
        fail_closed_audit_events,
    )
    .await?;

    // The PullRequest's own claim is settled here rather than handed to the
    // caller: what it deduplicates is the *retrieval*, and the served-response
    // cache — not the application — is what makes a replayed retrieval
    // idempotent.
    let pull_claim = match pull_decision {
        DedupDecision::Claimed(claim) => Some(claim),
        DedupDecision::Duplicate => None,
        DedupDecision::InFlight => {
            // An identical PullRequest is still being served. Dequeuing now
            // would hand out a second message under a MessageId the initiator
            // may never correlate, so answer empty and let it retry.
            return Ok(build_pull_output(
                Arc::clone(&pull_message_id),
                Arc::clone(&mpc),
                None,
                true,
                None,
                None,
                DeliveryOutcome::Indeterminate,
                RetryDecision::from_outcome(DeliveryOutcome::Indeterminate),
            ));
        }
    };
    let duplicate_pull = pull_claim.is_none();

    // Everything below can fail, and a failed retrieval produced no response
    // for the served-cache to replay — so the key must be released, not spent.
    // One settle point, for the same reason `finish_non_fragment_push` has one
    // (D59): an early `?` between the claim and an inline settlement is exactly
    // how the push path lost messages.
    let result = serve_pull_request(PullServe {
        session,
        event_bus,
        store,
        reconciliation_hook,
        dedup_backend: &dedup_backend,
        signer_pins: signer_pins.as_ref(),
        pull_key: &pull_key,
        queue_key: &queue_key,
        pull_message_id: &pull_message_id,
        mpc: &mpc,
        duplicate_pull,
        receipt_payload,
        interop,
        interop_exceptions,
        require_signed_receipt,
        require_signed_push,
        fail_closed_audit_events,
    })
    .await;

    match (result, pull_claim) {
        (Ok(output), Some(claim)) => {
            claim.accept().await?;
            Ok(output)
        }
        (Ok(output), None) => Ok(output),
        (Err(err), Some(claim)) => {
            // Release before reporting: the initiator's retry with the same
            // MessageId must be processed, not answered `InFlight`.
            claim.abandon().await?;
            Err(err)
        }
        (Err(err), None) => Err(err),
    }
}

/// Invariant context for the part of a pull that runs under a live claim.
struct PullServe<'a> {
    session: &'a SessionContext,
    event_bus: &'a EventBus,
    store: &'a As4PullStore,
    reconciliation_hook: &'a dyn ReconciliationStorage,
    dedup_backend: &'a Arc<dyn DedupStorage>,
    signer_pins: Option<&'a Arc<dyn crate::as4::As4SignerPins>>,
    pull_key: &'a PullRequestKey,
    queue_key: &'a PullQueueKey,
    pull_message_id: &'a Arc<str>,
    mpc: &'a Arc<str>,
    duplicate_pull: bool,
    receipt_payload: Option<Vec<u8>>,
    interop: crate::core::InteropMode,
    interop_exceptions: crate::interop::InteropExceptionPolicy,
    require_signed_receipt: bool,
    require_signed_push: bool,
    fail_closed_audit_events: bool,
}

/// Serve one `PullRequest`, with the retrieval claim already held.
///
/// Every `?` here releases that claim, because the caller settles on the
/// result rather than inline.
async fn serve_pull_request(ctx: PullServe<'_>) -> Result<As4ReceivePullOutput> {
    let PullServe {
        session,
        event_bus,
        store,
        reconciliation_hook,
        dedup_backend,
        signer_pins,
        pull_key,
        queue_key,
        pull_message_id,
        mpc,
        duplicate_pull,
        receipt_payload,
        interop,
        interop_exceptions,
        require_signed_receipt,
        require_signed_push,
        fail_closed_audit_events,
    } = ctx;

    // A replayed PullRequest must never dequeue a *second* message. Inside the
    // served-cache window `atomic_take` already returns the original response;
    // outside it the cache has been evicted, so the only safe answer is "no
    // payload" — dequeuing would consume a message the initiator never learns
    // about. The initiator must retry with a fresh MessageId.
    let (cached_pulled, queued) = if duplicate_pull {
        (store.cached_response(pull_key).await, None)
    } else {
        store.atomic_take(pull_key, queue_key).await?
    };

    if duplicate_pull && cached_pulled.is_none() {
        return Ok(build_pull_output(
            Arc::clone(pull_message_id),
            Arc::clone(mpc),
            None,
            true,
            None,
            None,
            DeliveryOutcome::Indeterminate,
            RetryDecision::from_outcome(DeliveryOutcome::Indeterminate),
        ));
    }

    if let Some(push_out) = cached_pulled {
        let pulled_mpc = push_out.user_message.mpc.as_deref().unwrap_or(DEFAULT_MPC);
        ensure_pull_mpc_matches(
            session,
            mpc,
            normalize_mpc(pulled_mpc),
            &push_out.user_message.message_id,
        )?;

        let outcome = DeliveryOutcome::SuccessConfirmed;
        // Replayed retrieval: the UserMessage's own claim was settled by the
        // call that first delivered it, so this one carries none.
        return Ok(build_pull_output(
            Arc::clone(pull_message_id),
            Arc::clone(mpc),
            Some(Arc::from(push_out.user_message.message_id.as_str())),
            true,
            Some(push_out),
            None,
            outcome,
            RetryDecision::from_outcome(outcome),
        ));
    }

    let Some(queued) = queued else {
        let (outcome, retry) = handle_empty_pull_partition(
            session,
            event_bus,
            reconciliation_hook,
            pull_message_id,
            fail_closed_audit_events,
        )?;
        return Ok(build_pull_output(
            Arc::clone(pull_message_id),
            Arc::clone(mpc),
            None,
            false,
            None,
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
    let (push_out, message_claim) = receive_queued_pull_message(
        session,
        event_bus,
        QueuedPullDelivery {
            store,
            queue_key,
            queued,
            receipt_payload,
            push_policy,
            dedup_backend: Arc::clone(dedup_backend),
            signer_pins: signer_pins.cloned(),
        },
    )
    .await?;

    let pulled_mpc = push_out.user_message.mpc.as_deref().unwrap_or(DEFAULT_MPC);
    if let Err(err) = ensure_pull_mpc_matches(
        session,
        mpc,
        normalize_mpc(pulled_mpc),
        &push_out.user_message.message_id,
    ) {
        // The message is not delivered, so its key must not stay spent — the
        // next retrieval has to be able to process it.
        message_claim.abandon().await?;
        return Err(err);
    }

    let correlation_message_id = Some(Arc::from(push_out.user_message.message_id.as_str()));

    store
        .cache_pulled(pull_key.clone(), Arc::clone(&push_out))
        .await;

    Ok(build_pull_output(
        Arc::clone(pull_message_id),
        Arc::clone(mpc),
        correlation_message_id,
        false,
        Some(push_out),
        Some(message_claim),
        DeliveryOutcome::SuccessConfirmed,
        RetryDecision::from_outcome(DeliveryOutcome::SuccessConfirmed),
    ))
}
