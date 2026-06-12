//! AS4 inbound receive pipeline — push, stream, and partial-verify paths.
//!
//! # Pipeline architecture
//!
//! The receive pipeline is split across 13 sub-modules with the following responsibilities:
//!
//! | Module | Role |
//! |--------|------|
//! | [`entrypoints`] | Public API surface: sync, async, fragment-aware, and ordered variants |
//! | [`sync_core`] | Core synchronous receive-and-dedup logic shared by all sync paths |
//! | [`async_bridge`] | Bridges the sync core onto the Tokio async runtime |
//! | [`async_completion`] | Async completion path for long-running dedup/receipt correlations |
//! | [`ordered`] | Conversation-ordered receive (per-party FIFO guarantee) |
//! | [`ordered_async`] | Async wrapper for conversation-ordered receive |
//! | [`processing`] | Message classification: fragment detection, routing, policy enforcement |
//! | [`payload`] | Payload extraction and decryption (xmlenc, XOP) |
//! | [`metadata`] | UserMessage metadata parsing (MessageInfo, PartyInfo, CollaborationInfo) |
//! | [`receipt`] | Receipt (AS4 Signal) correlation and verification |
//! | [`verifier`] | WS-Security signature and PKIX chain verification |
//! | [`verifier_wrappers`] | Policy-aware wrappers that plumb `RevocationPolicy` into the verifier |
//! | [`runtime_guards`] | Tokio runtime pre-condition guards (prevent blocking calls on async executors) |
//!
//! ## Request flow
//!
//! ```text
//! HTTP layer
//!   └─ entrypoints::receive_push_with_dedup_sync / async
//!        └─ sync_core::receive_push_with_dedup_inner
//!             ├─ processing::maybe_handle_fragment_message
//!             │    ├─ [fragment] → large_message::As4FragmentJoiner
//!             │    └─ [complete] → verifier + payload + metadata
//!             └─ verifier_wrappers::verify_push_message
//!                  └─ verifier::verify_enveloped_signature + validate_pkix_chain
//! ```
//!
//! ## Fragment scope policy
//!
//! When `fragment_scope_policy` is [`FragmentScopePolicy::RequireAuthenticatedScope`] (default),
//! `As4ReceivePushRequest::authenticated_sender_scope` **must** be `Some(_)` — a transport-layer
//! identity (e.g., mTLS client certificate CN) that cannot be forged by the message sender.
//! When it is `None`, the pipeline returns [`crate::core::ErrorCode::PolicyViolation`].
//!
//! Use [`FragmentScopePolicy::UseSoapSenderId`] only for closed networks where SOAP-level
//! sender identity is trusted (e.g., within a single organisation's internal EDI backbone).

use super::large_message::As4FragmentJoiner;
mod async_bridge;
mod async_completion;
mod entrypoints;
mod metadata;
mod ordered;
mod ordered_async;
mod payload;
mod processing;
mod receipt;
mod runtime_guards;
mod sync_core;
mod verifier;
mod verifier_wrappers;
use super::types::{As4PushPolicy, As4ReceivePushProgress};
use crate::core::{PayloadInput, Result, SessionContext};
use crate::observability::EventBus;
use crate::storage::DedupStorage;

pub use entrypoints::{
    As4ReceivePushAsyncFragmentAwareRequest, As4ReceivePushOrderedFragmentAwareRequest,
    As4ReceivePushOrderedRequest, As4ReceivePushSyncFragmentAwareRequest,
    As4ReceivePushSyncRequest, receive_push_ordered, receive_push_ordered_fragment_aware,
    receive_push_with_dedup_async, receive_push_with_dedup_async_fragment_aware,
    receive_push_with_dedup_sync, receive_push_with_dedup_sync_fragment_aware,
};
#[cfg(test)]
pub(crate) use verifier::private;
pub use verifier::{As4Verifier, As4WsSecVerifier};
use verifier_wrappers::{
    receive_push_with_dedup_async_with_verifier, receive_push_with_dedup_sync_with_verifier,
};

/// Bundled context passed through the inner receive pipeline.
///
/// Grouping the five invariant parameters into a single struct eliminates
/// repeated argument lists, reduces stack pressure on every inlined call,
/// and makes it straightforward to add cross-cutting context (e.g. a
/// correlation scope) without touching every function signature.
pub(super) struct As4PushReceiveCtx<'a> {
    pub(super) session: &'a SessionContext,
    pub(super) event_bus: &'a EventBus,
    pub(super) policy: &'a As4PushPolicy,
    pub(super) dedup_backend: &'a dyn DedupStorage,
    pub(super) verifier: &'a (dyn As4Verifier + Send + Sync),
}

fn receive_push_with_dedup_inner(
    ctx: &As4PushReceiveCtx<'_>,
    payload_input: PayloadInput<'_>,
    receipt_payload: Option<&[u8]>,
    http_content_type: &str,
    fragment_joiner: Option<&mut As4FragmentJoiner>,
    authenticated_sender_scope: Option<&str>,
) -> Result<As4ReceivePushProgress> {
    runtime_guards::enforce_receive_push_runtime_guards(
        ctx.session,
        ctx.event_bus,
        ctx.policy,
        ctx.dedup_backend,
    )?;

    let payload_bytes = payload_input.as_slice();

    if let Some(fragment_progress) = processing::maybe_handle_fragment_message(
        ctx,
        payload_bytes,
        receipt_payload,
        http_content_type,
        fragment_joiner,
        authenticated_sender_scope,
    )? {
        return Ok(fragment_progress);
    }

    processing::process_non_fragment_push(ctx, payload_bytes, receipt_payload, http_content_type)
}

#[cfg(test)]
#[cfg_attr(not(feature = "interop-relaxed"), allow(unused_imports))]
mod tests;
