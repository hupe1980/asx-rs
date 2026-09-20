use super::super::As4SignerPins;
use super::super::coordination::ConversationOrderGate;
use super::super::large_message::As4FragmentJoiner;
use super::super::types::{As4ReceiveOutcome, As4ReceivePushProgress, As4ReceivePushRequest};
use super::ordered::As4Ordered;
use super::ordered_async;
use super::{As4WsSecVerifier, EventBus, SessionContext, sync_core};
use crate::core::Result;
use crate::storage::DedupStorage;
use std::sync::Arc;

/// An inbound AS4 push, for the async receive entry points.
///
/// Conversation ordering is a **field**, not a different function: whether a
/// deployment preserves per-conversation arrival order is a property of that
/// deployment, so turning it on is a configuration change rather than a
/// call-site rewrite.
#[derive(Debug)]
pub struct As4ReceivePush<'a> {
    pub request: As4ReceivePushRequest,
    /// Replay protection. See [`crate::storage::DedupStorage`].
    pub dedup: Arc<dyn DedupStorage>,
    /// Conversation ordering gate (ebMS3 §5.1.5).
    ///
    /// `None` — the default for most deployments — processes messages as they
    /// arrive, and the returned [`As4Ordered`] holds no turn. `Some(gate)`
    /// reserves the conversation's place from the raw bytes on arrival and
    /// holds it until the guard is dropped.
    ///
    /// Pass `&gate` for the in-process [`super::As4ConversationOrderGate`], or
    /// a distributed implementation for a multi-replica deployment.
    pub ordering: Option<&'a dyn ConversationOrderGate>,
    /// Which signing certificate each **claimed** `eb:From` party may use.
    ///
    /// A signature that verifies against the network's trust anchors proves
    /// membership of the network, not the identity of the sender — every
    /// access point shares those anchors. Pinning is what attributes a verified
    /// signature to the party that claimed to send it.
    ///
    /// `None` falls back to the session's single-partner pin
    /// ([`SessionContextBuilder::with_fingerprint_sha256`]). A signed message
    /// whose claimed sender resolves to **no** pin is refused either way:
    /// there is no configuration in which this crate attributes a signature to
    /// an unpinned party.
    ///
    /// [`SessionContextBuilder::with_fingerprint_sha256`]: crate::core::SessionContextBuilder::with_fingerprint_sha256
    pub signer_pins: Option<Arc<dyn As4SignerPins>>,
}

/// An inbound AS4 push, for the synchronous receive entry points.
///
/// There is no `ordering` here: reserving a conversation's turn means waiting
/// for it, and waiting is async. A deployment that needs ordered delivery uses
/// [`receive_push`].
#[derive(Debug)]
pub struct As4ReceivePushSync {
    pub request: As4ReceivePushRequest,
    /// Replay protection. See [`crate::storage::DedupStorage`].
    pub dedup: Arc<dyn DedupStorage>,
    /// Which signing certificate each **claimed** `eb:From` party may use.
    ///
    /// A signature that verifies against the network's trust anchors proves
    /// membership of the network, not the identity of the sender — every
    /// access point shares those anchors. Pinning is what attributes a verified
    /// signature to the party that claimed to send it.
    ///
    /// `None` falls back to the session's single-partner pin
    /// ([`SessionContextBuilder::with_fingerprint_sha256`]). A signed message
    /// whose claimed sender resolves to **no** pin is refused either way:
    /// there is no configuration in which this crate attributes a signature to
    /// an unpinned party.
    ///
    /// [`SessionContextBuilder::with_fingerprint_sha256`]: crate::core::SessionContextBuilder::with_fingerprint_sha256
    pub signer_pins: Option<Arc<dyn As4SignerPins>>,
}

// ── Async ────────────────────────────────────────────────────────────────────

/// Receive an inbound AS4 push message.
///
/// The parse, signature verification and decryption run on Tokio's blocking
/// pool, so this is safe to call from an async handler.
///
/// # Ordering
///
/// The returned [`As4Ordered`] is a guard. With
/// [`ordering`](As4ReceivePush::ordering) set it **holds the conversation's
/// turn** until it is dropped, so deliver the message to the application
/// first — dropping the value is what lets the next message in that
/// conversation through. With `ordering: None` it holds nothing and
/// [`As4Ordered::into_inner`] is free.
///
/// Both halves of the ordered case are load-bearing: reserving the turn after
/// the work would order by processing time rather than arrival, and releasing
/// it before returning would leave delivery unserialized (D54).
///
/// ```no_run
/// # use asx_rs::as4::{As4ReceivePush, receive_push};
/// # async fn example(
/// #     session: &asx_rs::core::SessionContext,
/// #     bus: &asx_rs::observability::EventBus,
/// #     request: asx_rs::as4::As4ReceivePushRequest,
/// #     dedup: std::sync::Arc<dyn asx_rs::storage::DedupStorage>,
/// # ) -> asx_rs::Result<()> {
/// let outcome = receive_push(session, bus, As4ReceivePush {
///     request,
///     dedup,
///     ordering: None,
///     signer_pins: None, // falls back to the session's single-partner pin
/// })
/// .await?
/// .into_inner();
/// # let _ = outcome;
/// # Ok(())
/// # }
/// ```
#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %session.partner_id())))]
pub async fn receive_push(
    session: &SessionContext,
    event_bus: &EventBus,
    push: As4ReceivePush<'_>,
) -> Result<As4Ordered<As4ReceiveOutcome>> {
    let As4ReceivePush {
        request,
        dedup,
        ordering,
        signer_pins,
    } = push;

    ordered_async::receive_push_with_verifier(
        session,
        event_bus,
        request,
        dedup,
        ordering,
        Arc::new(As4WsSecVerifier),
        signer_pins,
    )
    .await
}

/// Receive an inbound AS4 push, reassembling ebMS3 Part 2 message fragments.
///
/// Fragment-awareness is a different method rather than a field because it is
/// the axis that changes the answer: a fragment group that is not yet complete
/// produces [`As4ReceivePushProgress::PendingFragment`], which
/// [`receive_push`] has no way to report.
///
/// Only a *completed* message takes a turn: an incomplete fragment group, a
/// duplicate and an in-flight claim are never delivered, so none of them holds
/// the conversation open.
#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %session.partner_id())))]
pub async fn receive_push_fragment_aware(
    session: &SessionContext,
    event_bus: &EventBus,
    push: As4ReceivePush<'_>,
    fragments: Arc<std::sync::Mutex<As4FragmentJoiner>>,
) -> Result<As4Ordered<As4ReceivePushProgress>> {
    let As4ReceivePush {
        request,
        dedup,
        ordering,
        signer_pins,
    } = push;

    ordered_async::receive_push_fragment_aware_with_verifier(
        session,
        event_bus,
        request,
        dedup,
        ordering,
        Arc::new(As4WsSecVerifier),
        signer_pins,
        fragments,
    )
    .await
}

// ── Sync ─────────────────────────────────────────────────────────────────────

/// Receive an inbound AS4 push message on the calling thread.
///
/// Use [`receive_push`] from async code: this blocks for the whole parse,
/// verification and decryption, and cannot preserve conversation order.
pub fn receive_push_sync(
    session: &SessionContext,
    event_bus: &EventBus,
    push: As4ReceivePushSync,
) -> Result<As4ReceiveOutcome> {
    let As4ReceivePushSync {
        request,
        dedup,
        signer_pins,
    } = push;

    super::receive_push_sync_with_verifier(
        session,
        event_bus,
        request,
        &dedup,
        &As4WsSecVerifier,
        signer_pins.as_ref(),
    )
}

/// [`receive_push_sync`], reassembling ebMS3 Part 2 message fragments.
pub fn receive_push_sync_fragment_aware(
    session: &SessionContext,
    event_bus: &EventBus,
    push: As4ReceivePushSync,
    fragments: &mut As4FragmentJoiner,
) -> Result<As4ReceivePushProgress> {
    let As4ReceivePushSync {
        request,
        dedup,
        signer_pins,
    } = push;

    sync_core::receive_push_sync_fragment_aware_with_verifier(
        session,
        event_bus,
        request,
        &dedup,
        &As4WsSecVerifier,
        signer_pins.as_ref(),
        Some(fragments),
    )
}

// ── Test-only verifier injection ─────────────────────────────────────────────

/// [`receive_push_sync`] with a caller-supplied verifier — `testing` only.
///
/// Lets integration tests and [`crate::as4::mock_endpoint::MockAs4Endpoint`]
/// inject a custom [`super::As4Verifier`] (e.g.
/// [`super::verifier::InsecureBypassAs4Verifier`]) without real PKI material.
///
/// # ⚠ Security
///
/// Never enable the `testing` feature in production builds. This bypasses the
/// production-hardened default verifier path.
#[cfg(feature = "testing")]
pub fn receive_push_sync_with_custom_verifier(
    session: &SessionContext,
    event_bus: &EventBus,
    push: As4ReceivePushSync,
    verifier: &(dyn super::As4Verifier + Send + Sync),
) -> Result<As4ReceiveOutcome> {
    super::receive_push_sync_with_verifier(
        session,
        event_bus,
        push.request,
        &push.dedup,
        verifier,
        push.signer_pins.as_ref(),
    )
}

/// [`receive_push`] with a caller-supplied verifier — `testing` only.
///
/// See [`receive_push_sync_with_custom_verifier`] for the security note.
#[cfg(feature = "testing")]
pub async fn receive_push_with_custom_verifier<V>(
    session: &SessionContext,
    event_bus: &EventBus,
    push: As4ReceivePush<'_>,
    verifier: V,
) -> Result<As4Ordered<As4ReceiveOutcome>>
where
    V: super::As4Verifier + Send + Sync + 'static,
{
    let As4ReceivePush {
        request,
        dedup,
        ordering,
        signer_pins,
    } = push;

    ordered_async::receive_push_with_verifier(
        session,
        event_bus,
        request,
        dedup,
        ordering,
        Arc::new(verifier),
        signer_pins,
    )
    .await
}
