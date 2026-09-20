mod conversation_gate;
mod coordination;
mod large_message;
mod pull;
mod receipt_verify;
mod receive;
mod send;
mod send_mime;
mod services;
mod signals;
mod stream;

mod types;
pub use types::*;

mod pull_store;
pub use pull_store::As4PullEnqueueOutcome;
pub use pull_store::As4PullQueueOverflowPolicy;
pub use pull_store::{As4PullQueueSnapshot, As4PullStoreSnapshot, As4QueuedPullMessageSnapshot};
pub use pull_store::{As4PullStore, As4PullStoreLimits};

pub use conversation_gate::{As4ConversationOrderGate, ConversationGuard};
pub use coordination::{
    As4TopologyCoordination, ConversationGuardHandle, ConversationOrderGate, ConversationTurnHandle,
};

// Free-function API — the former `*` associated functions are now
// top-level functions in the `as4` module (the module itself is the namespace).
pub use large_message::{
    As4FragmentJoiner, As4FragmentJoinerLimits, As4JoinProgress, As4JoinedLargeMessage,
    As4SplitFragmentOutput, send_sync_fragmented,
};
pub use pull::{
    As4EnqueuePullWithReliabilityRequest, As4ReceivePullWithReliabilityRequest,
    enqueue_pull_with_reliability, receive_pull_with_reliability,
};
pub use receipt_verify::{
    As4NonRepudiation, As4ReceiptPolicy, As4SyncSignal, DEFAULT_MAX_RECEIPT_BYTES,
    verify_sync_response,
};
/// Re-export of the `As4Verifier` sealing trait — available only under
/// `testing` so external crates can implement their own custom verifiers.
///
/// ```toml
/// # Enable in dev-dependencies only
/// asx-rs = { version = "0.14", features = ["as4", "testing"] }
/// ```
///
/// ```rust,ignore
/// use asx_rs::as4::{As4Verifier, verifier_seal};
///
/// struct RecordingVerifier { ... }
/// impl verifier_seal::Sealed for RecordingVerifier {}
/// impl As4Verifier for RecordingVerifier { ... }
/// ```
#[cfg(feature = "testing")]
pub use receive::private as verifier_seal;
pub use receive::{
    As4Ordered, As4ReceivePush, As4ReceivePushSync, As4Verifier, As4WsSecVerifier, receive_push,
    receive_push_fragment_aware, receive_push_sync, receive_push_sync_fragment_aware,
};
#[cfg(feature = "testing")]
pub use receive::{
    InsecureBypassAs4Verifier, receive_push_sync_with_custom_verifier,
    receive_push_with_custom_verifier,
};
pub use send::{
    As4AdditionalPayload, As4SendPreparedRequest, As4SendRequest, send_async, send_async_prepared,
    send_sync, send_sync_prepared,
};
pub use send_mime::{package_as_mime, package_as_mime_with_extra_attachments};
pub use signals::{
    generate_error_signal, generate_pull_request, generate_receipt, generate_receipt_for_output,
    generate_receipt_with_nri, generate_signed_receipt_for_output,
    generate_signed_receipt_with_nri,
};
pub use signer_pins::{As4SignerPinMap, As4SignerPins};

mod parser;

pub mod mime_packaging;
pub use mime_packaging::{
    MimeAttachment, MimePackageBuilder, PayloadFilename, PayloadFilenameError,
};

pub mod pmode;
pub mod signer_pins;
/// The ebMS3 Test Service (Core §5.2.2).
///
/// **Not** test scaffolding: §5.2.2 makes the Test Service mandatory for a
/// conformant MSH, and the eDelivery conformance suite exercises it as the
/// `PING` profile. It was gated behind the `testing` feature — which raises a
/// `compile_error!` in release builds — so no production deployment could
/// implement a protocol feature the specification requires.
pub mod test_service;

/// In-process AS4 mock endpoint for integration testing.
///
/// Available under `as4 + testing + server` features.
/// See [`mock_endpoint::MockAs4Endpoint`] for details.
#[cfg(all(feature = "testing", feature = "server"))]
pub mod mock_endpoint;

#[cfg(test)]
mod tests;
