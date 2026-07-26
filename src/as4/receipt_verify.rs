//! Verification of the counterparty's synchronous AS4 response signal.
//!
//! In the AS4 One-Way/Push MEP with Reception Awareness (eDelivery AS4 v1.15
//! §5.1, BDEW AS4-Profil §4.6.3) the receiving MSH answers the same HTTP
//! connection with either
//!
//! * an `eb:Receipt` SignalMessage acknowledging the `eb:UserMessage`, or
//! * an `eb:Error` SignalMessage rejecting it.
//!
//! This module turns that raw HTTP response body into a verified, typed
//! outcome.  It is the send-side counterpart of the receive-side receipt
//! generators in [`crate::as4::generate_signed_receipt_with_nri`].
//!
//! # What is actually verified
//!
//! [`verify_sync_response`] performs, in order:
//!
//! 1. **Size and structure bounds** — the response is capped at
//!    [`As4ReceiptPolicy::max_receipt_bytes`] and must be a SOAP envelope
//!    carrying an `eb:SignalMessage`.
//! 2. **Namespace-correct, unambiguous parsing** — prefixes (`eb:`, `eb3:`,
//!    `ns2:`, default namespace) and CDATA sections are all handled; nothing is
//!    matched by substring.  At most one `eb:Messaging` and one
//!    `eb:SignalMessage` are accepted, each `eb:MessageInfo` child at most
//!    once, and `NonRepudiationInformation` is read only from inside the
//!    `eb:Receipt` — so no injected element can shadow a real one.
//! 3. **Signal classification** — an `eb:Error` signal is returned as
//!    [`As4SyncSignal::Error`] with the ebMS3 error code, severity and
//!    description intact, instead of being reported as "no receipt".  A signal
//!    carrying both a Receipt and an Error is rejected as ambiguous.
//! 4. **Signature verification (NRR)** — when the receipt carries a
//!    `ds:Signature` it is verified against the session trust anchors,
//!    revocation policy and expected signer fingerprint, **and** the
//!    `eb:SignalMessage` acted on must itself be covered by that signature
//!    (directly or through a signed ancestor).  Without that binding a
//!    counterparty could leave a genuinely signed element in place and append
//!    an unsigned acknowledgement — XML Signature Wrapping.
//! 5. **Correlation** — `eb:RefToMessageId` must equal the sent
//!    [`As4SendOutput::message_id`].  An `eb:Error` correlating to a different
//!    message is rejected rather than attributed to this one.
//! 6. **Non-repudiation (NRR digest check)** — every `ds:Reference` of the
//!    *sent* message's own signature must be echoed by a
//!    `MessagePartNRInformation` entry in the receipt, with a matching digest
//!    algorithm and digest value.  This is the step that makes the receipt
//!    evidence rather than decoration: it proves the counterparty signed a
//!    statement about the exact bytes that were sent.
//! 7. **Freshness** — the receipt `eb:Timestamp` must be inside the configured
//!    replay window.  A receipt with no timestamp is rejected while a window is
//!    configured, so the guard cannot be bypassed by dropping the element.
//!
//! # What is *not* authenticated
//!
//! An `eb:Error` signal is reported as received, not as proven.  Error signals
//! are typically unsigned, so [`As4SyncSignal::Error`] establishes only that
//! *something* on the connection reported a rejection — treat it as a routing
//! hint (retry vs dead-letter), never as evidence about the message's fate.
//! Only [`As4VerifiedReceipt::is_non_repudiation_evidence`] asserts a
//! cryptographically proven outcome.
//!
//! # Example
//!
//! ```rust,ignore
//! let sent = asx_rs::as4::send_async(&session, &bus, request).await?;
//! let outcome = transport.send(&url, &sent).await?;
//!
//! let receipt = asx_rs::as4::verify_sync_response(
//!     &session,
//!     &bus,
//!     &sent,
//!     &outcome.body,
//!     outcome.header("Content-Type").unwrap_or("application/soap+xml"),
//!     &asx_rs::as4::As4ReceiptPolicy::regulated(),
//! )?
//! .into_receipt()?;
//!
//! assert!(receipt.non_repudiation.is_verified());
//! ```
//!
//! [`As4HttpTransport::send_and_verify`] wraps steps 1–7 together with the
//! HTTP send itself.
//!
//! [`As4HttpTransport::send_and_verify`]: crate::transport::As4HttpTransport::send_and_verify

use super::parser::parse_as4_signal_envelope;
use super::services::{
    enforce_signal_signature_coverage, expected_fingerprint_from_session,
    wssec_revocation_policy_from_session,
};
use super::stream::extract_multipart_related_payload_if_present;
use super::types::{As4ErrorSignal, As4NriReference, As4SendOutput, As4VerifiedReceipt};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
use crate::crypto::wssec::{WsSecVerifyOptions, parse_signature_references};
use crate::observability::{AsxEvent, EventBus, emit_protocol_event};
use crate::wire::enforce_payload_limit;
use std::sync::Arc;

/// `ErrorContext` stage label for every error raised by this module.
const STAGE: &str = "as4_verify_sync_response";

/// Default cap on a synchronous AS4 response body.
///
/// Matches the inbound receipt cap used by the receive path: a SignalMessage
/// carries no business payload, so anything larger is malformed or hostile.
pub const DEFAULT_MAX_RECEIPT_BYTES: usize = 256 * 1024;

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// Policy controlling how strictly a counterparty's synchronous AS4 signal is
/// verified.
///
/// Construct with [`regulated`](Self::regulated) (fail-closed, the right choice
/// for BDEW / PEPPOL / CEF deployments), [`strict`](Self::strict), or
/// [`relaxed`](Self::relaxed).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct As4ReceiptPolicy {
    /// Reject a receipt that echoes a `MessagePartNRInformation` entry for a
    /// URI the sent message never signed.
    ///
    /// eDelivery AS4 v1.15 §5.1.8 defines the receipt as echoing the original
    /// `ds:Reference` set, so an extra entry is non-conformant.  When `false`
    /// the entry is logged and reported through the event bus instead of
    /// failing the verification — the digests that *do* correspond to sent
    /// references are still fully checked either way.
    pub reject_unexpected_references: bool,
    /// Require the receipt to carry a WS-Security XML Signature that verifies
    /// — Non-Repudiation of Receipt (NRR).
    ///
    /// When `false`, an unsigned receipt is accepted, but a *present* signature
    /// is still verified: a signature that fails to verify is always an error.
    pub require_signed_receipt: bool,
    /// Require the receipt's `NonRepudiationInformation` to echo the digests of
    /// the sent message's signature.
    ///
    /// When `false`, a receipt with an empty `<NonRepudiationInformation/>` is
    /// accepted and reported as [`As4NonRepudiation::NotProvided`].  Digests
    /// that *are* present are always checked — a mismatch is always an error.
    pub require_non_repudiation: bool,
    /// SHA-256 fingerprint (hex, optionally colon-separated) the receipt signer
    /// certificate must match.
    ///
    /// `None` (the default) uses the partner fingerprint pinned on the session
    /// via [`crate::core::CertHandle::fingerprint_sha256`], which is the same
    /// material the inbound path pins against.  Set this only when the
    /// counterparty signs receipts with a different certificate than the one it
    /// signs messages with.
    pub expected_signer_fingerprint_sha256: Option<String>,
    /// Replay window applied to the receipt's `eb:Timestamp`.
    ///
    /// `None` disables the check.  Defaults to 5 minutes per eDelivery AS4
    /// v1.15 §5.1.3.
    pub timestamp_freshness_window: Option<std::time::Duration>,
    /// When `true`, failure to emit an audit event fails the verification
    /// (fail-closed audit semantics).
    pub fail_closed_audit_events: bool,
    /// Maximum accepted response body size.  Defaults to
    /// [`DEFAULT_MAX_RECEIPT_BYTES`].
    pub max_receipt_bytes: usize,
}

impl Default for As4ReceiptPolicy {
    fn default() -> Self {
        Self::regulated()
    }
}

impl As4ReceiptPolicy {
    /// Fail-closed preset for regulated deployments (BDEW, PEPPOL, CEF).
    ///
    /// Signed receipt required, non-repudiation digests required,
    /// non-conformant extra references rejected, fail-closed audit emission,
    /// 5-minute freshness window.
    pub fn regulated() -> Self {
        Self {
            reject_unexpected_references: true,
            require_signed_receipt: true,
            require_non_repudiation: true,
            expected_signer_fingerprint_sha256: None,
            timestamp_freshness_window: Some(std::time::Duration::from_secs(300)),
            fail_closed_audit_events: true,
            max_receipt_bytes: DEFAULT_MAX_RECEIPT_BYTES,
        }
    }

    /// Alias for [`regulated`](Self::regulated), matching
    /// [`crate::as4::As4PushPolicy::strict`] on the receive side.
    pub fn strict() -> Self {
        Self::regulated()
    }

    /// Relaxed preset for interop bring-up and integration tests.
    ///
    /// Accepts unsigned receipts and receipts without non-repudiation digests.
    /// Digests and signatures that *are* present are still verified, and a
    /// mismatch is still an error.
    ///
    /// **Never use this against a production counterparty**: without NRR a
    /// receipt is not evidence of delivery.
    pub fn relaxed() -> Self {
        Self {
            reject_unexpected_references: false,
            require_signed_receipt: false,
            require_non_repudiation: false,
            expected_signer_fingerprint_sha256: None,
            timestamp_freshness_window: None,
            fail_closed_audit_events: false,
            max_receipt_bytes: DEFAULT_MAX_RECEIPT_BYTES,
        }
    }

    /// Pin the receipt signer certificate to an explicit SHA-256 fingerprint.
    pub fn with_expected_signer_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.expected_signer_fingerprint_sha256 = Some(fingerprint.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Outcome types
// ---------------------------------------------------------------------------

/// The counterparty's synchronous answer to a pushed `eb:UserMessage`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum As4SyncSignal {
    /// An `eb:Receipt` that passed every check demanded by the policy.
    Receipt(Box<As4VerifiedReceipt>),
    /// An `eb:Error` — the counterparty rejected the message.
    Error(Box<As4ErrorSignal>),
}

impl As4SyncSignal {
    /// The verified receipt, or an [`ErrorCode::InteropViolation`] carrying the
    /// counterparty's ebMS3 diagnostics when the signal was an `eb:Error`.
    ///
    /// Use this when delivery is binary: `verify_sync_response(..)?.into_receipt()?`.
    /// Match on the enum directly when the ebMS3 error code should drive
    /// retry-vs-dead-letter routing.
    pub fn into_receipt(self) -> Result<As4VerifiedReceipt> {
        match self {
            Self::Receipt(receipt) => Ok(*receipt),
            Self::Error(signal) => Err(AsxError::new(
                ErrorCode::InteropViolation,
                format!(
                    "counterparty rejected the AS4 message with an eb:Error signal: {}",
                    signal.summary()
                ),
                match &signal.ref_to_message_id {
                    Some(message_id) => {
                        ErrorContext::new(STAGE).with_message_id(message_id.clone())
                    }
                    None => ErrorContext::new(STAGE),
                },
            )),
        }
    }

    /// The verified receipt, if this signal is one.
    pub fn receipt(&self) -> Option<&As4VerifiedReceipt> {
        match self {
            Self::Receipt(receipt) => Some(receipt),
            Self::Error(_) => None,
        }
    }

    /// The error signal, if the counterparty rejected the message.
    pub fn error(&self) -> Option<&As4ErrorSignal> {
        match self {
            Self::Receipt(_) => None,
            Self::Error(signal) => Some(signal),
        }
    }
}

/// Result of checking a receipt's `NonRepudiationInformation` against the sent
/// message's signature.
///
/// There is deliberately no "mismatch" variant: a digest that is present and
/// wrong is a security failure and is always returned as an
/// [`ErrorCode::SecurityVerificationFailed`] error, never as a value the caller
/// could ignore.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum As4NonRepudiation {
    /// Every `ds:Reference` of the sent message was echoed with a matching
    /// digest algorithm and digest value.
    Verified {
        /// The verified references, in the order the receipt listed them.
        references: Vec<As4NriReference>,
    },
    /// The receipt carried an empty `<NonRepudiationInformation/>`.
    ///
    /// Only reachable when [`As4ReceiptPolicy::require_non_repudiation`] is
    /// `false`; the receipt acknowledges delivery but is not NRR evidence.
    NotProvided,
}

impl As4NonRepudiation {
    /// Whether the sent message's digests were echoed and matched.
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// The verified references, or an empty slice.
    pub fn references(&self) -> &[As4NriReference] {
        match self {
            Self::Verified { references } => references,
            Self::NotProvided => &[],
        }
    }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Parse and verify a counterparty's synchronous AS4 response.
///
/// `response_body` and `response_content_type` are the raw HTTP response body
/// and `Content-Type` returned by the counterparty — bare
/// `application/soap+xml` or `multipart/related` are both accepted.
///
/// See the [module documentation](self) for the full list of checks. Returns
/// [`As4SyncSignal::Error`] — not `Err` — when the counterparty replied with a
/// well-formed `eb:Error`; call [`As4SyncSignal::into_receipt`] to collapse
/// that into an error when the distinction does not matter.
///
/// # Errors
///
/// * [`ErrorCode::PayloadTooLarge`] — body exceeds
///   [`As4ReceiptPolicy::max_receipt_bytes`].
/// * [`ErrorCode::ParseFailed`] — body is empty, not UTF-8, or not a SOAP
///   envelope carrying an `eb:SignalMessage`.
/// * [`ErrorCode::SecurityVerificationFailed`] — the receipt signature failed
///   to verify, a required signature was absent, a non-repudiation digest did
///   not match, or the timestamp fell outside the replay window.
/// * [`ErrorCode::InteropViolation`] — `RefToMessageId` did not match the sent
///   message, or the receipt was structurally non-conformant in strict mode.
#[cfg_attr(
    feature = "trace",
    tracing::instrument(
        skip_all,
        fields(message_id = %sent.message_id, partner_id = %session.partner_id())
    )
)]
pub fn verify_sync_response(
    session: &SessionContext,
    event_bus: &EventBus,
    sent: &As4SendOutput,
    response_body: &[u8],
    response_content_type: &str,
    policy: &As4ReceiptPolicy,
) -> Result<As4SyncSignal> {
    let message_id = Arc::<str>::from(sent.message_id.as_str());

    let soap_xml = extract_signal_soap(session, response_body, response_content_type, policy)?;
    let parsed = parse_as4_signal_envelope(soap_xml, session, STAGE)?;

    if !parsed.has_signal_message {
        return Err(reject(
            session,
            event_bus,
            policy,
            &message_id,
            "semantic_interop_failure",
            "sync_response_missing_signal_message",
            ErrorCode::ParseFailed,
            "AS4 synchronous response carries no eb:SignalMessage; \
             expected an eb:Receipt or eb:Error per the One-Way/Push MEP",
        ));
    }

    // A signal that both acknowledges and rejects is self-contradictory; ebMS3
    // §5.2.2 gives a SignalMessage one role.  Refuse to pick a winner.
    if parsed.has_receipt && !parsed.errors.is_empty() {
        return Err(reject(
            session,
            event_bus,
            policy,
            &message_id,
            "semantic_interop_failure",
            "sync_response_receipt_and_error",
            ErrorCode::InteropViolation,
            "AS4 eb:SignalMessage carries both an eb:Receipt and an eb:Error; the \
             counterparty's intent is ambiguous and the message is neither confirmed \
             delivered nor confirmed rejected",
        ));
    }

    // An Error signal is a legitimate protocol outcome, not a parse failure.
    if !parsed.errors.is_empty() {
        let signal = As4ErrorSignal {
            message_id: parsed.message_id,
            ref_to_message_id: parsed.ref_to_message_id,
            timestamp: parsed.timestamp,
            errors: parsed.errors,
        };
        // An error signal that correlates to a *different* message must not be
        // attributed to this one: acting on it would dead-letter a message the
        // counterparty never rejected.  ebMS3 §6.2 allows the correlation to
        // sit on eb:MessageInfo or on the eb:Error `refToMessageId` attribute.
        let correlations: Vec<&str> = signal
            .ref_to_message_id
            .iter()
            .map(String::as_str)
            .chain(
                signal
                    .errors
                    .iter()
                    .filter_map(|e| e.ref_to_message_id.as_deref()),
            )
            .collect();

        if !correlations.is_empty()
            && !correlations
                .iter()
                .any(|candidate| *candidate == sent.message_id)
        {
            return Err(reject(
                session,
                event_bus,
                policy,
                &message_id,
                "semantic_interop_failure",
                "error_signal_ref_to_message_id_mismatch",
                ErrorCode::InteropViolation,
                format!(
                    "AS4 eb:Error signal correlates to {} but the sent message id is '{}'; \
                     refusing to attribute another message's rejection to this one",
                    correlations
                        .iter()
                        .map(|c| format!("'{c}'"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    sent.message_id
                ),
            ));
        }

        emit_receipt_taxonomy(
            session,
            event_bus,
            policy,
            &message_id,
            "semantic_interop_failure",
            if correlations.is_empty() {
                "sync_response_error_signal_uncorrelated"
            } else {
                "sync_response_error_signal"
            },
        )?;
        return Ok(As4SyncSignal::Error(Box::new(signal)));
    }

    if !parsed.has_receipt {
        return Err(reject(
            session,
            event_bus,
            policy,
            &message_id,
            "semantic_interop_failure",
            "sync_response_missing_receipt",
            ErrorCode::ParseFailed,
            "AS4 eb:SignalMessage carries neither eb:Receipt nor eb:Error",
        ));
    }

    let ref_to_message_id = parsed.ref_to_message_id.clone().ok_or_else(|| {
        reject(
            session,
            event_bus,
            policy,
            &message_id,
            "semantic_interop_failure",
            "receipt_missing_ref_to_message_id",
            ErrorCode::ParseFailed,
            "AS4 receipt is missing eb:RefToMessageId; the acknowledgement \
             cannot be correlated to the sent message",
        )
    })?;

    if ref_to_message_id != sent.message_id {
        return Err(reject(
            session,
            event_bus,
            policy,
            &message_id,
            "semantic_interop_failure",
            "receipt_ref_to_message_id_mismatch",
            ErrorCode::InteropViolation,
            format!(
                "AS4 receipt eb:RefToMessageId '{ref_to_message_id}' does not match the \
                 sent message id '{}'",
                sent.message_id
            ),
        ));
    }

    let signer_fingerprint_sha256 =
        verify_receipt_signature(session, event_bus, policy, &message_id, soap_xml, &parsed)?;

    check_receipt_freshness(
        session,
        event_bus,
        policy,
        &message_id,
        parsed.timestamp.as_deref(),
    )?;

    let non_repudiation = verify_non_repudiation(
        session,
        event_bus,
        policy,
        &message_id,
        sent,
        &parsed.nri_references,
    )?;

    emit_protocol_event(
        event_bus,
        session,
        AsxEvent::ReceiptReceived {
            message_id: Arc::clone(&message_id),
            signal: "as4",
        },
        policy.fail_closed_audit_events,
        STAGE,
    )?;

    Ok(As4SyncSignal::Receipt(Box::new(As4VerifiedReceipt {
        message_id: parsed.message_id,
        ref_to_message_id,
        timestamp: parsed.timestamp,
        signed: parsed.has_signature,
        signer_fingerprint_sha256,
        non_repudiation,
    })))
}

/// Unwrap the response body down to the SOAP envelope and validate its bounds.
fn extract_signal_soap<'a>(
    session: &SessionContext,
    response_body: &'a [u8],
    response_content_type: &str,
    policy: &As4ReceiptPolicy,
) -> Result<&'a str> {
    if response_body.is_empty() {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 synchronous response body is empty; the One-Way/Push MEP with \
             Reception Awareness requires an eb:Receipt or eb:Error on the same \
             connection. A counterparty using the asynchronous MEP should be \
             handled through the inbound receive path instead",
            ErrorContext::for_session(STAGE, session),
        ));
    }
    enforce_payload_limit(STAGE, response_body.len(), policy.max_receipt_bytes)?;

    let soap_bytes = match extract_multipart_related_payload_if_present(
        response_body,
        response_content_type,
        session,
        STAGE,
    )? {
        Some(multipart) => multipart.soap_xml,
        None => response_body,
    };

    crate::core::bytes_to_utf8_str(soap_bytes, STAGE, session)
}

/// Verify the receipt's WS-Security signature, returning the pinned signer
/// fingerprint when one was enforced.
fn verify_receipt_signature(
    session: &SessionContext,
    event_bus: &EventBus,
    policy: &As4ReceiptPolicy,
    message_id: &Arc<str>,
    soap_xml: &str,
    parsed: &super::parser::ParsedAs4SignalEnvelope,
) -> Result<Option<String>> {
    if !parsed.has_signature {
        if policy.require_signed_receipt {
            return Err(reject(
                session,
                event_bus,
                policy,
                message_id,
                "security_verification_failed",
                "receipt_signature_required_but_missing",
                ErrorCode::SecurityVerificationFailed,
                "AS4 receipt carries no ds:Signature but the policy requires \
                 Non-Repudiation of Receipt; set As4ReceiptPolicy::require_signed_receipt \
                 to false only for counterparties that do not sign receipts",
            ));
        }
        return Ok(None);
    }

    let expected_fingerprint = policy
        .expected_signer_fingerprint_sha256
        .as_deref()
        .or_else(|| expected_fingerprint_from_session(session));

    if expected_fingerprint.is_none() {
        return Err(reject(
            session,
            event_bus,
            policy,
            message_id,
            "security_verification_failed",
            "receipt_signer_fingerprint_missing",
            ErrorCode::PolicyViolation,
            "AS4 receipt signature verification requires a pinned signer \
             certificate: set cert_handle.fingerprint_sha256 on the session or \
             As4ReceiptPolicy::expected_signer_fingerprint_sha256",
        ));
    }

    let revocation_policy = wssec_revocation_policy_from_session(session)?;
    let soap_doc = roxmltree::Document::parse(soap_xml).map_err(|err| {
        reject(
            session,
            event_bus,
            policy,
            message_id,
            "security_verification_failed",
            "receipt_signature_document_unparseable",
            ErrorCode::ParseFailed,
            format!("failed to parse AS4 receipt for signature verification: {err}"),
        )
    })?;

    let coverage = match crate::crypto::wssec::verify::verify_enveloped_signature_optional_with_doc(
        &soap_doc,
        soap_xml,
        WsSecVerifyOptions::new()
            .with_expected_fingerprint(expected_fingerprint)
            .with_revocation(revocation_policy),
    ) {
        Ok(Some(coverage)) => coverage,
        // The streaming parser saw a ds:Signature but the WS-Security layer
        // found none to verify — the element is not a usable enveloped
        // signature.  Treat as verification failure, never as "unsigned".
        Ok(None) => {
            return Err(reject(
                session,
                event_bus,
                policy,
                message_id,
                "security_verification_failed",
                "receipt_signature_not_verifiable",
                ErrorCode::SecurityVerificationFailed,
                "AS4 receipt contains a ds:Signature element that is not a verifiable \
                 WS-Security enveloped signature",
            ));
        }
        Err(err) => {
            return Err(reject(
                session,
                event_bus,
                policy,
                message_id,
                "security_verification_failed",
                "receipt_signature_verification_failed",
                ErrorCode::SecurityVerificationFailed,
                format!("AS4 receipt signature verification failed: {}", err.message),
            ));
        }
    };

    if let Err(err) =
        enforce_signal_signature_coverage(session, &soap_doc, STAGE, message_id.as_ref(), &coverage)
    {
        emit_receipt_taxonomy(
            session,
            event_bus,
            policy,
            message_id,
            "security_verification_failed",
            "receipt_signal_not_signed",
        )?;
        return Err(err);
    }

    Ok(expected_fingerprint.map(ToOwned::to_owned))
}

fn check_receipt_freshness(
    session: &SessionContext,
    event_bus: &EventBus,
    policy: &As4ReceiptPolicy,
    message_id: &Arc<str>,
    timestamp: Option<&str>,
) -> Result<()> {
    let Some(window) = policy.timestamp_freshness_window else {
        return Ok(());
    };

    // A receipt with no eb:Timestamp cannot be replay-checked at all, so an
    // omission must not silently skip the window — that would make the guard
    // trivially bypassable by dropping one element.  ebMS3 §5.2.2.1 makes
    // eb:Timestamp mandatory in eb:MessageInfo.
    let Some(timestamp) = timestamp else {
        return Err(reject(
            session,
            event_bus,
            policy,
            message_id,
            "security_verification_failed",
            "receipt_timestamp_missing",
            ErrorCode::SecurityVerificationFailed,
            "AS4 receipt has no eb:Timestamp, so it cannot be checked against the \
             replay window; set As4ReceiptPolicy::timestamp_freshness_window to None \
             only for counterparties that omit it and where replay is bounded elsewhere",
        ));
    };

    let Some(ts_secs) = crate::time_utils::parse_rfc3339_to_unix_secs(timestamp) else {
        return Err(reject(
            session,
            event_bus,
            policy,
            message_id,
            "semantic_interop_failure",
            "receipt_timestamp_unparseable",
            ErrorCode::ParseFailed,
            format!("AS4 receipt eb:Timestamp '{timestamp}' is not a valid RFC 3339 timestamp"),
        ));
    };

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs() as i64;
    let delta_secs = (now_secs - ts_secs).unsigned_abs();

    if delta_secs > window.as_secs() {
        return Err(reject(
            session,
            event_bus,
            policy,
            message_id,
            "security_verification_failed",
            "receipt_timestamp_outside_freshness_window",
            ErrorCode::SecurityVerificationFailed,
            format!(
                "AS4 receipt eb:Timestamp is outside the freshness window \
                 (delta={}s, allowed={}s); receipt rejected to prevent replay",
                delta_secs,
                window.as_secs()
            ),
        ));
    }

    Ok(())
}

/// Check the receipt's `MessagePartNRInformation` digests against the digests
/// the sent message's own signature committed to.
fn verify_non_repudiation(
    session: &SessionContext,
    event_bus: &EventBus,
    policy: &As4ReceiptPolicy,
    message_id: &Arc<str>,
    sent: &As4SendOutput,
    receipt_refs: &[As4NriReference],
) -> Result<As4NonRepudiation> {
    if receipt_refs.is_empty() {
        if policy.require_non_repudiation {
            return Err(reject(
                session,
                event_bus,
                policy,
                message_id,
                "security_verification_failed",
                "receipt_non_repudiation_information_missing",
                ErrorCode::SecurityVerificationFailed,
                "AS4 receipt carries no ebbpsig:MessagePartNRInformation digests, so it \
                 is not Non-Repudiation of Receipt evidence for the sent message; set \
                 As4ReceiptPolicy::require_non_repudiation to false only for \
                 counterparties that acknowledge without NRR",
            ));
        }
        emit_receipt_taxonomy(
            session,
            event_bus,
            policy,
            message_id,
            "semantic_interop_failure",
            "receipt_non_repudiation_information_missing",
        )?;
        return Ok(As4NonRepudiation::NotProvided);
    }

    let sent_refs = sent_signature_references(session, event_bus, policy, message_id, sent)?;

    // Reject duplicate URIs before matching: a receipt that lists the same URI
    // twice with different digests would otherwise let a hostile MSH satisfy
    // the check with one entry while smuggling a second.
    for (index, reference) in receipt_refs.iter().enumerate() {
        if receipt_refs[..index]
            .iter()
            .any(|earlier| earlier.uri == reference.uri)
        {
            return Err(reject(
                session,
                event_bus,
                policy,
                message_id,
                "security_verification_failed",
                "receipt_non_repudiation_duplicate_reference",
                ErrorCode::SecurityVerificationFailed,
                format!(
                    "AS4 receipt lists ebbpsig:MessagePartNRInformation for URI '{}' more \
                     than once",
                    reference.uri
                ),
            ));
        }
    }

    for sent_ref in &sent_refs {
        let Some(echoed) = receipt_refs
            .iter()
            .find(|candidate| candidate.uri == sent_ref.uri)
        else {
            return Err(reject(
                session,
                event_bus,
                policy,
                message_id,
                "security_verification_failed",
                "receipt_non_repudiation_reference_missing",
                ErrorCode::SecurityVerificationFailed,
                format!(
                    "AS4 receipt does not echo a ds:Reference for '{}'; the counterparty \
                     acknowledged only part of the signed message",
                    sent_ref.uri
                ),
            ));
        };

        if echoed.digest_method_uri != sent_ref.digest_method_uri {
            return Err(reject(
                session,
                event_bus,
                policy,
                message_id,
                "security_verification_failed",
                "receipt_non_repudiation_digest_method_mismatch",
                ErrorCode::SecurityVerificationFailed,
                format!(
                    "AS4 receipt echoes ds:Reference '{}' with digest algorithm '{}' but \
                     the sent message used '{}'",
                    sent_ref.uri, echoed.digest_method_uri, sent_ref.digest_method_uri
                ),
            ));
        }

        if echoed.digest_value_b64 != sent_ref.digest_value_b64 {
            return Err(reject(
                session,
                event_bus,
                policy,
                message_id,
                "security_verification_failed",
                "receipt_non_repudiation_digest_mismatch",
                ErrorCode::SecurityVerificationFailed,
                format!(
                    "AS4 receipt digest for ds:Reference '{}' does not match the digest the \
                     sent message was signed over; the acknowledgement refers to different \
                     bytes than were sent",
                    sent_ref.uri
                ),
            ));
        }
    }

    // Entries the sent message never signed are non-conformant: eDelivery AS4
    // §5.1.8 defines the receipt as echoing the original ds:References.
    if let Some(unexpected) = receipt_refs
        .iter()
        .find(|candidate| !sent_refs.iter().any(|sent| sent.uri == candidate.uri))
    {
        let detail = format!(
            "AS4 receipt echoes ebbpsig:MessagePartNRInformation for '{}', which the sent \
             message never signed",
            unexpected.uri
        );
        if policy.reject_unexpected_references {
            return Err(reject(
                session,
                event_bus,
                policy,
                message_id,
                "semantic_interop_failure",
                "receipt_non_repudiation_unexpected_reference",
                ErrorCode::InteropViolation,
                detail,
            ));
        }
        tracing::warn!(
            target: "asx_rs::as4::receipt_verify",
            message_id = %message_id,
            uri = %unexpected.uri,
            "{detail}"
        );
        emit_receipt_taxonomy(
            session,
            event_bus,
            policy,
            message_id,
            "semantic_interop_failure",
            "receipt_non_repudiation_unexpected_reference",
        )?;
    }

    Ok(As4NonRepudiation::Verified {
        references: receipt_refs.to_vec(),
    })
}

/// Extract the `ds:Reference` set the sent message's own signature commits to.
fn sent_signature_references(
    session: &SessionContext,
    event_bus: &EventBus,
    policy: &As4ReceiptPolicy,
    message_id: &Arc<str>,
    sent: &As4SendOutput,
) -> Result<Vec<As4NriReference>> {
    // In MIME-attachment packaging (mandatory in strict mode) `soap_envelope.body`
    // is the whole `multipart/related` body, so the SOAP root part has to be
    // unwrapped before the signature can be read.
    let sent_soap_bytes = match extract_multipart_related_payload_if_present(
        &sent.soap_envelope.body,
        &sent.http_content_type,
        session,
        STAGE,
    )? {
        Some(multipart) => multipart.soap_xml,
        None => &sent.soap_envelope.body,
    };
    let sent_soap = crate::core::bytes_to_utf8_str(sent_soap_bytes, STAGE, session)?;

    let sig_refs = parse_signature_references(sent_soap).map_err(|err| {
        AsxError::new(
            ErrorCode::InvalidInput,
            format!(
                "cannot verify Non-Repudiation of Receipt: the sent message carries no \
                 readable ds:Signature to compare digests against ({}); unsigned sends \
                 cannot produce NRR evidence, so set \
                 As4ReceiptPolicy::require_non_repudiation to false for them",
                err.message
            ),
            ErrorContext::for_session_with_message(STAGE, session, message_id.as_ref()),
        )
    })?;

    if sig_refs.is_empty() {
        return Err(reject(
            session,
            event_bus,
            policy,
            message_id,
            "security_verification_failed",
            "sent_message_signature_has_no_references",
            ErrorCode::InvalidInput,
            "cannot verify Non-Repudiation of Receipt: the sent message's ds:SignedInfo \
             contains no ds:Reference elements",
        ));
    }

    Ok(sig_refs.into_iter().map(As4NriReference::from).collect())
}

// ---------------------------------------------------------------------------
// Audit helpers
// ---------------------------------------------------------------------------

fn emit_receipt_taxonomy(
    session: &SessionContext,
    event_bus: &EventBus,
    policy: &As4ReceiptPolicy,
    message_id: &Arc<str>,
    outcome: &'static str,
    detail: &'static str,
) -> Result<()> {
    emit_protocol_event(
        event_bus,
        session,
        AsxEvent::ReceiptTaxonomyOutcome {
            message_id: Arc::clone(message_id),
            signal: "as4",
            outcome,
            detail,
        },
        policy.fail_closed_audit_events,
        STAGE,
    )
}

/// Emit the taxonomy event for a rejection and build the error to return.
///
/// When the audit emission itself fails under fail-closed policy that failure
/// is returned instead — the verification still fails, and it fails loudly.
#[allow(clippy::too_many_arguments)]
fn reject(
    session: &SessionContext,
    event_bus: &EventBus,
    policy: &As4ReceiptPolicy,
    message_id: &Arc<str>,
    outcome: &'static str,
    detail: &'static str,
    code: ErrorCode,
    message: impl Into<String>,
) -> AsxError {
    if let Err(emit_err) =
        emit_receipt_taxonomy(session, event_bus, policy, message_id, outcome, detail)
    {
        return emit_err;
    }
    AsxError::new(
        code,
        message,
        ErrorContext::for_session_with_message(STAGE, session, message_id.as_ref()),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::as4::{
        As4ErrorCode, As4ErrorSeverity, As4ReceiptCredentials, As4ReceivedError, SoapEnvelope,
        generate_receipt_with_nri, generate_signed_receipt_with_nri,
    };
    use crate::core::{CertHandle, OcspFailureMode, OcspMode, SessionContextBuilder};
    use crate::crypto::wssec::{WsSecOutboundKeyInfoProfile, generate_xmlsig_signature};
    use crate::observability::{BackpressurePolicy, EventEmissionMode};
    use sha2::{Digest as _, Sha256};

    const SENT_MESSAGING_ID: &str = "sent-messaging";
    const SENT_BODY_ID: &str = "sent-body";

    /// Self-signed RSA keypair, generated inline rather than via
    /// `crate::fixtures` so these tests also run in the `as4`-without-`testing`
    /// feature lanes.
    fn keypair() -> (Vec<u8>, Vec<u8>) {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509, X509NameBuilder};

        let pkey = PKey::from_rsa(Rsa::generate(2048).expect("rsa")).expect("pkey");

        let mut name = X509NameBuilder::new().expect("name builder");
        name.append_entry_by_nid(Nid::COMMONNAME, "as4-receipt-verify-test")
            .expect("cn");
        let name = name.build();

        let mut serial = BigNum::new().expect("serial");
        serial
            .pseudo_rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
            .expect("serial rand");
        let serial = serial.to_asn1_integer().expect("serial asn1");

        let mut builder = X509::builder().expect("x509 builder");
        builder.set_version(2).expect("version");
        builder.set_serial_number(&serial).expect("serial");
        builder.set_subject_name(&name).expect("subject");
        builder.set_issuer_name(&name).expect("issuer");
        builder.set_pubkey(&pkey).expect("pubkey");
        builder
            .set_not_before(&Asn1Time::days_from_now(0).expect("not_before"))
            .expect("nb");
        builder
            .set_not_after(&Asn1Time::days_from_now(365).expect("not_after"))
            .expect("na");
        builder
            .sign(&pkey, MessageDigest::sha256())
            .expect("sign cert");

        (
            builder.build().to_pem().expect("cert pem"),
            pkey.private_key_to_pem_pkcs8().expect("key pem"),
        )
    }

    /// Best-effort bus so these tests never fail on audit emission — available
    /// without the `testing` feature, unlike `EventBus::new_for_testing`.
    fn test_bus() -> EventBus {
        EventBus::new_with_config_and_mode(
            64,
            None,
            BackpressurePolicy::default(),
            EventEmissionMode::BestEffort,
        )
        .expect("best-effort bus is infallible")
    }

    fn fingerprint_hex(cert_pem: &[u8]) -> String {
        let cert = openssl::x509::X509::from_pem(cert_pem).expect("cert pem");
        let der = cert.to_der().expect("cert der");
        Sha256::digest(&der)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// A session that pins `cert_pem` as the counterparty signing certificate
    /// and trusts it as an anchor, so receipt signatures verify.
    fn session_trusting(cert_pem: &[u8]) -> SessionContext {
        let cert_pem_str = String::from_utf8(cert_pem.to_vec()).expect("utf8 cert");
        SessionContextBuilder::new("sender-session", "partner-a")
            .profile_name("strict")
            .cert_handle(CertHandle {
                key_id: "cert:partner-a".into(),
                fingerprint_sha256: fingerprint_hex(cert_pem),
                trust_anchor_pems: vec![cert_pem_str],
                intermediate_ca_pems: vec![],
                revocation_crl_pems: vec![],
                ocsp_mode: OcspMode::Disabled,
                ocsp_failure_mode: OcspFailureMode::HardFail,
                stapled_ocsp_responses_der: vec![],
                responder_ocsp_responses_der: vec![],
                signing_cert_pem: None,
                signing_key_pem: None,
                recipient_cert_pem: None,
            })
            .build()
            .expect("session")
    }

    /// A signed outbound envelope standing in for a real `send_async` result.
    fn sent_output(message_id: &str, cert_pem: &[u8], key_pem: &[u8]) -> As4SendOutput {
        sent_output_with_ids(
            message_id,
            SENT_MESSAGING_ID,
            SENT_BODY_ID,
            cert_pem,
            key_pem,
        )
    }

    /// As [`sent_output`], with caller-chosen `wsu:Id`s so two messages can be
    /// given disjoint `ds:Reference` URIs.
    fn sent_output_with_ids(
        message_id: &str,
        messaging_wsu_id: &str,
        body_wsu_id: &str,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> As4SendOutput {
        let unsigned = format!(
            r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
 xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
 xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
 xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
 xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<S12:Header>
<!-- signature-placeholder -->
<eb:Messaging S12:mustUnderstand="true" wsu:Id="{messaging_wsu_id}">
<eb:UserMessage><eb:MessageInfo><eb:MessageId>{message_id}</eb:MessageId></eb:MessageInfo></eb:UserMessage>
</eb:Messaging>
</S12:Header>
<S12:Body wsu:Id="{body_wsu_id}"/>
</S12:Envelope>"#
        );

        let messaging_ref = format!("#{messaging_wsu_id}");
        let body_ref = format!("#{body_wsu_id}");
        let signature_xml = generate_xmlsig_signature(
            &unsigned,
            &[messaging_ref.as_str(), body_ref.as_str()],
            key_pem,
            cert_pem,
            WsSecOutboundKeyInfoProfile::default(),
        )
        .expect("sign sent envelope");
        let signed = unsigned.replace(
            "<!-- signature-placeholder -->",
            &format!("<wsse:Security>{signature_xml}</wsse:Security>"),
        );

        As4SendOutput {
            message_id: message_id.to_string(),
            action: "urn:test:action".into(),
            traceparent: None,
            http_content_type: "application/soap+xml".into(),
            soap_envelope: SoapEnvelope {
                action: "urn:test:action".into(),
                body: Arc::from(signed.into_bytes()),
            },
            ref_to_message_id: None,
        }
    }

    fn sent_nri(sent: &As4SendOutput) -> Vec<As4NriReference> {
        let xml = std::str::from_utf8(&sent.soap_envelope.body).expect("utf8");
        parse_signature_references(xml)
            .expect("sent references")
            .into_iter()
            .map(As4NriReference::from)
            .collect()
    }

    fn receipt_credentials(cert_pem: &[u8], key_pem: &[u8]) -> As4ReceiptCredentials {
        As4ReceiptCredentials {
            signing_key_pem: key_pem.to_vec(),
            signing_cert_pem: cert_pem.to_vec(),
            key_info_profile: WsSecOutboundKeyInfoProfile::default(),
        }
    }

    fn verify(
        session: &SessionContext,
        sent: &As4SendOutput,
        receipt: &[u8],
        policy: &As4ReceiptPolicy,
    ) -> Result<As4SyncSignal> {
        verify_sync_response(
            session,
            &test_bus(),
            sent,
            receipt,
            "application/soap+xml",
            policy,
        )
    }

    // ── Happy path ────────────────────────────────────────────────────────

    #[test]
    fn signed_receipt_with_matching_digests_is_full_nrr_evidence() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-nrr-1@example", &cert_pem, &key_pem);

        let receipt = generate_signed_receipt_with_nri(
            &session,
            "receipt-1@partner",
            &sent.message_id,
            &sent_nri(&sent),
            &receipt_credentials(&cert_pem, &key_pem),
        )
        .expect("signed receipt");

        let verified = verify(&session, &sent, &receipt, &As4ReceiptPolicy::regulated())
            .expect("verification succeeds")
            .into_receipt()
            .expect("receipt not error");

        assert!(verified.signed, "receipt signature must be verified");
        assert!(verified.non_repudiation.is_verified());
        assert!(verified.is_non_repudiation_evidence());
        assert_eq!(verified.ref_to_message_id, sent.message_id);
        assert_eq!(
            verified.non_repudiation.references().len(),
            2,
            "both sent ds:References must be echoed"
        );
    }

    // ── Prefix / CDATA robustness (the substring-scan failure modes) ───────

    #[test]
    fn receipt_using_a_different_namespace_prefix_is_accepted() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-prefix@example", &cert_pem, &key_pem);

        let receipt = generate_receipt_with_nri(
            &session,
            "receipt-prefix@partner",
            &sent.message_id,
            &sent_nri(&sent),
        )
        .expect("receipt");
        // Rewrite every `eb:` prefix to `eb3:` — semantically identical XML that
        // a substring scan for "<eb:Receipt" would miss entirely.
        let rewritten = String::from_utf8(receipt)
            .expect("utf8")
            .replace("xmlns:eb=", "xmlns:eb3=")
            .replace("<eb:", "<eb3:")
            .replace("</eb:", "</eb3:");

        let mut policy = As4ReceiptPolicy::regulated();
        policy.require_signed_receipt = false;

        let verified = verify(&session, &sent, rewritten.as_bytes(), &policy)
            .expect("prefix-agnostic parse")
            .into_receipt()
            .expect("receipt");
        assert!(verified.non_repudiation.is_verified());
    }

    #[test]
    fn receipt_with_cdata_ref_to_message_id_is_accepted() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-cdata@example", &cert_pem, &key_pem);

        let receipt = generate_receipt_with_nri(
            &session,
            "receipt-cdata@partner",
            &sent.message_id,
            &sent_nri(&sent),
        )
        .expect("receipt");
        let with_cdata = String::from_utf8(receipt).expect("utf8").replace(
            &format!("<eb:RefToMessageId>{}</eb:RefToMessageId>", sent.message_id),
            &format!(
                "<eb:RefToMessageId><![CDATA[{}]]></eb:RefToMessageId>",
                sent.message_id
            ),
        );

        let mut policy = As4ReceiptPolicy::regulated();
        policy.require_signed_receipt = false;

        let verified = verify(&session, &sent, with_cdata.as_bytes(), &policy)
            .expect("CDATA parse")
            .into_receipt()
            .expect("receipt");
        assert_eq!(verified.ref_to_message_id, sent.message_id);
    }

    // ── Non-repudiation enforcement ───────────────────────────────────────

    #[test]
    fn tampered_digest_is_rejected_as_security_failure() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-tamper@example", &cert_pem, &key_pem);

        let mut refs = sent_nri(&sent);
        refs[0].digest_value_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into();
        let receipt = generate_signed_receipt_with_nri(
            &session,
            "receipt-tamper@partner",
            &sent.message_id,
            &refs,
            &receipt_credentials(&cert_pem, &key_pem),
        )
        .expect("signed receipt");

        let err = verify(&session, &sent, &receipt, &As4ReceiptPolicy::regulated())
            .expect_err("digest mismatch must fail");
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
        assert!(
            err.message.contains("does not match the digest"),
            "unexpected message: {}",
            err.message
        );
    }

    #[test]
    fn receipt_omitting_a_signed_reference_is_rejected() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-partial@example", &cert_pem, &key_pem);

        let refs = vec![sent_nri(&sent).remove(0)];
        let receipt = generate_signed_receipt_with_nri(
            &session,
            "receipt-partial@partner",
            &sent.message_id,
            &refs,
            &receipt_credentials(&cert_pem, &key_pem),
        )
        .expect("signed receipt");

        let err = verify(&session, &sent, &receipt, &As4ReceiptPolicy::regulated())
            .expect_err("partial NRI must fail");
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
        assert!(err.message.contains("does not echo a ds:Reference"));
    }

    #[test]
    fn empty_non_repudiation_information_fails_regulated_and_passes_relaxed() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-empty-nri@example", &cert_pem, &key_pem);

        let receipt =
            generate_receipt_with_nri(&session, "receipt-empty@partner", &sent.message_id, &[])
                .expect("receipt");

        let err = verify(&session, &sent, &receipt, &As4ReceiptPolicy::regulated())
            .expect_err("empty NRI must fail under the regulated policy");
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);

        let verified = verify(&session, &sent, &receipt, &As4ReceiptPolicy::relaxed())
            .expect("relaxed accepts")
            .into_receipt()
            .expect("receipt");
        assert_eq!(verified.non_repudiation, As4NonRepudiation::NotProvided);
        assert!(!verified.is_non_repudiation_evidence());
    }

    #[test]
    fn unexpected_extra_reference_is_rejected_in_strict_mode() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-extra@example", &cert_pem, &key_pem);

        let mut refs = sent_nri(&sent);
        refs.push(As4NriReference {
            uri: "cid:not-sent@example".into(),
            digest_method_uri: refs[0].digest_method_uri.clone(),
            digest_value_b64: refs[0].digest_value_b64.clone(),
        });
        let receipt = generate_signed_receipt_with_nri(
            &session,
            "receipt-extra@partner",
            &sent.message_id,
            &refs,
            &receipt_credentials(&cert_pem, &key_pem),
        )
        .expect("signed receipt");

        let err = verify(&session, &sent, &receipt, &As4ReceiptPolicy::regulated())
            .expect_err("unexpected reference must fail in strict mode");
        assert_eq!(err.code, ErrorCode::InteropViolation);
        assert!(err.message.contains("never signed"));
    }

    // ── Correlation and signature enforcement ─────────────────────────────

    #[test]
    fn ref_to_message_id_mismatch_is_rejected() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-correlate@example", &cert_pem, &key_pem);

        let receipt = generate_receipt_with_nri(
            &session,
            "receipt-correlate@partner",
            "some-other-message@example",
            &sent_nri(&sent),
        )
        .expect("receipt");

        let err = verify(&session, &sent, &receipt, &As4ReceiptPolicy::relaxed())
            .expect_err("mismatched RefToMessageId must fail");
        assert_eq!(err.code, ErrorCode::InteropViolation);
        assert!(err.message.contains("does not match the sent message id"));
    }

    #[test]
    fn unsigned_receipt_is_rejected_when_nrr_is_required() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-unsigned@example", &cert_pem, &key_pem);

        let receipt = generate_receipt_with_nri(
            &session,
            "receipt-unsigned@partner",
            &sent.message_id,
            &sent_nri(&sent),
        )
        .expect("receipt");

        let err = verify(&session, &sent, &receipt, &As4ReceiptPolicy::regulated())
            .expect_err("unsigned receipt must fail when NRR is required");
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
        assert!(err.message.contains("no ds:Signature"));
    }

    #[test]
    fn receipt_signed_by_an_unpinned_certificate_is_rejected() {
        let (cert_pem, key_pem) = keypair();
        let (rogue_cert_pem, rogue_key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-rogue@example", &cert_pem, &key_pem);

        let receipt = generate_signed_receipt_with_nri(
            &session,
            "receipt-rogue@partner",
            &sent.message_id,
            &sent_nri(&sent),
            &receipt_credentials(&rogue_cert_pem, &rogue_key_pem),
        )
        .expect("signed receipt");

        let err = verify(&session, &sent, &receipt, &As4ReceiptPolicy::regulated())
            .expect_err("receipt signed by an unpinned cert must fail");
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
    }

    // ── Error signals ─────────────────────────────────────────────────────

    #[test]
    fn error_signal_is_returned_as_a_typed_outcome() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-error@example", &cert_pem, &key_pem);

        let error_signal = crate::as4::generate_error_signal(
            &session,
            "error-1@partner",
            &sent.message_id,
            As4ErrorCode::InvalidReceipt,
            As4ErrorSeverity::Failure,
            "receipt could not be produced",
        )
        .expect("error signal");

        let signal = verify(
            &session,
            &sent,
            &error_signal,
            &As4ReceiptPolicy::regulated(),
        )
        .expect("error signal parses");

        let received = signal.error().expect("must classify as an error signal");
        assert!(received.is_failure());
        assert_eq!(
            received.ref_to_message_id.as_deref(),
            Some(&*sent.message_id)
        );
        assert_eq!(received.errors.len(), 1);
        assert_eq!(
            received.errors[0].code(),
            Some(As4ErrorCode::InvalidReceipt)
        );
        assert_eq!(
            received.errors[0].parsed_severity(),
            Some(As4ErrorSeverity::Failure)
        );
        assert!(
            received.errors[0]
                .description
                .as_deref()
                .is_some_and(|d| d.contains("receipt could not be produced"))
        );

        let err = signal.into_receipt().expect_err("into_receipt must fail");
        assert_eq!(err.code, ErrorCode::InteropViolation);
        assert!(err.message.contains("EBMS:0302"));
    }

    // ── Malformed / hostile responses ─────────────────────────────────────

    #[test]
    fn empty_response_body_is_rejected() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-empty@example", &cert_pem, &key_pem);

        let err = verify(&session, &sent, b"", &As4ReceiptPolicy::relaxed())
            .expect_err("empty body must fail");
        assert_eq!(err.code, ErrorCode::ParseFailed);
    }

    #[test]
    fn oversized_response_body_is_rejected() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-large@example", &cert_pem, &key_pem);

        let mut policy = As4ReceiptPolicy::relaxed();
        policy.max_receipt_bytes = 64;
        let err = verify(&session, &sent, &vec![b'x'; 4096], &policy)
            .expect_err("oversized body must fail");
        assert_eq!(err.code, ErrorCode::PayloadTooLarge);
    }

    #[test]
    fn response_without_a_signal_message_is_rejected() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-nosignal@example", &cert_pem, &key_pem);

        let body = br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"><S12:Body/></S12:Envelope>"#;
        let err = verify(&session, &sent, body, &As4ReceiptPolicy::relaxed())
            .expect_err("missing SignalMessage must fail");
        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(err.message.contains("no eb:SignalMessage"));
    }

    #[test]
    fn duplicate_nri_reference_uris_are_rejected() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-dup@example", &cert_pem, &key_pem);

        let mut refs = sent_nri(&sent);
        let mut shadow = refs[0].clone();
        shadow.digest_value_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into();
        refs.push(shadow);

        let receipt =
            generate_receipt_with_nri(&session, "receipt-dup@partner", &sent.message_id, &refs)
                .expect("receipt");

        let mut policy = As4ReceiptPolicy::regulated();
        policy.require_signed_receipt = false;
        let err = verify(&session, &sent, &receipt, &policy)
            .expect_err("duplicate reference URIs must fail");
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
        assert!(err.message.contains("more than once"));
    }

    #[test]
    fn stale_receipt_timestamp_is_rejected() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-stale@example", &cert_pem, &key_pem);

        let receipt = generate_receipt_with_nri(
            &session,
            "receipt-stale@partner",
            &sent.message_id,
            &sent_nri(&sent),
        )
        .expect("receipt");
        let stale = String::from_utf8(receipt).expect("utf8").replace(
            &crate::time_utils::format_rfc3339_secs(std::time::SystemTime::now()),
            "2001-01-01T00:00:00Z",
        );

        let mut policy = As4ReceiptPolicy::regulated();
        policy.require_signed_receipt = false;
        let err = verify(&session, &sent, stale.as_bytes(), &policy)
            .expect_err("stale timestamp must fail");
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
        assert!(err.message.contains("freshness window"));
    }

    // ── Error-code mapping ────────────────────────────────────────────────

    #[test]
    fn ebms_error_codes_round_trip() {
        for code in [
            As4ErrorCode::ValueNotRecognized,
            As4ErrorCode::FeatureNotSupported,
            As4ErrorCode::ValueInconsistent,
            As4ErrorCode::Other,
            As4ErrorCode::MissingReceipt,
            As4ErrorCode::InvalidReceipt,
            As4ErrorCode::DecompressionFailure,
        ] {
            assert_eq!(As4ErrorCode::from_ebms_code(code.ebms_code()), Some(code));
        }
        assert_eq!(
            As4ErrorCode::from_ebms_code("ebms:0004"),
            Some(As4ErrorCode::Other)
        );
        assert_eq!(As4ErrorCode::from_ebms_code("EBMS:0201"), None);
        assert_eq!(As4ErrorCode::from_ebms_code("garbage"), None);
    }

    /// The wrapping guard above catches a *duplicated* `eb:Messaging`.  This
    /// covers the single-block case: a signature that verifies but does not
    /// cover the `eb:Messaging` the caller acts on — e.g. the counterparty
    /// signed only the SOAP Body, leaving the acknowledgement itself
    /// substitutable.
    #[test]
    fn receipt_whose_messaging_block_is_not_signed_is_rejected() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-uncovered@example", &cert_pem, &key_pem);

        let nri: String = sent_nri(&sent)
            .iter()
            .map(|r| {
                format!(
                    "<ebbpsig:MessagePartNRInformation><ds:Reference URI=\"{}\">\
<ds:DigestMethod Algorithm=\"{}\"></ds:DigestMethod>\
<ds:DigestValue>{}</ds:DigestValue></ds:Reference></ebbpsig:MessagePartNRInformation>",
                    r.uri, r.digest_method_uri, r.digest_value_b64
                )
            })
            .collect();

        // eb:Messaging deliberately carries no wsu:Id, so nothing binds it to
        // the signature; only the Body is signed.
        let envelope = format!(
            "<S12:Envelope xmlns:S12=\"http://www.w3.org/2003/05/soap-envelope\" \
xmlns:eb=\"http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/\" \
xmlns:ebbpsig=\"http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0\" \
xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" \
xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" \
xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
<S12:Header><!-- sig -->\
<eb:Messaging S12:mustUnderstand=\"true\">\
<eb:SignalMessage><eb:MessageInfo>\
<eb:Timestamp>{ts}</eb:Timestamp>\
<eb:MessageId>uncovered@partner</eb:MessageId>\
<eb:RefToMessageId>{ref_id}</eb:RefToMessageId>\
</eb:MessageInfo>\
<eb:Receipt><ebbpsig:NonRepudiationInformation>{nri}</ebbpsig:NonRepudiationInformation></eb:Receipt>\
</eb:SignalMessage></eb:Messaging>\
</S12:Header><S12:Body wsu:Id=\"only-body\"/></S12:Envelope>",
            ts = crate::time_utils::format_rfc3339_secs(std::time::SystemTime::now()),
            ref_id = sent.message_id,
        );

        let signature_xml = generate_xmlsig_signature(
            &envelope,
            &["#only-body"],
            &key_pem,
            &cert_pem,
            WsSecOutboundKeyInfoProfile::default(),
        )
        .expect("sign body only");
        let signed = envelope.replace(
            "<!-- sig -->",
            &format!("<wsse:Security>{signature_xml}</wsse:Security>"),
        );

        let err = verify(
            &session,
            &sent,
            signed.as_bytes(),
            &As4ReceiptPolicy::regulated(),
        )
        .expect_err("a receipt whose eb:Messaging is unsigned must be rejected");

        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
        assert!(
            err.message.contains("not covered by the verified"),
            "must be rejected by the coverage binding: {}",
            err.message
        );
    }

    /// Bundled signals cannot be correlated to one sent message unambiguously.
    #[test]
    fn multiple_signal_messages_are_rejected() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-bundle@example", &cert_pem, &key_pem);

        let receipt = generate_receipt_with_nri(
            &session,
            "receipt-bundle@partner",
            &sent.message_id,
            &sent_nri(&sent),
        )
        .expect("receipt");
        let doubled = String::from_utf8(receipt).expect("utf8").replace(
            "</eb:SignalMessage>",
            "</eb:SignalMessage><eb:SignalMessage><eb:MessageInfo>\
<eb:RefToMessageId>other@example</eb:RefToMessageId></eb:MessageInfo>\
<eb:Receipt/></eb:SignalMessage>",
        );

        let mut policy = As4ReceiptPolicy::regulated();
        policy.require_signed_receipt = false;
        let err = verify(&session, &sent, doubled.as_bytes(), &policy)
            .expect_err("bundled signals must be rejected");
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
        assert!(err.message.contains("more than one eb:SignalMessage"));
    }

    /// A rejection for someone else's message must never be attributed to ours
    /// — acting on it would dead-letter a message that was never rejected.
    #[test]
    fn error_signal_for_a_different_message_is_rejected() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-ours@example", &cert_pem, &key_pem);

        let foreign_error = crate::as4::generate_error_signal(
            &session,
            "error-foreign@partner",
            "someone-elses-message@example",
            As4ErrorCode::Other,
            As4ErrorSeverity::Failure,
            "rejected",
        )
        .expect("error signal");

        let err = verify(
            &session,
            &sent,
            &foreign_error,
            &As4ReceiptPolicy::regulated(),
        )
        .expect_err("an error signal for another message must not be attributed to ours");
        assert_eq!(err.code, ErrorCode::InteropViolation);
        assert!(err.message.contains("refusing to attribute"));
    }

    /// Dropping `eb:Timestamp` must not silently bypass the replay window.
    #[test]
    fn receipt_without_a_timestamp_is_rejected_when_a_window_is_configured() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-nots@example", &cert_pem, &key_pem);

        let receipt = generate_receipt_with_nri(
            &session,
            "receipt-nots@partner",
            &sent.message_id,
            &sent_nri(&sent),
        )
        .expect("receipt");
        let ts = crate::time_utils::format_rfc3339_secs(std::time::SystemTime::now());
        let without_ts = String::from_utf8(receipt)
            .expect("utf8")
            .replace(&format!("<eb:Timestamp>{ts}</eb:Timestamp>"), "");

        let mut policy = As4ReceiptPolicy::regulated();
        policy.require_signed_receipt = false;
        let err = verify(&session, &sent, without_ts.as_bytes(), &policy)
            .expect_err("a missing timestamp must not skip the replay window");
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
        assert!(err.message.contains("no eb:Timestamp"));

        // Explicitly disabling the window is still allowed.
        policy.timestamp_freshness_window = None;
        verify(&session, &sent, without_ts.as_bytes(), &policy)
            .expect("an explicitly disabled window accepts a receipt without a timestamp");
    }

    /// A repeated MessageInfo element makes the signal ambiguous.
    #[test]
    fn duplicate_ref_to_message_id_is_rejected() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-dup-ref@example", &cert_pem, &key_pem);

        let receipt = generate_receipt_with_nri(
            &session,
            "receipt-dup-ref@partner",
            &sent.message_id,
            &sent_nri(&sent),
        )
        .expect("receipt");
        let injected = String::from_utf8(receipt).expect("utf8").replace(
            &format!("<eb:RefToMessageId>{}</eb:RefToMessageId>", sent.message_id),
            &format!(
                "<eb:RefToMessageId>{}</eb:RefToMessageId>\
<eb:RefToMessageId>attacker@example</eb:RefToMessageId>",
                sent.message_id
            ),
        );

        let mut policy = As4ReceiptPolicy::regulated();
        policy.require_signed_receipt = false;
        let err = verify(&session, &sent, injected.as_bytes(), &policy)
            .expect_err("a duplicated eb:RefToMessageId must be rejected");
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
        assert!(err.message.contains("more than one eb:RefToMessageId"));
    }

    /// NonRepudiationInformation outside the eb:Receipt is not an
    /// acknowledgement and must not be harvested as one.
    #[test]
    fn non_repudiation_information_outside_the_receipt_is_ignored() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-stray-nri@example", &cert_pem, &key_pem);

        let stray: String = sent_nri(&sent)
            .iter()
            .map(|r| {
                format!(
                    "<ebbpsig:MessagePartNRInformation><ds:Reference URI=\"{}\">\
<ds:DigestMethod Algorithm=\"{}\"></ds:DigestMethod>\
<ds:DigestValue>{}</ds:DigestValue></ds:Reference></ebbpsig:MessagePartNRInformation>",
                    r.uri, r.digest_method_uri, r.digest_value_b64
                )
            })
            .collect();

        // Empty Receipt, digests parked in a sibling element inside the signal.
        let receipt =
            generate_receipt_with_nri(&session, "receipt-stray@partner", &sent.message_id, &[])
                .expect("receipt");
        let moved = String::from_utf8(receipt).expect("utf8").replace(
            "<eb:Receipt><ebbpsig:NonRepudiationInformation/></eb:Receipt>",
            &format!(
                "<eb:Receipt/><ebbpsig:NonRepudiationInformation xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">{stray}</ebbpsig:NonRepudiationInformation>"
            ),
        );

        let mut policy = As4ReceiptPolicy::regulated();
        policy.require_signed_receipt = false;
        let err = verify(&session, &sent, moved.as_bytes(), &policy).expect_err(
            "digests outside the eb:Receipt must not satisfy the non-repudiation check",
        );
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
        assert!(err.message.contains("no ebbpsig:MessagePartNRInformation"));
    }

    /// A signal that both acknowledges and rejects is self-contradictory.
    #[test]
    fn signal_with_both_receipt_and_error_is_rejected() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);
        let sent = sent_output("msg-both@example", &cert_pem, &key_pem);

        let receipt = generate_receipt_with_nri(
            &session,
            "receipt-both@partner",
            &sent.message_id,
            &sent_nri(&sent),
        )
        .expect("receipt");
        let with_error = String::from_utf8(receipt).expect("utf8").replace(
            "</eb:Receipt>",
            "</eb:Receipt><eb:Error errorCode=\"EBMS:0004\" severity=\"failure\"/>",
        );

        let mut policy = As4ReceiptPolicy::regulated();
        policy.require_signed_receipt = false;
        let err = verify(&session, &sent, with_error.as_bytes(), &policy)
            .expect_err("a signal cannot both acknowledge and reject");
        assert_eq!(err.code, ErrorCode::InteropViolation);
        assert!(err.message.contains("both an eb:Receipt and an eb:Error"));
    }

    #[test]
    fn missing_severity_attribute_counts_as_failure() {
        let received = As4ReceivedError {
            error_code: "EBMS:0004".into(),
            severity: None,
            category: None,
            origin: None,
            ref_to_message_id: None,
            short_description: None,
            description: None,
            error_detail: None,
        };
        assert!(received.is_failure(), "absent severity must fail closed");
    }

    /// PoC: wrap a legitimately signed receipt and inject an unsigned
    /// `eb:Messaging` acknowledging a different message with forged digests.
    #[test]
    fn wrapped_receipt_must_not_be_accepted() {
        let (cert_pem, key_pem) = keypair();
        let session = session_trusting(&cert_pem);

        // Message A: the one the counterparty legitimately acknowledged.
        let sent_a = sent_output("msg-A@example", &cert_pem, &key_pem);
        // Message B: the one the attacker wants forged evidence for.  Distinct
        // wsu:Ids, so the forged NRI cannot collide with the genuine receipt's.
        let sent_b = sent_output_with_ids(
            "msg-B@example",
            "b-messaging",
            "b-body",
            &cert_pem,
            &key_pem,
        );

        let genuine = crate::as4::generate_signed_receipt_with_nri(
            &session,
            "receipt-A@partner",
            &sent_a.message_id,
            &sent_nri(&sent_a),
            &receipt_credentials(&cert_pem, &key_pem),
        )
        .expect("signed receipt for A");
        let genuine = String::from_utf8(genuine).expect("utf8");

        // Forge an unsigned Messaging block for B and prepend it inside the
        // Header, leaving the signed block (and its wsu:Id) intact.
        let refs_b = sent_nri(&sent_b);
        let nri_b: String = refs_b
            .iter()
            .map(|r| {
                format!(
                    "<ebbpsig:MessagePartNRInformation><ds:Reference URI=\"{}\">\
<ds:DigestMethod Algorithm=\"{}\"></ds:DigestMethod>\
<ds:DigestValue>{}</ds:DigestValue></ds:Reference></ebbpsig:MessagePartNRInformation>",
                    r.uri, r.digest_method_uri, r.digest_value_b64
                )
            })
            .collect();
        let forged_block = format!(
            "<eb:Messaging S12:mustUnderstand=\"true\">\
<eb:SignalMessage><eb:MessageInfo>\
<eb:Timestamp>{ts}</eb:Timestamp>\
<eb:MessageId>forged@attacker</eb:MessageId>\
<eb:RefToMessageId>{ref_id}</eb:RefToMessageId>\
</eb:MessageInfo>\
<eb:Receipt><ebbpsig:NonRepudiationInformation>{nri_b}</ebbpsig:NonRepudiationInformation></eb:Receipt>\
</eb:SignalMessage></eb:Messaging>",
            ts = crate::time_utils::format_rfc3339_secs(std::time::SystemTime::now()),
            ref_id = sent_b.message_id,
        );
        let wrapped = genuine.replacen("<S12:Header>", &format!("<S12:Header>{forged_block}"), 1);

        let result = verify_sync_response(
            &session,
            &test_bus(),
            &sent_b,
            wrapped.as_bytes(),
            "application/soap+xml",
            &As4ReceiptPolicy::regulated(),
        );

        let err = result.expect_err(
            "a receipt whose eb:Messaging is not covered by the verified signature \
             must be rejected (XML Signature Wrapping)",
        );
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
        assert!(
            err.message.contains("more than one eb:Messaging"),
            "must be rejected by the wrapping guard, not incidentally: {}",
            err.message
        );
    }
}
