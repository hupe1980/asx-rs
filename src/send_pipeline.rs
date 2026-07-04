//! Shared send pipeline utilities for AS2 and AS4 message dispatch.
//!
//! Both protocols share a common outbound lifecycle:
//!
//! 1. Validate message ID and payload (protocol-level preconditions)
//! 2. Validate credentials against the requested crypto operations
//! 3. Emit `OutboundPrepared` event
//! 4. Apply cryptographic operations (protocol-specific)
//! 5. Emit `MessageSigned` / `MessageEncrypted` per step
//! 6. Assemble wire format (protocol-specific)
//!
//! This module provides the protocol-agnostic helpers for steps 1–3 and 5,
//! eliminating duplicated boilerplate across `as2.rs` and `as4/mod.rs`.

use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
use crate::observability::{AsxEvent, AsxProtocol, EventBus, emit_protocol_event};
use crate::reliability::{RetryClass, RetryDecision};
use std::sync::Arc;

/// Validate that `message_id` is non-empty and return a trimmed copy.
/// `context` is the error context label (e.g. `"as2_send_validate"`).
pub fn validate_message_id(
    message_id: &str,
    context: &'static str,
    session: &SessionContext,
) -> Result<()> {
    if message_id.trim().is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "message_id must not be empty",
            ErrorContext::for_session(context, session),
        ));
    }
    Ok(())
}

/// Validate that signing credentials are present when `sign = true`.
pub fn validate_signing_credentials(
    sign: bool,
    has_key: bool,
    has_cert: bool,
    context: &'static str,
    protocol: &'static str,
    session: &SessionContext,
) -> Result<()> {
    if sign && (!has_key || !has_cert) {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            format!("{protocol} signing requires signing_key_pem and signing_cert_pem"),
            ErrorContext::for_session(context, session),
        ));
    }
    Ok(())
}

/// Validate that encryption credentials are present when `encrypt = true`.
pub fn validate_encryption_credentials(
    encrypt: bool,
    has_recipient_cert: bool,
    context: &'static str,
    protocol: &'static str,
    session: &SessionContext,
) -> Result<()> {
    if encrypt && !has_recipient_cert {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            format!("{protocol} encryption requires recipient_cert_pem"),
            ErrorContext::for_session(context, session),
        ));
    }
    Ok(())
}

/// Emit `AsxEvent::OutboundPrepared` for the given protocol and message.
pub fn emit_outbound_prepared(
    event_bus: &EventBus,
    session: &SessionContext,
    message_id: &str,
    protocol: AsxProtocol,
    fail_closed_audit_events: bool,
) -> Result<()> {
    emit_protocol_event(
        event_bus,
        session,
        AsxEvent::OutboundPrepared {
            message_id: Arc::from(message_id),
            protocol,
        },
        fail_closed_audit_events,
        "send_pipeline_outbound_prepared",
    )
}

/// Emit `AsxEvent::MessageSigned` for the given message (only when signing was applied).
pub fn emit_message_signed(
    event_bus: &EventBus,
    session: &SessionContext,
    message_id: &str,
    fail_closed_audit_events: bool,
) -> Result<()> {
    emit_protocol_event(
        event_bus,
        session,
        AsxEvent::MessageSigned {
            message_id: Arc::from(message_id),
        },
        fail_closed_audit_events,
        "send_pipeline_message_signed",
    )
}

/// Emit `AsxEvent::MessageEncrypted` for the given message (only when encryption was applied).
pub fn emit_message_encrypted(
    event_bus: &EventBus,
    session: &SessionContext,
    message_id: &str,
    fail_closed_audit_events: bool,
) -> Result<()> {
    emit_protocol_event(
        event_bus,
        session,
        AsxEvent::MessageEncrypted {
            message_id: Arc::from(message_id),
        },
        fail_closed_audit_events,
        "send_pipeline_message_encrypted",
    )
}

/// Classify a send-path error into a retry decision used by default async
/// send orchestration.
pub fn classify_send_retry(err: &AsxError) -> RetryDecision {
    let class = match err.code {
        ErrorCode::TransportFailure | ErrorCode::CapacityExhausted | ErrorCode::Timeout => {
            RetryClass::Transient
        }
        ErrorCode::ReliabilityFailure => RetryClass::Indeterminate,
        ErrorCode::InvalidInput
        | ErrorCode::PolicyViolation
        | ErrorCode::DecryptionFailed
        | ErrorCode::InteropViolation
        | ErrorCode::ParseFailed
        | ErrorCode::SecurityVerificationFailed
        | ErrorCode::NotFound
        | ErrorCode::PayloadTooLarge
        | ErrorCode::CertificateRevoked
        | ErrorCode::CertificateExpired => RetryClass::Permanent,
        ErrorCode::StorageBackendFailure => RetryClass::Transient,
    };

    RetryDecision {
        should_retry: matches!(class, RetryClass::Transient | RetryClass::Indeterminate),
        class,
    }
}

#[cfg(test)]
mod tests {
    use super::classify_send_retry;
    use crate::core::{AsxError, ErrorCode, ErrorContext};

    #[test]
    fn classify_send_retry_maps_transient_and_permanent() {
        let transient = AsxError::new(
            ErrorCode::TransportFailure,
            "transport",
            ErrorContext::new("test"),
        );
        let permanent = AsxError::new(
            ErrorCode::PolicyViolation,
            "policy",
            ErrorContext::new("test"),
        );

        assert!(classify_send_retry(&transient).should_retry);
        assert!(!classify_send_retry(&permanent).should_retry);
    }
}
