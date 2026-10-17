//! Shared send pipeline utilities for AS2 and AS4 message dispatch.
//!
//! Both protocols share a common outbound lifecycle:
//!
//! 1. Validate message ID and payload (protocol-level preconditions)
//! 2. Validate credentials against the requested crypto operations
//! 3. Apply cryptographic operations (protocol-specific, in `asx.sign` /
//!    `asx.encrypt` spans)
//! 4. Assemble wire format (protocol-specific)
//!
//! This module holds the protocol-agnostic helpers for steps 1–2.

use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};

/// Validate that `message_id` is non-empty and return a trimmed copy.
/// `context` is the error context label (e.g. `"as2_send_validate"`).
pub(crate) fn validate_message_id(
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
pub(crate) fn validate_signing_credentials(
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
pub(crate) fn validate_encryption_credentials(
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
