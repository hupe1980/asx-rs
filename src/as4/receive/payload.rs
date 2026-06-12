use super::super::stream::{MultipartAs4Payload, decrypt_xmlenc_payload_if_present};
use super::super::types::As4PushPolicy;
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
use crate::lifecycle::{DomainReady, TrustEvidence, UntrustedBytes};
use crate::sbdh::{SbdhHeader, StandardBusinessDocument};
use crate::wire::{DEFAULT_MAX_BODY_BYTES, enforce_payload_limit};
use memchr::memmem;
use std::sync::Arc;

const MAX_AS4_PAYLOAD_BYTES: usize = DEFAULT_MAX_BODY_BYTES;

pub(super) struct WsSecVerifiedGate;

pub(super) enum ResolvedVerifiedPayload<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl<'a> ResolvedVerifiedPayload<'a> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }

    fn into_payload_input(self) -> crate::core::PayloadInput<'a> {
        match self {
            Self::Borrowed(bytes) => crate::core::PayloadInput::Borrowed(bytes),
            Self::Owned(bytes) => crate::core::PayloadInput::Owned(bytes),
        }
    }
}

pub(super) struct WsSecVerifiedPayload<'a> {
    payload_input: crate::core::PayloadInput<'a>,
    _gate: WsSecVerifiedGate,
}

impl<'a> WsSecVerifiedPayload<'a> {
    pub(super) fn new(payload: ResolvedVerifiedPayload<'a>, gate: WsSecVerifiedGate) -> Self {
        Self {
            payload_input: payload.into_payload_input(),
            _gate: gate,
        }
    }
}

pub(super) fn promote_payload_to_domain_ready(
    session: &SessionContext,
    verified_payload: WsSecVerifiedPayload<'_>,
) -> Result<DomainReady<Arc<[u8]>>> {
    let payload_input = verified_payload.payload_input;
    let payload_len = payload_input.as_slice().len();
    enforce_payload_limit("as4_receive_parse", payload_len, MAX_AS4_PAYLOAD_BYTES)?;
    if payload_len == 0 {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "as4 payload is empty",
            ErrorContext::new("as4_receive_parse")
                .with_session_and_partner(session.session_id(), session.partner_id()),
        ));
    }

    let trust = TrustEvidence::verified_and_decryptable();
    // SAFETY: structural validation was performed by the WS-Security verifier
    // before this point (size check, XML well-formedness); advancing unchecked is deliberate.
    let trusted = UntrustedBytes::new(payload_input.into_arc())
        .into_parsed_unchecked()
        .verify(trust.signature)?
        .decrypt(trust.decryption)?
        .into_domain_ready();

    Ok(trusted)
}

pub(super) fn maybe_unwrap_sbdh_payload<'a>(
    session: &SessionContext,
    message_id: &str,
    payload: ResolvedVerifiedPayload<'a>,
) -> Result<(ResolvedVerifiedPayload<'a>, Option<SbdhHeader>)> {
    let payload_bytes = payload.as_slice();
    if memmem::find(payload_bytes, b"<StandardBusinessDocument").is_none() {
        return Ok((payload, None));
    }

    let wrapped = StandardBusinessDocument::unwrap(payload_bytes).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!(
                "failed to parse SBDH-wrapped AS4 business payload: {}",
                err.message
            ),
            ErrorContext::for_session_with_message("as4_receive_sbdh_unwrap", session, message_id),
        )
    })?;

    Ok((
        ResolvedVerifiedPayload::Owned(wrapped.payload),
        Some(wrapped.header),
    ))
}

pub(super) fn resolve_verified_payload<'a>(
    session: &SessionContext,
    policy: &As4PushPolicy,
    message_id: &str,
    multipart: Option<MultipartAs4Payload<'a>>,
    soap_bytes: &'a [u8],
) -> Result<ResolvedVerifiedPayload<'a>> {
    let multipart = multipart.ok_or_else(|| {
        AsxError::new(
            ErrorCode::PolicyViolation,
            "AS4 inbound payload must be multipart/related with a detached payload attachment",
            ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
        )
    })?;

    let payload_part = multipart.payload_attachment.ok_or_else(|| {
        AsxError::new(
            ErrorCode::InteropViolation,
            "AS4 message has no MIME payload attachment: inline SOAP body payloads are not \
             supported. PEPPOL/CEF require MIME multipart/related attachment packaging. \
             If the sending partner uses inline body mode, reconfigure their AS4 gateway \
             to use SwA/XOP MIME attachment packaging.",
            ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
        )
    })?;

    if let Some(decrypted) = decrypt_xmlenc_payload_if_present(
        payload_part,
        policy.inbound_decryption_key_pem.as_deref(),
        "as4_receive_push",
    )? {
        return Ok(ResolvedVerifiedPayload::Owned(decrypted));
    }

    if memmem::find(soap_bytes, b"<asx:Base64>").is_some() {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "embedded AS4 payload receive is unsupported; inbound payload must be multipart/related",
            ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
        ));
    }

    Ok(ResolvedVerifiedPayload::Borrowed(payload_part))
}
