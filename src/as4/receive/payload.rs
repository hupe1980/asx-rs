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

/// A resolved payload together with the Content-ID it arrived under.
pub(super) struct ResolvedNamedPayload<'a> {
    pub content_id: String,
    pub payload: ResolvedVerifiedPayload<'a>,
}

/// Resolve **every** payload attachment: decrypt each if XML-encrypted, and
/// enforce the encryption policy per attachment.
///
/// Returns at least one payload; the first is the primary. Each attachment is
/// checked independently, so a message that encrypts its first payload and
/// leaves a second in plaintext is rejected under
/// `require_encrypted_inbound` rather than passing on the strength of the
/// first.
pub(super) fn resolve_verified_payloads<'a>(
    session: &SessionContext,
    policy: &As4PushPolicy,
    message_id: &str,
    multipart: Option<MultipartAs4Payload<'a>>,
    soap_bytes: &'a [u8],
) -> Result<Vec<ResolvedNamedPayload<'a>>> {
    let multipart = multipart.ok_or_else(|| {
        AsxError::new(
            ErrorCode::PolicyViolation,
            "AS4 inbound payload must be multipart/related with a detached payload attachment",
            ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
        )
    })?;

    if multipart.payloads.is_empty() {
        if memmem::find(soap_bytes, b"<asx:Base64>").is_some() {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                "embedded AS4 payload receive is unsupported; inbound payload must be multipart/related",
                ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
            ));
        }
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            "AS4 message has no MIME payload attachment: inline SOAP body payloads are not \
             supported. PEPPOL/CEF require MIME multipart/related attachment packaging. \
             If the sending partner uses inline body mode, reconfigure their AS4 gateway \
             to use SwA MIME attachment packaging.",
            ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
        ));
    }

    let mut resolved = Vec::with_capacity(multipart.payloads.len());
    for attachment in &multipart.payloads {
        let payload = if let Some(decrypted) = decrypt_xmlenc_payload_if_present(
            attachment.bytes,
            policy.inbound_decryption_key_pem.as_deref(),
            "as4_receive_push",
        )? {
            ResolvedVerifiedPayload::Owned(decrypted)
        } else {
            // Fail closed if the policy requires encryption: no
            // xenc:EncryptedData marker was found in this attachment.
            if policy.require_encrypted_inbound {
                return Err(AsxError::new(
                    ErrorCode::PolicyViolation,
                    format!(
                        "inbound AS4 payload cid:{} is not XML-encrypted but \
                         require_encrypted_inbound = true",
                        attachment.content_id
                    ),
                    ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
                ));
            }
            ResolvedVerifiedPayload::Borrowed(attachment.bytes)
        };

        resolved.push(ResolvedNamedPayload {
            content_id: attachment.content_id.to_string(),
            payload,
        });
    }

    Ok(resolved)
}

/// `CompressionType` part properties from the verified `eb:Messaging` header,
/// keyed by the referenced payload Content-ID.
///
/// AS4 profile §3.1 makes this the only conformant signal that a payload
/// attachment is compressed — sniffing the gzip magic number instead would
/// silently expand a business document that merely happens to be a gzip file.
/// Reading it from the signed header means the flag is integrity-protected
/// along with the rest of the ebMS3 metadata.
pub(super) fn compression_types_by_content_id(
    soap_bytes: &[u8],
) -> std::collections::HashMap<String, String> {
    const EBMS3_NS: &str = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/";
    let mut out = std::collections::HashMap::new();

    let Ok(xml) = std::str::from_utf8(soap_bytes) else {
        return out;
    };
    let Ok(doc) = roxmltree::Document::parse(xml) else {
        return out;
    };

    for part_info in doc.descendants().filter(|n| {
        n.is_element()
            && n.tag_name().name() == "PartInfo"
            && n.tag_name().namespace() == Some(EBMS3_NS)
    }) {
        let Some(href) = part_info.attribute("href") else {
            continue;
        };
        let content_id = normalize_content_id(href);

        let compression = part_info
            .descendants()
            .filter(|n| {
                n.is_element()
                    && n.tag_name().name() == "Property"
                    && n.tag_name().namespace() == Some(EBMS3_NS)
            })
            .find(|n| n.attribute("name") == Some("CompressionType"))
            .and_then(|n| n.attribute("value").map(str::trim))
            .filter(|v| !v.is_empty());

        if let Some(compression) = compression {
            out.insert(content_id, compression.to_string());
        }
    }

    out
}

/// Strip a `cid:` scheme prefix and angle brackets so `cid:p@e`, `<p@e>` and
/// `p@e` all compare equal.
fn normalize_content_id(value: &str) -> String {
    let value = value.trim();
    let value = value.strip_prefix('<').unwrap_or(value);
    let value = value.strip_suffix('>').unwrap_or(value);
    let value = value
        .get(..4)
        .filter(|p| p.eq_ignore_ascii_case("cid:"))
        .map_or(value, |_| &value[4..]);
    value.to_string()
}

/// Reverse AS4 payload compression when the signed `eb:PartInfo` declares it.
pub(super) fn decompress_payload_if_declared<'a>(
    session: &SessionContext,
    content_id: &str,
    compression_types: &std::collections::HashMap<String, String>,
    payload: ResolvedVerifiedPayload<'a>,
) -> Result<ResolvedVerifiedPayload<'a>> {
    let Some(compression_type) = compression_types.get(&normalize_content_id(content_id)) else {
        return Ok(payload);
    };

    if !compression_type.eq_ignore_ascii_case(crate::crypto::compression::AS4_COMPRESSION_TYPE) {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!(
                "AS4 payload declares unsupported CompressionType \"{compression_type}\"; \
                 the AS4 profile defines only \"{}\"",
                crate::crypto::compression::AS4_COMPRESSION_TYPE
            ),
            ErrorContext::for_session("as4_receive_decompress", session),
        ));
    }

    #[cfg(feature = "compression")]
    {
        let plain =
            crate::crypto::compression::decompress_gzip(payload.as_slice()).map_err(|err| {
                AsxError::new(
                    err.code,
                    format!(
                        "failed to decompress AS4 payload attachment: {}",
                        err.message
                    ),
                    ErrorContext::for_session("as4_receive_decompress", session),
                )
            })?;
        Ok(ResolvedVerifiedPayload::Owned(plain))
    }
    #[cfg(not(feature = "compression"))]
    {
        Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "partner sent a gzip-compressed AS4 payload but the 'compression' feature \
             is disabled",
            ErrorContext::for_session("as4_receive_decompress", session),
        ))
    }
}
