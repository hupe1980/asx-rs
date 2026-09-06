//! AS4 outbound send pipeline.

use std::sync::Arc;

use super::send_mime::package_as_mime_with_extra_attachments;
use super::services::enforce_strict_as4_send_runtime_policy_consistency;
use super::types::{
    As4PreparedSendCredentials, As4SendCredentials, As4SendOutput, As4SendPolicy, SoapEnvelope,
    validate_as4_send_policy_and_credentials_consistency,
};
use crate::as4::mime_packaging::{MimeAttachment, PayloadFilename};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
#[cfg(feature = "as4")]
use crate::crypto::soap_builder::{SoapEnvelopeBuilder, WsSecurityHeaderBuilder};
use crate::crypto::wssec::{
    encrypt_payload_xmlenc_preparsed, generate_xmlsig_signature_with_external_references_preparsed,
};
use crate::observability::{AsxProtocol, EventBus};
use crate::reliability::{RetryConfig, RetryScheduler};
use crate::sbdh::StandardBusinessDocument;
use crate::send_pipeline as pipeline;
use crate::transport::trace_context::generate_traceparent;

const SOAP12_NAMESPACE: &str = "http://www.w3.org/2003/05/soap-envelope";
const SOAP12_HTTP_CONTENT_TYPE: &str = "application/soap+xml";
const SOAP12_MUST_UNDERSTAND_TOKEN: &str = "true";

#[derive(Debug, Clone, Default)]
pub struct As4SendRequest {
    pub message_id: String,
    pub payload: Vec<u8>,
    pub policy: As4SendPolicy,
    /// Per-request signing / encryption credentials.
    ///
    /// - `None` — use the signing cert, signing key, and recipient cert stored
    ///   in the session's `CertHandle` (set via
    ///   `SessionContextBuilder::with_signing_cert_pem` /
    ///   `with_signing_key_pem` / `with_recipient_cert_pem`).
    /// - `Some(creds)` — use `creds` exactly, ignoring any session-level
    ///   credential material.  Use this for per-message credential overrides
    ///   (e.g. partner-specific encryption certs in a hub/spoke topology).
    pub credentials: Option<As4SendCredentials>,
    /// A pre-validated filename emitted as `Content-Disposition: attachment;
    /// filename="..."` on the MIME payload part.
    ///
    /// Required for BDEW *Allgemeine Festlegungen* §AF §2.12 compliance.
    /// When `None`, the part still carries `Content-Disposition: attachment`
    /// for PEPPOL AS4 profile conformance.
    ///
    /// Build the filename for your profile, then parse it:
    ///
    /// ```ignore
    /// let name = format!("MSCONS_{}_{}_{}_{}_REF.txt", sender, receiver, date, time);
    /// let req = As4SendRequest { payload_filename: Some(name.parse()?), .. };
    /// ```
    pub payload_filename: Option<PayloadFilename>,
    /// `eb:PartInfo` MimeType of the primary payload — the media type
    /// *before* compression/encryption. `None` keeps the historical defaults
    /// (`application/octet-stream`, or `application/xml` when encrypting).
    pub payload_mime_type: Option<String>,
    /// Explicit Content-ID for the primary payload (bare, no `cid:` prefix).
    /// Derived from the content digest when `None`. eDelivery conformance
    /// payload profiles pin specific values (`xmlpayload@gitb`, …).
    pub payload_content_id: Option<String>,
    /// Additional payload parts for a multi-payload UserMessage. Each part is
    /// referenced from its own signed `eb:PartInfo`, signed, and — when the
    /// policy says so — compressed and encrypted exactly like the primary.
    pub additional_payloads: Vec<As4AdditionalPayload>,
}

/// One additional payload part of a multi-payload AS4 UserMessage.
///
/// ebMS3 allows several `eb:PartInfo` entries per message; the eDelivery
/// conformance payload profiles exercise up to four. The receive side has
/// surfaced every part via [`As4ReceivePushOutput::payloads`] for a while —
/// this is the sending counterpart.
///
/// [`As4ReceivePushOutput::payloads`]: crate::as4::As4ReceivePushOutput::payloads
#[derive(Clone, Debug)]
pub struct As4AdditionalPayload {
    pub bytes: Vec<u8>,
    /// `eb:PartInfo` MimeType — the media type *before* compression/encryption.
    pub mime_type: String,
    /// Explicit Content-ID (bare, no `cid:` prefix); derived from the content
    /// digest when `None`.
    pub content_id: Option<String>,
    /// `Content-Disposition` filename on the MIME part.
    pub filename: Option<PayloadFilename>,
}

impl As4AdditionalPayload {
    pub fn new(bytes: Vec<u8>, mime_type: impl Into<String>) -> Self {
        Self {
            bytes,
            mime_type: mime_type.into(),
            content_id: None,
            filename: None,
        }
    }

    pub fn with_content_id(mut self, content_id: impl Into<String>) -> Self {
        self.content_id = Some(content_id.into());
        self
    }

    pub fn with_filename(mut self, filename: PayloadFilename) -> Self {
        self.filename = Some(filename);
        self
    }
}

#[derive(Debug, Clone)]
pub struct As4SendPreparedRequest {
    pub message_id: String,
    pub payload: Vec<u8>,
    pub policy: As4SendPolicy,
    pub prepared: As4PreparedSendCredentials,
    /// See [`As4SendRequest::payload_filename`].
    pub payload_filename: Option<PayloadFilename>,
    /// See [`As4SendRequest::payload_mime_type`].
    pub payload_mime_type: Option<String>,
    /// See [`As4SendRequest::payload_content_id`].
    pub payload_content_id: Option<String>,
    /// See [`As4SendRequest::additional_payloads`].
    pub additional_payloads: Vec<As4AdditionalPayload>,
}

#[inline]
fn generated_xml_bytes_to_string(bytes: Vec<u8>) -> String {
    debug_assert!(
        std::str::from_utf8(&bytes).is_ok(),
        "generated XML must be UTF-8"
    );
    // Generated XML must be valid UTF-8; in release builds we still fail fast
    // with a clear panic message if this invariant is violated.
    String::from_utf8(bytes).expect("generated XML must be UTF-8")
}

fn encrypt_soap_header_block(
    soap_xml: &str,
    recipient_cert: &openssl::x509::X509Ref,
    payload_algorithm: crate::crypto::wssec::XmlEncPayloadAlgorithm,
    soap_namespace: &'static str,
    must_understand_token: &'static str,
) -> Result<String> {
    let start = soap_xml.find("<ebms:Messaging").ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 SOAP envelope is missing eb:Messaging header block",
            ErrorContext::new("as4_send_encrypt_soap_header"),
        )
    })?;
    let end_rel = soap_xml[start..].find("</ebms:Messaging>").ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 SOAP envelope is missing closing eb:Messaging header block",
            ErrorContext::new("as4_send_encrypt_soap_header"),
        )
    })?;
    let end = start + end_rel + "</ebms:Messaging>".len();

    let encrypted_header = crate::crypto::wssec::encrypt_soap_header_xmlenc_preparsed(
        &soap_xml.as_bytes()[start..end],
        recipient_cert,
        payload_algorithm,
        soap_namespace,
        must_understand_token,
    )?;
    let encrypted_header = String::from_utf8(encrypted_header).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("generated XML Encryption header is not valid UTF-8: {err}"),
            ErrorContext::new("as4_send_encrypt_soap_header"),
        )
    })?;

    let mut rewritten = String::with_capacity(soap_xml.len() + encrypted_header.len());
    rewritten.push_str(&soap_xml[..start]);
    rewritten.push_str(&encrypted_header);
    rewritten.push_str(&soap_xml[end..]);
    Ok(rewritten)
}

/// Send an AS4 message with explicit credentials for signing/encryption.
#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %session.partner_id())))]
pub fn send_sync(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4SendRequest,
) -> Result<As4SendOutput> {
    let As4SendRequest {
        message_id,
        payload,
        policy,
        credentials: credentials_opt,
        payload_filename,
        payload_mime_type,
        payload_content_id,
        additional_payloads,
    } = request;

    // Resolve effective credentials: per-request `Some(c)` is merged with the
    // session CertHandle for any `None` fields, so callers only need to supply
    // the fields they actually want to override.  `None` credentials fall back
    // entirely to the session.
    let session_creds;
    let credentials = {
        let ch = session.cert_handle();
        let session_signing_cert = ch
            .signing_cert_pem
            .as_ref()
            .map(|s| Arc::from(s.as_bytes()));
        let session_signing_key = ch.signing_key_pem.as_ref().map(|s| s.as_bytes().to_vec());
        let session_recipient_cert = ch
            .recipient_cert_pem
            .as_ref()
            .map(|s| Arc::from(s.as_bytes()));
        match credentials_opt {
            None => {
                session_creds = As4SendCredentials {
                    signing_cert_pem: session_signing_cert,
                    signing_key_pem: session_signing_key,
                    recipient_cert_pem: session_recipient_cert,
                };
                &session_creds
            }
            Some(ref c) => {
                // Partial override: use per-request value when set, fall back
                // to session material for each `None` field individually.
                session_creds = As4SendCredentials {
                    signing_cert_pem: c.signing_cert_pem.clone().or(session_signing_cert),
                    signing_key_pem: c.signing_key_pem.clone().or(session_signing_key),
                    recipient_cert_pem: c.recipient_cert_pem.clone().or(session_recipient_cert),
                };
                &session_creds
            }
        }
    };

    pipeline::validate_message_id(&message_id, "as4_send_validate", session)?;

    enforce_strict_as4_send_runtime_policy_consistency(session, "as4_send_validate", &policy)?;

    validate_as4_send_policy_and_credentials_consistency(
        "as4_send_validate",
        &policy,
        credentials,
        ErrorCode::PolicyViolation,
    )
    .map_err(|err| {
        AsxError::new(
            err.code,
            err.message,
            ErrorContext::for_session("as4_send_validate", session),
        )
    })?;

    if payload.is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "AS4 payload must not be empty",
            ErrorContext::for_session("as4_send_validate", session),
        ));
    }

    let prepared = credentials
        .prepare_for_policy(&policy, "as4_send_validate", ErrorCode::PolicyViolation)
        .map_err(|err| {
            AsxError::new(
                err.code,
                err.message,
                ErrorContext::for_session("as4_send_validate", session),
            )
        })?;

    send_sync_prepared(
        session,
        event_bus,
        As4SendPreparedRequest {
            message_id,
            payload,
            policy,
            prepared,
            payload_filename,
            payload_mime_type,
            payload_content_id,
            additional_payloads,
        },
    )
}

/// Send an AS4 message with pre-parsed credentials.
#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %session.partner_id())))]
pub fn send_sync_prepared(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4SendPreparedRequest,
) -> Result<As4SendOutput> {
    let As4SendPreparedRequest {
        message_id,
        payload,
        policy,
        prepared,
        payload_filename,
        payload_mime_type,
        payload_content_id,
        additional_payloads,
    } = request;
    send_sync_prepared_ref(
        session,
        event_bus,
        message_id,
        payload,
        policy,
        &prepared,
        payload_filename,
        PrimaryPartOverrides {
            mime_type: payload_mime_type,
            content_id: payload_content_id,
        },
        additional_payloads,
    )
}

/// Per-request overrides for the primary payload part.
struct PrimaryPartOverrides {
    mime_type: Option<String>,
    content_id: Option<String>,
}

/// An additional part after per-part transforms, ready for signing/packaging.
struct OutboundExtraPart {
    content_id: String,
    mime_type: String,
    bytes: Vec<u8>,
    filename: Option<PayloadFilename>,
}

/// The MIME **part** `Content-Type` on the wire. Diverges from the
/// `eb:PartInfo` MimeType (which always names the original business media
/// type) once transforms apply: compressed parts travel as gzip, encrypted
/// parts as opaque octets. This is also what keeps the WSS SwA attachment
/// transform deterministic for the receiver — WSS4J selects XML/text/binary
/// digesting by the part's wire type.
fn part_wire_content_type<'a>(policy: &As4SendPolicy, declared_mime: &'a str) -> &'a str {
    if policy.compress {
        "application/gzip"
    } else if policy.encrypt {
        "application/octet-stream"
    } else {
        declared_mime
    }
}

#[allow(clippy::too_many_arguments)]
fn send_sync_prepared_ref(
    session: &SessionContext,
    event_bus: &EventBus,
    message_id: String,
    payload: Vec<u8>,
    policy: As4SendPolicy,
    prepared: &As4PreparedSendCredentials,
    payload_filename: Option<PayloadFilename>,
    primary_overrides: PrimaryPartOverrides,
    additional_payloads: Vec<As4AdditionalPayload>,
) -> Result<As4SendOutput> {
    pipeline::validate_message_id(&message_id, "as4_send_validate", session)?;

    crate::presets::enforce_strict_runtime_bootstrap_for_strict_interop(
        "as4_send_validate",
        session,
        policy.interop,
    )?;

    enforce_strict_as4_send_runtime_policy_consistency(session, "as4_send_validate", &policy)?;

    if payload.is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "AS4 payload must not be empty",
            ErrorContext::for_session("as4_send_validate", session),
        ));
    }

    let signing_cert = prepared.signing_cert.as_ref().map(|cert| cert.as_ref());
    let signing_key = prepared.signing_key.as_ref().map(|key| key.as_ref());
    let recipient_cert = prepared.recipient_cert.as_ref().map(|cert| cert.as_ref());
    pipeline::validate_signing_credentials(
        policy.sign,
        signing_key.is_some(),
        signing_cert.is_some(),
        "as4_send_validate",
        "AS4",
        session,
    )?;
    pipeline::validate_encryption_credentials(
        policy.encrypt,
        recipient_cert.is_some(),
        "as4_send_validate",
        "AS4",
        session,
    )?;
    pipeline::emit_outbound_prepared(
        event_bus,
        session,
        &message_id,
        AsxProtocol::As4,
        policy.fail_closed_audit_events,
    )?;

    let payload = if let Some(header) = policy.sbdh_header.as_ref() {
        StandardBusinessDocument {
            header: header.clone(),
            payload,
        }
        .wrap()
        .map_err(|err| {
            AsxError::new(
                err.code,
                format!("failed to wrap AS4 payload with SBDH: {}", err.message),
                ErrorContext::for_session("as4_send_sbdh_wrap", session),
            )
        })?
    } else {
        payload
    };

    let mut payload_to_send = if policy.compress {
        #[cfg(feature = "compression")]
        {
            crate::crypto::compression::compress_gzip(&payload, 6)?
        }
        #[cfg(not(feature = "compression"))]
        {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                "AS4 compression requested but 'compression' feature is disabled",
                ErrorContext::for_session("as4_send_compress", session),
            ));
        }
    } else {
        payload
    };

    if policy.encrypt {
        let recipient_cert = recipient_cert.ok_or_else(|| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                "AS4 recipient certificate is missing",
                ErrorContext::for_session("as4_send_encrypt", session),
            )
        })?;
        payload_to_send = encrypt_payload_xmlenc_preparsed(
            &payload_to_send,
            recipient_cert,
            policy.outbound_xmlenc_payload_algorithm,
        )?;
    }

    // AS4 profile §3.1: `MimeType` describes the payload *before* compression,
    // and compression is advertised separately via `CompressionType`. Labelling
    // the part `application/gzip` and stopping there would discard the original
    // media type and leave the receiver no conformant signal to decompress.
    let payload_mime_type: String = primary_overrides.mime_type.unwrap_or_else(|| {
        if policy.encrypt {
            "application/xml".to_string()
        } else {
            "application/octet-stream".to_string()
        }
    });
    let payload_mime_type = payload_mime_type.as_str();
    // Advertised whenever compression was applied — including under
    // encryption: the receiver decrypts first and the signed `CompressionType`
    // property is its only conformant signal to then decompress. Suppressing
    // it for encrypted payloads delivered gzip bytes as the business document.
    let payload_compression_type = policy
        .compress
        .then_some(crate::crypto::compression::AS4_COMPRESSION_TYPE);

    let payload_content_id = primary_overrides
        .content_id
        .unwrap_or_else(|| MimeAttachment::content_id_from_digest(&payload_to_send));

    // Additional parts get the same per-part treatment as the primary:
    // compress when the policy says so, then encrypt. SBDH wrapping applies to
    // the primary business document only.
    let mut extra_parts: Vec<OutboundExtraPart> = Vec::with_capacity(additional_payloads.len());
    for part in additional_payloads {
        let mut bytes = part.bytes;
        if policy.compress {
            #[cfg(feature = "compression")]
            {
                bytes = crate::crypto::compression::compress_gzip(&bytes, 6)?;
            }
            #[cfg(not(feature = "compression"))]
            {
                return Err(AsxError::new(
                    ErrorCode::PolicyViolation,
                    "AS4 compression requested but 'compression' feature is disabled",
                    ErrorContext::for_session("as4_send_compress", session),
                ));
            }
        }
        if policy.encrypt {
            let recipient_cert = prepared.recipient_cert.as_ref().ok_or_else(|| {
                AsxError::new(
                    ErrorCode::PolicyViolation,
                    "AS4 recipient certificate is missing",
                    ErrorContext::for_session("as4_send_encrypt", session),
                )
            })?;
            bytes = encrypt_payload_xmlenc_preparsed(
                &bytes,
                recipient_cert,
                policy.outbound_xmlenc_payload_algorithm,
            )?;
        }
        let content_id = part
            .content_id
            .unwrap_or_else(|| MimeAttachment::content_id_from_digest(&bytes));
        extra_parts.push(OutboundExtraPart {
            content_id,
            mime_type: part.mime_type,
            bytes,
            filename: part.filename,
        });
    }

    // Every part needs a distinct Content-ID: it is the MIME-part address, the
    // eb:PartInfo href, and the ds:Reference URI. A duplicate would make two
    // references resolve to one attachment and leave the other unverifiable.
    {
        let mut seen = std::collections::HashSet::new();
        seen.insert(payload_content_id.as_str());
        for part in &extra_parts {
            if !seen.insert(part.content_id.as_str()) {
                return Err(AsxError::new(
                    ErrorCode::InvalidInput,
                    format!("duplicate payload Content-ID: {}", part.content_id),
                    ErrorContext::for_session("as4_send_validate", session),
                ));
            }
        }
    }
    let original_sender = policy
        .original_sender
        .clone()
        .unwrap_or_else(|| session.session_id().to_string());
    let final_recipient = policy
        .final_recipient
        .clone()
        .unwrap_or_else(|| session.partner_id().to_string());
    let tracking_identifier = policy
        .tracking_identifier
        .clone()
        .unwrap_or_else(|| message_id.clone());
    let conversation_id = policy.conversation_id.clone();

    // Party identifiers: explicit policy values win; the session ids are a
    // fallback for closed asx↔asx loops only — a real counterparty resolves
    // its P-Mode against these values.
    let from_party_id = policy
        .from_party_id
        .as_deref()
        .unwrap_or_else(|| session.session_id());
    let to_party_id = policy
        .to_party_id
        .as_deref()
        .unwrap_or_else(|| session.partner_id());

    // Pin `eb:MessageInfo/eb:Timestamp` once. The envelope is built twice below
    // — unsigned to compute the `eb:Messaging` digest, then again with the
    // `wsse:Security` header — and reading the clock inside each build let the
    // two straddle a second boundary, shipping an envelope whose `eb:Messaging`
    // no longer matched the digest that was signed. About one send in a
    // thousand went out unverifiable.
    let message_timestamp = crate::time_utils::format_rfc3339_secs(std::time::SystemTime::now());
    let build_soap_xml = |payload: Vec<u8>, reserve_ws_security: bool| -> Result<String> {
        let extra_part_infos: Vec<(String, String, Option<String>)> = extra_parts
            .iter()
            .map(|part| {
                (
                    part.content_id.clone(),
                    part.mime_type.clone(),
                    policy
                        .compress
                        .then(|| crate::crypto::compression::AS4_COMPRESSION_TYPE.to_string()),
                )
            })
            .collect();
        let mut builder = SoapEnvelopeBuilder::new(&message_id, from_party_id, to_party_id)
            .with_extra_part_infos(extra_part_infos)
            .with_party_id_types(
                policy.from_party_id_type.clone(),
                policy.to_party_id_type.clone(),
            )
            .with_roles(&policy.from_role, &policy.to_role)
            .with_action(&policy.action)
            .with_service(&policy.service, &policy.service_type)
            .with_four_corner_properties(&original_sender, &final_recipient, &tracking_identifier)
            .with_payload_content_id(&payload_content_id)
            .with_payload_mime_type(payload_mime_type)
            .with_detached_payload_reference()
            .with_payload(payload);
        if let Some(compression_type) = payload_compression_type {
            builder = builder.with_payload_compression_type(compression_type);
        }
        if let Some(ref_id) = &policy.ref_to_message_id {
            builder = builder.with_ref_to_message_id(ref_id);
        }
        if let Some(conv_id) = &conversation_id {
            builder = builder.with_conversation_id(conv_id);
        }
        if let Some(agreement) = &policy.agreement_ref {
            builder = builder.with_agreement_ref(agreement, policy.agreement_ref_type.clone());
        }
        if let Some(wsa) = &policy.ws_addressing {
            builder = builder.with_ws_addressing(wsa.clone());
        }
        if reserve_ws_security {
            builder = builder.with_ws_security_placeholder();
        }
        builder = builder.with_message_timestamp(message_timestamp.clone());
        let built = builder.build().map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("failed to build SOAP envelope: {err:?}"),
                ErrorContext::for_session("as4_soap_builder", session),
            )
        })?;
        Ok(generated_xml_bytes_to_string(built))
    };

    // AS4 SwA packaging: the payload travels as a detached MIME part
    // referenced from the signed `eb:PartInfo` header, and the SOAP Body is
    // empty. (Through 0.12.0 asx emitted MTOM-style `xop:Include` in the Body with
    // an `application/xop+xml` root part, which WSS4J-based receivers reject
    // at DOM conversion.)
    // Built exactly once. When signing, the `wsse:Security` slot is reserved with
    // a placeholder and the finished header is spliced in after the signature is
    // computed — the placeholder sits outside both signed subtrees, so it cannot
    // move a digest. Rebuilding the envelope to add the header is what let
    // `eb:Timestamp` differ between the bytes that were digested and the bytes
    // that shipped, roughly once in a thousand sends (D42).
    let unsigned_xml = build_soap_xml(Vec::new(), policy.sign)?;

    let mut soap_xml = if policy.sign {
        let signing_key = signing_key.ok_or_else(|| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                "AS4 signing key is missing",
                ErrorContext::for_session("as4_send_sign", session),
            )
        })?;
        let signing_cert_ref = signing_cert.ok_or_else(|| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                "AS4 signing certificate is missing",
                ErrorContext::for_session("as4_send_sign", session),
            )
        })?;
        let signing_cert_pem_bytes = signing_cert_ref.to_pem().map_err(|_err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "failed to serialize AS4 signing certificate to PEM",
                ErrorContext::for_session("as4_send_sign", session),
            )
        })?;

        // Sign the entire <ebms:Messaging> block (covers all UserMessage
        // metadata), the SOAP Body, and the payload attachment. Previously only
        // <ebms:MessageId> was signed, leaving From/To/Service/Action/PartInfo
        // unprotected against tampering.
        let messaging_reference = format!("#{}", crate::crypto::soap_builder::MESSAGING_WSU_ID);
        let body_reference = format!("#{}", crate::crypto::soap_builder::SOAP_BODY_WSU_ID);
        let payload_reference = format!("cid:{payload_content_id}");
        let extra_references: Vec<String> = extra_parts
            .iter()
            .map(|part| format!("cid:{}", part.content_id))
            .collect();
        let mut reference_uris: Vec<&str> = vec![
            messaging_reference.as_str(),
            body_reference.as_str(),
            payload_reference.as_str(),
        ];
        reference_uris.extend(extra_references.iter().map(String::as_str));
        // WSS SwA §4.4: the attachment digest input depends on the part's wire
        // content type — XML parts are digested over their Exclusive C14N
        // form, text/* parts over CRLF-normalized octets. This must match
        // what WSS4J-based receivers recompute.
        let primary_digest_input = crate::crypto::wssec::swa_attachment_digest_input(
            Some(part_wire_content_type(&policy, payload_mime_type)),
            &payload_to_send,
        )?;
        let extra_digest_inputs = extra_parts
            .iter()
            .map(|part| {
                crate::crypto::wssec::swa_attachment_digest_input(
                    Some(part_wire_content_type(&policy, &part.mime_type)),
                    &part.bytes,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let mut external_refs: Vec<(&str, &[u8])> =
            vec![(payload_reference.as_str(), primary_digest_input.as_ref())];
        external_refs.extend(
            extra_references
                .iter()
                .map(String::as_str)
                .zip(extra_digest_inputs.iter().map(|input| input.as_ref())),
        );
        let signature_xml = generate_xmlsig_signature_with_external_references_preparsed(
            &unsigned_xml,
            &reference_uris,
            &external_refs,
            signing_key,
            signing_cert_ref,
            policy.outbound_key_info_profile,
        )?;

        // Build the WS-Security header, choosing BST token type based on the
        // outbound key-info profile.  X509PKIPathv1 requires a PKIPath-encoded
        // BST (DER SEQUENCE { Certificate }) referenced by SecurityTokenReference;
        // all other profiles embed the leaf certificate as X509v3.
        let use_pkipath = policy.outbound_key_info_profile
            == crate::crypto::wssec::WsSecOutboundKeyInfoProfile::X509PKIPathv1;
        let mut header_builder = WsSecurityHeaderBuilder::new().with_signature_xml(signature_xml);
        header_builder = if use_pkipath {
            let cert_der = signing_cert_ref.to_der().map_err(|_err| {
                AsxError::new(
                    ErrorCode::ParseFailed,
                    "failed to DER-encode AS4 signing certificate for PKIPath BST",
                    ErrorContext::for_session("as4_send_sign", session),
                )
            })?;
            let pkipath = crate::crypto::soap_builder::build_pkipath_der(&cert_der);
            header_builder.with_signing_cert_pkipath_der(pkipath)
        } else {
            header_builder.with_signing_cert(signing_cert_pem_bytes)
        };
        let wsse_header = header_builder.build().map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("failed to build WS-Security header: {err:?}"),
                ErrorContext::for_session("as4_send_sign", session),
            )
        })?;
        let wsse_header = generated_xml_bytes_to_string(wsse_header);

        // Splice, do not rebuild. `splice_ws_security_header` requires exactly
        // one placeholder, so the insertion cannot silently miss.
        crate::crypto::soap_builder::splice_ws_security_header(&unsigned_xml, &wsse_header)?
    } else {
        unsigned_xml
    };

    if policy.encrypt_soap_headers {
        let recipient_cert = recipient_cert.ok_or_else(|| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                "AS4 recipient certificate is missing for SOAP header encryption",
                ErrorContext::for_session("as4_send_encrypt_soap_header", session),
            )
        })?;
        soap_xml = encrypt_soap_header_block(
            &soap_xml,
            recipient_cert,
            policy.outbound_xmlenc_payload_algorithm,
            SOAP12_NAMESPACE,
            SOAP12_MUST_UNDERSTAND_TOKEN,
        )?;
    }

    let soap_body = soap_xml.into_bytes();

    let extra_attachments: Vec<MimeAttachment> = extra_parts
        .into_iter()
        .map(|part| {
            let disposition = match &part.filename {
                Some(name) => format!("attachment; filename=\"{}\"", name.as_str()),
                None => "attachment".to_string(),
            };
            let wire_content_type = part_wire_content_type(&policy, &part.mime_type).to_string();
            MimeAttachment::new(&part.content_id, wire_content_type, part.bytes, "binary")
                .with_disposition(disposition)
        })
        .collect();
    let primary_wire_content_type = part_wire_content_type(&policy, payload_mime_type);
    let (outbound_body, http_content_type) = package_as_mime_with_extra_attachments(
        soap_body,
        payload_to_send,
        &payload_content_id,
        primary_wire_content_type,
        SOAP12_HTTP_CONTENT_TYPE,
        payload_filename.as_ref(),
        extra_attachments,
    )?;

    if policy.sign {
        pipeline::emit_message_signed(
            event_bus,
            session,
            &message_id,
            policy.fail_closed_audit_events,
        )?;
    }
    if policy.encrypt {
        pipeline::emit_message_encrypted(
            event_bus,
            session,
            &message_id,
            policy.fail_closed_audit_events,
        )?;
    }

    let traceparent = generate_traceparent(&session.correlation_scope().root_id, &message_id);

    Ok(As4SendOutput {
        message_id,
        action: policy.action,
        traceparent: Some(traceparent),
        http_content_type,
        soap_envelope: SoapEnvelope {
            action: "ebms:user-message".into(),
            body: outbound_body.into(),
        },
        ref_to_message_id: policy.ref_to_message_id,
    })
}

/// Async-safe wrapper around [`send_sync`] that isolates synchronous SOAP/XMLDSig
/// and MIME assembly work onto Tokio's blocking thread pool.
pub async fn send_async(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4SendRequest,
) -> Result<As4SendOutput> {
    let scheduler = RetryScheduler::new(RetryConfig::default());
    let request = request;

    scheduler
        .retry_with_decider(
            || {
                let blocking_session = session.clone();
                let blocking_bus = event_bus.clone();
                let error_session = session.clone();
                let request = request.clone();
                async move {
                    let permit = crate::core::CryptoAdmissionControl::process_global()
                        .acquire("as4_send_async_admission", &blocking_session)
                        .await?;
                    tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        send_sync(&blocking_session, &blocking_bus, request)
                    })
                    .await
                    .map_err(|err| {
                        AsxError::new(
                            ErrorCode::TransportFailure,
                            format!("AS4 send blocking task failed: {err}"),
                            ErrorContext::for_session("as4_send_async_join", &error_session),
                        )
                    })?
                }
            },
            |err| pipeline::classify_send_retry(err).should_retry,
        )
        .await
}

pub async fn send_async_prepared(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4SendPreparedRequest,
) -> Result<As4SendOutput> {
    let scheduler = RetryScheduler::new(RetryConfig::default());
    let request = Arc::new(request);

    scheduler
        .retry_with_decider(
            || {
                let blocking_session = session.clone();
                let blocking_bus = event_bus.clone();
                let error_session = session.clone();
                let request = Arc::clone(&request);
                async move {
                    let permit = crate::core::CryptoAdmissionControl::process_global()
                        .acquire("as4_send_async_admission", &blocking_session)
                        .await?;
                    tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        let request = request.as_ref();
                        send_sync_prepared_ref(
                            &blocking_session,
                            &blocking_bus,
                            request.message_id.clone(),
                            request.payload.clone(),
                            request.policy.clone(),
                            &request.prepared,
                            request.payload_filename.clone(),
                            PrimaryPartOverrides {
                                mime_type: request.payload_mime_type.clone(),
                                content_id: request.payload_content_id.clone(),
                            },
                            request.additional_payloads.clone(),
                        )
                    })
                    .await
                    .map_err(|err| {
                        AsxError::new(
                            ErrorCode::TransportFailure,
                            format!("AS4 send blocking task failed: {err}"),
                            ErrorContext::for_session("as4_send_async_join", &error_session),
                        )
                    })?
                }
            },
            |err| pipeline::classify_send_retry(err).should_retry,
        )
        .await
}
