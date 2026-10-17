//! AS4 outbound send pipeline.

use super::services::enforce_strict_as4_send_runtime_policy_consistency;
use super::types::{As4SendOutput, As4SendPolicy, SoapEnvelope};
use crate::as4::mime_packaging::{
    MimeAttachment, PayloadFilename, validate_content_id, validate_media_type,
};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
#[cfg(feature = "as4")]
use crate::crypto::soap_builder::SoapEnvelopeBuilder;
use crate::sbdh::StandardBusinessDocument;
use crate::send_pipeline as pipeline;

const SOAP12_HTTP_CONTENT_TYPE: &str = "application/soap+xml";
/// The HTTP `Content-Type` of a message without payload parts: one plain
/// SOAP 1.2 envelope, no MIME multipart.
const SOAP12_PLAIN_CONTENT_TYPE: &str = "application/soap+xml; charset=UTF-8";

/// One additional payload part of a multi-payload AS4 UserMessage.
///
/// ebMS3 allows several `eb:PartInfo` entries per message; the eDelivery
/// conformance payload profiles exercise up to four.
#[derive(Clone, Debug)]
pub(crate) struct As4AdditionalPayload {
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
    pub(crate) fn new(bytes: Vec<u8>, mime_type: impl Into<String>) -> Self {
        Self {
            bytes,
            mime_type: mime_type.into(),
            content_id: None,
            filename: None,
        }
    }

    pub(crate) fn with_filename(mut self, filename: PayloadFilename) -> Self {
        self.filename = Some(filename);
        self
    }
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

/// Per-request overrides for the primary payload part.
pub(crate) struct PrimaryPartOverrides {
    pub(crate) mime_type: Option<String>,
    pub(crate) content_id: Option<String>,
}

/// An additional part after per-part transforms, ready for signing/packaging.
struct OutboundExtraPart {
    content_id: String,
    mime_type: String,
    bytes: Vec<u8>,
    filename: Option<PayloadFilename>,
}

/// The part's type **before encryption**: what the SwA
/// `Attachment-Content-Signature-Transform` digests by (WSS4J selects
/// XML/text/binary digesting by it) and what `EncryptedData/@MimeType`
/// restores. Diverges from the `eb:PartInfo` MimeType (the original business
/// type) once compressed.
fn part_plain_content_type<'a>(policy: &As4SendPolicy, declared_mime: &'a str) -> &'a str {
    if policy.compress {
        "application/gzip"
    } else {
        declared_mime
    }
}

/// The MIME **part** `Content-Type` on the wire: encrypted parts are opaque
/// octets (WSS SwA 1.1 §5.5.2 step 10).
fn part_wire_content_type<'a>(policy: &As4SendPolicy, declared_mime: &'a str) -> &'a str {
    if policy.encrypt {
        "application/octet-stream"
    } else {
        part_plain_content_type(policy, declared_mime)
    }
}

/// Inputs of one draft beyond the policy and payloads.
pub(crate) struct DraftInputs {
    pub(crate) message_id: String,
    /// The primary payload part. `None`: a message without payload parts (a
    /// BDEW path switch), sent as a plain SOAP envelope.
    pub(crate) payload: Option<Vec<u8>>,
    pub(crate) policy: As4SendPolicy,
    pub(crate) payload_filename: Option<PayloadFilename>,
    pub(crate) primary_overrides: PrimaryPartOverrides,
    pub(crate) additional_payloads: Vec<As4AdditionalPayload>,
    /// `eb:Timestamp`, RFC 3339 with seconds. `None`: now.
    pub(crate) timestamp: Option<String>,
    /// The signing algorithm and certificate chain (leaf first, DER). `None`:
    /// the policy does not sign.
    pub(crate) signer: Option<(crate::crypto::alg::SignatureAlgorithm, Vec<Vec<u8>>)>,
    /// Emit `Content-Disposition` on payload parts (Peppol AS4 §4.10 forbids
    /// it).
    pub(crate) content_disposition: bool,
}

/// A message built up to its signature: the canonical `SignedInfo` is what
/// the key signs; [`finish_send`] assembles the rest. Splitting here lets an
/// asynchronous `Signer` run between the two pure halves.
pub(crate) struct SendDraft {
    session: SessionContext,
    message_id: String,
    policy: As4SendPolicy,
    envelope: DraftEnvelope,
    payload_to_send: Option<Vec<u8>>,
    payload_content_id: String,
    payload_mime_type: String,
    payload_filename: Option<PayloadFilename>,
    extra_parts: Vec<OutboundExtraPart>,
    /// The SwA encryption envelope for `wsse:Security`.
    encryption: Option<crate::xml::XmlFragment>,
    content_disposition: bool,
}

enum DraftEnvelope {
    Unsigned(String),
    Signed {
        unsigned: crate::crypto::soap_builder::UnsignedEnvelope,
        prepared: crate::crypto::wssec::sign::PreparedSignature,
        chain_der: Vec<Vec<u8>>,
    },
}

impl SendDraft {
    /// The bytes the signer signs, with the algorithm; `None` when unsigned.
    pub(crate) fn to_sign(&self) -> Option<(crate::crypto::alg::SignatureAlgorithm, &[u8])> {
        match &self.envelope {
            DraftEnvelope::Unsigned(_) => None,
            DraftEnvelope::Signed { prepared, .. } => Some((
                prepared.algorithm,
                prepared.canonical_signed_info.as_slice(),
            )),
        }
    }
}

/// A deterministic Content-ID for part `index` of `message_id`: a retry of the same message produces the same `cid:`
/// references and the same `eb:PartInfo`.
pub(crate) fn derived_content_id(message_id: &str, index: usize) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(message_id.as_bytes());
    let hex: String = digest.iter().take(12).map(|b| format!("{b:02x}")).collect();
    format!("part{index}.{hex}@asx")
}

/// Build the message up to its signature. Validation, SBDH, compression,
/// encryption, the envelope and the canonical `SignedInfo` happen here.
pub(crate) fn draft_send(
    session: &SessionContext,
    inputs: DraftInputs,
    recipient_cert: Option<openssl::x509::X509>,
    (signing_key_present, signing_cert_present): (bool, bool),
) -> Result<SendDraft> {
    let DraftInputs {
        message_id,
        payload,
        policy,
        payload_filename,
        primary_overrides,
        additional_payloads,
        timestamp,
        signer,
        content_disposition,
    } = inputs;
    pipeline::validate_message_id(&message_id, "as4_send_validate", session)?;

    // Caller identifiers reach MIME headers and signed XML: check them before
    // any digest is taken.
    if let Some(content_id) = primary_overrides.content_id.as_deref() {
        validate_content_id(content_id, "payload_content_id")?;
    }
    if let Some(mime_type) = primary_overrides.mime_type.as_deref() {
        validate_media_type(mime_type, "payload_mime_type")?;
    }
    for (index, part) in additional_payloads.iter().enumerate() {
        if let Some(content_id) = part.content_id.as_deref() {
            validate_content_id(
                content_id,
                &format!("additional_payloads[{index}].content_id"),
            )?;
        }
        validate_media_type(
            &part.mime_type,
            &format!("additional_payloads[{index}].mime_type"),
        )?;
    }

    enforce_strict_as4_send_runtime_policy_consistency(session, "as4_send_validate", &policy)?;

    if payload.as_ref().is_some_and(Vec::is_empty) {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "AS4 payload must not be empty",
            ErrorContext::for_session("as4_send_validate", session),
        ));
    }
    if payload.is_none() && (!additional_payloads.is_empty() || policy.sbdh_header.is_some()) {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "an AS4 message without a primary payload carries no other part and no SBDH",
            ErrorContext::for_session("as4_send_validate", session),
        ));
    }

    pipeline::validate_signing_credentials(
        policy.sign,
        signing_key_present,
        signing_cert_present,
        "as4_send_validate",
        "AS4",
        session,
    )?;
    let recipient_cert_ref = recipient_cert.as_deref();
    pipeline::validate_encryption_credentials(
        policy.encrypt,
        recipient_cert_ref.is_some(),
        "as4_send_validate",
        "AS4",
        session,
    )?;

    let payload = match (policy.sbdh_header.as_ref(), payload) {
        (Some(header), Some(payload)) => Some(
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
            })?,
        ),
        (_, payload) => payload,
    };

    if policy.encrypt && !policy.sign {
        // Sign, then encrypt (eDelivery AS4 1.15 §3.2.6, ebMS3 §7.6): the
        // envelope lives in the signed message's `wsse:Security` header.
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "AS4 encryption requires a signed message (sign, then encrypt)",
            ErrorContext::for_session("as4_send_encrypt", session),
        ));
    }

    // Compress → sign over the compressed bytes → encrypt (AS4 §5.1.8(b),
    // WSS SwA §5.5).
    let mut payload_to_send = match payload {
        Some(payload) if policy.compress => {
            Some(crate::crypto::compression::compress_gzip(&payload, 6)?)
        }
        payload => payload,
    };
    let has_primary = payload_to_send.is_some();

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
    // Advertised whenever compression was applied — including under
    // encryption: the receiver decrypts first and the signed `CompressionType`
    // property is its only conformant signal to then decompress.
    let payload_compression_type = (policy.compress && has_primary)
        .then_some(crate::crypto::compression::AS4_COMPRESSION_TYPE);

    let payload_content_id = primary_overrides
        .content_id
        .unwrap_or_else(|| derived_content_id(&message_id, 0));

    // Additional parts get the same per-part treatment as the primary:
    // compressed when the policy says so (encrypted after signing). SBDH
    // wrapping applies to the primary business document only.
    let mut extra_parts: Vec<OutboundExtraPart> = Vec::with_capacity(additional_payloads.len());
    for (index, part) in additional_payloads.into_iter().enumerate() {
        let mut bytes = part.bytes;
        if policy.compress {
            bytes = crate::crypto::compression::compress_gzip(&bytes, 6)?;
        }
        let content_id = part
            .content_id
            .unwrap_or_else(|| derived_content_id(&message_id, index + 1));
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

    // Pin `eb:MessageInfo/eb:Timestamp` once; a caller-supplied value keeps
    // a retry's NRR digests equal to the original's.
    let message_timestamp =
        timestamp.unwrap_or_else(|| crate::time_utils::format_rfc3339_secs(session.clock().now()));
    let four_corner = policy.original_sender.is_some()
        || policy.final_recipient.is_some()
        || policy.tracking_identifier.is_some()
        || policy.sbdh_header.is_some();
    let envelope_builder = || -> SoapEnvelopeBuilder {
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
            .with_payload(Vec::new());
        // No primary part: no `eb:PayloadInfo` at all.
        if has_primary {
            builder = builder
                .with_payload_content_id(&payload_content_id)
                .with_payload_mime_type(&payload_mime_type)
                .with_detached_payload_reference();
        }
        builder = if four_corner || !session_is_profile_built(session) {
            builder.with_four_corner_properties(
                &original_sender,
                &final_recipient,
                &tracking_identifier,
            )
        } else {
            builder.without_message_properties()
        };
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
        builder.with_message_timestamp(message_timestamp.clone())
    };
    let build_failed = |err: AsxError| {
        // A caller value XML cannot carry is the caller's error, named.
        if err.code == ErrorCode::InvalidInput {
            return err;
        }
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("failed to build SOAP envelope: {err:?}"),
            ErrorContext::for_session("as4_soap_builder", session),
        )
    };

    // AS4 SwA packaging: the payload travels as a detached MIME part
    // referenced from the signed `eb:PartInfo` header, and the SOAP Body is
    // empty. Built exactly once: when signing, the `wsse:Security`
    // position is a slot the writer reserves; the signature is computed over
    // the envelope with the slot empty and the finished header is filled in
    // afterwards — the slot sits outside both signed subtrees.
    let envelope = if policy.sign {
        let Some((algorithm, chain_der)) = signer else {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                "AS4 signing key is missing",
                ErrorContext::for_session("as4_send_sign", session),
            ));
        };
        if chain_der.is_empty() {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                "AS4 signing certificate is missing",
                ErrorContext::for_session("as4_send_sign", session),
            ));
        }
        let unsigned = envelope_builder()
            .build_with_security_slot()
            .map_err(build_failed)?;

        // Sign the entire <ebms:Messaging> block, the SOAP Body, and every
        // payload attachment.
        let messaging_reference = format!("#{}", crate::crypto::soap_builder::MESSAGING_WSU_ID);
        let body_reference = format!("#{}", crate::crypto::soap_builder::SOAP_BODY_WSU_ID);
        let payload_reference = format!("cid:{payload_content_id}");
        let extra_references: Vec<String> = extra_parts
            .iter()
            .map(|part| format!("cid:{}", part.content_id))
            .collect();
        let mut reference_uris: Vec<&str> =
            vec![messaging_reference.as_str(), body_reference.as_str()];
        if has_primary {
            reference_uris.push(payload_reference.as_str());
        }
        reference_uris.extend(extra_references.iter().map(String::as_str));
        // WSS SwA §4.4: the attachment digest input depends on the part's
        // content type before encryption; the digest covers the
        // pre-encryption bytes, so a retry reproduces it.
        let primary_digest_input = payload_to_send
            .as_deref()
            .map(|bytes| {
                crate::crypto::wssec::swa_attachment_digest_input(
                    Some(part_plain_content_type(&policy, &payload_mime_type)),
                    bytes,
                )
            })
            .transpose()?;
        let extra_digest_inputs = extra_parts
            .iter()
            .map(|part| {
                crate::crypto::wssec::swa_attachment_digest_input(
                    Some(part_plain_content_type(&policy, &part.mime_type)),
                    &part.bytes,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let mut external_refs: Vec<(&str, &[u8])> = primary_digest_input
            .as_ref()
            .map(|input| (payload_reference.as_str(), input.as_ref()))
            .into_iter()
            .collect();
        external_refs.extend(
            extra_references
                .iter()
                .map(String::as_str)
                .zip(extra_digest_inputs.iter().map(|input| input.as_ref())),
        );
        let prepared = crate::crypto::wssec::sign::prepare_envelope_signature(
            unsigned.text(),
            &reference_uris,
            &external_refs,
            algorithm,
        )?;
        DraftEnvelope::Signed {
            unsigned,
            prepared,
            chain_der,
        }
    } else {
        let built = envelope_builder().build().map_err(build_failed)?;
        DraftEnvelope::Unsigned(generated_xml_bytes_to_string(built))
    };

    // Encrypt after the digests are taken: one content key for the message,
    // one EncryptedData per part (WSS SwA 1.1 §5.5).
    let encryption = if policy.encrypt {
        let recipient = recipient_cert_ref.ok_or_else(|| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                "AS4 recipient certificate is missing",
                ErrorContext::for_session("as4_send_encrypt", session),
            )
        })?;
        let primary_type = part_plain_content_type(&policy, &payload_mime_type).to_string();
        let extra_types: Vec<String> = extra_parts
            .iter()
            .map(|part| part_plain_content_type(&policy, &part.mime_type).to_string())
            .collect();
        // Zero parts encrypt to nothing: no `EncryptedKey`.
        let mut outbound: Vec<_> = payload_to_send
            .as_deref()
            .map(|plaintext| crate::crypto::wssec::xmlenc::OutboundPart {
                content_id: &payload_content_id,
                mime_type: &primary_type,
                plaintext,
            })
            .into_iter()
            .collect();
        outbound.extend(
            extra_parts
                .iter()
                .zip(&extra_types)
                .map(
                    |(part, mime_type)| crate::crypto::wssec::xmlenc::OutboundPart {
                        content_id: &part.content_id,
                        mime_type,
                        plaintext: &part.bytes,
                    },
                ),
        );
        let envelope = crate::crypto::wssec::xmlenc::encrypt_attachments(
            &outbound,
            recipient,
            policy.recipient_form,
            policy.outbound_xmlenc_payload_algorithm,
            &envelope_id_seed(&message_id),
        )?;
        drop(outbound);
        match envelope {
            Some(envelope) => {
                let mut bodies = envelope.bodies.into_iter();
                if payload_to_send.is_some() {
                    payload_to_send = bodies.next();
                }
                for (part, body) in extra_parts.iter_mut().zip(bodies) {
                    part.bytes = body;
                }
                Some(envelope.header)
            }
            None => None,
        }
    } else {
        None
    };

    Ok(SendDraft {
        session: session.clone(),
        message_id,
        policy,
        envelope,
        payload_to_send,
        payload_content_id,
        payload_mime_type,
        payload_filename,
        extra_parts,
        encryption,
        content_disposition,
    })
}

/// The identifier seed of the encryption envelope (`EK-`, `ED-`, `X509-`):
/// derived from the message id like the Content-IDs, NCName-safe.
fn envelope_id_seed(message_id: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(message_id.as_bytes())
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Whether this session was built from a `Profile` (the four-corner
/// properties are then the Peppol envelope's, never a session fallback).
fn session_is_profile_built(session: &SessionContext) -> bool {
    session.metadata().profile_built
}

/// Assemble the signed envelope and the MIME package. `raw_signature` is the
/// key's output for [`SendDraft::to_sign`] (DER for ECDSA).
pub(crate) fn finish_send(
    draft: SendDraft,
    raw_signature: Option<Vec<u8>>,
) -> Result<As4SendOutput> {
    let SendDraft {
        session,
        message_id,
        policy,
        envelope,
        payload_to_send,
        payload_content_id,
        payload_mime_type,
        payload_filename,
        extra_parts,
        encryption,
        content_disposition,
    } = draft;
    let session = &session;
    let soap_xml = match envelope {
        DraftEnvelope::Unsigned(xml) => xml,
        DraftEnvelope::Signed {
            unsigned,
            prepared,
            chain_der,
        } => {
            let raw = raw_signature.ok_or_else(|| {
                AsxError::new(
                    ErrorCode::PolicyViolation,
                    "AS4 signature value is missing",
                    ErrorContext::for_session("as4_send_sign", session),
                )
            })?;
            let wsse_header = crate::crypto::soap_builder::security_header(
                prepared,
                raw,
                &chain_der,
                policy.outbound_key_info_profile,
                session.clock().now(),
                encryption,
            )?;
            unsigned.seal(wsse_header)?
        }
    };

    let soap_body = soap_xml.into_bytes();

    let Some(payload_to_send) = payload_to_send else {
        // No payload part: one plain SOAP envelope.
        return Ok(As4SendOutput {
            message_id,
            action: policy.action,
            http_content_type: SOAP12_PLAIN_CONTENT_TYPE.to_string(),
            soap_envelope: SoapEnvelope {
                action: "ebms:user-message".into(),
                body: soap_body.into(),
            },
            ref_to_message_id: policy.ref_to_message_id,
        });
    };

    let disposition = |filename: Option<&PayloadFilename>| match filename {
        Some(name) => Some(format!("attachment; filename=\"{}\"", name.as_str())),
        None if content_disposition => Some("attachment".to_string()),
        None => None,
    };
    let primary_wire_content_type = part_wire_content_type(&policy, &payload_mime_type);
    let mut primary = MimeAttachment::new(
        &payload_content_id,
        primary_wire_content_type,
        payload_to_send,
        "binary",
    );
    if let Some(value) = disposition(payload_filename.as_ref()) {
        primary = primary.with_disposition(value);
    }
    let mut attachments = vec![primary];
    for part in extra_parts {
        let wire_content_type = part_wire_content_type(&policy, &part.mime_type).to_string();
        let mut attachment =
            MimeAttachment::new(&part.content_id, wire_content_type, part.bytes, "binary");
        if let Some(value) = disposition(part.filename.as_ref()) {
            attachment = attachment.with_disposition(value);
        }
        attachments.push(attachment);
    }
    let (outbound_body, http_content_type) =
        super::send_mime::package_attachments(soap_body, SOAP12_HTTP_CONTENT_TYPE, attachments)?;

    Ok(As4SendOutput {
        message_id,
        action: policy.action,
        http_content_type,
        soap_envelope: SoapEnvelope {
            action: "ebms:user-message".into(),
            body: outbound_body.into(),
        },
        ref_to_message_id: policy.ref_to_message_id,
    })
}
