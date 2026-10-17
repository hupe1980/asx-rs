//! AS4 signal generation: Receipt and Error signals.

use super::types::{As4ErrorCode, As4ErrorSeverity, As4NriReference, As4ReceiptCredentials};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
#[cfg(feature = "as4")]
use crate::crypto::soap_builder::WsSecurityHeaderBuilder;
use crate::crypto::wssec::generate_xmlsig_signature;
use crate::xml::{Slot, XmlDoc, XmlOut, ns};

/// Generate an AS4 `eb:Receipt` SignalMessage per ebMS3 §5.2.2.1 and §5.1.3.
///
/// The returned bytes are a complete SOAP 1.2 envelope containing a
/// `eb:SignalMessage` with an `eb:Receipt` element referencing
/// `ref_to_message_id`. The receipt contains an empty
/// `<ebbpsig:NonRepudiationInformation/>` placeholder.
///
/// For a conformant NRO receipt that echoes the original message's signed
/// references, use [`generate_receipt_with_nri`] instead.
///
/// The receipt is unsigned; if the P-Mode requires a signed receipt (NRR),
/// use [`generate_signed_receipt_with_nri`] instead.
pub fn generate_receipt(
    session: &SessionContext,
    message_id: &str,
    ref_to_message_id: &str,
) -> Result<Vec<u8>> {
    generate_receipt_with_nri(session, message_id, ref_to_message_id, &[])
}

/// Generate an AS4 `eb:Receipt` SignalMessage with Non-Repudiation of Origin
/// (NRO) information per ebMS3 §5.2.2.1 and eDelivery AS4 §5.1.3.
///
/// When `nri_refs` is non-empty each entry becomes a
/// `<ebbpsig:MessagePartNRInformation>/<ds:Reference>` element inside the
/// `<ebbpsig:NonRepudiationInformation>` block, as required by the AS4
/// Non-Repudiation of Origin profile.
///
/// Obtain `nri_refs` by calling
/// [`crate::crypto::wssec::parse_signature_references`] on the raw bytes of
/// the inbound signed message and mapping each
/// [`crate::crypto::wssec::WsSecSignatureReference`] to
/// [`As4NriReference`]:
///
/// ```text
/// let sig_refs = parse_signature_references(xml_str)?;
/// let nri: Vec<As4NriReference> = sig_refs.into_iter().map(As4NriReference::from).collect();
/// let receipt = generate_receipt_with_nri(&session, &id, &ref_id, &nri)?;
/// ```
///
/// The receipt is unsigned; for a receipt carrying a WS-Security XML
/// Signature (Non-Repudiation of Receipt), use
/// [`generate_signed_receipt_with_nri`].
pub fn generate_receipt_with_nri(
    session: &SessionContext,
    message_id: &str,
    ref_to_message_id: &str,
    nri_refs: &[As4NriReference],
) -> Result<Vec<u8>> {
    validate_receipt_signal_ids(
        session,
        "as4_generate_receipt",
        message_id,
        ref_to_message_id,
    )?;

    let timestamp = crate::time_utils::format_rfc3339_secs(session.clock().now());
    let namespaces: &[(&'static str, &'static str)] = if nri_refs.is_empty() {
        &[("ebbpsig", ns::EBBP_SIGNALS)]
    } else {
        &[("ebbpsig", ns::EBBP_SIGNALS), ("ds", ns::DS)]
    };
    let (doc, _) = write_signal(
        &SignalEnvelope {
            namespaces,
            reserve_security: false,
            messaging_id: None,
            body_id: None,
            timestamp: &timestamp,
            message_id,
            ref_to_message_id: Some(ref_to_message_id),
        },
        |out| write_receipt(out, nri_refs),
    )?;
    Ok(doc.into_string()?.into_bytes())
}

/// The fixed frame of every signal this crate emits.
struct SignalEnvelope<'a> {
    /// Namespaces beyond `S12` and `eb`, declared on the envelope.
    namespaces: &'a [(&'static str, &'static str)],
    /// Reserve the `wsse:Security` position (before `eb:Messaging`).
    reserve_security: bool,
    messaging_id: Option<&'static str>,
    body_id: Option<&'static str>,
    timestamp: &'a str,
    message_id: &'a str,
    ref_to_message_id: Option<&'a str>,
}

/// Write `S12:Envelope/S12:Header/eb:Messaging/eb:SignalMessage` with its
/// `eb:MessageInfo`; `body` writes the signal itself.
fn write_signal(
    spec: &SignalEnvelope<'_>,
    body: impl FnOnce(&mut XmlOut) -> Result<()>,
) -> Result<(XmlDoc, Option<Slot>)> {
    let mut out = XmlOut::new();
    out.start("S12:Envelope")?
        .ns("S12", ns::SOAP12)?
        .ns("eb", ns::EBMS3)?;
    for (prefix, uri) in spec.namespaces {
        out.ns(prefix, uri)?;
    }
    out.start("S12:Header")?;
    let slot = spec.reserve_security.then(|| out.slot());
    out.start("eb:Messaging")?
        .attr("S12:mustUnderstand", "true", "S12:mustUnderstand")?;
    if let Some(id) = spec.messaging_id {
        out.attr("wsu:Id", id, "wsu:Id")?;
    }
    out.start("eb:SignalMessage")?;
    out.start("eb:MessageInfo")?;
    out.leaf("eb:Timestamp", spec.timestamp, "eb:Timestamp")?;
    out.leaf("eb:MessageId", spec.message_id, "eb:MessageId")?;
    if let Some(ref_to) = spec.ref_to_message_id {
        out.leaf("eb:RefToMessageId", ref_to, "eb:RefToMessageId")?;
    }
    out.end()?;
    body(&mut out)?;
    out.end()?; // SignalMessage
    out.end()?; // Messaging
    out.end()?; // Header
    out.start("S12:Body")?;
    if let Some(id) = spec.body_id {
        out.attr("wsu:Id", id, "wsu:Id")?;
    }
    out.end()?;
    out.end()?;
    Ok((out.finish()?, slot))
}

/// `eb:Receipt` with its `ebbpsig:NonRepudiationInformation`: one
/// `MessagePartNRInformation/ds:Reference` per echoed reference (eDelivery
/// AS4 §5.1.3 Non-Repudiation of Origin), or an empty block.
fn write_receipt(out: &mut XmlOut, nri_refs: &[As4NriReference]) -> Result<()> {
    out.start("eb:Receipt")?
        .start("ebbpsig:NonRepudiationInformation")?;
    for r in nri_refs {
        out.start("ebbpsig:MessagePartNRInformation")?
            .start("ds:Reference")?
            .attr("URI", &r.uri, "ds:Reference/@URI")?;
        out.start("ds:DigestMethod")?
            .attr(
                "Algorithm",
                &r.digest_method_uri,
                "ds:DigestMethod/@Algorithm",
            )?
            .end()?;
        out.leaf("ds:DigestValue", &r.digest_value_b64, "ds:DigestValue")?;
        out.end()?.end()?;
    }
    out.end()?.end()?;
    Ok(())
}

/// Validate the message-ID pair shared by all receipt generators.
fn validate_receipt_signal_ids(
    session: &SessionContext,
    stage: &'static str,
    message_id: &str,
    ref_to_message_id: &str,
) -> Result<()> {
    if message_id.trim().is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "message_id must not be empty",
            ErrorContext::for_session(stage, session),
        ));
    }
    if ref_to_message_id.trim().is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "ref_to_message_id must not be empty",
            ErrorContext::for_session(stage, session),
        ));
    }
    Ok(())
}

/// Validate that a PEM signing key and certificate parse and match each other.
fn validate_signal_signing_credentials(
    session: &SessionContext,
    stage: &'static str,
    signal_name: &str,
    signing_key_pem: &[u8],
    signing_cert_pem: &[u8],
) -> Result<()> {
    let signing_cert = openssl::x509::X509::from_pem(signing_cert_pem).map_err(|_err| {
        AsxError::new(
            ErrorCode::InvalidInput,
            format!("AS4 {signal_name} signing_cert_pem is not a valid PEM X.509 certificate"),
            ErrorContext::for_session(stage, session),
        )
    })?;

    let signing_key =
        openssl::pkey::PKey::private_key_from_pem(signing_key_pem).map_err(|_err| {
            AsxError::new(
                ErrorCode::InvalidInput,
                format!("AS4 {signal_name} signing_key_pem is not a valid PEM private key"),
                ErrorContext::for_session(stage, session),
            )
        })?;

    let signing_cert_public = signing_cert.public_key().map_err(|_err| {
        AsxError::new(
            ErrorCode::InvalidInput,
            format!("AS4 {signal_name} signing_cert_pem does not contain a usable public key"),
            ErrorContext::for_session(stage, session),
        )
    })?;

    if !signing_key.public_eq(&signing_cert_public) {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!("AS4 {signal_name} signing_cert_pem does not match signing_key_pem"),
            ErrorContext::for_session(stage, session),
        ));
    }
    Ok(())
}

const RECEIPT_MESSAGING_WSU_ID: &str = "as4-receipt-messaging";
const RECEIPT_BODY_WSU_ID: &str = "as4-receipt-body";

/// Generate a **signed** AS4 `eb:Receipt` SignalMessage with Non-Repudiation
/// Information per ebMS3 §5.2.2.1 and eDelivery AS4 §5.1.8.
///
/// The returned SOAP envelope carries a `wsse:Security` header whose XML
/// Signature covers the `eb:Messaging` header (the SignalMessage including
/// the `NonRepudiationInformation` block) and the SOAP Body — providing
/// Non-Repudiation of Receipt (NRR) as required by profiles such as the BDEW
/// AS4-Profil §2.2.4.  The result verifies with
/// [`crate::crypto::wssec::verify_enveloped_signature`] and is accepted by
/// counterparties enforcing `require_signed_receipt = true`.
///
/// Obtain `nri_refs` from the inbound signed message via
/// [`crate::crypto::wssec::parse_signature_references`].
pub fn generate_signed_receipt_with_nri(
    session: &SessionContext,
    message_id: &str,
    ref_to_message_id: &str,
    nri_refs: &[As4NriReference],
    credentials: &As4ReceiptCredentials,
) -> Result<Vec<u8>> {
    let stage = "as4_generate_signed_receipt";
    validate_receipt_signal_ids(session, stage, message_id, ref_to_message_id)?;
    validate_signal_signing_credentials(
        session,
        stage,
        "Receipt",
        &credentials.signing_key_pem,
        &credentials.signing_cert_pem,
    )?;

    let timestamp = crate::time_utils::format_rfc3339_secs(session.clock().now());
    let (doc, slot) = write_signal(
        &SignalEnvelope {
            namespaces: &[
                ("ebbpsig", ns::EBBP_SIGNALS),
                ("wsse", ns::WSSE),
                ("wsu", ns::WSU),
                ("ds", ns::DS),
            ],
            reserve_security: true,
            messaging_id: Some(RECEIPT_MESSAGING_WSU_ID),
            body_id: Some(RECEIPT_BODY_WSU_ID),
            timestamp: &timestamp,
            message_id,
            ref_to_message_id: Some(ref_to_message_id),
        },
        |out| write_receipt(out, nri_refs),
    )?;

    let messaging_ref = format!("#{RECEIPT_MESSAGING_WSU_ID}");
    let body_ref = format!("#{RECEIPT_BODY_WSU_ID}");
    seal_signed_signal(
        doc,
        slot,
        &[messaging_ref.as_str(), body_ref.as_str()],
        &credentials.signing_key_pem,
        &credentials.signing_cert_pem,
        credentials.key_info_profile,
        stage,
        session,
    )
}

/// Sign the signal's envelope (its security slot still empty — it lies
/// outside every signed subtree) and fill the slot with the `wsse:Security`
/// header carrying the signature.
#[allow(clippy::too_many_arguments)]
fn seal_signed_signal(
    mut doc: XmlDoc,
    slot: Option<Slot>,
    reference_uris: &[&str],
    signing_key_pem: &[u8],
    signing_cert_pem: &[u8],
    key_info_profile: crate::crypto::wssec::WsSecOutboundKeyInfoProfile,
    stage: &'static str,
    session: &SessionContext,
) -> Result<Vec<u8>> {
    let slot = slot.ok_or_else(|| {
        AsxError::new(
            ErrorCode::InvalidInput,
            "a signed signal needs a reserved wsse:Security slot",
            ErrorContext::for_session(stage, session),
        )
    })?;
    let envelope = doc.text_with_empty_slots();
    let signature_xml = generate_xmlsig_signature(
        &envelope,
        reference_uris,
        signing_key_pem,
        signing_cert_pem,
        key_info_profile,
    )?;
    let header = WsSecurityHeaderBuilder::new()
        .at(session.clock().now())
        .with_signing_cert(signing_cert_pem.to_vec())
        .with_signature_xml(signature_xml)
        .build_fragment()
        .map_err(|err| {
            AsxError::new(
                err.code,
                format!("failed to build the WS-Security header: {}", err.message),
                ErrorContext::for_session(stage, session),
            )
        })?;
    doc.fill(slot, header)?;
    Ok(doc.into_string()?.into_bytes())
}

/// Generate an AS4 `eb:Error` SignalMessage per ebMS3 §6.7.3.
pub fn generate_error_signal(
    session: &SessionContext,
    message_id: &str,
    ref_to_message_id: &str,
    error_code: As4ErrorCode,
    severity: As4ErrorSeverity,
    description: &str,
) -> Result<Vec<u8>> {
    validate_receipt_signal_ids(
        session,
        "as4_generate_error_signal",
        message_id,
        ref_to_message_id,
    )?;
    if description.trim().is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "description must not be empty",
            ErrorContext::for_session("as4_generate_error_signal", session),
        ));
    }

    let timestamp = crate::time_utils::format_rfc3339_secs(session.clock().now());
    let (doc, _) = write_signal(
        &SignalEnvelope {
            namespaces: &[],
            reserve_security: false,
            messaging_id: None,
            body_id: None,
            timestamp: &timestamp,
            message_id,
            ref_to_message_id: Some(ref_to_message_id),
        },
        |out| {
            out.start("eb:Error")?
                .attr("errorCode", error_code.ebms_code(), "eb:Error/@errorCode")?
                .attr("severity", severity.as_str(), "eb:Error/@severity")?
                .attr("category", "CONTENT", "eb:Error/@category")?
                .attr("origin", "ebMS", "eb:Error/@origin")?;
            out.start("eb:Description")?
                .attr("xml:lang", "en", "xml:lang")?
                .text(description, "eb:Description")?
                .end()?;
            out.end()?;
            Ok(())
        },
    )?;
    Ok(doc.into_string()?.into_bytes())
}

// ── Draft/finish signals ────────────────────────────────────────────────────

/// A signal built up to its signature: sign
/// [`SignalDraft::to_sign`], then [`finish_signal`].
pub(crate) struct SignalDraft {
    doc: XmlDoc,
    slot: Slot,
    prepared: crate::crypto::wssec::sign::PreparedSignature,
    /// The draft's clock reading, reused for the `wsu:Timestamp`.
    now: std::time::SystemTime,
}

impl SignalDraft {
    pub(crate) fn to_sign(&self) -> (crate::crypto::alg::SignatureAlgorithm, &[u8]) {
        (
            self.prepared.algorithm,
            &self.prepared.canonical_signed_info,
        )
    }
}

/// An NRR receipt for `ref_to_message_id`, echoing `nri_refs`, up to its
/// signature.
pub(crate) fn draft_receipt(
    now: std::time::SystemTime,
    message_id: &str,
    ref_to_message_id: &str,
    nri_refs: &[As4NriReference],
    algorithm: crate::crypto::alg::SignatureAlgorithm,
) -> Result<SignalDraft> {
    let timestamp = crate::time_utils::format_rfc3339_secs(now);
    let (doc, slot) = write_signal(
        &SignalEnvelope {
            namespaces: &[
                ("ebbpsig", ns::EBBP_SIGNALS),
                ("wsse", ns::WSSE),
                ("wsu", ns::WSU),
                ("ds", ns::DS),
            ],
            reserve_security: true,
            messaging_id: Some(RECEIPT_MESSAGING_WSU_ID),
            body_id: Some(RECEIPT_BODY_WSU_ID),
            timestamp: &timestamp,
            message_id,
            ref_to_message_id: Some(ref_to_message_id),
        },
        |out| write_receipt(out, nri_refs),
    )?;
    let slot = slot.ok_or_else(|| {
        AsxError::new(
            ErrorCode::InvalidInput,
            "a signed signal needs a reserved wsse:Security slot",
            ErrorContext::new("as4_generate_signed_receipt"),
        )
    })?;
    let messaging_ref = format!("#{RECEIPT_MESSAGING_WSU_ID}");
    let body_ref = format!("#{RECEIPT_BODY_WSU_ID}");
    let prepared = crate::crypto::wssec::sign::prepare_envelope_signature(
        &doc.text_with_empty_slots(),
        &[messaging_ref.as_str(), body_ref.as_str()],
        &[],
        algorithm,
    )?;
    Ok(SignalDraft {
        doc,
        slot,
        prepared,
        now,
    })
}

/// Seal a signal with the key's `raw_signature` (DER for ECDSA) and the
/// signer chain (leaf first, DER) in the profile's token form.
pub(crate) fn finish_signal(
    draft: SignalDraft,
    raw_signature: Vec<u8>,
    chain_der: &[Vec<u8>],
    key_info: crate::crypto::wssec::WsSecOutboundKeyInfoProfile,
) -> Result<Vec<u8>> {
    let SignalDraft {
        mut doc,
        slot,
        prepared,
        now,
    } = draft;
    let header = crate::crypto::soap_builder::security_header(
        prepared,
        raw_signature,
        chain_der,
        key_info,
        now,
        None,
    )?;
    doc.fill(slot, header)?;
    Ok(doc.into_string()?.into_bytes())
}

/// An `eb:Error` signal (ebMS3 §6.7) with a free-form code and an optional
/// `eb:ErrorDetail`. `ref_to_message_id` is absent when the message could not
/// be read.
#[allow(clippy::too_many_arguments)]
pub(crate) fn error_signal(
    now: std::time::SystemTime,
    message_id: &str,
    ref_to_message_id: Option<&str>,
    code: &str,
    short_description: &str,
    category: &str,
    description: &str,
    detail: Option<&str>,
) -> Result<Vec<u8>> {
    let timestamp = crate::time_utils::format_rfc3339_secs(now);
    let (doc, _) = write_signal(
        &SignalEnvelope {
            namespaces: &[],
            reserve_security: false,
            messaging_id: None,
            body_id: None,
            timestamp: &timestamp,
            message_id,
            ref_to_message_id,
        },
        |out| {
            out.start("eb:Error")?
                .attr("errorCode", code, "eb:Error/@errorCode")?
                .attr("severity", "failure", "eb:Error/@severity")?
                .attr(
                    "shortDescription",
                    short_description,
                    "eb:Error/@shortDescription",
                )?
                .attr("category", category, "eb:Error/@category")?
                .attr("origin", "ebMS", "eb:Error/@origin")?;
            if let Some(ref_to) = ref_to_message_id {
                out.attr(
                    "refToMessageInError",
                    ref_to,
                    "eb:Error/@refToMessageInError",
                )?;
            }
            out.start("eb:Description")?
                .attr("xml:lang", "en", "xml:lang")?
                .text(description, "eb:Description")?
                .end()?;
            if let Some(detail) = detail {
                out.leaf("eb:ErrorDetail", detail, "eb:ErrorDetail")?;
            }
            out.end()?;
            Ok(())
        },
    )?;
    Ok(doc.into_string()?.into_bytes())
}
