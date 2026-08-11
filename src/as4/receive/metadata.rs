use super::super::parser::{
    parse_as4_user_message_document, parse_as4_user_message_from_doc,
    precheck_as4_user_message_structure_bytes,
};
use super::super::services::check_duplicate_push_sync;
use super::super::stream::{MultipartAs4Payload, extract_multipart_related_payload_if_present};
use super::super::types::As4PushPolicy;
use super::{As4Verifier, payload};
use crate::core::{Result, SessionContext};
use crate::observability::{AsxIngressStage, EventBus};
use crate::storage::DedupStorage;
use roxmltree::Document;

fn verify_wssec_gate(
    session: &SessionContext,
    xml: &str,
    soap_doc: &Document<'_>,
    policy: &As4PushPolicy,
    message_id: &str,
    external_references: &[(&str, &[u8])],
    verifier: &(dyn As4Verifier + Send + Sync),
) -> Result<payload::WsSecVerifiedGate> {
    verifier.verify_security(
        session,
        policy,
        xml,
        soap_doc,
        message_id,
        external_references,
    )?;
    Ok(payload::WsSecVerifiedGate)
}

/// `cid:` reference material for WS-Security verification: **every** payload
/// attachment, so each one's digest can be checked and each one can be proven
/// signature-covered.
///
/// Each attachment's bytes are pre-transformed per the WSS SwA
/// `Attachment-Content-Signature-Transform`, selected by the MIME part's
/// `Content-Type` — XML-typed parts are digested over their Exclusive C14N
/// form, `text/*` parts over CRLF-normalized octets (what WSS4J-based signers
/// compute).
type SwaExternalReference<'a> = (&'a str, std::borrow::Cow<'a, [u8]>);

fn wssec_external_references<'a>(
    multipart: &'a Option<MultipartAs4Payload<'a>>,
) -> Result<Vec<SwaExternalReference<'a>>> {
    let Some(multipart) = multipart.as_ref() else {
        return Ok(Vec::new());
    };
    multipart
        .external_references()
        .into_iter()
        .map(|(cid, content_type, bytes)| {
            crate::crypto::wssec::swa_attachment_digest_input(content_type, bytes)
                .map(|input| (cid, input))
        })
        .collect()
}

#[allow(clippy::type_complexity)]
pub(super) fn parse_verify_and_emit_receive_push_metadata<'a>(
    session: &SessionContext,
    event_bus: &EventBus,
    payload_bytes: &'a [u8],
    http_content_type: &str,
    policy: &As4PushPolicy,
    dedup_backend: &dyn DedupStorage,
    verifier: &(dyn As4Verifier + Send + Sync),
) -> Result<(
    Option<MultipartAs4Payload<'a>>,
    &'a [u8],
    super::super::ParsedAs4UserMessage,
    payload::WsSecVerifiedGate,
    bool, // is_duplicate
)> {
    let multipart = extract_multipart_related_payload_if_present(
        payload_bytes,
        http_content_type,
        session,
        "as4_receive_push",
    )?;
    let soap_bytes = multipart
        .as_ref()
        .map(|m| m.soap_xml)
        .unwrap_or(payload_bytes);

    precheck_as4_user_message_structure_bytes(soap_bytes, session, "as4_receive_push")?;

    let xml = crate::core::bytes_to_utf8_str(soap_bytes, "as4_receive_push", session)?;
    let doc = parse_as4_user_message_document(xml, session)?;
    let wssec_external_references = wssec_external_references(&multipart)?;
    let wssec_external_references: Vec<(&str, &[u8])> = wssec_external_references
        .iter()
        .map(|(cid, input)| (*cid, input.as_ref()))
        .collect();

    let parsed = parse_as4_user_message_from_doc(
        session,
        event_bus,
        &doc,
        policy.interop,
        policy.fail_closed_audit_events,
    )?;
    let gate = verify_wssec_gate(
        session,
        xml,
        &doc,
        policy,
        &parsed.message_id,
        &wssec_external_references,
        verifier,
    )?;

    let is_duplicate = check_duplicate_push_sync(
        session,
        event_bus,
        dedup_backend,
        &parsed.message_id,
        AsxIngressStage::As4ReceivePush,
        policy.fail_closed_audit_events,
    )?;

    Ok((multipart, soap_bytes, parsed, gate, is_duplicate))
}
