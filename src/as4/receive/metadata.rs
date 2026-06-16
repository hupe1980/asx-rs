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
    external_reference: Option<(&str, &[u8])>,
    verifier: &(dyn As4Verifier + Send + Sync),
) -> Result<payload::WsSecVerifiedGate> {
    verifier.verify_security(
        session,
        policy,
        xml,
        soap_doc,
        message_id,
        external_reference,
    )?;
    Ok(payload::WsSecVerifiedGate)
}

fn wssec_external_reference<'a>(
    multipart: &'a Option<MultipartAs4Payload<'a>>,
) -> Option<(&'a str, &'a [u8])> {
    let multipart = multipart.as_ref()?;
    let payload = multipart.payload_attachment?;
    let cid = multipart.payload_content_id?;
    Some((cid, payload))
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
    let wssec_external_reference = wssec_external_reference(&multipart);

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
        wssec_external_reference
            .as_ref()
            .map(|(uri, payload)| (*uri, *payload)),
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
