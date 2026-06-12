use super::{ParsedAs4Receipt, ParsedAs4UserMessage};
use crate::as4::types::ParsedWsAddressingHeaders;
use crate::core::InteropMode;
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
use crate::observability::{AsxEvent, EventBus, emit_audit_event};
use memchr::{memchr, memmem, memrchr};
#[cfg(test)]
use quick_xml::Reader;
use quick_xml::events::Event as XmlEvent;
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;
use roxmltree::{Document, Node};

const EBMS3_CORE_NS: &str = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/";
const EBBP_SIGNALS_NS: &str = "http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0";
const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const SOAP12_NS: &str = "http://www.w3.org/2003/05/soap-envelope";
const SOAP12_ROLE_ULTIMATE_RECEIVER: &str =
    "http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver";
const WSSE_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

/// Limit on total number of XML elements in parsed AS4 document.
/// Prevents XML bomb DoS attacks (deeply nested or broadly repeated elements).
/// Legitimate AS4 messages typically have <100 elements; this limit is conservative.
const MAX_XML_ELEMENTS: usize = 10_000;
const MAX_AS4_PRECHECK_HEADER_SPAN_BYTES: usize = 256 * 1024;

#[derive(Default)]
struct As4UserMessageParseState {
    has_messaging: bool,
    has_user_message: bool,
    has_security: bool,
    messaging_must_understand_true: bool,
    message_id: Option<String>,
    ref_to_message_id: Option<String>,
    action: Option<String>,
    original_sender: Option<String>,
    final_recipient: Option<String>,
    tracking_identifier: Option<String>,
    service: Option<String>,
    conversation_id: Option<String>,
    timestamp: Option<String>,
    from_party_ids: Vec<String>,
    to_party_ids: Vec<String>,
    mpc: Option<String>,
    // WS-Addressing headers (optional; populated when present)
    wsa_message_id: Option<String>,
    wsa_action: Option<String>,
    wsa_to: Option<String>,
    wsa_reply_to: Option<String>,
}

/// Fast structural precheck over raw bytes before UTF-8 + XML DOM parsing.
///
/// This is a best-effort fail-fast guard for malformed ingress payloads; it
/// only checks for required SOAP/ebMS element markers and does not replace full
/// XML parsing or policy validation.
pub(super) fn precheck_as4_user_message_structure_bytes(
    raw_xml: &[u8],
    session: &SessionContext,
    stage: &'static str,
) -> Result<()> {
    ensure_required_marker_present(
        raw_xml,
        b"Envelope",
        "AS4 payload missing SOAP Envelope marker",
        session,
        stage,
    )?;
    ensure_required_marker_present(
        raw_xml,
        b"Header",
        "AS4 payload missing SOAP Header marker",
        session,
        stage,
    )?;
    ensure_required_marker_present(
        raw_xml,
        b"Body",
        "AS4 payload missing SOAP Body marker",
        session,
        stage,
    )?;

    // Fail closed: ebMS markers for UserMessage path must be in SOAP Header.
    let body_tag_pos = first_opening_tag_pos_by_local_name(raw_xml, b"Body").ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 payload missing SOAP Body marker",
            ErrorContext::for_session(stage, session),
        )
    })?;
    let header_window = &raw_xml[..body_tag_pos];
    ensure_required_marker_present(
        header_window,
        b"Messaging",
        "AS4 SOAP Header missing eb:Messaging marker",
        session,
        stage,
    )?;
    ensure_required_marker_present(
        header_window,
        b"UserMessage",
        "AS4 SOAP Header missing eb:UserMessage marker",
        session,
        stage,
    )?;

    if header_span_exceeds_limit(raw_xml, MAX_AS4_PRECHECK_HEADER_SPAN_BYTES) {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 payload header region exceeds precheck safety limit",
            ErrorContext::for_session(stage, session),
        ));
    }

    Ok(())
}

/// Fast structural precheck over raw receipt bytes before UTF-8 + XML parse.
///
/// This catches obviously malformed/non-AS4 receipt payloads early while
/// keeping full semantic validation in the XML parser path.
pub(super) fn precheck_as4_receipt_structure_bytes(
    raw_xml: &[u8],
    session: &SessionContext,
    stage: &'static str,
) -> Result<()> {
    ensure_required_marker_present(
        raw_xml,
        b"Envelope",
        "AS4 receipt payload missing SOAP Envelope marker",
        session,
        stage,
    )?;
    ensure_required_marker_present(
        raw_xml,
        b"SignalMessage",
        "AS4 receipt payload missing eb:SignalMessage marker",
        session,
        stage,
    )?;
    ensure_required_marker_present(
        raw_xml,
        b"Receipt",
        "AS4 receipt payload missing eb:Receipt marker",
        session,
        stage,
    )?;
    ensure_required_marker_present(
        raw_xml,
        b"RefToMessageId",
        "AS4 receipt payload missing eb:RefToMessageId marker",
        session,
        stage,
    )?;

    Ok(())
}

fn ensure_required_marker_present(
    raw: &[u8],
    marker_local_name: &[u8],
    error_message: &'static str,
    session: &SessionContext,
    stage: &'static str,
) -> Result<()> {
    if first_opening_tag_pos_by_local_name(raw, marker_local_name).is_none() {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            error_message,
            ErrorContext::for_session(stage, session),
        ));
    }

    Ok(())
}

/// Match a small marker set in one linear pass across input bytes.
///
/// This avoids multiple full-buffer scans when validating required structural
/// tokens in fail-fast prechecks.
#[cfg(test)]
fn has_all_markers_single_pass(raw: &[u8], markers: &[&[u8]]) -> bool {
    if markers.iter().any(|marker| marker.is_empty()) {
        return false;
    }
    if markers.is_empty() {
        return true;
    }

    let mut seen = vec![false; markers.len()];
    let mut remaining = markers.len();

    let mut pos = 0;
    while let Some((_, local_name, next_pos)) = next_opening_tag_local_name(raw, pos) {
        if remaining == 0 {
            break;
        }

        for (idx, marker) in markers.iter().enumerate() {
            if seen[idx] {
                continue;
            }
            if local_name == *marker {
                seen[idx] = true;
                remaining -= 1;
                break;
            }
        }

        pos = next_pos;
    }

    remaining == 0
}

fn next_opening_tag_local_name(raw: &[u8], mut pos: usize) -> Option<(usize, &[u8], usize)> {
    while pos < raw.len() {
        if raw[pos] != b'<' {
            pos += 1;
            continue;
        }

        let next = raw.get(pos + 1)?;

        // Ignore closing tags and skip XML declarations/comments/CDATA/doctype.
        if *next == b'/' {
            pos += 2;
            continue;
        }
        if *next == b'!' {
            let after_lt = &raw[pos + 1..];

            // Comment: <!-- ... -->
            if after_lt.starts_with(b"!--") {
                if let Some(end_rel) = memmem::find(after_lt, b"-->") {
                    pos = pos + 1 + end_rel + 3;
                } else {
                    return None;
                }
                continue;
            }

            // CDATA: <![CDATA[ ... ]]>
            if after_lt.starts_with(b"![CDATA[") {
                if let Some(end_rel) = memmem::find(after_lt, b"]]>") {
                    pos = pos + 1 + end_rel + 3;
                } else {
                    return None;
                }
                continue;
            }

            // Doctype/declaration subset: skip to the next '>' as fail-fast precheck behavior.
            if let Some(end_rel) = memchr(b'>', after_lt) {
                pos = pos + 1 + end_rel + 1;
            } else {
                return None;
            }
            continue;
        }
        if *next == b'?' {
            let after_lt = &raw[pos + 1..];
            if let Some(end_rel) = memmem::find(after_lt, b"?>") {
                pos = pos + 1 + end_rel + 2;
            } else {
                return None;
            }
            continue;
        }

        let name_start = pos + 1;
        let mut name_end = name_start;
        while name_end < raw.len() {
            let b = raw[name_end];
            if b == b'>' || b == b'/' || b.is_ascii_whitespace() {
                break;
            }
            name_end += 1;
        }

        if name_end == name_start {
            pos += 1;
            continue;
        }

        let qname = &raw[name_start..name_end];
        let local_name = if let Some(colon) = memrchr(b':', qname) {
            &qname[colon + 1..]
        } else {
            qname
        };
        return Some((pos, local_name, name_end));
    }

    None
}

/// Heuristic header-size guard for fail-fast ingress prechecks.
///
/// Searches for the first `Header` marker and the first subsequent `Body`
/// marker; rejects when the byte distance exceeds `max_header_span`.
fn header_span_exceeds_limit(raw: &[u8], max_header_span: usize) -> bool {
    let mut cursor = 0;
    let mut header_name_end = None;

    while let Some((tag_pos, local_name, next_pos)) = next_opening_tag_local_name(raw, cursor) {
        if let Some(header_end) = header_name_end {
            if local_name == b"Body" {
                return tag_pos.saturating_sub(header_end) > max_header_span;
            }
        } else if local_name == b"Header" {
            header_name_end = Some(next_pos);
        }

        cursor = next_pos;
    }

    false
}

pub(super) fn parse_as4_user_message_document<'a>(
    xml: &'a str,
    session: &SessionContext,
) -> Result<Document<'a>> {
    let doc = roxmltree::Document::parse(xml).map_err(|e| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("failed to parse AS4 SOAP envelope: {e}"),
            ErrorContext::for_session("as4_parse_user_message", session),
        )
    })?;

    let element_count = doc.descendants().filter(|n| n.is_element()).count();
    if element_count > MAX_XML_ELEMENTS {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            format!(
                "AS4 XML document exceeds element limit ({} > {})",
                element_count, MAX_XML_ELEMENTS
            ),
            ErrorContext::for_session("as4_parse_user_message", session),
        ));
    }

    Ok(doc)
}

/// Build a [`ParsedWsAddressingHeaders`] from the parse state.
///
/// Returns `None` when no WS-Addressing elements were present in the SOAP Header.
fn build_parsed_wsa_headers(state: &As4UserMessageParseState) -> Option<ParsedWsAddressingHeaders> {
    if state.wsa_message_id.is_none()
        && state.wsa_action.is_none()
        && state.wsa_to.is_none()
        && state.wsa_reply_to.is_none()
    {
        return None;
    }
    Some(ParsedWsAddressingHeaders {
        message_id: state.wsa_message_id.clone(),
        action: state.wsa_action.clone(),
        to: state.wsa_to.clone(),
        reply_to: state.wsa_reply_to.clone(),
    })
}

pub(super) fn parse_as4_user_message_from_doc(
    session: &SessionContext,
    event_bus: &EventBus,
    doc: &Document<'_>,
    interop: InteropMode,
    fail_closed_audit_events: bool,
) -> Result<ParsedAs4UserMessage> {
    let state =
        parse_as4_user_message_summary_dom_from_doc(doc, session, interop == InteropMode::Strict)?;

    if !state.has_messaging {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 SOAP Header missing eb:Messaging",
            ErrorContext::for_session("as4_parse_user_message", session),
        ));
    }

    if !state.has_user_message {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 eb:Messaging missing UserMessage",
            ErrorContext::for_session("as4_parse_user_message", session),
        ));
    }

    if interop == InteropMode::Strict && !state.messaging_must_understand_true {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            "AS4 eb:Messaging must set SOAP mustUnderstand=true",
            ErrorContext::for_session("as4_parse_user_message", session),
        ));
    }

    if !state.has_security {
        if interop == InteropMode::Strict {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                "AS4 SOAP Header missing wsse:Security",
                ErrorContext::for_session("as4_parse_user_message", session),
            ));
        }

        emit_audit_event(
            event_bus,
            session,
            AsxEvent::InteropGuardrailEvaluated {
                message_id: state
                    .message_id
                    .as_deref()
                    .unwrap_or("unknown")
                    .to_string()
                    .into(),
                code: "as4_missing_wsse_security_header",
                outcome: "SecurityBlocked",
                detail: "missing_wsse_security_header",
            },
            fail_closed_audit_events,
            "as4_parse_user_message",
        )?;
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "security-blocked interop exception as4_missing_wsse_security_header; runtime override is forbidden",
            ErrorContext::for_session("as4_parse_user_message", session),
        ));
    }

    // Extract WS-Addressing fields BEFORE any partial moves on `state`.
    let wsa_headers = build_parsed_wsa_headers(&state);

    let message_id = state.message_id.ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 UserMessage missing MessageId",
            ErrorContext::for_session("as4_parse_user_message", session),
        )
    })?;
    let action = state.action.ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 UserMessage missing Action",
            ErrorContext::for_session_with_message(
                "as4_parse_user_message",
                session,
                message_id.clone(),
            ),
        )
    })?;
    if state.from_party_ids.is_empty() {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 UserMessage missing From/PartyId",
            ErrorContext::for_session_with_message(
                "as4_parse_user_message",
                session,
                message_id.clone(),
            ),
        ));
    }
    if state.to_party_ids.is_empty() {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 UserMessage missing To/PartyId",
            ErrorContext::for_session_with_message(
                "as4_parse_user_message",
                session,
                message_id.clone(),
            ),
        ));
    }

    if interop == InteropMode::Strict
        && let Some(mpc_value) = state.mpc.as_deref()
        && !is_valid_mpc_uri(mpc_value)
    {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            "AS4 UserMessage mpc must be a valid URI",
            ErrorContext::for_session_with_message(
                "as4_parse_user_message",
                session,
                message_id.clone(),
            ),
        ));
    }

    if interop == InteropMode::Strict {
        if state.original_sender.is_none() {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                "AS4 UserMessage missing Property originalSender",
                ErrorContext::for_session_with_message(
                    "as4_parse_user_message",
                    session,
                    message_id.clone(),
                ),
            ));
        }
        if state.final_recipient.is_none() {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                "AS4 UserMessage missing Property finalRecipient",
                ErrorContext::for_session_with_message(
                    "as4_parse_user_message",
                    session,
                    message_id.clone(),
                ),
            ));
        }
        if state.tracking_identifier.is_none() {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                "AS4 UserMessage missing Property trackingIdentifier",
                ErrorContext::for_session_with_message(
                    "as4_parse_user_message",
                    session,
                    message_id.clone(),
                ),
            ));
        }
    }

    Ok(ParsedAs4UserMessage {
        message_id,
        action,
        from_party_ids: state.from_party_ids,
        to_party_ids: state.to_party_ids,
        mpc: state.mpc,
        conversation_id: state.conversation_id,
        has_ws_security_header: state.has_security,
        service: state.service,
        ref_to_message_id: state.ref_to_message_id,
        original_sender: state.original_sender,
        final_recipient: state.final_recipient,
        tracking_identifier: state.tracking_identifier,
        timestamp: state.timestamp,
        wsa_headers,
    })
}

fn parse_as4_user_message_summary_dom_from_doc(
    doc: &Document<'_>,
    session: &SessionContext,
    strict_interop: bool,
) -> Result<As4UserMessageParseState> {
    let mut state = As4UserMessageParseState::default();

    let root = doc.root_element();
    if root.tag_name().name() != "Envelope" {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 payload root element must be SOAP Envelope",
            ErrorContext::for_session("as4_parse_user_message", session),
        ));
    }

    let Some(root_ns) = root.tag_name().namespace() else {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 SOAP Envelope must declare namespace",
            ErrorContext::for_session("as4_parse_user_message", session),
        ));
    };

    if root_ns != SOAP12_NS {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            "AS4 policy requires SOAP 1.2 envelope namespace",
            ErrorContext::for_session("as4_parse_user_message", session),
        ));
    }

    let soap_ns = root_ns;

    let header = root.children().find(|n| {
        n.is_element()
            && n.tag_name().namespace() == Some(soap_ns)
            && n.tag_name().name() == "Header"
    });

    let body = root.children().find(|n| {
        n.is_element() && n.tag_name().namespace() == Some(soap_ns) && n.tag_name().name() == "Body"
    });

    let header = header.ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 SOAP Envelope missing Header",
            ErrorContext::for_session("as4_parse_user_message", session),
        )
    })?;

    if body.is_none() {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 SOAP Envelope missing Body",
            ErrorContext::for_session("as4_parse_user_message", session),
        ));
    }

    let mut messaging_node = None;

    for child in header.children().filter(|n| n.is_element()) {
        let targeting = parse_soap_header_targeting_dom(child, soap_ns);

        if child.tag_name().namespace() == Some(EBMS3_CORE_NS)
            && child.tag_name().name() == "Messaging"
        {
            if strict_interop && state.has_messaging {
                return Err(AsxError::new(
                    ErrorCode::InteropViolation,
                    "AS4 SOAP Header contains duplicate eb:Messaging blocks",
                    ErrorContext::for_session("as4_parse_user_message", session),
                ));
            }

            if strict_interop && targeting.invalid_must_understand {
                return Err(AsxError::new(
                    ErrorCode::InteropViolation,
                    "AS4 eb:Messaging has invalid SOAP mustUnderstand token",
                    ErrorContext::for_session("as4_parse_user_message", session),
                ));
            }

            if strict_interop && !header_is_targeted_to_receiver_dom(&targeting) {
                return Err(AsxError::new(
                    ErrorCode::InteropViolation,
                    "AS4 eb:Messaging SOAP targeting must resolve to receiver role",
                    ErrorContext::for_session("as4_parse_user_message", session),
                ));
            }

            state.has_messaging = true;
            if targeting.must_understand_true {
                state.messaging_must_understand_true = true;
            }
            if messaging_node.is_none() {
                messaging_node = Some(child);
            }
            continue;
        }

        if child.tag_name().namespace() == Some(WSSE_NS) && child.tag_name().name() == "Security" {
            if strict_interop && targeting.invalid_must_understand {
                return Err(AsxError::new(
                    ErrorCode::InteropViolation,
                    "AS4 SOAP Header block has invalid SOAP mustUnderstand token",
                    ErrorContext::for_session("as4_parse_user_message", session),
                ));
            }

            let security_targeted_to_receiver = header_is_targeted_to_receiver_dom(&targeting);
            if strict_interop && security_targeted_to_receiver && state.has_security {
                return Err(AsxError::new(
                    ErrorCode::InteropViolation,
                    "AS4 SOAP Header contains duplicate receiver-targeted wsse:Security blocks",
                    ErrorContext::for_session("as4_parse_user_message", session),
                ));
            }

            if security_targeted_to_receiver {
                state.has_security = true;
            }
            continue;
        }

        // WS-Addressing 1.0 header elements — extract and record.
        // `wsa:Action` commonly carries `mustUnderstand="true"`; process it
        // before the unknown-mandatory-block check to avoid false rejections.
        const WSA_NS: &str = "http://www.w3.org/2005/08/addressing";
        if child.tag_name().namespace() == Some(WSA_NS) {
            match child.tag_name().name() {
                "MessageID" => {
                    if let Some(v) = child.text() {
                        let v = v.trim();
                        if !v.is_empty() {
                            state.wsa_message_id = Some(v.to_string());
                        }
                    }
                }
                "Action" => {
                    if let Some(v) = child.text() {
                        let v = v.trim();
                        if !v.is_empty() {
                            state.wsa_action = Some(v.to_string());
                        }
                    }
                }
                "To" => {
                    if let Some(v) = child.text() {
                        let v = v.trim();
                        if !v.is_empty() {
                            state.wsa_to = Some(v.to_string());
                        }
                    }
                }
                "ReplyTo" => {
                    // `wsa:ReplyTo` contains `wsa:Address` child.
                    if let Some(addr) = child.descendants().find(|n| {
                        n.is_element()
                            && n.tag_name().namespace() == Some(WSA_NS)
                            && n.tag_name().name() == "Address"
                    }) && let Some(v) = addr.text()
                    {
                        let v = v.trim();
                        if !v.is_empty() {
                            state.wsa_reply_to = Some(v.to_string());
                        }
                    }
                }
                _ => {}
            }
            // WS-Addressing elements are understood — do NOT fall through to
            // the unknown-mandatory-block rejection below.
            continue;
        }

        if strict_interop
            && targeting.must_understand_true
            && header_is_targeted_to_receiver_dom(&targeting)
        {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "AS4 SOAP Header contains unknown mandatory receiver-targeted block",
                ErrorContext::for_session("as4_parse_user_message", session),
            ));
        }

        if strict_interop && targeting.invalid_must_understand {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "AS4 SOAP Header block has invalid SOAP mustUnderstand token",
                ErrorContext::for_session("as4_parse_user_message", session),
            ));
        }
    }

    if let Some(messaging) = messaging_node
        && let Some(user_message) = messaging.descendants().find(|n| {
            n.is_element()
                && n.tag_name().namespace() == Some(EBMS3_CORE_NS)
                && n.tag_name().name() == "UserMessage"
        })
    {
        state.has_user_message = true;

        if let Some(mpc) = user_message.attribute("mpc") {
            let mpc = mpc.trim();
            if !mpc.is_empty() {
                state.mpc = Some(mpc.to_string());
            }
        }

        let message_ids = descendant_texts(&user_message, EBMS3_CORE_NS, "MessageId");
        if strict_interop && message_ids.len() > 1 {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "AS4 UserMessage contains duplicate MessageId",
                ErrorContext::for_session("as4_parse_user_message", session),
            ));
        }
        state.message_id = message_ids.into_iter().next();

        state.ref_to_message_id = descendant_text(&user_message, EBMS3_CORE_NS, "RefToMessageId");

        let actions = descendant_texts(&user_message, EBMS3_CORE_NS, "Action");
        if strict_interop && actions.len() > 1 {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "AS4 UserMessage contains duplicate Action",
                ErrorContext::for_session("as4_parse_user_message", session),
            ));
        }
        state.action = actions.into_iter().next();

        state.service = descendant_text(&user_message, EBMS3_CORE_NS, "Service");
        state.conversation_id = descendant_text(&user_message, EBMS3_CORE_NS, "ConversationId");
        state.timestamp = descendant_text(&user_message, EBMS3_CORE_NS, "Timestamp");

        let original_senders = message_property_values(&user_message, "originalSender");
        if strict_interop && original_senders.len() > 1 {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "AS4 UserMessage contains duplicate Property originalSender",
                ErrorContext::for_session("as4_parse_user_message", session),
            ));
        }
        state.original_sender = original_senders.into_iter().next();

        let final_recipients = message_property_values(&user_message, "finalRecipient");
        if strict_interop && final_recipients.len() > 1 {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "AS4 UserMessage contains duplicate Property finalRecipient",
                ErrorContext::for_session("as4_parse_user_message", session),
            ));
        }
        state.final_recipient = final_recipients.into_iter().next();

        let tracking_identifiers = message_property_values(&user_message, "trackingIdentifier");
        if strict_interop && tracking_identifiers.len() > 1 {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "AS4 UserMessage contains duplicate Property trackingIdentifier",
                ErrorContext::for_session("as4_parse_user_message", session),
            ));
        }
        state.tracking_identifier = tracking_identifiers.into_iter().next();

        state.from_party_ids = party_ids_for(&user_message, "From");
        state.to_party_ids = party_ids_for(&user_message, "To");
    }

    Ok(state)
}

fn parse_soap_header_targeting_dom(node: Node<'_, '_>, soap_ns: &str) -> SoapHeaderTargetingDom {
    let mut targeting = SoapHeaderTargetingDom::default();

    for attr in node.attributes() {
        if attr.namespace() != Some(soap_ns) {
            continue;
        }

        let normalized = attr.value().trim();
        match attr.name() {
            "mustUnderstand" => {
                let value = normalized.to_ascii_lowercase();
                if value == "true" || value == "1" {
                    targeting.must_understand_true = true;
                } else if value != "false" && value != "0" {
                    targeting.invalid_must_understand = true;
                }
            }
            "role" if soap_ns == SOAP12_NS => {
                targeting.role = Some(normalized.to_string());
            }
            _ => {}
        }
    }

    targeting
}

fn header_is_targeted_to_receiver_dom(targeting: &SoapHeaderTargetingDom) -> bool {
    if let Some(role_value) = targeting.role.as_deref() {
        let normalized = role_value.trim();
        return normalized.is_empty() || normalized == SOAP12_ROLE_ULTIMATE_RECEIVER;
    }

    true
}

#[derive(Default)]
struct SoapHeaderTargetingDom {
    must_understand_true: bool,
    invalid_must_understand: bool,
    role: Option<String>,
}

fn descendant_text(node: &Node<'_, '_>, ns: &str, local_name: &str) -> Option<String> {
    descendant_texts(node, ns, local_name).into_iter().next()
}

fn descendant_texts(node: &Node<'_, '_>, ns: &str, local_name: &str) -> Vec<String> {
    node.descendants()
        .filter(|n| {
            n.is_element()
                && n.tag_name().namespace() == Some(ns)
                && n.tag_name().name() == local_name
        })
        .filter_map(|n| n.text())
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn party_ids_for(user_message: &Node<'_, '_>, direction: &str) -> Vec<String> {
    user_message
        .descendants()
        .filter(|n| {
            n.is_element()
                && n.tag_name().namespace() == Some(EBMS3_CORE_NS)
                && n.tag_name().name() == "PartyId"
                && n.ancestors().any(|a| {
                    a.is_element()
                        && a.tag_name().namespace() == Some(EBMS3_CORE_NS)
                        && a.tag_name().name() == direction
                })
        })
        .filter_map(|n| n.text())
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn message_property_values(user_message: &Node<'_, '_>, property_name: &str) -> Vec<String> {
    user_message
        .descendants()
        .filter(|n| {
            n.is_element()
                && n.tag_name().namespace() == Some(EBMS3_CORE_NS)
                && n.tag_name().name() == "Property"
                && n.attribute("name") == Some(property_name)
                && n.ancestors().any(|a| {
                    a.is_element()
                        && a.tag_name().namespace() == Some(EBMS3_CORE_NS)
                        && a.tag_name().name() == "MessageProperties"
                })
        })
        .filter_map(property_value_from_node)
        .collect()
}

fn property_value_from_node(node: Node<'_, '_>) -> Option<String> {
    if let Some(value_attr) = node.attribute("value") {
        let value = value_attr.trim();
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }

    node.text()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn parse_as4_receipt(
    session: &SessionContext,
    event_bus: &EventBus,
    xml: &str,
    interop: InteropMode,
    fail_closed_audit_events: bool,
) -> Result<ParsedAs4Receipt> {
    if xml.is_empty() {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "as4 receipt payload is empty",
            ErrorContext::for_session("as4_parse_receipt", session),
        ));
    }

    let parsed = parse_as4_receipt_signal_summary_streaming(xml, session)?;
    if !parsed.has_signal_message {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 signal payload missing eb:SignalMessage",
            ErrorContext::for_session("as4_parse_receipt", session),
        ));
    }

    if !parsed.has_receipt {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 eb:SignalMessage missing eb:Receipt",
            ErrorContext::for_session("as4_parse_receipt", session),
        ));
    }

    if !parsed.has_non_repudiation_info {
        if interop == InteropMode::Strict {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "AS4 receipt missing NonRepudiationInformation",
                ErrorContext::for_session("as4_parse_receipt", session),
            ));
        }

        emit_audit_event(
            event_bus,
            session,
            AsxEvent::InteropGuardrailEvaluated {
                message_id: parsed
                    .ref_to_message_id
                    .as_deref()
                    .unwrap_or("unknown")
                    .to_string()
                    .into(),
                code: "as4_missing_non_repudiation_info",
                outcome: "SecurityBlocked",
                detail: "missing_non_repudiation_information",
            },
            fail_closed_audit_events,
            "as4_parse_receipt",
        )?;

        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "security-blocked interop exception as4_missing_non_repudiation_info; runtime override is forbidden",
            ErrorContext::for_session("as4_parse_receipt", session),
        ));
    }

    let ref_to_message_id = parsed.ref_to_message_id.ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 receipt missing RefToMessageId",
            ErrorContext::for_session("as4_parse_receipt", session),
        )
    })?;

    Ok(ParsedAs4Receipt {
        ref_to_message_id,
        is_signed: parsed.has_signature,
        has_non_repudiation_info: parsed.has_non_repudiation_info,
    })
}

#[derive(Debug, Default)]
struct ParsedAs4ReceiptSignalSummary {
    has_signal_message: bool,
    has_receipt: bool,
    has_non_repudiation_info: bool,
    has_signature: bool,
    ref_to_message_id: Option<String>,
}

fn parse_as4_receipt_signal_summary_streaming(
    xml: &str,
    session: &SessionContext,
) -> Result<ParsedAs4ReceiptSignalSummary> {
    let mut reader = NsReader::from_reader(xml.as_bytes());
    reader.config_mut().trim_text(true);

    let mut summary = ParsedAs4ReceiptSignalSummary::default();
    let mut element_count = 0usize;
    let mut depth = 0usize;
    let mut signal_message_depth: Option<usize> = None;
    let mut ref_to_message_id_depth: Option<usize> = None;

    loop {
        let (ns, event) = reader.read_resolved_event().map_err(|e| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("failed to parse AS4 receipt signal: {e}"),
                ErrorContext::for_session("as4_parse_receipt", session),
            )
        })?;

        match event {
            XmlEvent::Start(element) => {
                depth += 1;
                element_count += 1;
                if element_count > MAX_XML_ELEMENTS {
                    return Err(AsxError::new(
                        ErrorCode::ParseFailed,
                        format!(
                            "AS4 XML document exceeds element limit ({} > {})",
                            element_count, MAX_XML_ELEMENTS
                        ),
                        ErrorContext::for_session("as4_parse_receipt", session),
                    ));
                }

                let local_name = element.local_name();
                let local_name = local_name.as_ref();

                if ns_matches(&ns, EBMS3_CORE_NS) && local_name == b"SignalMessage" {
                    summary.has_signal_message = true;
                    signal_message_depth = Some(depth);
                }

                if signal_message_depth.is_some() && ns_matches(&ns, EBMS3_CORE_NS) {
                    if local_name == b"Receipt" {
                        summary.has_receipt = true;
                    } else if local_name == b"RefToMessageId" && summary.ref_to_message_id.is_none()
                    {
                        ref_to_message_id_depth = Some(depth);
                    }
                }

                if ns_matches(&ns, XMLDSIG_NS) && local_name == b"Signature" {
                    summary.has_signature = true;
                }

                if (ns_matches(&ns, EBMS3_CORE_NS) || ns_matches(&ns, EBBP_SIGNALS_NS))
                    && local_name == b"NonRepudiationInformation"
                {
                    summary.has_non_repudiation_info = true;
                }
            }
            XmlEvent::Empty(element) => {
                element_count += 1;
                if element_count > MAX_XML_ELEMENTS {
                    return Err(AsxError::new(
                        ErrorCode::ParseFailed,
                        format!(
                            "AS4 XML document exceeds element limit ({} > {})",
                            element_count, MAX_XML_ELEMENTS
                        ),
                        ErrorContext::for_session("as4_parse_receipt", session),
                    ));
                }

                let local_name = element.local_name();
                let local_name = local_name.as_ref();

                if signal_message_depth.is_some()
                    && ns_matches(&ns, EBMS3_CORE_NS)
                    && local_name == b"Receipt"
                {
                    summary.has_receipt = true;
                }

                if ns_matches(&ns, EBMS3_CORE_NS) && local_name == b"SignalMessage" {
                    summary.has_signal_message = true;
                }

                if ns_matches(&ns, XMLDSIG_NS) && local_name == b"Signature" {
                    summary.has_signature = true;
                }

                if (ns_matches(&ns, EBMS3_CORE_NS) || ns_matches(&ns, EBBP_SIGNALS_NS))
                    && local_name == b"NonRepudiationInformation"
                {
                    summary.has_non_repudiation_info = true;
                }
            }
            XmlEvent::Text(text) => {
                if ref_to_message_id_depth.is_some()
                    && summary.ref_to_message_id.is_none()
                    && let Some(value) = decode_text_event(text.as_ref(), session)?
                {
                    summary.ref_to_message_id = Some(value);
                }
            }
            XmlEvent::CData(text) => {
                if ref_to_message_id_depth.is_some()
                    && summary.ref_to_message_id.is_none()
                    && let Some(value) = decode_text_event(text.as_ref(), session)?
                {
                    summary.ref_to_message_id = Some(value);
                }
            }
            XmlEvent::End(_) => {
                if signal_message_depth == Some(depth) {
                    signal_message_depth = None;
                }
                if ref_to_message_id_depth == Some(depth) {
                    ref_to_message_id_depth = None;
                }
                depth = depth.saturating_sub(1);
            }
            XmlEvent::Eof => break,
            _ => {}
        }
    }

    Ok(summary)
}

#[inline]
fn ns_matches(ns: &ResolveResult<'_>, expected: &str) -> bool {
    matches!(ns, ResolveResult::Bound(namespace) if namespace.as_ref() == expected.as_bytes())
}

fn decode_text_event(bytes: &[u8], session: &SessionContext) -> Result<Option<String>> {
    decode_text_event_with_stage(bytes, session, "as4_parse_receipt")
}

fn decode_text_event_with_stage(
    bytes: &[u8],
    session: &SessionContext,
    stage: &'static str,
) -> Result<Option<String>> {
    let decoded = std::str::from_utf8(bytes).map_err(|e| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("failed to parse AS4 XML text: {e}"),
            ErrorContext::for_session(stage, session),
        )
    })?;
    let unescaped = quick_xml::escape::unescape(decoded).map_err(|e| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("failed to parse AS4 XML text: {e}"),
            ErrorContext::for_session(stage, session),
        )
    })?;
    let trimmed = unescaped.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

fn is_valid_mpc_uri(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed
        .chars()
        .any(|c| c.is_ascii_control() || c.is_whitespace())
    {
        return false;
    }
    let Some(colon_idx) = trimmed.find(':') else {
        return false;
    };
    colon_idx > 0 && colon_idx < trimmed.len() - 1
}

/// Extract `<eb:ConversationId>` from an AS4 SOAP envelope payload for use as a
/// per-conversation gate key.
///
/// Extract the `eb:ConversationId` text from a raw SOAP envelope byte slice
/// without full parsing.
///
/// Uses a bounded byte-scan over the SOAP header region (no XML DOM parsing,
/// no full-envelope allocation). Returns `None` on any parse/structural
/// failure; ordered receive then rejects ingress without an explicit
/// `ConversationId` gate key.
#[cfg(test)]
pub(super) fn extract_conversation_id_for_gate(payload: &[u8]) -> Option<String> {
    extract_conversation_id_for_gate_fast(payload)
}

#[cfg(test)]
fn extract_conversation_id_for_gate_fast(payload: &[u8]) -> Option<String> {
    let bounded = &payload[..payload.len().min(MAX_AS4_PRECHECK_HEADER_SPAN_BYTES)];
    // Fail closed: ordered gate extraction must be bounded to the SOAP Header
    // region, which requires finding the first Body opening tag boundary.
    let body_tag_pos = first_opening_tag_pos_by_local_name(bounded, b"Body")?;
    let search_window = &bounded[..body_tag_pos];

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum GateTag {
        Header,
        Messaging,
        UserMessage,
        CollaborationInfo,
        ConversationIdTarget,
        ConversationIdOther,
        Other,
    }

    fn gate_tag(local_name: &[u8]) -> GateTag {
        match local_name {
            b"Header" => GateTag::Header,
            b"Messaging" => GateTag::Messaging,
            b"UserMessage" => GateTag::UserMessage,
            b"CollaborationInfo" => GateTag::CollaborationInfo,
            b"ConversationId" => GateTag::ConversationIdOther,
            _ => GateTag::Other,
        }
    }

    fn qname_local_name(qname: &[u8]) -> &[u8] {
        if let Some(colon) = memrchr(b':', qname) {
            &qname[colon + 1..]
        } else {
            qname
        }
    }

    let mut reader = Reader::from_reader(search_window);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut stack: Vec<GateTag> = Vec::new();
    let mut depth_header = 0usize;
    let mut depth_messaging = 0usize;
    let mut depth_user_message = 0usize;
    let mut depth_collab = 0usize;
    let mut expect_conversation_text = false;
    let mut pending_conversation_text: Option<Vec<u8>> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                let tag = gate_tag(qname_local_name(e.name().as_ref()));
                match tag {
                    GateTag::Header => depth_header += 1,
                    GateTag::Messaging => depth_messaging += 1,
                    GateTag::UserMessage => depth_user_message += 1,
                    GateTag::CollaborationInfo => depth_collab += 1,
                    GateTag::ConversationIdOther => {
                        let in_expected_context = depth_header > 0
                            && depth_messaging > 0
                            && depth_user_message > 0
                            && depth_collab > 0;
                        if in_expected_context {
                            expect_conversation_text = true;
                            stack.push(GateTag::ConversationIdTarget);
                            buf.clear();
                            continue;
                        }
                    }
                    GateTag::ConversationIdTarget => {}
                    GateTag::Other => {}
                }
                stack.push(tag);
            }
            Ok(XmlEvent::Empty(_e)) => {
                // Ignore empty ConversationId and other empty tags in gate extraction.
                expect_conversation_text = false;
                pending_conversation_text = None;
            }
            Ok(XmlEvent::Text(t)) => {
                if !expect_conversation_text {
                    buf.clear();
                    continue;
                }

                let raw = t.as_ref();
                let value = trim_ascii_whitespace_bytes(raw);
                if value.is_empty() {
                    return None;
                }
                pending_conversation_text = Some(value.to_vec());
                buf.clear();
                continue;
            }
            Ok(XmlEvent::CData(t)) => {
                if !expect_conversation_text {
                    buf.clear();
                    continue;
                }

                let value = trim_ascii_whitespace_bytes(t.as_ref());
                if value.is_empty() {
                    return None;
                }
                pending_conversation_text = Some(value.to_vec());
                buf.clear();
                continue;
            }
            Ok(XmlEvent::End(e)) => {
                let end_tag = gate_tag(qname_local_name(e.name().as_ref()));
                if let Some(start_tag) = stack.pop() {
                    if start_tag != GateTag::Other
                        && end_tag != GateTag::Other
                        && start_tag != end_tag
                    {
                        let compatible_conversation_end = end_tag == GateTag::ConversationIdOther
                            && matches!(
                                start_tag,
                                GateTag::ConversationIdTarget | GateTag::ConversationIdOther
                            );
                        if !compatible_conversation_end {
                            return None;
                        }
                    }
                    match start_tag {
                        GateTag::Header => depth_header = depth_header.saturating_sub(1),
                        GateTag::Messaging => depth_messaging = depth_messaging.saturating_sub(1),
                        GateTag::UserMessage => {
                            depth_user_message = depth_user_message.saturating_sub(1)
                        }
                        GateTag::CollaborationInfo => depth_collab = depth_collab.saturating_sub(1),
                        GateTag::ConversationIdTarget => {
                            if let Some(bytes) = pending_conversation_text.take() {
                                if let Ok(value) = String::from_utf8(bytes) {
                                    return Some(value);
                                }
                                return None;
                            }
                            return None;
                        }
                        GateTag::ConversationIdOther => {}
                        GateTag::Other => {}
                    }
                }
            }
            Ok(XmlEvent::Eof) => break,
            Err(_) => return None,
            _ => {}
        }

        buf.clear();
    }

    None
}

fn first_opening_tag_pos_by_local_name(raw: &[u8], local_name: &[u8]) -> Option<usize> {
    let mut pos = 0;
    while let Some((tag_pos, name, next_pos)) = next_opening_tag_local_name(raw, pos) {
        if name == local_name {
            return Some(tag_pos);
        }
        pos = next_pos;
    }
    None
}

#[cfg(test)]
fn trim_ascii_whitespace_bytes(input: &[u8]) -> &[u8] {
    let start = input
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(input.len());
    let end = input
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(start);
    &input[start..end]
}

#[cfg(test)]
mod tests {
    use super::{
        extract_conversation_id_for_gate, has_all_markers_single_pass, header_span_exceeds_limit,
        parse_as4_receipt, parse_as4_user_message_document, parse_as4_user_message_from_doc,
        precheck_as4_receipt_structure_bytes, precheck_as4_user_message_structure_bytes,
    };
    use crate::core::{AsxError, ErrorCode, InteropMode, SessionContext};
    use crate::observability::EventBus;

    fn strict_user_message_with_properties(properties_xml: &str) -> String {
        format!(
            "<S12:Envelope xmlns:S12=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:eb=\"http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/\" xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><S12:Header><eb:Messaging S12:mustUnderstand=\"true\"><eb:UserMessage><eb:MessageInfo><eb:MessageId>msg-1</eb:MessageId></eb:MessageInfo><eb:PartyInfo><eb:From><eb:PartyId>sender-a</eb:PartyId></eb:From><eb:To><eb:PartyId>receiver-b</eb:PartyId></eb:To></eb:PartyInfo><eb:CollaborationInfo><eb:Service>urn:svc</eb:Service><eb:Action>urn:act</eb:Action></eb:CollaborationInfo>{properties_xml}</eb:UserMessage></eb:Messaging><wsse:Security/></S12:Header><S12:Body/></S12:Envelope>"
        )
    }

    fn parse_user_message_error(xml: &str, interop: InteropMode) -> AsxError {
        let session = SessionContext::new("s-parse-root", "p1", "strict").expect("session");
        let event_bus = EventBus::new(16).expect("bus");
        let doc = parse_as4_user_message_document(xml, &session).expect("doc");

        parse_as4_user_message_from_doc(&session, &event_bus, &doc, interop, true)
            .expect_err("parse must fail")
    }

    fn parse_receipt_error(xml: &str, interop: InteropMode) -> AsxError {
        let session = SessionContext::new("s-parse-receipt", "p1", "strict").expect("session");
        let event_bus = EventBus::new(16).expect("bus");

        parse_as4_receipt(&session, &event_bus, xml, interop, true)
            .expect_err("receipt parse must fail")
    }

    #[test]
    fn marker_precheck_matches_all_required_tokens() {
        let raw = br#"<S12:Envelope><S12:Header><eb:Messaging><eb:UserMessage/></eb:Messaging></S12:Header><S12:Body/></S12:Envelope>"#;
        let markers: [&[u8]; 5] = [
            b"Envelope",
            b"Header",
            b"Body",
            b"Messaging",
            b"UserMessage",
        ];
        assert!(has_all_markers_single_pass(raw, &markers));
    }

    #[test]
    fn marker_precheck_rejects_missing_marker() {
        let raw =
            br#"<S12:Envelope><S12:Header><eb:Messaging/></S12:Header><S12:Body/></S12:Envelope>"#;
        let markers: [&[u8]; 5] = [
            b"Envelope",
            b"Header",
            b"Body",
            b"Messaging",
            b"UserMessage",
        ];
        assert!(!has_all_markers_single_pass(raw, &markers));
    }

    #[test]
    fn marker_precheck_ignores_plain_text_mentions() {
        let raw = b"Envelope Header Body Messaging UserMessage";
        let markers: [&[u8]; 5] = [
            b"Envelope",
            b"Header",
            b"Body",
            b"Messaging",
            b"UserMessage",
        ];
        assert!(!has_all_markers_single_pass(raw, &markers));
    }

    #[test]
    fn marker_precheck_rejects_empty_marker() {
        let raw = b"Envelope Header Body Messaging UserMessage";
        let markers: [&[u8]; 2] = [b"Envelope", b""];
        assert!(!has_all_markers_single_pass(raw, &markers));
    }

    #[test]
    fn marker_precheck_ignores_comment_embedded_tag_mentions() {
        let raw = br#"<S12:Envelope><S12:Header><!-- <S12:Body/><eb:Messaging/><eb:UserMessage/> --></S12:Header></S12:Envelope>"#;
        let markers: [&[u8]; 5] = [
            b"Envelope",
            b"Header",
            b"Body",
            b"Messaging",
            b"UserMessage",
        ];
        assert!(!has_all_markers_single_pass(raw, &markers));
    }

    #[test]
    fn marker_precheck_ignores_cdata_embedded_tag_mentions() {
        let raw = br#"<S12:Envelope><S12:Header><![CDATA[<S12:Body/><eb:Messaging/><eb:UserMessage/>]]></S12:Header></S12:Envelope>"#;
        let markers: [&[u8]; 5] = [
            b"Envelope",
            b"Header",
            b"Body",
            b"Messaging",
            b"UserMessage",
        ];
        assert!(!has_all_markers_single_pass(raw, &markers));
    }

    #[test]
    fn extract_conversation_id_for_gate_fast_path_reads_header_value() {
        let raw = br#"<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/'><S12:Header><eb:Messaging><eb:UserMessage><eb:CollaborationInfo><eb:ConversationId>conv-123</eb:ConversationId></eb:CollaborationInfo></eb:UserMessage></eb:Messaging></S12:Header><S12:Body/></S12:Envelope>"#;
        assert_eq!(
            extract_conversation_id_for_gate(raw),
            Some("conv-123".to_string())
        );
    }

    #[test]
    fn extract_conversation_id_for_gate_ignores_body_marker_collision() {
        let raw = br#"<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/'><S12:Header><eb:Messaging><eb:UserMessage><eb:CollaborationInfo><eb:ConversationId>conv-header</eb:ConversationId></eb:CollaborationInfo></eb:UserMessage></eb:Messaging></S12:Header><S12:Body><eb:ConversationId>conv-body</eb:ConversationId></S12:Body></S12:Envelope>"#;
        assert_eq!(
            extract_conversation_id_for_gate(raw),
            Some("conv-header".to_string())
        );
    }

    #[test]
    fn extract_conversation_id_for_gate_ignores_non_tag_token_mentions() {
        let raw = br#"<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/'><S12:Header><eb:Messaging><eb:UserMessage><eb:CollaborationInfo><eb:Service>ConversationId</eb:Service></eb:CollaborationInfo></eb:UserMessage></eb:Messaging></S12:Header><S12:Body/></S12:Envelope>"#;
        assert_eq!(extract_conversation_id_for_gate(raw), None);
    }

    #[test]
    fn extract_conversation_id_for_gate_rejects_mismatched_closing_tag() {
        let raw = br#"<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/'><S12:Header><eb:Messaging><eb:UserMessage><eb:CollaborationInfo><eb:ConversationId>conv-123</eb:Service></eb:CollaborationInfo></eb:UserMessage></eb:Messaging></S12:Header><S12:Body/></S12:Envelope>"#;
        assert_eq!(extract_conversation_id_for_gate(raw), None);
    }

    #[test]
    fn extract_conversation_id_for_gate_rejects_when_body_tag_is_missing() {
        let raw = br#"<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/'><S12:Header><eb:Messaging><eb:UserMessage><eb:CollaborationInfo><eb:ConversationId>conv-123</eb:ConversationId></eb:CollaborationInfo></eb:UserMessage></eb:Messaging></S12:Header></S12:Envelope>"#;
        assert_eq!(extract_conversation_id_for_gate(raw), None);
    }

    #[test]
    fn extract_conversation_id_for_gate_rejects_when_only_body_boundary_is_plain_text() {
        let raw = br#"<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/'><S12:Header><eb:Messaging><eb:UserMessage><eb:CollaborationInfo><eb:ConversationId>conv-123</eb:ConversationId></eb:CollaborationInfo></eb:UserMessage></eb:Messaging>Body</S12:Header></S12:Envelope>"#;
        assert_eq!(extract_conversation_id_for_gate(raw), None);
    }

    #[test]
    fn extract_conversation_id_for_gate_ignores_conversation_id_outside_collaboration_info() {
        let raw = br#"<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/'><S12:Header><eb:Messaging><eb:UserMessage><eb:MessageInfo><eb:ConversationId>wrong-place</eb:ConversationId></eb:MessageInfo><eb:CollaborationInfo><eb:ConversationId>right-place</eb:ConversationId></eb:CollaborationInfo></eb:UserMessage></eb:Messaging></S12:Header><S12:Body/></S12:Envelope>"#;
        assert_eq!(
            extract_conversation_id_for_gate(raw),
            Some("right-place".to_string())
        );
    }

    #[test]
    fn extract_conversation_id_for_gate_rejects_conversation_id_when_user_message_context_missing()
    {
        let raw = br#"<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/'><S12:Header><eb:Messaging><eb:CollaborationInfo><eb:ConversationId>not-allowed</eb:ConversationId></eb:CollaborationInfo></eb:Messaging></S12:Header><S12:Body/></S12:Envelope>"#;
        assert_eq!(extract_conversation_id_for_gate(raw), None);
    }

    #[test]
    fn extract_conversation_id_for_gate_ignores_comment_embedded_tag_mentions() {
        let raw = br#"<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/'><S12:Header><eb:Messaging><eb:UserMessage><eb:CollaborationInfo><!-- <eb:ConversationId>fake</eb:ConversationId> --></eb:CollaborationInfo></eb:UserMessage></eb:Messaging></S12:Header><S12:Body/></S12:Envelope>"#;
        assert_eq!(extract_conversation_id_for_gate(raw), None);
    }

    #[test]
    fn extract_conversation_id_for_gate_ignores_cdata_embedded_tag_mentions() {
        let raw = br#"<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/'><S12:Header><eb:Messaging><eb:UserMessage><eb:CollaborationInfo><![CDATA[<eb:ConversationId>fake</eb:ConversationId>]]></eb:CollaborationInfo></eb:UserMessage></eb:Messaging></S12:Header><S12:Body/></S12:Envelope>"#;
        assert_eq!(extract_conversation_id_for_gate(raw), None);
    }

    #[test]
    fn header_span_guard_rejects_large_gap() {
        let mut raw = b"<S12:Envelope><S12:Header ".to_vec();
        raw.extend(std::iter::repeat_n(b'x', 128));
        raw.extend_from_slice(b"></S12:Header><S12:Body/></S12:Envelope>");
        assert!(header_span_exceeds_limit(&raw, 32));
        assert!(!header_span_exceeds_limit(&raw, 512));
    }

    #[test]
    fn header_span_guard_ignores_plain_text_mentions() {
        let raw = b"Header xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx Body";
        assert!(!header_span_exceeds_limit(raw, 8));
    }

    #[test]
    fn header_span_guard_ignores_comment_embedded_body_token() {
        let raw = b"<S12:Envelope><S12:Header><!-- <S12:Body/> --></S12:Header></S12:Envelope>";
        assert!(!header_span_exceeds_limit(raw, 8));
    }

    #[test]
    fn user_message_precheck_rejects_when_messaging_is_only_in_body() {
        let session = SessionContext::new("s-precheck", "p1", "strict").expect("session");
        let raw = br#"<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/'><S12:Header/><S12:Body><eb:Messaging><eb:UserMessage/></eb:Messaging></S12:Body></S12:Envelope>"#;
        let err = precheck_as4_user_message_structure_bytes(raw, &session, "as4_receive_push")
            .expect_err("precheck must fail");
        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(
            err.to_string()
                .contains("AS4 SOAP Header missing eb:Messaging marker")
        );
    }

    #[test]
    fn user_message_precheck_rejects_when_body_boundary_is_missing() {
        let session = SessionContext::new("s-precheck", "p1", "strict").expect("session");
        let raw = br#"<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/'><S12:Header><eb:Messaging><eb:UserMessage/></eb:Messaging></S12:Header></S12:Envelope>"#;
        let err = precheck_as4_user_message_structure_bytes(raw, &session, "as4_receive_push")
            .expect_err("precheck must fail");
        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(
            err.to_string()
                .contains("AS4 payload missing SOAP Body marker")
        );
    }

    #[test]
    fn user_message_precheck_rejects_missing_envelope_with_explicit_contract() {
        let session = SessionContext::new("s-precheck", "p1", "strict").expect("session");
        let raw = br#"<S12:Header><eb:Messaging><eb:UserMessage/></eb:Messaging></S12:Header><S12:Body/>"#;
        let err = precheck_as4_user_message_structure_bytes(raw, &session, "as4_receive_push")
            .expect_err("precheck must fail");
        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(
            err.to_string()
                .contains("AS4 payload missing SOAP Envelope marker")
        );
    }

    #[test]
    fn receipt_precheck_rejects_missing_ref_to_message_id_with_explicit_contract() {
        let session = SessionContext::new("s-precheck", "p1", "strict").expect("session");
        let raw = br#"<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/'><S12:Header><eb:Messaging><eb:SignalMessage><eb:Receipt/></eb:SignalMessage></eb:Messaging></S12:Header><S12:Body/></S12:Envelope>"#;
        let err = precheck_as4_receipt_structure_bytes(raw, &session, "as4_receive_receipt")
            .expect_err("precheck must fail");
        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(
            err.to_string()
                .contains("AS4 receipt payload missing eb:RefToMessageId marker")
        );
    }

    #[test]
    fn strict_user_message_parse_rejects_missing_tracking_identifier_property() {
        let session = SessionContext::new("s-parse-strict", "p1", "strict").expect("session");
        let event_bus = EventBus::new(16).expect("bus");
        let xml = strict_user_message_with_properties(
            "<eb:MessageProperties><eb:Property name=\"originalSender\" value=\"sender-a\"/><eb:Property name=\"finalRecipient\" value=\"receiver-b\"/></eb:MessageProperties>",
        );
        let doc = parse_as4_user_message_document(&xml, &session).expect("doc");

        let err =
            parse_as4_user_message_from_doc(&session, &event_bus, &doc, InteropMode::Strict, true)
                .expect_err("strict mode must require trackingIdentifier");

        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(
            err.to_string()
                .contains("AS4 UserMessage missing Property trackingIdentifier")
        );
    }

    #[test]
    fn strict_user_message_parse_rejects_missing_original_sender_property() {
        let session = SessionContext::new("s-parse-strict", "p1", "strict").expect("session");
        let event_bus = EventBus::new(16).expect("bus");
        let xml = strict_user_message_with_properties(
            "<eb:MessageProperties><eb:Property name=\"finalRecipient\" value=\"receiver-b\"/><eb:Property name=\"trackingIdentifier\" value=\"trk-123\"/></eb:MessageProperties>",
        );
        let doc = parse_as4_user_message_document(&xml, &session).expect("doc");

        let err =
            parse_as4_user_message_from_doc(&session, &event_bus, &doc, InteropMode::Strict, true)
                .expect_err("strict mode must require originalSender");

        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(
            err.to_string()
                .contains("AS4 UserMessage missing Property originalSender")
        );
    }

    #[test]
    fn strict_user_message_parse_rejects_missing_final_recipient_property() {
        let session = SessionContext::new("s-parse-strict", "p1", "strict").expect("session");
        let event_bus = EventBus::new(16).expect("bus");
        let xml = strict_user_message_with_properties(
            "<eb:MessageProperties><eb:Property name=\"originalSender\" value=\"sender-a\"/><eb:Property name=\"trackingIdentifier\" value=\"trk-123\"/></eb:MessageProperties>",
        );
        let doc = parse_as4_user_message_document(&xml, &session).expect("doc");

        let err =
            parse_as4_user_message_from_doc(&session, &event_bus, &doc, InteropMode::Strict, true)
                .expect_err("strict mode must require finalRecipient");

        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(
            err.to_string()
                .contains("AS4 UserMessage missing Property finalRecipient")
        );
    }

    #[test]
    fn strict_user_message_parse_extracts_four_corner_properties() {
        let session = SessionContext::new("s-parse-strict", "p1", "strict").expect("session");
        let event_bus = EventBus::new(16).expect("bus");
        let xml = strict_user_message_with_properties(
            "<eb:MessageProperties><eb:Property name=\"originalSender\" value=\"participant-a\"/><eb:Property name=\"finalRecipient\">participant-b</eb:Property><eb:Property name=\"trackingIdentifier\" value=\"trk-123\"/></eb:MessageProperties>",
        );
        let doc = parse_as4_user_message_document(&xml, &session).expect("doc");

        let parsed =
            parse_as4_user_message_from_doc(&session, &event_bus, &doc, InteropMode::Strict, true)
                .expect("strict parse");

        assert_eq!(parsed.original_sender.as_deref(), Some("participant-a"));
        assert_eq!(parsed.final_recipient.as_deref(), Some("participant-b"));
        assert_eq!(parsed.tracking_identifier.as_deref(), Some("trk-123"));
    }

    #[test]
    fn parse_user_message_rejects_non_envelope_root_explicitly() {
        let err = parse_user_message_error("<root/>", InteropMode::Strict);

        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(
            err.to_string()
                .contains("AS4 payload root element must be SOAP Envelope")
        );
    }

    #[test]
    fn parse_user_message_rejects_envelope_without_namespace_explicitly() {
        let err =
            parse_user_message_error("<Envelope><Header/><Body/></Envelope>", InteropMode::Strict);

        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(
            err.to_string()
                .contains("AS4 SOAP Envelope must declare namespace")
        );
    }

    #[test]
    fn parse_user_message_rejects_soap12_envelope_missing_header_explicitly() {
        let err = parse_user_message_error(
            "<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope'><S12:Body/></S12:Envelope>",
            InteropMode::Strict,
        );

        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(err.to_string().contains("AS4 SOAP Envelope missing Header"));
    }

    #[test]
    fn parse_user_message_rejects_soap12_envelope_missing_body_explicitly() {
        let err = parse_user_message_error(
            "<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope'><S12:Header/></S12:Envelope>",
            InteropMode::Strict,
        );

        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(err.to_string().contains("AS4 SOAP Envelope missing Body"));
    }

    #[test]
    fn parse_user_message_rejects_soap12_header_missing_messaging_explicitly() {
        let err = parse_user_message_error(
            "<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'><S12:Header><wsse:Security/></S12:Header><S12:Body/></S12:Envelope>",
            InteropMode::Strict,
        );

        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(
            err.to_string()
                .contains("AS4 SOAP Header missing eb:Messaging")
        );
    }

    #[test]
    fn parse_user_message_rejects_messaging_missing_user_message_explicitly() {
        let err = parse_user_message_error(
            "<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'><S12:Header><eb:Messaging S12:mustUnderstand='true'/><wsse:Security/></S12:Header><S12:Body/></S12:Envelope>",
            InteropMode::Strict,
        );

        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(
            err.to_string()
                .contains("AS4 eb:Messaging missing UserMessage")
        );
    }

    #[test]
    fn parse_user_message_rejects_missing_wsse_security_explicitly_in_strict_mode() {
        let err = parse_user_message_error(
            "<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/'><S12:Header><eb:Messaging S12:mustUnderstand='true'><eb:UserMessage><eb:MessageInfo><eb:MessageId>msg-1</eb:MessageId></eb:MessageInfo><eb:PartyInfo><eb:From><eb:PartyId>sender-a</eb:PartyId></eb:From><eb:To><eb:PartyId>receiver-b</eb:PartyId></eb:To></eb:PartyInfo><eb:CollaborationInfo><eb:Service>urn:svc</eb:Service><eb:Action>urn:act</eb:Action></eb:CollaborationInfo></eb:UserMessage></eb:Messaging></S12:Header><S12:Body/></S12:Envelope>",
            InteropMode::Strict,
        );

        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(
            err.to_string()
                .contains("AS4 SOAP Header missing wsse:Security")
        );
    }

    #[test]
    fn parse_receipt_rejects_missing_signal_message_explicitly() {
        let err = parse_receipt_error(
            "<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/'><S12:Header><eb:Messaging/></S12:Header><S12:Body/></S12:Envelope>",
            InteropMode::Strict,
        );

        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(
            err.to_string()
                .contains("AS4 signal payload missing eb:SignalMessage")
        );
    }

    #[test]
    fn parse_receipt_rejects_signal_message_missing_receipt_explicitly() {
        let err = parse_receipt_error(
            "<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/'><S12:Header><eb:Messaging><eb:SignalMessage><eb:MessageInfo><eb:RefToMessageId>msg-1</eb:RefToMessageId></eb:MessageInfo></eb:SignalMessage></eb:Messaging></S12:Header><S12:Body/></S12:Envelope>",
            InteropMode::Strict,
        );

        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(
            err.to_string()
                .contains("AS4 eb:SignalMessage missing eb:Receipt")
        );
    }
}
