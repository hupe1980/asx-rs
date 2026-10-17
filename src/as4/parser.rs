use super::ParsedAs4UserMessage;
use crate::as4::types::{As4NriReference, As4ReceivedError, ParsedWsAddressingHeaders};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
use roxmltree::{Document, Node};

const EBMS3_CORE_NS: &str = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/";
const EBBP_SIGNALS_NS: &str = "http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0";
const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const SOAP12_NS: &str = "http://www.w3.org/2003/05/soap-envelope";
const SOAP12_ROLE_ULTIMATE_RECEIVER: &str =
    "http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver";
const WSSE_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

#[derive(Default)]
struct As4UserMessageParseState {
    from_party_type: Option<String>,
    to_party_type: Option<String>,
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

pub(super) fn parse_as4_user_message_document<'a>(
    xml: &'a str,
    session: &SessionContext,
) -> Result<Document<'a>> {
    crate::xml::parse(
        xml,
        crate::xml::XmlLimits::ENVELOPE,
        "as4_parse_user_message",
    )
    .map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("failed to parse AS4 SOAP envelope: {}", err.message),
            ErrorContext::for_session("as4_parse_user_message", session),
        )
    })
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
    doc: &Document<'_>,
) -> Result<ParsedAs4UserMessage> {
    let state = parse_as4_user_message_summary_dom_from_doc(doc, session)?;

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

    if !state.messaging_must_understand_true {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            "AS4 eb:Messaging must set SOAP mustUnderstand=true",
            ErrorContext::for_session("as4_parse_user_message", session),
        ));
    }

    if !state.has_security {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "AS4 SOAP Header missing wsse:Security",
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

    if let Some(mpc_value) = state.mpc.as_deref()
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

    // The four-corner properties are the Peppol envelope's; a session built
    // from a `Profile` does not require them of BDEW, eDelivery or ENTSOG
    // senders.
    let require_four_corner = !session.metadata().profile_built;
    if state.original_sender.is_none() && require_four_corner {
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
    if state.final_recipient.is_none() && require_four_corner {
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
    if state.tracking_identifier.is_none() && require_four_corner {
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

    Ok(ParsedAs4UserMessage {
        message_id,
        action,
        from_party_ids: state.from_party_ids,
        to_party_ids: state.to_party_ids,
        from_party_type: state.from_party_type,
        to_party_type: state.to_party_type,
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
            if state.has_messaging {
                return Err(AsxError::new(
                    ErrorCode::InteropViolation,
                    "AS4 SOAP Header contains duplicate eb:Messaging blocks",
                    ErrorContext::for_session("as4_parse_user_message", session),
                ));
            }

            if targeting.invalid_must_understand {
                return Err(AsxError::new(
                    ErrorCode::InteropViolation,
                    "AS4 eb:Messaging has invalid SOAP mustUnderstand token",
                    ErrorContext::for_session("as4_parse_user_message", session),
                ));
            }

            if !header_is_targeted_to_receiver_dom(&targeting) {
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
            if targeting.invalid_must_understand {
                return Err(AsxError::new(
                    ErrorCode::InteropViolation,
                    "AS4 SOAP Header block has invalid SOAP mustUnderstand token",
                    ErrorContext::for_session("as4_parse_user_message", session),
                ));
            }

            let security_targeted_to_receiver = header_is_targeted_to_receiver_dom(&targeting);
            if security_targeted_to_receiver && state.has_security {
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

        if targeting.must_understand_true && header_is_targeted_to_receiver_dom(&targeting) {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "AS4 SOAP Header contains unknown mandatory receiver-targeted block",
                ErrorContext::for_session("as4_parse_user_message", session),
            ));
        }

        if targeting.invalid_must_understand {
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
        if message_ids.len() > 1 {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "AS4 UserMessage contains duplicate MessageId",
                ErrorContext::for_session("as4_parse_user_message", session),
            ));
        }
        state.message_id = message_ids.into_iter().next();

        state.ref_to_message_id = descendant_text(&user_message, EBMS3_CORE_NS, "RefToMessageId");

        let actions = descendant_texts(&user_message, EBMS3_CORE_NS, "Action");
        if actions.len() > 1 {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "AS4 UserMessage contains duplicate Action",
                ErrorContext::for_session("as4_parse_user_message", session),
            ));
        }
        state.action = actions.into_iter().next();

        state.service = descendant_text(&user_message, EBMS3_CORE_NS, "Service");

        // `eb:ConversationId` is `maxOccurs="1"` in ebMS3 Core. Taking the
        // first of several is document order deciding which conversation a
        // message belongs to — and a schema validator and a downstream MSH
        // need not agree on which one that is.
        let conversation_ids = descendant_texts(&user_message, EBMS3_CORE_NS, "ConversationId");
        if conversation_ids.len() > 1 {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "AS4 UserMessage contains duplicate ConversationId",
                ErrorContext::for_session("as4_parse_user_message", session),
            ));
        }
        state.conversation_id = conversation_ids.into_iter().next();

        state.timestamp = descendant_text(&user_message, EBMS3_CORE_NS, "Timestamp");

        let original_senders = message_property_values(&user_message, "originalSender", session)?;
        if original_senders.len() > 1 {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "AS4 UserMessage contains duplicate Property originalSender",
                ErrorContext::for_session("as4_parse_user_message", session),
            ));
        }
        state.original_sender = original_senders.into_iter().next();

        let final_recipients = message_property_values(&user_message, "finalRecipient", session)?;
        if final_recipients.len() > 1 {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "AS4 UserMessage contains duplicate Property finalRecipient",
                ErrorContext::for_session("as4_parse_user_message", session),
            ));
        }
        state.final_recipient = final_recipients.into_iter().next();

        let tracking_identifiers =
            message_property_values(&user_message, "trackingIdentifier", session)?;
        if tracking_identifiers.len() > 1 {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "AS4 UserMessage contains duplicate Property trackingIdentifier",
                ErrorContext::for_session("as4_parse_user_message", session),
            ));
        }
        state.tracking_identifier = tracking_identifiers.into_iter().next();

        state.from_party_ids = party_ids_for(&user_message, "From");
        state.from_party_type = first_party_type(&user_message, "From");
        state.to_party_type = first_party_type(&user_message, "To");
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

/// The `type` attribute of the first `eb:PartyId` under `direction`.
fn first_party_type(user_message: &Node<'_, '_>, direction: &str) -> Option<String> {
    user_message
        .descendants()
        .find(|n| {
            n.is_element()
                && n.tag_name().namespace() == Some(EBMS3_CORE_NS)
                && n.tag_name().name() == "PartyId"
                && n.ancestors().any(|a| {
                    a.is_element()
                        && a.tag_name().namespace() == Some(EBMS3_CORE_NS)
                        && a.tag_name().name() == direction
                })
        })
        .and_then(|n| n.attribute("type"))
        .map(|t| t.trim().to_string())
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

fn message_property_values(
    user_message: &Node<'_, '_>,
    property_name: &str,
    session: &SessionContext,
) -> Result<Vec<String>> {
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
        .map(|node| property_value_from_node(node, session, "as4_parse_user_message"))
        .filter_map(Result::transpose)
        .collect()
}

/// The value of an `eb:Property`: its element text (ebMS3 header schema:
/// `Property` is simpleContent with the single attribute `name`). A `value`
/// attribute is not read; a property that carries its value only there is
/// refused naming it, because accepting both forms is an
/// ambiguity a sender could steer.
pub(super) fn property_value_from_node(
    node: Node<'_, '_>,
    session: &SessionContext,
    stage: &'static str,
) -> Result<Option<String>> {
    let text: String = node
        .children()
        .filter(|c| c.is_text())
        .filter_map(|c| c.text())
        .collect();
    let text = text.trim();
    if !text.is_empty() {
        return Ok(Some(text.to_string()));
    }
    if node.attribute("value").is_some() {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!(
                "eb:Property \"{}\" carries its value in a `value` attribute; ebMS3 Property \
                 values are element text",
                node.attribute("name").unwrap_or_default()
            ),
            ErrorContext::for_session(stage, session),
        ));
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// SignalMessage parser (Receipt + Error)
// ---------------------------------------------------------------------------
//
// Used by the outbound receipt verification in `as4::receipt_verify`.
//
// Structural rules enforced here, all of them anti-wrapping measures rather
// than mere syntax checks:
//
// * at most one `eb:Messaging` block and one `eb:SignalMessage` — otherwise an
//   unsigned block could supply the values the caller acts on while a genuine
//   signed block satisfies the signature check;
// * `NonRepudiationInformation` is harvested only from inside the
//   `eb:Receipt` of that SignalMessage;
// * each `eb:MessageInfo` child appears at most once, so an injected duplicate
//   cannot shadow the real value.

/// Upper bound on `<ebbpsig:MessagePartNRInformation>` entries retained from a
/// counterparty receipt.  A conformant AS4 receipt echoes one entry per
/// `<ds:Reference>` of the original signature — in practice 2–5 (Messaging,
/// Body, and one per MIME attachment).  The cap bounds allocation from a
/// hostile MSH independently of the element-count guard.
const MAX_SIGNAL_NRI_REFERENCES: usize = 256;

/// Upper bound on `<eb:Error>` entries retained from a counterparty signal.
const MAX_SIGNAL_ERRORS: usize = 64;

/// Everything the receipt paths need from a counterparty `eb:SignalMessage`.
///
/// Populated by [`parse_as4_signal_envelope`] from the DOM the signature
/// verifier checks — namespace-resolved, so `eb:`, `eb3:`, `ns2:` and
/// default-namespace documents are handled identically, and character
/// references and CDATA are part of the text they appear in.
#[derive(Debug, Default)]
pub(super) struct ParsedAs4SignalEnvelope {
    pub(super) has_signal_message: bool,
    pub(super) has_receipt: bool,
    pub(super) has_non_repudiation_info: bool,
    pub(super) has_signature: bool,
    pub(super) message_id: Option<String>,
    pub(super) ref_to_message_id: Option<String>,
    pub(super) timestamp: Option<String>,
    pub(super) nri_references: Vec<As4NriReference>,
    pub(super) errors: Vec<As4ReceivedError>,
}

fn is_element(node: &Node<'_, '_>, ns: &str, local: &str) -> bool {
    node.is_element() && node.tag_name().namespace() == Some(ns) && node.tag_name().name() == local
}

/// All text inside `node` (character references and CDATA included),
/// trimmed; `None` when empty.
fn element_text(node: Node<'_, '_>) -> Option<String> {
    let text: String = node
        .descendants()
        .filter(|n| n.is_text())
        .filter_map(|n| n.text())
        .collect();
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// An unprefixed attribute, trimmed; `None` when absent or empty. ebMS3
/// (`errorCode`, `severity`, …) and XMLDSig (`URI`, `Algorithm`) both declare
/// these unqualified, so prefixed look-alikes are deliberately ignored.
fn signal_attribute(node: Node<'_, '_>, name: &str) -> Option<String> {
    node.attribute(name)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// Parse an AS4 `eb:SignalMessage` envelope (Receipt and/or Error) from the
/// parsed document.
///
/// This applies no *policy* — it extracts structure and enforces the
/// unambiguity rules described above.  Policy enforcement lives in
/// `receipt_verify`, so callers can distinguish "counterparty rejected the message"
/// (Error signal) from "counterparty acknowledged it" (Receipt).
pub(super) fn parse_as4_signal_envelope(
    doc: &Document<'_>,
    session: &SessionContext,
    stage: &'static str,
) -> Result<ParsedAs4SignalEnvelope> {
    let parse_error = |message: String| {
        AsxError::new(
            ErrorCode::ParseFailed,
            message,
            ErrorContext::for_session(stage, session),
        )
    };
    // Structural shapes that are signature-wrapping vectors rather than mere
    // syntax problems — classified so callers and alerting can tell a
    // malformed response from an attack shape.
    let wrapping_error = |message: String| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            message,
            ErrorContext::for_session(stage, session),
        )
    };

    let mut out = ParsedAs4SignalEnvelope {
        has_signature: doc
            .descendants()
            .any(|n| is_element(&n, XMLDSIG_NS, "Signature")),
        ..ParsedAs4SignalEnvelope::default()
    };

    // A signature can only cover one eb:Messaging; merging fields across
    // blocks would let an unsigned block supply the values the caller acts on
    // while a genuine signed block satisfies the signature.
    if doc
        .descendants()
        .filter(|n| is_element(n, EBMS3_CORE_NS, "Messaging"))
        .nth(1)
        .is_some()
    {
        return Err(wrapping_error(
            "AS4 signal envelope contains more than one eb:Messaging header block \
             (possible XML signature wrapping)"
                .to_string(),
        ));
    }

    let mut signals = doc
        .descendants()
        .filter(|n| is_element(n, EBMS3_CORE_NS, "SignalMessage"));
    let Some(signal) = signals.next() else {
        return Ok(out);
    };
    // Likewise, a second SignalMessage could carry a Receipt for a different
    // message alongside a genuine one. ebMS3 permits bundled signals; this
    // crate deliberately does not accept them, because correlating a bundle
    // to one sent message is ambiguous.
    if signals.next().is_some() {
        return Err(wrapping_error(
            "AS4 signal envelope contains more than one eb:SignalMessage; bundled signals \
             are not accepted because the acknowledgement cannot be unambiguously \
             correlated to the sent message"
                .to_string(),
        ));
    }
    out.has_signal_message = true;

    // ebMS3 §5.2.2.1 declares each MessageInfo child at most once, so a second
    // occurrence is rejected rather than silently first-wins — otherwise an
    // injected duplicate could shadow the real value.
    for info in signal
        .descendants()
        .filter(|n| is_element(n, EBMS3_CORE_NS, "MessageInfo"))
    {
        for (local, slot) in [
            ("MessageId", &mut out.message_id),
            ("RefToMessageId", &mut out.ref_to_message_id),
            ("Timestamp", &mut out.timestamp),
        ] {
            for node in info
                .descendants()
                .filter(|n| is_element(n, EBMS3_CORE_NS, local))
            {
                let Some(value) = element_text(node) else {
                    continue;
                };
                if slot.is_some() {
                    return Err(wrapping_error(format!(
                        "AS4 eb:SignalMessage contains more than one eb:{local}; a repeated \
                         element makes the signal ambiguous (possible element injection)"
                    )));
                }
                *slot = Some(value);
            }
        }
    }

    // NonRepudiationInformation is only meaningful inside the eb:Receipt of
    // this SignalMessage; a block placed elsewhere is not an acknowledgement
    // of anything and must not be harvested as one.
    for receipt in signal
        .descendants()
        .filter(|n| is_element(n, EBMS3_CORE_NS, "Receipt"))
    {
        out.has_receipt = true;
        for nri in receipt.descendants().filter(|n| {
            is_element(n, EBBP_SIGNALS_NS, "NonRepudiationInformation")
                || is_element(n, EBMS3_CORE_NS, "NonRepudiationInformation")
        }) {
            out.has_non_repudiation_info = true;
            for reference in nri
                .descendants()
                .filter(|n| is_element(n, XMLDSIG_NS, "Reference"))
            {
                if out.nri_references.len() >= MAX_SIGNAL_NRI_REFERENCES {
                    return Err(parse_error(format!(
                        "AS4 receipt NonRepudiationInformation exceeds the \
                         MessagePartNRInformation limit ({MAX_SIGNAL_NRI_REFERENCES})"
                    )));
                }
                let digest_method_uri = reference
                    .descendants()
                    .find(|n| is_element(n, XMLDSIG_NS, "DigestMethod"))
                    .and_then(|n| signal_attribute(n, "Algorithm"));
                let digest_value_b64 = reference
                    .descendants()
                    .find(|n| is_element(n, XMLDSIG_NS, "DigestValue"))
                    .and_then(element_text);
                if let (Some(uri), Some(digest_method_uri), Some(digest_value_b64)) = (
                    signal_attribute(reference, "URI"),
                    digest_method_uri,
                    digest_value_b64,
                ) {
                    out.nri_references.push(As4NriReference {
                        uri,
                        digest_method_uri,
                        digest_value_b64,
                    });
                }
            }
        }
    }

    for error in signal
        .descendants()
        .filter(|n| is_element(n, EBMS3_CORE_NS, "Error"))
        .take(MAX_SIGNAL_ERRORS)
    {
        let child_text = |local: &str| {
            error
                .descendants()
                .find(|n| is_element(n, EBMS3_CORE_NS, local))
                .and_then(element_text)
        };
        out.errors.push(As4ReceivedError {
            error_code: signal_attribute(error, "errorCode")
                .unwrap_or_else(|| "unknown".to_string()),
            severity: signal_attribute(error, "severity"),
            category: signal_attribute(error, "category"),
            origin: signal_attribute(error, "origin"),
            ref_to_message_id: signal_attribute(error, "refToMessageId"),
            short_description: signal_attribute(error, "shortDescription"),
            description: child_text("Description"),
            error_detail: child_text("ErrorDetail"),
        });
    }

    Ok(out)
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

#[cfg(test)]
mod tests {
    use super::{parse_as4_user_message_document, parse_as4_user_message_from_doc};
    use crate::core::{AsxError, ErrorCode, SessionContext};

    fn strict_user_message_with_properties(properties_xml: &str) -> String {
        format!(
            "<S12:Envelope xmlns:S12=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:eb=\"http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/\" xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><S12:Header><eb:Messaging S12:mustUnderstand=\"true\"><eb:UserMessage><eb:MessageInfo><eb:MessageId>msg-1</eb:MessageId></eb:MessageInfo><eb:PartyInfo><eb:From><eb:PartyId>sender-a</eb:PartyId></eb:From><eb:To><eb:PartyId>receiver-b</eb:PartyId></eb:To></eb:PartyInfo><eb:CollaborationInfo><eb:Service>urn:svc</eb:Service><eb:Action>urn:act</eb:Action></eb:CollaborationInfo>{properties_xml}</eb:UserMessage></eb:Messaging><wsse:Security/></S12:Header><S12:Body/></S12:Envelope>"
        )
    }

    fn parse_user_message_error(xml: &str) -> AsxError {
        let session = SessionContext::new("s-parse-root", "p1", "strict").expect("session");
        let doc = parse_as4_user_message_document(xml, &session).expect("doc");

        parse_as4_user_message_from_doc(&session, &doc).expect_err("parse must fail")
    }

    /// The DOM alone refuses an envelope whose eb:Messaging sits in the Body.
    #[test]
    fn user_message_dom_rejects_messaging_only_in_body() {
        let err = parse_user_message_error(
            r#"<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/'><S12:Header/><S12:Body><eb:Messaging><eb:UserMessage/></eb:Messaging></S12:Body></S12:Envelope>"#,
        );
        assert_eq!(err.code, ErrorCode::ParseFailed);
    }

    /// The DOM alone refuses an envelope without a Body.
    #[test]
    fn user_message_dom_rejects_missing_body() {
        let err = parse_user_message_error(
            r#"<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/'><S12:Header><eb:Messaging><eb:UserMessage/></eb:Messaging></S12:Header></S12:Envelope>"#,
        );
        assert_eq!(err.code, ErrorCode::ParseFailed);
    }

    /// A repeated four-corner property is ambiguous and rejected, never
    /// resolved by document order.
    #[test]
    fn duplicate_four_corner_properties_are_rejected() {
        for name in ["originalSender", "finalRecipient", "trackingIdentifier"] {
            let mut props = String::from(
                "<eb:MessageProperties><eb:Property name=\"originalSender\">sender-a</eb:Property><eb:Property name=\"finalRecipient\">receiver-b</eb:Property><eb:Property name=\"trackingIdentifier\">t-1</eb:Property>",
            );
            props.push_str(&format!(
                "<eb:Property name=\"{name}\">second</eb:Property></eb:MessageProperties>"
            ));
            let err = parse_user_message_error(&strict_user_message_with_properties(&props));
            assert_eq!(err.code, ErrorCode::InteropViolation, "{name}");
            assert!(
                err.message.contains(&format!("duplicate Property {name}")),
                "{name}: {}",
                err.message
            );
        }
    }

    #[test]
    fn strict_user_message_parse_rejects_missing_tracking_identifier_property() {
        let session = SessionContext::new("s-parse-strict", "p1", "strict").expect("session");
        let xml = strict_user_message_with_properties(
            "<eb:MessageProperties><eb:Property name=\"originalSender\">sender-a</eb:Property><eb:Property name=\"finalRecipient\">receiver-b</eb:Property></eb:MessageProperties>",
        );
        let doc = parse_as4_user_message_document(&xml, &session).expect("doc");

        let err = parse_as4_user_message_from_doc(&session, &doc)
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
        let xml = strict_user_message_with_properties(
            "<eb:MessageProperties><eb:Property name=\"finalRecipient\">receiver-b</eb:Property><eb:Property name=\"trackingIdentifier\">trk-123</eb:Property></eb:MessageProperties>",
        );
        let doc = parse_as4_user_message_document(&xml, &session).expect("doc");

        let err = parse_as4_user_message_from_doc(&session, &doc)
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
        let xml = strict_user_message_with_properties(
            "<eb:MessageProperties><eb:Property name=\"originalSender\">sender-a</eb:Property><eb:Property name=\"trackingIdentifier\">trk-123</eb:Property></eb:MessageProperties>",
        );
        let doc = parse_as4_user_message_document(&xml, &session).expect("doc");

        let err = parse_as4_user_message_from_doc(&session, &doc)
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
        let xml = strict_user_message_with_properties(
            "<eb:MessageProperties><eb:Property name=\"originalSender\">participant-a</eb:Property><eb:Property name=\"finalRecipient\">participant-b</eb:Property><eb:Property name=\"trackingIdentifier\">trk-123</eb:Property></eb:MessageProperties>",
        );
        let doc = parse_as4_user_message_document(&xml, &session).expect("doc");

        let parsed = parse_as4_user_message_from_doc(&session, &doc).expect("strict parse");

        assert_eq!(parsed.original_sender.as_deref(), Some("participant-a"));
        assert_eq!(parsed.final_recipient.as_deref(), Some("participant-b"));
        assert_eq!(parsed.tracking_identifier.as_deref(), Some("trk-123"));
    }

    #[test]
    fn parse_user_message_rejects_non_envelope_root_explicitly() {
        let err = parse_user_message_error("<root/>");

        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(
            err.to_string()
                .contains("AS4 payload root element must be SOAP Envelope")
        );
    }

    #[test]
    fn parse_user_message_rejects_envelope_without_namespace_explicitly() {
        let err = parse_user_message_error("<Envelope><Header/><Body/></Envelope>");

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
        );

        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(err.to_string().contains("AS4 SOAP Envelope missing Header"));
    }

    #[test]
    fn parse_user_message_rejects_soap12_envelope_missing_body_explicitly() {
        let err = parse_user_message_error(
            "<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope'><S12:Header/></S12:Envelope>",
        );

        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(err.to_string().contains("AS4 SOAP Envelope missing Body"));
    }

    #[test]
    fn parse_user_message_rejects_soap12_header_missing_messaging_explicitly() {
        let err = parse_user_message_error(
            "<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'><S12:Header><wsse:Security/></S12:Header><S12:Body/></S12:Envelope>",
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
        );

        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(
            err.to_string()
                .contains("AS4 SOAP Header missing wsse:Security")
        );
    }
}

#[cfg(test)]
mod gate_key_multipart_probe {}
