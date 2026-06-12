#![cfg(all(feature = "as4", feature = "testing"))]
#[path = "common/as4_adversarial.rs"]
mod common;
// Adversarial SOAP/ebMS corpus for AS4 parser hardening.
//
// This suite covers structural, encoding, and semantic edge cases that
// standards-compliant parsers should reject deterministically, based on
// ebMS 3.0 §5, SOAP 1.2, and XML 1.0 processing rules.

use crate::common::{as4_strict_push_policy, as4_unsigned_push_policy};
use asx::as4::{As4ReceivePushRequest, As4ReceivePushSyncRequest, receive_push_with_dedup_sync};
use asx::core::{ErrorCode, SessionContext};
use asx::observability::EventBus;
use asx::reliability::InMemoryDedupBackend;

fn session() -> SessionContext {
    SessionContext::new("s-adversarial", "p-adversarial", "strict").expect("session")
}

fn dedup() -> InMemoryDedupBackend {
    InMemoryDedupBackend::default()
}

fn bus() -> EventBus {
    EventBus::new(32).expect("bus")
}

fn content_type_for_payload(payload: &[u8]) -> String {
    if let Some(boundary) = detect_multipart_boundary(payload) {
        return format!(
            "multipart/related; boundary=\"{boundary}\"; type=\"application/soap+xml\""
        );
    }

    "application/soap+xml".to_string()
}

fn detect_multipart_boundary(payload: &[u8]) -> Option<String> {
    if !payload.starts_with(b"--") {
        return None;
    }

    let line_end = payload.windows(2).position(|window| window == b"\r\n")?;
    let boundary = &payload[2..line_end];

    if boundary.is_empty() {
        return None;
    }

    let boundary = std::str::from_utf8(boundary).ok()?.trim();
    if boundary.is_empty() {
        return None;
    }

    Some(boundary.to_string())
}

fn ensure_required_strict_properties_in_xml(xml: &str) -> String {
    let has_original_sender = xml.contains("name=\"originalSender\"");
    let has_final_recipient = xml.contains("name=\"finalRecipient\"");
    let has_tracking_identifier = xml.contains("name=\"trackingIdentifier\"");

    if has_original_sender && has_final_recipient && has_tracking_identifier {
        return xml.to_string();
    }

    let Some(user_message_close) = xml.find("</eb:UserMessage>") else {
        return xml.to_string();
    };

    let mut out = String::with_capacity(xml.len() + 256);
    out.push_str(&xml[..user_message_close]);
    out.push_str(
        "<eb:MessageProperties>\
            <eb:Property name=\"originalSender\">urn:test:sender</eb:Property>\
            <eb:Property name=\"finalRecipient\">urn:test:recipient</eb:Property>\
            <eb:Property name=\"trackingIdentifier\">urn:test:tracking</eb:Property>\
        </eb:MessageProperties>",
    );
    out.push_str(&xml[user_message_close..]);
    out
}

fn push(payload: &[u8]) -> asx::core::Result<asx::as4::As4ReceivePushOutput> {
    let bus = bus();
    let _events = bus.subscribe_scoped_events();
    let normalized_payload = if detect_multipart_boundary(payload).is_none() {
        String::from_utf8_lossy(payload).into_owned()
    } else {
        String::new()
    };
    let payload_owned = if normalized_payload.is_empty() {
        payload.to_vec()
    } else {
        ensure_required_strict_properties_in_xml(&normalized_payload).into_bytes()
    };
    let http_content_type = content_type_for_payload(&payload_owned);
    receive_push_with_dedup_sync(
        &session(),
        &bus,
        As4ReceivePushSyncRequest {
            request: As4ReceivePushRequest {
                http_content_type,
                payload: payload_owned.into(),
                receipt_payload: None,
                policy: as4_unsigned_push_policy(),
                authenticated_sender_scope: None,
            },
            dedup_backend: &dedup(),
        },
    )
}

fn push_signed_required(payload: &[u8]) -> asx::core::Result<asx::as4::As4ReceivePushOutput> {
    let bus = bus();
    let _events = bus.subscribe_scoped_events();
    let normalized_payload = if detect_multipart_boundary(payload).is_none() {
        String::from_utf8_lossy(payload).into_owned()
    } else {
        String::new()
    };
    let payload_owned = if normalized_payload.is_empty() {
        payload.to_vec()
    } else {
        ensure_required_strict_properties_in_xml(&normalized_payload).into_bytes()
    };
    let http_content_type = content_type_for_payload(&payload_owned);
    receive_push_with_dedup_sync(
        &session(),
        &bus,
        As4ReceivePushSyncRequest {
            request: As4ReceivePushRequest {
                http_content_type,
                payload: payload_owned.into(),
                receipt_payload: None,
                policy: as4_strict_push_policy(),
                authenticated_sender_scope: None,
            },
            dedup_backend: &dedup(),
        },
    )
}

fn multipart_payload_with_cid(soap_xml: &[u8], payload_cid: &str, payload: &[u8]) -> Vec<u8> {
    let boundary = "asx-adversarial-boundary";
    let mut soap = ensure_required_strict_properties_in_xml(&String::from_utf8_lossy(soap_xml));

    if !soap.contains("xmlns:xop=\"http://www.w3.org/2004/08/xop/include\"") {
        soap = soap.replacen(
            "<S12:Envelope ",
            "<S12:Envelope xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" ",
            1,
        );
    }

    let include = format!("<xop:Include href=\"cid:{payload_cid}\"/>");
    if soap.contains("<S12:Body/>") {
        soap = soap.replacen("<S12:Body/>", &format!("<S12:Body>{include}</S12:Body>"), 1);
    } else if soap.contains("<S12:Body>") {
        soap = soap.replacen("<S12:Body>", &format!("<S12:Body>{include}"), 1);
    }

    let mut out = Vec::new();
    out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    out.extend_from_slice(
        b"Content-Type: application/xop+xml; charset=UTF-8; type=\"application/soap+xml\"\r\n",
    );
    out.extend_from_slice(b"Content-ID: <soap-root@example.com>\r\n\r\n");
    out.extend_from_slice(soap.as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    out.extend_from_slice(
        format!("Content-Type: application/octet-stream\r\nContent-ID: <{payload_cid}>\r\n\r\n")
            .as_bytes(),
    );
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    out
}

// ── Structural completeness ──────────────────────────────────────────────────

#[test]
fn rejects_completely_malformed_xml() {
    let err = push(b"not xml at all <<< >>>").expect_err("must reject");
    assert_eq!(err.code, ErrorCode::ParseFailed);
}

#[test]
fn rejects_empty_xml_document() {
    let err = push(b"").expect_err("empty must reject");
    assert_eq!(err.code, ErrorCode::ParseFailed);
}

#[test]
fn rejects_soap_envelope_without_header() {
    // SOAP envelope with Body but no Header → missing required structure.
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("no Header must reject");
    assert_eq!(err.code, ErrorCode::ParseFailed);
}

#[test]
fn rejects_soap_envelope_without_body() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-1</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
        </S12:Envelope>"#,
    )
    .expect_err("no Body must reject");
    assert_eq!(err.code, ErrorCode::ParseFailed);
}

#[test]
fn rejects_soap_envelope_without_messaging_element() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("no eb:Messaging must reject");
    assert_eq!(err.code, ErrorCode::ParseFailed);
}

#[test]
fn rejects_messaging_without_user_message() {
    // eb:Messaging present but contains no eb:UserMessage.
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:SignalMessage>
                        <eb:MessageInfo><eb:MessageId>sig-1</eb:MessageId></eb:MessageInfo>
                    </eb:SignalMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("no UserMessage must reject");
    assert_eq!(err.code, ErrorCode::ParseFailed);
}

// ── Required field validation ────────────────────────────────────────────────

#[test]
fn rejects_user_message_without_message_id() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("missing MessageId must reject");
    assert_eq!(err.code, ErrorCode::ParseFailed);
}

#[test]
fn rejects_user_message_without_action() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-no-act</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo/>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("missing Action must reject");
    assert_eq!(err.code, ErrorCode::ParseFailed);
}

#[test]
fn rejects_user_message_without_from_party_id() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-no-from</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("missing From/PartyId must reject");
    assert_eq!(err.code, ErrorCode::ParseFailed);
}

#[test]
fn rejects_user_message_without_to_party_id() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-no-to</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("missing To/PartyId must reject");
    assert_eq!(err.code, ErrorCode::ParseFailed);
}

// ── Encoding / injection resilience ─────────────────────────────────────────

#[test]
fn rejects_non_utf8_payload() {
    // 0xFF bytes are invalid in UTF-8 and must not be silently decoded.
    let mut payload =
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope">"#.to_vec();
    payload.push(0xFF);
    payload.extend_from_slice(b"</S12:Envelope>");
    let err = push(&payload).expect_err("non-UTF-8 must reject");
    assert_eq!(err.code, ErrorCode::ParseFailed);
}

#[test]
fn accepts_xml_entity_encoded_message_id() {
    // XML entity encoding in MessageId must round-trip through the parser.
    // The parser should decode &amp; entities without rejecting the document.
    let out = push(&multipart_payload_with_cid(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg&amp;entity&lt;test&gt;</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
        "body@example.com",
        b"entity-encoded-message-id-payload",
    ))
    .expect("entity-encoded MessageId must parse");
    // quick-xml 0.38 emits separate Text events at entity boundaries; the
    // parser must accumulate them so the full decoded value is preserved.
    assert_eq!(out.user_message.message_id, "msg&entity<test>");
}

#[test]
fn accepts_deeply_nested_but_valid_envelope() {
    // A valid envelope with extra namespace declarations and nested empty elements
    // inside the SOAP Body should be accepted.
    let out = push(&multipart_payload_with_cid(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo>
                            <eb:MessageId>msg-deep-1</eb:MessageId>
                        </eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId type="urn:oasis:names:tc:ebcore:partyid-type:iso6523:0088">A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo>
                            <eb:Service type="urn:oasis:names:tc:ebcore:service:unregistered">TestService</eb:Service>
                            <eb:Action>SubmitOrder</eb:Action>
                            <eb:ConversationId>conv-deep-1</eb:ConversationId>
                        </eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security><wsse:Timestamp/></wsse:Security>
            </S12:Header>
            <S12:Body>
                <app:Payload xmlns:app="urn:example:app"><app:Data/></app:Payload>
            </S12:Body>
        </S12:Envelope>"#,
        "body@example.com",
        b"deep-envelope-payload",
    ))
    .expect("deep valid envelope must parse");
    assert_eq!(out.user_message.message_id, "msg-deep-1");
    assert_eq!(out.user_message.action, "SubmitOrder");
    assert_eq!(
        out.user_message.conversation_id,
        Some("conv-deep-1".to_string())
    );
}

// ── First-element-wins / injection guard ────────────────────────────────────

#[test]
fn rejects_duplicate_message_id_in_strict_mode() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo>
                            <eb:MessageId>msg-legitimate</eb:MessageId>
                            <eb:MessageId>msg-injected</eb:MessageId>
                        </eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("strict mode must reject duplicate MessageId");
    assert_eq!(err.code, ErrorCode::InteropViolation);
    assert!(
        err.to_string()
            .contains("AS4 UserMessage contains duplicate MessageId")
    );
}

#[test]
fn rejects_receipt_without_ref_to_message_id() {
    let payload = br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            xmlns:ebbpsig="http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0">
        <S12:Header>
            <eb:Messaging>
                <eb:SignalMessage>
                    <eb:MessageInfo>
                        <eb:MessageId>sig-no-ref</eb:MessageId>
                    </eb:MessageInfo>
                    <eb:Receipt>
                        <ebbpsig:NonRepudiationInformation/>
                    </eb:Receipt>
                </eb:SignalMessage>
            </eb:Messaging>
            <ds:Signature/>
        </S12:Header>
        <S12:Body/>
    </S12:Envelope>"#;

    let err = push(payload).expect_err("receipt without RefToMessageId must reject");
    assert_eq!(err.code, ErrorCode::ParseFailed);
}

#[test]
fn rejects_duplicate_action_in_strict_mode() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-act-dup</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo>
                            <eb:Action>LegitimateAction</eb:Action>
                            <eb:Action>InjectedAction</eb:Action>
                        </eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("strict mode must reject duplicate Action");
    assert_eq!(err.code, ErrorCode::InteropViolation);
    assert!(
        err.to_string()
            .contains("AS4 UserMessage contains duplicate Action")
    );
}

/// ebMS3 §5.2.2.4 allows multiple <eb:PartyId> per party for multi-scheme identifiers.
/// Strict mode MUST accept them; rejection was a conformance bug.
#[test]
fn accepts_multiple_from_party_ids_in_strict_mode() {
    let out = push(&multipart_payload_with_cid(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-from-multi</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From>
                                <eb:PartyId>GLN:1234567890</eb:PartyId>
                                <eb:PartyId>DUNS:987654321</eb:PartyId>
                            </eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
        "body@example.com",
        b"multiple-from-party-id-payload",
    ))
    .expect("ebMS3 §5.2.2.4: multiple From/PartyId must be accepted in strict mode");
    assert_eq!(out.user_message.from_party_id(), "GLN:1234567890");
    assert_eq!(out.user_message.from_party_ids.len(), 2);
    assert_eq!(out.user_message.from_party_ids[1], "DUNS:987654321");
}

/// ebMS3 §5.2.2.4 allows multiple <eb:PartyId> per party for multi-scheme identifiers.
#[test]
fn accepts_multiple_to_party_ids_in_strict_mode() {
    let out = push(&multipart_payload_with_cid(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-to-multi</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To>
                                <eb:PartyId>GLN:9876543210</eb:PartyId>
                                <eb:PartyId>DUNS:123456789</eb:PartyId>
                            </eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
        "body@example.com",
        b"multiple-to-party-id-payload",
    ))
    .expect("ebMS3 §5.2.2.4: multiple To/PartyId must be accepted in strict mode");
    assert_eq!(out.user_message.to_party_id(), "GLN:9876543210");
    assert_eq!(out.user_message.to_party_ids.len(), 2);
    assert_eq!(out.user_message.to_party_ids[1], "DUNS:123456789");
}

#[test]
fn rejects_messaging_must_understand_false_in_strict_mode() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="false">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-mu-false</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("strict mode must reject mustUnderstand=false");
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_duplicate_top_level_messaging_headers_in_strict_mode() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-dupe-a</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-dupe-b</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("strict mode must reject duplicate top-level Messaging headers");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_duplicate_top_level_security_headers_in_strict_mode() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-dupe-sec</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("strict mode must reject duplicate top-level Security headers");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_messaging_with_soap12_next_role_in_strict_mode() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true" S12:role="http://www.w3.org/2003/05/soap-envelope/role/next">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-role-next</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("strict mode must reject intermediary-targeted SOAP role");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_non_targeted_security_header_with_soap12_next_role_in_strict_mode() {
    let err = push(&multipart_payload_with_cid(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-security-next-role</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security S12:role="http://www.w3.org/2003/05/soap-envelope/role/next"/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
        "body@example.com",
        b"security-next-role-payload",
    ))
    .expect_err("strict mode must reject when wsse:Security is not targeted to this receiver");

    assert_eq!(err.code, ErrorCode::ParseFailed);
    assert!(
        err.to_string()
            .contains("AS4 SOAP Header missing wsse:Security")
    );
}

#[test]
fn rejects_non_targeted_security_header_with_custom_soap12_role_in_strict_mode() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-security-custom-role</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security S12:role="urn:partner:role:custom-hop"/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("strict mode must reject when SOAP 1.2 wsse:Security is targeted away from this receiver via custom role");

    assert_eq!(err.code, ErrorCode::ParseFailed);
    assert!(
        err.to_string()
            .contains("AS4 SOAP Header missing wsse:Security")
    );
}

#[test]
fn accepts_targeted_security_when_non_targeted_security_header_is_also_present_in_strict_mode() {
    let out = push(&multipart_payload_with_cid(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-security-mixed-targets</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security S12:role="http://www.w3.org/2003/05/soap-envelope/role/next"/>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
        "body@example.com",
        b"security-mixed-targets-payload",
    ))
    .expect("strict mode should accept a receiver-targeted wsse:Security even when a non-targeted wsse:Security header is present");

    assert_eq!(out.user_message.message_id, "msg-security-mixed-targets");
}

#[test]
fn rejects_non_targeted_security_header_with_soap11_next_actor_in_strict_mode() {
    let err = push(
        br#"<S11:Envelope xmlns:S11="http://schemas.xmlsoap.org/soap/envelope/"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S11:Header>
                <eb:Messaging S11:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-security-soap11-next-actor</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security S11:actor="http://schemas.xmlsoap.org/soap/actor/next"/>
            </S11:Header>
            <S11:Body/>
        </S11:Envelope>"#,
    )
    .expect_err("strict mode must reject when SOAP 1.1 wsse:Security is not targeted to this receiver");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_non_targeted_security_header_with_custom_soap11_actor_in_strict_mode() {
    let err = push(
        br#"<S11:Envelope xmlns:S11="http://schemas.xmlsoap.org/soap/envelope/"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S11:Header>
                <eb:Messaging S11:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-security-custom-actor</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security S11:actor="urn:partner:role:custom-hop"/>
            </S11:Header>
            <S11:Body/>
        </S11:Envelope>"#,
    )
    .expect_err("strict mode must reject when SOAP 1.1 wsse:Security is targeted away from this receiver via custom actor");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_soap11_mixed_security_targets_in_strict_mode() {
    let err = push(&multipart_payload_with_cid(
        br#"<S11:Envelope xmlns:S11="http://schemas.xmlsoap.org/soap/envelope/"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S11:Header>
                <eb:Messaging S11:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-security-soap11-mixed-targets</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security S11:actor="http://schemas.xmlsoap.org/soap/actor/next"/>
                <wsse:Security/>
            </S11:Header>
            <S11:Body/>
        </S11:Envelope>"#,
        "body@example.com",
        b"security-soap11-mixed-targets-payload",
    ))
    .expect_err("strict mode must reject SOAP 1.1 envelopes");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_messaging_with_soap11_actor_in_strict_mode() {
    let err = push(
        br#"<S11:Envelope xmlns:S11="http://schemas.xmlsoap.org/soap/envelope/"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S11:Header>
                <eb:Messaging S11:mustUnderstand="true" S11:actor="http://schemas.xmlsoap.org/soap/actor/next">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-actor-next</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S11:Header>
            <S11:Body/>
        </S11:Envelope>"#,
    )
    .expect_err("strict mode must reject intermediary-targeted SOAP actor");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn accepts_messaging_with_soap12_ultimate_receiver_role_in_strict_mode() {
    let out = push(&multipart_payload_with_cid(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true" S12:role="http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-role-ultimate</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
        "body@example.com",
        b"role-ultimate-payload",
    ))
    .expect("strict mode should accept ultimateReceiver role targeting");

    assert_eq!(out.user_message.message_id, "msg-role-ultimate");
}

#[test]
fn rejects_unknown_mandatory_top_level_header_in_strict_mode() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:ext="urn:partner:ext:v1">
            <S12:Header>
                <ext:PartnerRoutingHint S12:mustUnderstand="true">route-a</ext:PartnerRoutingHint>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-unknown-mandatory</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("strict mode must reject unknown mandatory SOAP header blocks");

    assert_eq!(err.code, ErrorCode::InteropViolation);
    assert!(
        err.to_string()
            .contains("AS4 SOAP Header contains unknown mandatory receiver-targeted block")
    );
}

#[test]
fn accepts_unknown_non_mandatory_top_level_header_in_strict_mode() {
    let out = push(&multipart_payload_with_cid(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:ext="urn:partner:ext:v1">
            <S12:Header>
                <ext:PartnerRoutingHint S12:mustUnderstand="false">route-a</ext:PartnerRoutingHint>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-unknown-optional</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
        "body@example.com",
        b"unknown-optional-header-payload",
    ))
    .expect("strict mode should allow unknown non-mandatory SOAP headers");

    assert_eq!(out.user_message.message_id, "msg-unknown-optional");
}

#[test]
fn accepts_unknown_mandatory_header_targeted_to_soap12_next_in_strict_mode() {
    let out = push(&multipart_payload_with_cid(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:ext="urn:partner:ext:v1">
            <S12:Header>
                <ext:PartnerRoutingHint S12:mustUnderstand="true" S12:role="http://www.w3.org/2003/05/soap-envelope/role/next">route-a</ext:PartnerRoutingHint>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-unknown-next-role</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
        "body@example.com",
        b"unknown-mandatory-next-role-payload",
    ))
    .expect("strict mode should allow unknown mandatory headers targeted to SOAP next role");

    assert_eq!(out.user_message.message_id, "msg-unknown-next-role");
}

#[test]
fn accepts_unknown_mandatory_header_targeted_to_soap12_none_role_in_strict_mode() {
    let out = push(&multipart_payload_with_cid(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:ext="urn:partner:ext:v1">
            <S12:Header>
                <ext:PartnerRoutingHint
                    S12:mustUnderstand="true"
                    S12:role="http://www.w3.org/2003/05/soap-envelope/role/none">route-a</ext:PartnerRoutingHint>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-unknown-none-role</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
        "body@example.com",
        b"unknown-none-role-payload",
    ))
    .expect("strict mode should accept unknown mandatory headers targeted to SOAP 1.2 role/none");

    assert_eq!(out.user_message.message_id, "msg-unknown-none-role");
}

#[test]
fn accepts_unknown_mandatory_header_targeted_to_custom_soap12_role_in_strict_mode() {
    let out = push(&multipart_payload_with_cid(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:ext="urn:partner:ext:v1">
            <S12:Header>
                <ext:PartnerRoutingHint
                    S12:mustUnderstand="true"
                    S12:role="urn:partner:role:custom-hop">route-a</ext:PartnerRoutingHint>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-unknown-custom-role</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
        "body@example.com",
        b"unknown-custom-role-payload",
    ))
    .expect("strict mode should accept unknown mandatory headers with user-defined SOAP 1.2 role targets");

    assert_eq!(out.user_message.message_id, "msg-unknown-custom-role");
}

#[test]
fn rejects_soap11_unknown_mandatory_header_targeted_to_next_actor_in_strict_mode() {
    let err = push(&multipart_payload_with_cid(
        br#"<S11:Envelope xmlns:S11="http://schemas.xmlsoap.org/soap/envelope/"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:ext="urn:partner:ext:v1">
            <S11:Header>
                <ext:PartnerRoutingHint S11:mustUnderstand="true" S11:actor="http://schemas.xmlsoap.org/soap/actor/next">route-a</ext:PartnerRoutingHint>
                <eb:Messaging S11:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-unknown-next-actor</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S11:Header>
            <S11:Body/>
        </S11:Envelope>"#,
        "body@example.com",
        b"unknown-mandatory-next-actor-payload",
    ))
    .expect_err("strict mode must reject SOAP 1.1 envelopes");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_soap11_unknown_mandatory_header_targeted_to_custom_actor_in_strict_mode() {
    let err = push(&multipart_payload_with_cid(
        br#"<S11:Envelope xmlns:S11="http://schemas.xmlsoap.org/soap/envelope/"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:ext="urn:partner:ext:v1">
            <S11:Header>
                <ext:PartnerRoutingHint
                    S11:mustUnderstand="true"
                    S11:actor="urn:partner:role:custom-hop">route-a</ext:PartnerRoutingHint>
                <eb:Messaging S11:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-unknown-custom-actor</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S11:Header>
            <S11:Body/>
        </S11:Envelope>"#,
        "body@example.com",
        b"unknown-custom-actor-payload",
    ))
    .expect_err("strict mode must reject SOAP 1.1 envelopes");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_unknown_mandatory_header_targeted_to_soap12_ultimate_receiver_in_strict_mode() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:ext="urn:partner:ext:v1">
            <S12:Header>
                <ext:PartnerRoutingHint
                    S12:mustUnderstand="true"
                    S12:role="http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver">route-a</ext:PartnerRoutingHint>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-unknown-ultimate</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("strict mode must reject unknown mandatory headers targeted at ultimateReceiver");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_unknown_mandatory_header_with_empty_soap11_actor_in_strict_mode() {
    let err = push(
        br#"<S11:Envelope xmlns:S11="http://schemas.xmlsoap.org/soap/envelope/"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:ext="urn:partner:ext:v1">
            <S11:Header>
                <ext:PartnerRoutingHint
                    S11:mustUnderstand="true"
                    S11:actor="">route-a</ext:PartnerRoutingHint>
                <eb:Messaging S11:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-unknown-empty-actor</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S11:Header>
            <S11:Body/>
        </S11:Envelope>"#,
    )
    .expect_err("strict mode must reject unknown mandatory headers targeted to receiver via empty SOAP actor");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_unknown_mandatory_header_after_messaging_in_strict_mode() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:ext="urn:partner:ext:v1">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-unknown-post-messaging</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
                <ext:PartnerRoutingHint S12:mustUnderstand="true">route-z</ext:PartnerRoutingHint>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("strict mode must reject unknown mandatory headers regardless of top-level header order");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_messaging_with_invalid_must_understand_token_in_strict_mode() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="yes">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-invalid-mu-messaging</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("strict mode must reject invalid mustUnderstand token on Messaging");

    assert_eq!(err.code, ErrorCode::InteropViolation);
    assert!(
        err.to_string()
            .contains("AS4 eb:Messaging has invalid SOAP mustUnderstand token")
    );
}

#[test]
fn rejects_unknown_header_with_invalid_must_understand_token_in_strict_mode() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:ext="urn:partner:ext:v1">
            <S12:Header>
                <ext:PartnerRoutingHint S12:mustUnderstand="maybe">route-invalid</ext:PartnerRoutingHint>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-invalid-mu-unknown</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("strict mode must reject invalid mustUnderstand token on top-level extension headers");

    assert_eq!(err.code, ErrorCode::InteropViolation);
    assert!(
        err.to_string()
            .contains("AS4 SOAP Header block has invalid SOAP mustUnderstand token")
    );
}

#[test]
fn rejects_messaging_with_unqualified_must_understand_in_strict_mode() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-unqualified-mu</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("strict mode must reject non-SOAP mustUnderstand on Messaging");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn accepts_unknown_header_with_unqualified_must_understand_in_strict_mode() {
    let out = push(&multipart_payload_with_cid(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:ext="urn:partner:ext:v1">
            <S12:Header>
                <ext:PartnerRoutingHint mustUnderstand="true">route-unqualified</ext:PartnerRoutingHint>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-unknown-unqualified-mu</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
        "body@example.com",
        b"unqualified-mu-on-extension-is-non-soap",
    ))
    .expect("strict mode should ignore non-SOAP mustUnderstand on unknown headers");

    assert_eq!(out.user_message.message_id, "msg-unknown-unqualified-mu");
}

#[test]
fn rejects_security_header_with_invalid_must_understand_token_in_strict_mode() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-security-invalid-mu</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security S12:mustUnderstand="maybe"/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("strict mode must reject invalid SOAP mustUnderstand on wsse:Security");

    assert_eq!(err.code, ErrorCode::InteropViolation);
    assert!(
        err.to_string()
            .contains("AS4 SOAP Header block has invalid SOAP mustUnderstand token")
    );
}

#[test]
fn accepts_messaging_with_custom_soap_prefix_must_understand_in_strict_mode() {
    let out = push(&multipart_payload_with_cid(
        br#"<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <env:Header>
                <eb:Messaging env:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-custom-soap-prefix</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </env:Header>
            <env:Body/>
        </env:Envelope>"#,
        "body@example.com",
        b"custom-soap-prefix-payload",
    ))
    .expect("strict mode should accept SOAP mustUnderstand with non-default SOAP prefix");

    assert_eq!(out.user_message.message_id, "msg-custom-soap-prefix");
}

#[test]
fn accepts_messaging_with_header_scoped_soap_prefix_in_strict_mode() {
    let out = push(&multipart_payload_with_cid(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header xmlns:h12="http://www.w3.org/2003/05/soap-envelope">
                <eb:Messaging h12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-header-scope-prefix</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
        "body@example.com",
        b"header-scoped-soap-prefix-payload",
    ))
    .expect("strict mode should accept SOAP mustUnderstand from header-scoped SOAP prefix");

    assert_eq!(out.user_message.message_id, "msg-header-scope-prefix");
}

#[test]
fn rejects_unknown_mandatory_receiver_header_among_multi_hop_extensions_in_strict_mode() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:ext="urn:partner:ext:v2">
            <S12:Header xmlns:h12="http://www.w3.org/2003/05/soap-envelope">
                <ext:HopOneHint h12:mustUnderstand="true" h12:role="http://www.w3.org/2003/05/soap-envelope/role/next">hop1</ext:HopOneHint>
                <ext:ReceiverHint h12:mustUnderstand="true" h12:role="http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver">recv</ext:ReceiverHint>
                <ext:HopTwoHint h12:mustUnderstand="true" h12:role="http://www.w3.org/2003/05/soap-envelope/role/next">hop2</ext:HopTwoHint>
                <eb:Messaging h12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-multi-hop-receiver</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("strict mode must reject any mandatory unknown receiver-targeted header even with intermediary-targeted neighbors");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn accepts_multi_hop_intermediary_mandatory_headers_with_header_scoped_soap_prefix_in_strict_mode()
{
    let out = push(&multipart_payload_with_cid(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:ext="urn:partner:ext:v2">
            <S12:Header xmlns:h12="http://www.w3.org/2003/05/soap-envelope">
                <ext:HopOneHint h12:mustUnderstand="true" h12:role="http://www.w3.org/2003/05/soap-envelope/role/next">hop1</ext:HopOneHint>
                <ext:HopTwoHint h12:mustUnderstand="true" h12:role="http://www.w3.org/2003/05/soap-envelope/role/next">hop2</ext:HopTwoHint>
                <eb:Messaging h12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-multi-hop-next-only</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
        "body@example.com",
        b"multi-hop-next-only-payload",
    ))
    .expect("strict mode should accept mandatory unknown headers that are all intermediary-targeted");

    assert_eq!(out.user_message.message_id, "msg-multi-hop-next-only");
}

#[test]
fn accepts_composite_multi_hop_extensions_and_mixed_wsse_targets_in_strict_mode() {
    let out = push(&multipart_payload_with_cid(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:ext="urn:partner:ext:v4">
            <S12:Header xmlns:h12="http://www.w3.org/2003/05/soap-envelope">
                <ext:HopHintOne h12:mustUnderstand="true" h12:role="http://www.w3.org/2003/05/soap-envelope/role/next">hop1</ext:HopHintOne>
                <ext:HopHintTwo h12:mustUnderstand="true" h12:role="urn:partner:hop:security-gateway">hop2</ext:HopHintTwo>
                <eb:Messaging h12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-composite-multi-hop-wsse</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security h12:role="http://www.w3.org/2003/05/soap-envelope/role/next"/>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
        "body@example.com",
        b"composite-multi-hop-wsse-payload",
    ))
    .expect("strict mode should accept intermediary-targeted mandatory extensions when a receiver-targeted wsse:Security is present");

    assert_eq!(out.user_message.message_id, "msg-composite-multi-hop-wsse");
}

#[test]
fn rejects_receiver_targeted_partner_extension_even_with_valid_mixed_wsse_targets_in_strict_mode() {
    let err = push(&multipart_payload_with_cid(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:ext="urn:partner:ext:v4">
            <S12:Header xmlns:h12="http://www.w3.org/2003/05/soap-envelope">
                <ext:HopHint h12:mustUnderstand="true" h12:role="http://www.w3.org/2003/05/soap-envelope/role/next">hop</ext:HopHint>
                <ext:ReceiverHint h12:mustUnderstand="true" h12:role="http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver">recv</ext:ReceiverHint>
                <eb:Messaging h12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-composite-receiver-extension</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security h12:role="http://www.w3.org/2003/05/soap-envelope/role/next"/>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
        "body@example.com",
        b"composite-receiver-extension-payload",
    ))
    .expect_err("strict mode must reject receiver-targeted mandatory unknown extension headers even when wsse targeting is otherwise valid");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_soap11_composite_intermediary_extensions_in_strict_mode() {
    let err = push(&multipart_payload_with_cid(
        br#"<S11:Envelope xmlns:S11="http://schemas.xmlsoap.org/soap/envelope/"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:ext="urn:partner:ext:v4">
            <S11:Header xmlns:h11="http://schemas.xmlsoap.org/soap/envelope/">
                <ext:HopHintOne h11:mustUnderstand="1" h11:actor="http://schemas.xmlsoap.org/soap/actor/next">hop1</ext:HopHintOne>
                <ext:HopHintTwo h11:mustUnderstand="1" h11:actor="urn:partner:hop:security-gateway">hop2</ext:HopHintTwo>
                <eb:Messaging h11:mustUnderstand="1">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-soap11-composite-multi-hop-wsse</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security h11:actor="http://schemas.xmlsoap.org/soap/actor/next"/>
                <wsse:Security/>
            </S11:Header>
            <S11:Body/>
        </S11:Envelope>"#,
        "body@example.com",
        b"soap11-composite-multi-hop-wsse-payload",
    ))
    .expect_err("strict mode must reject SOAP 1.1 envelopes");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_messaging_with_element_local_shadowed_soap_prefix_in_strict_mode() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging xmlns:S12="urn:attacker:shadow" S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-shadowed-soap-prefix</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("strict mode must reject Messaging when mustUnderstand uses element-local non-SOAP shadowed prefix");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn accepts_unknown_header_with_element_local_shadowed_soap_prefix_in_strict_mode() {
    let out = push(&multipart_payload_with_cid(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:ext="urn:partner:ext:v3">
            <S12:Header>
                <ext:PartnerRoutingHint xmlns:S12="urn:attacker:shadow" S12:mustUnderstand="true">shadowed</ext:PartnerRoutingHint>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-shadowed-extension-prefix</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
        "body@example.com",
        b"shadowed-extension-prefix-payload",
    ))
    .expect("strict mode should ignore non-SOAP shadowed mustUnderstand on unknown header");

    assert_eq!(out.user_message.message_id, "msg-shadowed-extension-prefix");
}

#[test]
fn rejects_peppol_profile_mandatory_receiver_extension_header_in_strict_mode() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:pp="urn:fdc:peppol.eu:transport:as4:profile:2.0">
            <S12:Header>
                <pp:PeppolRoutingHint
                    S12:mustUnderstand="true"
                    S12:role="http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver">peppol-route</pp:PeppolRoutingHint>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-peppol-receiver-ext</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("strict mode must reject unknown mandatory Peppol extension headers targeted to receiver");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn accepts_peppol_profile_mandatory_intermediary_extension_header_in_strict_mode() {
    let out = push(&multipart_payload_with_cid(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:pp="urn:fdc:peppol.eu:transport:as4:profile:2.0">
            <S12:Header>
                <pp:PeppolRoutingHint
                    S12:mustUnderstand="true"
                    S12:role="http://www.w3.org/2003/05/soap-envelope/role/next">peppol-next</pp:PeppolRoutingHint>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-peppol-next-ext</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
        "body@example.com",
        b"peppol-intermediary-extension-payload",
    ))
    .expect("strict mode should accept intermediary-targeted mandatory Peppol extension headers");

    assert_eq!(out.user_message.message_id, "msg-peppol-next-ext");
}

#[test]
fn rejects_edelivery_profile_mandatory_receiver_extension_header_in_strict_mode() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:edel="urn:eu:edelivery:profile:as4:1.15">
            <S12:Header>
                <edel:ConformanceMarker S12:mustUnderstand="true">edelivery-marker</edel:ConformanceMarker>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-edelivery-receiver-ext</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("strict mode must reject unknown mandatory eDelivery extension headers when receiver-targeted by default");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_peppol_profile_mandatory_soap11_next_actor_extension_header_in_strict_mode() {
    let err = push(&multipart_payload_with_cid(
        br#"<S11:Envelope xmlns:S11="http://schemas.xmlsoap.org/soap/envelope/"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:pp="urn:fdc:peppol.eu:transport:as4:profile:2.0">
            <S11:Header>
                <pp:PeppolRoutingHint S11:mustUnderstand="1" S11:actor="http://schemas.xmlsoap.org/soap/actor/next">pp-next</pp:PeppolRoutingHint>
                <eb:Messaging S11:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-peppol-soap11-next</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S11:Header>
            <S11:Body/>
        </S11:Envelope>"#,
        "body@example.com",
        b"peppol-soap11-next-actor-payload",
    ))
    .expect_err("strict mode must reject SOAP 1.1 envelopes");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_peppol_profile_mandatory_soap11_empty_actor_extension_header_in_strict_mode() {
    let err = push(
        br#"<S11:Envelope xmlns:S11="http://schemas.xmlsoap.org/soap/envelope/"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:pp="urn:fdc:peppol.eu:transport:as4:profile:2.0">
            <S11:Header>
                <pp:PeppolRoutingHint S11:mustUnderstand="true" S11:actor="">pp-empty</pp:PeppolRoutingHint>
                <eb:Messaging S11:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-peppol-soap11-empty-actor</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S11:Header>
            <S11:Body/>
        </S11:Envelope>"#,
    )
    .expect_err("strict mode must reject SOAP 1.1 receiver-targeted mandatory Peppol extension headers via empty actor");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_edelivery_profile_mandatory_soap11_empty_actor_extension_header_in_strict_mode() {
    let err = push(
        br#"<S11:Envelope xmlns:S11="http://schemas.xmlsoap.org/soap/envelope/"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:edel="urn:eu:edelivery:profile:as4:1.15">
            <S11:Header>
                <edel:ConformanceMarker S11:mustUnderstand="1" S11:actor="">edel-empty</edel:ConformanceMarker>
                <eb:Messaging S11:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-edel-soap11-empty-actor</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S11:Header>
            <S11:Body/>
        </S11:Envelope>"#,
    )
    .expect_err("strict mode must reject SOAP 1.1 receiver-targeted mandatory eDelivery extension headers via empty actor");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_soap11_unknown_mandatory_header_with_header_scoped_prefix_in_strict_mode() {
    let err = push(&multipart_payload_with_cid(
        br#"<S11:Envelope xmlns:S11="http://schemas.xmlsoap.org/soap/envelope/"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:ext="urn:partner:ext:soap11:v1">
            <S11:Header xmlns:h11="http://schemas.xmlsoap.org/soap/envelope/">
                <ext:Soap11HopHint h11:mustUnderstand="true" h11:actor="http://schemas.xmlsoap.org/soap/actor/next">hop</ext:Soap11HopHint>
                <eb:Messaging h11:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-soap11-header-scope-next</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S11:Header>
            <S11:Body/>
        </S11:Envelope>"#,
        "body@example.com",
        b"soap11-header-scope-next-actor-payload",
    ))
    .expect_err("strict mode must reject SOAP 1.1 envelopes");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_unknown_mandatory_header_targeted_to_soap11_receiver_with_header_scoped_prefix_in_strict_mode()
 {
    let err = push(
        br#"<S11:Envelope xmlns:S11="http://schemas.xmlsoap.org/soap/envelope/"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:ext="urn:partner:ext:soap11:v1">
            <S11:Header xmlns:h11="http://schemas.xmlsoap.org/soap/envelope/">
                <ext:Soap11ReceiverHint h11:mustUnderstand="1" h11:actor="">recv</ext:Soap11ReceiverHint>
                <eb:Messaging h11:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-soap11-header-scope-recv</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S11:Header>
            <S11:Body/>
        </S11:Envelope>"#,
    )
    .expect_err("strict mode must reject SOAP 1.1 receiver-targeted unknown mandatory header with header-scoped SOAP prefix");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_messaging_with_shadowed_soap11_prefix_must_understand_in_strict_mode() {
    let err = push(
        br#"<S11:Envelope xmlns:S11="http://schemas.xmlsoap.org/soap/envelope/"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S11:Header>
                <eb:Messaging xmlns:S11="urn:attacker:shadow:soap11" S11:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-shadowed-soap11-mu</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S11:Header>
            <S11:Body/>
        </S11:Envelope>"#,
    )
    .expect_err("strict mode must reject Messaging when SOAP 1.1 mustUnderstand uses element-local shadowed prefix");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn accepts_messaging_must_understand_numeric_one_in_strict_mode() {
    let out = push(&multipart_payload_with_cid(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="1">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-mu-one</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
        "body@example.com",
        b"must-understand-one-payload",
    ))
    .expect("strict mode should accept mustUnderstand=1");

    assert_eq!(out.user_message.message_id, "msg-mu-one");
}

#[test]
fn rejects_soap11_envelope_wire_shape() {
    let err = push(&multipart_payload_with_cid(
        br#"<S11:Envelope xmlns:S11="http://schemas.xmlsoap.org/soap/envelope/"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S11:Header>
                <eb:Messaging S11:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-soap11</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S11:Header>
            <S11:Body/>
        </S11:Envelope>"#,
        "body@example.com",
        b"soap11-wire-shape-payload",
    ))
    .expect_err("SOAP 1.1 envelope wire-shape must be rejected");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_unsigned_receipt_when_signed_receipt_required() {
    let payload = br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
            xmlns:ebbpsig="http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0">
        <S12:Header>
            <eb:Messaging>
                <eb:SignalMessage>
                    <eb:MessageInfo>
                        <eb:MessageId>sig-unsigned</eb:MessageId>
                        <eb:RefToMessageId>msg-1</eb:RefToMessageId>
                    </eb:MessageInfo>
                    <eb:Receipt>
                        <ebbpsig:NonRepudiationInformation/>
                    </eb:Receipt>
                </eb:SignalMessage>
            </eb:Messaging>
        </S12:Header>
        <S12:Body/>
    </S12:Envelope>"#;

    let err = push(payload).expect_err("unsigned receipt must reject");
    assert_eq!(err.code, ErrorCode::ParseFailed);
}

#[test]
fn rejects_security_element_outside_soap_header() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-no-header-security</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
            </S12:Header>
            <S12:Body>
                <wsse:Security/>
            </S12:Body>
        </S12:Envelope>"#,
    )
    .expect_err("security in body must not satisfy strict header requirement");
    assert_eq!(err.code, ErrorCode::ParseFailed);
    assert!(
        err.to_string()
            .contains("AS4 SOAP Header missing wsse:Security")
    );
}

#[test]
fn rejects_messaging_usermessage_outside_soap_header() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <wsse:Security/>
            </S12:Header>
            <S12:Body>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-body-messaging</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
            </S12:Body>
        </S12:Envelope>"#,
    )
    .expect_err("messaging in body must not satisfy required header structure");
    assert_eq!(err.code, ErrorCode::ParseFailed);
}

#[test]
fn rejects_fake_namespace_messaging_in_soap_header() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:x="urn:attacker:fake"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <x:Messaging S12:mustUnderstand="true">
                    <x:UserMessage>
                        <x:MessageInfo><x:MessageId>msg-fake-messaging</x:MessageId></x:MessageInfo>
                        <x:PartyInfo>
                            <x:From><x:PartyId>A</x:PartyId></x:From>
                            <x:To><x:PartyId>B</x:PartyId></x:To>
                        </x:PartyInfo>
                        <x:CollaborationInfo><x:Action>Act</x:Action></x:CollaborationInfo>
                    </x:UserMessage>
                </x:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("fake namespace messaging must not satisfy ebMS structure");
    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn rejects_fake_namespace_security_header() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:x="urn:attacker:fake">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-fake-security</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <x:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("fake namespace security header must not satisfy wsse requirement");
    assert_eq!(err.code, ErrorCode::ParseFailed);
    assert!(
        err.to_string()
            .contains("AS4 SOAP Header missing wsse:Security")
    );
}

#[test]
fn rejects_usermessage_with_mpc_missing_uri_scheme() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage mpc="not-a-uri">
                        <eb:MessageInfo><eb:MessageId>msg-invalid-mpc</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("strict mode must reject mpc without URI scheme");
    assert_eq!(err.code, ErrorCode::InteropViolation);
    assert!(
        err.to_string()
            .contains("AS4 UserMessage mpc must be a valid URI")
    );
}

#[test]
fn rejects_usermessage_with_mpc_containing_whitespace() {
    let err = push(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage mpc="http://example.com/invalid mpc">
                        <eb:MessageInfo><eb:MessageId>msg-invalid-mpc-space</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    )
    .expect_err("strict mode must reject mpc with whitespace");
    assert_eq!(err.code, ErrorCode::InteropViolation);
    assert!(
        err.to_string()
            .contains("AS4 UserMessage mpc must be a valid URI")
    );
}

#[test]
fn rejects_push_with_tampered_ds_signature_structure() {
    let payload = br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
            xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <S12:Header>
            <eb:Messaging S12:mustUnderstand="true">
                <eb:UserMessage>
                    <eb:MessageInfo><eb:MessageId>msg-bad-ds</eb:MessageId></eb:MessageInfo>
                    <eb:PartyInfo>
                        <eb:From><eb:PartyId>A</eb:PartyId></eb:From>
                        <eb:To><eb:PartyId>B</eb:PartyId></eb:To>
                    </eb:PartyInfo>
                    <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                </eb:UserMessage>
            </eb:Messaging>
            <wsse:Security>
                <ds:Signature>
                    <ds:SignatureValue>AAAA</ds:SignatureValue>
                </ds:Signature>
            </wsse:Security>
        </S12:Header>
        <S12:Body/>
    </S12:Envelope>"#;

    let err = push_signed_required(payload)
        .expect_err("tampered ds:Signature structure must fail cryptographic verification");
    assert_eq!(err.code, ErrorCode::ParseFailed);
}

#[test]
fn rejects_receipt_namespace_confusion_with_fake_receipt_element() {
    let bus = bus();
    let _events = bus.subscribe_scoped_events();
    let payload = multipart_payload_with_cid(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-push-1</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>sender-a</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>receiver-b</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo>
                            <eb:Action>SubmitOrder</eb:Action>
                            <eb:ConversationId>conv-44</eb:ConversationId>
                        </eb:CollaborationInfo>
                        <eb:PayloadInfo>
                            <eb:PartInfo href="cid:body@example.com"/>
                        </eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security>
                    <wsse:BinarySecurityToken>stub</wsse:BinarySecurityToken>
                </wsse:Security>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
        "body@example.com",
        b"receipt-namespace-confusion-payload",
    );
    let fake_ns_receipt = br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
            xmlns:x="urn:attacker:fake"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <S12:Header>
            <eb:Messaging>
                <eb:SignalMessage>
                    <eb:MessageInfo>
                        <eb:RefToMessageId>msg-push-1</eb:RefToMessageId>
                    </eb:MessageInfo>
                    <x:Receipt>
                        <x:NonRepudiationInformation/>
                    </x:Receipt>
                </eb:SignalMessage>
            </eb:Messaging>
            <ds:Signature>
                <ds:SignatureValue>AAAA</ds:SignatureValue>
            </ds:Signature>
        </S12:Header>
        <S12:Body/>
    </S12:Envelope>"#;

    let err = receive_push_with_dedup_sync(
        &session(),
        &bus,
        As4ReceivePushSyncRequest {
            request: As4ReceivePushRequest {
                http_content_type: content_type_for_payload(&payload),
                payload: payload.into(),
                receipt_payload: Some(fake_ns_receipt.to_vec()),
                policy: as4_unsigned_push_policy(),
                authenticated_sender_scope: None,
            },
            dedup_backend: &dedup(),
        },
    )
    .expect_err("namespace-confused receipt must be rejected");

    assert_eq!(err.code, ErrorCode::ParseFailed);
}
