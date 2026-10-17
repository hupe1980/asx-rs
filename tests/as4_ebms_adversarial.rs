#![cfg(feature = "as4")]
//! Adversarial SOAP/ebMS corpus against `As4::inbound`.
//!
//! Every envelope is posted to a real [`asx::Inbound`] and judged by the
//! response table: the HTTP status, the `eb:Error`
//! code and, where the case names one, the refusal reason, with the
//! handler never called. Structural, encoding and semantic edge cases follow
//! ebMS 3.0 §5, SOAP 1.2 and XML 1.0. The hand-crafted envelopes are unsigned
//! and wrapped as SwA, so the parser judges them before any signature is
//! looked at (`structurally_valid_unsigned_envelope_is_refused_as_unsigned`
//! is the control). The *accepted* variants, and the signature-wrapping and
//! ambiguity cases, mutate a genuine signed and encrypted message
//! captured from `As4::send`; a mutation of signed content is re-signed with
//! the sender's key, so the verdict is about the shape alone. Receipt cases
//! are in `as4_receipt_verification.rs`.

#[path = "common/inbound_harness.rs"]
mod inbound_harness;
#[path = "common/peers.rs"]
mod peers;

use inbound_harness::{Answer, Genuine, Receiver, genuine, header_first, messaging, request, swa};
use peers::{Preset, pair};

fn detect_multipart_boundary(payload: &[u8]) -> Option<String> {
    if !payload.starts_with(b"--") {
        return None;
    }
    let line_end = payload.windows(2).position(|window| window == b"\r\n")?;
    let boundary = std::str::from_utf8(&payload[2..line_end]).ok()?.trim();
    (!boundary.is_empty()).then(|| boundary.to_string())
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

/// Post a crafted envelope (SwA-wrapped unless it already is multipart) to
/// an eDelivery receiver. It must be refused with HTTP 400 and must not reach
/// the handler; the caller checks the code and reason.
async fn refused(payload: impl AsRef<[u8]>, why: &str) -> Answer {
    let payload = payload.as_ref();
    let request = match detect_multipart_boundary(payload) {
        Some(boundary) => request(
            &format!("multipart/related; boundary=\"{boundary}\"; type=\"application/soap+xml\""),
            payload.to_vec(),
        ),
        None => {
            let xml = match std::str::from_utf8(payload) {
                Ok(xml) => ensure_required_strict_properties_in_xml(xml).into_bytes(),
                Err(_) => payload.to_vec(),
            };
            swa(&xml)
        }
    };
    let p = pair(Preset::Edelivery);
    let receiver = Receiver::of(&p);
    let answer = receiver.post(request).await;
    assert_eq!(
        answer.status,
        http::StatusCode::BAD_REQUEST,
        "{why}: {answer:?}"
    );
    receiver.assert_not_delivered();
    answer
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

#[tokio::test]
async fn rejects_completely_malformed_xml() {
    let answer = refused(b"not xml at all <<< >>>", "must reject").await;
    answer.assert_refused_because("EBMS:0004", "XML is not well-formed");
}

#[tokio::test]
async fn rejects_empty_xml_document() {
    let answer = refused(b"", "empty must reject").await;
    answer.assert_refused_because("EBMS:0004", "XML is not well-formed");
}

#[tokio::test]
async fn rejects_soap_envelope_without_header() {
    // SOAP envelope with Body but no Header → missing required structure.
    let answer = refused(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Body/>
        </S12:Envelope>"#,
    "no Header must reject",
    )
    .await;
    answer.assert_refused_because("EBMS:0004", "AS4 SOAP Envelope missing Header");
}

#[tokio::test]
async fn rejects_soap_envelope_without_body() {
    let answer = refused(
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
    "no Body must reject",
    )
    .await;
    answer.assert_refused_because("EBMS:0004", "AS4 SOAP Envelope missing Body");
}

#[tokio::test]
async fn rejects_soap_envelope_without_messaging_element() {
    let answer = refused(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
    "no eb:Messaging must reject",
    )
    .await;
    answer.assert_refused_because("EBMS:0004", "AS4 SOAP Header missing eb:Messaging");
}

#[tokio::test]
async fn rejects_messaging_without_user_message() {
    // eb:Messaging present but contains no eb:UserMessage.
    let answer = refused(
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
    "no UserMessage must reject",
    )
    .await;
    answer.assert_refused_because("EBMS:0004", "AS4 eb:Messaging missing UserMessage");
}

// ── Required field validation ────────────────────────────────────────────────

#[tokio::test]
async fn rejects_user_message_without_message_id() {
    let answer = refused(
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
    "missing MessageId must reject",
    )
    .await;
    answer.assert_refused_because("EBMS:0004", "AS4 UserMessage missing MessageId");
}

#[tokio::test]
async fn rejects_user_message_without_action() {
    let answer = refused(
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
    "missing Action must reject",
    )
    .await;
    answer.assert_refused_because("EBMS:0004", "AS4 UserMessage missing Action");
}

#[tokio::test]
async fn rejects_user_message_without_from_party_id() {
    let answer = refused(
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
    "missing From/PartyId must reject",
    )
    .await;
    answer.assert_refused_because("EBMS:0004", "AS4 UserMessage missing From/PartyId");
}

#[tokio::test]
async fn rejects_user_message_without_to_party_id() {
    let answer = refused(
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
    "missing To/PartyId must reject",
    )
    .await;
    answer.assert_refused_because("EBMS:0004", "AS4 UserMessage missing To/PartyId");
}

// ── Encoding / injection resilience ─────────────────────────────────────────

#[tokio::test]
async fn rejects_non_utf8_payload() {
    // 0xFF bytes are invalid in UTF-8 and must not be silently decoded.
    let mut payload =
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope">"#.to_vec();
    payload.push(0xFF);
    payload.extend_from_slice(b"</S12:Envelope>");
    let answer = refused(&payload, "non-UTF-8 must reject").await;
    answer.assert_refused_because("EBMS:0004", "as4_receive_push: payload is not valid UTF-8");
}

#[tokio::test]
async fn rejects_duplicate_message_id_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject duplicate MessageId",
    )
    .await;
    answer.assert_refused_because("EBMS:0004", "AS4 UserMessage contains duplicate MessageId");
}

#[tokio::test]
async fn rejects_receipt_without_ref_to_message_id() {
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

    let answer = refused(payload, "receipt without RefToMessageId must reject").await;
    answer.assert_refused_because("EBMS:0004", "AS4 eb:Messaging missing UserMessage");
}

#[tokio::test]
async fn rejects_duplicate_action_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject duplicate Action",
    )
    .await;
    answer.assert_refused_because("EBMS:0004", "AS4 UserMessage contains duplicate Action");
}

/// ebMS3 §5.2.2.4 allows multiple <eb:PartyId> per party for multi-scheme identifiers.
/// Strict mode MUST accept them; rejection was a conformance bug.
/// ebMS3 §5.2.2.4 allows multiple <eb:PartyId> per party for multi-scheme identifiers.
#[tokio::test]
async fn rejects_messaging_must_understand_false_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject mustUnderstand=false",
    )
    .await;
    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 eb:Messaging must set SOAP mustUnderstand=true",
    );
}

#[tokio::test]
async fn rejects_duplicate_top_level_messaging_headers_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject duplicate top-level Messaging headers",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 SOAP Header contains duplicate eb:Messaging blocks",
    );
}

#[tokio::test]
async fn rejects_duplicate_top_level_security_headers_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject duplicate top-level Security headers",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 SOAP Header contains duplicate receiver-targeted wsse:Security blocks",
    );
}

#[tokio::test]
async fn rejects_messaging_with_soap12_next_role_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject intermediary-targeted SOAP role",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 eb:Messaging SOAP targeting must resolve to receiver role",
    );
}

#[tokio::test]
async fn rejects_non_targeted_security_header_with_soap12_next_role_in_strict_mode() {
    let answer = refused(&multipart_payload_with_cid(
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
    ), "strict mode must reject when wsse:Security is not targeted to this receiver").await;

    answer.assert_refused_because("EBMS:0004", "AS4 SOAP Header missing wsse:Security");
}

#[tokio::test]
async fn rejects_non_targeted_security_header_with_custom_soap12_role_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject when SOAP 1.2 wsse:Security is targeted away from this receiver via custom role",
    )
    .await;

    answer.assert_refused_because("EBMS:0004", "AS4 SOAP Header missing wsse:Security");
}

#[tokio::test]
async fn rejects_non_targeted_security_header_with_soap11_next_actor_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject when SOAP 1.1 wsse:Security is not targeted to this receiver",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 policy requires SOAP 1.2 envelope namespace",
    );
}

#[tokio::test]
async fn rejects_non_targeted_security_header_with_custom_soap11_actor_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject when SOAP 1.1 wsse:Security is targeted away from this receiver via custom actor",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 policy requires SOAP 1.2 envelope namespace",
    );
}

#[tokio::test]
async fn rejects_soap11_mixed_security_targets_in_strict_mode() {
    let answer = refused(&multipart_payload_with_cid(
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
    ), "strict mode must reject SOAP 1.1 envelopes").await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 policy requires SOAP 1.2 envelope namespace",
    );
}

#[tokio::test]
async fn rejects_messaging_with_soap11_actor_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject intermediary-targeted SOAP actor",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 policy requires SOAP 1.2 envelope namespace",
    );
}

#[tokio::test]
async fn rejects_unknown_mandatory_top_level_header_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject unknown mandatory SOAP header blocks",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 SOAP Header contains unknown mandatory receiver-targeted block",
    );
}

#[tokio::test]
async fn rejects_soap11_unknown_mandatory_header_targeted_to_next_actor_in_strict_mode() {
    let answer = refused(&multipart_payload_with_cid(
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
    ), "strict mode must reject SOAP 1.1 envelopes").await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 policy requires SOAP 1.2 envelope namespace",
    );
}

#[tokio::test]
async fn rejects_soap11_unknown_mandatory_header_targeted_to_custom_actor_in_strict_mode() {
    let answer = refused(&multipart_payload_with_cid(
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
    ), "strict mode must reject SOAP 1.1 envelopes").await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 policy requires SOAP 1.2 envelope namespace",
    );
}

#[tokio::test]
async fn rejects_unknown_mandatory_header_targeted_to_soap12_ultimate_receiver_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject unknown mandatory headers targeted at ultimateReceiver",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 SOAP Header contains unknown mandatory receiver-targeted block",
    );
}

#[tokio::test]
async fn rejects_unknown_mandatory_header_with_empty_soap11_actor_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject unknown mandatory headers targeted to receiver via empty SOAP actor",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 policy requires SOAP 1.2 envelope namespace",
    );
}

#[tokio::test]
async fn rejects_unknown_mandatory_header_after_messaging_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject unknown mandatory headers regardless of top-level header order",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 SOAP Header contains unknown mandatory receiver-targeted block",
    );
}

#[tokio::test]
async fn rejects_messaging_with_invalid_must_understand_token_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject invalid mustUnderstand token on Messaging",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 eb:Messaging has invalid SOAP mustUnderstand token",
    );
}

#[tokio::test]
async fn rejects_unknown_header_with_invalid_must_understand_token_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject invalid mustUnderstand token on top-level extension headers",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 SOAP Header block has invalid SOAP mustUnderstand token",
    );
}

#[tokio::test]
async fn rejects_messaging_with_unqualified_must_understand_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject non-SOAP mustUnderstand on Messaging",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 eb:Messaging must set SOAP mustUnderstand=true",
    );
}

#[tokio::test]
async fn rejects_security_header_with_invalid_must_understand_token_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject invalid SOAP mustUnderstand on wsse:Security",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 SOAP Header block has invalid SOAP mustUnderstand token",
    );
}

#[tokio::test]
async fn rejects_unknown_mandatory_receiver_header_among_multi_hop_extensions_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject any mandatory unknown receiver-targeted header even with intermediary-targeted neighbors",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 SOAP Header contains unknown mandatory receiver-targeted block",
    );
}

#[tokio::test]
async fn rejects_receiver_targeted_partner_extension_even_with_valid_mixed_wsse_targets_in_strict_mode()
 {
    let answer = refused(&multipart_payload_with_cid(
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
    ), "strict mode must reject receiver-targeted mandatory unknown extension headers even when wsse targeting is otherwise valid").await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 SOAP Header contains unknown mandatory receiver-targeted block",
    );
}

#[tokio::test]
async fn rejects_soap11_composite_intermediary_extensions_in_strict_mode() {
    let answer = refused(&multipart_payload_with_cid(
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
    ), "strict mode must reject SOAP 1.1 envelopes").await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 policy requires SOAP 1.2 envelope namespace",
    );
}

#[tokio::test]
async fn rejects_messaging_with_element_local_shadowed_soap_prefix_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject Messaging when mustUnderstand uses element-local non-SOAP shadowed prefix",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 eb:Messaging must set SOAP mustUnderstand=true",
    );
}

#[tokio::test]
async fn rejects_peppol_profile_mandatory_receiver_extension_header_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject unknown mandatory Peppol extension headers targeted to receiver",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 SOAP Header contains unknown mandatory receiver-targeted block",
    );
}

#[tokio::test]
async fn rejects_edelivery_profile_mandatory_receiver_extension_header_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject unknown mandatory eDelivery extension headers when receiver-targeted by default",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 SOAP Header contains unknown mandatory receiver-targeted block",
    );
}

#[tokio::test]
async fn rejects_peppol_profile_mandatory_soap11_next_actor_extension_header_in_strict_mode() {
    let answer = refused(&multipart_payload_with_cid(
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
    ), "strict mode must reject SOAP 1.1 envelopes").await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 policy requires SOAP 1.2 envelope namespace",
    );
}

#[tokio::test]
async fn rejects_peppol_profile_mandatory_soap11_empty_actor_extension_header_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject SOAP 1.1 receiver-targeted mandatory Peppol extension headers via empty actor",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 policy requires SOAP 1.2 envelope namespace",
    );
}

#[tokio::test]
async fn rejects_edelivery_profile_mandatory_soap11_empty_actor_extension_header_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject SOAP 1.1 receiver-targeted mandatory eDelivery extension headers via empty actor",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 policy requires SOAP 1.2 envelope namespace",
    );
}

#[tokio::test]
async fn rejects_soap11_unknown_mandatory_header_with_header_scoped_prefix_in_strict_mode() {
    let answer = refused(&multipart_payload_with_cid(
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
    ), "strict mode must reject SOAP 1.1 envelopes").await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 policy requires SOAP 1.2 envelope namespace",
    );
}

#[tokio::test]
async fn rejects_unknown_mandatory_header_targeted_to_soap11_receiver_with_header_scoped_prefix_in_strict_mode()
 {
    let answer = refused(
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
    "strict mode must reject SOAP 1.1 receiver-targeted unknown mandatory header with header-scoped SOAP prefix",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 policy requires SOAP 1.2 envelope namespace",
    );
}

#[tokio::test]
async fn rejects_messaging_with_shadowed_soap11_prefix_must_understand_in_strict_mode() {
    let answer = refused(
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
    "strict mode must reject Messaging when SOAP 1.1 mustUnderstand uses element-local shadowed prefix",
    )
    .await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 policy requires SOAP 1.2 envelope namespace",
    );
}

#[tokio::test]
async fn rejects_soap11_envelope_wire_shape() {
    let answer = refused(&multipart_payload_with_cid(
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
    ), "SOAP 1.1 envelope wire-shape must be rejected").await;

    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 policy requires SOAP 1.2 envelope namespace",
    );
}

#[tokio::test]
async fn rejects_unsigned_receipt_when_signed_receipt_required() {
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

    let answer = refused(payload, "unsigned receipt must reject").await;
    answer.assert_refused_because("EBMS:0004", "AS4 eb:Messaging missing UserMessage");
}

#[tokio::test]
async fn rejects_security_element_outside_soap_header() {
    let answer = refused(
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
    "security in body must not satisfy strict header requirement",
    )
    .await;
    answer.assert_refused_because("EBMS:0004", "AS4 SOAP Header missing wsse:Security");
}

#[tokio::test]
async fn rejects_messaging_usermessage_outside_soap_header() {
    let answer = refused(
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
    "messaging in body must not satisfy required header structure",
    )
    .await;
    answer.assert_refused_because("EBMS:0004", "AS4 SOAP Header missing eb:Messaging");
}

#[tokio::test]
async fn rejects_fake_namespace_messaging_in_soap_header() {
    let answer = refused(
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
    "fake namespace messaging must not satisfy ebMS structure",
    )
    .await;
    answer.assert_refused_because(
        "EBMS:0004",
        "AS4 SOAP Header contains unknown mandatory receiver-targeted block",
    );
}

#[tokio::test]
async fn rejects_fake_namespace_security_header() {
    let answer = refused(
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
    "fake namespace security header must not satisfy wsse requirement",
    )
    .await;
    answer.assert_refused_because("EBMS:0004", "AS4 SOAP Header missing wsse:Security");
}

#[tokio::test]
async fn rejects_usermessage_with_mpc_missing_uri_scheme() {
    let answer = refused(
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
    "strict mode must reject mpc without URI scheme",
    )
    .await;
    answer.assert_refused_because("EBMS:0004", "AS4 UserMessage mpc must be a valid URI");
}

#[tokio::test]
async fn rejects_usermessage_with_mpc_containing_whitespace() {
    let answer = refused(
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
    "strict mode must reject mpc with whitespace",
    )
    .await;
    answer.assert_refused_because("EBMS:0004", "AS4 UserMessage mpc must be a valid URI");
}

#[tokio::test]
async fn rejects_push_with_tampered_ds_signature_structure() {
    let payload = br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
            xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <S12:Header>
            <eb:Messaging S12:mustUnderstand="true">
                <eb:UserMessage>
                    <eb:MessageInfo><eb:MessageId>msg-bad-ds</eb:MessageId></eb:MessageInfo>
                    <eb:PartyInfo>
                        <eb:From><eb:PartyId>party-a</eb:PartyId></eb:From>
                        <eb:To><eb:PartyId>party-b</eb:PartyId></eb:To>
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

    // A configured sender, so the signature structure is what gets judged.
    let answer = refused(
        payload,
        "tampered ds:Signature structure must fail cryptographic verification",
    )
    .await;
    answer.assert_refused_because("EBMS:0004", "ds:Signature missing ds:SignedInfo");
}

// ── Control: the structural verdicts above are about structure ──────────────

/// A structurally complete crafted envelope is refused for its missing
/// signature (EBMS:0101), not as malformed: the EBMS:0004 verdicts above come
/// from the parser, before any signature is looked at.
#[tokio::test]
async fn structurally_valid_unsigned_envelope_is_refused_as_unsigned() {
    let answer = refused(
        br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
                    <eb:UserMessage>
                        <eb:MessageInfo><eb:MessageId>msg-control</eb:MessageId></eb:MessageInfo>
                        <eb:PartyInfo>
                            <eb:From><eb:PartyId>party-a</eb:PartyId></eb:From>
                            <eb:To><eb:PartyId>party-b</eb:PartyId></eb:To>
                        </eb:PartyInfo>
                        <eb:CollaborationInfo><eb:Action>Act</eb:Action></eb:CollaborationInfo>
                        <eb:PayloadInfo><eb:PartInfo href="cid:body@example.com"/></eb:PayloadInfo>
                    </eb:UserMessage>
                </eb:Messaging>
                <wsse:Security/>
            </S12:Header>
            <S12:Body/>
        </S12:Envelope>"#,
        "an unsigned message is refused",
    )
    .await;
    // Unsigned where the profile requires a signature is EBMS:0103.
    answer.assert_refused_because("EBMS:0103", "signature is required but not present");
}

// ── Accepted variants of a genuine message ──────────────────────────────────

const NEXT: &str = "http://www.w3.org/2003/05/soap-envelope/role/next";

async fn edelivery() -> (Genuine, Receiver) {
    let g = genuine(Preset::Edelivery).await;
    let r = g.receiver();
    (g, r)
}

/// The genuine message id.
fn message_id(soap: &str) -> String {
    let start = soap.find("<ebms:MessageId").unwrap();
    let start = start + soap[start..].find('>').unwrap() + 1;
    soap[start..start + soap[start..].find('<').unwrap()].to_string()
}

#[tokio::test]
async fn accepts_xml_entity_encoded_message_id() {
    // Entity references in MessageId decode into one contiguous text value.
    let (g, r) = edelivery().await;
    let soap = g.soap();
    let id = message_id(&soap);
    let delivered = r
        .accepted(g.resigned(|s| s.replace(&format!(">{id}<"), ">msg&amp;entity@asx.test<")))
        .await;
    assert_eq!(delivered.message_id, "msg&entity@asx.test");
}

#[tokio::test]
async fn accepts_deeply_nested_but_valid_envelope() {
    // Extra namespace declarations and nested elements in the (signed) Body.
    let (g, r) = edelivery().await;
    let delivered = r
        .accepted(g.resigned(|s| {
            s.replacen(
                "<soap:Envelope ",
                "<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" ",
                1,
            )
            .replace(
                "<soap:Body wsu:Id=\"as4-body\"/>",
                "<soap:Body wsu:Id=\"as4-body\"><app:Payload xmlns:app=\"urn:example:app\">\
                 <app:Data/></app:Payload></soap:Body>",
            )
            .replace(
                "<ebms:ConversationId>1</ebms:ConversationId>",
                "<ebms:ConversationId>conv-deep-1</ebms:ConversationId>",
            )
        }))
        .await;
    assert_eq!(delivered.action, "urn:example:action");
    assert_eq!(delivered.conversation_id, "conv-deep-1");
}

/// ebMS3 §5.2.2.4 allows multiple <eb:PartyId> per party for multi-scheme
/// identifiers. Strict mode MUST accept them; the first one is the party.
#[tokio::test]
async fn accepts_multiple_from_party_ids_in_strict_mode() {
    let (g, r) = edelivery().await;
    let delivered = r
        .accepted(g.resigned(|s| {
            s.replacen(
                "party-a</ebms:PartyId>",
                "party-a</ebms:PartyId><ebms:PartyId type=\"urn:oasis:names:tc:ebcore:partyid-type:iso6523:0060\">987654321</ebms:PartyId>",
                1,
            )
        }))
        .await;
    assert_eq!(delivered.from, "party-a");
}

#[tokio::test]
async fn accepts_multiple_to_party_ids_in_strict_mode() {
    let (g, r) = edelivery().await;
    r.accepted(g.resigned(|s| {
        s.replacen(
            "party-b</ebms:PartyId>",
            "party-b</ebms:PartyId><ebms:PartyId type=\"urn:oasis:names:tc:ebcore:partyid-type:iso6523:0060\">123456789</ebms:PartyId>",
            1,
        )
    }))
    .await;
}

#[tokio::test]
async fn accepts_targeted_security_when_non_targeted_security_header_is_also_present_in_strict_mode()
 {
    // An unsigned header block: the genuine signature still holds.
    let (g, r) = edelivery().await;
    r.accepted(g.mutated(|s| header_first(&s, &format!("<wsse:Security soap:role=\"{NEXT}\"/>"))))
        .await;
}

#[tokio::test]
async fn accepts_messaging_with_soap12_ultimate_receiver_role_in_strict_mode() {
    let (g, r) = edelivery().await;
    r.accepted(g.resigned(|s| {
        s.replacen(
            "<ebms:Messaging soap:mustUnderstand=\"true\"",
            "<ebms:Messaging soap:mustUnderstand=\"true\" \
             soap:role=\"http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver\"",
            1,
        )
    }))
    .await;
}

/// Unknown header blocks the receiver does not have to process: accepted.
#[tokio::test]
async fn accepts_unknown_headers_it_need_not_understand() {
    for (case, header) in [
        (
            "non-mandatory",
            r#"<ext:PartnerRoutingHint xmlns:ext="urn:partner:ext:v1" soap:mustUnderstand="false">route-a</ext:PartnerRoutingHint>"#.to_string(),
        ),
        (
            "mandatory, role next",
            format!(r#"<ext:PartnerRoutingHint xmlns:ext="urn:partner:ext:v1" soap:mustUnderstand="true" soap:role="{NEXT}">route-a</ext:PartnerRoutingHint>"#),
        ),
        (
            "mandatory, role none",
            r#"<ext:PartnerRoutingHint xmlns:ext="urn:partner:ext:v1" soap:mustUnderstand="true" soap:role="http://www.w3.org/2003/05/soap-envelope/role/none">route-a</ext:PartnerRoutingHint>"#.to_string(),
        ),
        (
            "mandatory, custom role",
            r#"<ext:PartnerRoutingHint xmlns:ext="urn:partner:ext:v1" soap:mustUnderstand="true" soap:role="urn:partner:role:custom-hop">route-a</ext:PartnerRoutingHint>"#.to_string(),
        ),
        (
            "unqualified mustUnderstand is not SOAP's",
            r#"<ext:PartnerRoutingHint xmlns:ext="urn:partner:ext:v1" mustUnderstand="true">route-unqualified</ext:PartnerRoutingHint>"#.to_string(),
        ),
        (
            "element-local shadowed SOAP prefix",
            r#"<ext:PartnerRoutingHint xmlns:ext="urn:partner:ext:v3" xmlns:soap="urn:attacker:shadow" soap:mustUnderstand="true">shadowed</ext:PartnerRoutingHint>"#.to_string(),
        ),
        (
            "intermediary-targeted Peppol extension",
            format!(r#"<pp:PeppolRoutingHint xmlns:pp="urn:fdc:peppol.eu:transport:as4:profile:2.0" soap:mustUnderstand="true" soap:role="{NEXT}">peppol-next</pp:PeppolRoutingHint>"#),
        ),
    ] {
        let (g, r) = edelivery().await;
        let answer = r.post(g.mutated(|s| header_first(&s, &header))).await;
        assert!(answer.is_receipt(), "{case}: {answer:?}");
        assert_eq!(r.calls(), 1, "{case}");
    }
}

#[tokio::test]
async fn accepts_messaging_with_custom_soap_prefix_must_understand_in_strict_mode() {
    let (g, r) = edelivery().await;
    r.accepted(g.resigned(|s| {
        s.replace("xmlns:soap=", "xmlns:env=")
            .replace("soap:", "env:")
    }))
    .await;
}

#[tokio::test]
async fn accepts_messaging_with_header_scoped_soap_prefix_in_strict_mode() {
    let (g, r) = edelivery().await;
    r.accepted(g.resigned(|s| {
        s.replacen(
            "<soap:Header>",
            "<soap:Header xmlns:h12=\"http://www.w3.org/2003/05/soap-envelope\">",
            1,
        )
        .replacen(
            "<ebms:Messaging soap:mustUnderstand",
            "<ebms:Messaging h12:mustUnderstand",
            1,
        )
    }))
    .await;
}

#[tokio::test]
async fn accepts_multi_hop_intermediary_mandatory_headers_with_header_scoped_soap_prefix_in_strict_mode()
 {
    let (g, r) = edelivery().await;
    r.accepted(g.resigned(|s| {
        s.replacen(
            "<soap:Header>",
            &format!(
                "<soap:Header xmlns:h12=\"http://www.w3.org/2003/05/soap-envelope\">\
                 <ext:HopOneHint xmlns:ext=\"urn:partner:ext:v2\" h12:mustUnderstand=\"true\" h12:role=\"{NEXT}\">hop1</ext:HopOneHint>\
                 <ext:HopTwoHint xmlns:ext=\"urn:partner:ext:v2\" h12:mustUnderstand=\"true\" h12:role=\"{NEXT}\">hop2</ext:HopTwoHint>"
            ),
            1,
        )
        .replacen(
            "<ebms:Messaging soap:mustUnderstand",
            "<ebms:Messaging h12:mustUnderstand",
            1,
        )
    }))
    .await;
}

#[tokio::test]
async fn accepts_composite_multi_hop_extensions_and_mixed_wsse_targets_in_strict_mode() {
    let (g, r) = edelivery().await;
    r.accepted(g.resigned(|s| {
        s.replacen(
            "<soap:Header>",
            &format!(
                "<soap:Header xmlns:h12=\"http://www.w3.org/2003/05/soap-envelope\">\
                 <ext:HopHintOne xmlns:ext=\"urn:partner:ext:v4\" h12:mustUnderstand=\"true\" h12:role=\"{NEXT}\">hop1</ext:HopHintOne>\
                 <ext:HopHintTwo xmlns:ext=\"urn:partner:ext:v4\" h12:mustUnderstand=\"true\" h12:role=\"urn:partner:hop:security-gateway\">hop2</ext:HopHintTwo>\
                 <wsse:Security h12:role=\"{NEXT}\"/>"
            ),
            1,
        )
        .replacen(
            "<ebms:Messaging soap:mustUnderstand",
            "<ebms:Messaging h12:mustUnderstand",
            1,
        )
    }))
    .await;
}

#[tokio::test]
async fn accepts_messaging_must_understand_numeric_one_in_strict_mode() {
    let (g, r) = edelivery().await;
    r.accepted(g.resigned(|s| {
        s.replacen(
            "<ebms:Messaging soap:mustUnderstand=\"true\"",
            "<ebms:Messaging soap:mustUnderstand=\"1\"",
            1,
        )
    }))
    .await;
}

/// The same mutations without re-signing break the `eb:Messaging` digest: the
/// accepted verdicts above are not a verifier that skips the header.
#[tokio::test]
async fn messaging_mutation_without_resigning_is_refused() {
    let (g, r) = edelivery().await;
    r.refused(
        g.mutated(|s| {
            s.replacen(
                "<ebms:Messaging soap:mustUnderstand=\"true\"",
                "<ebms:Messaging soap:mustUnderstand=\"1\"",
                1,
            )
        }),
        "EBMS:0101",
    )
    .await;
}

// ── Signature wrapping and ambiguity ────────────────────────────────────────

const FORGED_ACTION: &str = "urn:attacker:action";

/// The genuine `eb:Messaging`, rewritten by an attacker: another action, no
/// `wsu:Id` (or the genuine one, when `keep_id`).
fn forged_messaging(soap: &str, keep_id: bool) -> String {
    let forged = messaging(soap).replace("urn:example:action", FORGED_ACTION);
    if keep_id {
        forged
    } else {
        forged.replace(" wsu:Id=\"as4-messaging\"", "")
    }
}

/// Two top-level `eb:Messaging` headers, the signed one first.
#[tokio::test]
async fn duplicate_messaging_after_the_signed_one_is_refused() {
    let (g, r) = edelivery().await;
    let answer = r
        .refused(
            g.mutated(|s| {
                let forged = forged_messaging(&s, false);
                let end = s.find("</ebms:Messaging>").unwrap() + "</ebms:Messaging>".len();
                format!("{}{forged}{}", &s[..end], &s[end..])
            }),
            "EBMS:0004",
        )
        .await;
    assert!(
        answer.description().contains("duplicate eb:Messaging"),
        "{answer:?}"
    );
}

/// A forged `eb:Messaging` placed before the signed one.
#[tokio::test]
async fn duplicate_messaging_before_the_signed_one_is_refused() {
    let (g, r) = edelivery().await;
    r.refused(
        g.mutated(|s| header_first(&s, &forged_messaging(&s, false))),
        "EBMS:0004",
    )
    .await;
}

/// XSW: the signed `eb:Messaging` is moved into a wrapper header and a
/// forged one takes its place. The signature still verifies over the moved
/// element; the processed header is not the signed one.
#[tokio::test]
async fn signed_messaging_moved_into_a_wrapper_is_refused() {
    let (g, r) = edelivery().await;
    let answer = r
        .post(g.mutated(|s| {
            let genuine = messaging(&s).to_string();
            let forged = forged_messaging(&s, false);
            s.replacen(
                &genuine,
                &format!(
                    "{forged}<ext:Wrapper xmlns:ext=\"urn:attacker:wrap\" \
                     soap:mustUnderstand=\"false\">{genuine}</ext:Wrapper>"
                ),
                1,
            )
        }))
        .await;
    answer.assert_refused_because("EBMS:0101", "exactly one eb:Messaging");
    r.assert_not_delivered();
}

/// ID ambiguity: the forged header carries the signed element's
/// `wsu:Id`, the genuine one hides in a wrapper. Two elements with one Id
/// must never resolve to "the first one".
#[tokio::test]
async fn duplicate_wsu_id_is_refused() {
    let (g, r) = edelivery().await;
    let answer = r
        .post(g.mutated(|s| {
            let genuine = messaging(&s).to_string();
            let forged = forged_messaging(&s, true);
            s.replacen(
                &genuine,
                &format!(
                    "{forged}<ext:Wrapper xmlns:ext=\"urn:attacker:wrap\">{genuine}</ext:Wrapper>"
                ),
                1,
            )
        }))
        .await;
    answer.assert_refused_because("EBMS:0004", "multiple elements share ID as4-messaging");
    r.assert_not_delivered();
}

/// ID ambiguity: the Body carries the Messaging header's `wsu:Id` as well.
#[tokio::test]
async fn body_reusing_the_messaging_id_is_refused() {
    let (g, r) = edelivery().await;
    let answer = r
        .post(g.mutated(|s| {
            s.replace(
                "<soap:Body wsu:Id=\"as4-body\"/>",
                "<soap:Body wsu:Id=\"as4-messaging\"/>",
            )
        }))
        .await;
    answer.assert_refused_because("EBMS:0004", "multiple elements share ID as4-messaging");
    r.assert_not_delivered();
}

/// Two `ds:Signature` elements in the receiver's `wsse:Security`.
#[tokio::test]
async fn multiple_signatures_are_refused() {
    let (g, r) = edelivery().await;
    let answer = r
        .post(g.mutated(|s| {
            let start = s.find("<ds:Signature").unwrap();
            let end = s.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
            let signature = s[start..end].to_string();
            format!("{}{signature}{}", &s[..end], &s[end..])
        }))
        .await;
    answer.assert_refused_because("EBMS:0004", "multiple ds:Signature elements");
    r.assert_not_delivered();
}

/// The genuine `wsse:Security` re-targeted at the next hop: no signature is
/// addressed to this receiver.
#[tokio::test]
async fn security_header_targeted_at_another_role_is_refused() {
    let (g, r) = edelivery().await;
    let answer = r
        .post(g.mutated(|s| {
            s.replacen(
                "<wsse:Security xmlns:wsse=",
                &format!("<wsse:Security soap:role=\"{NEXT}\" xmlns:wsse="),
                1,
            )
        }))
        .await;
    answer.assert_refused_because("EBMS:0004", "missing wsse:Security");
    r.assert_not_delivered();
}

/// A forged header re-signed by a key that is not the token's.
#[tokio::test]
async fn messaging_resigned_by_another_key_is_refused() {
    let (g, r) = edelivery().await;
    let attacker =
        asx_testkit::pki::TestCa::new("attacker root", asx_testkit::pki::KeyAlg::Rsa2048)
            .rsa_party("party-a");
    let attachments: Vec<(String, Vec<u8>)> = g.parts()[1..]
        .iter()
        .map(|p| (format!("cid:{}", p.content_id().unwrap()), p.body.clone()))
        .collect();
    let soap = g.soap().replace("urn:example:action", FORGED_ACTION);
    let forged = inbound_harness::resign(&soap, &attachments, &attacker.signing);
    r.refused(g.with_soap(&forged), "EBMS:0101").await;
}

/// The genuine signed `eb:Messaging` claiming another recipient after a
/// valid re-signature by the real sender: the `eb:To` check (EBMS:0004).
#[tokio::test]
async fn message_for_another_recipient_is_refused() {
    let (g, r) = edelivery().await;
    r.refused(
        g.resigned(|s| s.replacen("party-b</ebms:PartyId>", "party-c</ebms:PartyId>", 1)),
        "EBMS:0004",
    )
    .await;
}

// ── Fragments (not supported) ───────────────────────────────────────────────

/// A `mf:MessageFragment` whose `href` holds a multibyte character is
/// refused, never a panic and never delivered.
#[tokio::test]
async fn fragment_message_is_refused() {
    let boundary = "frag-adversarial-boundary";
    let soap = "<S12:Envelope xmlns:S12=\"http://www.w3.org/2003/05/soap-envelope\" \
         xmlns:eb=\"http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/\" \
         xmlns:mf=\"http://docs.oasis-open.org/ebxml-msg/ns/v3.0/mf/2010/04/\">\
         <S12:Header><eb:Messaging S12:mustUnderstand=\"true\"><eb:UserMessage><eb:PartyInfo><eb:From>\
         <eb:PartyId>party-a</eb:PartyId></eb:From></eb:PartyInfo></eb:UserMessage>\
         </eb:Messaging><mf:MessageFragment href=\"abc\u{e9}@x\"><mf:GroupId>g-1</mf:GroupId>\
         <mf:FragmentCount>2</mf:FragmentCount><mf:FragmentNum>1</mf:FragmentNum>\
         </mf:MessageFragment></S12:Header><S12:Body/></S12:Envelope>";
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Type: application/soap+xml\r\nContent-ID: <soap@test>\r\n\r\n",
    );
    body.extend_from_slice(soap.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Type: application/octet-stream\r\nContent-ID: <other@x>\r\n\r\n",
    );
    body.extend_from_slice(b"fragment-data");
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let answer = refused(&body, "a fragment is refused").await;
    answer.assert_refused("EBMS:0004");
}
