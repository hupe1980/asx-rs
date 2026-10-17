#![cfg(feature = "as4")]
//! Every document the crate emits is written by one writer that a caller value
//! cannot break: a value with
//! `< & " ' >` reads back unchanged, and a value XML 1.0 cannot carry
//! (U+0001, U+FFFE) is refused with `InvalidInput` naming the field — never
//! stripped, never emitted ill-formed.

use asx::__fuzz::sbdh::{
    SbdhDocumentIdentification, SbdhHeader, SbdhParty, StandardBusinessDocument,
    wrap_binary_payload, wrap_text_payload,
};
use asx::__fuzz::soap_builder::{
    SoapEnvelopeBuilder, WsAddressingHeaders, WsSecurityHeaderBuilder,
};
use asx::__fuzz::{As4ErrorCode, As4ErrorSeverity, generate_error_signal, generate_receipt};
use asx::__fuzz::{AsxError, ErrorCode, SessionContext};

const TRICKY: &str = "a<b&c\"d'e>f\tg";
const EB: &str = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/";

fn session() -> SessionContext {
    SessionContext::new("emission", "partner", "strict").unwrap()
}

fn doc(bytes: &[u8]) -> roxmltree::Document<'_> {
    let text = std::str::from_utf8(bytes).expect("utf8");
    roxmltree::Document::parse(text).unwrap_or_else(|e| panic!("well-formed: {e}\n{text}"))
}

fn text_of(doc: &roxmltree::Document<'_>, local: &str) -> Vec<String> {
    doc.descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == local)
        .map(|n| {
            let text: String = n
                .children()
                .filter(|c| c.is_text())
                .filter_map(|c| c.text())
                .collect();
            if text.trim().is_empty() {
                String::new()
            } else {
                text
            }
        })
        .collect()
}

fn assert_refused(result: Result<impl std::fmt::Debug, AsxError>, field: &str) {
    let err = result.expect_err("a character XML cannot carry must be refused");
    assert_eq!(err.code, ErrorCode::InvalidInput, "{}", err.message);
    assert!(
        err.message.contains(field),
        "must name {field}: {}",
        err.message
    );
}

fn envelope(value: &str) -> SoapEnvelopeBuilder {
    SoapEnvelopeBuilder::new(
        format!("id-{value}"),
        format!("from-{value}"),
        format!("to-{value}"),
    )
    .with_message_timestamp("2026-10-16T12:00:00Z")
    .with_action(format!("action-{value}"))
    .with_service(format!("service-{value}"), format!("type-{value}"))
    .with_ref_to_message_id(format!("ref-{value}"))
    .with_conversation_id(format!("conv-{value}"))
    .with_roles(format!("rf-{value}"), format!("rt-{value}"))
    .with_party_id_types(Some(format!("ft-{value}")), Some(format!("tt-{value}")))
    .with_agreement_ref(format!("agr-{value}"), Some(format!("agrt-{value}")))
    .with_four_corner_properties(
        format!("c1-{value}"),
        format!("c4-{value}"),
        format!("trk-{value}"),
    )
    .with_detached_payload_reference()
    .with_payload_content_id(format!("cid-{value}"))
    .with_payload_mime_type(format!("mime-{value}"))
    .with_payload_compression_type(format!("gz-{value}"))
    .with_extra_part_infos(vec![(
        format!("x-{value}"),
        format!("xm-{value}"),
        Some(format!("xg-{value}")),
    )])
    .with_ws_addressing(WsAddressingHeaders {
        message_id: format!("wsa-id-{value}"),
        action: format!("wsa-act-{value}"),
        to: format!("wsa-to-{value}"),
        reply_to: Some(format!("wsa-reply-{value}")),
    })
}

#[test]
fn soap_envelope_values_round_trip() {
    let bytes = envelope(TRICKY).build().expect("build");
    let d = doc(&bytes);
    let t = |local: &str| text_of(&d, local);
    assert_eq!(t("MessageId"), [format!("id-{TRICKY}")]);
    assert_eq!(
        t("Action"),
        [format!("wsa-act-{TRICKY}"), format!("action-{TRICKY}")]
    );
    assert_eq!(t("Service"), [format!("service-{TRICKY}")]);
    assert_eq!(t("RefToMessageId"), [format!("ref-{TRICKY}")]);
    assert_eq!(t("ConversationId"), [format!("conv-{TRICKY}")]);
    assert_eq!(t("Role"), [format!("rf-{TRICKY}"), format!("rt-{TRICKY}")]);
    assert_eq!(t("AgreementRef"), [format!("agr-{TRICKY}")]);
    assert_eq!(t("To"), [format!("wsa-to-{TRICKY}"), String::new()]);
    assert_eq!(t("Address"), [format!("wsa-reply-{TRICKY}")]);
    let properties: Vec<(String, String)> = d
        .descendants()
        .filter(|n| n.tag_name().name() == "Property" && n.tag_name().namespace() == Some(EB))
        .map(|n| {
            (
                n.attribute("name").unwrap().to_string(),
                n.text().unwrap_or_default().to_string(),
            )
        })
        .collect();
    for (name, value) in [
        ("originalSender", format!("c1-{TRICKY}")),
        ("finalRecipient", format!("c4-{TRICKY}")),
        ("trackingIdentifier", format!("trk-{TRICKY}")),
        ("MimeType", format!("mime-{TRICKY}")),
        ("CompressionType", format!("gz-{TRICKY}")),
        ("MimeType", format!("xm-{TRICKY}")),
        ("CompressionType", format!("xg-{TRICKY}")),
    ] {
        assert!(
            properties.contains(&(name.to_string(), value.clone())),
            "{name}={value} missing in {properties:?}"
        );
    }
    let hrefs: Vec<&str> = d
        .descendants()
        .filter(|n| n.tag_name().name() == "PartInfo")
        .filter_map(|n| n.attribute("href"))
        .collect();
    assert_eq!(
        hrefs,
        [format!("cid:cid-{TRICKY}"), format!("cid:x-{TRICKY}")]
    );
    let party_types: Vec<&str> = d
        .descendants()
        .filter(|n| n.tag_name().name() == "PartyId")
        .filter_map(|n| n.attribute("type"))
        .collect();
    assert_eq!(
        party_types,
        [format!("ft-{TRICKY}"), format!("tt-{TRICKY}")]
    );
}

#[test]
fn soap_envelope_refuses_forbidden_characters() {
    assert_refused(envelope("x").with_action("a\u{1}b").build(), "Action");
    assert_refused(
        envelope("x")
            .with_four_corner_properties("c1\u{FFFE}", "c4", "t")
            .build(),
        "originalSender",
    );
    assert_refused(
        envelope("x").with_payload_content_id("p\u{1}").build(),
        "PartInfo",
    );
}

#[test]
fn ws_security_header_takes_only_a_well_formed_signature() {
    let signature = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>"#;
    let header = WsSecurityHeaderBuilder::new()
        .with_signature_xml(signature)
        .build()
        .expect("header");
    let d = doc(&header);
    assert_eq!(d.root_element().tag_name().name(), "Security");
    assert!(d.descendants().any(|n| n.tag_name().name() == "Signature"));
    assert_refused(
        WsSecurityHeaderBuilder::new()
            .with_signature_xml("<ds:Signature>")
            .build(),
        "signature",
    );
}

#[test]
fn signals_round_trip_and_refuse() {
    let s = session();
    let receipt = generate_receipt(&s, &format!("r-{TRICKY}"), &format!("ref-{TRICKY}")).unwrap();
    let d = doc(&receipt);
    assert_eq!(text_of(&d, "MessageId"), [format!("r-{TRICKY}")]);
    assert_eq!(text_of(&d, "RefToMessageId"), [format!("ref-{TRICKY}")]);
    assert_refused(generate_receipt(&s, "r\u{1}", "ref"), "MessageId");

    let error = generate_error_signal(
        &s,
        "e@x",
        "ref@x",
        As4ErrorCode::Other,
        As4ErrorSeverity::Failure,
        &format!("desc-{TRICKY}"),
    )
    .unwrap();
    assert_eq!(
        text_of(&doc(&error), "Description"),
        [format!("desc-{TRICKY}")]
    );
    assert_refused(
        generate_error_signal(
            &s,
            "e@x",
            "ref@x",
            As4ErrorCode::Other,
            As4ErrorSeverity::Failure,
            "d\u{FFFE}",
        ),
        "Description",
    );
}

fn sbdh(sender: &str) -> StandardBusinessDocument {
    StandardBusinessDocument {
        header: SbdhHeader {
            header_version: "1.0".into(),
            sender: SbdhParty {
                identifier: sender.into(),
                authority: "iso6523-actorid-upis".into(),
            },
            receiver: SbdhParty {
                identifier: "0088:r".into(),
                authority: "iso6523-actorid-upis".into(),
            },
            document_identification: SbdhDocumentIdentification {
                standard: "urn:x".into(),
                type_version: "2.1".into(),
                instance_identifier: "i".into(),
                r#type: "Invoice".into(),
                multiple_type: false,
                creation_date_and_time: "2026-10-16T12:00:00Z".into(),
            },
            business_scope: vec![],
        },
        payload: b"<Invoice xmlns=\"urn:x\"/>".to_vec(),
    }
}

#[test]
fn sbdh_and_payload_wrappers_round_trip_and_refuse() {
    let wrapped = sbdh(&format!("0088:{TRICKY}")).wrap().unwrap();
    let back = StandardBusinessDocument::unwrap(&wrapped).unwrap();
    assert_eq!(back.header.sender.identifier, format!("0088:{TRICKY}"));
    assert_refused(sbdh("0088:\u{1}").wrap(), "sender");

    let text = wrap_text_payload(&format!("t-{TRICKY}"), &format!("m-{TRICKY}")).unwrap();
    let d = roxmltree::Document::parse(&text).unwrap();
    assert_eq!(
        d.root_element().text(),
        Some(format!("t-{TRICKY}").as_str())
    );
    assert_eq!(
        d.root_element().attribute("mimeType"),
        Some(format!("m-{TRICKY}").as_str())
    );
    assert_refused(wrap_text_payload("t\u{1}", "text/plain"), "payload");
    assert_refused(wrap_binary_payload(b"x", "m\u{FFFE}", None), "mime_type");
    let binary = wrap_binary_payload(b"x", "a/b", Some(TRICKY)).unwrap();
    assert_eq!(
        roxmltree::Document::parse(&binary)
            .unwrap()
            .root_element()
            .attribute("encoding"),
        Some(TRICKY)
    );
}
