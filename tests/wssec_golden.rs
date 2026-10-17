#![cfg(feature = "as4")]
//! Emission goldens: what the crate emits must not change except where a wire
//! change is intended and recorded.
//!
//! - RSA `ds:Signature` bytes are compared **exactly**: PKCS #1 v1.5 is
//!   deterministic, so any byte that moves is a change partners would see.
//! - Envelopes, signals and the SBDH are compared by **infoset**
//!   (`common/infoset.rs`): their meaning is pinned, not their bytes.
//!   Clock-derived values are masked.

#[path = "common/infoset.rs"]
mod infoset;

use asx::__fuzz::SessionContext;
use asx::__fuzz::sbdh::{
    SbdhDocumentIdentification, SbdhHeader, SbdhParty, SbdhScope, StandardBusinessDocument,
};
use asx::__fuzz::soap_builder::{SoapEnvelopeBuilder, WsAddressingHeaders};
use asx::__fuzz::wssec::{
    WsSecOutboundKeyInfoProfile, generate_xmlsig_signature,
    generate_xmlsig_signature_with_external_references,
};
use asx::__fuzz::{
    As4ErrorCode, As4ErrorSeverity, As4NriReference, generate_error_signal, generate_receipt,
    generate_receipt_with_nri,
};
use infoset::{assert_golden_text, assert_same_infoset};

const RSA_KEY: &[u8] = include_bytes!("fixtures/pki/receipt_signing.key.pem");
const RSA_CERT: &[u8] = include_bytes!("fixtures/pki/receipt_signing.cert.pem");

/// A fixed envelope with two `wsu:Id` targets, as the AS4 send path signs it.
const ENVELOPE: &str = concat!(
    r#"<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" "#,
    r#"xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/" "#,
    r#"xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">"#,
    r#"<soap:Header><eb:Messaging wsu:Id="as4-messaging"><eb:UserMessage>"#,
    r#"<eb:MessageInfo><eb:MessageId>golden@asx.test</eb:MessageId></eb:MessageInfo>"#,
    r#"</eb:UserMessage></eb:Messaging></soap:Header>"#,
    r#"<soap:Body wsu:Id="as4-body"><p:Doc xmlns:p="urn:asx:golden">A &amp; B</p:Doc></soap:Body>"#,
    r#"</soap:Envelope>"#
);

fn session() -> SessionContext {
    SessionContext::new("golden-session", "golden-partner", "golden-profile").expect("session")
}

/// Values carrying every character XML treats specially.
const TRICKY: &str = r#"a<b&c"d'e>f"#;

#[test]
fn rsa_xmlsig_signature_bytes_golden() {
    let same_document = generate_xmlsig_signature(
        ENVELOPE,
        &["#as4-messaging", "#as4-body"],
        RSA_KEY,
        RSA_CERT,
        WsSecOutboundKeyInfoProfile::X509DataAndRsaKeyValue,
    )
    .expect("sign");
    assert_golden_text("rsa_signature_same_document.xml", &same_document);

    let payload: &[u8] = b"UNB+UNOC:3+sender+receiver+260804:1200+1'";
    let with_attachment = generate_xmlsig_signature_with_external_references(
        ENVELOPE,
        &["#as4-messaging", "#as4-body", "cid:payload-1@asx.test"],
        &[("cid:payload-1@asx.test", payload)],
        RSA_KEY,
        RSA_CERT,
        WsSecOutboundKeyInfoProfile::BinarySecurityTokenX509v3,
    )
    .expect("sign with attachment");
    assert_golden_text("rsa_signature_with_attachment.xml", &with_attachment);
}

#[test]
fn soap_envelope_infoset_golden() {
    let envelope = SoapEnvelopeBuilder::new(
        format!("msg-{TRICKY}@asx.test"),
        format!("from-{TRICKY}"),
        format!("to-{TRICKY}"),
    )
    .with_message_timestamp("2026-10-16T12:00:00Z")
    .with_action(format!("urn:action:{TRICKY}"))
    .with_service(format!("urn:service:{TRICKY}"), format!("type-{TRICKY}"))
    .with_ref_to_message_id(format!("ref-{TRICKY}"))
    .with_conversation_id(format!("conv-{TRICKY}"))
    .with_roles(format!("role-from-{TRICKY}"), format!("role-to-{TRICKY}"))
    .with_agreement_ref(
        format!("agreement-{TRICKY}"),
        Some(format!("pmode-{TRICKY}")),
    )
    .with_four_corner_properties(
        format!("c1-{TRICKY}"),
        format!("c4-{TRICKY}"),
        format!("track-{TRICKY}"),
    )
    .with_detached_payload_reference()
    .with_payload_content_id(format!("payload-{TRICKY}@asx.test"))
    .with_payload_mime_type("application/xml")
    .with_payload_compression_type("application/gzip")
    .with_extra_part_infos(vec![(
        "second@asx.test".to_string(),
        "text/plain".to_string(),
        None,
    )])
    .with_ws_addressing(WsAddressingHeaders::new(
        format!("urn:uuid:{TRICKY}"),
        format!("urn:wsa:{TRICKY}"),
        format!("https://partner.test/as4?{TRICKY}"),
    ))
    .build()
    .expect("envelope");
    let xml = String::from_utf8(envelope).expect("utf8");
    assert_same_infoset("soap_envelope.infoset", &xml, &[]);
}

#[test]
fn signals_infoset_golden() {
    let session = session();
    let masked = ["Timestamp"];

    let receipt = generate_receipt(
        &session,
        &format!("rcpt-{TRICKY}"),
        &format!("ref-{TRICKY}"),
    )
    .expect("receipt");
    assert_same_infoset(
        "receipt_unsigned.infoset",
        &String::from_utf8(receipt).expect("utf8"),
        &masked,
    );

    let nri = [As4NriReference {
        uri: format!("cid:{TRICKY}"),
        digest_method_uri: "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
        digest_value_b64: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".to_string(),
    }];
    let receipt_nri =
        generate_receipt_with_nri(&session, "rcpt-nri@asx.test", "ref@asx.test", &nri)
            .expect("receipt with nri");
    assert_same_infoset(
        "receipt_unsigned_nri.infoset",
        &String::from_utf8(receipt_nri).expect("utf8"),
        &masked,
    );

    let error = generate_error_signal(
        &session,
        &format!("err-{TRICKY}"),
        &format!("ref-{TRICKY}"),
        As4ErrorCode::ValueInconsistent,
        As4ErrorSeverity::Failure,
        &format!("description {TRICKY}"),
    )
    .expect("error signal");
    assert_same_infoset(
        "error_signal.infoset",
        &String::from_utf8(error).expect("utf8"),
        &masked,
    );
}

#[test]
fn sbdh_infoset_golden() {
    let document = StandardBusinessDocument {
        header: SbdhHeader {
            header_version: "1.0".to_string(),
            sender: SbdhParty {
                identifier: format!("0088:{TRICKY}"),
                authority: format!("auth-{TRICKY}"),
            },
            receiver: SbdhParty {
                identifier: "0088:receiver".to_string(),
                authority: "iso6523-actorid-upis".to_string(),
            },
            document_identification: SbdhDocumentIdentification {
                standard: format!("urn:standard:{TRICKY}"),
                type_version: "2.1".to_string(),
                instance_identifier: format!("instance-{TRICKY}"),
                r#type: "Invoice".to_string(),
                multiple_type: false,
                creation_date_and_time: "2026-10-16T12:00:00Z".to_string(),
            },
            business_scope: vec![
                SbdhScope::with_scheme("DOCUMENTID", format!("doc-{TRICKY}"), "busdox-docid-qns"),
                SbdhScope::indicator("MLS_TYPE"),
            ],
        },
        payload: br#"<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"><ID>1 &amp; 2</ID></Invoice>"#.to_vec(),
    };
    let xml = String::from_utf8(document.wrap().expect("wrap")).expect("utf8");
    assert_same_infoset("sbdh.infoset", &xml, &[]);
}
