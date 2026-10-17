#![cfg(feature = "as4")]
//! The strict baseline: an inbound AS4 message without `wsse:Security` is
//! refused under every profile; there is no relaxed mode to fall back to.

#[path = "common/peers.rs"]
mod peers;
#[allow(unreachable_pub)]
#[path = "common/ported_as4.rs"]
mod ported;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use asx::Verified;
use asx::as4::UserMessage;
use asx::testkit::audit::MemoryAuditSink;
use asx::testkit::loopback::Loopback;

const UNSIGNED: &str = r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope" xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
<S12:Header>
<eb:Messaging S12:mustUnderstand="true">
<eb:UserMessage>
<eb:MessageInfo><eb:Timestamp>2026-01-01T00:00:00Z</eb:Timestamp><eb:MessageId>msg-no-security@asx.test</eb:MessageId></eb:MessageInfo>
<eb:PartyInfo><eb:From><eb:PartyId>sender-a</eb:PartyId><eb:Role>http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/initiator</eb:Role></eb:From><eb:To><eb:PartyId>receiver-b</eb:PartyId><eb:Role>http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/responder</eb:Role></eb:To></eb:PartyInfo>
<eb:CollaborationInfo><eb:Service>urn:example:service</eb:Service><eb:Action>SubmitOrder</eb:Action><eb:ConversationId>c-1</eb:ConversationId></eb:CollaborationInfo>
</eb:UserMessage>
</eb:Messaging>
</S12:Header>
<S12:Body/>
</S12:Envelope>"#;

#[tokio::test]
async fn every_profile_refuses_a_message_without_wsse_security() {
    for preset in peers::AS4_PRESETS {
        let ca = preset.ca();
        let (a, b) = preset.parties(&ca);
        let sink = MemoryAuditSink::new();
        let receiver = ported::client(
            preset.profile(),
            &ca,
            &b,
            a.partner(peers::A_URL),
            &Loopback::new(),
            |builder| builder.audit(sink.clone()),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let inbound = receiver.inbound(
            asx::MemoryDedup::default(),
            move |_m: Verified<UserMessage>| {
                counted.fetch_add(1, Ordering::SeqCst);
                async { Ok::<(), asx::Reject>(()) }
            },
        );
        let request = http::Request::post(peers::B_URL)
            .header(http::header::CONTENT_TYPE, "application/soap+xml")
            .body(bytes::Bytes::from_static(UNSIGNED.as_bytes()))
            .unwrap();
        let (status, body) = ported::post(&inbound, request).await;
        let body = String::from_utf8_lossy(&body);
        assert_eq!(status, http::StatusCode::BAD_REQUEST, "{preset:?}: {body}");
        assert!(
            body.contains("eb:Error") || body.contains(":Error "),
            "{preset:?}: {body}"
        );
        assert!(body.contains("errorCode=\"EBMS:0"), "{preset:?}: {body}");
        assert!(!body.contains("Receipt"), "{preset:?}: never receipted");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "{preset:?}: never delivered"
        );
        assert!(
            sink.records().is_empty(),
            "{preset:?}: unauthenticated, never recorded"
        );
    }
}
