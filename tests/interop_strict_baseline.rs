#![cfg(all(feature = "as2", feature = "as4"))]
#[path = "common/as2_verifier_fixture.rs"]
mod common;

use asx::as2::receive_with_mdn_with_reliability;

use asx::as2::{As2MdnMode, As2ReceiveMdnRequest, As2ReceivePolicy};
use asx::as4::{
    As4PushPolicy, As4PushPolicyBuilder, As4ReceivePushRequest, As4ReceivePushSyncRequest,
    receive_push_with_dedup_sync,
};
use asx::core::{ErrorCode, InteropMode, SessionContext};
use asx::lifecycle::TrustEvidence;
use asx::observability::EventBus;
use common::{DeterministicTrustVerifier as InsecureBypassTrustVerifier, fixture};

fn session(profile: &str) -> SessionContext {
    SessionContext::new("strict-baseline-s1", "partner-strict", profile).expect("session")
}

#[test]
fn defaults_are_strict_for_as2_and_as4_policies() {
    assert_eq!(
        As2ReceivePolicy::default().interop_mode,
        InteropMode::Strict
    );
    assert_eq!(As4PushPolicy::default().interop, InteropMode::Strict);
}

#[test]
fn as2_strict_mode_rejects_malformed_boundary_with_stage_context() {
    let mdn = fixture("as2_mdn_malformed_boundary.golden");
    let hook = asx::reliability::InMemoryReconciliationHook::default();
    let dedup = asx::reliability::InMemoryDedupBackend::default();
    let verifier = InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable());

    let err = receive_with_mdn_with_reliability(
        &session("strict"),
        &EventBus::new(32).expect("bus"),
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.into(),
            mdn_mode: As2MdnMode::Synchronous,
            expected_mic: None,
            policy: As2ReceivePolicy {
                fail_closed_audit_events: false,
                ..As2ReceivePolicy::default()
            },
            original_message_id: None,
        },
        &hook,
        &dedup,
        &verifier,
    )
    .expect_err("strict mode should reject malformed boundary");

    assert_eq!(err.code, ErrorCode::InteropViolation);
    assert_eq!(err.context.stage, "as2_receive_mdn_boundary");
}

#[test]
fn as4_strict_mode_rejects_missing_security_header_with_stage_context() {
    let payload = br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope" xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
    <S12:Header>
    <eb:Messaging S12:mustUnderstand="true">
    <eb:UserMessage>
    <eb:MessageInfo><eb:MessageId>msg-no-security</eb:MessageId></eb:MessageInfo>
    <eb:PartyInfo><eb:From><eb:PartyId>sender-a</eb:PartyId></eb:From><eb:To><eb:PartyId>receiver-b</eb:PartyId></eb:To></eb:PartyInfo>
    <eb:CollaborationInfo><eb:Action>SubmitOrder</eb:Action></eb:CollaborationInfo>
    </eb:UserMessage>
    </eb:Messaging>
    </S12:Header>
    <S12:Body/>
    </S12:Envelope>"#;
    let dedup = asx::reliability::InMemoryDedupBackend::default();

    let err = receive_push_with_dedup_sync(
        &session("strict"),
        &EventBus::new(32).expect("bus"),
        As4ReceivePushSyncRequest {
            request: As4ReceivePushRequest {
                http_content_type: "application/soap+xml".into(),
                payload: payload.to_vec().into(),
                receipt_payload: None,
                policy: As4PushPolicyBuilder::new()
                    .fail_closed_audit_events(false)
                    .build()
                    .expect("policy"),
                authenticated_sender_scope: None,
            },
            dedup_backend: &dedup,
        },
    )
    .expect_err("strict mode should reject missing wsse:Security");

    assert!(matches!(
        err.code,
        ErrorCode::InteropViolation
            | ErrorCode::PolicyViolation
            | ErrorCode::SecurityVerificationFailed
            | ErrorCode::ParseFailed
    ));
    assert_eq!(err.context.stage, "as4_parse_user_message");
}
