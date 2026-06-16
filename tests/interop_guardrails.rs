#![cfg(feature = "interop-relaxed")]
#![cfg(all(feature = "as2", feature = "as4", feature = "testing"))]
#[path = "common/as2_verifier_fixture.rs"]
mod common;

use asx_rs::as2::receive_with_mdn_with_reliability;
use asx_rs::as2::{
    As2MdnMode, As2ReceiveMdnRequest, As2ReceivePolicy, As2RegulatedSpoolKeyProvider,
};
use asx_rs::as4::{
    As4PushPolicyBuilder, As4ReceivePushRequest, As4ReceivePushSyncRequest,
    receive_push_with_dedup_sync,
};
use asx_rs::core::{ErrorCode, InteropMode, SessionContext};
use asx_rs::interop::{InteropExceptionCode, InteropExceptionPolicy};
use asx_rs::lifecycle::TrustEvidence;
use asx_rs::observability::{AsxEvent, EventBus};
use asx_rs::reliability::InMemoryDedupBackend;
use common::{DeterministicTrustVerifier as InsecureBypassTrustVerifier, fixture};
use tokio::time::{Duration, timeout};

fn session(id: &str, profile: &str) -> SessionContext {
    SessionContext::new(id, "partner-guard", profile).expect("session")
}

fn dedup_backend() -> InMemoryDedupBackend {
    InMemoryDedupBackend::default()
}

#[cfg(feature = "interop-relaxed")]
#[tokio::test]
async fn guardrail_outcomes_include_allowed_and_denied_for_as2() {
    let bus = EventBus::new(32).expect("bus");
    let mut rx = bus.subscribe_scoped_events();
    let mdn = fixture("as2_mdn_partner_quirk_case.golden");

    let allowed_session = session("g-as2-allow", "partner-quirks");
    let dedup = dedup_backend();
    let verifier = InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable());
    let hook = asx_rs::reliability::InMemoryReconciliationHook::default();
    receive_with_mdn_with_reliability(
        &allowed_session,
        &bus,
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.clone().into(),
            mdn_mode: As2MdnMode::Synchronous,
            expected_mic: None,
            policy: As2ReceivePolicy {
                interop_mode: InteropMode::Relaxed,
                interop_exceptions: InteropExceptionPolicy::scoped(
                    "partner-quirks",
                    vec![InteropExceptionCode::As2AllowMissingMdnBoundary],
                ),
                fail_closed_audit_events: false,
                regulated_spool_key_provider: As2RegulatedSpoolKeyProvider::LocalEnv,
                enforce_as2_version: true,
            },
            original_message_id: None,
        },
        &hook,
        &dedup,
        &verifier,
    )
    .expect("allowed path");

    let denied_session = session("g-as2-deny", "strict-profile");
    let hook = asx_rs::reliability::InMemoryReconciliationHook::default();
    let err = receive_with_mdn_with_reliability(
        &denied_session,
        &bus,
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.into(),
            mdn_mode: As2MdnMode::Synchronous,
            expected_mic: None,
            policy: As2ReceivePolicy {
                interop_mode: InteropMode::Relaxed,
                interop_exceptions: InteropExceptionPolicy::default(),
                fail_closed_audit_events: false,
                regulated_spool_key_provider: As2RegulatedSpoolKeyProvider::LocalEnv,
                enforce_as2_version: true,
            },
            original_message_id: None,
        },
        &hook,
        &dedup,
        &verifier,
    )
    .expect_err("denied path");
    assert_eq!(err.code, ErrorCode::InteropViolation);

    let mut saw_allowed = false;
    let mut saw_denied = false;
    for _ in 0..12 {
        let next = timeout(Duration::from_millis(50), rx.recv()).await;
        if let Ok(Some(scoped)) = next
            && let AsxEvent::InteropGuardrailEvaluated {
                code,
                outcome,
                detail,
                ..
            } = scoped.event.as_ref()
            && *code == "as2_missing_mdn_boundary"
            && *detail == "missing_mdn_boundary"
        {
            if scoped.session_id == allowed_session.session_id() && *outcome == "Allowed" {
                saw_allowed = true;
            }
            if scoped.session_id == denied_session.session_id() && *outcome == "Denied" {
                saw_denied = true;
            }
            if saw_allowed && saw_denied {
                break;
            }
        }
    }

    assert!(saw_allowed, "expected allowed guardrail outcome event");
    assert!(saw_denied, "expected denied guardrail outcome event");
}

#[cfg(feature = "interop-relaxed")]
#[tokio::test]
async fn security_blocked_exceptions_are_non_overridable() {
    let bus = EventBus::new(32).expect("bus");
    let mut rx = bus.subscribe_scoped_events();
    let payload = br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope" xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
    <S12:Header>
    <eb:Messaging S12:mustUnderstand="true">
    <eb:UserMessage>
    <eb:MessageInfo><eb:MessageId>msg-blocked</eb:MessageId></eb:MessageInfo>
    <eb:PartyInfo><eb:From><eb:PartyId>sender-a</eb:PartyId></eb:From><eb:To><eb:PartyId>receiver-b</eb:PartyId></eb:To></eb:PartyInfo>
    <eb:CollaborationInfo><eb:Action>SubmitOrder</eb:Action></eb:CollaborationInfo>
    </eb:UserMessage>
    </eb:Messaging>
    </S12:Header>
    <S12:Body/>
    </S12:Envelope>"#;

    let strict_policy = As4PushPolicyBuilder::new()
        .interop(InteropMode::Relaxed)
        .require_signed_receipt(false)
        .allow_unsigned_push(true)
        .fail_closed_audit_events(false)
        .build()
        .expect("policy");

    let dedup = dedup_backend();
    let err = receive_push_with_dedup_sync(
        &session("g-as4-blocked", "partner-quirks"),
        &bus,
        As4ReceivePushSyncRequest {
            request: As4ReceivePushRequest {
                http_content_type: "application/soap+xml".into(),
                payload: payload.to_vec().into(),
                receipt_payload: None,
                policy: strict_policy,
                authenticated_sender_scope: None,
            },
            dedup_backend: &dedup,
        },
    )
    .expect_err("security-blocked exception must not be overridable");

    assert_eq!(err.code, ErrorCode::PolicyViolation);

    let mut saw_blocked = false;
    for _ in 0..10 {
        let next = timeout(Duration::from_millis(50), rx.recv()).await;
        if let Ok(Some(scoped)) = next
            && let AsxEvent::InteropGuardrailEvaluated { code, outcome, .. } = scoped.event.as_ref()
            && scoped.session_id == "g-as4-blocked"
            && *code == "as4_missing_wsse_security_header"
            && *outcome == "SecurityBlocked"
        {
            saw_blocked = true;
            break;
        }
    }
    assert!(saw_blocked, "expected security-blocked guardrail event");
}
