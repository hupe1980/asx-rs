#![cfg_attr(not(feature = "interop-relaxed"), allow(unused_imports, dead_code))]
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
use asx_rs::reliability::{InMemoryDedupBackend, InMemoryReconciliationHook};
use common::{DeterministicTrustVerifier as InsecureBypassTrustVerifier, fixture};
use tokio::time::{Duration, timeout};

fn session(session_id: &str, profile: &str) -> SessionContext {
    SessionContext::new(session_id, "partner-relaxed", profile).expect("session")
}

fn reliability() -> (InMemoryReconciliationHook, InMemoryDedupBackend) {
    (
        InMemoryReconciliationHook::default(),
        InMemoryDedupBackend::default(),
    )
}

fn multipart_payload_with_xop(soap_xml: &[u8]) -> Vec<u8> {
    let boundary = "asx-interop-boundary";
    let payload_cid = "interop-body@example.com";
    let mut soap = String::from_utf8_lossy(soap_xml).into_owned();

    if !soap.contains("xmlns:xop=\"http://www.w3.org/2004/08/xop/include\"") {
        soap = soap.replacen(
            "<S12:Envelope ",
            "<S12:Envelope xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" ",
            1,
        );
    }
    if soap.contains("<S12:Body/>") {
        soap = soap.replacen(
            "<S12:Body/>",
            &format!("<S12:Body><xop:Include href=\"cid:{payload_cid}\"/></S12:Body>"),
            1,
        );
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
    out.extend_from_slice(b"interop-detached-payload\r\n");
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    out
}

#[cfg(feature = "interop-relaxed")]
#[tokio::test]
async fn as2_relaxed_exception_is_profile_scoped_and_audited() {
    let bus = EventBus::new(32).expect("bus");
    let mut scoped_rx = bus.subscribe_scoped_events();
    let mdn = fixture("as2_mdn_partner_quirk_case.golden");

    let allowed = session("as2-relaxed-allow", "partner-quirks");
    let denied = session("as2-relaxed-deny", "strict-profile");

    let policy = As2ReceivePolicy {
        interop_mode: InteropMode::Relaxed,
        interop_exceptions: InteropExceptionPolicy::scoped(
            "partner-quirks",
            vec![InteropExceptionCode::As2AllowMissingMdnBoundary],
        ),
        fail_closed_audit_events: false,
        regulated_spool_key_provider: As2RegulatedSpoolKeyProvider::LocalEnv,
        enforce_as2_version: true,
    };

    let (hook, dedup) = reliability();
    let verifier = InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable());
    let ok = receive_with_mdn_with_reliability(
        &allowed,
        &bus,
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.clone().into(),
            mdn_mode: As2MdnMode::Synchronous,
            expected_mic: None,
            policy: policy.clone(),
            original_message_id: None,
        },
        &hook,
        &dedup,
        &verifier,
    )
    .expect("allowed relaxed profile should pass");
    assert_eq!(ok.interop_reason_codes, vec!["as2_missing_mdn_boundary"]);

    let denied_err = receive_with_mdn_with_reliability(
        &denied,
        &bus,
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.into(),
            mdn_mode: As2MdnMode::Synchronous,
            expected_mic: None,
            policy,
            original_message_id: None,
        },
        &hook,
        &dedup,
        &verifier,
    )
    .expect_err("exception must not leak into other profiles");
    assert_eq!(denied_err.code, ErrorCode::InteropViolation);

    let mut saw_relax_event = false;
    for _ in 0..6 {
        let next = timeout(Duration::from_millis(50), scoped_rx.recv()).await;
        if let Ok(Some(scoped)) = next
            && let AsxEvent::InteropRelaxationApplied { detail, .. } = scoped.event.as_ref()
            && scoped.session_id == allowed.session_id()
            && *detail == "as2_missing_mdn_boundary"
        {
            saw_relax_event = true;
            break;
        }
    }
    assert!(
        saw_relax_event,
        "expected as2 interop relaxation audit event"
    );
}

#[cfg(feature = "interop-relaxed")]
#[tokio::test]
async fn as4_missing_non_repudiation_info_is_security_blocked_and_audited() {
    let bus = EventBus::new(32).expect("bus");
    let mut scoped_rx = bus.subscribe_scoped_events();

    let payload = br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope" xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
    <S12:Header>
    <wsse:Security/>
    <eb:Messaging S12:mustUnderstand="true">
    <eb:UserMessage>
    <eb:MessageInfo><eb:MessageId>msg-relaxed-scope</eb:MessageId></eb:MessageInfo>
    <eb:PartyInfo><eb:From><eb:PartyId>sender-a</eb:PartyId></eb:From><eb:To><eb:PartyId>receiver-b</eb:PartyId></eb:To></eb:PartyInfo>
    <eb:CollaborationInfo><eb:Action>SubmitOrder</eb:Action></eb:CollaborationInfo>
    </eb:UserMessage>
    </eb:Messaging>
    </S12:Header>
    <S12:Body/>
    </S12:Envelope>"#;

    let receipt_missing_nri = br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope" xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <S12:Header>
    <eb:Messaging>
    <eb:SignalMessage>
    <eb:MessageInfo><eb:RefToMessageId>msg-relaxed-scope</eb:RefToMessageId></eb:MessageInfo>
    <eb:Receipt/>
    </eb:SignalMessage>
    </eb:Messaging>
    <ds:Signature/>
    </S12:Header>
    <S12:Body/>
    </S12:Envelope>"#;

    let blocked_scoped = session("as4-relaxed-blocked-scoped", "partner-quirks");
    let blocked_unscoped = session("as4-relaxed-blocked-unscoped", "strict-profile");

    let policy = As4PushPolicyBuilder::new()
        .interop(InteropMode::Relaxed)
        .interop_exceptions(InteropExceptionPolicy::scoped(
            "partner-quirks",
            vec![InteropExceptionCode::As2AllowMissingMdnBoundary],
        ))
        .require_signed_receipt(false)
        .allow_unsigned_push(true)
        .fail_closed_audit_events(false)
        .build()
        .expect("policy");

    let (_, dedup) = reliability();
    let multipart_payload = multipart_payload_with_xop(payload);
    let multipart_content_type =
        "multipart/related; boundary=\"asx-interop-boundary\"; type=\"application/soap+xml\"";

    let scoped_err = receive_push_with_dedup_sync(
        &blocked_scoped,
        &bus,
        As4ReceivePushSyncRequest {
            request: As4ReceivePushRequest {
                http_content_type: multipart_content_type.into(),
                payload: multipart_payload.clone().into(),
                receipt_payload: Some(receipt_missing_nri.to_vec()),
                policy: policy.clone(),
                authenticated_sender_scope: None,
            },
            dedup_backend: &dedup,
        },
    )
    .expect_err("security-blocked exception must not be overridable (scoped)");
    assert_eq!(scoped_err.code, ErrorCode::PolicyViolation);

    let unscoped_err = receive_push_with_dedup_sync(
        &blocked_unscoped,
        &bus,
        As4ReceivePushSyncRequest {
            request: As4ReceivePushRequest {
                http_content_type: multipart_content_type.into(),
                payload: multipart_payload.into(),
                receipt_payload: Some(receipt_missing_nri.to_vec()),
                policy,
                authenticated_sender_scope: None,
            },
            dedup_backend: &dedup,
        },
    )
    .expect_err("security-blocked exception must not be overridable (unscoped)");
    assert_eq!(unscoped_err.code, ErrorCode::PolicyViolation);

    let mut saw_scoped_blocked = false;
    let mut saw_unscoped_blocked = false;
    for _ in 0..12 {
        let next = timeout(Duration::from_millis(50), scoped_rx.recv()).await;
        if let Ok(Some(scoped)) = next
            && let AsxEvent::InteropGuardrailEvaluated { code, outcome, .. } = scoped.event.as_ref()
            && *code == "as4_missing_non_repudiation_info"
            && *outcome == "SecurityBlocked"
        {
            if scoped.session_id == blocked_scoped.session_id() {
                saw_scoped_blocked = true;
            }
            if scoped.session_id == blocked_unscoped.session_id() {
                saw_unscoped_blocked = true;
            }
            if saw_scoped_blocked && saw_unscoped_blocked {
                break;
            }
        }
    }
    assert!(
        saw_scoped_blocked,
        "expected scoped security-blocked audit event"
    );
    assert!(
        saw_unscoped_blocked,
        "expected unscoped security-blocked audit event"
    );
}
