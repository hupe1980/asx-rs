#![cfg(feature = "interop-relaxed")]
#![cfg(all(feature = "as2", feature = "as4", feature = "testing"))]
#[path = "common/as2_verifier.rs"]
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
use common::DeterministicTrustVerifier as InsecureBypassTrustVerifier;
use tokio::time::{Duration, timeout};

fn strict_session() -> SessionContext {
    SessionContext::new("sess-strict", "partner-a", "strict-profile").expect("session")
}

fn relaxed_session() -> SessionContext {
    SessionContext::new("sess-relaxed", "partner-a", "partner-quirks").expect("session")
}

fn reliability() -> (InMemoryReconciliationHook, InMemoryDedupBackend) {
    (
        InMemoryReconciliationHook::default(),
        InMemoryDedupBackend::default(),
    )
}

#[cfg(feature = "interop-relaxed")]
#[tokio::test]
async fn as2_session_scoped_policies_are_isolated_under_concurrency() {
    let bus = EventBus::new(64).expect("bus");
    let strict = strict_session();
    let relaxed = relaxed_session();

    let mut strict_rx = bus
        .subscribe_session_events(strict.session_id())
        .expect("subscribe strict");
    let mut relaxed_rx = bus
        .subscribe_session_events(relaxed.session_id())
        .expect("subscribe relaxed");

    let mdn_boundary_quirk =
        b"content-type: multipart/report; report-type=disposition-notification\r\n\
\r\n\
final-recipient: rfc822; HUB\r\n\
original-message-id: <msg-44@example>\r\n\
disposition: automatic-action/MDN-sent-automatically; processed/warning: boundary-quirk\r\n";

    let strict_req = As2ReceiveMdnRequest {
        payload: b"payload".to_vec().into(),
        mdn_payload: mdn_boundary_quirk.to_vec().into(),
        mdn_mode: As2MdnMode::Synchronous,
        require_signed_mdn: false,
        expected_mic: None,
        policy: As2ReceivePolicy {
            fail_closed_audit_events: false,
            ..As2ReceivePolicy::default()
        },
        original_message_id: None,
    };

    let relaxed_req = As2ReceiveMdnRequest {
        payload: b"payload".to_vec().into(),
        mdn_payload: mdn_boundary_quirk.to_vec().into(),
        mdn_mode: As2MdnMode::Synchronous,
        require_signed_mdn: false,
        expected_mic: None,
        policy: As2ReceivePolicy {
            interop_mode: InteropMode::Relaxed,
            interop_exceptions: InteropExceptionPolicy::scoped(
                relaxed.profile_name(),
                vec![InteropExceptionCode::As2AllowMissingMdnBoundary],
            ),
            fail_closed_audit_events: false,
            regulated_spool_key_provider: As2RegulatedSpoolKeyProvider::LocalEnv,
            enforce_as2_version: true,
        },
        original_message_id: None,
    };

    let (strict_hook, strict_dedup) = reliability();
    let (relaxed_hook, relaxed_dedup) = reliability();
    let verifier = InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable());
    let (strict_out, relaxed_out) = tokio::join!(
        async {
            receive_with_mdn_with_reliability(
                &strict,
                &bus,
                strict_req,
                &strict_hook,
                &strict_dedup,
                &verifier,
            )
        },
        async {
            receive_with_mdn_with_reliability(
                &relaxed,
                &bus,
                relaxed_req,
                &relaxed_hook,
                &relaxed_dedup,
                &verifier,
            )
        }
    );

    let strict_err = strict_out.expect_err("strict must reject boundary quirk without exception");
    assert_eq!(strict_err.code, ErrorCode::InteropViolation);
    assert!(relaxed_out.is_ok(), "relaxed_out={relaxed_out:?}");

    let mut relaxed_events = Vec::new();
    for _ in 0..4 {
        let Ok(Some(evt)) = timeout(Duration::from_millis(250), relaxed_rx.recv()).await else {
            break;
        };
        relaxed_events.push(evt);
    }

    assert!(relaxed_events.iter().any(|evt| matches!(
        evt.as_ref(),
        AsxEvent::InteropRelaxationApplied { rule, .. } if *rule == "as2_interop_exception"
    )));
    assert!(
        relaxed_events
            .iter()
            .any(|evt| matches!(evt.as_ref(), AsxEvent::MdnReceived { .. }))
    );

    let mut strict_relaxation_seen = false;
    for _ in 0..4 {
        let Ok(Some(evt)) = timeout(Duration::from_millis(120), strict_rx.recv()).await else {
            break;
        };
        if matches!(evt.as_ref(), AsxEvent::InteropRelaxationApplied { .. }) {
            strict_relaxation_seen = true;
            break;
        }
    }
    assert!(!strict_relaxation_seen);
}

#[cfg(feature = "interop-relaxed")]
#[tokio::test]
async fn as4_strict_and_relaxed_sessions_run_concurrently_without_event_leakage() {
    let bus = EventBus::new(64).expect("bus");
    let strict =
        SessionContext::new("s-as4-strict", "partner-g", "strict-profile").expect("session");
    let relaxed =
        SessionContext::new("s-as4-relaxed", "partner-g", "relaxed-profile").expect("session");

    let mut strict_rx = bus
        .subscribe_session_events(strict.session_id())
        .expect("subscribe strict");
    let mut relaxed_rx = bus
        .subscribe_session_events(relaxed.session_id())
        .expect("subscribe relaxed");

    let strict_payload = br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope" xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
      <S12:Header>
                <eb:Messaging S12:mustUnderstand="true"> 
          <eb:UserMessage>
            <eb:MessageInfo><eb:MessageId>msg-strict</eb:MessageId></eb:MessageInfo>
            <eb:PartyInfo><eb:From><eb:PartyId>a</eb:PartyId></eb:From><eb:To><eb:PartyId>b</eb:PartyId></eb:To></eb:PartyInfo>
            <eb:CollaborationInfo><eb:Action>Submit</eb:Action></eb:CollaborationInfo>
          </eb:UserMessage>
        </eb:Messaging>
      </S12:Header>
      <S12:Body/>
    </S12:Envelope>"#;

    let relaxed_payload = br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope" xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
      <S12:Header>
                <eb:Messaging S12:mustUnderstand="true">
          <eb:UserMessage>
            <eb:MessageInfo><eb:MessageId>msg-relaxed</eb:MessageId></eb:MessageInfo>
            <eb:PartyInfo><eb:From><eb:PartyId>a</eb:PartyId></eb:From><eb:To><eb:PartyId>b</eb:PartyId></eb:To></eb:PartyInfo>
            <eb:CollaborationInfo><eb:Action>Submit</eb:Action></eb:CollaborationInfo>
          </eb:UserMessage>
        </eb:Messaging>
      </S12:Header>
      <S12:Body/>
    </S12:Envelope>"#;

    let strict_dedup = InMemoryDedupBackend::default();
    let relaxed_dedup = InMemoryDedupBackend::default();
    let (strict_out, relaxed_out) = tokio::join!(
        async {
            receive_push_with_dedup_sync(
                &strict,
                &bus,
                As4ReceivePushSyncRequest {
                    request: As4ReceivePushRequest {
                        http_content_type: "application/soap+xml".into(),
                        payload: strict_payload.to_vec().into(),
                        receipt_payload: None,
                        policy: As4PushPolicyBuilder::new()
                            .fail_closed_audit_events(false)
                            .build()
                            .expect("policy"),
                        authenticated_sender_scope: None,
                    },
                    dedup_backend: &strict_dedup,
                },
            )
        },
        async {
            receive_push_with_dedup_sync(
                &relaxed,
                &bus,
                As4ReceivePushSyncRequest {
                    request: As4ReceivePushRequest {
                        http_content_type: "application/soap+xml".into(),
                        payload: relaxed_payload.to_vec().into(),
                        receipt_payload: None,
                        policy: As4PushPolicyBuilder::new()
                            .interop(InteropMode::Relaxed)
                            .require_signed_receipt(false)
                            .allow_unsigned_push(true)
                            .fail_closed_audit_events(false)
                            .build()
                            .expect("policy"),
                        authenticated_sender_scope: None,
                    },
                    dedup_backend: &relaxed_dedup,
                },
            )
        }
    );

    let strict_code = strict_out
        .expect_err("strict should reject missing security header")
        .code;
    assert!(matches!(
        strict_code,
        ErrorCode::InteropViolation
            | ErrorCode::PolicyViolation
            | ErrorCode::SecurityVerificationFailed
            | ErrorCode::ParseFailed
    ));

    let relaxed_code = relaxed_out
        .expect_err("relaxed should be security-blocked, not accepted")
        .code;
    assert!(matches!(
        relaxed_code,
        ErrorCode::InteropViolation
            | ErrorCode::PolicyViolation
            | ErrorCode::SecurityVerificationFailed
            | ErrorCode::ParseFailed
    ));

    let mut relaxed_guardrail_seen = false;
    for _ in 0..6 {
        let Ok(Some(evt)) = timeout(Duration::from_millis(250), relaxed_rx.recv()).await else {
            break;
        };
        if matches!(evt.as_ref(), AsxEvent::InteropGuardrailEvaluated { .. }) {
            relaxed_guardrail_seen = true;
            break;
        }
    }
    assert!(relaxed_guardrail_seen);

    let mut strict_relaxation_seen = false;
    for _ in 0..4 {
        let Ok(Some(evt)) = timeout(Duration::from_millis(120), strict_rx.recv()).await else {
            break;
        };
        if matches!(evt.as_ref(), AsxEvent::InteropRelaxationApplied { .. }) {
            strict_relaxation_seen = true;
            break;
        }
    }
    assert!(!strict_relaxation_seen);
}

// ── As4ConversationOrderGate tests ──────────────────────────────────────────

#[cfg(feature = "as4")]
mod conversation_order_gate {
    use asx_rs::as4::{As4ConversationOrderGate, ConversationGuard};
    use asx_rs::core::ErrorCode;
    use std::sync::Arc;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn same_conversation_is_serialized() {
        let gate = Arc::new(As4ConversationOrderGate::new(8));

        // Task A acquires the guard first.
        let guard_a: ConversationGuard = gate.acquire("conv-1").await.expect("guard_a");

        // Task B tries to acquire the same conversation — must block.
        let gate_b = gate.clone();
        let b_task = tokio::spawn(async move {
            gate_b.acquire("conv-1").await.expect("guard_b acquired");
            // Guard dropped at end of this block.
        });

        // Brief yield so task B can reach its acquire().await.
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            !b_task.is_finished(),
            "task B must be blocked while A holds guard"
        );

        // Release A's guard — B should immediately unblock.
        drop(guard_a);

        timeout(Duration::from_millis(200), b_task)
            .await
            .expect("task B completes within timeout")
            .expect("task B joined without panic");
    }

    #[tokio::test]
    async fn different_conversations_run_in_parallel() {
        let gate = Arc::new(As4ConversationOrderGate::new(8));

        // Hold the guard for conv-1.
        let _guard_1 = gate.acquire("conv-1").await.expect("conv-1");

        // conv-2 must NOT be blocked by conv-1's guard.
        let gate2 = gate.clone();
        let guard_2 = timeout(Duration::from_millis(50), async move {
            gate2.acquire("conv-2").await
        })
        .await
        .expect("conv-2 must not block on conv-1")
        .expect("conv-2 guard");

        drop(guard_2);
    }

    #[tokio::test]
    async fn capacity_exhausted_after_eviction_attempt() {
        let gate = As4ConversationOrderGate::new(2);

        // Fill both slots.
        let g1 = gate.acquire("conv-A").await.expect("A");
        let g2 = gate.acquire("conv-B").await.expect("B");

        // Capacity is exhausted with no dead slots to evict.
        let err = gate.acquire("conv-C").await.expect_err("should fail");
        assert_eq!(err.code, ErrorCode::CapacityExhausted);

        // Drop g1 — slot A's strong count drops to zero (dead).
        drop(g1);

        // Now eviction should reclaim slot A, allowing conv-C.
        gate.acquire("conv-C").await.expect("conv-C after eviction");

        drop(g2);
    }

    #[tokio::test]
    async fn slot_is_reused_for_sequential_acquires() {
        let gate = As4ConversationOrderGate::new(4);

        // Acquire and release the same conversation many times — capacity must
        // never be exhausted (dead slots are transparently reclaimed).
        for _ in 0..20 {
            let _g = gate.acquire("conv-X").await.expect("acquire");
            // dropped at end of iteration
        }
    }

    #[tokio::test]
    async fn sequential_same_conversation_never_deadlocks() {
        let gate = As4ConversationOrderGate::new(4);

        let g1 = gate.acquire("conv-Y").await.expect("first");
        drop(g1);

        // Second acquire for the same key must succeed immediately after release.
        let _g2 = timeout(Duration::from_millis(50), gate.acquire("conv-Y"))
            .await
            .expect("second acquire must not time out")
            .expect("second guard");
    }

    #[tokio::test]
    async fn capacity_getter_matches_constructor() {
        let gate = As4ConversationOrderGate::new(512);
        assert_eq!(gate.capacity(), 512);
    }
}
