#![cfg(feature = "interop-relaxed")]
#![cfg(all(feature = "as2", feature = "testing"))]

#[path = "common/as2_verifier.rs"]
mod common;

use asx_rs::as2::{
    As2MdnMode, As2ReceiveMdnRequest, As2ReceivePolicy, As2RegulatedSpoolKeyProvider,
    receive_with_mdn_with_reliability,
};
use asx_rs::core::{ErrorCode, InteropMode, SessionContext};
use asx_rs::interop::{InteropExceptionCode, InteropExceptionPolicy};
use asx_rs::lifecycle::TrustEvidence;
use asx_rs::observability::EventBus;
use asx_rs::reliability::{
    DeliveryOutcome, InMemoryDedupBackend, InMemoryReconciliationHook, ReconciliationReason,
};
use asx_rs::storage::ReconciliationStorage as _;
use common::DeterministicTrustVerifier as InsecureBypassTrustVerifier;
use tokio::time::{Duration, timeout};

// Full RFC 4130 §7.4.3 Received-Content-MIC format: "{base64-digest}, {algorithm}".
// Include the algorithm name so both the digest and the hash function are
// cross-validated against the inbound MDN.
const EXPECTED_MIC: &str = "ZXELZG2MstvZ8CzynjCRhlEuxafCsnlFN6wFAV9r8AA=, sha-256";

fn session() -> SessionContext {
    SessionContext::new("sess-rx-1", "partner-a", "strict").expect("session")
}

fn reliability() -> (InMemoryReconciliationHook, InMemoryDedupBackend) {
    (
        InMemoryReconciliationHook::default(),
        InMemoryDedupBackend::default(),
    )
}

fn test_receive_policy() -> As2ReceivePolicy {
    As2ReceivePolicy {
        fail_closed_audit_events: false,
        ..As2ReceivePolicy::default()
    }
}

#[tokio::test]
async fn sync_mdn_with_matching_mic_is_success_confirmed() {
    let mdn = std::fs::read("tests/fixtures/as2_mdn_sync_ok.golden").expect("fixture");
    let (hook, dedup) = reliability();
    let out = receive_with_mdn_with_reliability(
        &session(),
        &EventBus::new(32).expect("bus"),
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.into(),
            mdn_mode: As2MdnMode::Synchronous,
            expected_mic: Some(EXPECTED_MIC.to_string()),
            policy: test_receive_policy(),
            original_message_id: None,
        },
        &hook,
        &dedup,
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect("receive");

    assert_eq!(out.outcome, DeliveryOutcome::SuccessConfirmed);
}

#[tokio::test]
async fn async_warning_mdn_without_mic_is_pending_verification() {
    let mdn = std::fs::read("tests/fixtures/as2_mdn_async_pending.golden").expect("fixture");
    let (hook, dedup) = reliability();
    let out = receive_with_mdn_with_reliability(
        &session(),
        &EventBus::new(32).expect("bus"),
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.into(),
            mdn_mode: As2MdnMode::Asynchronous,
            expected_mic: Some(EXPECTED_MIC.to_string()),
            policy: test_receive_policy(),
            original_message_id: None,
        },
        &hook,
        &dedup,
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect("receive");

    assert_eq!(out.outcome, DeliveryOutcome::AcceptedPendingVerification);
}

#[tokio::test]
async fn malformed_boundary_is_rejected_in_strict_mode() {
    let mdn = std::fs::read("tests/fixtures/as2_mdn_malformed_boundary.golden").expect("fixture");
    let (hook, dedup) = reliability();
    let err = receive_with_mdn_with_reliability(
        &session(),
        &EventBus::new(32).expect("bus"),
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.into(),
            mdn_mode: As2MdnMode::Synchronous,
            expected_mic: Some(EXPECTED_MIC.to_string()),
            policy: As2ReceivePolicy {
                interop_mode: InteropMode::Strict,
                interop_exceptions: InteropExceptionPolicy::default(),
                fail_closed_audit_events: false,
                regulated_spool_key_provider: As2RegulatedSpoolKeyProvider::LocalEnv,
                enforce_as2_version: true,
            },
            original_message_id: None,
        },
        &hook,
        &dedup,
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect_err("strict parse failure");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[tokio::test]
async fn strict_multipart_report_without_machine_readable_part_is_rejected() {
    let mdn = br#"Content-Type: multipart/report; report-type=disposition-notification; boundary="as2-mdn-b"

--as2-mdn-b
Content-Type: text/plain

Human-readable only

--as2-mdn-b--
"#;
    let (hook, dedup) = reliability();
    let err = receive_with_mdn_with_reliability(
        &session(),
        &EventBus::new(32).expect("bus"),
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.to_vec().into(),
            mdn_mode: As2MdnMode::Synchronous,
            expected_mic: None,
            policy: test_receive_policy(),
            original_message_id: None,
        },
        &hook,
        &dedup,
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect_err("strict multipart/report without notification body must fail");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[tokio::test]
async fn strict_structured_multipart_report_with_returned_content_is_successful() {
    let mdn = br#"Content-Type: multipart/report; report-type=disposition-notification; boundary="as2-mdn-b"

--as2-mdn-b
Content-Type: text/plain

Human-readable summary

--as2-mdn-b
Content-Type: message/disposition-notification

Final-Recipient: rfc822; partner-a
Original-Message-ID: <msg-42@example>
Disposition: automatic-action/MDN-sent-automatically; processed
Received-Content-MIC: KUPgyYBxFU9pqBBAxdTOeAw3hlDAepf6m2Pfoy8VI0g=,
 sha-256

--as2-mdn-b
Content-Type: message/rfc822

[original message]

--as2-mdn-b--
"#;
    let (hook, dedup) = reliability();
    let out = receive_with_mdn_with_reliability(
        &session(),
        &EventBus::new(32).expect("bus"),
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.to_vec().into(),
            mdn_mode: As2MdnMode::Synchronous,
            expected_mic: None,
            policy: test_receive_policy(),
            original_message_id: None,
        },
        &hook,
        &dedup,
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect("structured multipart/report should parse");

    assert_eq!(out.outcome, DeliveryOutcome::SuccessConfirmed);
    assert_eq!(
        out.mdn.final_recipient.as_deref(),
        Some("rfc822; partner-a")
    );
    assert_eq!(
        out.mdn.original_message_id.as_deref(),
        Some("<msg-42@example>")
    );
    assert_eq!(
        out.mdn.disposition,
        "automatic-action/MDN-sent-automatically; processed"
    );
}

#[tokio::test]
async fn duplicate_disposition_fields_are_rejected_in_strict_mode() {
    let mdn = br#"Content-Type: multipart/report; report-type=disposition-notification; boundary="as2-mdn-b"

--as2-mdn-b
Content-Type: text/plain

Human-readable summary

--as2-mdn-b
Content-Type: message/disposition-notification

Final-Recipient: rfc822; partner-a
Original-Message-ID: <msg-duplicate-disposition@example>
Disposition: automatic-action/MDN-sent-automatically; processed
Disposition: automatic-action/MDN-sent-automatically; processed

--as2-mdn-b--
"#;
    let (hook, dedup) = reliability();
    let err = receive_with_mdn_with_reliability(
        &session(),
        &EventBus::new(32).expect("bus"),
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.to_vec().into(),
            mdn_mode: As2MdnMode::Synchronous,
            expected_mic: None,
            policy: test_receive_policy(),
            original_message_id: None,
        },
        &hook,
        &dedup,
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect_err("duplicate disposition fields must fail closed");

    assert_eq!(err.code, ErrorCode::InteropViolation);
    assert!(err.message.contains("duplicate Disposition field"));
}

#[tokio::test]
async fn duplicate_received_content_mic_fields_are_rejected_in_strict_mode() {
    let mdn = br#"Content-Type: multipart/report; report-type=disposition-notification; boundary="as2-mdn-b"

--as2-mdn-b
Content-Type: text/plain

Human-readable summary

--as2-mdn-b
Content-Type: message/disposition-notification

Final-Recipient: rfc822; partner-a
Original-Message-ID: <msg-duplicate-mic@example>
Disposition: automatic-action/MDN-sent-automatically; processed
Received-Content-MIC: KUPgyYBxFU9pqBBAxdTOeAw3hlDAepf6m2Pfoy8VI0g=, sha-256
Received-Content-MIC: KUPgyYBxFU9pqBBAxdTOeAw3hlDAepf6m2Pfoy8VI0g=, sha-256

--as2-mdn-b--
"#;
    let (hook, dedup) = reliability();
    let err = receive_with_mdn_with_reliability(
        &session(),
        &EventBus::new(32).expect("bus"),
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.to_vec().into(),
            mdn_mode: As2MdnMode::Synchronous,
            expected_mic: Some(EXPECTED_MIC.to_string()),
            policy: test_receive_policy(),
            original_message_id: None,
        },
        &hook,
        &dedup,
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect_err("duplicate mic fields must fail closed");

    assert_eq!(err.code, ErrorCode::InteropViolation);
    assert!(err.message.contains("duplicate Received-Content-MIC field"));
}

#[tokio::test]
async fn mdn_notification_with_non_utf8_octets_is_rejected() {
    let mut mdn = b"Content-Type: multipart/report; report-type=disposition-notification; boundary=as2-mdn-b\r\n\r\n--as2-mdn-b\r\nContent-Type: text/plain\r\n\r\nHuman-readable\r\n\r\n--as2-mdn-b\r\nContent-Type: message/disposition-notification\r\n\r\nFinal-Recipient: rfc822; partner-".to_vec();
    mdn.push(0xFF);
    mdn.extend_from_slice(b"\r\nOriginal-Message-ID: <msg-42@example>\r\nDisposition: automatic-action/MDN-sent-automatically; processed\r\nReceived-Content-MIC: ");
    mdn.extend_from_slice(EXPECTED_MIC.as_bytes());
    mdn.extend_from_slice(b", sha-256\r\n\r\n--as2-mdn-b--\r\n");

    let (hook, dedup) = reliability();
    let err = receive_with_mdn_with_reliability(
        &session(),
        &EventBus::new(32).expect("bus"),
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.into(),
            mdn_mode: As2MdnMode::Synchronous,
            expected_mic: Some(EXPECTED_MIC.to_string()),
            policy: test_receive_policy(),
            original_message_id: None,
        },
        &hook,
        &dedup,
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect_err("MDN body with non-UTF-8 octets must be rejected (fail-closed)");

    assert_eq!(
        err.code,
        asx_rs::core::ErrorCode::ParseFailed,
        "expected ParseFailed for non-UTF-8 MDN body, got: {err:?}"
    );
}

#[tokio::test]
async fn mdn_with_quoted_received_content_mic_matches_expected() {
    // The MDN contains the digest quoted but with the algorithm outside the quotes.
    // This tests that the parser correctly strips surrounding quotes from the digest
    // while preserving the algorithm suffix (RFC 4130 §7.4.3 Received-Content-MIC grammar).
    let digest_only = "ZXELZG2MstvZ8CzynjCRhlEuxafCsnlFN6wFAV9r8AA=";
    let mdn = format!(
        "Content-Type: multipart/report; report-type=disposition-notification; boundary=as2-mdn-b\r\n\r\n--as2-mdn-b\r\nContent-Type: text/plain\r\n\r\nHuman-readable\r\n\r\n--as2-mdn-b\r\nContent-Type: message/disposition-notification\r\n\r\nFinal-Recipient: rfc822; partner-a\r\nOriginal-Message-ID: <msg-quoted@example>\r\nDisposition: automatic-action/MDN-sent-automatically; processed\r\nReceived-Content-MIC: \"{}\", sha-256\r\n\r\n--as2-mdn-b--\r\n",
        digest_only
    );

    let (hook, dedup) = reliability();
    let out = receive_with_mdn_with_reliability(
        &session(),
        &EventBus::new(32).expect("bus"),
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.into_bytes().into(),
            mdn_mode: As2MdnMode::Synchronous,
            expected_mic: Some(EXPECTED_MIC.to_string()),
            policy: test_receive_policy(),
            original_message_id: None,
        },
        &hook,
        &dedup,
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect("quoted MIC must match expected digest");

    assert_eq!(out.outcome, DeliveryOutcome::SuccessConfirmed);
}

#[cfg(feature = "interop-relaxed")]
#[tokio::test]
async fn partner_quirk_parses_in_relaxed_mode() {
    let mdn = std::fs::read("tests/fixtures/as2_mdn_partner_quirk_case.golden").expect("fixture");
    let (hook, dedup) = reliability();
    let out = receive_with_mdn_with_reliability(
        &session(),
        &EventBus::new(32).expect("bus"),
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.into(),
            mdn_mode: As2MdnMode::Synchronous,
            expected_mic: Some(EXPECTED_MIC.to_string()),
            policy: As2ReceivePolicy {
                interop_mode: InteropMode::Relaxed,
                interop_exceptions: InteropExceptionPolicy::scoped(
                    "strict",
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
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect("relaxed parse");

    assert_eq!(out.outcome, DeliveryOutcome::SuccessConfirmed);
    assert_eq!(out.interop_reason_codes, vec!["as2_missing_mdn_boundary"]);
}

#[cfg(feature = "interop-relaxed")]
#[tokio::test]
async fn relaxed_partner_quirk_without_exception_is_rejected() {
    let mdn = std::fs::read("tests/fixtures/as2_mdn_partner_quirk_case.golden").expect("fixture");
    let (hook, dedup) = reliability();
    let err = receive_with_mdn_with_reliability(
        &session(),
        &EventBus::new(32).expect("bus"),
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.into(),
            mdn_mode: As2MdnMode::Synchronous,
            expected_mic: Some(EXPECTED_MIC.to_string()),
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
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect_err("relaxed without configured exception must fail");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[tokio::test]
async fn retry_side_effects_are_not_duplicated_for_same_message() {
    let mdn = std::fs::read("tests/fixtures/as2_mdn_async_pending.golden").expect("fixture");
    let bus = EventBus::new(32).expect("bus");
    let (hook, dedup) = reliability();

    let first = receive_with_mdn_with_reliability(
        &session(),
        &bus,
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.clone().into(),
            mdn_mode: As2MdnMode::Asynchronous,
            expected_mic: Some(EXPECTED_MIC.to_string()),
            policy: test_receive_policy(),
            original_message_id: None,
        },
        &hook,
        &dedup,
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect("first receive");

    let second = receive_with_mdn_with_reliability(
        &session(),
        &bus,
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.into(),
            mdn_mode: As2MdnMode::Asynchronous,
            expected_mic: Some(EXPECTED_MIC.to_string()),
            policy: test_receive_policy(),
            original_message_id: None,
        },
        &hook,
        &dedup,
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect("second receive");

    assert_eq!(first.outcome, DeliveryOutcome::AcceptedPendingVerification);
    assert_eq!(second.outcome, DeliveryOutcome::AcceptedPendingVerification);

    let queued = hook.queued_requests().await.expect("queued requests");
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].reason, ReconciliationReason::PendingVerification);
}

#[tokio::test]
async fn duplicate_mdn_ingress_emits_duplicate_detected_event() {
    let mdn = std::fs::read("tests/fixtures/as2_mdn_sync_ok.golden").expect("fixture");
    let bus = EventBus::new(32).expect("bus");
    let mut events = bus.subscribe_scoped_events();
    let hook = InMemoryReconciliationHook::default();
    let dedup = InMemoryDedupBackend::default();

    for _ in 0..2 {
        receive_with_mdn_with_reliability(
            &session(),
            &bus,
            As2ReceiveMdnRequest {
                payload: vec![1].into(),
                mdn_payload: mdn.clone().into(),
                mdn_mode: As2MdnMode::Synchronous,
                expected_mic: Some(EXPECTED_MIC.to_string()),
                policy: test_receive_policy(),
                original_message_id: None,
            },
            &hook,
            &dedup,
            &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
        )
        .expect("receive with dedup");
    }

    let mut duplicate_seen = false;
    for _ in 0..20 {
        let scoped = match timeout(Duration::from_millis(200), events.recv()).await {
            Ok(Some(scoped)) => scoped,
            Ok(None) | Err(_) => break,
        };

        if let asx_rs::observability::AsxEvent::DuplicateDetected {
            message_id,
            ingress,
            ..
        } = scoped.event.as_ref()
        {
            assert_eq!(message_id.as_ref(), "<msg-42@example>");
            assert_eq!(
                ingress,
                &asx_rs::observability::AsxIngressStage::As2ReceiveWithMdn
            );
            duplicate_seen = true;
            break;
        }
    }

    assert!(
        duplicate_seen,
        "expected duplicate-detected event in scoped stream"
    );
}

#[tokio::test]
async fn duplicate_async_mdn_does_not_emit_mdn_received_twice() {
    let mdn = std::fs::read("tests/fixtures/as2_mdn_async_pending.golden").expect("fixture");
    let bus = EventBus::new(32).expect("bus");
    let mut events = bus.subscribe_scoped_events();
    let hook = InMemoryReconciliationHook::default();
    let dedup = InMemoryDedupBackend::default();

    for _ in 0..2 {
        receive_with_mdn_with_reliability(
            &session(),
            &bus,
            As2ReceiveMdnRequest {
                payload: vec![1].into(),
                mdn_payload: mdn.clone().into(),
                mdn_mode: As2MdnMode::Asynchronous,
                expected_mic: Some(EXPECTED_MIC.to_string()),
                policy: test_receive_policy(),
                original_message_id: None,
            },
            &hook,
            &dedup,
            &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
        )
        .expect("receive with dedup");
    }

    let mut mdn_received_count = 0;
    for _ in 0..24 {
        let scoped = match timeout(Duration::from_millis(200), events.recv()).await {
            Ok(Some(scoped)) => scoped,
            Ok(None) | Err(_) => break,
        };

        if let asx_rs::observability::AsxEvent::MdnReceived { .. } = scoped.event.as_ref() {
            mdn_received_count += 1;
        }
    }

    assert_eq!(mdn_received_count, 1);
}
