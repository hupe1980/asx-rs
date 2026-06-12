#![cfg(feature = "as2")]
use asx::as2::send_sync;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

use asx::as2::{As2MicAlgorithm, As2SendCredentials, As2SendPolicy, As2SendRequest, SmimeCipher};
use asx::core::{InteropMode, SessionContext};
use asx::observability::{AsxEvent, EventBus};

#[tokio::test]
async fn as2_send_matches_golden_payload_and_mic() {
    let session = SessionContext::new("sess-1", "partner-a", "strict")
        .expect("session")
        .with_strict_runtime_bootstrap_validated(true);
    let bus = EventBus::new(64).expect("event bus");
    let mut scoped_rx = bus.subscribe_scoped_events();

    let payload = b"ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       *240101*1200*U*00401*000000001*0*T*:~".to_vec();

    let out = send_sync(
        &session,
        &bus,
        As2SendRequest {
            message_id: "msg-42".to_string(),
            payload,
            policy: As2SendPolicy {
                interop_mode: InteropMode::Strict,
                fail_closed_audit_events: false,
                sign: false,
                encrypt: false,
                compress: false,
                payload_content_type: None,
                as2_from_id: String::new(),
                mic_algorithm: As2MicAlgorithm::Sha256,
                encryption_cipher: SmimeCipher::Aes256Cbc,
            },
            credentials: As2SendCredentials::default(),
        },
    )
    .expect("send");

    let expected_payload =
        std::fs::read_to_string("tests/fixtures/as2_send_payload.golden").expect("payload fixture");
    let expected_mic = std::fs::read_to_string("tests/fixtures/as2_send_mic.golden")
        .expect("mic fixture")
        .trim()
        .to_string();

    assert_eq!(String::from_utf8_lossy(&out.mime.body), expected_payload);
    assert_eq!(out.mic_base64, expected_mic);

    let mut stages = Vec::new();
    for _ in 0..2 {
        let evt = scoped_rx.recv().await.expect("event");
        if evt.session_id == session.session_id() {
            stages.push(evt.event.as_ref().clone());
        }
    }

    assert!(matches!(stages[0], AsxEvent::OutboundPrepared { .. }));
    assert!(matches!(stages[1], AsxEvent::MicComputed { .. }));
}

#[cfg(feature = "interop-relaxed")]
#[tokio::test]
async fn strict_and_relaxed_policy_differs_only_when_configured() {
    let session = SessionContext::new("sess-2", "partner-b", "strict")
        .expect("session")
        .with_strict_runtime_bootstrap_validated(true);
    let bus = EventBus::new(64).expect("event bus");

    let strict = send_sync(
        &session,
        &bus,
        As2SendRequest {
            message_id: "msg-77".to_string(),
            payload: Vec::new(),
            policy: As2SendPolicy {
                interop_mode: InteropMode::Strict,
                fail_closed_audit_events: false,
                sign: true,
                encrypt: true,
                compress: false,
                payload_content_type: None,
                as2_from_id: String::new(),
                mic_algorithm: As2MicAlgorithm::Sha256,
                encryption_cipher: SmimeCipher::Aes256Cbc,
            },
            credentials: As2SendCredentials::default(),
        },
    );
    assert!(strict.is_err());

    let relaxed = send_sync(
        &session,
        &bus,
        As2SendRequest {
            message_id: "  msg-77  ".to_string(),
            payload: Vec::new(),
            policy: As2SendPolicy {
                interop_mode: InteropMode::Relaxed,
                fail_closed_audit_events: false,
                sign: false,
                encrypt: false,
                compress: false,
                payload_content_type: None,
                as2_from_id: String::new(),
                mic_algorithm: As2MicAlgorithm::Sha256,
                encryption_cipher: SmimeCipher::Aes256Cbc,
            },
            credentials: As2SendCredentials::default(),
        },
    )
    .expect("relaxed ok");

    assert_eq!(relaxed.message_id, "msg-77");
}

#[tokio::test]
async fn mic_uses_exact_octet_boundary_without_payload_rewrite() {
    let session = SessionContext::new("sess-3", "partner-c", "strict")
        .expect("session")
        .with_strict_runtime_bootstrap_validated(true);
    let bus = EventBus::new(64).expect("event bus");

    let payload = b"Content-Transfer-Encoding: binary\r\n\r\nA\r\nB\r\n--x--".to_vec();
    let content_type = "application/edi-x12";

    let out = send_sync(
        &session,
        &bus,
        As2SendRequest {
            message_id: "msg-99".to_string(),
            payload: payload.clone(),
            policy: As2SendPolicy {
                interop_mode: InteropMode::Strict,
                fail_closed_audit_events: false,
                sign: false,
                encrypt: false,
                compress: false,
                payload_content_type: Some(content_type),
                as2_from_id: String::new(),
                mic_algorithm: As2MicAlgorithm::Sha256,
                encryption_cipher: SmimeCipher::Aes256Cbc,
            },
            credentials: As2SendCredentials::default(),
        },
    )
    .expect("send");

    let mut expected_input = Vec::with_capacity(16 + content_type.len() + 4 + payload.len());
    expected_input.extend_from_slice(b"Content-Type: ");
    expected_input.extend_from_slice(content_type.as_bytes());
    expected_input.extend_from_slice(b"\r\n\r\n");
    expected_input.extend_from_slice(&payload);
    let expected_mic = STANDARD.encode(Sha256::digest(&expected_input));

    assert_eq!(out.mic_base64, expected_mic);
}
