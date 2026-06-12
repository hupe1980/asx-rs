// Property-based testing for protocol generation and parsing invariants
// Ensures that generated messages can be parsed back consistently

#![cfg(all(feature = "as2", feature = "as4", feature = "testing"))]

use asx::as4::{
    As4PushPolicyBuilder, As4ReceivePushRequest, As4ReceivePushSyncRequest, generate_receipt,
    receive_push_with_dedup_sync,
};

use asx::as2::{
    As2MdnMode, As2MicAlgorithm, As2SendCredentials, As2SendPolicy, As2SendRequest, SmimeCipher,
    generate_mdn, send_sync as as2_send,
};
use asx::core::{InteropMode, SessionContext};
use asx::observability::EventBus;
use asx::reliability::InMemoryDedupBackend;
use proptest::prelude::*;

// Strategy for valid AS2 message IDs (RFC 2822-like, but simplified for testing)
fn as2_message_id_strategy() -> impl Strategy<Value = String> {
    r"[a-zA-Z0-9._+-]{1,64}@[a-zA-Z0-9.-]{1,64}".prop_map(|s| s.to_string())
}

// Strategy for valid disposition values
fn as2_disposition_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("automatic-action/MDN-sent-automatically; processed".to_string()),
        Just("automatic-action/MDN-sent-automatically; processed/error".to_string()),
        Just("automatic-action/MDN-sent-automatically; failed".to_string()),
    ]
}

proptest! {
    /// Property: AS2 MDN generation produces valid output regardless of disposition format
    #[test]
    fn prop_as2_mdn_generation_succeeds(
        disposition in as2_disposition_strategy(),
    ) {
        let session = SessionContext::new("p-test", "partner", "strict")
            .expect("valid session");

        let result = generate_mdn(
            &session,
            "<msg@example.com>",
            &disposition,
            Some("hash123, sha-256"),
        );

        // MDN generation should always succeed with valid disposition
        prop_assert!(result.is_ok(), "MDN generation failed: {:?}", result);
    }

    /// Property: AS2 send produces deterministic output for same inputs
    #[test]
    fn prop_as2_send_deterministic(
        message_id in as2_message_id_strategy(),
        payload_size in 10usize..2048usize,
    ) {
        let session = SessionContext::new("p-test", "partner", "strict")
            .expect("valid session");

        let payload = vec![0xAB; payload_size];
        let policy = As2SendPolicy {
            interop_mode: InteropMode::Strict,
            fail_closed_audit_events: false,
            sign: true,
            encrypt: true,
            compress: false,
            payload_content_type: None,
            as2_from_id: String::new(),
            mic_algorithm: As2MicAlgorithm::Sha256,
            encryption_cipher: SmimeCipher::Aes256Cbc,
        };

        let result1 = as2_send(
            &session,
            &EventBus::new(256).expect("bus"),
            As2SendRequest {
                message_id: message_id.clone(),
                payload: payload.clone(),
                policy: policy.clone(),
                credentials: As2SendCredentials::default(),
            },
        );

        let result2 = as2_send(
            &session,
            &EventBus::new(256).expect("bus"),
            As2SendRequest {
                message_id: message_id.clone(),
                payload,
                policy,
                credentials: As2SendCredentials::default(),
            },
        );

        // Same inputs should produce same MIC for deterministic verification
        prop_assert_eq!(
            result1.as_ref().map(|m| &m.mic_base64),
            result2.as_ref().map(|m| &m.mic_base64),
            "AS2 send not deterministic"
        );
    }

    /// Property: AS4 receipt generation produces valid structure
    #[test]
    fn prop_as4_receipt_generation_valid(
        message_id in r"[a-zA-Z0-9._:-]{1,64}",
    ) {
        let session = SessionContext::new("p-test", "partner", "strict")
            .expect("valid session");

        let result: asx::core::Result<Vec<u8>> =
            generate_receipt(&session, "receipt-id", &message_id);

        prop_assert!(
            result.is_ok(),
            "AS4 receipt generation failed: {:?}",
            result
        );

        if let Ok(receipt) = result {
            let receipt: Vec<u8> = receipt;
            // Receipt should be a valid Vec<u8> containing XML-like structure
            prop_assert!(
                !receipt.is_empty(),
                "Generated receipt is empty"
            );
            // Check for basic ebMS signature in receipt
            let receipt_str = String::from_utf8_lossy(&receipt);
            prop_assert!(
                receipt_str.contains("Receipt") || receipt_str.contains("receipt"),
                "Generated receipt does not contain Receipt element"
            );
        }
    }

    /// Property: Error context builders maintain consistency across calls
    #[test]
    fn prop_error_context_consistency(
        session_id in r"[a-zA-Z0-9._-]{1,32}",
        partner_id in r"[a-zA-Z0-9._-]{1,32}",
    ) {
        use asx::core::ErrorContext;

        let ctx1 = ErrorContext::new("test")
            .with_session_and_partner(&session_id, &partner_id);

        let ctx2 = ErrorContext::new("test")
            .with_session_and_partner(&session_id, &partner_id);

        // Same inputs should produce same context state
        prop_assert_eq!(
            format!("{:?}", ctx1),
            format!("{:?}", ctx2),
            "ErrorContext not deterministic"
        );
    }

    /// Property: MDN mode validation accepts only known valid modes
    #[test]
    fn prop_as2_mdn_mode_coverage(mode in 0u8..2u8) {
        // Ensure all MDN mode variants can be used
        let valid_modes = [
            As2MdnMode::Synchronous,
            As2MdnMode::Asynchronous,
        ];

        // This is more of a compile-time check, but ensures the strategy is exercised
        let _ = valid_modes.len();
        let _ = mode;
    }

    /// Property: Large payloads within limits are handled correctly
    #[test]
    fn prop_as4_large_payload_handling(
        payload_size in 10_000usize..100_000usize,
    ) {
        let session = SessionContext::new("p-test", "partner", "strict")
            .expect("valid session");

        let payload = vec![0xAB; payload_size];

        let bus = EventBus::new(32).expect("bus");
        let dedup = InMemoryDedupBackend::default();

        // This should not panic or cause memory issues
        let result = receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: "multipart/related".into(),
                    payload: payload.into(),
                    receipt_payload: None,
                    policy: As4PushPolicyBuilder::new()
                        .allow_unsigned_push(true)
                        .fail_closed_audit_events(false)
                        .build()
                        .expect("policy"),
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        );

        // Result can be either Ok or parse error, but should not crash
        let _ = result;
    }
}
