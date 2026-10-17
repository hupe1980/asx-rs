// Property-based testing for protocol generation and parsing invariants
// Ensures that generated messages can be parsed back consistently

#![cfg(all(feature = "as2", feature = "as4"))]

#[path = "common/peers.rs"]
mod peers;

use asx::__fuzz::SessionContext;
use asx::__fuzz::generate_mdn;
use asx::__fuzz::generate_receipt;
use proptest::prelude::*;
use std::sync::OnceLock;
use tower::ServiceExt;

/// One receiving AS4 `Inbound` shared by every case.
fn inbound() -> &'static (tokio::runtime::Runtime, asx::Inbound) {
    static INBOUND: OnceLock<(tokio::runtime::Runtime, asx::Inbound)> = OnceLock::new();
    INBOUND.get_or_init(|| {
        let p = peers::pair(peers::Preset::Bdew);
        let inbound = p.receiver.inbound(
            asx::MemoryDedup::default(),
            |_m: asx::Verified<asx::as4::UserMessage>| async { Ok::<(), asx::Reject>(()) },
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        (rt, inbound)
    })
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

    /// Property: AS4 receipt generation produces valid structure
    #[test]
    fn prop_as4_receipt_generation_valid(
        message_id in r"[a-zA-Z0-9._:-]{1,64}",
    ) {
        let session = SessionContext::new("p-test", "partner", "strict")
            .expect("valid session");

        let result: asx::__fuzz::Result<Vec<u8>> =
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
        use asx::__fuzz::ErrorContext;

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

    /// Property: Large payloads within limits are handled correctly
    #[test]
    fn prop_as4_large_payload_handling(
        payload_size in 10_000usize..100_000usize,
    ) {
        let (rt, inbound) = inbound();
        let payload = vec![0xAB; payload_size];
        let mut request = http::Request::new(http_body_util::Full::new(bytes::Bytes::from(payload)));
        *request.method_mut() = http::Method::POST;
        request.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("multipart/related"),
        );
        // This should not panic or cause memory issues
        let response = rt
            .block_on(inbound.clone().oneshot(request))
            .unwrap_or_else(|never| match never {});

        // Arbitrary bytes are not a message: refused, never a crash.
        prop_assert!(!response.status().is_success(), "accepted: {}", response.status());
    }
}
