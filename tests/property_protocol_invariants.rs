#![cfg(all(feature = "as2", feature = "as4"))]
use asx_rs::as2::generate_mdn;
use asx_rs::as4::generate_receipt;

use asx_rs::core::SessionContext;
use proptest::prelude::*;

fn session() -> SessionContext {
    SessionContext::new("prop-s1", "partner-a", "strict").expect("session")
}

proptest! {
    #[test]
    fn as2_generated_mdn_contains_required_fields(
        message_id in "[A-Za-z0-9<>@._-]{1,40}",
        disposition in "[A-Za-z0-9/;:_-]{1,64}"
    ) {
        let mdn = generate_mdn(
            &session(),
            &message_id,
            &disposition,
            Some("mic-value, sha-256"),
        ).expect("mdn");

        let text = String::from_utf8(mdn).expect("utf8");
        prop_assert!(text.contains("Final-Recipient:"));
        prop_assert!(text.contains("Original-Message-ID:"));
        prop_assert!(text.contains("Disposition:"));
        prop_assert!(text.contains("Received-Content-MIC:"));
    }

    #[test]
    fn as4_generated_receipt_contains_ref_to_message_id(
        message_id in "[A-Za-z0-9._:-]{1,48}",
    ) {
        let receipt_id = format!("receipt-{}", message_id);
        let receipt = generate_receipt(&session(), &receipt_id, &message_id).expect("receipt");
        let xml = String::from_utf8(receipt).expect("utf8");

        prop_assert!(xml.contains("<eb:RefToMessageId>"));
        prop_assert!(xml.contains(&message_id));
        prop_assert!(xml.contains("<eb:MessageId>"));
        prop_assert!(xml.contains(&receipt_id));
    }
}
