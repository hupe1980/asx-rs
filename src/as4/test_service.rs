//! ebMS3 Test Service (§5.2.2) — standardised connectivity / ping mechanism.
//!
//! The ebMS3 Core Specification §5.2.2 defines a mandatory "Test Service" that all
//! conformant MSH implementations MUST support.  A TestService UserMessage is
//! identified by a reserved service URI and action URI.  The receiving MSH MAY reply
//! with an empty payload or a loopback of the received payload.
//!
//! ## Usage — sending a test ping
//!
//! ```rust
//! # #[cfg(feature = "interop-relaxed")]
//! # {
//! # use asx_rs::as4::test_service::{test_service_send_policy, TEST_SERVICE_URI, TEST_ACTION_URI};
//! # use asx_rs::core::InteropMode;
//! let (policy, _creds) = test_service_send_policy()
//!     .interop(InteropMode::Relaxed)
//!     .sign(false)
//!     .build()
//!     .expect("test policy");
//! assert_eq!(policy.service, TEST_SERVICE_URI);
//! assert_eq!(policy.action, TEST_ACTION_URI);
//! # }
//! ```
//!
//! ## Usage — detecting a test ping on receive
//!
//! ```rust
//! # use asx_rs::as4::test_service::is_test_service_message;
//! # use asx_rs::as4::ParsedAs4UserMessage;
//! # let msg = ParsedAs4UserMessage {
//! #     message_id: "x".into(), action: asx_rs::as4::test_service::TEST_ACTION_URI.into(),
//! #     from_party_ids: vec!["a".into()], to_party_ids: vec!["b".into()], mpc: None,
//! #     conversation_id: None, has_ws_security_header: false,
//! #     service: Some(asx_rs::as4::test_service::TEST_SERVICE_URI.into()),
//! #     ref_to_message_id: None,
//! #     original_sender: None,
//! #     final_recipient: None,
//! #     tracking_identifier: None,
//! #     timestamp: None,
//! #     wsa_headers: None,
//! # };
//! if is_test_service_message(&msg) {
//!     // respond with an echo or acknowledge and discard
//! }
//! ```

use super::{As4SendPolicyBuilder, ParsedAs4UserMessage};

/// ebMS3 Test Service URI (Core Specification §5.2.2).
///
/// Any `<eb:Service>` element with this value identifies a test/connectivity message.
pub const TEST_SERVICE_URI: &str =
    "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/service";

/// ebMS3 Test Action URI (Core Specification §5.2.2).
///
/// Any `<eb:Action>` element with this value identifies a test/connectivity message.
pub const TEST_ACTION_URI: &str =
    "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/test";

/// Returns `true` when `msg` is an **ebMS3 Test Service message** (§5.2.2).
///
/// A test message has both `<eb:Service>` = [`TEST_SERVICE_URI`] and
/// `<eb:Action>` = [`TEST_ACTION_URI`].
///
/// Detection is based on a case-sensitive comparison per ebMS3 §5.2.2.
pub fn is_test_service_message(msg: &ParsedAs4UserMessage) -> bool {
    msg.action == TEST_ACTION_URI && msg.service.as_deref() == Some(TEST_SERVICE_URI)
}

/// Create an [`As4SendPolicyBuilder`] pre-configured for the **ebMS3 Test Service**.
///
/// The builder is initialised with [`TEST_SERVICE_URI`] and [`TEST_ACTION_URI`].
/// Callers can chain further configuration (e.g., `.sign(true)`, `.signing_cert_pem(...)`)
/// before calling `.build()`.
///
/// # Example
/// ```rust
/// # #[cfg(feature = "interop-relaxed")]
/// # {
/// # use asx_rs::as4::test_service::test_service_send_policy;
/// # use asx_rs::core::InteropMode;
/// let (policy, _creds) = test_service_send_policy()
///     .interop(InteropMode::Relaxed)
///     .sign(false)
///     .build()
///     .expect("build");
/// # }
/// ```
pub fn test_service_send_policy() -> As4SendPolicyBuilder {
    As4SendPolicyBuilder::new()
        .service(TEST_SERVICE_URI, "")
        .action(TEST_ACTION_URI)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::as4::ParsedAs4UserMessage;

    fn make_msg(action: &str, service: Option<&str>) -> ParsedAs4UserMessage {
        ParsedAs4UserMessage {
            message_id: "test-id".into(),
            action: action.into(),
            from_party_ids: vec!["a".into()],
            to_party_ids: vec!["b".into()],
            mpc: None,
            conversation_id: None,
            has_ws_security_header: false,
            service: service.map(|s| s.into()),
            ref_to_message_id: None,
            original_sender: None,
            final_recipient: None,
            tracking_identifier: None,
            timestamp: None,
            wsa_headers: None,
        }
    }

    #[test]
    fn test_service_detection_matches_both_uris() {
        let msg = make_msg(TEST_ACTION_URI, Some(TEST_SERVICE_URI));
        assert!(is_test_service_message(&msg));
    }

    #[test]
    fn test_service_detection_rejects_wrong_action() {
        let msg = make_msg("urn:other:action", Some(TEST_SERVICE_URI));
        assert!(!is_test_service_message(&msg));
    }

    #[test]
    fn test_service_detection_rejects_wrong_service() {
        let msg = make_msg(TEST_ACTION_URI, Some("http://example.org/other"));
        assert!(!is_test_service_message(&msg));
    }

    #[test]
    fn test_service_detection_rejects_missing_service() {
        let msg = make_msg(TEST_ACTION_URI, None);
        assert!(!is_test_service_message(&msg));
    }

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn test_service_send_policy_sets_correct_uris() {
        let (policy, _) = test_service_send_policy()
            .interop(crate::core::InteropMode::Relaxed)
            .sign(false)
            .build()
            .expect("build");
        assert_eq!(policy.service, TEST_SERVICE_URI);
        assert_eq!(policy.action, TEST_ACTION_URI);
        assert_eq!(policy.service_type, "");
    }
}
