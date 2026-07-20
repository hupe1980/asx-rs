mod conversation_gate;
mod coordination;
mod large_message;
mod pull;
mod receive;
mod send;
mod send_mime;
mod services;
mod signals;
mod stream;

mod types;
pub use types::*;

mod pull_store;
pub use pull_store::As4PullEnqueueOutcome;
pub use pull_store::As4PullQueueOverflowPolicy;
pub use pull_store::{As4PullQueueSnapshot, As4PullStoreSnapshot, As4QueuedPullMessageSnapshot};
pub use pull_store::{As4PullStore, As4PullStoreLimits};

pub use conversation_gate::{As4ConversationOrderGate, ConversationGuard};
pub use coordination::{As4TopologyCoordination, ConversationGuardHandle, ConversationOrderGate};

// Free-function API — the former `*` associated functions are now
// top-level functions in the `as4` module (the module itself is the namespace).
pub use large_message::{
    As4FragmentJoiner, As4FragmentJoinerLimits, As4JoinProgress, As4JoinedLargeMessage,
    As4SplitFragmentOutput, send_sync_fragmented,
};
pub use pull::{
    As4EnqueuePullWithReliabilityRequest, As4ReceivePullWithReliabilityRequest,
    enqueue_pull_with_reliability, receive_pull_with_reliability,
};
/// Re-export of the `As4Verifier` sealing trait — available only under
/// `testing` so external crates can implement their own custom verifiers.
///
/// ```toml
/// # Enable in dev-dependencies only
/// asx-rs = { version = "0.10", features = ["as4", "testing"] }
/// ```
///
/// ```rust,ignore
/// use asx_rs::as4::{As4Verifier, verifier_seal};
///
/// struct RecordingVerifier { ... }
/// impl verifier_seal::Sealed for RecordingVerifier {}
/// impl As4Verifier for RecordingVerifier { ... }
/// ```
#[cfg(feature = "testing")]
pub use receive::private as verifier_seal;
pub use receive::{
    As4ReceivePushAsyncFragmentAwareRequest, As4ReceivePushOrderedFragmentAwareRequest,
    As4ReceivePushOrderedRequest, As4ReceivePushSyncFragmentAwareRequest,
    As4ReceivePushSyncRequest, As4Verifier, As4WsSecVerifier, receive_push_ordered,
    receive_push_ordered_fragment_aware, receive_push_with_dedup_async,
    receive_push_with_dedup_async_fragment_aware, receive_push_with_dedup_sync,
    receive_push_with_dedup_sync_fragment_aware,
};
#[cfg(feature = "testing")]
pub use receive::{
    InsecureBypassAs4Verifier, receive_push_with_dedup_async_with_custom_verifier,
    receive_push_with_dedup_sync_with_custom_verifier,
};
pub use send::{
    As4SendPreparedRequest, As4SendRequest, send_async, send_async_prepared, send_sync,
    send_sync_prepared,
};
pub use send_mime::{inject_xop_include, package_as_mime};
pub use signals::{
    generate_error_signal, generate_pull_request, generate_receipt, generate_receipt_for_output,
    generate_receipt_with_nri, generate_signed_receipt_for_output,
    generate_signed_receipt_with_nri,
};

mod parser;

pub mod mime_packaging;
pub use mime_packaging::{
    MimeAttachment, MimePackageBuilder, PayloadFilename, PayloadFilenameError,
};

pub mod pmode;
#[cfg(feature = "testing")]
pub mod test_service;

/// In-process AS4 mock endpoint for integration testing.
///
/// Available under `as4 + testing + server` features.
/// See [`mock_endpoint::MockAs4Endpoint`] for details.
#[cfg(all(feature = "testing", feature = "server"))]
pub mod mock_endpoint;

#[cfg(test)]
const DEFAULT_MPC: &str =
    "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/defaultMPC";

#[cfg(test)]
mod tests {
    use super::stream::{
        constant_time_eq, extract_multipart_related_payload_if_present, extract_xop_cid_href_bytes,
    };
    use super::*;
    use crate::core::InteropMode;
    #[cfg(feature = "interop-relaxed")]
    use crate::core::{CertHandle, OcspFailureMode, OcspMode};
    use crate::core::{ErrorCode, SessionContext};
    use crate::crypto::wssec::WsSecOutboundKeyInfoProfile;
    use crate::interop::{InteropExceptionCode, InteropExceptionPolicy};
    use crate::observability::{AsxEvent, EventBus};
    use crate::reliability::{InMemoryDedupBackend, InMemoryReconciliationHook};
    use crate::sbdh::{SBDH_NAMESPACE, SbdhDocumentIdentification, SbdhHeader, SbdhParty};
    use crate::storage::{BoxFuture, DedupStorage, ReconciliationStorage};
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509, X509NameBuilder};
    #[cfg(feature = "interop-relaxed")]
    use sha2::{Digest as _, Sha256 as sha2_Sha256};
    use std::sync::Arc;

    use tokio::time::{Duration, timeout};

    use crate::crypto::wssec::{WsSecVerifyOptions, verify_enveloped_signature};

    fn pull_payload(message_id: &str) -> Vec<u8> {
        multipart_user_message_payload(message_id, "SubmitOrder", None, b"pull-payload")
    }

    fn test_sbdh_header(instance_identifier: &str) -> SbdhHeader {
        SbdhHeader {
            header_version: "1.0".into(),
            sender: SbdhParty {
                identifier: "0007:1234567890123".into(),
                authority: "iso6523-actorid-upis".into(),
            },
            receiver: SbdhParty {
                identifier: "0007:9876543210987".into(),
                authority: "iso6523-actorid-upis".into(),
            },
            document_identification: SbdhDocumentIdentification {
                standard: "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2".into(),
                type_version: "2.1".into(),
                instance_identifier: instance_identifier.into(),
                r#type: "Invoice".into(),
                multiple_type: false,
                creation_date_and_time: "2026-05-27T00:00:00+00:00".into(),
            },
        }
    }

    fn multipart_user_message_payload(
        message_id: &str,
        action: &str,
        conversation_id: Option<&str>,
        payload_bytes: &[u8],
    ) -> Vec<u8> {
        let boundary = "asx-test-boundary";
        let cid = format!("payload-{message_id}@example.com");
        let conversation_xml = conversation_id
            .map(|id| format!("<eb:ConversationId>{id}</eb:ConversationId>"))
            .unwrap_or_default();

        let mime_prefix = format!(
            "--{boundary}\r\n\
Content-Type: application/xop+xml; charset=UTF-8; type=\"application/soap+xml\"\r\n\
Content-ID: <soap-root@example.com>\r\n\
\r\n\
<S12:Envelope xmlns:S12=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:eb=\"http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/\" xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:xop=\"http://www.w3.org/2004/08/xop/include\">\
    <S12:Header><eb:Messaging S12:mustUnderstand=\"true\"><eb:UserMessage><eb:MessageInfo><eb:MessageId>{message_id}</eb:MessageId></eb:MessageInfo><eb:PartyInfo><eb:From><eb:PartyId>sender-a</eb:PartyId></eb:From><eb:To><eb:PartyId>receiver-b</eb:PartyId></eb:To></eb:PartyInfo><eb:CollaborationInfo><eb:Action>{action}</eb:Action>{conversation_xml}</eb:CollaborationInfo><eb:MessageProperties><eb:Property name=\"originalSender\" value=\"sender-a\"/><eb:Property name=\"finalRecipient\" value=\"receiver-b\"/><eb:Property name=\"trackingIdentifier\" value=\"{message_id}\"/></eb:MessageProperties></eb:UserMessage></eb:Messaging><wsse:Security></wsse:Security></S12:Header><S12:Body><xop:Include href=\"cid:{cid}\"/></S12:Body></S12:Envelope>\r\n\
--{boundary}\r\n\
Content-Type: application/octet-stream\r\n\
Content-ID: <{cid}>\r\n\
\r\n"
        );
        let mime_suffix = format!("\r\n--{boundary}--\r\n");

        let mut out = mime_prefix.into_bytes();
        out.extend_from_slice(payload_bytes);
        out.extend_from_slice(mime_suffix.as_bytes());
        out
    }

    #[test]
    fn extract_xop_cid_href_bytes_returns_cid_without_utf8_decoding_entire_soap() {
        let soap = b"<S12:Envelope><S12:Body><xop:Include href=\"cid:payload-123@example.com\"/></S12:Body></S12:Envelope>";
        let cid = extract_xop_cid_href_bytes(soap).expect("cid");
        assert_eq!(cid, "payload-123@example.com");
    }

    #[test]
    fn extract_xop_cid_href_bytes_rejects_non_utf8_cid_segment() {
        let soap =
            b"<S12:Envelope><S12:Body><xop:Include href=\"cid:\xFF\"/></S12:Body></S12:Envelope>";
        assert!(extract_xop_cid_href_bytes(soap).is_none());
    }

    #[test]
    fn multipart_content_id_matching_accepts_mixed_case_cid_prefix() {
        let session = SessionContext::new("s-multipart-cid", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let multipart = concat!(
            "--boundary123\r\n",
            "Content-Type: application/xop+xml; charset=UTF-8; type=\"application/soap+xml\"\r\n",
            "Content-ID: <soap-root@example.com>\r\n",
            "\r\n",
            "<S12:Envelope xmlns:S12=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:xop=\"http://www.w3.org/2004/08/xop/include\"><S12:Body><xop:Include href=\"cid:payload-123@example.com\"/></S12:Body></S12:Envelope>\r\n",
            "--boundary123\r\n",
            "Content-Type: application/octet-stream\r\n",
            "Content-ID: <CID:payload-123@example.com>\r\n",
            "\r\n",
            "payload-bytes\r\n",
            "--boundary123--\r\n"
        )
        .as_bytes();

        let parsed = extract_multipart_related_payload_if_present(
            multipart,
            "multipart/related; boundary=boundary123",
            &session,
            "as4_receive_push",
        )
        .expect("multipart parse");

        let parsed = parsed.expect("multipart payload");
        assert_eq!(parsed.payload_attachment, Some(b"payload-bytes".as_slice()));
        assert_eq!(parsed.payload_content_id, Some("payload-123@example.com"));
    }

    struct DurableTestDedup(InMemoryDedupBackend);

    impl DedupStorage for DurableTestDedup {
        fn is_durable(&self) -> bool {
            true
        }

        fn cluster_safe(&self) -> bool {
            true
        }

        fn first_seen<'a>(
            &'a self,
            idempotency_key: &'a str,
        ) -> BoxFuture<'a, crate::core::Result<bool>> {
            self.0.first_seen(idempotency_key)
        }
    }

    fn reliability() -> (DurableTestReconciliation, DurableTestDedup) {
        (
            DurableTestReconciliation(InMemoryReconciliationHook::default()),
            DurableTestDedup(InMemoryDedupBackend::default()),
        )
    }

    struct DurableTestReconciliation(InMemoryReconciliationHook);

    impl ReconciliationStorage for DurableTestReconciliation {
        fn is_durable(&self) -> bool {
            true
        }

        fn cluster_safe(&self) -> bool {
            true
        }

        fn enqueue<'a>(
            &'a self,
            request: crate::reliability::ReconciliationRequest,
        ) -> BoxFuture<'a, crate::core::Result<bool>> {
            self.0.enqueue(request)
        }

        fn queued_requests(
            &self,
        ) -> BoxFuture<'_, crate::core::Result<Vec<crate::reliability::ReconciliationRequest>>>
        {
            self.0.queued_requests()
        }

        fn resolve<'a>(
            &'a self,
            idempotency_key: &'a str,
        ) -> BoxFuture<'a, crate::core::Result<bool>> {
            self.0.resolve(idempotency_key)
        }
    }

    fn durable_reliability() -> (DurableTestReconciliation, DurableTestDedup) {
        (
            DurableTestReconciliation(InMemoryReconciliationHook::default()),
            DurableTestDedup(InMemoryDedupBackend::default()),
        )
    }

    fn test_as4_credentials() -> As4SendCredentials {
        let rsa = Rsa::generate(2048).expect("rsa");
        let pkey = PKey::from_rsa(rsa).expect("pkey");

        let mut name = X509NameBuilder::new().expect("name builder");
        name.append_entry_by_nid(Nid::COMMONNAME, "asx-as4-test")
            .expect("cn");
        let name = name.build();

        let mut serial = BigNum::new().expect("serial");
        serial
            .pseudo_rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
            .expect("serial rand");
        let serial = serial.to_asn1_integer().expect("serial asn1");

        let mut builder = X509::builder().expect("x509 builder");
        builder.set_version(2).expect("version");
        builder.set_serial_number(&serial).expect("serial");
        builder.set_subject_name(&name).expect("subject");
        builder.set_issuer_name(&name).expect("issuer");
        builder.set_pubkey(&pkey).expect("pubkey");
        let not_before = Asn1Time::days_from_now(0).expect("not_before");
        let not_after = Asn1Time::days_from_now(365).expect("not_after");
        builder.set_not_before(&not_before).expect("nb");
        builder.set_not_after(&not_after).expect("na");
        builder
            .sign(&pkey, MessageDigest::sha256())
            .expect("sign cert");
        let cert = builder.build();

        As4SendCredentials {
            signing_cert_pem: Some(cert.to_pem().expect("cert pem").into()),
            signing_key_pem: Some(pkey.private_key_to_pem_pkcs8().expect("private key pem")),
            recipient_cert_pem: Some(cert.to_pem().expect("recipient cert pem").into()),
        }
    }

    /// Create a session that trusts the certificate embedded in `creds`.
    /// Required for tests that receive signed messages — PKIX validation is
    /// fail-closed and rejects signatures when no trust anchor is configured.
    #[cfg(feature = "interop-relaxed")]
    fn session_with_trust(
        session_id: &str,
        partner_id: &str,
        creds: &As4SendCredentials,
    ) -> SessionContext {
        let cert_pem = creds
            .signing_cert_pem
            .as_ref()
            .expect("test creds must have signing cert");
        let cert_pem_str =
            String::from_utf8(cert_pem.to_vec()).expect("cert pem must be valid utf8");

        // Compute SHA-256 fingerprint of the cert DER so the verifier can pin it.
        let cert = openssl::x509::X509::from_pem(cert_pem).expect("valid certificate PEM");
        let der = cert.to_der().expect("valid certificate DER");
        let digest = sha2_Sha256::digest(&der);
        let fingerprint: String = digest
            .iter()
            .flat_map(|b| {
                [
                    char::from_digit((b >> 4) as u32, 16).unwrap(),
                    char::from_digit((b & 0x0f) as u32, 16).unwrap(),
                ]
            })
            .collect();

        SessionContext::new(session_id, partner_id, "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true)
            .with_cert_handle(CertHandle {
                trust_anchor_pems: vec![cert_pem_str],
                ocsp_mode: OcspMode::Disabled,
                ocsp_failure_mode: OcspFailureMode::HardFail,
                fingerprint_sha256: fingerprint,
                ..CertHandle::new("test-cert")
            })
            .expect("cert handle")
    }

    #[test]
    fn receive_push_with_dedup_rejects_empty_payload() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let dedup = DurableTestDedup(InMemoryDedupBackend::default());
        let err = receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: "application/soap+xml".into(),
                    payload: Arc::from([]),
                    receipt_payload: None,
                    policy: As4PushPolicy {
                        require_signed_push: false,
                        fail_closed_audit_events: false,
                        ..As4PushPolicy::default()
                    },
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect_err("empty payload must fail");
        assert!(matches!(
            err.code,
            ErrorCode::ParseFailed | ErrorCode::PolicyViolation
        ));
    }

    #[test]
    fn receive_push_with_dedup_rejects_non_xml_payload() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let dedup = DurableTestDedup(InMemoryDedupBackend::default());
        let err = receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: "application/soap+xml".into(),
                    payload: Arc::from(b"\x00\x01\x02garbage bytes not xml".as_slice()),
                    receipt_payload: None,
                    policy: As4PushPolicy {
                        require_signed_push: false,
                        fail_closed_audit_events: false,
                        ..As4PushPolicy::default()
                    },
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect_err("non-XML payload must fail");
        assert!(matches!(
            err.code,
            ErrorCode::ParseFailed | ErrorCode::PolicyViolation
        ));
    }

    #[test]
    fn as4_send_rejects_missing_signing_credentials() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let err = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-send-1".to_string(),
                payload: b"payload".to_vec(),
                policy: As4SendPolicy::default(),
                credentials: Some(As4SendCredentials::default()),
                payload_filename: None,
            },
        )
        .expect_err("missing creds must fail");
        assert_eq!(err.code, ErrorCode::PolicyViolation);
    }

    #[tokio::test]
    async fn as4_send_async_rejects_missing_signing_credentials() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let err = send_async(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-send-async-1".to_string(),
                payload: b"payload".to_vec(),
                policy: As4SendPolicy::default(),
                credentials: Some(As4SendCredentials::default()),
                payload_filename: None,
            },
        )
        .await
        .expect_err("missing creds must fail");
        assert_eq!(err.code, ErrorCode::PolicyViolation);
    }

    #[test]
    fn as4_send_mime_mode_emits_multipart_related() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let policy = As4SendPolicy {
            sign: true,
            payload_packaging_mode: super::pmode::PayloadPackagingMode::MimeAttachment,
            ..Default::default()
        };

        let out = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-send-mime-1".to_string(),
                payload: b"payload".to_vec(),
                policy,
                credentials: Some(test_as4_credentials()),
                payload_filename: None,
            },
        )
        .expect("send");

        assert!(
            out.http_content_type
                .to_ascii_lowercase()
                .starts_with("multipart/related;"),
            "expected multipart content type, got: {}",
            out.http_content_type
        );
        assert!(
            out.http_content_type
                .contains("start=\"<soap-body@example.com>\""),
            "missing MIME start parameter"
        );

        let mime_body = std::str::from_utf8(&out.soap_envelope.body).expect("mime body utf8");
        assert!(
            mime_body.contains("<xop:Include href=\"cid:payload-"),
            "xop include reference must be present"
        );
        assert!(
            mime_body.contains("<ds:Reference URI=\"cid:payload-"),
            "SignedInfo must include cid payload reference in MIME mode"
        );
        assert!(
            !mime_body.contains("<asx:Base64>"),
            "embedded base64 must be removed in MIME mode"
        );
    }

    // --- FR-001 / BUG-001: Content-Disposition on payload attachment ----------

    #[test]
    fn as4_send_emits_content_disposition_attachment_when_no_filename() {
        // PEPPOL AS4 profile requires Content-Disposition on every payload
        // part even when no explicit filename is set.
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let policy = As4SendPolicy {
            sign: true,
            payload_packaging_mode: super::pmode::PayloadPackagingMode::MimeAttachment,
            ..Default::default()
        };

        let out = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-cd-none-1".to_string(),
                payload: b"EDIFACT".to_vec(),
                policy,
                credentials: Some(test_as4_credentials()),
                payload_filename: None,
            },
        )
        .expect("send");

        let mime_body = std::str::from_utf8(&out.soap_envelope.body).expect("utf8");
        // Baseline Content-Disposition must always be present.
        assert!(
            mime_body.contains("Content-Disposition: attachment"),
            "Content-Disposition: attachment must always be emitted for PEPPOL conformance"
        );
        // No filename= parameter when none was supplied.
        assert!(
            !mime_body.contains("filename="),
            "filename= must not appear when payload_filename is None"
        );
    }

    #[test]
    fn as4_send_emits_content_disposition_with_filename_when_set() {
        // BDEW §AF §2.12 mandates filename in Content-Disposition.
        // The caller builds the filename string however their profile requires,
        // then wraps it in `PayloadFilename` for safe embedding.
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let policy = As4SendPolicy {
            sign: true,
            payload_packaging_mode: super::pmode::PayloadPackagingMode::MimeAttachment,
            ..Default::default()
        };

        let filename = "MSCONS_4011234000000_4011234000001_260101_1230_REF123.txt";
        let out = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-cd-fname-1".to_string(),
                payload: b"EDIFACT".to_vec(),
                policy,
                credentials: Some(test_as4_credentials()),
                payload_filename: Some(
                    super::mime_packaging::PayloadFilename::new(filename).unwrap(),
                ),
            },
        )
        .expect("send");

        let mime_body = std::str::from_utf8(&out.soap_envelope.body).expect("utf8");
        let expected = format!("Content-Disposition: attachment; filename=\"{filename}\"");
        assert!(
            mime_body.contains(&expected),
            "expected '{expected}' in MIME body"
        );
    }

    // --- End FR-001 / BUG-001 -------------------------------------------------
    // Note: PayloadFilename validation tests (header injection, empty string,
    // over-length) live in `mime_packaging::tests` — that is the type boundary
    // where invariants are enforced. The send pipeline never receives an
    // already-invalid PayloadFilename; the type system prevents it.

    #[test]
    fn as4_send_wraps_business_payload_with_sbdh_when_configured() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let policy = As4SendPolicy {
            sign: true,
            sbdh_header: Some(test_sbdh_header("urn:uuid:asx-sbdh-send")),
            payload_packaging_mode: super::pmode::PayloadPackagingMode::MimeAttachment,
            ..Default::default()
        };

        let out = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-send-sbdh-1".to_string(),
                payload: b"<Invoice xmlns=\"urn:test\"><ID>INV-1</ID></Invoice>".to_vec(),
                policy,
                credentials: Some(test_as4_credentials()),
                payload_filename: None,
            },
        )
        .expect("send with sbdh");

        let mime_body = std::str::from_utf8(&out.soap_envelope.body).expect("mime body utf8");
        assert!(mime_body.contains("<StandardBusinessDocument xmlns=\""));
        assert!(mime_body.contains(SBDH_NAMESPACE));
        assert!(mime_body.contains("<HeaderVersion>1.0</HeaderVersion>"));
        assert!(mime_body.contains("urn:uuid:asx-sbdh-send"));
    }

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn send_with_custom_action_and_service_appears_in_soap() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let (mut policy, _) = As4SendPolicyBuilder::new()
            .interop(InteropMode::Relaxed)
            .sign(false)
            .build()
            .expect("build policy");
        policy.action = "urn:acme:SubmitInvoice".to_string();
        policy.service = "http://acme.example/services".to_string();
        policy.service_type = "acme-service-type".to_string();
        let out = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-custom-action".to_string(),
                payload: b"data".to_vec(),
                policy,
                credentials: Some(test_as4_credentials()),
                payload_filename: None,
            },
        )
        .expect("send");
        let xml = std::str::from_utf8(&out.soap_envelope.body).expect("utf8");
        assert!(xml.contains("urn:acme:SubmitInvoice"), "action not emitted");
        assert!(
            xml.contains("http://acme.example/services"),
            "service not emitted"
        );
        assert!(
            xml.contains("acme-service-type"),
            "service_type not emitted"
        );
        assert_eq!(out.action, "urn:acme:SubmitInvoice");
    }

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn two_way_mep_send_embeds_ref_to_message_id() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let (mut policy, _) = As4SendPolicyBuilder::new()
            .interop(InteropMode::Relaxed)
            .sign(false)
            .build()
            .expect("build policy");
        policy.ref_to_message_id = Some("original-msg-001".to_string());
        let out = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-reply".to_string(),
                payload: b"response payload".to_vec(),
                policy,
                credentials: Some(test_as4_credentials()),
                payload_filename: None,
            },
        )
        .expect("send");
        let xml = std::str::from_utf8(&out.soap_envelope.body).expect("utf8");
        assert!(
            xml.contains("<ebms:RefToMessageId>original-msg-001</ebms:RefToMessageId>"),
            "RefToMessageId not emitted in SOAP: {xml}"
        );
        assert_eq!(out.ref_to_message_id.as_deref(), Some("original-msg-001"));
    }

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn two_way_mep_receive_extracts_ref_to_message_id() {
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let creds = test_as4_credentials();
        let session = session_with_trust("s1", "p1", &creds);
        // Build a signed reply message so the receiver can accept it under Strict interop
        let (mut policy, built_creds) = As4SendPolicyBuilder::new()
            .signing_cert_pem(creds.signing_cert_pem.clone().unwrap())
            .signing_key_pem(creds.signing_key_pem.clone().unwrap())
            .build()
            .expect("build policy");
        policy.interop = InteropMode::Strict;
        policy.payload_packaging_mode = super::pmode::PayloadPackagingMode::MimeAttachment;
        policy.ref_to_message_id = Some("original-msg-002".to_string());
        let out = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-reply-2".to_string(),
                payload: b"reply payload".to_vec(),
                policy,
                credentials: Some(built_creds),
                payload_filename: None,
            },
        )
        .expect("send");

        let (_, dedup) = reliability();
        let received = receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: out.http_content_type.clone(),
                    payload: out.soap_envelope.body,
                    receipt_payload: None,
                    policy: As4PushPolicy {
                        interop: InteropMode::Relaxed,
                        interop_exceptions: InteropExceptionPolicy::default(),
                        require_signed_receipt: false,
                        require_signed_push: true,
                        fail_closed_audit_events: false,
                        inbound_decryption_key_pem: None,
                        require_encrypted_inbound: false,
                        timestamp_freshness_window: None,
                        fragment_scope_policy: FragmentScopePolicy::UseSoapSenderId,
                    },
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect("receive")
        .unwrap_output();
        assert_eq!(
            received.user_message.ref_to_message_id.as_deref(),
            Some("original-msg-002"),
            "ref_to_message_id not extracted from parsed UserMessage"
        );
    }

    #[test]
    fn as4_send_signed_xmlsig_roundtrip_verifies() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let out = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-send-3".to_string(),
                payload: b"payload".to_vec(),
                policy: As4SendPolicy {
                    interop: InteropMode::Strict,
                    outbound_key_info_profile: WsSecOutboundKeyInfoProfile::X509DataAndRsaKeyValue,
                    sign: true,
                    encrypt: false,
                    compress: false,
                    payload_packaging_mode: super::pmode::PayloadPackagingMode::MimeAttachment,
                    ..As4SendPolicy::default()
                },
                credentials: Some(test_as4_credentials()),
                payload_filename: None,
            },
        )
        .expect("send");

        let multipart = extract_multipart_related_payload_if_present(
            &out.soap_envelope.body,
            &out.http_content_type,
            &session,
            "as4_send_verify_sig",
        )
        .expect("multipart parse")
        .expect("multipart payload");
        let payload_cid = multipart.payload_content_id.expect("payload cid");
        let payload_bytes = multipart.payload_attachment.expect("payload attachment");
        let payload_uri = format!("cid:{payload_cid}");
        let external_refs = [(payload_uri.as_str(), payload_bytes)];
        let xml = std::str::from_utf8(multipart.soap_xml).expect("utf8");
        assert!(xml.contains("<ds:Signature"), "signature should exist");
        verify_enveloped_signature(
            xml,
            WsSecVerifyOptions::new().with_external_references(&external_refs),
        )
        .expect("verify");
    }

    #[test]
    fn as4_send_x509data_only_profile_omits_rsa_keyvalue() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let out = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-send-x509-only".to_string(),
                payload: b"payload".to_vec(),
                policy: As4SendPolicy {
                    interop: InteropMode::Strict,
                    outbound_key_info_profile: WsSecOutboundKeyInfoProfile::X509DataOnly,
                    sign: true,
                    encrypt: false,
                    compress: false,
                    payload_packaging_mode: super::pmode::PayloadPackagingMode::MimeAttachment,
                    ..As4SendPolicy::default()
                },
                credentials: Some(test_as4_credentials()),
                payload_filename: None,
            },
        )
        .expect("send");

        let multipart = extract_multipart_related_payload_if_present(
            &out.soap_envelope.body,
            &out.http_content_type,
            &session,
            "as4_send_verify_keyinfo",
        )
        .expect("multipart parse")
        .expect("multipart payload");
        let payload_cid = multipart.payload_content_id.expect("payload cid");
        let payload_bytes = multipart.payload_attachment.expect("payload attachment");
        let payload_uri = format!("cid:{payload_cid}");
        let external_refs = [(payload_uri.as_str(), payload_bytes)];
        let xml = std::str::from_utf8(multipart.soap_xml).expect("utf8");
        assert!(xml.contains("<ds:X509Data>"));
        assert!(!xml.contains("<ds:RSAKeyValue>"));

        assert!(xml.contains("<ds:Signature"), "signature should exist");
        verify_enveloped_signature(
            xml,
            WsSecVerifyOptions::new().with_external_references(&external_refs),
        )
        .expect("verify");
    }

    #[test]
    fn as4_send_encrypt_emits_xmlenc_payload() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let out = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-send-4".to_string(),
                payload: b"payload".to_vec(),
                policy: As4SendPolicy {
                    interop: InteropMode::Strict,
                    outbound_key_info_profile: WsSecOutboundKeyInfoProfile::X509DataAndRsaKeyValue,
                    sign: true,
                    encrypt: true,
                    compress: false,
                    payload_packaging_mode: super::pmode::PayloadPackagingMode::MimeAttachment,
                    ..As4SendPolicy::default()
                },
                credentials: Some(test_as4_credentials()),
                payload_filename: None,
            },
        )
        .expect("send encrypt");

        let multipart = extract_multipart_related_payload_if_present(
            &out.soap_envelope.body,
            &out.http_content_type,
            &session,
            "as4_send_encrypt_payload",
        )
        .expect("multipart parse")
        .expect("multipart payload");
        let attachment = multipart
            .payload_attachment
            .expect("multipart payload attachment");
        let encrypted_xml = std::str::from_utf8(attachment).expect("xml payload");
        assert!(encrypted_xml.contains("xenc:EncryptedData"));
        assert!(encrypted_xml.contains("xenc:EncryptedKey"));
    }

    #[test]
    fn as4_send_encrypts_soap_header_when_requested() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let out = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-send-4b".to_string(),
                payload: b"payload".to_vec(),
                policy: As4SendPolicy {
                    interop: InteropMode::Strict,
                    outbound_key_info_profile: WsSecOutboundKeyInfoProfile::X509DataAndRsaKeyValue,
                    sign: true,
                    encrypt: false,
                    encrypt_soap_headers: true,
                    compress: false,
                    payload_packaging_mode: super::pmode::PayloadPackagingMode::MimeAttachment,
                    ..As4SendPolicy::default()
                },
                credentials: Some(test_as4_credentials()),
                payload_filename: None,
            },
        )
        .expect("send header encrypt");

        let multipart = extract_multipart_related_payload_if_present(
            &out.soap_envelope.body,
            &out.http_content_type,
            &session,
            "as4_send_encrypt_soap_header",
        )
        .expect("multipart parse")
        .expect("multipart payload");
        let xml = std::str::from_utf8(multipart.soap_xml).expect("utf8");
        assert!(xml.contains("xenc:EncryptedHeader"));
        assert!(xml.contains("xenc:EncryptedData"));
        assert!(!xml.contains("<ebms:Messaging"));
    }

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn as4_receive_push_decrypts_outbound_xmlenc_loop() {
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let creds = test_as4_credentials();
        let session = session_with_trust("s1", "p1", &creds);
        let outbound = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-send-5".to_string(),
                payload: b"payload".to_vec(),
                policy: As4SendPolicy {
                    interop: InteropMode::Strict,
                    outbound_key_info_profile: WsSecOutboundKeyInfoProfile::X509DataOnly,
                    sign: true,
                    encrypt: true,
                    compress: false,
                    payload_packaging_mode: super::pmode::PayloadPackagingMode::MimeAttachment,
                    ..As4SendPolicy::default()
                },
                credentials: Some(creds.clone()),
                payload_filename: None,
            },
        )
        .expect("send encrypt+sign");

        let (_, dedup) = reliability();
        let received = receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: outbound.http_content_type.clone(),
                    payload: outbound.soap_envelope.body,
                    receipt_payload: None,
                    policy: As4PushPolicy {
                        interop: InteropMode::Relaxed,
                        interop_exceptions: InteropExceptionPolicy::default(),
                        require_signed_receipt: false,
                        require_signed_push: true,
                        fail_closed_audit_events: false,
                        inbound_decryption_key_pem: creds.signing_key_pem.clone().map(Arc::from),
                        require_encrypted_inbound: false,
                        timestamp_freshness_window: None,
                        fragment_scope_policy: FragmentScopePolicy::UseSoapSenderId,
                    },
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect("receive and decrypt")
        .unwrap_output();

        assert_eq!(received.payload.as_ref().as_ref(), b"payload");
    }

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn as4_receive_push_accepts_multipart_related_payload() {
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let creds = test_as4_credentials();
        let session = session_with_trust("s-mime-recv", "p1", &creds);

        let outbound = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-send-mime-recv".to_string(),
                payload: b"payload-mime".to_vec(),
                policy: As4SendPolicy {
                    interop: InteropMode::Strict,
                    outbound_key_info_profile: WsSecOutboundKeyInfoProfile::X509DataOnly,
                    sign: true,
                    encrypt: false,
                    compress: false,
                    payload_packaging_mode: super::pmode::PayloadPackagingMode::MimeAttachment,
                    ..As4SendPolicy::default()
                },
                credentials: Some(creds.clone()),
                payload_filename: None,
            },
        )
        .expect("send mime");

        let (_, dedup) = reliability();
        let received = receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: outbound.http_content_type.clone(),
                    payload: outbound.soap_envelope.body,
                    receipt_payload: None,
                    policy: As4PushPolicy {
                        interop: InteropMode::Relaxed,
                        interop_exceptions: InteropExceptionPolicy::default(),
                        require_signed_receipt: false,
                        require_signed_push: true,
                        fail_closed_audit_events: false,
                        inbound_decryption_key_pem: None,
                        require_encrypted_inbound: false,
                        timestamp_freshness_window: None,
                        fragment_scope_policy: FragmentScopePolicy::UseSoapSenderId,
                    },
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect("receive mime")
        .unwrap_output();

        assert_eq!(received.payload.as_ref().as_ref(), b"payload-mime");
        assert_eq!(received.user_message.message_id, "msg-send-mime-recv");
    }

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn as4_receive_unwraps_sbdh_payload_when_present() {
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let creds = test_as4_credentials();
        let session = session_with_trust("s-sbdh-recv", "p1", &creds);

        let policy = As4SendPolicy {
            sign: true,
            payload_packaging_mode: super::pmode::PayloadPackagingMode::MimeAttachment,
            sbdh_header: Some(test_sbdh_header("urn:uuid:asx-sbdh-recv")),
            ..As4SendPolicy::default()
        };

        let business_payload = b"<Invoice xmlns=\"urn:test\"><ID>INV-2</ID></Invoice>";
        let outbound = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-sbdh-roundtrip".to_string(),
                payload: business_payload.to_vec(),
                policy,
                credentials: Some(creds),
                payload_filename: None,
            },
        )
        .expect("send sbdh payload");

        let (_, dedup) = reliability();
        let received = receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: outbound.http_content_type.clone(),
                    payload: outbound.soap_envelope.body,
                    receipt_payload: None,
                    policy: As4PushPolicy {
                        interop: InteropMode::Relaxed,
                        interop_exceptions: InteropExceptionPolicy::default(),
                        require_signed_receipt: false,
                        require_signed_push: true,
                        fail_closed_audit_events: false,
                        inbound_decryption_key_pem: None,
                        require_encrypted_inbound: false,
                        timestamp_freshness_window: None,
                        fragment_scope_policy: FragmentScopePolicy::UseSoapSenderId,
                    },
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect("receive sbdh payload")
        .unwrap_output();

        let sbdh = received.sbdh_header.expect("sbdh header parsed");
        assert_eq!(sbdh.sender.identifier, "0007:1234567890123");
        assert_eq!(sbdh.receiver.identifier, "0007:9876543210987");
        assert_eq!(
            received.payload.as_ref().as_ref(),
            business_payload,
            "business payload should be unwrapped from SBDH envelope"
        );
    }

    #[cfg(feature = "interop-relaxed")]
    #[tokio::test]
    async fn as4_receive_push_with_dedup_async_accepts_multipart_related_payload() {
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let creds = test_as4_credentials();
        let session = session_with_trust("s-mime-recv-async", "p1", &creds);

        let outbound = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-send-mime-recv-async".to_string(),
                payload: b"payload-mime-async".to_vec(),
                policy: As4SendPolicy {
                    interop: InteropMode::Strict,
                    outbound_key_info_profile: WsSecOutboundKeyInfoProfile::X509DataOnly,
                    sign: true,
                    encrypt: false,
                    compress: false,
                    payload_packaging_mode: super::pmode::PayloadPackagingMode::MimeAttachment,
                    ..As4SendPolicy::default()
                },
                credentials: Some(creds.clone()),
                payload_filename: None,
            },
        )
        .expect("send mime");

        let (_, dedup) = reliability();
        let dedup_backend: Arc<dyn crate::storage::DedupStorage> = Arc::new(dedup);
        let received = receive_push_with_dedup_async(
            &session,
            &bus,
            As4ReceivePushRequest {
                http_content_type: outbound.http_content_type.clone(),
                payload: outbound.soap_envelope.body,
                receipt_payload: None,
                policy: As4PushPolicy {
                    interop: InteropMode::Relaxed,
                    interop_exceptions: InteropExceptionPolicy::default(),
                    require_signed_receipt: false,
                    require_signed_push: true,
                    fail_closed_audit_events: false,
                    inbound_decryption_key_pem: None,
                    require_encrypted_inbound: false,
                    timestamp_freshness_window: None,
                    fragment_scope_policy: FragmentScopePolicy::UseSoapSenderId,
                },
                authenticated_sender_scope: None,
            },
            dedup_backend,
        )
        .await
        .expect("receive mime")
        .unwrap_output();

        assert_eq!(received.payload.as_ref().as_ref(), b"payload-mime-async");
        assert_eq!(received.user_message.message_id, "msg-send-mime-recv-async");
    }

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn as4_receive_push_rejects_multipart_root_part_with_non_xop_content_type() {
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let creds = test_as4_credentials();
        let session = session_with_trust("s-mime-root-type", "p1", &creds);

        let outbound = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-send-mime-root-type".to_string(),
                payload: b"payload-mime".to_vec(),
                policy: As4SendPolicy {
                    interop: InteropMode::Strict,
                    outbound_key_info_profile: WsSecOutboundKeyInfoProfile::X509DataOnly,
                    sign: true,
                    encrypt: false,
                    compress: false,
                    payload_packaging_mode: super::pmode::PayloadPackagingMode::MimeAttachment,
                    ..As4SendPolicy::default()
                },
                credentials: Some(creds.clone()),
                payload_filename: None,
            },
        )
        .expect("send mime");

        let tampered = String::from_utf8(outbound.soap_envelope.body.to_vec())
            .expect("mime utf8")
            .replacen(
                "Content-Type: application/xop+xml; charset=UTF-8",
                "Content-Type: text/plain; charset=UTF-8",
                1,
            )
            .into_bytes();

        let (_, dedup) = reliability();
        let err = receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: outbound.http_content_type.clone(),
                    payload: Arc::from(tampered),
                    receipt_payload: None,
                    policy: As4PushPolicy {
                        interop: InteropMode::Relaxed,
                        interop_exceptions: InteropExceptionPolicy::default(),
                        require_signed_receipt: false,
                        require_signed_push: true,
                        fail_closed_audit_events: false,
                        inbound_decryption_key_pem: None,
                        require_encrypted_inbound: false,
                        timestamp_freshness_window: None,
                        fragment_scope_policy: FragmentScopePolicy::UseSoapSenderId,
                    },
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect_err("multipart root part with non-xop content type must be rejected");

        assert_eq!(err.code, ErrorCode::ParseFailed);
    }

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn as4_receive_push_rejects_tampered_multipart_payload_reference_digest() {
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let creds = test_as4_credentials();
        let session = session_with_trust("s-mime-recv-tamper", "p1", &creds);

        let outbound = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-send-mime-recv-tamper".to_string(),
                payload: b"payload-mime".to_vec(),
                policy: As4SendPolicy {
                    interop: InteropMode::Strict,
                    outbound_key_info_profile: WsSecOutboundKeyInfoProfile::X509DataOnly,
                    sign: true,
                    encrypt: false,
                    compress: false,
                    payload_packaging_mode: super::pmode::PayloadPackagingMode::MimeAttachment,
                    ..As4SendPolicy::default()
                },
                credentials: Some(creds.clone()),
                payload_filename: None,
            },
        )
        .expect("send mime");

        let mut tampered = outbound.soap_envelope.body.to_vec();
        if let Some(idx) = tampered
            .windows(b"payload-mime".len())
            .position(|w| w == b"payload-mime")
        {
            tampered[idx] = b'X';
        } else {
            panic!("expected payload marker to tamper");
        }

        let (_, dedup) = reliability();
        let err = receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: outbound.http_content_type.clone(),
                    payload: Arc::from(tampered),
                    receipt_payload: None,
                    policy: As4PushPolicy {
                        interop: InteropMode::Relaxed,
                        interop_exceptions: InteropExceptionPolicy::default(),
                        require_signed_receipt: false,
                        require_signed_push: true,
                        fail_closed_audit_events: false,
                        inbound_decryption_key_pem: None,
                        require_encrypted_inbound: false,
                        timestamp_freshness_window: None,
                        fragment_scope_policy: FragmentScopePolicy::UseSoapSenderId,
                    },
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect_err("tampered mime attachment must fail signature verification");

        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn as4_receive_push_parses_user_message_and_receipt() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let payload = multipart_user_message_payload(
            "msg-1",
            "SubmitOrder",
            Some("conv-7"),
            b"payload-msg-1",
        );
        let receipt = br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope" xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
    <S12:Header>
    <eb:Messaging><eb:SignalMessage><eb:MessageInfo><eb:RefToMessageId>msg-1</eb:RefToMessageId></eb:MessageInfo><eb:Receipt><eb:NonRepudiationInformation/></eb:Receipt></eb:SignalMessage></eb:Messaging>
    </S12:Header><S12:Body/></S12:Envelope>"#;

        let (_, dedup) = reliability();
        let out = receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: "multipart/related; boundary=asx-test-boundary".into(),
                    payload: Arc::from(payload),
                    receipt_payload: Some(receipt.to_vec()),
                    policy: As4PushPolicy {
                        interop: InteropMode::Strict,
                        interop_exceptions: InteropExceptionPolicy::default(),
                        require_signed_receipt: false,
                        require_signed_push: false,
                        fail_closed_audit_events: false,
                        inbound_decryption_key_pem: None,
                        require_encrypted_inbound: false,
                        timestamp_freshness_window: None,
                        fragment_scope_policy: FragmentScopePolicy::UseSoapSenderId,
                    },
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect("push receive")
        .unwrap_output();

        assert_eq!(out.user_message.message_id, "msg-1");
        assert_eq!(out.user_message.action, "SubmitOrder");
        assert_eq!(out.user_message.from_party_id(), "sender-a");
        assert_eq!(out.user_message.to_party_id(), "receiver-b");
        assert!(!out.receipt.expect("receipt").is_signed);
    }

    #[test]
    fn generate_receipt_is_deterministic() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let out = generate_receipt(&session, "receipt-msg-1", "msg-1").expect("receipt");
        let xml = match std::str::from_utf8(&out) {
            Ok(xml) => xml,
            Err(err) => panic!("receipt XML must be valid UTF-8: {err}"),
        };
        assert!(
            xml.contains("<eb:MessageId>receipt-msg-1</eb:MessageId>"),
            "receipt must include its own MessageId per ebMS3 §5.2.2.1"
        );
        assert!(
            xml.contains("<eb:RefToMessageId>msg-1</eb:RefToMessageId>"),
            "receipt must reference the original message ID"
        );
        // Receipts are unsigned by default; callers apply signing credentials
        // via generate_xmlsig_signature before transmitting for NRI.
        assert!(
            !xml.contains("<ds:Signature>"),
            "unsigned receipt must not contain a stub signature element"
        );
    }

    #[test]
    fn generate_receipt_rejects_empty_message_id() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let err = generate_receipt(&session, "", "ref-1").expect_err("must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn generate_receipt_rejects_empty_ref() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let err = generate_receipt(&session, "msg-id", "").expect_err("must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn generate_receipt_with_nri_embeds_reference_elements() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let nri_refs = vec![As4NriReference {
            uri: "#body".to_string(),
            digest_method_uri: "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
            digest_value_b64: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".to_string(),
        }];
        let out = generate_receipt_with_nri(&session, "receipt-nri-1", "msg-1", &nri_refs)
            .expect("receipt with nri");
        let xml = std::str::from_utf8(&out).expect("valid UTF-8");
        assert!(
            xml.contains("<ebbpsig:NonRepudiationInformation>"),
            "NRI element must be non-empty when refs are provided"
        );
        assert!(
            xml.contains("<ebbpsig:MessagePartNRInformation>"),
            "must contain MessagePartNRInformation per ebMS3 §5.2.2.1"
        );
        assert!(
            xml.contains("<ds:Reference URI=\"#body\">"),
            "ds:Reference must echo the original URI"
        );
        assert!(
            xml.contains("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="),
            "digest value must be preserved"
        );
        assert!(
            xml.contains("xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\""),
            "ds namespace must be declared when NRI refs are present"
        );
    }

    #[test]
    fn generate_receipt_with_nri_empty_refs_matches_generate_receipt() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let plain = generate_receipt(&session, "r1", "ref-1").expect("plain");
        let with_nri =
            generate_receipt_with_nri(&session, "r1", "ref-1", &[]).expect("nri with empty refs");
        // Timestamps make byte-for-byte equality unreliable; compare structure instead.
        let plain_xml = std::str::from_utf8(&plain).expect("utf8");
        let nri_xml = std::str::from_utf8(&with_nri).expect("utf8");
        assert!(
            plain_xml.contains("<ebbpsig:NonRepudiationInformation/>"),
            "empty-refs receipt must contain self-closing NRI element"
        );
        assert!(
            nri_xml.contains("<ebbpsig:NonRepudiationInformation/>"),
            "nri with empty refs must match plain receipt NRI form"
        );
        assert!(
            !nri_xml.contains("xmlns:ds="),
            "ds namespace must not appear when no NRI refs are provided"
        );
    }

    #[test]
    fn generate_receipt_with_nri_xml_injection_is_escaped() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let nri_refs = vec![As4NriReference {
            uri: "#body\"><script>attack</script>".to_string(),
            digest_method_uri: "http://example.com/?a=1&b=2".to_string(),
            digest_value_b64: "abc123".to_string(),
        }];
        let out = generate_receipt_with_nri(&session, "r1", "ref-1", &nri_refs).expect("receipt");
        let xml = std::str::from_utf8(&out).expect("utf8");
        assert!(!xml.contains("<script>"), "XML injection must be escaped");
        assert!(xml.contains("&amp;"), "ampersand must be entity-escaped");
    }

    fn test_receipt_credentials() -> As4ReceiptCredentials {
        let creds = test_as4_credentials();
        As4ReceiptCredentials {
            signing_key_pem: creds.signing_key_pem.clone().unwrap(),
            signing_cert_pem: creds.signing_cert_pem.as_deref().unwrap().to_vec(),
            key_info_profile: WsSecOutboundKeyInfoProfile::default(),
        }
    }

    fn test_nri_refs() -> Vec<As4NriReference> {
        vec![As4NriReference {
            uri: "#body".to_string(),
            digest_method_uri: "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
            digest_value_b64: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".to_string(),
        }]
    }

    #[test]
    fn generate_signed_receipt_with_nri_verifies_and_parses_as_signed() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let creds = test_receipt_credentials();
        let out = generate_signed_receipt_with_nri(
            &session,
            "receipt-signed-1",
            "msg-1",
            &test_nri_refs(),
            &creds,
        )
        .expect("signed receipt");
        let xml = std::str::from_utf8(&out).expect("utf8");

        assert!(
            xml.contains("wsse:Security"),
            "signed receipt must carry a wsse:Security header"
        );
        assert!(
            xml.contains("<ds:Signature"),
            "signed receipt must carry a ds:Signature"
        );
        assert!(
            xml.contains("<ebbpsig:MessagePartNRInformation>"),
            "NRI refs must be echoed"
        );
        assert!(
            xml.contains("<eb:RefToMessageId>msg-1</eb:RefToMessageId>"),
            "receipt must reference the original message ID"
        );

        // The signature must verify with the library's own verifier …
        verify_enveloped_signature(xml, WsSecVerifyOptions::new())
            .expect("library-generated signed receipt must verify");

        // … and the receipt parser must classify it as signed NRR receipt,
        // i.e. it passes a `require_signed_receipt = true` policy gate.
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let parsed =
            super::parser::parse_as4_receipt(&session, &bus, xml, InteropMode::Strict, false)
                .expect("signed receipt must parse");
        assert!(parsed.is_signed, "receipt must be detected as signed");
        assert!(
            parsed.has_non_repudiation_info,
            "receipt must be detected as carrying NRI"
        );
        assert_eq!(parsed.ref_to_message_id, "msg-1");
    }

    #[test]
    fn generate_signed_receipt_tampering_breaks_verification() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let creds = test_receipt_credentials();
        let out = generate_signed_receipt_with_nri(
            &session,
            "receipt-signed-2",
            "msg-1",
            &test_nri_refs(),
            &creds,
        )
        .expect("signed receipt");
        let xml = std::str::from_utf8(&out).expect("utf8");
        let tampered = xml.replace(
            "<eb:RefToMessageId>msg-1</eb:RefToMessageId>",
            "<eb:RefToMessageId>msg-2</eb:RefToMessageId>",
        );
        assert_ne!(xml, tampered, "tampering must change the envelope");
        verify_enveloped_signature(&tampered, WsSecVerifyOptions::new())
            .expect_err("tampered signed receipt must fail verification");
    }

    #[test]
    fn generate_signed_receipt_rejects_mismatched_credentials() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let creds_a = test_as4_credentials();
        let creds_b = test_as4_credentials();
        let creds = As4ReceiptCredentials {
            signing_key_pem: creds_b.signing_key_pem.clone().unwrap(),
            signing_cert_pem: creds_a.signing_cert_pem.as_deref().unwrap().to_vec(),
            key_info_profile: WsSecOutboundKeyInfoProfile::default(),
        };
        let err =
            generate_signed_receipt_with_nri(&session, "receipt-signed-3", "msg-1", &[], &creds)
                .expect_err("mismatched cert/key must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("does not match signing_key_pem"));
    }

    #[test]
    fn generate_signed_receipt_rejects_empty_message_id() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let creds = test_receipt_credentials();
        let err = generate_signed_receipt_with_nri(&session, "", "ref-1", &[], &creds)
            .expect_err("must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn generate_signed_receipt_for_output_echoes_inbound_digests() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();

        // Obtain a genuine receive output for message "msg-1".
        let payload = multipart_user_message_payload(
            "msg-1",
            "SubmitOrder",
            Some("conv-7"),
            b"payload-msg-1",
        );
        let (_, dedup) = reliability();
        let out = receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: "multipart/related; boundary=asx-test-boundary".into(),
                    payload: Arc::from(payload),
                    receipt_payload: None,
                    policy: As4PushPolicy {
                        interop: InteropMode::Strict,
                        interop_exceptions: InteropExceptionPolicy::default(),
                        require_signed_receipt: false,
                        require_signed_push: false,
                        fail_closed_audit_events: false,
                        inbound_decryption_key_pem: None,
                        require_encrypted_inbound: false,
                        timestamp_freshness_window: None,
                        fragment_scope_policy: FragmentScopePolicy::UseSoapSenderId,
                    },
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect("push receive")
        .unwrap_output();

        // Build a *signed* inbound wire message to extract NRI digests from.
        let sent = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-1".to_string(),
                payload: b"payload-msg-1".to_vec(),
                policy: As4SendPolicy {
                    interop: InteropMode::Strict,
                    outbound_key_info_profile: WsSecOutboundKeyInfoProfile::X509DataAndRsaKeyValue,
                    sign: true,
                    encrypt: false,
                    compress: false,
                    payload_packaging_mode: super::pmode::PayloadPackagingMode::MimeAttachment,
                    ..As4SendPolicy::default()
                },
                credentials: Some(test_as4_credentials()),
                payload_filename: None,
            },
        )
        .expect("send");

        let creds = test_receipt_credentials();
        let receipt = generate_signed_receipt_for_output(
            &session,
            "receipt-signed-out-1",
            &out,
            &sent.soap_envelope.body,
            &sent.http_content_type,
            &creds,
        )
        .expect("signed receipt for output");
        let receipt_xml = std::str::from_utf8(&receipt).expect("utf8");

        // The receipt must echo the digests of the inbound message signature.
        let multipart = extract_multipart_related_payload_if_present(
            &sent.soap_envelope.body,
            &sent.http_content_type,
            &session,
            "test_extract",
        )
        .expect("multipart parse")
        .expect("multipart payload");
        let inbound_xml = std::str::from_utf8(multipart.soap_xml).expect("utf8");
        let inbound_refs =
            crate::crypto::wssec::parse_signature_references(inbound_xml).expect("inbound refs");
        assert!(!inbound_refs.is_empty(), "inbound message must be signed");
        for r in &inbound_refs {
            assert!(
                receipt_xml.contains(&r.digest_value_base64),
                "receipt NRI must echo inbound digest {}",
                r.digest_value_base64
            );
        }

        assert!(
            receipt_xml.contains("<eb:RefToMessageId>msg-1</eb:RefToMessageId>"),
            "receipt must reference the received message"
        );
        verify_enveloped_signature(receipt_xml, WsSecVerifyOptions::new())
            .expect("signed receipt for output must verify");
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn generate_signed_receipt_for_output_rejects_unsigned_inbound() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();

        let payload = multipart_user_message_payload(
            "msg-unsigned-1",
            "SubmitOrder",
            None,
            b"payload-unsigned",
        );
        let (_, dedup) = reliability();
        let out = receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: "multipart/related; boundary=asx-test-boundary".into(),
                    payload: Arc::from(payload.clone()),
                    receipt_payload: None,
                    policy: As4PushPolicy {
                        interop: InteropMode::Strict,
                        interop_exceptions: InteropExceptionPolicy::default(),
                        require_signed_receipt: false,
                        require_signed_push: false,
                        fail_closed_audit_events: false,
                        inbound_decryption_key_pem: None,
                        require_encrypted_inbound: false,
                        timestamp_freshness_window: None,
                        fragment_scope_policy: FragmentScopePolicy::UseSoapSenderId,
                    },
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect("push receive")
        .unwrap_output();

        let creds = test_receipt_credentials();
        let err = generate_signed_receipt_for_output(
            &session,
            "receipt-signed-out-2",
            &out,
            &payload,
            "multipart/related; boundary=asx-test-boundary",
            &creds,
        )
        .expect_err("unsigned inbound must not yield an NRR receipt");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(
            err.message.contains("cannot build NRR receipt"),
            "error must explain the missing inbound signature: {}",
            err.message
        );
    }

    #[test]
    fn strict_mode_rejects_missing_wsse_security_header_even_with_scoped_exception() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
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

        let (_, dedup) = reliability();
        let err = receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: "application/soap+xml".into(),
                    payload: Arc::from(payload.to_vec()),
                    receipt_payload: None,
                    policy: As4PushPolicy {
                        interop_exceptions: InteropExceptionPolicy::scoped(
                            "strict",
                            vec![InteropExceptionCode::As2AllowMissingMdnBoundary],
                        ),
                        fail_closed_audit_events: false,
                        ..As4PushPolicy::default()
                    },
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect_err("strict mode must reject missing wsse:Security even with exception policy");

        assert_eq!(err.code, ErrorCode::PolicyViolation);
    }

    #[test]
    fn strict_mode_rejects_missing_messaging_must_understand() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let payload = br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope" xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
    <S12:Header>
    <eb:Messaging>
    <eb:UserMessage>
    <eb:MessageInfo><eb:MessageId>msg-no-mu</eb:MessageId></eb:MessageInfo>
    <eb:PartyInfo><eb:From><eb:PartyId>sender-a</eb:PartyId></eb:From><eb:To><eb:PartyId>receiver-b</eb:PartyId></eb:To></eb:PartyInfo>
    <eb:CollaborationInfo><eb:Action>SubmitOrder</eb:Action></eb:CollaborationInfo>
    </eb:UserMessage>
    </eb:Messaging>
    <wsse:Security/>
    </S12:Header>
    <S12:Body/>
    </S12:Envelope>"#;

        let (_, dedup) = reliability();
        let err = receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: "application/soap+xml".into(),
                    payload: Arc::from(payload.to_vec()),
                    receipt_payload: None,
                    policy: As4PushPolicy {
                        fail_closed_audit_events: false,
                        ..As4PushPolicy::default()
                    },
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect_err("strict mode must reject missing mustUnderstand");

        assert_eq!(err.code, ErrorCode::InteropViolation);
    }

    #[test]
    fn strict_mode_surfaces_crypto_failures() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let payload = multipart_user_message_payload(
            "msg-strict-wssec-profile",
            "SubmitOrder",
            None,
            b"payload-strict-wssec-profile",
        );

        let (_, dedup) = reliability();
        let err = receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: "multipart/related; boundary=asx-test-boundary".into(),
                    payload: Arc::from(payload),
                    receipt_payload: None,
                    policy: As4PushPolicy {
                        interop: InteropMode::Strict,
                        fail_closed_audit_events: false,
                        ..As4PushPolicy::default()
                    },
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect_err("strict runtime should continue to crypto verification");

        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
    }

    #[test]
    fn strict_mode_rejects_interop_exception_overrides_runtime_policy() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let payload = multipart_user_message_payload(
            "msg-strict-interop-exception",
            "SubmitOrder",
            None,
            b"payload-strict-interop-exception",
        );

        let (_, dedup) = reliability();
        let err = receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: "multipart/related; boundary=asx-test-boundary".into(),
                    payload: Arc::from(payload),
                    receipt_payload: None,
                    policy: As4PushPolicy {
                        interop: InteropMode::Strict,
                        interop_exceptions: InteropExceptionPolicy::scoped(
                            "strict",
                            vec![InteropExceptionCode::As2AllowMissingMdnBoundary],
                        ),
                        fail_closed_audit_events: false,
                        ..As4PushPolicy::default()
                    },
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect_err("strict runtime policy must reject interop exception overrides");

        assert_eq!(err.code, ErrorCode::PolicyViolation);
        assert!(err.message.contains("interop exception"));
    }

    #[cfg(not(feature = "testing"))]
    #[test]
    fn strict_mode_rejects_runtime_push_policy_with_unsigned_receipt_requirement() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let (_, dedup) = durable_reliability();

        let err = receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: "application/soap+xml".into(),
                    payload: Arc::from(b"not-xml".to_vec()),
                    receipt_payload: None,
                    policy: As4PushPolicy {
                        interop: InteropMode::Strict,
                        require_signed_receipt: false,
                        fail_closed_audit_events: false,
                        ..As4PushPolicy::default()
                    },
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect_err("strict runtime policy must reject require_signed_receipt=false");

        assert_eq!(err.code, ErrorCode::PolicyViolation);
        assert!(err.message.contains("require_signed_receipt"));
    }

    #[test]
    fn strict_mode_rejects_runtime_send_policy_with_empty_action() {
        let session = SessionContext::new("s-send-runtime-empty-action", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let creds = test_as4_credentials();

        let err = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-send-runtime-empty-action".to_string(),
                payload: b"payload".to_vec(),
                policy: As4SendPolicy {
                    interop: InteropMode::Strict,
                    action: "   ".to_string(),
                    ..As4SendPolicy::default()
                },
                credentials: Some(creds),
                payload_filename: None,
            },
        )
        .expect_err("strict runtime send policy must reject empty action");

        assert_eq!(err.code, ErrorCode::PolicyViolation);
        assert!(err.message.contains("action must not be empty"));
    }

    #[test]
    fn strict_mode_rejects_runtime_send_policy_with_mismatched_signing_credentials() {
        let session = SessionContext::new("s-send-runtime-mismatch", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();

        let signer_a = test_as4_credentials();
        let signer_b = test_as4_credentials();
        let mismatched = As4SendCredentials {
            signing_cert_pem: signer_a.signing_cert_pem.clone(),
            signing_key_pem: signer_b.signing_key_pem.clone(),
            recipient_cert_pem: signer_a.recipient_cert_pem.clone(),
        };

        let err = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-send-runtime-mismatch".to_string(),
                payload: b"payload".to_vec(),
                policy: As4SendPolicy::default(),
                credentials: Some(mismatched),
                payload_filename: None,
            },
        )
        .expect_err("strict runtime send policy must reject mismatched signing credentials");

        assert_eq!(err.code, ErrorCode::PolicyViolation);
        assert!(
            err.message
                .contains("signing_cert_pem does not match signing_key_pem")
        );
    }

    #[test]
    fn strict_mode_rejects_runtime_send_policy_with_empty_service() {
        let session = SessionContext::new("s-send-runtime-empty-service", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let creds = test_as4_credentials();

        let err = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-send-runtime-empty-service".to_string(),
                payload: b"payload".to_vec(),
                policy: As4SendPolicy {
                    interop: InteropMode::Strict,
                    service: "   ".to_string(),
                    ..As4SendPolicy::default()
                },
                credentials: Some(creds),
                payload_filename: None,
            },
        )
        .expect_err("strict runtime send policy must reject empty service");

        assert_eq!(err.code, ErrorCode::PolicyViolation);
        assert!(err.message.contains("service"));
    }

    #[test]
    fn strict_mode_rejects_runtime_send_policy_with_empty_ref_to_message_id() {
        let session = SessionContext::new("s-send-runtime-empty-ref", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let creds = test_as4_credentials();

        let err = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-send-runtime-empty-ref".to_string(),
                payload: b"payload".to_vec(),
                policy: As4SendPolicy {
                    interop: InteropMode::Strict,
                    ref_to_message_id: Some("   ".to_string()),
                    ..As4SendPolicy::default()
                },
                credentials: Some(creds),
                payload_filename: None,
            },
        )
        .expect_err("strict runtime send policy must reject empty ref_to_message_id");

        assert_eq!(err.code, ErrorCode::PolicyViolation);
        assert!(err.message.contains("ref_to_message_id"));
    }

    #[cfg(not(feature = "testing"))]
    #[tokio::test]
    async fn strict_mode_rejects_runtime_pull_policy_with_unsigned_receipt_requirement() {
        let session = SessionContext::new("s-pull-runtime", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let store = As4PullStore::new();
        let (hook, dedup_backend) = durable_reliability();

        let err = receive_pull_with_reliability(
            &session,
            &bus,
            As4ReceivePullWithReliabilityRequest {
                store: &store,
                request: As4ReceivePullRequest {
                    pull_message_id: "pull-runtime-1".to_string(),
                    policy: As4PullPolicy {
                        interop: InteropMode::Strict,
                        require_signed_receipt: false,
                        fail_closed_audit_events: false,
                        ..As4PullPolicy::default()
                    },
                    receipt_payload: None,
                    authorization_info: None,
                },
                reconciliation_hook: &hook,
                dedup_backend: Arc::new(dedup_backend),
            },
        )
        .await
        .expect_err("strict runtime pull policy must reject require_signed_receipt=false");

        assert_eq!(err.code, ErrorCode::PolicyViolation);
        assert!(
            err.message.contains("require_signed_receipt")
                || err
                    .message
                    .contains("strict-runtime bootstrap token binding")
        );
    }

    #[cfg(feature = "interop-relaxed")]
    #[tokio::test]
    async fn relaxed_missing_security_header_is_security_blocked_and_audited() {
        let session = SessionContext::new("s-relaxed", "p1", "partner-quirks")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let mut scoped_rx = bus.subscribe_scoped_events();
        let payload = br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope" xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
    <S12:Header>
    <eb:Messaging S12:mustUnderstand="true">
    <eb:UserMessage>
    <eb:MessageInfo><eb:MessageId>msg-interop</eb:MessageId></eb:MessageInfo>
    <eb:PartyInfo><eb:From><eb:PartyId>sender-a</eb:PartyId></eb:From><eb:To><eb:PartyId>receiver-b</eb:PartyId></eb:To></eb:PartyInfo>
    <eb:CollaborationInfo><eb:Action>SubmitOrder</eb:Action></eb:CollaborationInfo>
    </eb:UserMessage>
    </eb:Messaging>
    </S12:Header>
    <S12:Body/>
    </S12:Envelope>"#;

        let (_, dedup) = reliability();
        let denied = receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: "application/soap+xml".into(),
                    payload: Arc::from(payload.to_vec()),
                    receipt_payload: None,
                    policy: As4PushPolicy {
                        interop: InteropMode::Relaxed,
                        interop_exceptions: InteropExceptionPolicy::default(),
                        require_signed_receipt: false,
                        require_signed_push: false,
                        fail_closed_audit_events: false,
                        inbound_decryption_key_pem: None,
                        require_encrypted_inbound: false,
                        timestamp_freshness_window: None,
                        fragment_scope_policy: FragmentScopePolicy::UseSoapSenderId,
                    },
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect_err("relaxed path should be security-blocked");
        assert_eq!(denied.code, ErrorCode::PolicyViolation);

        let blocked = receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: "application/soap+xml".into(),
                    payload: Arc::from(payload.to_vec()),
                    receipt_payload: None,
                    policy: As4PushPolicy {
                        interop: InteropMode::Relaxed,
                        interop_exceptions: InteropExceptionPolicy::default(),
                        require_signed_receipt: false,
                        require_signed_push: false,
                        fail_closed_audit_events: false,
                        inbound_decryption_key_pem: None,
                        require_encrypted_inbound: false,
                        timestamp_freshness_window: None,
                        fragment_scope_policy: FragmentScopePolicy::UseSoapSenderId,
                    },
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect_err("scoped exception should still be security-blocked");
        assert_eq!(blocked.code, ErrorCode::PolicyViolation);

        let mut saw_guardrail = false;
        for _ in 0..8 {
            let Ok(Some(evt)) = timeout(Duration::from_millis(200), scoped_rx.recv()).await else {
                break;
            };
            if let AsxEvent::InteropGuardrailEvaluated {
                message_id,
                code,
                outcome,
                ..
            } = evt.event.as_ref()
                && message_id.as_ref() == "msg-interop"
                && *code == "as4_missing_wsse_security_header"
                && *outcome == "SecurityBlocked"
            {
                saw_guardrail = true;
                break;
            }
        }
        assert!(saw_guardrail);
    }

    #[cfg(feature = "interop-relaxed")]
    #[tokio::test]
    async fn relaxed_mode_emits_no_wssec_relaxation_audit() {
        let session = SessionContext::new("s1", "p1", "relaxed")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let mut scoped_rx = bus.subscribe_scoped_events();
        let payload =
            multipart_user_message_payload("msg-compat", "SubmitOrder", None, b"payload-compat");

        let (_, dedup) = reliability();
        receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: "multipart/related; boundary=asx-test-boundary".into(),
                    payload: Arc::from(payload),
                    receipt_payload: None,
                    policy: As4PushPolicy {
                        interop: InteropMode::Relaxed,
                        interop_exceptions: InteropExceptionPolicy::default(),
                        require_signed_receipt: false,
                        require_signed_push: false,
                        fail_closed_audit_events: false,
                        inbound_decryption_key_pem: None,
                        require_encrypted_inbound: false,
                        timestamp_freshness_window: None,
                        fragment_scope_policy: FragmentScopePolicy::UseSoapSenderId,
                    },
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect("push receive");

        let mut saw_audit = false;
        for _ in 0..6 {
            let Ok(Some(evt)) = timeout(Duration::from_millis(200), scoped_rx.recv()).await else {
                break;
            };
            if let AsxEvent::InteropRelaxationApplied { message_id, .. } = evt.event.as_ref() {
                assert_eq!(message_id.as_ref(), "msg-compat");
                saw_audit = true;
                break;
            }
        }
        assert!(!saw_audit);
    }

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn missing_security_header_fails_closed_when_audit_emit_fails() {
        let session = SessionContext::new("s1", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let payload = br#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope" xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
    <S12:Header>
    <eb:Messaging S12:mustUnderstand="true">
    <eb:UserMessage>
    <eb:MessageInfo><eb:MessageId>msg-fail-closed</eb:MessageId></eb:MessageInfo>
    <eb:PartyInfo><eb:From><eb:PartyId>sender-a</eb:PartyId></eb:From><eb:To><eb:PartyId>receiver-b</eb:PartyId></eb:To></eb:PartyInfo>
    <eb:CollaborationInfo><eb:Action>SubmitOrder</eb:Action></eb:CollaborationInfo>
    </eb:UserMessage>
    </eb:Messaging>
    </S12:Header>
    <S12:Body/>
    </S12:Envelope>"#;

        let (_, dedup) = reliability();
        let err = receive_push_with_dedup_sync(
            &session,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: "application/soap+xml".into(),
                    payload: Arc::from(payload.to_vec()),
                    receipt_payload: None,
                    policy: As4PushPolicy {
                        interop: InteropMode::Relaxed,
                        interop_exceptions: InteropExceptionPolicy::default(),
                        require_signed_receipt: false,
                        require_signed_push: true,
                        fail_closed_audit_events: true,
                        inbound_decryption_key_pem: None,
                        require_encrypted_inbound: false,
                        timestamp_freshness_window: None,
                        fragment_scope_policy: FragmentScopePolicy::UseSoapSenderId,
                    },
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect_err("audit emission failure must fail closed");

        assert_eq!(err.code, ErrorCode::ReliabilityFailure);
    }

    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "current_thread")]
    async fn pull_store_queue_limit_rejects_new_message_by_default() {
        let session = SessionContext::new("s-pull-queue", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let store = As4PullStore::with_limits(As4PullStoreLimits {
            max_queue_per_mpc: 1,
            max_served_entries: 8,
            queue_overflow_policy: As4PullQueueOverflowPolicy::RejectNew,
        })
        .expect("store");

        let first = store
            .enqueue(
                &session,
                DEFAULT_MPC,
                As4QueuedPullMessage {
                    message_id: Arc::from("msg-old"),
                    http_content_type: Arc::from("multipart/related; boundary=asx-test-boundary"),
                    payload: Arc::from(pull_payload("msg-old")),
                },
            )
            .await
            .expect("enqueue old");
        assert_eq!(first, As4PullEnqueueOutcome::Enqueued);
        let err = store
            .enqueue(
                &session,
                DEFAULT_MPC,
                As4QueuedPullMessage {
                    message_id: Arc::from("msg-new"),
                    http_content_type: Arc::from("multipart/related; boundary=asx-test-boundary"),
                    payload: Arc::from(pull_payload("msg-new")),
                },
            )
            .await
            .expect_err("enqueue must reject when queue is full");
        assert_eq!(err.code, ErrorCode::CapacityExhausted);

        let (hook, dedup) = durable_reliability();
        let dedup_backend: Arc<dyn crate::storage::DedupStorage> = Arc::new(dedup);
        let out = receive_pull_with_reliability(
            &session,
            &bus,
            As4ReceivePullWithReliabilityRequest {
                store: &store,
                request: As4ReceivePullRequest {
                    pull_message_id: "pull-1".to_string(),
                    policy: As4PullPolicy {
                        require_signed_push: false,
                        fail_closed_audit_events: false,
                        ..As4PullPolicy::default()
                    },
                    receipt_payload: None,
                    authorization_info: None,
                },
                reconciliation_hook: &hook,
                dedup_backend,
            },
        )
        .await
        .expect("pull should succeed");

        let pulled = out.pulled.expect("pulled message");
        assert_eq!(pulled.user_message.message_id, "msg-old");
    }

    #[cfg(not(feature = "testing"))]
    #[tokio::test(flavor = "current_thread")]
    async fn durable_dedup_receive_pull_rejects_non_durable_backend() {
        let session = SessionContext::new("s-pull-dedup", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let store = As4PullStore::default();
        let (hook, _) = durable_reliability();
        let dedup_backend: Arc<dyn crate::storage::DedupStorage> =
            Arc::new(InMemoryDedupBackend::default());

        let err = receive_pull_with_reliability(
            &session,
            &bus,
            As4ReceivePullWithReliabilityRequest {
                store: &store,
                request: As4ReceivePullRequest {
                    pull_message_id: "pull-dedup-1".to_string(),
                    policy: As4PullPolicy {
                        require_signed_push: false,
                        fail_closed_audit_events: false,
                        ..As4PullPolicy::default()
                    },
                    receipt_payload: None,
                    authorization_info: None,
                },
                reconciliation_hook: &hook,
                dedup_backend,
            },
        )
        .await
        .expect_err("non-durable dedup backend must be rejected");

        assert_eq!(err.code, ErrorCode::ReliabilityFailure);
        assert!(err.message.contains("durable dedup backend"));
    }

    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "current_thread")]
    async fn pull_store_queue_limit_can_evict_oldest_when_configured() {
        let session = SessionContext::new("s-pull-queue-evict", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let store = As4PullStore::with_limits(As4PullStoreLimits {
            max_queue_per_mpc: 1,
            max_served_entries: 8,
            queue_overflow_policy: As4PullQueueOverflowPolicy::EvictOldest,
        })
        .expect("store");

        let first = store
            .enqueue(
                &session,
                DEFAULT_MPC,
                As4QueuedPullMessage {
                    message_id: Arc::from("msg-old"),
                    http_content_type: Arc::from("multipart/related; boundary=asx-test-boundary"),
                    payload: Arc::from(pull_payload("msg-old")),
                },
            )
            .await
            .expect("enqueue old");
        assert_eq!(first, As4PullEnqueueOutcome::Enqueued);

        let second = store
            .enqueue(
                &session,
                DEFAULT_MPC,
                As4QueuedPullMessage {
                    message_id: Arc::from("msg-new"),
                    http_content_type: Arc::from("multipart/related; boundary=asx-test-boundary"),
                    payload: Arc::from(pull_payload("msg-new")),
                },
            )
            .await
            .expect("enqueue new");
        assert!(matches!(
            second,
            As4PullEnqueueOutcome::EvictedOldestAndEnqueued { .. }
        ));

        let (hook, dedup) = durable_reliability();
        let dedup_backend: Arc<dyn crate::storage::DedupStorage> = Arc::new(dedup);
        let out = receive_pull_with_reliability(
            &session,
            &bus,
            As4ReceivePullWithReliabilityRequest {
                store: &store,
                request: As4ReceivePullRequest {
                    pull_message_id: "pull-evict-1".to_string(),
                    policy: As4PullPolicy {
                        require_signed_push: false,
                        fail_closed_audit_events: false,
                        ..As4PullPolicy::default()
                    },
                    receipt_payload: None,
                    authorization_info: None,
                },
                reconciliation_hook: &hook,
                dedup_backend,
            },
        )
        .await
        .expect("pull should succeed");

        let pulled = out.pulled.expect("pulled message");
        assert_eq!(pulled.user_message.message_id, "msg-new");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enqueue_pull_with_reliability_reject_overflow_queues_reconciliation_and_audit() {
        let session = SessionContext::new("s-pull-queue-rel", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let mut scoped_rx = bus.subscribe_scoped_events();
        let store = As4PullStore::with_limits(As4PullStoreLimits {
            max_queue_per_mpc: 1,
            max_served_entries: 8,
            queue_overflow_policy: As4PullQueueOverflowPolicy::RejectNew,
        })
        .expect("store");
        let (hook, _dedup) = durable_reliability();

        let first = enqueue_pull_with_reliability(
            &session,
            &bus,
            As4EnqueuePullWithReliabilityRequest {
                store: &store,
                mpc: DEFAULT_MPC.to_string(),
                message: As4QueuedPullMessage {
                    message_id: Arc::from("msg-old"),
                    http_content_type: Arc::from("multipart/related; boundary=asx-test-boundary"),
                    payload: Arc::from(pull_payload("msg-old")),
                },
                reconciliation_hook: &hook,
                fail_closed_audit_events: false,
            },
        )
        .await
        .expect("first enqueue");
        assert_eq!(first, As4PullEnqueueOutcome::Enqueued);

        let err = enqueue_pull_with_reliability(
            &session,
            &bus,
            As4EnqueuePullWithReliabilityRequest {
                store: &store,
                mpc: DEFAULT_MPC.to_string(),
                message: As4QueuedPullMessage {
                    message_id: Arc::from("msg-new"),
                    http_content_type: Arc::from("multipart/related; boundary=asx-test-boundary"),
                    payload: Arc::from(pull_payload("msg-new")),
                },
                reconciliation_hook: &hook,
                fail_closed_audit_events: false,
            },
        )
        .await
        .expect_err("overflow must reject new message");
        assert_eq!(err.code, ErrorCode::CapacityExhausted);

        let queued =
            crate::storage::drive_dedup_future(hook.queued_requests()).expect("queued requests");
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].message_id, "msg-new");

        let mut saw_overflow = false;
        let mut saw_reconciliation = false;
        for _ in 0..8 {
            let Ok(Some(evt)) = timeout(Duration::from_millis(200), scoped_rx.recv()).await else {
                break;
            };
            match evt.event.as_ref() {
                AsxEvent::PullQueueOverflow {
                    message_id,
                    action,
                    policy,
                } if message_id.as_ref() == "msg-new"
                    && *action == "rejected_new"
                    && *policy == "reject_new" =>
                {
                    saw_overflow = true;
                }
                AsxEvent::ReconciliationQueued { message_id, reason }
                    if message_id.as_ref() == "msg-new"
                        && *reason == "queue_overflow_rejected_new" =>
                {
                    saw_reconciliation = true;
                }
                _ => {}
            }
            if saw_overflow && saw_reconciliation {
                break;
            }
        }

        assert!(saw_overflow);
        assert!(saw_reconciliation);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enqueue_pull_with_reliability_evict_overflow_queues_reconciliation_and_audit() {
        let session = SessionContext::new("s-pull-queue-rel-evict", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let mut scoped_rx = bus.subscribe_scoped_events();
        let store = As4PullStore::with_limits(As4PullStoreLimits {
            max_queue_per_mpc: 1,
            max_served_entries: 8,
            queue_overflow_policy: As4PullQueueOverflowPolicy::EvictOldest,
        })
        .expect("store");
        let (hook, _dedup) = durable_reliability();

        enqueue_pull_with_reliability(
            &session,
            &bus,
            As4EnqueuePullWithReliabilityRequest {
                store: &store,
                mpc: DEFAULT_MPC.to_string(),
                message: As4QueuedPullMessage {
                    message_id: Arc::from("msg-old"),
                    http_content_type: Arc::from("multipart/related; boundary=asx-test-boundary"),
                    payload: Arc::from(pull_payload("msg-old")),
                },
                reconciliation_hook: &hook,
                fail_closed_audit_events: false,
            },
        )
        .await
        .expect("first enqueue");

        let second = enqueue_pull_with_reliability(
            &session,
            &bus,
            As4EnqueuePullWithReliabilityRequest {
                store: &store,
                mpc: DEFAULT_MPC.to_string(),
                message: As4QueuedPullMessage {
                    message_id: Arc::from("msg-new"),
                    http_content_type: Arc::from("multipart/related; boundary=asx-test-boundary"),
                    payload: Arc::from(pull_payload("msg-new")),
                },
                reconciliation_hook: &hook,
                fail_closed_audit_events: false,
            },
        )
        .await
        .expect("second enqueue");
        assert!(matches!(
            second,
            As4PullEnqueueOutcome::EvictedOldestAndEnqueued { .. }
        ));

        let queued =
            crate::storage::drive_dedup_future(hook.queued_requests()).expect("queued requests");
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].message_id, "msg-old");

        let mut saw_overflow = false;
        let mut saw_reconciliation = false;
        for _ in 0..8 {
            let Ok(Some(evt)) = timeout(Duration::from_millis(200), scoped_rx.recv()).await else {
                break;
            };
            match evt.event.as_ref() {
                AsxEvent::PullQueueOverflow {
                    message_id,
                    action,
                    policy,
                } if message_id.as_ref() == "msg-old"
                    && *action == "evicted_oldest"
                    && *policy == "evict_oldest" =>
                {
                    saw_overflow = true;
                }
                AsxEvent::ReconciliationQueued { message_id, reason }
                    if message_id.as_ref() == "msg-old"
                        && *reason == "queue_overflow_evict_oldest" =>
                {
                    saw_reconciliation = true;
                }
                _ => {}
            }
            if saw_overflow && saw_reconciliation {
                break;
            }
        }

        assert!(saw_overflow);
        assert!(saw_reconciliation);
    }

    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "current_thread")]
    async fn pull_store_served_cache_limit_evicts_oldest_pull_id() {
        let session = SessionContext::new("s-pull-served", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let store = As4PullStore::with_limits(As4PullStoreLimits {
            max_queue_per_mpc: 4,
            max_served_entries: 1,
            queue_overflow_policy: As4PullQueueOverflowPolicy::RejectNew,
        })
        .expect("store");

        let first = store
            .enqueue(
                &session,
                DEFAULT_MPC,
                As4QueuedPullMessage {
                    message_id: Arc::from("msg-1"),
                    http_content_type: Arc::from("multipart/related; boundary=asx-test-boundary"),
                    payload: Arc::from(pull_payload("msg-1")),
                },
            )
            .await
            .expect("enqueue msg-1");
        assert_eq!(first, As4PullEnqueueOutcome::Enqueued);

        let second = store
            .enqueue(
                &session,
                DEFAULT_MPC,
                As4QueuedPullMessage {
                    message_id: Arc::from("msg-2"),
                    http_content_type: Arc::from("multipart/related; boundary=asx-test-boundary"),
                    payload: Arc::from(pull_payload("msg-2")),
                },
            )
            .await
            .expect("enqueue msg-2");
        assert_eq!(second, As4PullEnqueueOutcome::Enqueued);

        let (hook, dedup) = durable_reliability();
        let dedup_backend: Arc<dyn crate::storage::DedupStorage> = Arc::new(dedup);
        let first = receive_pull_with_reliability(
            &session,
            &bus,
            As4ReceivePullWithReliabilityRequest {
                store: &store,
                request: As4ReceivePullRequest {
                    pull_message_id: "pull-1".to_string(),
                    policy: As4PullPolicy {
                        require_signed_push: false,
                        fail_closed_audit_events: false,
                        ..As4PullPolicy::default()
                    },
                    receipt_payload: None,
                    authorization_info: None,
                },
                reconciliation_hook: &hook,
                dedup_backend: Arc::clone(&dedup_backend),
            },
        )
        .await
        .expect("first pull");
        assert!(!first.duplicate_retrieval);

        let second = receive_pull_with_reliability(
            &session,
            &bus,
            As4ReceivePullWithReliabilityRequest {
                store: &store,
                request: As4ReceivePullRequest {
                    pull_message_id: "pull-2".to_string(),
                    policy: As4PullPolicy {
                        require_signed_push: false,
                        fail_closed_audit_events: false,
                        ..As4PullPolicy::default()
                    },
                    receipt_payload: None,
                    authorization_info: None,
                },
                reconciliation_hook: &hook,
                dedup_backend: Arc::clone(&dedup_backend),
            },
        )
        .await
        .expect("second pull");
        assert!(!second.duplicate_retrieval);

        let replay_old_id = receive_pull_with_reliability(
            &session,
            &bus,
            As4ReceivePullWithReliabilityRequest {
                store: &store,
                request: As4ReceivePullRequest {
                    pull_message_id: "pull-1".to_string(),
                    policy: As4PullPolicy {
                        require_signed_push: false,
                        fail_closed_audit_events: false,
                        ..As4PullPolicy::default()
                    },
                    receipt_payload: None,
                    authorization_info: None,
                },
                reconciliation_hook: &hook,
                dedup_backend,
            },
        )
        .await
        .expect("old pull id replay");
        assert!(!replay_old_id.duplicate_retrieval);
        assert!(replay_old_id.pulled.is_none());
    }

    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "current_thread")]
    async fn pull_receive_requeues_message_when_push_processing_fails() {
        let session = SessionContext::new("s-pull-requeue", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let store = As4PullStore::new();

        store
            .enqueue(
                &session,
                DEFAULT_MPC,
                As4QueuedPullMessage {
                    message_id: Arc::from("msg-invalid"),
                    http_content_type: Arc::from("multipart/related; boundary=asx-test-boundary"),
                    payload: Arc::from(b"not-a-valid-multipart-body".as_slice()),
                },
            )
            .await
            .expect("enqueue invalid payload");

        let (hook, dedup) = durable_reliability();
        let dedup_backend: Arc<dyn crate::storage::DedupStorage> = Arc::new(dedup);

        let first_err = receive_pull_with_reliability(
            &session,
            &bus,
            As4ReceivePullWithReliabilityRequest {
                store: &store,
                request: As4ReceivePullRequest {
                    pull_message_id: "pull-requeue-1".to_string(),
                    policy: As4PullPolicy {
                        require_signed_push: false,
                        fail_closed_audit_events: false,
                        ..As4PullPolicy::default()
                    },
                    receipt_payload: None,
                    authorization_info: None,
                },
                reconciliation_hook: &hook,
                dedup_backend: Arc::clone(&dedup_backend),
            },
        )
        .await
        .expect_err("invalid queued payload must fail pull processing");
        assert_eq!(first_err.code, ErrorCode::ParseFailed);

        let second_err = receive_pull_with_reliability(
            &session,
            &bus,
            As4ReceivePullWithReliabilityRequest {
                store: &store,
                request: As4ReceivePullRequest {
                    pull_message_id: "pull-requeue-2".to_string(),
                    policy: As4PullPolicy {
                        require_signed_push: false,
                        fail_closed_audit_events: false,
                        ..As4PullPolicy::default()
                    },
                    receipt_payload: None,
                    authorization_info: None,
                },
                reconciliation_hook: &hook,
                dedup_backend,
            },
        )
        .await
        .expect_err("message should remain queued and fail again on second pull");
        assert_eq!(second_err.code, ErrorCode::ParseFailed);
    }

    #[test]
    fn as4_push_policy_builder_rejects_invalid_key_pem() {
        let err = As4PushPolicyBuilder::new()
            .inbound_decryption_key_pem(b"not-a-valid-pem".to_vec())
            .build()
            .expect_err("invalid PEM must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("PEM"));
    }

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn as4_push_policy_builder_accepts_valid_key_pem() {
        let creds = test_as4_credentials();
        let policy = As4PushPolicyBuilder::new()
            .interop(InteropMode::Relaxed)
            .require_signed_receipt(false)
            .inbound_decryption_key_pem(creds.signing_key_pem.clone().unwrap())
            .build()
            .expect("valid key must build");
        assert_eq!(policy.interop, InteropMode::Relaxed);
        assert!(!policy.require_signed_receipt);
        assert!(policy.inbound_decryption_key_pem.is_some());
    }

    #[test]
    fn as4_push_policy_builder_accepts_strict_only_wssec_profile() {
        let policy = As4PushPolicyBuilder::new()
            .interop(InteropMode::Strict)
            .build()
            .expect("strict mode with strict-only wssec profile must build");

        assert_eq!(policy.interop, InteropMode::Strict);
    }

    #[cfg(not(feature = "testing"))]
    #[test]
    fn as4_push_policy_builder_rejects_strict_unsigned_receipt_policy() {
        let err = As4PushPolicyBuilder::new()
            .interop(InteropMode::Strict)
            .require_signed_receipt(false)
            .build()
            .expect_err("strict push policy must require signed receipts in non-testing builds");

        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("require_signed_receipt"));
    }

    #[cfg(not(feature = "testing"))]
    #[test]
    fn as4_push_policy_builder_rejects_strict_fail_open_audit() {
        let err = As4PushPolicyBuilder::new()
            .interop(InteropMode::Strict)
            .fail_closed_audit_events(false)
            .build()
            .expect_err("strict push policy must require fail_closed audit in non-testing builds");

        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("fail_closed_audit_events"));
    }

    #[test]
    fn as4_pull_policy_builder_rejects_strict_with_interop_exceptions() {
        let err = As4PullPolicyBuilder::new()
            .interop(InteropMode::Strict)
            .interop_exceptions(InteropExceptionPolicy::scoped(
                "strict",
                vec![InteropExceptionCode::As2AllowMissingMdnBoundary],
            ))
            .build()
            .expect_err("strict mode must reject interop exception overrides");

        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("interop exception"));
    }

    #[cfg(not(feature = "testing"))]
    #[test]
    fn as4_pull_policy_builder_rejects_strict_unsigned_receipt_policy() {
        let err = As4PullPolicyBuilder::new()
            .interop(InteropMode::Strict)
            .require_signed_receipt(false)
            .build()
            .expect_err("strict pull policy must require signed receipts in non-testing builds");

        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("require_signed_receipt"));
    }

    #[cfg(not(feature = "testing"))]
    #[test]
    fn as4_pull_policy_builder_rejects_strict_fail_open_audit() {
        let err = As4PullPolicyBuilder::new()
            .interop(InteropMode::Strict)
            .fail_closed_audit_events(false)
            .build()
            .expect_err("strict pull policy must require fail_closed audit in non-testing builds");

        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("fail_closed_audit_events"));
    }

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn as4_pull_policy_builder_rejects_empty_expected_authorization_info() {
        let err = As4PullPolicyBuilder::new()
            .interop(InteropMode::Relaxed)
            .expected_authorization_info(Some("   ".to_string()))
            .build()
            .expect_err("empty expected_authorization_info must fail");

        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("expected_authorization_info"));
    }

    #[test]
    fn as4_send_policy_builder_rejects_sign_without_cert() {
        let err = As4SendPolicyBuilder::new()
            .sign(true)
            .build()
            .expect_err("sign=true without cert must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("signing_cert_pem"));
    }

    #[test]
    fn as4_send_policy_builder_rejects_sign_without_key() {
        let creds = test_as4_credentials();
        let err = As4SendPolicyBuilder::new()
            .sign(true)
            .signing_cert_pem(creds.signing_cert_pem.clone().unwrap())
            // key intentionally omitted
            .build()
            .expect_err("sign=true without key must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("signing_key_pem"));
    }

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn as4_send_policy_builder_rejects_encrypt_without_recipient_cert() {
        let err = As4SendPolicyBuilder::new()
            .interop(InteropMode::Relaxed)
            .sign(false)
            .encrypt(true)
            .build()
            .expect_err("encrypt=true without recipient cert must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("recipient_cert_pem"));
    }

    #[test]
    fn as4_send_policy_builder_accepts_valid_config() {
        let creds = test_as4_credentials();
        let (policy, built_creds) = As4SendPolicyBuilder::new()
            .sign(true)
            .encrypt(false)
            .compress(false)
            .signing_cert_pem(creds.signing_cert_pem.clone().unwrap())
            .signing_key_pem(creds.signing_key_pem.clone().unwrap())
            .build()
            .expect("valid config must build");
        assert!(policy.sign);
        assert!(!policy.encrypt);
        assert!(built_creds.signing_cert_pem.is_some());
    }

    #[test]
    fn as4_send_policy_builder_accepts_strict_only_wssec_profile() {
        let creds = test_as4_credentials();
        let (policy, _) = As4SendPolicyBuilder::new()
            .interop(InteropMode::Strict)
            .sign(true)
            .signing_cert_pem(creds.signing_cert_pem.clone().expect("cert"))
            .signing_key_pem(creds.signing_key_pem.clone().expect("key"))
            .build()
            .expect("strict send builder with strict-only wssec profile must build");

        assert_eq!(policy.interop, InteropMode::Strict);
    }

    #[test]
    fn as4_send_runtime_accepts_strict_only_wssec_profile() {
        let session = SessionContext::new("s-send-strict", "p1", "strict")
            .expect("session")
            .with_strict_runtime_bootstrap_validated(true);
        let bus = EventBus::new(16).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let creds = test_as4_credentials();
        let out = send_sync(
            &session,
            &bus,
            As4SendRequest {
                message_id: "msg-send-strict-profile".to_string(),
                payload: b"payload-send".to_vec(),
                policy: As4SendPolicy {
                    interop: InteropMode::Strict,
                    sign: true,
                    encrypt: false,
                    compress: false,
                    fail_closed_audit_events: true,
                    payload_packaging_mode: super::pmode::PayloadPackagingMode::MimeAttachment,
                    ..As4SendPolicy::default()
                },
                credentials: Some(creds),
                payload_filename: None,
            },
        )
        .expect("strict send runtime with strict-only profile must succeed");

        assert_eq!(out.message_id, "msg-send-strict-profile");
    }

    #[cfg(not(feature = "testing"))]
    #[test]
    fn as4_send_policy_builder_rejects_strict_sign_disabled() {
        let err = As4SendPolicyBuilder::new()
            .interop(InteropMode::Strict)
            .sign(false)
            .build()
            .expect_err("strict send builder must reject sign=false in non-testing builds");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("sign=false"));
    }

    #[cfg(not(feature = "testing"))]
    #[test]
    fn as4_send_policy_builder_rejects_strict_fail_open_audit() {
        let creds = test_as4_credentials();
        let err = As4SendPolicyBuilder::new()
            .interop(InteropMode::Strict)
            .sign(true)
            .fail_closed_audit_events(false)
            .signing_cert_pem(creds.signing_cert_pem.clone().expect("cert"))
            .signing_key_pem(creds.signing_key_pem.clone().expect("key"))
            .build()
            .expect_err("strict send builder must reject fail_open audit in non-testing builds");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("fail_closed_audit_events"));
    }

    #[test]
    fn as4_send_policy_builder_rejects_empty_action() {
        let err = As4SendPolicyBuilder::new()
            .action("   ")
            .build()
            .expect_err("empty action must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("action"));
    }

    #[test]
    fn as4_send_policy_builder_rejects_empty_service() {
        let err = As4SendPolicyBuilder::new()
            .service("", "example")
            .build()
            .expect_err("empty service must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("service"));
    }

    #[test]
    fn as4_send_policy_builder_rejects_empty_ref_to_message_id() {
        let err = As4SendPolicyBuilder::new()
            .ref_to_message_id("   ")
            .build()
            .expect_err("empty ref_to_message_id must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("ref_to_message_id"));
    }

    #[test]
    fn as4_send_policy_builder_rejects_invalid_signing_cert_pem() {
        let creds = test_as4_credentials();
        let err = As4SendPolicyBuilder::new()
            .sign(true)
            .signing_cert_pem(b"not-a-certificate".to_vec())
            .signing_key_pem(creds.signing_key_pem.clone().expect("key"))
            .build()
            .expect_err("invalid signing cert pem must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("signing_cert_pem"));
    }

    #[test]
    fn as4_send_policy_builder_rejects_mismatched_signing_cert_and_key() {
        let creds_a = test_as4_credentials();
        let creds_b = test_as4_credentials();

        let err = As4SendPolicyBuilder::new()
            .sign(true)
            .signing_cert_pem(creds_a.signing_cert_pem.clone().expect("cert a"))
            .signing_key_pem(creds_b.signing_key_pem.clone().expect("key b"))
            .build()
            .expect_err("mismatched signing cert/key must fail");

        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("does not match"));
    }

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn as4_send_policy_builder_rejects_invalid_recipient_cert_pem() {
        let err = As4SendPolicyBuilder::new()
            .interop(InteropMode::Relaxed)
            .sign(false)
            .encrypt(true)
            .recipient_cert_pem(b"not-a-certificate".to_vec())
            .build()
            .expect_err("invalid recipient cert pem must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("recipient_cert_pem"));
    }

    // ── C12: generate_pull_request ───────────────────────────────────────────

    fn make_session() -> SessionContext {
        SessionContext::new("test-session", "test-partner", "test-profile").expect("test session")
    }

    #[test]
    fn generate_pull_request_unsigned_contains_mpc_and_message_id() {
        let session = make_session();
        let policy = As4GeneratePullRequestPolicy {
            mpc: "urn:example:mpc".to_string(),
            message_id: "test-pull-uuid-1@example.com".to_string(),
            credentials: None,
            authorization_info: None,
        };
        let bytes =
            generate_pull_request(&session, &policy).expect("unsigned pull request must succeed");
        let xml = String::from_utf8(bytes).expect("valid UTF-8");
        assert!(
            xml.contains("eb:PullRequest"),
            "must contain PullRequest element"
        );
        assert!(xml.contains("urn:example:mpc"), "must embed the MPC");
        assert!(
            xml.contains("test-pull-uuid-1@example.com"),
            "must embed message_id"
        );
        // Unsigned: no WS-Security header
        assert!(
            !xml.contains("wsse:Security"),
            "unsigned envelope must not have wsse:Security"
        );
    }

    #[test]
    fn generate_pull_request_rejects_empty_mpc() {
        let session = make_session();
        let policy = As4GeneratePullRequestPolicy {
            mpc: String::new(),
            message_id: "id@example.com".to_string(),
            credentials: None,
            authorization_info: None,
        };
        let err = generate_pull_request(&session, &policy).expect_err("empty MPC must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("MPC"));
    }

    #[test]
    fn generate_pull_request_rejects_empty_message_id() {
        let session = make_session();
        let policy = As4GeneratePullRequestPolicy {
            mpc: "urn:example:mpc".to_string(),
            message_id: "   ".to_string(),
            credentials: None,
            authorization_info: None,
        };
        let err = generate_pull_request(&session, &policy).expect_err("empty message_id must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("message_id"));
    }

    #[test]
    fn generate_pull_request_rejects_empty_authorization_info_when_set() {
        let session = make_session();
        let policy = As4GeneratePullRequestPolicy {
            mpc: "urn:example:mpc".to_string(),
            message_id: "id@example.com".to_string(),
            credentials: None,
            authorization_info: Some("   ".to_string()),
        };
        let err = generate_pull_request(&session, &policy)
            .expect_err("empty authorization_info must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("authorization_info"));
    }

    #[test]
    fn generate_pull_request_signed_contains_wssec_header() {
        let session = make_session();
        let creds_raw = test_as4_credentials();
        let creds = As4PullRequestCredentials {
            signing_key_pem: creds_raw.signing_key_pem.clone().unwrap(),
            signing_cert_pem: creds_raw.signing_cert_pem.as_deref().unwrap().to_vec(),
            key_info_profile: WsSecOutboundKeyInfoProfile::default(),
        };
        let policy = As4GeneratePullRequestPolicy {
            mpc: "urn:example:mpc".to_string(),
            message_id: "signed-pull@example.com".to_string(),
            credentials: Some(creds),
            authorization_info: None,
        };
        let bytes =
            generate_pull_request(&session, &policy).expect("signed pull request must succeed");
        let xml = String::from_utf8(bytes).expect("valid UTF-8");
        assert!(
            xml.contains("eb:PullRequest"),
            "must contain PullRequest element"
        );
        assert!(
            xml.contains("wsse:Security"),
            "signed envelope must include wsse:Security header"
        );
        assert!(
            xml.contains("ds:Signature"),
            "signed envelope must include ds:Signature"
        );
        assert!(xml.contains("urn:example:mpc"), "must embed the MPC");
        // Regression: the envelope must be well-formed XML (wsse prefix
        // declared) and the signature must verify end-to-end.
        verify_enveloped_signature(&xml, WsSecVerifyOptions::new())
            .expect("signed pull request must verify");
    }

    #[test]
    fn generate_pull_request_rejects_invalid_signing_cert_pem() {
        let session = make_session();
        let creds_raw = test_as4_credentials();
        let creds = As4PullRequestCredentials {
            signing_key_pem: creds_raw.signing_key_pem.clone().unwrap(),
            signing_cert_pem: b"not-a-certificate".to_vec(),
            key_info_profile: WsSecOutboundKeyInfoProfile::default(),
        };
        let policy = As4GeneratePullRequestPolicy {
            mpc: "urn:example:mpc".to_string(),
            message_id: "signed-pull@example.com".to_string(),
            credentials: Some(creds),
            authorization_info: None,
        };

        let err = generate_pull_request(&session, &policy)
            .expect_err("invalid signing cert pem must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("signing_cert_pem"));
    }

    #[test]
    fn generate_pull_request_rejects_invalid_signing_key_pem() {
        let session = make_session();
        let creds_raw = test_as4_credentials();
        let creds = As4PullRequestCredentials {
            signing_key_pem: b"not-a-private-key".to_vec(),
            signing_cert_pem: creds_raw.signing_cert_pem.as_deref().unwrap().to_vec(),
            key_info_profile: WsSecOutboundKeyInfoProfile::default(),
        };
        let policy = As4GeneratePullRequestPolicy {
            mpc: "urn:example:mpc".to_string(),
            message_id: "signed-pull@example.com".to_string(),
            credentials: Some(creds),
            authorization_info: None,
        };

        let err = generate_pull_request(&session, &policy)
            .expect_err("invalid signing key pem must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("signing_key_pem"));
    }

    #[test]
    fn generate_pull_request_rejects_mismatched_signing_cert_and_key() {
        let session = make_session();
        let creds_a = test_as4_credentials();
        let creds_b = test_as4_credentials();
        let creds = As4PullRequestCredentials {
            signing_key_pem: creds_b.signing_key_pem.clone().unwrap(),
            signing_cert_pem: creds_a.signing_cert_pem.as_deref().unwrap().to_vec(),
            key_info_profile: WsSecOutboundKeyInfoProfile::default(),
        };
        let policy = As4GeneratePullRequestPolicy {
            mpc: "urn:example:mpc".to_string(),
            message_id: "signed-pull@example.com".to_string(),
            credentials: Some(creds),
            authorization_info: None,
        };

        let err = generate_pull_request(&session, &policy)
            .expect_err("mismatched signing cert/key must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("does not match"));
    }

    #[test]
    fn generate_pull_request_xml_injection_is_escaped() {
        let session = make_session();
        let policy = As4GeneratePullRequestPolicy {
            mpc: "urn:mpc<inject>".to_string(),
            message_id: "id&evil@example.com".to_string(),
            credentials: None,
            authorization_info: None,
        };
        let bytes =
            generate_pull_request(&session, &policy).expect("should succeed with escaped content");
        let xml = String::from_utf8(bytes).expect("valid UTF-8");
        assert!(!xml.contains("<inject>"), "raw < must be escaped in MPC");
        assert!(
            xml.contains("&lt;inject&gt;") || xml.contains("&amp;") || xml.contains("&lt;"),
            "content must be XML-escaped"
        );
    }

    // ── C13: AuthorizationInfo ────────────────────────────────────────────────

    #[test]
    fn generate_pull_request_includes_authorization_info_when_set() {
        let session = make_session();
        let policy = As4GeneratePullRequestPolicy {
            mpc: "urn:example:mpc".to_string(),
            message_id: "auth-pull@example.com".to_string(),
            credentials: None,
            authorization_info: Some("secret-token-42".to_string()),
        };
        let bytes = generate_pull_request(&session, &policy).expect("should succeed");
        let xml = String::from_utf8(bytes).expect("valid UTF-8");
        assert!(
            xml.contains("eb:AuthorizationInfo"),
            "must include AuthorizationInfo element"
        );
        assert!(
            xml.contains("secret-token-42"),
            "must include the token value"
        );
    }

    #[test]
    fn generate_pull_request_authorization_info_is_xml_escaped() {
        let session = make_session();
        let policy = As4GeneratePullRequestPolicy {
            mpc: "urn:example:mpc".to_string(),
            message_id: "auth-pull@example.com".to_string(),
            credentials: None,
            authorization_info: Some("token<evil>".to_string()),
        };
        let bytes = generate_pull_request(&session, &policy).expect("should succeed");
        let xml = String::from_utf8(bytes).expect("valid UTF-8");
        assert!(
            !xml.contains("<evil>"),
            "raw < in auth token must be escaped"
        );
        assert!(xml.contains("&lt;evil&gt;"), "must be XML-escaped");
    }

    #[test]
    fn constant_time_eq_returns_true_for_equal_slices() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn constant_time_eq_returns_false_for_differing_slices() {
        assert!(!constant_time_eq(b"secret", b"wrong_"));
        assert!(!constant_time_eq(b"secret", b"secre")); // different length
        assert!(!constant_time_eq(b"", b"x"));
    }
}
