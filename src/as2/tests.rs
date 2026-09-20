use super::*;
use crate::core::{AsxError, ErrorContext};
use crate::observability::audit_sink::{InMemoryAuditSink, ReplayCursor};
use crate::observability::{BackpressurePolicy, EventBus, EventEmissionMode};
use crate::reliability::{InMemoryDedupBackend, InMemoryReconciliationHook};
use crate::storage::{BoxFuture, DedupVerdict};
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509NameBuilder};
use std::sync::Arc;

/// A provider whose answer the test dictates, standing in for a real key manager.
#[derive(Debug)]
struct TestSpoolEncryptionKeyProvider {
    label: &'static str,
    resolve: std::result::Result<Arc<[u8; 32]>, AsxError>,
}

impl SpoolEncryptionKeyProvider for TestSpoolEncryptionKeyProvider {
    fn label(&self) -> &'static str {
        self.label
    }

    fn resolve_key(&self, _session: &SessionContext) -> Result<Arc<[u8; 32]>> {
        self.resolve.clone()
    }
}

fn session() -> SessionContext {
    SessionContext::new("s1", "p1", "strict")
        .expect("session")
        .with_strict_runtime_bootstrap_validated(true)
}

#[derive(Debug)]
struct DurableTestDedup(InMemoryDedupBackend);

impl DedupStorage for DurableTestDedup {
    fn is_durable(&self) -> bool {
        true
    }

    fn cluster_safe(&self) -> bool {
        true
    }

    fn claim<'a>(
        &'a self,
        idempotency_key: &'a str,
    ) -> BoxFuture<'a, crate::core::Result<DedupVerdict>> {
        self.0.claim(idempotency_key)
    }

    fn accept<'a>(&'a self, idempotency_key: &'a str) -> BoxFuture<'a, crate::core::Result<()>> {
        self.0.accept(idempotency_key)
    }

    fn abandon<'a>(&'a self, idempotency_key: &'a str) -> BoxFuture<'a, crate::core::Result<()>> {
        self.0.abandon(idempotency_key)
    }
}

#[derive(Debug)]

struct DurableTestReconciliationWrapper(InMemoryReconciliationHook);

impl ReconciliationStorage for DurableTestReconciliationWrapper {
    fn is_durable(&self) -> bool {
        true
    }

    fn cluster_safe(&self) -> bool {
        true
    }

    fn enqueue<'a>(
        &'a self,
        request: ReconciliationRequest,
    ) -> BoxFuture<'a, crate::core::Result<bool>> {
        self.0.enqueue(request)
    }

    fn queued_requests(&self) -> BoxFuture<'_, crate::core::Result<Vec<ReconciliationRequest>>> {
        self.0.queued_requests()
    }

    fn resolve<'a>(&'a self, idempotency_key: &'a str) -> BoxFuture<'a, crate::core::Result<bool>> {
        self.0.resolve(idempotency_key)
    }
}

fn durable_reliability() -> (
    DurableTestReconciliationWrapper,
    Arc<dyn crate::storage::DedupStorage>,
) {
    (
        DurableTestReconciliationWrapper(InMemoryReconciliationHook::default()),
        Arc::new(DurableTestDedup(InMemoryDedupBackend::default())),
    )
}

fn strict_bus() -> EventBus {
    let sink = Arc::new(InMemoryAuditSink::new().expect("audit sink"));
    EventBus::new_with_config_and_mode(
        16,
        Some(sink),
        BackpressurePolicy::default(),
        EventEmissionMode::StrictTransactional,
    )
    .expect("bus")
}

#[derive(Debug)]

struct AlwaysFailReconciliation;

#[cfg(not(feature = "testing"))]
#[derive(Debug)]
struct DurableTestReconciliation(InMemoryReconciliationHook);

#[cfg(not(feature = "testing"))]
impl ReconciliationStorage for DurableTestReconciliation {
    fn is_durable(&self) -> bool {
        true
    }

    fn cluster_safe(&self) -> bool {
        true
    }

    fn enqueue<'a>(
        &'a self,
        request: ReconciliationRequest,
    ) -> BoxFuture<'a, crate::core::Result<bool>> {
        self.0.enqueue(request)
    }

    fn queued_requests(&self) -> BoxFuture<'_, crate::core::Result<Vec<ReconciliationRequest>>> {
        self.0.queued_requests()
    }

    fn resolve<'a>(&'a self, idempotency_key: &'a str) -> BoxFuture<'a, crate::core::Result<bool>> {
        self.0.resolve(idempotency_key)
    }
}

impl ReconciliationStorage for AlwaysFailReconciliation {
    fn is_durable(&self) -> bool {
        true
    }

    fn cluster_safe(&self) -> bool {
        true
    }

    fn enqueue<'a>(
        &'a self,
        _request: ReconciliationRequest,
    ) -> BoxFuture<'a, crate::core::Result<bool>> {
        Box::pin(async move {
            Err(AsxError::new(
                ErrorCode::ReliabilityFailure,
                "simulated reconciliation backend outage",
                ErrorContext::new("as2_test_reconciliation_fail"),
            ))
        })
    }

    fn queued_requests(&self) -> BoxFuture<'_, crate::core::Result<Vec<ReconciliationRequest>>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn resolve<'a>(
        &'a self,
        _idempotency_key: &'a str,
    ) -> BoxFuture<'a, crate::core::Result<bool>> {
        Box::pin(async move { Ok(false) })
    }
}

fn test_as2_credentials() -> As2SendCredentials {
    let rsa = Rsa::generate(2048).expect("rsa");
    let pkey = PKey::from_rsa(rsa).expect("pkey");

    let mut name = X509NameBuilder::new().expect("name builder");
    name.append_entry_by_nid(Nid::COMMONNAME, "asx-test-signer")
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
        .sign(&pkey, openssl::hash::MessageDigest::sha256())
        .expect("sign cert");
    let cert = builder.build();

    As2SendCredentials {
        signing_cert_pem: Some(cert.to_pem().expect("cert pem").into()),
        signing_key_pem: Some(pkey.private_key_to_pem_pkcs8().expect("private key pem")),
        recipient_cert_pem: Some(cert.to_pem().expect("recipient cert pem").into()),
    }
}

#[test]
fn as2_receive_rejects_empty_payload() {
    let err = receive_sync(
        &session(),
        vec![],
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect_err("empty must fail");
    assert_eq!(err.code, ErrorCode::ParseFailed);
}

#[test]
fn as2_receive_rejects_invalid_signature() {
    let err = receive_sync(
        &session(),
        vec![1],
        &InsecureBypassTrustVerifier::new(TrustEvidence::signature_failed()),
    )
    .expect_err("invalid sig");
    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
}

#[test]
fn as2_cms_smime_verifier_rejects_unsigned_payload() {
    let err = receive_sync(
        &session(),
        b"plain-payload".to_vec(),
        &CmsSmimeTrustVerifier::default(),
    )
    .expect_err("unsigned payload must fail CMS verification");
    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
}

/// The default signature policy (`As2SignaturePolicy::Required`) must reject an
/// encrypted-only (unsigned) message; `allowing_unsigned()` opts into accepting
/// it. The unsigned-encrypted message is produced via relaxed-mode send (strict
/// send mandates signing).
#[cfg(feature = "interop-relaxed")]
#[test]
fn require_signed_rejects_encrypted_only_message() {
    let creds = test_as2_credentials();
    let bus = EventBus::new(16).expect("bus");
    let out = send_sync(
        &session(),
        &bus,
        As2SendRequest {
            message_id: "enc-only-1".into(),
            payload: b"<Invoice/>".to_vec(),
            policy: As2SendPolicy {
                interop_mode: InteropMode::Relaxed,
                fail_closed_audit_events: false,
                sign: false,
                encrypt: true,
                compress: false,
                payload_content_type: None,
                as2_from_id: String::new(),
                mic_algorithm: As2MicAlgorithm::Sha256,
                encryption_cipher: SmimeCipher::Aes256Cbc,
            },
            credentials: Some(creds.clone()),
        },
    )
    .expect("encrypted-only send");

    let key_pem = creds.signing_key_pem.clone().expect("key pem");
    let cert_pem = creds
        .recipient_cert_pem
        .clone()
        .expect("recipient cert")
        .to_vec();

    // The default policy (signatures Required) rejects an unsigned encrypted
    // message: encryption alone does not authenticate the sender.
    let strict_verifier =
        CmsSmimeTrustVerifier::with_decryption_credentials(key_pem.clone(), cert_pem.clone());
    let err = receive_sync(&session(), out.mime.body.to_vec(), &strict_verifier)
        .expect_err("the default policy must reject an unsigned encrypted message");
    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);

    // Opting in to As2SignaturePolicy::Optional accepts and decrypts it.
    let lenient_verifier =
        CmsSmimeTrustVerifier::with_decryption_credentials(key_pem, cert_pem).allowing_unsigned();
    receive_sync(&session(), out.mime.body.to_vec(), &lenient_verifier)
        .expect("Optional policy accepts encrypted-only message");
}

#[test]
fn as2_receive_rejects_missing_key() {
    let err = receive_sync(
        &session(),
        vec![1],
        &InsecureBypassTrustVerifier::new(TrustEvidence::missing_decryption_material()),
    )
    .expect_err("missing key");
    assert_eq!(err.code, ErrorCode::DecryptionFailed);
}

#[test]
fn as2_receive_rejects_oversized_payload() {
    let err = receive_sync(
        &session(),
        vec![0u8; MAX_AS2_PAYLOAD_BYTES + 1],
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect_err("oversized payload must fail");
    assert_eq!(err.code, ErrorCode::PayloadTooLarge);
}

#[tokio::test]
async fn as2_receive_stream_accepts_chunked_input() {
    let payload = vec![7u8; 64];
    let verifier = SyncToAsyncTrustVerifier::new(InsecureBypassTrustVerifier::new(
        TrustEvidence::verified_and_decryptable(),
    ));
    let (out, metrics) = receive_stream_with_metrics(
        &session(),
        &As2ReceivePolicy::default(),
        payload.as_slice(),
        &verifier,
        StreamLimits {
            max_body_bytes: 128,
            chunk_bytes: 11,
        },
    )
    .await
    .expect("chunked stream receive");
    assert_eq!(out.as_ref().as_ref().len(), 64);
    assert!(metrics.chunks > 1);
}

#[tokio::test]
async fn as2_receive_stream_audits_spool_materialization() {
    let session = SessionContext::new("s1", "p1", "as2_default")
        .expect("session")
        .with_strict_runtime_bootstrap_validated(true);
    let payload = vec![3u8; 1200 * 1024];
    let verifier = SyncToAsyncTrustVerifier::new(InsecureBypassTrustVerifier::new(
        TrustEvidence::verified_and_decryptable(),
    ));
    let bus = strict_bus();
    let mut events = bus.subscribe_scoped_events();

    let (_out, metrics) = receive_stream_with_metrics_and_audit(
        &session,
        &As2ReceivePolicy::default(),
        &bus,
        true,
        payload.as_slice(),
        &verifier,
        StreamLimits {
            max_body_bytes: 2 * 1024 * 1024,
            chunk_bytes: 32 * 1024,
        },
    )
    .await
    .expect("stream receive should succeed");

    assert!(metrics.used_spool);
    assert!(metrics.materialized_from_spool);

    let mut saw_materialization = false;
    for _ in 0..4 {
        let scoped = tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
            .await
            .expect("event wait should not time out")
            .expect("event should be present");

        if let AsxEvent::MaterializationApplied {
            stage,
            reason,
            source,
            ..
        } = scoped.event.as_ref()
        {
            assert_eq!(*stage, "as2_receive_stream");
            assert_eq!(*reason, "spooled_payload_to_contiguous_bytes");
            assert_eq!(*source, "spool");
            saw_materialization = true;
            break;
        }
    }

    assert!(
        saw_materialization,
        "expected MaterializationApplied event in audited stream receive"
    );
}

#[test]
fn emit_stream_ingest_observations_emits_spool_headroom_checked_event() {
    let session = SessionContext::new("s-headroom", "p-headroom", "as2_default").expect("session");
    let bus = strict_bus();
    let mut events = bus.subscribe_scoped_events();
    let metrics = StreamReadMetrics {
        startup_hygiene_checked: true,
        spool_free_bytes: Some(4096),
        spool_min_free_bytes: Some(1024),
        ..StreamReadMetrics::default()
    };

    emit_stream_ingest_observations(&session, &bus, true, &metrics)
        .expect("ingest observation emission");

    let scoped = events.try_recv().expect("headroom event should be present");
    match scoped.event.as_ref() {
        AsxEvent::SpoolHeadroomChecked {
            stage,
            free_bytes,
            min_required_bytes,
        } => {
            assert_eq!(*stage, "as2_receive_stream");
            assert_eq!(*free_bytes, 4096);
            assert_eq!(*min_required_bytes, 1024);
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn provider_health_state_transition_emits_degraded_then_recovered() {
    let session =
        SessionContext::new("s-transition", "p-transition", "as2_default").expect("session");
    let bus = strict_bus();
    let mut events = bus.subscribe_scoped_events();

    maybe_emit_provider_health_state_transition(
        &session,
        &bus,
        true,
        "static",
        "failing",
        "key_resolution",
    )
    .expect("degraded transition event");

    let degraded = events.try_recv().expect("degraded event should be present");
    match degraded.event.as_ref() {
        AsxEvent::SpoolKeyProviderHealthStateChanged {
            provider,
            previous_state,
            current_state,
            reason,
        } => {
            assert_eq!(*provider, "static");
            assert_eq!(*previous_state, "unknown");
            assert_eq!(*current_state, "failing");
            assert_eq!(*reason, "key_resolution");
        }
        other => panic!("unexpected event: {other:?}"),
    }

    maybe_emit_provider_health_state_transition(
        &session,
        &bus,
        true,
        "static",
        "healthy",
        "policy_ready",
    )
    .expect("recovered transition event");

    let recovered = events
        .try_recv()
        .expect("recovered event should be present");
    match recovered.event.as_ref() {
        AsxEvent::SpoolKeyProviderHealthStateChanged {
            provider,
            previous_state,
            current_state,
            reason,
        } => {
            assert_eq!(*provider, "static");
            assert_eq!(*previous_state, "failing");
            assert_eq!(*current_state, "healthy");
            assert_eq!(*reason, "policy_ready");
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[tokio::test]
async fn as2_receive_stream_emits_provider_health_check_failure_event() {
    let session = SessionContext::new("s2", "p2", "as4_openpeppol_strict")
        .expect("session")
        .with_strict_runtime_bootstrap_validated(true);
    let payload = vec![7u8; 64];
    let verifier = SyncToAsyncTrustVerifier::new(InsecureBypassTrustVerifier::new(
        TrustEvidence::verified_and_decryptable(),
    ));
    let bus = strict_bus();
    let mut events = bus.subscribe_scoped_events();

    let err = receive_stream_with_metrics_and_audit(
        &session,
        // A profile that mandates an encrypted spool with no key provider
        // configured must fail closed, not spool in the clear.
        &As2ReceivePolicy::default(),
        &bus,
        true,
        payload.as_slice(),
        &verifier,
        StreamLimits {
            max_body_bytes: 128,
            chunk_bytes: 11,
        },
    )
    .await
    .expect_err("missing provider key-path must fail closed");

    assert_eq!(err.code, ErrorCode::PolicyViolation);

    let mut saw_failure = false;
    for _ in 0..4 {
        let scoped = tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
            .await
            .expect("event wait should not time out")
            .expect("event should be present");

        if let AsxEvent::SpoolKeyProviderHealthCheckFailed {
            provider,
            health_state,
            phase,
            error_code,
        } = scoped.event.as_ref()
        {
            assert_eq!(*provider, "unconfigured");
            assert_eq!(*health_state, "failing");
            assert_eq!(*phase, "provider_selection");
            assert_eq!(*error_code, "policy_violation");
            saw_failure = true;
            break;
        }
    }

    assert!(
        saw_failure,
        "expected SpoolKeyProviderHealthCheckFailed event in audited stream receive"
    );

    let replay = bus
        .replay_audit_events_from(
            &ReplayCursor {
                last_event_id: "0".into(),
                position: 0,
                last_timestamp: 0,
                integrity_tag_b64: String::new(),
            },
            8,
        )
        .expect("audit replay");

    assert!(
        replay
            .iter()
            .any(|evt| evt.code == "spool_key_provider_health_check_failed"),
        "expected stable provider-failure audit code in persisted events"
    );
}

#[tokio::test]
async fn as2_receive_stream_fails_closed_without_a_spool_key_provider() {
    let session = SessionContext::new("s3", "p3", "as4_openpeppol_strict").expect("session");
    let payload = vec![9u8; 64];
    let verifier = SyncToAsyncTrustVerifier::new(InsecureBypassTrustVerifier::new(
        TrustEvidence::verified_and_decryptable(),
    ));

    let err = receive_stream_with_metrics(
        &session,
        &As2ReceivePolicy::default(),
        payload.as_slice(),
        &verifier,
        StreamLimits {
            max_body_bytes: 128,
            chunk_bytes: 11,
        },
    )
    .await
    .expect_err("missing provider key-path must fail closed");

    assert_eq!(err.code, ErrorCode::PolicyViolation);
}

#[test]
fn regulated_provider_key_resolution_failure_domain_is_reported() {
    let session = SessionContext::new("s5", "p5", "as4_openpeppol_strict").expect("session");
    let provider = TestSpoolEncryptionKeyProvider {
        label: "vault",
        resolve: Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "injected key resolution failure",
            ErrorContext::for_session("as2_receive_stream_policy", &session),
        )),
    };

    let outcome = regulated_stream_body_policy_build_with_provider(&session, 2048, &provider);

    match outcome {
        StreamBodyPolicyBuildOutcome::ProviderFailure { error, observation } => {
            assert_eq!(error.code, ErrorCode::PolicyViolation);
            assert_eq!(error.message, "injected key resolution failure");
            assert_eq!(observation.provider, "vault");
            assert_eq!(observation.health_state, "failing");
            assert_eq!(observation.phase, "key_resolution");
            assert_eq!(observation.error_code, "policy_violation");
        }
        StreamBodyPolicyBuildOutcome::Ready { .. } => {
            panic!("expected key-resolution provider failure")
        }
    }
}

#[test]
fn regulated_provider_success_observation_reports_healthy_state() {
    let session = SessionContext::new("s6", "p6", "as4_openpeppol_strict").expect("session");
    let provider = TestSpoolEncryptionKeyProvider {
        label: "aws-kms",
        resolve: Ok(Arc::new([7u8; 32])),
    };

    let outcome = regulated_stream_body_policy_build_with_provider(&session, 4096, &provider);

    match outcome {
        StreamBodyPolicyBuildOutcome::Ready {
            body_policy,
            provider_observation,
        } => {
            assert!(matches!(
                body_policy.spool_encryption,
                SpoolEncryption::Aes256Gcm { .. }
            ));
            let observation = provider_observation.expect("provider observation");
            assert_eq!(observation.provider, "aws-kms");
            assert_eq!(observation.health_state, "healthy");
        }
        StreamBodyPolicyBuildOutcome::ProviderFailure { error, .. } => {
            panic!("expected successful provider resolution, got {error:?}")
        }
    }
}

/// The point of the provider trait: an embedder can wire any key manager
/// without the crate knowing anything about it.
#[tokio::test]
async fn a_custom_spool_key_provider_is_used_for_regulated_profiles() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct CountingProvider {
        calls: Arc<AtomicUsize>,
    }

    impl SpoolEncryptionKeyProvider for CountingProvider {
        fn label(&self) -> &'static str {
            "counting-kms"
        }

        fn resolve_key(&self, _session: &SessionContext) -> Result<Arc<[u8; 32]>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new([0x2Au8; 32]))
        }
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let session = SessionContext::new("s-custom", "p-custom", "as4_openpeppol_strict")
        .expect("session")
        .with_strict_runtime_bootstrap_validated(true);
    let policy = As2ReceivePolicy {
        spool_key_provider: Some(Arc::new(CountingProvider {
            calls: Arc::clone(&calls),
        })),
        ..As2ReceivePolicy::default()
    };
    let verifier = SyncToAsyncTrustVerifier::new(InsecureBypassTrustVerifier::new(
        TrustEvidence::verified_and_decryptable(),
    ));

    receive_stream_with_metrics(
        &session,
        &policy,
        vec![3u8; 64].as_slice(),
        &verifier,
        StreamLimits {
            max_body_bytes: 4096,
            chunk_bytes: 16,
        },
    )
    .await
    .expect("a supplied provider satisfies the encrypted-spool requirement");

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the custom provider must be the one consulted"
    );
}

/// `StaticSpoolKey` is enough to run a regulated profile end to end.
#[tokio::test]
async fn static_spool_key_satisfies_a_regulated_profile() {
    let session = SessionContext::new("s-static", "p-static", "as4_cef_strict")
        .expect("session")
        .with_strict_runtime_bootstrap_validated(true);
    let key = StaticSpoolKey::from_hex(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    .expect("key");
    let policy = As2ReceivePolicy {
        spool_key_provider: Some(Arc::new(key)),
        ..As2ReceivePolicy::default()
    };
    let verifier = SyncToAsyncTrustVerifier::new(InsecureBypassTrustVerifier::new(
        TrustEvidence::verified_and_decryptable(),
    ));

    receive_stream_with_metrics(
        &session,
        &policy,
        vec![5u8; 32].as_slice(),
        &verifier,
        StreamLimits {
            max_body_bytes: 4096,
            chunk_bytes: 16,
        },
    )
    .await
    .expect("StaticSpoolKey satisfies the encrypted-spool requirement");
}

#[tokio::test]
async fn strict_send_rejects_empty_payload() {
    let bus = EventBus::new(16).expect("bus");
    let err = send_sync(
        &session(),
        &bus,
        As2SendRequest {
            message_id: "msg-1".into(),
            payload: vec![],
            policy: As2SendPolicy::default(),
            credentials: Some(test_as2_credentials()),
        },
    )
    .expect_err("strict reject");

    assert_eq!(err.code, ErrorCode::PolicyViolation);
}

#[tokio::test]
async fn strict_send_async_rejects_empty_payload() {
    let bus = EventBus::new(16).expect("bus");
    let err = send_async(
        &session(),
        &bus,
        As2SendRequest {
            message_id: "msg-1".into(),
            payload: vec![],
            policy: As2SendPolicy::default(),
            credentials: Some(test_as2_credentials()),
        },
    )
    .await
    .expect_err("strict reject");

    assert_eq!(err.code, ErrorCode::PolicyViolation);
}

#[test]
fn strict_send_rejects_as2_from_header_injection_value() {
    let bus = EventBus::new(16).expect("bus");
    let err = send_sync(
        &session(),
        &bus,
        As2SendRequest {
            message_id: "msg-1".into(),
            payload: b"payload".to_vec(),
            policy: As2SendPolicy {
                interop_mode: InteropMode::Strict,
                fail_closed_audit_events: true,
                sign: true,
                encrypt: true,
                compress: false,
                payload_content_type: None,
                as2_from_id: "sender\r\nX-Evil: 1".to_string(),
                mic_algorithm: As2MicAlgorithm::Sha256,
                encryption_cipher: SmimeCipher::Aes256Cbc,
            },
            credentials: Some(test_as2_credentials()),
        },
    )
    .expect_err("strict AS2 send must reject AS2-From header injection attempts");

    assert_eq!(err.code, ErrorCode::PolicyViolation);
    assert!(err.message.contains("AS2-From"));
}

#[test]
fn strict_send_rejects_mismatched_signing_cert_and_key() {
    let bus = EventBus::new(16).expect("bus");
    let creds_a = test_as2_credentials();
    let creds_b = test_as2_credentials();

    let err = send_sync(
        &session(),
        &bus,
        As2SendRequest {
            message_id: "msg-1".into(),
            payload: b"payload".to_vec(),
            policy: As2SendPolicy::default(),
            credentials: Some(As2SendCredentials {
                signing_cert_pem: creds_a.signing_cert_pem.clone(),
                signing_key_pem: creds_b.signing_key_pem.clone(),
                recipient_cert_pem: creds_a.recipient_cert_pem.clone(),
            }),
        },
    )
    .expect_err("strict AS2 send must reject mismatched signing cert/key");

    assert_eq!(err.code, ErrorCode::PolicyViolation);
    assert!(err.message.contains("does not match signing key"));
}

#[tokio::test]
async fn receive_async_rejects_empty_payload() {
    let verifier: Arc<dyn As2TrustVerifier + Send + Sync> = Arc::new(
        InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    );
    let err = receive_async(&session(), vec![], verifier)
        .await
        .expect_err("empty must fail");
    assert_eq!(err.code, ErrorCode::ParseFailed);
}

#[cfg(feature = "interop-relaxed")]
#[tokio::test]
async fn relaxed_send_allows_empty_payload() {
    let bus = EventBus::new(16).expect("bus");
    let out = send_sync(
        &session(),
        &bus,
        As2SendRequest {
            message_id: "  msg-1  ".into(),
            payload: vec![],
            policy: As2SendPolicy {
                interop_mode: InteropMode::Relaxed,
                fail_closed_audit_events: false,
                sign: true,
                encrypt: true,
                compress: false,
                payload_content_type: None,
                as2_from_id: String::new(),
                mic_algorithm: As2MicAlgorithm::Sha256,
                encryption_cipher: SmimeCipher::Aes256Cbc,
            },
            credentials: Some(test_as2_credentials()),
        },
    )
    .expect("relaxed send");

    assert_eq!(out.message_id, "msg-1");
    // RFC 4130 §7.3.1: a signed message is MIC'd over the signed MIME entity.
    // Relaxed mode substitutes a single "\n" for the empty payload, so the
    // entity is the octet-stream header block plus that byte.
    let expected_entity =
        b"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n\n";
    assert_eq!(
        out.mic_base64,
        {
            use base64::Engine as _;
            use sha2::Digest;
            base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(expected_entity))
        },
        "MIC must digest the signed entity"
    );
}

#[test]
fn generate_mdn_is_deterministic() {
    let out = generate_mdn(
        &session(),
        "<msg-1@example.com>",
        "automatic-action/MDN-sent-automatically; processed",
        Some("abc123, sha-256"),
    )
    .expect("mdn generation");

    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains("Content-Type: multipart/report;"));
    assert!(text.contains("report-type=disposition-notification"));
    assert!(text.contains("Content-Type: text/plain; charset=us-ascii"));
    assert!(text.contains("Content-Type: message/disposition-notification"));
    assert!(text.contains("Original-Message-ID: <msg-1@example.com>"));
    assert!(text.contains("Disposition: automatic-action/MDN-sent-automatically; processed"));
    assert!(text.contains("Received-Content-MIC: abc123, sha-256"));
}

#[test]
fn generated_mdn_parses_in_strict_mode() {
    let bus = strict_bus();
    let _events = bus.subscribe_scoped_events();
    let mdn = generate_mdn(
        &session(),
        "<msg-parse@example.com>",
        "automatic-action/MDN-sent-automatically; processed",
        Some("ZXELZG2MstvZ8CzynjCRhlEuxafCsnlFN6wFAV9r8AA=, sha-256"),
    )
    .expect("mdn generation");

    let (parsed, reasons) = parse_mdn(
        &mdn,
        As2ReceivePolicy::default(),
        false,
        &session(),
        &bus,
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect("strict parse");

    assert!(reasons.is_empty());
    assert_eq!(
        parsed.original_message_id.as_deref(),
        Some("<msg-parse@example.com>")
    );
    assert_eq!(
        parsed.disposition,
        "automatic-action/MDN-sent-automatically; processed"
    );
    assert!(parsed.received_content_mic.is_some());
}

/// C-4: when a signed receipt was requested, an unsigned MDN must be rejected
/// in strict mode (non-repudiation downgrade defence, RFC 4130 §7.3).
#[test]
fn unsigned_mdn_rejected_when_signed_receipt_required() {
    let bus = strict_bus();
    let _events = bus.subscribe_scoped_events();
    let mdn = generate_mdn(
        &session(),
        "<msg-require-signed@example.com>",
        "automatic-action/MDN-sent-automatically; processed",
        Some("ZXELZG2MstvZ8CzynjCRhlEuxafCsnlFN6wFAV9r8AA=, sha-256"),
    )
    .expect("mdn generation");

    // require_signed_mdn = true + unsigned MDN → rejected.
    let err = parse_mdn(
        &mdn,
        As2ReceivePolicy::default(),
        true,
        &session(),
        &bus,
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect_err("unsigned MDN must be rejected when a signed receipt was required");
    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);

    // require_signed_mdn = false → same MDN parses fine.
    parse_mdn(
        &mdn,
        As2ReceivePolicy::default(),
        false,
        &session(),
        &bus,
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect("unsigned MDN accepted when no signed receipt was required");
}

#[test]
fn generate_mdn_rejects_empty_message_id() {
    let err = generate_mdn(
        &session(),
        "",
        "automatic-action/MDN-sent-automatically; processed",
        None,
    )
    .expect_err("must fail");
    assert_eq!(err.code, ErrorCode::InvalidInput);
}

#[test]
fn parse_signed_receipt_protocol_is_case_insensitive_and_allows_quotes() {
    assert!(ingress::parse_signed_receipt_protocol_pkcs7(
        "signed-receipt-protocol=optional,pkcs7-signature"
    ));
    assert!(ingress::parse_signed_receipt_protocol_pkcs7(
        "Signed-Receipt-Protocol=\"optional,application/pkcs7-signature\""
    ));
    assert!(!ingress::parse_signed_receipt_protocol_pkcs7(
        "signed-receipt-protocol=optional,unknown"
    ));
}

#[test]
fn parse_signed_receipt_micalg_is_case_insensitive_and_allows_quotes() {
    assert_eq!(
        ingress::parse_signed_receipt_micalg("signed-receipt-micalg=required,sha-256"),
        Some(As2MicAlgorithm::Sha256)
    );
    assert_eq!(
        ingress::parse_signed_receipt_micalg(
            "Signed-Receipt-Micalg=\"required, sha256\"; signed-receipt-protocol=required,pkcs7-signature"
        ),
        Some(As2MicAlgorithm::Sha256)
    );
    assert_eq!(
        ingress::parse_signed_receipt_micalg("signed-receipt-micalg=required,sha-1"),
        None
    );
    assert_eq!(
        ingress::parse_signed_receipt_micalg("signed-receipt-micalg=required,SHA-384"),
        Some(As2MicAlgorithm::Sha384)
    );
    assert_eq!(
        ingress::parse_signed_receipt_micalg("signed-receipt-micalg=required,sha512"),
        Some(As2MicAlgorithm::Sha512)
    );
    assert_eq!(
        ingress::parse_signed_receipt_micalg("signed-receipt-micalg=required,md5"),
        None
    );
}

#[test]
fn receive_from_ingress_negotiates_mic_with_mixed_case_option_key() {
    let payload = b"ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       *240101*0101*U*00501*000000001*0*P*>~";
    let session = session();
    let verifier = InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable());
    let out = receive_from_ingress(As2IngressReceiveRequest {
        session: &session,
        payload,
        content_type: "application/edi-x12",
        original_message_id: Some("<msg-micalg@example.com>"),
        as2_from_header: "p1",
        disposition_notification_to: Some("https://partner.example/mdn"),
        disposition_notification_options: Some("Signed-Receipt-Micalg=required,sha-256"),
        mdn_signing_credentials: None,
        verifier: &verifier,
    })
    .expect("ingress receive");

    assert_eq!(out.mic_algorithm, As2MicAlgorithm::Sha256);
    assert!(out.received_content_mic.is_some());
    assert!(out.sync_mdn.is_some());
}

#[test]
fn receive_from_ingress_signed_receipt_requires_mdn_signing_credentials() {
    let payload = b"ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       *240101*0101*U*00501*000000001*0*P*>~";
    let session = session();
    let verifier = InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable());
    let err = receive_from_ingress(As2IngressReceiveRequest {
        session: &session,
        payload,
        content_type: "application/edi-x12",
        original_message_id: Some("<msg-1@example.com>"),
        as2_from_header: "p1",
        disposition_notification_to: Some("https://partner.example/mdn"),
        disposition_notification_options: Some("signed-receipt-protocol=optional,pkcs7-signature"),
        mdn_signing_credentials: None,
        verifier: &verifier,
    })
    .expect_err("must reject missing signing credentials");

    assert_eq!(err.code, ErrorCode::PolicyViolation);
}

#[test]
fn receive_from_ingress_generates_signed_sync_mdn_when_requested() {
    let creds = test_as2_credentials();
    let mdn_signing = As2MdnSigningCredentials {
        signing_cert_pem: creds
            .signing_cert_pem
            .as_deref()
            .expect("test signing cert")
            .to_vec(),
        signing_key_pem: creds.signing_key_pem.clone().expect("test signing key"),
    };
    let payload =
        b"UNB+UNOA:1+SENDER+RECEIVER+240101:0101+1'UNH+1+INVOIC:D:01B:UN'UNT+2+1'UNZ+1+1'";

    let session = session();
    let verifier = InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable());
    let out = receive_from_ingress(As2IngressReceiveRequest {
        session: &session,
        payload,
        content_type: "application/edifact",
        original_message_id: Some("<msg-2@example.com>"),
        as2_from_header: "p1",
        disposition_notification_to: Some("https://partner.example/mdn"),
        disposition_notification_options: Some("signed-receipt-protocol=optional,pkcs7-signature"),
        mdn_signing_credentials: Some(&mdn_signing),
        verifier: &verifier,
    })
    .expect("ingress with signed mdn");

    let mdn = out.sync_mdn.expect("sync mdn");
    assert!(mdn.is_signed);
    assert!(
        mdn.content_type
            .to_ascii_lowercase()
            .starts_with("multipart/signed")
    );
    assert!(
        String::from_utf8_lossy(&mdn.bytes)
            .to_ascii_lowercase()
            .contains("content-type: multipart/signed")
    );
}

#[test]
fn receive_from_ingress_ignores_sha1_mic_request_and_uses_sha256_default() {
    let payload = b"ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       *240101*0101*U*00501*000000001*0*P*>~";
    let session = session();
    let verifier = InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable());
    let out = receive_from_ingress(As2IngressReceiveRequest {
        session: &session,
        payload,
        content_type: "application/edi-x12",
        original_message_id: Some("<msg-sha1@example.com>"),
        as2_from_header: "p1",
        disposition_notification_to: Some("https://partner.example/mdn"),
        disposition_notification_options: Some("signed-receipt-micalg=required,sha-1"),
        mdn_signing_credentials: None,
        verifier: &verifier,
    })
    .expect("unsupported sha-1 micalg must fall back to default");
    assert_eq!(out.mic_algorithm, As2MicAlgorithm::Sha256);
    assert!(out.received_content_mic.is_some());
}

#[test]
fn receive_with_mdn_processed_and_matching_mic_is_success() {
    let bus = EventBus::new(16).expect("bus");
    let _events = bus.subscribe_scoped_events();
    let mdn =
        b"Content-Type: multipart/report; report-type=disposition-notification; boundary=\"b\"\r\n\
Final-Recipient: rfc822; partner-a\r\n\
Original-Message-ID: <msg-1@example>\r\n\
Disposition: automatic-action/MDN-sent-automatically; processed\r\n\
Received-content-MIC: ZXELZG2MstvZ8CzynjCRhlEuxafCsnlFN6wFAV9r8AA=, sha-256\r\n";

    let (hook, dedup) = durable_reliability();
    let out = receive_with_mdn_with_reliability(
        &session(),
        &bus,
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.to_vec().into(),
            mdn_mode: As2MdnMode::Synchronous,
            require_signed_mdn: false,
            expected_mic: Some("ZXELZG2MstvZ8CzynjCRhlEuxafCsnlFN6wFAV9r8AA=, sha-256".to_string()),
            policy: As2ReceivePolicy {
                fail_closed_audit_events: false,
                ..As2ReceivePolicy::default()
            },
            original_message_id: None,
        },
        &hook,
        dedup.clone(),
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect("receive mdn");

    assert_eq!(out.outcome, DeliveryOutcome::SuccessConfirmed);
    assert!(!out.retry_decision.should_retry);
}

#[test]
fn receive_with_mdn_failure_is_failure_confirmed() {
    let bus = EventBus::new(16).expect("bus");
    let _events = bus.subscribe_scoped_events();
    let mdn = b"Content-Type: multipart/report; report-type=disposition-notification; boundary=\"b\"\r\n\
Final-Recipient: rfc822; partner-a\r\n\
Disposition: automatic-action/MDN-sent-automatically; failed/failure: unsupported MIC-algorithms\r\n";

    let (hook, dedup) = durable_reliability();
    let out = receive_with_mdn_with_reliability(
        &session(),
        &bus,
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.to_vec().into(),
            mdn_mode: As2MdnMode::Synchronous,
            require_signed_mdn: false,
            expected_mic: None,
            policy: As2ReceivePolicy {
                fail_closed_audit_events: false,
                ..As2ReceivePolicy::default()
            },
            original_message_id: None,
        },
        &hook,
        dedup.clone(),
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect("receive mdn");

    assert_eq!(out.outcome, DeliveryOutcome::FailureConfirmed);
}

#[test]
fn receive_with_mdn_async_missing_mic_is_pending_verification() {
    let bus = EventBus::new(16).expect("bus");
    let _events = bus.subscribe_scoped_events();
    let mdn = b"Content-Type: multipart/report; report-type=disposition-notification; boundary=\"b\"\r\n\
Final-Recipient: rfc822; partner-a\r\n\
Disposition: automatic-action/MDN-sent-automatically; processed/warning: authentication-failed, processing continued\r\n";

    let (hook, dedup) = durable_reliability();
    let out = receive_with_mdn_with_reliability(
        &session(),
        &bus,
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.to_vec().into(),
            mdn_mode: As2MdnMode::Asynchronous,
            require_signed_mdn: false,
            expected_mic: Some("ZXELZG2MstvZ8CzynjCRhlEuxafCsnlFN6wFAV9r8AA=, sha-256".to_string()),
            policy: As2ReceivePolicy {
                fail_closed_audit_events: false,
                ..As2ReceivePolicy::default()
            },
            original_message_id: None,
        },
        &hook,
        dedup.clone(),
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect("receive mdn");

    assert_eq!(out.outcome, DeliveryOutcome::AcceptedPendingVerification);
}

#[test]
fn receive_with_mdn_unknown_disposition_is_indeterminate() {
    let bus = EventBus::new(16).expect("bus");
    let _events = bus.subscribe_scoped_events();
    let mdn =
        b"Content-Type: multipart/report; report-type=disposition-notification; boundary=\"b\"\r\n\
Final-Recipient: rfc822; partner-a\r\n\
Disposition: automatic-action/MDN-sent-automatically; partner-custom\r\n";

    let (hook, dedup) = durable_reliability();
    let out = receive_with_mdn_with_reliability(
        &session(),
        &bus,
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.to_vec().into(),
            mdn_mode: As2MdnMode::Synchronous,
            require_signed_mdn: false,
            expected_mic: Some("ZXELZG2MstvZ8CzynjCRhlEuxafCsnlFN6wFAV9r8AA=, sha-256".to_string()),
            policy: As2ReceivePolicy {
                fail_closed_audit_events: false,
                ..As2ReceivePolicy::default()
            },
            original_message_id: None,
        },
        &hook,
        dedup.clone(),
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect("receive mdn");

    assert_eq!(out.outcome, DeliveryOutcome::Indeterminate);
    assert!(out.retry_decision.should_retry);
}

#[test]
fn strict_mdn_requires_multipart_report_or_signed_content_type() {
    let bus = EventBus::new(16).expect("bus");
    let (hook, dedup) = durable_reliability();
    let mdn = b"Content-Type: text/plain\r\n\
Final-Recipient: rfc822; partner-a\r\n\
Disposition: automatic-action/MDN-sent-automatically; processed\r\n";

    let err = receive_with_mdn_with_reliability(
        &session(),
        &bus,
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.to_vec().into(),
            mdn_mode: As2MdnMode::Synchronous,
            require_signed_mdn: false,
            expected_mic: None,
            policy: As2ReceivePolicy {
                fail_closed_audit_events: false,
                ..As2ReceivePolicy::default()
            },
            original_message_id: None,
        },
        &hook,
        dedup.clone(),
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect_err("strict mdn content-type check");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}

#[test]
fn strict_receive_with_mdn_rejects_interop_exception_overrides_runtime_policy() {
    let bus = strict_bus();
    let (hook, dedup) = durable_reliability();
    let mdn =
        b"Content-Type: multipart/report; report-type=disposition-notification; boundary=mdn\r\n\
\r\n\
--mdn\r\n\
Content-Type: text/plain\r\n\
\r\n\
ok\r\n\
--mdn\r\n\
Content-Type: message/disposition-notification\r\n\
\r\n\
Final-Recipient: rfc822; partner-a\r\n\
Original-Message-ID: <orig-1@example.com>\r\n\
Disposition: automatic-action/MDN-sent-automatically; processed\r\n\
\r\n\
--mdn--\r\n";

    let err = receive_with_mdn_with_reliability(
        &session(),
        &bus,
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.to_vec().into(),
            mdn_mode: As2MdnMode::Synchronous,
            require_signed_mdn: false,
            expected_mic: None,
            policy: As2ReceivePolicy {
                interop_mode: InteropMode::Strict,
                interop_exceptions: InteropExceptionPolicy::scoped(
                    "strict",
                    vec![InteropExceptionCode::As2AllowMissingMdnBoundary],
                ),
                ..As2ReceivePolicy::default()
            },
            original_message_id: None,
        },
        &hook,
        dedup.clone(),
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect_err("strict runtime policy must reject interop exception overrides");

    assert_eq!(err.code, ErrorCode::PolicyViolation);
    assert!(err.message.contains("interop exception"));
}

#[cfg(not(feature = "testing"))]
#[test]
fn strict_receive_with_mdn_rejects_non_durable_dedup_backend() {
    let bus = strict_bus();
    let hook = DurableTestReconciliation(InMemoryReconciliationHook::default());
    let dedup: Arc<dyn crate::storage::DedupStorage> = Arc::new(InMemoryDedupBackend::default());
    let mdn =
        b"Content-Type: multipart/report; report-type=disposition-notification; boundary=mdn\r\n\
\r\n\
--mdn\r\n\
Content-Type: text/plain\r\n\
\r\n\
ok\r\n\
--mdn\r\n\
Content-Type: message/disposition-notification\r\n\
\r\n\
Final-Recipient: rfc822; partner-a\r\n\
Original-Message-ID: <orig-1@example.com>\r\n\
Disposition: automatic-action/MDN-sent-automatically; processed\r\n\
\r\n\
--mdn--\r\n";

    let err = receive_with_mdn_with_reliability(
        &session(),
        &bus,
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.to_vec().into(),
            mdn_mode: As2MdnMode::Synchronous,
            require_signed_mdn: false,
            expected_mic: None,
            policy: As2ReceivePolicy::default(),
            original_message_id: Some("orig-1".to_string()),
        },
        &hook,
        dedup.clone(),
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect_err("non-durable dedup backend must be rejected");

    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
    assert!(
        err.message.contains("durable dedup backend"),
        "{}",
        err.message
    );
}

#[cfg(not(feature = "testing"))]
#[test]
fn receive_with_mdn_rejects_invalid_utf8_payload() {
    let bus = EventBus::new(16).expect("bus");
    let (hook, dedup) = durable_reliability();
    let mdn = vec![0xff, 0xfe, 0xfd, b'\n'];

    let err = receive_with_mdn_with_reliability(
        &session(),
        &bus,
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.into(),
            mdn_mode: As2MdnMode::Synchronous,
            require_signed_mdn: false,
            expected_mic: None,
            policy: As2ReceivePolicy {
                fail_closed_audit_events: false,
                ..As2ReceivePolicy::default()
            },
            original_message_id: None,
        },
        &hook,
        dedup.clone(),
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect_err("invalid utf8 mdn must fail");

    // In non-testing mode with strict interop, invalid UTF-8 may surface as
    // InteropViolation (content-type check fires before UTF-8 decode) or ParseFailed.
    // Either indicates the payload was rejected.
    assert!(
        err.code == ErrorCode::ParseFailed || err.code == ErrorCode::InteropViolation,
        "expected ParseFailed or InteropViolation, got {:?}: {}",
        err.code,
        err.message
    );
}

#[test]
fn missing_boundary_fails_closed_when_audit_emit_fails() {
    let bus = EventBus::new(16).expect("bus");
    let (hook, dedup) = durable_reliability();
    let mdn = b"Content-Type: multipart/report; report-type=disposition-notification\r\n\
Final-Recipient: rfc822; partner-a\r\n\
Disposition: automatic-action/MDN-sent-automatically; processed\r\n";

    let err = receive_with_mdn_with_reliability(
        &session(),
        &bus,
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.to_vec().into(),
            mdn_mode: As2MdnMode::Synchronous,
            require_signed_mdn: false,
            expected_mic: None,
            policy: As2ReceivePolicy {
                interop_mode: InteropMode::Strict,
                interop_exceptions: InteropExceptionPolicy::default(),
                fail_closed_audit_events: true,
                spool_key_provider: None,
                enforce_as2_version: false,
            },
            original_message_id: None,
        },
        &hook,
        dedup.clone(),
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect_err("audit emission failure must fail closed");

    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
}

#[test]
fn parse_mdn_failure_with_original_id_fails_closed_when_reconciliation_enqueue_fails() {
    let bus = strict_bus();
    let dedup: Arc<dyn crate::storage::DedupStorage> =
        Arc::new(DurableTestDedup(InMemoryDedupBackend::default()));
    let mdn = vec![0xff, 0xfe, 0xfd, b'\n'];

    let err = receive_with_mdn_with_reliability(
        &session(),
        &bus,
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.into(),
            mdn_mode: As2MdnMode::Synchronous,
            require_signed_mdn: false,
            expected_mic: None,
            policy: As2ReceivePolicy {
                fail_closed_audit_events: false,
                ..As2ReceivePolicy::default()
            },
            original_message_id: Some("orig-1".to_string()),
        },
        &AlwaysFailReconciliation,
        dedup.clone(),
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect_err("reconciliation enqueue failure must fail closed");

    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
    assert!(
        err.message
            .contains("AS2 MDN parse failed and reconciliation enqueue failed"),
        "{}",
        err.message
    );
}

// ---- correlate_async_mdn tests ---------------------------------------------------

fn build_minimal_async_mdn(original_message_id: &str) -> Vec<u8> {
    let boundary = "asx-test-mdn-boundary";
    format!(
        "Content-Type: multipart/report; report-type=disposition-notification; boundary=\"{boundary}\"\r\n\
MIME-Version: 1.0\r\n\
\r\n\
--{boundary}\r\n\
Content-Type: text/plain; charset=us-ascii\r\n\
\r\n\
The message has been processed.\r\n\
\r\n\
--{boundary}\r\n\
Content-Type: message/disposition-notification\r\n\
\r\n\
Final-Recipient: rfc822; partner-a\r\n\
Original-Message-ID: {original_message_id}\r\n\
Disposition: automatic-action/MDN-sent-automatically; processed\r\n\
\r\n\
--{boundary}--\r\n"
    )
    .into_bytes()
}

#[test]
fn correlate_async_mdn_resolves_pending_indeterminate_entry() {
    let reconciliation = InMemoryReconciliationHook::default();
    use crate::storage::drive_dedup_future;
    drive_dedup_future(
        reconciliation.enqueue(
            crate::reliability::ReconciliationRequest::for_outcome(
                "<mdn-test-001@example.com>",
                "partner-a",
                crate::reliability::DeliveryOutcome::Indeterminate,
            )
            .expect("request"),
        ),
    )
    .expect("enqueue");

    let mdn = build_minimal_async_mdn("<mdn-test-001@example.com>");
    let outcome =
        correlate_async_mdn(&mdn, "partner-a", &reconciliation).expect("correlate_async_mdn");

    assert_eq!(
        outcome,
        AsyncMdnCorrelationOutcome::Resolved {
            original_message_id: "<mdn-test-001@example.com>".to_string()
        }
    );
}

#[test]
fn correlate_async_mdn_returns_not_pending_when_no_entry() {
    let reconciliation = InMemoryReconciliationHook::default();
    let mdn = build_minimal_async_mdn("<mdn-test-002@example.com>");

    let outcome =
        correlate_async_mdn(&mdn, "partner-a", &reconciliation).expect("correlate_async_mdn");

    assert_eq!(
        outcome,
        AsyncMdnCorrelationOutcome::NotPending {
            original_message_id: "<mdn-test-002@example.com>".to_string()
        }
    );
}

#[test]
fn correlate_async_mdn_returns_no_original_message_id_for_empty_mdn() {
    let reconciliation = InMemoryReconciliationHook::default();
    // Minimal MIME without a disposition-notification part
    let mdn = b"Content-Type: text/plain\r\n\r\nno MDN here";

    let outcome =
        correlate_async_mdn(mdn, "partner-a", &reconciliation).expect("correlate_async_mdn");

    assert_eq!(outcome, AsyncMdnCorrelationOutcome::NoOriginalMessageId);
}

// ── RFC 4130 §7.3.1 MIC round-trip ──────────────────────────────────────────
//
// These are the tests the suite was missing: every prior "matching MIC" test
// asserted a hardcoded digest on both sides, so sender and receiver could
// disagree completely and still pass.  Here the sender's MIC and the receiver's
// `Received-Content-MIC` are computed independently and compared.

/// Self-signed signer usable as its own trust anchor, plus the session that
/// trusts it.
fn signing_identity() -> (As2SendCredentials, String, String) {
    let creds = test_as2_credentials();
    let cert_pem = String::from_utf8(creds.signing_cert_pem.as_ref().unwrap().to_vec())
        .expect("cert pem is utf-8");
    let cert = X509::from_pem(cert_pem.as_bytes()).expect("parse cert");
    let fingerprint = cert
        .digest(openssl::hash::MessageDigest::sha256())
        .expect("digest")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    (creds, cert_pem, fingerprint)
}

fn trusting_session(cert_pem: &str, fingerprint: &str) -> SessionContext {
    crate::core::SessionContextBuilder::new("s-mic", "p1")
        .with_trust_anchor_pem(cert_pem.to_string())
        // PKCS7_NOINTERN: the signer leaf must be supplied out-of-band.
        .with_intermediate_ca_pem(cert_pem.to_string())
        .with_fingerprint_sha256(fingerprint.to_string())
        // Self-signed fixture: no responder to reach, and these tests run
        // outside a Tokio runtime.
        .with_ocsp_mode(crate::core::OcspMode::Disabled)
        .build()
        .expect("session")
        .with_strict_runtime_bootstrap_validated(true)
}

/// Drive a full send → receive cycle and return
/// `(sender_mic, receiver_mic, delivered_payload)`.
fn mic_round_trip(
    payload: &[u8],
    content_type: &'static str,
    sign: bool,
    encrypt: bool,
    compress: bool,
) -> (String, String, Vec<u8>) {
    let bus = EventBus::new(16).expect("bus");
    let (creds, cert_pem, fingerprint) = signing_identity();
    let key_pem = creds.signing_key_pem.clone().expect("key");
    let session = trusting_session(&cert_pem, &fingerprint);

    let out = send_sync(
        &session,
        &bus,
        As2SendRequest {
            message_id: "mic-rt".to_string(),
            payload: payload.to_vec(),
            policy: As2SendPolicy {
                interop_mode: crate::core::InteropMode::Strict,
                fail_closed_audit_events: false,
                sign,
                encrypt,
                compress,
                payload_content_type: Some(content_type),
                as2_from_id: "p1".to_string(),
                mic_algorithm: As2MicAlgorithm::Sha256,
                encryption_cipher: SmimeCipher::Aes256Cbc,
            },
            credentials: Some(creds),
        },
    )
    .expect("send");

    let mut verifier =
        CmsSmimeTrustVerifier::with_decryption_credentials(key_pem, cert_pem.clone().into_bytes());
    if !sign {
        verifier = verifier.allowing_unsigned();
    }

    let inbound = receive_from_ingress(As2IngressReceiveRequest {
        session: &session,
        payload: &out.mime.body,
        content_type: &out.mime.content_type,
        original_message_id: Some("mic-rt"),
        as2_from_header: "p1",
        disposition_notification_to: Some("http://example.test/mdn"),
        disposition_notification_options: Some("signed-receipt-micalg=required,sha-256"),
        mdn_signing_credentials: None,
        verifier: &verifier,
    })
    .expect("receive");

    let received_mic = inbound
        .received_content_mic
        .expect("MDN must carry Received-Content-MIC");
    let received_digest = received_mic
        .split(',')
        .next()
        .expect("mic digest")
        .trim()
        .to_string();

    (
        out.mic_base64,
        received_digest,
        inbound.content.as_ref().to_vec(),
    )
}

#[test]
fn signed_body_without_embedded_mime_headers_is_verified() {
    // RFC 4130 partners differ in whether the HTTP body repeats the outer
    // MIME headers. asx embeds them; openssl-CLI-based stacks do too; but a
    // partner may send the multipart content with the media type only in the
    // HTTP Content-Type header. Strip asx's embedded headers to simulate that
    // partner and require the receive path to synthesize them back from the
    // transport header.
    let payload = b"UNB+UNOC:3+SENDER+RECEIVER+240101:1200+1'";
    let bus = EventBus::new(16).expect("bus");
    let (creds, cert_pem, fingerprint) = signing_identity();
    let key_pem = creds.signing_key_pem.clone().expect("key");
    let session = trusting_session(&cert_pem, &fingerprint);

    let out = send_sync(
        &session,
        &bus,
        As2SendRequest {
            message_id: "headerless".to_string(),
            payload: payload.to_vec(),
            policy: As2SendPolicy {
                interop_mode: crate::core::InteropMode::Strict,
                fail_closed_audit_events: false,
                sign: true,
                encrypt: false,
                compress: false,
                payload_content_type: Some("application/edifact"),
                as2_from_id: "p1".to_string(),
                mic_algorithm: As2MicAlgorithm::Sha256,
                encryption_cipher: SmimeCipher::Aes256Cbc,
            },
            credentials: Some(creds),
        },
    )
    .expect("send");

    // Drop everything up to and including the first blank line — the embedded
    // outer MIME headers — leaving the bare multipart content.
    let body = out.mime.body.to_vec();
    // Header block may use CRLF or LF line endings; take the earliest blank line.
    let crlf = body
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4);
    let lf = body.windows(2).position(|w| w == b"\n\n").map(|i| i + 2);
    let sep = match (crlf, lf) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => panic!("embedded MIME headers present in asx output"),
    };
    let headerless = &body[sep..];
    assert!(
        !headerless.starts_with(b"MIME-Version"),
        "test must exercise the headerless shape"
    );

    let verifier =
        CmsSmimeTrustVerifier::with_decryption_credentials(key_pem, cert_pem.clone().into_bytes());
    let inbound = receive_from_ingress(As2IngressReceiveRequest {
        session: &session,
        payload: headerless,
        content_type: &out.mime.content_type,
        original_message_id: Some("headerless"),
        as2_from_header: "p1",
        disposition_notification_to: Some("http://example.test/mdn"),
        disposition_notification_options: Some("signed-receipt-micalg=required,sha-256"),
        mdn_signing_credentials: None,
        verifier: &verifier,
    })
    .expect("headerless signed body must verify via the transport Content-Type");

    assert_eq!(inbound.content.as_ref().as_ref(), payload);
}

#[test]
fn signed_message_mic_round_trips_and_delivers_the_payload() {
    let payload = b"ISA*00*          *00*          *ZZ*SENDER~";
    let (sent, received, delivered) =
        mic_round_trip(payload, "application/edi-x12", true, false, false);

    assert_eq!(
        sent, received,
        "sender MIC and receiver Received-Content-MIC must agree for a signed message"
    );
    assert_eq!(
        delivered,
        payload.to_vec(),
        "the application must receive the EDI payload, not the S/MIME envelope"
    );
}

#[test]
fn encrypted_and_signed_message_mic_round_trips() {
    let payload = b"UNB+UNOC:3+SENDER+RECEIVER+240101:1200+1'";
    let (sent, received, delivered) =
        mic_round_trip(payload, "application/edifact", true, true, false);

    assert_eq!(sent, received, "MIC must survive sign-then-encrypt");
    assert_eq!(delivered, payload.to_vec());
}

#[test]
fn unprotected_message_mic_round_trips() {
    let payload = b"<Invoice><Id>1</Id></Invoice>";
    let (sent, received, delivered) =
        mic_round_trip(payload, "application/xml", false, false, false);

    assert_eq!(sent, received, "MIC must agree for an unprotected message");
    assert_eq!(delivered, payload.to_vec());
}

#[cfg(feature = "compression")]
#[test]
fn compressed_signed_message_mic_round_trips_and_decompresses() {
    // Repetitive so compression actually engages.
    let payload = b"ISA*00*SEGMENT~".repeat(64);
    let (sent, received, delivered) =
        mic_round_trip(&payload, "application/edi-x12", true, false, true);

    assert_eq!(
        sent, received,
        "MIC must be computed over the compressed entity that was signed"
    );
    assert_eq!(
        delivered, payload,
        "the receive path must reverse RFC 5402 compression"
    );
}

/// The payload's declared media type has to survive onto the wire — losing it
/// (e.g. to OpenSSL's PKCS7_TEXT flag) both misinforms the partner and
/// desynchronizes the MIC.
#[test]
fn signed_entity_carries_the_declared_payload_content_type() {
    let bus = EventBus::new(16).expect("bus");
    let (creds, cert_pem, fingerprint) = signing_identity();
    let session = trusting_session(&cert_pem, &fingerprint);

    let out = send_sync(
        &session,
        &bus,
        As2SendRequest {
            message_id: "ct-1".to_string(),
            payload: b"ISA*00~".to_vec(),
            policy: As2SendPolicy {
                interop_mode: crate::core::InteropMode::Strict,
                fail_closed_audit_events: false,
                sign: true,
                encrypt: false,
                compress: false,
                payload_content_type: Some("application/edi-x12"),
                as2_from_id: "p1".to_string(),
                mic_algorithm: As2MicAlgorithm::Sha256,
                encryption_cipher: SmimeCipher::Aes256Cbc,
            },
            credentials: Some(creds),
        },
    )
    .expect("send");

    let wire = String::from_utf8_lossy(&out.mime.body);
    assert!(
        wire.contains("Content-Type: application/edi-x12"),
        "signed part must declare the payload's real media type; got:\n{wire}"
    );
    assert!(
        !wire.contains("Content-Type: text/plain"),
        "signed part must not be relabelled text/plain; got:\n{wire}"
    );
}
