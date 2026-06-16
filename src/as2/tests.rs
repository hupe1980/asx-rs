use super::*;
use crate::core::{AsxError, ErrorContext};
use crate::observability::audit_sink::{InMemoryAuditSink, ReplayCursor};
use crate::observability::{BackpressurePolicy, EventBus, EventEmissionMode};
use crate::reliability::{InMemoryDedupBackend, InMemoryReconciliationHook};
use crate::storage::BoxFuture;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509NameBuilder};
use std::sync::Arc;

struct TestSpoolEncryptionKeyProvider {
    provider: As2RegulatedSpoolKeyProvider,
    resolve: std::result::Result<Arc<[u8; 32]>, AsxError>,
}

impl SpoolEncryptionKeyProvider for TestSpoolEncryptionKeyProvider {
    fn provider_kind(&self) -> As2RegulatedSpoolKeyProvider {
        self.provider
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

#[cfg(feature = "client")]
fn signed_key_response_hmac(session: &SessionContext, key_hex: &str, secret: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let input = key_response_signing_input(
        As2RegulatedSpoolKeyProvider::KmsHttp.as_str(),
        session.session_id(),
        session.partner_id(),
        session.profile_name(),
        key_hex,
    );
    let hmac_key = PKey::hmac(secret.as_bytes()).expect("hmac key");
    let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &hmac_key)
        .expect("signer");
    signer.update(input.as_bytes()).expect("signer update");
    let sig = signer.sign_to_vec().expect("signer finalize");
    STANDARD.encode(sig)
}

#[cfg(feature = "client")]
fn no_mtls_tls_config() -> HttpKeyProviderTlsConfig {
    HttpKeyProviderTlsConfig::default()
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

struct DurableTestReconciliationWrapper(InMemoryReconciliationHook);

impl ReconciliationStorage for DurableTestReconciliationWrapper {
    fn is_durable(&self) -> bool {
        true
    }

    fn cluster_safe(&self) -> bool {
        true
    }

    fn enqueue(&self, request: ReconciliationRequest) -> crate::core::Result<bool> {
        self.0.enqueue(request)
    }

    fn queued_requests(&self) -> crate::core::Result<Vec<ReconciliationRequest>> {
        self.0.queued_requests()
    }

    fn resolve(&self, idempotency_key: &str) -> crate::core::Result<bool> {
        self.0.resolve(idempotency_key)
    }
}

fn durable_reliability() -> (DurableTestReconciliationWrapper, DurableTestDedup) {
    (
        DurableTestReconciliationWrapper(InMemoryReconciliationHook::default()),
        DurableTestDedup(InMemoryDedupBackend::default()),
    )
}

fn strict_bus() -> EventBus {
    let sink = Arc::new(InMemoryAuditSink::new());
    EventBus::new_with_config_and_mode(
        16,
        Some(sink),
        BackpressurePolicy::default(),
        EventEmissionMode::StrictTransactional,
    )
    .expect("bus")
}

struct AlwaysFailReconciliation;

#[cfg(not(feature = "testing"))]
struct DurableTestReconciliation(InMemoryReconciliationHook);

#[cfg(not(feature = "testing"))]
impl ReconciliationStorage for DurableTestReconciliation {
    fn is_durable(&self) -> bool {
        true
    }

    fn cluster_safe(&self) -> bool {
        true
    }

    fn enqueue(&self, request: ReconciliationRequest) -> crate::core::Result<bool> {
        self.0.enqueue(request)
    }

    fn queued_requests(&self) -> crate::core::Result<Vec<ReconciliationRequest>> {
        self.0.queued_requests()
    }

    fn resolve(&self, idempotency_key: &str) -> crate::core::Result<bool> {
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

    fn enqueue(&self, _request: ReconciliationRequest) -> crate::core::Result<bool> {
        Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            "simulated reconciliation backend outage",
            ErrorContext::new("as2_test_reconciliation_fail"),
        ))
    }

    fn queued_requests(&self) -> crate::core::Result<Vec<ReconciliationRequest>> {
        Ok(Vec::new())
    }

    fn resolve(&self, _idempotency_key: &str) -> crate::core::Result<bool> {
        Ok(false)
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
        signing_cert_pem: Some(cert.to_pem().expect("cert pem")),
        signing_key_pem: Some(pkey.private_key_to_pem_pkcs8().expect("private key pem")),
        recipient_cert_pem: Some(cert.to_pem().expect("recipient cert pem")),
    }
}

#[test]
fn as2_receive_policy_defaults_to_local_env_provider_selection() {
    assert_eq!(
        As2ReceivePolicy::default().regulated_spool_key_provider,
        As2RegulatedSpoolKeyProvider::LocalEnv
    );
}

#[test]
fn regulated_provider_selection_exposes_stable_labels() {
    assert_eq!(As2RegulatedSpoolKeyProvider::LocalEnv.as_str(), "local-env");
    assert_eq!(As2RegulatedSpoolKeyProvider::KmsFile.backend(), "file");
    assert_eq!(As2RegulatedSpoolKeyProvider::KmsHttp.backend(), "http");
}

#[test]
fn regulated_provider_selection_parses_and_formats() {
    let parsed: As2RegulatedSpoolKeyProvider = "hsm-file".parse().expect("parse provider");
    assert_eq!(parsed, As2RegulatedSpoolKeyProvider::HsmFile);
    assert_eq!(parsed.to_string(), "hsm-file");

    let parsed_http: As2RegulatedSpoolKeyProvider =
        "kms-http".parse().expect("parse http provider");
    assert_eq!(parsed_http, As2RegulatedSpoolKeyProvider::KmsHttp);
    assert_eq!(parsed_http.to_string(), "kms-http");

    let err = "not-a-provider"
        .parse::<As2RegulatedSpoolKeyProvider>()
        .expect_err("invalid provider should fail");
    assert!(err.contains("unsupported AS2 regulated spool key provider"));
}

#[cfg(feature = "client")]
#[tokio::test(flavor = "multi_thread")]
async fn regulated_http_provider_fetches_key_from_endpoint() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    let session =
        SessionContext::new("s-http", "p-http", "as4_openpeppol_strict").expect("session");
    let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let shared_secret = "test-kms-shared-secret";
    let key_hmac = signed_key_response_hmac(&session, key_hex, shared_secret);

    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).expect("read");
        let body = format!(
            "{{\"key_hex\":\"{}\",\"key_hmac_sha256\":\"{}\"}}",
            key_hex, key_hmac
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
    });

    let fetched_key_hex = fetch_spool_key_hex_over_http(
        As2RegulatedSpoolKeyProvider::KmsHttp,
        &session,
        format!("http://{addr}/v1/key"),
        None,
        shared_secret,
        &no_mtls_tls_config(),
    )
    .expect("http key fetch");

    server.join().expect("server thread");
    assert_eq!(
        fetched_key_hex,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
}

#[cfg(feature = "client")]
#[tokio::test(flavor = "multi_thread")]
async fn regulated_http_provider_retries_transient_server_error() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    let session = SessionContext::new("s-http-retry", "p-http-retry", "as4_openpeppol_strict")
        .expect("session");
    let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let shared_secret = "test-kms-shared-secret";
    let key_hmac = signed_key_response_hmac(&session, key_hex, shared_secret);

    let server = std::thread::spawn(move || {
        for response_index in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).expect("read");

            if response_index == 0 {
                stream
                    .write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .expect("write 503 response");
                continue;
            }

            let body = format!(
                "{{\"key_hex\":\"{}\",\"key_hmac_sha256\":\"{}\"}}",
                key_hex, key_hmac
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        }
    });

    let fetched_key_hex = fetch_spool_key_hex_over_http(
        As2RegulatedSpoolKeyProvider::KmsHttp,
        &session,
        format!("http://{addr}/v1/key"),
        None,
        shared_secret,
        &no_mtls_tls_config(),
    )
    .expect("http key fetch with retry");

    server.join().expect("server thread");
    assert_eq!(fetched_key_hex, key_hex);
}

#[cfg(feature = "client")]
#[tokio::test(flavor = "multi_thread")]
async fn regulated_http_provider_rejects_invalid_response_hmac() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).expect("read");
        let body = r#"{"key_hex":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","key_hmac_sha256":"aW52YWxpZA=="}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
    });

    let session = SessionContext::new(
        "s-http-bad-hmac",
        "p-http-bad-hmac",
        "as4_openpeppol_strict",
    )
    .expect("session");
    let err = fetch_spool_key_hex_over_http(
        As2RegulatedSpoolKeyProvider::KmsHttp,
        &session,
        format!("http://{addr}/v1/key"),
        None,
        "test-kms-shared-secret",
        &no_mtls_tls_config(),
    )
    .expect_err("invalid response hmac must fail closed");

    server.join().expect("server thread");
    assert_eq!(err.code, ErrorCode::PolicyViolation);
    assert!(
        err.message.contains("response hmac verification failed"),
        "expected authenticated response validation failure"
    );
}

#[cfg(feature = "client")]
#[test]
fn regulated_http_provider_circuit_opens_after_repeated_failures() {
    let session = SessionContext::new("s-http-circuit", "p-http-circuit", "as4_openpeppol_strict")
        .expect("session");
    let endpoint =
        reqwest::Url::parse("https://kms.example.test/v1/key-opens").expect("endpoint url");
    let resilience = HttpKeyProviderResilienceConfig::default();

    note_http_key_provider_circuit_success(As2RegulatedSpoolKeyProvider::KmsHttp, &endpoint);

    for _ in 0..resilience.circuit_failure_threshold {
        note_http_key_provider_circuit_failure(
            As2RegulatedSpoolKeyProvider::KmsHttp,
            &endpoint,
            "injected failure",
            &resilience,
        );
    }

    let err = ensure_http_key_provider_circuit_allows_request(
        As2RegulatedSpoolKeyProvider::KmsHttp,
        &session,
        &endpoint,
        &resilience,
    )
    .expect_err("circuit should be open after threshold failures");

    assert_eq!(err.code, ErrorCode::PolicyViolation);
    assert!(err.message.contains("circuit is open"));

    note_http_key_provider_circuit_success(As2RegulatedSpoolKeyProvider::KmsHttp, &endpoint);
}

#[cfg(feature = "client")]
#[test]
fn regulated_http_provider_circuit_respects_custom_threshold() {
    let session = SessionContext::new(
        "s-http-circuit-custom",
        "p-http-circuit-custom",
        "as4_openpeppol_strict",
    )
    .expect("session");
    let endpoint =
        reqwest::Url::parse("https://kms.example.test/v1/key-custom").expect("endpoint url");
    let resilience = HttpKeyProviderResilienceConfig {
        circuit_failure_threshold: 2,
        circuit_open_base_secs: 1,
        circuit_open_jitter_secs: 0,
        ..HttpKeyProviderResilienceConfig::default()
    };

    note_http_key_provider_circuit_success(As2RegulatedSpoolKeyProvider::KmsHttp, &endpoint);

    note_http_key_provider_circuit_failure(
        As2RegulatedSpoolKeyProvider::KmsHttp,
        &endpoint,
        "first failure",
        &resilience,
    );

    ensure_http_key_provider_circuit_allows_request(
        As2RegulatedSpoolKeyProvider::KmsHttp,
        &session,
        &endpoint,
        &resilience,
    )
    .expect("circuit should remain closed before custom threshold");

    note_http_key_provider_circuit_failure(
        As2RegulatedSpoolKeyProvider::KmsHttp,
        &endpoint,
        "second failure",
        &resilience,
    );

    let err = ensure_http_key_provider_circuit_allows_request(
        As2RegulatedSpoolKeyProvider::KmsHttp,
        &session,
        &endpoint,
        &resilience,
    )
    .expect_err("circuit should open at configured threshold");
    assert_eq!(err.code, ErrorCode::PolicyViolation);
    assert!(err.message.contains("circuit is open"));

    note_http_key_provider_circuit_success(As2RegulatedSpoolKeyProvider::KmsHttp, &endpoint);
}

#[cfg(feature = "client")]
#[test]
fn regulated_http_provider_backoff_jitter_respects_budget() {
    let resilience = HttpKeyProviderResilienceConfig {
        retry_backoff_base_ms: 100,
        retry_backoff_jitter_ms: 50,
        ..HttpKeyProviderResilienceConfig::default()
    };

    let attempt_1 = http_key_provider_backoff_for_attempt(
        1,
        &resilience,
        "kms-http",
        "s-http-jitter",
        "p-http-jitter",
        "as4_openpeppol_strict",
        "https://kms.example.test/v1/key",
    )
    .as_millis() as u64;

    let attempt_2 = http_key_provider_backoff_for_attempt(
        2,
        &resilience,
        "kms-http",
        "s-http-jitter",
        "p-http-jitter",
        "as4_openpeppol_strict",
        "https://kms.example.test/v1/key",
    )
    .as_millis() as u64;

    assert!((100..=150).contains(&attempt_1));
    assert!((200..=250).contains(&attempt_2));
}

#[test]
fn parse_spool_encryption_key_hex_accepts_64_hex_chars() {
    let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let key = parse_spool_encryption_key_hex(key_hex).expect("hex parse");
    assert_eq!(key.len(), 32);
    assert_eq!(key[0], 0x01);
    assert_eq!(key[31], 0xef);
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
    assert_eq!(err.code, ErrorCode::PolicyViolation);
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
        "local-env",
        "env",
        "failing",
        "key_resolution",
    )
    .expect("degraded transition event");

    let degraded = events.try_recv().expect("degraded event should be present");
    match degraded.event.as_ref() {
        AsxEvent::SpoolKeyProviderHealthStateChanged {
            provider,
            backend,
            previous_state,
            current_state,
            reason,
        } => {
            assert_eq!(*provider, "local-env");
            assert_eq!(*backend, "env");
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
        "local-env",
        "env",
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
            backend,
            previous_state,
            current_state,
            reason,
        } => {
            assert_eq!(*provider, "local-env");
            assert_eq!(*backend, "env");
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
        &As2ReceivePolicy {
            regulated_spool_key_provider: As2RegulatedSpoolKeyProvider::HsmFile,
            ..As2ReceivePolicy::default()
        },
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
            backend,
            auth_mode,
            auth_fingerprint_label,
            auth_rotation_hint,
            health_state,
            phase,
            error_code,
        } = scoped.event.as_ref()
        {
            assert_eq!(*provider, "hsm-file");
            assert_eq!(*backend, "file");
            assert_eq!(*auth_mode, "file-key");
            assert_eq!(auth_fingerprint_label.as_ref(), "not-applicable");
            assert_eq!(*auth_rotation_hint, "not-applicable");
            assert_eq!(*health_state, "failing");
            assert_eq!(*phase, "key_resolution");
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
async fn as2_receive_stream_with_metrics_fails_on_missing_regulated_provider_config() {
    let session = SessionContext::new("s3", "p3", "as4_openpeppol_strict").expect("session");
    let payload = vec![9u8; 64];
    let verifier = SyncToAsyncTrustVerifier::new(InsecureBypassTrustVerifier::new(
        TrustEvidence::verified_and_decryptable(),
    ));

    let err = receive_stream_with_metrics(
        &session,
        &As2ReceivePolicy {
            regulated_spool_key_provider: As2RegulatedSpoolKeyProvider::HsmFile,
            ..As2ReceivePolicy::default()
        },
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
fn regulated_provider_startup_self_test_failure_domain_is_reported() {
    let session = SessionContext::new("s4", "p4", "as4_openpeppol_strict").expect("session");
    let provider = TestSpoolEncryptionKeyProvider {
        provider: As2RegulatedSpoolKeyProvider::KmsEnv,
        resolve: Ok(Arc::new([0u8; 32])),
    };

    let outcome = regulated_stream_body_policy_build_with_provider(&session, 1024, &provider);

    match outcome {
        StreamBodyPolicyBuildOutcome::ProviderFailure { error, observation } => {
            assert_eq!(error.code, ErrorCode::PolicyViolation);
            assert!(error.message.contains("startup self-test failed"));
            assert_eq!(observation.provider, "kms-env");
            assert_eq!(observation.backend, "env");
            assert_eq!(observation.health_state, "failing");
            assert_eq!(observation.phase, "startup_self_test");
            assert_eq!(observation.error_code, "policy_violation");
        }
        StreamBodyPolicyBuildOutcome::Ready { .. } => {
            panic!("expected startup self-test provider failure")
        }
    }
}

#[test]
fn regulated_provider_key_resolution_failure_domain_is_reported() {
    let session = SessionContext::new("s5", "p5", "as4_openpeppol_strict").expect("session");
    let provider = TestSpoolEncryptionKeyProvider {
        provider: As2RegulatedSpoolKeyProvider::HsmFile,
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
            assert_eq!(observation.provider, "hsm-file");
            assert_eq!(observation.backend, "file");
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
fn regulated_http_provider_missing_endpoint_is_fail_closed() {
    let session = SessionContext::new("s-http-missing", "p-http-missing", "as4_openpeppol_strict")
        .expect("session");
    let provider = HttpJsonSpoolEncryptionKeyProvider::new(As2RegulatedSpoolKeyProvider::KmsHttp);

    let err = provider
        .resolve_key(&session)
        .expect_err("missing endpoint must fail closed");

    assert_eq!(err.code, ErrorCode::PolicyViolation);
    assert!(
        err.message.contains("ASX_SPOOL_KMS_DATA_KEY_HTTP_URL"),
        "expected missing endpoint env var in error message"
    );
}

#[cfg(feature = "client")]
#[test]
fn regulated_http_provider_rejects_non_loopback_plain_http_endpoint() {
    let session = SessionContext::new("s-http-policy", "p-http-policy", "as4_openpeppol_strict")
        .expect("session");

    let err = fetch_spool_key_hex_over_http(
        As2RegulatedSpoolKeyProvider::KmsHttp,
        &session,
        "http://example.com/v1/key".to_string(),
        None,
        "test-kms-shared-secret",
        &no_mtls_tls_config(),
    )
    .expect_err("non-loopback plain http must fail closed");

    assert_eq!(err.code, ErrorCode::PolicyViolation);
    assert!(err.message.contains("requires https endpoint URL"));
}

#[cfg(feature = "client")]
#[test]
fn regulated_http_provider_requires_mtls_for_non_loopback_https_endpoint() {
    let session = SessionContext::new(
        "s-http-mtls-required",
        "p-http-mtls-required",
        "as4_openpeppol_strict",
    )
    .expect("session");
    let endpoint = reqwest::Url::parse("https://kms.example.com/v1/key").expect("endpoint");

    let err = validate_http_key_provider_mtls_policy(
        As2RegulatedSpoolKeyProvider::KmsHttp,
        &session,
        &endpoint,
        &HttpKeyProviderTlsConfig::default(),
    )
    .expect_err("missing mTLS config must fail closed");

    assert_eq!(err.code, ErrorCode::PolicyViolation);
    assert!(
        err.message
            .contains("requires mTLS client certificate and key")
    );
}

#[cfg(feature = "client")]
#[test]
fn regulated_http_provider_rejects_partial_mtls_configuration() {
    let session = SessionContext::new(
        "s-http-mtls-partial",
        "p-http-mtls-partial",
        "as4_openpeppol_strict",
    )
    .expect("session");
    let endpoint = reqwest::Url::parse("https://kms.example.com/v1/key").expect("endpoint");
    let tls_config = HttpKeyProviderTlsConfig {
        client_cert_pem_path: Some("/tmp/kms-client-cert.pem".to_string()),
        client_key_pem_path: None,
        trust_anchor_cert_pem_paths: Vec::new(),
    };

    let err = resolve_http_key_provider_client_identity_pem(
        As2RegulatedSpoolKeyProvider::KmsHttp,
        &session,
        &endpoint,
        &tls_config,
    )
    .expect_err("partial mTLS config must fail closed");

    assert_eq!(err.code, ErrorCode::PolicyViolation);
    assert!(
        err.message
            .contains("requires both mTLS client certificate and key")
    );
}

#[cfg(feature = "client")]
#[test]
fn regulated_http_provider_requires_pinned_trust_anchor_for_non_loopback_https_endpoint() {
    let session = SessionContext::new(
        "s-http-pinned-anchor-required",
        "p-http-pinned-anchor-required",
        "as4_openpeppol_strict",
    )
    .expect("session");
    let endpoint = reqwest::Url::parse("https://kms.example.com/v1/key").expect("endpoint");
    let tls_config = HttpKeyProviderTlsConfig {
        client_cert_pem_path: Some("/tmp/kms-client-cert.pem".to_string()),
        client_key_pem_path: Some("/tmp/kms-client-key.pem".to_string()),
        trust_anchor_cert_pem_paths: Vec::new(),
    };

    let err = validate_http_key_provider_mtls_policy(
        As2RegulatedSpoolKeyProvider::KmsHttp,
        &session,
        &endpoint,
        &tls_config,
    )
    .expect_err("missing pinned trust anchor must fail closed");

    assert_eq!(err.code, ErrorCode::PolicyViolation);
    assert!(
        err.message
            .contains("requires pinned trust-anchor certificate")
    );
}

#[cfg(feature = "client")]
#[test]
fn regulated_http_provider_accepts_multiple_pinned_trust_anchors_for_rotation() {
    let session = SessionContext::new(
        "s-http-pinned-anchor-rotation",
        "p-http-pinned-anchor-rotation",
        "as4_openpeppol_strict",
    )
    .expect("session");
    let endpoint = reqwest::Url::parse("https://kms.example.com/v1/key").expect("endpoint");
    let tls_config = HttpKeyProviderTlsConfig {
        client_cert_pem_path: Some("/tmp/kms-client-cert.pem".to_string()),
        client_key_pem_path: Some("/tmp/kms-client-key.pem".to_string()),
        trust_anchor_cert_pem_paths: vec![
            "/tmp/kms-ca-current.pem".to_string(),
            "/tmp/kms-ca-next.pem".to_string(),
        ],
    };

    validate_http_key_provider_mtls_policy(
        As2RegulatedSpoolKeyProvider::KmsHttp,
        &session,
        &endpoint,
        &tls_config,
    )
    .expect("multiple pinned trust anchors should be accepted for rotation windows");
}

#[cfg(feature = "client")]
#[test]
fn regulated_http_provider_loopback_http_does_not_require_pinned_trust_anchor() {
    let session = SessionContext::new(
        "s-http-loopback-no-pin",
        "p-http-loopback-no-pin",
        "as4_openpeppol_strict",
    )
    .expect("session");
    let endpoint = reqwest::Url::parse("http://127.0.0.1:8080/v1/key").expect("endpoint");

    validate_http_key_provider_mtls_policy(
        As2RegulatedSpoolKeyProvider::KmsHttp,
        &session,
        &endpoint,
        &HttpKeyProviderTlsConfig::default(),
    )
    .expect("loopback HTTP harness should not require mTLS or pinned anchor");
}

#[test]
fn regulated_provider_startup_self_test_accepts_non_zero_key() {
    let session = SessionContext::new("s-self-test-ok", "p-self-test-ok", "as4_openpeppol_strict")
        .expect("session");
    let key = [7u8; 32];

    validate_spool_encryption_key_startup_self_test(
        As2RegulatedSpoolKeyProvider::LocalEnv,
        &session,
        &key,
    )
    .expect("startup self-test should pass for usable key material");
}

#[test]
fn regulated_http_provider_key_resolution_failure_domain_is_reported() {
    let session = SessionContext::new(
        "s-http-observation",
        "p-http-observation",
        "as4_openpeppol_strict",
    )
    .expect("session");

    let outcome = as2_stream_body_policy_build(
        &session,
        &As2ReceivePolicy {
            regulated_spool_key_provider: As2RegulatedSpoolKeyProvider::KmsHttp,
            ..As2ReceivePolicy::default()
        },
    );

    match outcome {
        StreamBodyPolicyBuildOutcome::ProviderFailure { observation, .. } => {
            assert_eq!(observation.provider, "kms-http");
            assert_eq!(observation.backend, "http");
            assert_eq!(observation.auth_mode, "mtls-pinned-trust-anchor");
            assert_eq!(
                observation.auth_fingerprint_label,
                "client:unconfigured;anchors:unconfigured"
            );
            assert_eq!(observation.auth_rotation_hint, "unconfigured");
            assert_eq!(observation.health_state, "failing");
            assert_eq!(observation.phase, "key_resolution");
            assert_eq!(observation.error_code, "policy_violation");
        }
        StreamBodyPolicyBuildOutcome::Ready { .. } => {
            panic!("expected provider failure when HTTP endpoint is missing")
        }
    }
}

#[test]
fn regulated_provider_success_observation_reports_healthy_state() {
    let session = SessionContext::new("s6", "p6", "as4_openpeppol_strict").expect("session");
    let provider = TestSpoolEncryptionKeyProvider {
        provider: As2RegulatedSpoolKeyProvider::LocalEnv,
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
            assert_eq!(observation.provider, "local-env");
            assert_eq!(observation.backend, "env");
            assert_eq!(observation.auth_mode, "env-key");
            assert_eq!(observation.auth_fingerprint_label, "not-applicable");
            assert_eq!(observation.auth_rotation_hint, "not-applicable");
            assert_eq!(observation.health_state, "healthy");
        }
        StreamBodyPolicyBuildOutcome::ProviderFailure { error, .. } => {
            panic!("expected successful provider resolution, got {error:?}")
        }
    }
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
            credentials: test_as2_credentials(),
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
            credentials: test_as2_credentials(),
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
            credentials: test_as2_credentials(),
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
            credentials: As2SendCredentials {
                signing_cert_pem: creds_a.signing_cert_pem.clone(),
                signing_key_pem: creds_b.signing_key_pem.clone(),
                recipient_cert_pem: creds_a.recipient_cert_pem.clone(),
            },
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
            credentials: test_as2_credentials(),
        },
    )
    .expect("relaxed send");

    assert_eq!(out.message_id, "msg-1");
    assert_eq!(
        out.mic_base64,
        "8276mMbsVoT8+rLPugVLcL4l/jozb4Eu2ryV2chhR1k="
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
        signing_cert_pem: creds.signing_cert_pem.clone().expect("test signing cert"),
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
            expected_mic: Some("ZXELZG2MstvZ8CzynjCRhlEuxafCsnlFN6wFAV9r8AA=, sha-256".to_string()),
            policy: As2ReceivePolicy {
                fail_closed_audit_events: false,
                ..As2ReceivePolicy::default()
            },
            original_message_id: None,
        },
        &hook,
        &dedup,
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
            expected_mic: None,
            policy: As2ReceivePolicy {
                fail_closed_audit_events: false,
                ..As2ReceivePolicy::default()
            },
            original_message_id: None,
        },
        &hook,
        &dedup,
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
            expected_mic: Some("ZXELZG2MstvZ8CzynjCRhlEuxafCsnlFN6wFAV9r8AA=, sha-256".to_string()),
            policy: As2ReceivePolicy {
                fail_closed_audit_events: false,
                ..As2ReceivePolicy::default()
            },
            original_message_id: None,
        },
        &hook,
        &dedup,
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
            expected_mic: Some("ZXELZG2MstvZ8CzynjCRhlEuxafCsnlFN6wFAV9r8AA=, sha-256".to_string()),
            policy: As2ReceivePolicy {
                fail_closed_audit_events: false,
                ..As2ReceivePolicy::default()
            },
            original_message_id: None,
        },
        &hook,
        &dedup,
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
            expected_mic: None,
            policy: As2ReceivePolicy {
                fail_closed_audit_events: false,
                ..As2ReceivePolicy::default()
            },
            original_message_id: None,
        },
        &hook,
        &dedup,
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
        &dedup,
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
    let dedup = InMemoryDedupBackend::default();
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
            expected_mic: None,
            policy: As2ReceivePolicy::default(),
            original_message_id: Some("orig-1".to_string()),
        },
        &hook,
        &dedup,
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
            expected_mic: None,
            policy: As2ReceivePolicy {
                fail_closed_audit_events: false,
                ..As2ReceivePolicy::default()
            },
            original_message_id: None,
        },
        &hook,
        &dedup,
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
            expected_mic: None,
            policy: As2ReceivePolicy {
                interop_mode: InteropMode::Strict,
                interop_exceptions: InteropExceptionPolicy::default(),
                fail_closed_audit_events: true,
                regulated_spool_key_provider: As2RegulatedSpoolKeyProvider::LocalEnv,
                enforce_as2_version: false,
            },
            original_message_id: None,
        },
        &hook,
        &dedup,
        &InsecureBypassTrustVerifier::new(TrustEvidence::verified_and_decryptable()),
    )
    .expect_err("audit emission failure must fail closed");

    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
}

#[test]
fn parse_mdn_failure_with_original_id_fails_closed_when_reconciliation_enqueue_fails() {
    let bus = strict_bus();
    let dedup = DurableTestDedup(InMemoryDedupBackend::default());
    let mdn = vec![0xff, 0xfe, 0xfd, b'\n'];

    let err = receive_with_mdn_with_reliability(
        &session(),
        &bus,
        As2ReceiveMdnRequest {
            payload: vec![1].into(),
            mdn_payload: mdn.into(),
            mdn_mode: As2MdnMode::Synchronous,
            expected_mic: None,
            policy: As2ReceivePolicy {
                fail_closed_audit_events: false,
                ..As2ReceivePolicy::default()
            },
            original_message_id: Some("orig-1".to_string()),
        },
        &AlwaysFailReconciliation,
        &dedup,
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
    reconciliation
        .enqueue(
            crate::reliability::ReconciliationRequest::for_outcome(
                "<mdn-test-001@example.com>",
                "partner-a",
                crate::reliability::DeliveryOutcome::Indeterminate,
            )
            .expect("request"),
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
