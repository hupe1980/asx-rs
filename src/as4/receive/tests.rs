#![cfg_attr(not(feature = "interop-relaxed"), allow(unused_imports, dead_code))]
use super::*;
use crate::as4::conversation_gate::As4ConversationOrderGate;
#[cfg(feature = "interop-relaxed")]
use crate::as4::send_sync_fragmented;
use crate::as4::types::{
    As4PushPolicyBuilder, As4ReceivePushProgress, As4ReceivePushRequest, As4SendCredentials,
    As4SendPolicyBuilder,
};
use crate::core::{CertHandle, ErrorCode, OcspFailureMode, OcspMode, SessionContext};
use crate::reliability::InMemoryDedupBackend;
use crate::storage::{BoxFuture, DedupStorage};
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509NameBuilder};
use roxmltree::Document;
use std::sync::Arc;
use std::time::Duration;

struct DurableTestDedup(InMemoryDedupBackend);

impl DedupStorage for DurableTestDedup {
    fn is_durable(&self) -> bool {
        true
    }

    fn first_seen<'a>(&'a self, idempotency_key: &'a str) -> BoxFuture<'a, Result<bool>> {
        self.0.first_seen(idempotency_key)
    }
}

fn test_as4_credentials() -> As4SendCredentials {
    let rsa = Rsa::generate(2048).expect("rsa");
    let pkey = PKey::from_rsa(rsa).expect("pkey");

    let mut name = X509NameBuilder::new().expect("name builder");
    name.append_entry_by_nid(Nid::COMMONNAME, "asx-as4-receive-test")
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
        signing_cert_pem: Some(cert.to_pem().expect("cert pem")),
        signing_key_pem: Some(pkey.private_key_to_pem_pkcs8().expect("private key pem")),
        recipient_cert_pem: Some(cert.to_pem().expect("recipient cert pem")),
    }
}

fn session_with_trust(
    session_id: &str,
    partner_id: &str,
    creds: &As4SendCredentials,
) -> SessionContext {
    let cert_pem = creds
        .signing_cert_pem
        .as_ref()
        .expect("test creds must have signing cert");
    let cert_pem_str = String::from_utf8(cert_pem.clone()).expect("cert pem utf8");
    let cert = X509::from_pem(cert_pem).expect("cert parse");
    let cert_digest = cert
        .digest(MessageDigest::sha256())
        .expect("cert sha256 fingerprint");
    let cert_fingerprint = cert_digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    SessionContext::new(session_id, partner_id, "strict")
        .expect("session")
        .with_cert_handle(CertHandle {
            trust_anchor_pems: vec![cert_pem_str],
            fingerprint_sha256: cert_fingerprint,
            ocsp_mode: OcspMode::Disabled,
            ocsp_failure_mode: OcspFailureMode::HardFail,
            ..CertHandle::new("recv-test-cert")
        })
        .expect("cert handle")
}

#[cfg(feature = "interop-relaxed")]
#[cfg(not(feature = "testing"))]
#[test]
fn durable_dedup_receive_push_rejects_non_durable_backend() {
    let session = SessionContext::new("sess-dedup", "partner-a", "strict").expect("session");
    let bus = EventBus::new(16).expect("bus");
    let policy = As4PushPolicyBuilder::new()
        .interop(crate::core::InteropMode::Relaxed)
        .fail_closed_audit_events(false)
        .build()
        .expect("policy");
    let request = As4ReceivePushRequest {
        http_content_type: "application/soap+xml".into(),
        payload: Arc::from(b"<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope'><s:Header><wsse:Security xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'/></s:Header><s:Body/></s:Envelope>".as_slice()),
        receipt_payload: None,
policy,
        authenticated_sender_scope: None,
    };
    let dedup = InMemoryDedupBackend::new(Duration::from_secs(60));

    let err = receive_push_with_dedup_sync(
        &session,
        &bus,
        As4ReceivePushSyncRequest {
            request,
            dedup_backend: &dedup,
        },
    )
    .expect_err("non-durable dedup backend must be rejected");

    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
    assert!(err.message.contains("durable dedup backend"));
}

#[cfg(not(feature = "testing"))]
#[test]
fn wssec_verifier_unsigned_path_requires_signature_when_missing() {
    let session =
        SessionContext::new("sess-registered-pin", "partner-a", "strict").expect("session");
    let policy = As4PushPolicy {
        require_signed_push: true,
        fail_closed_audit_events: false,
        ..As4PushPolicy::default()
    };
    let xml =
        "<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope'><s:Header/></s:Envelope>";
    let doc = Document::parse(xml).expect("document");

    let err = As4WsSecVerifier
        .verify_security(&session, &policy, xml, &doc, "msg-registered", None)
        .expect_err("unsigned strict receive should fail when signature is required");

    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
    assert!(err.message.contains("signature is required"));
}

#[cfg(feature = "interop-relaxed")]
#[tokio::test]
async fn ordered_receive_requires_conversation_id() {
    let creds = test_as4_credentials();
    let session = session_with_trust("sess-ordered-no-conv", "partner-a", &creds);
    let bus = EventBus::new(16).expect("bus");

    // Build a properly signed multipart AS4 message WITHOUT a ConversationId.
    let (send_policy, send_creds) = As4SendPolicyBuilder::new()
        .interop(crate::core::InteropMode::Relaxed)
        .sign(true)
        .encrypt(false)
        .fail_closed_audit_events(false)
        .action("urn:test:no-conv")
        .service("urn:test:svc", "")
        .signing_cert_pem(
            creds
                .signing_cert_pem
                .as_ref()
                .expect("signing cert")
                .clone(),
        )
        .signing_key_pem(creds.signing_key_pem.as_ref().expect("signing key").clone())
        .build()
        .expect("send policy");

    let send_out = crate::as4::send_sync(
        &session,
        &bus,
        crate::as4::As4SendRequest {
            message_id: "ordered-no-conv-id@test".to_string(),
            payload: b"test payload".to_vec(),
            policy: send_policy,
            credentials: Some(send_creds),
        },
    )
    .expect("send");

    let policy = {
        let builder = As4PushPolicyBuilder::new()
            .interop(crate::core::InteropMode::Relaxed)
            .fail_closed_audit_events(false)
            .timestamp_freshness_window(None);
        #[cfg(feature = "testing")]
        let builder = builder.allow_unsigned_push(false); // signature is present — verify it
        builder.build().expect("policy")
    };

    let dedup = DurableTestDedup(InMemoryDedupBackend::new(Duration::from_secs(60)));
    let gate = As4ConversationOrderGate::new(64);
    let dedup_backend: Arc<dyn crate::storage::DedupStorage> = Arc::new(dedup);

    let err = receive_push_ordered(
        &session,
        &bus,
        As4ReceivePushOrderedRequest {
            request: As4ReceivePushRequest {
                http_content_type: send_out.http_content_type,
                payload: send_out.soap_envelope.body,
                receipt_payload: None,
                policy,
                authenticated_sender_scope: None,
            },
            dedup_backend,
            gate: &gate,
        },
    )
    .await
    .expect_err("missing ConversationId must fail");

    assert_eq!(
        err.code,
        ErrorCode::PolicyViolation,
        "unexpected error: {err:?}"
    );
    assert!(
        err.message.contains("ConversationId"),
        "unexpected message: {}",
        err.message
    );
}

struct SlowVerifier {
    _marker: (),
}

impl SlowVerifier {
    fn new() -> Self {
        Self { _marker: () }
    }
}

impl private::Sealed for SlowVerifier {}

impl As4Verifier for SlowVerifier {
    fn verify_security(
        &self,
        _session: &SessionContext,
        _policy: &As4PushPolicy,
        _soap_xml: &str,
        _soap_doc: &Document<'_>,
        message_id: &str,
        _external_reference: Option<(&str, &[u8])>,
    ) -> Result<()> {
        if message_id == "msg-1" {
            std::thread::sleep(Duration::from_millis(120));
        } else {
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }
}

fn ordered_test_payload(message_id: &str, ref_to_message_id: Option<&str>) -> Arc<[u8]> {
    let ref_to_xml = ref_to_message_id
        .map(|value| format!("<eb:RefToMessageId>{value}</eb:RefToMessageId>"))
        .unwrap_or_default();
    Arc::from(
        format!(
            "<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'><s:Header><wsse:Security/><eb:Messaging s:mustUnderstand='true'><eb:UserMessage><eb:MessageInfo><eb:MessageId>{}</eb:MessageId>{}</eb:MessageInfo><eb:CollaborationInfo><eb:Action>urn:test:action</eb:Action><eb:ConversationId>conv-stage-e</eb:ConversationId></eb:CollaborationInfo><eb:PartyInfo><eb:From><eb:PartyId>from-a</eb:PartyId></eb:From><eb:To><eb:PartyId>to-b</eb:PartyId></eb:To></eb:PartyInfo><eb:MessageProperties><eb:Property name='originalSender' value='from-a'/><eb:Property name='finalRecipient' value='to-b'/><eb:Property name='trackingIdentifier' value='{}'/></eb:MessageProperties></eb:UserMessage></eb:Messaging></s:Header><s:Body/></s:Envelope>",
            message_id,
            ref_to_xml,
            message_id,
        )
        .into_bytes(),
    )
}

fn ordered_test_multipart_payload(
    message_id: &str,
    ref_to_message_id: Option<&str>,
) -> (Arc<[u8]>, String) {
    let boundary = format!("asx-ordered-boundary-{message_id}");
    let cid = format!("payload-{message_id}@example.com");
    let ref_to_xml = ref_to_message_id
        .map(|value| format!("<eb:RefToMessageId>{value}</eb:RefToMessageId>"))
        .unwrap_or_default();

    let soap = format!(
        "<S12:Envelope xmlns:S12='http://www.w3.org/2003/05/soap-envelope' xmlns:eb='http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:xop='http://www.w3.org/2004/08/xop/include'><S12:Header><wsse:Security/><eb:Messaging S12:mustUnderstand='true'><eb:UserMessage><eb:MessageInfo><eb:MessageId>{message_id}</eb:MessageId>{ref_to_xml}</eb:MessageInfo><eb:CollaborationInfo><eb:Action>urn:test:action</eb:Action><eb:ConversationId>conv-stage-e</eb:ConversationId></eb:CollaborationInfo><eb:PartyInfo><eb:From><eb:PartyId>from-a</eb:PartyId></eb:From><eb:To><eb:PartyId>to-b</eb:PartyId></eb:To></eb:PartyInfo><eb:MessageProperties><eb:Property name='originalSender' value='from-a'/><eb:Property name='finalRecipient' value='to-b'/><eb:Property name='trackingIdentifier' value='{message_id}'/></eb:MessageProperties></eb:UserMessage></eb:Messaging></S12:Header><S12:Body><xop:Include href='cid:{cid}'/></S12:Body></S12:Envelope>",
    );

    let mut payload = format!(
        "--{boundary}\r\nContent-Type: application/xop+xml; charset=UTF-8; type=\"application/soap+xml\"\r\nContent-ID: <soap-root@example.com>\r\n\r\n{soap}\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\nContent-ID: <{cid}>\r\n\r\n"
    )
    .into_bytes();
    payload.extend_from_slice(b"ordered-payload");
    payload.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    (
        Arc::from(payload),
        format!("multipart/related; boundary={boundary}"),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordered_receive_reserves_arrival_order_but_allows_parallel_heavy_verify() {
    let session =
        SessionContext::new("sess-ordered-stage-e", "partner-a", "strict").expect("session");
    let bus = EventBus::new(16).expect("bus");
    let policy = As4PushPolicyBuilder::new().build().expect("policy");
    let dedup: Arc<dyn crate::storage::DedupStorage> = Arc::new(DurableTestDedup(
        InMemoryDedupBackend::new(Duration::from_secs(60)),
    ));
    let gate = Arc::new(As4ConversationOrderGate::new(64));
    let verifier = Arc::new(SlowVerifier::new());

    let request_a = As4ReceivePushRequest {
        http_content_type: "application/soap+xml".into(),
        payload: ordered_test_payload("msg-1", None),
        receipt_payload: None,
        policy: policy.clone(),
        authenticated_sender_scope: None,
    };
    let request_b = As4ReceivePushRequest {
        http_content_type: "application/soap+xml".into(),
        payload: ordered_test_payload("msg-2", None),
        receipt_payload: None,
        policy,
        authenticated_sender_scope: None,
    };

    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(4);

    let s1 = session.clone();
    let b1 = bus.clone();
    let d1 = dedup.clone();
    let g1 = gate.clone();
    let v1 = verifier.clone();
    let tx1 = tx.clone();
    let t1 = tokio::spawn(async move {
        let _ = ordered_async::receive_push_ordered_with_verifier(
            &s1,
            &b1,
            request_a,
            d1,
            g1.as_ref(),
            v1,
        )
        .await;
        tx1.send("msg-1".to_string()).await.expect("send msg-1");
    });

    tokio::time::sleep(Duration::from_millis(10)).await;

    let s2 = session.clone();
    let b2 = bus.clone();
    let d2 = dedup.clone();
    let g2 = gate.clone();
    let v2 = verifier.clone();
    let tx2 = tx.clone();
    let t2 = tokio::spawn(async move {
        let _ = ordered_async::receive_push_ordered_with_verifier(
            &s2,
            &b2,
            request_b,
            d2,
            g2.as_ref(),
            v2,
        )
        .await;
        tx2.send("msg-2".to_string()).await.expect("send msg-2");
    });

    let first = rx.recv().await.expect("first completion");
    let second = rx.recv().await.expect("second completion");

    t1.await.expect("join t1");
    t2.await.expect("join t2");

    assert_eq!(first, "msg-1");
    assert_eq!(second, "msg-2");
}

#[cfg(feature = "interop-relaxed")]
#[tokio::test]
async fn ordered_receive_rejects_response_before_original_completion() {
    let session =
        SessionContext::new("sess-ordered-ref-to", "partner-a", "strict").expect("session");
    let bus = EventBus::new(16).expect("bus");
    let policy = As4PushPolicyBuilder::new()
        .interop(crate::core::InteropMode::Relaxed)
        .fail_closed_audit_events(false)
        .build()
        .expect("policy");
    let dedup: Arc<dyn crate::storage::DedupStorage> = Arc::new(DurableTestDedup(
        InMemoryDedupBackend::new(Duration::from_secs(60)),
    ));
    let gate = As4ConversationOrderGate::new(64);
    let verifier: Arc<dyn As4Verifier + Send + Sync> = Arc::new(SlowVerifier::new());

    let (early_payload, early_content_type) =
        ordered_test_multipart_payload("msg-response", Some("msg-original"));
    let early_response = As4ReceivePushRequest {
        http_content_type: early_content_type,
        payload: early_payload,
        receipt_payload: None,
        policy: policy.clone(),
        authenticated_sender_scope: None,
    };

    let _err = ordered_async::receive_push_ordered_with_verifier(
        &session,
        &bus,
        early_response,
        Arc::clone(&dedup),
        &gate,
        Arc::clone(&verifier),
    )
    .await
    .expect_err("response before original must fail");

    let (original_payload, original_content_type) =
        ordered_test_multipart_payload("msg-original", None);
    let original = As4ReceivePushRequest {
        http_content_type: original_content_type,
        payload: original_payload,
        receipt_payload: None,
        policy: policy.clone(),
        authenticated_sender_scope: None,
    };
    ordered_async::receive_push_ordered_with_verifier(
        &session,
        &bus,
        original,
        Arc::clone(&dedup),
        &gate,
        Arc::clone(&verifier),
    )
    .await
    .expect("original should pass");

    let (valid_response_payload, valid_response_content_type) =
        ordered_test_multipart_payload("msg-response", Some("msg-original"));
    let valid_response = As4ReceivePushRequest {
        http_content_type: valid_response_content_type,
        payload: valid_response_payload,
        receipt_payload: None,
        policy,
        authenticated_sender_scope: None,
    };
    ordered_async::receive_push_ordered_with_verifier(
        &session,
        &bus,
        valid_response,
        dedup,
        &gate,
        verifier,
    )
    .await
    .expect("response should pass after original completion");
}

#[cfg(feature = "interop-relaxed")]
#[tokio::test]
async fn ordered_fragment_aware_receive_completes_in_conversation_turn_order() {
    let creds = test_as4_credentials();
    let session = session_with_trust("sess-ordered-fragment-aware", "partner-a", &creds);
    let bus = EventBus::new(32).expect("bus");
    let send_policy = As4SendPolicyBuilder::new()
        .interop(crate::core::InteropMode::Relaxed)
        .sign(true)
        .encrypt(false)
        .fail_closed_audit_events(false)
        .action("urn:test:ordered-fragment")
        .conversation_id("conv-ordered-fragment")
        .service("urn:test:svc", "")
        .signing_cert_pem(
            creds
                .signing_cert_pem
                .as_ref()
                .expect("signing cert")
                .clone(),
        )
        .signing_key_pem(creds.signing_key_pem.as_ref().expect("signing key").clone())
        .build()
        .expect("send policy")
        .0;
    let fragments = send_sync_fragmented(
        &session,
        &bus,
        "mid-ordered-fragment".to_string(),
        vec![b'o'; 4096],
        send_policy,
        Some(creds),
        1024,
    )
    .expect("fragment split");

    let request = As4ReceivePushRequest {
        http_content_type: fragments[0].http_content_type.clone(),
        payload: fragments[0].body.clone(),
        receipt_payload: None,
        policy: {
            let builder = As4PushPolicyBuilder::new().interop(crate::core::InteropMode::Relaxed);
            #[cfg(feature = "testing")]
            let builder = builder.allow_unsigned_push(true);
            builder
                .fail_closed_audit_events(false)
                .build()
                .expect("policy")
        },
        authenticated_sender_scope: Some(Arc::from("partner-a")),
    };
    let dedup: Arc<dyn crate::storage::DedupStorage> = Arc::new(DurableTestDedup(
        InMemoryDedupBackend::new(Duration::from_secs(60)),
    ));
    let gate = As4ConversationOrderGate::new(32);
    let fragment_joiner = Arc::new(std::sync::Mutex::new(As4FragmentJoiner::new()));

    let progress = receive_push_ordered_fragment_aware(
        &session,
        &bus,
        As4ReceivePushOrderedFragmentAwareRequest {
            request,
            dedup_backend: dedup,
            gate: &gate,
            fragment_joiner,
        },
    )
    .await
    .expect("ordered fragment-aware receive");

    match progress {
        As4ReceivePushProgress::PendingFragment { .. } => {}
        As4ReceivePushProgress::Complete(_) => {}
        As4ReceivePushProgress::Duplicate { .. } => panic!("unexpected duplicate"),
    }
}

#[cfg(feature = "interop-relaxed")]
#[tokio::test]
async fn async_fragment_aware_receive_accepts_typed_request() {
    let creds = test_as4_credentials();
    let session = session_with_trust("sess-async-fragment-aware", "partner-a", &creds);
    let bus = EventBus::new(32).expect("bus");
    let send_policy = As4SendPolicyBuilder::new()
        .interop(crate::core::InteropMode::Relaxed)
        .sign(true)
        .encrypt(false)
        .fail_closed_audit_events(false)
        .action("urn:test:async-fragment")
        .service("urn:test:svc", "")
        .signing_cert_pem(
            creds
                .signing_cert_pem
                .as_ref()
                .expect("signing cert")
                .clone(),
        )
        .signing_key_pem(creds.signing_key_pem.as_ref().expect("signing key").clone())
        .build()
        .expect("send policy")
        .0;

    let fragments = send_sync_fragmented(
        &session,
        &bus,
        "mid-async-fragment".to_string(),
        vec![b'a'; 3072],
        send_policy,
        Some(creds),
        1024,
    )
    .expect("fragment split");

    let request = As4ReceivePushRequest {
        http_content_type: fragments[0].http_content_type.clone(),
        payload: fragments[0].body.clone(),
        receipt_payload: None,
        policy: {
            let builder = As4PushPolicyBuilder::new().interop(crate::core::InteropMode::Relaxed);
            #[cfg(feature = "testing")]
            let builder = builder.allow_unsigned_push(true);
            builder
                .fail_closed_audit_events(false)
                .build()
                .expect("policy")
        },
        authenticated_sender_scope: Some(Arc::from("partner-a")),
    };

    let dedup: Arc<dyn crate::storage::DedupStorage> = Arc::new(DurableTestDedup(
        InMemoryDedupBackend::new(Duration::from_secs(300)),
    ));
    let fragment_joiner = Arc::new(std::sync::Mutex::new(As4FragmentJoiner::new()));

    let progress = receive_push_with_dedup_async_fragment_aware(
        &session,
        &bus,
        As4ReceivePushAsyncFragmentAwareRequest {
            request,
            dedup_backend: dedup,
            fragment_joiner,
        },
    )
    .await
    .expect("async fragment-aware receive");

    match progress {
        As4ReceivePushProgress::PendingFragment { .. } => {}
        As4ReceivePushProgress::Complete(_) => {}
        As4ReceivePushProgress::Duplicate { .. } => panic!("unexpected duplicate"),
    }
}

#[cfg(feature = "interop-relaxed")]
#[test]
fn fragment_aware_receive_reassembles_and_processes_message() {
    let creds = test_as4_credentials();
    let session = session_with_trust("sess-fragment-aware", "partner-a", &creds);
    let bus = EventBus::new(32).expect("bus");

    let payload = vec![b'f'; 4096];
    let send_payload = payload.clone();
    let (send_policy, _send_credentials) = As4SendPolicyBuilder::new()
        .interop(crate::core::InteropMode::Relaxed)
        .sign(true)
        .encrypt(false)
        .fail_closed_audit_events(false)
        .action("urn:test:fragment-aware")
        .service("urn:test:svc", "")
        .signing_cert_pem(
            creds
                .signing_cert_pem
                .as_ref()
                .expect("signing cert")
                .clone(),
        )
        .signing_key_pem(creds.signing_key_pem.as_ref().expect("signing key").clone())
        .build()
        .expect("send policy");

    let fragments = send_sync_fragmented(
        &session,
        &bus,
        "mid-fragment-aware".to_string(),
        send_payload,
        send_policy,
        Some(creds.clone()),
        1024,
    )
    .expect("fragment split");

    let receive_policy = As4PushPolicyBuilder::new()
        .interop(crate::core::InteropMode::Relaxed)
        .fail_closed_audit_events(false);
    #[cfg(feature = "testing")]
    let receive_policy = receive_policy.allow_unsigned_push(true);
    let receive_policy = receive_policy.build().expect("receive policy");
    let dedup = DurableTestDedup(InMemoryDedupBackend::new(Duration::from_secs(300)));
    let mut joiner = As4FragmentJoiner::new();

    let mut completed = None;
    for fragment in fragments {
        let request = As4ReceivePushRequest {
            http_content_type: fragment.http_content_type,
            payload: fragment.body,
            receipt_payload: None,
            policy: receive_policy.clone(),
            authenticated_sender_scope: Some(Arc::from("partner-a")),
        };

        let progress = receive_push_with_dedup_sync_fragment_aware(
            &session,
            &bus,
            As4ReceivePushSyncFragmentAwareRequest {
                request,
                dedup_backend: &dedup,
                fragment_joiner: &mut joiner,
            },
        )
        .expect("fragment-aware receive");

        if let As4ReceivePushProgress::Complete(out) = progress {
            completed = Some(*out);
        }
    }

    let output = completed.expect("final fragment should complete reassembly");
    assert_eq!(output.payload.as_ref().as_ref(), payload.as_slice());
    assert_eq!(output.user_message.action, "urn:test:fragment-aware");
}

#[cfg(feature = "interop-relaxed")]
#[test]
fn non_fragment_aware_receive_rejects_message_fragment_payload() {
    let creds = test_as4_credentials();
    let session = session_with_trust("sess-fragment-reject", "partner-a", &creds);
    let bus = EventBus::new(16).expect("bus");
    let (send_policy, _send_credentials) = As4SendPolicyBuilder::new()
        .interop(crate::core::InteropMode::Relaxed)
        .sign(true)
        .encrypt(false)
        .fail_closed_audit_events(false)
        .action("urn:test:fragment-reject")
        .service("urn:test:svc", "")
        .signing_cert_pem(
            creds
                .signing_cert_pem
                .as_ref()
                .expect("signing cert")
                .clone(),
        )
        .signing_key_pem(creds.signing_key_pem.as_ref().expect("signing key").clone())
        .build()
        .expect("send policy");

    let fragments = send_sync_fragmented(
        &session,
        &bus,
        "mid-fragment-reject".to_string(),
        vec![b'r'; 2048],
        send_policy,
        Some(creds),
        1024,
    )
    .expect("fragment split");

    let fragment = fragments.into_iter().next().expect("first fragment");
    let request = As4ReceivePushRequest {
        http_content_type: fragment.http_content_type,
        payload: fragment.body,
        receipt_payload: None,
        policy: {
            let builder = As4PushPolicyBuilder::new()
                .interop(crate::core::InteropMode::Relaxed)
                .fail_closed_audit_events(false);
            #[cfg(feature = "testing")]
            let builder = builder.allow_unsigned_push(true);
            builder.build().expect("policy")
        },
        authenticated_sender_scope: Some(Arc::from("partner-a")),
    };
    let dedup = DurableTestDedup(InMemoryDedupBackend::new(Duration::from_secs(60)));

    let err = receive_push_with_dedup_sync(
        &session,
        &bus,
        As4ReceivePushSyncRequest {
            request,
            dedup_backend: &dedup,
        },
    )
    .expect_err("non-fragment-aware receive should reject MessageFragment payload");

    assert_eq!(err.code, ErrorCode::PolicyViolation);
    assert!(err.message.contains("fragment-aware"));
}
