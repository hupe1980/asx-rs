#![cfg(all(feature = "as4", feature = "testing"))]
use asx::as4::{enqueue_pull_with_reliability, receive_pull_with_reliability};

use asx::as4::{
    As4EnqueuePullWithReliabilityRequest, As4PullEnqueueOutcome, As4PullPolicy,
    As4PullPolicyBuilder, As4PullStore, As4QueuedPullMessage, As4ReceivePullRequest,
    As4ReceivePullWithReliabilityRequest,
};
use asx::core::SessionContext;
use asx::observability::EventBus;
use asx::reliability::{
    DeliveryOutcome, InMemoryDedupBackend, InMemoryReconciliationHook, ReconciliationReason,
};
use asx::storage::{DedupStorage, ReconciliationStorage as _};
use std::sync::Arc;
use tokio::sync::Barrier;
use tokio::time::{Duration, timeout};

const PULL_FLOW_BOUNDARY: &str = "asx-pull-flow-boundary";

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("tests/fixtures/{name}");
    std::fs::read(path).expect("fixture")
}

fn multipart_pull_fixture(name: &str) -> Vec<u8> {
    let payload_cid = "pull-flow-body@example.com";
    let mut soap = String::from_utf8(fixture(name)).expect("utf8 fixture");

    if !soap.contains("xmlns:xop=\"http://www.w3.org/2004/08/xop/include\"") {
        soap = soap.replacen(
            "<S12:Envelope ",
            "<S12:Envelope xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" ",
            1,
        );
    }
    if soap.contains("<S12:Body/>") {
        soap = soap.replacen(
            "<S12:Body/>",
            &format!("<S12:Body><xop:Include href=\"cid:{payload_cid}\"/></S12:Body>"),
            1,
        );
    }

    // Keep pull-flow fixtures aligned with strict AS4 parsing rules.
    if !soap.contains("<eb:MessageProperties>") {
        soap = soap.replacen(
            "</eb:CollaborationInfo>",
            "</eb:CollaborationInfo><eb:MessageProperties><eb:Property name=\"originalSender\" value=\"sender-a\"/><eb:Property name=\"finalRecipient\" value=\"receiver-b\"/><eb:Property name=\"trackingIdentifier\" value=\"msg-pull-1\"/></eb:MessageProperties>",
            1,
        );
    }

    let mut out = Vec::new();
    out.extend_from_slice(format!("--{PULL_FLOW_BOUNDARY}\r\n").as_bytes());
    out.extend_from_slice(
        b"Content-Type: application/xop+xml; charset=UTF-8; type=\"application/soap+xml\"\r\n",
    );
    out.extend_from_slice(b"Content-ID: <soap-root@example.com>\r\n\r\n");
    out.extend_from_slice(soap.as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(format!("--{PULL_FLOW_BOUNDARY}\r\n").as_bytes());
    out.extend_from_slice(
        format!("Content-Type: application/octet-stream\r\nContent-ID: <{payload_cid}>\r\n\r\n")
            .as_bytes(),
    );
    out.extend_from_slice(b"pull-flow-detached-payload\r\n");
    out.extend_from_slice(format!("--{PULL_FLOW_BOUNDARY}--\r\n").as_bytes());
    out
}

fn session() -> SessionContext {
    SessionContext::new("as4-pull-session-1", "partner-a", "strict").expect("session")
}

fn reliability() -> (InMemoryReconciliationHook, Arc<dyn DedupStorage>) {
    (
        InMemoryReconciliationHook::default(),
        Arc::new(InMemoryDedupBackend::default()),
    )
}

fn pull_policy(mpc: &str) -> As4PullPolicy {
    As4PullPolicyBuilder::new()
        .mpc(mpc)
        .allow_unsigned_push(true)
        .fail_closed_audit_events(false)
        .build()
        .expect("policy")
}

#[tokio::test(flavor = "current_thread")]
async fn as4_pull_empty_then_delayed_retrieval_is_correlated() {
    let bus = EventBus::new(32).expect("bus");
    let _events = bus.subscribe_scoped_events();
    let store = As4PullStore::new();
    let s = session();

    let (hook, dedup) = reliability();
    let first = receive_pull_with_reliability(
        &s,
        &bus,
        As4ReceivePullWithReliabilityRequest {
            store: &store,
            request: As4ReceivePullRequest {
                pull_message_id: "pull-1".to_string(),
                policy: pull_policy("urn:mpc:priority"),
                receipt_payload: None,
                authorization_info: None,
            },
            reconciliation_hook: &hook,
            dedup_backend: Arc::clone(&dedup),
        },
    )
    .await
    .expect("empty pull request should succeed with warning semantics");

    assert_eq!(first.outcome, DeliveryOutcome::Indeterminate);
    assert!(first.retry.should_retry);
    assert!(first.pulled.is_none());

    let enqueue = enqueue_pull_with_reliability(
        &s,
        &bus,
        As4EnqueuePullWithReliabilityRequest {
            store: &store,
            mpc: "urn:mpc:priority".to_string(),
            message: As4QueuedPullMessage {
                message_id: Arc::from("msg-pull-1"),
                payload: Arc::from(multipart_pull_fixture("as4_pull_user_message.golden")),
                http_content_type: Arc::from("multipart/related; boundary=asx-pull-flow-boundary"),
            },
            reconciliation_hook: &hook,
            fail_closed_audit_events: false,
        },
    )
    .await
    .expect("enqueue pulled message");
    assert_eq!(enqueue, As4PullEnqueueOutcome::Enqueued);

    let second = receive_pull_with_reliability(
        &s,
        &bus,
        As4ReceivePullWithReliabilityRequest {
            store: &store,
            request: As4ReceivePullRequest {
                pull_message_id: "pull-2".to_string(),
                policy: pull_policy("urn:mpc:priority"),
                receipt_payload: None,
                authorization_info: None,
            },
            reconciliation_hook: &hook,
            dedup_backend: Arc::clone(&dedup),
        },
    )
    .await
    .expect("delayed pull request");

    assert_eq!(second.outcome, DeliveryOutcome::SuccessConfirmed);
    assert!(!second.retry.should_retry);
    assert_eq!(second.correlation_message_id.as_deref(), Some("msg-pull-1"));
    assert_eq!(
        second
            .pulled
            .as_ref()
            .expect("pulled output")
            .user_message
            .mpc
            .as_deref(),
        Some("urn:mpc:priority")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn as4_pull_duplicate_retrieval_replays_same_message() {
    let bus = EventBus::new(32).expect("bus");
    let _events = bus.subscribe_scoped_events();
    let store = As4PullStore::new();
    let s = session();

    let (hook, dedup) = reliability();

    let enqueue = enqueue_pull_with_reliability(
        &s,
        &bus,
        As4EnqueuePullWithReliabilityRequest {
            store: &store,
            mpc: "urn:mpc:priority".to_string(),
            message: As4QueuedPullMessage {
                message_id: Arc::from("msg-pull-1"),
                payload: Arc::from(multipart_pull_fixture("as4_pull_user_message.golden")),
                http_content_type: Arc::from("multipart/related; boundary=asx-pull-flow-boundary"),
            },
            reconciliation_hook: &hook,
            fail_closed_audit_events: false,
        },
    )
    .await
    .expect("enqueue pulled message");
    assert_eq!(enqueue, As4PullEnqueueOutcome::Enqueued);

    let first = receive_pull_with_reliability(
        &s,
        &bus,
        As4ReceivePullWithReliabilityRequest {
            store: &store,
            request: As4ReceivePullRequest {
                pull_message_id: "pull-dup-1".to_string(),
                policy: pull_policy("urn:mpc:priority"),
                receipt_payload: None,
                authorization_info: None,
            },
            reconciliation_hook: &hook,
            dedup_backend: Arc::clone(&dedup),
        },
    )
    .await
    .expect("first pull");

    let second = receive_pull_with_reliability(
        &s,
        &bus,
        As4ReceivePullWithReliabilityRequest {
            store: &store,
            request: As4ReceivePullRequest {
                pull_message_id: "pull-dup-1".to_string(),
                policy: pull_policy("urn:mpc:priority"),
                receipt_payload: None,
                authorization_info: None,
            },
            reconciliation_hook: &hook,
            dedup_backend: Arc::clone(&dedup),
        },
    )
    .await
    .expect("duplicate pull");

    assert!(!first.duplicate_retrieval);
    assert!(second.duplicate_retrieval);
    assert_eq!(first.outcome, DeliveryOutcome::SuccessConfirmed);
    assert_eq!(second.outcome, DeliveryOutcome::SuccessConfirmed);
    assert_eq!(
        first.correlation_message_id, second.correlation_message_id,
        "duplicate pull should correlate to original pulled user message"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn as4_pull_timing_race_delivers_to_only_one_request() {
    let bus = Arc::new(EventBus::new(64).expect("bus"));
    let _events = bus.subscribe_scoped_events();
    let store = Arc::new(As4PullStore::new());
    let s = Arc::new(session());

    let (hook, _dedup) = reliability();
    let enqueue = enqueue_pull_with_reliability(
        &s,
        &bus,
        As4EnqueuePullWithReliabilityRequest {
            store: &store,
            mpc: "urn:mpc:priority".to_string(),
            message: As4QueuedPullMessage {
                message_id: Arc::from("msg-pull-1"),
                payload: Arc::from(multipart_pull_fixture("as4_pull_user_message.golden")),
                http_content_type: Arc::from("multipart/related; boundary=asx-pull-flow-boundary"),
            },
            reconciliation_hook: &hook,
            fail_closed_audit_events: false,
        },
    )
    .await
    .expect("enqueue pulled message");
    assert_eq!(enqueue, As4PullEnqueueOutcome::Enqueued);

    let barrier = Arc::new(Barrier::new(2));

    let worker = |pull_message_id: &'static str,
                  barrier: Arc<Barrier>,
                  bus: Arc<EventBus>,
                  store: Arc<As4PullStore>,
                  session: Arc<SessionContext>| {
        tokio::spawn(async move {
            barrier.wait().await;
            let (hook, dedup) = reliability();
            receive_pull_with_reliability(
                &session,
                &bus,
                As4ReceivePullWithReliabilityRequest {
                    store: &store,
                    request: As4ReceivePullRequest {
                        pull_message_id: pull_message_id.to_string(),
                        policy: pull_policy("urn:mpc:priority"),
                        receipt_payload: None,
                        authorization_info: None,
                    },
                    reconciliation_hook: &hook,
                    dedup_backend: Arc::clone(&dedup),
                },
            )
            .await
            .expect("pull race call")
        })
    };

    let h1 = worker(
        "pull-race-1",
        Arc::clone(&barrier),
        Arc::clone(&bus),
        Arc::clone(&store),
        Arc::clone(&s),
    );
    let h2 = worker("pull-race-2", barrier, bus, store, s);

    let r1 = h1.await.expect("join 1");
    let r2 = h2.await.expect("join 2");

    let success_count = [r1.outcome, r2.outcome]
        .iter()
        .filter(|outcome| **outcome == DeliveryOutcome::SuccessConfirmed)
        .count();
    let indeterminate_count = [r1.outcome, r2.outcome]
        .iter()
        .filter(|outcome| **outcome == DeliveryOutcome::Indeterminate)
        .count();

    assert_eq!(
        success_count, 1,
        "only one racing pull should get the message"
    );
    assert_eq!(
        indeterminate_count, 1,
        "the other racing pull should observe empty-channel semantics"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn as4_pull_indeterminate_reconciliation_is_not_duplicated_for_same_pull_request() {
    let bus = EventBus::new(32).expect("bus");
    let _events = bus.subscribe_scoped_events();
    let store = As4PullStore::new();
    let s = session();
    let (hook, dedup) = reliability();

    let first = receive_pull_with_reliability(
        &s,
        &bus,
        As4ReceivePullWithReliabilityRequest {
            store: &store,
            request: As4ReceivePullRequest {
                pull_message_id: "pull-empty-1".to_string(),
                policy: pull_policy("urn:mpc:priority"),
                receipt_payload: None,
                authorization_info: None,
            },
            reconciliation_hook: &hook,
            dedup_backend: Arc::clone(&dedup),
        },
    )
    .await
    .expect("first empty pull");

    let second = receive_pull_with_reliability(
        &s,
        &bus,
        As4ReceivePullWithReliabilityRequest {
            store: &store,
            request: As4ReceivePullRequest {
                pull_message_id: "pull-empty-1".to_string(),
                policy: pull_policy("urn:mpc:priority"),
                receipt_payload: None,
                authorization_info: None,
            },
            reconciliation_hook: &hook,
            dedup_backend: Arc::clone(&dedup),
        },
    )
    .await
    .expect("second empty pull");

    assert_eq!(first.outcome, DeliveryOutcome::Indeterminate);
    assert_eq!(second.outcome, DeliveryOutcome::Indeterminate);

    let queued = hook.queued_requests().expect("queued requests");
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].reason, ReconciliationReason::Indeterminate);
}

#[tokio::test(flavor = "current_thread")]
async fn as4_pull_dedup_is_correct_under_parallel_duplicate_requests() {
    let bus = Arc::new(EventBus::new(64).expect("bus"));
    let _events = bus.subscribe_scoped_events();
    let mut rx = bus
        .subscribe_session_events("as4-pull-session-1")
        .expect("subscribe");
    let store = Arc::new(As4PullStore::new());
    let s = Arc::new(session());
    let dedup = Arc::new(InMemoryDedupBackend::default());
    let reconcile = Arc::new(InMemoryReconciliationHook::default());
    let barrier = Arc::new(Barrier::new(2));

    let worker = |barrier: Arc<Barrier>,
                  bus: Arc<EventBus>,
                  store: Arc<As4PullStore>,
                  session: Arc<SessionContext>,
                  dedup: Arc<InMemoryDedupBackend>,
                  reconcile: Arc<InMemoryReconciliationHook>| {
        tokio::spawn(async move {
            barrier.wait().await;
            receive_pull_with_reliability(
                &session,
                &bus,
                As4ReceivePullWithReliabilityRequest {
                    store: &store,
                    request: As4ReceivePullRequest {
                        pull_message_id: "pull-parallel-dup".to_string(),
                        policy: pull_policy("urn:mpc:priority"),
                        receipt_payload: None,
                        authorization_info: None,
                    },
                    reconciliation_hook: &*reconcile,
                    dedup_backend: Arc::clone(&dedup) as Arc<dyn DedupStorage>,
                },
            )
            .await
            .expect("parallel pull")
        })
    };

    let h1 = worker(
        Arc::clone(&barrier),
        Arc::clone(&bus),
        Arc::clone(&store),
        Arc::clone(&s),
        Arc::clone(&dedup),
        Arc::clone(&reconcile),
    );
    let h2 = worker(barrier, bus.clone(), store, s, dedup, reconcile);

    let _ = h1.await.expect("join 1");
    let _ = h2.await.expect("join 2");

    let mut duplicate_seen = false;
    for _ in 0..8 {
        if let Ok(Some(evt)) = timeout(Duration::from_millis(200), rx.recv()).await
            && let asx::observability::AsxEvent::DuplicateDetected {
                message_id,
                ingress,
                ..
            } = evt.as_ref()
            && message_id.as_ref() == "pull-parallel-dup"
            && *ingress == asx::observability::AsxIngressStage::As4ReceivePull
        {
            duplicate_seen = true;
            break;
        }
    }

    assert!(duplicate_seen);
}
