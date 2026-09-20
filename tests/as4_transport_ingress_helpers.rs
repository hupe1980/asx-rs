#![cfg(all(feature = "as4", not(feature = "testing")))]

use asx_rs::as4::As4PushPolicy;
use asx_rs::as4::As4TopologyCoordination;
use asx_rs::core::ErrorCode;
use asx_rs::http::HttpRequest;
use asx_rs::observability::EventBus;
use asx_rs::observability::audit_sink::{
    AuditEvent, AuditSinkDurability, DurableAuditSink, InMemoryAuditSink, ReplayCursor,
};
use asx_rs::presets::{DeploymentTopology, StrictRuntimeBootstrap};
use asx_rs::reliability::{InMemoryDedupBackend, ReconciliationRequest};
use asx_rs::storage::{BoxFuture, DedupStorage, DedupVerdict, ReconciliationStorage};
use asx_rs::transport::ingress::As4IngressReceivePushSyncRequest;
use asx_rs::transport::ingress::as4_ingress_from_http;
use std::sync::Arc;

#[derive(Debug)]
struct DurableTestAuditSink {
    inner: InMemoryAuditSink,
}

impl DurableTestAuditSink {
    fn new() -> Self {
        Self {
            inner: InMemoryAuditSink::new().expect("audit sink"),
        }
    }
}

impl DurableAuditSink for DurableTestAuditSink {
    fn durability(&self) -> AuditSinkDurability {
        AuditSinkDurability::Durable
    }

    fn has_replay_cursor_integrity_protection(&self) -> bool {
        self.inner.has_replay_cursor_integrity_protection()
    }

    fn store_event(&self, event: &AuditEvent) -> asx_rs::core::Result<()> {
        self.inner.store_event(event)
    }

    fn retrieve_events_from(
        &self,
        cursor: &ReplayCursor,
        limit: usize,
    ) -> asx_rs::core::Result<Vec<AuditEvent>> {
        self.inner.retrieve_events_from(cursor, limit)
    }

    fn current_cursor(&self) -> asx_rs::core::Result<ReplayCursor> {
        self.inner.current_cursor()
    }

    fn verify_replay_cursor_integrity(&self, cursor: &ReplayCursor) -> asx_rs::core::Result<()> {
        self.inner.verify_replay_cursor_integrity(cursor)
    }

    fn acknowledge_cursor(&self, cursor: &ReplayCursor) -> asx_rs::core::Result<()> {
        self.inner.acknowledge_cursor(cursor)
    }

    fn clear(&self) -> asx_rs::core::Result<()> {
        self.inner.clear()
    }
}

#[derive(Debug)]
struct DurableClusterSafeDedup;

impl DedupStorage for DurableClusterSafeDedup {
    fn is_durable(&self) -> bool {
        true
    }

    fn cluster_safe(&self) -> bool {
        true
    }

    fn claim<'a>(
        &'a self,
        _idempotency_key: &'a str,
    ) -> BoxFuture<'a, asx_rs::core::Result<DedupVerdict>> {
        Box::pin(async move { Ok(DedupVerdict::Claimed) })
    }

    fn accept<'a>(&'a self, _idempotency_key: &'a str) -> BoxFuture<'a, asx_rs::core::Result<()>> {
        Box::pin(async move { Ok(()) })
    }

    fn abandon<'a>(&'a self, _idempotency_key: &'a str) -> BoxFuture<'a, asx_rs::core::Result<()>> {
        Box::pin(async move { Ok(()) })
    }
}

#[derive(Debug)]
struct ClusterSafeCoordination {
    component: &'static str,
}

impl As4TopologyCoordination for ClusterSafeCoordination {
    fn cluster_safe(&self) -> bool {
        true
    }

    fn topology_component(&self) -> &'static str {
        self.component
    }
}

#[derive(Debug)]
struct DurableClusterSafeReconciliation;

impl ReconciliationStorage for DurableClusterSafeReconciliation {
    fn is_durable(&self) -> bool {
        true
    }

    fn cluster_safe(&self) -> bool {
        true
    }

    fn enqueue(
        &self,
        _request: ReconciliationRequest,
    ) -> BoxFuture<'_, asx_rs::core::Result<bool>> {
        Box::pin(async { Ok(false) })
    }

    fn queued_requests(&self) -> BoxFuture<'_, asx_rs::core::Result<Vec<ReconciliationRequest>>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn resolve<'a>(
        &'a self,
        _idempotency_key: &'a str,
    ) -> BoxFuture<'a, asx_rs::core::Result<bool>> {
        Box::pin(async { Ok(false) })
    }
}

fn strict_runtime_token() -> asx_rs::presets::StrictRuntimeBootstrapToken {
    let event_bus = EventBus::new_regulated(16, Arc::new(DurableTestAuditSink::new()))
        .expect("strict production event bus");
    let pull_store = ClusterSafeCoordination {
        component: "as4_pull_store",
    };
    let conversation_gate = ClusterSafeCoordination {
        component: "as4_conversation_order_gate",
    };
    StrictRuntimeBootstrap::new("transport_as4_ingress_helper")
        .event_bus(&event_bus)
        .reconciliation(&DurableClusterSafeReconciliation)
        .dedup(&DurableClusterSafeDedup)
        .topology(DeploymentTopology::Clustered)
        .as4_pull_store(&pull_store)
        .as4_conversation_gate(&conversation_gate)
        .validate()
        .expect("strict runtime token")
}

fn strict_session() -> asx_rs::core::SessionContext {
    asx_rs::core::SessionContext::new("sess-as4-ingress", "partner-a", "strict").expect("session")
}

fn invalid_as4_ingress() -> asx_rs::transport::ingress::As4HttpIngress {
    as4_ingress_from_http(HttpRequest {
        method: "POST".to_string(),
        uri: "/as4/inbox".to_string(),
        headers: vec![(
            "Content-Type".to_string(),
            "application/soap+xml".to_string(),
        )]
        .into(),
        body: b"not-soap".to_vec().into(),
    })
    .expect("ingress")
}

#[test]
fn as4_transport_helper_without_token_fails_closed_in_strict_mode() {
    let ingress = invalid_as4_ingress();
    let err = ingress
        .receive_push_sync(As4IngressReceivePushSyncRequest {
            session: &strict_session(),
            event_bus: &EventBus::new(16).expect("bus"),
            policy: As4PushPolicy::strict(),
            dedup: std::sync::Arc::new(InMemoryDedupBackend::default()),
            signer_pins: None,
            receipt_payload: None,
        })
        .expect_err("strict helper without token must fail closed");

    assert_eq!(err.code, ErrorCode::PolicyViolation);
    assert!(
        err.message.contains("strict-runtime bootstrap token"),
        "message points at the startup gate: {}",
        err.message
    );
}

#[test]
fn as4_transport_helper_with_token_reaches_protocol_validation() {
    let ingress = invalid_as4_ingress();
    let token = strict_runtime_token();
    let strict_session = token.bind(&strict_session());

    let err = ingress
        .receive_push_sync(As4IngressReceivePushSyncRequest {
            session: &strict_session,
            event_bus: &EventBus::new(16).expect("bus"),
            policy: As4PushPolicy::strict(),
            dedup: std::sync::Arc::new(InMemoryDedupBackend::default()),
            signer_pins: None,
            receipt_payload: Some(b"invalid-receipt".to_vec()),
        })
        .expect_err("invalid payload should fail after token check");

    assert_ne!(err.code, ErrorCode::PolicyViolation);
}
