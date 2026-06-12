#![cfg(all(feature = "as4", not(feature = "testing")))]

use asx::as4::As4PushPolicy;
use asx::as4::As4TopologyCoordination;
use asx::core::ErrorCode;
use asx::http::HttpRequest;
use asx::observability::EventBus;
use asx::observability::audit_sink::{
    AuditEvent, AuditSinkDurability, DurableAuditSink, InMemoryAuditSink, ReplayCursor,
};
use asx::presets::{
    DeploymentTopology, issue_strict_runtime_bootstrap_token_with_as4_topology,
    strict_production_event_bus,
};
use asx::reliability::{InMemoryDedupBackend, ReconciliationRequest};
use asx::storage::{DedupStorage, ReconciliationStorage};
use asx::transport::ingress::As4IngressReceivePushSyncRequest;
use asx::transport::ingress::as4_ingress_from_http;
use std::sync::Arc;

struct DurableTestAuditSink {
    inner: InMemoryAuditSink,
}

impl DurableTestAuditSink {
    fn new() -> Self {
        Self {
            inner: InMemoryAuditSink::new(),
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

    fn store_event(&self, event: &AuditEvent) -> asx::core::Result<()> {
        self.inner.store_event(event)
    }

    fn retrieve_events_from(
        &self,
        cursor: &ReplayCursor,
        limit: usize,
    ) -> asx::core::Result<Vec<AuditEvent>> {
        self.inner.retrieve_events_from(cursor, limit)
    }

    fn current_cursor(&self) -> asx::core::Result<ReplayCursor> {
        self.inner.current_cursor()
    }

    fn verify_replay_cursor_integrity(&self, cursor: &ReplayCursor) -> asx::core::Result<()> {
        self.inner.verify_replay_cursor_integrity(cursor)
    }

    fn acknowledge_cursor(&self, cursor: &ReplayCursor) -> asx::core::Result<()> {
        self.inner.acknowledge_cursor(cursor)
    }

    fn clear(&self) -> asx::core::Result<()> {
        self.inner.clear()
    }
}

struct DurableClusterSafeDedup;

impl DedupStorage for DurableClusterSafeDedup {
    fn is_durable(&self) -> bool {
        true
    }

    fn cluster_safe(&self) -> bool {
        true
    }

    fn first_seen(&self, _idempotency_key: &str) -> asx::core::Result<bool> {
        Ok(true)
    }
}

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

struct DurableClusterSafeReconciliation;

impl ReconciliationStorage for DurableClusterSafeReconciliation {
    fn is_durable(&self) -> bool {
        true
    }

    fn cluster_safe(&self) -> bool {
        true
    }

    fn enqueue(&self, _request: ReconciliationRequest) -> asx::core::Result<bool> {
        Ok(false)
    }

    fn queued_requests(&self) -> asx::core::Result<Vec<ReconciliationRequest>> {
        Ok(Vec::new())
    }

    fn resolve(&self, _idempotency_key: &str) -> asx::core::Result<bool> {
        Ok(false)
    }
}

fn strict_runtime_token() -> asx::presets::StrictRuntimeBootstrapToken {
    let event_bus = strict_production_event_bus(16, Arc::new(DurableTestAuditSink::new()))
        .expect("strict production event bus");
    let pull_store = ClusterSafeCoordination {
        component: "as4_pull_store",
    };
    let conversation_gate = ClusterSafeCoordination {
        component: "as4_conversation_order_gate",
    };
    issue_strict_runtime_bootstrap_token_with_as4_topology(
        "transport_as4_ingress_helper",
        &event_bus,
        &DurableClusterSafeReconciliation,
        &DurableClusterSafeDedup,
        DeploymentTopology::Clustered,
        Some(&pull_store),
        Some(&conversation_gate),
    )
    .expect("strict runtime token")
}

fn strict_session() -> asx::core::SessionContext {
    asx::core::SessionContext::new("sess-as4-ingress", "partner-a", "strict").expect("session")
}

fn invalid_as4_ingress() -> asx::transport::ingress::As4HttpIngress {
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
        .receive_push_with_dedup_sync(As4IngressReceivePushSyncRequest {
            session: &strict_session(),
            event_bus: &EventBus::new(16).expect("bus"),
            policy: As4PushPolicy::strict(),
            dedup_backend: &InMemoryDedupBackend::default(),
            receipt_payload: None,
        })
        .expect_err("strict helper without token must fail closed");

    assert_eq!(err.code, ErrorCode::PolicyViolation);
    assert!(
        err.message
            .contains("strict-runtime bootstrap token binding")
    );
}

#[test]
fn as4_transport_helper_with_token_reaches_protocol_validation() {
    let ingress = invalid_as4_ingress();
    let token = strict_runtime_token();
    let strict_session = asx::presets::session_with_strict_runtime_bootstrap_token(
        "transport_as4_ingress_helpers",
        &token,
        &strict_session(),
    )
    .expect("strict session");

    let err = ingress
        .receive_push_with_dedup_sync(As4IngressReceivePushSyncRequest {
            session: &strict_session,
            event_bus: &EventBus::new(16).expect("bus"),
            policy: As4PushPolicy::strict(),
            dedup_backend: &InMemoryDedupBackend::default(),
            receipt_payload: Some(b"invalid-receipt".to_vec()),
        })
        .expect_err("invalid payload should fail after token check");

    assert_ne!(err.code, ErrorCode::PolicyViolation);
}
