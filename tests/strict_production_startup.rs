#![cfg(not(feature = "testing"))]

use std::sync::Arc;

#[cfg(feature = "as4")]
use asx_rs::as4::{As4ConversationOrderGate, As4PullStore};
use asx_rs::core::{ErrorCode, Result};
use asx_rs::observability::audit_sink::{
    AuditEvent, AuditSinkDurability, DurableAuditSink, ReplayCursor,
};
use asx_rs::observability::{BackpressurePolicy, EventBus, EventEmissionMode};
#[cfg(feature = "as4")]
use asx_rs::presets::DeploymentTopology;
use asx_rs::presets::StrictRuntimeBootstrap;
use asx_rs::storage::{BoxFuture, DedupStorage, DedupVerdict, ReconciliationStorage};

#[derive(Debug)]
struct DurableTestAuditSink;

impl DurableAuditSink for DurableTestAuditSink {
    fn durability(&self) -> AuditSinkDurability {
        AuditSinkDurability::Durable
    }

    fn has_replay_cursor_integrity_protection(&self) -> bool {
        true
    }

    fn store_event(&self, _event: &AuditEvent) -> Result<()> {
        Ok(())
    }

    fn retrieve_events_from(
        &self,
        _cursor: &ReplayCursor,
        _limit: usize,
    ) -> Result<Vec<AuditEvent>> {
        Ok(Vec::new())
    }

    fn current_cursor(&self) -> Result<ReplayCursor> {
        Ok(ReplayCursor {
            last_event_id: "0".to_string(),
            position: 0,
            last_timestamp: 0,
            integrity_tag_b64: String::new(),
        })
    }

    fn acknowledge_cursor(&self, _cursor: &ReplayCursor) -> Result<()> {
        Ok(())
    }

    fn clear(&self) -> Result<()> {
        Ok(())
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
        _request: asx_rs::reliability::ReconciliationRequest,
    ) -> BoxFuture<'_, Result<bool>> {
        Box::pin(async { Ok(false) })
    }

    fn queued_requests(
        &self,
    ) -> BoxFuture<'_, Result<Vec<asx_rs::reliability::ReconciliationRequest>>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn resolve<'a>(&'a self, _idempotency_key: &'a str) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async { Ok(false) })
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
struct NonDurableReconciliation;

impl ReconciliationStorage for NonDurableReconciliation {
    fn is_durable(&self) -> bool {
        false
    }

    fn enqueue(
        &self,
        _request: asx_rs::reliability::ReconciliationRequest,
    ) -> BoxFuture<'_, Result<bool>> {
        Box::pin(async { Ok(false) })
    }

    fn queued_requests(
        &self,
    ) -> BoxFuture<'_, Result<Vec<asx_rs::reliability::ReconciliationRequest>>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn resolve<'a>(&'a self, _idempotency_key: &'a str) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async { Ok(false) })
    }
}

#[derive(Debug)]
struct NonClusterSafeDedup;

impl DedupStorage for NonClusterSafeDedup {
    fn is_durable(&self) -> bool {
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

fn regulated_bus() -> EventBus {
    EventBus::new_regulated(16, Arc::new(DurableTestAuditSink)).expect("bus")
}

#[test]
fn strict_startup_validation_accepts_regulated_runtime_wiring() {
    let bus = regulated_bus();

    StrictRuntimeBootstrap::new("strict_startup_integration")
        .event_bus(&bus)
        .reconciliation(&DurableClusterSafeReconciliation)
        .dedup(&DurableClusterSafeDedup)
        .validate()
        .expect("regulated wiring must validate");
}

#[test]
fn strict_startup_validation_rejects_best_effort_event_bus() {
    let bus = EventBus::builder()
        .capacity(16)
        .backpressure(BackpressurePolicy::default())
        .emission_mode(EventEmissionMode::BestEffort)
        .build()
        .expect("bus");

    let err = StrictRuntimeBootstrap::new("strict_startup_integration")
        .event_bus(&bus)
        .reconciliation(&DurableClusterSafeReconciliation)
        .dedup(&DurableClusterSafeDedup)
        .validate()
        .expect_err("best-effort event bus must be rejected in strict startup validation");

    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
    assert!(err.message.contains("strict event emission mode"));
}

/// `StrictWithAuditFallback` requires a production-durable sink at construction
/// and persists to it when no subscriber is live, so it *is* a strict mode.
/// The gate used to demand `StrictTransactional` exactly, which made the mode
/// its own documentation recommends unusable in a regulated deployment.
#[test]
fn strict_startup_validation_accepts_audit_fallback_mode() {
    let bus = EventBus::builder()
        .capacity(16)
        .audit_sink(Arc::new(DurableTestAuditSink))
        .emission_mode(EventEmissionMode::StrictWithAuditFallback)
        .build()
        .expect("bus");

    StrictRuntimeBootstrap::new("strict_startup_integration")
        .event_bus(&bus)
        .reconciliation(&DurableClusterSafeReconciliation)
        .dedup(&DurableClusterSafeDedup)
        .validate()
        .expect("audit-fallback strict mode must pass the startup gate");
}

#[test]
fn strict_startup_validation_rejects_non_durable_reconciliation_backend() {
    let bus = regulated_bus();

    let err = StrictRuntimeBootstrap::new("strict_startup_integration")
        .event_bus(&bus)
        .reconciliation(&NonDurableReconciliation)
        .dedup(&DurableClusterSafeDedup)
        .validate()
        .expect_err("non-durable reconciliation backend must fail closed");

    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
    assert!(err.message.contains("durable reconciliation backend"));
}

#[test]
fn strict_startup_validation_rejects_non_cluster_safe_dedup_backend() {
    let bus = regulated_bus();

    let err = StrictRuntimeBootstrap::new("strict_startup_integration")
        .event_bus(&bus)
        .reconciliation(&DurableClusterSafeReconciliation)
        .dedup(&NonClusterSafeDedup)
        .validate()
        .expect_err("non-cluster-safe dedup backend must fail closed");

    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
    assert!(err.message.contains("cluster-safe dedup backend"));
}

/// Every component is mandatory: forgetting one must be an error, not a silently
/// narrower check.
#[test]
fn strict_startup_validation_requires_every_component() {
    let bus = regulated_bus();

    let err = StrictRuntimeBootstrap::new("strict_startup_integration")
        .event_bus(&bus)
        .dedup(&DurableClusterSafeDedup)
        .validate()
        .expect_err("a missing reconciliation backend must be an error");

    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert!(err.message.contains("reconciliation"));
}

#[cfg(feature = "as4")]
#[test]
fn strict_startup_validation_as4_topology_allows_single_node_process_local_components() {
    let bus = regulated_bus();
    let store = As4PullStore::new();
    let gate = As4ConversationOrderGate::new(16);

    let token = StrictRuntimeBootstrap::new("strict_startup_integration")
        .event_bus(&bus)
        .reconciliation(&DurableClusterSafeReconciliation)
        .dedup(&DurableClusterSafeDedup)
        .topology(DeploymentTopology::SingleNode)
        .as4_pull_store(&store)
        .as4_conversation_gate(&gate)
        .validate()
        .expect("single node may use process-local components");

    assert_eq!(token.as4_topology(), Some(DeploymentTopology::SingleNode));
}

#[cfg(feature = "as4")]
#[test]
fn strict_startup_validation_as4_topology_rejects_clustered_process_local_components() {
    let bus = regulated_bus();
    let store = As4PullStore::new();
    let gate = As4ConversationOrderGate::new(16);

    let err = StrictRuntimeBootstrap::new("strict_startup_integration")
        .event_bus(&bus)
        .reconciliation(&DurableClusterSafeReconciliation)
        .dedup(&DurableClusterSafeDedup)
        .topology(DeploymentTopology::Clustered)
        .as4_pull_store(&store)
        .as4_conversation_gate(&gate)
        .validate()
        .expect_err("clustered startup must reject process-local AS4 pull/ordering components");

    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
    assert!(
        err.message.contains("pull-store") || err.message.contains("conversation-ordering"),
        "message names the offending component: {}",
        err.message
    );
}

/// A clustered deployment that supplies nothing at all must not slip through.
#[cfg(feature = "as4")]
#[test]
fn strict_startup_validation_clustered_without_coordination_is_rejected() {
    let bus = regulated_bus();

    let err = StrictRuntimeBootstrap::new("strict_startup_integration")
        .event_bus(&bus)
        .reconciliation(&DurableClusterSafeReconciliation)
        .dedup(&DurableClusterSafeDedup)
        .topology(DeploymentTopology::Clustered)
        .validate()
        .expect_err("clustered startup with no coordination backends must fail closed");

    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
    assert!(err.message.contains("pull-store"));
}
