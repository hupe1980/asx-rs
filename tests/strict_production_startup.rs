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
use asx_rs::presets::{DeploymentTopology, validate_strict_production_as4_topology_readiness};
use asx_rs::presets::{strict_production_event_bus, validate_strict_production_startup_readiness};
use asx_rs::storage::{BoxFuture, DedupStorage, ReconciliationStorage};

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

struct DurableClusterSafeReconciliation;

impl ReconciliationStorage for DurableClusterSafeReconciliation {
    fn is_durable(&self) -> bool {
        true
    }

    fn cluster_safe(&self) -> bool {
        true
    }

    fn enqueue(&self, _request: asx_rs::reliability::ReconciliationRequest) -> Result<bool> {
        Ok(false)
    }

    fn queued_requests(&self) -> Result<Vec<asx_rs::reliability::ReconciliationRequest>> {
        Ok(Vec::new())
    }

    fn resolve(&self, _idempotency_key: &str) -> Result<bool> {
        Ok(false)
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

    fn first_seen<'a>(
        &'a self,
        _idempotency_key: &'a str,
    ) -> BoxFuture<'a, crate::core::Result<bool>> {
        Box::pin(async move { Ok(true) })
    }
}

struct NonDurableReconciliation;

impl ReconciliationStorage for NonDurableReconciliation {
    fn is_durable(&self) -> bool {
        false
    }

    fn enqueue(&self, _request: asx_rs::reliability::ReconciliationRequest) -> Result<bool> {
        Ok(false)
    }

    fn queued_requests(&self) -> Result<Vec<asx_rs::reliability::ReconciliationRequest>> {
        Ok(Vec::new())
    }

    fn resolve(&self, _idempotency_key: &str) -> Result<bool> {
        Ok(false)
    }
}

struct NonClusterSafeDedup;

impl DedupStorage for NonClusterSafeDedup {
    fn is_durable(&self) -> bool {
        true
    }

    fn first_seen<'a>(
        &'a self,
        _idempotency_key: &'a str,
    ) -> BoxFuture<'a, crate::core::Result<bool>> {
        Box::pin(async move { Ok(true) })
    }
}

#[test]
fn strict_startup_validation_accepts_regulated_runtime_wiring() {
    let bus = strict_production_event_bus(16, Arc::new(DurableTestAuditSink)).expect("bus");

    let result = validate_strict_production_startup_readiness(
        "strict_startup_integration",
        &bus,
        &DurableClusterSafeReconciliation,
        &DurableClusterSafeDedup,
    );

    assert!(result.is_ok());
}

#[test]
fn strict_startup_validation_rejects_non_transactional_event_bus() {
    let bus = EventBus::new_with_config_and_mode(
        16,
        None,
        BackpressurePolicy::default(),
        EventEmissionMode::BestEffort,
    )
    .expect("bus");

    let err = validate_strict_production_startup_readiness(
        "strict_startup_integration",
        &bus,
        &DurableClusterSafeReconciliation,
        &DurableClusterSafeDedup,
    )
    .expect_err("best-effort event bus must be rejected in strict startup validation");

    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
    assert!(err.message.contains("StrictTransactional"));
}

#[test]
fn strict_startup_validation_rejects_non_durable_reconciliation_backend() {
    let bus = strict_production_event_bus(16, Arc::new(DurableTestAuditSink)).expect("bus");

    let err = validate_strict_production_startup_readiness(
        "strict_startup_integration",
        &bus,
        &NonDurableReconciliation,
        &DurableClusterSafeDedup,
    )
    .expect_err("non-durable reconciliation backend must fail closed");

    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
    assert!(err.message.contains("durable reconciliation backend"));
}

#[test]
fn strict_startup_validation_rejects_non_cluster_safe_dedup_backend() {
    let bus = strict_production_event_bus(16, Arc::new(DurableTestAuditSink)).expect("bus");

    let err = validate_strict_production_startup_readiness(
        "strict_startup_integration",
        &bus,
        &DurableClusterSafeReconciliation,
        &NonClusterSafeDedup,
    )
    .expect_err("non-cluster-safe dedup backend must fail closed");

    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
    assert!(err.message.contains("cluster-safe dedup backend"));
}

#[cfg(feature = "as4")]
#[test]
fn strict_startup_validation_as4_topology_allows_single_node_process_local_components() {
    let store = As4PullStore::new();
    let gate = As4ConversationOrderGate::new(16);

    let result = validate_strict_production_as4_topology_readiness(
        "strict_startup_integration",
        DeploymentTopology::SingleNode,
        Some(&store),
        Some(&gate),
    );

    assert!(result.is_ok());
}

#[cfg(feature = "as4")]
#[test]
fn strict_startup_validation_as4_topology_rejects_clustered_process_local_components() {
    let store = As4PullStore::new();
    let gate = As4ConversationOrderGate::new(16);

    let err = validate_strict_production_as4_topology_readiness(
        "strict_startup_integration",
        DeploymentTopology::Clustered,
        Some(&store),
        Some(&gate),
    )
    .expect_err("clustered startup must reject process-local AS4 pull/ordering components");

    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
    assert!(
        err.message.contains("cluster-safe AS4 pull-store")
            || err
                .message
                .contains("distributed AS4 conversation ordering coordination")
    );
}
