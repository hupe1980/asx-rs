use std::any::type_name_of_val;
use std::sync::Arc;
use std::time::SystemTime;

#[cfg(feature = "as4")]
use crate::as4::As4TopologyCoordination;
use crate::core::SessionContext;
use crate::core::{AsxError, ErrorCode, ErrorContext, InteropMode, Result};
use crate::observability::audit_sink::DurableAuditSink;
use crate::observability::{EventBus, EventEmissionMode};
use crate::storage::{DedupStorage, ReconciliationStorage};

/// Runtime deployment topology used by strict-production startup validators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeploymentTopology {
    /// Single process / single replica deployment.
    SingleNode,
    /// Multi-replica deployment where cross-node coordination is required.
    Clustered,
}

/// Typed proof that strict-production startup validation succeeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictRuntimeBootstrapToken {
    issued_at: SystemTime,
    stage: &'static str,
    as4_topology: Option<DeploymentTopology>,
}

impl StrictRuntimeBootstrapToken {
    /// Stage used when the token was minted.
    pub fn stage(&self) -> &'static str {
        self.stage
    }

    /// Timestamp at which startup validation succeeded.
    pub fn issued_at(&self) -> SystemTime {
        self.issued_at
    }

    /// AS4 topology scope validated during token issuance (if any).
    pub fn as4_topology(&self) -> Option<DeploymentTopology> {
        self.as4_topology
    }
}

/// Strict production preset components shared across protocol stacks.
///
/// This constructor intentionally uses `EventBus::new_regulated` so callers
/// cannot accidentally deploy fail-open observability behavior in regulated
/// environments.
pub fn strict_production_event_bus(
    capacity: usize,
    audit_sink: Arc<dyn DurableAuditSink>,
) -> Result<EventBus> {
    EventBus::new_regulated(capacity, audit_sink)
}

/// Enforce durable reconciliation backend requirements for strict production
/// receive/reconciliation paths.
pub fn require_durable_reconciliation_backend(
    stage: &'static str,
    reconciliation: &dyn ReconciliationStorage,
) -> Result<()> {
    let durable = reconciliation.is_durable();
    let cluster_safe = reconciliation.cluster_safe();
    let backend_type = type_name_of_val(reconciliation);

    if !durable {
        return Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            format!(
                "strict production preset requires a durable reconciliation backend; backend_type={backend_type}; durable={durable}; cluster_safe={cluster_safe}"
            ),
            ErrorContext::new(stage),
        ));
    }
    if !cluster_safe {
        return Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            format!(
                "strict production preset requires a cluster-safe reconciliation backend; backend_type={backend_type}; durable={durable}; cluster_safe={cluster_safe}"
            ),
            ErrorContext::new(stage),
        ));
    }
    Ok(())
}

/// Enforce durable dedup backend requirements for strict production receive
/// paths that rely on replay protection.
pub fn require_durable_dedup_backend(stage: &'static str, dedup: &dyn DedupStorage) -> Result<()> {
    let durable = dedup.is_durable();
    let cluster_safe = dedup.cluster_safe();
    let backend_type = type_name_of_val(dedup);

    if !durable {
        return Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            format!(
                "strict production preset requires a durable dedup backend; backend_type={backend_type}; durable={durable}; cluster_safe={cluster_safe}"
            ),
            ErrorContext::new(stage),
        ));
    }
    if !cluster_safe {
        return Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            format!(
                "strict production preset requires a cluster-safe dedup backend; backend_type={backend_type}; durable={durable}; cluster_safe={cluster_safe}"
            ),
            ErrorContext::new(stage),
        ));
    }
    Ok(())
}

/// Enforce strict production runtime guards for receive/enqueue paths.
///
/// This centralizes fail-closed runtime checks to keep AS2/AS4 call sites
/// consistent and prevent drift between backend and observability guards.
pub fn enforce_strict_production_runtime_receive_guards(
    stage: &'static str,
    session: &SessionContext,
    event_bus: &EventBus,
    fail_closed_audit_events: bool,
    reconciliation: Option<&dyn ReconciliationStorage>,
    dedup: Option<&dyn DedupStorage>,
) -> Result<()> {
    #[cfg(not(feature = "testing"))]
    {
        if let Some(reconciliation) = reconciliation {
            require_durable_reconciliation_backend(stage, reconciliation)?;
        }
        if let Some(dedup) = dedup {
            require_durable_dedup_backend(stage, dedup)?;
        }
    }

    #[cfg(feature = "testing")]
    let _ = (reconciliation, dedup);

    #[cfg(any(feature = "as2", feature = "as4"))]
    {
        crate::observability::require_durable_audit_sink(
            session,
            event_bus,
            fail_closed_audit_events,
            stage,
        )
    }

    #[cfg(not(any(feature = "as2", feature = "as4")))]
    {
        let _ = (session, event_bus, fail_closed_audit_events, stage);
        Ok(())
    }
}

/// Validate strict production startup/readiness invariants in one call.
///
/// This check is intended for host bootstrap gates before accepting protocol
/// traffic in regulated deployments.
pub fn validate_strict_production_startup_readiness(
    stage: &'static str,
    event_bus: &EventBus,
    reconciliation: &dyn ReconciliationStorage,
    dedup: &dyn DedupStorage,
) -> Result<()> {
    let mode = event_bus.emission_mode();
    let has_durable_audit_sink = event_bus.has_production_durable_audit_sink();

    if mode != EventEmissionMode::StrictTransactional {
        return Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            format!(
                "strict production preset requires StrictTransactional event emission mode; emission_mode={mode:?}; durable_audit_sink={has_durable_audit_sink}"
            ),
            ErrorContext::new(stage),
        ));
    }

    if !has_durable_audit_sink {
        return Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            format!(
                "strict production preset requires a durable audit sink; emission_mode={mode:?}; durable_audit_sink={has_durable_audit_sink}"
            ),
            ErrorContext::new(stage),
        ));
    }

    require_durable_reconciliation_backend(stage, reconciliation)?;
    require_durable_dedup_backend(stage, dedup)
}

/// Validate strict-production startup and mint a typed runtime bootstrap token.
pub fn issue_strict_runtime_bootstrap_token(
    stage: &'static str,
    event_bus: &EventBus,
    reconciliation: &dyn ReconciliationStorage,
    dedup: &dyn DedupStorage,
) -> Result<StrictRuntimeBootstrapToken> {
    validate_strict_production_startup_readiness(stage, event_bus, reconciliation, dedup)?;
    Ok(StrictRuntimeBootstrapToken {
        issued_at: SystemTime::now(),
        stage,
        as4_topology: None,
    })
}

/// Validate strict-production AS4 distributed-topology readiness.
///
/// This check fails closed when clustered deployments use process-local
/// ordering/pull components that cannot coordinate across replicas.
#[cfg(feature = "as4")]
pub fn validate_strict_production_as4_topology_readiness(
    stage: &'static str,
    topology: DeploymentTopology,
    pull_store: Option<&dyn As4TopologyCoordination>,
    conversation_gate: Option<&dyn As4TopologyCoordination>,
) -> Result<()> {
    if topology == DeploymentTopology::SingleNode {
        return Ok(());
    }

    let Some(pull_store) = pull_store else {
        return Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            "strict production clustered topology requires a cluster-safe AS4 pull-store coordination backend",
            ErrorContext::new(stage),
        ));
    };
    if !pull_store.cluster_safe() {
        return Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            format!(
                "strict production clustered topology requires cluster-safe AS4 {} coordination",
                pull_store.topology_component()
            ),
            ErrorContext::new(stage),
        ));
    }

    let Some(conversation_gate) = conversation_gate else {
        return Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            "strict production clustered topology requires distributed AS4 conversation ordering coordination backend",
            ErrorContext::new(stage),
        ));
    };
    if !conversation_gate.cluster_safe() {
        return Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            format!(
                "strict production clustered topology requires distributed AS4 {} coordination",
                conversation_gate.topology_component()
            ),
            ErrorContext::new(stage),
        ));
    }

    Ok(())
}

/// Validate strict-production startup + AS4 topology and mint a typed token.
#[cfg(feature = "as4")]
pub fn issue_strict_runtime_bootstrap_token_with_as4_topology(
    stage: &'static str,
    event_bus: &EventBus,
    reconciliation: &dyn ReconciliationStorage,
    dedup: &dyn DedupStorage,
    topology: DeploymentTopology,
    pull_store: Option<&dyn As4TopologyCoordination>,
    conversation_gate: Option<&dyn As4TopologyCoordination>,
) -> Result<StrictRuntimeBootstrapToken> {
    validate_strict_production_startup_readiness(stage, event_bus, reconciliation, dedup)?;
    validate_strict_production_as4_topology_readiness(
        stage,
        topology,
        pull_store,
        conversation_gate,
    )?;
    Ok(StrictRuntimeBootstrapToken {
        issued_at: SystemTime::now(),
        stage,
        as4_topology: Some(topology),
    })
}

/// Require a strict runtime bootstrap token at protocol entry points.
pub fn require_strict_runtime_bootstrap_token(
    stage: &'static str,
    token: &StrictRuntimeBootstrapToken,
) -> Result<()> {
    if token.stage.trim().is_empty() {
        return Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            "strict runtime bootstrap token is invalid: empty stage",
            ErrorContext::new(stage),
        ));
    }
    Ok(())
}

/// Return a cloned session marked as startup-validated by the provided token.
pub fn session_with_strict_runtime_bootstrap_token(
    stage: &'static str,
    token: &StrictRuntimeBootstrapToken,
    session: &SessionContext,
) -> Result<SessionContext> {
    require_strict_runtime_bootstrap_token(stage, token)?;
    Ok(session
        .clone()
        .with_strict_runtime_bootstrap_validated(true))
}

/// Fail closed for strict-interop entry points unless startup validation was bound to the session.
pub fn enforce_strict_runtime_bootstrap_for_strict_interop(
    stage: &'static str,
    session: &SessionContext,
    interop: InteropMode,
) -> Result<()> {
    #[cfg(feature = "testing")]
    {
        let _ = (stage, session, interop);
        Ok(())
    }

    #[cfg(not(feature = "testing"))]
    {
        if interop == InteropMode::Strict && !session.strict_runtime_bootstrap_validated() {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                "strict interop entry point requires strict-runtime bootstrap token binding; bind startup token via presets::session_with_strict_runtime_bootstrap_token(...) before invoking strict protocol APIs",
                ErrorContext::for_session(stage, session),
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "as2")]
#[derive(Debug, Clone)]
pub struct As2StrictProductionPreset {
    pub send_policy: crate::as2::As2SendPolicy,
    pub receive_policy: crate::as2::As2ReceivePolicy,
}

#[cfg(feature = "as2")]
impl As2StrictProductionPreset {
    pub fn new() -> Self {
        Self {
            send_policy: crate::as2::As2SendPolicy::regulated(),
            receive_policy: crate::as2::As2ReceivePolicy::regulated(),
        }
    }
}

#[cfg(feature = "as2")]
impl Default for As2StrictProductionPreset {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "as4")]
#[derive(Debug, Clone)]
pub struct As4StrictProductionPreset {
    pub send_policy: crate::as4::As4SendPolicy,
    pub push_policy: crate::as4::As4PushPolicy,
    pub pull_policy: crate::as4::As4PullPolicy,
}

#[cfg(feature = "as4")]
impl As4StrictProductionPreset {
    pub fn new() -> Self {
        Self {
            send_policy: crate::as4::As4SendPolicy::regulated(),
            push_policy: crate::as4::As4PushPolicy::regulated(),
            pull_policy: crate::as4::As4PullPolicy::regulated(),
        }
    }
}

#[cfg(feature = "as4")]
impl Default for As4StrictProductionPreset {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::BackpressurePolicy;
    use crate::observability::audit_sink::{
        AuditEvent, AuditSinkDurability, DurableAuditSink, ReplayCursor,
    };
    use crate::storage::BoxFuture;

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

    struct NonDurableReconciliation;

    struct NonDurableDedup;

    struct DurableClusterSafeReconciliation;

    struct DurableClusterSafeDedup;

    impl DedupStorage for NonDurableDedup {
        fn is_durable(&self) -> bool {
            false
        }

        fn first_seen<'a>(
            &'a self,
            _idempotency_key: &'a str,
        ) -> BoxFuture<'a, crate::core::Result<bool>> {
            Box::pin(async move { Ok(true) })
        }
    }

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

    impl ReconciliationStorage for NonDurableReconciliation {
        fn is_durable(&self) -> bool {
            false
        }

        fn enqueue<'a>(
            &'a self,
            _request: crate::reliability::ReconciliationRequest,
        ) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async move { Ok(false) })
        }

        fn queued_requests(
            &self,
        ) -> BoxFuture<'_, Result<Vec<crate::reliability::ReconciliationRequest>>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn resolve<'a>(&'a self, _idempotency_key: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async move { Ok(false) })
        }
    }

    impl ReconciliationStorage for DurableClusterSafeReconciliation {
        fn is_durable(&self) -> bool {
            true
        }

        fn cluster_safe(&self) -> bool {
            true
        }

        fn enqueue<'a>(
            &'a self,
            _request: crate::reliability::ReconciliationRequest,
        ) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async move { Ok(false) })
        }

        fn queued_requests(
            &self,
        ) -> BoxFuture<'_, Result<Vec<crate::reliability::ReconciliationRequest>>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn resolve<'a>(&'a self, _idempotency_key: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async move { Ok(false) })
        }
    }

    #[test]
    fn strict_production_event_bus_uses_regulated_mode() {
        let bus = strict_production_event_bus(16, Arc::new(DurableTestAuditSink)).expect("bus");
        assert_eq!(
            bus.emission_mode(),
            crate::observability::EventEmissionMode::StrictTransactional
        );
        assert!(bus.has_production_durable_audit_sink());
    }

    #[test]
    fn strict_production_reconciliation_requires_durability() {
        let err = require_durable_reconciliation_backend(
            "strict_production_test",
            &NonDurableReconciliation,
        )
        .expect_err("non-durable backend must be rejected");

        assert_eq!(err.code, ErrorCode::ReliabilityFailure);
        assert!(err.message.contains("durable reconciliation backend"));
        assert!(err.message.contains("backend_type="));
        assert!(err.message.contains("durable=false"));
        assert!(err.message.contains("cluster_safe=false"));
    }

    #[test]
    fn strict_production_dedup_requires_durability() {
        let err = require_durable_dedup_backend("strict_production_test", &NonDurableDedup)
            .expect_err("non-durable dedup backend must be rejected");

        assert_eq!(err.code, ErrorCode::ReliabilityFailure);
        assert!(err.message.contains("durable dedup backend"));
        assert!(err.message.contains("backend_type="));
        assert!(err.message.contains("durable=false"));
        assert!(err.message.contains("cluster_safe=false"));
    }

    struct DurableButNonClusterReconciliation;

    impl ReconciliationStorage for DurableButNonClusterReconciliation {
        fn is_durable(&self) -> bool {
            true
        }

        fn enqueue<'a>(
            &'a self,
            _request: crate::reliability::ReconciliationRequest,
        ) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async move { Ok(false) })
        }

        fn queued_requests(
            &self,
        ) -> BoxFuture<'_, Result<Vec<crate::reliability::ReconciliationRequest>>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn resolve<'a>(&'a self, _idempotency_key: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async move { Ok(false) })
        }
    }

    struct DurableButNonClusterDedup;

    impl DedupStorage for DurableButNonClusterDedup {
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
    fn strict_production_reconciliation_requires_cluster_safety() {
        let err = require_durable_reconciliation_backend(
            "strict_production_test",
            &DurableButNonClusterReconciliation,
        )
        .expect_err("non-cluster-safe backend must be rejected");

        assert_eq!(err.code, ErrorCode::ReliabilityFailure);
        assert!(err.message.contains("cluster-safe reconciliation backend"));
        assert!(err.message.contains("backend_type="));
        assert!(err.message.contains("durable=true"));
        assert!(err.message.contains("cluster_safe=false"));
    }

    #[test]
    fn strict_production_dedup_requires_cluster_safety() {
        let err =
            require_durable_dedup_backend("strict_production_test", &DurableButNonClusterDedup)
                .expect_err("non-cluster-safe dedup must be rejected");

        assert_eq!(err.code, ErrorCode::ReliabilityFailure);
        assert!(err.message.contains("cluster-safe dedup backend"));
        assert!(err.message.contains("backend_type="));
        assert!(err.message.contains("durable=true"));
        assert!(err.message.contains("cluster_safe=false"));
    }

    #[test]
    fn strict_runtime_receive_guards_pass_for_durable_cluster_safe_backends() {
        let session = SessionContext::new("sess", "partner-a", "strict").expect("session");
        let bus = strict_production_event_bus(16, Arc::new(DurableTestAuditSink)).expect("bus");

        let result = enforce_strict_production_runtime_receive_guards(
            "strict_production_runtime_guard",
            &session,
            &bus,
            true,
            Some(&DurableClusterSafeReconciliation),
            Some(&DurableClusterSafeDedup),
        );

        assert!(result.is_ok());
    }

    #[test]
    #[cfg(not(feature = "testing"))]
    fn strict_runtime_receive_guards_fail_closed_for_non_durable_dedup() {
        let session = SessionContext::new("sess", "partner-a", "strict").expect("session");
        let bus = strict_production_event_bus(16, Arc::new(DurableTestAuditSink)).expect("bus");

        let err = enforce_strict_production_runtime_receive_guards(
            "strict_production_runtime_guard",
            &session,
            &bus,
            true,
            Some(&DurableClusterSafeReconciliation),
            Some(&NonDurableDedup),
        )
        .expect_err("non-durable dedup must be rejected at startup");

        assert_eq!(err.code, ErrorCode::ReliabilityFailure);
        assert!(err.message.contains("durable dedup backend"));
        assert!(err.message.contains("backend_type="));
        assert!(err.message.contains("durable=false"));
        assert!(err.message.contains("cluster_safe=false"));
    }

    #[test]
    #[cfg(feature = "testing")]
    fn strict_runtime_receive_guards_allow_non_durable_backends_in_testing_mode() {
        let session = SessionContext::new("sess", "partner-a", "strict").expect("session");
        let bus = strict_production_event_bus(16, Arc::new(DurableTestAuditSink)).expect("bus");

        let result = enforce_strict_production_runtime_receive_guards(
            "strict_production_runtime_guard",
            &session,
            &bus,
            true,
            Some(&DurableClusterSafeReconciliation),
            Some(&NonDurableDedup),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn strict_production_startup_readiness_passes_for_regulated_event_bus_and_durable_backends() {
        let bus = strict_production_event_bus(16, Arc::new(DurableTestAuditSink)).expect("bus");

        let result = validate_strict_production_startup_readiness(
            "strict_production_startup",
            &bus,
            &DurableClusterSafeReconciliation,
            &DurableClusterSafeDedup,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn strict_production_startup_readiness_rejects_non_strict_emission_mode() {
        let bus = EventBus::new_with_config_and_mode(
            16,
            None,
            BackpressurePolicy::default(),
            EventEmissionMode::BestEffort,
        )
        .expect("best effort bus");

        let err = validate_strict_production_startup_readiness(
            "strict_production_startup",
            &bus,
            &DurableClusterSafeReconciliation,
            &DurableClusterSafeDedup,
        )
        .expect_err("best-effort event bus must be rejected");

        assert_eq!(err.code, ErrorCode::ReliabilityFailure);
        assert!(err.message.contains("StrictTransactional"));
        assert!(err.message.contains("durable_audit_sink=false"));
    }

    #[test]
    fn strict_production_startup_readiness_rejects_missing_durable_audit_sink() {
        let bus = EventBus::new(16).expect("strict bus");

        let err = validate_strict_production_startup_readiness(
            "strict_production_startup",
            &bus,
            &DurableClusterSafeReconciliation,
            &DurableClusterSafeDedup,
        )
        .expect_err("strict bus without durable audit sink must be rejected");

        assert_eq!(err.code, ErrorCode::ReliabilityFailure);
        assert!(err.message.contains("durable audit sink"));
        assert!(err.message.contains("StrictTransactional"));
        assert!(err.message.contains("durable_audit_sink=false"));
    }

    #[test]
    fn issue_strict_runtime_bootstrap_token_mints_token_after_validation() {
        let bus = strict_production_event_bus(16, Arc::new(DurableTestAuditSink)).expect("bus");

        let token = issue_strict_runtime_bootstrap_token(
            "strict_bootstrap_issue",
            &bus,
            &DurableClusterSafeReconciliation,
            &DurableClusterSafeDedup,
        )
        .expect("token");

        assert_eq!(token.stage(), "strict_bootstrap_issue");
        assert_eq!(token.as4_topology(), None);
    }

    #[test]
    fn require_strict_runtime_bootstrap_token_accepts_issued_token() {
        let bus = strict_production_event_bus(16, Arc::new(DurableTestAuditSink)).expect("bus");

        let token = issue_strict_runtime_bootstrap_token(
            "strict_bootstrap_issue",
            &bus,
            &DurableClusterSafeReconciliation,
            &DurableClusterSafeDedup,
        )
        .expect("token");

        let result = require_strict_runtime_bootstrap_token("strict_token_check", &token);
        assert!(result.is_ok());
    }

    #[cfg(not(feature = "testing"))]
    #[test]
    fn strict_interop_enforcement_rejects_unbound_session() {
        let session = SessionContext::new("sess", "partner-a", "strict").expect("session");

        let err = enforce_strict_runtime_bootstrap_for_strict_interop(
            "strict_entrypoint",
            &session,
            InteropMode::Strict,
        )
        .expect_err("strict interop must require runtime bootstrap token binding");

        assert_eq!(err.code, ErrorCode::PolicyViolation);
        assert!(
            err.message
                .contains("strict-runtime bootstrap token binding")
        );
        assert!(
            err.message
                .contains("session_with_strict_runtime_bootstrap_token"),
            "guidance should point to session-first strict bootstrap flow"
        );
        assert!(
            !err.message.contains("*_with_strict_runtime_token"),
            "guidance must not reference removed strict wrapper APIs"
        );
    }

    #[test]
    fn strict_interop_enforcement_accepts_token_bound_session() {
        let bus = strict_production_event_bus(16, Arc::new(DurableTestAuditSink)).expect("bus");
        let session = SessionContext::new("sess", "partner-a", "strict").expect("session");
        let token = issue_strict_runtime_bootstrap_token(
            "strict_bootstrap_issue",
            &bus,
            &DurableClusterSafeReconciliation,
            &DurableClusterSafeDedup,
        )
        .expect("token");

        let bound_session =
            session_with_strict_runtime_bootstrap_token("strict_bind", &token, &session)
                .expect("bound session");

        let result = enforce_strict_runtime_bootstrap_for_strict_interop(
            "strict_entrypoint",
            &bound_session,
            InteropMode::Strict,
        );
        assert!(result.is_ok());
    }

    #[cfg(feature = "as4")]
    #[test]
    fn strict_production_as4_topology_readiness_allows_single_node() {
        struct TestCoordination;

        impl As4TopologyCoordination for TestCoordination {
            fn cluster_safe(&self) -> bool {
                false
            }

            fn topology_component(&self) -> &'static str {
                "test-component"
            }
        }

        let pull_store = TestCoordination;
        let conversation_gate = TestCoordination;
        let result = validate_strict_production_as4_topology_readiness(
            "strict_production_topology",
            DeploymentTopology::SingleNode,
            Some(&pull_store),
            Some(&conversation_gate),
        );

        assert!(result.is_ok());
    }

    #[cfg(feature = "as4")]
    #[test]
    fn strict_production_as4_topology_readiness_rejects_non_cluster_safe_pull_store() {
        struct PullStoreCoordination;
        struct ConversationGateCoordination;

        impl As4TopologyCoordination for PullStoreCoordination {
            fn cluster_safe(&self) -> bool {
                false
            }

            fn topology_component(&self) -> &'static str {
                "pull-store"
            }
        }

        impl As4TopologyCoordination for ConversationGateCoordination {
            fn cluster_safe(&self) -> bool {
                true
            }

            fn topology_component(&self) -> &'static str {
                "conversation-order-gate"
            }
        }

        let pull_store = PullStoreCoordination;
        let conversation_gate = ConversationGateCoordination;
        let err = validate_strict_production_as4_topology_readiness(
            "strict_production_topology",
            DeploymentTopology::Clustered,
            Some(&pull_store),
            Some(&conversation_gate),
        )
        .expect_err("clustered topology must reject non-cluster-safe pull store");

        assert_eq!(err.code, ErrorCode::ReliabilityFailure);
        assert!(err.message.contains("cluster-safe AS4 pull-store"));
    }

    #[cfg(feature = "as4")]
    #[test]
    fn strict_production_as4_topology_readiness_rejects_non_cluster_safe_conversation_gate() {
        struct PullStoreCoordination;
        struct ConversationGateCoordination;

        impl As4TopologyCoordination for PullStoreCoordination {
            fn cluster_safe(&self) -> bool {
                true
            }

            fn topology_component(&self) -> &'static str {
                "pull-store"
            }
        }

        impl As4TopologyCoordination for ConversationGateCoordination {
            fn cluster_safe(&self) -> bool {
                false
            }

            fn topology_component(&self) -> &'static str {
                "conversation-order-gate"
            }
        }

        let pull_store = PullStoreCoordination;
        let conversation_gate = ConversationGateCoordination;
        let err = validate_strict_production_as4_topology_readiness(
            "strict_production_topology",
            DeploymentTopology::Clustered,
            Some(&pull_store),
            Some(&conversation_gate),
        )
        .expect_err("clustered topology must reject process-local conversation gate");

        assert_eq!(err.code, ErrorCode::ReliabilityFailure);
        assert!(
            err.message
                .contains("distributed AS4 conversation-order-gate coordination"),
            "unexpected error message: {}",
            err.message
        );
    }

    #[cfg(feature = "as4")]
    #[test]
    fn issue_strict_runtime_bootstrap_token_with_as4_topology_sets_scope() {
        let bus = strict_production_event_bus(16, Arc::new(DurableTestAuditSink)).expect("bus");

        struct ClusterSafeCoordination(&'static str);

        impl As4TopologyCoordination for ClusterSafeCoordination {
            fn cluster_safe(&self) -> bool {
                true
            }

            fn topology_component(&self) -> &'static str {
                self.0
            }
        }

        let pull_store = ClusterSafeCoordination("postgres-pull-store");
        let conversation_gate = ClusterSafeCoordination("postgres-conversation-order-gate");

        let token = issue_strict_runtime_bootstrap_token_with_as4_topology(
            "strict_bootstrap_issue",
            &bus,
            &DurableClusterSafeReconciliation,
            &DurableClusterSafeDedup,
            DeploymentTopology::Clustered,
            Some(&pull_store),
            Some(&conversation_gate),
        )
        .expect("token");

        assert_eq!(token.as4_topology(), Some(DeploymentTopology::Clustered));
    }

    #[cfg(feature = "as2")]
    #[test]
    fn as2_strict_production_preset_defaults_are_fail_closed() {
        let preset = As2StrictProductionPreset::new();
        assert_eq!(
            preset.send_policy.interop_mode,
            crate::core::InteropMode::Strict
        );
        assert_eq!(
            preset.receive_policy.interop_mode,
            crate::core::InteropMode::Strict
        );
        assert!(preset.send_policy.fail_closed_audit_events);
        assert!(preset.receive_policy.fail_closed_audit_events);
    }

    #[cfg(feature = "as4")]
    #[test]
    fn as4_strict_production_preset_defaults_are_fail_closed() {
        let preset = As4StrictProductionPreset::new();
        assert_eq!(preset.send_policy, crate::as4::As4SendPolicy::regulated());
        assert_eq!(preset.send_policy.interop, crate::core::InteropMode::Strict);
        assert_eq!(preset.push_policy.interop, crate::core::InteropMode::Strict);
        assert_eq!(preset.pull_policy.interop, crate::core::InteropMode::Strict);
        assert!(preset.send_policy.fail_closed_audit_events);
        assert!(preset.push_policy.fail_closed_audit_events);
        assert!(preset.pull_policy.fail_closed_audit_events);
        assert!(preset.push_policy.require_signed_push);
        assert!(preset.pull_policy.require_signed_push);
    }
}
