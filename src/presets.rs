//! Startup validation for regulated deployments.
//!
//! A deployment that is *configured* strictly but never *validated* strictly is
//! indistinguishable from a correct one until the first message that depends on
//! the difference. This module turns that into a startup error.
//!
//! ```no_run
//! use asx_rs::presets::{DeploymentTopology, StrictRuntimeBootstrap};
//!
//! # fn main() -> asx_rs::Result<()> {
//! # let (event_bus, dedup, reconciliation, session): (
//! #     asx_rs::observability::EventBus,
//! #     std::sync::Arc<dyn asx_rs::storage::DedupStorage>,
//! #     std::sync::Arc<dyn asx_rs::storage::ReconciliationStorage>,
//! #     asx_rs::core::SessionContext,
//! # ) = unimplemented!();
//! let token = StrictRuntimeBootstrap::new("startup")
//!     .event_bus(&event_bus)
//!     .dedup(dedup.as_ref())
//!     .reconciliation(reconciliation.as_ref())
//!     .topology(DeploymentTopology::SingleNode)
//!     .validate()?;
//!
//! // Only a token-bound session may enter a strict protocol entry point.
//! let session = token.bind(&session);
//! # let _ = session;
//! # Ok(())
//! # }
//! ```

use std::any::type_name_of_val;
use std::time::SystemTime;

#[cfg(feature = "as4")]
use crate::as4::As4TopologyCoordination;
use crate::core::SessionContext;
use crate::core::{AsxError, ErrorCode, ErrorContext, InteropMode, Result};
use crate::observability::{EventBus, EventEmissionMode};
use crate::storage::{DedupStorage, ReconciliationStorage};

/// Runtime deployment topology used by strict-production startup validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeploymentTopology {
    /// Single process / single replica.
    SingleNode,
    /// Multiple replicas, where cross-node coordination is required for the
    /// AS4 pull store and the conversation ordering gate.
    Clustered,
}

/// Unforgeable proof that strict-production startup validation succeeded.
///
/// The only way to obtain one is [`StrictRuntimeBootstrap::validate`], and the
/// only thing it is good for is [`bind`](Self::bind)ing a session so that
/// strict protocol entry points will accept it. There is no public
/// constructor, no `Default`, and no way to set the session marker without it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictRuntimeBootstrapToken {
    issued_at: SystemTime,
    stage: &'static str,
    as4_topology: Option<DeploymentTopology>,
}

impl StrictRuntimeBootstrapToken {
    /// The stage label validation ran under.
    #[must_use]
    pub fn stage(&self) -> &'static str {
        self.stage
    }

    /// When validation succeeded.
    #[must_use]
    pub fn issued_at(&self) -> SystemTime {
        self.issued_at
    }

    /// The AS4 topology this token covers, if AS4 coordination was validated.
    #[must_use]
    pub fn as4_topology(&self) -> Option<DeploymentTopology> {
        self.as4_topology
    }

    /// Return a clone of `session` marked as startup-validated.
    ///
    /// Strict protocol entry points refuse a session that carries no marker.
    #[must_use]
    pub fn bind(&self, session: &SessionContext) -> SessionContext {
        session
            .clone()
            .with_strict_runtime_bootstrap_validated(true)
    }
}

/// Startup validator for regulated deployments.
///
/// Checks, in one place, that the runtime a deployment is about to accept
/// traffic on is the one its profile assumes:
///
/// | Component | Requirement |
/// |---|---|
/// | [`EventBus`] | Strict emission (not `BestEffort`) and a production-durable audit sink |
/// | [`DedupStorage`] | `is_durable()` **and** `cluster_safe()` |
/// | [`ReconciliationStorage`] | `is_durable()` **and** `cluster_safe()` |
/// | AS4 pull store / conversation gate | `cluster_safe()`, when the topology is [`DeploymentTopology::Clustered`] |
///
/// Those last two are self-declarations: this validates that the operator made
/// a claim, not that the claim is true. The restart tests a backend must
/// actually pass are the embedder's to run.
pub struct StrictRuntimeBootstrap<'a> {
    stage: &'static str,
    event_bus: Option<&'a EventBus>,
    dedup: Option<&'a dyn DedupStorage>,
    reconciliation: Option<&'a dyn ReconciliationStorage>,
    topology: DeploymentTopology,
    #[cfg(feature = "as4")]
    as4_pull_store: Option<&'a dyn As4TopologyCoordination>,
    #[cfg(feature = "as4")]
    as4_conversation_gate: Option<&'a dyn As4TopologyCoordination>,
    #[cfg(not(feature = "as4"))]
    _marker: std::marker::PhantomData<&'a ()>,
}

impl std::fmt::Debug for StrictRuntimeBootstrap<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StrictRuntimeBootstrap")
            .field("stage", &self.stage)
            .field("event_bus", &self.event_bus.is_some())
            .field("dedup", &self.dedup.is_some())
            .field("reconciliation", &self.reconciliation.is_some())
            .field("topology", &self.topology)
            .finish_non_exhaustive()
    }
}

impl<'a> StrictRuntimeBootstrap<'a> {
    /// Begin validation. `stage` labels the errors this produces.
    #[must_use]
    pub fn new(stage: &'static str) -> Self {
        Self {
            stage,
            event_bus: None,
            dedup: None,
            reconciliation: None,
            topology: DeploymentTopology::SingleNode,
            #[cfg(feature = "as4")]
            as4_pull_store: None,
            #[cfg(feature = "as4")]
            as4_conversation_gate: None,
            #[cfg(not(feature = "as4"))]
            _marker: std::marker::PhantomData,
        }
    }

    /// The bus protocol operations will emit through. Required.
    #[must_use]
    pub fn event_bus(mut self, event_bus: &'a EventBus) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    /// The duplicate-detection backend. Required.
    #[must_use]
    pub fn dedup(mut self, dedup: &'a dyn DedupStorage) -> Self {
        self.dedup = Some(dedup);
        self
    }

    /// The reconciliation backend. Required.
    #[must_use]
    pub fn reconciliation(mut self, reconciliation: &'a dyn ReconciliationStorage) -> Self {
        self.reconciliation = Some(reconciliation);
        self
    }

    /// Declare the deployment topology. Defaults to
    /// [`DeploymentTopology::SingleNode`]; declaring `Clustered` turns on the
    /// AS4 coordination checks below.
    #[must_use]
    pub fn topology(mut self, topology: DeploymentTopology) -> Self {
        self.topology = topology;
        self
    }

    /// The AS4 pull store. Required when the topology is `Clustered`.
    #[cfg(feature = "as4")]
    #[must_use]
    pub fn as4_pull_store(mut self, pull_store: &'a dyn As4TopologyCoordination) -> Self {
        self.as4_pull_store = Some(pull_store);
        self
    }

    /// The AS4 conversation ordering gate. Required when the topology is
    /// `Clustered`.
    #[cfg(feature = "as4")]
    #[must_use]
    pub fn as4_conversation_gate(mut self, gate: &'a dyn As4TopologyCoordination) -> Self {
        self.as4_conversation_gate = Some(gate);
        self
    }

    /// Run every configured check and mint a token.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidInput`] when a required component was not supplied,
    /// and [`ErrorCode::ReliabilityFailure`] when one of them does not meet the
    /// strict-production requirement. Every message names the component, its
    /// concrete type and the properties it declared.
    pub fn validate(self) -> Result<StrictRuntimeBootstrapToken> {
        let stage = self.stage;
        let event_bus = self.event_bus.ok_or_else(|| {
            missing_component(stage, "event_bus", "StrictRuntimeBootstrap::event_bus")
        })?;
        let dedup = self
            .dedup
            .ok_or_else(|| missing_component(stage, "dedup", "StrictRuntimeBootstrap::dedup"))?;
        let reconciliation = self.reconciliation.ok_or_else(|| {
            missing_component(
                stage,
                "reconciliation",
                "StrictRuntimeBootstrap::reconciliation",
            )
        })?;

        validate_event_bus(stage, event_bus)?;
        require_durable_backend(stage, "reconciliation", reconciliation.as_durability())?;
        require_durable_backend(stage, "dedup", dedup.as_durability())?;

        #[cfg(feature = "as4")]
        let as4_topology = {
            validate_as4_topology(
                stage,
                self.topology,
                self.as4_pull_store,
                self.as4_conversation_gate,
            )?;
            Some(self.topology)
        };
        #[cfg(not(feature = "as4"))]
        let as4_topology = None;

        Ok(StrictRuntimeBootstrapToken {
            issued_at: SystemTime::now(),
            stage,
            as4_topology,
        })
    }
}

fn missing_component(stage: &'static str, component: &str, setter: &str) -> AsxError {
    AsxError::new(
        ErrorCode::InvalidInput,
        format!(
            "strict runtime bootstrap requires a {component}; call {setter}(..) before validate()"
        ),
        ErrorContext::new(stage),
    )
}

/// The durability properties a storage backend declares about itself.
#[derive(Debug, Clone, Copy)]
pub struct BackendDurability {
    /// Survives a process restart.
    pub durable: bool,
    /// Coordinates correctly across replicas.
    pub cluster_safe: bool,
    /// The concrete backend type, for error messages.
    pub backend_type: &'static str,
}

trait DeclaredDurability {
    fn as_durability(&self) -> BackendDurability;
}

impl DeclaredDurability for &dyn DedupStorage {
    fn as_durability(&self) -> BackendDurability {
        BackendDurability {
            durable: self.is_durable(),
            cluster_safe: self.cluster_safe(),
            backend_type: type_name_of_val(*self),
        }
    }
}

impl DeclaredDurability for &dyn ReconciliationStorage {
    fn as_durability(&self) -> BackendDurability {
        BackendDurability {
            durable: self.is_durable(),
            cluster_safe: self.cluster_safe(),
            backend_type: type_name_of_val(*self),
        }
    }
}

fn require_durable_backend(
    stage: &'static str,
    component: &str,
    d: BackendDurability,
) -> Result<()> {
    let missing = if !d.durable {
        "durable"
    } else if !d.cluster_safe {
        "cluster-safe"
    } else {
        return Ok(());
    };
    Err(AsxError::new(
        ErrorCode::ReliabilityFailure,
        format!(
            "strict production requires a {missing} {component} backend; backend_type={}; durable={}; cluster_safe={}",
            d.backend_type, d.durable, d.cluster_safe
        ),
        ErrorContext::new(stage),
    ))
}

fn validate_event_bus(stage: &'static str, event_bus: &EventBus) -> Result<()> {
    let mode = event_bus.emission_mode();
    let has_durable_audit_sink = event_bus.has_production_durable_audit_sink();

    // `StrictWithAuditFallback` is a *strict* mode: it cannot be constructed
    // without a production-durable sink, and it persists every event there when
    // no subscriber is live. Rejecting it here would have forced regulated
    // deployments that follow its own documentation to fail this gate.
    if matches!(mode, EventEmissionMode::BestEffort) {
        return Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            format!(
                "strict production requires a strict event emission mode \
                 (StrictTransactional or StrictWithAuditFallback); emission_mode={mode:?}; \
                 durable_audit_sink={has_durable_audit_sink}"
            ),
            ErrorContext::new(stage),
        ));
    }

    if !has_durable_audit_sink {
        return Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            format!(
                "strict production requires a durable audit sink; emission_mode={mode:?}; \
                 durable_audit_sink={has_durable_audit_sink}"
            ),
            ErrorContext::new(stage),
        ));
    }

    Ok(())
}

#[cfg(feature = "as4")]
fn validate_as4_topology(
    stage: &'static str,
    topology: DeploymentTopology,
    pull_store: Option<&dyn As4TopologyCoordination>,
    conversation_gate: Option<&dyn As4TopologyCoordination>,
) -> Result<()> {
    if topology == DeploymentTopology::SingleNode {
        return Ok(());
    }

    for (component, coordination, setter) in [
        (
            "pull-store",
            pull_store,
            "StrictRuntimeBootstrap::as4_pull_store",
        ),
        (
            "conversation-ordering",
            conversation_gate,
            "StrictRuntimeBootstrap::as4_conversation_gate",
        ),
    ] {
        let Some(coordination) = coordination else {
            return Err(AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!(
                    "clustered topology requires a cluster-safe AS4 {component} backend; \
                     supply one via {setter}(..)"
                ),
                ErrorContext::new(stage),
            ));
        };
        if !coordination.cluster_safe() {
            return Err(AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!(
                    "clustered topology requires cluster-safe AS4 {} coordination",
                    coordination.topology_component()
                ),
                ErrorContext::new(stage),
            ));
        }
    }

    Ok(())
}

/// Enforce strict production runtime guards on receive and enqueue paths.
///
/// Centralised so AS2 and AS4 call sites cannot drift apart on which guards
/// they run.
pub(crate) fn enforce_strict_production_runtime_receive_guards(
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
            require_durable_backend(stage, "reconciliation", reconciliation.as_durability())?;
        }
        if let Some(dedup) = dedup {
            require_durable_backend(stage, "dedup", dedup.as_durability())?;
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

/// Fail closed at a strict-interop entry point unless startup validation was
/// bound to the session by [`StrictRuntimeBootstrapToken::bind`].
pub(crate) fn enforce_strict_runtime_bootstrap_for_strict_interop(
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
                "strict interop entry point requires a strict-runtime bootstrap token; \
                 validate startup with presets::StrictRuntimeBootstrap and bind the session \
                 with StrictRuntimeBootstrapToken::bind(..)",
                ErrorContext::for_session(stage, session),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::audit_sink::{
        AuditEvent, AuditSinkDurability, DurableAuditSink, ReplayCursor,
    };
    use crate::storage::BoxFuture;

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

    struct NonDurableReconciliation;

    #[derive(Debug)]

    struct NonDurableDedup;

    #[derive(Debug)]

    struct DurableClusterSafeReconciliation;

    #[derive(Debug)]

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

    #[derive(Debug)]

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

    #[derive(Debug)]

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

    fn regulated_bus() -> EventBus {
        EventBus::new_regulated(16, std::sync::Arc::new(DurableTestAuditSink)).expect("bus")
    }

    fn ready() -> StrictRuntimeBootstrap<'static> {
        StrictRuntimeBootstrap::new("strict_production_test")
    }

    #[test]
    fn regulated_bus_is_strict_and_durable() {
        let bus = regulated_bus();
        assert_eq!(bus.emission_mode(), EventEmissionMode::StrictTransactional);
        assert!(bus.has_production_durable_audit_sink());
    }

    #[test]
    fn validate_requires_every_component() {
        let bus = regulated_bus();

        let err = ready().validate().expect_err("event bus is required");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("event_bus"));

        let err = ready()
            .event_bus(&bus)
            .validate()
            .expect_err("dedup is required");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("dedup"));

        let err = ready()
            .event_bus(&bus)
            .dedup(&DurableClusterSafeDedup)
            .validate()
            .expect_err("reconciliation is required");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("reconciliation"));
    }

    #[test]
    fn validate_rejects_non_durable_backends() {
        let bus = regulated_bus();

        let err = ready()
            .event_bus(&bus)
            .dedup(&DurableClusterSafeDedup)
            .reconciliation(&NonDurableReconciliation)
            .validate()
            .expect_err("non-durable reconciliation must be rejected");
        assert_eq!(err.code, ErrorCode::ReliabilityFailure);
        assert!(err.message.contains("durable reconciliation backend"));
        assert!(err.message.contains("backend_type="));

        let err = ready()
            .event_bus(&bus)
            .dedup(&NonDurableDedup)
            .reconciliation(&DurableClusterSafeReconciliation)
            .validate()
            .expect_err("non-durable dedup must be rejected");
        assert_eq!(err.code, ErrorCode::ReliabilityFailure);
        assert!(err.message.contains("durable dedup backend"));
    }

    #[test]
    fn validate_rejects_non_cluster_safe_backends() {
        let bus = regulated_bus();

        let err = ready()
            .event_bus(&bus)
            .dedup(&DurableClusterSafeDedup)
            .reconciliation(&DurableButNonClusterReconciliation)
            .validate()
            .expect_err("non-cluster-safe reconciliation must be rejected");
        assert_eq!(err.code, ErrorCode::ReliabilityFailure);
        assert!(err.message.contains("cluster-safe reconciliation backend"));
        assert!(err.message.contains("durable=true"));
        assert!(err.message.contains("cluster_safe=false"));

        let err = ready()
            .event_bus(&bus)
            .dedup(&DurableButNonClusterDedup)
            .reconciliation(&DurableClusterSafeReconciliation)
            .validate()
            .expect_err("non-cluster-safe dedup must be rejected");
        assert_eq!(err.code, ErrorCode::ReliabilityFailure);
        assert!(err.message.contains("cluster-safe dedup backend"));
    }

    #[test]
    fn validate_rejects_best_effort_emission() {
        let bus = EventBus::builder()
            .capacity(16)
            .emission_mode(EventEmissionMode::BestEffort)
            .build()
            .expect("bus");

        let err = ready()
            .event_bus(&bus)
            .dedup(&DurableClusterSafeDedup)
            .reconciliation(&DurableClusterSafeReconciliation)
            .validate()
            .expect_err("best-effort emission must be rejected");

        assert_eq!(err.code, ErrorCode::ReliabilityFailure);
        assert!(err.message.contains("strict event emission mode"));
    }

    /// `StrictWithAuditFallback` is a strict mode that cannot be built without a
    /// production-durable sink, so the startup gate must accept it. Rejecting it
    /// made the mode its own documentation recommends unusable in a regulated
    /// deployment.
    #[test]
    fn validate_accepts_strict_with_audit_fallback() {
        let bus = EventBus::builder()
            .capacity(16)
            .audit_sink(std::sync::Arc::new(DurableTestAuditSink))
            .emission_mode(EventEmissionMode::StrictWithAuditFallback)
            .build()
            .expect("bus");

        ready()
            .event_bus(&bus)
            .dedup(&DurableClusterSafeDedup)
            .reconciliation(&DurableClusterSafeReconciliation)
            .validate()
            .expect("audit-fallback strict mode is a strict mode");
    }

    #[test]
    fn validate_rejects_missing_durable_audit_sink() {
        let bus = EventBus::new(16).expect("bus");

        let err = ready()
            .event_bus(&bus)
            .dedup(&DurableClusterSafeDedup)
            .reconciliation(&DurableClusterSafeReconciliation)
            .validate()
            .expect_err("missing durable audit sink must be rejected");

        assert_eq!(err.code, ErrorCode::ReliabilityFailure);
        assert!(err.message.contains("durable audit sink"));
    }

    #[test]
    fn validate_mints_a_token_on_success() {
        let bus = regulated_bus();
        let token = ready()
            .event_bus(&bus)
            .dedup(&DurableClusterSafeDedup)
            .reconciliation(&DurableClusterSafeReconciliation)
            .validate()
            .expect("startup validation must succeed");

        assert_eq!(token.stage(), "strict_production_test");
        assert!(token.issued_at() <= SystemTime::now());
    }

    #[test]
    fn receive_guards_pass_for_durable_cluster_safe_backends() {
        let session = SessionContext::new("s", "p", "strict").expect("session");
        let bus = regulated_bus();

        enforce_strict_production_runtime_receive_guards(
            "strict_production_test",
            &session,
            &bus,
            true,
            Some(&DurableClusterSafeReconciliation),
            Some(&DurableClusterSafeDedup),
        )
        .expect("durable cluster-safe backends must pass");
    }

    #[cfg(not(feature = "testing"))]
    #[test]
    fn receive_guards_fail_closed_for_non_durable_dedup() {
        let session = SessionContext::new("s", "p", "strict").expect("session");
        let bus = regulated_bus();

        let err = enforce_strict_production_runtime_receive_guards(
            "strict_production_test",
            &session,
            &bus,
            true,
            Some(&DurableClusterSafeReconciliation),
            Some(&NonDurableDedup),
        )
        .expect_err("non-durable dedup must fail closed");

        assert_eq!(err.code, ErrorCode::ReliabilityFailure);
    }

    #[cfg(feature = "testing")]
    #[test]
    fn receive_guards_allow_non_durable_backends_under_testing_feature() {
        let session = SessionContext::new("s", "p", "strict").expect("session");
        let bus = regulated_bus();

        enforce_strict_production_runtime_receive_guards(
            "strict_production_test",
            &session,
            &bus,
            false,
            Some(&NonDurableReconciliation),
            Some(&NonDurableDedup),
        )
        .expect("the testing feature relaxes backend durability");
    }

    #[cfg(all(feature = "as4", not(feature = "testing")))]
    #[test]
    fn clustered_topology_requires_cluster_safe_as4_coordination() {
        struct NotClusterSafe(&'static str);
        impl As4TopologyCoordination for NotClusterSafe {
            fn cluster_safe(&self) -> bool {
                false
            }
            fn topology_component(&self) -> &'static str {
                self.0
            }
        }
        struct ClusterSafe(&'static str);
        impl As4TopologyCoordination for ClusterSafe {
            fn cluster_safe(&self) -> bool {
                true
            }
            fn topology_component(&self) -> &'static str {
                self.0
            }
        }

        let bus = regulated_bus();
        let base = || {
            StrictRuntimeBootstrap::new("strict_production_test")
                .dedup(&DurableClusterSafeDedup)
                .reconciliation(&DurableClusterSafeReconciliation)
                .topology(DeploymentTopology::Clustered)
        };

        // No coordination supplied at all.
        let err = base()
            .event_bus(&bus)
            .validate()
            .expect_err("clustered topology needs a pull store");
        assert_eq!(err.code, ErrorCode::ReliabilityFailure);
        assert!(err.message.contains("pull-store"));

        // Pull store present but process-local.
        let err = base()
            .event_bus(&bus)
            .as4_pull_store(&NotClusterSafe("pull-store"))
            .as4_conversation_gate(&ClusterSafe("conversation-ordering"))
            .validate()
            .expect_err("process-local pull store must be rejected");
        assert!(err.message.contains("pull-store"));

        // Conversation gate present but process-local.
        let err = base()
            .event_bus(&bus)
            .as4_pull_store(&ClusterSafe("pull-store"))
            .as4_conversation_gate(&NotClusterSafe("conversation-ordering"))
            .validate()
            .expect_err("process-local conversation gate must be rejected");
        assert!(err.message.contains("conversation-ordering"));

        // Both cluster-safe.
        let token = base()
            .event_bus(&bus)
            .as4_pull_store(&ClusterSafe("pull-store"))
            .as4_conversation_gate(&ClusterSafe("conversation-ordering"))
            .validate()
            .expect("cluster-safe coordination must pass");
        assert_eq!(token.as4_topology(), Some(DeploymentTopology::Clustered));
    }

    #[cfg(feature = "as4")]
    #[test]
    fn single_node_topology_needs_no_as4_coordination() {
        let bus = regulated_bus();
        let token = ready()
            .event_bus(&bus)
            .dedup(&DurableClusterSafeDedup)
            .reconciliation(&DurableClusterSafeReconciliation)
            .topology(DeploymentTopology::SingleNode)
            .validate()
            .expect("single node needs no distributed coordination");
        assert_eq!(token.as4_topology(), Some(DeploymentTopology::SingleNode));
    }

    #[cfg(not(feature = "testing"))]
    #[test]
    fn strict_interop_rejects_an_unbound_session() {
        let session = SessionContext::new("s", "p", "strict").expect("session");
        let err = enforce_strict_runtime_bootstrap_for_strict_interop(
            "as4_receive_push_sync",
            &session,
            InteropMode::Strict,
        )
        .expect_err("an unbound session must be refused");

        assert_eq!(err.code, ErrorCode::PolicyViolation);
        assert!(err.message.contains("StrictRuntimeBootstrap"));
    }

    #[cfg(not(feature = "testing"))]
    #[test]
    fn strict_interop_accepts_a_token_bound_session() {
        let bus = regulated_bus();
        let token = ready()
            .event_bus(&bus)
            .dedup(&DurableClusterSafeDedup)
            .reconciliation(&DurableClusterSafeReconciliation)
            .validate()
            .expect("startup validation");

        let session = token.bind(&SessionContext::new("s", "p", "strict").expect("session"));
        assert!(session.strict_runtime_bootstrap_validated());

        enforce_strict_runtime_bootstrap_for_strict_interop(
            "as4_receive_push_sync",
            &session,
            InteropMode::Strict,
        )
        .expect("a token-bound session must be accepted");
    }

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn relaxed_interop_needs_no_token() {
        let session = SessionContext::new("s", "p", "relaxed").expect("session");
        enforce_strict_runtime_bootstrap_for_strict_interop(
            "as4_receive_push_sync",
            &session,
            InteropMode::Relaxed,
        )
        .expect("relaxed interop is not gated on startup validation");
    }
}
