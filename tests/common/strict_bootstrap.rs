//! Mint a real [`StrictRuntimeBootstrapToken`] for integration tests.
//!
//! Strict-interop entry points refuse a session that was not startup-validated,
//! and the marker has no public setter — deliberately, because a marker any
//! caller could raise would assert that validation ran without it having run.
//!
//! Tests therefore do what a deployment does: declare durable, cluster-safe
//! backends and run the real gate. That keeps these tests honest (they exercise
//! the same code path production does) and keeps them compiling in every
//! feature combination, including the ones without `testing`.

#![allow(dead_code)]

use std::sync::Arc;

use asx_rs::core::{Result, SessionContext};
use asx_rs::observability::EventBus;
use asx_rs::observability::audit_sink::{
    AuditEvent, AuditSinkDurability, DurableAuditSink, ReplayCursor,
};
use asx_rs::presets::{StrictRuntimeBootstrap, StrictRuntimeBootstrapToken};
use asx_rs::reliability::ReconciliationRequest;
use asx_rs::storage::{BoxFuture, DedupStorage, DedupVerdict, ReconciliationStorage};

#[derive(Debug)]
struct TestAuditSink;

impl DurableAuditSink for TestAuditSink {
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
struct TestDedup;

impl DedupStorage for TestDedup {
    fn is_durable(&self) -> bool {
        true
    }
    fn cluster_safe(&self) -> bool {
        true
    }
    fn claim<'a>(&'a self, _key: &'a str) -> BoxFuture<'a, Result<DedupVerdict>> {
        Box::pin(async { Ok(DedupVerdict::Claimed) })
    }
    fn accept<'a>(&'a self, _key: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }
    fn abandon<'a>(&'a self, _key: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Debug)]
struct TestReconciliation;

impl ReconciliationStorage for TestReconciliation {
    fn is_durable(&self) -> bool {
        true
    }
    fn cluster_safe(&self) -> bool {
        true
    }
    fn enqueue<'a>(&'a self, _request: ReconciliationRequest) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async { Ok(true) })
    }
    fn queued_requests(&self) -> BoxFuture<'_, Result<Vec<ReconciliationRequest>>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn resolve<'a>(&'a self, _key: &'a str) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async { Ok(true) })
    }
}

/// Run the real startup gate against in-test backends and return its token.
pub(crate) fn strict_runtime_token() -> StrictRuntimeBootstrapToken {
    let bus = EventBus::new_regulated(16, Arc::new(TestAuditSink)).expect("regulated event bus");
    StrictRuntimeBootstrap::new("integration_test")
        .event_bus(&bus)
        .dedup(&TestDedup)
        .reconciliation(&TestReconciliation)
        .validate()
        .expect("startup validation")
}

/// Return `session` marked as startup-validated by a real token.
pub(crate) fn strict_bound(session: SessionContext) -> SessionContext {
    strict_runtime_token().bind(&session)
}
