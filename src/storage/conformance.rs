//! A conformance suite an embedder runs against its own storage backend.
//!
//! `is_durable()` and `cluster_safe()` are **self-declarations**. The strict
//! production startup gate can only check that the operator made a claim, never
//! that the claim is true — which leaves the crate's most load-bearing
//! integration point (replay protection, delivery evidence) resting on an
//! assertion nothing verifies.
//!
//! This module is the other half. It drives a backend through the properties
//! the protocol paths actually depend on, including the two that are easy to
//! get wrong and impossible to notice in a single-threaded smoke test:
//!
//! - **`first_seen` is atomic.** Under concurrent calls for one key, exactly one
//!   caller may see `true`. A `SELECT`-then-`INSERT` backend passes every serial
//!   test and admits duplicate business documents under load.
//! - **State survives a reconnect.** A durable backend must return the same
//!   answer through a *fresh handle*, which is as close to a process restart as
//!   a library can get.
//!
//! It cannot prove durability across a real crash, and it says so rather than
//! implying otherwise.
//!
//! # Using it
//!
//! ```no_run
//! # #[cfg(feature = "testing")]
//! # {
//! use asx_rs::storage::conformance::{DedupConformance, StorageFactory};
//! use asx_rs::storage::DedupStorage;
//! use std::sync::Arc;
//!
//! # struct MyPool;
//! # #[derive(Debug)] struct MyDedup;
//! # impl DedupStorage for MyDedup {
//! #   fn is_durable(&self) -> bool { true }
//! #   fn cluster_safe(&self) -> bool { true }
//! #   fn first_seen<'a>(&'a self, _k: &'a str) -> asx_rs::storage::BoxFuture<'a, asx_rs::Result<bool>> {
//! #     Box::pin(async { Ok(true) })
//! #   }
//! # }
//! struct MyDedupFactory(MyPool);
//!
//! impl StorageFactory<dyn DedupStorage> for MyDedupFactory {
//!     // A *fresh handle* onto the same backing store — a new connection, not a
//!     // clone of the same in-memory map.
//!     fn connect(&self) -> Arc<dyn DedupStorage> {
//!         Arc::new(MyDedup)
//!     }
//! }
//!
//! # async fn run(factory: MyDedupFactory) {
//! let report = DedupConformance::new(&factory).run().await;
//! assert!(report.passed(), "{report}");
//! # }
//! # }
//! ```

use std::fmt;
use std::sync::Arc;

use crate::core::Result;
use crate::observability::audit_sink::{
    AuditEvent, AuditMetadata, AuditSeverity, AuditSinkDurability, DurableAuditSink, ReplayCursor,
};
use crate::reliability::ReconciliationRequest;
use crate::storage::{DedupStorage, ReconciliationStorage};

/// Produces a **fresh handle onto the same backing store**.
///
/// The point is the word *fresh*: returning a clone of one in-memory map makes
/// the reconnect checks vacuous, and a backend that does so will pass this
/// suite while losing every key on restart. For a database this is a new
/// connection from the pool; for a file-backed store, a re-open.
pub trait StorageFactory<T: ?Sized> {
    /// Open a new handle onto the store.
    fn connect(&self) -> Arc<T>;
}

/// One check's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckOutcome {
    /// Stable identifier, usable in a test name or a CI filter.
    pub id: &'static str,
    /// What the check establishes, in one line.
    pub describes: &'static str,
    /// `None` when the check passed; the failure reason otherwise.
    pub failure: Option<String>,
}

impl CheckOutcome {
    fn pass(id: &'static str, describes: &'static str) -> Self {
        Self {
            id,
            describes,
            failure: None,
        }
    }

    fn fail(id: &'static str, describes: &'static str, why: impl Into<String>) -> Self {
        Self {
            id,
            describes,
            failure: Some(why.into()),
        }
    }

    /// Whether this check passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.failure.is_none()
    }
}

/// The result of running a conformance suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceReport {
    /// Which suite produced this.
    pub suite: &'static str,
    /// Every check, in execution order.
    pub checks: Vec<CheckOutcome>,
}

impl ConformanceReport {
    /// Whether every check passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.checks.iter().all(CheckOutcome::passed)
    }

    /// The checks that failed.
    #[must_use]
    pub fn failures(&self) -> Vec<&CheckOutcome> {
        self.checks.iter().filter(|c| !c.passed()).collect()
    }
}

impl fmt::Display for ConformanceReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let failed = self.failures().len();
        writeln!(
            f,
            "{}: {}/{} checks passed",
            self.suite,
            self.checks.len() - failed,
            self.checks.len()
        )?;
        for check in &self.checks {
            match &check.failure {
                None => writeln!(f, "  ok    {} — {}", check.id, check.describes)?,
                Some(why) => writeln!(
                    f,
                    "  FAIL  {} — {}\n        {why}",
                    check.id, check.describes
                )?,
            }
        }
        Ok(())
    }
}

/// Conformance suite for [`DedupStorage`].
pub struct DedupConformance<'a> {
    factory: &'a dyn StorageFactory<dyn DedupStorage>,
    key_prefix: String,
    concurrency: usize,
}

impl fmt::Debug for DedupConformance<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DedupConformance")
            .field("key_prefix", &self.key_prefix)
            .field("concurrency", &self.concurrency)
            .finish_non_exhaustive()
    }
}

impl<'a> DedupConformance<'a> {
    /// Build a suite over `factory`.
    ///
    /// Keys are prefixed with a random-ish run id so a shared test database can
    /// be reused without cross-run interference.
    #[must_use]
    pub fn new(factory: &'a dyn StorageFactory<dyn DedupStorage>) -> Self {
        Self {
            factory,
            key_prefix: format!("asx-conformance-{}", run_id()),
            concurrency: 16,
        }
    }

    /// Override the key prefix, e.g. to make failures reproducible.
    #[must_use]
    pub fn key_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = prefix.into();
        self
    }

    /// How many tasks race for one key in the atomicity check. Default 16.
    #[must_use]
    pub fn concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency.max(2);
        self
    }

    /// Run every check. Never panics; failures are reported.
    pub async fn run(&self) -> ConformanceReport {
        let mut checks = Vec::new();
        checks.push(self.first_seen_is_true_once().await);
        checks.push(self.distinct_keys_are_independent().await);
        checks.push(self.concurrent_first_seen_admits_exactly_one().await);
        checks.push(self.state_survives_a_reconnect().await);
        checks.push(self.declares_its_properties_consistently());
        ConformanceReport {
            suite: "DedupStorage",
            checks,
        }
    }

    fn key(&self, name: &str) -> String {
        format!("{}-{name}", self.key_prefix)
    }

    async fn first_seen_is_true_once(&self) -> CheckOutcome {
        const ID: &str = "dedup.first_seen_is_true_once";
        const WHAT: &str = "the same key is new once and a duplicate thereafter";
        let store = self.factory.connect();
        let key = self.key("once");

        match store.first_seen(&key).await {
            Ok(true) => {}
            Ok(false) => return CheckOutcome::fail(ID, WHAT, "a fresh key reported as duplicate"),
            Err(err) => {
                return CheckOutcome::fail(ID, WHAT, format!("first call errored: {err:?}"));
            }
        }
        match store.first_seen(&key).await {
            Ok(false) => CheckOutcome::pass(ID, WHAT),
            Ok(true) => CheckOutcome::fail(
                ID,
                WHAT,
                "a repeated key reported as new — replay protection is not working",
            ),
            Err(err) => CheckOutcome::fail(ID, WHAT, format!("second call errored: {err:?}")),
        }
    }

    async fn distinct_keys_are_independent(&self) -> CheckOutcome {
        const ID: &str = "dedup.distinct_keys_are_independent";
        const WHAT: &str = "recording one key does not mark another as seen";
        let store = self.factory.connect();
        let a = self.key("independent-a");
        let b = self.key("independent-b");

        if let Err(err) = store.first_seen(&a).await {
            return CheckOutcome::fail(ID, WHAT, format!("recording key a errored: {err:?}"));
        }
        match store.first_seen(&b).await {
            Ok(true) => CheckOutcome::pass(ID, WHAT),
            Ok(false) => CheckOutcome::fail(
                ID,
                WHAT,
                "an unrelated key reported as duplicate — keys are colliding",
            ),
            Err(err) => CheckOutcome::fail(ID, WHAT, format!("recording key b errored: {err:?}")),
        }
    }

    /// The check that separates a correct backend from a plausible one.
    ///
    /// A `SELECT`-then-`INSERT` implementation passes every serial test and
    /// admits duplicates the moment two replicas process the same message at
    /// once. The atomic forms are `INSERT … ON CONFLICT DO NOTHING`, `SET NX`,
    /// or a conditional write.
    async fn concurrent_first_seen_admits_exactly_one(&self) -> CheckOutcome {
        const ID: &str = "dedup.concurrent_first_seen_admits_exactly_one";
        const WHAT: &str = "under concurrent calls for one key, exactly one caller sees `true`";
        let key = self.key("race");

        let mut handles = Vec::with_capacity(self.concurrency);
        for _ in 0..self.concurrency {
            let store = self.factory.connect();
            let key = key.clone();
            handles.push(tokio::spawn(async move { store.first_seen(&key).await }));
        }

        let mut firsts = 0usize;
        for handle in handles {
            match handle.await {
                Ok(Ok(true)) => firsts += 1,
                Ok(Ok(false)) => {}
                Ok(Err(err)) => {
                    return CheckOutcome::fail(ID, WHAT, format!("a racing call errored: {err:?}"));
                }
                Err(err) => {
                    return CheckOutcome::fail(ID, WHAT, format!("a racing task panicked: {err}"));
                }
            }
        }

        match firsts {
            1 => CheckOutcome::pass(ID, WHAT),
            0 => CheckOutcome::fail(
                ID,
                WHAT,
                "no caller saw `true` — the key was never recorded as new",
            ),
            n => CheckOutcome::fail(
                ID,
                WHAT,
                format!(
                    "{n} of {} concurrent callers saw `true`; `first_seen` is not atomic, so \
                     {} duplicate messages would be processed under load. Use an atomic \
                     conditional write (INSERT ... ON CONFLICT DO NOTHING, SET NX)",
                    self.concurrency,
                    n - 1
                ),
            ),
        }
    }

    /// A durable backend must answer the same through a **fresh handle**.
    ///
    /// Skipped, not failed, when the backend declares itself non-durable: an
    /// in-memory store losing state on reconnect is correct behaviour.
    async fn state_survives_a_reconnect(&self) -> CheckOutcome {
        const ID: &str = "dedup.state_survives_a_reconnect";
        const WHAT: &str = "a durable backend still reports a duplicate through a fresh handle";
        let first = self.factory.connect();
        if !first.is_durable() {
            return CheckOutcome::pass(
                ID,
                "skipped: backend declares is_durable() == false, so losing state is correct",
            );
        }
        let key = self.key("reconnect");
        if let Err(err) = first.first_seen(&key).await {
            return CheckOutcome::fail(ID, WHAT, format!("recording errored: {err:?}"));
        }
        drop(first);

        let reconnected = self.factory.connect();
        match reconnected.first_seen(&key).await {
            Ok(false) => CheckOutcome::pass(ID, WHAT),
            Ok(true) => CheckOutcome::fail(
                ID,
                WHAT,
                "the key was forgotten by a fresh handle — this backend declares \
                 is_durable() == true but does not persist. RFC 4130 §5.2.1 wants a \
                 48-hour replay window; this one does not survive a reconnect",
            ),
            Err(err) => CheckOutcome::fail(ID, WHAT, format!("reconnected call errored: {err:?}")),
        }
    }

    fn declares_its_properties_consistently(&self) -> CheckOutcome {
        const ID: &str = "dedup.declares_its_properties_consistently";
        const WHAT: &str = "cluster_safe() implies is_durable()";
        let store = self.factory.connect();
        if store.cluster_safe() && !store.is_durable() {
            return CheckOutcome::fail(
                ID,
                WHAT,
                "cluster_safe() == true with is_durable() == false: a store shared across \
                 replicas is by definition out of process, so it cannot be non-durable",
            );
        }
        CheckOutcome::pass(ID, WHAT)
    }
}

/// Conformance suite for [`ReconciliationStorage`].
pub struct ReconciliationConformance<'a> {
    factory: &'a dyn StorageFactory<dyn ReconciliationStorage>,
    partner_id: String,
}

impl fmt::Debug for ReconciliationConformance<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReconciliationConformance")
            .field("partner_id", &self.partner_id)
            .finish_non_exhaustive()
    }
}

impl<'a> ReconciliationConformance<'a> {
    /// Build a suite over `factory`.
    #[must_use]
    pub fn new(factory: &'a dyn StorageFactory<dyn ReconciliationStorage>) -> Self {
        Self {
            factory,
            partner_id: format!("asx-conformance-{}", run_id()),
        }
    }

    /// Override the partner id used to scope the test records.
    #[must_use]
    pub fn partner_id(mut self, partner_id: impl Into<String>) -> Self {
        self.partner_id = partner_id.into();
        self
    }

    /// Run every check. Never panics; failures are reported.
    pub async fn run(&self) -> ConformanceReport {
        let mut checks = Vec::new();
        checks.push(self.enqueued_requests_are_queued().await);
        checks.push(self.resolve_removes_exactly_one().await);
        checks.push(self.resolving_an_unknown_key_is_false().await);
        checks.push(self.state_survives_a_reconnect().await);
        ConformanceReport {
            suite: "ReconciliationStorage",
            checks,
        }
    }

    fn request(&self, message_id: &str) -> Result<ReconciliationRequest> {
        ReconciliationRequest::new_indeterminate(message_id, &self.partner_id)
    }

    async fn enqueued_requests_are_queued(&self) -> CheckOutcome {
        const ID: &str = "reconciliation.enqueued_requests_are_queued";
        const WHAT: &str = "an enqueued request is returned by queued_requests()";
        let store = self.factory.connect();
        let request = match self.request("conformance-queued") {
            Ok(r) => r,
            Err(err) => return CheckOutcome::fail(ID, WHAT, format!("bad fixture: {err:?}")),
        };
        let key = request.idempotency_key.clone();

        if let Err(err) = store.enqueue(request).await {
            return CheckOutcome::fail(ID, WHAT, format!("enqueue errored: {err:?}"));
        }
        match store.queued_requests().await {
            Ok(queued) if queued.iter().any(|r| r.idempotency_key == key) => {
                CheckOutcome::pass(ID, WHAT)
            }
            Ok(_) => CheckOutcome::fail(
                ID,
                WHAT,
                "the enqueued request is not in queued_requests(); a message awaiting an \
                 async MDN or receipt would never be followed up",
            ),
            Err(err) => CheckOutcome::fail(ID, WHAT, format!("queued_requests errored: {err:?}")),
        }
    }

    async fn resolve_removes_exactly_one(&self) -> CheckOutcome {
        const ID: &str = "reconciliation.resolve_removes_exactly_one";
        const WHAT: &str = "resolve() removes its own record and leaves the others";
        let store = self.factory.connect();
        let (keep, drop_it) = match (
            self.request("conformance-keep"),
            self.request("conformance-drop"),
        ) {
            (Ok(a), Ok(b)) => (a, b),
            _ => return CheckOutcome::fail(ID, WHAT, "bad fixture"),
        };
        let keep_key = keep.idempotency_key.clone();
        let drop_key = drop_it.idempotency_key.clone();

        if store.enqueue(keep).await.is_err() || store.enqueue(drop_it).await.is_err() {
            return CheckOutcome::fail(ID, WHAT, "enqueue errored");
        }
        match store.resolve(&drop_key).await {
            Ok(true) => {}
            Ok(false) => {
                return CheckOutcome::fail(
                    ID,
                    WHAT,
                    "resolve() reported no such key after enqueue",
                );
            }
            Err(err) => return CheckOutcome::fail(ID, WHAT, format!("resolve errored: {err:?}")),
        }
        match store.queued_requests().await {
            Ok(queued) => {
                let dropped_gone = !queued.iter().any(|r| r.idempotency_key == drop_key);
                let kept_present = queued.iter().any(|r| r.idempotency_key == keep_key);
                if dropped_gone && kept_present {
                    CheckOutcome::pass(ID, WHAT)
                } else if !dropped_gone {
                    CheckOutcome::fail(ID, WHAT, "the resolved record is still queued")
                } else {
                    CheckOutcome::fail(
                        ID,
                        WHAT,
                        "resolve() removed an unrelated record — a message still awaiting \
                         confirmation was silently dropped",
                    )
                }
            }
            Err(err) => CheckOutcome::fail(ID, WHAT, format!("queued_requests errored: {err:?}")),
        }
    }

    async fn resolving_an_unknown_key_is_false(&self) -> CheckOutcome {
        const ID: &str = "reconciliation.resolving_an_unknown_key_is_false";
        const WHAT: &str = "resolve() on an unknown key returns Ok(false), not an error";
        let store = self.factory.connect();
        match store
            .resolve("asx-conformance-key-that-was-never-enqueued")
            .await
        {
            Ok(false) => CheckOutcome::pass(ID, WHAT),
            Ok(true) => CheckOutcome::fail(ID, WHAT, "reported success for a key never enqueued"),
            Err(err) => CheckOutcome::fail(
                ID,
                WHAT,
                format!(
                    "errored instead of returning Ok(false): {err:?}. A late duplicate \
                     confirmation is ordinary, not exceptional"
                ),
            ),
        }
    }

    async fn state_survives_a_reconnect(&self) -> CheckOutcome {
        const ID: &str = "reconciliation.state_survives_a_reconnect";
        const WHAT: &str = "a durable backend still lists the request through a fresh handle";
        let first = self.factory.connect();
        if !first.is_durable() {
            return CheckOutcome::pass(
                ID,
                "skipped: backend declares is_durable() == false, so losing state is correct",
            );
        }
        let request = match self.request("conformance-reconnect") {
            Ok(r) => r,
            Err(err) => return CheckOutcome::fail(ID, WHAT, format!("bad fixture: {err:?}")),
        };
        let key = request.idempotency_key.clone();
        if let Err(err) = first.enqueue(request).await {
            return CheckOutcome::fail(ID, WHAT, format!("enqueue errored: {err:?}"));
        }
        drop(first);

        let reconnected = self.factory.connect();
        match reconnected.queued_requests().await {
            Ok(queued) if queued.iter().any(|r| r.idempotency_key == key) => {
                CheckOutcome::pass(ID, WHAT)
            }
            Ok(_) => CheckOutcome::fail(
                ID,
                WHAT,
                "the request was forgotten by a fresh handle — this backend declares \
                 is_durable() == true but does not persist. A crash would lose every \
                 message awaiting confirmation, which is exactly the evidence the queue exists \
                 to keep",
            ),
            Err(err) => CheckOutcome::fail(ID, WHAT, format!("queued_requests errored: {err:?}")),
        }
    }
}

/// A per-run discriminator so a shared test store can be reused.
fn run_id() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

// ── DurableAuditSink ────────────────────────────────────────────────────────

/// Conformance suite for [`DurableAuditSink`].
///
/// The audit trail is *evidence* in these networks, and its durability was the
/// last of the three storage traits resting on a self-declaration
/// ([ROADMAP.md] C3/N8). The checks here are the ones a regulated deployment
/// actually depends on: an event that was stored can be read back, replay
/// resumes from a cursor rather than restarting, the cursor survives a
/// reconnect, and a tampered cursor is refused by a sink that claims to
/// protect them.
///
/// [ROADMAP.md]: https://github.com/hupe1980/asx-rs
pub struct AuditSinkConformance<'a> {
    factory: &'a dyn StorageFactory<dyn DurableAuditSink>,
    prefix: String,
}

impl fmt::Debug for AuditSinkConformance<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditSinkConformance")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl<'a> AuditSinkConformance<'a> {
    /// Build a suite over `factory`.
    #[must_use]
    pub fn new(factory: &'a dyn StorageFactory<dyn DurableAuditSink>) -> Self {
        Self {
            factory,
            prefix: format!("asx-conformance-{}", run_id()),
        }
    }

    /// Override the event-id prefix used to scope the test records.
    #[must_use]
    pub fn event_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Run every check. Never panics; failures are reported.
    pub async fn run(&self) -> ConformanceReport {
        let mut checks = vec![
            self.stored_events_are_readable(),
            self.replay_resumes_from_the_cursor(),
            self.cursor_advances_with_stored_events(),
            self.state_survives_a_reconnect(),
            self.tampered_cursors_are_refused(),
        ];
        if let Some(check) = self.durability_claim_is_consistent() {
            checks.push(check);
        }
        ConformanceReport {
            suite: "DurableAuditSink",
            checks,
        }
    }

    fn event(&self, suffix: &str, position: u64) -> AuditEvent {
        AuditEvent {
            event_id: format!("{}-{suffix}", self.prefix),
            session_id: Some(format!("{}-session", self.prefix)),
            partner_id: Some(format!("{}-partner", self.prefix)),
            code: "conformance_probe".to_string(),
            timestamp: position,
            message: format!("conformance probe {suffix}"),
            metadata: AuditMetadata {
                stage: Some("storage_conformance".to_string()),
                severity: AuditSeverity::Low,
                action: Some("probe".to_string()),
                result: Some("ok".to_string()),
            },
        }
    }

    fn stored_events_are_readable(&self) -> CheckOutcome {
        const ID: &str = "audit_sink.stored_events_are_readable";
        const WHAT: &str =
            "an event that store_event() accepted comes back from retrieve_events_from()";
        let sink = self.factory.connect();
        let event = self.event("readable", 1);

        if let Err(err) = sink.store_event(&event) {
            return CheckOutcome::fail(ID, WHAT, format!("store_event errored: {err:?}"));
        }
        match sink.retrieve_events_from(&ReplayCursor::unsigned_start(), 128) {
            Ok(events) if events.iter().any(|e| e.event_id == event.event_id) => {
                CheckOutcome::pass(ID, WHAT)
            }
            Ok(_) => CheckOutcome::fail(
                ID,
                WHAT,
                "the stored event is not readable from the bootstrap cursor; the audit trail \
                 accepts writes it cannot produce as evidence",
            ),
            Err(err) => CheckOutcome::fail(ID, WHAT, format!("retrieve errored: {err:?}")),
        }
    }

    fn replay_resumes_from_the_cursor(&self) -> CheckOutcome {
        const ID: &str = "audit_sink.replay_resumes_from_the_cursor";
        const WHAT: &str = "replay from a cursor returns what followed it, not the whole log";
        let sink = self.factory.connect();
        let first = self.event("resume-1", 1);
        let second = self.event("resume-2", 2);

        for event in [&first, &second] {
            if let Err(err) = sink.store_event(event) {
                return CheckOutcome::fail(ID, WHAT, format!("store_event errored: {err:?}"));
            }
        }

        // Acknowledge the first, then replay: only the second should appear.
        let after_first = match sink.retrieve_events_from(&ReplayCursor::unsigned_start(), 1) {
            Ok(events) if events.len() == 1 => events,
            Ok(events) => {
                return CheckOutcome::fail(
                    ID,
                    WHAT,
                    format!(
                        "a limit of 1 returned {} events; the limit is what bounds a replay of a large trail",
                        events.len()
                    ),
                );
            }
            Err(err) => return CheckOutcome::fail(ID, WHAT, format!("retrieve errored: {err:?}")),
        };

        let cursor = match sink.current_cursor() {
            Ok(cursor) => cursor,
            Err(err) => {
                return CheckOutcome::fail(ID, WHAT, format!("current_cursor errored: {err:?}"));
            }
        };
        if let Err(err) = sink.acknowledge_cursor(&cursor) {
            return CheckOutcome::fail(ID, WHAT, format!("acknowledge_cursor errored: {err:?}"));
        }

        match sink.retrieve_events_from(&cursor, 128) {
            Ok(events) => {
                if events.iter().any(|e| e.event_id == after_first[0].event_id) {
                    CheckOutcome::fail(
                        ID,
                        WHAT,
                        "replaying from a cursor re-delivered an event at or before it; a \
                         consumer resuming after a restart would process the trail twice",
                    )
                } else {
                    CheckOutcome::pass(ID, WHAT)
                }
            }
            Err(err) => CheckOutcome::fail(ID, WHAT, format!("retrieve errored: {err:?}")),
        }
    }

    fn cursor_advances_with_stored_events(&self) -> CheckOutcome {
        const ID: &str = "audit_sink.cursor_advances_with_stored_events";
        const WHAT: &str = "current_cursor() moves forward as events are stored";
        let sink = self.factory.connect();
        let before = match sink.current_cursor() {
            Ok(cursor) => cursor,
            Err(err) => {
                return CheckOutcome::fail(ID, WHAT, format!("current_cursor errored: {err:?}"));
            }
        };
        if let Err(err) = sink.store_event(&self.event("advance", 1)) {
            return CheckOutcome::fail(ID, WHAT, format!("store_event errored: {err:?}"));
        }
        match sink.current_cursor() {
            Ok(after) if after.position > before.position => CheckOutcome::pass(ID, WHAT),
            Ok(after) => CheckOutcome::fail(
                ID,
                WHAT,
                format!(
                    "position stayed at {} after a store; a consumer has no way to tell that \
                     new evidence exists",
                    after.position
                ),
            ),
            Err(err) => CheckOutcome::fail(ID, WHAT, format!("current_cursor errored: {err:?}")),
        }
    }

    fn state_survives_a_reconnect(&self) -> CheckOutcome {
        const ID: &str = "audit_sink.state_survives_a_reconnect";
        const WHAT: &str = "events and cursor position are visible through a fresh handle";
        let event = self.event("reconnect", 1);
        {
            let sink = self.factory.connect();
            if let Err(err) = sink.store_event(&event) {
                return CheckOutcome::fail(ID, WHAT, format!("store_event errored: {err:?}"));
            }
        }
        let reconnected = self.factory.connect();
        if reconnected.durability() != AuditSinkDurability::Durable {
            return CheckOutcome::pass(
                ID,
                "sink declares itself ephemeral; reconnect is not required",
            );
        }
        match reconnected.retrieve_events_from(&ReplayCursor::unsigned_start(), 128) {
            Ok(events) if events.iter().any(|e| e.event_id == event.event_id) => {
                CheckOutcome::pass(ID, WHAT)
            }
            Ok(_) => CheckOutcome::fail(
                ID,
                WHAT,
                "a Durable sink lost the event across a fresh handle. This is the check a \
                 backend keeping state in process memory fails, and it is the whole basis of \
                 the durability declaration the startup gate accepts",
            ),
            Err(err) => CheckOutcome::fail(ID, WHAT, format!("retrieve errored: {err:?}")),
        }
    }

    fn tampered_cursors_are_refused(&self) -> CheckOutcome {
        const ID: &str = "audit_sink.tampered_cursors_are_refused";
        const WHAT: &str = "a sink claiming cursor integrity protection rejects an edited cursor";
        let sink = self.factory.connect();
        if !sink.has_replay_cursor_integrity_protection() {
            return CheckOutcome::pass(
                ID,
                "sink declares no cursor integrity protection; nothing to check",
            );
        }
        if let Err(err) = sink.store_event(&self.event("tamper", 1)) {
            return CheckOutcome::fail(ID, WHAT, format!("store_event errored: {err:?}"));
        }
        let mut cursor = match sink.current_cursor() {
            Ok(cursor) => cursor,
            Err(err) => {
                return CheckOutcome::fail(ID, WHAT, format!("current_cursor errored: {err:?}"));
            }
        };
        cursor.position = cursor.position.wrapping_add(1_000);
        cursor.last_event_id = format!("{}-forged", cursor.last_event_id);

        match sink.verify_replay_cursor_integrity(&cursor) {
            Err(_) => CheckOutcome::pass(ID, WHAT),
            Ok(()) => CheckOutcome::fail(
                ID,
                WHAT,
                "an edited cursor verified. A cursor is what a consumer presents to say how \
                 far it has read; if it can be forged, so can a claim to have processed the \
                 trail",
            ),
        }
    }

    /// A sink that declares itself `Durable` and its cursors unprotected is not
    /// a contradiction, but the combination is worth surfacing: the startup
    /// gate accepts the durability claim, and nothing then guards the cursor.
    fn durability_claim_is_consistent(&self) -> Option<CheckOutcome> {
        const ID: &str = "audit_sink.durability_claim_is_consistent";
        const WHAT: &str = "a Durable sink protects its replay cursors";
        let sink = self.factory.connect();
        if sink.durability() != AuditSinkDurability::Durable {
            return None;
        }
        if sink.has_replay_cursor_integrity_protection() {
            Some(CheckOutcome::pass(ID, WHAT))
        } else {
            Some(CheckOutcome::fail(
                ID,
                WHAT,
                "the sink is declared Durable but its replay cursors carry no integrity tag, \
                 so a cursor read back from storage cannot be distinguished from one an \
                 attacker wrote",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{BoxFuture, InMemoryDedupStorage};
    use std::collections::HashSet;
    use std::sync::Mutex;

    /// A shared in-memory store handed out as "fresh" handles, so the reconnect
    /// checks see the same state — the closest stand-in for a real database.
    #[derive(Debug, Default)]
    struct SharedDedup {
        seen: Mutex<HashSet<String>>,
        durable: bool,
    }

    impl DedupStorage for SharedDedup {
        fn is_durable(&self) -> bool {
            self.durable
        }
        fn cluster_safe(&self) -> bool {
            self.durable
        }
        fn first_seen<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async move {
                let mut seen = self.seen.lock().map_err(|_| {
                    crate::core::AsxError::new(
                        crate::core::ErrorCode::ReliabilityFailure,
                        "poisoned",
                        crate::core::ErrorContext::new("test"),
                    )
                })?;
                Ok(seen.insert(key.to_string()))
            })
        }
    }

    struct SharedFactory(Arc<SharedDedup>);

    impl StorageFactory<dyn DedupStorage> for SharedFactory {
        fn connect(&self) -> Arc<dyn DedupStorage> {
            self.0.clone()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_correct_backend_passes_every_check() {
        let factory = SharedFactory(Arc::new(SharedDedup {
            durable: true,
            ..Default::default()
        }));
        let report = DedupConformance::new(&factory).run().await;
        assert!(report.passed(), "{report}");
    }

    /// A backend that claims durability but forgets on reconnect must fail —
    /// otherwise the suite would rubber-stamp exactly the class of backend the
    /// startup gate cannot detect.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_backend_that_lies_about_durability_fails() {
        #[derive(Debug)]
        struct ForgetfulButClaimsDurable;
        impl DedupStorage for ForgetfulButClaimsDurable {
            fn is_durable(&self) -> bool {
                true
            }
            fn first_seen<'a>(&'a self, _key: &'a str) -> BoxFuture<'a, Result<bool>> {
                Box::pin(async { Ok(true) }) // always "new"
            }
        }
        struct Factory;
        impl StorageFactory<dyn DedupStorage> for Factory {
            fn connect(&self) -> Arc<dyn DedupStorage> {
                Arc::new(ForgetfulButClaimsDurable)
            }
        }

        let report = DedupConformance::new(&Factory).run().await;
        assert!(!report.passed(), "a forgetful backend must not pass");
        let failed: Vec<_> = report.failures().iter().map(|c| c.id).collect();
        assert!(
            failed.contains(&"dedup.first_seen_is_true_once"),
            "{report}"
        );
        assert!(
            failed.contains(&"dedup.state_survives_a_reconnect"),
            "{report}"
        );
    }

    /// The atomicity check must actually catch a non-atomic implementation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_non_atomic_backend_fails_the_race_check() {
        #[derive(Debug, Default)]
        struct CheckThenSet {
            seen: Mutex<HashSet<String>>,
        }
        impl DedupStorage for CheckThenSet {
            fn is_durable(&self) -> bool {
                false
            }
            fn first_seen<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<bool>> {
                Box::pin(async move {
                    // The classic SELECT-then-INSERT: correct serially, wrong
                    // the moment two callers interleave at the await point.
                    let already = self
                        .seen
                        .lock()
                        .map(|s| s.contains(key))
                        .unwrap_or_default();
                    tokio::task::yield_now().await;
                    if already {
                        return Ok(false);
                    }
                    if let Ok(mut s) = self.seen.lock() {
                        s.insert(key.to_string());
                    }
                    Ok(true)
                })
            }
        }
        struct Factory(Arc<CheckThenSet>);
        impl StorageFactory<dyn DedupStorage> for Factory {
            fn connect(&self) -> Arc<dyn DedupStorage> {
                self.0.clone()
            }
        }

        let report = DedupConformance::new(&Factory(Arc::new(CheckThenSet::default())))
            .concurrency(32)
            .run()
            .await;

        let failed: Vec<_> = report.failures().iter().map(|c| c.id).collect();
        assert!(
            failed.contains(&"dedup.concurrent_first_seen_admits_exactly_one"),
            "a SELECT-then-INSERT backend must fail the race check: {report}"
        );
    }

    /// The crate's own in-memory backend must pass everything that applies to a
    /// non-durable store.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_in_tree_in_memory_dedup_conforms() {
        struct Factory(Arc<InMemoryDedupStorage>);
        impl StorageFactory<dyn DedupStorage> for Factory {
            fn connect(&self) -> Arc<dyn DedupStorage> {
                self.0.clone()
            }
        }
        let report = DedupConformance::new(&Factory(Arc::new(InMemoryDedupStorage::default())))
            .run()
            .await;
        assert!(report.passed(), "{report}");
    }

    /// Every in-tree `DedupStorage` must pass its own suite. If one of these
    /// ever fails, the crate is shipping a backend it tells embedders not to
    /// write.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn every_in_tree_dedup_backend_conforms() {
        use crate::storage::memory::{
            BoundedFifoDedupStorage, DurableInMemoryDedupBackend, TtlDedupStorage,
        };
        use std::time::Duration;

        struct Factory(Arc<dyn DedupStorage>);
        impl StorageFactory<dyn DedupStorage> for Factory {
            fn connect(&self) -> Arc<dyn DedupStorage> {
                self.0.clone()
            }
        }

        let backends: Vec<(&str, Arc<dyn DedupStorage>)> = vec![
            (
                "InMemoryDedupStorage",
                Arc::new(InMemoryDedupStorage::default()),
            ),
            (
                "BoundedFifoDedupStorage",
                Arc::new(BoundedFifoDedupStorage::new(1024)),
            ),
            (
                "TtlDedupStorage",
                Arc::new(TtlDedupStorage::new(Duration::from_secs(48 * 3600))),
            ),
            (
                "DurableInMemoryDedupBackend",
                Arc::new(DurableInMemoryDedupBackend::new(Duration::from_secs(
                    48 * 3600,
                ))),
            ),
        ];

        for (name, backend) in backends {
            let report = DedupConformance::new(&Factory(backend)).run().await;
            assert!(report.passed(), "{name} does not conform:\n{report}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_in_tree_reconciliation_store_conforms() {
        use crate::storage::InMemoryReconciliationStorage;
        struct Factory(Arc<InMemoryReconciliationStorage>);
        impl StorageFactory<dyn ReconciliationStorage> for Factory {
            fn connect(&self) -> Arc<dyn ReconciliationStorage> {
                self.0.clone()
            }
        }
        let report = ReconciliationConformance::new(&Factory(Arc::new(
            InMemoryReconciliationStorage::default(),
        )))
        .run()
        .await;
        assert!(report.passed(), "{report}");
    }

    // ── DurableAuditSink suite ──────────────────────────────────────────

    /// A shared in-memory sink handed out as "fresh" handles, standing in for a
    /// real durable store.
    #[derive(Debug)]
    struct SharedAuditSink {
        inner: crate::observability::audit_sink::InMemoryAuditSink,
    }

    impl DurableAuditSink for SharedAuditSink {
        fn durability(&self) -> AuditSinkDurability {
            AuditSinkDurability::Durable
        }
        fn has_replay_cursor_integrity_protection(&self) -> bool {
            self.inner.has_replay_cursor_integrity_protection()
        }
        fn store_event(&self, event: &AuditEvent) -> Result<()> {
            self.inner.store_event(event)
        }
        fn retrieve_events_from(
            &self,
            cursor: &ReplayCursor,
            limit: usize,
        ) -> Result<Vec<AuditEvent>> {
            self.inner.retrieve_events_from(cursor, limit)
        }
        fn current_cursor(&self) -> Result<ReplayCursor> {
            self.inner.current_cursor()
        }
        fn verify_replay_cursor_integrity(&self, cursor: &ReplayCursor) -> Result<()> {
            self.inner.verify_replay_cursor_integrity(cursor)
        }
        fn acknowledge_cursor(&self, cursor: &ReplayCursor) -> Result<()> {
            self.inner.acknowledge_cursor(cursor)
        }
        fn clear(&self) -> Result<()> {
            self.inner.clear()
        }
    }

    struct SharedAuditFactory(Arc<SharedAuditSink>);
    impl StorageFactory<dyn DurableAuditSink> for SharedAuditFactory {
        fn connect(&self) -> Arc<dyn DurableAuditSink> {
            self.0.clone()
        }
    }

    #[tokio::test]
    async fn the_in_tree_audit_sink_conforms() {
        let sink = Arc::new(SharedAuditSink {
            inner: crate::observability::audit_sink::InMemoryAuditSink::new()
                .expect("in-memory audit sink"),
        });
        let report = AuditSinkConformance::new(&SharedAuditFactory(sink))
            .run()
            .await;
        assert!(report.passed(), "{report}");
    }

    /// A sink that hands out an independent store per handle loses everything
    /// on reconnect — which is what a process restart looks like — while still
    /// declaring itself `Durable`. The suite must say so, or it is the same
    /// unverified assertion it exists to replace.
    #[tokio::test]
    async fn a_sink_that_loses_state_across_handles_fails() {
        struct FreshEveryTime;
        impl StorageFactory<dyn DurableAuditSink> for FreshEveryTime {
            fn connect(&self) -> Arc<dyn DurableAuditSink> {
                Arc::new(SharedAuditSink {
                    inner: crate::observability::audit_sink::InMemoryAuditSink::new()
                        .expect("in-memory audit sink"),
                })
            }
        }
        let report = AuditSinkConformance::new(&FreshEveryTime).run().await;
        assert!(
            !report.passed(),
            "a sink that forgets on reconnect must fail"
        );
        assert!(
            report
                .failures()
                .iter()
                .any(|c| c.id == "audit_sink.state_survives_a_reconnect"),
            "{report}"
        );
    }

    /// A sink that claims cursor integrity protection and accepts an edited
    /// cursor must fail: a forged cursor is a forged claim to have read the
    /// trail.
    #[tokio::test]
    async fn a_sink_that_accepts_a_forged_cursor_fails() {
        #[derive(Debug)]
        struct ForgivingCursors(crate::observability::audit_sink::InMemoryAuditSink);
        impl DurableAuditSink for ForgivingCursors {
            fn durability(&self) -> AuditSinkDurability {
                AuditSinkDurability::Durable
            }
            fn has_replay_cursor_integrity_protection(&self) -> bool {
                true
            }
            fn store_event(&self, event: &AuditEvent) -> Result<()> {
                self.0.store_event(event)
            }
            fn retrieve_events_from(
                &self,
                cursor: &ReplayCursor,
                limit: usize,
            ) -> Result<Vec<AuditEvent>> {
                self.0.retrieve_events_from(cursor, limit)
            }
            fn current_cursor(&self) -> Result<ReplayCursor> {
                self.0.current_cursor()
            }
            fn verify_replay_cursor_integrity(&self, _cursor: &ReplayCursor) -> Result<()> {
                Ok(())
            }
            fn acknowledge_cursor(&self, cursor: &ReplayCursor) -> Result<()> {
                self.0.acknowledge_cursor(cursor)
            }
            fn clear(&self) -> Result<()> {
                self.0.clear()
            }
        }
        struct Factory(Arc<ForgivingCursors>);
        impl StorageFactory<dyn DurableAuditSink> for Factory {
            fn connect(&self) -> Arc<dyn DurableAuditSink> {
                self.0.clone()
            }
        }
        let sink = Arc::new(ForgivingCursors(
            crate::observability::audit_sink::InMemoryAuditSink::new().expect("sink"),
        ));
        let report = AuditSinkConformance::new(&Factory(sink)).run().await;
        assert!(!report.passed(), "a forgeable cursor must fail");
        assert!(
            report
                .failures()
                .iter()
                .any(|c| c.id == "audit_sink.tampered_cursors_are_refused"),
            "{report}"
        );
    }
}
