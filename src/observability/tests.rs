use super::*;
use crate::observability::audit_sink::{InMemoryAuditSink, ReplayCursor};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::{Duration, timeout};

fn session(session_id: &str, partner_id: &str) -> SessionContext {
    SessionContext::new(session_id, partner_id, "strict").expect("session context")
}

#[derive(Debug, Default)]
struct RecordingMetricsSink {
    counters: Mutex<Vec<RecordedCounter>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedCounter {
    name: &'static str,
    value: u64,
    labels: Vec<(&'static str, String)>,
}

impl MetricsSink for RecordingMetricsSink {
    fn increment_counter(&self, name: &'static str, value: u64, labels: &[(&'static str, &str)]) {
        let mut counters = self.counters.lock().expect("metrics lock");
        counters.push(RecordedCounter {
            name,
            value,
            labels: labels.iter().map(|(k, v)| (*k, (*v).to_string())).collect(),
        });
    }

    fn record_histogram(&self, _name: &'static str, _value: f64, _labels: &[(&'static str, &str)]) {
    }

    fn set_gauge(&self, _name: &'static str, _value: f64, _labels: &[(&'static str, &str)]) {}
}

#[tokio::test]
async fn scoped_stream_contains_session_ids() {
    let bus = EventBus::new(16).expect("event bus");
    let mut rx = bus.subscribe_scoped_events();
    let s1 = session("s1", "p1");

    bus.emit(
        &s1,
        AsxEvent::MessageSigned {
            message_id: "m1".into(),
        },
    )
    .expect("emit");

    let evt = timeout(Duration::from_millis(200), rx.recv())
        .await
        .expect("timely recv")
        .expect("broadcast recv");
    assert_eq!(evt.session_id, "s1");
    assert_eq!(evt.partner_id, "p1");
}

#[tokio::test]
async fn session_subscription_does_not_leak_other_sessions() {
    let bus = EventBus::new(16).expect("event bus");
    let _scoped = bus.subscribe_scoped_events();
    let mut s1_rx = bus.subscribe_session_events("s1").expect("subscribe s1");
    let s1 = session("s1", "p1");
    let s2 = session("s2", "p2");

    bus.emit(
        &s2,
        AsxEvent::MessageSigned {
            message_id: "m2".into(),
        },
    )
    .expect("emit s2");

    bus.emit(
        &s1,
        AsxEvent::MessageSigned {
            message_id: "m1".into(),
        },
    )
    .expect("emit s1");

    let received = timeout(Duration::from_millis(200), s1_rx.recv())
        .await
        .expect("timely recv")
        .expect("event present");

    // Session subscription delivers raw AsxEvent; session isolation is the focus.
    // partner_id is available on ScopedAsxEvent from subscribe_scoped_events().
    match received.as_ref() {
        AsxEvent::MessageSigned { message_id } => {
            assert_eq!(message_id.as_ref(), "m1");
        }
        _ => panic!("unexpected event variant"),
    }
}

#[tokio::test]
async fn ordering_is_preserved_per_session() {
    let bus = EventBus::new(32).expect("event bus");
    let _scoped = bus.subscribe_scoped_events();
    let mut rx = bus.subscribe_session_events("s1").expect("subscribe s1");
    let s1 = session("s1", "p1");

    for i in 0..5 {
        bus.emit(
            &s1,
            AsxEvent::RetryScheduled {
                message_id: format!("m{i}").into(),
                attempt: i,
                reason: "transient",
            },
        )
        .expect("emit ordered event");
    }

    for expected in 0..5 {
        let evt = timeout(Duration::from_millis(200), rx.recv())
            .await
            .expect("timely recv")
            .expect("event present");
        match evt.as_ref() {
            AsxEvent::RetryScheduled { attempt, .. } => assert_eq!(*attempt, expected),
            _ => panic!("unexpected event variant"),
        }
    }
}

#[tokio::test]
async fn session_fanout_reuses_shared_event_handle() {
    let bus = EventBus::new(16).expect("event bus");
    let _scoped = bus.subscribe_scoped_events();
    let s1 = session("s1", "p1");
    let mut rx_a = bus.subscribe_session_events("s1").expect("subscribe a");
    let mut rx_b = bus.subscribe_session_events("s1").expect("subscribe b");

    bus.emit(
        &s1,
        AsxEvent::MessageSigned {
            message_id: "m1".into(),
        },
    )
    .expect("emit");

    let a = timeout(Duration::from_millis(200), rx_a.recv())
        .await
        .expect("timely recv a")
        .expect("event a");
    let b = timeout(Duration::from_millis(200), rx_b.recv())
        .await
        .expect("timely recv b")
        .expect("event b");

    assert!(
        Arc::ptr_eq(&a, &b),
        "fanout should share one event allocation across subscribers"
    );
}

#[test]
fn strict_mode_rejects_no_subscribers() {
    let bus = EventBus::new(16).expect("event bus");
    let sess = session("s-no-subscriber", "p1");

    let err = bus
        .emit(
            &sess,
            AsxEvent::MessageSigned {
                message_id: "m1".into(),
            },
        )
        .expect_err("strict mode must fail when no subscribers");

    assert_eq!(bus.emission_mode(), EventEmissionMode::StrictTransactional);
    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
    assert_eq!(bus.metrics().dropped(), 1);
}

#[test]
fn strict_constructors_default_to_transactional_mode() {
    let strict = EventBus::new(16).expect("strict bus");
    assert_eq!(
        strict.emission_mode(),
        EventEmissionMode::StrictTransactional
    );

    let strict_with_config = EventBus::new_with_config_and_mode(
        16,
        None,
        BackpressurePolicy::default(),
        EventEmissionMode::StrictTransactional,
    )
    .expect("strict config bus");
    assert_eq!(
        strict_with_config.emission_mode(),
        EventEmissionMode::StrictTransactional
    );

    let strict_with_metrics = EventBus::new_with_config_and_mode_and_metrics(
        16,
        None,
        BackpressurePolicy::default(),
        EventEmissionMode::StrictTransactional,
        Arc::new(NoopMetricsSink),
    )
    .expect("strict metrics bus");
    assert_eq!(
        strict_with_metrics.emission_mode(),
        EventEmissionMode::StrictTransactional
    );

    let strict_with_durable = EventBus::new_with_config_and_mode(
        16,
        Some(Arc::new(InMemoryAuditSink::new().expect("audit sink"))),
        BackpressurePolicy::default(),
        EventEmissionMode::StrictTransactional,
    )
    .expect("strict durable bus");
    assert_eq!(
        strict_with_durable.emission_mode(),
        EventEmissionMode::StrictTransactional
    );
}

#[test]
fn best_effort_mode_tracks_drop_without_failing() {
    let bus = EventBus::new_with_config_and_mode(
        16,
        None,
        BackpressurePolicy::default(),
        EventEmissionMode::BestEffort,
    )
    .expect("event bus");
    let sess = session("s-best-effort", "p1");

    bus.emit(
        &sess,
        AsxEvent::MessageSigned {
            message_id: "m1".into(),
        },
    )
    .expect("best-effort mode should not fail when no subscribers are active");

    assert_eq!(bus.emission_mode(), EventEmissionMode::BestEffort);
    assert_eq!(bus.metrics().dropped(), 1);
}

#[test]
fn emit_does_not_fail_under_subscription_churn() {
    let bus = EventBus::new(16).expect("event bus");
    let _scoped = bus.subscribe_scoped_events();
    let sess = session("s-lock-contention", "p1");
    let _sub = bus
        .subscribe_session_events("s-lock-contention")
        .expect("subscribe session");

    bus.emit(
        &sess,
        AsxEvent::MessageSigned {
            message_id: "m1".into(),
        },
    )
    .expect("emit should not fail from registry contention");
}

#[test]
fn subscribe_succeeds_during_parallel_emits() {
    let bus = EventBus::new_with_config_and_mode(
        16,
        None,
        BackpressurePolicy::default(),
        EventEmissionMode::BestEffort,
    )
    .expect("event bus");
    let _scoped = bus.subscribe_scoped_events();
    let sess = session("s-lock-contention", "p1");

    // Seed one subscription so emit takes the session path while we add another.
    let _sub_a = bus
        .subscribe_session_events("s-lock-contention")
        .expect("subscribe A");

    for _ in 0..32 {
        bus.emit(
            &sess,
            AsxEvent::MessageSigned {
                message_id: "m1".into(),
            },
        )
        .expect("emit under churn");

        let _sub_b = bus
            .subscribe_session_events("s-lock-contention")
            .expect("subscribe B under emit churn");
    }
}

#[derive(Debug)]
struct FailingAuditSink;

impl DurableAuditSink for FailingAuditSink {
    fn store_event(&self, _event: &AuditEvent) -> Result<()> {
        Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            "forced durable sink failure",
            ErrorContext::new("failing_audit_sink"),
        ))
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
            last_event_id: "0".into(),
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

    fn store_event(&self, event: &AuditEvent) -> Result<()> {
        self.inner.store_event(event)
    }

    fn retrieve_events_from(&self, cursor: &ReplayCursor, limit: usize) -> Result<Vec<AuditEvent>> {
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

#[derive(Debug)]
struct ReentrantAuditSink {
    bus: Mutex<Option<EventBus>>,
    attempted_reentry: AtomicBool,
}

impl ReentrantAuditSink {
    fn new() -> Self {
        Self {
            bus: Mutex::new(None),
            attempted_reentry: AtomicBool::new(false),
        }
    }

    fn set_bus(&self, bus: EventBus) {
        *self.bus.lock().expect("bus lock") = Some(bus);
    }
}

impl DurableAuditSink for ReentrantAuditSink {
    fn durability(&self) -> AuditSinkDurability {
        AuditSinkDurability::Durable
    }

    fn store_event(&self, _event: &AuditEvent) -> Result<()> {
        if !self.attempted_reentry.swap(true, Ordering::SeqCst)
            && let Some(bus) = self.bus.lock().expect("bus lock").as_ref()
        {
            let nested = emit_audit_event(
                bus,
                &session("s-reentrant", "p-reentrant"),
                AsxEvent::InteropGuardrailEvaluated {
                    message_id: "nested-msg".into(),
                    code: "nested",
                    outcome: "SecurityBlocked",
                    detail: "nested",
                },
                true,
                "reentrant_nested",
            );
            if nested.is_err() {
                return Err(AsxError::new(
                    ErrorCode::ReliabilityFailure,
                    "nested emit rejected",
                    ErrorContext::new("reentrant_audit_sink"),
                ));
            }
        }
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
            last_event_id: "0".into(),
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

#[test]
fn emit_rejects_reentrant_audit_sink_store_event() {
    let sink = Arc::new(ReentrantAuditSink::new());
    let bus = EventBus::new_with_config_and_mode(
        16,
        Some(sink.clone()),
        BackpressurePolicy::default(),
        EventEmissionMode::StrictTransactional,
    )
    .expect("event bus");
    sink.set_bus(bus.clone());

    let _subscriber = bus.subscribe_scoped_events();
    let err = emit_audit_event(
        &bus,
        &session("s-reentrant", "p-reentrant"),
        AsxEvent::InteropGuardrailEvaluated {
            message_id: "outer-msg".into(),
            code: "outer",
            outcome: "SecurityBlocked",
            detail: "outer",
        },
        true,
        "reentrant_test",
    )
    .expect_err("reentrant sink must fail closed");

    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
    assert!(sink.attempted_reentry.load(Ordering::SeqCst));
}

#[test]
fn emit_audit_event_persists_to_durable_sink() {
    let sink = Arc::new(InMemoryAuditSink::new().expect("audit sink"));
    let bus = EventBus::new_with_config_and_mode(
        16,
        Some(sink.clone()),
        BackpressurePolicy::default(),
        EventEmissionMode::StrictTransactional,
    )
    .expect("event bus");
    let sess = session("s-audit", "p-audit");
    let _subscriber = bus.subscribe_scoped_events();

    emit_audit_event(
        &bus,
        &sess,
        AsxEvent::InteropGuardrailEvaluated {
            message_id: "msg-1".into(),
            code: "test_guardrail",
            outcome: "SecurityBlocked",
            detail: "detail",
        },
        true,
        "audit_stage",
    )
    .expect("audit event emit");

    let events = sink
        .retrieve_events_from(
            &ReplayCursor {
                last_event_id: "0".into(),
                position: 0,
                last_timestamp: 0,
                integrity_tag_b64: String::new(),
            },
            10,
        )
        .expect("retrieve events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].code, "interop_guardrail_evaluated");
    assert_eq!(events[0].metadata.stage.as_deref(), Some("audit_stage"));
}

/// Regression: `emit_audit_event` under `StrictWithAuditFallback` with **no**
/// subscribers must persist the event exactly once. Previously it pre-persisted
/// and then `emit`'s no-subscriber fallback persisted a second copy under a
/// different `event_id`, inflating the compliance log.
#[test]
fn emit_audit_event_persists_exactly_once_in_audit_fallback_without_subscribers() {
    let sink = Arc::new(DurableTestAuditSink::new());
    let bus = EventBus::new_with_config_and_mode(
        16,
        Some(sink.clone()),
        BackpressurePolicy::default(),
        EventEmissionMode::StrictWithAuditFallback,
    )
    .expect("event bus");
    let sess = session("s-audit-once", "p-audit");
    // Intentionally no subscriber → emit takes the audit-fallback path.

    emit_audit_event(
        &bus,
        &sess,
        AsxEvent::InteropGuardrailEvaluated {
            message_id: "msg-once".into(),
            code: "test_guardrail",
            outcome: "SecurityBlocked",
            detail: "detail",
        },
        true,
        "audit_stage",
    )
    .expect("audit event emit");

    let events = sink
        .retrieve_events_from(
            &ReplayCursor {
                last_event_id: "0".into(),
                position: 0,
                last_timestamp: 0,
                integrity_tag_b64: String::new(),
            },
            10,
        )
        .expect("retrieve events");
    assert_eq!(
        events.len(),
        1,
        "audit event must be persisted exactly once"
    );
}

#[test]
fn emit_audit_event_fail_closed_when_sink_write_fails() {
    let sink = Arc::new(FailingAuditSink);
    let bus = EventBus::new_with_config_and_mode(
        16,
        Some(sink),
        BackpressurePolicy::default(),
        EventEmissionMode::StrictTransactional,
    )
    .expect("event bus");
    let sess = session("s-audit", "p-audit");

    let err = emit_audit_event(
        &bus,
        &sess,
        AsxEvent::InteropGuardrailEvaluated {
            message_id: "msg-1".into(),
            code: "test_guardrail",
            outcome: "SecurityBlocked",
            detail: "detail",
        },
        true,
        "audit_stage",
    )
    .expect_err("fail-closed must error");

    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
}

#[test]
fn strict_with_audit_fallback_fails_closed_when_sink_write_fails() {
    let sink = Arc::new(FailingAuditSink);
    let bus = EventBus::new_strict_with_audit_fallback(16, sink).expect("event bus");
    let sess = session("s-fallback-fail", "p-fallback-fail");

    let err = bus
        .emit(
            &sess,
            AsxEvent::InteropGuardrailEvaluated {
                message_id: "msg-fallback-fail".into(),
                code: "guardrail",
                outcome: "SecurityBlocked",
                detail: "fallback",
            },
        )
        .expect_err("strict audit fallback must fail closed when sink write fails");

    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
}

#[test]
fn strict_with_audit_fallback_persists_without_subscribers() {
    let sink = Arc::new(DurableTestAuditSink::new());
    let bus = EventBus::new_strict_with_audit_fallback(16, sink.clone()).expect("event bus");
    let sess = session("s-fallback-ok", "p-fallback-ok");

    bus.emit(
        &sess,
        AsxEvent::InteropGuardrailEvaluated {
            message_id: "msg-fallback-ok".into(),
            code: "guardrail",
            outcome: "Allowed",
            detail: "fallback",
        },
    )
    .expect("fallback emit should persist and succeed");

    assert_eq!(bus.metrics().emitted(), 1);
    assert_eq!(bus.metrics().dropped(), 0);

    let events = sink
        .retrieve_events_from(
            &ReplayCursor {
                last_event_id: "0".into(),
                position: 0,
                last_timestamp: 0,
                integrity_tag_b64: String::new(),
            },
            10,
        )
        .expect("retrieve events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].code, "interop_guardrail_evaluated");
}

#[test]
fn audit_replay_and_acknowledge_cursor_round_trip() {
    let sink = Arc::new(InMemoryAuditSink::new().expect("audit sink"));
    let bus = EventBus::new_with_config_and_mode(
        16,
        Some(sink),
        BackpressurePolicy::default(),
        EventEmissionMode::StrictTransactional,
    )
    .expect("event bus");
    let sess = session("s-audit", "p-audit");
    let _subscriber = bus.subscribe_scoped_events();

    emit_audit_event(
        &bus,
        &sess,
        AsxEvent::InteropGuardrailEvaluated {
            message_id: "msg-1".into(),
            code: "c1",
            outcome: "Allowed",
            detail: "d1",
        },
        true,
        "audit_stage",
    )
    .expect("emit #1");
    emit_audit_event(
        &bus,
        &sess,
        AsxEvent::InteropGuardrailEvaluated {
            message_id: "msg-2".into(),
            code: "c2",
            outcome: "Allowed",
            detail: "d2",
        },
        true,
        "audit_stage",
    )
    .expect("emit #2");

    let replay = bus
        .replay_audit_events_from(
            &ReplayCursor {
                last_event_id: "0".into(),
                position: 0,
                last_timestamp: 0,
                integrity_tag_b64: String::new(),
            },
            10,
        )
        .expect("replay");
    assert_eq!(replay.len(), 2);

    let signed_ack_cursor = bus.current_audit_cursor().expect("signed cursor");
    bus.acknowledge_audit_cursor(&signed_ack_cursor)
        .expect("ack");
    let cursor = bus.current_audit_cursor().expect("cursor");
    assert_eq!(cursor.position, 2);
}

#[test]
fn audit_replay_without_sink_returns_error() {
    let bus = EventBus::new(16).expect("event bus");
    let err = bus
        .current_audit_cursor()
        .expect_err("missing sink must error");
    assert_eq!(err.code, ErrorCode::InvalidInput);
}

#[test]
fn regulated_profile_enforces_strict_defaults() {
    let sink = Arc::new(DurableTestAuditSink::new());
    let bus = EventBus::new_regulated(16, sink).expect("event bus");
    assert_eq!(bus.emission_mode(), EventEmissionMode::StrictTransactional);

    // In strict mode with no active subscribers, event emission fails closed.
    let sess = session("s-reg", "p-reg");
    let err = bus
        .emit(
            &sess,
            AsxEvent::MessageSigned {
                message_id: "m-reg".into(),
            },
        )
        .expect_err("regulated mode requires active subscribers");
    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
}

#[tokio::test]
async fn transactional_mode_fails_before_broadcast_when_session_queue_is_full() {
    let bus = EventBus::new_with_config_and_mode(
        16,
        None,
        BackpressurePolicy {
            session_channel_capacity: 1,
            ..BackpressurePolicy::default()
        },
        EventEmissionMode::StrictTransactional,
    )
    .expect("event bus");

    let sess = session("s-transactional", "p1");
    let mut scoped = bus.subscribe_scoped_events();
    let mut session_rx = bus
        .subscribe_session_events("s-transactional")
        .expect("subscribe session");

    bus.emit(
        &sess,
        AsxEvent::MessageSigned {
            message_id: "m1".into(),
        },
    )
    .expect("first emit should succeed");

    // Keep session queue full by not draining `session_rx` yet.
    let err = bus
        .emit(
            &sess,
            AsxEvent::MessageSigned {
                message_id: "m2".into(),
            },
        )
        .expect_err("transactional emit must fail when session queue is full");
    assert_eq!(err.code, ErrorCode::ReliabilityFailure);

    // Scoped stream should only contain the first event.
    let first = scoped.try_recv().expect("first scoped event present");
    assert_eq!(first.event.kind(), "message_signed");
    assert!(matches!(
        scoped.try_recv(),
        Err(ScopedEventTryRecvError::Empty)
    ));

    // Drain and confirm no hidden second session delivery happened.
    let first_session = timeout(Duration::from_millis(50), session_rx.recv())
        .await
        .expect("timely first session event")
        .expect("first session event present");
    assert_eq!(first_session.kind(), "message_signed");
    assert!(
        timeout(Duration::from_millis(20), session_rx.recv())
            .await
            .is_err(),
        "second session event must not be delivered"
    );
}

#[tokio::test]
async fn strict_with_audit_fallback_fails_when_session_queue_is_full() {
    let bus = EventBus::new_with_config_and_mode(
        16,
        Some(Arc::new(DurableTestAuditSink::new())),
        BackpressurePolicy {
            session_channel_capacity: 1,
            ..BackpressurePolicy::default()
        },
        EventEmissionMode::StrictWithAuditFallback,
    )
    .expect("event bus");

    let sess = session("s-strict-session-overflow", "p1");
    let _scoped = bus.subscribe_scoped_events();
    let mut session_rx = bus
        .subscribe_session_events("s-strict-session-overflow")
        .expect("subscribe session");

    bus.emit(
        &sess,
        AsxEvent::MessageSigned {
            message_id: "m1".into(),
        },
    )
    .expect("first emit should succeed");

    let err = bus
        .emit(
            &sess,
            AsxEvent::MessageSigned {
                message_id: "m2".into(),
            },
        )
        .expect_err("strict fallback mode must fail when session queue is full");
    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
    assert!(err.message.contains("session subscriber queue is full"));

    // Drain and confirm only the first event was delivered.
    let first = timeout(Duration::from_millis(50), session_rx.recv())
        .await
        .expect("timely first session event")
        .expect("first session event present");
    assert_eq!(first.kind(), "message_signed");
    assert!(
        timeout(Duration::from_millis(20), session_rx.recv())
            .await
            .is_err(),
        "second session event must not be delivered"
    );
}

#[test]
fn strict_with_audit_fallback_requires_sink() {
    let err = match EventBus::new_with_config_and_mode(
        16,
        None,
        BackpressurePolicy::default(),
        EventEmissionMode::StrictWithAuditFallback,
    ) {
        Ok(_) => panic!("strict fallback without sink must fail"),
        Err(err) => err,
    };

    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert!(
        err.message
            .contains("requires a configured durable audit sink")
    );
}

#[test]
fn strict_with_audit_fallback_rejects_ephemeral_sink() {
    let err = match EventBus::new_with_config_and_mode(
        16,
        Some(Arc::new(InMemoryAuditSink::new().expect("audit sink"))),
        BackpressurePolicy::default(),
        EventEmissionMode::StrictWithAuditFallback,
    ) {
        Ok(_) => panic!("strict fallback with ephemeral sink must fail"),
        Err(err) => err,
    };

    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert!(
        err.message
            .contains("requires a production-durable audit sink")
    );
}

#[test]
fn regulated_profile_rejects_ephemeral_audit_sink() {
    let sink = Arc::new(InMemoryAuditSink::new().expect("audit sink"));
    let err = match EventBus::new_regulated(16, sink) {
        Ok(_) => panic!("ephemeral sink must be rejected"),
        Err(err) => err,
    };
    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert!(err.message.contains("production-durable audit sink"));
}

#[cfg(any(feature = "as2", feature = "as4"))]
#[test]
fn durable_sink_not_required_when_fail_closed_disabled() {
    let bus = EventBus::new(16).expect("event bus");
    let sess = session("s-audit-optional", "p-optional");

    let result = require_durable_audit_sink(&sess, &bus, false, "as4_receive_push");

    assert!(result.is_ok());
}

#[cfg(any(feature = "as2", feature = "as4"))]
#[test]
fn durable_sink_required_when_fail_closed_enabled() {
    let bus = EventBus::new(16).expect("event bus");
    let sess = session("s-audit-required", "p-required");

    let err = require_durable_audit_sink(&sess, &bus, true, "as4_receive_push")
        .expect_err("fail-closed mode requires durable sink");

    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
    assert!(err.message.contains("requires"));
    assert!(err.message.contains("audit sink"));
}

#[cfg(all(not(feature = "testing"), any(feature = "as2", feature = "as4")))]
#[test]
fn fail_closed_requires_production_durable_sink_in_non_testing_builds() {
    let bus = EventBus::new_with_config_and_mode(
        16,
        Some(Arc::new(InMemoryAuditSink::new().expect("audit sink"))),
        BackpressurePolicy::default(),
        EventEmissionMode::StrictTransactional,
    )
    .expect("event bus");
    let sess = session("s-audit-prod-required", "p-required");

    let err = require_durable_audit_sink(&sess, &bus, true, "as4_receive_push")
        .expect_err("non-testing fail-closed mode requires production durability");

    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
    assert!(err.message.contains("production-durable audit sink"));
}

#[test]
fn production_durable_sink_rejects_ephemeral_sink() {
    let bus = EventBus::new_with_config_and_mode(
        16,
        Some(Arc::new(InMemoryAuditSink::new().expect("audit sink"))),
        BackpressurePolicy::default(),
        EventEmissionMode::StrictTransactional,
    )
    .expect("event bus");
    assert!(!bus.has_production_durable_audit_sink());
}

#[test]
fn production_durable_sink_accepts_durable_sink() {
    let bus = EventBus::new_with_config_and_mode(
        16,
        Some(Arc::new(DurableTestAuditSink::new())),
        BackpressurePolicy::default(),
        EventEmissionMode::StrictTransactional,
    )
    .expect("event bus");
    assert!(bus.has_production_durable_audit_sink());
}

#[test]
fn backpressure_track_mode_never_fails_on_drop() {
    // Default policy (Track) — should allow any number of drops without error.
    let bus = EventBus::new_with_config_and_mode(
        16,
        None,
        BackpressurePolicy {
            max_dropped: Some(1),
            max_lagged: None,
            action: BackpressureAction::Track,
            window_secs: 60,
            session_channel_capacity: 64,
        },
        EventEmissionMode::BestEffort,
    )
    .expect("event bus");
    let sess = session("s-bp-track", "p1");

    bus.emit(
        &sess,
        AsxEvent::MessageSigned {
            message_id: "m".into(),
        },
    )
    .expect("track mode must not fail on dropped events in best-effort mode");
    assert_eq!(bus.metrics().dropped(), 1);
}

#[test]
fn backpressure_fail_closed_on_drop_threshold() {
    let bus = EventBus::new_with_config_and_mode(
        16,
        None,
        BackpressurePolicy {
            max_dropped: Some(3),
            max_lagged: None,
            action: BackpressureAction::FailClosed,
            window_secs: 60,
            session_channel_capacity: 64,
        },
        EventEmissionMode::BestEffort,
    )
    .expect("event bus");
    let sess = session("s-bp-drop", "p1");

    bus.emit(
        &sess,
        AsxEvent::MessageSigned {
            message_id: "m-1".into(),
        },
    )
    .expect("below threshold should not fail");

    bus.emit(
        &sess,
        AsxEvent::MessageSigned {
            message_id: "m-2".into(),
        },
    )
    .expect("below threshold should not fail");

    let err = bus
        .emit(
            &sess,
            AsxEvent::MessageSigned {
                message_id: "m-3".into(),
            },
        )
        .expect_err("at threshold must fail closed");
    assert_eq!(err.code, ErrorCode::ReliabilityFailure);
    assert!(err.message.contains("dropped"));
}

#[test]
fn backpressure_fail_closed_lagged_window_self_heals_after_expiry() {
    use std::sync::atomic::Ordering;
    use std::time::{SystemTime, UNIX_EPOCH};

    let bus = EventBus::new_with_config_and_mode(
        16,
        None,
        BackpressurePolicy {
            max_dropped: None,
            max_lagged: Some(2),
            action: BackpressureAction::FailClosed,
            window_secs: 60,
            session_channel_capacity: 64,
        },
        EventEmissionMode::BestEffort,
    )
    .expect("event bus");
    let sess = session("s-bp-lag", "p1");

    // Simulate a *past* window that saturated the lagged counter. Before the
    // read-path reset fix, this stale count would wedge FailClosed forever.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    bus.metrics
        .window_epoch
        .store(now.saturating_sub(120), Ordering::SeqCst);
    bus.metrics.window_lagged.store(99, Ordering::SeqCst);

    // The window has expired, so the effective count is 0 and emit succeeds.
    assert_eq!(bus.metrics.current_window_lagged(), 0);
    bus.emit(
        &sess,
        AsxEvent::MessageSigned {
            message_id: "m-after-window".into(),
        },
    )
    .expect("expired-window lag count must not wedge FailClosed");
}

#[test]
fn init_rejects_zero_session_channel_capacity() {
    let result = EventBus::new_with_config_and_mode(
        16,
        None,
        BackpressurePolicy {
            max_dropped: None,
            max_lagged: None,
            action: BackpressureAction::Track,
            window_secs: 60,
            session_channel_capacity: 0,
        },
        EventEmissionMode::StrictTransactional,
    );

    let err = match result {
        Ok(_) => panic!("zero session channel capacity must be rejected"),
        Err(err) => err,
    };

    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert!(err.message.contains("session channel capacity"));
}

#[test]
fn init_rejects_zero_backpressure_window_secs() {
    let result = EventBus::new_with_config_and_mode(
        16,
        None,
        BackpressurePolicy {
            max_dropped: None,
            max_lagged: None,
            action: BackpressureAction::Track,
            window_secs: 0,
            session_channel_capacity: 64,
        },
        EventEmissionMode::StrictTransactional,
    );

    let err = match result {
        Ok(_) => panic!("zero backpressure window must be rejected"),
        Err(err) => err,
    };

    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert!(err.message.contains("window_secs"));
}

#[test]
fn receipt_taxonomy_outcomes_export_label_stable_metric_counter() {
    let metrics_sink = Arc::new(RecordingMetricsSink::default());
    let bus = EventBus::new_with_config_and_mode_and_metrics(
        16,
        None,
        BackpressurePolicy::default(),
        EventEmissionMode::BestEffort,
        metrics_sink.clone(),
    )
    .expect("event bus");
    let sess = session("s-taxonomy", "p1");

    bus.emit(
        &sess,
        AsxEvent::ReceiptTaxonomyOutcome {
            message_id: "msg-1".into(),
            signal: "as4",
            outcome: "security_verification_failed",
            detail: "receipt_signature_verification_failed",
        },
    )
    .expect("emit taxonomy outcome");

    let counters = metrics_sink.counters.lock().expect("metrics lock");
    let taxonomy = counters
        .iter()
        .find(|c| c.name == "asx_as4_receipt_taxonomy_outcome_total")
        .expect("taxonomy metric");

    assert_eq!(taxonomy.value, 1);
    assert!(taxonomy.labels.contains(&("protocol", "as4".to_string())));
    assert!(taxonomy.labels.contains(&("signal", "as4".to_string())));
    assert!(
        taxonomy
            .labels
            .contains(&("outcome", "security_verification_failed".to_string()))
    );
    assert!(taxonomy.labels.contains(&(
        "detail",
        "receipt_signature_verification_failed".to_string()
    )));
}

#[test]
fn spool_key_provider_health_check_failed_event_metadata_is_stable() {
    let event = AsxEvent::SpoolKeyProviderHealthCheckFailed {
        provider: "kms-env",
        health_state: "failing",
        phase: "key_resolution",
        error_code: "policy_violation",
    };

    assert_eq!(event.kind(), "spool_key_provider_health_check_failed");
    assert_eq!(event_code(&event), "spool_key_provider_health_check_failed");
    assert_eq!(
        event_message(&event),
        "Spool key provider health check failed"
    );
}

#[test]
fn spool_key_provider_health_checked_event_metadata_is_stable() {
    let event = AsxEvent::SpoolKeyProviderHealthChecked {
        provider: "local-env",
        health_state: "healthy",
        resolve_key_ms: 2,
    };

    assert_eq!(event.kind(), "spool_key_provider_health_checked");
    assert_eq!(event_code(&event), "spool_key_provider_health_checked");
    assert_eq!(event_message(&event), "Spool key provider health checked");
}

#[test]
fn spool_headroom_checked_event_metadata_is_stable() {
    let event = AsxEvent::SpoolHeadroomChecked {
        stage: "as2_receive_stream",
        free_bytes: 1024,
        min_required_bytes: 512,
    };

    assert_eq!(event.kind(), "spool_headroom_checked");
    assert_eq!(event_code(&event), "spool_headroom_checked");
    assert_eq!(event_message(&event), "Spool headroom checked");
}

#[test]
fn spool_key_provider_health_state_changed_event_metadata_is_stable() {
    let event = AsxEvent::SpoolKeyProviderHealthStateChanged {
        provider: "local-env",
        previous_state: "failing",
        current_state: "healthy",
        reason: "policy_ready",
    };

    assert_eq!(event.kind(), "spool_key_provider_health_state_changed");
    assert_eq!(
        event_code(&event),
        "spool_key_provider_health_state_changed"
    );
    assert_eq!(
        event_message(&event),
        "Spool key provider health state changed"
    );
}

// ── FR-2 regression: EventBus::new_for_testing ─────────────────────────────

#[cfg(feature = "testing")]
#[test]
fn new_for_testing_is_best_effort_and_infallible() {
    let bus = EventBus::new_for_testing();
    assert_eq!(bus.emission_mode(), EventEmissionMode::BestEffort);
}

#[cfg(feature = "testing")]
#[test]
fn new_for_testing_silently_drops_events_without_subscriber() {
    let bus = EventBus::new_for_testing();
    let sess = crate::core::SessionContext::new("s-testing", "p1", "strict").expect("session");
    // Emitting without a subscriber must not fail in BestEffort mode.
    let result = bus.emit(
        &sess,
        crate::observability::AsxEvent::MessageSigned {
            message_id: "m1".into(),
        },
    );
    assert!(
        result.is_ok(),
        "new_for_testing must never fail on emit: {result:?}"
    );
    assert_eq!(
        bus.metrics().dropped(),
        1,
        "event should be counted as dropped"
    );
}
