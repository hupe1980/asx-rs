use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc::error::TrySendError;

use super::emission_policy::{handle_broadcast_send_failure, validate_lagged_backpressure};
use super::scoped_subscriptions::{
    collect_active_scoped_senders, route_event_to_scoped_subscribers,
};
use super::session_subscriptions::{
    collect_active_session_senders, route_event_to_session_subscribers,
};
use super::{
    AsxError, AsxEvent, ErrorCode, ErrorContext, EventBus, EventEmissionMode, Result,
    ScopedAsxEvent, SessionContext,
};

fn strict_emit_error(session: &SessionContext, message: &'static str) -> AsxError {
    AsxError::new(
        ErrorCode::ReliabilityFailure,
        message,
        ErrorContext::new("event_bus_emit")
            .with_session_and_partner(session.session_id(), session.partner_id()),
    )
}

fn persist_via_audit_fallback(
    bus: &EventBus,
    session: &SessionContext,
    event: &AsxEvent,
    stage: &'static str,
) -> Result<()> {
    bus.persist_audit_event(session, event, stage)?;
    bus.metrics.emitted.fetch_add(1, Ordering::Relaxed);
    validate_lagged_backpressure(bus, session)
}

impl EventBus {
    #[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(session_id = %session.session_id())))]
    pub fn emit(&self, session: &SessionContext, event: AsxEvent) -> Result<()> {
        // Public emits own their audit-fallback persistence.
        self.emit_internal(session, event, true)
    }

    /// Core emit. `persist_audit_fallback` controls whether the no-subscriber
    /// path writes the event to the durable audit sink.
    ///
    /// [`emit_audit_event`] persists the event itself *before* emitting (so the
    /// audit record survives regardless of subscriber liveness), then calls
    /// this with `persist_audit_fallback = false` — otherwise the same event
    /// would be written to the compliance log twice under two `event_id`s.
    fn emit_internal(
        &self,
        session: &SessionContext,
        event: AsxEvent,
        persist_audit_fallback: bool,
    ) -> Result<()> {
        let shared_event = Arc::new(event);
        self.metrics
            .observe_event(shared_event.as_ref(), self.metrics_sink.as_ref());

        // In strict mode we fail closed before any side effects if no broadcast
        // subscribers are active, so callers can safely retry without duplicate
        // per-session side effects. However, per-session mpsc subscribers count
        // as active subscribers and allow emission to proceed.
        if matches!(self.emission_mode, EventEmissionMode::StrictTransactional)
            && collect_active_scoped_senders(self).is_empty()
            && !self.session_senders.contains_key(session.session_id())
        {
            let dropped = self.metrics.inc_dropped();
            return handle_broadcast_send_failure(self, session, shared_event.as_ref(), dropped);
        }

        // Audit-fallback mode: when no broadcast subscriber is active, write
        // the event to the durable audit sink and succeed without failing the
        // protocol call. This decouples subscriber liveness from message send.
        if matches!(
            self.emission_mode,
            EventEmissionMode::StrictWithAuditFallback
        ) && collect_active_scoped_senders(self).is_empty()
            && !self.session_senders.contains_key(session.session_id())
        {
            tracing::debug!(
                session_id = %session.session_id(),
                partner_id = %session.partner_id(),
                event_kind = shared_event.kind(),
                "no scoped subscribers; routing event to audit fallback sink"
            );
            // Persist to audit sink if available; write failures are fail-closed
            // in fallback mode because the sink is the compliance record.
            if self.audit_sink.is_some() {
                if persist_audit_fallback {
                    persist_via_audit_fallback(
                        self,
                        session,
                        shared_event.as_ref(),
                        "event_bus_audit_fallback",
                    )?;
                } else {
                    // Caller already persisted this event; just account for it.
                    self.metrics.emitted.fetch_add(1, Ordering::Relaxed);
                    validate_lagged_backpressure(self, session)?;
                }
                return Ok(());
            }
            self.metrics.inc_dropped();
            return Ok(());
        }

        let mut transactional_scoped_permits = Vec::new();
        let mut transactional_permits = Vec::new();
        if matches!(self.emission_mode, EventEmissionMode::StrictTransactional) {
            for sender in collect_active_scoped_senders(self) {
                match sender.try_reserve_owned() {
                    Ok(permit) => transactional_scoped_permits.push(permit),
                    Err(TrySendError::Full(_)) => {
                        self.metrics.inc_lagged(1);
                        return Err(strict_emit_error(
                            session,
                            "transactional event emission failed: scoped subscriber queue is full",
                        ));
                    }
                    Err(TrySendError::Closed(_)) => {
                        return Err(strict_emit_error(
                            session,
                            "transactional event emission failed: scoped subscriber closed",
                        ));
                    }
                }
            }

            for sender in collect_active_session_senders(self, session.session_id()) {
                match sender.try_reserve_owned() {
                    Ok(permit) => transactional_permits.push(permit),
                    Err(TrySendError::Full(_)) => {
                        self.metrics.inc_lagged(1);
                        return Err(strict_emit_error(
                            session,
                            "transactional event emission failed: session subscriber queue is full",
                        ));
                    }
                    Err(TrySendError::Closed(_)) => {
                        return Err(strict_emit_error(
                            session,
                            "transactional event emission failed: session subscriber closed",
                        ));
                    }
                }
            }
        }

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let scoped = ScopedAsxEvent {
            session_id: session.session_id().to_string(),
            partner_id: session.partner_id().to_string(),
            timestamp_ms,
            traceparent: session.correlation_scope().traceparent.clone(),
            event: Arc::clone(&shared_event),
        };

        if matches!(self.emission_mode, EventEmissionMode::StrictTransactional) {
            for permit in transactional_scoped_permits {
                permit.send(scoped.clone());
            }
            for permit in transactional_permits {
                permit.send(Arc::clone(&shared_event));
            }
        } else {
            let scoped_route = route_event_to_scoped_subscribers(self, &scoped);
            if scoped_route.lagged_count > 0
                && matches!(
                    self.emission_mode,
                    EventEmissionMode::StrictWithAuditFallback
                )
            {
                return Err(strict_emit_error(
                    session,
                    "strict event emission failed: scoped subscriber queue is full",
                ));
            }

            // Route directly to per-session mpsc subscribers (O(1) lookup).
            // Dead senders are pruned lazily.
            let session_route =
                route_event_to_session_subscribers(self, session.session_id(), &shared_event);
            if session_route.lagged_count > 0
                && matches!(
                    self.emission_mode,
                    EventEmissionMode::StrictWithAuditFallback
                )
            {
                return Err(strict_emit_error(
                    session,
                    "strict event emission failed: session subscriber queue is full",
                ));
            }

            if scoped_route.delivered_count == 0 && session_route.delivered_count == 0 {
                if matches!(
                    self.emission_mode,
                    EventEmissionMode::StrictWithAuditFallback
                ) && self.audit_sink.is_some()
                {
                    if persist_audit_fallback {
                        persist_via_audit_fallback(
                            self,
                            session,
                            shared_event.as_ref(),
                            "event_bus_audit_fallback",
                        )?;
                    } else {
                        self.metrics.emitted.fetch_add(1, Ordering::Relaxed);
                        validate_lagged_backpressure(self, session)?;
                    }
                    return Ok(());
                }

                let dropped = self.metrics.inc_dropped();
                return handle_broadcast_send_failure(
                    self,
                    session,
                    shared_event.as_ref(),
                    dropped,
                );
            }
        }

        self.metrics.emitted.fetch_add(1, Ordering::Relaxed);
        validate_lagged_backpressure(self, session)?;
        Ok(())
    }
}

pub fn emit_audit_event(
    bus: &EventBus,
    session: &SessionContext,
    event: AsxEvent,
    fail_closed: bool,
    stage: &'static str,
) -> Result<()> {
    match bus.persist_audit_event(session, &event, stage) {
        Ok(()) => {}
        Err(_) if !fail_closed => {}
        Err(err) => return Err(err),
    }

    // We already persisted the event above, so tell `emit` not to persist again
    // in its no-subscriber audit-fallback path — otherwise the same event lands
    // in the durable compliance log twice under two distinct `event_id`s.
    match bus.emit_internal(session, event, false) {
        Ok(()) => Ok(()),
        Err(_) if !fail_closed => Ok(()),
        Err(_) => Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            "audit event emission failed under fail-closed policy",
            ErrorContext::new(stage)
                .with_session_and_partner(session.session_id(), session.partner_id()),
        )),
    }
}

#[cfg(any(feature = "as2", feature = "as4"))]
pub(crate) fn emit_protocol_event(
    bus: &EventBus,
    session: &SessionContext,
    event: AsxEvent,
    fail_closed: bool,
    stage: &'static str,
) -> Result<()> {
    match bus.emit(session, event) {
        Ok(()) => Ok(()),
        Err(_) if !fail_closed => Ok(()),
        Err(_) => Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            "protocol event emission failed under fail-closed policy",
            ErrorContext::new(stage)
                .with_session_and_partner(session.session_id(), session.partner_id()),
        )),
    }
}

/// Verify that a durable audit sink is configured when fail-closed audit policy is active.
/// Both As2Message and As4Message share this precondition check.
#[cfg(any(feature = "as2", feature = "as4"))]
pub(crate) fn require_durable_audit_sink(
    session: &SessionContext,
    event_bus: &EventBus,
    fail_closed_audit_events: bool,
    stage: &'static str,
) -> Result<()> {
    if !fail_closed_audit_events {
        return Ok(());
    }

    #[cfg(not(feature = "testing"))]
    if !event_bus.has_production_durable_audit_sink() {
        return Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            "fail-closed audit policy requires production-durable audit sink",
            ErrorContext::for_session(stage, session),
        ));
    }

    #[cfg(feature = "testing")]
    if !event_bus.has_durable_audit_sink() {
        return Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            "fail-closed audit policy requires configured durable audit sink",
            ErrorContext::for_session(stage, session),
        ));
    }

    Ok(())
}
