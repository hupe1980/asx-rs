use super::{
    AsxError, AsxEvent, BackpressureAction, ErrorCode, ErrorContext, EventBus, EventEmissionMode,
    Result, SessionContext,
};

pub(super) fn validate_lagged_backpressure(bus: &EventBus, session: &SessionContext) -> Result<()> {
    if bus.backpressure.action == BackpressureAction::FailClosed
        && let Some(max_lagged) = bus.backpressure.max_lagged
    {
        // Window-aware read: resets a stale count from an expired window so a
        // past burst cannot wedge FailClosed forever (see current_window_lagged).
        let lagged = bus.metrics.current_window_lagged();
        if lagged >= max_lagged {
            return Err(AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!(
                    "event bus backpressure threshold exceeded: \
                     {lagged} lagged events in window (limit {max_lagged})"
                ),
                ErrorContext::new("event_bus_emit").with_session_id(session.session_id()),
            ));
        }
    }
    Ok(())
}

pub(super) fn handle_broadcast_send_failure(
    bus: &EventBus,
    session: &SessionContext,
    event: &AsxEvent,
    dropped: u64,
) -> Result<()> {
    tracing::warn!(
        session_id = %session.session_id(),
        partner_id = %session.partner_id(),
        event_kind = event.kind(),
        dropped,
        emission_mode = ?bus.emission_mode,
        "event bus dropped event"
    );

    if bus.backpressure.action == BackpressureAction::FailClosed
        && let Some(max_dropped) = bus.backpressure.max_dropped
        && dropped >= max_dropped
    {
        return Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            format!(
                "event bus backpressure threshold exceeded: \
                 {dropped} dropped events (limit {max_dropped})"
            ),
            ErrorContext::new("event_bus_emit").with_session_id(session.session_id()),
        ));
    }

    match bus.emission_mode {
        EventEmissionMode::BestEffort => Ok(()),
        EventEmissionMode::StrictWithAuditFallback | EventEmissionMode::StrictTransactional => {
            Err(AsxError::new(
                ErrorCode::ReliabilityFailure,
                "event bus send failed (no active subscribers)",
                ErrorContext::new("event_bus_emit").with_session_id(session.session_id()),
            ))
        }
    }
}
