use super::audit_persistence::{
    acknowledge_audit_cursor as acknowledge_audit_cursor_impl,
    current_audit_cursor as current_audit_cursor_impl,
    persist_audit_event as persist_audit_event_impl,
    replay_audit_events_from as replay_audit_events_from_impl,
};
use super::{AsxEvent, AuditEvent, EventBus, ReplayCursor, Result, SessionContext};

impl EventBus {
    pub fn replay_audit_events_from(
        &self,
        cursor: &ReplayCursor,
        limit: usize,
    ) -> Result<Vec<AuditEvent>> {
        replay_audit_events_from_impl(self, cursor, limit)
    }

    pub fn current_audit_cursor(&self) -> Result<ReplayCursor> {
        current_audit_cursor_impl(self)
    }

    pub fn acknowledge_audit_cursor(&self, cursor: &ReplayCursor) -> Result<()> {
        acknowledge_audit_cursor_impl(self, cursor)
    }

    pub(super) fn persist_audit_event(
        &self,
        session: &SessionContext,
        event: &AsxEvent,
        stage: &'static str,
    ) -> Result<()> {
        persist_audit_event_impl(self, session, event, stage)
    }
}
