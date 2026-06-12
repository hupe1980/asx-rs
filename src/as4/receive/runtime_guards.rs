use super::super::services::enforce_strict_as4_runtime_policy_consistency;
use super::super::types::As4PushPolicy;
use crate::core::{Result, SessionContext};
use crate::observability::EventBus;
use crate::storage::DedupStorage;

pub(super) fn enforce_receive_push_runtime_guards(
    session: &SessionContext,
    event_bus: &EventBus,
    policy: &As4PushPolicy,
    dedup_backend: &dyn DedupStorage,
) -> Result<()> {
    crate::presets::enforce_strict_production_runtime_receive_guards(
        "as4_receive_push",
        session,
        event_bus,
        policy.fail_closed_audit_events,
        None,
        Some(dedup_backend),
    )?;

    enforce_strict_as4_runtime_policy_consistency(
        session,
        "as4_receive_push",
        policy.interop,
        &policy.interop_exceptions,
        policy.require_signed_push(),
        policy.require_signed_receipt,
        policy.fail_closed_audit_events,
    )?;

    Ok(())
}
