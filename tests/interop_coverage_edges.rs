#![cfg_attr(not(feature = "interop-relaxed"), allow(unused_imports, dead_code))]
#![cfg(all(feature = "as2", feature = "as4"))]

use asx::core::{ErrorCode, InteropMode, SessionContext};
use asx::interop::{
    BaseProfile, CanonicalizationPolicy, EffectivePolicySnapshot, InteropDecision,
    InteropExceptionCode, InteropExceptionPolicy, ProfilePolicyOverrides, ProfileStack,
    RegionalProfilePack, SecurityPolicy, ValidationPolicy, diff_effective_policy_snapshots,
    enforce_exception,
};

fn base_stack() -> ProfileStack {
    ProfileStack {
        base: BaseProfile {
            name: "base".to_string(),
            version: "1".to_string(),
            mode: InteropMode::Strict,
            canonicalization: CanonicalizationPolicy::default(),
            security: SecurityPolicy::default(),
            validation: ValidationPolicy::default(),
        },
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![],
    }
}

fn session() -> SessionContext {
    SessionContext::new("s-edge", "partner-edge", "edge-profile").expect("session")
}

#[test]
fn interop_exception_reason_codes_are_stable() {
    assert_eq!(
        InteropExceptionCode::As2AllowMissingMdnBoundary.reason_code(),
        "as2_missing_mdn_boundary"
    );
}

#[cfg(feature = "interop-relaxed")]
#[test]
fn enforce_exception_allowed_and_denied_paths_are_distinct() {
    let s = session();
    let scoped = InteropExceptionPolicy::scoped(
        "edge-profile",
        vec![InteropExceptionCode::As2AllowMissingMdnBoundary],
    );

    let allowed = enforce_exception(
        &s,
        InteropMode::Relaxed,
        &scoped,
        InteropExceptionCode::As2AllowMissingMdnBoundary,
        "interop_enforce_allowed",
        "unused strict message",
    )
    .expect("allowed in relaxed mode with scoped policy");
    assert_eq!(
        allowed,
        InteropDecision::RelaxedException {
            reason_code: "as2_missing_mdn_boundary"
        }
    );

    let strict_denied = enforce_exception(
        &s,
        InteropMode::Strict,
        &scoped,
        InteropExceptionCode::As2AllowMissingMdnBoundary,
        "interop_enforce_strict_denied",
        "strict path denied",
    )
    .expect_err("strict mode must deny exception");
    assert_eq!(strict_denied.code, ErrorCode::InteropViolation);
    assert_eq!(strict_denied.message, "strict path denied");

    let relaxed_denied = enforce_exception(
        &s,
        InteropMode::Relaxed,
        &InteropExceptionPolicy::default(),
        InteropExceptionCode::As2AllowMissingMdnBoundary,
        "interop_enforce_relaxed_denied",
        "not used in relaxed denied",
    )
    .expect_err("relaxed mode without policy must deny exception");
    assert_eq!(relaxed_denied.code, ErrorCode::InteropViolation);
    assert!(
        relaxed_denied
            .message
            .contains("missing scoped exception policy")
    );
}

#[test]
fn snapshot_event_detail_shows_none_when_resolution_trace_is_empty() {
    let snapshot = EffectivePolicySnapshot {
        session_id: "s-none".to_string(),
        partner_id: "p-none".to_string(),
        profile_name: "profile-none".to_string(),
        resolved_mode: InteropMode::Strict,
        canonicalization: CanonicalizationPolicy::default(),
        security: SecurityPolicy::default(),
        validation: ValidationPolicy::default(),
        resolution_trace: vec![],
        resolution_diagnostics: vec![],
    };

    let detail = snapshot.as_event_detail();
    assert!(detail.contains("trace=none"));
}

#[test]
fn profile_diff_with_no_changes_is_low_risk_and_not_blocking() {
    let s = session();
    let before = base_stack().resolve(&s).snapshot;
    let after = before.clone();

    let report = diff_effective_policy_snapshots(&before, &after);
    assert_eq!(report.highest_risk, asx::interop::DiffRiskLevel::Low);
    assert!(report.changes.is_empty());
    assert!(!report.release_blocked);
}

#[cfg(feature = "interop-relaxed")]
#[test]
fn apply_regional_packs_applies_in_sequence() {
    let pack_a = RegionalProfilePack {
        pack_id: "a".to_string(),
        version: "1.0.0".to_string(),
        applies_to_base_profile: "base".to_string(),
        overrides: ProfilePolicyOverrides {
            mode: Some(InteropMode::Relaxed),
            ..ProfilePolicyOverrides::default()
        },
    };
    let pack_b = RegionalProfilePack {
        pack_id: "b".to_string(),
        version: "1.0.1".to_string(),
        applies_to_base_profile: "base".to_string(),
        overrides: ProfilePolicyOverrides {
            validation: Some(ValidationPolicy {
                require_as2_mic: false,
                ..ValidationPolicy::default()
            }),
            ..ProfilePolicyOverrides::default()
        },
    };

    let merged = base_stack()
        .apply_regional_packs(&[pack_a, pack_b])
        .expect("packs should apply sequentially");
    let effective = merged.resolve(&session());

    assert_eq!(effective.mode, InteropMode::Relaxed);
    assert!(!effective.validation.require_as2_mic);
}

#[test]
fn regional_pack_from_json_rejects_empty_pack_id() {
    let json = r#"{
      "pack_id": "",
      "version": "1.0.0",
      "applies_to_base_profile": "base",
      "overrides": {
        "mode": null,
        "canonicalization": null,
        "security": null,
                "validation": null
      }
    }"#;

    let err = RegionalProfilePack::from_json(json).expect_err("empty pack_id must fail");
    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert!(err.message.contains("pack_id must not be empty"));
}

#[test]
fn apply_regional_pack_rejects_wrong_base_profile_target() {
    let pack = RegionalProfilePack {
        pack_id: "wrong-target".to_string(),
        version: "1.0.0".to_string(),
        applies_to_base_profile: "other-base".to_string(),
        overrides: ProfilePolicyOverrides::default(),
    };

    let err = base_stack()
        .apply_regional_pack(&pack)
        .expect_err("pack target mismatch must fail");
    assert_eq!(err.code, ErrorCode::PolicyViolation);
    assert!(err.message.contains("targets base profile"));
}

#[test]
fn snapshot_from_json_rejects_invalid_payload() {
    let err = EffectivePolicySnapshot::from_json("not-json").expect_err("invalid json must fail");
    assert_eq!(err.code, ErrorCode::ParseFailed);
    assert!(
        err.message
            .contains("failed to deserialize effective policy snapshot")
    );
}
