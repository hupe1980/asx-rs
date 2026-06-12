#![cfg_attr(not(feature = "interop-relaxed"), allow(unused_imports, dead_code))]
#![cfg_attr(not(feature = "interop-relaxed"), allow(unused_imports))]
use asx::core::{InteropMode, SessionContext};
use asx::interop::{
    BaseProfile, CanonicalizationPolicy, DiffRiskLevel, ProfileExtension, ProfilePolicyOverrides,
    ProfileStack, SecurityPolicy, ValidationPolicy, diff_effective_policy_snapshots,
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

#[cfg(feature = "interop-relaxed")]
#[test]
fn diff_output_is_stable_and_machine_readable() {
    let before_stack = base_stack();
    let after_stack = ProfileStack {
        base: before_stack.base.clone(),
        extensions: vec![ProfileExtension {
            name: "vendor-delta".to_string(),
            overrides: ProfilePolicyOverrides {
                mode: Some(InteropMode::Relaxed),
                ..ProfilePolicyOverrides::default()
            },
        }],
        overrides: vec![],
        partner_overrides: vec![],
    };

    let session = SessionContext::new("s-diff", "partner-a", "profile-diff").expect("session");
    let before = before_stack.resolve(&session).snapshot;
    let after = after_stack.resolve(&session).snapshot;

    let report = diff_effective_policy_snapshots(&before, &after);
    let json = report.to_json_pretty().expect("json");

    assert!(json.contains("\"changes\""));
    assert!(json.contains("\"field\""));
    assert!(json.contains("\"stage\""));
    assert!(json.contains("\"risk\""));
    assert!(json.contains("\"release_blocked\""));
    assert_eq!(report.highest_risk, DiffRiskLevel::Medium);
    assert!(!report.release_blocked);
}

#[test]
fn high_risk_security_downgrade_is_blocked() {
    let before_stack = base_stack();
    let after_stack = ProfileStack {
        base: BaseProfile {
            security: SecurityPolicy {
                require_signature: false,
                ..SecurityPolicy::default()
            },
            ..before_stack.base.clone()
        },
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![],
    };

    let session = SessionContext::new("s-risk", "partner-a", "profile-risk").expect("session");
    let before = before_stack.resolve(&session).snapshot;
    let after = after_stack.resolve(&session).snapshot;

    let report = diff_effective_policy_snapshots(&before, &after);
    assert_eq!(report.highest_risk, DiffRiskLevel::High);
    assert!(report.release_blocked);
}
