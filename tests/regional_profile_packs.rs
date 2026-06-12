#![cfg_attr(not(feature = "interop-relaxed"), allow(unused_imports, dead_code))]
#![cfg_attr(not(feature = "interop-relaxed"), allow(unused_imports))]
use asx::core::{ErrorCode, InteropMode, SessionContext};
use asx::interop::{
    BaseProfile, CanonicalizationPolicy, ProfilePolicyOverrides, ProfileStack, RegionalProfilePack,
    SecurityPolicy, ValidationPolicy,
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

fn fixture(path: &str) -> String {
    std::fs::read_to_string(path).expect("fixture")
}

#[cfg(feature = "interop-relaxed")]
#[test]
fn two_regional_packs_load_and_apply_without_code_changes() {
    let eu = RegionalProfilePack::from_json(&fixture("tests/fixtures/regional-packs/eu-pack.json"))
        .expect("eu pack");
    let us = RegionalProfilePack::from_json(&fixture("tests/fixtures/regional-packs/us-pack.json"))
        .expect("us pack");

    let stack = base_stack();
    let eu_stack = stack.apply_regional_pack(&eu).expect("apply eu");
    let us_stack = stack.apply_regional_pack(&us).expect("apply us");

    let eu_session = SessionContext::new("s-eu", "partner-a", "eu-profile").expect("session");
    let us_session = SessionContext::new("s-us", "partner-b", "us-profile").expect("session");

    let eu_effective = eu_stack.resolve(&eu_session);
    let us_effective = us_stack.resolve(&us_session);

    assert_eq!(eu_effective.mode, InteropMode::Strict);

    assert_eq!(us_effective.mode, InteropMode::Relaxed);
    assert!(
        us_effective
            .snapshot
            .resolution_trace
            .iter()
            .any(|step| step.contains("regional:us-healthcare@2.1.0"))
    );
}

#[test]
fn regional_pack_without_wssec_metadata_applies_and_keeps_validation() {
    let incompatible = RegionalProfilePack {
        pack_id: "jp-pack".to_string(),
        version: "1.2.3".to_string(),
        applies_to_base_profile: "base".to_string(),
        overrides: ProfilePolicyOverrides {
            mode: Some(InteropMode::Strict),
            ..ProfilePolicyOverrides::default()
        },
    };

    let merged = base_stack()
        .apply_regional_pack(&incompatible)
        .expect("pack should apply with strict-only metadata model");
    let effective =
        merged.resolve(&SessionContext::new("s-jp", "partner-jp", "jp-profile").expect("session"));
    assert_eq!(effective.mode, InteropMode::Strict);
}

#[test]
fn invalid_version_is_rejected_at_load_time() {
    let invalid = r#"{
            "pack_id": "bad-version",
            "version": "2026Q2",
            "applies_to_base_profile": "base",
            "overrides": {
                "mode": "Strict",
                "canonicalization": null,
                "security": null,
                                "validation": null
      }
    }"#;

    let err = RegionalProfilePack::from_json(invalid).expect_err("invalid version must fail");
    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert!(err.message.contains("expected semver-like x.y.z"));
}
