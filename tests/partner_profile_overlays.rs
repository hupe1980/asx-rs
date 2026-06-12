#![cfg_attr(not(feature = "interop-relaxed"), allow(unused_imports, dead_code))]
#![cfg_attr(not(feature = "interop-relaxed"), allow(unused_imports))]
use asx::core::{InteropMode, SessionContext};
use asx::interop::{
    BaseProfile, CanonicalizationPolicy, PartnerProfileOverlay, ProfileExtension, ProfileOverride,
    ProfilePolicyOverrides, ProfileStack, SecurityPolicy, ValidationPolicy,
};

fn base_profile() -> BaseProfile {
    BaseProfile {
        name: "base".into(),
        version: "1".into(),
        mode: InteropMode::Strict,
        canonicalization: CanonicalizationPolicy::default(),
        security: SecurityPolicy::default(),
        validation: ValidationPolicy::default(),
    }
}

#[cfg(feature = "interop-relaxed")]
#[test]
fn conflicting_partner_overlays_resolve_per_partner_without_leakage() {
    let stack = ProfileStack {
        base: base_profile(),
        extensions: vec![ProfileExtension {
            name: "vendor".into(),
            overrides: ProfilePolicyOverrides {
                mode: Some(InteropMode::Relaxed),
                ..ProfilePolicyOverrides::default()
            },
        }],
        overrides: vec![ProfileOverride {
            name: "global".into(),
            overrides: ProfilePolicyOverrides {
                validation: Some(ValidationPolicy {
                    require_as2_mic: false,
                    ..ValidationPolicy::default()
                }),
                ..ProfilePolicyOverrides::default()
            },
        }],
        partner_overrides: vec![
            PartnerProfileOverlay {
                name: "acme-override".into(),
                partner_id: "partner-acme".into(),
                overrides: ProfilePolicyOverrides {
                    mode: Some(InteropMode::Strict),
                    ..ProfilePolicyOverrides::default()
                },
            },
            PartnerProfileOverlay {
                name: "globex-override".into(),
                partner_id: "partner-globex".into(),
                overrides: ProfilePolicyOverrides {
                    mode: Some(InteropMode::Relaxed),
                    ..ProfilePolicyOverrides::default()
                },
            },
        ],
    };

    let acme_session =
        SessionContext::new("sess-acme", "partner-acme", "partner-profile").expect("acme session");
    let globex_session = SessionContext::new("sess-globex", "partner-globex", "partner-profile")
        .expect("globex session");

    let acme = stack.resolve(&acme_session);
    let globex = stack.resolve(&globex_session);

    assert_eq!(acme.mode, InteropMode::Strict);
    assert_eq!(globex.mode, InteropMode::Relaxed);

    assert!(
        acme.snapshot
            .resolution_trace
            .iter()
            .any(|step| step.contains("partner_override:partner-acme:acme-override"))
    );
    assert!(
        globex
            .snapshot
            .resolution_trace
            .iter()
            .any(|step| step.contains("partner_override:partner-globex:globex-override"))
    );
}

#[test]
fn resolve_for_session_attaches_snapshot_metadata() {
    let stack = ProfileStack {
        base: base_profile(),
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![PartnerProfileOverlay {
            name: "acme-override".to_string(),
            partner_id: "partner-acme".to_string(),
            overrides: ProfilePolicyOverrides::default(),
        }],
    };

    let session =
        SessionContext::new("sess-attach", "partner-acme", "partner-profile").expect("session");
    let resolved = stack
        .resolve_for_session(&session)
        .expect("resolved session profile");

    let snapshot_json = resolved
        .session
        .effective_policy_snapshot_json()
        .expect("snapshot metadata attached");
    let decoded = asx::interop::EffectivePolicySnapshot::from_json(snapshot_json).expect("decode");

    assert_eq!(decoded, resolved.effective_profile.snapshot);
    assert_eq!(decoded.partner_id, "partner-acme");
    assert_eq!(decoded.session_id, "sess-attach");
}
