#![cfg_attr(not(feature = "interop-relaxed"), allow(unused_imports, dead_code))]
#![cfg(all(feature = "as2", feature = "as4"))]

use asx_rs::core::{InteropMode, SessionContext};
use asx_rs::interop::{
    BaseProfile, CanonicalizationPolicy, PartnerProfileOverlay, ProfileExtension,
    ProfilePolicyOverrides, ProfileStack, ProfileValidationCode, SecurityPolicy, ValidationPolicy,
};
use proptest::prelude::*;

fn session(partner: &str, profile: &str) -> SessionContext {
    SessionContext::new(format!("prop-{partner}-{profile}"), partner, profile).expect("session")
}

#[cfg_attr(not(feature = "interop-relaxed"), allow(deprecated))]
fn mode_strategy() -> impl Strategy<Value = InteropMode> {
    prop_oneof![Just(InteropMode::Strict), Just(InteropMode::Relaxed)]
}

fn base_profile(mode: InteropMode) -> BaseProfile {
    BaseProfile {
        name: "base".to_string(),
        version: "1".to_string(),
        mode,
        canonicalization: CanonicalizationPolicy::default(),
        security: SecurityPolicy::default(),
        validation: ValidationPolicy::default(),
    }
}

proptest! {
    #[test]
    fn property_deterministic_resolution_is_stable(
        base_mode in mode_strategy(),
        extension_modes in proptest::collection::vec(prop::option::of(mode_strategy()), 0..4),
        override_modes in proptest::collection::vec(prop::option::of(mode_strategy()), 0..4),
    ) {
        let extensions = extension_modes.iter().enumerate().map(|(idx, mode)| ProfileExtension {
            name: format!("ext-{idx}"),
            overrides: ProfilePolicyOverrides {
                mode: *mode,
                ..ProfilePolicyOverrides::default()
            },
        }).collect();

        let overrides = override_modes.iter().enumerate().map(|(idx, mode)| asx_rs::interop::ProfileOverride {
            name: format!("ov-{idx}"),
            overrides: ProfilePolicyOverrides {
                mode: *mode,
                ..ProfilePolicyOverrides::default()
            },
        }).collect();

        let stack = ProfileStack {
            base: base_profile(base_mode),
            extensions,
            overrides,
            partner_overrides: vec![],
        };

        let s = session("partner-a", "strict");
        let first = stack.resolve(&s);
        let second = stack.resolve(&s);

        prop_assert_eq!(&first, &second);
        prop_assert_eq!(&first.snapshot.resolution_trace, &second.snapshot.resolution_trace);
        prop_assert_eq!(&first.snapshot.resolution_diagnostics, &second.snapshot.resolution_diagnostics);
    }

    #[test]
    fn property_partner_override_precedence_is_monotonic(
        base_mode in mode_strategy(),
        ext_mode in mode_strategy(),
        global_mode in mode_strategy(),
        partner_modes in proptest::collection::vec(mode_strategy(), 1..5),
    ) {
        let partner_overrides = partner_modes.iter().enumerate().map(|(idx, mode)| PartnerProfileOverlay {
            name: format!("partner-step-{idx}"),
            partner_id: "partner-a".to_string(),
            overrides: ProfilePolicyOverrides {
                mode: Some(*mode),
                ..ProfilePolicyOverrides::default()
            },
        }).collect();

        let stack = ProfileStack {
            base: base_profile(base_mode),
            extensions: vec![ProfileExtension {
                name: "ext".to_string(),
                overrides: ProfilePolicyOverrides {
                    mode: Some(ext_mode),
                    ..ProfilePolicyOverrides::default()
                },
            }],
            overrides: vec![asx_rs::interop::ProfileOverride {
                name: "global".to_string(),
                overrides: ProfilePolicyOverrides {
                    mode: Some(global_mode),
                    ..ProfilePolicyOverrides::default()
                },
            }],
            partner_overrides,
        };

        let a = stack.resolve(&session("partner-a", "p"));
        let b = stack.resolve(&session("partner-b", "p"));

        prop_assert_eq!(a.mode, *partner_modes.last().expect("non-empty"));
        prop_assert_eq!(b.mode, global_mode);
    }

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn property_conflicting_profile_inputs_fail_fast_with_machine_codes(
        strict_mode in any::<bool>(),
        disable_signature in any::<bool>(),
        disable_encryption in any::<bool>(),
    ) {
        let stack = ProfileStack {
            base: BaseProfile {
                name: "base".to_string(),
                version: "1".to_string(),
                mode: if strict_mode { InteropMode::Strict } else { InteropMode::Relaxed },
                canonicalization: CanonicalizationPolicy::default(),
                security: SecurityPolicy {
                    require_signature: !disable_signature,
                    require_encryption: !disable_encryption,
                },
                validation: ValidationPolicy::default(),
            },
            extensions: vec![],
            overrides: vec![],
            partner_overrides: vec![],
        };

        if let Err(failure) = stack.validate() {
            let codes: Vec<ProfileValidationCode> = failure.errors.iter().map(|issue| issue.code).collect();
            for issue in &failure.errors {
                prop_assert!(!issue.remediation_hint.trim().is_empty());
            }
            prop_assert!(!codes.is_empty());
        }
    }
}
