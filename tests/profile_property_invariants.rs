#![cfg(feature = "interop-relaxed")]
#![cfg(all(feature = "as2", feature = "as4"))]

use asx_rs::core::{InteropMode, SessionContext};
use asx_rs::interop::{
    As2ValidationPolicy, BaseProfile, CanonicalizationPolicy, PartnerProfileOverlay,
    ProfileExtension, ProfilePolicyOverrides, ProfileStack, ProfileValidationCode, SecurityPolicy,
    ValidationPolicy,
};
use proptest::prelude::*;

fn session(partner: &str, profile: &str) -> SessionContext {
    SessionContext::new(format!("prop-{partner}-{profile}"), partner, profile).expect("session")
}

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
        security_floor: SecurityPolicy::default(),
        validation: ValidationPolicy::default(),
        as2_validation: As2ValidationPolicy::default(),
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
                mode: if strict_mode { InteropMode::Strict } else { InteropMode::Relaxed },
                security: SecurityPolicy {
                    require_signature: !disable_signature,
                    require_encryption: !disable_encryption,
                },
                ..base_profile(InteropMode::Strict)
            },
            extensions: vec![],
            overrides: vec![],
            partner_overrides: vec![],
        };

        // The default floor is sign-and-encrypt, so dropping *either*
        // requirement must fail — this is the BUG-2 invariant: a base that
        // keeps signing but drops encryption is no longer accepted.
        let result = stack.validate();
        prop_assert_eq!(result.is_err(), disable_signature || disable_encryption);

        if let Err(failure) = result {
            let codes: Vec<ProfileValidationCode> = failure.errors.iter().map(|issue| issue.code).collect();
            for issue in &failure.errors {
                prop_assert!(!issue.remediation_hint.trim().is_empty());
            }
            prop_assert!(codes.contains(&ProfileValidationCode::SecurityFloorViolation));
            // Display must be usable in a log line, never the Debug form.
            prop_assert!(failure.to_string().starts_with("profile validation failed:"));
        }
    }

    /// Monotonicity: no partner overlay can push a partner below the floor,
    /// however many overlays it stacks.
    #[test]
    fn property_no_partner_overlay_can_breach_the_security_floor(
        overlay_policies in proptest::collection::vec(
            (any::<bool>(), any::<bool>()),
            1..5,
        ),
    ) {
        let partner_overrides = overlay_policies.iter().enumerate().map(|(idx, (sig, enc))| PartnerProfileOverlay {
            name: format!("overlay-{idx}"),
            partner_id: "9900000000001".to_string(),
            overrides: ProfilePolicyOverrides {
                security: Some(SecurityPolicy {
                    require_signature: *sig,
                    require_encryption: *enc,
                }),
                ..ProfilePolicyOverrides::default()
            },
        }).collect();

        let stack = ProfileStack {
            base: base_profile(InteropMode::Strict),
            extensions: vec![],
            overrides: vec![],
            partner_overrides,
        };

        let last = overlay_policies.last().copied().expect("non-empty");
        let final_policy_is_full = last.0 && last.1;

        // validate() agrees with what the partner actually resolves to.
        prop_assert_eq!(stack.validate().is_ok(), final_policy_is_full);

        let resolved = stack.resolve_partner("9900000000001");
        prop_assert_eq!(
            resolved.satisfies(SecurityPolicy::SIGN_AND_ENCRYPT),
            final_policy_is_full
        );
    }
}
