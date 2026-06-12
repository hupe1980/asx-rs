use super::*;
use crate::core::SessionContext;

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
fn override_precedence_is_deterministic() {
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
            name: "partner".into(),
            overrides: ProfilePolicyOverrides {
                mode: Some(InteropMode::Strict),
                ..ProfilePolicyOverrides::default()
            },
        }],
        partner_overrides: vec![],
    };

    let session = SessionContext::new("s1", "p1", "strict-profile").expect("session");
    let effective = stack.resolve(&session);
    assert_eq!(effective.mode, InteropMode::Strict);
    assert_eq!(
        effective.snapshot.resolution_trace,
        vec![
            "base:base=>Strict".to_string(),
            format!(
                "base:base.canonicalization=>{:?}",
                CanonicalizationPolicy::default()
            ),
            format!("base:base.security=>{:?}", SecurityPolicy::default()),
            format!("base:base.validation=>{:?}", ValidationPolicy::default()),
            "extension:vendor.mode=>Relaxed".into(),
            "override:partner.mode=>Strict".into(),
        ]
    );
    assert_eq!(
        effective.snapshot.resolution_diagnostics,
        vec![
            ResolutionDiagnostic {
                layer: ResolutionLayer::Extension,
                layer_name: "vendor".to_string(),
                field: ResolutionField::Mode,
                previous_value: "Strict".to_string(),
                new_value: "Relaxed".to_string(),
            },
            ResolutionDiagnostic {
                layer: ResolutionLayer::Override,
                layer_name: "partner".to_string(),
                field: ResolutionField::Mode,
                previous_value: "Relaxed".to_string(),
                new_value: "Strict".to_string(),
            },
        ]
    );
}

#[cfg(feature = "interop-relaxed")]
#[test]
fn extension_conflicts_resolve_by_declaration_order() {
    let stack = ProfileStack {
        base: base_profile(),
        extensions: vec![
            ProfileExtension {
                name: "vendor-a".into(),
                overrides: ProfilePolicyOverrides {
                    mode: Some(InteropMode::Relaxed),
                    ..ProfilePolicyOverrides::default()
                },
            },
            ProfileExtension {
                name: "vendor-b".into(),
                overrides: ProfilePolicyOverrides {
                    mode: Some(InteropMode::Strict),
                    ..ProfilePolicyOverrides::default()
                },
            },
        ],
        overrides: vec![],
        partner_overrides: vec![],
    };

    let session = SessionContext::new("s1", "p1", "profile-a").expect("session");
    let effective = stack.resolve(&session);
    assert_eq!(effective.mode, InteropMode::Strict);
    assert_eq!(
        effective.snapshot.resolution_trace,
        vec![
            "base:base=>Strict".to_string(),
            format!(
                "base:base.canonicalization=>{:?}",
                CanonicalizationPolicy::default()
            ),
            format!("base:base.security=>{:?}", SecurityPolicy::default()),
            format!("base:base.validation=>{:?}", ValidationPolicy::default()),
            "extension:vendor-a.mode=>Relaxed".into(),
            "extension:vendor-b.mode=>Strict".into(),
        ]
    );
}

#[cfg(feature = "interop-relaxed")]
#[test]
fn snapshot_is_session_aware_and_attachable() {
    let stack = ProfileStack {
        base: BaseProfile {
            name: "default".into(),
            ..base_profile()
        },
        extensions: vec![],
        overrides: vec![ProfileOverride {
            name: "runtime".into(),
            overrides: ProfilePolicyOverrides {
                mode: Some(InteropMode::Relaxed),
                ..ProfilePolicyOverrides::default()
            },
        }],
        partner_overrides: vec![],
    };

    let session = SessionContext::new("sess-42", "partner-z", "runtime-profile").expect("session");
    let effective = stack.resolve(&session);

    assert_eq!(effective.name, "default@runtime-profile");
    assert_eq!(effective.snapshot.session_id, "sess-42");
    assert_eq!(effective.snapshot.partner_id, "partner-z");
    assert_eq!(effective.snapshot.profile_name, "runtime-profile");
    assert_eq!(effective.snapshot.resolved_mode, InteropMode::Relaxed);

    let detail = effective.snapshot.as_event_detail();
    assert!(detail.contains("session=sess-42"));
    assert!(detail.contains("partner=partner-z"));
    assert!(detail.contains("profile=runtime-profile"));
    assert!(detail.contains("mode=Relaxed"));
}

#[cfg(feature = "interop-relaxed")]
#[test]
fn snapshot_json_round_trip_is_stable() {
    let stack = ProfileStack {
        base: base_profile(),
        extensions: vec![ProfileExtension {
            name: "vendor".into(),
            overrides: ProfilePolicyOverrides {
                mode: Some(InteropMode::Relaxed),
                security: Some(SecurityPolicy {
                    require_encryption: false,
                    ..SecurityPolicy::default()
                }),
                ..ProfilePolicyOverrides::default()
            },
        }],
        overrides: vec![],
        partner_overrides: vec![],
    };
    let session = SessionContext::new("sess-1", "partner-1", "profile-1").expect("session");
    let snapshot = stack.resolve(&session).snapshot;
    let json = snapshot.to_json_pretty().expect("json");
    let decoded = EffectivePolicySnapshot::from_json(&json).expect("decode");

    assert_eq!(snapshot, decoded);
    assert!(json.contains("\"resolved_mode\""));
    assert!(json.contains("\"canonicalization\""));
    assert!(json.contains("\"security\""));
    assert!(json.contains("\"validation\""));
    assert!(json.contains("\"resolution_diagnostics\""));
}

#[cfg(feature = "interop-relaxed")]
#[test]
fn identical_inputs_yield_identical_effective_profiles() {
    let stack = ProfileStack {
        base: base_profile(),
        extensions: vec![ProfileExtension {
            name: "vendor-a".into(),
            overrides: ProfilePolicyOverrides {
                mode: Some(InteropMode::Relaxed),
                security: Some(SecurityPolicy {
                    require_encryption: false,
                    ..SecurityPolicy::default()
                }),
                ..ProfilePolicyOverrides::default()
            },
        }],
        overrides: vec![ProfileOverride {
            name: "partner-a".into(),
            overrides: ProfilePolicyOverrides::default(),
        }],
        partner_overrides: vec![],
    };

    let session = SessionContext::new("s1", "p1", "profile-a").expect("session");
    let first = stack.resolve(&session);
    let second = stack.resolve(&session);

    assert_eq!(first, second);
    assert_eq!(
        first.snapshot.resolution_trace,
        second.snapshot.resolution_trace
    );
    assert_eq!(
        first.snapshot.resolution_diagnostics,
        second.snapshot.resolution_diagnostics
    );
}

#[test]
fn explicit_policy_layers_resolve_deterministically() {
    let stack = ProfileStack {
        base: BaseProfile {
            name: "base".into(),
            version: "1".into(),
            mode: InteropMode::Strict,
            canonicalization: CanonicalizationPolicy {
                normalize_mime_headers: true,
                ..CanonicalizationPolicy::default()
            },
            security: SecurityPolicy::default(),
            validation: ValidationPolicy::default(),
        },
        extensions: vec![ProfileExtension {
            name: "vendor".into(),
            overrides: ProfilePolicyOverrides::default(),
        }],
        overrides: vec![ProfileOverride {
            name: "partner".into(),
            overrides: ProfilePolicyOverrides {
                validation: Some(ValidationPolicy {
                    require_as2_mic: false,
                    ..ValidationPolicy::default()
                }),
                ..ProfilePolicyOverrides::default()
            },
        }],
        partner_overrides: vec![],
    };

    let session = SessionContext::new("s1", "partner-a", "profile-a").expect("session");
    let effective = stack.resolve(&session);

    assert!(!effective.validation.require_as2_mic);
    assert_eq!(effective.mode, InteropMode::Strict);
}

#[test]
fn scoped_exception_policy_is_profile_bounded() {
    let s_allowed = SessionContext::new("s1", "p1", "partner-quirks").expect("session");
    let s_denied = SessionContext::new("s2", "p1", "strict-profile").expect("session");
    let policy = InteropExceptionPolicy::scoped(
        "partner-quirks",
        vec![InteropExceptionCode::As2AllowMissingMdnBoundary],
    );

    assert!(policy.allows(&s_allowed, InteropExceptionCode::As2AllowMissingMdnBoundary));
    assert!(!policy.allows(&s_denied, InteropExceptionCode::As2AllowMissingMdnBoundary));
}

#[cfg(feature = "interop-relaxed")]
#[test]
fn guardrail_classification_is_allowed_or_denied() {
    let session = SessionContext::new("s1", "p1", "partner-quirks").expect("session");
    let scoped_policy = InteropExceptionPolicy::scoped(
        "partner-quirks",
        vec![InteropExceptionCode::As2AllowMissingMdnBoundary],
    );

    assert_eq!(
        evaluate_exception_guardrail(
            &session,
            InteropMode::Relaxed,
            &scoped_policy,
            InteropExceptionCode::As2AllowMissingMdnBoundary,
        ),
        InteropGuardrailOutcome::Allowed
    );

    assert_eq!(
        evaluate_exception_guardrail(
            &session,
            InteropMode::Strict,
            &scoped_policy,
            InteropExceptionCode::As2AllowMissingMdnBoundary,
        ),
        InteropGuardrailOutcome::Denied
    );

    assert_eq!(
        evaluate_exception_guardrail(
            &session,
            InteropMode::Relaxed,
            &InteropExceptionPolicy::default(),
            InteropExceptionCode::As2AllowMissingMdnBoundary,
        ),
        InteropGuardrailOutcome::Denied
    );
}

#[test]
fn invalid_profile_combinations_fail_fast_with_machine_readable_codes() {
    let stack = ProfileStack {
        base: BaseProfile {
            name: "base".into(),
            version: "1".into(),
            mode: InteropMode::Strict,
            canonicalization: CanonicalizationPolicy::default(),
            security: SecurityPolicy {
                require_signature: false,
                require_encryption: false,
            },
            validation: ValidationPolicy::default(),
        },
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![],
    };

    let failure = stack.validate().expect_err("must fail");
    let codes: Vec<ProfileValidationCode> = failure.errors.iter().map(|e| e.code).collect();

    assert!(codes.contains(&ProfileValidationCode::NoCriticalSecurityInvariant));
    assert!(
        failure
            .errors
            .iter()
            .all(|issue| !issue.remediation_hint.trim().is_empty())
    );
}

#[test]
fn lint_finds_dead_and_contradictory_policy_entries() {
    let stack = ProfileStack {
        base: base_profile(),
        extensions: vec![ProfileExtension {
            name: "vendor-a".into(),
            overrides: ProfilePolicyOverrides {
                mode: Some(InteropMode::Strict),
                ..ProfilePolicyOverrides::default()
            },
        }],
        overrides: vec![],
        partner_overrides: vec![],
    };

    // A single DeadOverride (setting the same effective value) is a lint, not an error —
    // validate() succeeds with lint warnings.
    let report = stack
        .validate()
        .expect("valid stack with dead-override lint");
    let lint_codes: Vec<ProfileLintCode> =
        report.lints.iter().map(|finding| finding.code).collect();

    assert!(lint_codes.contains(&ProfileLintCode::DeadOverride));
}

#[test]
fn valid_profile_returns_report_with_lints_only() {
    let stack = ProfileStack {
        base: base_profile(),
        extensions: vec![ProfileExtension {
            name: "vendor-a".into(),
            overrides: ProfilePolicyOverrides {
                mode: Some(InteropMode::Strict),
                ..ProfilePolicyOverrides::default()
            },
        }],
        overrides: vec![],
        partner_overrides: vec![],
    };

    let report = stack.validate().expect("valid stack");
    assert_eq!(report.lints.len(), 1);
    assert_eq!(report.lints[0].code, ProfileLintCode::DeadOverride);
    assert!(!report.lints[0].remediation_hint.trim().is_empty());
}

#[cfg(feature = "interop-relaxed")]
#[test]
fn partner_profile_overlays_are_partner_scoped_with_traceable_precedence() {
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
                name: "acme-final".into(),
                partner_id: "partner-acme".into(),
                overrides: ProfilePolicyOverrides {
                    mode: Some(InteropMode::Strict),
                    ..ProfilePolicyOverrides::default()
                },
            },
            PartnerProfileOverlay {
                name: "globex-final".into(),
                partner_id: "partner-globex".into(),
                overrides: ProfilePolicyOverrides {
                    mode: Some(InteropMode::Relaxed),
                    ..ProfilePolicyOverrides::default()
                },
            },
        ],
    };

    let acme = SessionContext::new("s-acme", "partner-acme", "p3-overlay").expect("session");
    let globex = SessionContext::new("s-globex", "partner-globex", "p3-overlay").expect("session");

    let acme_effective = stack.resolve(&acme);
    let globex_effective = stack.resolve(&globex);

    assert_eq!(acme_effective.mode, InteropMode::Strict);
    assert!(
        acme_effective
            .snapshot
            .resolution_trace
            .iter()
            .any(|step| step == "partner_override:partner-acme:acme-final.mode=>Strict")
    );
    assert!(
        acme_effective
            .snapshot
            .resolution_diagnostics
            .iter()
            .any(|diag| {
                diag.layer == ResolutionLayer::PartnerOverride
                    && diag.layer_name == "partner-acme:acme-final"
                    && diag.field == ResolutionField::Mode
            })
    );

    assert_eq!(globex_effective.mode, InteropMode::Relaxed);
    assert!(
        globex_effective
            .snapshot
            .resolution_trace
            .iter()
            .any(|step| step == "partner_override:partner-globex:globex-final.mode=>Relaxed")
    );
}

#[test]
fn resolve_for_session_attaches_snapshot_to_session_metadata() {
    let stack = ProfileStack {
        base: base_profile(),
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![PartnerProfileOverlay {
            name: "acme".into(),
            partner_id: "partner-acme".into(),
            overrides: ProfilePolicyOverrides::default(),
        }],
    };

    let session = SessionContext::new("s-meta", "partner-acme", "p3-overlay").expect("session");
    let resolved = stack
        .resolve_for_session(&session)
        .expect("resolve and attach");

    let snapshot_json = resolved
        .session
        .effective_policy_snapshot_json()
        .expect("snapshot in metadata");
    let decoded = EffectivePolicySnapshot::from_json(snapshot_json).expect("decode snapshot");

    assert_eq!(decoded.session_id, "s-meta");
    assert_eq!(decoded.partner_id, "partner-acme");
    assert_eq!(decoded, resolved.effective_profile.snapshot);
}

#[cfg(feature = "interop-relaxed")]
#[test]
fn profile_diff_report_is_machine_readable_and_stable() {
    let before_stack = ProfileStack {
        base: base_profile(),
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![],
    };
    let after_stack = ProfileStack {
        base: base_profile(),
        extensions: vec![ProfileExtension {
            name: "vendor-relaxed".into(),
            overrides: ProfilePolicyOverrides {
                mode: Some(InteropMode::Relaxed),
                ..ProfilePolicyOverrides::default()
            },
        }],
        overrides: vec![],
        partner_overrides: vec![],
    };

    let session = SessionContext::new("s-diff", "partner-a", "diff-profile").expect("session");
    let before = before_stack.resolve(&session).snapshot;
    let after = after_stack.resolve(&session).snapshot;

    let report = diff_effective_policy_snapshots(&before, &after);
    let json = report.to_json_pretty().expect("json");

    assert!(json.contains("\"changes\""));
    assert!(json.contains("\"highest_risk\""));
    assert!(json.contains("\"release_blocked\""));
    assert!(
        report
            .changes
            .iter()
            .any(|entry| entry.field == ResolutionField::Mode)
    );
}

#[test]
fn profile_diff_blocks_release_for_high_risk_changes() {
    let before_stack = ProfileStack {
        base: base_profile(),
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![],
    };
    let after_stack = ProfileStack {
        base: BaseProfile {
            security: SecurityPolicy {
                require_signature: false,
                ..SecurityPolicy::default()
            },
            ..base_profile()
        },
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![],
    };

    let session = SessionContext::new("s-risk", "partner-a", "risk-profile").expect("session");
    let before = before_stack.resolve(&session).snapshot;
    let after = after_stack.resolve(&session).snapshot;

    let report = diff_effective_policy_snapshots(&before, &after);
    assert_eq!(report.highest_risk, DiffRiskLevel::High);
    assert!(report.release_blocked);
    assert!(
        report
            .changes
            .iter()
            .any(|entry| entry.field == ResolutionField::Security)
    );
}

#[test]
fn diff_no_changes_is_low_risk_and_does_not_block_release() {
    let stack = ProfileStack {
        base: base_profile(),
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![],
    };
    let session = SessionContext::new("s-nodiff", "partner-a", "p").expect("session");
    let snapshot = stack.resolve(&session).snapshot;
    let report = diff_effective_policy_snapshots(&snapshot, &snapshot);

    assert!(report.changes.is_empty());
    assert_eq!(report.highest_risk, DiffRiskLevel::Low);
    assert!(!report.release_blocked);
    report.to_json_pretty().expect("json serializable");
}

#[test]
fn diff_encryption_disabled_is_high_risk() {
    let before_stack = ProfileStack {
        base: base_profile(),
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![],
    };
    let after_stack = ProfileStack {
        base: BaseProfile {
            security: SecurityPolicy {
                require_encryption: false,
                ..SecurityPolicy::default()
            },
            ..base_profile()
        },
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![],
    };
    let session = SessionContext::new("s-enc", "partner-a", "p").expect("session");
    let before = before_stack.resolve(&session).snapshot;
    let after = after_stack.resolve(&session).snapshot;

    let report = diff_effective_policy_snapshots(&before, &after);
    assert_eq!(report.highest_risk, DiffRiskLevel::High);
    assert!(report.release_blocked);
}

#[test]
fn diff_payload_limits_disabled_is_high_risk() {
    let before_stack = ProfileStack {
        base: base_profile(),
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![],
    };
    let after_stack = ProfileStack {
        base: BaseProfile {
            validation: ValidationPolicy {
                enforce_payload_limits: false,
                ..ValidationPolicy::default()
            },
            ..base_profile()
        },
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![],
    };
    let session = SessionContext::new("s-payload", "partner-a", "p").expect("session");
    let before = before_stack.resolve(&session).snapshot;
    let after = after_stack.resolve(&session).snapshot;

    let report = diff_effective_policy_snapshots(&before, &after);
    assert_eq!(report.highest_risk, DiffRiskLevel::High);
    assert!(report.release_blocked);
    assert!(
        report
            .changes
            .iter()
            .any(|e| e.field == ResolutionField::Validation)
    );
}

#[test]
fn diff_mic_requirement_change_is_medium_risk() {
    let before_stack = ProfileStack {
        base: base_profile(),
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![],
    };
    let after_stack = ProfileStack {
        base: BaseProfile {
            validation: ValidationPolicy {
                require_as2_mic: false,
                ..ValidationPolicy::default()
            },
            ..base_profile()
        },
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![],
    };
    let session = SessionContext::new("s-mic", "partner-a", "p").expect("session");
    let before = before_stack.resolve(&session).snapshot;
    let after = after_stack.resolve(&session).snapshot;

    let report = diff_effective_policy_snapshots(&before, &after);
    assert_eq!(report.highest_risk, DiffRiskLevel::Medium);
    assert!(!report.release_blocked);
}

#[test]
fn diff_canonicalization_change_is_medium_risk() {
    let alt_c14n = CanonicalizationPolicy {
        normalize_mime_headers: false,
        ..CanonicalizationPolicy::default()
    };
    let before_stack = ProfileStack {
        base: base_profile(),
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![],
    };
    let after_stack = ProfileStack {
        base: BaseProfile {
            canonicalization: alt_c14n,
            ..base_profile()
        },
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![],
    };
    let session = SessionContext::new("s-c14n", "partner-a", "p").expect("session");
    let before = before_stack.resolve(&session).snapshot;
    let after = after_stack.resolve(&session).snapshot;

    let report = diff_effective_policy_snapshots(&before, &after);
    assert_eq!(report.highest_risk, DiffRiskLevel::Medium);
    assert!(
        report
            .changes
            .iter()
            .any(|e| e.field == ResolutionField::Canonicalization)
    );
}

#[test]
fn snapshot_as_event_detail_empty_trace_shows_none() {
    let snapshot = EffectivePolicySnapshot {
        session_id: "s1".into(),
        partner_id: "p1".into(),
        profile_name: "prof".into(),
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
fn interop_guardrail_outcome_as_str() {
    assert_eq!(InteropGuardrailOutcome::Allowed.as_str(), "Allowed");
    assert_eq!(InteropGuardrailOutcome::Denied.as_str(), "Denied");
}

#[test]
fn enforce_exception_strict_mode_returns_error() {
    let session = SessionContext::new("s1", "p1", "strict-profile").expect("session");
    let policy = InteropExceptionPolicy::default();
    let err = enforce_exception(
        &session,
        InteropMode::Strict,
        &policy,
        InteropExceptionCode::As2AllowMissingMdnBoundary,
        "test_stage",
        "strict mode message",
    )
    .expect_err("must fail in strict mode");
    assert!(err.to_string().contains("strict mode message"));
}

#[cfg(feature = "interop-relaxed")]
#[test]
fn enforce_exception_relaxed_allowed_returns_decision() {
    let session = SessionContext::new("s1", "p1", "partner-quirks").expect("session");
    let policy = InteropExceptionPolicy::scoped(
        "partner-quirks",
        vec![InteropExceptionCode::As2AllowMissingMdnBoundary],
    );
    let decision = enforce_exception(
        &session,
        InteropMode::Relaxed,
        &policy,
        InteropExceptionCode::As2AllowMissingMdnBoundary,
        "test_stage",
        "should not appear",
    )
    .expect("must succeed");
    assert!(
        matches!(decision, InteropDecision::RelaxedException { reason_code }
            if reason_code == "as2_missing_mdn_boundary")
    );
}

#[cfg(feature = "interop-relaxed")]
#[test]
fn enforce_exception_relaxed_denied_missing_policy_returns_error() {
    let session = SessionContext::new("s1", "p1", "other-profile").expect("session");
    let policy = InteropExceptionPolicy::default();
    let err = enforce_exception(
        &session,
        InteropMode::Relaxed,
        &policy,
        InteropExceptionCode::As2AllowMissingMdnBoundary,
        "test_stage",
        "strict message not used",
    )
    .expect_err("must fail");
    assert!(err.to_string().contains("missing scoped exception policy"));
}

#[test]
fn regional_pack_from_json_rejects_oversized_input() {
    let oversized = "x".repeat(RegionalProfilePack::MAX_PACK_JSON_BYTES + 1);
    let err = RegionalProfilePack::from_json(&oversized).expect_err("must reject oversized");
    assert_eq!(err.code, crate::core::ErrorCode::PayloadTooLarge);
}

#[test]
fn regional_pack_from_json_rejects_invalid_json() {
    let err = RegionalProfilePack::from_json("not-json!!").expect_err("must reject invalid json");
    assert_eq!(err.code, crate::core::ErrorCode::ParseFailed);
}

#[test]
fn regional_pack_validate_rejects_empty_pack_id() {
    let json = serde_json::json!({
        "pack_id": "",
        "version": "1.0.0",
        "applies_to_base_profile": "base",
        "overrides": {}
    })
    .to_string();
    let err = RegionalProfilePack::from_json(&json).expect_err("must reject empty pack_id");
    assert_eq!(err.code, crate::core::ErrorCode::InvalidInput);
}

#[test]
fn regional_pack_validate_rejects_empty_base_profile() {
    let json = serde_json::json!({
        "pack_id": "test-pack",
        "version": "1.0.0",
        "applies_to_base_profile": "",
        "overrides": {}
    })
    .to_string();
    let err =
        RegionalProfilePack::from_json(&json).expect_err("must reject empty base profile name");
    assert_eq!(err.code, crate::core::ErrorCode::InvalidInput);
}

#[test]
fn regional_pack_validate_rejects_invalid_version() {
    let json = serde_json::json!({
        "pack_id": "test-pack",
        "version": "not-semver",
        "applies_to_base_profile": "base",
        "overrides": {}
    })
    .to_string();
    let err = RegionalProfilePack::from_json(&json).expect_err("must reject invalid version");
    assert_eq!(err.code, crate::core::ErrorCode::InvalidInput);
}

#[test]
fn regional_pack_validate_rejects_extra_version_parts() {
    let json = serde_json::json!({
        "pack_id": "test-pack",
        "version": "1.2.3.4",
        "applies_to_base_profile": "base",
        "overrides": {}
    })
    .to_string();
    let err = RegionalProfilePack::from_json(&json).expect_err("must reject 4-part version");
    assert_eq!(err.code, crate::core::ErrorCode::InvalidInput);
}

#[test]
fn regional_pack_apply_rejects_base_profile_mismatch() {
    let stack = ProfileStack {
        base: base_profile(),
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![],
    };
    let json = serde_json::json!({
        "pack_id": "test-pack",
        "version": "1.0.0",
        "applies_to_base_profile": "wrong-base",
        "overrides": {}
    })
    .to_string();
    let pack = RegionalProfilePack::from_json(&json).expect("valid pack");
    let err = stack
        .apply_regional_pack(&pack)
        .expect_err("must reject mismatched base");
    assert_eq!(err.code, crate::core::ErrorCode::PolicyViolation);
}

#[test]
fn regional_packs_apply_multiple_packs_in_order() {
    let stack = ProfileStack {
        base: base_profile(),
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![],
    };
    let pack_a = serde_json::json!({
        "pack_id": "pack-a",
        "version": "1.0.0",
        "applies_to_base_profile": "base",
        "overrides": {}
    })
    .to_string();
    let pack_b = serde_json::json!({
        "pack_id": "pack-b",
        "version": "2.0.0",
        "applies_to_base_profile": "base",
        "overrides": {}
    })
    .to_string();
    let p_a = RegionalProfilePack::from_json(&pack_a).expect("pack-a");
    let p_b = RegionalProfilePack::from_json(&pack_b).expect("pack-b");
    let merged = stack
        .apply_regional_packs(&[p_a, p_b])
        .expect("apply packs");
    assert_eq!(merged.extensions.len(), 2);
    assert!(merged.extensions[0].name.contains("pack-a"));
    assert!(merged.extensions[1].name.contains("pack-b"));
}
