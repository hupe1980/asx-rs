//! Security-floor enforcement, monotonic-relaxation reporting, session-free
//! resolution, and error-type composability for [`asx_rs::interop`].
//!
//! Driven by integrator feedback from a BDEW Marktkommunikation deployment
//! (`asx-rs` 0.11.0): a partner overlay could turn `require_encryption` off and
//! `ProfileStack::validate()` still reported the stack as valid, and
//! `ProfileValidationFailure` implemented neither `Display` nor `Error`.

use std::error::Error as StdError;

use asx_rs::core::{AsxError, ErrorCode, SessionContext};
use asx_rs::interop::{
    BaseProfile, PartnerProfileOverlay, ProfileLintCode, ProfileLintSeverity, ProfileOverride,
    ProfilePolicyOverrides, ProfileStack, ProfileValidationCode, ProfileValidationOptions,
    SecurityPolicy, SecurityRequirement, diff_effective_policy_snapshots,
};

fn stack_with(partner_overrides: Vec<PartnerProfileOverlay>) -> ProfileStack {
    ProfileStack {
        base: BaseProfile::new("bdew-mako", "1.2"),
        extensions: vec![],
        overrides: vec![],
        partner_overrides,
    }
}

fn overlay(name: &str, partner_id: &str, security: SecurityPolicy) -> PartnerProfileOverlay {
    PartnerProfileOverlay {
        name: name.to_string(),
        partner_id: partner_id.to_string(),
        overrides: ProfilePolicyOverrides {
            security: Some(security),
            ..Default::default()
        },
    }
}

// ---------------------------------------------------------------------------
// BUG-2 — the reported downgrade
// ---------------------------------------------------------------------------

/// The exact reproduction from the feedback: a partner overlay that keeps
/// signing but drops encryption. In 0.11.0 this validated cleanly.
#[test]
fn partner_overlay_dropping_encryption_is_rejected() {
    let stack = stack_with(vec![overlay(
        "legacy-partner",
        "9900000000001",
        SecurityPolicy {
            require_signature: true,
            require_encryption: false,
        },
    )]);

    let failure = stack
        .validate()
        .expect_err("a partner overlay must not be able to disable encryption");

    assert!(failure.has_code(ProfileValidationCode::SecurityFloorViolation));
    assert_eq!(failure.affected_partners(), vec!["9900000000001"]);

    let issue = failure.first_error().expect("at least one error");
    assert_eq!(issue.partner_id.as_deref(), Some("9900000000001"));
    assert!(issue.layer.contains("legacy-partner"));
    assert!(
        issue.message.contains("require_encryption"),
        "message must name the missing requirement, got: {}",
        issue.message
    );
    assert!(!issue.remediation_hint.trim().is_empty());
}

/// The same overlay against a profile that genuinely permits sign-only:
/// accepted, but the relaxation is surfaced as a `Critical` lint rather than
/// disappearing silently.
#[test]
fn relaxation_above_the_floor_is_a_critical_lint_not_an_error() {
    let stack = ProfileStack {
        base: BaseProfile::new("legacy", "1.0").with_security_floor(SecurityPolicy::SIGN_ONLY),
        ..stack_with(vec![overlay(
            "legacy-partner",
            "9900000000001",
            SecurityPolicy::SIGN_ONLY,
        )])
    };

    let report = stack
        .validate()
        .expect("sign-only clears a sign-only floor");

    let relaxation = report
        .lints
        .iter()
        .find(|lint| lint.code == ProfileLintCode::SecurityRelaxation)
        .expect("relaxation must still be reported");

    assert_eq!(relaxation.severity, ProfileLintSeverity::Critical);
    assert_eq!(relaxation.partner_id.as_deref(), Some("9900000000001"));
    assert_eq!(
        report.highest_lint_severity(),
        Some(ProfileLintSeverity::Critical)
    );
    assert_eq!(
        report.lints_at_least(ProfileLintSeverity::Critical).count(),
        1
    );
}

/// `forbid_security_relaxation` escalates that lint to a hard error, for
/// deployments where overlays must not touch security at all.
#[test]
fn forbidding_relaxation_escalates_the_lint_to_an_error() {
    let stack = ProfileStack {
        base: BaseProfile::new("legacy", "1.0").with_security_floor(SecurityPolicy::SIGN_ONLY),
        ..stack_with(vec![overlay(
            "legacy-partner",
            "9900000000001",
            SecurityPolicy::SIGN_ONLY,
        )])
    };

    assert!(stack.validate().is_ok());

    let failure = stack
        .validate_with(&ProfileValidationOptions::default().forbidding_security_relaxation())
        .expect_err("relaxation must be fatal when forbidden");

    assert!(failure.has_code(ProfileValidationCode::SecurityRelaxation));
}

/// A deployment floor is combined with the profile's own floor by taking the
/// stronger of the two, so a host mandate can only tighten validation.
#[test]
fn deployment_floor_overrides_a_permissive_profile_floor() {
    let stack = ProfileStack {
        base: BaseProfile::new("legacy", "1.0").with_security_floor(SecurityPolicy::SIGN_ONLY),
        ..stack_with(vec![overlay(
            "legacy-partner",
            "9900000000001",
            SecurityPolicy::SIGN_ONLY,
        )])
    };

    assert!(stack.validate().is_ok(), "profile's own floor permits it");

    let failure = stack
        .validate_with_floor(SecurityPolicy::SIGN_AND_ENCRYPT)
        .expect_err("host mandate must win");
    assert!(failure.has_code(ProfileValidationCode::SecurityFloorViolation));

    // A floor weaker than the profile's own must not loosen anything.
    let strict = ProfileStack {
        base: BaseProfile::new("bdew", "1.2"),
        ..stack_with(vec![overlay(
            "legacy-partner",
            "9900000000001",
            SecurityPolicy::SIGN_ONLY,
        )])
    };
    assert!(
        strict
            .validate_with_floor(SecurityPolicy::UNCONSTRAINED)
            .is_err(),
        "a weaker deployment floor must not relax BaseProfile::security_floor"
    );
}

/// A dip that a later overlay restores has no runtime effect, so it must not
/// fail validation — but it is still reported as a lint.
#[test]
fn a_relaxation_masked_by_a_later_overlay_lints_without_failing() {
    let stack = stack_with(vec![
        overlay("step-1-relax", "9900000000001", SecurityPolicy::SIGN_ONLY),
        overlay(
            "step-2-restore",
            "9900000000001",
            SecurityPolicy::SIGN_AND_ENCRYPT,
        ),
    ]);

    let report = stack
        .validate()
        .expect("the resolved policy is what matters, and it is fully protected");

    assert!(
        report
            .lints
            .iter()
            .any(|lint| lint.code == ProfileLintCode::SecurityRelaxation),
        "the masked dip must still be visible"
    );
    assert_eq!(
        stack.resolve_partner("9900000000001").security,
        SecurityPolicy::SIGN_AND_ENCRYPT
    );
}

/// One partner's overlay must not contaminate another partner's findings.
/// Before the per-partner fork, validation walked every overlay in one
/// cumulative chain, so a downgrade on partner A was attributed to partner B.
#[test]
fn partner_scopes_are_isolated_from_each_other() {
    let stack = stack_with(vec![
        overlay("weak", "partner-a", SecurityPolicy::SIGN_ONLY),
        PartnerProfileOverlay {
            name: "unrelated".to_string(),
            partner_id: "partner-b".to_string(),
            overrides: ProfilePolicyOverrides::default(),
        },
    ]);

    let failure = stack.validate().expect_err("partner-a is below the floor");

    assert_eq!(
        failure.affected_partners(),
        vec!["partner-a"],
        "partner-b declares no security override and must be clean"
    );
    assert_eq!(
        stack.resolve_partner("partner-b").security,
        SecurityPolicy::SIGN_AND_ENCRYPT
    );
}

/// A global (non-partner) override is caught the same way, and attributed to
/// the deployment baseline rather than to a partner.
#[test]
fn global_override_below_the_floor_is_attributed_to_the_baseline() {
    let stack = ProfileStack {
        base: BaseProfile::new("bdew-mako", "1.2"),
        extensions: vec![],
        overrides: vec![ProfileOverride {
            name: "deployment-global".into(),
            overrides: ProfilePolicyOverrides {
                security: Some(SecurityPolicy::ENCRYPT_ONLY),
                ..Default::default()
            },
        }],
        partner_overrides: vec![],
    };

    let failure = stack.validate().expect_err("global override drops signing");
    assert!(failure.affected_partners().is_empty());

    let issue = failure.first_error().expect("error");
    assert_eq!(issue.layer, "override:deployment-global");
    assert!(issue.message.contains("require_signature"));
}

// ---------------------------------------------------------------------------
// BUG-1 — error composability
// ---------------------------------------------------------------------------

#[test]
fn validation_failure_composes_as_a_standard_error() {
    let stack = stack_with(vec![overlay(
        "legacy-partner",
        "9900000000001",
        SecurityPolicy::SIGN_ONLY,
    )]);
    let failure = stack.validate().expect_err("must fail");

    // Display, not Debug.
    let rendered = failure.to_string();
    assert!(rendered.starts_with("profile validation failed: 1 error(s)"));
    assert!(rendered.contains("security_floor_violation"));
    assert!(rendered.contains("hint:"));
    assert!(
        !rendered.contains("ProfileValidationIssue"),
        "Display must not leak the Debug rendering: {rendered}"
    );
    assert!(
        !rendered.contains('\n'),
        "Display must stay on one line for log composition"
    );

    // std::error::Error, with the first issue as the source.
    let source = StdError::source(&failure).expect("source");
    assert!(source.to_string().contains("security_floor_violation"));

    // Boxable and usable in the anyhow / thiserror `#[from]` position.
    let boxed: Box<dyn StdError + Send + Sync> = Box::new(failure.clone());
    assert!(boxed.to_string().contains("profile validation failed"));

    // `?` into the crate's own error type.
    fn startup(stack: &ProfileStack) -> Result<(), AsxError> {
        stack.validate()?;
        Ok(())
    }
    let err = startup(&stack).expect_err("must propagate");
    assert_eq!(err.code, ErrorCode::PolicyViolation);
    assert!(err.to_string().contains("security_floor_violation"));
}

#[test]
fn report_renders_every_finding_across_multiple_lines() {
    let stack = stack_with(vec![
        overlay("weak-a", "partner-a", SecurityPolicy::SIGN_ONLY),
        overlay("weak-b", "partner-b", SecurityPolicy::ENCRYPT_ONLY),
    ]);
    let failure = stack.validate().expect_err("both partners are below floor");

    let report = failure.report();
    let lines: Vec<&str> = report.lines().collect();

    assert!(lines[0].starts_with("profile validation failed: 2 error(s)"));
    assert_eq!(
        lines.iter().filter(|l| l.contains("error ")).count(),
        2,
        "report must enumerate every error:\n{report}"
    );
    assert!(report.contains("partner-a"));
    assert!(report.contains("partner-b"));
    assert!(
        report.contains("lint  1."),
        "relaxation lints belong in the operator report too:\n{report}"
    );
}

#[test]
fn display_elides_beyond_the_error_limit_while_report_does_not() {
    let partners = ["p1", "p2", "p3", "p4", "p5"];
    let stack = stack_with(
        partners
            .iter()
            .map(|p| overlay("weak", p, SecurityPolicy::SIGN_ONLY))
            .collect(),
    );

    let failure = stack.validate().expect_err("all five are below floor");
    assert_eq!(failure.errors.len(), partners.len());
    assert_eq!(failure.affected_partners(), partners);

    let rendered = failure.to_string();
    let elided = partners.len() - asx_rs::interop::ProfileValidationFailure::DISPLAY_ERROR_LIMIT;
    assert!(
        rendered.contains(&format!("(+{elided} more)")),
        "Display must stay bounded: {rendered}"
    );
    for partner in partners {
        assert!(
            failure.report().contains(partner),
            "report() must not elide {partner}"
        );
    }
}

// ---------------------------------------------------------------------------
// FR-1 — session-free resolution
// ---------------------------------------------------------------------------

#[test]
fn resolve_all_partners_enumerates_the_baseline_and_every_partner() {
    let stack = stack_with(vec![
        overlay("weak", "partner-a", SecurityPolicy::SIGN_ONLY),
        overlay("also-weak", "partner-a", SecurityPolicy::SIGN_ONLY),
        PartnerProfileOverlay {
            name: "unrelated".to_string(),
            partner_id: "partner-b".to_string(),
            overrides: ProfilePolicyOverrides::default(),
        },
    ]);

    assert_eq!(stack.partner_ids(), vec!["partner-a", "partner-b"]);

    let views = stack.resolve_all_partners();
    let labels: Vec<&str> = views.iter().map(|v| v.scope_label()).collect();
    assert_eq!(labels, vec!["<baseline>", "partner-a", "partner-b"]);

    assert!(views[0].partner_id.is_none());
    assert!(views[0].satisfies(SecurityPolicy::SIGN_AND_ENCRYPT));
    assert!(!views[1].satisfies(SecurityPolicy::SIGN_AND_ENCRYPT));
    assert!(views[2].satisfies(SecurityPolicy::SIGN_AND_ENCRYPT));

    // This is the audit the integrator had to hand-roll.
    let weak: Vec<&str> = views
        .iter()
        .filter(|v| !v.satisfies(SecurityPolicy::SIGN_AND_ENCRYPT))
        .map(|v| v.scope_label())
        .collect();
    assert_eq!(weak, vec!["partner-a"]);
}

/// The session-free view must never drift from what a live session resolves to
/// — they share one resolution path.
#[test]
fn session_free_resolution_matches_session_resolution() {
    let stack = stack_with(vec![overlay(
        "legacy-partner",
        "9900000000001",
        SecurityPolicy::SIGN_ONLY,
    )]);

    for partner in ["9900000000001", "some-other-partner"] {
        let session = SessionContext::new("s1", partner, "prof").expect("session");
        let effective = stack.resolve(&session);
        let view = stack.resolve_partner(partner);

        assert_eq!(view.security, effective.security);
        assert_eq!(view.mode, effective.mode);
        assert_eq!(view.canonicalization, effective.canonicalization);
        assert_eq!(view.validation, effective.validation);
        assert_eq!(view.as2_validation, effective.as2_validation);
        assert_eq!(view.resolution_trace, effective.snapshot.resolution_trace);
        assert_eq!(
            view.resolution_diagnostics,
            effective.snapshot.resolution_diagnostics
        );
    }

    // A partner with no overlay resolves to the baseline policy.
    assert_eq!(
        stack.resolve_partner("unknown").security,
        stack.resolve_baseline().security
    );
}

// ---------------------------------------------------------------------------
// Floor visibility in snapshots and release gating
// ---------------------------------------------------------------------------

/// Lowering the floor is a High-risk, release-blocking change even though the
/// resolved policy is unchanged — it is exactly what makes a later overlay able
/// to relax security without validation objecting.
#[test]
fn lowering_the_security_floor_blocks_release_in_the_diff_gate() {
    let session = SessionContext::new("s1", "partner-a", "prof").expect("session");

    let before = stack_with(vec![]).resolve(&session).snapshot;
    let after = ProfileStack {
        base: BaseProfile::new("bdew-mako", "1.2")
            .with_security_floor(SecurityPolicy::UNCONSTRAINED),
        ..stack_with(vec![])
    }
    .resolve(&session)
    .snapshot;

    assert_eq!(
        before.security, after.security,
        "the resolved policy is deliberately unchanged"
    );

    let report = diff_effective_policy_snapshots(&before, &after);
    assert!(report.release_blocked, "a lowered floor must block release");
    assert!(
        report
            .changes
            .iter()
            .any(|c| c.rationale.contains("Security floor lowered")),
        "{:?}",
        report.changes
    );

    // Raising it back is a change worth reporting, but not a downgrade.
    let raised = diff_effective_policy_snapshots(&after, &before);
    assert!(!raised.release_blocked);
}

// ---------------------------------------------------------------------------
// Lattice
// ---------------------------------------------------------------------------

#[test]
fn security_policy_lattice_is_consistent() {
    let all = [
        SecurityPolicy::UNCONSTRAINED,
        SecurityPolicy::SIGN_ONLY,
        SecurityPolicy::ENCRYPT_ONLY,
        SecurityPolicy::SIGN_AND_ENCRYPT,
    ];

    assert_eq!(SecurityPolicy::default(), SecurityPolicy::SIGN_AND_ENCRYPT);

    for a in all {
        assert!(a.satisfies(a), "reflexive");
        assert!(a.satisfies(SecurityPolicy::UNCONSTRAINED), "bottom");
        assert!(SecurityPolicy::SIGN_AND_ENCRYPT.satisfies(a), "top");
        assert!(a.unmet_by(a).is_empty());

        for b in all {
            // strengthen is the join, weaken is the meet.
            assert!(a.strengthen(b).satisfies(a) && a.strengthen(b).satisfies(b));
            assert!(a.satisfies(a.weaken(b)) && b.satisfies(a.weaken(b)));
            assert_eq!(a.strengthen(b), b.strengthen(a));
            assert_eq!(a.weaken(b), b.weaken(a));
            // satisfies <=> nothing unmet <=> nothing relaxed.
            assert_eq!(b.satisfies(a), a.unmet_by(b).is_empty());
            assert_eq!(a.unmet_by(b), a.relaxations_to(b));
        }
    }

    assert_eq!(
        SecurityPolicy::SIGN_AND_ENCRYPT.unmet_by(SecurityPolicy::UNCONSTRAINED),
        SecurityRequirement::ALL.to_vec()
    );
    assert_eq!(SecurityRequirement::Signature.as_str(), "require_signature");
    assert_eq!(
        SecurityRequirement::Encryption.as_str(),
        "require_encryption"
    );
}

#[test]
fn diagnostic_codes_are_stable_strings() {
    assert_eq!(
        ProfileValidationCode::NoCriticalSecurityInvariant.as_str(),
        "no_critical_security_invariant"
    );
    assert_eq!(
        ProfileValidationCode::SecurityFloorViolation.as_str(),
        "security_floor_violation"
    );
    assert_eq!(
        ProfileValidationCode::SecurityRelaxation.as_str(),
        "security_relaxation"
    );
    assert_eq!(ProfileLintCode::DeadOverride.as_str(), "dead_override");
    assert_eq!(
        ProfileLintCode::SecurityRelaxation.as_str(),
        "security_relaxation"
    );
    assert_eq!(ProfileLintSeverity::Info.as_str(), "info");
    assert_eq!(ProfileLintSeverity::Critical.as_str(), "critical");
    assert!(ProfileLintSeverity::Critical > ProfileLintSeverity::Warning);
    assert!(ProfileLintSeverity::Warning > ProfileLintSeverity::Info);
}

/// The degenerate both-off case is still reported when the floor is permissive
/// enough not to preempt it.
#[test]
fn unconstrained_policy_is_rejected_even_with_no_floor() {
    let stack = ProfileStack {
        base: BaseProfile {
            security: SecurityPolicy::UNCONSTRAINED,
            ..BaseProfile::new("anything-goes", "1.0")
                .with_security_floor(SecurityPolicy::UNCONSTRAINED)
        },
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![],
    };

    let failure = stack.validate().expect_err("no invariant at all must fail");
    assert!(failure.has_code(ProfileValidationCode::NoCriticalSecurityInvariant));
    assert!(
        !failure.has_code(ProfileValidationCode::SecurityFloorViolation),
        "an unconstrained floor cannot be violated"
    );
}

#[test]
fn default_base_profile_is_fail_closed() {
    let base = BaseProfile::default();
    assert_eq!(base.security, SecurityPolicy::SIGN_AND_ENCRYPT);
    assert_eq!(base.security_floor, SecurityPolicy::SIGN_AND_ENCRYPT);
    assert!(stack_with(vec![]).validate().is_ok());
}

/// A baseline-level violation is reported once, not once per partner.
///
/// Every partner really is below the floor, but restating one root cause N+1
/// times buries it — and the `Display` line, which renders remediation hints,
/// would grow without bound. Partners whose overlays leave security untouched
/// resolve byte-for-byte to the baseline, so the baseline error covers them.
#[test]
fn a_baseline_violation_is_not_restated_once_per_partner() {
    let untouched = |id: &str| PartnerProfileOverlay {
        name: format!("{id}-overlay"),
        partner_id: id.to_string(),
        overrides: ProfilePolicyOverrides::default(),
    };

    let stack = ProfileStack {
        base: BaseProfile::new("bdew-mako", "1.2"),
        extensions: vec![],
        overrides: vec![ProfileOverride {
            name: "global-weak".into(),
            overrides: ProfilePolicyOverrides {
                security: Some(SecurityPolicy::SIGN_ONLY),
                ..Default::default()
            },
        }],
        partner_overrides: vec![untouched("pa"), untouched("pb"), untouched("pc")],
    };

    let failure = stack.validate().expect_err("baseline is below the floor");

    assert_eq!(failure.errors.len(), 1, "{}", failure.report());
    assert!(failure.affected_partners().is_empty());
    assert_eq!(
        failure.first_error().expect("error").layer,
        "override:global-weak"
    );

    // …but every partner really does resolve below the floor, and the
    // session-free view still says so.
    for partner in ["pa", "pb", "pc"] {
        assert!(
            !stack
                .resolve_partner(partner)
                .satisfies(SecurityPolicy::SIGN_AND_ENCRYPT)
        );
    }

    // A partner that *does* move security away from the baseline is still
    // reported in its own right.
    let mut with_own = stack.clone();
    with_own
        .partner_overrides
        .push(overlay("pd-weak", "pd", SecurityPolicy::ENCRYPT_ONLY));
    let failure = with_own.validate().expect_err("still failing");
    assert_eq!(failure.affected_partners(), vec!["pd"]);
    assert_eq!(failure.errors.len(), 2, "{}", failure.report());
}
