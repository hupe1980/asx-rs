use asx::core::InteropMode;
use asx::interop::{
    ProfileLintFinding, ProfileValidationFailure, ProfileValidationIssue, SecurityPolicy,
};
use serde::Serialize;

pub fn run(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("usage: profile-lint-gate".to_string());
    }

    let mut failures = Vec::new();
    let catalog = profile_catalog();
    let profiles_checked = catalog.len();

    for profile in catalog {
        let mut profile_failures = Vec::new();

        if profile.base.base.mode != InteropMode::Strict {
            profile_failures.push(ProfileGateFailure::Simple {
                kind: "mode",
                message: "base mode must be Strict".to_string(),
            });
        }

        for (requirement, present) in [
            ("signature", profile.base.base.security.require_signature),
            ("encryption", profile.base.base.security.require_encryption),
        ] {
            if !present {
                profile_failures.push(ProfileGateFailure::Simple {
                    kind: "security",
                    message: format!("base policy must require {requirement}"),
                });
            }
        }

        // The gate asserts the shipped mandate (sign *and* encrypt) rather than
        // trusting each profile's own floor, so a profile cannot opt out of the
        // gate by lowering `BaseProfile::security_floor`. This resolves every
        // declared partner, so a partner overlay that relaxes security fails
        // here even when the base profile is impeccable.
        match profile
            .base
            .validate_with_floor(SecurityPolicy::SIGN_AND_ENCRYPT)
        {
            Ok(report) => {
                if !report.lints.is_empty() {
                    profile_failures.push(ProfileGateFailure::Lints {
                        lints: report.lints,
                    });
                }
            }
            Err(ProfileValidationFailure { errors, lints }) => {
                if !errors.is_empty() {
                    profile_failures.push(ProfileGateFailure::Errors { errors });
                }
                if !lints.is_empty() {
                    profile_failures.push(ProfileGateFailure::Lints { lints });
                }
            }
        }

        if !profile_failures.is_empty() {
            failures.push(ProfileFailureRecord {
                profile: profile.name,
                failures: profile_failures,
            });
        }
    }

    let summary = GateSummary {
        gate: "profile-lint-gate",
        profiles_checked,
        enforced_security_floor: SecurityPolicy::SIGN_AND_ENCRYPT,
        failures,
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&summary)
            .map_err(|err| format!("failed to serialize gate output: {err}"))?
    );

    if summary.failures.is_empty() {
        return Ok(());
    }

    // Render through Display rather than Debug so the CI log is readable
    // alongside the machine-readable JSON above.
    for record in &summary.failures {
        for failure in &record.failures {
            match failure {
                ProfileGateFailure::Simple { kind, message } => {
                    eprintln!("{}: [{kind}] {message}", record.profile);
                }
                ProfileGateFailure::Errors { errors } => {
                    for issue in errors {
                        eprintln!("{}: {issue}", record.profile);
                    }
                }
                ProfileGateFailure::Lints { lints } => {
                    for lint in lints {
                        eprintln!("{}: {lint}", record.profile);
                    }
                }
            }
        }
    }

    Err("profile lint gate failed: profile validation errors/lints detected".to_string())
}

struct NamedProfile {
    name: &'static str,
    base: asx::interop::ProfileStack,
}

fn profile_catalog() -> [NamedProfile; 0] {
    // asx::profiles sub-crates are not yet published; catalog is empty until
    // profile crates are implemented and added as xtask dependencies.
    []
}

#[derive(Debug, Serialize)]
struct GateSummary {
    gate: &'static str,
    profiles_checked: usize,
    /// Recorded in the gate output so a change to the enforced mandate is
    /// visible in CI history rather than only in this source file.
    enforced_security_floor: SecurityPolicy,
    failures: Vec<ProfileFailureRecord>,
}

#[derive(Debug, Serialize)]
struct ProfileFailureRecord {
    profile: &'static str,
    failures: Vec<ProfileGateFailure>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ProfileGateFailure {
    Simple { kind: &'static str, message: String },
    Errors { errors: Vec<ProfileValidationIssue> },
    Lints { lints: Vec<ProfileLintFinding> },
}
