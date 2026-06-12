use asx::core::InteropMode;
use asx::interop::{ProfileLintFinding, ProfileValidationFailure, ProfileValidationIssue};
use serde::Serialize;

pub fn run(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("usage: profile-lint-gate".to_string());
    }

    let mut failures = Vec::new();

    for profile in profile_catalog() {
        let mut profile_failures = Vec::new();

        if profile.base.base.mode != InteropMode::Strict {
            profile_failures.push(ProfileGateFailure::Simple {
                kind: "mode",
                message: "base mode must be Strict".to_string(),
            });
        }

        if !profile.base.base.security.require_signature {
            profile_failures.push(ProfileGateFailure::Simple {
                kind: "security",
                message: "base policy must require signature".to_string(),
            });
        }

        if !profile.base.base.security.require_encryption {
            profile_failures.push(ProfileGateFailure::Simple {
                kind: "security",
                message: "base policy must require encryption".to_string(),
            });
        }

        match profile.base.validate() {
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
        profiles_checked: 0,
        failures,
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&summary)
            .map_err(|err| format!("failed to serialize gate output: {err}"))?
    );

    if summary.failures.is_empty() {
        Ok(())
    } else {
        Err("profile lint gate failed: profile validation errors/lints detected".to_string())
    }
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
