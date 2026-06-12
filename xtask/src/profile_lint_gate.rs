use asx::core::InteropMode;
use asx::interop::{ProfileLintFinding, ProfileValidationFailure, ProfileValidationIssue};
use asx::profiles::bdew::BdewProfile;
use asx::profiles::bpc::BpcProfile;
use asx::profiles::cef::CefProfile;
use asx::profiles::dbnalliance::DbnProfile;
use asx::profiles::edelivery2::EDelivery2Profile;
use asx::profiles::eespa::EespaProfile;
use asx::profiles::entsog::EntsoGProfile;
use asx::profiles::erds::ErdsProfile;
use asx::profiles::euctp::EuctpProfile;
use asx::profiles::eudamed::EudamedProfile;
use asx::profiles::hredelivery::HrEdeliveryProfile;
use asx::profiles::peppol::PeppolProfile;
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
        profiles_checked: 12,
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

fn profile_catalog() -> [NamedProfile; 12] {
    [
        NamedProfile {
            name: "bdew",
            base: BdewProfile::profile_stack(),
        },
        NamedProfile {
            name: "bpc",
            base: BpcProfile::profile_stack(),
        },
        NamedProfile {
            name: "cef",
            base: CefProfile::profile_stack(),
        },
        NamedProfile {
            name: "dbnalliance",
            base: DbnProfile::profile_stack(),
        },
        NamedProfile {
            name: "edelivery2",
            base: EDelivery2Profile::profile_stack(),
        },
        NamedProfile {
            name: "eespa",
            base: EespaProfile::profile_stack(),
        },
        NamedProfile {
            name: "entsog",
            base: EntsoGProfile::profile_stack(),
        },
        NamedProfile {
            name: "erds",
            base: ErdsProfile::profile_stack(),
        },
        NamedProfile {
            name: "euctp",
            base: EuctpProfile::profile_stack(),
        },
        NamedProfile {
            name: "eudamed",
            base: EudamedProfile::profile_stack(),
        },
        NamedProfile {
            name: "hredelivery",
            base: HrEdeliveryProfile::profile_stack(),
        },
        NamedProfile {
            name: "peppol",
            base: PeppolProfile::profile_stack(),
        },
    ]
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
