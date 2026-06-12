use asx::interop::{DiffRiskLevel, EffectivePolicySnapshot, diff_effective_policy_snapshots};

pub fn run(args: &[String]) -> Result<(), String> {
    let mut args = args.iter();
    let before_path = args.next().ok_or_else(|| {
        "usage: profile-diff-gate <before_snapshot.json> <after_snapshot.json>".to_string()
    })?;
    let after_path = args.next().ok_or_else(|| {
        "usage: profile-diff-gate <before_snapshot.json> <after_snapshot.json>".to_string()
    })?;

    if args.next().is_some() {
        return Err(
            "usage: profile-diff-gate <before_snapshot.json> <after_snapshot.json>".to_string(),
        );
    }

    let before_raw = std::fs::read_to_string(before_path)
        .map_err(|err| format!("failed reading before snapshot {}: {}", before_path, err))?;
    let after_raw = std::fs::read_to_string(after_path)
        .map_err(|err| format!("failed reading after snapshot {}: {}", after_path, err))?;

    let before = EffectivePolicySnapshot::from_json(&before_raw)
        .map_err(|err| format!("invalid before snapshot: {}", err))?;
    let after = EffectivePolicySnapshot::from_json(&after_raw)
        .map_err(|err| format!("invalid after snapshot: {}", err))?;

    let report = diff_effective_policy_snapshots(&before, &after);
    let json = report
        .to_json_pretty()
        .map_err(|err| format!("failed to serialize diff report: {}", err))?;
    println!("{}", json);

    if report.highest_risk == DiffRiskLevel::High || report.release_blocked {
        return Err("high-risk profile diff detected; release gate blocked".to_string());
    }

    Ok(())
}
