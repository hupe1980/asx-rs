use serde_json::Value;

pub fn run(args: &[String]) -> Result<(), String> {
    let mut args = args.iter();
    let report_path = args.next().ok_or_else(|| {
        "usage: profile-coverage-gate <llvm_cov_json> [threshold_percent] [file_substrings_csv]"
            .to_string()
    })?;
    let threshold = args
        .next()
        .map(|v| v.parse::<f64>())
        .transpose()
        .map_err(|err| format!("invalid threshold: {}", err))?
        .unwrap_or(85.0);
    let file_filters: Vec<String> = args
        .next()
        .cloned()
        .unwrap_or_else(|| "src/interop.rs".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if args.next().is_some() {
        return Err(
            "usage: profile-coverage-gate <llvm_cov_json> [threshold_percent] [file_substrings_csv]"
                .to_string(),
        );
    }

    let raw = std::fs::read_to_string(report_path)
        .map_err(|err| format!("failed reading coverage json {}: {}", report_path, err))?;
    let json: Value = serde_json::from_str(&raw)
        .map_err(|err| format!("failed parsing coverage json {}: {}", report_path, err))?;

    let files = json
        .get("data")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.get("files"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| "coverage json missing data[0].files".to_string())?;

    let mut selected = 0usize;
    let mut total_lines = 0u64;
    let mut covered_lines = 0u64;

    for file in files {
        let filename = file
            .get("filename")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if !file_filters.iter().any(|f| filename.contains(f)) {
            continue;
        }

        let lines = file
            .get("summary")
            .and_then(|v| v.get("lines"))
            .ok_or_else(|| format!("coverage json missing summary.lines for {}", filename))?;
        let count = lines
            .get("count")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| format!("coverage json missing lines.count for {}", filename))?;
        let covered = lines
            .get("covered")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| format!("coverage json missing lines.covered for {}", filename))?;

        total_lines += count;
        covered_lines += covered;
        selected += 1;
    }

    if selected == 0 || total_lines == 0 {
        return Err(format!(
            "no matching files found for coverage gate filters: {}",
            file_filters.join(",")
        ));
    }

    let percent = (covered_lines as f64 / total_lines as f64) * 100.0;
    println!(
        "{{\"coverage_gate\":\"profile-interop\",\"threshold\":{:.2},\"actual\":{:.2},\"files\":\"{}\"}}",
        threshold,
        percent,
        file_filters.join(",")
    );

    if percent + f64::EPSILON < threshold {
        return Err(format!(
            "coverage {:.2}% is below threshold {:.2}% for filters {}",
            percent,
            threshold,
            file_filters.join(",")
        ));
    }

    Ok(())
}
