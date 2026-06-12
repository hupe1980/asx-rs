use asx::matrix::run_interop_fixture_matrix;
use std::path::Path;

pub fn run(args: &[String]) -> Result<(), String> {
    let mut args = args.iter();
    let catalog_path = args
        .next()
        .cloned()
        .unwrap_or_else(|| "tests/fixtures/interop/catalog.json".to_string());
    let quarantine_path = args
        .next()
        .cloned()
        .unwrap_or_else(|| "tests/fixtures/interop/quarantine.json".to_string());
    let iterations = args
        .next()
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|err| format!("invalid iterations argument: {}", err))?
        .unwrap_or(3);

    if args.next().is_some() {
        return Err(
            "usage: interop-matrix [catalog_path] [quarantine_path] [iterations]".to_string(),
        );
    }

    let summary = run_interop_fixture_matrix(
        Path::new(&catalog_path),
        Path::new(&quarantine_path),
        iterations,
    )
    .map_err(|err| format!("{}", err))?;

    let json = summary.to_json_pretty().map_err(|err| format!("{}", err))?;
    println!("{}", json);

    if summary.has_blocking_failures() {
        return Err(
            "matrix run contains blocking failures or unquarantined flaky fixtures".to_string(),
        );
    }

    Ok(())
}
