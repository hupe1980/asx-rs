use asx::fixtures::validate_fixture_catalog;
use std::path::Path;

pub fn run(args: &[String]) -> Result<(), String> {
    let mut args = args.iter();
    let catalog_path = args
        .next()
        .cloned()
        .unwrap_or_else(|| "tests/fixtures/interop/catalog.json".to_string());

    if args.next().is_some() {
        return Err(
            "usage: fixture-repo-validate [fixture_catalog.json]; default catalog is tests/fixtures/interop/catalog.json"
                .to_string(),
        );
    }

    let report =
        validate_fixture_catalog(Path::new(&catalog_path)).map_err(|err| format!("{}", err))?;
    let json = report.to_json_pretty().map_err(|err| format!("{}", err))?;

    println!("{}", json);
    Ok(())
}
