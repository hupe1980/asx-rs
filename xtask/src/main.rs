#[cfg(feature = "testing")]
mod fixture_repo_validate;
#[cfg(any(feature = "as2", feature = "as4"))]
mod fuzz_gate;
#[cfg(feature = "testing")]
mod interop_matrix;
mod perf_gate;
mod profile_coverage_gate;
mod profile_diff_gate;
#[cfg(feature = "as4")]
mod profile_lint_gate;
#[cfg(feature = "as4")]
mod wssec_vector_gate;

fn main() {
    if let Err(err) = run() {
        eprintln!("xtask failed: {err}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let command = args.next().ok_or_else(|| usage().to_string())?;
    let rest: Vec<String> = args.collect();

    match command.as_str() {
        "fixture-repo-validate" | "fixture_repo_validate" => {
            #[cfg(feature = "testing")]
            return fixture_repo_validate::run(&rest);
            #[cfg(not(feature = "testing"))]
            return Err("fixture-repo-validate requires the 'testing' feature".to_string());
        }
        "fuzz-gate" | "fuzz_gate" => {
            #[cfg(any(feature = "as2", feature = "as4"))]
            return fuzz_gate::run(&rest);
            #[cfg(not(any(feature = "as2", feature = "as4")))]
            return Err("fuzz-gate requires the 'as2' or 'as4' feature".to_string());
        }
        "interop-matrix" | "interop_matrix" => {
            #[cfg(feature = "testing")]
            return interop_matrix::run(&rest);
            #[cfg(not(feature = "testing"))]
            return Err("interop-matrix requires the 'testing' feature".to_string());
        }
        "perf-gate" | "perf_gate" => perf_gate::run(&rest),
        "profile-coverage-gate" | "profile_coverage_gate" => profile_coverage_gate::run(&rest),
        "profile-diff-gate" | "profile_diff_gate" => profile_diff_gate::run(&rest),
        "profile-lint-gate" | "profile_lint_gate" => {
            #[cfg(feature = "as4")]
            return profile_lint_gate::run(&rest);
            #[cfg(not(feature = "as4"))]
            return Err("profile-lint-gate requires the 'as4' feature".to_string());
        }
        "wssec-vector-gate" | "wssec_vector_gate" => {
            #[cfg(feature = "as4")]
            return wssec_vector_gate::run(&rest);
            #[cfg(not(feature = "as4"))]
            return Err("wssec-vector-gate requires the 'as4' feature".to_string());
        }
        "help" | "-h" | "--help" => {
            println!("{}", usage());
            Ok(())
        }
        _ => Err(format!("unknown command: {command}\n{}", usage())),
    }
}

fn usage() -> &'static str {
    "usage: cargo run -p xtask -- <command> [args]\n\ncommands:\n  fixture-repo-validate [catalog_path]\n  fuzz-gate [iterations] [budget_ms] [output_dir]\n  interop-matrix [catalog_path] [quarantine_path] [iterations]\n  perf-gate [--iterations N] [--check-baseline PATH] [--write-baseline PATH] [--max-regression F]\n  profile-coverage-gate <llvm_cov_json> [threshold_percent] [file_substrings_csv]\n  profile-diff-gate <before_snapshot.json> <after_snapshot.json>\n  profile-lint-gate\n  wssec-vector-gate"
}
