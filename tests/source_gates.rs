//! Source gates: properties of `src/` that the type system cannot state,
//! checked by reading the source.
//!
//! - The internal policy views are built only by the profile views
//!   (`src/profile.rs` for AS4, `src/as2/client.rs` for AS2).
//! - `Verified::new` has exactly four call sites: the AS4 and AS2 send
//!   clients (a verified receipt or MDN) and the AS4 and AS2 inbound paths (a
//!   verified message).
//! - No `block_on`/`block_in_place` in the library.
//! - No removed revocation knob (`OcspMode`, `revocation_crl_pems`,
//!   `ocsp_client`), one CRL parser (`src/revocation/crl.rs`) and one OCSP
//!   verifier (`src/revocation/ocsp.rs`).
//! - No `testing` feature branch and no `InteropMode`.
//! - Wall-clock time only through `crate::clock`; golden examples ≤ 25 lines;
//!   no ```` ```ignore ```` doctest.

use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `(path relative to the crate root, line number, line)` of every non-comment
/// line in `src/`.
fn src_lines() -> Vec<(String, usize, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    files.sort();
    let mut lines = Vec::new();
    for file in files {
        let rel = file
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(&file).expect("read source");
        for (i, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            lines.push((rel.clone(), i + 1, line.to_string()));
        }
    }
    lines
}

const POLICY_TYPES: [&str; 4] = [
    "As4SendPolicy",
    "As4PushPolicy",
    "As4ReceiptPolicy",
    "As2SendPolicy",
];

const POLICY_VIEW_FILES: [&str; 2] = ["src/profile.rs", "src/as2/client.rs"];

/// A struct literal or a constructor call of `ty` on `line`.
fn constructs(line: &str, ty: &str) -> bool {
    let mut rest = line;
    while let Some(at) = rest.find(ty) {
        let before = &rest[..at];
        let after = &rest[at + ty.len()..];
        let boundary = !before
            .chars()
            .last()
            .is_some_and(|c| c.is_alphanumeric() || c == '_');
        let declaration = before.trim_end().ends_with("struct")
            || before.trim_end().ends_with("for")
            || before.trim_start().starts_with("impl")
            || before.contains("->");
        let literal = after.starts_with(" {") && !declaration;
        let constructor = [
            "::default(",
            "::strict(",
            "::regulated(",
            "::relaxed(",
            "::new(",
            "::builder(",
        ]
        .iter()
        .any(|c| after.starts_with(c));
        if boundary && (literal || constructor) {
            return true;
        }
        rest = after;
    }
    false
}

#[test]
fn internal_policies_are_built_only_by_the_profile_views() {
    let lines = src_lines();
    let mut found_in_views = 0;
    let mut outside = Vec::new();
    for (file, n, line) in &lines {
        for ty in POLICY_TYPES {
            if constructs(line, ty) {
                if POLICY_VIEW_FILES.contains(&file.as_str()) {
                    found_in_views += 1;
                } else {
                    outside.push(format!("{file}:{n}: {}", line.trim()));
                }
            }
        }
    }
    assert!(
        outside.is_empty(),
        "internal policy built outside the profile views (FR-004):\n{}",
        outside.join("\n")
    );
    // The gate is not vacuous: the four views are found.
    assert_eq!(
        found_in_views, 4,
        "the profile views construct each policy once"
    );
    // The removed AS2 receive policy stays removed.
    assert!(
        !lines.iter().any(|(_, _, l)| l.contains("As2ReceivePolicy")),
        "As2ReceivePolicy is deleted"
    );
}

#[test]
fn the_scanner_sees_literals_and_constructors() {
    assert!(constructs("let p = As4SendPolicy {", "As4SendPolicy"));
    assert!(constructs(
        "As4ReceiptPolicy::default()",
        "As4ReceiptPolicy"
    ));
    assert!(constructs("x(As2SendPolicy::strict())", "As2SendPolicy"));
    assert!(!constructs("pub struct As4SendPolicy {", "As4SendPolicy"));
    assert!(!constructs(
        "impl std::fmt::Debug for As4PushPolicy {",
        "As4PushPolicy"
    ));
    assert!(!constructs(
        "policy: &As4ReceiptPolicy,",
        "As4ReceiptPolicy"
    ));
    assert!(!constructs(
        "fn view() -> crate::as4::As4PushPolicy {",
        "As4PushPolicy"
    ));
}

#[test]
fn verified_new_has_exactly_four_call_sites() {
    let sites: Vec<String> = src_lines()
        .into_iter()
        .filter(|(_, _, l)| l.contains("Verified::new(") && !l.contains("fn new("))
        .map(|(f, n, l)| format!("{f}:{n}: {}", l.trim()))
        .collect();
    assert_eq!(
        sites.len(),
        4,
        "Verified::new call sites:\n{}",
        sites.join("\n")
    );
    for expected in [
        "src/as4/send_client.rs",
        "src/as2/send_client.rs",
        "src/as4/inbound.rs",
        "src/as2/inbound.rs",
    ] {
        assert!(
            sites.iter().any(|s| s.starts_with(expected)),
            "{expected} constructs the verified value: {sites:?}"
        );
    }
}

#[test]
fn no_blocking_bridge_in_the_library() {
    let offenders: Vec<String> = src_lines()
        .into_iter()
        .filter(|(_, _, l)| l.contains("block_on") || l.contains("block_in_place"))
        .map(|(f, n, l)| format!("{f}:{n}: {}", l.trim()))
        .collect();
    assert!(
        offenders.is_empty(),
        "blocking bridge in the library (FR-027):\n{}",
        offenders.join("\n")
    );
}

#[test]
fn no_0_15_revocation_knob_is_left() {
    let offenders: Vec<String> = src_lines()
        .into_iter()
        .filter(|(_, _, l)| {
            [
                "OcspMode",
                "OcspFailureMode",
                "revocation_crl_pems",
                "ocsp_client",
            ]
            .iter()
            .any(|needle| l.contains(needle))
        })
        .map(|(f, n, l)| format!("{f}:{n}: {}", l.trim()))
        .collect();
    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

/// One CRL parser and one OCSP verifier.
#[test]
fn one_crl_parser_and_one_ocsp_verifier() {
    let lines = src_lines();
    let sites = |needles: &[&str]| -> Vec<String> {
        lines
            .iter()
            .filter(|(_, _, l)| needles.iter().any(|n| l.contains(n)))
            .map(|(f, _, _)| f.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    };
    assert_eq!(
        sites(&["X509Crl::from_der", "CertificateRevocationList::from_der"]),
        ["src/revocation/crl.rs"],
        "one CRL parser"
    );
    assert_eq!(
        sites(&["OcspResponse::from_der", ".find_status("]),
        ["src/revocation/ocsp.rs"],
        "one OCSP verifier"
    );
}

#[test]
fn no_testing_feature_and_no_interop_mode() {
    let offenders: Vec<String> = src_lines()
        .into_iter()
        .filter(|(_, _, l)| l.contains("feature = \"testing\"") || l.contains("InteropMode"))
        .map(|(f, n, l)| format!("{f}:{n}: {}", l.trim()))
        .collect();
    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

/// Wall-clock time only through `crate::clock`: no
/// `SystemTime::now()` outside `src/clock.rs`, and durations on Tokio's clock
/// (which tests pause), never `std::time::Instant`.
#[test]
fn wall_clock_only_through_crate_clock() {
    let offenders: Vec<String> = src_lines()
        .into_iter()
        .filter(|(f, _, l)| {
            (l.contains("SystemTime::now()") && f != "src/clock.rs")
                || l.contains("std::time::Instant")
                || (l.contains("use std::time::{")
                    && l.split(['{', '}', ',']).any(|s| s.trim() == "Instant"))
        })
        .map(|(f, n, l)| format!("{f}:{n}: {}", l.trim()))
        .collect();
    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

/// The golden-path examples stay short: at most 25 user
/// lines each, not counting blank lines, comments and `use` lines.
#[test]
fn golden_examples_fit_25_user_lines() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for name in ["as4_send", "as4_receive_axum", "as2_send_mdn"] {
        let text = std::fs::read_to_string(root.join(format!("examples/{name}.rs"))).unwrap();
        let n = text
            .lines()
            .map(str::trim_start)
            .filter(|l| !l.is_empty() && !l.starts_with("//") && !l.starts_with("use "))
            .count();
        assert!(n <= 25, "examples/{name}.rs has {n} user lines (limit 25)");
    }
}

/// No uncompiled doctest: a ```` ```ignore ```` block looks checked and is
/// not. Use `no_run` (compiled) or `text` (not Rust).
#[test]
fn no_ignored_doctests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    let offenders: Vec<String> = files
        .iter()
        .flat_map(|f| {
            let text = std::fs::read_to_string(f).unwrap();
            text.lines()
                .enumerate()
                .filter(|(_, l)| {
                    let t = l.trim_start();
                    (t.starts_with("///") || t.starts_with("//!"))
                        && (t.contains("```ignore") || t.contains("```rust,ignore"))
                })
                .map(|(n, _)| format!("{}:{}", f.display(), n + 1))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}
