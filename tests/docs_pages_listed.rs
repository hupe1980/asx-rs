//! Every page under `site/content/docs/` is compiled by the docs gate: it is
//! named in `src/docs.rs`, so a new page cannot escape
//! `cargo test --doc`.

#[test]
fn every_site_page_is_compiled_by_the_docs_gate() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let listed = std::fs::read_to_string(root.join("src/docs.rs")).expect("src/docs.rs");
    let mut missing = Vec::new();
    for entry in std::fs::read_dir(root.join("site/content/docs")).expect("site/content/docs") {
        let name = entry
            .expect("dir entry")
            .file_name()
            .into_string()
            .expect("utf-8 name");
        if name.ends_with(".md") && !listed.contains(&format!("\"{name}\"")) {
            missing.push(name);
        }
    }
    assert!(
        listed.contains("../README.md"),
        "src/docs.rs must include README.md"
    );
    assert!(
        missing.is_empty(),
        "pages not compiled by src/docs.rs: {missing:?}"
    );
}
