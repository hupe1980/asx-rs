//! Compare XML documents by **infoset** rather than by bytes: element names,
//! namespaces, attributes and non-whitespace text. Indentation, attribute
//! order, prefix choice and empty-element form do not count, so an emitter can
//! be rewritten while a golden still proves the document means the same thing.
//!
//! Goldens live under `tests/fixtures/golden/`. Set `ASX_BLESS=1` to (re)write
//! one from the current output — only when a wire change is intended and
//! recorded in the CHANGELOG.

#![allow(dead_code)]

use std::fmt::Write as _;
use std::path::PathBuf;

/// A canonical, line-oriented rendering of the infoset of `xml`.
///
/// One line per element: depth-indented `{namespace}local`, then its
/// attributes sorted by `{namespace}name`, then its trimmed non-empty text.
/// The text of an element whose local name is in `masked` (e.g. clock-derived
/// `Timestamp`) is rendered as `*`.
pub(crate) fn infoset(xml: &str, masked: &[&str]) -> String {
    let doc = roxmltree::Document::parse(xml)
        .unwrap_or_else(|e| panic!("document must be well-formed XML: {e}\n{xml}"));
    let mut out = String::new();
    render(doc.root_element(), 0, masked, &mut out);
    out
}

fn render(node: roxmltree::Node<'_, '_>, depth: usize, masked: &[&str], out: &mut String) {
    let name = node.tag_name();
    let _ = write!(
        out,
        "{:indent$}{{{}}}{}",
        "",
        name.namespace().unwrap_or(""),
        name.name(),
        indent = depth * 2
    );
    let mut attrs: Vec<String> = node
        .attributes()
        .map(|a| {
            let value = if masked.contains(&a.name()) {
                "*"
            } else {
                a.value()
            };
            format!(
                "{{{}}}{}={:?}",
                a.namespace().unwrap_or(""),
                a.name(),
                value
            )
        })
        .collect();
    attrs.sort();
    for attr in attrs {
        let _ = write!(out, " @{attr}");
    }
    let text: String = node
        .children()
        .filter(|c| c.is_text())
        .filter_map(|c| c.text())
        .collect();
    let text = text.trim();
    if !text.is_empty() {
        let text = if masked.contains(&name.name()) {
            "*"
        } else {
            text
        };
        let _ = write!(out, " = {text:?}");
    }
    out.push('\n');
    for child in node.children().filter(|c| c.is_element()) {
        render(child, depth + 1, masked, out);
    }
}

/// Path of the golden named `name` under `tests/fixtures/golden/`.
pub(crate) fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/golden")
        .join(name)
}

/// Assert that `actual` has the infoset recorded in the golden `name`.
pub(crate) fn assert_same_infoset(name: &str, actual_xml: &str, masked: &[&str]) {
    let actual = infoset(actual_xml, masked);
    assert_golden_text(name, &actual);
}

/// Assert that `actual` equals the golden `name` byte for byte.
pub(crate) fn assert_golden_text(name: &str, actual: &str) {
    let path = golden_path(name);
    if std::env::var_os("ASX_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().expect("golden dir")).expect("golden dir");
        std::fs::write(&path, actual).expect("write golden");
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "golden {} is missing ({e}); record it with ASX_BLESS=1",
            path.display()
        )
    });
    assert!(
        expected == actual,
        "output differs from golden {}\n--- expected ---\n{expected}\n--- actual ---\n{actual}",
        path.display()
    );
}
