//! Source gate: outside the writer
//! (`src/xml/writer.rs`) and the C14N serializer
//! (`src/crypto/wssec/canonicalize.rs`), no production code in `src/` spells
//! markup in a string literal — every emitted document goes through
//! `XmlOut`. A literal whose content starts with `<` + a name character,
//! `</`, `<?` or `<!` is markup; `#[cfg(test)]` modules, `*tests.rs` files and
//! comments are skipped.
//!
//! Comparisons against markup (a sniff, a slice boundary) are not emission;
//! each one is listed in [`ALLOWED`] with its purpose.

use std::path::{Path, PathBuf};

/// `(file, literal, purpose)`: markup literals that are compared against,
/// never written.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "src/as4/receive/payload.rs",
        "<?",
        "skips the prolog when reading the SBDH root element name",
    ),
    (
        "src/as4/receive/payload.rs",
        "<!--",
        "skips a prolog comment when reading the SBDH root element name",
    ),
];

/// `Debug` placeholders that look like tags but are not XML.
const NOT_XML: &[&str] = &["<redacted>", "<none>", "<absent>", "<unparseable>"];

/// Files that may write (writer, C14N serializer) or tokenize (the parser's
/// pre-scan delimiters) markup.
const WRITERS: &[&str] = &[
    "src/xml/writer.rs",
    "src/xml/parse.rs",
    "src/crypto/wssec/canonicalize.rs",
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("src dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Remove `#[cfg(test)]` / `#[cfg(all(test, …))]` modules (brace-matched).
fn strip_test_modules(src: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        let is_test_attr = trimmed.starts_with("#[cfg(test)]")
            || (trimmed.starts_with("#[cfg(all(test") && trimmed.ends_with(")]"));
        if is_test_attr && i + 1 < lines.len() && {
            let next = lines[i + 1].trim();
            (next.starts_with("mod ") || next.starts_with("pub(crate) mod ")) && next.ends_with('{')
        } {
            let mut depth = 0i64;
            let mut j = i + 1;
            loop {
                depth += lines[j].matches('{').count() as i64;
                depth -= lines[j].matches('}').count() as i64;
                if depth <= 0 || j + 1 >= lines.len() {
                    break;
                }
                j += 1;
            }
            i = j + 1;
            continue;
        }
        out.push_str(lines[i]);
        out.push('\n');
        i += 1;
    }
    out
}

/// String literals (normal and raw) outside comments, with their line.
fn string_literals(src: &str) -> Vec<(usize, String)> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let mut line = 1;
    while i < b.len() {
        match b[i] {
            b'\n' => {
                line += 1;
                i += 1;
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    if b[i] == b'\n' {
                        line += 1;
                    }
                    i += 1;
                }
                i += 2;
            }
            b'\'' => {
                // char literal or lifetime: skip `'x'`, `'\x'`, or a lifetime name.
                if b.get(i + 2) == Some(&b'\'') {
                    i += 3;
                } else if b.get(i + 1) == Some(&b'\\') {
                    i += 2;
                    while i < b.len() && b[i] != b'\'' {
                        i += 1;
                    }
                    i += 1;
                } else {
                    i += 1;
                }
            }
            b'r' if (b.get(i + 1) == Some(&b'"') || b.get(i + 1) == Some(&b'#'))
                && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')) =>
            {
                let mut j = i + 1;
                let mut hashes = 0;
                while b.get(j) == Some(&b'#') {
                    hashes += 1;
                    j += 1;
                }
                if b.get(j) != Some(&b'"') {
                    i += 1;
                    continue;
                }
                let start = j + 1;
                let mut end = start;
                let terminator: Vec<u8> = std::iter::once(b'"')
                    .chain(std::iter::repeat_n(b'#', hashes))
                    .collect();
                while end < b.len() && !b[end..].starts_with(&terminator) {
                    end += 1;
                }
                let text = String::from_utf8_lossy(&b[start..end]).into_owned();
                out.push((line, text.clone()));
                line += text.matches('\n').count();
                i = end + terminator.len();
            }
            b'"' => {
                let start = i + 1;
                let mut end = start;
                while end < b.len() && b[end] != b'"' {
                    if b[end] == b'\\' {
                        end += 1;
                    }
                    end += 1;
                }
                let text = String::from_utf8_lossy(&b[start..end.min(b.len())]).into_owned();
                out.push((line, text.clone()));
                line += text.matches('\n').count();
                i = end + 1;
            }
            _ => i += 1,
        }
    }
    out
}

fn is_markup(literal: &str) -> bool {
    let mut chars = literal.chars();
    chars.next() == Some('<')
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || matches!(c, '_' | '/' | '?' | '!'))
}

#[test]
fn no_markup_is_built_outside_the_writer() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    let mut violations = Vec::new();
    for file in files {
        let rel = file
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if WRITERS.contains(&rel.as_str())
            || rel.ends_with("tests.rs")
            || rel.ends_with("/test_support.rs")
        {
            continue;
        }
        let source = strip_test_modules(&std::fs::read_to_string(&file).unwrap());
        for (line, literal) in string_literals(&source) {
            if is_markup(&literal)
                && !NOT_XML.contains(&literal.as_str())
                && !ALLOWED.iter().any(|(f, l, _)| *f == rel && *l == literal)
            {
                violations.push(format!("{rel}:{line}: {literal:?}"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "markup built outside XmlOut ({}):\n{}",
        violations.len(),
        violations.join("\n")
    );
}

#[test]
fn the_gate_sees_what_it_must() {
    let sample = "fn f() { let x = format!(\"<a>{}</a>\", 1); // \"<ignored>\"\n}\n";
    let found: Vec<_> = string_literals(sample)
        .into_iter()
        .filter(|(_, l)| is_markup(l))
        .collect();
    assert_eq!(found, vec![(1, "<a>{}</a>".to_string())]);
    let raw = "let y = r#\"<b c=\"d\"/>\"#;";
    assert!(
        string_literals(raw)
            .iter()
            .any(|(_, l)| l == "<b c=\"d\"/>")
    );
    let tests = "#[cfg(test)]\nmod tests {\n    const X: &str = \"<t/>\";\n}\n";
    assert!(string_literals(&strip_test_modules(tests)).is_empty());
}
