//! `xml::parse`: the only way the library turns text into a DOM.
//!
//! Order: byte limit → a linear pre-scan that refuses
//! `DOCTYPE`, bounds the nesting depth and the attributes per element →
//! `roxmltree` with `allow_dtd: false` and the node limit. The pre-scan exists
//! because `roxmltree` 0.21's tokenizer recurses once per nesting level, so a
//! depth check after `Document::parse` is too late: a 5,000-level document
//! overflows a small stack before any post-parse check runs.

use roxmltree::{Document, ParsingOptions};

use super::XmlLimits;
use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

/// Parse `text` under `limits`; failures are `ParseFailed` naming the limit,
/// with `stage` as the error context.
pub(crate) fn parse<'a>(
    text: &'a str,
    limits: XmlLimits,
    stage: &'static str,
) -> Result<Document<'a>> {
    if text.len() > limits.max_bytes {
        return Err(fail(
            stage,
            format!(
                "XML document exceeds the {} byte limit ({} bytes)",
                limits.max_bytes,
                text.len()
            ),
        ));
    }
    prescan(text.as_bytes(), limits, stage)?;
    let options = ParsingOptions {
        allow_dtd: false,
        nodes_limit: limits.max_nodes,
        ..ParsingOptions::default()
    };
    Document::parse_with_options(text, options).map_err(|e| match e {
        roxmltree::Error::NodesLimitReached => fail(
            stage,
            format!(
                "XML document exceeds the node limit of {} nodes",
                limits.max_nodes
            ),
        ),
        roxmltree::Error::DtdDetected => fail(
            stage,
            "XML document type declarations (DOCTYPE) are not allowed".to_string(),
        ),
        other => fail(stage, format!("XML is not well-formed: {other}")),
    })
}

/// One linear pass over the markup: refuses `<!DOCTYPE` (and any other
/// markup declaration), and bounds nesting depth and attributes per element
/// before a tree exists. Comments, CDATA sections, processing instructions and
/// quoted attribute values are skipped with the delimiters `roxmltree` uses,
/// so the scan can only over-count on input that `roxmltree` then rejects.
fn prescan(bytes: &[u8], limits: XmlLimits, stage: &'static str) -> Result<()> {
    let skip_to = |from: usize, needle: &[u8]| -> usize {
        memchr::memmem::find(&bytes[from..], needle)
            .map(|at| from + at + needle.len())
            .unwrap_or(bytes.len())
    };
    let mut depth: usize = 0;
    let mut i = 0;
    while let Some(at) = memchr::memchr(b'<', &bytes[i..]) {
        let start = i + at;
        let rest = &bytes[start..];
        if rest.starts_with(b"<!--") {
            i = skip_to(start + 4, b"-->");
        } else if rest.starts_with(b"<![CDATA[") {
            i = skip_to(start + 9, b"]]>");
        } else if rest.starts_with(b"<?") {
            i = skip_to(start + 2, b"?>");
        } else if rest.starts_with(b"<!") {
            // `<!DOCTYPE`, or a markup declaration that is only legal inside one.
            return Err(fail(
                stage,
                "XML document type declarations (DOCTYPE) are not allowed".to_string(),
            ));
        } else if rest.starts_with(b"</") {
            depth = depth.saturating_sub(1);
            i = skip_to(start + 2, b">");
        } else {
            // A start tag: walk to its unquoted `>`, counting `=` outside quotes.
            let mut j = start + 1;
            let mut quote: Option<u8> = None;
            let mut attributes: usize = 0;
            let mut self_closing = false;
            while j < bytes.len() {
                let b = bytes[j];
                match quote {
                    Some(q) if b == q => quote = None,
                    Some(_) => {}
                    None => match b {
                        b'"' | b'\'' => quote = Some(b),
                        b'=' => attributes += 1,
                        b'>' => {
                            self_closing = bytes[j - 1] == b'/';
                            break;
                        }
                        _ => {}
                    },
                }
                j += 1;
            }
            if attributes > usize::from(limits.max_attributes) {
                return Err(fail(
                    stage,
                    format!(
                        "XML element has more than {} attributes (attribute limit)",
                        limits.max_attributes
                    ),
                ));
            }
            if !self_closing {
                depth += 1;
                if depth > usize::from(limits.max_depth) {
                    return Err(fail(
                        stage,
                        format!(
                            "XML nesting exceeds the depth limit of {} levels",
                            limits.max_depth
                        ),
                    ));
                }
            }
            i = (j + 1).min(bytes.len());
        }
        if i >= bytes.len() {
            break;
        }
    }
    Ok(())
}

/// [`parse`] for bytes: the input must be UTF-8 (a leading BOM is skipped).
pub(crate) fn parse_bytes<'a>(
    bytes: &'a [u8],
    limits: XmlLimits,
    stage: &'static str,
) -> Result<Document<'a>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| fail(stage, format!("XML document is not valid UTF-8: {e}")))?;
    parse(text.strip_prefix('\u{feff}').unwrap_or(text), limits, stage)
}

fn fail(stage: &'static str, message: String) -> AsxError {
    AsxError::new(ErrorCode::ParseFailed, message, ErrorContext::new(stage))
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAGE: &str = "xml_parse_test";

    /// Run `f` on a thread with a 256 KiB stack: a parser that recurses per
    /// nesting level overflows it on the depth probe.
    fn on_small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(f)
            .expect("spawn")
            .join()
            .expect("the parser must not overflow a 256 KiB stack")
    }

    fn expect_limit(xml: String, limits: XmlLimits, needle: &'static str) {
        let err = on_small_stack(move || parse(&xml, limits, STAGE).map(|_| ()).unwrap_err());
        assert_eq!(err.code, ErrorCode::ParseFailed);
        assert!(
            err.message.contains(needle),
            "error must name the {needle} limit: {}",
            err.message
        );
    }

    #[test]
    fn rejects_doctype_p1() {
        let xml = r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e "x">]><r>&e;</r>"#.to_string();
        expect_limit(xml, XmlLimits::ENVELOPE, "DOCTYPE");
        // Without an internal subset, too.
        expect_limit(
            "<!DOCTYPE r><r/>".to_string(),
            XmlLimits::ENVELOPE,
            "DOCTYPE",
        );
    }

    #[test]
    fn rejects_oversize_p2() {
        let limits = XmlLimits::payload(64);
        let xml = format!("<r>{}</r>", "x".repeat(64));
        expect_limit(xml, limits, "byte limit");
    }

    #[test]
    fn rejects_deep_nesting_on_a_small_stack_p3() {
        let depth = 5_000;
        let xml = format!("{}{}", "<a>".repeat(depth), "</a>".repeat(depth));
        expect_limit(xml.clone(), XmlLimits::ENVELOPE, "depth limit");
        expect_limit(xml, XmlLimits::payload(1 << 20), "depth limit");
        // Exactly at the limit is fine.
        let ok = format!("{}{}", "<a>".repeat(64), "</a>".repeat(64));
        assert!(parse(&ok, XmlLimits::ENVELOPE, STAGE).is_ok());
        let over = format!("{}{}", "<a>".repeat(65), "</a>".repeat(65));
        expect_limit(over, XmlLimits::ENVELOPE, "depth limit");
    }

    #[test]
    fn rejects_node_limit_p4() {
        let xml = format!("<r>{}</r>", "<a/>".repeat(20_001));
        expect_limit(xml, XmlLimits::ENVELOPE, "node limit");
    }

    #[test]
    fn rejects_attribute_limit_p5() {
        let attrs: String = (0..1_000).map(|i| format!(" a{i}=\"v\"")).collect();
        expect_limit(
            format!("<r{attrs}/>"),
            XmlLimits::ENVELOPE,
            "attribute limit",
        );
        // Namespace declarations count as attributes too.
        let decls: String = (0..1_000)
            .map(|i| format!(" xmlns:p{i}=\"urn:x:{i}\""))
            .collect();
        expect_limit(
            format!("<r{decls}/>"),
            XmlLimits::ENVELOPE,
            "attribute limit",
        );
    }

    #[test]
    fn accepts_markup_characters_in_comments_cdata_pis_and_attribute_values() {
        let xml = concat!(
            "<?xml version=\"1.0\"?>",
            "<!-- <a><b><c> -->",
            "<r a=\"x>y\" b='&lt;&amp;'>",
            "<![CDATA[<x><y><z>]]>",
            "<?pi <a><b>?>",
            "<s>&lt;t&gt;</s>",
            "</r>"
        );
        let doc = parse(xml, XmlLimits::ENVELOPE, STAGE).expect("parse");
        let root = doc.root_element();
        assert_eq!(root.attribute("a"), Some("x>y"));
        assert_eq!(root.attribute("b"), Some("<&"));
        // Comment/CDATA/PI content did not count towards depth: a document of
        // depth 2 with many '<' inside them is accepted under depth 2.
        let tight = XmlLimits {
            max_depth: 2,
            ..XmlLimits::ENVELOPE
        };
        assert!(parse(xml, tight, STAGE).is_ok());
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in ["<r>", "<r></s>", "", "<a/><b/>", "<r a=\"1\" a=\"2\"/>"] {
            let err = parse(bad, XmlLimits::ENVELOPE, STAGE).unwrap_err();
            assert_eq!(err.code, ErrorCode::ParseFailed, "{bad}");
        }
    }

    #[test]
    fn parse_bytes_requires_utf8_and_skips_a_bom() {
        assert!(parse_bytes(b"\xef\xbb\xbf<r/>", XmlLimits::ENVELOPE, STAGE).is_ok());
        let err = parse_bytes(b"<r>\xff</r>", XmlLimits::ENVELOPE, STAGE).unwrap_err();
        assert_eq!(err.code, ErrorCode::ParseFailed);
    }

    /// The repository's XML fixtures parse to the same tree as plain
    /// `roxmltree` under the class limits.
    #[test]
    fn repository_fixtures_parse_to_the_same_tree() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let mut files = Vec::new();
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("fixtures dir") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path
                    .extension()
                    .is_some_and(|e| e == "xml" || e == "golden")
                {
                    files.push(path);
                }
            }
        }
        let mut checked = 0;
        for path in files {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(reference) = roxmltree::Document::parse(&text) else {
                continue;
            };
            let ours = parse(&text, XmlLimits::payload(16 << 20), STAGE)
                .unwrap_or_else(|e| panic!("{}: {}", path.display(), e.message));
            let render = |d: &roxmltree::Document<'_>| {
                d.descendants()
                    .map(|n| format!("{:?}{:?}{:?}", n.node_type(), n.tag_name(), n.text()))
                    .collect::<Vec<_>>()
            };
            assert_eq!(render(&ours), render(&reference), "{}", path.display());
            if text.len() <= XmlLimits::ENVELOPE.max_bytes {
                assert!(
                    parse(&text, XmlLimits::ENVELOPE, STAGE).is_ok(),
                    "{} must fit the envelope class",
                    path.display()
                );
            }
            checked += 1;
        }
        assert!(checked >= 5, "expected XML fixtures, found {checked}");
    }
}
