//! `XmlOut`: the only way the library writes markup.
//!
//! - Caller values go through [`XmlOut::text`] and [`XmlOut::attr`], which
//!   escape with the C14N rules (text: `&`, `<`, `>`, CR; attributes: `&`,
//!   `<`, `"`, TAB, LF, CR) — valid ordinary XML that a canonicalizer leaves
//!   unchanged — and refuse a character XML 1.0 cannot carry with
//!   `InvalidInput` naming the field. Nothing is stripped.
//! - Element and attribute names are `&'static str`: names are never caller
//!   data. Every prefix used must have been declared with [`XmlOut::ns`] on
//!   this or an enclosing element (`xml:` excepted).
//! - End tags come from the writer's stack, so they cannot mismatch.
//! - A [`Slot`] reserves a position for a fragment written later (the
//!   `wsse:Security` header); it is filled exactly once, and an unfilled slot
//!   fails [`XmlDoc::into_string`]. Pre-written markup can only be inserted as
//!   an [`XmlFragment`], which only a finished writer produces.

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

/// How an element with no content is closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EmptyForm {
    /// `<a/>` — ordinary XML.
    SelfClosing,
    /// `<a></a>` — Canonical XML form, used for `ds:SignedInfo`.
    StartEnd,
}

/// A position reserved in an [`XmlOut`], filled later through
/// [`XmlDoc::fill`].
#[derive(Debug)]
pub(crate) struct Slot(usize);

/// Markup produced by a finished writer. There is no other constructor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct XmlFragment(String);

impl XmlFragment {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn into_string(self) -> String {
        self.0
    }
}

/// A finished document with zero or more open slots.
#[derive(Debug)]
pub(crate) struct XmlDoc {
    /// Text between slots: `segments.len() == slots.len() + 1`.
    segments: Vec<String>,
    slots: Vec<Option<String>>,
}

#[derive(Debug)]
struct Open {
    qname: &'static str,
    /// Prefixes declared on this element.
    declared: Vec<&'static str>,
}

/// Streaming XML writer into a `String`.
#[derive(Debug)]
pub(crate) struct XmlOut {
    buf: String,
    stack: Vec<Open>,
    /// A start tag is open (attributes may still be added).
    tag_open: bool,
    empty_form: EmptyForm,
    segments: Vec<String>,
}

fn invalid(field: &str, detail: impl std::fmt::Display) -> AsxError {
    AsxError::new(
        ErrorCode::InvalidInput,
        format!("{field}: {detail}"),
        ErrorContext::new("xml_writer"),
    )
}

fn misuse(detail: &str) -> AsxError {
    AsxError::new(
        ErrorCode::InvalidInput,
        format!("XML writer misuse: {detail}"),
        ErrorContext::new("xml_writer"),
    )
}

/// XML 1.0 `Char`: TAB, LF, CR, U+0020–U+D7FF, U+E000–U+FFFD,
/// U+10000–U+10FFFF (surrogates cannot occur in a Rust `char`).
fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..)
}

fn check_chars(value: &str, field: &str) -> Result<()> {
    match value.chars().find(|c| !is_xml_char(*c)) {
        None => Ok(()),
        Some(c) => Err(invalid(
            field,
            format!(
                "contains U+{:04X}, a character XML 1.0 cannot carry; the value is refused, \
                 not altered",
                c as u32
            ),
        )),
    }
}

/// Printable ASCII with nothing to escape in text (`plain_text`) or in a
/// double-quoted attribute (`plain_attr`): written as-is. Most values
/// (IDs, timestamps, base64, URIs) take this path.
fn plain_text(value: &str) -> bool {
    value
        .bytes()
        .all(|b| (0x20..0x7F).contains(&b) && !matches!(b, b'<' | b'>' | b'&'))
}

fn plain_attr(value: &str) -> bool {
    value
        .bytes()
        .all(|b| (0x20..0x7F).contains(&b) && !matches!(b, b'<' | b'&' | b'"'))
}

fn prefix_of(qname: &str) -> Option<&str> {
    qname.split_once(':').map(|(p, _)| p)
}

impl XmlOut {
    /// A writer for ordinary XML (`<a/>` for empty elements).
    pub(crate) fn new() -> Self {
        Self::with_form(EmptyForm::SelfClosing)
    }

    /// A writer whose output is already in Canonical XML element form.
    pub(crate) fn canonical() -> Self {
        Self::with_form(EmptyForm::StartEnd)
    }

    fn with_form(empty_form: EmptyForm) -> Self {
        Self {
            // Every emitted document is a few hundred bytes to a few KiB;
            // one allocation up front instead of a doubling series.
            buf: String::with_capacity(2048),
            stack: Vec::with_capacity(16),
            tag_open: false,
            empty_form,
            segments: Vec::new(),
        }
    }

    /// `<?xml version="1.0" encoding="UTF-8"?>` and a line break.
    pub(crate) fn declaration(&mut self) -> &mut Self {
        self.buf
            .push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        self
    }

    fn close_start_tag(&mut self) {
        if self.tag_open {
            self.buf.push('>');
            self.tag_open = false;
        }
    }

    fn prefix_in_scope(&self, prefix: &str) -> bool {
        prefix == "xml"
            || self
                .stack
                .iter()
                .any(|open| open.declared.contains(&prefix))
    }

    fn check_prefix(&self, qname: &str) -> Result<()> {
        match prefix_of(qname) {
            Some(prefix) if !self.prefix_in_scope(prefix) => Err(misuse(&format!(
                "prefix `{prefix}` of `{qname}` is not declared"
            ))),
            _ => Ok(()),
        }
    }

    /// Open element `qname`. Its prefix must be declared on it (call
    /// [`Self::ns`] right after) or on an enclosing element.
    pub(crate) fn start(&mut self, qname: &'static str) -> Result<&mut Self> {
        self.close_start_tag();
        self.buf.push('<');
        self.buf.push_str(qname);
        self.tag_open = true;
        self.stack.push(Open {
            qname,
            declared: Vec::new(),
        });
        Ok(self)
    }

    /// Declare `xmlns:prefix="uri"` (or the default namespace for an empty
    /// prefix) on the open start tag.
    pub(crate) fn ns(&mut self, prefix: &'static str, uri: &'static str) -> Result<&mut Self> {
        if !self.tag_open {
            return Err(misuse("ns() outside a start tag"));
        }
        if prefix.is_empty() {
            self.buf.push_str(" xmlns=\"");
        } else {
            self.buf.push_str(" xmlns:");
            self.buf.push_str(prefix);
            self.buf.push_str("=\"");
        }
        crate::crypto::wssec::canonicalize::escape_attr_value(uri, &mut self.buf)
            .map_err(|_| misuse("namespace URI"))?;
        self.buf.push('"');
        if let Some(open) = self.stack.last_mut() {
            open.declared.push(prefix);
        }
        Ok(self)
    }

    /// Add attribute `qname="value"` to the open start tag.
    pub(crate) fn attr(
        &mut self,
        qname: &'static str,
        value: &str,
        field: &'static str,
    ) -> Result<&mut Self> {
        if !self.tag_open {
            return Err(misuse("attr() outside a start tag"));
        }
        let plain = plain_attr(value);
        if !plain {
            check_chars(value, field)?;
        }
        self.check_prefix(qname)?;
        self.buf.push(' ');
        self.buf.push_str(qname);
        self.buf.push_str("=\"");
        if plain {
            self.buf.push_str(value);
        } else {
            crate::crypto::wssec::canonicalize::escape_attr_value(value, &mut self.buf)
                .map_err(|_| invalid(field, "could not be written"))?;
        }
        self.buf.push('"');
        Ok(self)
    }

    /// Character content of the innermost open element.
    pub(crate) fn text(&mut self, value: &str, field: &'static str) -> Result<&mut Self> {
        if self.stack.is_empty() {
            return Err(misuse("text() outside an element"));
        }
        let plain = plain_text(value);
        if !plain {
            check_chars(value, field)?;
        }
        self.close_start_tag();
        if plain {
            self.buf.push_str(value);
        } else {
            crate::crypto::wssec::canonicalize::escape_text(value, &mut self.buf)
                .map_err(|_| invalid(field, "could not be written"))?;
        }
        Ok(self)
    }

    /// Close the innermost open element.
    pub(crate) fn end(&mut self) -> Result<&mut Self> {
        let open = self
            .stack
            .pop()
            .ok_or_else(|| misuse("end() with no open element"))?;
        // The element's own prefix is checked here, once its declarations
        // (written after `start`) are known.
        if let Some(prefix) = prefix_of(open.qname)
            && !open.declared.contains(&prefix)
            && !self.prefix_in_scope(prefix)
        {
            return Err(misuse(&format!(
                "prefix `{prefix}` of `{}` is not declared",
                open.qname
            )));
        }
        if self.tag_open {
            self.tag_open = false;
            match self.empty_form {
                EmptyForm::SelfClosing => self.buf.push_str("/>"),
                EmptyForm::StartEnd => {
                    self.buf.push_str("></");
                    self.buf.push_str(open.qname);
                    self.buf.push('>');
                }
            }
        } else {
            self.buf.push_str("</");
            self.buf.push_str(open.qname);
            self.buf.push('>');
        }
        Ok(self)
    }

    /// `start(qname)`, `text(value)`, `end()`.
    pub(crate) fn leaf(
        &mut self,
        qname: &'static str,
        value: &str,
        field: &'static str,
    ) -> Result<&mut Self> {
        self.start(qname)?;
        self.text(value, field)?;
        self.end()
    }

    /// Reserve the current position for a fragment supplied later.
    pub(crate) fn slot(&mut self) -> Slot {
        self.close_start_tag();
        self.segments.push(std::mem::take(&mut self.buf));
        Slot(self.segments.len() - 1)
    }

    /// Insert a fragment produced by another writer.
    pub(crate) fn fragment(&mut self, fragment: &XmlFragment) -> Result<&mut Self> {
        self.close_start_tag();
        self.buf.push_str(&fragment.0);
        Ok(self)
    }

    /// Insert the root element of a caller-supplied XML document (e.g. an SBDH
    /// payload): it must parse under `limits`; any XML declaration, prolog
    /// comment or processing instruction around the root is dropped.
    pub(crate) fn document_element(
        &mut self,
        document: &str,
        limits: super::XmlLimits,
        field: &'static str,
    ) -> Result<&mut Self> {
        if self.stack.is_empty() {
            return Err(misuse("document_element() outside an element"));
        }
        let doc = super::parse(document, limits, "xml_writer").map_err(|err| {
            invalid(
                field,
                format!("is not a well-formed XML document: {}", err.message),
            )
        })?;
        let range = doc.root_element().range();
        self.close_start_tag();
        self.buf.push_str(&document[range]);
        Ok(self)
    }

    /// Finish writing; every element must be closed.
    pub(crate) fn finish(mut self) -> Result<XmlDoc> {
        if let Some(open) = self.stack.last() {
            return Err(misuse(&format!(
                "finish() with `{}` still open",
                open.qname
            )));
        }
        self.segments.push(std::mem::take(&mut self.buf));
        let slots = vec![None; self.segments.len() - 1];
        Ok(XmlDoc {
            segments: self.segments,
            slots,
        })
    }
}

impl XmlDoc {
    /// Fill `slot` with `fragment`; a slot is filled exactly once.
    pub(crate) fn fill(&mut self, slot: Slot, fragment: XmlFragment) -> Result<()> {
        let entry = self
            .slots
            .get_mut(slot.0)
            .ok_or_else(|| misuse("slot of another writer"))?;
        if entry.is_some() {
            return Err(misuse("slot filled twice"));
        }
        *entry = Some(fragment.0);
        Ok(())
    }

    /// The text with every unfilled slot empty. The AS4 send path signs this:
    /// the `wsse:Security` slot lies outside every signed subtree, so filling
    /// it later cannot change a digest.
    pub(crate) fn text_with_empty_slots(&self) -> String {
        let mut out = String::with_capacity(self.segments.iter().map(String::len).sum());
        for (i, segment) in self.segments.iter().enumerate() {
            out.push_str(segment);
            if let Some(Some(fill)) = self.slots.get(i) {
                out.push_str(fill);
            }
        }
        out
    }

    /// The document with every slot filled, as a fragment.
    pub(crate) fn into_fragment(self) -> Result<XmlFragment> {
        self.into_string().map(XmlFragment)
    }

    /// The document text. Fails while a slot is unfilled.
    pub(crate) fn into_string(self) -> Result<String> {
        if self.slots.iter().any(Option::is_none) {
            return Err(misuse("a reserved slot was never filled"));
        }
        if self.slots.is_empty() {
            return Ok(self.segments.into_iter().next().unwrap_or_default());
        }
        let mut out = String::with_capacity(
            self.segments.iter().map(String::len).sum::<usize>()
                + self.slots.iter().flatten().map(String::len).sum::<usize>(),
        );
        let mut slots = self.slots.into_iter();
        for segment in self.segments {
            out.push_str(&segment);
            if let Some(Some(fill)) = slots.next() {
                out.push_str(&fill);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::{XmlLimits, parse};

    fn written(f: impl FnOnce(&mut XmlOut) -> Result<()>) -> String {
        let mut out = XmlOut::new();
        f(&mut out).expect("write");
        out.finish().expect("finish").into_string().expect("string")
    }

    #[test]
    fn text_escaping_table() {
        let xml = written(|o| {
            o.start("r")?
                .text("a&b<c>d\"e'f\rg\th\ni", "value")?
                .end()?;
            Ok(())
        });
        assert_eq!(xml, "<r>a&amp;b&lt;c&gt;d\"e'f&#xD;g\th\ni</r>");
        let doc = parse(&xml, XmlLimits::ENVELOPE, "t").unwrap();
        assert_eq!(doc.root_element().text(), Some("a&b<c>d\"e'f\rg\th\ni"));
    }

    #[test]
    fn attribute_escaping_table() {
        let xml = written(|o| {
            o.start("r")?
                .attr("a", "a&b<c>d\"e'f\rg\th\ni", "value")?
                .end()?;
            Ok(())
        });
        assert_eq!(xml, "<r a=\"a&amp;b&lt;c>d&quot;e'f&#xD;g&#x9;h&#xA;i\"/>");
        let doc = parse(&xml, XmlLimits::ENVELOPE, "t").unwrap();
        assert_eq!(
            doc.root_element().attribute("a"),
            Some("a&b<c>d\"e'f\rg\th\ni")
        );
    }

    #[test]
    fn forbidden_characters_are_refused_naming_the_field() {
        for bad in ["\u{1}", "\u{8}", "\u{B}", "\u{FFFE}", "\u{FFFF}"] {
            let value = format!("x{bad}y");
            let mut out = XmlOut::new();
            out.start("r").unwrap();
            let err = out.text(&value, "eb:MessageId").unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput);
            assert!(err.message.contains("eb:MessageId"), "{}", err.message);

            let mut out = XmlOut::new();
            out.start("r").unwrap();
            let err = out.attr("a", &value, "PartInfo/@href").unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput);
            assert!(err.message.contains("PartInfo/@href"), "{}", err.message);
        }
        // TAB, LF and CR are XML characters.
        written(|o| {
            o.start("r")?
                .attr("a", "\t\n\r", "f")?
                .text("\t\n\r", "f")?
                .end()?;
            Ok(())
        });
    }

    #[test]
    fn end_tags_come_from_the_stack() {
        let mut out = XmlOut::new();
        assert!(out.end().is_err(), "end() with nothing open");

        let mut out = XmlOut::new();
        out.start("r").unwrap();
        let err = out.finish().unwrap_err();
        assert!(err.message.contains("still open"), "{}", err.message);

        let xml = written(|o| {
            o.start("a")?
                .start("b")?
                .leaf("c", "x", "c")?
                .end()?
                .end()?;
            Ok(())
        });
        assert_eq!(xml, "<a><b><c>x</c></b></a>");
    }

    #[test]
    fn prefixes_must_be_declared() {
        let mut out = XmlOut::new();
        out.start("p:r").unwrap();
        assert!(out.end().is_err(), "undeclared element prefix");

        let mut out = XmlOut::new();
        out.start("r").unwrap();
        assert!(
            out.attr("p:a", "v", "a").is_err(),
            "undeclared attribute prefix"
        );

        let xml = written(|o| {
            o.start("p:r")?.ns("p", "urn:p")?.attr("p:a", "v", "a")?;
            o.start("p:c")?
                .attr("xml:lang", "en", "lang")?
                .end()?
                .end()?;
            Ok(())
        });
        assert_eq!(
            xml,
            "<p:r xmlns:p=\"urn:p\" p:a=\"v\"><p:c xml:lang=\"en\"/></p:r>"
        );
    }

    #[test]
    fn slots_are_filled_exactly_once() {
        let mut out = XmlOut::new();
        out.start("r").unwrap();
        let _unfilled = out.slot();
        out.leaf("b", "x", "b").unwrap();
        out.end().unwrap();
        let doc = out.finish().unwrap();
        assert!(doc.into_string().is_err(), "unfilled slot");

        let fragment = || {
            let mut f = XmlOut::new();
            f.leaf("a", "1", "a").unwrap();
            f.finish().unwrap().into_fragment().unwrap()
        };

        let mut out = XmlOut::new();
        out.start("r").unwrap();
        let slot2 = out.slot();
        out.leaf("b", "x", "b").unwrap();
        out.end().unwrap();
        let mut doc = out.finish().unwrap();
        doc.fill(slot2, fragment()).unwrap();
        assert_eq!(doc.into_string().unwrap(), "<r><a>1</a><b>x</b></r>");

        let mut out = XmlOut::new();
        out.start("r").unwrap();
        let slot = out.slot();
        let again = Slot(slot.0);
        out.end().unwrap();
        let mut doc = out.finish().unwrap();
        doc.fill(slot, fragment()).unwrap();
        assert!(doc.fill(again, fragment()).is_err(), "second fill");
    }

    #[test]
    fn canonical_form_writes_start_end_pairs() {
        let mut out = XmlOut::canonical();
        out.start("r")
            .unwrap()
            .start("e")
            .unwrap()
            .end()
            .unwrap()
            .end()
            .unwrap();
        assert_eq!(
            out.finish().unwrap().into_string().unwrap(),
            "<r><e></e></r>"
        );
    }

    #[test]
    fn document_element_inserts_a_parsed_root_only() {
        let xml = written(|o| {
            o.start("w")?.document_element(
                "<?xml version=\"1.0\"?>\n<!--c--><d a=\"1\"><e>&amp;</e></d>",
                XmlLimits::payload(1024),
                "payload",
            )?;
            o.end()?;
            Ok(())
        });
        assert_eq!(xml, "<w><d a=\"1\"><e>&amp;</e></d></w>");
        let mut out = XmlOut::new();
        out.start("w").unwrap();
        let err = out
            .document_element("<d>", XmlLimits::payload(1024), "payload")
            .unwrap_err();
        assert!(err.message.contains("payload"), "{}", err.message);
    }

    mod property {
        use super::*;
        use crate::crypto::wssec::WsSecCanonicalizationProfile;
        use crate::crypto::wssec::canonicalize::try_serialize_node;
        use proptest::prelude::*;

        #[derive(Clone, Debug)]
        enum Node {
            Text(String),
            Element(usize, Vec<(usize, String)>, Vec<Node>),
        }

        const NAMES: [&str; 4] = ["p:a", "p:b", "p:c", "p:d"];
        const ATTRS: [&str; 3] = ["x", "y", "z"];

        fn value() -> impl Strategy<Value = String> {
            proptest::collection::vec(
                prop_oneof![
                    Just('<'),
                    Just('&'),
                    Just('>'),
                    Just('"'),
                    Just('\''),
                    Just('\t'),
                    Just('\n'),
                    Just('\r'),
                    Just('a'),
                    Just('é'),
                    Just('\u{1F600}'),
                ],
                0..8,
            )
            .prop_map(|chars| chars.into_iter().collect())
        }

        fn node() -> impl Strategy<Value = Node> {
            let leaf = value().prop_map(Node::Text);
            leaf.prop_recursive(4, 24, 4, |inner| {
                (
                    0..NAMES.len(),
                    proptest::collection::btree_map(0..ATTRS.len(), value(), 0..3),
                    proptest::collection::vec(inner, 0..4),
                )
                    .prop_map(|(name, attrs, children)| {
                        Node::Element(name, attrs.into_iter().collect(), children)
                    })
            })
        }

        fn write(out: &mut XmlOut, node: &Node) -> Result<()> {
            match node {
                Node::Text(t) => {
                    out.text(t, "text")?;
                }
                Node::Element(name, attrs, children) => {
                    out.start(NAMES[*name])?;
                    for (attr, v) in attrs {
                        out.attr(ATTRS[*attr], v, "attr")?;
                    }
                    for child in children {
                        write(out, child)?;
                    }
                    out.end()?;
                }
            }
            Ok(())
        }

        proptest! {
            /// The writer is C14N-compatible: its canonical-form output is
            /// already the Exclusive C14N of what it parses to.
            #[test]
            fn output_equals_its_own_canonical_form(children in proptest::collection::vec(node(), 0..4)) {
                let mut out = XmlOut::canonical();
                out.start("p:root").unwrap().ns("p", "urn:p").unwrap();
                for child in &children {
                    write(&mut out, child).unwrap();
                }
                out.end().unwrap();
                let xml = out.finish().unwrap().into_string().unwrap();
                let doc = parse(&xml, XmlLimits::ENVELOPE, "t").unwrap();
                let mut c14n = String::new();
                try_serialize_node(
                    doc.root_element(),
                    &mut c14n,
                    &WsSecCanonicalizationProfile::default(),
                    &std::collections::BTreeMap::new(),
                )
                .unwrap();
                prop_assert_eq!(c14n, xml);
            }
        }
    }
}
