use crate::core::Result;
use crate::core::{ErrorCode, SessionContext};

// ── CompressionType from the signed eb:Messaging, as text ───────────────────

const COMPRESSION_ENVELOPE: &str = concat!(
    r#"<S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope" "#,
    r#"xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">"#,
    r#"<S:Header><eb:Messaging><eb:UserMessage><eb:PayloadInfo>"#,
    r#"<eb:PartInfo href="cid:signed@asx.test"><eb:PartProperties>"#,
    r#"<eb:Property name="MimeType">application/xml</eb:Property>"#,
    r#"<eb:Property name="CompressionType">application/gzip</eb:Property>"#,
    r#"</eb:PartProperties></eb:PartInfo></eb:PayloadInfo></eb:UserMessage></eb:Messaging></S:Header>"#,
    r#"<S:Body><eb:PartInfo href="cid:injected@asx.test"><eb:PartProperties>"#,
    r#"<eb:Property name="CompressionType" value="application/gzip"/>"#,
    r#"</eb:PartProperties></eb:PartInfo></S:Body></S:Envelope>"#
);

fn compression_of(xml: &str) -> Result<std::collections::HashMap<String, String>> {
    let session = SessionContext::new("s-compression", "partner", "strict").expect("session");
    let doc = crate::xml::parse(xml, crate::xml::XmlLimits::ENVELOPE, "test").expect("parse");
    super::payload::part_properties(&session, &doc, "msg-compression").map(|p| p.compression)
}

/// The compression flag is read from the one `eb:Messaging` the signature
/// covers, as element text; a second, unsigned `eb:PartInfo` elsewhere in the
/// envelope changes nothing.
#[test]
fn compression_type_read_as_text_from_signed_messaging() {
    let types = compression_of(COMPRESSION_ENVELOPE).expect("compression types");
    assert_eq!(
        types.get("signed@asx.test").map(String::as_str),
        Some("application/gzip")
    );
    assert!(
        !types.contains_key("injected@asx.test"),
        "a PartInfo outside eb:Messaging must not be read: {types:?}"
    );
}

/// ebMS3 `Property` is simpleContent with only a `name`
/// attribute; a `value` attribute is not read, and a property that carries
/// only one is refused naming it.
#[test]
fn property_value_attribute_is_not_read() {
    let xml = COMPRESSION_ENVELOPE.replace(
        r#"<eb:Property name="CompressionType">application/gzip</eb:Property>"#,
        r#"<eb:Property name="CompressionType" value="application/gzip"/>"#,
    );
    let err = compression_of(&xml).expect_err("a value-only property is refused");
    assert_eq!(err.code, ErrorCode::InteropViolation);
    assert!(
        err.message.contains("Property") && err.message.contains("CompressionType"),
        "{}",
        err.message
    );
}

/// A part property named twice in one `eb:PartInfo` is ambiguous: refused,
/// whichever value comes last.
#[test]
fn a_repeated_part_property_is_refused() {
    for (name, value) in [
        ("CompressionType", "application/gzip"),
        ("MimeType", "text/plain"),
    ] {
        let repeated = format!(r#"<eb:Property name="{name}">{value}</eb:Property>"#);
        let xml = COMPRESSION_ENVELOPE.replacen(
            "</eb:PartProperties>",
            &format!("{repeated}</eb:PartProperties>"),
            1,
        );
        let err = compression_of(&xml).expect_err("a repeated property is refused");
        assert_eq!(err.code, ErrorCode::InteropViolation, "{name}");
        assert!(err.message.contains(name), "{}", err.message);
    }
}

// ── The inbound eb:Timestamp window ─────────────────────────────────────────

/// A message stamped at `sent`, judged by `processing`'s window at the
/// clock's reading.
fn stamped(sent: std::time::SystemTime) -> crate::as4::ParsedAs4UserMessage {
    crate::as4::ParsedAs4UserMessage {
        message_id: "window@asx.test".to_string(),
        timestamp: Some(crate::time_utils::format_rfc3339_secs(sent)),
        ..Default::default()
    }
}

fn judged(
    parsed: &crate::as4::ParsedAs4UserMessage,
    clock: &crate::clock::ManualClock,
) -> Result<()> {
    use crate::clock::Clock;
    let window = crate::profile::receive_view(&crate::Profile::bdew())
        .timestamp_window
        .expect("the profile bounds eb:Timestamp");
    parsed.check_timestamp_freshness(window, clock.now())
}

/// Retry vs freshness: a retry reuses `Message::timestamp`, so a message
/// stamped hours ago is accepted — including a BDEW sender's retries over
/// 72 h. The past bound is the dedup retention (7 days), within which a
/// replay is a duplicate.
#[test]
fn timestamp_in_the_past_is_accepted_within_the_dedup_retention() {
    let sent = crate::clock::system().now();
    let parsed = stamped(sent);
    let clock = crate::clock::ManualClock::at(sent);
    for after in [0, 299, 301, 3_600, 24 * 3_600, 72 * 3_600, 7 * 24 * 3_600] {
        clock.set(sent + std::time::Duration::from_secs(after));
        judged(&parsed, &clock).unwrap_or_else(|e| panic!("{after} s later: {e}"));
    }
}

/// Beyond the dedup retention a replay could no longer be recognised as a
/// duplicate: refused.
#[test]
fn timestamp_older_than_the_dedup_retention_is_refused() {
    let sent = crate::clock::system().now();
    let parsed = stamped(sent);
    let clock = crate::clock::ManualClock::at(sent);
    clock.advance(std::time::Duration::from_secs(7 * 24 * 3_600 + 1));
    let err = judged(&parsed, &clock).expect_err("older than 7 days");
    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
}

/// The future bound stays the clock skew of eDelivery 1.15 §5.1.3 (300 s).
#[test]
fn timestamp_more_than_300_s_in_the_future_is_refused() {
    let now = crate::clock::system().now();
    let clock = crate::clock::ManualClock::at(now);
    judged(&stamped(now + std::time::Duration::from_secs(300)), &clock)
        .expect("300 s ahead is within the skew");
    let err = judged(&stamped(now + std::time::Duration::from_secs(301)), &clock)
        .expect_err("301 s ahead");
    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
}
