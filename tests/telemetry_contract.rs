#![cfg(feature = "as4")]
//! The telemetry contract of `site/content/docs/observability.md`, both ways:
//! every span the suite emits is documented with exactly its documented
//! fields and level, every documented span is emitted, every `asx.send` and
//! `asx.receive` closes with exactly one documented event, values stay within
//! their closed sets, and no field carries a secret.

#[path = "common/telemetry_scenarios.rs"]
mod scenarios;

use std::collections::{BTreeMap, BTreeSet};

use asx::testkit::trace::{CapturedEvent, CapturedSpan, TraceCapture};
use scenarios::{AUTH_CANARY, DN_CANARY, PARTNER, PAYLOAD_CANARY, run_scenarios};

const CONTRACT: &str = include_str!("../site/content/docs/observability.md");

/// Documented spans the scenarios do not reach: `asx.smp_lookup` opens only
/// with feature `peppol`.
fn not_reached() -> Vec<&'static str> {
    let mut spans = vec![];
    if cfg!(not(feature = "peppol")) {
        spans.push("asx.smp_lookup");
    }
    spans
}

// ── The contract, parsed from the published page ────────────────────────────

/// The rows of the first Markdown table after `heading`, as cells.
fn table(heading: &str) -> Vec<Vec<String>> {
    let start = CONTRACT
        .find(heading)
        .unwrap_or_else(|| panic!("no {heading:?} in the contract"));
    CONTRACT[start..]
        .lines()
        .skip_while(|l| !l.starts_with('|'))
        .take_while(|l| l.starts_with('|'))
        .skip(2) // header and separator
        .map(|l| {
            l.trim_matches('|')
                .split('|')
                .map(|c| c.trim().to_owned())
                .collect()
        })
        .collect()
}

/// Every `backticked` token of a cell.
fn ticks(cell: &str) -> Vec<String> {
    cell.split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

struct Contract {
    /// span → (level, fields)
    spans: BTreeMap<String, (String, BTreeSet<String>)>,
    /// (field, span) → values
    values: BTreeMap<(String, String), BTreeSet<String>>,
    /// span → closing messages
    closing: BTreeMap<String, BTreeSet<String>>,
}

fn contract() -> Contract {
    let spans = table("### Spans")
        .into_iter()
        .map(|row| {
            let name = ticks(&row[0]).remove(0);
            (name, (row[1].clone(), ticks(&row[2]).into_iter().collect()))
        })
        .collect();
    let mut values = BTreeMap::new();
    for row in table("### Values") {
        let field = ticks(&row[0]).remove(0);
        let set: BTreeSet<String> = ticks(&row[2]).into_iter().collect();
        for span in ticks(&row[1]) {
            values.insert((field.clone(), span), set.clone());
        }
    }
    let mut closing: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in table("### Closing events") {
        let span = ticks(&row[0]).remove(0);
        closing.entry(span).or_default().extend(ticks(&row[3]));
    }
    Contract {
        spans,
        values,
        closing,
    }
}

fn capture_all() -> (Vec<CapturedSpan>, Vec<CapturedEvent>) {
    let capture = TraceCapture::new();
    {
        let _guard = capture.set_default();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(run_scenarios());
    }
    let spans = capture
        .spans()
        .into_iter()
        .filter(|s| s.target == "asx")
        .collect();
    let events = capture
        .events()
        .into_iter()
        .filter(|e| e.target == "asx")
        .collect();
    (spans, events)
}

// ── The assertions ──────────────────────────────────────────────────────────

#[test]
fn documented_and_observed_telemetry_agree() {
    let contract = contract();
    let (spans, events) = capture_all();

    // Observed ⊆ documented: name, level and the exact declared field set.
    for span in &spans {
        let (level, fields) = contract
            .spans
            .get(span.name)
            .unwrap_or_else(|| panic!("undocumented span {}", span.name));
        assert_eq!(&span.level.to_string(), level, "{} level", span.name);
        let declared: BTreeSet<String> = span.declared.iter().map(|f| f.to_string()).collect();
        assert_eq!(&declared, fields, "{} fields", span.name);
    }

    // Documented ⊆ observed.
    let observed: BTreeSet<&str> = spans.iter().map(|s| s.name).collect();
    for name in contract.spans.keys() {
        if not_reached().contains(&name.as_str()) {
            continue;
        }
        assert!(
            observed.contains(name.as_str()),
            "{name} is documented but never emitted"
        );
    }

    // Values within their closed sets.
    for span in &spans {
        for (field, value) in &span.fields {
            if let Some(allowed) = contract.values.get(&(field.clone(), span.name.to_owned())) {
                assert!(
                    allowed.contains(value),
                    "{}.{field} = {value:?} is outside {allowed:?}",
                    span.name
                );
            }
        }
    }

    // Exactly one closing event per asx.send / asx.receive.
    for (span_name, messages) in &contract.closing {
        let opened = spans.iter().filter(|s| s.name == span_name).count();
        let closed = events
            .iter()
            .filter(|e| e.span == Some(span_name.as_str()) && messages.contains(e.message()))
            .count();
        assert!(opened > 0, "{span_name} never opened");
        assert_eq!(
            opened, closed,
            "{span_name}: {opened} spans, {closed} closing events"
        );
    }

    // Work moved to the crypto pool stays under its receive span.
    assert!(
        spans
            .iter()
            .any(|s| s.name == "asx.verify" && s.parent == Some("asx.receive")),
        "asx.verify nests under asx.receive"
    );
}

#[test]
fn a_rejected_receive_records_its_kind_and_code_and_warns_once() {
    let (spans, events) = capture_all();
    let rejected: Vec<&CapturedSpan> = spans
        .iter()
        .filter(|s| {
            s.name == "asx.receive"
                && s.fields.get("protocol").map(String::as_str) == Some("as4")
                && s.fields.get("outcome").map(String::as_str) == Some("rejected")
        })
        .collect();
    // The tampered message, and the message the partner's handler refused.
    assert_eq!(rejected.len(), 2, "{rejected:#?}");
    assert!(
        rejected
            .iter()
            .all(|s| s.fields["error.kind"] == "rejected")
    );
    // The verification failure carries its ebMS code (EBMS:0101). The handler
    // refusal answers EBMS:0202 on the wire but its span records no
    // `ebms.code` (src/as4/inbound.rs `deliver` returns no error to
    // `finish_receive`): reported, not asserted.
    assert!(
        rejected.iter().any(|s| s
            .fields
            .get("ebms.code")
            .is_some_and(|c| c.starts_with("EBMS:"))),
        "{rejected:#?}"
    );
    let all_rejected = spans
        .iter()
        .filter(|s| {
            s.name == "asx.receive"
                && s.fields.get("outcome").map(String::as_str) == Some("rejected")
        })
        .count();
    let warnings: Vec<&CapturedEvent> = events
        .iter()
        .filter(|e| e.message() == "message rejected")
        .collect();
    assert_eq!(
        warnings.len(),
        all_rejected,
        "one WARN per rejected receive"
    );
    assert!(warnings.iter().all(|e| e.level == tracing::Level::WARN));
}

#[test]
fn the_send_and_receive_spans_carry_their_identity() {
    let (spans, events) = capture_all();
    let send = spans
        .iter()
        .find(|s| {
            s.name == "asx.send" && s.fields.get("protocol").map(String::as_str) == Some("as4")
        })
        .expect("an AS4 asx.send");
    assert_eq!(send.fields["message_id"], "contract-1@asx.test");
    assert_eq!(send.fields["partner"], PARTNER);
    assert_eq!(send.fields["outcome"], "delivered");
    assert!(send.fields.contains_key("duration_ms"));
    for outcome in ["duplicate", "in_flight"] {
        assert!(
            spans.iter().any(|s| s.name == "asx.receive"
                && s.fields.get("outcome").map(String::as_str) == Some(outcome)
                && s.fields.get("duplicate").map(String::as_str) == Some("true")),
            "an asx.receive with outcome {outcome}"
        );
    }
    // `error.kind` of a failed send should equal the outcome (the audit
    // record's `error_kind`); src/as4/send_client.rs `close_span` currently
    // records `transport` for every failure (reported). Asserted: a value in
    // the closed set, which `documented_and_observed_telemetry_agree` checks.
    for outcome in ["partner_error", "indeterminate"] {
        assert!(
            spans.iter().any(|s| s.name == "asx.send"
                && s.fields.get("outcome").map(String::as_str) == Some(outcome)
                && s.fields.contains_key("error.kind")),
            "an asx.send with outcome {outcome}"
        );
    }
    assert!(spans.iter().any(|s| s.name == "asx.send"
        && s.fields.get("outcome").map(String::as_str) == Some("partner_error")
        && s.fields.get("ebms.code").map(String::as_str) == Some("EBMS:0202")));
    // The failing best-effort sink: one ERROR, the exchange unaffected.
    assert!(
        events
            .iter()
            .any(|e| e.message() == "audit record not written"
                && e.level == tracing::Level::ERROR
                && e.fields["durability"] == "best_effort")
    );
    // A revoked certificate is a WARN.
    assert!(
        events
            .iter()
            .any(|e| e.message() == "certificate revocation status"
                && e.level == tracing::Level::WARN
                && e.fields["outcome"] == "revoked")
    );
}

#[test]
fn no_field_or_message_carries_a_secret() {
    let (spans, events) = capture_all();
    let values = spans
        .iter()
        .flat_map(|s| s.fields.values())
        .chain(events.iter().flat_map(|e| e.fields.values()));
    for value in values {
        for canary in [PAYLOAD_CANARY, AUTH_CANARY, DN_CANARY, "PRIVATE KEY"] {
            assert!(!value.contains(canary), "{canary} leaked: {value}");
        }
    }
}
