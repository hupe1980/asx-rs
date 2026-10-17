#![cfg(all(feature = "metrics", feature = "as4"))]
//! The metric contract of `site/content/docs/observability.md`, both ways:
//! documented names, label keys and closed label values equal what the suite
//! emits, and no label carries an identifier.

#[path = "common/telemetry_scenarios.rs"]
mod scenarios;

use std::collections::{BTreeMap, BTreeSet};

use metrics_util::debugging::{DebugValue, DebuggingRecorder};

const CONTRACT: &str = include_str!("../site/content/docs/observability.md");

fn table(heading: &str) -> Vec<Vec<String>> {
    let start = CONTRACT.find(heading).expect("heading");
    CONTRACT[start..]
        .lines()
        .skip_while(|l| !l.starts_with('|'))
        .take_while(|l| l.starts_with('|'))
        .skip(2)
        .map(|l| {
            l.trim_matches('|')
                .split('|')
                .map(|c| c.trim().to_owned())
                .collect()
        })
        .collect()
}

fn ticks(cell: &str) -> Vec<String> {
    cell.split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// The closed set of `label` on `metric`, from the values table.
fn allowed(metric: &str, label: &str) -> BTreeSet<String> {
    let span = match (metric, label) {
        ("asx_messages_sent_total" | "asx_send_duration_seconds", "outcome") => "asx.send",
        ("asx_messages_received_total" | "asx_receive_duration_seconds", "outcome") => {
            "asx.receive"
        }
        ("asx_receipt_verifications_total", "outcome") => "asx.receipt",
        ("asx_revocation_checks_total", "outcome" | "method") => "asx.revocation",
        ("asx_receipt_verifications_total", "nrr") => "asx.receipt",
        ("asx_audit_failures_total", "durability") => "asx.audit",
        (_, "protocol") => "asx.send",
        other => panic!("no closed set for {other:?}"),
    };
    table("### Values")
        .into_iter()
        .find(|row| ticks(&row[0])[0] == label && ticks(&row[1]).iter().any(|s| s == span))
        .map(|row| ticks(&row[2]).into_iter().collect())
        .unwrap_or_else(|| panic!("no values row for {label} on {span}"))
}

#[test]
fn documented_and_emitted_metrics_agree() {
    let documented: BTreeMap<String, (String, BTreeSet<String>)> = table("## Metrics")
        .into_iter()
        .map(|row| {
            (
                ticks(&row[0]).remove(0),
                (row[1].clone(), ticks(&row[2]).into_iter().collect()),
            )
        })
        .collect();
    assert_eq!(documented.len(), 7);

    // A dedicated test binary: the debugging recorder is installed globally so
    // the crypto pool's threads report to it too.
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().expect("install the debugging recorder");
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(scenarios::run_scenarios());

    let mut seen = BTreeSet::new();
    let mut counters: BTreeMap<(String, Vec<(String, String)>), u64> = BTreeMap::new();
    let mut samples: BTreeMap<(String, Vec<(String, String)>), usize> = BTreeMap::new();
    for (key, _unit, _description, value) in snapshotter.snapshot().into_vec() {
        let key = key.key();
        let name = key.name().to_owned();
        if !name.starts_with("asx_") {
            continue;
        }
        let (kind, labels) = documented
            .get(&name)
            .unwrap_or_else(|| panic!("undocumented metric {name}"));
        let keys: BTreeSet<String> = key.labels().map(|l| l.key().to_owned()).collect();
        assert_eq!(&keys, labels, "{name} label keys");
        let mut pairs = Vec::new();
        for label in key.labels() {
            assert!(
                allowed(&name, label.key()).contains(label.value()),
                "{name}{{{}={}}} is outside the closed set",
                label.key(),
                label.value()
            );
            assert!(
                !scenarios::IDENTIFIERS.contains(&label.value()),
                "{name} carries an identifier as a label: {}",
                label.value()
            );
            pairs.push((label.key().to_owned(), label.value().to_owned()));
        }
        pairs.sort();
        match value {
            DebugValue::Counter(n) => {
                assert_eq!(kind, "counter", "{name}");
                counters.insert((name.clone(), pairs), n);
            }
            DebugValue::Histogram(values) => {
                assert_eq!(kind, "histogram", "{name}");
                samples.insert((name.clone(), pairs), values.len());
            }
            DebugValue::Gauge(_) => panic!("{name}: no gauge is documented"),
        }
        seen.insert(name);
    }
    let documented_names: BTreeSet<String> = documented.keys().cloned().collect();
    assert_eq!(seen, documented_names, "documented == emitted");

    let labels = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
        let mut v: Vec<_> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        v.sort();
        v
    };
    // One AS4 send was delivered, and timed once.
    let as4_delivered = labels(&[("protocol", "as4"), ("outcome", "delivered")]);
    assert_eq!(
        counters[&("asx_messages_sent_total".to_owned(), as4_delivered.clone())],
        1
    );
    assert_eq!(
        samples[&("asx_send_duration_seconds".to_owned(), as4_delivered)],
        1
    );
    // One duplicate and one in-flight retransmission were received.
    for outcome in ["duplicate", "in_flight"] {
        assert_eq!(
            counters[&(
                "asx_messages_received_total".to_owned(),
                labels(&[("protocol", "as4"), ("outcome", outcome)])
            )],
            1,
            "{outcome}"
        );
    }
    // The refused and the unverifiable send.
    for outcome in ["partner_error", "indeterminate"] {
        assert_eq!(
            counters[&(
                "asx_messages_sent_total".to_owned(),
                labels(&[("protocol", "as4"), ("outcome", outcome)])
            )],
            1,
            "{outcome}"
        );
    }
    // The failing best-effort sink is counted.
    assert_eq!(
        counters[&(
            "asx_audit_failures_total".to_owned(),
            labels(&[("durability", "best_effort")])
        )],
        1
    );
}
