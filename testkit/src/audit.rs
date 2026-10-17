//! An in-memory [`AuditSink`] for tests, and the conformance suite every
//! production sink should pass.
//!
//! [`AuditSink::durability`] is a self-declaration; [`conformance`] is what
//! checks it. The suite opens fresh handles to the same store, records,
//! reads back and fails a sink that keeps records only per handle, drops
//! them, stores a retried record twice, alters bytes, merges records of one
//! message, or loses writes under concurrency.

use std::fmt;
use std::sync::{Arc, Mutex};

use asx::{AuditDurability, AuditRecord, AuditSink, BoxFuture};
use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};

type SinkResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// A durable-declaring sink that keeps records in memory. Clones share one
/// store, so a clone is "a fresh handle to the same store". Idempotent by
/// [`AuditRecord::record_id`].
#[derive(Debug, Clone, Default)]
pub struct MemoryAuditSink {
    records: Arc<Mutex<Vec<AuditRecord>>>,
}

impl MemoryAuditSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every record stored so far, in order.
    pub fn records(&self) -> Vec<AuditRecord> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Every record as its JSON form (fields of the stored-data contract).
    pub fn records_json(&self) -> Vec<Value> {
        self.records()
            .iter()
            .map(|r| serde_json::to_value(r).expect("an AuditRecord serializes"))
            .collect()
    }
}

impl AuditSink for MemoryAuditSink {
    fn durability(&self) -> AuditDurability {
        AuditDurability::Durable
    }

    fn record<'a>(&'a self, record: &'a AuditRecord) -> BoxFuture<'a, SinkResult> {
        let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        if !records.iter().any(|r| r.record_id() == record.record_id()) {
            records.push(record.clone());
        }
        Box::pin(std::future::ready(Ok(())))
    }
}

/// What the conformance suite needs and the trait deliberately lacks.
pub trait AuditSinkHarness: Send + Sync {
    type Sink: AuditSink + 'static;

    /// A new handle to the **same** backing store (a new connection, file
    /// handle or process-equivalent).
    fn open(&self) -> BoxFuture<'_, Self::Sink>;

    /// Every record in the store, any order.
    fn read_all<'a>(&'a self, sink: &'a Self::Sink) -> BoxFuture<'a, Vec<AuditRecord>>;
}

/// One failed check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceFailure {
    pub check: &'static str,
    pub detail: String,
}

impl fmt::Display for ConformanceFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.check, self.detail)
    }
}

pub const DECLARES_DURABLE: &str = "audit.declares_durable";
pub const RECORDED_IS_READABLE: &str = "audit.recorded_is_readable";
pub const RECORDS_SURVIVE_A_FRESH_HANDLE: &str = "audit.records_survive_a_fresh_handle";
pub const EVERY_FIELD_ROUND_TRIPS: &str = "audit.every_field_round_trips";
pub const BYTES_ROUND_TRIP_EXACTLY: &str = "audit.bytes_round_trip_exactly";
pub const RECORD_IS_IDEMPOTENT_BY_ID: &str = "audit.record_is_idempotent_by_id";
pub const CONCURRENT_RECORDS_ALL_LAND: &str = "audit.concurrent_records_all_land";
pub const DISTINCT_IDS_ARE_DISTINCT_RECORDS: &str = "audit.distinct_ids_are_distinct_records";

/// Run every check and return the failures (empty = pass). Call it inside
/// the embedder's Tokio runtime; the concurrency check spawns tasks.
///
/// Each check judges only its own property: a record that never arrived
/// fails `recorded_is_readable`, not every later check as well. A sink that
/// declares `BestEffort` fails `declares_durable` and nothing else runs.
pub async fn conformance<H: AuditSinkHarness>(harness: &H) -> Vec<ConformanceFailure> {
    let mut failures = Vec::new();
    let mut fail = |check: &'static str, detail: String| {
        failures.push(ConformanceFailure { check, detail });
    };

    let first = harness.open().await;
    if first.durability() != AuditDurability::Durable {
        fail(
            DECLARES_DURABLE,
            format!("declares {:?}", first.durability()),
        );
        return failures;
    }

    let samples = sample_records();

    // recorded_is_readable: through the same handle.
    let probe = with_new_ids(&samples[0], "readable");
    let wrote = first.record(&probe).await;
    let same = harness.read_all(&first).await;
    let readable = wrote.is_ok() && contains_id(&same, probe.record_id());
    if let Err(err) = wrote {
        fail(RECORDED_IS_READABLE, format!("record returned Err: {err}"));
    } else if !contains_id(&same, probe.record_id()) {
        fail(
            RECORDED_IS_READABLE,
            format!("record {} acknowledged but not readable", probe.record_id()),
        );
    }

    // records_survive_a_fresh_handle.
    let durable_probe = with_new_ids(&samples[0], "fresh-handle");
    let _ = first.record(&durable_probe).await;
    let visible_here = contains_id(&harness.read_all(&first).await, durable_probe.record_id());
    let fresh = harness.open().await;
    if visible_here && !contains_id(&harness.read_all(&fresh).await, durable_probe.record_id()) {
        fail(
            RECORDS_SURVIVE_A_FRESH_HANDLE,
            format!(
                "record {} is visible through its own handle only",
                durable_probe.record_id()
            ),
        );
    }

    // every_field_round_trips / bytes_round_trip_exactly.
    for sample in &samples {
        let _ = first.record(sample).await;
    }
    let reader = harness.open().await;
    let stored = harness.read_all(&reader).await;
    for sample in &samples {
        let Some(found) = stored.iter().find(|r| r.record_id() == sample.record_id()) else {
            continue;
        };
        let (want, got) = (json(sample), json(found));
        if without_bytes(&want) != without_bytes(&got) {
            fail(
                EVERY_FIELD_ROUND_TRIPS,
                format!(
                    "record {} changed: wrote {want}, read {got}",
                    sample.record_id()
                ),
            );
        }
        if bytes_of(&want) != bytes_of(&got) {
            fail(
                BYTES_ROUND_TRIP_EXACTLY,
                format!("record {} byte fields changed", sample.record_id()),
            );
        }
    }

    // record_is_idempotent_by_id.
    let retried = with_new_ids(&samples[0], "idempotent");
    let _ = first.record(&retried).await;
    let _ = first.record(&retried).await;
    let copies = harness
        .read_all(&harness.open().await)
        .await
        .iter()
        .filter(|r| r.record_id() == retried.record_id())
        .count();
    if copies > 1 {
        fail(
            RECORD_IS_IDEMPOTENT_BY_ID,
            format!(
                "record {} stored {copies} times after a retry",
                retried.record_id()
            ),
        );
    }

    // distinct_ids_are_distinct_records: two legs of one message.
    let leg_a = with_new_ids(&samples[1], "two-legs");
    let mut leg_b = json(&leg_a);
    leg_b["record_id"] = Value::String(uuid::Uuid::new_v4().to_string());
    leg_b["outcome"] = Value::String("delivered".into());
    let leg_b: AuditRecord = serde_json::from_value(leg_b).expect("a valid record");
    let _ = first.record(&leg_a).await;
    let _ = first.record(&leg_b).await;
    let all = harness.read_all(&harness.open().await).await;
    if contains_id(&all, leg_a.record_id()) != contains_id(&all, leg_b.record_id()) {
        fail(
            DISTINCT_IDS_ARE_DISTINCT_RECORDS,
            format!(
                "records {} and {} share message_id {} and only one survived",
                leg_a.record_id(),
                leg_b.record_id(),
                leg_a.message_id()
            ),
        );
    }

    // concurrent_records_all_land: 64 writes from separate tasks over 8 handles.
    let mut handles = Vec::with_capacity(8);
    for _ in 0..8 {
        handles.push(Arc::new(harness.open().await));
    }
    let batch: Vec<AuditRecord> = (0..64)
        .map(|i| with_new_ids(&samples[i % samples.len()], &format!("concurrent-{i}")))
        .collect();
    let mut tasks = tokio::task::JoinSet::new();
    for (i, record) in batch.iter().cloned().enumerate() {
        let sink = Arc::clone(&handles[i % handles.len()]);
        tasks.spawn(async move {
            let _ = sink.record(&record).await;
        });
    }
    while tasks.join_next().await.is_some() {}
    // Read back through the handle that wrote each record: whether another
    // handle sees it is `records_survive_a_fresh_handle`'s question.
    let mut seen = Vec::with_capacity(handles.len());
    for handle in &handles {
        seen.push(harness.read_all(handle).await);
    }
    let lost: Vec<&str> = batch
        .iter()
        .enumerate()
        .filter(|(i, r)| !contains_id(&seen[i % handles.len()], r.record_id()))
        .map(|(_, r)| r.record_id())
        .collect();
    // A sink that loses even sequential writes already failed above.
    if readable && !lost.is_empty() {
        fail(
            CONCURRENT_RECORDS_ALL_LAND,
            format!("{} of 64 concurrent records lost: {lost:?}", lost.len()),
        );
    }

    failures
}

/// Sample records for embedders' own tests: one per outcome, unicode ids and
/// parties, empty and absent collections, and a 1 MiB non-UTF-8 signal.
/// Every record has a distinct `message_id`.
pub fn sample_records() -> Vec<AuditRecord> {
    let mut values: Vec<Value> =
        serde_json::from_str(include_str!("../fixtures/audit/sample-records.json"))
            .expect("sample-records.json is valid JSON");
    let big: Vec<u8> = (0..1024 * 1024u32)
        .map(|i| [0xff, 0xfe, 0x80, 0x00, 0xc3][(i % 5) as usize])
        .collect();
    let mut large = values[0].clone();
    large["record_id"] = Value::String("01929d3e-6a1b-7c3e-9f00-3b5c2e4d1aff".into());
    large["message_id"] = Value::String("m-large-signal@sender.example".into());
    large["signal"]["ref_to_message_id"] = Value::String("m-large-signal@sender.example".into());
    large["signal"]["bytes"] =
        Value::String(base64::engine::general_purpose::STANDARD.encode(&big));
    large["signal"]["sha256"] = Value::String(hex(&Sha256::digest(&big)));
    values.push(large);
    values
        .into_iter()
        .map(|v| serde_json::from_value(v).expect("sample record matches the contract"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn json(record: &AuditRecord) -> Value {
    serde_json::to_value(record).expect("an AuditRecord serializes")
}

/// `record` with a fresh `record_id` and a message id unique to `tag`.
fn with_new_ids(record: &AuditRecord, tag: &str) -> AuditRecord {
    let mut v = json(record);
    let id = uuid::Uuid::new_v4().to_string();
    let message_id = format!("conformance-{tag}-{id}");
    v["record_id"] = Value::String(id);
    v["message_id"] = Value::String(message_id.clone());
    if v["signal"].is_object() {
        v["signal"]["ref_to_message_id"] = Value::String(message_id);
    }
    serde_json::from_value(v).expect("a valid record")
}

fn contains_id(records: &[AuditRecord], id: &str) -> bool {
    records.iter().any(|r| r.record_id() == id)
}

/// JSON pointers of the byte fields of the contract.
fn byte_fields(v: &Value) -> Vec<String> {
    let mut out = vec![
        "/signer/certificate_der".to_owned(),
        "/mic/value".to_owned(),
        "/signal/bytes".to_owned(),
    ];
    for (list, prefix) in [("references", "/references"), ("nrr", "/signal/nrr")] {
        let array = if list == "nrr" {
            v.pointer("/signal/nrr")
        } else {
            v.get(list)
        };
        let len = array.and_then(Value::as_array).map_or(0, Vec::len);
        out.extend((0..len).map(|i| format!("{prefix}/{i}/digest")));
    }
    out
}

fn bytes_of(v: &Value) -> Vec<Option<Value>> {
    byte_fields(v)
        .iter()
        .map(|p| v.pointer(p).cloned())
        .collect()
}

fn without_bytes(v: &Value) -> Value {
    let mut v = v.clone();
    for p in byte_fields(&v) {
        if let Some(slot) = v.pointer_mut(&p) {
            *slot = Value::Null;
        }
    }
    v
}
