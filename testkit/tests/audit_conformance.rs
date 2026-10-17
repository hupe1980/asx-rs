//! The audit-sink conformance suite passes the reference sink and fails each
//! deliberately broken one with exactly its named check.

use std::sync::{Arc, Mutex};

use asx::{AuditDurability, AuditRecord, AuditSink, BoxFuture};
use asx_testkit::audit::{self, AuditSinkHarness, MemoryAuditSink, conformance};
use base64::Engine as _;
use serde_json::Value;

type SinkResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

struct MemoryHarness(MemoryAuditSink);

impl AuditSinkHarness for MemoryHarness {
    type Sink = MemoryAuditSink;
    fn open(&self) -> BoxFuture<'_, MemoryAuditSink> {
        Box::pin(std::future::ready(self.0.clone()))
    }
    fn read_all<'a>(&'a self, sink: &'a MemoryAuditSink) -> BoxFuture<'a, Vec<AuditRecord>> {
        Box::pin(std::future::ready(sink.records()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Defect {
    PerHandle,
    Dropping,
    DoubleWrite,
    Textifying,
    BestEffort,
    LastWriteWinsByMessageId,
    LossyUnderConcurrency,
}

#[derive(Debug, Clone)]
struct BrokenSink {
    defect: Defect,
    store: Arc<Mutex<Vec<AuditRecord>>>,
}

impl BrokenSink {
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<AuditRecord>> {
        self.store.lock().unwrap()
    }
}

/// Re-encode every byte field as lossy UTF-8 text, as a sink that stores
/// bytes in a text column would.
fn textify(record: &AuditRecord) -> AuditRecord {
    let engine = base64::engine::general_purpose::STANDARD;
    let mut v = serde_json::to_value(record).unwrap();
    let fix = |slot: Option<&mut Value>| {
        if let Some(Value::String(text)) = slot {
            let bytes = engine.decode(text.as_bytes()).unwrap();
            *text = engine.encode(String::from_utf8_lossy(&bytes).as_bytes());
        }
    };
    fix(v.pointer_mut("/signal/bytes"));
    fix(v.pointer_mut("/signer/certificate_der"));
    fix(v.pointer_mut("/mic/value"));
    serde_json::from_value(v).unwrap()
}

impl AuditSink for BrokenSink {
    fn durability(&self) -> AuditDurability {
        if self.defect == Defect::BestEffort {
            AuditDurability::BestEffort
        } else {
            AuditDurability::Durable
        }
    }

    fn record<'a>(&'a self, record: &'a AuditRecord) -> BoxFuture<'a, SinkResult> {
        Box::pin(async move {
            match self.defect {
                Defect::Dropping => {}
                Defect::DoubleWrite => {
                    let mut store = self.lock();
                    store.push(record.clone());
                    store.push(record.clone());
                }
                Defect::Textifying => {
                    let mut store = self.lock();
                    if !store.iter().any(|r| r.record_id() == record.record_id()) {
                        store.push(textify(record));
                    }
                }
                Defect::LastWriteWinsByMessageId => {
                    let mut store = self.lock();
                    store.retain(|r| r.message_id() != record.message_id());
                    store.push(record.clone());
                }
                Defect::LossyUnderConcurrency => {
                    // A non-atomic read-modify-write: concurrent writers
                    // overwrite each other's appends.
                    let mut snapshot = self.lock().clone();
                    tokio::task::yield_now().await;
                    if !snapshot.iter().any(|r| r.record_id() == record.record_id()) {
                        snapshot.push(record.clone());
                    }
                    *self.lock() = snapshot;
                }
                Defect::PerHandle | Defect::BestEffort => {
                    let mut store = self.lock();
                    if !store.iter().any(|r| r.record_id() == record.record_id()) {
                        store.push(record.clone());
                    }
                }
            }
            Ok(())
        })
    }
}

struct BrokenHarness(BrokenSink);

impl AuditSinkHarness for BrokenHarness {
    type Sink = BrokenSink;
    fn open(&self) -> BoxFuture<'_, BrokenSink> {
        let sink = if self.0.defect == Defect::PerHandle {
            BrokenSink {
                defect: Defect::PerHandle,
                store: Arc::default(),
            }
        } else {
            self.0.clone()
        };
        Box::pin(std::future::ready(sink))
    }
    fn read_all<'a>(&'a self, sink: &'a BrokenSink) -> BoxFuture<'a, Vec<AuditRecord>> {
        Box::pin(std::future::ready(sink.lock().clone()))
    }
}

async fn failed_checks(defect: Defect) -> Vec<&'static str> {
    let harness = BrokenHarness(BrokenSink {
        defect,
        store: Arc::default(),
    });
    conformance(&harness)
        .await
        .into_iter()
        .map(|f| f.check)
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_sink_passes() {
    let failures = conformance(&MemoryHarness(MemoryAuditSink::new())).await;
    assert!(failures.is_empty(), "{failures:#?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_handle_sink_fails_fresh_handle_check() {
    assert_eq!(
        failed_checks(Defect::PerHandle).await,
        [audit::RECORDS_SURVIVE_A_FRESH_HANDLE]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_sink_fails_readable_check() {
    assert_eq!(
        failed_checks(Defect::Dropping).await,
        [audit::RECORDED_IS_READABLE]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn double_write_sink_fails_idempotency_check() {
    assert_eq!(
        failed_checks(Defect::DoubleWrite).await,
        [audit::RECORD_IS_IDEMPOTENT_BY_ID]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn textifying_sink_fails_bytes_check() {
    let failed = failed_checks(Defect::Textifying).await;
    assert!(!failed.is_empty());
    assert!(
        failed.iter().all(|c| *c == audit::BYTES_ROUND_TRIP_EXACTLY),
        "{failed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn best_effort_sink_fails_only_the_durability_declaration() {
    assert_eq!(
        failed_checks(Defect::BestEffort).await,
        [audit::DECLARES_DURABLE]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn last_write_wins_by_message_id_sink_fails_distinct_ids_check() {
    assert_eq!(
        failed_checks(Defect::LastWriteWinsByMessageId).await,
        [audit::DISTINCT_IDS_ARE_DISTINCT_RECORDS]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lossy_sink_fails_concurrency_check() {
    assert_eq!(
        failed_checks(Defect::LossyUnderConcurrency).await,
        [audit::CONCURRENT_RECORDS_ALL_LAND]
    );
}

#[test]
fn sample_records_cover_every_outcome_and_a_large_binary_signal() {
    let samples = audit::sample_records();
    let outcomes: std::collections::BTreeSet<String> = samples
        .iter()
        .map(|r| {
            serde_json::to_value(r).unwrap()["outcome"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(
        outcomes.into_iter().collect::<Vec<_>>(),
        [
            "accepted",
            "delivered",
            "duplicate",
            "indeterminate",
            "partner_error",
            "rejected",
            "sent"
        ]
    );
    let large = samples
        .iter()
        .filter_map(AuditRecord::signal)
        .map(<[u8]>::len)
        .max()
        .unwrap();
    assert_eq!(large, 1024 * 1024);
    let ids: std::collections::HashSet<&str> = samples.iter().map(|r| r.message_id()).collect();
    assert_eq!(ids.len(), samples.len(), "message ids are distinct");
}
