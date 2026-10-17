use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn full_record() -> AuditRecord {
    RecordBuilder::new(
        &crate::clock::system(),
        Protocol::As4,
        Direction::Outbound,
        "msg-1@sender.example",
        "9900000000001",
        "9900000000002",
    )
    .ref_to_message_id(None)
    .conversation_id(Some("conv-1"))
    .profile(Some("bdew"))
    .service_action(Some("svc"), Some("act"))
    .message_timestamp(Some("2026-10-16T09:30:11.902Z"))
    // 5 bytes: base64 needs padding.
    .signer_der(Some(vec![0x30, 0x82, 0xff, 0x00, 0x01]))
    .references([(
        "#body",
        "http://www.w3.org/2001/04/xmlenc#sha256",
        "AAECAw==",
    )])
    .signal(Signal {
        bytes: &[0xff, 0xfe, 0x00, b'<'],
        message_id: Some("receipt-7"),
        ref_to_message_id: Some("<msg-1@sender.example>"),
        timestamp: Some("2026-10-16T09:30:12.201Z"),
        signed: true,
        nrr: &[(
            "#body",
            "http://www.w3.org/2001/04/xmlenc#sha256",
            "AAECAw==",
        )],
    })
    .disposition(Some("receipt"))
    .finish(AuditOutcome::Delivered, None)
    .expect("valid record")
}

fn json(rec: &AuditRecord) -> serde_json::Value {
    serde_json::to_value(rec).expect("serialize")
}

#[test]
fn byte_fields_are_padded_standard_base64() {
    let v = json(&full_record());
    assert_eq!(v["signer"]["certificate_der"], "MIL/AAE=");
    assert_eq!(v["signal"]["bytes"], "//4APA==");
    assert_eq!(v["references"][0]["digest"], "AAECAw==");
    assert_eq!(v["signal"]["nrr"][0]["digest"], "AAECAw==");
}

#[test]
fn hex_fields_are_lowercase_sha256() {
    let v = json(&full_record());
    let fp = v["signer"]["fingerprint_sha256"].as_str().unwrap();
    assert_eq!(fp, sha256_hex(&[0x30, 0x82, 0xff, 0x00, 0x01]));
    assert_eq!(fp.len(), 64);
    assert!(
        fp.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(
        v["signal"]["sha256"].as_str().unwrap(),
        sha256_hex(&[0xff, 0xfe, 0x00, b'<'])
    );
}

#[test]
fn recorded_at_has_exactly_three_fraction_digits_and_z() {
    let v = json(&full_record());
    let t = v["recorded_at"].as_str().unwrap();
    assert_eq!(t.len(), 24, "{t}");
    assert_eq!(&t[19..20], ".");
    assert!(t[20..23].bytes().all(|b| b.is_ascii_digit()));
    assert!(t.ends_with('Z'));
}

#[test]
fn absent_values_are_written_as_null() {
    let v = json(&full_record());
    let obj = v.as_object().unwrap();
    for key in ["ref_to_message_id", "mic", "error_kind", "ebms_code"] {
        assert_eq!(obj.get(key), Some(&serde_json::Value::Null), "{key}");
    }
    assert_eq!(v["quirks"], serde_json::json!([]));
    assert_eq!(v["outcome"], "delivered");
    assert_eq!(v["protocol"], "as4");
    assert_eq!(v["direction"], "outbound");
}

#[test]
fn unknown_fields_are_ignored_on_read() {
    let rec = full_record();
    let mut v = json(&rec);
    v.as_object_mut()
        .unwrap()
        .insert("peppol".into(), serde_json::json!({"c1_country": "DE"}));
    let back: AuditRecord = serde_json::from_value(v).expect("deserialize with extra field");
    assert_eq!(back, rec);
}

#[test]
fn serialize_then_deserialize_is_identity() {
    let rec = full_record();
    let text = serde_json::to_string(&rec).unwrap();
    let back: AuditRecord = serde_json::from_str(&text).unwrap();
    assert_eq!(back, rec);
}

#[test]
fn recorded_at_in_another_precision_is_refused() {
    let mut v = json(&full_record());
    v["recorded_at"] = "2026-10-16T09:30:12Z".into();
    assert!(serde_json::from_value::<AuditRecord>(v).is_err());
}

#[test]
fn accessors_expose_the_index_keys() {
    let rec = full_record();
    assert_eq!(rec.message_id(), "msg-1@sender.example");
    assert_eq!(rec.partner(), "9900000000002");
    assert_eq!(rec.signal(), Some(&[0xff, 0xfe, 0x00, b'<'][..]));
    assert_eq!(rec.record_id().len(), 36);
}

#[test]
fn record_ids_are_unique_uuid_v7() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..1000 {
        let id = new_record_id(crate::clock::system().now()).unwrap();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "7", "version nibble: {id}");
        assert!(
            matches!(&id[19..20], "8" | "9" | "a" | "b"),
            "variant: {id}"
        );
        assert!(seen.insert(id));
    }
}

#[test]
fn builder_rejects_error_kind_on_a_success_outcome() {
    let b = RecordBuilder::new(
        &crate::clock::system(),
        Protocol::As2,
        Direction::Inbound,
        "m",
        "a",
        "b",
    );
    assert!(
        b.clone()
            .finish(AuditOutcome::Accepted, Some("rejected"))
            .is_err()
    );
    assert!(b.clone().finish(AuditOutcome::Rejected, None).is_err());
    assert!(b.finish(AuditOutcome::Rejected, Some("rejected")).is_ok());
}

#[test]
fn builder_rejects_a_signal_for_another_message() {
    let err = RecordBuilder::new(
        &crate::clock::system(),
        Protocol::As4,
        Direction::Outbound,
        "m-1",
        "a",
        "b",
    )
    .signal(Signal {
        bytes: b"x",
        message_id: None,
        ref_to_message_id: Some("m-2"),
        timestamp: None,
        signed: false,
        nrr: &[],
    })
    .finish(AuditOutcome::Delivered, None)
    .unwrap_err();
    assert!(err.message.contains("m-2"), "{err}");
}

#[derive(Debug)]
struct TestSink {
    durability: AuditDurability,
    fail: bool,
    calls: AtomicUsize,
}

impl TestSink {
    fn new(durability: AuditDurability, fail: bool) -> Self {
        Self {
            durability,
            fail,
            calls: AtomicUsize::new(0),
        }
    }
}

impl AuditSink for TestSink {
    fn durability(&self) -> AuditDurability {
        self.durability
    }

    fn record<'a>(
        &'a self,
        _record: &'a AuditRecord,
    ) -> BoxFuture<'a, std::result::Result<(), Box<dyn StdError + Send + Sync>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let result = if self.fail {
            Err("disk full".into())
        } else {
            Ok(())
        };
        Box::pin(std::future::ready(result))
    }
}

#[tokio::test]
async fn durable_sink_failure_fails_and_names_the_record() {
    let sink = TestSink::new(AuditDurability::Durable, true);
    let rec = full_record();
    let err = record(Some(&sink), &rec, "test").await.unwrap_err();
    assert_eq!(err.code, ErrorCode::StorageBackendFailure);
    assert!(err.message.contains(rec.record_id()), "{err}");
    assert!(err.message.contains(rec.message_id()), "{err}");
    assert!(err.message.contains(rec.signal_sha256().unwrap()), "{err}");
    assert!(err.message.contains("disk full"), "{err}");
}

#[tokio::test]
async fn best_effort_sink_failure_does_not_fail() {
    let sink = TestSink::new(AuditDurability::BestEffort, true);
    record(Some(&sink), &full_record(), "test").await.unwrap();
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn no_sink_records_nothing() {
    record(None, &full_record(), "test").await.unwrap();
}

#[test]
fn arc_forwards() {
    let sink: Arc<dyn AuditSink> = Arc::new(TestSink::new(AuditDurability::BestEffort, false));
    assert_eq!(sink.durability(), AuditDurability::BestEffort);
}
