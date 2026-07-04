use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

pub mod file_spool;
pub mod http;

pub use file_spool::{
    As2ProviderHealthFileSpoolIncidentChannel, As4ReceiptTaxonomyFileSpoolIncidentChannel,
    FileSpoolForwardSummary, FileSpoolIdempotencyLedgerPolicy, FileSpoolIncidentConfig,
    FileSpoolIncidentEntry, FileSpoolReplayCheckpoint, FileSpoolReplayCheckpointStatus,
};
pub use http::{
    As2ProviderHealthPagingIncidentChannel, As2ProviderHealthWebhookIncidentChannel,
    As4ReceiptTaxonomyPagingIncidentChannel, As4ReceiptTaxonomyWebhookIncidentChannel,
};

#[cfg(test)]
use crate::observability::{As2ProviderHealthIncidentChannel, As4ReceiptTaxonomyIncidentChannel};
#[cfg(test)]
use file_spool::{
    FileSpoolReplayLedgerFile, now_unix_millis, persist_replay_idempotency_ledger,
    replay_idempotency_ledger_path,
};
#[cfg(test)]
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IncidentQueueOverflowPolicy {
    BestEffortDrop,
    FailClosed,
}

impl IncidentQueueOverflowPolicy {
    fn as_str(self) -> &'static str {
        match self {
            Self::BestEffortDrop => "best_effort_drop",
            Self::FailClosed => "fail_closed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Configuration for incident channel delivery queuing and backpressure.
///
/// # Backpressure Chain Warning
///
/// ASX has **two independent backpressure points** that interact when `FailClosed` is chosen:
///
/// 1. **`EventBus` backpressure** — the inner event bus has its own channel capacity. When
///    the event bus queue is full, `emit_event` blocks or drops (depending on `EventBus`
///    configuration).
///
/// 2. **Incident channel backpressure** — when the incident queue reaches
///    `queue_capacity`, the emission path waits up to `enqueue_backpressure_wait_millis`
///    before yielding a `FailClosed` error that propagates back through the receive path.
///
/// Under a large burst (replay attack, cascading gateway failures) these two points can
/// form a **deadlock chain**:
///
/// - The receive path fills the `EventBus`.
/// - The `EventBus` worker fills the incident queue.
/// - The incident queue blocks with `FailClosed`, which propagates back to the receive
///   path *as a protocol error*, rejecting otherwise-valid inbound messages.
///
/// ## Recommended mitigations
///
/// - **High-traffic environments**: use `IncidentDeliveryPolicyBundle::BestEffortRealtime`
///   (`BestEffortDrop` overflow policy, 0ms wait) so incident queue pressure never blocks
///   the receive path. Use [`RegulatedHighThroughput`] or custom sizing for regulated
///   environments that need lossless incident delivery.
///
/// - **Rate-limit at the transport layer**: reject or throttle inbound connections
///   upstream (e.g. via nginx `limit_req`) before the burst reaches the incident queue.
///
/// - **Increase `queue_capacity`**: use [`recommend_incident_delivery_config`] with your
///   actual workload `peak_incidents_per_sec` and `sustained_burst_secs` to derive a
///   properly sized queue rather than relying on the 64-slot default.
///
/// - **Separate receive and incident workers**: if operating at very high message
///   rates, run the incident delivery channel on a dedicated Tokio worker pool so that
///   incident queue pressure never affects the protocol receive path.
///
/// [`RegulatedHighThroughput`]: IncidentDeliveryPolicyBundle::RegulatedHighThroughput
pub struct IncidentDeliveryConfig {
    pub queue_capacity: usize,
    pub request_timeout_secs: u64,
    pub enqueue_backpressure_wait_millis: u64,
    pub queue_overflow: IncidentQueueOverflowPolicy,
}

impl Default for IncidentDeliveryConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 64,
            request_timeout_secs: 5,
            enqueue_backpressure_wait_millis: 25,
            queue_overflow: IncidentQueueOverflowPolicy::FailClosed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IncidentDeliveryPolicyBundle {
    RegulatedLowLatency,
    RegulatedHighThroughput,
    BestEffortRealtime,
}

impl IncidentDeliveryPolicyBundle {
    pub fn into_config(self) -> IncidentDeliveryConfig {
        match self {
            Self::RegulatedLowLatency => IncidentDeliveryConfig {
                queue_capacity: 64,
                request_timeout_secs: 5,
                enqueue_backpressure_wait_millis: 25,
                queue_overflow: IncidentQueueOverflowPolicy::FailClosed,
            },
            Self::RegulatedHighThroughput => IncidentDeliveryConfig {
                queue_capacity: 256,
                request_timeout_secs: 5,
                enqueue_backpressure_wait_millis: 100,
                queue_overflow: IncidentQueueOverflowPolicy::FailClosed,
            },
            Self::BestEffortRealtime => IncidentDeliveryConfig {
                queue_capacity: 256,
                request_timeout_secs: 3,
                enqueue_backpressure_wait_millis: 0,
                queue_overflow: IncidentQueueOverflowPolicy::BestEffortDrop,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncidentDeliverySizingInput {
    pub peak_incidents_per_sec: usize,
    pub sustained_burst_secs: u64,
    pub delivery_p99_millis: u64,
    pub regulated: bool,
}

#[inline]
fn ceil_div_u64(value: u64, divisor: u64) -> u64 {
    value.saturating_add(divisor.saturating_sub(1)) / divisor
}

#[inline]
fn next_power_of_two_capped(value: usize, cap: usize) -> usize {
    if value <= 1 {
        return 1;
    }

    match value.checked_next_power_of_two() {
        Some(pow2) => pow2.min(cap),
        None => cap,
    }
}

/// Derive a deterministic incident-delivery configuration from workload signals.
///
/// This provides a fail-closed baseline for high-cardinality deployments where
/// queue sizing and timeouts must be explicit and reproducible in reviews.
pub fn recommend_incident_delivery_config(
    input: IncidentDeliverySizingInput,
) -> Result<IncidentDeliveryConfig> {
    if input.peak_incidents_per_sec == 0 {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "incident sizing peak_incidents_per_sec must be greater than zero",
            ErrorContext::new("incident_delivery_sizing"),
        ));
    }

    if input.sustained_burst_secs == 0 {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "incident sizing sustained_burst_secs must be greater than zero",
            ErrorContext::new("incident_delivery_sizing"),
        ));
    }

    if input.delivery_p99_millis == 0 {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "incident sizing delivery_p99_millis must be greater than zero",
            ErrorContext::new("incident_delivery_sizing"),
        ));
    }

    let burst_secs = input.sustained_burst_secs.clamp(1, 30) as usize;
    let projected_backlog = input.peak_incidents_per_sec.saturating_mul(burst_secs);

    let (min_capacity, max_capacity, overflow_policy) = if input.regulated {
        (
            128usize,
            16_384usize,
            IncidentQueueOverflowPolicy::FailClosed,
        )
    } else {
        (
            64usize,
            16_384usize,
            IncidentQueueOverflowPolicy::BestEffortDrop,
        )
    };

    let queue_capacity =
        next_power_of_two_capped(projected_backlog.max(min_capacity), max_capacity)
            .max(min_capacity);

    let request_timeout_secs =
        ceil_div_u64(input.delivery_p99_millis.saturating_mul(4), 1_000).clamp(2, 30);

    let enqueue_backpressure_wait_millis = if input.regulated {
        input.delivery_p99_millis.saturating_mul(2).clamp(25, 750)
    } else {
        0
    };

    Ok(IncidentDeliveryConfig {
        queue_capacity,
        request_timeout_secs,
        enqueue_backpressure_wait_millis,
        queue_overflow: overflow_policy,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncidentDeliveryMetricsSnapshot {
    pub queue_capacity: usize,
    pub queued_depth: usize,
    pub accepted_total: u64,
    pub dropped_total: u64,
    pub capacity_exhausted_total: u64,
    pub worker_stopped_total: u64,
}

#[derive(Debug)]
struct IncidentDeliveryMetrics {
    queue_capacity: usize,
    queued_depth: AtomicUsize,
    accepted_total: AtomicU64,
    dropped_total: AtomicU64,
    capacity_exhausted_total: AtomicU64,
    worker_stopped_total: AtomicU64,
}

impl IncidentDeliveryMetrics {
    fn new(queue_capacity: usize) -> Self {
        Self {
            queue_capacity,
            queued_depth: AtomicUsize::new(0),
            accepted_total: AtomicU64::new(0),
            dropped_total: AtomicU64::new(0),
            capacity_exhausted_total: AtomicU64::new(0),
            worker_stopped_total: AtomicU64::new(0),
        }
    }

    fn record_enqueue_accepted(&self) {
        self.accepted_total.fetch_add(1, Ordering::Relaxed);
        self.queued_depth.fetch_add(1, Ordering::Relaxed);
    }

    fn record_enqueue_dropped(&self) {
        self.dropped_total.fetch_add(1, Ordering::Relaxed);
    }

    fn record_capacity_exhausted(&self) {
        self.capacity_exhausted_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_worker_stopped(&self) {
        self.worker_stopped_total.fetch_add(1, Ordering::Relaxed);
    }

    fn record_dequeue(&self) {
        let _ = self
            .queued_depth
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(1))
            });
    }

    fn snapshot(&self) -> IncidentDeliveryMetricsSnapshot {
        IncidentDeliveryMetricsSnapshot {
            queue_capacity: self.queue_capacity,
            queued_depth: self.queued_depth.load(Ordering::Relaxed),
            accepted_total: self.accepted_total.load(Ordering::Relaxed),
            dropped_total: self.dropped_total.load(Ordering::Relaxed),
            capacity_exhausted_total: self.capacity_exhausted_total.load(Ordering::Relaxed),
            worker_stopped_total: self.worker_stopped_total.load(Ordering::Relaxed),
        }
    }
}

impl fmt::Display for IncidentDeliveryConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "queue_capacity={}, request_timeout_secs={}, enqueue_backpressure_wait_millis={}, queue_overflow={}",
            self.queue_capacity,
            self.request_timeout_secs,
            self.enqueue_backpressure_wait_millis,
            self.queue_overflow.as_str()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::observability::{
        As2ProviderHealthAlertCategory, As2ProviderHealthAlertIncident,
        As2ProviderHealthAlertSeverity, As4ReceiptTaxonomyAlertCategory,
        As4ReceiptTaxonomyAlertIncident, As4ReceiptTaxonomyAlertSeverity,
    };

    fn read_http_request(mut stream: TcpStream) -> String {
        let mut header = Vec::new();
        let mut byte = [0u8; 1];

        loop {
            stream.read_exact(&mut byte).expect("read request byte");
            header.push(byte[0]);
            if header.ends_with(b"\r\n\r\n") {
                break;
            }
        }

        let header_text = String::from_utf8(header.clone()).expect("valid utf8 headers");
        let content_length = header_text
            .lines()
            .find_map(|line| {
                let lower = line.to_ascii_lowercase();
                lower
                    .strip_prefix("content-length: ")
                    .and_then(|value| value.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);

        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            stream.read_exact(&mut body).expect("read request body");
        }

        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("write response");

        header.extend_from_slice(&body);
        String::from_utf8(header).expect("valid utf8 request")
    }

    fn unique_spool_path(prefix: &str) -> PathBuf {
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("asx-{prefix}-{now_nanos}.jsonl"))
    }

    fn unique_checkpoint_path(prefix: &str) -> PathBuf {
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("asx-{prefix}-{now_nanos}.checkpoint.json"))
    }

    #[derive(Debug)]
    struct RecordingAs2Channel {
        sent: Mutex<Vec<String>>,
        fail_after: Option<usize>,
    }

    impl RecordingAs2Channel {
        fn new(fail_after: Option<usize>) -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                fail_after,
            }
        }
    }

    impl As2ProviderHealthIncidentChannel for RecordingAs2Channel {
        fn send_incident(&self, incident: &As2ProviderHealthAlertIncident) -> Result<()> {
            let mut sent = self.sent.lock().expect("lock recording channel");
            if let Some(limit) = self.fail_after
                && sent.len() >= limit
            {
                return Err(AsxError::new(
                    ErrorCode::ReliabilityFailure,
                    "simulated as2 forward failure",
                    ErrorContext::new("recording_as2_channel"),
                ));
            }
            sent.push(incident.dedup_key.clone());
            Ok(())
        }
    }

    #[derive(Debug)]
    struct RecordingAs4Channel {
        sent: Mutex<Vec<String>>,
        fail_after: Option<usize>,
    }

    impl RecordingAs4Channel {
        fn new(fail_after: Option<usize>) -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                fail_after,
            }
        }
    }

    impl As4ReceiptTaxonomyIncidentChannel for RecordingAs4Channel {
        fn send_incident(&self, incident: &As4ReceiptTaxonomyAlertIncident) -> Result<()> {
            let mut sent = self.sent.lock().expect("lock recording channel");
            if let Some(limit) = self.fail_after
                && sent.len() >= limit
            {
                return Err(AsxError::new(
                    ErrorCode::ReliabilityFailure,
                    "simulated as4 forward failure",
                    ErrorContext::new("recording_as4_channel"),
                ));
            }
            sent.push(incident.dedup_key.clone());
            Ok(())
        }
    }

    fn as2_incident(dedup_key: &str) -> As2ProviderHealthAlertIncident {
        As2ProviderHealthAlertIncident {
            dedup_key: dedup_key.to_string(),
            signal: "as2",
            severity: As2ProviderHealthAlertSeverity::Critical,
            category: As2ProviderHealthAlertCategory::TransitionToFailingRate,
            observed_rate_ppm: 600_000,
            sample_size: 20,
            runbook_hint: "Investigate provider health.",
        }
    }

    #[test]
    fn policy_bundle_regulated_low_latency_maps_to_fail_closed_defaults() {
        let config = IncidentDeliveryPolicyBundle::RegulatedLowLatency.into_config();
        assert_eq!(config.queue_capacity, 64);
        assert_eq!(config.request_timeout_secs, 5);
        assert_eq!(config.enqueue_backpressure_wait_millis, 25);
        assert_eq!(
            config.queue_overflow,
            IncidentQueueOverflowPolicy::FailClosed
        );
    }

    #[test]
    fn policy_bundle_best_effort_realtime_maps_to_drop_policy() {
        let config = IncidentDeliveryPolicyBundle::BestEffortRealtime.into_config();
        assert_eq!(config.queue_capacity, 256);
        assert_eq!(config.request_timeout_secs, 3);
        assert_eq!(config.enqueue_backpressure_wait_millis, 0);
        assert_eq!(
            config.queue_overflow,
            IncidentQueueOverflowPolicy::BestEffortDrop
        );
    }

    #[test]
    fn recommend_incident_delivery_config_regulated_maps_to_fail_closed_profile() {
        let config = recommend_incident_delivery_config(IncidentDeliverySizingInput {
            peak_incidents_per_sec: 300,
            sustained_burst_secs: 4,
            delivery_p99_millis: 180,
            regulated: true,
        })
        .expect("regulated sizing recommendation must succeed");

        assert_eq!(config.queue_capacity, 2048);
        assert_eq!(config.request_timeout_secs, 2);
        assert_eq!(config.enqueue_backpressure_wait_millis, 360);
        assert_eq!(
            config.queue_overflow,
            IncidentQueueOverflowPolicy::FailClosed
        );
    }

    #[test]
    fn recommend_incident_delivery_config_best_effort_maps_to_drop_profile() {
        let config = recommend_incident_delivery_config(IncidentDeliverySizingInput {
            peak_incidents_per_sec: 40,
            sustained_burst_secs: 2,
            delivery_p99_millis: 900,
            regulated: false,
        })
        .expect("best-effort sizing recommendation must succeed");

        assert_eq!(config.queue_capacity, 128);
        assert_eq!(config.request_timeout_secs, 4);
        assert_eq!(config.enqueue_backpressure_wait_millis, 0);
        assert_eq!(
            config.queue_overflow,
            IncidentQueueOverflowPolicy::BestEffortDrop
        );
    }

    #[test]
    fn recommend_incident_delivery_config_rejects_zero_inputs() {
        let err = recommend_incident_delivery_config(IncidentDeliverySizingInput {
            peak_incidents_per_sec: 0,
            sustained_burst_secs: 1,
            delivery_p99_millis: 100,
            regulated: true,
        })
        .expect_err("zero peak incidents must fail fast");
        assert_eq!(err.code, ErrorCode::InvalidInput);

        let err = recommend_incident_delivery_config(IncidentDeliverySizingInput {
            peak_incidents_per_sec: 10,
            sustained_burst_secs: 0,
            delivery_p99_millis: 100,
            regulated: true,
        })
        .expect_err("zero burst window must fail fast");
        assert_eq!(err.code, ErrorCode::InvalidInput);

        let err = recommend_incident_delivery_config(IncidentDeliverySizingInput {
            peak_incidents_per_sec: 10,
            sustained_burst_secs: 1,
            delivery_p99_millis: 0,
            regulated: true,
        })
        .expect_err("zero delivery p99 must fail fast");
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn as2_webhook_channel_posts_json_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept request");
            read_http_request(stream)
        });

        let channel = As2ProviderHealthWebhookIncidentChannel::with_raw_config(
            format!("http://{addr}"),
            IncidentDeliveryConfig {
                queue_capacity: 8,
                request_timeout_secs: 2,
                enqueue_backpressure_wait_millis: 25,
                queue_overflow: IncidentQueueOverflowPolicy::FailClosed,
            },
        )
        .expect("construct webhook channel");

        let incident = As2ProviderHealthAlertIncident {
            dedup_key: "as2:provider-health:critical:transition_to_failing_rate".to_string(),
            signal: "as2",
            severity: As2ProviderHealthAlertSeverity::Critical,
            category: As2ProviderHealthAlertCategory::TransitionToFailingRate,
            observed_rate_ppm: 600_000,
            sample_size: 20,
            runbook_hint: "Investigate provider health.",
        };

        channel.send_incident(&incident).expect("enqueue incident");
        let request = server.join().expect("server thread");
        assert!(request.contains("POST / HTTP/1.1"));
        assert!(request.contains("\"adapter\":\"as2_provider_health_webhook\""));
        assert!(request.contains("\"protocol\":\"as2\""));
        assert!(
            request.contains(
                "\"dedup_key\":\"as2:provider-health:critical:transition_to_failing_rate\""
            )
        );
    }

    #[test]
    fn as4_webhook_channel_posts_json_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept request");
            read_http_request(stream)
        });

        let channel = As4ReceiptTaxonomyWebhookIncidentChannel::with_raw_config(
            format!("http://{addr}"),
            IncidentDeliveryConfig {
                queue_capacity: 8,
                request_timeout_secs: 2,
                enqueue_backpressure_wait_millis: 25,
                queue_overflow: IncidentQueueOverflowPolicy::FailClosed,
            },
        )
        .expect("construct webhook channel");

        let incident = As4ReceiptTaxonomyAlertIncident {
            dedup_key: "as4:receipt-taxonomy:critical:security_verification_failed".to_string(),
            signal: "as4",
            severity: As4ReceiptTaxonomyAlertSeverity::Critical,
            category: As4ReceiptTaxonomyAlertCategory::SecurityVerificationFailed,
            observed_rate_ppm: 75_000,
            sample_size: 100,
            runbook_hint: "Check WS-Security signature verification.",
        };

        channel.send_incident(&incident).expect("enqueue incident");
        let request = server.join().expect("server thread");
        assert!(request.contains("POST / HTTP/1.1"));
        assert!(request.contains("\"adapter\":\"as4_receipt_taxonomy_webhook\""));
        assert!(request.contains("\"protocol\":\"as4\""));
        assert!(request.contains(
            "\"dedup_key\":\"as4:receipt-taxonomy:critical:security_verification_failed\""
        ));
    }

    #[test]
    fn as2_paging_channel_posts_json_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept request");
            read_http_request(stream)
        });

        let channel = As2ProviderHealthPagingIncidentChannel::with_raw_config(
            format!("http://{addr}"),
            "routing-key-123",
            "asx-test-service",
            IncidentDeliveryConfig {
                queue_capacity: 8,
                request_timeout_secs: 2,
                enqueue_backpressure_wait_millis: 25,
                queue_overflow: IncidentQueueOverflowPolicy::FailClosed,
            },
        )
        .expect("construct paging channel");

        let incident = As2ProviderHealthAlertIncident {
            dedup_key: "as2:provider-health:critical:transition_to_failing_rate".to_string(),
            signal: "as2",
            severity: As2ProviderHealthAlertSeverity::Critical,
            category: As2ProviderHealthAlertCategory::TransitionToFailingRate,
            observed_rate_ppm: 600_000,
            sample_size: 20,
            runbook_hint: "Investigate provider health.",
        };

        channel.send_incident(&incident).expect("enqueue incident");
        let request = server.join().expect("server thread");
        assert!(request.contains("POST / HTTP/1.1"));
        assert!(request.contains("\"routing_key\":\"routing-key-123\""));
        assert!(request.contains("\"source\":\"asx-test-service\""));
        assert!(request.contains(
            "\"summary\":\"AS2 provider-health incident: critical transition_to_failing_rate\""
        ));
    }

    #[test]
    fn as4_paging_channel_posts_json_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept request");
            read_http_request(stream)
        });

        let channel = As4ReceiptTaxonomyPagingIncidentChannel::with_raw_config(
            format!("http://{addr}"),
            "routing-key-456",
            "asx-test-service",
            IncidentDeliveryConfig {
                queue_capacity: 8,
                request_timeout_secs: 2,
                enqueue_backpressure_wait_millis: 25,
                queue_overflow: IncidentQueueOverflowPolicy::FailClosed,
            },
        )
        .expect("construct paging channel");

        let incident = As4ReceiptTaxonomyAlertIncident {
            dedup_key: "as4:receipt-taxonomy:critical:security_verification_failed".to_string(),
            signal: "as4",
            severity: As4ReceiptTaxonomyAlertSeverity::Critical,
            category: As4ReceiptTaxonomyAlertCategory::SecurityVerificationFailed,
            observed_rate_ppm: 75_000,
            sample_size: 100,
            runbook_hint: "Check WS-Security signature verification.",
        };

        channel.send_incident(&incident).expect("enqueue incident");
        let request = server.join().expect("server thread");
        assert!(request.contains("POST / HTTP/1.1"));
        assert!(request.contains("\"routing_key\":\"routing-key-456\""));
        assert!(request.contains("\"source\":\"asx-test-service\""));
        assert!(request.contains(
            "\"summary\":\"AS4 receipt-taxonomy incident: critical security_verification_failed\""
        ));
    }

    #[test]
    fn webhook_channel_rejects_zero_queue_capacity() {
        let err = As2ProviderHealthWebhookIncidentChannel::with_raw_config(
            "http://127.0.0.1:9",
            IncidentDeliveryConfig {
                queue_capacity: 0,
                request_timeout_secs: 1,
                enqueue_backpressure_wait_millis: 25,
                queue_overflow: IncidentQueueOverflowPolicy::FailClosed,
            },
        )
        .expect_err("zero queue capacity must fail fast");
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn webhook_channel_rejects_zero_request_timeout_secs() {
        let err = As2ProviderHealthWebhookIncidentChannel::with_raw_config(
            "http://127.0.0.1:9",
            IncidentDeliveryConfig {
                queue_capacity: 1,
                request_timeout_secs: 0,
                enqueue_backpressure_wait_millis: 25,
                queue_overflow: IncidentQueueOverflowPolicy::FailClosed,
            },
        )
        .expect_err("zero request timeout must fail fast");
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn webhook_channel_shutdown_and_drain_is_deterministic() {
        let mut channel = As2ProviderHealthWebhookIncidentChannel::with_raw_config(
            "http://127.0.0.1:9",
            IncidentDeliveryConfig {
                queue_capacity: 4,
                request_timeout_secs: 1,
                enqueue_backpressure_wait_millis: 25,
                queue_overflow: IncidentQueueOverflowPolicy::FailClosed,
            },
        )
        .expect("construct webhook channel");

        channel
            .shutdown_and_drain(Duration::from_millis(500))
            .expect("shutdown and drain");

        let incident = As2ProviderHealthAlertIncident {
            dedup_key: "as2:provider-health:critical:transition_to_failing_rate".to_string(),
            signal: "as2",
            severity: As2ProviderHealthAlertSeverity::Critical,
            category: As2ProviderHealthAlertCategory::TransitionToFailingRate,
            observed_rate_ppm: 600_000,
            sample_size: 20,
            runbook_hint: "Investigate provider health.",
        };

        let err = channel
            .send_incident(&incident)
            .expect_err("sending after shutdown must fail");
        assert_eq!(err.code, ErrorCode::TransportFailure);
    }

    #[test]
    fn fail_closed_reports_capacity_when_queue_stays_full_without_wait_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            thread::sleep(Duration::from_millis(300));
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        });

        let channel = As2ProviderHealthWebhookIncidentChannel::with_raw_config(
            format!("http://{addr}"),
            IncidentDeliveryConfig {
                queue_capacity: 1,
                request_timeout_secs: 1,
                enqueue_backpressure_wait_millis: 0,
                queue_overflow: IncidentQueueOverflowPolicy::FailClosed,
            },
        )
        .expect("construct webhook channel");

        channel
            .send_incident(&as2_incident("as2:test:burst:1"))
            .expect("enqueue first incident");

        thread::sleep(Duration::from_millis(20));

        // Each failed attempt under FailClosed increments capacity_exhausted_total,
        // so track retries here and add them to the expected final count.
        let mut fill_retries: u64 = 0;
        let fill_deadline = Instant::now() + Duration::from_millis(500);
        loop {
            let second_result = channel.send_incident(&as2_incident("as2:test:burst:2"));
            if second_result.is_ok() {
                break;
            }
            fill_retries += 1;
            if Instant::now() >= fill_deadline {
                panic!("failed to enqueue second incident before deadline");
            }
            thread::sleep(Duration::from_millis(1));
        }

        let err = channel
            .send_incident(&as2_incident("as2:test:burst:3"))
            .expect_err("third incident must fail closed when queue remains saturated");
        assert_eq!(err.code, ErrorCode::CapacityExhausted);

        let metrics = channel.metrics_snapshot();
        assert_eq!(metrics.queue_capacity, 1);
        assert_eq!(metrics.accepted_total, 2);
        // fill_retries failed FailClosed attempts + the one burst:3 rejection
        assert_eq!(metrics.capacity_exhausted_total, fill_retries + 1);
        assert_eq!(metrics.dropped_total, 0);

        let _ = server.join();
    }

    #[test]
    fn best_effort_drop_updates_exact_metrics_snapshot() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let server = thread::spawn(move || {
            let (first, _) = listener.accept().expect("accept first request");
            thread::sleep(Duration::from_millis(150));
            let _ = read_http_request(first);
            let (second, _) = listener.accept().expect("accept second request");
            let _ = read_http_request(second);
        });

        let channel = As2ProviderHealthWebhookIncidentChannel::with_raw_config(
            format!("http://{addr}"),
            IncidentDeliveryConfig {
                queue_capacity: 1,
                request_timeout_secs: 1,
                enqueue_backpressure_wait_millis: 0,
                queue_overflow: IncidentQueueOverflowPolicy::BestEffortDrop,
            },
        )
        .expect("construct webhook channel");

        channel
            .send_incident(&as2_incident("as2:test:drop:1"))
            .expect("enqueue first incident");

        thread::sleep(Duration::from_millis(20));

        // BestEffortDrop always returns Ok even when dropping, so we cannot rely on
        // the return value to detect a successful enqueue. Poll accepted_total instead,
        // and track how many attempts were silently dropped in the loop.
        let mut drop2_extra_drops: u64 = 0;
        let fill_deadline = Instant::now() + Duration::from_millis(500);
        loop {
            let before = channel.metrics_snapshot().accepted_total;
            channel
                .send_incident(&as2_incident("as2:test:drop:2"))
                .expect("no error on drop policy");
            if channel.metrics_snapshot().accepted_total > before {
                break; // drop:2 was actually enqueued
            }
            drop2_extra_drops += 1;
            if Instant::now() >= fill_deadline {
                panic!("drop:2 was never accepted before deadline");
            }
            thread::sleep(Duration::from_millis(5));
        }

        channel
            .send_incident(&as2_incident("as2:test:drop:3"))
            .expect("third incident should be dropped by policy, not error");

        let metrics = channel.metrics_snapshot();
        assert_eq!(metrics.queue_capacity, 1);
        assert_eq!(metrics.accepted_total, 2);
        // drop2_extra_drops silent drops in the loop + the one drop:3 rejection
        assert_eq!(metrics.dropped_total, drop2_extra_drops + 1);
        assert_eq!(metrics.capacity_exhausted_total, 0);

        let _ = server.join();
    }

    #[test]
    fn fail_closed_wait_budget_absorbs_transient_queue_saturation() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let server = thread::spawn(move || {
            let (first, _) = listener.accept().expect("accept first request");
            thread::sleep(Duration::from_millis(120));
            let _ = read_http_request(first);
            let (second, _) = listener.accept().expect("accept second request");
            let _ = read_http_request(second);
        });

        let channel = As2ProviderHealthWebhookIncidentChannel::with_raw_config(
            format!("http://{addr}"),
            IncidentDeliveryConfig {
                queue_capacity: 1,
                request_timeout_secs: 1,
                enqueue_backpressure_wait_millis: 300,
                queue_overflow: IncidentQueueOverflowPolicy::FailClosed,
            },
        )
        .expect("construct webhook channel");

        channel
            .send_incident(&as2_incident("as2:test:recovery:1"))
            .expect("enqueue first incident");
        thread::sleep(Duration::from_millis(20));

        let fill_deadline = Instant::now() + Duration::from_millis(200);
        loop {
            let second_result = channel.send_incident(&as2_incident("as2:test:recovery:2"));
            if second_result.is_ok() {
                break;
            }
            if Instant::now() >= fill_deadline {
                panic!("failed to enqueue second incident before deadline");
            }
            thread::sleep(Duration::from_millis(1));
        }

        channel
            .send_incident(&as2_incident("as2:test:recovery:3"))
            .expect("third incident should enqueue after transient saturation clears");

        let _ = server.join();
    }

    #[test]
    fn as2_file_spool_channel_appends_incident_jsonl() {
        let path = unique_spool_path("as2-incident-spool");
        let channel =
            As2ProviderHealthFileSpoolIncidentChannel::with_config(FileSpoolIncidentConfig {
                path: path.clone(),
                fsync_each_write: true,
                idempotency_ledger_policy: FileSpoolIdempotencyLedgerPolicy::default(),
            })
            .expect("construct as2 file spool channel");

        let incident = As2ProviderHealthAlertIncident {
            dedup_key: "as2:provider-health:critical:transition_to_failing_rate".to_string(),
            signal: "as2",
            severity: As2ProviderHealthAlertSeverity::Critical,
            category: As2ProviderHealthAlertCategory::TransitionToFailingRate,
            observed_rate_ppm: 600_000,
            sample_size: 20,
            runbook_hint: "Investigate provider health.",
        };

        channel.send_incident(&incident).expect("spool incident");

        let contents = fs::read_to_string(&path).expect("read spool file");
        assert!(contents.contains("\"adapter\":\"as2_provider_health_file_spool\""));
        assert!(contents.contains("\"protocol\":\"as2\""));
        assert!(
            contents.contains(
                "\"dedup_key\":\"as2:provider-health:critical:transition_to_failing_rate\""
            )
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn as4_file_spool_channel_appends_incident_jsonl() {
        let path = unique_spool_path("as4-incident-spool");
        let channel =
            As4ReceiptTaxonomyFileSpoolIncidentChannel::with_config(FileSpoolIncidentConfig {
                path: path.clone(),
                fsync_each_write: true,
                idempotency_ledger_policy: FileSpoolIdempotencyLedgerPolicy::default(),
            })
            .expect("construct as4 file spool channel");

        let incident = As4ReceiptTaxonomyAlertIncident {
            dedup_key: "as4:receipt-taxonomy:critical:security_verification_failed".to_string(),
            signal: "as4",
            severity: As4ReceiptTaxonomyAlertSeverity::Critical,
            category: As4ReceiptTaxonomyAlertCategory::SecurityVerificationFailed,
            observed_rate_ppm: 75_000,
            sample_size: 100,
            runbook_hint: "Check WS-Security signature verification.",
        };

        channel.send_incident(&incident).expect("spool incident");

        let contents = fs::read_to_string(&path).expect("read spool file");
        assert!(contents.contains("\"adapter\":\"as4_receipt_taxonomy_file_spool\""));
        assert!(contents.contains("\"protocol\":\"as4\""));
        assert!(contents.contains(
            "\"dedup_key\":\"as4:receipt-taxonomy:critical:security_verification_failed\""
        ));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn as2_file_spool_channel_replay_and_drain_are_deterministic() {
        let path = unique_spool_path("as2-incident-spool-replay");
        let channel =
            As2ProviderHealthFileSpoolIncidentChannel::with_config(FileSpoolIncidentConfig {
                path: path.clone(),
                fsync_each_write: true,
                idempotency_ledger_policy: FileSpoolIdempotencyLedgerPolicy::default(),
            })
            .expect("construct as2 file spool channel");

        let incident = As2ProviderHealthAlertIncident {
            dedup_key: "as2:provider-health:critical:transition_to_failing_rate".to_string(),
            signal: "as2",
            severity: As2ProviderHealthAlertSeverity::Critical,
            category: As2ProviderHealthAlertCategory::TransitionToFailingRate,
            observed_rate_ppm: 600_000,
            sample_size: 20,
            runbook_hint: "Investigate provider health.",
        };

        channel.send_incident(&incident).expect("spool incident");

        let replayed = channel
            .replay_spooled_incidents()
            .expect("replay spooled incidents");
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].protocol, "as2");
        assert_eq!(
            replayed[0].dedup_key,
            "as2:provider-health:critical:transition_to_failing_rate"
        );

        let contents_after_replay =
            fs::read_to_string(&path).expect("read spool file after replay");
        assert!(!contents_after_replay.trim().is_empty());

        let drained = channel
            .drain_spooled_incidents()
            .expect("drain spooled incidents");
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].protocol, "as2");

        let contents_after_drain = fs::read_to_string(&path).expect("read spool file after drain");
        assert!(contents_after_drain.trim().is_empty());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn as4_file_spool_channel_drain_returns_entries_and_truncates_file() {
        let path = unique_spool_path("as4-incident-spool-drain");
        let channel =
            As4ReceiptTaxonomyFileSpoolIncidentChannel::with_config(FileSpoolIncidentConfig {
                path: path.clone(),
                fsync_each_write: true,
                idempotency_ledger_policy: FileSpoolIdempotencyLedgerPolicy::default(),
            })
            .expect("construct as4 file spool channel");

        let incident = As4ReceiptTaxonomyAlertIncident {
            dedup_key: "as4:receipt-taxonomy:critical:security_verification_failed".to_string(),
            signal: "as4",
            severity: As4ReceiptTaxonomyAlertSeverity::Critical,
            category: As4ReceiptTaxonomyAlertCategory::SecurityVerificationFailed,
            observed_rate_ppm: 75_000,
            sample_size: 100,
            runbook_hint: "Check WS-Security signature verification.",
        };

        channel.send_incident(&incident).expect("spool incident");

        let drained = channel
            .drain_spooled_incidents()
            .expect("drain spooled incidents");
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].protocol, "as4");
        assert_eq!(
            drained[0].dedup_key,
            "as4:receipt-taxonomy:critical:security_verification_failed"
        );

        let contents_after_drain = fs::read_to_string(&path).expect("read spool file after drain");
        assert!(contents_after_drain.trim().is_empty());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn as2_file_spool_drain_forward_writes_committed_checkpoint() {
        let path = unique_spool_path("as2-incident-forward");
        let checkpoint_path = unique_checkpoint_path("as2-incident-forward");
        let ledger_path = replay_idempotency_ledger_path(&checkpoint_path);
        let channel =
            As2ProviderHealthFileSpoolIncidentChannel::with_config(FileSpoolIncidentConfig {
                path: path.clone(),
                fsync_each_write: true,
                idempotency_ledger_policy: FileSpoolIdempotencyLedgerPolicy::default(),
            })
            .expect("construct as2 file spool channel");

        channel
            .send_incident(&as2_incident("as2:forward:test:1"))
            .expect("spool first incident");
        channel
            .send_incident(&as2_incident("as2:forward:test:2"))
            .expect("spool second incident");

        let downstream = RecordingAs2Channel::new(None);
        let summary = channel
            .drain_and_forward_with_checkpoint(&downstream, checkpoint_path.clone())
            .expect("drain and forward with checkpoint");

        assert_eq!(summary.checkpoint.status, "committed");
        assert_eq!(summary.checkpoint.forwarded_entries, 2);
        assert_eq!(summary.checkpoint.skipped_duplicate_entries, 0);
        assert_eq!(summary.checkpoint.requeued_entries, 0);

        let remaining = channel
            .replay_spooled_incidents()
            .expect("replay remaining incidents");
        assert!(remaining.is_empty());

        let checkpoint_contents =
            fs::read_to_string(&checkpoint_path).expect("read checkpoint file");
        let checkpoint: FileSpoolReplayCheckpoint =
            serde_json::from_str(&checkpoint_contents).expect("parse checkpoint json");
        assert_eq!(checkpoint.status, "committed");
        assert_eq!(checkpoint.forwarded_entries, 2);
        assert_eq!(checkpoint.skipped_duplicate_entries, 0);

        let sent = downstream.sent.lock().expect("lock sent list");
        assert_eq!(sent.len(), 2);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&checkpoint_path);
        let _ = fs::remove_file(&ledger_path);
    }

    #[test]
    fn as4_file_spool_drain_forward_failure_requeues_and_checkpoints_failed() {
        let path = unique_spool_path("as4-incident-forward-failure");
        let checkpoint_path = unique_checkpoint_path("as4-incident-forward-failure");
        let ledger_path = replay_idempotency_ledger_path(&checkpoint_path);
        let channel =
            As4ReceiptTaxonomyFileSpoolIncidentChannel::with_config(FileSpoolIncidentConfig {
                path: path.clone(),
                fsync_each_write: true,
                idempotency_ledger_policy: FileSpoolIdempotencyLedgerPolicy::default(),
            })
            .expect("construct as4 file spool channel");

        let first = As4ReceiptTaxonomyAlertIncident {
            dedup_key: "as4:forward:test:1".to_string(),
            signal: "as4",
            severity: As4ReceiptTaxonomyAlertSeverity::Critical,
            category: As4ReceiptTaxonomyAlertCategory::SecurityVerificationFailed,
            observed_rate_ppm: 75_000,
            sample_size: 100,
            runbook_hint: "Check WS-Security signature verification.",
        };
        let second = As4ReceiptTaxonomyAlertIncident {
            dedup_key: "as4:forward:test:2".to_string(),
            signal: "as4",
            severity: As4ReceiptTaxonomyAlertSeverity::Warning,
            category: As4ReceiptTaxonomyAlertCategory::SemanticInteropFailure,
            observed_rate_ppm: 25_000,
            sample_size: 100,
            runbook_hint: "Review interoperability profile mapping and payload semantics.",
        };

        channel.send_incident(&first).expect("spool first incident");
        channel
            .send_incident(&second)
            .expect("spool second incident");

        let downstream = RecordingAs4Channel::new(Some(1));
        let err = channel
            .drain_and_forward_with_checkpoint(&downstream, checkpoint_path.clone())
            .expect_err("forward must fail on second incident");
        assert_eq!(err.code, ErrorCode::ReliabilityFailure);

        let remaining = channel
            .replay_spooled_incidents()
            .expect("replay remaining incidents");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].dedup_key, "as4:forward:test:2");

        let checkpoint_contents =
            fs::read_to_string(&checkpoint_path).expect("read checkpoint file");
        let checkpoint: FileSpoolReplayCheckpoint =
            serde_json::from_str(&checkpoint_contents).expect("parse checkpoint json");
        assert_eq!(checkpoint.status, "failed");
        assert_eq!(checkpoint.forwarded_entries, 1);
        assert_eq!(checkpoint.skipped_duplicate_entries, 0);
        assert_eq!(checkpoint.requeued_entries, 1);

        let sent = downstream.sent.lock().expect("lock sent list");
        assert_eq!(sent.len(), 1);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&checkpoint_path);
        let _ = fs::remove_file(&ledger_path);
    }

    #[test]
    fn as4_file_spool_forward_failure_requeues_remaining_tail_entries() {
        let path = unique_spool_path("as4-incident-forward-tail-requeue");
        let checkpoint_path = unique_checkpoint_path("as4-incident-forward-tail-requeue");
        let ledger_path = replay_idempotency_ledger_path(&checkpoint_path);
        let channel =
            As4ReceiptTaxonomyFileSpoolIncidentChannel::with_config(FileSpoolIncidentConfig {
                path: path.clone(),
                fsync_each_write: true,
                idempotency_ledger_policy: FileSpoolIdempotencyLedgerPolicy::default(),
            })
            .expect("construct as4 file spool channel");

        for key in [
            "as4:forward:tail:1",
            "as4:forward:tail:2",
            "as4:forward:tail:3",
        ] {
            let incident = As4ReceiptTaxonomyAlertIncident {
                dedup_key: key.to_string(),
                signal: "as4",
                severity: As4ReceiptTaxonomyAlertSeverity::Critical,
                category: As4ReceiptTaxonomyAlertCategory::SecurityVerificationFailed,
                observed_rate_ppm: 75_000,
                sample_size: 100,
                runbook_hint: "Check WS-Security signature verification.",
            };
            channel.send_incident(&incident).expect("spool incident");
        }

        let downstream = RecordingAs4Channel::new(Some(1));
        let err = channel
            .drain_and_forward_with_checkpoint(&downstream, checkpoint_path.clone())
            .expect_err("forward must fail on second incident");
        assert_eq!(err.code, ErrorCode::ReliabilityFailure);

        let remaining = channel
            .replay_spooled_incidents()
            .expect("replay remaining incidents");
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].dedup_key, "as4:forward:tail:2");
        assert_eq!(remaining[1].dedup_key, "as4:forward:tail:3");

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&checkpoint_path);
        let _ = fs::remove_file(&ledger_path);
    }

    #[test]
    fn as2_file_spool_forward_skips_already_forwarded_dedup_keys_across_runs() {
        let path = unique_spool_path("as2-incident-forward-idempotent");
        let checkpoint_path = unique_checkpoint_path("as2-incident-forward-idempotent");
        let ledger_path = replay_idempotency_ledger_path(&checkpoint_path);
        let channel =
            As2ProviderHealthFileSpoolIncidentChannel::with_config(FileSpoolIncidentConfig {
                path: path.clone(),
                fsync_each_write: true,
                idempotency_ledger_policy: FileSpoolIdempotencyLedgerPolicy::default(),
            })
            .expect("construct as2 file spool channel");

        channel
            .send_incident(&as2_incident("as2:forward:idempotent:1"))
            .expect("spool first incident");
        let downstream_first = RecordingAs2Channel::new(None);
        let first_summary = channel
            .drain_and_forward_with_checkpoint(&downstream_first, checkpoint_path.clone())
            .expect("forward first run");
        assert_eq!(first_summary.checkpoint.forwarded_entries, 1);
        assert_eq!(first_summary.checkpoint.skipped_duplicate_entries, 0);

        channel
            .send_incident(&as2_incident("as2:forward:idempotent:1"))
            .expect("spool duplicate incident");
        let downstream_second = RecordingAs2Channel::new(None);
        let second_summary = channel
            .drain_and_forward_with_checkpoint(&downstream_second, checkpoint_path.clone())
            .expect("forward second run");
        assert_eq!(second_summary.checkpoint.forwarded_entries, 0);
        assert_eq!(second_summary.checkpoint.skipped_duplicate_entries, 1);
        assert_eq!(second_summary.checkpoint.requeued_entries, 0);

        let sent_first = downstream_first.sent.lock().expect("lock first sent list");
        assert_eq!(sent_first.len(), 1);
        let sent_second = downstream_second
            .sent
            .lock()
            .expect("lock second sent list");
        assert_eq!(sent_second.len(), 0);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&checkpoint_path);
        let _ = fs::remove_file(&ledger_path);
    }

    #[test]
    fn as2_file_spool_ledger_compacts_to_max_entries() {
        let path = unique_spool_path("as2-ledger-max-entries");
        let checkpoint_path = unique_checkpoint_path("as2-ledger-max-entries");
        let ledger_path = replay_idempotency_ledger_path(&checkpoint_path);
        let channel =
            As2ProviderHealthFileSpoolIncidentChannel::with_config(FileSpoolIncidentConfig {
                path: path.clone(),
                fsync_each_write: true,
                idempotency_ledger_policy: FileSpoolIdempotencyLedgerPolicy {
                    max_entries: 2,
                    retention_secs: 86_400,
                },
            })
            .expect("construct as2 file spool channel");

        for key in ["as2:ledger:max:1", "as2:ledger:max:2", "as2:ledger:max:3"] {
            channel
                .send_incident(&as2_incident(key))
                .expect("spool incident");
        }

        let downstream = RecordingAs2Channel::new(None);
        let summary = channel
            .drain_and_forward_with_checkpoint(&downstream, checkpoint_path.clone())
            .expect("forward incidents");
        assert_eq!(summary.checkpoint.forwarded_entries, 3);

        let ledger_contents = fs::read_to_string(&ledger_path).expect("read ledger file");
        let ledger: FileSpoolReplayLedgerFile =
            serde_json::from_str(&ledger_contents).expect("parse ledger json");
        assert_eq!(ledger.entries.len(), 2);

        let mut keys: Vec<String> = ledger.entries.into_iter().map(|e| e.dedup_key).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "as2:ledger:max:2".to_string(),
                "as2:ledger:max:3".to_string()
            ]
        );

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&checkpoint_path);
        let _ = fs::remove_file(&ledger_path);
    }

    #[test]
    fn as2_file_spool_ledger_retention_evicts_stale_dedup_keys() {
        let path = unique_spool_path("as2-ledger-retention");
        let checkpoint_path = unique_checkpoint_path("as2-ledger-retention");
        let ledger_path = replay_idempotency_ledger_path(&checkpoint_path);
        let channel =
            As2ProviderHealthFileSpoolIncidentChannel::with_config(FileSpoolIncidentConfig {
                path: path.clone(),
                fsync_each_write: true,
                idempotency_ledger_policy: FileSpoolIdempotencyLedgerPolicy {
                    max_entries: 100,
                    retention_secs: 1,
                },
            })
            .expect("construct as2 file spool channel");

        let stale_millis = now_unix_millis().saturating_sub(60_000);
        let stale_ledger =
            std::collections::HashMap::from([("as2:ledger:retention:1".to_string(), stale_millis)]);
        persist_replay_idempotency_ledger(&ledger_path, &stale_ledger)
            .expect("seed stale ledger entry");

        channel
            .send_incident(&as2_incident("as2:ledger:retention:1"))
            .expect("spool duplicate of stale key");

        let downstream = RecordingAs2Channel::new(None);
        let summary = channel
            .drain_and_forward_with_checkpoint(&downstream, checkpoint_path.clone())
            .expect("forward incident after retention compaction");
        assert_eq!(summary.checkpoint.forwarded_entries, 1);
        assert_eq!(summary.checkpoint.skipped_duplicate_entries, 0);

        let sent = downstream.sent.lock().expect("lock sent list");
        assert_eq!(sent.len(), 1);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&checkpoint_path);
        let _ = fs::remove_file(&ledger_path);
    }

    #[test]
    fn as2_file_spool_rejects_legacy_newline_ledger_format() {
        let path = unique_spool_path("as2-ledger-legacy-format");
        let checkpoint_path = unique_checkpoint_path("as2-ledger-legacy-format");
        let ledger_path = replay_idempotency_ledger_path(&checkpoint_path);
        let channel =
            As2ProviderHealthFileSpoolIncidentChannel::with_config(FileSpoolIncidentConfig {
                path: path.clone(),
                fsync_each_write: true,
                idempotency_ledger_policy: FileSpoolIdempotencyLedgerPolicy::default(),
            })
            .expect("construct as2 file spool channel");

        fs::write(&ledger_path, "as2:legacy:key-1\nas2:legacy:key-2\n")
            .expect("write legacy newline ledger");

        channel
            .send_incident(&as2_incident("as2:legacy:key-1"))
            .expect("spool incident");

        let downstream = RecordingAs2Channel::new(None);
        let err = channel
            .drain_and_forward_with_checkpoint(&downstream, checkpoint_path.clone())
            .expect_err("legacy newline ledger should fail to load");
        assert_eq!(err.code, ErrorCode::ReliabilityFailure);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&checkpoint_path);
        let _ = fs::remove_file(&ledger_path);
    }
}
