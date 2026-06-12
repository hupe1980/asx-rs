//! Canonical Prometheus-style metric names emitted by the ASX runtime.
//!
//! Use these constants when registering or querying metrics in dashboards,
//! alerting rules, and tests to avoid typo-drift between the library and
//! downstream consumers.
//!
//! All metrics follow the `asx_<subsystem>_<name>_<unit>` naming convention.
//! Units that lack a natural SI base (e.g. totals/counters) omit the unit
//! suffix and use `_total` per OpenMetrics conventions.

// ── AS2 ──────────────────────────────────────────────────────────────────────

/// Histogram: end-to-end latency of an AS2 outbound send (seconds).
pub const METRIC_AS2_SEND_DURATION_SECONDS: &str = "asx_as2_send_duration_seconds";

/// Histogram: end-to-end latency of an AS2 inbound receive (seconds).
pub const METRIC_AS2_RECEIVE_DURATION_SECONDS: &str = "asx_as2_receive_duration_seconds";

/// Counter: number of AS2 messages sent, labelled by `partner_id` and
/// `mic_algorithm` (`sha-256`, `sha-384`, `sha-512`, `sha-1`).
pub const METRIC_AS2_SEND_TOTAL: &str = "asx_as2_send_total";

/// Counter: MIC algorithm distribution on outbound AS2 messages.
/// Labels: `algorithm`.
pub const METRIC_AS2_MIC_ALGORITHM_TOTAL: &str = "asx_as2_mic_algorithm_total";

/// Counter: AS2 MDN outcomes.  Labels: `status` (`processed`, `failed`,
/// `warning`, `unknown`), `partner_id`.
pub const METRIC_AS2_MDN_OUTCOME_TOTAL: &str = "asx_as2_mdn_outcome_total";

// ── AS4 ──────────────────────────────────────────────────────────────────────

/// Histogram: end-to-end latency of an AS4 outbound push (seconds).
pub const METRIC_AS4_SEND_DURATION_SECONDS: &str = "asx_as4_send_duration_seconds";

/// Histogram: end-to-end latency of an AS4 inbound push receive (seconds).
pub const METRIC_AS4_RECEIVE_DURATION_SECONDS: &str = "asx_as4_receive_duration_seconds";

/// Counter: AS4 pull-request attempts.  Labels: `mpc`, `outcome`
/// (`hit`, `miss`, `error`).
pub const METRIC_AS4_PULL_ATTEMPT_TOTAL: &str = "asx_as4_pull_attempt_total";

// ── Reliability / deduplication ───────────────────────────────────────────────

/// Counter: deduplication cache hits (duplicate message suppressed).
/// Labels: `protocol` (`as2`, `as4`), `partner_id`.
pub const METRIC_DEDUP_HIT_TOTAL: &str = "asx_dedup_hit_total";

/// Counter: deduplication cache misses (message accepted as novel).
/// Labels: `protocol`, `partner_id`.
pub const METRIC_DEDUP_MISS_TOTAL: &str = "asx_dedup_miss_total";

// ── Per-partner throughput ────────────────────────────────────────────────────

/// Counter: total message bytes transferred per partner.
/// Labels: `partner_id`, `direction` (`inbound`, `outbound`),
/// `protocol` (`as2`, `as4`).
pub const METRIC_PARTNER_BYTES_TOTAL: &str = "asx_partner_bytes_total";

/// Counter: total messages processed per partner.
/// Labels: `partner_id`, `direction`, `protocol`.
pub const METRIC_PARTNER_MESSAGE_TOTAL: &str = "asx_partner_message_total";

// ── Crypto / security ─────────────────────────────────────────────────────────

/// Counter: OCSP check outcomes.  Labels: `outcome`
/// (`good`, `revoked`, `unknown`, `error`, `cache_hit`).
pub const METRIC_OCSP_CHECK_TOTAL: &str = "asx_ocsp_check_total";

/// Histogram: OCSP responder round-trip latency (seconds).
pub const METRIC_OCSP_RESPONDER_DURATION_SECONDS: &str = "asx_ocsp_responder_duration_seconds";

// ── Incident channels ─────────────────────────────────────────────────────────

/// Counter: incident events emitted per channel.
/// Labels: `channel_id`, `severity` (`low`, `medium`, `high`, `critical`).
pub const METRIC_INCIDENT_EVENT_TOTAL: &str = "asx_incident_event_total";
