//! OpenTelemetry (OTLP) [`MetricsSink`] bridge.
//!
//! Connects the ASX [`MetricsSink`] trait to an OpenTelemetry
//! [`opentelemetry::metrics::Meter`], enabling metrics to be exported
//! via any configured OTLP exporter (Prometheus scrape, OTLP/gRPC,
//! OTLP/HTTP, cloud vendor SDKs, etc.).
//!
//! ## Usage
//!
//! ```rust,ignore
//! use opentelemetry::metrics::MeterProvider as _;
//! use opentelemetry_sdk::metrics::SdkMeterProvider;
//! use asx_rs::observability::OtelMetricsSink;
//!
//! // Configure your MeterProvider (here: the SDK default in-memory provider).
//! let provider = SdkMeterProvider::default();
//! let meter = provider.meter("asx");
//!
//! // Create the bridge.
//! let sink = Arc::new(OtelMetricsSink::new(meter));
//!
//! // Pass to EventBus builder.
//! EventBus::builder()
//!     .metrics_sink(sink)
//!     .build()?;
//! ```
//!
//! ## Label mapping
//!
//! ASX labels are `(&'static str, &str)` pairs.  They are converted to
//! `opentelemetry::KeyValue` on each observation.  High-cardinality labels
//! (e.g. per-message UUIDs) should be avoided; prefer per-partner or
//! per-action aggregation.
//!
//! ## Instrument caching
//!
//! Instruments (counters, histograms, gauges) are created lazily on first use
//! and cached in a [`DashMap`] keyed by metric name.  Repeated calls for the
//! same name reuse the same instrument instance, which is required by the
//! OpenTelemetry specification.
//!
//! ## `f64` gauge precision
//!
//! OpenTelemetry's `ObservableGauge` is asynchronous (pull-based).  For the
//! push-based [`MetricsSink::set_gauge`] interface, this bridge uses a
//! synchronous `Gauge` instrument (available since OTel API 0.24 as
//! `Meter::f64_gauge`).

use super::MetricsSink;
use dashmap::DashMap;
use opentelemetry_api::metrics::{Counter, Gauge, Histogram, Meter};
use opentelemetry_api::{KeyValue, StringValue};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Instrument caches
// ---------------------------------------------------------------------------

/// OpenTelemetry [`MetricsSink`] bridge.
///
/// See [module documentation](self) for usage and behaviour details.
#[derive(Clone, Debug)]
pub struct OtelMetricsSink {
    meter: Meter,
    counters: Arc<DashMap<&'static str, Counter<u64>>>,
    histograms: Arc<DashMap<&'static str, Histogram<f64>>>,
    gauges: Arc<DashMap<&'static str, Gauge<f64>>>,
}

impl OtelMetricsSink {
    /// Create a new bridge backed by the provided [`Meter`].
    ///
    /// The `meter` is typically obtained from a configured `MeterProvider`:
    ///
    /// ```rust,ignore
    /// let meter = provider.meter("asx");
    /// let sink = OtelMetricsSink::new(meter);
    /// ```
    pub fn new(meter: Meter) -> Self {
        Self {
            meter,
            counters: Arc::new(DashMap::new()),
            histograms: Arc::new(DashMap::new()),
            gauges: Arc::new(DashMap::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// Label conversion helper
// ---------------------------------------------------------------------------

#[inline]
fn to_kv(labels: &[(&'static str, &str)]) -> Vec<KeyValue> {
    labels
        .iter()
        .map(|(k, v)| KeyValue::new(*k, StringValue::from(v.to_string())))
        .collect()
}

// ---------------------------------------------------------------------------
// MetricsSink implementation
// ---------------------------------------------------------------------------

impl MetricsSink for OtelMetricsSink {
    fn increment_counter(&self, name: &'static str, value: u64, labels: &[(&'static str, &str)]) {
        let counter = self
            .counters
            .entry(name)
            .or_insert_with(|| self.meter.u64_counter(name).build())
            .clone();
        counter.add(value, &to_kv(labels));
    }

    fn record_histogram(&self, name: &'static str, value: f64, labels: &[(&'static str, &str)]) {
        let hist = self
            .histograms
            .entry(name)
            .or_insert_with(|| self.meter.f64_histogram(name).build())
            .clone();
        hist.record(value, &to_kv(labels));
    }

    fn set_gauge(&self, name: &'static str, value: f64, labels: &[(&'static str, &str)]) {
        let gauge = self
            .gauges
            .entry(name)
            .or_insert_with(|| self.meter.f64_gauge(name).build())
            .clone();
        gauge.record(value, &to_kv(labels));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_api::metrics::MeterProvider as _;
    use opentelemetry_sdk::metrics::SdkMeterProvider;

    fn make_sink() -> OtelMetricsSink {
        let provider = SdkMeterProvider::default();
        let meter = provider.meter("asx_test");
        OtelMetricsSink::new(meter)
    }

    #[test]
    fn counter_does_not_panic() {
        let sink = make_sink();
        sink.increment_counter("asx_test_messages_total", 1, &[("partner_id", "partner-a")]);
        sink.increment_counter("asx_test_messages_total", 5, &[("partner_id", "partner-a")]);
    }

    #[test]
    fn histogram_does_not_panic() {
        let sink = make_sink();
        sink.record_histogram(
            "asx_test_processing_duration_seconds",
            0.042,
            &[("action", "send")],
        );
    }

    #[test]
    fn gauge_does_not_panic() {
        let sink = make_sink();
        sink.set_gauge("asx_test_queue_depth", 7.0, &[("partner_id", "p2")]);
    }

    #[test]
    fn different_names_use_distinct_instruments() {
        let sink = make_sink();
        sink.increment_counter("asx_counter_a_total", 1, &[]);
        sink.increment_counter("asx_counter_b_total", 1, &[]);
        assert_eq!(sink.counters.len(), 2);
    }

    #[test]
    fn same_name_reuses_instrument() {
        let sink = make_sink();
        for _ in 0..5 {
            sink.increment_counter("asx_reuse_test_total", 1, &[]);
        }
        assert_eq!(sink.counters.len(), 1);
    }
}
