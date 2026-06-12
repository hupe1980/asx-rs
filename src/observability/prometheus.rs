use super::MetricsSink;
use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct MetricKey {
    name: &'static str,
    labels: Vec<(&'static str, String)>,
}

#[derive(Debug, Clone)]
struct HistogramSnapshot {
    cumulative_buckets: Vec<u64>,
    count: u64,
    sum: f64,
}

#[derive(Debug)]
struct HistogramState {
    /// Cumulative bucket counts in ascending `le` order.
    cumulative_buckets: Vec<u64>,
    count: u64,
    sum: f64,
}

impl HistogramState {
    fn new(bucket_count: usize) -> Self {
        Self {
            cumulative_buckets: vec![0; bucket_count],
            count: 0,
            sum: 0.0,
        }
    }

    fn observe(&mut self, value: f64, buckets: &[f64]) {
        if !value.is_finite() {
            return;
        }

        self.count = self.count.saturating_add(1);
        self.sum += value;

        if let Some(idx) = buckets.iter().position(|upper| value <= *upper) {
            for count in self.cumulative_buckets.iter_mut().skip(idx) {
                *count = count.saturating_add(1);
            }
        }
    }

    fn snapshot(&self) -> HistogramSnapshot {
        HistogramSnapshot {
            cumulative_buckets: self.cumulative_buckets.clone(),
            count: self.count,
            sum: self.sum,
        }
    }
}

/// In-process Prometheus/OpenMetrics text sink for [`MetricsSink`].
///
/// This sink keeps metrics in memory and renders them in Prometheus exposition
/// text format via [`render`][Self::render]. It is designed for direct
/// integration in ASX services that expose `/metrics` without requiring callers
/// to implement their own sink bridge.
#[derive(Debug)]
pub struct PrometheusMetricsSink {
    counters: DashMap<MetricKey, AtomicU64>,
    gauges: DashMap<MetricKey, Mutex<f64>>,
    histograms: DashMap<MetricKey, Mutex<HistogramState>>,
    histogram_buckets: Vec<f64>,
}

impl Default for PrometheusMetricsSink {
    fn default() -> Self {
        Self::new()
    }
}

impl PrometheusMetricsSink {
    /// Create a sink with default Prometheus-style latency buckets in seconds.
    #[must_use]
    pub fn new() -> Self {
        Self {
            counters: DashMap::new(),
            gauges: DashMap::new(),
            histograms: DashMap::new(),
            histogram_buckets: vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ],
        }
    }

    /// Override histogram buckets (`le`) used for all histogram metrics.
    #[must_use]
    pub fn with_histogram_buckets(mut self, mut buckets: Vec<f64>) -> Self {
        buckets.retain(|v| v.is_finite() && *v > 0.0);
        buckets.sort_by(f64::total_cmp);
        buckets.dedup_by(|a, b| a.total_cmp(b).is_eq());

        if !buckets.is_empty() {
            self.histogram_buckets = buckets;
        }

        self
    }

    /// Render current metrics in Prometheus/OpenMetrics text exposition format.
    pub fn render(&self) -> String {
        let mut out = String::new();

        let mut counter_names = BTreeSet::new();
        let mut gauge_names = BTreeSet::new();
        let mut histogram_names = BTreeSet::new();

        let mut counters = Vec::new();
        for entry in &self.counters {
            let key = entry.key().clone();
            let value = entry.value().load(Ordering::Relaxed);
            counter_names.insert(key.name);
            counters.push((key, value));
        }
        counters.sort_by(|(a, _), (b, _)| a.cmp(b));

        let mut gauges = Vec::new();
        for entry in &self.gauges {
            let key = entry.key().clone();
            let value = *entry.value().lock();
            gauge_names.insert(key.name);
            gauges.push((key, value));
        }
        gauges.sort_by(|(a, _), (b, _)| a.cmp(b));

        let mut histograms = Vec::new();
        for entry in &self.histograms {
            let key = entry.key().clone();
            let snapshot = entry.value().lock().snapshot();
            histogram_names.insert(key.name);
            histograms.push((key, snapshot));
        }
        histograms.sort_by(|(a, _), (b, _)| a.cmp(b));

        for name in counter_names {
            out.push_str("# HELP ");
            out.push_str(name);
            out.push_str(" Counter emitted by ASX runtime.\n");
            out.push_str("# TYPE ");
            out.push_str(name);
            out.push_str(" counter\n");
        }
        for (key, value) in counters {
            out.push_str(&format_metric_sample(key.name, &key.labels, value as f64));
        }

        for name in gauge_names {
            out.push_str("# HELP ");
            out.push_str(name);
            out.push_str(" Gauge emitted by ASX runtime.\n");
            out.push_str("# TYPE ");
            out.push_str(name);
            out.push_str(" gauge\n");
        }
        for (key, value) in gauges {
            out.push_str(&format_metric_sample(key.name, &key.labels, value));
        }

        for name in histogram_names {
            out.push_str("# HELP ");
            out.push_str(name);
            out.push_str(" Histogram emitted by ASX runtime.\n");
            out.push_str("# TYPE ");
            out.push_str(name);
            out.push_str(" histogram\n");
        }
        for (key, snapshot) in histograms {
            for (idx, upper) in self.histogram_buckets.iter().enumerate() {
                let mut labels = key.labels.clone();
                labels.push(("le", format_float(*upper)));
                out.push_str(&format_metric_sample(
                    &format!("{}_bucket", key.name),
                    &labels,
                    snapshot.cumulative_buckets[idx] as f64,
                ));
            }

            let mut inf_labels = key.labels.clone();
            inf_labels.push(("le", "+Inf".to_string()));
            out.push_str(&format_metric_sample(
                &format!("{}_bucket", key.name),
                &inf_labels,
                snapshot.count as f64,
            ));
            out.push_str(&format_metric_sample(
                &format!("{}_sum", key.name),
                &key.labels,
                snapshot.sum,
            ));
            out.push_str(&format_metric_sample(
                &format!("{}_count", key.name),
                &key.labels,
                snapshot.count as f64,
            ));
        }

        out
    }
}

impl MetricsSink for PrometheusMetricsSink {
    fn increment_counter(&self, name: &'static str, value: u64, labels: &[(&'static str, &str)]) {
        let key = metric_key(name, labels);
        self.counters
            .entry(key)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(value, Ordering::Relaxed);
    }

    fn record_histogram(&self, name: &'static str, value: f64, labels: &[(&'static str, &str)]) {
        let key = metric_key(name, labels);
        let buckets = &self.histogram_buckets;
        let bucket_count = buckets.len();
        let entry = self
            .histograms
            .entry(key)
            .or_insert_with(|| Mutex::new(HistogramState::new(bucket_count)));
        let mut guard = entry.value().lock();
        guard.observe(value, buckets);
    }

    fn set_gauge(&self, name: &'static str, value: f64, labels: &[(&'static str, &str)]) {
        if !value.is_finite() {
            return;
        }
        let key = metric_key(name, labels);
        *self
            .gauges
            .entry(key)
            .or_insert_with(|| Mutex::new(0.0))
            .value()
            .lock() = value;
    }
}

fn metric_key(name: &'static str, labels: &[(&'static str, &str)]) -> MetricKey {
    let mut normalized = BTreeMap::new();
    for (k, v) in labels {
        normalized.insert(*k, (*v).to_string());
    }

    MetricKey {
        name,
        labels: normalized.into_iter().collect(),
    }
}

fn format_metric_sample(name: &str, labels: &[(&'static str, String)], value: f64) -> String {
    let mut out = String::new();
    out.push_str(name);

    if !labels.is_empty() {
        out.push('{');
        for (idx, (k, v)) in labels.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            out.push_str(k);
            out.push_str("=\"");
            out.push_str(&escape_label_value(v));
            out.push('"');
        }
        out.push('}');
    }

    out.push(' ');
    out.push_str(&format_float(value));
    out.push('\n');
    out
}

fn escape_label_value(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

fn format_float(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value.is_sign_positive() {
            "+Inf".to_string()
        } else {
            "-Inf".to_string()
        };
    }

    let mut s = format!("{value:.12}");
    while s.contains('.') && s.ends_with('0') {
        s.pop();
    }
    if s.ends_with('.') {
        s.pop();
    }
    if s.is_empty() { "0".to_string() } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_sink_records_and_renders_counter_gauge_histogram() {
        let sink = PrometheusMetricsSink::new().with_histogram_buckets(vec![0.1, 1.0]);

        sink.increment_counter("asx_test_counter_total", 2, &[("partner_id", "p1")]);
        sink.increment_counter("asx_test_counter_total", 3, &[("partner_id", "p1")]);
        sink.set_gauge("asx_test_queue_depth", 7.0, &[("session", "s1")]);
        sink.record_histogram("asx_test_duration_seconds", 0.05, &[("partner_id", "p1")]);
        sink.record_histogram("asx_test_duration_seconds", 2.0, &[("partner_id", "p1")]);

        let rendered = sink.render();

        assert!(rendered.contains("# TYPE asx_test_counter_total counter"));
        assert!(rendered.contains("asx_test_counter_total{partner_id=\"p1\"} 5"));

        assert!(rendered.contains("# TYPE asx_test_queue_depth gauge"));
        assert!(rendered.contains("asx_test_queue_depth{session=\"s1\"} 7"));

        assert!(rendered.contains("# TYPE asx_test_duration_seconds histogram"));
        assert!(
            rendered.contains("asx_test_duration_seconds_bucket{partner_id=\"p1\",le=\"0.1\"} 1")
        );
        assert!(
            rendered.contains("asx_test_duration_seconds_bucket{partner_id=\"p1\",le=\"1\"} 1")
        );
        assert!(
            rendered.contains("asx_test_duration_seconds_bucket{partner_id=\"p1\",le=\"+Inf\"} 2")
        );
        assert!(rendered.contains("asx_test_duration_seconds_count{partner_id=\"p1\"} 2"));
        assert!(rendered.contains("asx_test_duration_seconds_sum{partner_id=\"p1\"} 2.05"));
    }

    #[test]
    fn prometheus_sink_normalizes_label_order() {
        let sink = PrometheusMetricsSink::new();
        sink.increment_counter("asx_label_order_total", 1, &[("b", "2"), ("a", "1")]);
        sink.increment_counter("asx_label_order_total", 1, &[("a", "1"), ("b", "2")]);

        let rendered = sink.render();
        assert!(rendered.contains("asx_label_order_total{a=\"1\",b=\"2\"} 2"));
    }
}
