use std::sync::atomic::Ordering;

use super::{
    AS2_PROVIDER_HEALTH_ALERT_TOTAL, AS4_RECEIPT_TAXONOMY_ALERT_TOTAL,
    AS4_RECEIPT_TAXONOMY_OUTCOME_TOTAL, AsxEvent, EventBusMetrics, MetricsSink,
};

pub(super) fn observe_event(metrics: &EventBusMetrics, event: &AsxEvent, sink: &dyn MetricsSink) {
    if let AsxEvent::ReceiptTaxonomyOutcome {
        signal,
        outcome,
        detail,
        ..
    } = event
    {
        metrics
            .receipt_taxonomy_total
            .fetch_add(1, Ordering::Relaxed);
        sink.increment_counter(
            AS4_RECEIPT_TAXONOMY_OUTCOME_TOTAL,
            1,
            &[
                ("protocol", "as4"),
                ("signal", *signal),
                ("outcome", *outcome),
                ("detail", *detail),
            ],
        );
        match *outcome {
            "security_verification_failed" => {
                metrics
                    .receipt_taxonomy_security_verification_failed
                    .fetch_add(1, Ordering::Relaxed);
            }
            "semantic_interop_failure" => {
                metrics
                    .receipt_taxonomy_semantic_interop_failure
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    if let AsxEvent::ReceiptTaxonomyAlertRaised {
        signal,
        severity,
        category,
        ..
    } = event
    {
        sink.increment_counter(
            AS4_RECEIPT_TAXONOMY_ALERT_TOTAL,
            1,
            &[
                ("protocol", "as4"),
                ("signal", *signal),
                ("severity", *severity),
                ("category", *category),
            ],
        );
    }

    if let AsxEvent::SpoolKeyProviderHealthStateChanged { current_state, .. } = event {
        metrics
            .provider_health_transition_total
            .fetch_add(1, Ordering::Relaxed);
        if *current_state == "failing" {
            metrics
                .provider_health_transition_to_failing
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    if let AsxEvent::SpoolProviderHealthAlertRaised {
        severity, category, ..
    } = event
    {
        sink.increment_counter(
            AS2_PROVIDER_HEALTH_ALERT_TOTAL,
            1,
            &[
                ("protocol", "as2"),
                ("severity", *severity),
                ("category", *category),
            ],
        );
    }
}
