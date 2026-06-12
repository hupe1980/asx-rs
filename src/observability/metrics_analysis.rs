use std::sync::atomic::Ordering;

use super::{
    As2ProviderHealthAlert, As2ProviderHealthAlertCategory, As2ProviderHealthAlertPolicy,
    As2ProviderHealthAlertSeverity, As2ProviderHealthSnapshot, As4ReceiptTaxonomyAlert,
    As4ReceiptTaxonomyAlertCategory, As4ReceiptTaxonomyAlertPolicy,
    As4ReceiptTaxonomyAlertSeverity, As4ReceiptTaxonomySnapshot, EventBusMetrics,
};

impl EventBusMetrics {
    pub fn receipt_taxonomy_security_verification_failed(&self) -> u64 {
        self.receipt_taxonomy_security_verification_failed
            .load(Ordering::Relaxed)
    }

    pub fn receipt_taxonomy_semantic_interop_failure(&self) -> u64 {
        self.receipt_taxonomy_semantic_interop_failure
            .load(Ordering::Relaxed)
    }

    pub fn as4_receipt_taxonomy_snapshot(&self) -> As4ReceiptTaxonomySnapshot {
        let security_verification_failed = self.receipt_taxonomy_security_verification_failed();
        let semantic_interop_failure = self.receipt_taxonomy_semantic_interop_failure();
        let total = self.receipt_taxonomy_total.load(Ordering::Relaxed);
        As4ReceiptTaxonomySnapshot {
            security_verification_failed,
            semantic_interop_failure,
            total,
        }
    }

    pub fn as2_provider_health_snapshot(&self) -> As2ProviderHealthSnapshot {
        As2ProviderHealthSnapshot {
            transition_to_failing: self
                .provider_health_transition_to_failing
                .load(Ordering::Relaxed),
            total_transitions: self
                .provider_health_transition_total
                .load(Ordering::Relaxed),
        }
    }

    pub fn evaluate_as2_provider_health_alerts(
        &self,
        policy: &As2ProviderHealthAlertPolicy,
    ) -> Vec<As2ProviderHealthAlert> {
        let snapshot = self.as2_provider_health_snapshot();
        if snapshot.total_transitions < policy.min_sample_size {
            return Vec::new();
        }

        let degraded_rate_ppm =
            ppm_ratio(snapshot.transition_to_failing, snapshot.total_transitions);

        let Some(severity) = classify_provider_health_rate(
            degraded_rate_ppm,
            policy.warning_rate_ppm,
            policy.critical_rate_ppm,
        ) else {
            return Vec::new();
        };

        vec![As2ProviderHealthAlert {
            severity,
            category: As2ProviderHealthAlertCategory::TransitionToFailingRate,
            observed_rate_ppm: degraded_rate_ppm,
            warning_rate_ppm: policy.warning_rate_ppm,
            critical_rate_ppm: policy.critical_rate_ppm,
            sample_size: snapshot.total_transitions,
            runbook_hint: "verify key-provider backend dependency health, credentials/secrets freshness, and partner-specific provider drift",
        }]
    }

    pub fn evaluate_as4_receipt_taxonomy_alerts(
        &self,
        policy: &As4ReceiptTaxonomyAlertPolicy,
    ) -> Vec<As4ReceiptTaxonomyAlert> {
        let snapshot = self.as4_receipt_taxonomy_snapshot();
        if snapshot.total < policy.min_sample_size {
            return Vec::new();
        }

        let security_rate_ppm = ppm_ratio(snapshot.security_verification_failed, snapshot.total);
        let semantic_rate_ppm = ppm_ratio(snapshot.semantic_interop_failure, snapshot.total);

        let mut alerts = Vec::new();
        if let Some(severity) = classify_rate(
            security_rate_ppm,
            policy.security_verification_failed_warning_rate_ppm,
            policy.security_verification_failed_critical_rate_ppm,
        ) {
            alerts.push(As4ReceiptTaxonomyAlert {
                severity,
                category: As4ReceiptTaxonomyAlertCategory::SecurityVerificationFailed,
                observed_rate_ppm: security_rate_ppm,
                warning_rate_ppm: policy.security_verification_failed_warning_rate_ppm,
                critical_rate_ppm: policy.security_verification_failed_critical_rate_ppm,
                sample_size: snapshot.total,
                runbook_hint: "verify signer trust chain, signature transform parity, and cert rotation timeline",
            });
        }

        if let Some(severity) = classify_rate(
            semantic_rate_ppm,
            policy.semantic_interop_failure_warning_rate_ppm,
            policy.semantic_interop_failure_critical_rate_ppm,
        ) {
            alerts.push(As4ReceiptTaxonomyAlert {
                severity,
                category: As4ReceiptTaxonomyAlertCategory::SemanticInteropFailure,
                observed_rate_ppm: semantic_rate_ppm,
                warning_rate_ppm: policy.semantic_interop_failure_warning_rate_ppm,
                critical_rate_ppm: policy.semantic_interop_failure_critical_rate_ppm,
                sample_size: snapshot.total,
                runbook_hint: "verify RefToMessageId correlation, signal parser namespace handling, and partner profile drift",
            });
        }

        alerts.sort_by_key(|alert| match alert.severity {
            As4ReceiptTaxonomyAlertSeverity::Critical => 0,
            As4ReceiptTaxonomyAlertSeverity::Warning => 1,
        });
        alerts
    }
}

fn classify_rate(
    rate_ppm: u64,
    warning_ppm: u64,
    critical_ppm: u64,
) -> Option<As4ReceiptTaxonomyAlertSeverity> {
    if rate_ppm >= critical_ppm {
        return Some(As4ReceiptTaxonomyAlertSeverity::Critical);
    }
    if rate_ppm >= warning_ppm {
        return Some(As4ReceiptTaxonomyAlertSeverity::Warning);
    }
    None
}

fn classify_provider_health_rate(
    rate_ppm: u64,
    warning_ppm: u64,
    critical_ppm: u64,
) -> Option<As2ProviderHealthAlertSeverity> {
    if rate_ppm >= critical_ppm {
        return Some(As2ProviderHealthAlertSeverity::Critical);
    }
    if rate_ppm >= warning_ppm {
        return Some(As2ProviderHealthAlertSeverity::Warning);
    }
    None
}

fn ppm_ratio(count: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    ((count as u128 * 1_000_000u128) / total as u128) as u64
}
