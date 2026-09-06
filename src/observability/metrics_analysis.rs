use std::sync::atomic::Ordering;

use super::{As2ProviderHealthSnapshot, As4ReceiptTaxonomySnapshot, EventBusMetrics};

impl EventBusMetrics {
    /// Receipts rejected because a cryptographic check failed.
    pub fn receipt_taxonomy_security_verification_failed(&self) -> u64 {
        self.receipt_taxonomy_security_verification_failed
            .load(Ordering::Relaxed)
    }

    /// Receipts rejected because the counterparty's shape or correlation was wrong.
    pub fn receipt_taxonomy_semantic_interop_failure(&self) -> u64 {
        self.receipt_taxonomy_semantic_interop_failure
            .load(Ordering::Relaxed)
    }

    /// Counter readout for the AS4 receipt-signal taxonomy.
    pub fn as4_receipt_taxonomy_snapshot(&self) -> As4ReceiptTaxonomySnapshot {
        As4ReceiptTaxonomySnapshot {
            security_verification_failed: self.receipt_taxonomy_security_verification_failed(),
            semantic_interop_failure: self.receipt_taxonomy_semantic_interop_failure(),
            total: self.receipt_taxonomy_total.load(Ordering::Relaxed),
        }
    }

    /// Counter readout for spool-key-provider health transitions.
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
}
