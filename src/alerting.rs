use std::sync::Arc;

use tokio::sync::watch;

use crate::core::{Result, SessionContext};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct As4ReceiptTaxonomySnapshot {
    pub security_verification_failed: u64,
    pub semantic_interop_failure: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct As2ProviderHealthSnapshot {
    pub transition_to_failing: u64,
    pub total_transitions: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum As4ReceiptTaxonomyAlertSeverity {
    Warning,
    Critical,
}

impl As4ReceiptTaxonomyAlertSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum As4ReceiptTaxonomyAlertCategory {
    SecurityVerificationFailed,
    SemanticInteropFailure,
}

impl As4ReceiptTaxonomyAlertCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecurityVerificationFailed => "security_verification_failed",
            Self::SemanticInteropFailure => "semantic_interop_failure",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As4ReceiptTaxonomyAlert {
    pub severity: As4ReceiptTaxonomyAlertSeverity,
    pub category: As4ReceiptTaxonomyAlertCategory,
    pub observed_rate_ppm: u64,
    pub warning_rate_ppm: u64,
    pub critical_rate_ppm: u64,
    pub sample_size: u64,
    pub runbook_hint: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As4ReceiptTaxonomyAlertIncident {
    pub dedup_key: String,
    pub signal: &'static str,
    pub severity: As4ReceiptTaxonomyAlertSeverity,
    pub category: As4ReceiptTaxonomyAlertCategory,
    pub observed_rate_ppm: u64,
    pub sample_size: u64,
    pub runbook_hint: &'static str,
}

pub trait As4ReceiptTaxonomyIncidentChannel: Send + Sync + std::fmt::Debug {
    fn send_incident(&self, incident: &As4ReceiptTaxonomyAlertIncident) -> Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum As2ProviderHealthAlertSeverity {
    Warning,
    Critical,
}

impl As2ProviderHealthAlertSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum As2ProviderHealthAlertCategory {
    TransitionToFailingRate,
}

impl As2ProviderHealthAlertCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TransitionToFailingRate => "transition_to_failing_rate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As2ProviderHealthAlert {
    pub severity: As2ProviderHealthAlertSeverity,
    pub category: As2ProviderHealthAlertCategory,
    pub observed_rate_ppm: u64,
    pub warning_rate_ppm: u64,
    pub critical_rate_ppm: u64,
    pub sample_size: u64,
    pub runbook_hint: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As2ProviderHealthAlertIncident {
    pub dedup_key: String,
    pub signal: &'static str,
    pub severity: As2ProviderHealthAlertSeverity,
    pub category: As2ProviderHealthAlertCategory,
    pub observed_rate_ppm: u64,
    pub sample_size: u64,
    pub runbook_hint: &'static str,
}

pub trait As2ProviderHealthIncidentChannel: Send + Sync + std::fmt::Debug {
    fn send_incident(&self, incident: &As2ProviderHealthAlertIncident) -> Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct As4ReceiptTaxonomyAlertPolicy {
    pub min_sample_size: u64,
    pub security_verification_failed_warning_rate_ppm: u64,
    pub security_verification_failed_critical_rate_ppm: u64,
    pub semantic_interop_failure_warning_rate_ppm: u64,
    pub semantic_interop_failure_critical_rate_ppm: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct As4ReceiptTaxonomyAlertDispatchPolicy {
    pub interval_secs: u64,
    pub dedup_cooldown_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct As2ProviderHealthAlertPolicy {
    pub min_sample_size: u64,
    pub warning_rate_ppm: u64,
    pub critical_rate_ppm: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct As2ProviderHealthAlertDispatchPolicy {
    pub interval_secs: u64,
    pub dedup_cooldown_secs: u64,
}

impl Default for As4ReceiptTaxonomyAlertDispatchPolicy {
    fn default() -> Self {
        Self {
            interval_secs: 60,
            dedup_cooldown_secs: 300,
        }
    }
}

impl Default for As4ReceiptTaxonomyAlertPolicy {
    fn default() -> Self {
        Self {
            min_sample_size: 100,
            security_verification_failed_warning_rate_ppm: 10_000,
            security_verification_failed_critical_rate_ppm: 50_000,
            semantic_interop_failure_warning_rate_ppm: 5_000,
            semantic_interop_failure_critical_rate_ppm: 20_000,
        }
    }
}

impl Default for As2ProviderHealthAlertPolicy {
    fn default() -> Self {
        Self {
            min_sample_size: 20,
            warning_rate_ppm: 10_000,
            critical_rate_ppm: 50_000,
        }
    }
}

impl Default for As2ProviderHealthAlertDispatchPolicy {
    fn default() -> Self {
        Self {
            interval_secs: 60,
            dedup_cooldown_secs: 300,
        }
    }
}

#[derive(Debug)]
pub struct As2ProviderHealthAlertSchedulerRequest {
    pub session: SessionContext,
    pub policy: As2ProviderHealthAlertPolicy,
    pub dispatch_policy: As2ProviderHealthAlertDispatchPolicy,
    pub channel_name: &'static str,
    pub channel: Arc<dyn As2ProviderHealthIncidentChannel>,
    pub fail_closed: bool,
    pub shutdown: watch::Receiver<bool>,
}

#[derive(Debug)]
pub struct As4ReceiptTaxonomyAlertSchedulerRequest {
    pub session: SessionContext,
    pub policy: As4ReceiptTaxonomyAlertPolicy,
    pub dispatch_policy: As4ReceiptTaxonomyAlertDispatchPolicy,
    pub channel_name: &'static str,
    pub channel: Arc<dyn As4ReceiptTaxonomyIncidentChannel>,
    pub fail_closed: bool,
    pub shutdown: watch::Receiver<bool>,
}
