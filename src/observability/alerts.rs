use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::watch;
use tokio::time::{MissedTickBehavior, interval};

use crate::alerting::{
    As2ProviderHealthAlert, As2ProviderHealthAlertDispatchPolicy, As2ProviderHealthAlertIncident,
    As2ProviderHealthAlertPolicy, As2ProviderHealthAlertSchedulerRequest,
    As2ProviderHealthIncidentChannel, As4ReceiptTaxonomyAlert,
    As4ReceiptTaxonomyAlertDispatchPolicy, As4ReceiptTaxonomyAlertIncident,
    As4ReceiptTaxonomyAlertPolicy, As4ReceiptTaxonomyAlertSchedulerRequest,
    As4ReceiptTaxonomyIncidentChannel,
};
use crate::core::{Result, SessionContext};

use super::{
    AS2_PROVIDER_HEALTH_INCIDENT_FORWARD_TOTAL, AS4_RECEIPT_TAXONOMY_INCIDENT_FORWARD_TOTAL,
    AsxEvent, EventBus, emit_audit_event,
};

impl EventBus {
    pub fn export_as4_receipt_taxonomy_alerts(
        &self,
        session: &SessionContext,
        policy: &As4ReceiptTaxonomyAlertPolicy,
        fail_closed: bool,
    ) -> Result<Vec<As4ReceiptTaxonomyAlert>> {
        let alerts = self.metrics.evaluate_as4_receipt_taxonomy_alerts(policy);
        for alert in &alerts {
            emit_audit_event(
                self,
                session,
                AsxEvent::ReceiptTaxonomyAlertRaised {
                    signal: "as4",
                    severity: alert.severity.as_str(),
                    category: alert.category.as_str(),
                    observed_rate_ppm: alert.observed_rate_ppm,
                    sample_size: alert.sample_size,
                },
                fail_closed,
                "as4_receipt_taxonomy_alert_export",
            )?;
        }
        Ok(alerts)
    }

    pub fn export_as4_receipt_taxonomy_alert_incidents(
        &self,
        session: &SessionContext,
        policy: &As4ReceiptTaxonomyAlertPolicy,
        dispatch_policy: &As4ReceiptTaxonomyAlertDispatchPolicy,
        fail_closed: bool,
    ) -> Result<Vec<As4ReceiptTaxonomyAlertIncident>> {
        let alerts = self.metrics.evaluate_as4_receipt_taxonomy_alerts(policy);
        let mut incidents = Vec::new();
        for alert in alerts {
            let dedup_key = format!(
                "as4:receipt-taxonomy:{}:{}",
                alert.severity.as_str(),
                alert.category.as_str()
            );
            if !self.should_dispatch_taxonomy_alert(&dedup_key, dispatch_policy.dedup_cooldown_secs)
            {
                continue;
            }
            emit_audit_event(
                self,
                session,
                AsxEvent::ReceiptTaxonomyAlertRaised {
                    signal: "as4",
                    severity: alert.severity.as_str(),
                    category: alert.category.as_str(),
                    observed_rate_ppm: alert.observed_rate_ppm,
                    sample_size: alert.sample_size,
                },
                fail_closed,
                "as4_receipt_taxonomy_alert_export",
            )?;
            incidents.push(As4ReceiptTaxonomyAlertIncident {
                dedup_key,
                signal: "as4",
                severity: alert.severity,
                category: alert.category,
                observed_rate_ppm: alert.observed_rate_ppm,
                sample_size: alert.sample_size,
                runbook_hint: alert.runbook_hint,
            });
        }
        Ok(incidents)
    }

    pub fn forward_as4_receipt_taxonomy_alerts(
        &self,
        session: &SessionContext,
        policy: &As4ReceiptTaxonomyAlertPolicy,
        dispatch_policy: &As4ReceiptTaxonomyAlertDispatchPolicy,
        channel_name: &'static str,
        channel: &dyn As4ReceiptTaxonomyIncidentChannel,
        fail_closed: bool,
    ) -> Result<Vec<As4ReceiptTaxonomyAlertIncident>> {
        let incidents = self.export_as4_receipt_taxonomy_alert_incidents(
            session,
            policy,
            dispatch_policy,
            fail_closed,
        )?;

        for incident in &incidents {
            match channel.send_incident(incident) {
                Ok(()) => {
                    self.metrics_sink.increment_counter(
                        AS4_RECEIPT_TAXONOMY_INCIDENT_FORWARD_TOTAL,
                        1,
                        &[
                            ("protocol", "as4"),
                            ("channel", channel_name),
                            ("severity", incident.severity.as_str()),
                            ("category", incident.category.as_str()),
                            ("result", "ok"),
                        ],
                    );
                }
                Err(err) => {
                    self.metrics_sink.increment_counter(
                        AS4_RECEIPT_TAXONOMY_INCIDENT_FORWARD_TOTAL,
                        1,
                        &[
                            ("protocol", "as4"),
                            ("channel", channel_name),
                            ("severity", incident.severity.as_str()),
                            ("category", incident.category.as_str()),
                            ("result", "error"),
                        ],
                    );
                    if fail_closed {
                        return Err(err);
                    }
                    tracing::warn!(
                        channel = channel_name,
                        dedup_key = %incident.dedup_key,
                        severity = incident.severity.as_str(),
                        category = incident.category.as_str(),
                        "taxonomy incident forward failed"
                    );
                }
            }
        }
        Ok(incidents)
    }

    pub fn export_as2_provider_health_alerts(
        &self,
        session: &SessionContext,
        policy: &As2ProviderHealthAlertPolicy,
        fail_closed: bool,
    ) -> Result<Vec<As2ProviderHealthAlert>> {
        let alerts = self.metrics.evaluate_as2_provider_health_alerts(policy);
        for alert in &alerts {
            emit_audit_event(
                self,
                session,
                AsxEvent::SpoolProviderHealthAlertRaised {
                    severity: alert.severity.as_str(),
                    category: alert.category.as_str(),
                    observed_rate_ppm: alert.observed_rate_ppm,
                    sample_size: alert.sample_size,
                },
                fail_closed,
                "as2_provider_health_alert_export",
            )?;
        }
        Ok(alerts)
    }

    pub fn export_as2_provider_health_alert_incidents(
        &self,
        session: &SessionContext,
        policy: &As2ProviderHealthAlertPolicy,
        dispatch_policy: &As2ProviderHealthAlertDispatchPolicy,
        fail_closed: bool,
    ) -> Result<Vec<As2ProviderHealthAlertIncident>> {
        let alerts = self.metrics.evaluate_as2_provider_health_alerts(policy);
        let mut incidents = Vec::new();
        for alert in alerts {
            let dedup_key = format!(
                "as2:provider-health:{}:{}",
                alert.severity.as_str(),
                alert.category.as_str()
            );
            if !self.should_dispatch_taxonomy_alert(&dedup_key, dispatch_policy.dedup_cooldown_secs)
            {
                continue;
            }
            emit_audit_event(
                self,
                session,
                AsxEvent::SpoolProviderHealthAlertRaised {
                    severity: alert.severity.as_str(),
                    category: alert.category.as_str(),
                    observed_rate_ppm: alert.observed_rate_ppm,
                    sample_size: alert.sample_size,
                },
                fail_closed,
                "as2_provider_health_alert_export",
            )?;
            incidents.push(As2ProviderHealthAlertIncident {
                dedup_key,
                signal: "as2",
                severity: alert.severity,
                category: alert.category,
                observed_rate_ppm: alert.observed_rate_ppm,
                sample_size: alert.sample_size,
                runbook_hint: alert.runbook_hint,
            });
        }

        Ok(incidents)
    }

    pub fn forward_as2_provider_health_alerts(
        &self,
        session: &SessionContext,
        policy: &As2ProviderHealthAlertPolicy,
        dispatch_policy: &As2ProviderHealthAlertDispatchPolicy,
        channel_name: &'static str,
        channel: &dyn As2ProviderHealthIncidentChannel,
        fail_closed: bool,
    ) -> Result<Vec<As2ProviderHealthAlertIncident>> {
        let incidents = self.export_as2_provider_health_alert_incidents(
            session,
            policy,
            dispatch_policy,
            fail_closed,
        )?;

        for incident in &incidents {
            match channel.send_incident(incident) {
                Ok(()) => {
                    self.metrics_sink.increment_counter(
                        AS2_PROVIDER_HEALTH_INCIDENT_FORWARD_TOTAL,
                        1,
                        &[
                            ("protocol", "as2"),
                            ("channel", channel_name),
                            ("severity", incident.severity.as_str()),
                            ("category", incident.category.as_str()),
                            ("result", "ok"),
                        ],
                    );
                }
                Err(err) => {
                    self.metrics_sink.increment_counter(
                        AS2_PROVIDER_HEALTH_INCIDENT_FORWARD_TOTAL,
                        1,
                        &[
                            ("protocol", "as2"),
                            ("channel", channel_name),
                            ("severity", incident.severity.as_str()),
                            ("category", incident.category.as_str()),
                            ("result", "error"),
                        ],
                    );
                    if fail_closed {
                        return Err(err);
                    }
                    tracing::warn!(
                        channel = channel_name,
                        dedup_key = %incident.dedup_key,
                        severity = incident.severity.as_str(),
                        category = incident.category.as_str(),
                        "provider-health incident forward failed"
                    );
                }
            }
        }

        Ok(incidents)
    }

    pub async fn run_as2_provider_health_alert_scheduler(
        &self,
        request: As2ProviderHealthAlertSchedulerRequest,
    ) -> Result<()> {
        let As2ProviderHealthAlertSchedulerRequest {
            session,
            policy,
            dispatch_policy,
            channel_name,
            channel,
            fail_closed,
            shutdown,
        } = request;

        run_alert_scheduler_loop(
            shutdown,
            dispatch_policy.interval_secs,
            fail_closed,
            || {
                self.forward_as2_provider_health_alerts(
                    &session,
                    &policy,
                    &dispatch_policy,
                    channel_name,
                    channel.as_ref(),
                    fail_closed,
                )
                .map(|_| ())
            },
            "provider-health alert scheduler iteration failed",
        )
        .await
    }

    pub async fn run_as4_receipt_taxonomy_alert_scheduler(
        &self,
        request: As4ReceiptTaxonomyAlertSchedulerRequest,
    ) -> Result<()> {
        let As4ReceiptTaxonomyAlertSchedulerRequest {
            session,
            policy,
            dispatch_policy,
            channel_name,
            channel,
            fail_closed,
            shutdown,
        } = request;

        run_alert_scheduler_loop(
            shutdown,
            dispatch_policy.interval_secs,
            fail_closed,
            || {
                self.forward_as4_receipt_taxonomy_alerts(
                    &session,
                    &policy,
                    &dispatch_policy,
                    channel_name,
                    channel.as_ref(),
                    fail_closed,
                )
                .map(|_| ())
            },
            "taxonomy alert scheduler iteration failed",
        )
        .await
    }

    fn should_dispatch_taxonomy_alert(&self, dedup_key: &str, cooldown_secs: u64) -> bool {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        match self
            .taxonomy_alert_dedup_epoch_secs
            .entry(dedup_key.to_string())
        {
            dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                let last = *occupied.get();
                if cooldown_secs > 0 && now_secs.saturating_sub(last) < cooldown_secs {
                    return false;
                }
                occupied.insert(now_secs);
                true
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(now_secs);
                true
            }
        }
    }
}

async fn run_alert_scheduler_loop<F>(
    mut shutdown: watch::Receiver<bool>,
    interval_secs: u64,
    fail_closed: bool,
    mut on_tick: F,
    tick_failure_log_message: &'static str,
) -> Result<()>
where
    F: FnMut() -> Result<()>,
{
    let mut ticker = interval(std::time::Duration::from_secs(interval_secs.max(1)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Err(err) = on_tick() {
                    if fail_closed {
                        return Err(err);
                    }
                    tracing::warn!("{}", tick_failure_log_message);
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }

    Ok(())
}
