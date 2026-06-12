use std::fmt;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::{
    mpsc::{self, error::TrySendError},
    watch,
};

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::observability::{
    As2ProviderHealthAlertIncident, As2ProviderHealthIncidentChannel,
    As4ReceiptTaxonomyAlertIncident, As4ReceiptTaxonomyIncidentChannel,
};

use super::{
    IncidentDeliveryConfig, IncidentDeliveryMetrics, IncidentDeliveryMetricsSnapshot,
    IncidentDeliveryPolicyBundle, IncidentQueueOverflowPolicy,
};

#[derive(Debug, Clone, Serialize)]
struct WebhookIncidentPayload {
    adapter: &'static str,
    protocol: &'static str,
    signal: &'static str,
    dedup_key: String,
    severity: &'static str,
    category: &'static str,
    observed_rate_ppm: u64,
    sample_size: u64,
    runbook_hint: &'static str,
}

trait IncidentHttpPayload: Serialize + Send + 'static + fmt::Debug {
    fn dedup_key(&self) -> &str;
}

impl IncidentHttpPayload for WebhookIncidentPayload {
    fn dedup_key(&self) -> &str {
        &self.dedup_key
    }
}

fn shared_incident_runtime() -> Result<&'static tokio::runtime::Runtime> {
    static RUNTIME: OnceLock<std::result::Result<tokio::runtime::Runtime, String>> =
        OnceLock::new();

    let runtime_result = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("asx-incident")
            .enable_all()
            .build()
            .map_err(|err| format!("failed to initialize shared incident runtime: {err}"))
    });

    match runtime_result {
        Ok(runtime) => Ok(runtime),
        Err(message) => Err(AsxError::new(
            ErrorCode::TransportFailure,
            message.clone(),
            ErrorContext::new("incident_delivery_runtime_init"),
        )),
    }
}

#[derive(Debug)]
struct IncidentHttpPublisher<P> {
    sender: Option<mpsc::Sender<P>>,
    worker_done: watch::Receiver<bool>,
    metrics: Arc<IncidentDeliveryMetrics>,
    adapter_name: &'static str,
    enqueue_backpressure_wait: Duration,
    queue_overflow: IncidentQueueOverflowPolicy,
    _marker: std::marker::PhantomData<P>,
}

impl<P> IncidentHttpPublisher<P>
where
    P: IncidentHttpPayload,
{
    fn new(
        endpoint: impl Into<String>,
        adapter_name: &'static str,
        config: IncidentDeliveryConfig,
    ) -> Result<Self> {
        let endpoint = endpoint.into();
        if endpoint.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "incident endpoint must not be empty",
                ErrorContext::new("incident_delivery_new"),
            ));
        }

        if config.queue_capacity == 0 {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "incident queue_capacity must be greater than zero",
                ErrorContext::new("incident_delivery_new"),
            ));
        }

        if config.request_timeout_secs == 0 {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "incident request_timeout_secs must be greater than zero",
                ErrorContext::new("incident_delivery_new"),
            ));
        }

        let queue_capacity = config.queue_capacity;
        let (sender, mut receiver) = mpsc::channel::<P>(queue_capacity);
        let (worker_done_tx, worker_done_rx) = watch::channel(false);
        let endpoint_arc: Arc<str> = Arc::from(endpoint.clone());
        let endpoint_for_worker = endpoint_arc.clone();
        let adapter_for_worker = adapter_name;
        let timeout_secs = config.request_timeout_secs;
        let enqueue_backpressure_wait =
            Duration::from_millis(config.enqueue_backpressure_wait_millis);
        let queue_overflow = config.queue_overflow;
        let metrics = Arc::new(IncidentDeliveryMetrics::new(queue_capacity));
        let metrics_for_worker = Arc::clone(&metrics);

        let runtime = shared_incident_runtime()?;
        runtime.spawn(async move {
            let client = match reqwest::Client::builder()
                .timeout(Duration::from_secs(timeout_secs))
                .user_agent(concat!(
                    env!("CARGO_PKG_NAME"),
                    "/",
                    env!("CARGO_PKG_VERSION")
                ))
                .build()
            {
                Ok(client) => client,
                Err(err) => {
                    tracing::error!(
                        adapter = adapter_for_worker,
                        endpoint = &*endpoint_for_worker,
                        error = %err,
                        "failed to build webhook client"
                    );
                    return;
                }
            };

            while let Some(payload) = receiver.recv().await {
                metrics_for_worker.record_dequeue();
                let endpoint = endpoint_for_worker.clone();
                let response = client.post(endpoint.as_ref()).json(&payload).send().await;

                match response {
                    Ok(resp) if resp.status().is_success() => {
                        tracing::debug!(
                            adapter = adapter_for_worker,
                            endpoint = &*endpoint_for_worker,
                            dedup_key = %payload.dedup_key(),
                            status = %resp.status(),
                            "incident delivered"
                        );
                    }
                    Ok(resp) => {
                        tracing::warn!(
                            adapter = adapter_for_worker,
                            endpoint = &*endpoint_for_worker,
                            dedup_key = %payload.dedup_key(),
                            status = %resp.status(),
                            "incident delivery returned non-success status"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            adapter = adapter_for_worker,
                            endpoint = &*endpoint_for_worker,
                            dedup_key = %payload.dedup_key(),
                            error = %err,
                            "incident delivery failed"
                        );
                    }
                }
            }

            let _ = worker_done_tx.send(true);
        });

        Ok(Self {
            sender: Some(sender),
            worker_done: worker_done_rx,
            metrics,
            adapter_name,
            enqueue_backpressure_wait,
            queue_overflow,
            _marker: std::marker::PhantomData,
        })
    }

    fn enqueue(&self, payload: P) -> Result<()> {
        let Some(sender) = self.sender.as_ref() else {
            return Err(AsxError::new(
                ErrorCode::TransportFailure,
                "incident delivery worker stopped",
                ErrorContext::new("incident_delivery_enqueue").with_message_id(self.adapter_name),
            ));
        };

        match sender.try_send(payload) {
            Ok(()) => {
                self.metrics.record_enqueue_accepted();
                Ok(())
            }
            Err(TrySendError::Full(payload)) => {
                let error_context = ErrorContext::new("incident_delivery_enqueue")
                    .with_message_id(self.adapter_name);
                match self.queue_overflow {
                    IncidentQueueOverflowPolicy::BestEffortDrop => {
                        self.metrics.record_enqueue_dropped();
                        tracing::warn!(
                            adapter = self.adapter_name,
                            dedup_key = %payload.dedup_key(),
                            "incident delivery queue full; dropping incident by policy"
                        );
                        Ok(())
                    }
                    IncidentQueueOverflowPolicy::FailClosed => {
                        if self.enqueue_backpressure_wait.is_zero() {
                            self.metrics.record_capacity_exhausted();
                            return Err(AsxError::new(
                                ErrorCode::CapacityExhausted,
                                "incident delivery queue is full",
                                error_context,
                            ));
                        }

                        let deadline = Instant::now() + self.enqueue_backpressure_wait;
                        let mut pending = payload;

                        loop {
                            match sender.try_send(pending) {
                                Ok(()) => {
                                    self.metrics.record_enqueue_accepted();
                                    return Ok(());
                                }
                                Err(TrySendError::Full(retry_payload)) => {
                                    if Instant::now() >= deadline {
                                        self.metrics.record_capacity_exhausted();
                                        return Err(AsxError::new(
                                            ErrorCode::CapacityExhausted,
                                            format!(
                                                "incident delivery queue stayed full for {}ms",
                                                self.enqueue_backpressure_wait.as_millis()
                                            ),
                                            error_context,
                                        ));
                                    }
                                    pending = retry_payload;
                                    std::thread::sleep(Duration::from_millis(1));
                                }
                                Err(TrySendError::Closed(_)) => {
                                    self.metrics.record_worker_stopped();
                                    return Err(AsxError::new(
                                        ErrorCode::TransportFailure,
                                        "incident delivery worker stopped",
                                        ErrorContext::new("incident_delivery_enqueue")
                                            .with_message_id(self.adapter_name),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            Err(TrySendError::Closed(_)) => {
                self.metrics.record_worker_stopped();
                Err(AsxError::new(
                    ErrorCode::TransportFailure,
                    "incident delivery worker stopped",
                    ErrorContext::new("incident_delivery_enqueue")
                        .with_message_id(self.adapter_name),
                ))
            }
        }
    }

    fn metrics_snapshot(&self) -> IncidentDeliveryMetricsSnapshot {
        self.metrics.snapshot()
    }

    fn shutdown(&mut self) {
        self.sender.take();
    }

    fn shutdown_and_drain(&mut self, timeout: Duration) -> Result<()> {
        self.shutdown();

        let mut worker_done = self.worker_done.clone();
        if *worker_done.borrow() {
            return Ok(());
        }

        let runtime = shared_incident_runtime()?;
        let drained = runtime.block_on(async move {
            tokio::time::timeout(timeout, async {
                loop {
                    if *worker_done.borrow_and_update() {
                        return;
                    }
                    if worker_done.changed().await.is_err() {
                        return;
                    }
                }
            })
            .await
        });

        match drained {
            Ok(()) => Ok(()),
            Err(_) => Err(AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!(
                    "incident delivery worker did not drain within {}ms",
                    timeout.as_millis()
                ),
                ErrorContext::new("incident_delivery_shutdown").with_message_id(self.adapter_name),
            )),
        }
    }
}

#[derive(Debug)]
pub struct As2ProviderHealthWebhookIncidentChannel {
    inner: IncidentHttpPublisher<WebhookIncidentPayload>,
}

impl As2ProviderHealthWebhookIncidentChannel {
    pub fn regulated(endpoint: impl Into<String>) -> Result<Self> {
        Self::with_policy(endpoint, IncidentDeliveryPolicyBundle::RegulatedLowLatency)
    }

    pub fn with_policy(
        endpoint: impl Into<String>,
        policy: IncidentDeliveryPolicyBundle,
    ) -> Result<Self> {
        Self::with_raw_config(endpoint, policy.into_config())
    }

    pub fn with_raw_config(
        endpoint: impl Into<String>,
        config: IncidentDeliveryConfig,
    ) -> Result<Self> {
        Ok(Self {
            inner: IncidentHttpPublisher::new(endpoint, "as2_provider_health_webhook", config)?,
        })
    }

    pub fn shutdown(&mut self) {
        self.inner.shutdown();
    }

    pub fn shutdown_and_drain(&mut self, timeout: Duration) -> Result<()> {
        self.inner.shutdown_and_drain(timeout)
    }

    pub fn metrics_snapshot(&self) -> IncidentDeliveryMetricsSnapshot {
        self.inner.metrics_snapshot()
    }
}

impl As2ProviderHealthIncidentChannel for As2ProviderHealthWebhookIncidentChannel {
    fn send_incident(&self, incident: &As2ProviderHealthAlertIncident) -> Result<()> {
        self.inner.enqueue(WebhookIncidentPayload {
            adapter: "as2_provider_health_webhook",
            protocol: "as2",
            signal: incident.signal,
            dedup_key: incident.dedup_key.clone(),
            severity: incident.severity.as_str(),
            category: incident.category.as_str(),
            observed_rate_ppm: incident.observed_rate_ppm,
            sample_size: incident.sample_size,
            runbook_hint: incident.runbook_hint,
        })
    }
}

#[derive(Debug)]
pub struct As4ReceiptTaxonomyWebhookIncidentChannel {
    inner: IncidentHttpPublisher<WebhookIncidentPayload>,
}

impl As4ReceiptTaxonomyWebhookIncidentChannel {
    pub fn regulated(endpoint: impl Into<String>) -> Result<Self> {
        Self::with_policy(endpoint, IncidentDeliveryPolicyBundle::RegulatedLowLatency)
    }

    pub fn with_policy(
        endpoint: impl Into<String>,
        policy: IncidentDeliveryPolicyBundle,
    ) -> Result<Self> {
        Self::with_raw_config(endpoint, policy.into_config())
    }

    pub fn with_raw_config(
        endpoint: impl Into<String>,
        config: IncidentDeliveryConfig,
    ) -> Result<Self> {
        Ok(Self {
            inner: IncidentHttpPublisher::new(endpoint, "as4_receipt_taxonomy_webhook", config)?,
        })
    }

    pub fn shutdown(&mut self) {
        self.inner.shutdown();
    }

    pub fn shutdown_and_drain(&mut self, timeout: Duration) -> Result<()> {
        self.inner.shutdown_and_drain(timeout)
    }

    pub fn metrics_snapshot(&self) -> IncidentDeliveryMetricsSnapshot {
        self.inner.metrics_snapshot()
    }
}

#[derive(Debug, Clone, Serialize)]
struct PagerDutyCustomDetails {
    dedup_key: String,
    protocol: &'static str,
    signal: &'static str,
    category: &'static str,
    observed_rate_ppm: u64,
    sample_size: u64,
    runbook_hint: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct PagerDutyIncidentPayload {
    summary: String,
    source: String,
    severity: &'static str,
    category: &'static str,
    custom_details: PagerDutyCustomDetails,
}

#[derive(Debug, Clone, Serialize)]
struct PagerDutyTriggerEvent {
    routing_key: String,
    event_action: &'static str,
    dedup_key: String,
    payload: PagerDutyIncidentPayload,
}

impl IncidentHttpPayload for PagerDutyTriggerEvent {
    fn dedup_key(&self) -> &str {
        &self.dedup_key
    }
}

#[derive(Debug)]
pub struct As2ProviderHealthPagingIncidentChannel {
    inner: IncidentHttpPublisher<PagerDutyTriggerEvent>,
    source: Arc<str>,
    routing_key: Arc<str>,
}

impl As2ProviderHealthPagingIncidentChannel {
    pub fn regulated(
        endpoint: impl Into<String>,
        routing_key: impl Into<String>,
        source: impl Into<String>,
    ) -> Result<Self> {
        Self::with_policy(
            endpoint,
            routing_key,
            source,
            IncidentDeliveryPolicyBundle::RegulatedLowLatency,
        )
    }

    pub fn with_policy(
        endpoint: impl Into<String>,
        routing_key: impl Into<String>,
        source: impl Into<String>,
        policy: IncidentDeliveryPolicyBundle,
    ) -> Result<Self> {
        Self::with_raw_config(endpoint, routing_key, source, policy.into_config())
    }

    pub fn with_raw_config(
        endpoint: impl Into<String>,
        routing_key: impl Into<String>,
        source: impl Into<String>,
        config: IncidentDeliveryConfig,
    ) -> Result<Self> {
        let routing_key = routing_key.into();
        if routing_key.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "paging routing key must not be empty",
                ErrorContext::new("incident_paging_new"),
            ));
        }
        let source = source.into();
        if source.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "paging source must not be empty",
                ErrorContext::new("incident_paging_new"),
            ));
        }

        Ok(Self {
            inner: IncidentHttpPublisher::new(endpoint, "as2_provider_health_paging", config)?,
            source: Arc::from(source),
            routing_key: Arc::from(routing_key),
        })
    }

    pub fn shutdown(&mut self) {
        self.inner.shutdown();
    }

    pub fn shutdown_and_drain(&mut self, timeout: Duration) -> Result<()> {
        self.inner.shutdown_and_drain(timeout)
    }

    pub fn metrics_snapshot(&self) -> IncidentDeliveryMetricsSnapshot {
        self.inner.metrics_snapshot()
    }
}

impl As2ProviderHealthIncidentChannel for As2ProviderHealthPagingIncidentChannel {
    fn send_incident(&self, incident: &As2ProviderHealthAlertIncident) -> Result<()> {
        self.inner.enqueue(PagerDutyTriggerEvent {
            routing_key: self.routing_key.as_ref().to_string(),
            event_action: "trigger",
            dedup_key: incident.dedup_key.clone(),
            payload: PagerDutyIncidentPayload {
                summary: format!(
                    "AS2 provider-health incident: {} {}",
                    incident.severity.as_str(),
                    incident.category.as_str()
                ),
                source: self.source.as_ref().to_string(),
                severity: incident.severity.as_str(),
                category: incident.category.as_str(),
                custom_details: PagerDutyCustomDetails {
                    dedup_key: incident.dedup_key.clone(),
                    protocol: "as2",
                    signal: incident.signal,
                    category: incident.category.as_str(),
                    observed_rate_ppm: incident.observed_rate_ppm,
                    sample_size: incident.sample_size,
                    runbook_hint: incident.runbook_hint,
                },
            },
        })
    }
}

#[derive(Debug)]
pub struct As4ReceiptTaxonomyPagingIncidentChannel {
    inner: IncidentHttpPublisher<PagerDutyTriggerEvent>,
    source: Arc<str>,
    routing_key: Arc<str>,
}

impl As4ReceiptTaxonomyPagingIncidentChannel {
    pub fn regulated(
        endpoint: impl Into<String>,
        routing_key: impl Into<String>,
        source: impl Into<String>,
    ) -> Result<Self> {
        Self::with_policy(
            endpoint,
            routing_key,
            source,
            IncidentDeliveryPolicyBundle::RegulatedLowLatency,
        )
    }

    pub fn with_policy(
        endpoint: impl Into<String>,
        routing_key: impl Into<String>,
        source: impl Into<String>,
        policy: IncidentDeliveryPolicyBundle,
    ) -> Result<Self> {
        Self::with_raw_config(endpoint, routing_key, source, policy.into_config())
    }

    pub fn with_raw_config(
        endpoint: impl Into<String>,
        routing_key: impl Into<String>,
        source: impl Into<String>,
        config: IncidentDeliveryConfig,
    ) -> Result<Self> {
        let routing_key = routing_key.into();
        if routing_key.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "paging routing key must not be empty",
                ErrorContext::new("incident_paging_new"),
            ));
        }
        let source = source.into();
        if source.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "paging source must not be empty",
                ErrorContext::new("incident_paging_new"),
            ));
        }

        Ok(Self {
            inner: IncidentHttpPublisher::new(endpoint, "as4_receipt_taxonomy_paging", config)?,
            source: Arc::from(source),
            routing_key: Arc::from(routing_key),
        })
    }

    pub fn shutdown(&mut self) {
        self.inner.shutdown();
    }

    pub fn shutdown_and_drain(&mut self, timeout: Duration) -> Result<()> {
        self.inner.shutdown_and_drain(timeout)
    }

    pub fn metrics_snapshot(&self) -> IncidentDeliveryMetricsSnapshot {
        self.inner.metrics_snapshot()
    }
}

impl As4ReceiptTaxonomyIncidentChannel for As4ReceiptTaxonomyPagingIncidentChannel {
    fn send_incident(&self, incident: &As4ReceiptTaxonomyAlertIncident) -> Result<()> {
        self.inner.enqueue(PagerDutyTriggerEvent {
            routing_key: self.routing_key.as_ref().to_string(),
            event_action: "trigger",
            dedup_key: incident.dedup_key.clone(),
            payload: PagerDutyIncidentPayload {
                summary: format!(
                    "AS4 receipt-taxonomy incident: {} {}",
                    incident.severity.as_str(),
                    incident.category.as_str()
                ),
                source: self.source.as_ref().to_string(),
                severity: incident.severity.as_str(),
                category: incident.category.as_str(),
                custom_details: PagerDutyCustomDetails {
                    dedup_key: incident.dedup_key.clone(),
                    protocol: "as4",
                    signal: incident.signal,
                    category: incident.category.as_str(),
                    observed_rate_ppm: incident.observed_rate_ppm,
                    sample_size: incident.sample_size,
                    runbook_hint: incident.runbook_hint,
                },
            },
        })
    }
}

impl As4ReceiptTaxonomyIncidentChannel for As4ReceiptTaxonomyWebhookIncidentChannel {
    fn send_incident(&self, incident: &As4ReceiptTaxonomyAlertIncident) -> Result<()> {
        self.inner.enqueue(WebhookIncidentPayload {
            adapter: "as4_receipt_taxonomy_webhook",
            protocol: "as4",
            signal: incident.signal,
            dedup_key: incident.dedup_key.clone(),
            severity: incident.severity.as_str(),
            category: incident.category.as_str(),
            observed_rate_ppm: incident.observed_rate_ppm,
            sample_size: incident.sample_size,
            runbook_hint: incident.runbook_hint,
        })
    }
}
