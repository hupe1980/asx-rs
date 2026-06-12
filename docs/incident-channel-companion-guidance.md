# Incident Channel Companion Guidance

This guide documents the trait-first contract for shipping vendor-specific incident delivery adapters in a companion crate while keeping `asx-rs` core transport-agnostic.

## Scope

Core exports these adapter traits:

- `As4ReceiptTaxonomyIncidentChannel`
- `As2ProviderHealthIncidentChannel`

Core does not require any paging/webhook vendor SDK and should not gain vendor-specific transport dependencies.

## Companion Crate Pattern

Create a separate crate (example name: `asx-incident-paging`) that depends on `asx-rs` and the vendor SDK.

```rust
use asx_rs::core::Result;
use asx_rs::observability::{
    As2ProviderHealthAlertIncident,
    As2ProviderHealthIncidentChannel,
    As4ReceiptTaxonomyAlertIncident,
    As4ReceiptTaxonomyIncidentChannel,
};

#[derive(Debug, Clone)]
pub struct VendorPagingIncidentChannel {
    service: VendorPagingClient,
}

impl VendorPagingIncidentChannel {
    pub fn new(service: VendorPagingClient) -> Self {
        Self { service }
    }
}

impl As4ReceiptTaxonomyIncidentChannel for VendorPagingIncidentChannel {
    fn send_incident(&self, incident: &As4ReceiptTaxonomyAlertIncident) -> Result<()> {
        let event = VendorEvent {
            dedup_key: incident.dedup_key.clone(),
            summary: format!(
                "as4 receipt taxonomy {} {}",
                incident.severity.as_str(),
                incident.category.as_str()
            ),
            details: vec![
                ("signal".into(), incident.signal.into()),
                ("observed_rate_ppm".into(), incident.observed_rate_ppm.to_string()),
                ("sample_size".into(), incident.sample_size.to_string()),
                ("runbook_hint".into(), incident.runbook_hint.into()),
            ],
        };
        self.service.trigger(event)
    }
}

impl As2ProviderHealthIncidentChannel for VendorPagingIncidentChannel {
    fn send_incident(&self, incident: &As2ProviderHealthAlertIncident) -> Result<()> {
        let event = VendorEvent {
            dedup_key: incident.dedup_key.clone(),
            summary: format!(
                "as2 provider health {} {}",
                incident.severity.as_str(),
                incident.category.as_str()
            ),
            details: vec![
                ("signal".into(), incident.signal.into()),
                ("observed_rate_ppm".into(), incident.observed_rate_ppm.to_string()),
                ("sample_size".into(), incident.sample_size.to_string()),
                ("runbook_hint".into(), incident.runbook_hint.into()),
            ],
        };
        self.service.trigger(event)
    }
}
```

## Dedup Key Templates

Use deterministic, low-cardinality keys that preserve routing semantics and suppress duplicate pages.

### AS4 Receipt Taxonomy

Template:

```text
as4:receipt:{severity}:{category}:{signal}
```

Examples:

- `as4:receipt:critical:security_verification_failed:as4_receipt_taxonomy`
- `as4:receipt:warning:semantic_interop_failure:as4_receipt_taxonomy`

### AS2 Provider Health

Template:

```text
as2:provider-health:{severity}:{category}:{signal}
```

Examples:

- `as2:provider-health:critical:transition_to_failing_rate:as2_provider_health`
- `as2:provider-health:warning:transition_to_failing_rate:as2_provider_health`

## Operational Rules

- Keep incident channels best-effort and non-blocking.
- Preserve `dedup_key` exactly when mapping to a vendor API field.
- Emit channel transport failures to logs/metrics; do not panic.
- Use bounded queues and fail with `CapacityExhausted` on local saturation.
- Keep redaction in place; do not include key material, payload bodies, or secrets in incident payloads.

## Compatibility Contract

Companion adapters should treat these incident structs as the contract boundary:

- `As4ReceiptTaxonomyAlertIncident`
- `As2ProviderHealthAlertIncident`

Breaking change policy is explicit in this RFC cycle, so companion crates should pin a major `asx-rs` version and follow core changes intentionally.
