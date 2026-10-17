+++
title = "Observability"
description = "Tracing spans and events, optional metrics, and the audit records of every exchange."
+++

Three observability seams; none can change what happens to a message:

- **`tracing`**: every send, receive, signature, decryption, receipt, MDN, SMP lookup, revocation check and audit write runs in a documented span.
- **`metrics`** (feature `metrics`): seven counters and histograms through the [`metrics`](https://docs.rs/metrics) facade.
- **[`AuditSink`](#audit-records)**: one evidence record per exchange leg.

The library never installs a subscriber or recorder and reads no environment variable. With nothing installed, spans cost a disabled-callsite check and metric macros are no-ops. Only an audit sink declared `Durable` can fail an exchange.

The tables below are a public contract, checked both ways against what the test suite emits (`tests/telemetry_contract.rs`, `tests/metrics_contract.rs`); changes are recorded in `CHANGELOG.md`.

## Wiring it up

The application installs a subscriber and a recorder, for example:

```toml
[dependencies]
asx-rs = { version = "0.16", features = ["metrics"] }
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
metrics-exporter-prometheus = "0.17"
```

```text
// in the application's main, once:
tracing_subscriber::fmt().json().with_env_filter("info,asx=info").init(); // asx=debug for the child spans
metrics_exporter_prometheus::PrometheusBuilder::new().install()?;
```

For OpenTelemetry, add `tracing-opentelemetry` as a layer: `asx.*` spans become OpenTelemetry spans under the caller's span (for example `tower-http`'s `TraceLayer`). The library propagates no `traceparent` header.

## Tracing

### Target

Every span and event uses the target `asx`: filter with `RUST_LOG=asx=info` (`asx=debug` for the child spans).

### Spans

Values learned during the operation (`outcome`, `error.kind`, `ebms.code`, `duplicate`, `duration_ms`, …) are recorded before the span closes; a field that does not apply stays empty.

| Span | Level | Fields |
|---|---|---|
| `asx.send` | INFO | `protocol`, `profile`, `partner`, `message_id`, `outcome`, `error.kind`, `ebms.code`, `duration_ms` |
| `asx.receive` | INFO | `protocol`, `profile`, `partner`, `message_id`, `outcome`, `error.kind`, `ebms.code`, `duplicate`, `duration_ms` |
| `asx.sign` | DEBUG | `algorithm`, `reference_count` |
| `asx.verify` | DEBUG | `algorithm`, `signer.fingerprint`, `outcome` |
| `asx.encrypt` | DEBUG | `algorithm`, `key_transport` |
| `asx.decrypt` | DEBUG | `algorithm`, `outcome` |
| `asx.receipt` | DEBUG | `message_id`, `signed`, `nrr`, `outcome` |
| `asx.mdn` | DEBUG | `message_id`, `disposition`, `signed`, `outcome` |
| `asx.smp_lookup` | DEBUG | `participant_scheme`, `document_type`, `transport_profile`, `outcome` |
| `asx.revocation` | DEBUG | `method`, `source`, `signer.fingerprint`, `outcome`, `reason` |
| `asx.audit` | DEBUG | `record_id`, `durability`, `outcome` |

- **`asx.send`** covers one `As4::send`, `As2::send`, `As2::send_async_mdn` or `As2::verify_async_mdn` call, including the verification of the receipt or MDN.
- **`asx.receive`** covers one request handled by an `Inbound`, from the first byte read to the response, the handler call included.
- Child spans nest under whichever of the two is current, also on the crypto pool.
- **`asx.mdn`** covers the verification of one MDN, synchronous or asynchronous, inside `asx.send`; `disposition` is the disposition type and modifier class (`processed`, `processed/warning`, `processed/error`, `failed`), never the partner's text; `signed` whether it was signed.
- **`asx.revocation`** covers the check of one non-anchor certificate of a verified signer's path, top-down, after the signature and the sender rule. `method` is the source that decided (`crl` when the certificate names no source), `source` whether the data came from the cache or the network.

Field values: identifiers verbatim; `signer.fingerprint` is the lowercase hex SHA-256 of the DER certificate, the only certificate datum recorded; `participant_scheme` and `document_type` carry identifier **schemes**, never a participant value; `duration_ms` is an integer.

Never recorded: payload or wire bytes, filenames from a message, private keys, secrets, HTTP header values other than `Content-Type`, certificate subject or issuer names.

### Values

| Field | Span | Values |
|---|---|---|
| `protocol` | `asx.send`, `asx.receive` | `as2`, `as4` |
| `outcome` | `asx.send` | `delivered`, `sent`, `partner_error`, `indeterminate`, `config`, `transport`, `storage` |
| `outcome` | `asx.receive` | `accepted`, `duplicate`, `in_flight`, `pending`, `rejected`, `storage` |
| `outcome` | `asx.verify`, `asx.decrypt`, `asx.receipt`, `asx.mdn`, `asx.smp_lookup`, `asx.audit` | `ok`, `failed` |
| `outcome` | `asx.revocation` | `good`, `revoked`, `unknown`, `error` |
| `error.kind` | `asx.send`, `asx.receive` | `config`, `rejected`, `partner_error`, `transport`, `indeterminate`, `storage` |
| `nrr` | `asx.receipt` | `verified`, `absent`, `mismatch`, `n/a` |
| `method` | `asx.revocation` | `ocsp`, `crl` |
| `source` | `asx.revocation` | `cache`, `network` |
| `reason` | `asx.revocation` | `ca_distrusted`, `not_obtainable`, `no_source`, `refresh_failing` |
| `durability` | `asx.audit` | `durable`, `best_effort` |

`ebms.code` is an ebMS 3.0 §6.7 error code (`EBMS:0001` … `EBMS:0303`). `error.kind` names an `ErrorKind` (`storage` is `ErrorKind::Backend`) and is also an audit record's `error_kind`. The receive outcome `pending` and the closing event `fragment received` are reserved and not emitted.

### Closing events

Every `asx.send` and `asx.receive` span ends with exactly one event inside it.

| Span | Condition | Level | Message |
|---|---|---|---|
| `asx.send` | delivered, or sent awaiting an asynchronous MDN | INFO | `message sent` |
| `asx.send` | the partner answered with an `eb:Error` or a negative MDN | WARN | `partner returned an error` |
| `asx.send` | transmitted, no verifiable receipt | ERROR | `delivery indeterminate` |
| `asx.send` | failed before or during transmission (`config`, `transport`, `storage`) | WARN | `send failed` |
| `asx.receive` | accepted | INFO | `message received` |
| `asx.receive` | a fragment of an incomplete group was stored | INFO | `fragment received` |
| `asx.receive` | duplicate or in flight | INFO | `duplicate message` |
| `asx.receive` | rejected, before or after authentication | WARN | `message rejected` |

Other events:

- an audit sink's failure: ERROR `audit record not written` (fields `record_id`, `message_id`, `signal.sha256`, `durability`) inside `asx.audit`;
- revocation status `revoked` or `unknown`: WARN `certificate revocation status` (field `outcome`) inside `asx.revocation`;
- a CA distrusted under the BDEW three-day rule: WARN `issuing CA distrusted`, and a CRL whose refresh keeps failing: WARN `CRL refresh failing`, both with fields `ca.fingerprint` (SHA-256 of the CA certificate), `since` (the last successful fetch, the passed `nextUpdate` or the first failed refresh, RFC 3339) and `reason`;
- everything else is DEBUG.

## Metrics

Feature `metrics`. Descriptions and units are registered on first emission. Label values come from the closed sets above; no label carries a partner, participant, message or certificate identifier.

| Name | Type | Labels |
|---|---|---|
| `asx_messages_sent_total` | counter | `protocol`, `outcome` |
| `asx_messages_received_total` | counter | `protocol`, `outcome` |
| `asx_receipt_verifications_total` | counter | `protocol`, `outcome`, `nrr` |
| `asx_revocation_checks_total` | counter | `method`, `outcome` |
| `asx_audit_failures_total` | counter | `durability` |
| `asx_send_duration_seconds` | histogram | `protocol`, `outcome` |
| `asx_receive_duration_seconds` | histogram | `protocol`, `outcome` |

- `asx_messages_*` and the duration histograms: when `asx.send` / `asx.receive` close, with the span's `outcome`.
- `asx_receipt_verifications_total`: when the verification of an AS4 receipt or an AS2 MDN ends (`outcome` `ok`/`failed`).
- `asx_revocation_checks_total`: when `asx.revocation` closes.
- `asx_audit_failures_total`: when a sink returns `Err`.

There is no `profile` label; the preset name is the span field `profile`.

## Audit records

Install an [`AuditSink`](https://docs.rs/asx-rs/latest/asx/trait.AuditSink.html) per client with `Builder::audit`; without one nothing is stored, but the record is still returned by `Verified::evidence()` and `Error::evidence()`. Implementing a sink, and what a sink failure means, is on the [persistence page](@/docs/persistence.md#the-audit-sink).

### When a record is written

| Leg | Direction / outcome | `signal` |
|---|---|---|
| AS4 send, receipt verified | outbound / `delivered` | the receipt as received |
| AS4 send, `eb:Error` received | outbound / `partner_error` | the error signal |
| AS4 send, response unverifiable | outbound / `indeterminate` | the response bytes, if any |
| AS2 send (or `verify_async_mdn`) answered by an MDN | outbound / `delivered`, `partner_error` or `indeterminate` | the MDN |
| AS4 or AS2 receive, handler returned `Ok` | inbound / `accepted` | the receipt or MDN issued for it |
| Duplicate, in flight, or refused (before or after authentication) | — | no record |

A record is written **before** an inbound dedup claim is accepted and before a verified receipt or MDN is returned to you.

### The stored form

`AuditRecord` is opaque; a sink stores its serde form. Bytes are standard base64 with padding, digests lowercase hex, `recorded_at` RFC 3339 UTC with three fractional digits, absent values `null`, enums snake_case; unknown fields are ignored on read, so newer records still load. Index accessors: `record_id()` (UUIDv7, the idempotency key), `message_id()`, `partner()`, `signal()`.

```json
{
  "record_id": "01929d3e-6a1b-7c3e-9f00-3b5c2e4d1a77",
  "recorded_at": "2026-10-16T09:30:12.345Z",
  "protocol": "as4", "direction": "outbound", "outcome": "delivered",
  "message_id": "c2a1f6e0-…@sender.example", "ref_to_message_id": null,
  "conversation_id": "conv-1", "local_party": "9900000000001", "partner": "9900000000002",
  "profile": "bdew", "service": "…", "action": "…",
  "message_timestamp": "2026-10-16T09:30:11.902Z",
  "signer": { "certificate_der": "MIIB…", "fingerprint_sha256": "3f1c…" },
  "references": [ { "uri": "#body", "digest_algorithm": "http://www.w3.org/2001/04/xmlenc#sha256", "digest": "q1w2…" } ],
  "mic": null,
  "signal": {
    "bytes": "PD94bWwg…", "sha256": "9a8b…", "message_id": "receipt-7@partner.example",
    "ref_to_message_id": "c2a1f6e0-…@sender.example", "timestamp": "2026-10-16T09:30:12.201Z",
    "signed": true, "nrr": [ { "uri": "#body", "digest_algorithm": "…", "digest": "q1w2…" } ]
  },
  "disposition": "receipt", "error_kind": null, "ebms_code": null, "quirks": []
}
```

`tests/fixtures/audit/record-as4-delivered.json` and `record-as2-mdn.json` pin this form. `quirks` lists every [partner quirk](@/docs/profiles.md#partners-and-quirks) the leg relied on.

### Check your sink before production

`asx::testkit::audit::conformance` checks the `durability()` claim through fresh handles to the same store.

```rust,no_run
use asx::{AuditRecord, BoxFuture};
use asx::testkit::audit::{conformance, AuditSinkHarness, MemoryAuditSink};

/// Opens handles to the store under test. `MemoryAuditSink` stands in for
/// yours: its clones share one store, as connections to a database do.
struct Harness(MemoryAuditSink);

impl AuditSinkHarness for Harness {
    type Sink = MemoryAuditSink;
    fn open(&self) -> BoxFuture<'_, MemoryAuditSink> {
        Box::pin(async move { self.0.clone() })
    }
    fn read_all<'a>(&'a self, sink: &'a MemoryAuditSink) -> BoxFuture<'a, Vec<AuditRecord>> {
        Box::pin(async move { sink.records() })
    }
}

#[tokio::main]
async fn main() {
    let failures = conformance(&Harness(MemoryAuditSink::new())).await;
    assert!(failures.is_empty(), "{failures:#?}");
}
```

| Check | Fails a sink that … |
|---|---|
| `audit.declares_durable` | declares `BestEffort` (nothing else runs) |
| `audit.recorded_is_readable` | acknowledges a record that its own handle cannot read |
| `audit.records_survive_a_fresh_handle` | keeps records per handle |
| `audit.every_field_round_trips` | loses or alters a field of `sample_records()` |
| `audit.bytes_round_trip_exactly` | alters non-UTF-8 bytes (a 1 MiB signal included) |
| `audit.record_is_idempotent_by_id` | stores a retried record twice |
| `audit.distinct_ids_are_distinct_records` | merges records that share a `message_id` |
| `audit.concurrent_records_all_land` | loses records under 64 concurrent writes over 8 handles |
