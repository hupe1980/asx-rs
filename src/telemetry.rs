//! The telemetry contract in code: span closing, the closing events and, with
//! the `metrics` feature, the counters and histograms.
//!
//! Every span and event uses target `asx`; names, fields, levels and metric
//! names are documented in `site/content/docs/observability.md` and checked
//! against what the suite emits (`tests/telemetry_contract.rs`,
//! `tests/metrics_contract.rs`). The library never installs a subscriber or a
//! recorder, and nothing here can fail an exchange.

#![cfg_attr(not(all(feature = "as2", feature = "as4")), allow(dead_code))]

use tokio::time::Instant;

use tracing::Span;
use tracing::field::Empty;

use crate::audit::AuditDurability;
use crate::core::{AsxError, ErrorCode, SessionContext};

/// The `asx.send` span: open around the call that settles a send's outcome.
pub(crate) fn send_span(
    protocol: &'static str,
    session: &SessionContext,
    message_id: &str,
) -> Span {
    tracing::info_span!(
        target: "asx",
        "asx.send",
        protocol,
        profile = session.profile_name(),
        partner = session.partner_id(),
        message_id,
        outcome = Empty,
        error.kind = Empty,
        ebms.code = Empty,
        duration_ms = Empty,
    )
}

/// The `asx.receive` span: open around a receive entry point.
pub(crate) fn receive_span(protocol: &'static str, session: &SessionContext) -> Span {
    tracing::info_span!(
        target: "asx",
        "asx.receive",
        protocol,
        profile = session.profile_name(),
        partner = session.partner_id(),
        message_id = Empty,
        outcome = Empty,
        error.kind = Empty,
        ebms.code = Empty,
        duplicate = Empty,
        duration_ms = Empty,
    )
}

/// Record `ok`/`failed` on a child span.
pub(crate) fn child_outcome<T, E>(span: &Span, result: &std::result::Result<T, E>) {
    span.record("outcome", if result.is_ok() { "ok" } else { "failed" });
}

/// The `asx.verify` span: the declared algorithm and the signer offered.
pub(crate) fn verify_span(algorithm: &str, signer_der: Option<&[u8]>) -> tracing::Span {
    let span = tracing::debug_span!(
        target: "asx",
        "asx.verify",
        algorithm,
        signer.fingerprint = tracing::field::Empty,
        outcome = tracing::field::Empty,
    );
    if let Some(der) = signer_der {
        span.record("signer.fingerprint", fingerprint(der).as_str());
    }
    span
}

/// The `asx.revocation` span for one certificate's check:
/// `method` (`crl`, `ocsp`), `source` (`cache`, `network`), `outcome` and
/// `reason` are recorded when it closes.
pub(crate) fn revocation_span(signer_der: Option<&[u8]>) -> Span {
    let span = tracing::debug_span!(
        target: "asx",
        "asx.revocation",
        method = Empty,
        source = Empty,
        signer.fingerprint = Empty,
        outcome = Empty,
        reason = Empty,
    );
    if let Some(der) = signer_der {
        span.record("signer.fingerprint", fingerprint(der).as_str());
    }
    span
}

/// Close `asx.revocation` with `good`, `revoked`, `unknown` or `error` and
/// an optional `reason` (`ca_distrusted`, `not_obtainable`, `no_source`,
/// `refresh_failing`); a revoked or unknown status is also a WARN event.
pub(crate) fn finish_revocation(
    span: &Span,
    method: &'static str,
    source: &'static str,
    outcome: &'static str,
    reason: Option<&'static str>,
) {
    span.record("method", method);
    span.record("source", source);
    span.record("outcome", outcome);
    if let Some(reason) = reason {
        span.record("reason", reason);
    }
    if matches!(outcome, "revoked" | "unknown") {
        span.in_scope(|| {
            tracing::warn!(target: "asx", outcome, "certificate revocation status");
        });
    }
    revocation_checked(method, outcome);
}

/// SHA-256 of a DER certificate, lowercase hex: the only certificate datum
/// telemetry carries.
pub(crate) fn fingerprint(der: &[u8]) -> String {
    crate::audit::sha256_hex(der)
}

/// The `error.kind` value (and `AuditRecord` `error_kind`) for an error: the
/// closed set `config`, `rejected`, `partner_error`, `transport`,
/// `indeterminate`, `storage` — the [`ErrorKind`](crate::ErrorKind) names.
pub(crate) fn error_kind(err: &AsxError) -> &'static str {
    error_kind_for(err.code)
}

pub(crate) fn error_kind_for(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::InvalidInput | ErrorCode::NotFound | ErrorCode::ReliabilityFailure => "config",
        ErrorCode::ParseFailed
        | ErrorCode::SecurityVerificationFailed
        | ErrorCode::DecryptionFailed
        | ErrorCode::PolicyViolation
        | ErrorCode::InteropViolation
        | ErrorCode::PayloadTooLarge
        | ErrorCode::CertificateRevoked
        | ErrorCode::CertificateExpired => "rejected",
        ErrorCode::TransportFailure | ErrorCode::Timeout => "transport",
        ErrorCode::CapacityExhausted => "indeterminate",
        ErrorCode::StorageBackendFailure => "storage",
    }
}

/// Outcome of an `asx.send` span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendOutcome {
    Delivered,
    PartnerError,
    Indeterminate,
    /// Failed before transmission: `config`, `transport` or `storage`.
    Failed(&'static str),
}

impl SendOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::PartnerError => "partner_error",
            Self::Indeterminate => "indeterminate",
            Self::Failed(kind) => kind,
        }
    }
}

/// Outcome of an `asx.receive` span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceiveOutcome {
    Accepted,
    Duplicate,
    InFlight,
    Rejected,
    Storage,
}

impl ReceiveOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Duplicate => "duplicate",
            Self::InFlight => "in_flight",
            Self::Rejected => "rejected",
            Self::Storage => "storage",
        }
    }
}

/// Record the late fields of an `asx.send` span, emit its one closing event
/// at the contracted level and, with `metrics`, count it.
pub(crate) fn finish_send(
    span: &tracing::Span,
    protocol: &'static str,
    outcome: SendOutcome,
    err: Option<&AsxError>,
    ebms_code: Option<&str>,
    started: Instant,
) {
    let duration = started.elapsed();
    let kind = err.map(error_kind).or(match outcome {
        SendOutcome::PartnerError => Some("partner_error"),
        SendOutcome::Indeterminate => Some("indeterminate"),
        _ => None,
    });
    span.record("outcome", outcome.as_str());
    span.record("duration_ms", duration.as_millis() as u64);
    if let Some(kind) = kind {
        span.record("error.kind", kind);
    }
    if let Some(code) = ebms_code {
        span.record("ebms.code", code);
    }
    match outcome {
        SendOutcome::Delivered => {
            span.in_scope(|| tracing::info!(target: "asx", "message sent"));
        }
        SendOutcome::PartnerError => {
            span.in_scope(|| tracing::warn!(target: "asx", { ebms.code = ebms_code.unwrap_or("") }, "partner returned an error"));
        }
        SendOutcome::Indeterminate => {
            span.in_scope(|| tracing::error!(target: "asx", { error.kind = kind.unwrap_or("indeterminate") }, "delivery indeterminate"));
        }
        SendOutcome::Failed(kind) => {
            span.in_scope(|| tracing::warn!(target: "asx", { error.kind = kind }, "send failed"));
        }
    }
    #[cfg(feature = "metrics")]
    metrics_impl::send(protocol, outcome.as_str(), duration);
    #[cfg(not(feature = "metrics"))]
    let _ = protocol;
}

/// Record the late fields of an `asx.receive` span, emit its one closing
/// event and, with `metrics`, count it.
pub(crate) fn finish_receive(
    span: &tracing::Span,
    protocol: &'static str,
    outcome: ReceiveOutcome,
    err: Option<&AsxError>,
    message_id: Option<&str>,
    started: Instant,
) {
    finish_receive_coded(span, protocol, outcome, err, None, message_id, started);
}

/// [`finish_receive`] with the eb:Error code the peer was answered with when
/// the error does not determine it (a handler refusal).
pub(crate) fn finish_receive_coded(
    span: &tracing::Span,
    protocol: &'static str,
    outcome: ReceiveOutcome,
    err: Option<&AsxError>,
    ebms_code: Option<&str>,
    message_id: Option<&str>,
    started: Instant,
) {
    let duration = started.elapsed();
    if let Some(id) = message_id {
        span.record("message_id", id);
    }
    span.record("outcome", outcome.as_str());
    span.record("duration_ms", duration.as_millis() as u64);
    match outcome {
        ReceiveOutcome::Accepted => {
            span.record("duplicate", false);
            span.in_scope(|| tracing::info!(target: "asx", "message received"));
        }
        ReceiveOutcome::Duplicate | ReceiveOutcome::InFlight => {
            span.record("duplicate", true);
            span.in_scope(|| tracing::info!(target: "asx", duplicate = true, "duplicate message"));
        }
        ReceiveOutcome::Rejected | ReceiveOutcome::Storage => {
            let kind = err.map(error_kind).unwrap_or("rejected");
            let code = ebms_code.or_else(|| err.map(ebms_code_for)).unwrap_or("");
            span.record("error.kind", kind);
            if !code.is_empty() {
                span.record("ebms.code", code);
            }
            span.in_scope(|| tracing::warn!(target: "asx", { error.kind = kind, ebms.code = code }, "message rejected"));
        }
    }
    #[cfg(feature = "metrics")]
    metrics_impl::receive(protocol, outcome.as_str(), duration);
    #[cfg(not(feature = "metrics"))]
    let _ = protocol;
}

/// The ebMS 3.0 §6.7 code an inbound rejection maps to (the code a
/// receiver returns in its `eb:Error`).
pub(crate) fn ebms_code_for(err: &AsxError) -> &'static str {
    match err.code {
        ErrorCode::SecurityVerificationFailed
        | ErrorCode::CertificateRevoked
        | ErrorCode::CertificateExpired => "EBMS:0101",
        ErrorCode::DecryptionFailed => "EBMS:0102",
        ErrorCode::ParseFailed | ErrorCode::InteropViolation => "EBMS:0009",
        ErrorCode::PolicyViolation => "EBMS:0010",
        ErrorCode::PayloadTooLarge => "EBMS:0303",
        _ => "EBMS:0004",
    }
}

/// A receipt or MDN verification ended (`asx_receipt_verifications_total`).
pub(crate) fn receipt_verified(protocol: &'static str, ok: bool, nrr: &'static str) {
    #[cfg(feature = "metrics")]
    metrics_impl::receipt(protocol, if ok { "ok" } else { "failed" }, nrr);
    #[cfg(not(feature = "metrics"))]
    let _ = (protocol, ok, nrr);
}

/// A revocation check ended (`asx_revocation_checks_total`).
pub(crate) fn revocation_checked(method: &'static str, outcome: &'static str) {
    #[cfg(feature = "metrics")]
    metrics_impl::revocation(method, outcome);
    #[cfg(not(feature = "metrics"))]
    let _ = (method, outcome);
}

/// A sink returned `Err` (`asx_audit_failures_total`).
pub(crate) fn audit_failed(durability: AuditDurability) {
    #[cfg(feature = "metrics")]
    metrics_impl::audit_failure(durability.as_str());
    #[cfg(not(feature = "metrics"))]
    let _ = durability;
}

#[cfg(feature = "metrics")]
mod metrics_impl {
    use std::sync::Once;
    use std::time::Duration;

    const SENT: &str = "asx_messages_sent_total";
    const RECEIVED: &str = "asx_messages_received_total";
    const RECEIPTS: &str = "asx_receipt_verifications_total";
    const REVOCATION: &str = "asx_revocation_checks_total";
    const AUDIT_FAILURES: &str = "asx_audit_failures_total";
    const SEND_SECONDS: &str = "asx_send_duration_seconds";
    const RECEIVE_SECONDS: &str = "asx_receive_duration_seconds";

    static DESCRIBE: Once = Once::new();

    fn describe() {
        DESCRIBE.call_once(|| {
            metrics::describe_counter!(SENT, "Outbound AS2/AS4 messages by outcome.");
            metrics::describe_counter!(RECEIVED, "Inbound AS2/AS4 messages by outcome.");
            metrics::describe_counter!(RECEIPTS, "Receipt and MDN verifications by outcome.");
            metrics::describe_counter!(REVOCATION, "Certificate revocation checks by outcome.");
            metrics::describe_counter!(AUDIT_FAILURES, "Audit records a sink failed to store.");
            metrics::describe_histogram!(
                SEND_SECONDS,
                metrics::Unit::Seconds,
                "Duration of an asx.send span."
            );
            metrics::describe_histogram!(
                RECEIVE_SECONDS,
                metrics::Unit::Seconds,
                "Duration of an asx.receive span."
            );
        });
    }

    pub(super) fn send(protocol: &'static str, outcome: &'static str, d: Duration) {
        describe();
        metrics::counter!(SENT, "protocol" => protocol, "outcome" => outcome).increment(1);
        metrics::histogram!(SEND_SECONDS, "protocol" => protocol, "outcome" => outcome)
            .record(d.as_secs_f64());
    }

    pub(super) fn receive(protocol: &'static str, outcome: &'static str, d: Duration) {
        describe();
        metrics::counter!(RECEIVED, "protocol" => protocol, "outcome" => outcome).increment(1);
        metrics::histogram!(RECEIVE_SECONDS, "protocol" => protocol, "outcome" => outcome)
            .record(d.as_secs_f64());
    }

    pub(super) fn receipt(protocol: &'static str, outcome: &'static str, nrr: &'static str) {
        describe();
        metrics::counter!(RECEIPTS, "protocol" => protocol, "outcome" => outcome, "nrr" => nrr)
            .increment(1);
    }

    pub(super) fn revocation(method: &'static str, outcome: &'static str) {
        describe();
        metrics::counter!(REVOCATION, "method" => method, "outcome" => outcome).increment(1);
    }

    pub(super) fn audit_failure(durability: &'static str) {
        describe();
        metrics::counter!(AUDIT_FAILURES, "durability" => durability).increment(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KINDS: [&str; 6] = [
        "config",
        "rejected",
        "partner_error",
        "transport",
        "indeterminate",
        "storage",
    ];

    #[test]
    fn every_error_code_maps_into_the_closed_kind_set() {
        // Exhaustive by construction: adding an ErrorCode without a row in
        // `error_kind_for` does not compile.
        for code in [
            ErrorCode::InvalidInput,
            ErrorCode::ParseFailed,
            ErrorCode::SecurityVerificationFailed,
            ErrorCode::DecryptionFailed,
            ErrorCode::PolicyViolation,
            ErrorCode::TransportFailure,
            ErrorCode::InteropViolation,
            ErrorCode::ReliabilityFailure,
            ErrorCode::NotFound,
            ErrorCode::CapacityExhausted,
            ErrorCode::PayloadTooLarge,
            ErrorCode::StorageBackendFailure,
            ErrorCode::CertificateRevoked,
            ErrorCode::CertificateExpired,
            ErrorCode::Timeout,
        ] {
            assert!(KINDS.contains(&error_kind_for(code)), "{code:?}");
        }
        assert_eq!(error_kind_for(ErrorCode::StorageBackendFailure), "storage");
        assert_eq!(
            error_kind_for(ErrorCode::SecurityVerificationFailed),
            "rejected"
        );
        assert_eq!(error_kind_for(ErrorCode::TransportFailure), "transport");
    }
}
