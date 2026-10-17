//! Evidence of each exchange leg: one [`AuditRecord`] per receipt, MDN or
//! authenticated inbound message, handed to the embedder's [`AuditSink`].
//!
//! The record is the non-repudiation evidence a regulated access point keeps:
//! who signed, which digests were signed, the receipt or MDN exactly as it
//! arrived (or as it was issued), the MIC and the disposition. It is opaque:
//! the library alone builds it, and its serde form — fixed by the stored-data
//! contract in `site/content/docs/observability.md` — is how a sink persists
//! it. The accessors cover the keys a store indexes on.
//!
//! Records are written **before** the caller can settle an inbound dedup claim
//! and before a verified receipt or MDN is returned on send. A sink that
//! declares [`AuditDurability::Durable`] fails the exchange when it fails; a
//! [`AuditDurability::BestEffort`] sink's failure is logged and counted.
//! Nothing is recorded for a message whose sender did not authenticate.
//!
//! The sink is set with `Builder::audit`; without one nothing is recorded.
//!
//! ```
//! use asx::{AuditDurability, AuditRecord, AuditSink, BoxFuture};
//!
//! #[derive(Debug)]
//! struct LogSink;
//!
//! impl AuditSink for LogSink {
//!     fn durability(&self) -> AuditDurability {
//!         AuditDurability::BestEffort
//!     }
//!     fn record<'a>(
//!         &'a self,
//!         record: &'a AuditRecord,
//!     ) -> BoxFuture<'a, Result<(), Box<dyn std::error::Error + Send + Sync>>> {
//!         println!("{} {}", record.record_id(), record.message_id());
//!         Box::pin(std::future::ready(Ok(())))
//!     }
//! }
//! ```

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::error::BoxFuture;

/// Where evidence of each exchange leg is kept.
///
/// The library calls [`record`](Self::record) once per leg. Implementations
/// must be idempotent on [`AuditRecord::record_id`] (a retried write must not
/// store a second copy) and must not call back into the library. There is no
/// read, replay or acknowledge method: querying the store is the embedder's.
///
/// Check an implementation with the conformance suite in `asx-rs-testkit`
/// (`asx_testkit::audit::conformance`) before relying on it.
pub trait AuditSink: Send + Sync + fmt::Debug {
    /// `Durable`: a record whose `record` returned `Ok` survives process and
    /// host failure, and an `Err` fails the exchange. `BestEffort`: errors are
    /// logged and counted, and the exchange continues.
    fn durability(&self) -> AuditDurability;

    /// Store `record`. Awaited inline: a slow durable sink slows the exchange.
    fn record<'a>(
        &'a self,
        record: &'a AuditRecord,
    ) -> BoxFuture<'a, std::result::Result<(), Box<dyn StdError + Send + Sync>>>;
}

impl<T: AuditSink + ?Sized> AuditSink for Arc<T> {
    fn durability(&self) -> AuditDurability {
        (**self).durability()
    }

    fn record<'a>(
        &'a self,
        record: &'a AuditRecord,
    ) -> BoxFuture<'a, std::result::Result<(), Box<dyn StdError + Send + Sync>>> {
        (**self).record(record)
    }
}

/// What a sink promises about a record it acknowledged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditDurability {
    /// Survives process and host failure; a failed write fails the exchange.
    Durable,
    /// May lose records; a failed write is logged and counted only.
    BestEffort,
}

impl AuditDurability {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Durable => "durable",
            Self::BestEffort => "best_effort",
        }
    }
}

/// One exchange leg's evidence.
///
/// Opaque: the library alone builds it. `Serialize`/`Deserialize` produce and
/// read the stored-data contract (byte fields standard padded base64, digests
/// lowercase hex, `recorded_at` RFC 3339 UTC with milliseconds, `null` for an
/// absent value, unknown fields ignored on read), which is how an embedder
/// persists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuditRecord {
    record_id: String,
    #[serde(with = "rfc3339_millis")]
    recorded_at: SystemTime,
    protocol: Protocol,
    direction: Direction,
    outcome: AuditOutcome,
    message_id: String,
    ref_to_message_id: Option<String>,
    conversation_id: Option<String>,
    local_party: String,
    partner: String,
    profile: Option<String>,
    service: Option<String>,
    action: Option<String>,
    message_timestamp: Option<String>,
    signer: Option<SignerEvidence>,
    #[serde(default)]
    references: Vec<ReferenceDigest>,
    mic: Option<Mic>,
    signal: Option<SignalEvidence>,
    disposition: Option<String>,
    error_kind: Option<String>,
    ebms_code: Option<String>,
    #[serde(default)]
    quirks: Vec<String>,
}

impl AuditRecord {
    /// Lowercase hyphenated UUIDv7; the sink's primary and idempotency key.
    pub fn record_id(&self) -> &str {
        &self.record_id
    }

    /// The user message's `eb:MessageId` / AS2 `Message-ID`.
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    /// The counterparty's id as configured on the session.
    pub fn partner(&self) -> &str {
        &self.partner
    }

    /// The receipt, MDN or `eb:Error` exactly as on the wire, if this leg has one.
    pub fn signal(&self) -> Option<&[u8]> {
        self.signal.as_ref().map(|s| s.bytes.as_slice())
    }

    /// The verified signer's certificate, DER.
    #[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(dead_code))]
    pub(crate) fn signer_certificate_der(&self) -> Option<&[u8]> {
        self.signer.as_ref().map(|s| s.certificate_der.as_slice())
    }

    /// The quirks applied on this leg and the preset name.
    #[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(dead_code))]
    pub(crate) fn stamp_profile(&mut self, profile: &str, quirks: Vec<String>) {
        self.profile = Some(profile.to_string());
        self.quirks = quirks;
    }

    pub(crate) fn signal_sha256(&self) -> Option<&str> {
        self.signal.as_ref().map(|s| s.sha256.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SignerEvidence {
    #[serde(with = "b64")]
    certificate_der: Vec<u8>,
    fingerprint_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReferenceDigest {
    uri: String,
    digest_algorithm: String,
    #[serde(with = "b64")]
    digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Mic {
    algorithm: String,
    #[serde(with = "b64")]
    value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SignalEvidence {
    #[serde(with = "b64")]
    bytes: Vec<u8>,
    sha256: String,
    message_id: Option<String>,
    ref_to_message_id: Option<String>,
    timestamp: Option<String>,
    signed: bool,
    #[serde(default)]
    nrr: Vec<ReferenceDigest>,
}

/// The fate of one exchange leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub(crate) enum AuditOutcome {
    /// Async MDN requested, not yet received.
    Sent,
    /// Receipt/MDN verified, positive.
    Delivered,
    /// The counterparty returned an ebMS error or a negative MDN.
    PartnerError,
    /// Transmitted; no verifiable receipt.
    Indeterminate,
    /// Inbound, receipt issued (or to be issued by the caller).
    Accepted,
    /// Inbound, a retransmission of an accepted message.
    Duplicate,
    /// Inbound, authenticated, refused.
    Rejected,
}

impl AuditOutcome {
    fn requires_error_kind(self) -> bool {
        matches!(
            self,
            Self::PartnerError | Self::Indeterminate | Self::Rejected
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Protocol {
    As2,
    As4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Direction {
    Outbound,
    Inbound,
}

// ── Building ────────────────────────────────────────────────────────────────

/// Assembles a record from pipeline state and enforces its invariants.
#[derive(Debug, Clone)]
pub(crate) struct RecordBuilder {
    rec: AuditRecord,
    /// `recorded_at` and the UUIDv7 time are read from it at `finish`.
    clock: crate::clock::SharedClock,
}

#[cfg_attr(not(all(feature = "as2", feature = "as4")), allow(dead_code))]
impl RecordBuilder {
    pub(crate) fn new(
        clock: &crate::clock::SharedClock,
        protocol: Protocol,
        direction: Direction,
        message_id: impl Into<String>,
        local_party: impl Into<String>,
        partner: impl Into<String>,
    ) -> Self {
        Self {
            clock: clock.clone(),
            rec: AuditRecord {
                record_id: String::new(),
                recorded_at: UNIX_EPOCH,
                protocol,
                direction,
                outcome: AuditOutcome::Accepted,
                message_id: message_id.into(),
                ref_to_message_id: None,
                conversation_id: None,
                local_party: local_party.into(),
                partner: partner.into(),
                profile: None,
                service: None,
                action: None,
                message_timestamp: None,
                signer: None,
                references: Vec::new(),
                mic: None,
                signal: None,
                disposition: None,
                error_kind: None,
                ebms_code: None,
                quirks: Vec::new(),
            },
        }
    }

    pub(crate) fn ref_to_message_id(mut self, value: Option<&str>) -> Self {
        self.rec.ref_to_message_id = value.map(str::to_owned);
        self
    }

    pub(crate) fn conversation_id(mut self, value: Option<&str>) -> Self {
        self.rec.conversation_id = value.map(str::to_owned);
        self
    }

    pub(crate) fn profile(mut self, value: Option<&str>) -> Self {
        self.rec.profile = value.map(str::to_owned);
        self
    }

    pub(crate) fn service_action(mut self, service: Option<&str>, action: Option<&str>) -> Self {
        self.rec.service = service.map(str::to_owned);
        self.rec.action = action.map(str::to_owned);
        self
    }

    pub(crate) fn message_timestamp(mut self, value: Option<&str>) -> Self {
        self.rec.message_timestamp = value.map(str::to_owned);
        self
    }

    /// The counterparty certificate that verified; the fingerprint is computed.
    pub(crate) fn signer_der(mut self, certificate_der: Option<Vec<u8>>) -> Self {
        self.rec.signer = certificate_der.map(|der| SignerEvidence {
            fingerprint_sha256: sha256_hex(&der),
            certificate_der: der,
        });
        self
    }

    /// `(uri, digest algorithm URI, base64 digest)` as in `ds:Reference`.
    /// A digest that is not base64 is kept as its text bytes rather than lost.
    pub(crate) fn references<'a>(
        mut self,
        references: impl IntoIterator<Item = (&'a str, &'a str, &'a str)>,
    ) -> Self {
        self.rec.references = reference_digests(references);
        self
    }

    pub(crate) fn mic(mut self, algorithm: &str, value: Vec<u8>) -> Self {
        self.rec.mic = Some(Mic {
            algorithm: algorithm.to_owned(),
            value,
        });
        self
    }

    pub(crate) fn signal(mut self, signal: Signal<'_>) -> Self {
        self.rec.signal = Some(SignalEvidence {
            sha256: sha256_hex(signal.bytes),
            bytes: signal.bytes.to_vec(),
            message_id: signal.message_id.map(str::to_owned),
            ref_to_message_id: signal.ref_to_message_id.map(str::to_owned),
            timestamp: signal.timestamp.map(str::to_owned),
            signed: signal.signed,
            nrr: reference_digests(signal.nrr.iter().copied()),
        });
        self
    }

    pub(crate) fn disposition(mut self, value: Option<&str>) -> Self {
        self.rec.disposition = value.map(str::to_owned);
        self
    }

    pub(crate) fn ebms_code(mut self, value: Option<&str>) -> Self {
        self.rec.ebms_code = value.map(str::to_owned);
        self
    }

    /// Stamp identity and time, set the outcome, and check the invariants:
    /// a signal acknowledges this record's message, and `error_kind` is present
    /// exactly when the outcome is a failure.
    pub(crate) fn finish(
        mut self,
        outcome: AuditOutcome,
        error_kind: Option<&'static str>,
    ) -> Result<AuditRecord> {
        let invalid = |detail: String| {
            AsxError::new(
                ErrorCode::InvalidInput,
                format!("invalid audit record: {detail}"),
                ErrorContext::new("audit_record_build"),
            )
        };
        if outcome.requires_error_kind() != error_kind.is_some() {
            return Err(invalid(format!(
                "outcome {outcome:?} with error_kind {error_kind:?}"
            )));
        }
        if let Some(signal) = &self.rec.signal
            && let Some(ref_to) = signal.ref_to_message_id.as_deref()
            && bare_id(ref_to) != bare_id(&self.rec.message_id)
        {
            return Err(invalid(format!(
                "signal acknowledges {ref_to:?}, record is for {:?}",
                self.rec.message_id
            )));
        }
        self.rec.outcome = outcome;
        self.rec.error_kind = error_kind.map(str::to_owned);
        let now = self.clock.now();
        self.rec.record_id = new_record_id(now)?;
        self.rec.recorded_at = millis(now);
        Ok(self.rec)
    }
}

/// A receipt, MDN or error signal for [`RecordBuilder::signal`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct Signal<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) message_id: Option<&'a str>,
    pub(crate) ref_to_message_id: Option<&'a str>,
    pub(crate) timestamp: Option<&'a str>,
    pub(crate) signed: bool,
    pub(crate) nrr: &'a [(&'a str, &'a str, &'a str)],
}

fn reference_digests<'a>(
    references: impl IntoIterator<Item = (&'a str, &'a str, &'a str)>,
) -> Vec<ReferenceDigest> {
    use base64::Engine as _;
    references
        .into_iter()
        .map(|(uri, algorithm, digest_b64)| ReferenceDigest {
            uri: uri.to_owned(),
            digest_algorithm: algorithm.to_owned(),
            digest: base64::engine::general_purpose::STANDARD
                .decode(digest_b64.trim())
                .unwrap_or_else(|_| digest_b64.as_bytes().to_vec()),
        })
        .collect()
}

/// A message id without the angle brackets AS2 headers carry.
fn bare_id(id: &str) -> &str {
    let id = id.trim();
    let id = id.strip_prefix('<').unwrap_or(id);
    id.strip_suffix('>').unwrap_or(id).trim()
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// `now` truncated to the millisecond the stored form keeps, so a record
/// equals its own serde round trip.
fn millis(now: SystemTime) -> SystemTime {
    let since = now.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    UNIX_EPOCH + Duration::from_millis(since.as_millis() as u64)
}

/// RFC 9562 §5.7 UUIDv7: 48-bit Unix milliseconds, version 7, variant `10`,
/// 74 random bits. Unique across processes without coordination.
pub(crate) fn new_record_id(now: SystemTime) -> Result<String> {
    let ms = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64;
    let mut b = [0u8; 16];
    getrandom::fill(&mut b[6..]).map_err(|err| {
        AsxError::new(
            ErrorCode::StorageBackendFailure,
            format!("no randomness for an audit record id: {err}"),
            ErrorContext::new("audit_record_id"),
        )
    })?;
    b[..6].copy_from_slice(&ms.to_be_bytes()[2..]);
    b[6] = (b[6] & 0x0f) | 0x70;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

// ── Writing ─────────────────────────────────────────────────────────────────

/// Hand `rec` to `sink`, applying its declared durability: a `Durable` sink's
/// error fails with [`ErrorCode::StorageBackendFailure`] naming the record,
/// the message and the signal digest; a `BestEffort` sink's error is logged at
/// `ERROR` and counted, and the call succeeds. `None` records nothing.
#[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(dead_code))]
pub(crate) async fn record(
    sink: Option<&dyn AuditSink>,
    rec: &AuditRecord,
    stage: &'static str,
) -> Result<()> {
    use tracing::Instrument as _;

    let Some(sink) = sink else {
        return Ok(());
    };
    let durability = sink.durability();
    let span = tracing::debug_span!(
        target: "asx",
        "asx.audit",
        record_id = %rec.record_id,
        durability = durability.as_str(),
        outcome = tracing::field::Empty,
    );
    let result = sink.record(rec).instrument(span.clone()).await;
    let Err(err) = result else {
        span.record("outcome", "ok");
        return Ok(());
    };
    span.record("outcome", "failed");
    let signal_sha256 = rec.signal_sha256().unwrap_or("");
    tracing::error!(
        target: "asx",
        parent: &span,
        record_id = %rec.record_id,
        message_id = %rec.message_id,
        signal.sha256 = signal_sha256,
        durability = durability.as_str(),
        "audit record not written"
    );
    crate::telemetry::audit_failed(durability);
    match durability {
        AuditDurability::BestEffort => Ok(()),
        AuditDurability::Durable => Err(AsxError::new(
            ErrorCode::StorageBackendFailure,
            format!(
                "durable audit sink failed to record {} for message {} (signal sha256 {}): {err}",
                rec.record_id,
                rec.message_id,
                if signal_sha256.is_empty() {
                    "none"
                } else {
                    signal_sha256
                },
            ),
            ErrorContext::new(stage).with_message_id(rec.message_id.clone()),
        )),
    }
}

// ── Serde helpers ───────────────────────────────────────────────────────────

/// Standard base64 with padding (RFC 4648 §4).
mod b64 {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(text.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// RFC 3339 UTC, exactly three fractional digits, `Z`.
mod rfc3339_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::SystemTime;

    pub(super) fn serialize<S: Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::time_utils::format_rfc3339_millis(*t))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SystemTime, D::Error> {
        let text = String::deserialize(d)?;
        crate::time_utils::parse_rfc3339_millis(&text).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "recorded_at must be RFC 3339 UTC with milliseconds (YYYY-MM-DDTHH:MM:SS.mmmZ), got {text:?}"
            ))
        })
    }
}

#[cfg(test)]
mod tests;
