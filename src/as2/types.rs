//! AS2 policy configuration, message type definitions, and version validation.
//!
//! This module contains the public types that callers of the AS2 send/receive
//! APIs use to configure behaviour and inspect results.  No crypto or I/O
//! is performed here.

use std::sync::Arc;
use zeroize::Zeroize;

use super::spool_key_provider::As2RegulatedSpoolKeyProvider;
use crate::core::{AsxError, ErrorCode, ErrorContext, InteropMode, Result};
#[cfg(feature = "as2")]
use crate::crypto::as2_smime::SmimeCipher;
use crate::http::HttpHeaders;
use crate::interop::InteropExceptionPolicy;
use crate::lifecycle::DomainReady;
use crate::reliability::{DeliveryOutcome, RetryDecision};

/// Raw MIME envelope returned from the AS2 send path, ready for HTTP transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MimeEnvelope {
    pub content_type: String,
    pub body: Arc<[u8]>,
}

impl MimeEnvelope {
    /// Convert the body to a [`bytes::Bytes`] without copying.
    ///
    /// This is the idiomatic way to pass the envelope body to `reqwest`,
    /// `axum`, or any other crate in the Tokio ecosystem that works with
    /// `bytes::Bytes`.
    ///
    /// # Performance
    ///
    /// The conversion is O(1) — it wraps the existing `Arc<[u8]>` inside a
    /// `Bytes` owner without cloning the underlying byte buffer.
    #[inline]
    pub fn body_bytes(&self) -> bytes::Bytes {
        bytes::Bytes::copy_from_slice(&self.body)
    }

    /// Convert `self` into a [`bytes::Bytes`], consuming the envelope body.
    ///
    /// Equivalent to [`body_bytes`](Self::body_bytes) but avoids the
    /// `Arc::clone` when the envelope is no longer needed after conversion.
    #[inline]
    pub fn into_body_bytes(self) -> bytes::Bytes {
        bytes::Bytes::from(self.body.to_vec())
    }
}

/// Well-known `Content-Type` strings for AS2 business payloads.
///
/// Pass one of these constants to [`As2SendPolicy::payload_content_type`] so
/// that the RFC 4130 §7.3.1 Message Integrity Check (MIC) is computed with the
/// correct content-type header, as required by AS2 trading agreements.
///
/// # Example
///
/// ```rust
/// # use asx::as2::{As2SendPolicy, payload_content_type};
/// let policy = As2SendPolicy {
///     payload_content_type: Some(payload_content_type::EDIFACT),
///     ..As2SendPolicy::strict()
/// };
/// ```
#[allow(unused)]
pub mod payload_content_type {
    /// UN/EDIFACT interchange (`application/EDIFACT`).
    ///
    /// Used by PEPPOL, GS1, and most European B2B networks for EDI messaging.
    /// Per RFC 1767.
    pub const EDIFACT: &str = "application/EDIFACT";

    /// ASC X12 EDI interchange (`application/EDI-X12`).
    ///
    /// Used by US-centric supply chain (retail, healthcare, logistics) networks.
    /// Per RFC 1767.
    pub const X12: &str = "application/EDI-X12";

    /// Generic EDI consent type (`application/edi-consent`).
    ///
    /// Per RFC 1767 §3.3.  Use when the interchange type is not EDIFACT or X12.
    pub const EDI_CONSENT: &str = "application/edi-consent";

    /// Plain XML payload (`application/xml`).
    ///
    /// Common for UBL, cXML, and custom XML interchange formats.
    pub const XML: &str = "application/xml";

    /// JSON payload (`application/json`).
    ///
    /// Used by AS2 deployments carrying REST-adjacent JSON interchange (e.g.
    /// some GS1 US Digital Commerce networks).
    pub const JSON: &str = "application/json";

    /// Raw binary payload (`application/octet-stream`).
    ///
    /// Default when [`As2SendPolicy::payload_content_type`] is `None`.
    pub const OCTET_STREAM: &str = "application/octet-stream";

    /// Plain text payload (`text/plain`).
    pub const TEXT: &str = "text/plain";
}

/// Algorithm used to compute the RFC 4130 §7.3.1 Message Integrity Check (MIC).
///
/// `Sha256` is the default and mandatory in interop-strict mode.
/// `Sha384` and `Sha512` are available as stronger alternatives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum As2MicAlgorithm {
    /// SHA-256 (RFC 5754). Default. Required in strict mode.
    #[default]
    Sha256,
    /// SHA-384 (RFC 5754). Stronger alternative; supported by phase2-lib and
    /// pyas2-lib.
    Sha384,
    /// SHA-512 (RFC 5754). Strongest standard MIC algorithm; supported by
    /// phase2-lib and pyas2-lib.
    Sha512,
}

/// Policy governing an outbound AS2 message send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As2SendPolicy {
    pub interop_mode: InteropMode,
    /// When true, protocol lifecycle event emission failures fail the send path.
    pub fail_closed_audit_events: bool,
    pub sign: bool,
    pub encrypt: bool,
    pub compress: bool,
    /// MIME Content-Type of the raw payload for RFC 4130 §7.3.1 MIC
    /// computation.  Defaults to `"application/octet-stream"` when `None`.
    pub payload_content_type: Option<&'static str>,
    /// Algorithm used to compute the RFC 4130 §7.3.1 MIC.
    /// Defaults to [`As2MicAlgorithm::Sha256`].
    pub mic_algorithm: As2MicAlgorithm,
    /// Symmetric cipher used for S/MIME (CMS EnvelopedData) encryption when
    /// `encrypt` is `true`.  Defaults to [`SmimeCipher::Aes256Cbc`].
    #[cfg(feature = "as2")]
    pub encryption_cipher: SmimeCipher,
    /// AS2-From header value (this party's AS2 identifier per RFC 4130 §6).
    /// Defaults to `session.session_id()` when empty.
    pub as2_from_id: String,
}

impl Default for As2SendPolicy {
    fn default() -> Self {
        Self {
            interop_mode: InteropMode::Strict,
            fail_closed_audit_events: true,
            sign: true,
            encrypt: true,
            compress: false,
            payload_content_type: None,
            mic_algorithm: As2MicAlgorithm::Sha256,
            #[cfg(feature = "as2")]
            encryption_cipher: SmimeCipher::Aes256Cbc,
            as2_from_id: String::new(),
        }
    }
}

impl As2SendPolicy {
    /// Return the recommended production-safe send policy preset.
    ///
    /// Signing and encryption are both enabled.  Use struct-update syntax
    /// (`{ ..As2SendPolicy::strict() }`) to adjust individual fields.
    pub fn strict() -> Self {
        Self::default()
    }

    /// Return the regulated deployment preset for AS2 send.
    ///
    /// This preset keeps strict interop and fail-closed audit behavior.
    pub fn regulated() -> Self {
        Self::default()
    }
}

/// Protocol-specific credentials for AS2 message sending (signing and encryption).
///
/// # Preferred API
///
/// For new integrations and multi-protocol deployments, prefer
/// [`PartnerCredentials`](crate::credentials::PartnerCredentials) as the primary
/// credential holder.  `PartnerCredentials` zeroizes the signing key on drop,
/// supports both AS2 and AS4 from one bundle, and provides
/// [`prepare_as2_for_policy`](crate::credentials::PartnerCredentials::prepare_as2_for_policy)
/// for single-pass parse-and-validate.
///
/// Use `As2SendCredentials` directly only when you are already in AS2-only
/// code that does not need the unified API.
#[derive(Debug, Clone, Default)]
pub struct As2SendCredentials {
    /// PEM-encoded signing certificate (required if policy.sign = true)
    pub signing_cert_pem: Option<Vec<u8>>,
    /// PEM-encoded signing private key (required if policy.sign = true)
    pub signing_key_pem: Option<Vec<u8>>,
    /// PEM-encoded recipient certificate for encryption (required if
    /// policy.encrypt = true)
    pub recipient_cert_pem: Option<Vec<u8>>,
}

impl Drop for As2SendCredentials {
    fn drop(&mut self) {
        if let Some(key) = self.signing_key_pem.as_mut() {
            key.zeroize();
        }
    }
}

#[cfg(feature = "as2")]
#[derive(Debug, Clone)]
pub struct As2PreparedSendCredentials {
    pub signing_cert: Option<openssl::x509::X509>,
    pub signing_key: Option<openssl::pkey::PKey<openssl::pkey::Private>>,
    pub recipient_cert: Option<openssl::x509::X509>,
}

impl As2SendCredentials {
    /// Parse and validate configured PEM material once for a given send policy.
    #[cfg(feature = "as2")]
    pub fn prepare_for_policy(
        &self,
        policy: &As2SendPolicy,
        stage: &'static str,
        error_code: ErrorCode,
    ) -> Result<As2PreparedSendCredentials> {
        let ctx = || ErrorContext::new(stage);

        let mut prepared = As2PreparedSendCredentials {
            signing_cert: None,
            signing_key: None,
            recipient_cert: None,
        };

        if policy.sign {
            let cert_pem = self.signing_cert_pem.as_ref().ok_or_else(|| {
                AsxError::new(error_code, "AS2 signing certificate is missing", ctx())
            })?;
            let key_pem = self
                .signing_key_pem
                .as_ref()
                .ok_or_else(|| AsxError::new(error_code, "AS2 signing key is missing", ctx()))?;

            let signing_cert = openssl::x509::X509::from_pem(cert_pem).map_err(|_| {
                AsxError::new(
                    error_code,
                    "AS2 signing certificate is not a valid PEM X.509 certificate",
                    ctx(),
                )
            })?;
            let signing_key = openssl::pkey::PKey::private_key_from_pem(key_pem).map_err(|_| {
                AsxError::new(
                    error_code,
                    "AS2 signing key is not a valid PEM private key",
                    ctx(),
                )
            })?;
            let signing_cert_public = signing_cert.public_key().map_err(|_| {
                AsxError::new(
                    error_code,
                    "AS2 signing certificate does not contain a usable public key",
                    ctx(),
                )
            })?;
            if !signing_key.public_eq(&signing_cert_public) {
                return Err(AsxError::new(
                    error_code,
                    "AS2 signing certificate does not match signing key",
                    ctx(),
                ));
            }

            prepared.signing_cert = Some(signing_cert);
            prepared.signing_key = Some(signing_key);
        }

        if policy.encrypt {
            let recipient_cert_pem = self.recipient_cert_pem.as_ref().ok_or_else(|| {
                AsxError::new(error_code, "AS2 recipient certificate is missing", ctx())
            })?;
            let recipient_cert =
                openssl::x509::X509::from_pem(recipient_cert_pem).map_err(|_| {
                    AsxError::new(
                        error_code,
                        "AS2 recipient certificate is not a valid PEM X.509 certificate",
                        ctx(),
                    )
                })?;
            prepared.recipient_cert = Some(recipient_cert);
        } else if let Some(recipient_cert_pem) = self.recipient_cert_pem.as_ref() {
            let recipient_cert =
                openssl::x509::X509::from_pem(recipient_cert_pem).map_err(|_| {
                    AsxError::new(
                        error_code,
                        "AS2 recipient certificate is not a valid PEM X.509 certificate",
                        ctx(),
                    )
                })?;
            prepared.recipient_cert = Some(recipient_cert);
        }

        Ok(prepared)
    }
}

/// Output from a successful AS2 send operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As2SendOutput {
    pub message_id: String,
    pub mime: MimeEnvelope,
    pub mic_base64: String,
    pub digest_alg: &'static str,
    /// W3C Trace Context `traceparent` header to forward on HTTP egress.
    pub traceparent: Option<String>,
    /// HTTP headers required by RFC 4130 §6 for the AS2 HTTP binding.
    /// These are ready-to-set key/value pairs: `(header-name, header-value)`.
    /// Includes: `AS2-Version`, `AS2-From`, `AS2-To`, `Message-ID`,
    /// `MIME-Version`, `Content-Type`.
    pub http_headers: HttpHeaders,
}

impl As2SendOutput {
    /// Returns the full `Received-Content-MIC` value in RFC 4130 format:
    /// `"{base64-mic}, {algorithm-name}"` (e.g. `"abc123==, sha-256"`).
    ///
    /// Use this as the `expected_mic` field in [`As2ReceiveMdnRequest`] so that
    /// both the digest value **and** the algorithm name are cross-validated
    /// against the inbound MDN (RFC 4130 §7.4.3).
    pub fn as_received_content_mic(&self) -> String {
        format!("{}, {}", self.mic_base64, self.digest_alg)
    }
}

/// Whether the sender requested a synchronous or asynchronous MDN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum As2MdnMode {
    Synchronous,
    Asynchronous,
    /// Partner did not request an MDN; any received disposition is accepted as
    /// SuccessConfirmed.
    None,
}

/// Policy governing an inbound AS2 message receive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As2ReceivePolicy {
    pub interop_mode: InteropMode,
    pub interop_exceptions: InteropExceptionPolicy,
    pub fail_closed_audit_events: bool,
    pub regulated_spool_key_provider: As2RegulatedSpoolKeyProvider,
    /// Require a valid `AS2-Version` header on every inbound message.
    ///
    /// When `true` (the default) the header must be present and must contain
    /// one of `1.0`, `1.1`, or `1.2`.  In [`InteropMode::Relaxed`] a missing
    /// header is tolerated; an unrecognised value always causes an error.
    pub enforce_as2_version: bool,
}

impl Default for As2ReceivePolicy {
    fn default() -> Self {
        Self {
            interop_mode: InteropMode::Strict,
            interop_exceptions: InteropExceptionPolicy::default(),
            fail_closed_audit_events: true,
            regulated_spool_key_provider: As2RegulatedSpoolKeyProvider::LocalEnv,
            enforce_as2_version: true,
        }
    }
}

impl As2ReceivePolicy {
    /// Return the recommended production-safe receive policy preset.
    ///
    /// Equivalent to `Default::default()` but named explicitly so that audit
    /// tooling can locate all call sites that rely on secure defaults.  Use
    /// struct-update syntax (`{ ..As2ReceivePolicy::strict() }`) to adjust
    /// individual fields when necessary.
    pub fn strict() -> Self {
        Self::default()
    }

    /// Return the regulated deployment preset for AS2 receive.
    ///
    /// This preset keeps strict interop, fail-closed audit behavior, and
    /// AS2-Version enforcement enabled.
    pub fn regulated() -> Self {
        Self::default()
    }
}

/// Builder for [`As2ReceivePolicy`].
///
/// Constructed via [`As2ReceivePolicyBuilder::new()`] or equivalently
/// via the `Default` impl. All fields default to the same secure-production
/// values as [`As2ReceivePolicy::strict()`]:
///
/// - `interop_mode`: [`InteropMode::Strict`]
/// - `interop_exceptions`: [`InteropExceptionPolicy::default()`]
/// - `fail_closed_audit_events`: `true`
/// - `regulated_spool_key_provider`: [`As2RegulatedSpoolKeyProvider::LocalEnv`]
/// - `enforce_as2_version`: `true`
///
/// # Example
/// ```
/// use asx::as2::{As2ReceivePolicyBuilder, As2RegulatedSpoolKeyProvider};
/// use asx::core::InteropMode;
///
/// let policy = As2ReceivePolicyBuilder::new()
///     .interop(InteropMode::Relaxed)
///     .fail_closed_audit_events(false)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct As2ReceivePolicyBuilder {
    interop_mode: InteropMode,
    interop_exceptions: InteropExceptionPolicy,
    fail_closed_audit_events: bool,
    regulated_spool_key_provider: As2RegulatedSpoolKeyProvider,
    enforce_as2_version: bool,
}

impl Default for As2ReceivePolicyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl As2ReceivePolicyBuilder {
    /// Create a builder initialised with the same secure defaults as
    /// [`As2ReceivePolicy::strict()`].
    pub fn new() -> Self {
        let defaults = As2ReceivePolicy::default();
        Self {
            interop_mode: defaults.interop_mode,
            interop_exceptions: defaults.interop_exceptions,
            fail_closed_audit_events: defaults.fail_closed_audit_events,
            regulated_spool_key_provider: defaults.regulated_spool_key_provider,
            enforce_as2_version: defaults.enforce_as2_version,
        }
    }

    /// Set the interop mode.
    pub fn interop(mut self, mode: InteropMode) -> Self {
        self.interop_mode = mode;
        self
    }

    /// Set the interop exception policy.
    pub fn interop_exceptions(mut self, exceptions: InteropExceptionPolicy) -> Self {
        self.interop_exceptions = exceptions;
        self
    }

    /// Control whether protocol audit events fail closed when the event bus is full.
    pub fn fail_closed_audit_events(mut self, fail_closed: bool) -> Self {
        self.fail_closed_audit_events = fail_closed;
        self
    }

    /// Configure the regulated spool key provider.
    pub fn regulated_spool_key_provider(mut self, provider: As2RegulatedSpoolKeyProvider) -> Self {
        self.regulated_spool_key_provider = provider;
        self
    }

    /// Require a valid `AS2-Version` header on inbound messages.
    pub fn enforce_as2_version(mut self, enforce: bool) -> Self {
        self.enforce_as2_version = enforce;
        self
    }

    /// Consume the builder and return the final [`As2ReceivePolicy`].
    pub fn build(self) -> As2ReceivePolicy {
        As2ReceivePolicy {
            interop_mode: self.interop_mode,
            interop_exceptions: self.interop_exceptions,
            fail_closed_audit_events: self.fail_closed_audit_events,
            regulated_spool_key_provider: self.regulated_spool_key_provider,
            enforce_as2_version: self.enforce_as2_version,
        }
    }
}

/// Validate the `AS2-Version` header in an incoming HTTP header list.
///
/// Headers should be provided as `(name, value)` pairs; name comparison is
/// case-insensitive.  Returns `Ok(())` when:
///
/// * `policy.enforce_as2_version` is `false`, **or**
/// * the header is present with a recognised version (`1.0`, `1.1`, `1.2`), **or**
/// * the header is absent **and** the policy's interop mode is
///   [`InteropMode::Relaxed`].
///
/// Returns an [`ErrorCode::InteropViolation`] error for unrecognised version
/// strings, or when the header is absent in [`InteropMode::Strict`] mode.
#[cfg(feature = "as2")]
pub fn validate_as2_version_header(
    headers: &[(String, String)],
    policy: &As2ReceivePolicy,
) -> Result<()> {
    if !policy.enforce_as2_version {
        return Ok(());
    }
    let version = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("AS2-Version"))
        .map(|(_, v)| v.trim().to_owned());
    match version.as_deref() {
        Some("1.0") | Some("1.1") | Some("1.2") => Ok(()),
        Some(v) => Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!("unrecognised AS2-Version '{v}'; expected 1.0, 1.1, or 1.2"),
            ErrorContext::new("as2_receive"),
        )),
        None if policy.interop_mode == InteropMode::Strict => Err(AsxError::new(
            ErrorCode::InteropViolation,
            "AS2-Version header is missing",
            ErrorContext::new("as2_receive"),
        )),
        None => Ok(()),
    }
}

/// Parsed MDN (RFC 4130 §7.4 Disposition Notification).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMdn {
    pub final_recipient: Option<String>,
    pub original_message_id: Option<String>,
    pub disposition: String,
    pub received_content_mic: Option<String>,
    pub is_signed: bool,
}

/// Result of [`receive_from_ingress`](crate::as2::receive_from_ingress):
/// verified domain content plus an optional auto-generated synchronous MDN
/// (RFC 4130 §7.4).
#[derive(Debug, Clone)]
pub struct As2InboundResult {
    /// Verified (and decrypted) domain payload, ready for application use.
    pub content: DomainReady<Arc<[u8]>>,
    /// Synchronous MDN entity to return in the HTTP response body.
    ///
    /// `Some` when the inbound request carried a `Disposition-Notification-To`
    /// header whose value looks like an HTTP/HTTPS URL (synchronous MDN).
    /// Return `sync_mdn.bytes` with `Content-Type: sync_mdn.content_type`.
    ///
    /// `None` when the sender did not request an MDN, when the request
    /// included a `mailto:` address (see `async_mdn_address`), or when
    /// `disposition_notification_to` was absent.
    pub sync_mdn: Option<As2GeneratedMdn>,
    /// RFC 4130 §7.3.1 MIC value (`base64(hash)` over the inbound MIME body).
    ///
    /// `None` only when `Disposition-Notification-To` was absent; always
    /// `Some` when `sync_mdn` is `Some`.
    pub received_content_mic: Option<String>,
    /// MIC algorithm used, matching what the sender negotiated via
    /// `Disposition-Notification-Options`, defaulting to SHA-256.
    pub mic_algorithm: As2MicAlgorithm,
    /// `mailto:` address from the inbound `Disposition-Notification-To` header
    /// when the sender requested **asynchronous** MDN delivery over SMTP.
    ///
    /// # ⚠ Embedder must dispatch asynchronous MDN
    ///
    /// When this field is `Some`, the library has **not** sent any email.
    /// SMTP dispatch is outside the scope of this HTTP transport library.
    /// Your application must:
    ///
    /// 1. Construct the MDN body with [`crate::as2::generate_mdn`] or
    ///    [`crate::as2::generate_signed_mdn`], using the `received_content_mic`
    ///    from this result.
    /// 2. Send the MDN via your SMTP client to this address.
    ///
    /// Ignoring this field violates RFC 4130 §7.3 and will cause partners
    /// that require async MDN confirmation to mark messages as unacknowledged.
    pub async_mdn_address: Option<String>,
}

/// Output from [`receive_with_mdn_with_reliability`](crate::as2::receive_with_mdn_with_reliability).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As2ReceiveMdnOutput {
    pub payload: DomainReady<Arc<[u8]>>,
    pub mdn: ParsedMdn,
    pub outcome: DeliveryOutcome,
    pub retry_decision: RetryDecision,
    pub interop_reason_codes: Vec<&'static str>,
}

/// Auto-generated MDN ready to write to an HTTP response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As2GeneratedMdn {
    pub bytes: Arc<[u8]>,
    pub content_type: String,
    pub is_signed: bool,
}

/// Signing credentials for MDN generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As2MdnSigningCredentials {
    pub signing_cert_pem: Vec<u8>,
    pub signing_key_pem: Vec<u8>,
}

impl Drop for As2MdnSigningCredentials {
    fn drop(&mut self) {
        self.signing_key_pem.zeroize();
    }
}

/// Request to correlate an inbound MDN against a previously sent message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As2ReceiveMdnRequest {
    /// Original outbound payload bytes being reconciled against the MDN.
    pub payload: Arc<[u8]>,
    /// Raw MDN bytes to parse and classify.
    pub mdn_payload: Arc<[u8]>,
    pub mdn_mode: As2MdnMode,
    pub expected_mic: Option<String>,
    pub policy: As2ReceivePolicy,
    /// Original outbound message ID, if known by the caller.
    ///
    /// When `parse_mdn` fails (e.g. malformed MDN or signature error) before
    /// the message ID can be extracted from the MDN itself, this value is used
    /// to queue a [`ReconciliationRequest`] with reason `PendingVerification`
    /// so the original message is not silently stranded.  Set to `None` when
    /// the message ID is unknown (e.g. async MDN without an out-of-band
    /// reference).
    pub original_message_id: Option<String>,
}
