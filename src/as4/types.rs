use super::pmode::PayloadPackagingMode;
use crate::core::InteropMode;
use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::crypto::soap_builder::WsAddressingHeaders;
use crate::crypto::wssec::{
    WsSecOutboundKeyInfoProfile, WsSecSignatureReference, XmlEncPayloadAlgorithm,
};
use crate::interop::InteropExceptionPolicy;
use crate::lifecycle::DomainReady;
use crate::reliability::{DeliveryOutcome, RetryDecision};
use crate::sbdh::SbdhHeader;
use std::sync::Arc;
use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoapEnvelope {
    pub action: String,
    pub body: Arc<[u8]>,
}

impl SoapEnvelope {
    /// Return the body as a [`bytes::Bytes`] without copying the data.
    ///
    /// Useful for passing the serialized SOAP envelope body to `reqwest`,
    /// `axum`, or any other bytes-oriented Tokio ecosystem crate.
    ///
    /// # Performance
    ///
    /// O(1) — wraps the `Arc<[u8]>` via a copy-from-slice.  Use
    /// [`into_body_bytes`](Self::into_body_bytes) when the envelope will not
    /// be reused after conversion.
    #[inline]
    pub fn body_bytes(&self) -> bytes::Bytes {
        bytes::Bytes::copy_from_slice(&self.body)
    }

    /// Consume `self` and return the body as a [`bytes::Bytes`].
    #[inline]
    pub fn into_body_bytes(self) -> bytes::Bytes {
        bytes::Bytes::from(self.body.to_vec())
    }
}

/// Controls how fragment groups are scoped to prevent cross-sender injection.
///
/// ebMS3 Part 2 security guidance requires that fragment group correlation keys
/// incorporate an **authenticated** sender identity so that a malicious actor
/// cannot forge `<eb:From>` to inject data into another sender's fragment group.
///
/// # ⚠ Security
///
/// The default (`RequireAuthenticatedScope`) is the safe choice for production.
/// `UseSoapSenderId` is provided only for controlled environments where all
/// senders are fully trusted and mTLS-based authentication is infeasible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum FragmentScopePolicy {
    /// **Secure default.** Fragment groups are scoped by the transport-layer
    /// authenticated sender identity supplied via
    /// [`As4ReceivePushRequest::authenticated_sender_scope`].
    ///
    /// When this policy is active, `ingest_fragment` returns
    /// [`ErrorCode::PolicyViolation`] if `authenticated_sender_scope` is `None`.
    /// Typical scope values: mTLS client certificate CN, peer IP, or AP identifier
    /// verified at the transport layer before the request was admitted.
    #[default]
    RequireAuthenticatedScope,
    /// **Insecure — legacy compatibility only.**
    ///
    /// Fragment groups are scoped by the `<eb:From/eb:PartyId>` value parsed
    /// from the unauthenticated SOAP envelope.  Any sender can forge this value
    /// to target another sender's fragment group.
    ///
    /// Only acceptable when:
    /// * all senders are on the same trusted internal network, **and**
    /// * upgrading to authenticated scope is not feasible in the short term.
    UseSoapSenderId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As4PushPolicy {
    pub interop: InteropMode,
    pub interop_exceptions: InteropExceptionPolicy,
    pub require_signed_receipt: bool,
    #[doc(hidden)]
    pub(crate) require_signed_push: bool,
    /// When `true` (the default), protocol event emission failures fail the
    /// receive operation (fail-closed audit semantics).
    pub fail_closed_audit_events: bool,
    pub inbound_decryption_key_pem: Option<Arc<[u8]>>,
    /// Replay-window enforcement for inbound `<eb:Timestamp>`.
    ///
    /// When `Some(window)`, inbound messages whose `<eb:Timestamp>` is more than
    /// `window` in the past (or future) are rejected with
    /// `SecurityVerificationFailed`.  This closes the replay window that exists
    /// when dedup storage alone is used as the replay defence.
    ///
    /// Per eDelivery AS4 v1.15 §5.1.3 the recommended window is **5 minutes**.
    /// Set to `None` to disable freshness enforcement (development / testing only).
    ///
    /// Defaults to `Some(Duration::from_secs(300))` (5 minutes) in production builds.
    pub timestamp_freshness_window: Option<std::time::Duration>,
    /// Policy for fragment group sender-scope determination.
    ///
    /// Controls whether fragment groups are keyed by the **authenticated**
    /// transport-layer sender identity (secure default) or the unauthenticated
    /// SOAP `<eb:From>` party ID (legacy fallback).
    ///
    /// See [`FragmentScopePolicy`] for the security implications of each variant.
    /// Defaults to [`FragmentScopePolicy::RequireAuthenticatedScope`].
    pub fragment_scope_policy: FragmentScopePolicy,
}

impl Default for As4PushPolicy {
    fn default() -> Self {
        Self {
            interop: InteropMode::Strict,
            interop_exceptions: InteropExceptionPolicy::default(),
            require_signed_receipt: true,
            require_signed_push: true,
            fail_closed_audit_events: true,
            inbound_decryption_key_pem: None,
            timestamp_freshness_window: Some(std::time::Duration::from_secs(300)),
            fragment_scope_policy: FragmentScopePolicy::RequireAuthenticatedScope,
        }
    }
}

impl As4PushPolicy {
    /// Return the recommended production-safe policy preset.
    ///
    /// Equivalent to `Default::default()` but named explicitly so that
    /// code-review and audit tooling can easily locate all call sites that
    /// are using hardened defaults vs. those that customise a field.
    ///
    /// Use [`As4PushPolicyBuilder`] to adjust individual fields.  Any field
    /// that weakens security — particularly
    /// `allow_unsigned_push` — is
    /// documented with an explicit security warning.
    pub fn strict() -> Self {
        Self::default()
    }

    /// Return the regulated deployment preset for inbound push receive.
    ///
    /// This preset is intentionally fail-closed:
    /// - strict interop mode
    /// - signed push required
    /// - signed receipt required
    /// - fail-closed audit emission
    /// - timestamp freshness enforcement enabled (5 minutes)
    pub fn regulated() -> Self {
        Self {
            interop: InteropMode::Strict,
            interop_exceptions: InteropExceptionPolicy::default(),
            require_signed_receipt: true,
            require_signed_push: true,
            fail_closed_audit_events: true,
            inbound_decryption_key_pem: None,
            timestamp_freshness_window: Some(std::time::Duration::from_secs(300)),
            fragment_scope_policy: FragmentScopePolicy::RequireAuthenticatedScope,
        }
    }

    /// Return whether inbound push messages must carry a valid signature.
    pub fn require_signed_push(&self) -> bool {
        self.require_signed_push
    }

    /// Return a relaxed push receive policy for use in integration tests.
    ///
    /// Relaxed mode; does not require signed push or signed receipt; audit
    /// events are best-effort.  Timestamp freshness enforcement is disabled.
    ///
    /// **Never use this in production code.**
    #[cfg(all(feature = "testing", feature = "interop-relaxed"))]
    pub fn test_relaxed() -> Self {
        Self {
            interop: InteropMode::Relaxed,
            require_signed_push: false,
            require_signed_receipt: false,
            fail_closed_audit_events: false,
            timestamp_freshness_window: None,
            fragment_scope_policy: FragmentScopePolicy::UseSoapSenderId,
            ..Self::default()
        }
    }
}

fn validate_strict_as4_policy_consistency(
    stage: &'static str,
    interop: InteropMode,
    interop_exceptions: &InteropExceptionPolicy,
) -> Result<()> {
    if interop == InteropMode::Strict
        && (interop_exceptions.scoped_profile_name.is_some()
            || !interop_exceptions.allowed.is_empty())
    {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "strict AS4 policy forbids configured interop exception overrides",
            ErrorContext::new(stage),
        ));
    }

    Ok(())
}

fn validate_strict_as4_send_policy_consistency(
    stage: &'static str,
    interop: InteropMode,
    sign: bool,
    fail_closed_audit_events: bool,
    payload_packaging_mode: PayloadPackagingMode,
) -> Result<()> {
    if interop == InteropMode::Strict {
        if !sign {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "strict AS4 send policy forbids sign=false",
                ErrorContext::new(stage),
            ));
        }
        if payload_packaging_mode != PayloadPackagingMode::MimeAttachment {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "strict AS4 send policy requires MIME attachment payload packaging",
                ErrorContext::new(stage),
            ));
        }
    }

    #[cfg(not(feature = "testing"))]
    if interop == InteropMode::Strict && !fail_closed_audit_events {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "strict AS4 send policy requires fail_closed_audit_events=true in non-testing builds",
            ErrorContext::new(stage),
        ));
    }
    #[cfg(feature = "testing")]
    let _ = fail_closed_audit_events;

    Ok(())
}

pub(crate) fn validate_as4_send_policy_and_credentials_consistency(
    stage: &'static str,
    policy: &As4SendPolicy,
    credentials: &As4SendCredentials,
    error_code: ErrorCode,
) -> Result<()> {
    let ctx = || ErrorContext::new(stage);

    if policy.action.trim().is_empty() {
        return Err(AsxError::new(
            error_code,
            "As4SendPolicy.action must not be empty",
            ctx(),
        ));
    }

    if policy.service.trim().is_empty() {
        return Err(AsxError::new(
            error_code,
            "As4SendPolicy.service must not be empty",
            ctx(),
        ));
    }

    if let Some(ref id) = policy.ref_to_message_id
        && id.trim().is_empty()
    {
        return Err(AsxError::new(
            error_code,
            "As4SendPolicy.ref_to_message_id must not be empty when set",
            ctx(),
        ));
    }

    if let Some(ref conversation_id) = policy.conversation_id
        && conversation_id.trim().is_empty()
    {
        return Err(AsxError::new(
            error_code,
            "As4SendPolicy.conversation_id must not be empty when set",
            ctx(),
        ));
    }

    if policy.sign {
        if credentials.signing_cert_pem.is_none() {
            return Err(AsxError::new(
                error_code,
                "sign = true requires signing_cert_pem",
                ctx(),
            ));
        }
        if credentials.signing_key_pem.is_none() {
            return Err(AsxError::new(
                error_code,
                "sign = true requires signing_key_pem",
                ctx(),
            ));
        }
    }

    if (policy.encrypt || policy.encrypt_soap_headers) && credentials.recipient_cert_pem.is_none() {
        return Err(AsxError::new(
            error_code,
            "encrypt = true or encrypt_soap_headers = true requires recipient_cert_pem",
            ctx(),
        ));
    }

    Ok(())
}

#[cfg(feature = "as4")]
#[derive(Debug, Clone)]
pub struct As4PreparedSendCredentials {
    pub signing_cert: Option<openssl::x509::X509>,
    pub signing_key: Option<openssl::pkey::PKey<openssl::pkey::Private>>,
    pub recipient_cert: Option<openssl::x509::X509>,
}

impl As4SendCredentials {
    /// Parse and validate all configured PEM material once so callers can reuse
    /// crypto-ready credentials across many sends.
    #[cfg(feature = "as4")]
    pub fn prepare_for_policy(
        &self,
        policy: &As4SendPolicy,
        stage: &'static str,
        error_code: ErrorCode,
    ) -> Result<As4PreparedSendCredentials> {
        let ctx = || ErrorContext::new(stage);

        let mut prepared = As4PreparedSendCredentials {
            signing_cert: None,
            signing_key: None,
            recipient_cert: None,
        };

        if policy.sign {
            let cert_pem = self.signing_cert_pem.as_ref().ok_or_else(|| {
                AsxError::new(error_code, "sign = true requires signing_cert_pem", ctx())
            })?;
            let key_pem = self.signing_key_pem.as_ref().ok_or_else(|| {
                AsxError::new(error_code, "sign = true requires signing_key_pem", ctx())
            })?;

            let signing_cert = openssl::x509::X509::from_pem(cert_pem).map_err(|_err| {
                AsxError::new(
                    error_code,
                    "signing_cert_pem is not a valid PEM X.509 certificate",
                    ctx(),
                )
            })?;

            let signing_key = openssl::pkey::PKey::private_key_from_pem(key_pem).map_err(|_err| {
                AsxError::new(
                    error_code,
                    "signing_key_pem is not a valid PEM private key (check PEM format and key type)",
                    ctx(),
                )
            })?;

            let signing_cert_public = signing_cert.public_key().map_err(|_err| {
                AsxError::new(
                    error_code,
                    "signing_cert_pem does not contain a usable public key",
                    ctx(),
                )
            })?;

            if !signing_key.public_eq(&signing_cert_public) {
                return Err(AsxError::new(
                    error_code,
                    "signing_cert_pem does not match signing_key_pem",
                    ctx(),
                ));
            }

            prepared.signing_cert = Some(signing_cert);
            prepared.signing_key = Some(signing_key);
        }

        if policy.encrypt {
            let cert_pem = self.recipient_cert_pem.as_ref().ok_or_else(|| {
                AsxError::new(
                    error_code,
                    "encrypt = true requires recipient_cert_pem",
                    ctx(),
                )
            })?;
            let recipient_cert = openssl::x509::X509::from_pem(cert_pem).map_err(|_err| {
                AsxError::new(
                    error_code,
                    "recipient_cert_pem is not a valid PEM X.509 certificate",
                    ctx(),
                )
            })?;
            prepared.recipient_cert = Some(recipient_cert);
        } else if let Some(cert_pem) = &self.recipient_cert_pem {
            let recipient_cert = openssl::x509::X509::from_pem(cert_pem).map_err(|_err| {
                AsxError::new(
                    error_code,
                    "recipient_cert_pem is not a valid PEM X.509 certificate",
                    ctx(),
                )
            })?;
            prepared.recipient_cert = Some(recipient_cert);
        }

        Ok(prepared)
    }
}

fn validate_strict_as4_receive_policy_consistency(
    stage: &'static str,
    interop: InteropMode,
    require_signed_receipt: bool,
    fail_closed_audit_events: bool,
) -> Result<()> {
    if interop == InteropMode::Strict && !require_signed_receipt {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "strict AS4 receive policy requires require_signed_receipt=true",
            ErrorContext::new(stage),
        ));
    }

    #[cfg(not(feature = "testing"))]
    if interop == InteropMode::Strict && !fail_closed_audit_events {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "strict AS4 receive policy requires fail_closed_audit_events=true in non-testing builds",
            ErrorContext::new(stage),
        ));
    }
    #[cfg(feature = "testing")]
    let _ = fail_closed_audit_events;

    Ok(())
}

/// Fluent builder for [`As4PushPolicy`] with eager validation.
///
/// Call [`build`](Self::build) when done; it validates PEM material if provided
/// and returns an error rather than letting the failure surface deep in crypto code.
#[derive(Default)]
pub struct As4PushPolicyBuilder(As4PushPolicy);

impl As4PushPolicyBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn interop(mut self, mode: InteropMode) -> Self {
        self.0.interop = mode;
        self
    }

    pub fn interop_exceptions(mut self, exc: InteropExceptionPolicy) -> Self {
        self.0.interop_exceptions = exc;
        self
    }

    pub fn require_signed_receipt(mut self, v: bool) -> Self {
        self.0.require_signed_receipt = v;
        self
    }

    /// Override the default WS-Security signature requirement for inbound push messages.
    ///
    /// # Security
    ///
    /// **Expert use only.** Passing `false` disables WS-Security signature verification
    /// for inbound AS4 push messages, meaning unsigned payloads from any sender will be
    /// accepted without authentication.  This violates the non-repudiation requirement
    /// of ebMS3 / AS4 and **must not be used in production** unless you have an
    /// alternative authentication mechanism at the transport layer.
    ///
    /// Only use this when integrating with a specific legacy partner that is explicitly
    /// known not to sign messages and cannot be upgraded.
    #[cfg(feature = "testing")]
    pub fn allow_unsigned_push(mut self, allow: bool) -> Self {
        self.0.require_signed_push = !allow;
        self
    }

    pub fn fail_closed_audit_events(mut self, v: bool) -> Self {
        self.0.fail_closed_audit_events = v;
        self
    }

    /// Set the PEM-encoded RSA private key used to decrypt inbound XML-Enc payloads.
    ///
    /// The key is validated immediately so that callers discover misconfiguration
    /// at startup rather than on the first decryption attempt.
    pub fn inbound_decryption_key_pem(mut self, pem: Vec<u8>) -> Self {
        self.0.inbound_decryption_key_pem = Some(Arc::from(pem));
        self
    }

    /// Configure the `<eb:Timestamp>` freshness window for inbound messages.
    ///
    /// Set to `Some(window)` to reject messages whose `<eb:Timestamp>` is older
    /// than `window` (or more than `window` in the future).  Set to `None` to
    /// disable freshness enforcement — **not recommended for production** as this
    /// opens a 24-hour replay window bounded only by the dedup store TTL.
    ///
    /// The default is `Some(Duration::from_secs(300))` (5 minutes per eDelivery
    /// AS4 v1.15 §5.1.3).
    pub fn timestamp_freshness_window(mut self, window: Option<std::time::Duration>) -> Self {
        self.0.timestamp_freshness_window = window;
        self
    }

    /// Set the fragment group scope policy.
    ///
    /// Defaults to [`FragmentScopePolicy::RequireAuthenticatedScope`], which
    /// requires the caller to supply [`As4ReceivePushRequest::authenticated_sender_scope`]
    /// for every fragment message.
    ///
    /// # ⚠ Security
    ///
    /// Only set to `UseSoapSenderId` when ALL senders are on a trusted network
    /// and you cannot provide a transport-layer identity.  This setting allows
    /// cross-sender fragment injection.
    pub fn fragment_scope_policy(mut self, policy: FragmentScopePolicy) -> Self {
        self.0.fragment_scope_policy = policy;
        self
    }

    /// Validate and produce the final [`As4PushPolicy`].
    ///
    /// Fails if a decryption key is present but its PEM encoding is invalid.
    pub fn build(self) -> Result<As4PushPolicy> {
        let stage = "as4_push_policy_build";

        validate_strict_as4_policy_consistency(stage, self.0.interop, &self.0.interop_exceptions)?;

        validate_strict_as4_receive_policy_consistency(
            stage,
            self.0.interop,
            self.0.require_signed_receipt,
            self.0.fail_closed_audit_events,
        )?;

        if let Some(ref pem) = self.0.inbound_decryption_key_pem {
            openssl::pkey::PKey::private_key_from_pem(pem.as_ref()).map_err(|_err| {
                AsxError::new(
                    ErrorCode::InvalidInput,
                    "inbound_decryption_key_pem is not a valid PEM private key (check PEM format and key type)",
                    ErrorContext::new(stage),
                )
            })?;
        }
        Ok(self.0)
    }
}

/// Policy for AS4 message sending (push or pull).
///
/// ## Two-Way / Push-and-Push MEP (eDelivery AS4 v1.15 §3.2.1)
///
/// To send a **response** UserMessage that correlates to a previously received push,
/// set [`ref_to_message_id`](Self::ref_to_message_id) to the `message_id` of the
/// original inbound message.  The builder emits `<eb:RefToMessageId>` in the SOAP
/// `<eb:MessageInfo>` block, which is the correlation mechanism defined by ebMS3
/// for the Two-Way/Push-and-Push MEP.
///
/// On the **receive** side, the correlation value is available via
/// [`ParsedAs4UserMessage::ref_to_message_id`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As4SendPolicy {
    pub interop: InteropMode,
    pub outbound_key_info_profile: WsSecOutboundKeyInfoProfile,
    /// When true, protocol lifecycle event emission failures fail the send path.
    pub fail_closed_audit_events: bool,
    pub sign: bool,
    pub encrypt: bool,
    /// XML Encryption payload algorithm used when `encrypt = true`.
    ///
    /// Defaults to `Aes128Gcm` for eDelivery AS4 v1.15 Common Profile
    /// conformance. Set to `Aes256Gcm` only for partner-specific agreements.
    pub outbound_xmlenc_payload_algorithm: XmlEncPayloadAlgorithm,
    /// When true, the outbound `eb:Messaging` SOAP header is wrapped in
    /// `xenc:EncryptedHeader` using the configured recipient certificate.
    pub encrypt_soap_headers: bool,
    pub compress: bool,
    /// ebMS3 `<eb:Action>` value for this message.
    ///
    /// Per ebMS3 Core Specification §5.2.2.7, the action identifies the
    /// business process step within the service agreement.  Must be agreed
    /// with the trading partner.  Defaults to a placeholder; always override
    /// for production deployments.
    pub action: String,
    /// ebMS3 `<eb:Service>` value (URI or name).
    ///
    /// Identifies the service or business process.  Must match the trading
    /// partner P-Mode agreement.  Defaults to a placeholder.
    pub service: String,
    /// ebMS3 `<eb:Service type="…">` attribute value.
    ///
    /// Typically `"urn:oasis:names:tc:ebcore:partyid-type:unregistered"` for
    /// unregistered services or a specific scheme URI for Peppol/CEF networks.
    /// Defaults to `"example"`.
    pub service_type: String,
    /// Optional `<eb:RefToMessageId>` for **Two-Way/Push-and-Push MEP**.
    ///
    /// When `Some(id)`, the outbound SOAP envelope includes
    /// `<eb:RefToMessageId>id</eb:RefToMessageId>` in `<eb:MessageInfo>`,
    /// correlating this message to the original inbound message with that ID.
    pub ref_to_message_id: Option<String>,
    /// Four Corner topology `originalSender` MessageProperty override.
    ///
    /// When `None`, outbound generation defaults to the primary `From/PartyId`.
    pub original_sender: Option<String>,
    /// Four Corner topology `finalRecipient` MessageProperty override.
    ///
    /// When `None`, outbound generation defaults to the primary `To/PartyId`.
    pub final_recipient: Option<String>,
    /// Four Corner topology `trackingIdentifier` MessageProperty override.
    ///
    /// When `None`, outbound generation defaults to the ebMS `MessageId`.
    pub tracking_identifier: Option<String>,
    /// Optional ebMS3 `<eb:ConversationId>` override.
    pub conversation_id: Option<String>,
    /// Optional WS-Addressing headers to include in outbound SOAP messages.
    ///
    /// When `Some`, the SOAP Header block will include `wsa:MessageID`,
    /// `wsa:Action`, `wsa:To`, and (optionally) `wsa:ReplyTo`.
    ///
    /// Required for CEF strict conformance testing and SOAP intermediary routing.
    /// Set `wsa:Action` to match the ebMS3 `<eb:Action>` value.
    pub ws_addressing: Option<WsAddressingHeaders>,
    /// Optional SBDH header used to wrap outbound business payloads.
    ///
    /// When set, AS4 send paths wrap the supplied business payload bytes in a
    /// `StandardBusinessDocument` envelope before compression/encryption/signing.
    pub sbdh_header: Option<SbdhHeader>,
    /// Payload packaging mode.
    ///
    /// ASX enforces MIME multipart/related payload attachments with Content-ID
    /// references for strict profile (PEPPOL/CEF) conformance.
    pub payload_packaging_mode: PayloadPackagingMode,
}

impl Default for As4SendPolicy {
    fn default() -> Self {
        Self {
            interop: InteropMode::Strict,
            outbound_key_info_profile: WsSecOutboundKeyInfoProfile::X509DataAndRsaKeyValue,
            fail_closed_audit_events: true,
            sign: true,
            encrypt: false,
            outbound_xmlenc_payload_algorithm: XmlEncPayloadAlgorithm::Aes128Gcm,
            encrypt_soap_headers: false,
            compress: false,
            action: "urn:example:action".into(),
            service: "http://example.org/example".into(),
            service_type: "example".into(),
            ref_to_message_id: None,
            original_sender: None,
            final_recipient: None,
            tracking_identifier: None,
            conversation_id: None,
            ws_addressing: None,
            sbdh_header: None,
            payload_packaging_mode: PayloadPackagingMode::default(),
        }
    }
}

impl As4SendPolicy {
    /// Return the recommended production-safe send policy preset.
    ///
    /// Signing is enabled by default.  Use [`As4SendPolicyBuilder`] to
    /// configure action/service values and attach credentials before calling
    /// [`send`](crate::as4::send_sync).
    pub fn strict() -> Self {
        Self::default()
    }

    /// Return the regulated deployment preset for AS4 send.
    ///
    /// This preset is intentionally explicit (not an alias to strict preset
    /// wiring) so production bundles can pin audited defaults in one place.
    pub fn regulated() -> Self {
        Self {
            interop: InteropMode::Strict,
            outbound_key_info_profile: WsSecOutboundKeyInfoProfile::X509DataAndRsaKeyValue,
            fail_closed_audit_events: true,
            sign: true,
            encrypt: false,
            outbound_xmlenc_payload_algorithm: XmlEncPayloadAlgorithm::Aes128Gcm,
            encrypt_soap_headers: false,
            compress: false,
            action: "urn:example:action".into(),
            service: "http://example.org/example".into(),
            service_type: "example".into(),
            ref_to_message_id: None,
            original_sender: None,
            final_recipient: None,
            tracking_identifier: None,
            conversation_id: None,
            ws_addressing: None,
            sbdh_header: None,
            payload_packaging_mode: PayloadPackagingMode::default(),
        }
    }

    /// Return a relaxed send policy for use in integration tests.
    ///
    /// This preset disables signing and strict audit enforcement so that
    /// test harnesses can exercise the send path without full PKI setup.
    ///
    /// **Never use this in production code.** It bypasses non-repudiation
    /// requirements of ebMS3 / AS4.
    #[cfg(all(feature = "testing", feature = "interop-relaxed"))]
    pub fn test_relaxed() -> Self {
        Self {
            interop: InteropMode::Relaxed,
            fail_closed_audit_events: false,
            sign: false,
            ..Self::default()
        }
    }
}

/// Fluent builder for [`As4SendPolicy`] + [`As4SendCredentials`] with combined validation.
///
/// [`build`](Self::build) enforces that credentials match the requested operations:
/// signing requires both a certificate and a private key; encryption requires a
/// recipient certificate.  Invalid PEM material is caught immediately.
#[derive(Default)]
pub struct As4SendPolicyBuilder {
    policy: As4SendPolicy,
    credentials: As4SendCredentials,
}

impl As4SendPolicyBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn interop(mut self, mode: InteropMode) -> Self {
        self.policy.interop = mode;
        self
    }

    pub fn outbound_key_info_profile(mut self, profile: WsSecOutboundKeyInfoProfile) -> Self {
        self.policy.outbound_key_info_profile = profile;
        self
    }

    pub fn fail_closed_audit_events(mut self, v: bool) -> Self {
        self.policy.fail_closed_audit_events = v;
        self
    }

    pub fn payload_packaging_mode(mut self, mode: PayloadPackagingMode) -> Self {
        self.policy.payload_packaging_mode = mode;
        self
    }

    pub fn sign(mut self, v: bool) -> Self {
        self.policy.sign = v;
        self
    }

    pub fn encrypt(mut self, v: bool) -> Self {
        self.policy.encrypt = v;
        self
    }

    pub fn outbound_xmlenc_payload_algorithm(mut self, v: XmlEncPayloadAlgorithm) -> Self {
        self.policy.outbound_xmlenc_payload_algorithm = v;
        self
    }

    /// Wrap the outbound `eb:Messaging` SOAP header in `xenc:EncryptedHeader`.
    pub fn encrypt_soap_headers(mut self, v: bool) -> Self {
        self.policy.encrypt_soap_headers = v;
        self
    }

    pub fn compress(mut self, v: bool) -> Self {
        self.policy.compress = v;
        self
    }

    /// Set the ebMS3 `<eb:Action>` value (default: `"urn:example:action"`).
    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.policy.action = action.into();
        self
    }

    /// Set the ebMS3 `<eb:Service>` value and optional `type` attribute.
    ///
    /// `service_type` is the `type="…"` attribute value.  Pass an empty
    /// string to omit the attribute.
    pub fn service(mut self, service: impl Into<String>, service_type: impl Into<String>) -> Self {
        self.policy.service = service.into();
        self.policy.service_type = service_type.into();
        self
    }

    /// Set `<eb:RefToMessageId>` for the **Two-Way/Push-and-Push MEP**.
    ///
    /// Pass the `message_id` from the inbound [`ParsedAs4UserMessage`] to
    /// correlate this response with the original request.
    pub fn ref_to_message_id(mut self, id: impl Into<String>) -> Self {
        self.policy.ref_to_message_id = Some(id.into());
        self
    }

    /// Set Four Corner topology `originalSender` MessageProperty override.
    pub fn original_sender(mut self, value: impl Into<String>) -> Self {
        self.policy.original_sender = Some(value.into());
        self
    }

    /// Set Four Corner topology `finalRecipient` MessageProperty override.
    pub fn final_recipient(mut self, value: impl Into<String>) -> Self {
        self.policy.final_recipient = Some(value.into());
        self
    }

    /// Set Four Corner topology `trackingIdentifier` MessageProperty override.
    pub fn tracking_identifier(mut self, value: impl Into<String>) -> Self {
        self.policy.tracking_identifier = Some(value.into());
        self
    }

    /// Set ebMS3 `<eb:ConversationId>` override.
    pub fn conversation_id(mut self, value: impl Into<String>) -> Self {
        self.policy.conversation_id = Some(value.into());
        self
    }

    /// Wrap outbound business payloads in an SBDH envelope.
    pub fn sbdh_header(mut self, header: SbdhHeader) -> Self {
        self.policy.sbdh_header = Some(header);
        self
    }

    /// Attach WS-Addressing 1.0 headers to outbound SOAP envelopes.
    ///
    /// When set, the SOAP Header block includes `wsa:MessageID`, `wsa:Action`,
    /// `wsa:To`, and (optionally) `wsa:ReplyTo`.
    ///
    /// Required for CEF strict conformance testing and deployments that route
    /// messages via SOAP intermediaries that dispatch on `wsa:Action`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use asx_rs::crypto::soap_builder::WsAddressingHeaders;
    ///
    /// let wsa = WsAddressingHeaders::new(
    ///     format!("urn:uuid:{}", uuid::Uuid::new_v4()),
    ///     "http://docs.oasis-open.org/ebxml-msg/as4/200902/action",
    ///     "https://partner-ap.example.com/as4",
    /// );
    /// let builder = As4SendPolicyBuilder::new().ws_addressing(wsa);
    /// ```
    pub fn ws_addressing(mut self, headers: WsAddressingHeaders) -> Self {
        self.policy.ws_addressing = Some(headers);
        self
    }

    pub fn signing_cert_pem(mut self, pem: Vec<u8>) -> Self {
        self.credentials.signing_cert_pem = Some(pem);
        self
    }

    pub fn signing_key_pem(mut self, pem: Vec<u8>) -> Self {
        self.credentials.signing_key_pem = Some(pem);
        self
    }

    pub fn recipient_cert_pem(mut self, pem: Vec<u8>) -> Self {
        self.credentials.recipient_cert_pem = Some(pem);
        self
    }

    /// Validate the policy–credentials combination and return both structs.
    ///
    /// # Errors
    /// - `sign = true` but `signing_cert_pem` or `signing_key_pem` is absent.
    /// - `encrypt = true` but `recipient_cert_pem` is absent.
    /// - Any supplied PEM material fails to parse.
    pub fn build(self) -> Result<(As4SendPolicy, As4SendCredentials)> {
        let stage = "as4_send_policy_build";

        validate_strict_as4_send_policy_consistency(
            stage,
            self.policy.interop,
            self.policy.sign,
            self.policy.fail_closed_audit_events,
            self.policy.payload_packaging_mode,
        )?;

        validate_as4_send_policy_and_credentials_consistency(
            stage,
            &self.policy,
            &self.credentials,
            ErrorCode::InvalidInput,
        )?;

        #[cfg(feature = "as4")]
        self.credentials
            .prepare_for_policy(&self.policy, stage, ErrorCode::InvalidInput)?;

        Ok((self.policy, self.credentials))
    }
}

/// Protocol-specific credentials for AS4 message sending (signing and encryption).
///
/// # Preferred API
///
/// For new integrations and multi-protocol deployments, prefer
/// [`PartnerCredentials`](crate::credentials::PartnerCredentials) as the primary
/// credential holder.  `PartnerCredentials` zeroizes the signing key on drop,
/// supports both AS2 and AS4 from one bundle, and provides
/// [`prepare_as4_for_policy`](crate::credentials::PartnerCredentials::prepare_as4_for_policy)
/// for single-pass parse-and-validate.
///
/// Use `As4SendCredentials` directly only when you are already in AS4-only
/// code that does not need the unified API.
#[derive(Debug, Clone, Default)]
pub struct As4SendCredentials {
    /// PEM-encoded signing certificate
    pub signing_cert_pem: Option<Vec<u8>>,
    /// PEM-encoded signing private key
    pub signing_key_pem: Option<Vec<u8>>,
    /// PEM-encoded recipient certificate for encryption
    pub recipient_cert_pem: Option<Vec<u8>>,
}

impl Drop for As4SendCredentials {
    fn drop(&mut self) {
        if let Some(key) = self.signing_key_pem.as_mut() {
            key.zeroize();
        }
    }
}

/// Output from AS4 message sending
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As4SendOutput {
    pub message_id: String,
    pub action: String,
    /// W3C Trace Context `traceparent` header to forward on HTTP egress.
    pub traceparent: Option<String>,
    /// HTTP `Content-Type` to use for transport send.
    ///
    /// `multipart/related` for MIME attachment mode.
    pub http_content_type: String,
    pub soap_envelope: SoapEnvelope,
    /// The `<eb:RefToMessageId>` value emitted in the outbound envelope, if any.
    ///
    /// Mirrors [`As4SendPolicy::ref_to_message_id`].  Callers can use this to
    /// confirm which correlation ID was embedded in the sent message.
    pub ref_to_message_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As4ReceivePushRequest {
    /// HTTP Content-Type associated with `payload`.
    pub http_content_type: String,
    pub payload: Arc<[u8]>,
    pub receipt_payload: Option<Vec<u8>>,
    pub policy: As4PushPolicy,
    /// Authenticated transport-layer sender identity for fragment group scoping.
    ///
    /// When [`FragmentScopePolicy::RequireAuthenticatedScope`] is active (the
    /// default), this field **must** be `Some` for fragment messages.  Typical
    /// values: mTLS client certificate CN, TLS peer IP, or an AP identifier
    /// verified at the transport layer **before** this request was admitted.
    ///
    /// For non-fragment (normal push) messages this field is ignored and may be
    /// `None`.
    pub authenticated_sender_scope: Option<Arc<str>>,
}

// ---------------------------------------------------------------------------
// WS-Addressing receive-path types
// ---------------------------------------------------------------------------

/// WS-Addressing headers extracted from an inbound AS4 SOAP envelope.
///
/// These are read from the `http://www.w3.org/2005/08/addressing` namespace
/// elements in the SOAP Header.  Fields are `None` when the corresponding
/// element was absent.
///
/// # Conformance note
///
/// For CEF eDelivery AS4 v1.15 strict mode, `message_id` and `action` are
/// mandatory.  `to` is strongly recommended.  Missing `message_id` or `action`
/// in strict mode triggers an `InteropPolicyViolation` error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedWsAddressingHeaders {
    /// `wsa:MessageID` — unique URI identifying this message instance.
    pub message_id: Option<String>,
    /// `wsa:Action` — SOAP action URI; should match `<eb:Action>`.
    pub action: Option<String>,
    /// `wsa:To` — intended recipient endpoint URI.
    pub to: Option<String>,
    /// `wsa:ReplyTo/wsa:Address` — reply-to endpoint, if present.
    pub reply_to: Option<String>,
}

impl ParsedWsAddressingHeaders {
    /// Returns `true` if all CEF mandatory WS-Addressing fields are present
    /// (`wsa:MessageID` and `wsa:Action`).
    #[inline]
    pub fn is_cef_conformant(&self) -> bool {
        self.message_id.is_some() && self.action.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAs4UserMessage {
    pub message_id: String,
    pub action: String,
    /// All `<eb:From>/<eb:PartyId>` values from the inbound UserMessage.
    ///
    /// ebMS3 §5.2.2.4 permits multiple `<eb:PartyId>` per party for
    /// multi-scheme identifiers (e.g., GLN + DUNS).  This `Vec` is always
    /// non-empty; the **first element** is the primary routing identifier,
    /// accessible via [`from_party_id()`][Self::from_party_id].
    pub from_party_ids: Vec<String>,
    /// All `<eb:To>/<eb:PartyId>` values from the inbound UserMessage.
    ///
    /// Always non-empty; primary routing identifier accessible via
    /// [`to_party_id()`][Self::to_party_id].
    pub to_party_ids: Vec<String>,
    pub mpc: Option<String>,
    pub conversation_id: Option<String>,
    pub has_ws_security_header: bool,
    /// `<eb:Service>` value from the inbound UserMessage's `<eb:CollaborationInfo>`.
    ///
    /// Required for P-Mode resolution and Test Service detection.
    pub service: Option<String>,
    /// Present when the inbound UserMessage carries `<eb:RefToMessageId>`.
    ///
    /// Non-`None` indicates the sender is using the **Two-Way/Push-and-Push MEP**
    /// and this message is a response correlated to the original request message.
    pub ref_to_message_id: Option<String>,
    /// Four Corner topology `originalSender` MessageProperty value.
    pub original_sender: Option<String>,
    /// Four Corner topology `finalRecipient` MessageProperty value.
    pub final_recipient: Option<String>,
    /// Four Corner topology `trackingIdentifier` MessageProperty value.
    pub tracking_identifier: Option<String>,
    /// `<eb:Timestamp>` from `<eb:MessageInfo>` in RFC 3339 / ISO 8601 format.
    ///
    /// Present on virtually all conformant AS4 messages.  When `Some`, callers
    /// should validate freshness via [`ParsedAs4UserMessage::check_timestamp_freshness`]
    /// before processing the payload.  A missing timestamp is allowed (the field is
    /// optional in ebMS3) but signals an older or non-conformant sender implementation.
    pub timestamp: Option<String>,
    /// WS-Addressing headers extracted from the inbound SOAP envelope, if present.
    ///
    /// `None` when the inbound message carries no `wsa:*` elements in the SOAP
    /// Header.  Non-`None` when at least one WS-Addressing element was present;
    /// individual fields may still be `None` if omitted by the sender.
    ///
    /// CEF strict conformance requires `wsa:MessageID` and `wsa:Action`.
    pub wsa_headers: Option<ParsedWsAddressingHeaders>,
}

impl ParsedAs4UserMessage {
    /// Returns the primary sender party identifier (first `<eb:From>/<eb:PartyId>`).
    ///
    /// For peers that advertise only a single `<eb:PartyId>` this is equivalent
    /// to the sole identifier.  When multiple scheme-specific identifiers are
    /// present (ebMS3 §5.2.2.4), this returns the first one as encountered in
    /// the XML, which is the primary routing identifier by convention.
    #[inline]
    pub fn from_party_id(&self) -> &str {
        &self.from_party_ids[0]
    }

    /// Returns the primary recipient party identifier (first `<eb:To>/<eb:PartyId>`).
    #[inline]
    pub fn to_party_id(&self) -> &str {
        &self.to_party_ids[0]
    }

    /// Validate that the `<eb:Timestamp>` is within the allowed freshness window.
    ///
    /// Per eDelivery AS4 v1.15 §5.1.3 and ebMS3 Core §6.3, the timestamp is
    /// expected to be within ±`window` of `now`.  The default recommended window
    /// is 5 minutes (300 seconds).
    ///
    /// Returns `Ok(())` when:
    /// - The timestamp is absent (lenient — a missing timestamp is warned elsewhere).
    /// - The parsed timestamp is within `[now - window, now + window]`.
    ///
    /// Returns `Err` when the timestamp is present but outside the freshness window,
    /// or when it cannot be parsed as RFC 3339.
    pub fn check_timestamp_freshness(
        &self,
        window: std::time::Duration,
    ) -> crate::core::Result<()> {
        use crate::core::{AsxError, ErrorCode, ErrorContext};

        let ts_str = match &self.timestamp {
            Some(s) => s,
            None => return Ok(()),
        };

        let ts = chrono::DateTime::parse_from_rfc3339(ts_str).map_err(|_| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("eb:Timestamp value '{ts_str}' is not a valid RFC 3339 timestamp"),
                ErrorContext::new("as4_timestamp_freshness"),
            )
        })?;

        let now = chrono::Utc::now();
        let ts_utc: chrono::DateTime<chrono::Utc> = ts.into();
        let delta = (now - ts_utc).abs();
        let window_chrono =
            chrono::Duration::from_std(window).unwrap_or(chrono::Duration::seconds(300));

        if delta > window_chrono {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!(
                    "eb:Timestamp is outside the freshness window (delta={:.0}s, allowed={}s); \
                     message rejected to prevent replay",
                    delta.num_milliseconds() as f64 / 1000.0,
                    window.as_secs(),
                ),
                ErrorContext::new("as4_timestamp_freshness")
                    .with_message_id(self.message_id.clone()),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAs4Receipt {
    pub ref_to_message_id: String,
    pub is_signed: bool,
    pub has_non_repudiation_info: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As4ReceivePushOutput {
    pub payload: DomainReady<Arc<[u8]>>,
    /// Parsed SBDH header when inbound business payload was SBDH-wrapped.
    pub sbdh_header: Option<SbdhHeader>,
    pub user_message: ParsedAs4UserMessage,
    pub receipt: Option<ParsedAs4Receipt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum As4ReceivePushProgress {
    PendingFragment {
        group_id: String,
        received_fragments: usize,
        expected_fragments: Option<usize>,
    },
    Complete(Box<As4ReceivePushOutput>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As4QueuedPullMessage {
    /// Message identifier used for overflow auditing and reconciliation.
    pub message_id: Arc<str>,
    /// Original HTTP Content-Type of the queued push payload.
    pub http_content_type: Arc<str>,
    pub payload: Arc<[u8]>,
}

/// A single `<ds:Reference>` extracted from an inbound message's XMLDSig
/// `<ds:SignedInfo>`.  Pass a slice of these to
/// [`crate::as4::generate_receipt_with_nri`] to build a conformant
/// Non-Repudiation of Origin (NRO) receipt per ebMS3 §5.2.2.1.
///
/// Obtain these values from [`crate::crypto::wssec::parse_signature_references`]
/// after verifying the inbound message signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As4NriReference {
    /// The `URI` attribute of the `<ds:Reference>` element (e.g., `"#body"`).
    pub uri: String,
    /// The `Algorithm` attribute of `<ds:DigestMethod>`.
    pub digest_method_uri: String,
    /// The base64-encoded digest value from `<ds:DigestValue>`.
    pub digest_value_b64: String,
}

impl From<&WsSecSignatureReference> for As4NriReference {
    /// Convert a [`WsSecSignatureReference`] (from `parse_signature_references`)
    /// directly into an [`As4NriReference`] suitable for
    /// [`crate::as4::generate_receipt_with_nri`].
    fn from(r: &WsSecSignatureReference) -> Self {
        Self {
            uri: r.uri.clone(),
            digest_method_uri: r.digest_method.algorithm_uri().to_string(),
            digest_value_b64: r.digest_value_base64.clone(),
        }
    }
}

impl From<WsSecSignatureReference> for As4NriReference {
    /// Convert an owned [`WsSecSignatureReference`] into an [`As4NriReference`]
    /// while reusing owned string buffers where possible.
    fn from(r: WsSecSignatureReference) -> Self {
        Self {
            uri: r.uri,
            digest_method_uri: r.digest_method.algorithm_uri().to_string(),
            digest_value_b64: r.digest_value_base64,
        }
    }
}

/// Credentials required to generate a signed AS4 `PullRequest` signal.
///
/// Per eDelivery AS4 v1.15 §4.5.5, pull requests MUST be signed using the
/// signing certificate of the Receiver Party.
#[derive(Debug, Clone)]
pub struct As4PullRequestCredentials {
    /// PEM-encoded RSA private key used to sign the pull request signal.
    pub signing_key_pem: Vec<u8>,
    /// PEM-encoded X.509 certificate corresponding to `signing_key_pem`.
    pub signing_cert_pem: Vec<u8>,
    /// Key-info profile controlling how the signing certificate appears in
    /// the `<ds:KeyInfo>` element of the generated XML signature.
    pub key_info_profile: WsSecOutboundKeyInfoProfile,
}

impl Drop for As4PullRequestCredentials {
    fn drop(&mut self) {
        self.signing_key_pem.zeroize();
    }
}

/// Parameters for [`crate::as4::generate_pull_request`].
#[derive(Debug, Clone)]
pub struct As4GeneratePullRequestPolicy {
    /// The Message Partition Channel to pull from.
    pub mpc: String,
    /// A unique message ID for this pull request signal.  Must conform to
    /// the ebMS3 message-ID format (typically a UUID or RFC 2822 msg-id).
    pub message_id: String,
    /// Optional signing credentials.  When `Some`, a WS-Security XML Signature
    /// is added per eDelivery AS4 v1.15 §4.5.5.  When `None`, the pull request
    /// is unsigned (permitted only when the trading-partner agreement explicitly
    /// opts out of pull-request signing).
    pub credentials: Option<As4PullRequestCredentials>,
    /// Optional `<eb:AuthorizationInfo>` token per ebMS3 §5.2.3.1.  Required
    /// by pull sub-profiles (e.g., CEF eDelivery pull profile) that mandate pull
    /// authorization via a shared secret or token.
    pub authorization_info: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As4PullPolicy {
    pub interop: InteropMode,
    pub mpc: String,
    pub interop_exceptions: InteropExceptionPolicy,
    pub require_signed_receipt: bool,
    #[doc(hidden)]
    pub(crate) require_signed_push: bool,
    /// When `true` (the default), protocol event emission failures fail the
    /// pull receive operation (fail-closed audit semantics).
    pub fail_closed_audit_events: bool,
    /// When `Some`, the pull receive path enforces that the incoming
    /// `<eb:AuthorizationInfo>` element matches this exact value (constant-time
    /// comparison).  A mismatch yields [`ErrorCode::SecurityVerificationFailed`].
    ///
    /// When `None`, no `AuthorizationInfo` check is performed — **any caller
    /// can pull messages from this MPC partition without authentication**.
    ///
    /// # ⚠ Security: unauthenticated pull access
    ///
    /// Per ebMS3 §5.2.3.1, `eb:PullRequest/eb:AuthorizationInfo` is optional
    /// at the protocol level, but that flexibility was designed for deployments
    /// where the transport layer (e.g., mTLS) owns the pull authorisation
    /// boundary.  Without mTLS or `expected_authorization_info`, the pull
    /// endpoint is effectively open to any party that knows the MPC URI.
    ///
    /// **Regulated networks (PEPPOL, CEF eDelivery) require pull authentication.**
    /// Set this field to a random, high-entropy secret shared with the pulling
    /// party, or enforce pull access via mTLS at the reverse proxy / load
    /// balancer before the request reaches this library.
    pub expected_authorization_info: Option<String>,
}

const DEFAULT_MPC: &str =
    "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/defaultMPC";

impl Default for As4PullPolicy {
    fn default() -> Self {
        Self {
            interop: InteropMode::Strict,
            mpc: String::from(DEFAULT_MPC),
            interop_exceptions: InteropExceptionPolicy::default(),
            require_signed_receipt: true,
            require_signed_push: true,
            fail_closed_audit_events: true,
            expected_authorization_info: None,
        }
    }
}

impl As4PullPolicy {
    /// Return the recommended production-safe pull policy preset.
    pub fn strict() -> Self {
        Self::default()
    }

    /// Return the regulated deployment preset for pull receive.
    ///
    /// This preset is fail-closed and requires signed pulled messages and
    /// signed receipts in strict interop mode.
    pub fn regulated() -> Self {
        Self {
            interop: InteropMode::Strict,
            mpc: String::from(DEFAULT_MPC),
            interop_exceptions: InteropExceptionPolicy::default(),
            require_signed_receipt: true,
            require_signed_push: true,
            fail_closed_audit_events: true,
            expected_authorization_info: None,
        }
    }

    /// Return whether pulled user messages must carry a valid signature.
    pub fn require_signed_push(&self) -> bool {
        self.require_signed_push
    }
}

/// Fluent builder for [`As4PullPolicy`].
#[derive(Default)]
pub struct As4PullPolicyBuilder(As4PullPolicy);

impl As4PullPolicyBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn interop(mut self, mode: InteropMode) -> Self {
        self.0.interop = mode;
        self
    }

    pub fn mpc(mut self, mpc: impl Into<String>) -> Self {
        self.0.mpc = mpc.into();
        self
    }

    pub fn interop_exceptions(mut self, exc: InteropExceptionPolicy) -> Self {
        self.0.interop_exceptions = exc;
        self
    }

    pub fn require_signed_receipt(mut self, v: bool) -> Self {
        self.0.require_signed_receipt = v;
        self
    }

    /// Override the default signature requirement for pulled user messages.
    ///
    /// # Security
    ///
    /// **Testing-only escape hatch.** Disabling this in production weakens
    /// trust guarantees for received AS4 user messages.
    #[cfg(feature = "testing")]
    pub fn allow_unsigned_push(mut self, allow: bool) -> Self {
        self.0.require_signed_push = !allow;
        self
    }

    pub fn fail_closed_audit_events(mut self, v: bool) -> Self {
        self.0.fail_closed_audit_events = v;
        self
    }

    pub fn expected_authorization_info(mut self, auth: Option<String>) -> Self {
        self.0.expected_authorization_info = auth;
        self
    }

    pub fn build(self) -> Result<As4PullPolicy> {
        let stage = "as4_pull_policy_build";

        validate_strict_as4_policy_consistency(stage, self.0.interop, &self.0.interop_exceptions)?;

        validate_strict_as4_receive_policy_consistency(
            stage,
            self.0.interop,
            self.0.require_signed_receipt,
            self.0.fail_closed_audit_events,
        )?;

        if self.0.mpc.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "As4PullPolicy.mpc must not be empty",
                ErrorContext::new(stage),
            ));
        }

        if let Some(ref auth) = self.0.expected_authorization_info
            && auth.trim().is_empty()
        {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "As4PullPolicy.expected_authorization_info must not be empty when set",
                ErrorContext::new(stage),
            ));
        }

        Ok(self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As4ReceivePullRequest {
    pub pull_message_id: String,
    pub policy: As4PullPolicy,
    pub receipt_payload: Option<Vec<u8>>,
    /// The `<eb:AuthorizationInfo>` value extracted from the incoming `<eb:PullRequest>`
    /// element, if present.  Matched against `policy.expected_authorization_info` when
    /// that field is `Some`.
    pub authorization_info: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As4ReceivePullOutput {
    pub pull_message_id: Arc<str>,
    pub correlation_message_id: Option<Arc<str>>,
    pub mpc: Arc<str>,
    pub duplicate_retrieval: bool,
    pub pulled: Option<Arc<As4ReceivePushOutput>>,
    pub outcome: DeliveryOutcome,
    pub retry: RetryDecision,
}

// ── Signal types ─────────────────────────────────────────────────────────────

/// AS4 error signal error codes per ebMS3 specification §6.7.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum As4ErrorCode {
    /// EBMS:0001 — Value not recognised.
    ValueNotRecognized,
    /// EBMS:0002 — Feature not supported.
    FeatureNotSupported,
    /// EBMS:0003 — Value inconsistent.
    ValueInconsistent,
    /// EBMS:0004 — Other.
    Other,
    /// EBMS:0301 — Missing receipt.
    MissingReceipt,
    /// EBMS:0302 — Invalid receipt.
    InvalidReceipt,
    /// EBMS:0303 — Decompression failure.
    DecompressionFailure,
}

impl As4ErrorCode {
    /// Returns the OASIS-defined `errorCode` attribute string, e.g. `"EBMS:0001"`.
    pub fn ebms_code(self) -> &'static str {
        match self {
            As4ErrorCode::ValueNotRecognized => "EBMS:0001",
            As4ErrorCode::FeatureNotSupported => "EBMS:0002",
            As4ErrorCode::ValueInconsistent => "EBMS:0003",
            As4ErrorCode::Other => "EBMS:0004",
            As4ErrorCode::MissingReceipt => "EBMS:0301",
            As4ErrorCode::InvalidReceipt => "EBMS:0302",
            As4ErrorCode::DecompressionFailure => "EBMS:0303",
        }
    }
}

/// Error severity for AS4 Error signal messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum As4ErrorSeverity {
    /// Processing must stop; the message cannot be delivered.
    Failure,
    /// Processing may continue but the sender should be aware.
    Warning,
}

impl As4ErrorSeverity {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            As4ErrorSeverity::Failure => "Failure",
            As4ErrorSeverity::Warning => "Warning",
        }
    }
}
