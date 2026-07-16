//! P-Mode (Processing Mode) registry for AS4 trading partner configuration.
//!
//! In ebMS3, a **P-Mode** specifies the complete protocol configuration for a
//! trading relationship: MEP, security, service/action URIs, payload packaging,
//! and reliability settings.  This module provides a [`PMode`] struct and a
//! [`PModeRegistry`] that resolves policies by partner identifier and service/action.
//!
//! ## Payload Packaging Modes
//!
//! ASX supports strict payload packaging:
//!
//! - **`MimeAttachment`**: payloads as MIME multipart/related
//!   attachments with Content-ID references. Required by PEPPOL/CEF AP networks
//!   for strict-profile conformance.
//!
//! P-Mode resolution is used to derive [`super::As4SendPolicy`] settings
//! automatically from the registry rather than hard-coding them per call.
//!
//! ## Example
//!
//! ```rust
//! # use asx_rs::as4::pmode::{PModeRegistry, PMode, MepType, PModeSecurity, PayloadPackagingMode};
//! let mut registry = PModeRegistry::new();
//!
//! registry.register(PMode {
//!     id: "pm-invoicing-partner-a".into(),
//!     partner_id: "partner-a".into(),
//!     service: "urn:service:invoicing".into(),
//!     service_type: "".into(),
//!     action: "urn:action:submit".into(),
//!     mep: MepType::OneWayPush,
//!     security: PModeSecurity {
//!         sign: true, encrypt: true, encrypt_soap_headers: false, compress: false,
//!         ..Default::default()
//!     },
//!     payload_packaging: PayloadPackagingMode::MimeAttachment,
//!     endpoint_url: Some("https://partner-a.example.com/as4".into()),
//! });
//!
//! let pm = registry.resolve("partner-a", "urn:service:invoicing", "urn:action:submit");
//! assert!(pm.is_some());
//! assert_eq!(pm.unwrap().id, "pm-invoicing-partner-a");
//! ```

use super::{As4SendPolicy, As4SendPolicyBuilder};
use crate::core::{AsxError, ErrorCode, ErrorContext, InteropMode, Result};

/// Payload packaging strategy for AS4 messages.
///
/// Controls how payloads are packaged in outbound AS4 messages.
///
/// # Supported Modes
///
/// Currently only [`MimeAttachment`] (MIME multipart/related with XOP `cid:` references)
/// is fully implemented for both sending and receiving.
///
/// # Inline SOAP Body Mode (Not Implemented)
///
/// The ebMS3 Core specification also allows payloads to be placed directly in the SOAP
/// body element (inline body packaging). This mode is **not implemented** in ASX:
///
/// - Inbound inline-body AS4 messages are rejected with [`ErrorCode::InteropViolation`]
///   and an explicit diagnostic message.
/// - Outbound: no inline-body variant exists; use `MimeAttachment` for all AP networks.
///
/// PEPPOL and CEF eDelivery mandate MIME attachment mode; inline body is rarely used
/// in production B2B networks. If you need to communicate with a partner that requires
/// inline body packaging, please open an issue.
///
/// [`ErrorCode::InteropViolation`]: crate::core::ErrorCode::InteropViolation
/// [`MimeAttachment`]: PayloadPackagingMode::MimeAttachment
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum PayloadPackagingMode {
    /// Use MIME multipart/related attachments (PEPPOL/CEF).
    ///
    /// Payloads are transmitted as MIME attachments with Content-ID references,
    /// conforming to OpenPeppol AS4 profile v2.0 and CEF eDelivery AS4 profile.
    /// Required for strict AP networks and PEPPOL/CEF deployments.
    #[default]
    MimeAttachment,
}

/// ebMS3 Message Exchange Pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum MepType {
    /// ebMS3 One-Way/Push — sender pushes; no response UserMessage on this P-Mode.
    #[default]
    OneWayPush,
    /// ebMS3 One-Way/Pull — receiver polls the sender's pull store for messages.
    OneWayPull,
    /// ebMS3 Two-Way/Push-and-Push — initiator pushes; responder replies with a push.
    TwoWayPushPush,
}

/// Security policy within a P-Mode.
///
/// Maps to the `PMode[].Security` parameter set defined in ebMS3 Core §6.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PModeSecurity {
    /// Whether outbound messages on this P-Mode must be signed.
    pub sign: bool,
    /// Whether outbound messages on this P-Mode must be encrypted.
    pub encrypt: bool,
    /// Whether the SOAP `eb:Messaging` header must be wrapped in
    /// `xenc:EncryptedHeader` before transport.
    pub encrypt_soap_headers: bool,
    /// Whether payloads should be compressed before signing (RFC 5402).
    pub compress: bool,
    /// WS-Security outbound `ds:KeyInfo` token profile.
    ///
    /// Controls the form of the signing certificate reference emitted in the
    /// outbound WS-Security `<ds:KeyInfo>` element:
    ///
    /// | Variant | Token type | Networks |
    /// |---|---|---|
    /// | `X509DataAndRsaKeyValue` | `<ds:X509Data>` + `<ds:RSAKeyValue>` (default) | PEPPOL (RSA) |
    /// | `X509DataOnly` | `<ds:X509Data>` only | General AS4, EC keys |
    /// | `X509PKIPathv1` | `wsse:BinarySecurityToken` + `SecurityTokenReference` | BDEW AS4-Profil §2.2.6.2.1 |
    ///
    /// For BDEW / BSI TR-03116-3 deployments set this to
    /// [`WsSecOutboundKeyInfoProfile::X509PKIPathv1`].
    pub outbound_key_info_profile: crate::crypto::wssec::WsSecOutboundKeyInfoProfile,
}

impl Default for PModeSecurity {
    fn default() -> Self {
        Self {
            sign: true,
            encrypt: false,
            encrypt_soap_headers: false,
            compress: false,
            outbound_key_info_profile: crate::crypto::wssec::WsSecOutboundKeyInfoProfile::default(),
        }
    }
}

/// P-Mode — per-trading-partner agreement configuration.
///
/// A P-Mode fully specifies the protocol parameters for sending messages to
/// (or receiving messages from) a named trading partner on a specific
/// service/action combination.
///
/// P-Modes are stored in a [`PModeRegistry`] and resolved at send-time.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PMode {
    /// Globally unique P-Mode identifier (e.g., `"pm-001"` or a URN).
    pub id: String,
    /// Remote party identifier — the partner's `<eb:PartyId>` value.
    pub partner_id: String,
    /// ebMS3 `<eb:Service>` URI agreed with the trading partner.
    pub service: String,
    /// ebMS3 `<eb:Service type="…">` attribute value.  Empty string omits the attribute.
    pub service_type: String,
    /// ebMS3 `<eb:Action>` URI agreed with the trading partner.
    pub action: String,
    /// Message Exchange Pattern.
    pub mep: MepType,
    /// Security policy.
    pub security: PModeSecurity,
    /// Payload packaging mode (strict MIME attachment packaging).
    pub payload_packaging: PayloadPackagingMode,
    /// ebMS3 `PMode[1].Protocol.Address` — outbound endpoint URL for this P-Mode.
    ///
    /// When `Some`, send pipelines can retrieve the endpoint directly from the
    /// P-Mode registration, eliminating the need for a separate partner-address
    /// registry.  Startup validation
    /// (`presets::validate_strict_production_topology`) will assert that all
    /// outbound P-Modes have a non-`None` endpoint URL when present.
    ///
    /// `None` preserves the existing behaviour where the endpoint URL is
    /// supplied by the caller at send-time (e.g. from a separate
    /// `PartnerDirectory` lookup).  Keeping this field `None` is safe for
    /// deployments that resolve endpoints through other means.
    pub endpoint_url: Option<String>,
}

impl PMode {
    fn validate_strict_policy_materialization(&self, stage: &'static str) -> Result<()> {
        fn require_non_empty(value: &str, field: &'static str, stage: &'static str) -> Result<()> {
            if value.trim().is_empty() {
                return Err(AsxError::new(
                    ErrorCode::InvalidInput,
                    format!("P-Mode {field} must not be empty"),
                    ErrorContext::new(stage),
                ));
            }
            Ok(())
        }

        require_non_empty(&self.id, "id", stage)?;
        require_non_empty(&self.partner_id, "partner_id", stage)?;
        require_non_empty(&self.service, "service", stage)?;
        require_non_empty(&self.action, "action", stage)?;

        if let Some(url) = &self.endpoint_url {
            if url.trim().is_empty() {
                return Err(AsxError::new(
                    ErrorCode::InvalidInput,
                    "P-Mode endpoint_url must not be empty when Some; use None to omit",
                    ErrorContext::new(stage),
                ));
            }
            #[cfg(not(feature = "testing"))]
            if !url.starts_with("https://") {
                return Err(AsxError::new(
                    ErrorCode::PolicyViolation,
                    format!(
                        "P-Mode endpoint_url must use the HTTPS scheme (eDelivery AS4 §4.1); \
                         got: {url}"
                    ),
                    ErrorContext::new(stage),
                ));
            }
        }

        #[cfg(not(feature = "testing"))]
        if !self.security.sign {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "P-Mode materialization forbids sign=false in non-testing builds",
                ErrorContext::new(stage),
            ));
        }

        Ok(())
    }

    /// Derive a base [`As4SendPolicyBuilder`] from this P-Mode.
    ///
    /// The returned builder is pre-configured with `sign`, `encrypt`, `compress`,
    /// `action`, `service`, and `service_type` from this P-Mode.  Callers add
    /// credentials and any per-message overrides before calling `.build()`.
    ///
    /// # Example
    /// ```rust
    /// # use asx_rs::as4::pmode::{PMode, MepType, PModeSecurity, PayloadPackagingMode};
    /// let pm = PMode {
    ///     id: "pm-1".into(), partner_id: "p1".into(),
    ///     service: "urn:svc".into(), service_type: "".into(),
    ///     action: "urn:act".into(), mep: MepType::OneWayPush,
    ///     security: PModeSecurity {
    ///         sign: false, encrypt: false, encrypt_soap_headers: false, compress: false,
    ///         ..Default::default()
    ///     },
    ///     payload_packaging: PayloadPackagingMode::MimeAttachment,
    ///     endpoint_url: None,
    /// };
    /// let _policy_builder = pm.to_send_policy_builder();
    /// // Caller would then add credentials and call .build()
    /// ```
    pub fn to_send_policy_builder(&self) -> As4SendPolicyBuilder {
        As4SendPolicyBuilder::new()
            .interop(InteropMode::Strict)
            .sign(self.security.sign)
            .encrypt(self.security.encrypt)
            .encrypt_soap_headers(self.security.encrypt_soap_headers)
            .compress(self.security.compress)
            .payload_packaging_mode(self.payload_packaging)
            .outbound_key_info_profile(self.security.outbound_key_info_profile)
            .action(&self.action)
            .service(&self.service, &self.service_type)
    }

    /// Derive a fully-specified [`As4SendPolicy`] from this P-Mode (no credentials).
    ///
    /// Useful for building receive-side policies from a P-Mode registration.
    pub fn to_send_policy(&self) -> Result<As4SendPolicy> {
        self.validate_strict_policy_materialization("as4_pmode_to_send_policy")?;

        Ok(As4SendPolicy {
            interop: InteropMode::Strict,
            sign: self.security.sign,
            encrypt: self.security.encrypt,
            encrypt_soap_headers: self.security.encrypt_soap_headers,
            compress: self.security.compress,
            action: self.action.clone(),
            service: self.service.clone(),
            service_type: self.service_type.clone(),
            payload_packaging_mode: self.payload_packaging,
            outbound_key_info_profile: self.security.outbound_key_info_profile,
            ..As4SendPolicy::default()
        })
    }

    /// Consume this P-Mode and derive a fully-specified [`As4SendPolicy`]
    /// without cloning owned string fields.
    pub fn into_send_policy(self) -> Result<As4SendPolicy> {
        self.validate_strict_policy_materialization("as4_pmode_into_send_policy")?;

        Ok(As4SendPolicy {
            interop: InteropMode::Strict,
            sign: self.security.sign,
            encrypt: self.security.encrypt,
            encrypt_soap_headers: self.security.encrypt_soap_headers,
            compress: self.security.compress,
            action: self.action,
            service: self.service,
            service_type: self.service_type,
            payload_packaging_mode: self.payload_packaging,
            outbound_key_info_profile: self.security.outbound_key_info_profile,
            ..As4SendPolicy::default()
        })
    }
}

/// Registry of P-Modes keyed by partner ID and service/action.
///
/// Resolution is **first-match**; register more-specific P-Modes before
/// catch-all fallbacks.
///
/// Thread safety: [`PModeRegistry`] is immutable after construction.  Build
/// it once at startup, then share via `Arc<PModeRegistry>`.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct PModeRegistry {
    modes: Vec<PMode>,
}

impl PModeRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a P-Mode.  Modes are evaluated in registration order.
    pub fn register(&mut self, mode: PMode) {
        self.modes.push(mode);
    }

    /// Resolve the first P-Mode matching `partner_id`, `service`, **and** `action`.
    ///
    /// Returns `None` when no matching P-Mode is registered.
    pub fn resolve(&self, partner_id: &str, service: &str, action: &str) -> Option<&PMode> {
        self.modes
            .iter()
            .find(|m| m.partner_id == partner_id && m.service == service && m.action == action)
    }

    /// Resolve the first P-Mode matching `partner_id` and `action` (any service).
    pub fn resolve_by_action(&self, partner_id: &str, action: &str) -> Option<&PMode> {
        self.modes
            .iter()
            .find(|m| m.partner_id == partner_id && m.action == action)
    }

    /// Resolve a P-Mode by its unique [`PMode::id`].
    pub fn resolve_by_id(&self, id: &str) -> Option<&PMode> {
        self.modes.iter().find(|m| m.id == id)
    }

    /// Resolve the first P-Mode matching `partner_id` for the given MEP.
    pub fn resolve_by_mep(&self, partner_id: &str, mep: MepType) -> Option<&PMode> {
        self.modes
            .iter()
            .find(|m| m.partner_id == partner_id && m.mep == mep)
    }

    /// All registered P-Modes.
    pub fn all(&self) -> &[PMode] {
        &self.modes
    }

    /// Number of registered P-Modes.
    pub fn len(&self) -> usize {
        self.modes.len()
    }

    /// Returns `true` when no P-Modes are registered.
    pub fn is_empty(&self) -> bool {
        self.modes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ErrorCode;

    fn pmode(id: &str, partner: &str, svc: &str, action: &str, mep: MepType) -> PMode {
        PMode {
            id: id.into(),
            partner_id: partner.into(),
            service: svc.into(),
            service_type: "".into(),
            action: action.into(),
            mep,
            security: PModeSecurity::default(),
            payload_packaging: PayloadPackagingMode::default(),
            endpoint_url: None,
        }
    }

    #[test]
    fn resolve_matches_all_three_dimensions() {
        let mut reg = PModeRegistry::new();
        reg.register(pmode("pm-1", "p1", "svc:a", "act:x", MepType::OneWayPush));
        reg.register(pmode("pm-2", "p1", "svc:b", "act:y", MepType::OneWayPull));

        assert_eq!(
            reg.resolve("p1", "svc:a", "act:x").map(|p| p.id.as_str()),
            Some("pm-1")
        );
        assert_eq!(
            reg.resolve("p1", "svc:b", "act:y").map(|p| p.id.as_str()),
            Some("pm-2")
        );
        assert!(
            reg.resolve("p1", "svc:a", "act:y").is_none(),
            "wrong action"
        );
        assert!(
            reg.resolve("p2", "svc:a", "act:x").is_none(),
            "wrong partner"
        );
    }

    #[test]
    fn resolve_by_id_returns_correct_pmode() {
        let mut reg = PModeRegistry::new();
        reg.register(pmode("pm-abc", "p1", "svc", "act", MepType::OneWayPush));
        assert_eq!(
            reg.resolve_by_id("pm-abc").map(|p| p.id.as_str()),
            Some("pm-abc")
        );
        assert!(reg.resolve_by_id("pm-xyz").is_none());
    }

    #[test]
    fn resolve_by_mep_returns_first_match() {
        let mut reg = PModeRegistry::new();
        reg.register(pmode("pm-1", "p1", "svc", "act1", MepType::OneWayPull));
        reg.register(pmode("pm-2", "p1", "svc", "act2", MepType::TwoWayPushPush));

        assert_eq!(
            reg.resolve_by_mep("p1", MepType::TwoWayPushPush)
                .map(|p| p.id.as_str()),
            Some("pm-2")
        );
        assert!(reg.resolve_by_mep("p1", MepType::OneWayPush).is_none());
    }

    #[test]
    fn payload_packaging_modes_default_and_explicit() {
        assert_eq!(
            PayloadPackagingMode::default(),
            PayloadPackagingMode::MimeAttachment
        );
        let mime = PayloadPackagingMode::MimeAttachment;
        assert_eq!(mime, PayloadPackagingMode::MimeAttachment);
    }

    #[test]
    fn pmode_preserves_payload_packaging_mode() {
        let mut pmode_mime = pmode("pm-m", "p1", "svc", "act", MepType::OneWayPush);
        pmode_mime.payload_packaging = PayloadPackagingMode::MimeAttachment;

        assert_eq!(
            pmode_mime.payload_packaging,
            PayloadPackagingMode::MimeAttachment
        );
    }

    #[test]
    fn pmode_to_send_policy_builder_sets_fields() {
        let pm = pmode(
            "pm-1",
            "p1",
            "urn:svc:invoice",
            "urn:act:submit",
            MepType::OneWayPush,
        );
        let policy = pm
            .to_send_policy()
            .expect("strict-compatible P-Mode must materialize");
        assert_eq!(policy.action, "urn:act:submit");
        assert_eq!(policy.service, "urn:svc:invoice");
        assert!(policy.sign);
        assert_eq!(policy.interop, InteropMode::Strict);
        assert!(policy.fail_closed_audit_events);
    }

    #[test]
    fn pmode_into_send_policy_sets_fields() {
        let pm = pmode(
            "pm-1",
            "p1",
            "urn:svc:invoice",
            "urn:act:submit",
            MepType::OneWayPush,
        );
        let policy = pm
            .into_send_policy()
            .expect("strict-compatible P-Mode must materialize");
        assert_eq!(policy.action, "urn:act:submit");
        assert_eq!(policy.service, "urn:svc:invoice");
        assert_eq!(
            policy.payload_packaging_mode,
            PayloadPackagingMode::MimeAttachment
        );
        assert_eq!(policy.interop, InteropMode::Strict);
        assert!(policy.fail_closed_audit_events);
    }

    #[test]
    fn pmode_to_send_policy_accepts_strict_only_wssec_profile() {
        let pm = pmode(
            "pm-1",
            "p1",
            "urn:svc:invoice",
            "urn:act:submit",
            MepType::OneWayPush,
        );

        let policy = pm
            .to_send_policy()
            .expect("strict P-Mode materialization with strict-only profile must succeed");

        assert_eq!(policy.interop, InteropMode::Strict);
    }

    #[test]
    fn pmode_into_send_policy_accepts_strict_only_wssec_profile() {
        let pm = pmode(
            "pm-1",
            "p1",
            "urn:svc:invoice",
            "urn:act:submit",
            MepType::OneWayPush,
        );

        let policy = pm
            .into_send_policy()
            .expect("strict P-Mode consume materialization with strict-only profile must succeed");

        assert_eq!(policy.interop, InteropMode::Strict);
    }

    #[test]
    fn registry_is_empty_when_new() {
        let reg = PModeRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn to_send_policy_rejects_empty_required_fields() {
        let mut pm = pmode(
            "pm-1",
            "p1",
            "urn:svc:invoice",
            "urn:act:submit",
            MepType::OneWayPush,
        );
        pm.action = "   ".into();

        let err = pm
            .to_send_policy()
            .expect_err("empty action must fail strict materialization");

        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("action"));
    }

    #[cfg(not(feature = "testing"))]
    #[test]
    fn to_send_policy_rejects_unsigned_strict_materialization() {
        let mut pm = pmode(
            "pm-1",
            "p1",
            "urn:svc:invoice",
            "urn:act:submit",
            MepType::OneWayPush,
        );
        pm.security.sign = false;

        let err = pm
            .to_send_policy()
            .expect_err("strict materialization with sign=false must fail in non-testing builds");

        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("sign=false"));
    }

    #[test]
    fn outbound_key_info_profile_propagated_through_to_send_policy() {
        use crate::crypto::wssec::WsSecOutboundKeyInfoProfile;

        let mut pm = pmode("pm-kip", "p1", "urn:svc", "urn:act", MepType::OneWayPush);
        pm.security.outbound_key_info_profile = WsSecOutboundKeyInfoProfile::X509PKIPathv1;

        let policy = pm
            .to_send_policy()
            .expect("P-Mode with X509PKIPathv1 must materialise");

        assert_eq!(
            policy.outbound_key_info_profile,
            WsSecOutboundKeyInfoProfile::X509PKIPathv1,
            "X509PKIPathv1 must be forwarded from PModeSecurity to As4SendPolicy"
        );
    }

    #[test]
    fn outbound_key_info_profile_propagated_through_into_send_policy() {
        use crate::crypto::wssec::WsSecOutboundKeyInfoProfile;

        let mut pm = pmode("pm-kip2", "p1", "urn:svc", "urn:act", MepType::OneWayPush);
        pm.security.outbound_key_info_profile = WsSecOutboundKeyInfoProfile::X509DataOnly;

        let policy = pm
            .into_send_policy()
            .expect("P-Mode with X509DataOnly must materialise");

        assert_eq!(
            policy.outbound_key_info_profile,
            WsSecOutboundKeyInfoProfile::X509DataOnly,
        );
    }

    #[test]
    fn outbound_key_info_profile_propagated_through_to_send_policy_builder() {
        use crate::crypto::wssec::WsSecOutboundKeyInfoProfile;

        let mut pm = pmode("pm-kip3", "p1", "urn:svc", "urn:act", MepType::OneWayPush);
        pm.security.outbound_key_info_profile = WsSecOutboundKeyInfoProfile::X509PKIPathv1;

        // Build manually since we don't have credentials here.
        let builder = pm.to_send_policy_builder();

        // Verify the builder was initialised with the correct profile by building a relaxed policy.
        #[cfg(feature = "testing")]
        {
            use crate::core::InteropMode;
            let policy = builder
                .interop(InteropMode::Relaxed)
                .sign(false)
                .fail_closed_audit_events(false)
                .action("urn:act")
                .service("urn:svc", "")
                .build()
                .expect("relaxed build must succeed");

            assert_eq!(
                policy.0.outbound_key_info_profile,
                WsSecOutboundKeyInfoProfile::X509PKIPathv1,
                "builder must carry X509PKIPathv1 from PModeSecurity"
            );
        }
    }

    #[test]
    fn pmode_security_default_uses_x509_data_and_rsa_key_value() {
        use crate::crypto::wssec::WsSecOutboundKeyInfoProfile;
        let sec = PModeSecurity::default();
        assert_eq!(
            sec.outbound_key_info_profile,
            WsSecOutboundKeyInfoProfile::X509DataAndRsaKeyValue,
            "default profile must be X509DataAndRsaKeyValue for backward compat"
        );
    }
}
