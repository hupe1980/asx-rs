use std::fmt;

use crate::core::{AsxError, ErrorCode, ErrorContext, InteropMode, Result, SessionContext};
use serde::{Deserialize, Serialize};

#[cfg(feature = "as4")]
use crate::crypto::wssec::WsSecCanonicalizationProfile;

#[cfg(not(feature = "as4"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WsSecCanonicalizationKind {
    Exclusive,
    Inclusive,
}

#[cfg(not(feature = "as4"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsSecCanonicalizationProfile {
    pub kind: WsSecCanonicalizationKind,
    pub include_comments: bool,
    pub inclusive_ns_prefixes: Vec<String>,
}

#[cfg(not(feature = "as4"))]
impl Default for WsSecCanonicalizationProfile {
    fn default() -> Self {
        Self {
            kind: WsSecCanonicalizationKind::Exclusive,
            include_comments: false,
            inclusive_ns_prefixes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalizationPolicy {
    pub wssec: WsSecCanonicalizationProfile,
    pub normalize_mime_headers: bool,
}

impl Default for CanonicalizationPolicy {
    fn default() -> Self {
        Self {
            wssec: WsSecCanonicalizationProfile::default(),
            normalize_mime_headers: true,
        }
    }
}

/// One of the two message-level protections a [`SecurityPolicy`] can require.
///
/// Used to name *which* requirement a layer dropped, so that validation
/// diagnostics can say `require_encryption` rather than dumping two booleans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecurityRequirement {
    /// WS-Security XML Signature (AS4) / CMS signature (AS2).
    Signature,
    /// XML Encryption (AS4) / CMS enveloped-data (AS2).
    Encryption,
}

impl SecurityRequirement {
    /// Field name of this requirement on [`SecurityPolicy`].
    ///
    /// Chosen to match the struct field exactly so operators can grep a
    /// validation message straight into their profile configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signature => "require_signature",
            Self::Encryption => "require_encryption",
        }
    }

    /// Both requirements, in declaration order.
    pub const ALL: [Self; 2] = [Self::Signature, Self::Encryption];
}

impl fmt::Display for SecurityRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Message-level protections a profile layer requires.
///
/// # This is independent of [`InteropMode`]
///
/// Neither the `interop-strict` Cargo feature nor [`InteropMode::Strict`]
/// implies a strict *security* policy. Interop mode governs header handling and
/// ambiguity tolerance; `SecurityPolicy` governs whether messages must be signed
/// and encrypted. A profile can be `InteropMode::Strict` and still resolve to
/// `require_encryption: false` — the two axes never constrain each other.
///
/// What does constrain the security axis is the profile's
/// [security floor](BaseProfile::security_floor), which
/// [`ProfileStack::validate`] enforces against every resolved layer.
///
/// # Lattice ordering
///
/// A policy is *stronger* than another when it requires everything the other
/// requires and possibly more. [`Self::satisfies`] is that partial order,
/// [`Self::strengthen`] its join, and [`Self::weaken`] its meet. Both defaults
/// are `true`, so the fail-closed policy is also the strongest one.
///
/// ```
/// use asx_rs::interop::{SecurityPolicy, SecurityRequirement};
///
/// let floor = SecurityPolicy::SIGN_AND_ENCRYPT;
/// let partner = SecurityPolicy::SIGN_ONLY;
///
/// assert!(!partner.satisfies(floor));
/// assert_eq!(floor.unmet_by(partner), vec![SecurityRequirement::Encryption]);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub require_signature: bool,
    pub require_encryption: bool,
}

impl SecurityPolicy {
    /// Sign *and* encrypt — the fail-closed policy, and what
    /// [`Default::default`] yields.
    ///
    /// Mandated by PEPPOL, CEF eDelivery and BDEW AS4-Profil v1.2 §2.2.6.2.2,
    /// so it is also the default [security floor](BaseProfile::security_floor).
    pub const SIGN_AND_ENCRYPT: Self = Self {
        require_signature: true,
        require_encryption: true,
    };

    /// Signature required, encryption optional.
    pub const SIGN_ONLY: Self = Self {
        require_signature: true,
        require_encryption: false,
    };

    /// Encryption required, signature optional.
    pub const ENCRYPT_ONLY: Self = Self {
        require_signature: false,
        require_encryption: true,
    };

    /// Neither protection required.
    ///
    /// Only meaningful as a *floor* (meaning "impose nothing beyond the
    /// per-layer checks"). As an effective policy it is rejected by
    /// [`ProfileStack::validate`] with
    /// [`ProfileValidationCode::NoCriticalSecurityInvariant`].
    pub const UNCONSTRAINED: Self = Self {
        require_signature: false,
        require_encryption: false,
    };

    /// Whether this policy requires `requirement`.
    pub fn requires(self, requirement: SecurityRequirement) -> bool {
        match requirement {
            SecurityRequirement::Signature => self.require_signature,
            SecurityRequirement::Encryption => self.require_encryption,
        }
    }

    /// Whether this policy is at least as strong as `floor`.
    pub fn satisfies(self, floor: Self) -> bool {
        self.unmet_by_is_empty(floor)
    }

    fn unmet_by_is_empty(self, floor: Self) -> bool {
        SecurityRequirement::ALL
            .iter()
            .all(|&req| !floor.requires(req) || self.requires(req))
    }

    /// Requirements that `self` (as a floor) demands but `candidate` does not
    /// provide, in declaration order.
    ///
    /// Empty exactly when `candidate.satisfies(self)`.
    pub fn unmet_by(self, candidate: Self) -> Vec<SecurityRequirement> {
        SecurityRequirement::ALL
            .into_iter()
            .filter(|&req| self.requires(req) && !candidate.requires(req))
            .collect()
    }

    /// Requirements that `self` demands but `next` drops — the monotonicity
    /// violations of a `self -> next` transition, in declaration order.
    ///
    /// Empty exactly when `next` is at least as strong as `self`.
    pub fn relaxations_to(self, next: Self) -> Vec<SecurityRequirement> {
        self.unmet_by(next)
    }

    /// Lattice join: require everything either policy requires.
    ///
    /// Used to combine a [`BaseProfile::security_floor`] with a
    /// deployment-imposed floor from [`ProfileValidationOptions`] — the
    /// stricter of the two wins per requirement.
    pub fn strengthen(self, other: Self) -> Self {
        Self {
            require_signature: self.require_signature || other.require_signature,
            require_encryption: self.require_encryption || other.require_encryption,
        }
    }

    /// Lattice meet: require only what both policies require.
    pub fn weaken(self, other: Self) -> Self {
        Self {
            require_signature: self.require_signature && other.require_signature,
            require_encryption: self.require_encryption && other.require_encryption,
        }
    }
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self::SIGN_AND_ENCRYPT
    }
}

impl fmt::Display for SecurityPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "require_signature={} require_encryption={}",
            self.require_signature, self.require_encryption
        )
    }
}

/// Protocol-neutral validation knobs that apply to both AS2 and AS4.
///
/// AS2-only settings live in [`As2ValidationPolicy`] so that an AS4 profile
/// never has to carry — or explicitly disable — a knob that cannot apply to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationPolicy {
    pub reject_ambiguous_headers: bool,
    pub enforce_payload_limits: bool,
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        Self {
            reject_ambiguous_headers: true,
            enforce_payload_limits: true,
        }
    }
}

/// AS2-only validation knobs.
///
/// Kept out of [`ValidationPolicy`] because these concepts have no AS4
/// equivalent: AS4 integrity is carried by the WS-Security XML Signature, not
/// by an RFC 4130 MIC.
///
/// Only meaningful in profiles that carry AS2 traffic; AS4-only profiles can
/// leave this at its default and ignore it entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct As2ValidationPolicy {
    /// Require an RFC 4130 §7.3 `Received-Content-MIC` on inbound MDNs.
    pub require_mic: bool,
}

impl Default for As2ValidationPolicy {
    fn default() -> Self {
        Self { require_mic: true }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProfilePolicyOverrides {
    pub mode: Option<InteropMode>,
    pub canonicalization: Option<CanonicalizationPolicy>,
    pub security: Option<SecurityPolicy>,
    pub validation: Option<ValidationPolicy>,
    /// AS2-only overrides.  `None` on AS4 profiles, which is the common case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as2_validation: Option<As2ValidationPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseProfile {
    /// Short human-readable name for this profile (e.g. `"peppol_as4_strict"`).
    pub name: String,
    /// Specification version string for this profile (e.g. `"2.0"`, `"1.14"`).
    ///
    /// Conveys the version of the underlying standard or network specification this
    /// profile implements.  Informational only — used in diagnostics and profile
    /// comparison but does not affect protocol behaviour.
    pub version: String,
    pub mode: InteropMode,
    pub canonicalization: CanonicalizationPolicy,
    pub security: SecurityPolicy,
    /// Minimum security policy that **no layer may relax**.
    ///
    /// [`ProfileStack::overrides`] and [`ProfileStack::partner_overrides`] are
    /// public, so any overlay can rewrite [`Self::security`]. The floor is the
    /// invariant that survives that: [`ProfileStack::validate`] resolves the
    /// stack for the deployment baseline *and for every declared partner*, and
    /// rejects any resolved policy that does not
    /// [satisfy](SecurityPolicy::satisfies) this floor.
    ///
    /// Defaults to [`SecurityPolicy::SIGN_AND_ENCRYPT`], which is what PEPPOL,
    /// CEF eDelivery and BDEW AS4-Profil v1.2 §2.2.6.2.2 all mandate. Lower it
    /// only for a profile that genuinely permits sign-only or plaintext
    /// exchange, and expect the resulting relaxation to be reported as a
    /// [`ProfileLintCode::SecurityRelaxation`] lint at
    /// [`ProfileLintSeverity::Critical`].
    pub security_floor: SecurityPolicy,
    pub validation: ValidationPolicy,
    /// AS2-only validation settings.  Ignored by AS4 profiles.
    pub as2_validation: As2ValidationPolicy,
}

impl BaseProfile {
    /// A strict, fail-closed base profile with the given name and version.
    ///
    /// Equivalent to [`BaseProfile::default`] with `name`/`version` set:
    /// strict interop mode, sign-and-encrypt required, and a
    /// [`security_floor`](Self::security_floor) that forbids any layer from
    /// dropping either protection.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            ..Self::default()
        }
    }

    /// Replace the [`security_floor`](Self::security_floor).
    pub fn with_security_floor(mut self, floor: SecurityPolicy) -> Self {
        self.security_floor = floor;
        self
    }
}

impl Default for BaseProfile {
    /// Strict interop mode, sign-and-encrypt required, and a matching
    /// sign-and-encrypt floor — the fail-closed starting point.
    fn default() -> Self {
        Self {
            name: "asx-base".to_string(),
            version: "1.0".to_string(),
            mode: InteropMode::Strict,
            canonicalization: CanonicalizationPolicy::default(),
            security: SecurityPolicy::default(),
            security_floor: SecurityPolicy::default(),
            validation: ValidationPolicy::default(),
            as2_validation: As2ValidationPolicy::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileExtension {
    pub name: String,
    pub overrides: ProfilePolicyOverrides,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileOverride {
    pub name: String,
    pub overrides: ProfilePolicyOverrides,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartnerProfileOverlay {
    pub name: String,
    pub partner_id: String,
    pub overrides: ProfilePolicyOverrides,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileStack {
    pub base: BaseProfile,
    pub extensions: Vec<ProfileExtension>,
    pub overrides: Vec<ProfileOverride>,
    pub partner_overrides: Vec<PartnerProfileOverlay>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionalProfilePack {
    pub pack_id: String,
    pub version: String,
    pub applies_to_base_profile: String,
    pub overrides: ProfilePolicyOverrides,
}

impl RegionalProfilePack {
    /// Maximum byte length accepted by [`Self::from_json`].
    ///
    /// Prevents allocation amplification from attacker-controlled JSON blobs.
    pub const MAX_PACK_JSON_BYTES: usize = 512 * 1024; // 512 KiB

    pub fn from_json(input: &str) -> Result<Self> {
        if input.len() > Self::MAX_PACK_JSON_BYTES {
            return Err(AsxError::new(
                ErrorCode::PayloadTooLarge,
                format!(
                    "regional profile pack JSON exceeds maximum allowed size \
                     ({} bytes, limit is {} bytes)",
                    input.len(),
                    Self::MAX_PACK_JSON_BYTES
                ),
                ErrorContext::new("interop_regional_pack_deserialize"),
            ));
        }
        let pack: Self = serde_json::from_str(input).map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("failed to deserialize regional profile pack: {err}"),
                ErrorContext::new("interop_regional_pack_deserialize"),
            )
        })?;
        pack.validate()?;
        Ok(pack)
    }

    fn validate(&self) -> Result<()> {
        if self.pack_id.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "regional pack pack_id must not be empty",
                ErrorContext::new("interop_regional_pack_validate"),
            ));
        }
        if self.applies_to_base_profile.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                format!(
                    "regional pack {} has empty applies_to_base_profile",
                    self.pack_id
                ),
                ErrorContext::new("interop_regional_pack_validate"),
            ));
        }
        if !Self::is_semver_like(&self.version) {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                format!(
                    "regional pack {} has invalid version {}; expected semver-like x.y.z",
                    self.pack_id, self.version
                ),
                ErrorContext::new("interop_regional_pack_validate"),
            ));
        }
        Ok(())
    }

    fn is_semver_like(version: &str) -> bool {
        let mut parts = version.split('.');
        let major = parts.next().unwrap_or("");
        let minor = parts.next().unwrap_or("");
        let patch = parts.next().unwrap_or("");
        if parts.next().is_some() {
            return false;
        }
        !major.is_empty()
            && !minor.is_empty()
            && !patch.is_empty()
            && major.chars().all(|c| c.is_ascii_digit())
            && minor.chars().all(|c| c.is_ascii_digit())
            && patch.chars().all(|c| c.is_ascii_digit())
    }

    fn extension_name(&self) -> String {
        format!("regional:{}@{}", self.pack_id, self.version)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSessionProfile {
    pub session: SessionContext,
    pub effective_profile: EffectiveProfile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveProfile {
    pub name: String,
    pub mode: InteropMode,
    pub canonicalization: CanonicalizationPolicy,
    pub security: SecurityPolicy,
    /// The [`BaseProfile::security_floor`] this policy was resolved under.
    ///
    /// Constant across resolution — the floor is deliberately not overridable,
    /// since it is the invariant the overlays are checked against.
    pub security_floor: SecurityPolicy,
    pub validation: ValidationPolicy,
    /// AS2-only validation settings.  Ignored by AS4 profiles.
    pub as2_validation: As2ValidationPolicy,
    pub snapshot: EffectivePolicySnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectivePolicySnapshot {
    pub session_id: String,
    pub partner_id: String,
    pub profile_name: String,
    pub resolved_mode: InteropMode,
    pub canonicalization: CanonicalizationPolicy,
    pub security: SecurityPolicy,
    /// The [`BaseProfile::security_floor`] in force when this snapshot was
    /// taken.
    ///
    /// Recorded so that [`diff_effective_policy_snapshots`] can flag a *lowered
    /// floor* between releases. Without it a change from
    /// [`SecurityPolicy::SIGN_AND_ENCRYPT`] to
    /// [`SecurityPolicy::UNCONSTRAINED`] is invisible to the diff — the
    /// resolved policy is unchanged, yet every future overlay has become free
    /// to relax it.
    pub security_floor: SecurityPolicy,
    pub validation: ValidationPolicy,
    #[serde(default)]
    pub as2_validation: As2ValidationPolicy,
    pub resolution_trace: Vec<String>,
    pub resolution_diagnostics: Vec<ResolutionDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolutionLayer {
    Extension,
    Override,
    PartnerOverride,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ResolutionField {
    Mode,
    Canonicalization,
    Security,
    /// The profile's security floor. Never produced by layer resolution — the
    /// floor is base-only — but reported by
    /// [`diff_effective_policy_snapshots`] when it changes between releases.
    SecurityFloor,
    Validation,
    /// AS2-only validation settings.
    As2Validation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionDiagnostic {
    pub layer: ResolutionLayer,
    pub layer_name: String,
    pub field: ResolutionField,
    pub previous_value: String,
    pub new_value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProfileValidationCode {
    /// A resolved layer requires neither a signature nor encryption.
    ///
    /// Only reachable when the [security floor](BaseProfile::security_floor)
    /// is permissive enough not to have caught the layer first; a floor of
    /// [`SecurityPolicy::SIGN_AND_ENCRYPT`] reports
    /// [`Self::SecurityFloorViolation`] instead.
    NoCriticalSecurityInvariant,
    /// A resolved layer does not satisfy the profile's
    /// [security floor](BaseProfile::security_floor).
    SecurityFloorViolation,
    /// A layer relaxed a security requirement that a lower layer had enabled,
    /// while [`ProfileValidationOptions::forbid_security_relaxation`] was set.
    ///
    /// Without that option the same transition is reported as a
    /// [`ProfileLintCode::SecurityRelaxation`] lint.
    SecurityRelaxation,
}

impl ProfileValidationCode {
    /// Stable snake_case identifier, suitable for log fields and alert rules.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoCriticalSecurityInvariant => "no_critical_security_invariant",
            Self::SecurityFloorViolation => "security_floor_violation",
            Self::SecurityRelaxation => "security_relaxation",
        }
    }
}

impl fmt::Display for ProfileValidationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProfileLintCode {
    /// A layer sets a field to the value already in effect.
    DeadOverride,
    /// A layer dropped a security requirement a lower layer had enabled, but
    /// the result still satisfies the [security floor](BaseProfile::security_floor).
    ///
    /// Escalate to a hard error with
    /// [`ProfileValidationOptions::forbid_security_relaxation`].
    SecurityRelaxation,
}

impl ProfileLintCode {
    /// Stable snake_case identifier, suitable for log fields and alert rules.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeadOverride => "dead_override",
            Self::SecurityRelaxation => "security_relaxation",
        }
    }
}

impl fmt::Display for ProfileLintCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How much attention a [`ProfileLintFinding`] deserves.
///
/// Lints never block [`ProfileStack::validate`]; the severity tells a CI gate
/// or startup log which ones to treat as blocking anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub enum ProfileLintSeverity {
    /// Cosmetic — the profile behaves as intended but says something twice.
    #[default]
    Info,
    /// Worth reviewing before release.
    Warning,
    /// Security-relevant. Blocks release in the shipped CI gates.
    Critical,
}

impl ProfileLintSeverity {
    /// Stable lowercase identifier, suitable for log fields and alert rules.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for ProfileLintSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileValidationIssue {
    pub code: ProfileValidationCode,
    pub message: String,
    pub remediation_hint: String,
    /// Qualified layer identifier, e.g. `base:peppol` or
    /// `partner_override:9900000000001:legacy`.
    pub layer: String,
    /// Partner whose resolved policy produced this issue.
    ///
    /// `None` for issues found on the deployment baseline (base profile,
    /// extensions and global overrides), which apply to every partner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partner_id: Option<String>,
}

impl fmt::Display for ProfileValidationIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.code, self.layer, self.message)?;
        if !self.remediation_hint.is_empty() {
            write!(f, " — hint: {}", self.remediation_hint)?;
        }
        Ok(())
    }
}

impl std::error::Error for ProfileValidationIssue {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileLintFinding {
    pub code: ProfileLintCode,
    pub severity: ProfileLintSeverity,
    pub message: String,
    pub remediation_hint: String,
    /// Qualified layer identifier, e.g. `override:deployment-global`.
    pub layer: String,
    /// Partner whose resolved policy produced this lint; `None` on the
    /// deployment baseline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partner_id: Option<String>,
}

impl fmt::Display for ProfileLintFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}/{}] {}: {}",
            self.severity, self.code, self.layer, self.message
        )?;
        if !self.remediation_hint.is_empty() {
            write!(f, " — hint: {}", self.remediation_hint)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProfileValidationReport {
    pub lints: Vec<ProfileLintFinding>,
}

impl ProfileValidationReport {
    /// Highest severity across all lints, or `None` when the report is clean.
    pub fn highest_lint_severity(&self) -> Option<ProfileLintSeverity> {
        self.lints.iter().map(|lint| lint.severity).max()
    }

    /// Lints at or above `severity`.
    pub fn lints_at_least(
        &self,
        severity: ProfileLintSeverity,
    ) -> impl Iterator<Item = &ProfileLintFinding> {
        self.lints.iter().filter(move |l| l.severity >= severity)
    }
}

/// Errors (and any lints collected alongside them) from a failed
/// [`ProfileStack::validate`].
///
/// Implements [`Display`](fmt::Display) and [`std::error::Error`], so it
/// composes with `thiserror`'s `#[from]` / `#[error(transparent)]`, with `?`
/// into `anyhow::Error`, and with `Box<dyn Error>`. [`Display`](fmt::Display)
/// renders a bounded one-line summary suitable for a startup log; use
/// [`Self::report`] for the full multi-line operator rendering.
///
/// ```
/// use asx_rs::interop::{BaseProfile, ProfileStack, SecurityPolicy};
///
/// let stack = ProfileStack {
///     base: BaseProfile {
///         security: SecurityPolicy::UNCONSTRAINED,
///         ..BaseProfile::new("demo", "1.0")
///     },
///     extensions: vec![],
///     overrides: vec![],
///     partner_overrides: vec![],
/// };
///
/// let err = stack.validate().unwrap_err();
/// assert!(err.to_string().starts_with("profile validation failed: 1 error"));
/// let _boxed: Box<dyn std::error::Error> = Box::new(err);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileValidationFailure {
    pub errors: Vec<ProfileValidationIssue>,
    pub lints: Vec<ProfileLintFinding>,
}

impl ProfileValidationFailure {
    /// Number of errors rendered inline by [`Display`](fmt::Display) before the
    /// remainder is elided as `(+N more)`.
    ///
    /// One, deliberately. Each issue renders its message *and* remediation
    /// hint, so a large stack failing wholesale would otherwise produce a
    /// multi-kilobyte "one-line" log entry. [`Self::report`] always renders
    /// everything.
    pub const DISPLAY_ERROR_LIMIT: usize = 1;

    /// First error, if any. Always `Some` for a value returned by
    /// [`ProfileStack::validate`], which never fails with an empty error list.
    pub fn first_error(&self) -> Option<&ProfileValidationIssue> {
        self.errors.first()
    }

    /// Whether any error carries `code`.
    pub fn has_code(&self, code: ProfileValidationCode) -> bool {
        self.errors.iter().any(|issue| issue.code == code)
    }

    /// Partners whose resolved policy produced at least one error, deduplicated
    /// in first-seen order. Baseline errors contribute no entry.
    pub fn affected_partners(&self) -> Vec<&str> {
        let mut seen: Vec<&str> = Vec::new();
        for partner in self.errors.iter().filter_map(|e| e.partner_id.as_deref()) {
            if !seen.contains(&partner) {
                seen.push(partner);
            }
        }
        seen
    }

    /// Full multi-line rendering: every error and lint on its own indented
    /// line, with remediation hints.
    ///
    /// This is what belongs in a startup failure log; [`Display`](fmt::Display)
    /// is the bounded one-line form for error-chain composition.
    pub fn report(&self) -> String {
        use fmt::Write as _;

        let mut out = format!(
            "profile validation failed: {} error(s), {} lint(s)",
            self.errors.len(),
            self.lints.len()
        );
        for (index, issue) in self.errors.iter().enumerate() {
            // `write!` into a String is infallible.
            let _ = write!(out, "\n  error {}. {issue}", index + 1);
        }
        for (index, lint) in self.lints.iter().enumerate() {
            let _ = write!(out, "\n  lint  {}. {lint}", index + 1);
        }
        out
    }
}

impl fmt::Display for ProfileValidationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "profile validation failed: {} error(s), {} lint(s)",
            self.errors.len(),
            self.lints.len()
        )?;

        let shown = self.errors.len().min(Self::DISPLAY_ERROR_LIMIT);
        for (index, issue) in self.errors.iter().take(shown).enumerate() {
            let separator = if index == 0 { ": " } else { "; " };
            write!(f, "{separator}{issue}")?;
        }
        if self.errors.len() > shown {
            write!(f, "; (+{} more)", self.errors.len() - shown)?;
        }
        Ok(())
    }
}

impl std::error::Error for ProfileValidationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.errors
            .first()
            .map(|issue| issue as &(dyn std::error::Error + 'static))
    }
}

impl From<ProfileValidationFailure> for AsxError {
    /// Lets `stack.validate()?` be used directly inside any function returning
    /// the crate's [`Result`], rendering through
    /// [`ProfileValidationFailure::report`] so the full finding list survives.
    fn from(failure: ProfileValidationFailure) -> Self {
        AsxError::new(
            ErrorCode::PolicyViolation,
            failure.report(),
            ErrorContext::new("interop_profile_validate"),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
pub enum DiffRiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffStage {
    Resolution,
    Security,
    Validation,
    Canonicalization,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectivePolicyDiffEntry {
    pub field: ResolutionField,
    pub stage: DiffStage,
    pub previous_value: String,
    pub new_value: String,
    pub risk: DiffRiskLevel,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileImpactReport {
    pub before_profile_name: String,
    pub after_profile_name: String,
    pub before_session_id: String,
    pub after_session_id: String,
    pub changes: Vec<EffectivePolicyDiffEntry>,
    pub highest_risk: DiffRiskLevel,
    pub release_blocked: bool,
}

pub type ProfileValidationResult<T> = std::result::Result<T, ProfileValidationFailure>;

/// Knobs for [`ProfileStack::validate_with`].
///
/// Construct with [`Default::default`] and the `with_*` methods; the struct is
/// `#[non_exhaustive]` so future knobs do not break callers.
///
/// ```
/// use asx_rs::interop::{ProfileValidationOptions, SecurityPolicy};
///
/// let options = ProfileValidationOptions::default()
///     .with_security_floor(SecurityPolicy::SIGN_AND_ENCRYPT)
///     .forbidding_security_relaxation();
/// # let _ = options;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ProfileValidationOptions {
    /// Floor imposed by the deployment, on top of [`BaseProfile::security_floor`].
    ///
    /// The two are combined with [`SecurityPolicy::strengthen`], so the
    /// stricter value wins per requirement and this can only tighten
    /// validation, never loosen it.
    pub security_floor: Option<SecurityPolicy>,
    /// Escalate every monotonic security relaxation from a
    /// [`ProfileLintCode::SecurityRelaxation`] lint to a
    /// [`ProfileValidationCode::SecurityRelaxation`] error, even when the
    /// relaxed policy still clears the floor.
    ///
    /// Use this when overlays are expected to specialise *non-security* policy
    /// only, and any security change at all should fail the build.
    pub forbid_security_relaxation: bool,
}

impl ProfileValidationOptions {
    /// Impose a deployment-wide security floor.
    pub fn with_security_floor(mut self, floor: SecurityPolicy) -> Self {
        self.security_floor = Some(floor);
        self
    }

    /// Treat any security relaxation as a hard error.
    pub fn forbidding_security_relaxation(mut self) -> Self {
        self.forbid_security_relaxation = true;
        self
    }

    fn resolve_against(&self, base: &BaseProfile) -> ResolvedValidationOptions {
        ResolvedValidationOptions {
            security_floor: self.security_floor.map_or(base.security_floor, |floor| {
                floor.strengthen(base.security_floor)
            }),
            forbid_security_relaxation: self.forbid_security_relaxation,
        }
    }
}

/// Effective policy for one resolution scope, computed without a live session.
///
/// [`ProfileStack::resolve`] needs a [`SessionContext`], which startup
/// validation does not have. This is the session-free counterpart: it answers
/// "what policy will partner X actually get?" before the first message.
///
/// ```
/// use asx_rs::interop::{
///     BaseProfile, PartnerProfileOverlay, ProfilePolicyOverrides, ProfileStack, SecurityPolicy,
/// };
///
/// let stack = ProfileStack {
///     base: BaseProfile::new("bdew", "1.2").with_security_floor(SecurityPolicy::SIGN_ONLY),
///     extensions: vec![],
///     overrides: vec![],
///     partner_overrides: vec![PartnerProfileOverlay {
///         name: "legacy".into(),
///         partner_id: "9900000000001".into(),
///         overrides: ProfilePolicyOverrides {
///             security: Some(SecurityPolicy::SIGN_ONLY),
///             ..Default::default()
///         },
///     }],
/// };
///
/// let weak: Vec<_> = stack
///     .resolve_all_partners()
///     .into_iter()
///     .filter(|view| !view.security.satisfies(SecurityPolicy::SIGN_AND_ENCRYPT))
///     .map(|view| view.scope_label().to_string())
///     .collect();
/// assert_eq!(weak, vec!["9900000000001"]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPolicyView {
    /// Partner this policy applies to, or `None` for the deployment baseline
    /// (base + extensions + global overrides, no partner overlay).
    pub partner_id: Option<String>,
    pub mode: InteropMode,
    pub canonicalization: CanonicalizationPolicy,
    pub security: SecurityPolicy,
    pub validation: ValidationPolicy,
    /// AS2-only validation settings.  Ignored by AS4 profiles.
    pub as2_validation: As2ValidationPolicy,
    pub resolution_trace: Vec<String>,
    pub resolution_diagnostics: Vec<ResolutionDiagnostic>,
}

impl ResolvedPolicyView {
    /// `"<baseline>"` or the partner id — a stable label for logs and reports.
    pub fn scope_label(&self) -> &str {
        self.partner_id.as_deref().unwrap_or("<baseline>")
    }

    /// Whether this resolved policy is at least as strong as `floor`.
    pub fn satisfies(&self, floor: SecurityPolicy) -> bool {
        self.security.satisfies(floor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InteropExceptionCode {
    As2AllowMissingMdnBoundary,
}

impl InteropExceptionCode {
    pub fn reason_code(self) -> &'static str {
        match self {
            Self::As2AllowMissingMdnBoundary => "as2_missing_mdn_boundary",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InteropGuardrailOutcome {
    Allowed,
    Denied,
}

impl InteropGuardrailOutcome {
    /// Return a canonical `&'static str` label for this outcome.
    /// Avoids `format!("{:?}", ...)` heap allocation at event-emission sites.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "Allowed",
            Self::Denied => "Denied",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InteropExceptionPolicy {
    pub scoped_profile_name: Option<String>,
    pub allowed: Vec<InteropExceptionCode>,
}

impl InteropExceptionPolicy {
    pub fn scoped(profile_name: impl Into<String>, allowed: Vec<InteropExceptionCode>) -> Self {
        Self {
            scoped_profile_name: Some(profile_name.into()),
            allowed,
        }
    }

    pub fn allows(&self, session: &SessionContext, code: InteropExceptionCode) -> bool {
        match &self.scoped_profile_name {
            Some(scope) if scope == session.profile_name() => self.allowed.contains(&code),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteropDecision {
    RelaxedException { reason_code: &'static str },
}

pub fn evaluate_exception_guardrail(
    session: &SessionContext,
    mode: InteropMode,
    policy: &InteropExceptionPolicy,
    code: InteropExceptionCode,
) -> InteropGuardrailOutcome {
    if mode == InteropMode::Strict {
        return InteropGuardrailOutcome::Denied;
    }

    if policy.allows(session, code) {
        InteropGuardrailOutcome::Allowed
    } else {
        InteropGuardrailOutcome::Denied
    }
}

pub fn enforce_exception(
    session: &SessionContext,
    mode: InteropMode,
    policy: &InteropExceptionPolicy,
    code: InteropExceptionCode,
    stage: &'static str,
    strict_message: impl Into<String>,
) -> Result<InteropDecision> {
    let strict_message = strict_message.into();
    match evaluate_exception_guardrail(session, mode, policy, code) {
        InteropGuardrailOutcome::Allowed => Ok(InteropDecision::RelaxedException {
            reason_code: code.reason_code(),
        }),
        InteropGuardrailOutcome::Denied => {
            let message = if mode == InteropMode::Strict {
                strict_message
            } else {
                format!(
                    "relaxed mode exception denied for reason {}; missing scoped exception policy",
                    code.reason_code()
                )
            };
            Err(AsxError::new(
                ErrorCode::InteropViolation,
                message,
                ErrorContext::for_session(stage, session),
            ))
        }
    }
}

impl EffectivePolicySnapshot {
    pub fn as_event_detail(&self) -> String {
        let trace = if self.resolution_trace.is_empty() {
            "none".into()
        } else {
            self.resolution_trace.join(" > ")
        };

        format!(
            "session={} partner={} profile={} mode={:?} trace={}",
            self.session_id, self.partner_id, self.profile_name, self.resolved_mode, trace
        )
    }

    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("failed to serialize effective policy snapshot: {err}"),
                ErrorContext::new("interop_snapshot_serialize")
                    .with_session_and_partner(&self.session_id, &self.partner_id),
            )
        })
    }

    pub fn from_json(input: &str) -> Result<Self> {
        serde_json::from_str(input).map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("failed to deserialize effective policy snapshot: {err}"),
                ErrorContext::new("interop_snapshot_deserialize"),
            )
        })
    }
}

impl ProfileImpactReport {
    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("failed to serialize profile impact report: {err}"),
                ErrorContext::new("interop_profile_diff_serialize"),
            )
        })
    }
}

pub fn diff_effective_policy_snapshots(
    before: &EffectivePolicySnapshot,
    after: &EffectivePolicySnapshot,
) -> ProfileImpactReport {
    let mut changes = Vec::new();

    if before.resolved_mode != after.resolved_mode {
        changes.push(EffectivePolicyDiffEntry {
            field: ResolutionField::Mode,
            stage: DiffStage::Resolution,
            previous_value: format!("{:?}", before.resolved_mode),
            new_value: format!("{:?}", after.resolved_mode),
            risk: DiffRiskLevel::Medium,
            rationale: "Interop mode changed; behavior may shift between strict and relaxed paths"
                .to_string(),
        });
    }

    if before.canonicalization != after.canonicalization {
        changes.push(EffectivePolicyDiffEntry {
            field: ResolutionField::Canonicalization,
            stage: DiffStage::Canonicalization,
            previous_value: format!("{:?}", before.canonicalization),
            new_value: format!("{:?}", after.canonicalization),
            risk: DiffRiskLevel::Medium,
            rationale:
                "Canonicalization behavior changed; signature-reference interoperability may drift"
                    .to_string(),
        });
    }

    if before.security != after.security {
        let risk = if (before.security.require_signature && !after.security.require_signature)
            || (before.security.require_encryption && !after.security.require_encryption)
        {
            DiffRiskLevel::High
        } else {
            DiffRiskLevel::Medium
        };
        changes.push(EffectivePolicyDiffEntry {
            field: ResolutionField::Security,
            stage: DiffStage::Security,
            previous_value: format!("{:?}", before.security),
            new_value: format!("{:?}", after.security),
            risk,
            rationale:
                "Security invariants changed; potential weakening of signature/encryption requirements"
                    .to_string(),
        });
    }

    if before.security_floor != after.security_floor {
        // Lowering the floor is High even when the *resolved* policy is
        // unchanged: it is precisely the change that makes a future overlay
        // able to relax security without validation objecting.
        let relaxed = before.security_floor.relaxations_to(after.security_floor);
        let (risk, rationale) = if relaxed.is_empty() {
            (
                DiffRiskLevel::Medium,
                "Security floor raised; overlays that previously validated may now be rejected"
                    .to_string(),
            )
        } else {
            (
                DiffRiskLevel::High,
                format!(
                    "Security floor lowered ({} no longer enforced); overlays may now relax \
                     security without failing validation",
                    join_requirements(&relaxed)
                ),
            )
        };
        changes.push(EffectivePolicyDiffEntry {
            field: ResolutionField::SecurityFloor,
            stage: DiffStage::Security,
            previous_value: format!("{:?}", before.security_floor),
            new_value: format!("{:?}", after.security_floor),
            risk,
            rationale,
        });
    }

    if before.validation != after.validation {
        let risk = if before.validation.enforce_payload_limits
            && !after.validation.enforce_payload_limits
        {
            DiffRiskLevel::High
        } else {
            DiffRiskLevel::Medium
        };
        changes.push(EffectivePolicyDiffEntry {
            field: ResolutionField::Validation,
            stage: DiffStage::Validation,
            previous_value: format!("{:?}", before.validation),
            new_value: format!("{:?}", after.validation),
            risk,
            rationale: "Validation constraints changed; malformed-input acceptance may differ"
                .to_string(),
        });
    }

    if before.as2_validation != after.as2_validation {
        // Graded Medium (non-blocking), matching how this change was classified
        // when `require_mic` lived inside `ValidationPolicy`: only
        // `enforce_payload_limits` escalates the validation stage to High.
        changes.push(EffectivePolicyDiffEntry {
            field: ResolutionField::As2Validation,
            stage: DiffStage::Validation,
            previous_value: format!("{:?}", before.as2_validation),
            new_value: format!("{:?}", after.as2_validation),
            risk: DiffRiskLevel::Medium,
            rationale: "AS2 validation constraints changed; MDN integrity enforcement may differ"
                .to_string(),
        });
    }

    let highest_risk = changes
        .iter()
        .map(|change| change.risk)
        .max()
        .unwrap_or(DiffRiskLevel::Low);

    ProfileImpactReport {
        before_profile_name: before.profile_name.clone(),
        after_profile_name: after.profile_name.clone(),
        before_session_id: before.session_id.clone(),
        after_session_id: after.session_id.clone(),
        release_blocked: highest_risk == DiffRiskLevel::High,
        highest_risk,
        changes,
    }
}

#[derive(Debug)]
struct ResolvedPolicyState {
    mode: InteropMode,
    canonicalization: CanonicalizationPolicy,
    security: SecurityPolicy,
    validation: ValidationPolicy,
    as2_validation: As2ValidationPolicy,
    trace: Vec<String>,
    diagnostics: Vec<ResolutionDiagnostic>,
}

#[derive(Debug, Clone)]
struct EffectivePolicyState {
    mode: InteropMode,
    canonicalization: CanonicalizationPolicy,
    security: SecurityPolicy,
    validation: ValidationPolicy,
    as2_validation: As2ValidationPolicy,
}

/// Findings sink for one resolution branch (the baseline, or one partner).
///
/// Carrying `partner_id` here is what lets every issue name the partner whose
/// resolved policy produced it without threading it through each call site.
struct LayerFindings<'a> {
    errors: &'a mut Vec<ProfileValidationIssue>,
    lints: &'a mut Vec<ProfileLintFinding>,
    partner_id: Option<&'a str>,
}

impl LayerFindings<'_> {
    fn push_error(&mut self, issue: ProfileValidationIssue) {
        self.errors.push(issue);
    }

    fn push_lint(&mut self, lint: ProfileLintFinding) {
        self.lints.push(lint);
    }

    fn scope_label(&self) -> String {
        self.partner_id.map_or_else(
            || "deployment baseline".to_string(),
            |p| format!("partner {p}"),
        )
    }
}

/// One validation scope in progress: the deployment baseline, or a fork of it
/// for a single partner.
///
/// Tracks the layer that last assigned `security` so the scope-level floor
/// error can point at the line to change, rather than at the base profile that
/// was overridden three layers down.
#[derive(Debug, Clone)]
struct ValidationScope {
    state: EffectivePolicyState,
    last_security_layer: String,
    previous_security: SecurityPolicy,
}

impl ValidationScope {
    fn apply(&mut self, qualified_layer: &str, overrides: &ProfilePolicyOverrides) {
        self.previous_security = self.state.security;
        ProfileStack::apply_effective_state_overrides(&mut self.state, overrides);
        if overrides.security.is_some() {
            self.last_security_layer = qualified_layer.to_string();
        }
    }
}

/// [`ProfileValidationOptions`] with the profile's own floor already folded in.
#[derive(Debug, Clone, Copy)]
struct ResolvedValidationOptions {
    security_floor: SecurityPolicy,
    forbid_security_relaxation: bool,
}

/// Render a requirement list as `require_signature and require_encryption`.
fn join_requirements(requirements: &[SecurityRequirement]) -> String {
    requirements
        .iter()
        .map(|req| req.as_str())
        .collect::<Vec<_>>()
        .join(" and ")
}

impl ProfileStack {
    pub fn apply_regional_pack(&self, pack: &RegionalProfilePack) -> Result<Self> {
        pack.validate()?;

        if pack.applies_to_base_profile != self.base.name {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                format!(
                    "regional pack {}@{} targets base profile {} but active base is {}",
                    pack.pack_id, pack.version, pack.applies_to_base_profile, self.base.name
                ),
                ErrorContext::new("interop_regional_pack_apply"),
            ));
        }

        let mut merged = self.clone();
        merged.extensions.push(ProfileExtension {
            name: pack.extension_name(),
            overrides: pack.overrides.clone(),
        });
        Ok(merged)
    }

    pub fn apply_regional_packs(&self, packs: &[RegionalProfilePack]) -> Result<Self> {
        let mut merged = self.clone();
        for pack in packs {
            merged = merged.apply_regional_pack(pack)?;
        }
        Ok(merged)
    }

    /// Report a layer that drops a security requirement its predecessors had
    /// enabled.
    ///
    /// This is a *lint* by default, not an error: a dip that a later layer
    /// restores has no runtime effect, so making it fatal would be a false
    /// positive. Whether the scope actually ends up insecure is decided once,
    /// against the resolved policy, by [`Self::validate_scope_security`].
    /// [`ProfileValidationOptions::forbid_security_relaxation`] escalates these
    /// to errors for deployments where overlays must not touch security at all.
    fn lint_security_relaxation(
        findings: &mut LayerFindings<'_>,
        layer: &str,
        previous: SecurityPolicy,
        next: SecurityPolicy,
        options: &ResolvedValidationOptions,
    ) {
        let relaxed = previous.relaxations_to(next);
        if relaxed.is_empty() {
            return;
        }

        let message = format!(
            "{layer} relaxes {} relative to the underlying layers (was {previous}, now {next})",
            join_requirements(&relaxed)
        );
        let hint = format!(
            "Remove the relaxation, or raise BaseProfile::security_floor so the weaker \
             policy is rejected outright rather than silently accepted for {}",
            findings.scope_label()
        );

        if options.forbid_security_relaxation {
            findings.push_error(ProfileValidationIssue {
                code: ProfileValidationCode::SecurityRelaxation,
                message,
                remediation_hint: hint,
                layer: layer.to_string(),
                partner_id: findings.partner_id.map(str::to_string),
            });
        } else {
            findings.push_lint(ProfileLintFinding {
                code: ProfileLintCode::SecurityRelaxation,
                severity: ProfileLintSeverity::Critical,
                message,
                remediation_hint: hint,
                layer: layer.to_string(),
                partner_id: findings.partner_id.map(str::to_string),
            });
        }
    }

    /// Check the *resolved* policy for one scope against the floor.
    ///
    /// Runs once per scope rather than per layer, because the resolved policy
    /// is the only one the runtime ever applies. `layer` names the last layer
    /// that assigned `security`, so the error points at the line to change.
    fn validate_scope_security(
        findings: &mut LayerFindings<'_>,
        layer: &str,
        resolved: SecurityPolicy,
        options: &ResolvedValidationOptions,
    ) {
        let unmet = options.security_floor.unmet_by(resolved);
        if !unmet.is_empty() {
            let scope = findings.scope_label();
            findings.push_error(ProfileValidationIssue {
                code: ProfileValidationCode::SecurityFloorViolation,
                message: format!(
                    "{scope} resolves to a security policy below the profile floor: \
                     missing {}; effective [{resolved}], floor [{}]; last set by {layer}",
                    join_requirements(&unmet),
                    options.security_floor
                ),
                remediation_hint: format!(
                    "Set {} on {layer}, or lower BaseProfile::security_floor if the profile \
                     genuinely permits the weaker policy",
                    join_requirements(&unmet)
                ),
                layer: layer.to_string(),
                partner_id: findings.partner_id.map(str::to_string),
            });
            return;
        }

        if resolved == SecurityPolicy::UNCONSTRAINED {
            let scope = findings.scope_label();
            findings.push_error(ProfileValidationIssue {
                code: ProfileValidationCode::NoCriticalSecurityInvariant,
                message: format!(
                    "{scope} resolves with neither signature nor encryption required; \
                     last set by {layer}"
                ),
                remediation_hint:
                    "Enable at least one critical security invariant: signature or encryption"
                        .to_string(),
                layer: layer.to_string(),
                partner_id: findings.partner_id.map(str::to_string),
            });
        }
    }

    fn lint_override_layer(
        findings: &mut LayerFindings<'_>,
        layer_name: &str,
        current: &EffectivePolicyState,
        overrides: &ProfilePolicyOverrides,
    ) {
        let mut dead = |message: String, remediation_hint: &str| {
            findings.push_lint(ProfileLintFinding {
                code: ProfileLintCode::DeadOverride,
                severity: ProfileLintSeverity::Info,
                message,
                remediation_hint: remediation_hint.to_string(),
                layer: layer_name.to_string(),
                partner_id: findings.partner_id.map(str::to_string),
            });
        };

        if let Some(mode) = overrides.mode
            && mode == current.mode
        {
            dead(
                format!(
                    "{layer_name} sets mode to {mode:?}, which matches already-effective value"
                ),
                "Remove redundant override or change it to a distinct value",
            );
        }

        if let Some(c14n) = overrides.canonicalization.as_ref()
            && *c14n == current.canonicalization
        {
            dead(
                format!("{layer_name} sets canonicalization to current effective value"),
                "Remove redundant canonicalization override",
            );
        }

        if let Some(security) = overrides.security
            && security == current.security
        {
            dead(
                format!("{layer_name} sets security policy to current effective value"),
                "Remove redundant security override",
            );
        }

        if let Some(validation) = overrides.validation
            && validation == current.validation
        {
            dead(
                format!("{layer_name} sets validation policy to current effective value"),
                "Remove redundant validation override",
            );
        }

        if let Some(as2_validation) = overrides.as2_validation
            && as2_validation == current.as2_validation
        {
            dead(
                format!("{layer_name} sets AS2 validation policy to current effective value"),
                "Remove redundant as2_validation override",
            );
        }
    }

    fn apply_effective_state_overrides(
        current: &mut EffectivePolicyState,
        overrides: &ProfilePolicyOverrides,
    ) {
        if let Some(mode) = overrides.mode {
            current.mode = mode;
        }
        if let Some(c14n) = overrides.canonicalization.as_ref() {
            current.canonicalization = c14n.clone();
        }
        if let Some(security) = overrides.security {
            current.security = security;
        }
        if let Some(validation) = overrides.validation {
            current.validation = validation;
        }
        if let Some(as2_validation) = overrides.as2_validation {
            current.as2_validation = as2_validation;
        }
    }

    /// Walk the deployment-wide layers: extensions, then global overrides.
    ///
    /// These apply to every partner, so both [`Self::validate_with`] and
    /// [`Self::resolve`] run them before any partner overlay.
    fn for_each_global_layer<F>(&self, mut f: F)
    where
        F: FnMut(ResolutionLayer, &'static str, &str, &ProfilePolicyOverrides),
    {
        for ext in &self.extensions {
            f(
                ResolutionLayer::Extension,
                "extension",
                &ext.name,
                &ext.overrides,
            );
        }

        for ov in &self.overrides {
            f(
                ResolutionLayer::Override,
                "override",
                &ov.name,
                &ov.overrides,
            );
        }
    }

    /// Walk the partner overlays for `partner_id`, in declaration order.
    ///
    /// `None` selects no overlays at all — the deployment baseline.
    fn for_each_partner_layer<F>(&self, partner_id: Option<&str>, mut f: F)
    where
        F: FnMut(ResolutionLayer, &'static str, String, &ProfilePolicyOverrides),
    {
        let Some(partner_id) = partner_id else {
            return;
        };

        for pov in &self.partner_overrides {
            if pov.partner_id != partner_id {
                continue;
            }
            f(
                ResolutionLayer::PartnerOverride,
                "partner_override",
                format!("{}:{}", pov.partner_id, pov.name),
                &pov.overrides,
            );
        }
    }

    /// Distinct partner identifiers that carry at least one overlay, in
    /// declaration order.
    pub fn partner_ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = Vec::new();
        for pov in &self.partner_overrides {
            if !ids.contains(&pov.partner_id.as_str()) {
                ids.push(&pov.partner_id);
            }
        }
        ids
    }

    /// Validate the stack with the default options.
    ///
    /// Equivalent to [`Self::validate_with`] with
    /// [`ProfileValidationOptions::default`]: the floor comes from
    /// [`BaseProfile::security_floor`] alone, and a relaxation that still
    /// clears the floor is a [`ProfileLintSeverity::Critical`] lint rather than
    /// an error.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileValidationFailure`] when any resolved layer — for the
    /// deployment baseline or for any declared partner — violates the security
    /// floor or leaves no critical security invariant in place. Lints collected
    /// before the failure are carried in the failure value.
    pub fn validate(&self) -> ProfileValidationResult<ProfileValidationReport> {
        self.validate_with(&ProfileValidationOptions::default())
    }

    /// Validate the stack against a deployment-imposed security floor.
    ///
    /// The effective floor is the stronger of `floor` and
    /// [`BaseProfile::security_floor`], per requirement. This is the
    /// startup-check form: a host that must guarantee sign-and-encrypt for
    /// every partner can assert it without trusting the profile's own floor.
    ///
    /// ```
    /// use asx_rs::interop::{
    ///     BaseProfile, PartnerProfileOverlay, ProfilePolicyOverrides, ProfileStack,
    ///     ProfileValidationCode, SecurityPolicy,
    /// };
    ///
    /// let stack = ProfileStack {
    ///     // A profile whose own floor permits sign-only …
    ///     base: BaseProfile::new("legacy", "1.0").with_security_floor(SecurityPolicy::SIGN_ONLY),
    ///     extensions: vec![],
    ///     overrides: vec![],
    ///     partner_overrides: vec![PartnerProfileOverlay {
    ///         name: "legacy-partner".into(),
    ///         partner_id: "9900000000001".into(),
    ///         overrides: ProfilePolicyOverrides {
    ///             security: Some(SecurityPolicy::SIGN_ONLY),
    ///             ..Default::default()
    ///         },
    ///     }],
    /// };
    ///
    /// // … still fails a host mandate of sign-and-encrypt.
    /// let failure = stack
    ///     .validate_with_floor(SecurityPolicy::SIGN_AND_ENCRYPT)
    ///     .unwrap_err();
    /// assert!(failure.has_code(ProfileValidationCode::SecurityFloorViolation));
    /// assert_eq!(failure.affected_partners(), vec!["9900000000001"]);
    /// ```
    ///
    /// # Errors
    ///
    /// As [`Self::validate`], additionally failing when any resolved layer
    /// falls below `floor`.
    pub fn validate_with_floor(
        &self,
        floor: SecurityPolicy,
    ) -> ProfileValidationResult<ProfileValidationReport> {
        self.validate_with(&ProfileValidationOptions::default().with_security_floor(floor))
    }

    /// Validate the stack with explicit options.
    ///
    /// Resolution is forked per partner: the base, extensions and global
    /// overrides are walked once to produce the deployment baseline, then each
    /// distinct partner in [`Self::partner_overrides`] is resolved from a copy
    /// of that baseline. One partner's overlay therefore never contaminates
    /// another's findings, and every issue is attributed to the partner whose
    /// resolved policy produced it via [`ProfileValidationIssue::partner_id`].
    ///
    /// # Errors
    ///
    /// Returns [`ProfileValidationFailure`] when any resolved layer produces a
    /// validation error; see [`ProfileValidationCode`] for the cases.
    pub fn validate_with(
        &self,
        options: &ProfileValidationOptions,
    ) -> ProfileValidationResult<ProfileValidationReport> {
        let options = options.resolve_against(&self.base);

        let mut errors = vec![];
        let mut lints = vec![];

        // Pass 1: the deployment baseline — base + extensions + global
        // overrides. This is also the policy any partner without an overlay
        // receives, so it is validated as a scope in its own right.
        let baseline = {
            let mut findings = LayerFindings {
                errors: &mut errors,
                lints: &mut lints,
                partner_id: None,
            };
            let baseline = self.walk_baseline_layers(&mut findings, &options);
            Self::validate_scope_security(
                &mut findings,
                &baseline.last_security_layer,
                baseline.state.security,
                &options,
            );
            baseline
        };

        // Pass 2: fork the baseline once per declared partner, so one
        // partner's overlay cannot contaminate another's findings.
        for partner_id in self.partner_ids() {
            let mut scope = baseline.clone();
            let mut findings = LayerFindings {
                errors: &mut errors,
                lints: &mut lints,
                partner_id: Some(partner_id),
            };
            self.for_each_partner_layer(
                Some(partner_id),
                |_, layer_kind, layer_name, overrides| {
                    let qualified_layer = format!("{layer_kind}:{layer_name}");
                    Self::lint_override_layer(
                        &mut findings,
                        &qualified_layer,
                        &scope.state,
                        overrides,
                    );
                    scope.apply(&qualified_layer, overrides);
                    Self::lint_security_relaxation(
                        &mut findings,
                        &qualified_layer,
                        scope.previous_security,
                        scope.state.security,
                        &options,
                    );
                },
            );

            // Skip the scope check when no partner overlay touched security:
            // the resolved policy is byte-for-byte the baseline's, so any
            // finding here would restate the baseline error once per partner.
            // The baseline error already applies to every partner.
            if scope.last_security_layer == baseline.last_security_layer
                && scope.state.security == baseline.state.security
            {
                continue;
            }

            Self::validate_scope_security(
                &mut findings,
                &scope.last_security_layer,
                scope.state.security,
                &options,
            );
        }

        if errors.is_empty() {
            Ok(ProfileValidationReport { lints })
        } else {
            Err(ProfileValidationFailure { errors, lints })
        }
    }

    /// Walk base + extensions + global overrides, recording per-layer findings,
    /// and return the resulting deployment baseline scope.
    fn walk_baseline_layers(
        &self,
        findings: &mut LayerFindings<'_>,
        options: &ResolvedValidationOptions,
    ) -> ValidationScope {
        let mut scope = ValidationScope {
            state: EffectivePolicyState {
                mode: self.base.mode,
                canonicalization: self.base.canonicalization.clone(),
                security: self.base.security,
                validation: self.base.validation,
                as2_validation: self.base.as2_validation,
            },
            last_security_layer: format!("base:{}", self.base.name),
            previous_security: self.base.security,
        };

        self.for_each_global_layer(|_, layer_kind, layer_name, overrides| {
            let qualified_layer = format!("{layer_kind}:{layer_name}");
            Self::lint_override_layer(findings, &qualified_layer, &scope.state, overrides);
            scope.apply(&qualified_layer, overrides);
            Self::lint_security_relaxation(
                findings,
                &qualified_layer,
                scope.previous_security,
                scope.state.security,
                options,
            );
        });

        scope
    }

    fn apply_overrides(
        resolved: &mut ResolvedPolicyState,
        layer: ResolutionLayer,
        layer_kind: &'static str,
        layer_name: &str,
        overrides: &ProfilePolicyOverrides,
    ) {
        if let Some(override_mode) = overrides.mode {
            let previous_mode = resolved.mode;
            resolved.mode = override_mode;
            resolved.trace.push(format!(
                "{layer_kind}:{layer_name}.mode=>{:?}",
                override_mode
            ));
            resolved.diagnostics.push(ResolutionDiagnostic {
                layer,
                layer_name: layer_name.to_string(),
                field: ResolutionField::Mode,
                previous_value: format!("{:?}", previous_mode),
                new_value: format!("{:?}", override_mode),
            });
        }
        if let Some(ref override_c14n) = overrides.canonicalization {
            let previous_c14n = resolved.canonicalization.clone();
            resolved.canonicalization = override_c14n.clone();
            resolved.trace.push(format!(
                "{layer_kind}:{layer_name}.canonicalization=>{:?}",
                override_c14n
            ));
            resolved.diagnostics.push(ResolutionDiagnostic {
                layer,
                layer_name: layer_name.to_string(),
                field: ResolutionField::Canonicalization,
                previous_value: format!("{:?}", previous_c14n),
                new_value: format!("{:?}", override_c14n),
            });
        }
        if let Some(override_security) = overrides.security {
            let previous_security = resolved.security;
            resolved.security = override_security;
            resolved.trace.push(format!(
                "{layer_kind}:{layer_name}.security=>{:?}",
                override_security
            ));
            resolved.diagnostics.push(ResolutionDiagnostic {
                layer,
                layer_name: layer_name.to_string(),
                field: ResolutionField::Security,
                previous_value: format!("{:?}", previous_security),
                new_value: format!("{:?}", override_security),
            });
        }
        if let Some(override_validation) = overrides.validation {
            let previous_validation = resolved.validation;
            resolved.validation = override_validation;
            resolved.trace.push(format!(
                "{layer_kind}:{layer_name}.validation=>{:?}",
                override_validation
            ));
            resolved.diagnostics.push(ResolutionDiagnostic {
                layer,
                layer_name: layer_name.to_string(),
                field: ResolutionField::Validation,
                previous_value: format!("{:?}", previous_validation),
                new_value: format!("{:?}", override_validation),
            });
        }
        if let Some(override_as2_validation) = overrides.as2_validation {
            let previous_as2_validation = resolved.as2_validation;
            resolved.as2_validation = override_as2_validation;
            resolved.trace.push(format!(
                "{layer_kind}:{layer_name}.as2_validation=>{:?}",
                override_as2_validation
            ));
            resolved.diagnostics.push(ResolutionDiagnostic {
                layer,
                layer_name: layer_name.to_string(),
                field: ResolutionField::As2Validation,
                previous_value: format!("{:?}", previous_as2_validation),
                new_value: format!("{:?}", override_as2_validation),
            });
        }
    }

    /// Resolve the stack for `partner_id`, or for the deployment baseline when
    /// it is `None`.
    ///
    /// Single source of truth for layer application — [`Self::resolve`],
    /// [`Self::resolve_baseline`] and [`Self::resolve_partner`] all go through
    /// it, so a session-free view can never drift from what a live session gets.
    fn resolve_state(&self, partner_id: Option<&str>) -> ResolvedPolicyState {
        let mut resolved = ResolvedPolicyState {
            mode: self.base.mode,
            canonicalization: self.base.canonicalization.clone(),
            security: self.base.security,
            validation: self.base.validation,
            as2_validation: self.base.as2_validation,
            trace: vec![
                format!("base:{}=>{:?}", self.base.name, self.base.mode),
                format!(
                    "base:{}.canonicalization=>{:?}",
                    self.base.name, self.base.canonicalization
                ),
                format!("base:{}.security=>{:?}", self.base.name, self.base.security),
                format!(
                    "base:{}.validation=>{:?}",
                    self.base.name, self.base.validation
                ),
            ],
            diagnostics: vec![],
        };

        self.for_each_global_layer(|layer, layer_kind, layer_name, overrides| {
            Self::apply_overrides(&mut resolved, layer, layer_kind, layer_name, overrides);
        });

        self.for_each_partner_layer(partner_id, |layer, layer_kind, layer_name, overrides| {
            Self::apply_overrides(&mut resolved, layer, layer_kind, &layer_name, overrides);
        });

        resolved
    }

    /// Effective policy with no partner overlay applied — what a partner
    /// without its own overlay receives.
    pub fn resolve_baseline(&self) -> ResolvedPolicyView {
        self.resolve_view(None)
    }

    /// Effective policy for `partner_id`, resolved without a
    /// [`SessionContext`].
    ///
    /// A partner with no declared overlay resolves to the baseline policy,
    /// tagged with its id.
    pub fn resolve_partner(&self, partner_id: &str) -> ResolvedPolicyView {
        self.resolve_view(Some(partner_id))
    }

    /// Every effective policy this stack can produce: the deployment baseline
    /// first, then one entry per distinct partner in
    /// [`Self::partner_overrides`], in declaration order.
    ///
    /// This is the startup-audit entry point — see [`ResolvedPolicyView`] for
    /// an example that asserts a security mandate across all partners. Prefer
    /// [`Self::validate_with_floor`] when the mandate is a plain security
    /// floor; use this when the assertion is over other policy fields.
    pub fn resolve_all_partners(&self) -> Vec<ResolvedPolicyView> {
        let mut views = Vec::with_capacity(self.partner_overrides.len() + 1);
        views.push(self.resolve_baseline());
        for partner_id in self.partner_ids() {
            views.push(self.resolve_partner(partner_id));
        }
        views
    }

    fn resolve_view(&self, partner_id: Option<&str>) -> ResolvedPolicyView {
        let resolved = self.resolve_state(partner_id);
        ResolvedPolicyView {
            partner_id: partner_id.map(str::to_string),
            mode: resolved.mode,
            canonicalization: resolved.canonicalization,
            security: resolved.security,
            validation: resolved.validation,
            as2_validation: resolved.as2_validation,
            resolution_trace: resolved.trace,
            resolution_diagnostics: resolved.diagnostics,
        }
    }

    pub fn resolve(&self, session: &SessionContext) -> EffectiveProfile {
        let resolved = self.resolve_state(Some(session.partner_id()));

        EffectiveProfile {
            name: format!("{}@{}", self.base.name, session.profile_name()),
            mode: resolved.mode,
            canonicalization: resolved.canonicalization.clone(),
            security: resolved.security,
            security_floor: self.base.security_floor,
            validation: resolved.validation,
            as2_validation: resolved.as2_validation,
            snapshot: EffectivePolicySnapshot {
                session_id: session.session_id().to_string(),
                partner_id: session.partner_id().to_string(),
                profile_name: session.profile_name().to_string(),
                resolved_mode: resolved.mode,
                canonicalization: resolved.canonicalization.clone(),
                security: resolved.security,
                security_floor: self.base.security_floor,
                validation: resolved.validation,
                as2_validation: resolved.as2_validation,
                resolution_trace: resolved.trace,
                resolution_diagnostics: resolved.diagnostics,
            },
        }
    }

    pub fn resolve_for_session(&self, session: &SessionContext) -> Result<ResolvedSessionProfile> {
        let effective_profile = self.resolve(session);
        let snapshot_json = effective_profile.snapshot.to_json_pretty()?;
        let attached_session = session
            .clone()
            .with_effective_policy_snapshot_json(snapshot_json)?;

        Ok(ResolvedSessionProfile {
            session: attached_session,
            effective_profile,
        })
    }
}

#[cfg(test)]
#[cfg_attr(not(feature = "interop-relaxed"), allow(unused_imports))]
mod tests;
