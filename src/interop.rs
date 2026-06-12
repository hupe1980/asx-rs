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
    pub strip_blank_text: bool,
    pub inclusive_ns_prefixes: Vec<String>,
}

#[cfg(not(feature = "as4"))]
impl Default for WsSecCanonicalizationProfile {
    fn default() -> Self {
        Self {
            kind: WsSecCanonicalizationKind::Exclusive,
            include_comments: false,
            strip_blank_text: true,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub require_signature: bool,
    pub require_encryption: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            require_signature: true,
            require_encryption: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationPolicy {
    pub reject_ambiguous_headers: bool,
    pub enforce_payload_limits: bool,
    pub require_as2_mic: bool,
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        Self {
            reject_ambiguous_headers: true,
            enforce_payload_limits: true,
            require_as2_mic: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProfilePolicyOverrides {
    pub mode: Option<InteropMode>,
    pub canonicalization: Option<CanonicalizationPolicy>,
    pub security: Option<SecurityPolicy>,
    pub validation: Option<ValidationPolicy>,
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
    pub validation: ValidationPolicy,
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
    pub validation: ValidationPolicy,
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
    pub validation: ValidationPolicy,
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
pub enum ResolutionField {
    Mode,
    Canonicalization,
    Security,
    Validation,
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
pub enum ProfileValidationCode {
    NoCriticalSecurityInvariant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProfileLintCode {
    DeadOverride,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileValidationIssue {
    pub code: ProfileValidationCode,
    pub message: String,
    pub remediation_hint: String,
    pub layer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileLintFinding {
    pub code: ProfileLintCode,
    pub message: String,
    pub remediation_hint: String,
    pub layer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProfileValidationReport {
    pub lints: Vec<ProfileLintFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileValidationFailure {
    pub errors: Vec<ProfileValidationIssue>,
    pub lints: Vec<ProfileLintFinding>,
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
    trace: Vec<String>,
    diagnostics: Vec<ResolutionDiagnostic>,
}

#[derive(Debug, Clone)]
struct EffectivePolicyState {
    mode: InteropMode,
    canonicalization: CanonicalizationPolicy,
    security: SecurityPolicy,
    validation: ValidationPolicy,
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

    fn validate_policy_layer(
        errors: &mut Vec<ProfileValidationIssue>,
        layer: &str,
        security: SecurityPolicy,
    ) {
        if !security.require_signature && !security.require_encryption {
            errors.push(ProfileValidationIssue {
                code: ProfileValidationCode::NoCriticalSecurityInvariant,
                message: format!("{layer} disables both signature and encryption requirements"),
                remediation_hint:
                    "Enable at least one critical security invariant: signature or encryption"
                        .to_string(),
                layer: layer.to_string(),
            });
        }
    }

    fn lint_override_layer(
        lints: &mut Vec<ProfileLintFinding>,
        layer_name: &str,
        current: &EffectivePolicyState,
        overrides: &ProfilePolicyOverrides,
    ) {
        if let Some(mode) = overrides.mode
            && mode == current.mode
        {
            lints.push(ProfileLintFinding {
                code: ProfileLintCode::DeadOverride,
                message: format!(
                    "{layer_name} sets mode to {:?}, which matches already-effective value",
                    mode
                ),
                remediation_hint: "Remove redundant override or change it to a distinct value"
                    .to_string(),
                layer: layer_name.to_string(),
            });
        }

        if let Some(c14n) = overrides.canonicalization.as_ref()
            && *c14n == current.canonicalization
        {
            lints.push(ProfileLintFinding {
                code: ProfileLintCode::DeadOverride,
                message: format!("{layer_name} sets canonicalization to current effective value"),
                remediation_hint: "Remove redundant canonicalization override".into(),
                layer: layer_name.to_string(),
            });
        }

        if let Some(security) = overrides.security
            && security == current.security
        {
            lints.push(ProfileLintFinding {
                code: ProfileLintCode::DeadOverride,
                message: format!("{layer_name} sets security policy to current effective value"),
                remediation_hint: "Remove redundant security override".into(),
                layer: layer_name.to_string(),
            });
        }

        if let Some(validation) = overrides.validation
            && validation == current.validation
        {
            lints.push(ProfileLintFinding {
                code: ProfileLintCode::DeadOverride,
                message: format!("{layer_name} sets validation policy to current effective value"),
                remediation_hint: "Remove redundant validation override".into(),
                layer: layer_name.to_string(),
            });
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
    }

    fn for_each_policy_override_layer<F>(&self, session: Option<&SessionContext>, mut f: F)
    where
        F: FnMut(ResolutionLayer, &'static str, String, &ProfilePolicyOverrides),
    {
        for ext in &self.extensions {
            f(
                ResolutionLayer::Extension,
                "extension",
                ext.name.clone(),
                &ext.overrides,
            );
        }

        for ov in &self.overrides {
            f(
                ResolutionLayer::Override,
                "override",
                ov.name.clone(),
                &ov.overrides,
            );
        }

        for pov in &self.partner_overrides {
            if let Some(s) = session
                && pov.partner_id != s.partner_id()
            {
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

    pub fn validate(&self) -> ProfileValidationResult<ProfileValidationReport> {
        let mut errors = vec![];
        let mut lints = vec![];

        let mut current = EffectivePolicyState {
            mode: self.base.mode,
            canonicalization: self.base.canonicalization.clone(),
            security: self.base.security,
            validation: self.base.validation,
        };

        Self::validate_policy_layer(
            &mut errors,
            &format!("base:{}", self.base.name),
            current.security,
        );

        self.for_each_policy_override_layer(None, |_, layer_kind, layer_name, overrides| {
            let qualified_layer = format!("{}:{}", layer_kind, layer_name);
            Self::lint_override_layer(&mut lints, &qualified_layer, &current, overrides);
            Self::apply_effective_state_overrides(&mut current, overrides);
            Self::validate_policy_layer(&mut errors, &qualified_layer, current.security);
        });

        if errors.is_empty() {
            Ok(ProfileValidationReport { lints })
        } else {
            Err(ProfileValidationFailure { errors, lints })
        }
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
    }

    pub fn resolve(&self, session: &SessionContext) -> EffectiveProfile {
        let mut resolved = ResolvedPolicyState {
            mode: self.base.mode,
            canonicalization: self.base.canonicalization.clone(),
            security: self.base.security,
            validation: self.base.validation,
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

        self.for_each_policy_override_layer(
            Some(session),
            |layer, layer_kind, layer_name, overrides| {
                Self::apply_overrides(&mut resolved, layer, layer_kind, &layer_name, overrides);
            },
        );

        EffectiveProfile {
            name: format!("{}@{}", self.base.name, session.profile_name()),
            mode: resolved.mode,
            canonicalization: resolved.canonicalization.clone(),
            security: resolved.security,
            validation: resolved.validation,
            snapshot: EffectivePolicySnapshot {
                session_id: session.session_id().to_string(),
                partner_id: session.partner_id().to_string(),
                profile_name: session.profile_name().to_string(),
                resolved_mode: resolved.mode,
                canonicalization: resolved.canonicalization.clone(),
                security: resolved.security,
                validation: resolved.validation,
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
