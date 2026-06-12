use super::types::As2ReceivePolicy;
use super::{AsxError, SessionContext, SpoolEncryption, SpoolLifecyclePolicy, StreamBodyPolicy};
use super::{SpoolEncryptionKeyProvider, regulated_spool_key_provider};
use super::{
    as2_spool_threshold_for_profile, profile_requires_encrypted_spool,
    validate_spool_encryption_key_startup_self_test,
};
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpoolKeyProviderObservation {
    pub(crate) provider: &'static str,
    pub(crate) backend: &'static str,
    pub(crate) auth_mode: &'static str,
    pub(crate) auth_fingerprint_label: String,
    pub(crate) auth_rotation_hint: &'static str,
    pub(crate) health_state: &'static str,
    pub(crate) startup_self_test_ms: u64,
    pub(crate) resolve_key_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpoolKeyProviderFailureObservation {
    pub(crate) provider: &'static str,
    pub(crate) backend: &'static str,
    pub(crate) auth_mode: &'static str,
    pub(crate) auth_fingerprint_label: String,
    pub(crate) auth_rotation_hint: &'static str,
    pub(crate) health_state: &'static str,
    pub(crate) phase: &'static str,
    pub(crate) error_code: &'static str,
}

pub(crate) enum StreamBodyPolicyBuildOutcome {
    Ready {
        body_policy: StreamBodyPolicy,
        provider_observation: Option<SpoolKeyProviderObservation>,
    },
    ProviderFailure {
        error: AsxError,
        observation: SpoolKeyProviderFailureObservation,
    },
}

pub(super) fn regulated_stream_body_policy_build_with_provider(
    session: &SessionContext,
    spool_threshold_bytes: usize,
    provider: &dyn SpoolEncryptionKeyProvider,
) -> StreamBodyPolicyBuildOutcome {
    let provider_kind = provider.provider_kind();
    let auth_telemetry = provider.auth_telemetry(session);

    let resolve_start = Instant::now();
    let key = match provider.resolve_key(session) {
        Ok(key) => key,
        Err(error) => {
            return StreamBodyPolicyBuildOutcome::ProviderFailure {
                observation: SpoolKeyProviderFailureObservation {
                    provider: provider_kind.as_str(),
                    backend: provider_kind.backend(),
                    auth_mode: auth_telemetry.auth_mode,
                    auth_fingerprint_label: auth_telemetry.auth_fingerprint_label,
                    auth_rotation_hint: auth_telemetry.auth_rotation_hint,
                    health_state: "failing",
                    phase: "key_resolution",
                    error_code: error.code.as_str(),
                },
                error,
            };
        }
    };
    let resolve_key_ms = u64::try_from(resolve_start.elapsed().as_millis()).unwrap_or(u64::MAX);

    let self_test_start = Instant::now();
    if let Err(error) =
        validate_spool_encryption_key_startup_self_test(provider_kind, session, key.as_ref())
    {
        return StreamBodyPolicyBuildOutcome::ProviderFailure {
            observation: SpoolKeyProviderFailureObservation {
                provider: provider_kind.as_str(),
                backend: provider_kind.backend(),
                auth_mode: auth_telemetry.auth_mode,
                auth_fingerprint_label: auth_telemetry.auth_fingerprint_label,
                auth_rotation_hint: auth_telemetry.auth_rotation_hint,
                health_state: "failing",
                phase: "startup_self_test",
                error_code: error.code.as_str(),
            },
            error,
        };
    }
    let startup_self_test_ms =
        u64::try_from(self_test_start.elapsed().as_millis()).unwrap_or(u64::MAX);

    StreamBodyPolicyBuildOutcome::Ready {
        body_policy: StreamBodyPolicy {
            spool_threshold_bytes,
            spool_dir: None,
            spool_encryption: SpoolEncryption::Aes256Gcm { key },
            spool_lifecycle: SpoolLifecyclePolicy {
                delete_on_materialize: true,
                secure_delete_on_materialize: true,
            },
            spool_retention_ttl_secs: Some(3600),
            spool_min_free_bytes: Some(64 * 1024 * 1024),
            startup_hygiene_checks: true,
        },
        provider_observation: Some(SpoolKeyProviderObservation {
            provider: provider_kind.as_str(),
            backend: provider_kind.backend(),
            auth_mode: auth_telemetry.auth_mode,
            auth_fingerprint_label: auth_telemetry.auth_fingerprint_label,
            auth_rotation_hint: auth_telemetry.auth_rotation_hint,
            health_state: "healthy",
            startup_self_test_ms,
            resolve_key_ms,
        }),
    }
}

pub(crate) fn as2_stream_body_policy_build(
    session: &SessionContext,
    policy: &As2ReceivePolicy,
) -> StreamBodyPolicyBuildOutcome {
    let profile_name = session.profile_name();
    let spool_threshold_bytes = as2_spool_threshold_for_profile(profile_name);
    if profile_requires_encrypted_spool(profile_name) {
        let provider = regulated_spool_key_provider(policy.regulated_spool_key_provider);
        return regulated_stream_body_policy_build_with_provider(
            session,
            spool_threshold_bytes,
            provider.as_ref(),
        );
    }

    StreamBodyPolicyBuildOutcome::Ready {
        body_policy: StreamBodyPolicy {
            spool_threshold_bytes,
            spool_dir: None,
            spool_encryption: SpoolEncryption::Plaintext,
            spool_lifecycle: SpoolLifecyclePolicy {
                delete_on_materialize: true,
                secure_delete_on_materialize: false,
            },
            spool_retention_ttl_secs: Some(3600),
            spool_min_free_bytes: Some(16 * 1024 * 1024),
            startup_hygiene_checks: true,
        },
        provider_observation: None,
    }
}
