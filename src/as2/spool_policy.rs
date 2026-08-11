use super::spool_key::{SpoolEncryptionKeyProvider, reject_unusable_key};
use super::types::As2ReceivePolicy;
use super::{AsxError, ErrorCode, ErrorContext, SessionContext, SpoolEncryption};
use super::{SpoolLifecyclePolicy, StreamBodyPolicy};
use super::{as2_spool_threshold_for_profile, profile_requires_encrypted_spool};
use std::time::Instant;

/// Recorded when a spool key provider answers successfully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpoolKeyProviderObservation {
    pub(crate) provider: &'static str,
    pub(crate) health_state: &'static str,
    pub(crate) resolve_key_ms: u64,
}

/// Recorded when a spool key provider fails to answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpoolKeyProviderFailureObservation {
    pub(crate) provider: &'static str,
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
    let label = provider.label();

    let resolve_start = Instant::now();
    let key = match provider.resolve_key(session) {
        Ok(key) => key,
        Err(error) => {
            return StreamBodyPolicyBuildOutcome::ProviderFailure {
                observation: SpoolKeyProviderFailureObservation {
                    provider: label,
                    health_state: "failing",
                    phase: "key_resolution",
                    error_code: error.code.as_str(),
                },
                error,
            };
        }
    };
    let resolve_key_ms = u64::try_from(resolve_start.elapsed().as_millis()).unwrap_or(u64::MAX);

    // A custom provider can return anything; re-check the one property that
    // distinguishes a key from a misconfiguration. There is deliberately no
    // AES known-answer test here: verifying OpenSSL on every spool decision
    // costs latency per message and has never been the failing component.
    if let Err(error) = reject_unusable_key(key.as_ref()) {
        return StreamBodyPolicyBuildOutcome::ProviderFailure {
            observation: SpoolKeyProviderFailureObservation {
                provider: label,
                health_state: "failing",
                phase: "key_validation",
                error_code: error.code.as_str(),
            },
            error,
        };
    }

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
            provider: label,
            health_state: "healthy",
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
        // Fail closed: a profile that mandates encrypted spooling must not
        // silently fall back to writing payloads to disk in the clear.
        let Some(provider) = policy.spool_key_provider.as_ref() else {
            let error = AsxError::new(
                ErrorCode::PolicyViolation,
                format!(
                    "profile '{profile_name}' requires an encrypted payload spool, but \
                     As2ReceivePolicy::spool_key_provider is not set. Supply a \
                     SpoolEncryptionKeyProvider — StaticSpoolKey::from_env(\"…\") for \
                     development, or your own KMS/HSM implementation"
                ),
                ErrorContext::for_session("as2_receive_stream_policy", session),
            );
            return StreamBodyPolicyBuildOutcome::ProviderFailure {
                observation: SpoolKeyProviderFailureObservation {
                    provider: "unconfigured",
                    health_state: "failing",
                    phase: "provider_selection",
                    error_code: error.code.as_str(),
                },
                error,
            };
        };

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
