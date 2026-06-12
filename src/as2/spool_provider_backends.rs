use super::auth_telemetry::compute_http_provider_auth_telemetry;
#[cfg(feature = "client")]
use super::spool_key_provider::{
    SPOOL_KEY_PROVIDER_HTTP_CIRCUIT_FAILURE_THRESHOLD_DEFAULT,
    SPOOL_KEY_PROVIDER_HTTP_CIRCUIT_OPEN_BASE_SECS_DEFAULT,
    SPOOL_KEY_PROVIDER_HTTP_CIRCUIT_OPEN_JITTER_SECS_DEFAULT,
    SPOOL_KEY_PROVIDER_HTTP_RETRY_BACKOFF_BASE_MS_DEFAULT,
    SPOOL_KEY_PROVIDER_HTTP_RETRY_BACKOFF_JITTER_MS_DEFAULT,
    SPOOL_KEY_PROVIDER_HTTP_RETRY_MAX_ATTEMPTS_DEFAULT,
};
use super::{
    As2RegulatedSpoolKeyProvider, AsxError, ErrorCode, ErrorContext, Result, SessionContext,
    fetch_spool_key_hex_over_http, parse_spool_encryption_key_hex,
};
use std::sync::Arc;

pub(super) trait SpoolEncryptionKeyProvider {
    fn provider_kind(&self) -> As2RegulatedSpoolKeyProvider;

    fn auth_telemetry(&self, _session: &SessionContext) -> SpoolKeyProviderAuthTelemetry {
        default_spool_key_provider_auth_telemetry(self.provider_kind())
    }

    fn resolve_key(&self, session: &SessionContext) -> Result<Arc<[u8; 32]>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::as2) struct SpoolKeyProviderAuthTelemetry {
    pub(in crate::as2) auth_mode: &'static str,
    pub(in crate::as2) auth_fingerprint_label: String,
    pub(in crate::as2) auth_rotation_hint: &'static str,
}

pub(in crate::as2) fn default_spool_key_provider_auth_telemetry(
    provider: As2RegulatedSpoolKeyProvider,
) -> SpoolKeyProviderAuthTelemetry {
    match provider {
        As2RegulatedSpoolKeyProvider::KmsHttp | As2RegulatedSpoolKeyProvider::HsmHttp => {
            SpoolKeyProviderAuthTelemetry {
                auth_mode: "mtls-pinned-trust-anchor",
                auth_fingerprint_label: "unconfigured".to_string(),
                auth_rotation_hint: "unconfigured",
            }
        }
        As2RegulatedSpoolKeyProvider::LocalEnv
        | As2RegulatedSpoolKeyProvider::KmsEnv
        | As2RegulatedSpoolKeyProvider::HsmEnv => SpoolKeyProviderAuthTelemetry {
            auth_mode: "env-key",
            auth_fingerprint_label: "not-applicable".to_string(),
            auth_rotation_hint: "not-applicable",
        },
        As2RegulatedSpoolKeyProvider::LocalFile
        | As2RegulatedSpoolKeyProvider::KmsFile
        | As2RegulatedSpoolKeyProvider::HsmFile => SpoolKeyProviderAuthTelemetry {
            auth_mode: "file-key",
            auth_fingerprint_label: "not-applicable".to_string(),
            auth_rotation_hint: "not-applicable",
        },
    }
}

#[derive(Debug, Clone, Copy)]
struct EnvHexSpoolEncryptionKeyProvider {
    provider: As2RegulatedSpoolKeyProvider,
}

impl EnvHexSpoolEncryptionKeyProvider {
    fn new(provider: As2RegulatedSpoolKeyProvider) -> Self {
        Self { provider }
    }
}

impl SpoolEncryptionKeyProvider for EnvHexSpoolEncryptionKeyProvider {
    fn provider_kind(&self) -> As2RegulatedSpoolKeyProvider {
        self.provider
    }

    fn resolve_key(&self, session: &SessionContext) -> Result<Arc<[u8; 32]>> {
        let env_var = self.provider.key_locator_env_var();
        let key_hex = std::env::var(env_var).map_err(|_| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                format!(
                    "regulated profile requires encrypted spool-at-rest; {} provider expects {}",
                    self.provider.as_str(),
                    env_var
                ),
                ErrorContext::for_session("as2_receive_stream_policy", session),
            )
        })?;
        parse_spool_encryption_key_hex(&key_hex).map_err(|err| {
            AsxError::new(
                err.code,
                format!(
                    "regulated profile requires valid {} key material from {}: {}",
                    self.provider.as_str(),
                    env_var,
                    err.message
                ),
                ErrorContext::for_session("as2_receive_stream_policy", session),
            )
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct FileHexSpoolEncryptionKeyProvider {
    provider: As2RegulatedSpoolKeyProvider,
}

impl FileHexSpoolEncryptionKeyProvider {
    fn new(provider: As2RegulatedSpoolKeyProvider) -> Self {
        Self { provider }
    }
}

impl SpoolEncryptionKeyProvider for FileHexSpoolEncryptionKeyProvider {
    fn provider_kind(&self) -> As2RegulatedSpoolKeyProvider {
        self.provider
    }

    fn resolve_key(&self, session: &SessionContext) -> Result<Arc<[u8; 32]>> {
        let path_env_var = self.provider.key_locator_env_var();
        let key_path = std::env::var(path_env_var).map_err(|_| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                format!(
                    "regulated profile requires encrypted spool-at-rest; {} provider expects key path in {}",
                    self.provider.as_str(),
                    path_env_var
                ),
                ErrorContext::for_session("as2_receive_stream_policy", session),
            )
        })?;

        let key_hex = std::fs::read_to_string(&key_path).map_err(|err| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                format!(
                    "regulated profile requires readable {} key file at {}: {err}",
                    self.provider.as_str(),
                    key_path
                ),
                ErrorContext::for_session("as2_receive_stream_policy", session),
            )
        })?;

        parse_spool_encryption_key_hex(&key_hex).map_err(|err| {
            AsxError::new(
                err.code,
                format!(
                    "regulated profile requires valid {} key material from file {}: {}",
                    self.provider.as_str(),
                    key_path,
                    err.message
                ),
                ErrorContext::for_session("as2_receive_stream_policy", session),
            )
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct HttpJsonSpoolEncryptionKeyProvider {
    provider: As2RegulatedSpoolKeyProvider,
}

#[derive(Debug, Clone, Default)]
pub(in crate::as2) struct HttpKeyProviderTlsConfig {
    pub(in crate::as2) client_cert_pem_path: Option<String>,
    pub(in crate::as2) client_key_pem_path: Option<String>,
    pub(in crate::as2) trust_anchor_cert_pem_paths: Vec<String>,
}

#[cfg(feature = "client")]
#[derive(Debug, Clone, Copy)]
pub(super) struct HttpKeyProviderResilienceConfig {
    pub(super) retry_max_attempts: usize,
    pub(super) retry_backoff_base_ms: u64,
    pub(super) retry_backoff_jitter_ms: u64,
    pub(super) circuit_failure_threshold: u32,
    pub(super) circuit_open_base_secs: u64,
    pub(super) circuit_open_jitter_secs: u64,
}

#[cfg(feature = "client")]
impl Default for HttpKeyProviderResilienceConfig {
    fn default() -> Self {
        Self {
            retry_max_attempts: SPOOL_KEY_PROVIDER_HTTP_RETRY_MAX_ATTEMPTS_DEFAULT,
            retry_backoff_base_ms: SPOOL_KEY_PROVIDER_HTTP_RETRY_BACKOFF_BASE_MS_DEFAULT,
            retry_backoff_jitter_ms: SPOOL_KEY_PROVIDER_HTTP_RETRY_BACKOFF_JITTER_MS_DEFAULT,
            circuit_failure_threshold: SPOOL_KEY_PROVIDER_HTTP_CIRCUIT_FAILURE_THRESHOLD_DEFAULT,
            circuit_open_base_secs: SPOOL_KEY_PROVIDER_HTTP_CIRCUIT_OPEN_BASE_SECS_DEFAULT,
            circuit_open_jitter_secs: SPOOL_KEY_PROVIDER_HTTP_CIRCUIT_OPEN_JITTER_SECS_DEFAULT,
        }
    }
}

impl HttpJsonSpoolEncryptionKeyProvider {
    pub(super) fn new(provider: As2RegulatedSpoolKeyProvider) -> Self {
        Self { provider }
    }

    fn resolve_tls_config(&self) -> HttpKeyProviderTlsConfig {
        HttpKeyProviderTlsConfig {
            client_cert_pem_path: self
                .provider
                .mtls_client_cert_env_var()
                .and_then(|name| std::env::var(name).ok())
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            client_key_pem_path: self
                .provider
                .mtls_client_key_env_var()
                .and_then(|name| std::env::var(name).ok())
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            trust_anchor_cert_pem_paths: self
                .provider
                .trust_anchor_cert_env_var()
                .and_then(|name| std::env::var(name).ok())
                .map(|v| {
                    v.split(',')
                        .map(str::trim)
                        .filter(|p| !p.is_empty())
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
        }
    }
}

impl SpoolEncryptionKeyProvider for HttpJsonSpoolEncryptionKeyProvider {
    fn provider_kind(&self) -> As2RegulatedSpoolKeyProvider {
        self.provider
    }

    fn auth_telemetry(&self, _session: &SessionContext) -> SpoolKeyProviderAuthTelemetry {
        compute_http_provider_auth_telemetry(self.provider, &self.resolve_tls_config())
    }

    fn resolve_key(&self, session: &SessionContext) -> Result<Arc<[u8; 32]>> {
        let endpoint_env_var = self.provider.key_locator_env_var();
        let endpoint = std::env::var(endpoint_env_var).map_err(|_| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                format!(
                    "regulated profile requires encrypted spool-at-rest; {} provider expects endpoint URL in {}",
                    self.provider.as_str(),
                    endpoint_env_var
                ),
                ErrorContext::for_session("as2_receive_stream_policy", session),
            )
        })?;

        let bearer_token = self
            .provider
            .bearer_token_env_var()
            .and_then(|name| std::env::var(name).ok())
            .filter(|value| !value.trim().is_empty());

        let response_hmac_secret_env =
            self.provider
                .response_hmac_secret_env_var()
                .ok_or_else(|| {
                    AsxError::new(
                        ErrorCode::PolicyViolation,
                        format!(
                            "regulated profile requires authenticated {} HTTP response contract",
                            self.provider.as_str()
                        ),
                        ErrorContext::for_session("as2_receive_stream_policy", session),
                    )
                })?;

        let response_hmac_secret = std::env::var(response_hmac_secret_env)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                AsxError::new(
                    ErrorCode::PolicyViolation,
                    format!(
                        "regulated profile requires authenticated {} HTTP response contract; expected shared response-signing secret in {}",
                        self.provider.as_str(),
                        response_hmac_secret_env
                    ),
                    ErrorContext::for_session("as2_receive_stream_policy", session),
                )
            })?;

        let tls_config = self.resolve_tls_config();

        let key_hex = fetch_spool_key_hex_over_http(
            self.provider,
            session,
            endpoint,
            bearer_token.as_deref(),
            &response_hmac_secret,
            &tls_config,
        )?;

        parse_spool_encryption_key_hex(&key_hex).map_err(|err| {
            AsxError::new(
                err.code,
                format!(
                    "regulated profile requires valid {} key material from HTTP endpoint: {}",
                    self.provider.as_str(),
                    err.message
                ),
                ErrorContext::for_session("as2_receive_stream_policy", session),
            )
        })
    }
}

pub(super) fn regulated_spool_key_provider(
    selection: As2RegulatedSpoolKeyProvider,
) -> Box<dyn SpoolEncryptionKeyProvider> {
    match selection {
        As2RegulatedSpoolKeyProvider::LocalEnv
        | As2RegulatedSpoolKeyProvider::KmsEnv
        | As2RegulatedSpoolKeyProvider::HsmEnv => {
            Box::new(EnvHexSpoolEncryptionKeyProvider::new(selection))
        }
        As2RegulatedSpoolKeyProvider::LocalFile
        | As2RegulatedSpoolKeyProvider::KmsFile
        | As2RegulatedSpoolKeyProvider::HsmFile => {
            Box::new(FileHexSpoolEncryptionKeyProvider::new(selection))
        }
        As2RegulatedSpoolKeyProvider::KmsHttp | As2RegulatedSpoolKeyProvider::HsmHttp => {
            Box::new(HttpJsonSpoolEncryptionKeyProvider::new(selection))
        }
    }
}
