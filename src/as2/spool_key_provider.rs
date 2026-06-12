pub(super) const SPOOL_KEY_PROVIDER_KMS_HTTP_MTLS_CERT_FILE_ENV: &str =
    "ASX_SPOOL_KMS_DATA_KEY_HTTP_MTLS_CERT_FILE";
pub(super) const SPOOL_KEY_PROVIDER_HSM_HTTP_MTLS_CERT_FILE_ENV: &str =
    "ASX_SPOOL_HSM_DATA_KEY_HTTP_MTLS_CERT_FILE";
pub(super) const SPOOL_KEY_PROVIDER_KMS_HTTP_MTLS_KEY_FILE_ENV: &str =
    "ASX_SPOOL_KMS_DATA_KEY_HTTP_MTLS_KEY_FILE";
pub(super) const SPOOL_KEY_PROVIDER_HSM_HTTP_MTLS_KEY_FILE_ENV: &str =
    "ASX_SPOOL_HSM_DATA_KEY_HTTP_MTLS_KEY_FILE";
pub(super) const SPOOL_KEY_PROVIDER_KMS_HTTP_TRUST_ANCHOR_CERT_FILE_ENV: &str =
    "ASX_SPOOL_KMS_DATA_KEY_HTTP_TRUST_ANCHOR_CERT_FILE";
pub(super) const SPOOL_KEY_PROVIDER_HSM_HTTP_TRUST_ANCHOR_CERT_FILE_ENV: &str =
    "ASX_SPOOL_HSM_DATA_KEY_HTTP_TRUST_ANCHOR_CERT_FILE";
#[cfg(feature = "client")]
pub(super) const SPOOL_KEY_PROVIDER_KMS_HTTP_RETRY_MAX_ATTEMPTS_ENV: &str =
    "ASX_SPOOL_KMS_DATA_KEY_HTTP_RETRY_MAX_ATTEMPTS";
#[cfg(feature = "client")]
pub(super) const SPOOL_KEY_PROVIDER_HSM_HTTP_RETRY_MAX_ATTEMPTS_ENV: &str =
    "ASX_SPOOL_HSM_DATA_KEY_HTTP_RETRY_MAX_ATTEMPTS";
#[cfg(feature = "client")]
pub(super) const SPOOL_KEY_PROVIDER_KMS_HTTP_RETRY_BACKOFF_BASE_MS_ENV: &str =
    "ASX_SPOOL_KMS_DATA_KEY_HTTP_RETRY_BACKOFF_BASE_MS";
#[cfg(feature = "client")]
pub(super) const SPOOL_KEY_PROVIDER_HSM_HTTP_RETRY_BACKOFF_BASE_MS_ENV: &str =
    "ASX_SPOOL_HSM_DATA_KEY_HTTP_RETRY_BACKOFF_BASE_MS";
#[cfg(feature = "client")]
pub(super) const SPOOL_KEY_PROVIDER_KMS_HTTP_RETRY_BACKOFF_JITTER_MS_ENV: &str =
    "ASX_SPOOL_KMS_DATA_KEY_HTTP_RETRY_BACKOFF_JITTER_MS";
#[cfg(feature = "client")]
pub(super) const SPOOL_KEY_PROVIDER_HSM_HTTP_RETRY_BACKOFF_JITTER_MS_ENV: &str =
    "ASX_SPOOL_HSM_DATA_KEY_HTTP_RETRY_BACKOFF_JITTER_MS";
#[cfg(feature = "client")]
pub(super) const SPOOL_KEY_PROVIDER_KMS_HTTP_CIRCUIT_FAILURE_THRESHOLD_ENV: &str =
    "ASX_SPOOL_KMS_DATA_KEY_HTTP_CIRCUIT_FAILURE_THRESHOLD";
#[cfg(feature = "client")]
pub(super) const SPOOL_KEY_PROVIDER_HSM_HTTP_CIRCUIT_FAILURE_THRESHOLD_ENV: &str =
    "ASX_SPOOL_HSM_DATA_KEY_HTTP_CIRCUIT_FAILURE_THRESHOLD";
#[cfg(feature = "client")]
pub(super) const SPOOL_KEY_PROVIDER_KMS_HTTP_CIRCUIT_OPEN_BASE_SECS_ENV: &str =
    "ASX_SPOOL_KMS_DATA_KEY_HTTP_CIRCUIT_OPEN_BASE_SECS";
#[cfg(feature = "client")]
pub(super) const SPOOL_KEY_PROVIDER_HSM_HTTP_CIRCUIT_OPEN_BASE_SECS_ENV: &str =
    "ASX_SPOOL_HSM_DATA_KEY_HTTP_CIRCUIT_OPEN_BASE_SECS";
#[cfg(feature = "client")]
pub(super) const SPOOL_KEY_PROVIDER_KMS_HTTP_CIRCUIT_OPEN_JITTER_SECS_ENV: &str =
    "ASX_SPOOL_KMS_DATA_KEY_HTTP_CIRCUIT_OPEN_JITTER_SECS";
#[cfg(feature = "client")]
pub(super) const SPOOL_KEY_PROVIDER_HSM_HTTP_CIRCUIT_OPEN_JITTER_SECS_ENV: &str =
    "ASX_SPOOL_HSM_DATA_KEY_HTTP_CIRCUIT_OPEN_JITTER_SECS";

pub(super) const SPOOL_KEY_PROVIDER_LOCAL_ENV: &str = "ASX_SPOOL_ENCRYPTION_KEY_HEX";
pub(super) const SPOOL_KEY_PROVIDER_KMS_ENV: &str = "ASX_SPOOL_KMS_DATA_KEY_HEX";
pub(super) const SPOOL_KEY_PROVIDER_HSM_ENV: &str = "ASX_SPOOL_HSM_DATA_KEY_HEX";
pub(super) const SPOOL_KEY_PROVIDER_LOCAL_FILE_ENV: &str = "ASX_SPOOL_ENCRYPTION_KEY_FILE";
pub(super) const SPOOL_KEY_PROVIDER_KMS_FILE_ENV: &str = "ASX_SPOOL_KMS_DATA_KEY_FILE";
pub(super) const SPOOL_KEY_PROVIDER_HSM_FILE_ENV: &str = "ASX_SPOOL_HSM_DATA_KEY_FILE";
pub(super) const SPOOL_KEY_PROVIDER_KMS_HTTP_URL_ENV: &str = "ASX_SPOOL_KMS_DATA_KEY_HTTP_URL";
pub(super) const SPOOL_KEY_PROVIDER_HSM_HTTP_URL_ENV: &str = "ASX_SPOOL_HSM_DATA_KEY_HTTP_URL";
pub(super) const SPOOL_KEY_PROVIDER_KMS_HTTP_BEARER_ENV: &str =
    "ASX_SPOOL_KMS_DATA_KEY_HTTP_BEARER_TOKEN";
pub(super) const SPOOL_KEY_PROVIDER_HSM_HTTP_BEARER_ENV: &str =
    "ASX_SPOOL_HSM_DATA_KEY_HTTP_BEARER_TOKEN";
pub(super) const SPOOL_KEY_PROVIDER_KMS_HTTP_HMAC_SECRET_ENV: &str =
    "ASX_SPOOL_KMS_DATA_KEY_HTTP_RESPONSE_HMAC_SECRET";
pub(super) const SPOOL_KEY_PROVIDER_HSM_HTTP_HMAC_SECRET_ENV: &str =
    "ASX_SPOOL_HSM_DATA_KEY_HTTP_RESPONSE_HMAC_SECRET";

#[cfg(feature = "client")]
pub(super) const SPOOL_KEY_PROVIDER_HTTP_RETRY_MAX_ATTEMPTS_DEFAULT: usize = 3;
#[cfg(feature = "client")]
pub(super) const SPOOL_KEY_PROVIDER_HTTP_RETRY_BACKOFF_BASE_MS_DEFAULT: u64 = 100;
#[cfg(feature = "client")]
pub(super) const SPOOL_KEY_PROVIDER_HTTP_RETRY_BACKOFF_JITTER_MS_DEFAULT: u64 = 50;
#[cfg(feature = "client")]
pub(super) const SPOOL_KEY_PROVIDER_HTTP_CIRCUIT_FAILURE_THRESHOLD_DEFAULT: u32 = 3;
#[cfg(feature = "client")]
pub(super) const SPOOL_KEY_PROVIDER_HTTP_CIRCUIT_OPEN_BASE_SECS_DEFAULT: u64 = 30;
#[cfg(feature = "client")]
pub(super) const SPOOL_KEY_PROVIDER_HTTP_CIRCUIT_OPEN_JITTER_SECS_DEFAULT: u64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum As2RegulatedSpoolKeyProvider {
    #[default]
    LocalEnv,
    KmsEnv,
    HsmEnv,
    LocalFile,
    KmsFile,
    HsmFile,
    KmsHttp,
    HsmHttp,
}

impl As2RegulatedSpoolKeyProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalEnv => "local-env",
            Self::KmsEnv => "kms-env",
            Self::HsmEnv => "hsm-env",
            Self::LocalFile => "local-file",
            Self::KmsFile => "kms-file",
            Self::HsmFile => "hsm-file",
            Self::KmsHttp => "kms-http",
            Self::HsmHttp => "hsm-http",
        }
    }

    pub(super) fn backend(self) -> &'static str {
        match self {
            Self::LocalEnv | Self::KmsEnv | Self::HsmEnv => "env",
            Self::LocalFile | Self::KmsFile | Self::HsmFile => "file",
            Self::KmsHttp | Self::HsmHttp => "http",
        }
    }

    pub(super) fn key_locator_env_var(self) -> &'static str {
        match self {
            Self::LocalEnv => SPOOL_KEY_PROVIDER_LOCAL_ENV,
            Self::KmsEnv => SPOOL_KEY_PROVIDER_KMS_ENV,
            Self::HsmEnv => SPOOL_KEY_PROVIDER_HSM_ENV,
            Self::LocalFile => SPOOL_KEY_PROVIDER_LOCAL_FILE_ENV,
            Self::KmsFile => SPOOL_KEY_PROVIDER_KMS_FILE_ENV,
            Self::HsmFile => SPOOL_KEY_PROVIDER_HSM_FILE_ENV,
            Self::KmsHttp => SPOOL_KEY_PROVIDER_KMS_HTTP_URL_ENV,
            Self::HsmHttp => SPOOL_KEY_PROVIDER_HSM_HTTP_URL_ENV,
        }
    }

    pub(super) fn bearer_token_env_var(self) -> Option<&'static str> {
        match self {
            Self::KmsHttp => Some(SPOOL_KEY_PROVIDER_KMS_HTTP_BEARER_ENV),
            Self::HsmHttp => Some(SPOOL_KEY_PROVIDER_HSM_HTTP_BEARER_ENV),
            _ => None,
        }
    }

    pub(super) fn response_hmac_secret_env_var(self) -> Option<&'static str> {
        match self {
            Self::KmsHttp => Some(SPOOL_KEY_PROVIDER_KMS_HTTP_HMAC_SECRET_ENV),
            Self::HsmHttp => Some(SPOOL_KEY_PROVIDER_HSM_HTTP_HMAC_SECRET_ENV),
            _ => None,
        }
    }

    pub(super) fn mtls_client_cert_env_var(self) -> Option<&'static str> {
        match self {
            Self::KmsHttp => Some(SPOOL_KEY_PROVIDER_KMS_HTTP_MTLS_CERT_FILE_ENV),
            Self::HsmHttp => Some(SPOOL_KEY_PROVIDER_HSM_HTTP_MTLS_CERT_FILE_ENV),
            _ => None,
        }
    }

    pub(super) fn mtls_client_key_env_var(self) -> Option<&'static str> {
        match self {
            Self::KmsHttp => Some(SPOOL_KEY_PROVIDER_KMS_HTTP_MTLS_KEY_FILE_ENV),
            Self::HsmHttp => Some(SPOOL_KEY_PROVIDER_HSM_HTTP_MTLS_KEY_FILE_ENV),
            _ => None,
        }
    }

    pub(super) fn trust_anchor_cert_env_var(self) -> Option<&'static str> {
        match self {
            Self::KmsHttp => Some(SPOOL_KEY_PROVIDER_KMS_HTTP_TRUST_ANCHOR_CERT_FILE_ENV),
            Self::HsmHttp => Some(SPOOL_KEY_PROVIDER_HSM_HTTP_TRUST_ANCHOR_CERT_FILE_ENV),
            _ => None,
        }
    }

    #[cfg(feature = "client")]
    pub(super) fn http_retry_max_attempts_env_var(self) -> Option<&'static str> {
        match self {
            Self::KmsHttp => Some(SPOOL_KEY_PROVIDER_KMS_HTTP_RETRY_MAX_ATTEMPTS_ENV),
            Self::HsmHttp => Some(SPOOL_KEY_PROVIDER_HSM_HTTP_RETRY_MAX_ATTEMPTS_ENV),
            _ => None,
        }
    }

    #[cfg(feature = "client")]
    pub(super) fn http_retry_backoff_base_ms_env_var(self) -> Option<&'static str> {
        match self {
            Self::KmsHttp => Some(SPOOL_KEY_PROVIDER_KMS_HTTP_RETRY_BACKOFF_BASE_MS_ENV),
            Self::HsmHttp => Some(SPOOL_KEY_PROVIDER_HSM_HTTP_RETRY_BACKOFF_BASE_MS_ENV),
            _ => None,
        }
    }

    #[cfg(feature = "client")]
    pub(super) fn http_retry_backoff_jitter_ms_env_var(self) -> Option<&'static str> {
        match self {
            Self::KmsHttp => Some(SPOOL_KEY_PROVIDER_KMS_HTTP_RETRY_BACKOFF_JITTER_MS_ENV),
            Self::HsmHttp => Some(SPOOL_KEY_PROVIDER_HSM_HTTP_RETRY_BACKOFF_JITTER_MS_ENV),
            _ => None,
        }
    }

    #[cfg(feature = "client")]
    pub(super) fn http_circuit_failure_threshold_env_var(self) -> Option<&'static str> {
        match self {
            Self::KmsHttp => Some(SPOOL_KEY_PROVIDER_KMS_HTTP_CIRCUIT_FAILURE_THRESHOLD_ENV),
            Self::HsmHttp => Some(SPOOL_KEY_PROVIDER_HSM_HTTP_CIRCUIT_FAILURE_THRESHOLD_ENV),
            _ => None,
        }
    }

    #[cfg(feature = "client")]
    pub(super) fn http_circuit_open_base_secs_env_var(self) -> Option<&'static str> {
        match self {
            Self::KmsHttp => Some(SPOOL_KEY_PROVIDER_KMS_HTTP_CIRCUIT_OPEN_BASE_SECS_ENV),
            Self::HsmHttp => Some(SPOOL_KEY_PROVIDER_HSM_HTTP_CIRCUIT_OPEN_BASE_SECS_ENV),
            _ => None,
        }
    }

    #[cfg(feature = "client")]
    pub(super) fn http_circuit_open_jitter_secs_env_var(self) -> Option<&'static str> {
        match self {
            Self::KmsHttp => Some(SPOOL_KEY_PROVIDER_KMS_HTTP_CIRCUIT_OPEN_JITTER_SECS_ENV),
            Self::HsmHttp => Some(SPOOL_KEY_PROVIDER_HSM_HTTP_CIRCUIT_OPEN_JITTER_SECS_ENV),
            _ => None,
        }
    }
}

impl std::fmt::Display for As2RegulatedSpoolKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for As2RegulatedSpoolKeyProvider {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.trim() {
            "local-env" => Ok(Self::LocalEnv),
            "kms-env" => Ok(Self::KmsEnv),
            "hsm-env" => Ok(Self::HsmEnv),
            "local-file" => Ok(Self::LocalFile),
            "kms-file" => Ok(Self::KmsFile),
            "hsm-file" => Ok(Self::HsmFile),
            "kms-http" => Ok(Self::KmsHttp),
            "hsm-http" => Ok(Self::HsmHttp),
            other => Err(format!(
                "unsupported AS2 regulated spool key provider '{other}'; expected one of: local-env, kms-env, hsm-env, local-file, kms-file, hsm-file, kms-http, hsm-http"
            )),
        }
    }
}
