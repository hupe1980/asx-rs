#[cfg(feature = "client")]
use super::spool_key_provider::{
    SPOOL_KEY_PROVIDER_HTTP_CIRCUIT_FAILURE_THRESHOLD_DEFAULT,
    SPOOL_KEY_PROVIDER_HTTP_CIRCUIT_OPEN_BASE_SECS_DEFAULT,
    SPOOL_KEY_PROVIDER_HTTP_CIRCUIT_OPEN_JITTER_SECS_DEFAULT,
    SPOOL_KEY_PROVIDER_HTTP_RETRY_BACKOFF_BASE_MS_DEFAULT,
    SPOOL_KEY_PROVIDER_HTTP_RETRY_BACKOFF_JITTER_MS_DEFAULT,
    SPOOL_KEY_PROVIDER_HTTP_RETRY_MAX_ATTEMPTS_DEFAULT,
};
#[cfg(feature = "client")]
use super::spool_provider_backends::HttpKeyProviderResilienceConfig;
use super::spool_provider_backends::HttpKeyProviderTlsConfig;
use super::{
    As2RegulatedSpoolKeyProvider, AsxError, ErrorCode, ErrorContext, Result, SessionContext,
};
#[cfg(feature = "client")]
use base64::{Engine as _, engine::general_purpose::STANDARD};
#[cfg(feature = "client")]
use sha2::{Digest, Sha256};
#[cfg(feature = "client")]
use std::collections::HashMap;
#[cfg(feature = "client")]
use std::sync::{Mutex, OnceLock};
#[cfg(feature = "client")]
use std::time::Instant;

#[cfg(feature = "client")]
static HTTP_KEY_PROVIDER_CIRCUIT_BY_ENDPOINT: OnceLock<
    Mutex<HashMap<String, HttpKeyProviderCircuitState>>,
> = OnceLock::new();

#[cfg(feature = "client")]
#[derive(Debug, Clone, Copy, Default)]
struct HttpKeyProviderCircuitState {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

#[cfg(feature = "client")]
pub(super) fn fetch_spool_key_hex_over_http(
    provider: As2RegulatedSpoolKeyProvider,
    session: &SessionContext,
    endpoint: String,
    bearer_token: Option<&str>,
    response_hmac_secret: &str,
    tls_config: &HttpKeyProviderTlsConfig,
) -> Result<String> {
    let endpoint_url = parse_and_validate_spool_key_endpoint(provider, session, &endpoint)?;
    let resilience_config = resolve_http_key_provider_resilience_config(provider, session)?;
    validate_http_key_provider_mtls_policy(provider, session, &endpoint_url, tls_config)?;
    let client_identity_pem = resolve_http_key_provider_client_identity_pem(
        provider,
        session,
        &endpoint_url,
        tls_config,
    )?;
    let pinned_trust_anchor_pems =
        resolve_http_key_provider_trust_anchor_pem(provider, session, &endpoint_url, tls_config)?;
    ensure_http_key_provider_circuit_allows_request(
        provider,
        session,
        &endpoint_url,
        &resilience_config,
    )?;

    let provider_label = provider.as_str().to_string();
    let session_id = session.session_id().to_string();
    let partner_id = session.partner_id().to_string();
    let profile_name = session.profile_name().to_string();
    let bearer = bearer_token.map(|s| s.to_string());
    let hmac_secret = response_hmac_secret.to_string();
    let identity_pem = client_identity_pem.clone();
    let trust_anchor_pems = pinned_trust_anchor_pems.clone();
    let endpoint_url_for_worker = endpoint_url.clone();
    let resilience = resilience_config;

    // Run the async HTTP fetch on the current Tokio runtime (which must be a
    // multi-thread runtime because this function is called from within a
    // `spawn_blocking` closure).  Using `block_in_place` + `block_on` avoids
    // spawning a redundant OS thread and a second Tokio runtime, while still
    // allowing the async reqwest client to drive I/O on the shared thread pool.
    let key_result = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async move {
            let mut client_builder = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .user_agent(concat!(
                    env!("CARGO_PKG_NAME"),
                    "/",
                    env!("CARGO_PKG_VERSION")
                ));

            if let Some(identity_pem) = identity_pem {
                let identity = reqwest::Identity::from_pem(&identity_pem)
                    .map_err(|err| format!("invalid mTLS client identity PEM: {err}"))?;
                client_builder = client_builder.identity(identity);
            }

            if !trust_anchor_pems.is_empty() {
                let mut anchors: Vec<reqwest::Certificate> =
                    Vec::with_capacity(trust_anchor_pems.len());
                for pem in &trust_anchor_pems {
                    anchors.push(
                        reqwest::Certificate::from_pem(pem).map_err(|err| {
                            format!("invalid trust-anchor certificate PEM: {err}")
                        })?,
                    );
                }
                client_builder = client_builder.tls_certs_only(anchors);
            }

            let client = client_builder
                .build()
                .map_err(|err| format!("http client build failed: {err}"))?;

            let mut last_retryable: Option<String> = None;
            for attempt in 1..=resilience.retry_max_attempts {
                let mut request =
                    client
                        .post(endpoint_url_for_worker.clone())
                        .json(&serde_json::json!({
                            "provider": &provider_label,
                            "session_id": &session_id,
                            "partner_id": &partner_id,
                            "profile_name": &profile_name,
                        }));

                if let Some(token) = bearer.clone() {
                    request = request.bearer_auth(token);
                }

                let response = match request.send().await {
                    Ok(response) => response,
                    Err(err) => {
                        if attempt < resilience.retry_max_attempts {
                            last_retryable =
                                Some(format!("attempt {attempt} request failed: {err}"));
                            tokio::time::sleep(http_key_provider_backoff_for_attempt(
                                attempt,
                                &resilience,
                                &provider_label,
                                &session_id,
                                &partner_id,
                                &profile_name,
                                endpoint_url_for_worker.as_str(),
                            ))
                            .await;
                            continue;
                        }
                        return Err(format!(
                            "http request failed after {attempt} attempts: {err}"
                        ));
                    }
                };

                let status = response.status();
                if status.is_server_error() && attempt < resilience.retry_max_attempts {
                    last_retryable =
                        Some(format!("attempt {attempt} returned server status {status}"));
                    tokio::time::sleep(http_key_provider_backoff_for_attempt(
                        attempt,
                        &resilience,
                        &provider_label,
                        &session_id,
                        &partner_id,
                        &profile_name,
                        endpoint_url_for_worker.as_str(),
                    ))
                    .await;
                    continue;
                }

                if !status.is_success() {
                    return Err(format!(
                        "http endpoint returned non-success status {status}"
                    ));
                }

                let json: serde_json::Value = response
                    .json()
                    .await
                    .map_err(|err| format!("invalid json response: {err}"))?;

                let key_hex = json
                    .get("key_hex")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "response missing string field 'key_hex'".to_string())?;

                let key_hmac_b64 = json
                    .get("key_hmac_sha256")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "response missing string field 'key_hmac_sha256'".to_string())?;

                verify_http_key_response_hmac(
                    &provider_label,
                    &session_id,
                    &partner_id,
                    &profile_name,
                    key_hex,
                    key_hmac_b64,
                    &hmac_secret,
                )
                .map_err(|err| {
                    format!("response hmac verification failed for key material: {err}")
                })?;

                return Ok(key_hex.to_string());
            }

            Err(last_retryable.unwrap_or_else(|| {
                "http key provider exhausted retries without successful response".to_string()
            }))
        })
    });

    match key_result {
        Ok(key_hex) => {
            note_http_key_provider_circuit_success(provider, &endpoint_url);
            Ok(key_hex)
        }
        Err(message) => {
            note_http_key_provider_circuit_failure(
                provider,
                &endpoint_url,
                &message,
                &resilience_config,
            );
            Err(AsxError::new(
                ErrorCode::PolicyViolation,
                format!(
                    "regulated profile {} provider failed to resolve key via HTTP endpoint: {message}",
                    provider.as_str()
                ),
                ErrorContext::for_session("as2_receive_stream_policy", session),
            ))
        }
    }
}

#[cfg(feature = "client")]
fn http_key_provider_circuit_state_map()
-> &'static Mutex<HashMap<String, HttpKeyProviderCircuitState>> {
    HTTP_KEY_PROVIDER_CIRCUIT_BY_ENDPOINT.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(feature = "client")]
fn http_key_provider_circuit_key(
    provider: As2RegulatedSpoolKeyProvider,
    endpoint: &reqwest::Url,
) -> String {
    format!("{}::{}", provider.as_str(), endpoint)
}

#[cfg(feature = "client")]
fn resolve_http_key_provider_resilience_config(
    provider: As2RegulatedSpoolKeyProvider,
    session: &SessionContext,
) -> Result<HttpKeyProviderResilienceConfig> {
    let retry_max_attempts = parse_http_key_provider_env_usize(
        provider,
        provider.http_retry_max_attempts_env_var(),
        SPOOL_KEY_PROVIDER_HTTP_RETRY_MAX_ATTEMPTS_DEFAULT,
        session,
    )?;
    let retry_backoff_base_ms = parse_http_key_provider_env_u64(
        provider,
        provider.http_retry_backoff_base_ms_env_var(),
        SPOOL_KEY_PROVIDER_HTTP_RETRY_BACKOFF_BASE_MS_DEFAULT,
        session,
    )?;
    let retry_backoff_jitter_ms = parse_http_key_provider_env_u64(
        provider,
        provider.http_retry_backoff_jitter_ms_env_var(),
        SPOOL_KEY_PROVIDER_HTTP_RETRY_BACKOFF_JITTER_MS_DEFAULT,
        session,
    )?;
    let circuit_failure_threshold = parse_http_key_provider_env_u32(
        provider,
        provider.http_circuit_failure_threshold_env_var(),
        SPOOL_KEY_PROVIDER_HTTP_CIRCUIT_FAILURE_THRESHOLD_DEFAULT,
        session,
    )?;
    let circuit_open_base_secs = parse_http_key_provider_env_u64(
        provider,
        provider.http_circuit_open_base_secs_env_var(),
        SPOOL_KEY_PROVIDER_HTTP_CIRCUIT_OPEN_BASE_SECS_DEFAULT,
        session,
    )?;
    let circuit_open_jitter_secs = parse_http_key_provider_env_u64(
        provider,
        provider.http_circuit_open_jitter_secs_env_var(),
        SPOOL_KEY_PROVIDER_HTTP_CIRCUIT_OPEN_JITTER_SECS_DEFAULT,
        session,
    )?;

    if retry_max_attempts == 0 {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            format!(
                "regulated profile {} provider requires retry max attempts >= 1",
                provider.as_str()
            ),
            ErrorContext::for_session("as2_receive_stream_policy", session),
        ));
    }

    if circuit_failure_threshold == 0 {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            format!(
                "regulated profile {} provider requires circuit failure threshold >= 1",
                provider.as_str()
            ),
            ErrorContext::for_session("as2_receive_stream_policy", session),
        ));
    }

    Ok(HttpKeyProviderResilienceConfig {
        retry_max_attempts,
        retry_backoff_base_ms,
        retry_backoff_jitter_ms,
        circuit_failure_threshold,
        circuit_open_base_secs,
        circuit_open_jitter_secs,
    })
}

#[cfg(feature = "client")]
fn parse_http_key_provider_env_usize(
    provider: As2RegulatedSpoolKeyProvider,
    env_var: Option<&'static str>,
    default: usize,
    session: &SessionContext,
) -> Result<usize> {
    match env_var {
        Some(name) => match std::env::var(name) {
            Ok(value) => value.trim().parse::<usize>().map_err(|err| {
                AsxError::new(
                    ErrorCode::PolicyViolation,
                    format!(
                        "regulated profile {} provider has invalid numeric setting in {}: {err}",
                        provider.as_str(),
                        name
                    ),
                    ErrorContext::for_session("as2_receive_stream_policy", session),
                )
            }),
            Err(_) => Ok(default),
        },
        None => Ok(default),
    }
}

#[cfg(feature = "client")]
fn parse_http_key_provider_env_u32(
    provider: As2RegulatedSpoolKeyProvider,
    env_var: Option<&'static str>,
    default: u32,
    session: &SessionContext,
) -> Result<u32> {
    match env_var {
        Some(name) => match std::env::var(name) {
            Ok(value) => value.trim().parse::<u32>().map_err(|err| {
                AsxError::new(
                    ErrorCode::PolicyViolation,
                    format!(
                        "regulated profile {} provider has invalid numeric setting in {}: {err}",
                        provider.as_str(),
                        name
                    ),
                    ErrorContext::for_session("as2_receive_stream_policy", session),
                )
            }),
            Err(_) => Ok(default),
        },
        None => Ok(default),
    }
}

#[cfg(feature = "client")]
fn parse_http_key_provider_env_u64(
    provider: As2RegulatedSpoolKeyProvider,
    env_var: Option<&'static str>,
    default: u64,
    session: &SessionContext,
) -> Result<u64> {
    match env_var {
        Some(name) => match std::env::var(name) {
            Ok(value) => value.trim().parse::<u64>().map_err(|err| {
                AsxError::new(
                    ErrorCode::PolicyViolation,
                    format!(
                        "regulated profile {} provider has invalid numeric setting in {}: {err}",
                        provider.as_str(),
                        name
                    ),
                    ErrorContext::for_session("as2_receive_stream_policy", session),
                )
            }),
            Err(_) => Ok(default),
        },
        None => Ok(default),
    }
}

#[cfg(feature = "client")]
pub(super) fn ensure_http_key_provider_circuit_allows_request(
    provider: As2RegulatedSpoolKeyProvider,
    session: &SessionContext,
    endpoint: &reqwest::Url,
    _resilience: &HttpKeyProviderResilienceConfig,
) -> Result<()> {
    let key = http_key_provider_circuit_key(provider, endpoint);
    let mut guard = http_key_provider_circuit_state_map()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(state) = guard.get_mut(&key)
        && let Some(open_until) = state.open_until
    {
        let now = Instant::now();
        if now < open_until {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                format!(
                    "regulated profile {} provider circuit is open for endpoint {}; retry after cooldown",
                    provider.as_str(),
                    endpoint
                ),
                ErrorContext::for_session("as2_receive_stream_policy", session),
            ));
        }

        state.open_until = None;
        state.consecutive_failures = 0;
    }
    Ok(())
}

#[cfg(feature = "client")]
pub(super) fn note_http_key_provider_circuit_success(
    provider: As2RegulatedSpoolKeyProvider,
    endpoint: &reqwest::Url,
) {
    let key = http_key_provider_circuit_key(provider, endpoint);
    let mut guard = http_key_provider_circuit_state_map()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.remove(&key);
}

#[cfg(feature = "client")]
pub(super) fn note_http_key_provider_circuit_failure(
    provider: As2RegulatedSpoolKeyProvider,
    endpoint: &reqwest::Url,
    reason: &str,
    resilience: &HttpKeyProviderResilienceConfig,
) {
    let key = http_key_provider_circuit_key(provider, endpoint);
    let mut guard = http_key_provider_circuit_state_map()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let threshold = resilience.circuit_failure_threshold;
    let state = guard.entry(key).or_default();
    state.consecutive_failures = state.consecutive_failures.saturating_add(1);
    if state.consecutive_failures >= threshold {
        let cooldown_secs = resilience.circuit_open_base_secs
            + stable_jitter_u64(
                &format!(
                    "{}|{}|{}|{}",
                    provider.as_str(),
                    endpoint,
                    state.consecutive_failures,
                    reason
                ),
                resilience.circuit_open_jitter_secs,
            );
        state.open_until = Some(Instant::now() + std::time::Duration::from_secs(cooldown_secs));
    }
}

#[cfg(feature = "client")]
pub(super) fn http_key_provider_backoff_for_attempt(
    attempt: usize,
    resilience: &HttpKeyProviderResilienceConfig,
    provider_label: &str,
    session_id: &str,
    partner_id: &str,
    profile_name: &str,
    endpoint: &str,
) -> std::time::Duration {
    let exponent = attempt.saturating_sub(1).min(8) as u32;
    let multiplier = 2u64.saturating_pow(exponent);
    let base_ms = resilience.retry_backoff_base_ms.saturating_mul(multiplier);
    let jitter_ms = stable_jitter_u64(
        &format!(
            "{provider_label}|{session_id}|{partner_id}|{profile_name}|{endpoint}|attempt:{attempt}"
        ),
        resilience.retry_backoff_jitter_ms,
    );
    std::time::Duration::from_millis(base_ms.saturating_add(jitter_ms))
}

#[cfg(feature = "client")]
pub(super) fn stable_jitter_u64(seed: &str, max_inclusive: u64) -> u64 {
    if max_inclusive == 0 {
        return 0;
    }

    let digest = Sha256::digest(seed.as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes) % (max_inclusive + 1)
}

#[cfg(feature = "client")]
pub(super) fn key_response_signing_input(
    provider: &str,
    session_id: &str,
    partner_id: &str,
    profile_name: &str,
    key_hex: &str,
) -> String {
    format!("{provider}\n{session_id}\n{partner_id}\n{profile_name}\n{key_hex}")
}

#[cfg(feature = "client")]
pub(super) fn verify_http_key_response_hmac(
    provider: &str,
    session_id: &str,
    partner_id: &str,
    profile_name: &str,
    key_hex: &str,
    key_hmac_sha256_b64: &str,
    shared_secret: &str,
) -> std::result::Result<(), String> {
    let signing_input =
        key_response_signing_input(provider, session_id, partner_id, profile_name, key_hex);

    let hmac_key = openssl::pkey::PKey::hmac(shared_secret.as_bytes())
        .map_err(|err| format!("hmac key error: {err}"))?;
    let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &hmac_key)
        .map_err(|err| format!("hmac signer init error: {err}"))?;
    signer
        .update(signing_input.as_bytes())
        .map_err(|err| format!("hmac signer update error: {err}"))?;
    let expected = signer
        .sign_to_vec()
        .map_err(|err| format!("hmac signer finalize error: {err}"))?;

    let provided = STANDARD
        .decode(key_hmac_sha256_b64)
        .map_err(|err| format!("invalid base64 hmac: {err}"))?;

    if provided != expected {
        return Err("signature mismatch".to_string());
    }

    Ok(())
}

#[cfg(feature = "client")]
fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

#[cfg(feature = "client")]
pub(super) fn validate_http_key_provider_mtls_policy(
    provider: As2RegulatedSpoolKeyProvider,
    session: &SessionContext,
    endpoint: &reqwest::Url,
    tls_config: &HttpKeyProviderTlsConfig,
) -> Result<()> {
    let requires_mtls =
        endpoint.scheme() == "https" && !endpoint.host_str().map(is_loopback_host).unwrap_or(false);

    if !requires_mtls {
        return Ok(());
    }

    match (
        &tls_config.client_cert_pem_path,
        &tls_config.client_key_pem_path,
        tls_config.trust_anchor_cert_pem_paths.is_empty(),
    ) {
        (Some(_), Some(_), false) => Ok(()),
        (Some(_), Some(_), true) => Err(AsxError::new(
            ErrorCode::PolicyViolation,
            format!(
                "regulated profile {} provider requires pinned trust-anchor certificate for non-loopback HTTPS endpoint {}",
                provider.as_str(),
                endpoint
            ),
            ErrorContext::for_session("as2_receive_stream_policy", session),
        )),
        _ => Err(AsxError::new(
            ErrorCode::PolicyViolation,
            format!(
                "regulated profile {} provider requires mTLS client certificate and key plus pinned trust anchor for non-loopback HTTPS endpoint {}",
                provider.as_str(),
                endpoint
            ),
            ErrorContext::for_session("as2_receive_stream_policy", session),
        )),
    }
}

#[cfg(feature = "client")]
pub(super) fn resolve_http_key_provider_trust_anchor_pem(
    provider: As2RegulatedSpoolKeyProvider,
    session: &SessionContext,
    endpoint: &reqwest::Url,
    tls_config: &HttpKeyProviderTlsConfig,
) -> Result<Vec<Vec<u8>>> {
    let requires_pinned_anchor =
        endpoint.scheme() == "https" && !endpoint.host_str().map(is_loopback_host).unwrap_or(false);

    if tls_config.trust_anchor_cert_pem_paths.is_empty() {
        if requires_pinned_anchor {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                format!(
                    "regulated profile {} provider requires pinned trust-anchor certificate for non-loopback HTTPS endpoint {}",
                    provider.as_str(),
                    endpoint
                ),
                ErrorContext::for_session("as2_receive_stream_policy", session),
            ));
        }
        return Ok(Vec::new());
    }

    let mut anchors = Vec::with_capacity(tls_config.trust_anchor_cert_pem_paths.len());
    for path in &tls_config.trust_anchor_cert_pem_paths {
        let pem = std::fs::read(path).map_err(|err| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                format!(
                    "regulated profile {} provider failed reading pinned trust-anchor certificate from {}: {err}",
                    provider.as_str(),
                    path
                ),
                ErrorContext::for_session("as2_receive_stream_policy", session),
            )
        })?;
        anchors.push(pem);
    }

    Ok(anchors)
}

#[cfg(feature = "client")]
pub(super) fn resolve_http_key_provider_client_identity_pem(
    provider: As2RegulatedSpoolKeyProvider,
    session: &SessionContext,
    endpoint: &reqwest::Url,
    tls_config: &HttpKeyProviderTlsConfig,
) -> Result<Option<Vec<u8>>> {
    match (
        &tls_config.client_cert_pem_path,
        &tls_config.client_key_pem_path,
    ) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = std::fs::read(cert_path).map_err(|err| {
                AsxError::new(
                    ErrorCode::PolicyViolation,
                    format!(
                        "regulated profile {} provider failed reading mTLS client certificate from {}: {err}",
                        provider.as_str(),
                        cert_path
                    ),
                    ErrorContext::for_session("as2_receive_stream_policy", session),
                )
            })?;
            let key_pem = std::fs::read(key_path).map_err(|err| {
                AsxError::new(
                    ErrorCode::PolicyViolation,
                    format!(
                        "regulated profile {} provider failed reading mTLS client key from {}: {err}",
                        provider.as_str(),
                        key_path
                    ),
                    ErrorContext::for_session("as2_receive_stream_policy", session),
                )
            })?;

            let mut pem = Vec::with_capacity(cert_pem.len() + 1 + key_pem.len());
            pem.extend_from_slice(&cert_pem);
            if !pem.ends_with(b"\n") {
                pem.push(b'\n');
            }
            pem.extend_from_slice(&key_pem);
            Ok(Some(pem))
        }
        (None, None) => Ok(None),
        _ => Err(AsxError::new(
            ErrorCode::PolicyViolation,
            format!(
                "regulated profile {} provider requires both mTLS client certificate and key paths when one is configured for endpoint {}",
                provider.as_str(),
                endpoint
            ),
            ErrorContext::for_session("as2_receive_stream_policy", session),
        )),
    }
}

#[cfg(feature = "client")]
pub(super) fn parse_and_validate_spool_key_endpoint(
    provider: As2RegulatedSpoolKeyProvider,
    session: &SessionContext,
    endpoint: &str,
) -> Result<reqwest::Url> {
    let endpoint_url = reqwest::Url::parse(endpoint).map_err(|err| {
        AsxError::new(
            ErrorCode::PolicyViolation,
            format!(
                "regulated profile {} provider expects a valid endpoint URL: {err}",
                provider.as_str()
            ),
            ErrorContext::for_session("as2_receive_stream_policy", session),
        )
    })?;

    let scheme = endpoint_url.scheme();
    if scheme == "https" {
        return Ok(endpoint_url);
    }

    if scheme == "http" {
        let host = endpoint_url.host_str().unwrap_or("");
        if is_loopback_host(host) {
            return Ok(endpoint_url);
        }
    }

    Err(AsxError::new(
        ErrorCode::PolicyViolation,
        format!(
            "regulated profile {} provider requires https endpoint URL (or loopback http for local harnesses)",
            provider.as_str()
        ),
        ErrorContext::for_session("as2_receive_stream_policy", session),
    ))
}

#[cfg(not(feature = "client"))]
pub(super) fn fetch_spool_key_hex_over_http(
    provider: As2RegulatedSpoolKeyProvider,
    session: &SessionContext,
    _endpoint: String,
    _bearer_token: Option<&str>,
    _response_hmac_secret: &str,
    _tls_config: &HttpKeyProviderTlsConfig,
) -> Result<String> {
    Err(AsxError::new(
        ErrorCode::PolicyViolation,
        format!(
            "regulated profile {} provider requires crate feature 'client' for HTTP key resolution",
            provider.as_str()
        ),
        ErrorContext::for_session("as2_receive_stream_policy", session),
    ))
}
