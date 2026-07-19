#[cfg(any(test, feature = "async-ocsp"))]
use openssl::hash::MessageDigest;
#[cfg(any(test, feature = "async-ocsp"))]
use openssl::ocsp::{OcspCertId, OcspRequest};
use openssl::x509::X509Ref;
use parking_lot::Mutex;
#[cfg(any(test, feature = "async-ocsp"))]
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};
#[cfg(any(test, feature = "async-ocsp"))]
use std::time::Duration;
#[cfg(any(test, feature = "async-ocsp"))]
use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

#[cfg(feature = "async-ocsp")]
const DEFAULT_CACHE_TTL_SECS: u64 = 300;
#[cfg(feature = "async-ocsp")]
const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(3);

/// Maximum number of entries in any OCSP response cache instance.
///
/// When the capacity limit is reached, the LRU entry is evicted automatically.
/// A value of 512 covers typical enterprise deployments (hundreds of distinct
/// partner certificates) with negligible memory footprint (each entry is a few
/// kB of DER-encoded OCSP response data).
pub const DEFAULT_OCSP_CACHE_CAPACITY: usize = 512;

#[derive(Debug, Clone)]
struct CachedResponses {
    expires_at_unix_secs: u64,
    responses_der: Vec<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// OcspResponseCache trait
// ---------------------------------------------------------------------------

pub trait OcspResponseCache: Send + Sync {
    fn get(&self, cache_key: &str, now_secs: u64) -> Result<Option<Vec<Vec<u8>>>>;
    fn put(
        &self,
        cache_key: &str,
        responses_der: &[Vec<u8>],
        expires_at_unix_secs: u64,
    ) -> Result<()>;
}

// ---------------------------------------------------------------------------
// LruOcspResponseCache — instance-scoped, bounded LRU
// ---------------------------------------------------------------------------

/// Instance-scoped OCSP response cache backed by an LRU eviction policy.
///
/// Unlike [`ProcessLocalOcspResponseCache`] which uses a process-global static,
/// this cache is created per-instance (e.g. per tenant, per `RevocationPolicy`)
/// and provides hard memory bounds via LRU eviction.
///
/// ## Usage
///
/// ```rust,ignore
/// let cache = Arc::new(LruOcspResponseCache::new(512));
/// // Pass to RevocationPolicy or fetch functions:
/// // revocation_policy.with_ocsp_cache(cache)
/// ```
///
/// ## Thread safety
///
/// All methods take `&self` and acquire an internal `parking_lot::Mutex`.
/// The lock is held only for the duration of the get/put operation (no I/O),
/// so contention is negligible in practice.
#[derive(Debug)]
pub struct LruOcspResponseCache {
    inner: Mutex<lru::LruCache<String, CachedResponses>>,
}

impl LruOcspResponseCache {
    /// Create a new LRU cache with the given capacity.
    ///
    /// When `capacity` entries are stored and a new entry is inserted, the
    /// least-recently-used entry is evicted automatically.
    pub fn new(capacity: usize) -> Self {
        let cap = std::num::NonZeroUsize::new(capacity.max(1))
            .expect("capacity is always ≥ 1 after max(1)");
        Self {
            inner: Mutex::new(lru::LruCache::new(cap)),
        }
    }

    /// Create with the default capacity ([`DEFAULT_OCSP_CACHE_CAPACITY`]).
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_OCSP_CACHE_CAPACITY)
    }
}

impl OcspResponseCache for LruOcspResponseCache {
    fn get(&self, cache_key: &str, now_secs: u64) -> Result<Option<Vec<Vec<u8>>>> {
        let mut guard = self.inner.lock();
        // `peek` does not update LRU order; `get` does.  Use `get` so that
        // recently-accessed certificates stay in cache under eviction pressure.
        Ok(guard
            .get(cache_key)
            .filter(|entry| entry.expires_at_unix_secs >= now_secs)
            .map(|entry| entry.responses_der.clone()))
    }

    fn put(
        &self,
        cache_key: &str,
        responses_der: &[Vec<u8>],
        expires_at_unix_secs: u64,
    ) -> Result<()> {
        let mut guard = self.inner.lock();
        // `push` inserts and returns the evicted entry (if any); we discard it.
        // LRU eviction is O(1) — no sweep required.
        guard.push(
            cache_key.to_string(),
            CachedResponses {
                expires_at_unix_secs,
                responses_der: responses_der.to_vec(),
            },
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ProcessLocalOcspResponseCache — process-global fallback (single-tenant)
// ---------------------------------------------------------------------------

/// Process-global OCSP response cache.
///
/// Backed by a process-global `parking_lot::Mutex<LruCache>` with hard-bound
/// LRU eviction at [`DEFAULT_OCSP_CACHE_CAPACITY`] entries.
///
/// ## ⚠ Multi-tenant warning
///
/// All callers that use `ProcessLocalOcspResponseCache` share a single cache
/// namespace.  In multi-tenant embeddings, use a per-tenant
/// [`LruOcspResponseCache`] instance instead and pass it via
/// `RevocationPolicy::with_ocsp_cache(...)`.
///
/// The `ocsp_cache_namespace` key prefix in `RevocationPolicy` provides logical
/// isolation within the same physical cache but does NOT prevent a cache-miss
/// storm in one tenant from evicting recently-fetched entries for other tenants.
/// Only instance-scoped caches provide hard memory and LRU isolation.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessLocalOcspResponseCache;

fn process_local_cache() -> &'static Mutex<lru::LruCache<String, CachedResponses>> {
    static CACHE: OnceLock<Mutex<lru::LruCache<String, CachedResponses>>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let cap = std::num::NonZeroUsize::new(DEFAULT_OCSP_CACHE_CAPACITY)
            .expect("DEFAULT_OCSP_CACHE_CAPACITY > 0");
        Mutex::new(lru::LruCache::new(cap))
    })
}

impl OcspResponseCache for ProcessLocalOcspResponseCache {
    fn get(&self, cache_key: &str, now_secs: u64) -> Result<Option<Vec<Vec<u8>>>> {
        Ok(process_local_cache()
            .lock()
            .get(cache_key)
            .filter(|entry| entry.expires_at_unix_secs >= now_secs)
            .map(|entry| entry.responses_der.clone()))
    }

    fn put(
        &self,
        cache_key: &str,
        responses_der: &[Vec<u8>],
        expires_at_unix_secs: u64,
    ) -> Result<()> {
        // `push` evicts the LRU entry when capacity is exceeded — O(1), no sweep.
        process_local_cache().lock().push(
            cache_key.to_string(),
            CachedResponses {
                expires_at_unix_secs,
                responses_der: responses_der.to_vec(),
            },
        );
        Ok(())
    }
}

/// Context for OCSP response fetching operations.
///
/// Bundles parameters needed for fetching OCSP responses, reducing parameter passing
/// complexity and improving API clarity compared to individual parameters.
#[cfg(any(test, feature = "async-ocsp"))]
pub(crate) struct OcspFetchContext<'a> {
    pub cache_key: &'a str,
    pub urls: &'a [String],
    pub request_der: &'a [u8],
    pub cache_provider: &'a dyn OcspResponseCache,
    pub ttl_secs: u64,
    pub timeout: Duration,
    pub now_secs: u64,
}

/// Sync OCSP HTTP transport interface — used only in unit tests via `FakeTransport`.
#[cfg(test)]
pub(crate) trait OcspHttpTransport {
    fn post_ocsp_request(
        &self,
        url: &str,
        request_der: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>>;
}

pub fn fetch_ocsp_responses_with_cache(cert: &X509Ref, issuer: &X509Ref) -> Result<Vec<Vec<u8>>> {
    fetch_ocsp_responses_with_cache_scoped(cert, issuer, "default-global")
}

pub fn fetch_ocsp_responses_with_cache_scoped(
    cert: &X509Ref,
    issuer: &X509Ref,
    cache_namespace: &str,
) -> Result<Vec<Vec<u8>>> {
    fetch_ocsp_responses_with_cache_provider_scoped(
        cert,
        issuer,
        Arc::new(ProcessLocalOcspResponseCache),
        cache_namespace,
    )
}

#[cfg(feature = "async-ocsp")]
pub async fn fetch_ocsp_responses_with_cache_async(
    cert: &X509Ref,
    issuer: &X509Ref,
) -> Result<Vec<Vec<u8>>> {
    fetch_ocsp_responses_with_cache_async_scoped(cert, issuer, "shared").await
}

#[cfg(feature = "async-ocsp")]
pub async fn fetch_ocsp_responses_with_cache_async_scoped(
    cert: &X509Ref,
    issuer: &X509Ref,
    cache_namespace: &str,
) -> Result<Vec<Vec<u8>>> {
    fetch_ocsp_responses_with_cache_provider_async_scoped(
        cert,
        issuer,
        Arc::new(ProcessLocalOcspResponseCache),
        cache_namespace,
    )
    .await
}

#[cfg(feature = "async-ocsp")]
pub async fn fetch_ocsp_responses_with_cache_provider_async(
    cert: &X509Ref,
    issuer: &X509Ref,
    cache_provider: Arc<dyn OcspResponseCache>,
) -> Result<Vec<Vec<u8>>> {
    fetch_ocsp_responses_with_cache_provider_async_scoped(cert, issuer, cache_provider, "shared")
        .await
}

#[cfg(feature = "async-ocsp")]
pub async fn fetch_ocsp_responses_with_cache_provider_async_scoped(
    cert: &X509Ref,
    issuer: &X509Ref,
    cache_provider: Arc<dyn OcspResponseCache>,
    cache_namespace: &str,
) -> Result<Vec<Vec<u8>>> {
    async_transport::fetch_ocsp_responses_with_cache_async_scoped(
        cert,
        issuer,
        cache_provider.as_ref(),
        cache_namespace,
    )
    .await
}

pub fn fetch_ocsp_responses_with_cache_provider(
    cert: &X509Ref,
    issuer: &X509Ref,
    cache_provider: Arc<dyn OcspResponseCache>,
) -> Result<Vec<Vec<u8>>> {
    fetch_ocsp_responses_with_cache_provider_scoped(cert, issuer, cache_provider, "shared")
}

pub fn fetch_ocsp_responses_with_cache_provider_scoped(
    cert: &X509Ref,
    issuer: &X509Ref,
    cache_provider: Arc<dyn OcspResponseCache>,
    cache_namespace: &str,
) -> Result<Vec<Vec<u8>>> {
    #[cfg(feature = "async-ocsp")]
    {
        let handle = tokio::runtime::Handle::try_current().map_err(|_| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                "OCSP fetching with 'async-ocsp' requires an active Tokio runtime; use the async OCSP API or inject a runtime upstream",
                ErrorContext::new("ocsp_client_fetch_async_runtime"),
            )
        })?;

        if matches!(
            handle.runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        ) {
            tokio::task::block_in_place(|| {
                handle.block_on(fetch_ocsp_responses_with_cache_provider_async_scoped(
                    cert,
                    issuer,
                    cache_provider,
                    cache_namespace,
                ))
            })
        } else {
            handle.block_on(fetch_ocsp_responses_with_cache_provider_async_scoped(
                cert,
                issuer,
                cache_provider,
                cache_namespace,
            ))
        }
    }

    #[cfg(not(feature = "async-ocsp"))]
    {
        let _ = (cert, issuer, cache_provider, cache_namespace);
        Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "OCSP responder fetching requires feature 'async-ocsp' (sync fallback removed)",
            ErrorContext::new("ocsp_client_fetch"),
        ))
    }
}

#[cfg(test)]
fn fetch_from_cache_or_responder(
    ctx: &OcspFetchContext<'_>,
    transport: &dyn OcspHttpTransport,
) -> Result<Vec<Vec<u8>>> {
    if let Some(cached) = ctx.cache_provider.get(ctx.cache_key, ctx.now_secs)? {
        return Ok(cached);
    }

    let mut responses = Vec::new();
    for url in ctx.urls {
        let Ok(body) = transport.post_ocsp_request(url, ctx.request_der, ctx.timeout) else {
            continue;
        };
        if !body.is_empty() {
            responses.push(body);
        }
    }

    if !responses.is_empty() {
        ctx.cache_provider.put(
            ctx.cache_key,
            &responses,
            ctx.now_secs.saturating_add(ctx.ttl_secs),
        )?;
    }

    Ok(responses)
}

#[cfg(any(test, feature = "async-ocsp"))]
#[allow(dead_code)]
fn build_ocsp_request_der(cert: &X509Ref, issuer: &X509Ref) -> Result<Vec<u8>> {
    let cert_id = OcspCertId::from_cert(MessageDigest::sha1(), cert, issuer).map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to build OCSP cert id: {err}"),
            ErrorContext::new("ocsp_client_request"),
        )
    })?;

    let mut request = OcspRequest::new().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to initialize OCSP request: {err}"),
            ErrorContext::new("ocsp_client_request"),
        )
    })?;
    request.add_id(cert_id).map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to add cert id to OCSP request: {err}"),
            ErrorContext::new("ocsp_client_request"),
        )
    })?;

    request.to_der().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to serialize OCSP request: {err}"),
            ErrorContext::new("ocsp_client_request"),
        )
    })
}

#[cfg(any(test, feature = "async-ocsp"))]
#[allow(dead_code)]
fn build_cache_key(
    cert: &X509Ref,
    issuer: &X509Ref,
    urls: &[String],
    cache_namespace: &str,
) -> Result<String> {
    let cert_der = cert.to_der().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to serialize certificate DER for OCSP cache key: {err}"),
            ErrorContext::new("ocsp_client_cache"),
        )
    })?;
    let issuer_der = issuer.to_der().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to serialize issuer DER for OCSP cache key: {err}"),
            ErrorContext::new("ocsp_client_cache"),
        )
    })?;

    let mut hasher = Sha256::new();
    hasher.update(cache_namespace.as_bytes());
    hasher.update([0xffu8]);
    hasher.update(cert_der);
    hasher.update(issuer_der);
    for url in urls {
        hasher.update([0u8]);
        hasher.update(url.as_bytes());
    }

    Ok(hex_lower(&hasher.finalize()))
}

#[cfg(any(test, feature = "async-ocsp"))]
#[allow(dead_code)]
fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(any(test, feature = "async-ocsp"))]
#[allow(dead_code)]
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

// Async OCSP support (feature-gated behind "async-ocsp")
#[cfg(feature = "async-ocsp")]
pub mod async_transport {
    use super::*;
    use crate::crypto::ocsp_discovery::discover_ocsp_responder_urls;

    /// Async variant of OcspHttpTransport for non-blocking I/O with tokio.
    ///
    /// Returns a boxed future so the trait is dyn-compatible; embedders that
    /// use `ReqwestOcspTransport` directly pay no boxing cost in practice.
    pub trait AsyncOcspHttpTransport: Send + Sync {
        fn post_ocsp_request_async<'a>(
            &'a self,
            url: &'a str,
            request_der: &'a [u8],
            timeout: Duration,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + 'a>>;
    }

    /// Reqwest-based OCSP transport for async/await
    #[derive(Debug, Default)]
    pub struct ReqwestOcspTransport {
        client: Option<reqwest::Client>,
    }

    impl ReqwestOcspTransport {
        /// Create a new reqwest-based OCSP transport
        pub fn new() -> Self {
            Self { client: None }
        }

        /// Create with a pre-configured reqwest client (for custom settings)
        pub fn with_client(client: reqwest::Client) -> Self {
            Self {
                client: Some(client),
            }
        }

        fn get_client(&self) -> reqwest::Client {
            self.client.clone().unwrap_or_else(|| {
                // The OCSP responder URL is taken from the certificate's AIA
                // extension and is therefore attacker-influenced for an
                // attacker-supplied cert. Never follow redirects: a `3xx` could
                // steer the request to an internal host (SSRF). A responder URL
                // is a fixed endpoint that has no legitimate reason to redirect.
                reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .unwrap_or_default()
            })
        }
    }

    impl AsyncOcspHttpTransport for ReqwestOcspTransport {
        fn post_ocsp_request_async<'a>(
            &'a self,
            url: &'a str,
            request_der: &'a [u8],
            timeout: Duration,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + 'a>>
        {
            Box::pin(async move {
                let client = self.get_client();

                let response = client
                    .post(url)
                    .header("Content-Type", "application/ocsp-request")
                    .header("Accept", "application/ocsp-response")
                    .timeout(timeout)
                    .body(request_der.to_vec())
                    .send()
                    .await
                    .map_err(|err| {
                        AsxError::new(
                            ErrorCode::TransportFailure,
                            format!("failed OCSP responder request (async): {err}"),
                            ErrorContext::new("ocsp_client_fetch_async"),
                        )
                    })?;

                if !response.status().is_success() {
                    return Err(AsxError::new(
                        ErrorCode::TransportFailure,
                        format!("OCSP responder returned HTTP status {}", response.status()),
                        ErrorContext::new("ocsp_client_fetch_async"),
                    ));
                }

                let body = response.bytes().await.map_err(|err| {
                    AsxError::new(
                        ErrorCode::TransportFailure,
                        format!("failed to read OCSP responder body (async): {err}"),
                        ErrorContext::new("ocsp_client_fetch_async"),
                    )
                })?;

                Ok(body.to_vec())
            }) // Box::pin
        }
    }

    /// Fetch OCSP responses asynchronously with caching
    pub async fn fetch_ocsp_responses_with_cache_async(
        cert: &X509Ref,
        issuer: &X509Ref,
        cache_provider: &dyn OcspResponseCache,
    ) -> Result<Vec<Vec<u8>>> {
        fetch_ocsp_responses_with_cache_async_scoped(cert, issuer, cache_provider, "shared").await
    }

    /// Fetch OCSP responses asynchronously with explicit cache namespace.
    pub async fn fetch_ocsp_responses_with_cache_async_scoped(
        cert: &X509Ref,
        issuer: &X509Ref,
        cache_provider: &dyn OcspResponseCache,
        cache_namespace: &str,
    ) -> Result<Vec<Vec<u8>>> {
        fetch_ocsp_responses_with_cache_and_transport_async_scoped(
            AsyncOcspFetchWithTransportRequest {
                cert,
                issuer,
                transport: &ReqwestOcspTransport::new(),
                cache_provider,
                ttl_secs: DEFAULT_CACHE_TTL_SECS,
                timeout: DEFAULT_HTTP_TIMEOUT,
                now_override_unix_secs: None,
                cache_namespace,
            },
        )
        .await
    }

    /// Async fetch with configurable transport
    pub async fn fetch_ocsp_responses_with_cache_and_transport_async(
        cert: &X509Ref,
        issuer: &X509Ref,
        transport: &dyn AsyncOcspHttpTransport,
        cache_provider: &dyn OcspResponseCache,
        ttl_secs: u64,
        timeout: Duration,
        now_override_unix_secs: Option<u64>,
    ) -> Result<Vec<Vec<u8>>> {
        fetch_ocsp_responses_with_cache_and_transport_async_scoped(
            AsyncOcspFetchWithTransportRequest {
                cert,
                issuer,
                transport,
                cache_provider,
                ttl_secs,
                timeout,
                now_override_unix_secs,
                cache_namespace: "shared",
            },
        )
        .await
    }

    pub struct AsyncOcspFetchWithTransportRequest<'a> {
        pub cert: &'a X509Ref,
        pub issuer: &'a X509Ref,
        pub transport: &'a dyn AsyncOcspHttpTransport,
        pub cache_provider: &'a dyn OcspResponseCache,
        pub ttl_secs: u64,
        pub timeout: Duration,
        pub now_override_unix_secs: Option<u64>,
        pub cache_namespace: &'a str,
    }

    /// Async fetch with configurable transport and explicit cache namespace.
    pub async fn fetch_ocsp_responses_with_cache_and_transport_async_scoped(
        request: AsyncOcspFetchWithTransportRequest<'_>,
    ) -> Result<Vec<Vec<u8>>> {
        let AsyncOcspFetchWithTransportRequest {
            cert,
            issuer,
            transport,
            cache_provider,
            ttl_secs,
            timeout,
            now_override_unix_secs,
            cache_namespace,
        } = request;

        let cert_owned = cert.to_owned();
        let mut urls = discover_ocsp_responder_urls(&cert_owned);
        urls.sort();
        urls.dedup();

        if urls.is_empty() {
            return Ok(Vec::new());
        }

        let request_der = build_ocsp_request_der(cert, issuer)?;
        let cache_key = build_cache_key(cert, issuer, &urls, cache_namespace)?;
        let now_secs = now_override_unix_secs.unwrap_or_else(current_unix_secs);

        let ctx = OcspFetchContext {
            cache_key: &cache_key,
            urls: &urls,
            request_der: &request_der,
            cache_provider,
            ttl_secs,
            timeout,
            now_secs,
        };

        fetch_from_cache_or_responder_async(&ctx, transport).await
    }

    pub(crate) async fn fetch_from_cache_or_responder_async(
        ctx: &OcspFetchContext<'_>,
        transport: &dyn AsyncOcspHttpTransport,
    ) -> Result<Vec<Vec<u8>>> {
        if let Some(cached) = ctx.cache_provider.get(ctx.cache_key, ctx.now_secs)? {
            return Ok(cached);
        }

        let mut responses = Vec::new();
        for url in ctx.urls {
            let Ok(body) = transport
                .post_ocsp_request_async(url, ctx.request_der, ctx.timeout)
                .await
            else {
                continue;
            };
            if !body.is_empty() {
                responses.push(body);
            }
        }

        if !responses.is_empty() {
            ctx.cache_provider.put(
                ctx.cache_key,
                &responses,
                ctx.now_secs.saturating_add(ctx.ttl_secs),
            )?;
        }

        Ok(responses)
    }
}

#[cfg(test)]
fn clear_ocsp_response_cache_for_tests() {
    process_local_cache().lock().clear();
}

/// Serializes all tests that touch the process-global OCSP response cache.
///
/// `cargo test` runs tests in parallel by default. Tests that call
/// `clear_ocsp_response_cache_for_tests()` share a single in-process LRU cache, so
/// without a serialization guard a concurrent `clear()` from another test can evict
/// an entry between the two `fetch_from_cache_or_responder` calls in the same test,
/// producing a spurious second transport call. Each cache-touching test must acquire
/// this guard before touching the cache.
#[cfg(test)]
static CACHE_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    struct InMemoryTestCache {
        store: parking_lot::Mutex<std::collections::HashMap<String, CachedResponses>>,
        gets: parking_lot::Mutex<u32>,
        puts: parking_lot::Mutex<u32>,
    }

    impl InMemoryTestCache {
        fn new() -> Self {
            Self {
                store: parking_lot::Mutex::new(std::collections::HashMap::new()),
                gets: parking_lot::Mutex::new(0),
                puts: parking_lot::Mutex::new(0),
            }
        }

        fn get_count(&self) -> u32 {
            *self.gets.lock()
        }

        fn put_count(&self) -> u32 {
            *self.puts.lock()
        }
    }

    impl OcspResponseCache for InMemoryTestCache {
        fn get(&self, cache_key: &str, now_secs: u64) -> Result<Option<Vec<Vec<u8>>>> {
            let mut gets = self.gets.lock();
            *gets += 1;
            drop(gets);

            let store = self.store.lock();
            Ok(store
                .get(cache_key)
                .filter(|entry| entry.expires_at_unix_secs >= now_secs)
                .map(|entry| entry.responses_der.clone()))
        }

        fn put(
            &self,
            cache_key: &str,
            responses_der: &[Vec<u8>],
            expires_at_unix_secs: u64,
        ) -> Result<()> {
            let mut puts = self.puts.lock();
            *puts += 1;
            drop(puts);

            let mut store = self.store.lock();
            store.insert(
                cache_key.to_string(),
                CachedResponses {
                    expires_at_unix_secs,
                    responses_der: responses_der.to_vec(),
                },
            );
            Ok(())
        }
    }

    struct FakeTransport {
        calls: parking_lot::Mutex<u32>,
        payload: Vec<u8>,
    }

    impl FakeTransport {
        fn new(payload: Vec<u8>) -> Self {
            Self {
                calls: parking_lot::Mutex::new(0),
                payload,
            }
        }

        fn call_count(&self) -> u32 {
            *self.calls.lock()
        }
    }

    impl OcspHttpTransport for FakeTransport {
        fn post_ocsp_request(
            &self,
            _url: &str,
            _request_der: &[u8],
            _timeout: Duration,
        ) -> Result<Vec<u8>> {
            let mut calls = self.calls.lock();
            *calls += 1;
            Ok(self.payload.clone())
        }
    }

    #[test]
    fn cache_hit_avoids_second_transport_call() {
        let _guard = CACHE_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_ocsp_response_cache_for_tests();
        let transport = FakeTransport::new(vec![1, 2, 3]);
        let cache_provider = ProcessLocalOcspResponseCache;
        let urls = vec!["http://example.test/ocsp".to_string()];
        let request = vec![9, 9, 9];

        let ctx = OcspFetchContext {
            cache_key: "key-1",
            urls: &urls,
            request_der: &request,
            cache_provider: &cache_provider,
            ttl_secs: 60,
            timeout: Duration::from_secs(1),
            now_secs: 100,
        };
        let first = fetch_from_cache_or_responder(&ctx, &transport).unwrap();

        let ctx = OcspFetchContext {
            cache_key: "key-1",
            urls: &urls,
            request_der: &request,
            cache_provider: &cache_provider,
            ttl_secs: 60,
            timeout: Duration::from_secs(1),
            now_secs: 101,
        };
        let second = fetch_from_cache_or_responder(&ctx, &transport).unwrap();

        assert_eq!(first, vec![vec![1, 2, 3]]);
        assert_eq!(second, vec![vec![1, 2, 3]]);
        assert_eq!(transport.call_count(), 1);
    }

    #[test]
    fn expired_cache_refetches_transport() {
        let _guard = CACHE_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_ocsp_response_cache_for_tests();
        let transport = FakeTransport::new(vec![4, 5, 6]);
        let cache_provider = ProcessLocalOcspResponseCache;
        let urls = vec!["http://example.test/ocsp".to_string()];
        let request = vec![8, 8, 8];

        let ctx = OcspFetchContext {
            cache_key: "key-2",
            urls: &urls,
            request_der: &request,
            cache_provider: &cache_provider,
            ttl_secs: 1,
            timeout: Duration::from_secs(1),
            now_secs: 100,
        };
        let _ = fetch_from_cache_or_responder(&ctx, &transport).unwrap();

        let ctx = OcspFetchContext {
            cache_key: "key-2",
            urls: &urls,
            request_der: &request,
            cache_provider: &cache_provider,
            ttl_secs: 1,
            timeout: Duration::from_secs(1),
            now_secs: 102,
        };
        let _ = fetch_from_cache_or_responder(&ctx, &transport).unwrap();

        assert_eq!(transport.call_count(), 2);
    }

    #[test]
    fn empty_responder_bodies_are_not_cached() {
        let _guard = CACHE_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_ocsp_response_cache_for_tests();
        let transport = FakeTransport::new(Vec::new());
        let cache_provider = ProcessLocalOcspResponseCache;
        let urls = vec!["http://example.test/ocsp".to_string()];
        let request = vec![7, 7, 7];

        let ctx = OcspFetchContext {
            cache_key: "key-3",
            urls: &urls,
            request_der: &request,
            cache_provider: &cache_provider,
            ttl_secs: 60,
            timeout: Duration::from_secs(1),
            now_secs: 100,
        };
        let first = fetch_from_cache_or_responder(&ctx, &transport).unwrap();

        let ctx = OcspFetchContext {
            cache_key: "key-3",
            urls: &urls,
            request_der: &request,
            cache_provider: &cache_provider,
            ttl_secs: 60,
            timeout: Duration::from_secs(1),
            now_secs: 101,
        };
        let second = fetch_from_cache_or_responder(&ctx, &transport).unwrap();

        assert!(first.is_empty());
        assert!(second.is_empty());
        assert_eq!(transport.call_count(), 2);
    }

    #[test]
    fn custom_cache_provider_is_used() {
        let transport = FakeTransport::new(vec![2, 4, 6]);
        let cache_provider = InMemoryTestCache::new();
        let urls = vec!["http://example.test/ocsp".to_string()];
        let request = vec![3, 3, 3];

        let ctx = OcspFetchContext {
            cache_key: "key-custom",
            urls: &urls,
            request_der: &request,
            cache_provider: &cache_provider,
            ttl_secs: 60,
            timeout: Duration::from_secs(1),
            now_secs: 100,
        };
        let first = fetch_from_cache_or_responder(&ctx, &transport).expect("first fetch");

        let ctx = OcspFetchContext {
            cache_key: "key-custom",
            urls: &urls,
            request_der: &request,
            cache_provider: &cache_provider,
            ttl_secs: 60,
            timeout: Duration::from_secs(1),
            now_secs: 101,
        };
        let second = fetch_from_cache_or_responder(&ctx, &transport).expect("second fetch");

        assert_eq!(first, vec![vec![2, 4, 6]]);
        assert_eq!(second, vec![vec![2, 4, 6]]);
        assert_eq!(transport.call_count(), 1);
        assert_eq!(cache_provider.get_count(), 2);
        assert_eq!(cache_provider.put_count(), 1);
    }

    // ── Async transport tests ────────────────────────────────────────────────

    #[cfg(feature = "async-ocsp")]
    mod async_transport_tests {
        use super::super::async_transport::AsyncOcspHttpTransport;
        use super::*;

        struct AsyncFakeTransport {
            calls: parking_lot::Mutex<u32>,
            payload: Vec<u8>,
            fail: bool,
        }

        impl AsyncFakeTransport {
            fn ok(payload: Vec<u8>) -> Self {
                Self {
                    calls: parking_lot::Mutex::new(0),
                    payload,
                    fail: false,
                }
            }

            fn failing() -> Self {
                Self {
                    calls: parking_lot::Mutex::new(0),
                    payload: Vec::new(),
                    fail: true,
                }
            }

            fn call_count(&self) -> u32 {
                *self.calls.lock()
            }
        }

        impl AsyncOcspHttpTransport for AsyncFakeTransport {
            fn post_ocsp_request_async<'a>(
                &'a self,
                _url: &'a str,
                _request_der: &'a [u8],
                _timeout: Duration,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + 'a>>
            {
                Box::pin(async move {
                    let mut calls = self.calls.lock();
                    *calls += 1;
                    drop(calls);
                    if self.fail {
                        return Err(AsxError::new(
                            ErrorCode::TransportFailure,
                            "injected async transport failure",
                            ErrorContext::new("async_fake_transport"),
                        ));
                    }
                    Ok(self.payload.clone())
                })
            }
        }

        // ── cache-or-responder (async) ───────────────────────────────────

        #[tokio::test]
        async fn async_cache_hit_avoids_transport_call() {
            let transport = AsyncFakeTransport::ok(vec![10, 20, 30]);
            let cache = InMemoryTestCache::new();
            let urls = vec!["http://example.test/ocsp".to_string()];
            let req_der = vec![1, 2, 3];

            // Prime the cache manually.
            cache
                .put("async-key-1", &[vec![10, 20, 30]], 9999)
                .expect("prime");

            let ctx = OcspFetchContext {
                cache_key: "async-key-1",
                urls: &urls,
                request_der: &req_der,
                cache_provider: &cache,
                ttl_secs: 60,
                timeout: Duration::from_secs(1),
                now_secs: 100,
            };
            let result = super::super::async_transport::fetch_from_cache_or_responder_async(
                &ctx, &transport,
            )
            .await
            .expect("cache hit");

            assert_eq!(result, vec![vec![10, 20, 30]]);
            // Transport must not have been called — cache served the response.
            assert_eq!(transport.call_count(), 0);
        }

        #[tokio::test]
        async fn async_cache_miss_calls_transport_and_stores_result() {
            let transport = AsyncFakeTransport::ok(vec![7, 8, 9]);
            let cache = InMemoryTestCache::new();
            let urls = vec!["http://example.test/ocsp".to_string()];
            let req_der = vec![4, 5, 6];

            let ctx = OcspFetchContext {
                cache_key: "async-key-2",
                urls: &urls,
                request_der: &req_der,
                cache_provider: &cache,
                ttl_secs: 60,
                timeout: Duration::from_secs(1),
                now_secs: 200,
            };
            let first = super::super::async_transport::fetch_from_cache_or_responder_async(
                &ctx, &transport,
            )
            .await
            .expect("first fetch");

            let ctx = OcspFetchContext {
                cache_key: "async-key-2",
                urls: &urls,
                request_der: &req_der,
                cache_provider: &cache,
                ttl_secs: 60,
                timeout: Duration::from_secs(1),
                now_secs: 201,
            };
            let second = super::super::async_transport::fetch_from_cache_or_responder_async(
                &ctx, &transport,
            )
            .await
            .expect("second fetch");

            assert_eq!(first, vec![vec![7, 8, 9]]);
            assert_eq!(second, vec![vec![7, 8, 9]]);
            // Transport called only on first miss; second served from cache.
            assert_eq!(transport.call_count(), 1);
            assert_eq!(cache.put_count(), 1);
        }

        #[tokio::test]
        async fn async_transport_failure_is_gracefully_skipped() {
            let transport = AsyncFakeTransport::failing();
            let cache = InMemoryTestCache::new();
            let urls = vec!["http://example.test/ocsp".to_string()];
            let req_der = vec![0u8; 16];

            let ctx = OcspFetchContext {
                cache_key: "async-key-fail",
                urls: &urls,
                request_der: &req_der,
                cache_provider: &cache,
                ttl_secs: 60,
                timeout: Duration::from_secs(1),
                now_secs: 300,
            };
            let result = super::super::async_transport::fetch_from_cache_or_responder_async(
                &ctx, &transport,
            )
            .await
            .expect("transport failure must not propagate — result is empty");

            // Transport errors are skipped; empty response is returned without panic.
            assert!(result.is_empty());
            // Nothing cached for a failed fetch.
            assert_eq!(cache.put_count(), 0);
        }

        #[tokio::test]
        async fn async_empty_transport_body_is_not_cached() {
            let transport = AsyncFakeTransport::ok(Vec::new()); // empty body
            let cache = InMemoryTestCache::new();
            let urls = vec!["http://example.test/ocsp".to_string()];
            let req_der = vec![0u8; 4];

            for i in 0u64..3 {
                let ctx = OcspFetchContext {
                    cache_key: "async-key-empty",
                    urls: &urls,
                    request_der: &req_der,
                    cache_provider: &cache,
                    ttl_secs: 60,
                    timeout: Duration::from_secs(1),
                    now_secs: 400 + i,
                };
                let res = super::super::async_transport::fetch_from_cache_or_responder_async(
                    &ctx, &transport,
                )
                .await
                .expect("call");
                assert!(res.is_empty());
            }

            // Transport called every time because empty body is not cached.
            assert_eq!(transport.call_count(), 3);
            assert_eq!(cache.put_count(), 0);
        }

        #[tokio::test]
        async fn async_concurrent_transport_calls_all_complete() {
            let transport = Arc::new(AsyncFakeTransport::ok(vec![42]));
            let cache = Arc::new(InMemoryTestCache::new());
            let urls = vec!["http://example.test/ocsp".to_string()];
            let req_der = vec![0u8; 8];

            const CONCURRENCY: usize = 32;
            let mut handles = Vec::with_capacity(CONCURRENCY);

            for i in 0..CONCURRENCY {
                let transport = transport.clone();
                let cache = cache.clone();
                let urls = urls.clone();
                let req_der = req_der.clone();
                let key = format!("async-concurrent-{i}");
                handles.push(tokio::spawn(async move {
                    let ctx = OcspFetchContext {
                        cache_key: &key,
                        urls: &urls,
                        request_der: &req_der,
                        cache_provider: cache.as_ref(),
                        ttl_secs: 60,
                        timeout: Duration::from_secs(1),
                        now_secs: 500,
                    };
                    super::super::async_transport::fetch_from_cache_or_responder_async(
                        &ctx,
                        transport.as_ref(),
                    )
                    .await
                }));
            }

            let mut successes = 0usize;
            for handle in handles {
                if handle.await.is_ok_and(|r| r.is_ok()) {
                    successes += 1;
                }
            }
            assert_eq!(
                successes, CONCURRENCY,
                "all {CONCURRENCY} concurrent async fetches must succeed"
            );
            // Each unique key misses cache → transport called once per key.
            assert_eq!(transport.call_count() as usize, CONCURRENCY);
        }
    }

    // The previous shared-runtime worker path and its metrics tests were removed.
}
