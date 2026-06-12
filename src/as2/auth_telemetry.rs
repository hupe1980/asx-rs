//! HTTP spool-key-provider authentication-telemetry helpers.
//!
//! Provides a process-global LRU fingerprint cache so that PEM-file SHA-256
//! labels are computed at most once per inode revision, and exposes
//! [`compute_http_spool_key_auth_telemetry_labels`] for callers that need the
//! `(auth_fingerprint_label, auth_rotation_hint)` pair for structured logging.

use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::as2::spool_key_provider::As2RegulatedSpoolKeyProvider;
use crate::as2::spool_provider_backends::{
    HttpKeyProviderTlsConfig, SpoolKeyProviderAuthTelemetry,
    default_spool_key_provider_auth_telemetry,
};

const HTTP_PROVIDER_FINGERPRINT_CACHE_MAX_ENTRIES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprintSignature {
    size_bytes: u64,
    modified_secs: u64,
    modified_nanos: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedFileFingerprint {
    signature: FileFingerprintSignature,
    label: String,
}

#[derive(Debug, Default)]
struct HttpProviderFingerprintCache {
    entries: HashMap<PathBuf, CachedFileFingerprint>,
    insertion_order: VecDeque<PathBuf>,
}

impl HttpProviderFingerprintCache {
    fn get_if_fresh(&self, path: &Path, signature: &FileFingerprintSignature) -> Option<String> {
        self.entries.get(path).and_then(|cached| {
            if &cached.signature == signature {
                Some(cached.label.clone())
            } else {
                None
            }
        })
    }

    fn insert(&mut self, path: PathBuf, entry: CachedFileFingerprint) {
        let already_present = self.entries.contains_key(&path);
        self.entries.insert(path.clone(), entry);
        if !already_present {
            self.insertion_order.push_back(path.clone());
        }

        while self.entries.len() > HTTP_PROVIDER_FINGERPRINT_CACHE_MAX_ENTRIES {
            if let Some(evicted) = self.insertion_order.pop_front() {
                self.entries.remove(&evicted);
            } else {
                break;
            }
        }
    }
}

fn http_provider_fingerprint_cache() -> &'static Mutex<HttpProviderFingerprintCache> {
    static CACHE: OnceLock<Mutex<HttpProviderFingerprintCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HttpProviderFingerprintCache::default()))
}

fn metadata_signature(path: &Path) -> std::io::Result<FileFingerprintSignature> {
    let metadata = std::fs::metadata(path)?;
    let modified = metadata.modified()?;
    let duration = modified
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    Ok(FileFingerprintSignature {
        size_bytes: metadata.len(),
        modified_secs: duration.as_secs(),
        modified_nanos: duration.subsec_nanos(),
    })
}

fn short_sha256_label(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(16);
    for b in &digest[..8] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn short_sha256_label_for_file_cached(path: &Path) -> Option<String> {
    let signature = metadata_signature(path).ok()?;

    if let Some(label) = http_provider_fingerprint_cache()
        .lock()
        .get_if_fresh(path, &signature)
    {
        return Some(label);
    }

    let bytes = std::fs::read(path).ok()?;
    let label = short_sha256_label(&bytes);

    http_provider_fingerprint_cache().lock().insert(
        path.to_path_buf(),
        CachedFileFingerprint {
            signature,
            label: label.clone(),
        },
    );

    Some(label)
}

pub(super) fn compute_http_provider_auth_telemetry(
    provider: As2RegulatedSpoolKeyProvider,
    tls_config: &HttpKeyProviderTlsConfig,
) -> SpoolKeyProviderAuthTelemetry {
    let mut telemetry = default_spool_key_provider_auth_telemetry(provider);
    let anchor_count = tls_config.trust_anchor_cert_pem_paths.len();
    telemetry.auth_rotation_hint = if anchor_count > 1 {
        "rotation-window"
    } else if anchor_count == 1 {
        "single-anchor"
    } else {
        "unconfigured"
    };

    let client_label = match tls_config.client_cert_pem_path.as_deref() {
        Some(path) => short_sha256_label_for_file_cached(Path::new(path))
            .map(|label| format!("client:{label}"))
            .unwrap_or_else(|| "client:unavailable".to_string()),
        None => "client:unconfigured".to_string(),
    };

    let anchor_labels = if tls_config.trust_anchor_cert_pem_paths.is_empty() {
        "anchors:unconfigured".to_string()
    } else {
        let labels = tls_config
            .trust_anchor_cert_pem_paths
            .iter()
            .map(|path| {
                short_sha256_label_for_file_cached(Path::new(path))
                    .unwrap_or_else(|| "unavailable".to_string())
            })
            .collect::<Vec<_>>();
        format!("anchors:{}", labels.join("+"))
    };

    telemetry.auth_fingerprint_label = format!("{client_label};{anchor_labels}");
    telemetry
}

/// Returns the `(auth_fingerprint_label, auth_rotation_hint)` telemetry pair
/// for an HTTP spool-key provider TLS configuration.
///
/// SHA-256 file labels are cached per-inode to avoid re-reading PEM files on
/// every call.
#[cfg(feature = "client")]
pub fn compute_http_spool_key_auth_telemetry_labels(
    provider: As2RegulatedSpoolKeyProvider,
    client_cert_pem_path: Option<String>,
    trust_anchor_cert_pem_paths: Vec<String>,
) -> (String, &'static str) {
    let telemetry = compute_http_provider_auth_telemetry(
        provider,
        &HttpKeyProviderTlsConfig {
            client_cert_pem_path,
            client_key_pem_path: None,
            trust_anchor_cert_pem_paths,
        },
    );
    (
        telemetry.auth_fingerprint_label,
        telemetry.auth_rotation_hint,
    )
}
