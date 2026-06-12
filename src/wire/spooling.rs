use crate::core::{
    AsxError, ErrorCode, ErrorContext, ReceivedBodyHandle, Result, SPOOLED_AES256_GCM_MAGIC,
    SPOOLED_AES256_GCM_NONCE_LEN, SPOOLED_AES256_GCM_TAG_LEN, SpoolEncryption,
};
use dashmap::DashSet;
use openssl::symm::{Cipher, Crypter, Mode};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{
    StreamBodyPolicy, StreamLimits, StreamReadMetrics, bounded_stream_reader, enforce_payload_limit,
};

static SPOOL_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);
static STARTUP_HYGIENE_COMPLETED_DIRS: OnceLock<DashSet<PathBuf>> = OnceLock::new();
pub(super) const STARTUP_HYGIENE_MAX_TTL_SCAN_ENTRIES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct SpoolHygieneObservation {
    startup_hygiene_checked: bool,
    spool_free_bytes: Option<u64>,
    spool_min_free_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct SpoolCleanupOutcome {
    complete: bool,
}

fn cleanup_expired_spool_files(
    stage: &'static str,
    spool_dir: &Path,
    retention_ttl_secs: u64,
) -> Result<SpoolCleanupOutcome> {
    let now = std::time::SystemTime::now();
    let ttl = std::time::Duration::from_secs(retention_ttl_secs);
    let mut scanned_spool_entries = 0usize;
    let mut complete = true;
    for entry in std::fs::read_dir(spool_dir).map_err(|err| {
        AsxError::new(
            ErrorCode::TransportFailure,
            format!(
                "failed to read spool directory {}: {err}",
                spool_dir.display()
            ),
            ErrorContext::new(stage),
        )
    })? {
        let entry = entry.map_err(|err| {
            AsxError::new(
                ErrorCode::TransportFailure,
                format!(
                    "failed to enumerate spool directory {}: {err}",
                    spool_dir.display()
                ),
                ErrorContext::new(stage),
            )
        })?;
        let path = entry.path();
        if path.extension().and_then(|v| v.to_str()) != Some("spool") {
            continue;
        }
        scanned_spool_entries = scanned_spool_entries.saturating_add(1);
        if scanned_spool_entries > STARTUP_HYGIENE_MAX_TTL_SCAN_ENTRIES {
            complete = false;
            break;
        }
        let metadata = entry.metadata().map_err(|err| {
            AsxError::new(
                ErrorCode::TransportFailure,
                format!("failed to stat spool file {}: {err}", path.display()),
                ErrorContext::new(stage),
            )
        })?;
        let modified = metadata.modified().map_err(|err| {
            AsxError::new(
                ErrorCode::TransportFailure,
                format!(
                    "failed to read mtime for spool file {}: {err}",
                    path.display()
                ),
                ErrorContext::new(stage),
            )
        })?;
        if now
            .duration_since(modified)
            .ok()
            .map(|age| age > ttl)
            .unwrap_or(false)
        {
            std::fs::remove_file(&path).map_err(|err| {
                AsxError::new(
                    ErrorCode::TransportFailure,
                    format!(
                        "failed to remove expired spool file {}: {err}",
                        path.display()
                    ),
                    ErrorContext::new(stage),
                )
            })?;
        }
    }
    Ok(SpoolCleanupOutcome { complete })
}

fn run_spool_hygiene_checks(
    stage: &'static str,
    policy: &StreamBodyPolicy,
    spool_dir: &Path,
) -> Result<SpoolHygieneObservation> {
    if !policy.startup_hygiene_checks {
        return Ok(SpoolHygieneObservation::default());
    }

    let completed_dirs = STARTUP_HYGIENE_COMPLETED_DIRS.get_or_init(DashSet::new);
    if completed_dirs.contains(spool_dir) {
        return Ok(SpoolHygieneObservation::default());
    }

    std::fs::create_dir_all(spool_dir).map_err(|err| {
        AsxError::new(
            ErrorCode::TransportFailure,
            format!(
                "failed to create spool directory {}: {err}",
                spool_dir.display()
            ),
            ErrorContext::new(stage),
        )
    })?;

    let mut ttl_cleanup_complete = true;
    if let Some(ttl_secs) = policy.spool_retention_ttl_secs {
        ttl_cleanup_complete = cleanup_expired_spool_files(stage, spool_dir, ttl_secs)?.complete;
    }

    let mut observed_free_bytes = None;
    if let Some(min_free_bytes) = policy.spool_min_free_bytes {
        let free_bytes = query_filesystem_free_bytes(spool_dir, stage)?;
        observed_free_bytes = Some(free_bytes);
        if free_bytes < min_free_bytes {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                format!(
                    "spool free-space headroom check failed: free {} bytes < required {} bytes ({})",
                    free_bytes,
                    min_free_bytes,
                    spool_dir.display()
                ),
                ErrorContext::new(stage),
            ));
        }
    }

    let probe = spool_dir.join(format!("{stage}-probe-{}-{}", std::process::id(), {
        static PROBE_SEQ: AtomicU64 = AtomicU64::new(0);
        PROBE_SEQ.fetch_add(1, Ordering::Relaxed)
    },));
    {
        let mut f = std::fs::File::create(&probe).map_err(|err| {
            AsxError::new(
                ErrorCode::TransportFailure,
                format!(
                    "failed to create spool probe file {}: {err}",
                    probe.display()
                ),
                ErrorContext::new(stage),
            )
        })?;
        use std::io::Write;
        f.write_all(b"asx-spool-probe").map_err(|err| {
            AsxError::new(
                ErrorCode::TransportFailure,
                format!(
                    "failed to write spool probe file {}: {err}",
                    probe.display()
                ),
                ErrorContext::new(stage),
            )
        })?;
    }
    std::fs::remove_file(&probe).map_err(|err| {
        AsxError::new(
            ErrorCode::TransportFailure,
            format!(
                "failed to remove spool probe file {}: {err}",
                probe.display()
            ),
            ErrorContext::new(stage),
        )
    })?;

    if ttl_cleanup_complete {
        completed_dirs.insert(spool_dir.to_path_buf());
    }
    Ok(SpoolHygieneObservation {
        startup_hygiene_checked: true,
        spool_free_bytes: observed_free_bytes,
        spool_min_free_bytes: policy.spool_min_free_bytes,
    })
}

#[cfg(unix)]
fn query_filesystem_free_bytes(path: &Path, stage: &'static str) -> Result<u64> {
    let stat = rustix::fs::statvfs(path).map_err(|err| {
        AsxError::new(
            ErrorCode::TransportFailure,
            format!(
                "failed to query spool filesystem free space for {}: {err}",
                path.display()
            ),
            ErrorContext::new(stage),
        )
    })?;

    Ok((stat.f_bavail as u128)
        .saturating_mul(stat.f_frsize as u128)
        .min(u64::MAX as u128) as u64)
}

#[cfg(not(unix))]
fn query_filesystem_free_bytes(path: &Path, stage: &'static str) -> Result<u64> {
    let _ = (path, stage);
    Err(AsxError::new(
        ErrorCode::PolicyViolation,
        "spool free-space headroom checks are unsupported on this platform",
        ErrorContext::new(stage),
    ))
}

fn build_spool_file_path(stage: &'static str, spool_dir: Option<&Path>) -> Result<PathBuf> {
    let base_dir = spool_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::env::temp_dir().join("asx-receive-spool"));
    std::fs::create_dir_all(&base_dir).map_err(|err| {
        AsxError::new(
            ErrorCode::TransportFailure,
            format!(
                "failed to create spool directory {}: {err}",
                base_dir.display()
            ),
            ErrorContext::new(stage),
        )
    })?;

    let counter = SPOOL_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| {
            AsxError::new(
                ErrorCode::TransportFailure,
                format!("system clock before UNIX_EPOCH: {err}"),
                ErrorContext::new(stage),
            )
        })?
        .as_nanos();
    Ok(base_dir.join(format!("{stage}-{pid}-{nanos}-{counter}.spool")))
}

enum SpoolWriter {
    Plaintext(std::fs::File),
    Aes256Gcm {
        file: std::fs::File,
        crypter: Crypter,
        cipher: Cipher,
    },
}

fn write_spool_chunk(writer: &mut SpoolWriter, chunk: &[u8], stage: &'static str) -> Result<()> {
    use std::io::Write;

    match writer {
        SpoolWriter::Plaintext(file) => file.write_all(chunk).map_err(|err| {
            AsxError::new(
                ErrorCode::TransportFailure,
                format!("failed to write spooled payload chunk: {err}"),
                ErrorContext::new(stage),
            )
        }),
        SpoolWriter::Aes256Gcm {
            file,
            crypter,
            cipher,
        } => {
            let mut out = vec![0u8; chunk.len() + cipher.block_size()];
            let out_len = crypter.update(chunk, &mut out).map_err(|err| {
                AsxError::new(
                    ErrorCode::TransportFailure,
                    format!("failed to encrypt spooled payload chunk: {err}"),
                    ErrorContext::new(stage),
                )
            })?;
            file.write_all(&out[..out_len]).map_err(|err| {
                AsxError::new(
                    ErrorCode::TransportFailure,
                    format!("failed to write encrypted spooled payload chunk: {err}"),
                    ErrorContext::new(stage),
                )
            })
        }
    }
}

pub(super) async fn read_bounded_stream_into_handle_async_impl<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
    limits: StreamLimits,
    body_policy: &StreamBodyPolicy,
    stage: &'static str,
) -> Result<(ReceivedBodyHandle, StreamReadMetrics)> {
    use std::io::Write;
    use tokio::io::AsyncReadExt;

    let mut reader = bounded_stream_reader(reader, limits, stage)?;
    let resolved_spool_dir = body_policy
        .spool_dir
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join("asx-receive-spool"));
    let hygiene = run_spool_hygiene_checks(stage, body_policy, &resolved_spool_dir)?;
    let mut metrics = StreamReadMetrics {
        startup_hygiene_checked: hygiene.startup_hygiene_checked,
        spool_free_bytes: hygiene.spool_free_bytes,
        spool_min_free_bytes: hygiene.spool_min_free_bytes,
        ..StreamReadMetrics::default()
    };
    let mut in_memory = Vec::with_capacity(
        limits
            .chunk_bytes
            .min(body_policy.spool_threshold_bytes)
            .min(limits.max_body_bytes),
    );
    let mut spool_writer: Option<SpoolWriter> = None;
    let mut spool_path: Option<PathBuf> = None;
    let mut spool_encryption: Option<SpoolEncryption> = None;
    let mut chunk = vec![0u8; limits.chunk_bytes];

    loop {
        let n = reader.read(&mut chunk).await.map_err(|err| {
            AsxError::new(
                ErrorCode::TransportFailure,
                format!("async stream read failed: {err}"),
                ErrorContext::new(stage),
            )
        })?;
        if n == 0 {
            break;
        }

        metrics.total_bytes += n;
        metrics.chunks += 1;
        metrics.max_chunk_seen = metrics.max_chunk_seen.max(n);
        enforce_payload_limit(stage, metrics.total_bytes, limits.max_body_bytes)?;

        if let Some(writer) = spool_writer.as_mut() {
            write_spool_chunk(writer, &chunk[..n], stage)?;
            continue;
        }

        if in_memory.len().saturating_add(n) <= body_policy.spool_threshold_bytes {
            in_memory.extend_from_slice(&chunk[..n]);
            continue;
        }

        let path = build_spool_file_path(stage, Some(&resolved_spool_dir))?;
        let mut file = std::fs::File::create(&path).map_err(|err| {
            AsxError::new(
                ErrorCode::TransportFailure,
                format!("failed to create spool file {}: {err}", path.display()),
                ErrorContext::new(stage),
            )
        })?;

        let encryption = body_policy.spool_encryption.clone();
        let mut writer = match &encryption {
            SpoolEncryption::Plaintext => SpoolWriter::Plaintext(file),
            SpoolEncryption::Aes256Gcm { key } => {
                let mut nonce = [0u8; SPOOLED_AES256_GCM_NONCE_LEN];
                getrandom::fill(&mut nonce).map_err(|err| {
                    AsxError::new(
                        ErrorCode::TransportFailure,
                        format!("failed to generate spool encryption nonce: {err}"),
                        ErrorContext::new(stage),
                    )
                })?;
                file.write_all(&SPOOLED_AES256_GCM_MAGIC).map_err(|err| {
                    AsxError::new(
                        ErrorCode::TransportFailure,
                        format!("failed to write spool encryption header: {err}"),
                        ErrorContext::new(stage),
                    )
                })?;
                file.write_all(&nonce).map_err(|err| {
                    AsxError::new(
                        ErrorCode::TransportFailure,
                        format!("failed to write spool encryption nonce: {err}"),
                        ErrorContext::new(stage),
                    )
                })?;
                let cipher = Cipher::aes_256_gcm();
                let mut crypter = Crypter::new(cipher, Mode::Encrypt, key.as_ref(), Some(&nonce))
                    .map_err(|err| {
                    AsxError::new(
                        ErrorCode::TransportFailure,
                        format!("failed to initialize spool encryption crypter: {err}"),
                        ErrorContext::new(stage),
                    )
                })?;
                crypter.pad(false);
                SpoolWriter::Aes256Gcm {
                    file,
                    crypter,
                    cipher,
                }
            }
        };

        if !in_memory.is_empty() {
            write_spool_chunk(&mut writer, &in_memory, stage)?;
            in_memory.clear();
        }
        write_spool_chunk(&mut writer, &chunk[..n], stage)?;

        spool_writer = Some(writer);
        spool_path = Some(path);
        spool_encryption = Some(encryption);
        metrics.used_spool = true;
    }

    if let Some(mut writer) = spool_writer {
        match &mut writer {
            SpoolWriter::Plaintext(file) => {
                file.flush().map_err(|err| {
                    AsxError::new(
                        ErrorCode::TransportFailure,
                        format!("failed to flush spooled payload: {err}"),
                        ErrorContext::new(stage),
                    )
                })?;
            }
            SpoolWriter::Aes256Gcm {
                file,
                crypter,
                cipher,
            } => {
                let mut out = vec![0u8; cipher.block_size()];
                let out_len = crypter.finalize(&mut out).map_err(|err| {
                    AsxError::new(
                        ErrorCode::TransportFailure,
                        format!("failed to finalize spool encryption stream: {err}"),
                        ErrorContext::new(stage),
                    )
                })?;
                if out_len > 0 {
                    file.write_all(&out[..out_len]).map_err(|err| {
                        AsxError::new(
                            ErrorCode::TransportFailure,
                            format!("failed to write final encrypted spool bytes: {err}"),
                            ErrorContext::new(stage),
                        )
                    })?;
                }

                let mut tag = [0u8; SPOOLED_AES256_GCM_TAG_LEN];
                crypter.get_tag(&mut tag).map_err(|err| {
                    AsxError::new(
                        ErrorCode::TransportFailure,
                        format!("failed to get spool encryption tag: {err}"),
                        ErrorContext::new(stage),
                    )
                })?;
                file.write_all(&tag).map_err(|err| {
                    AsxError::new(
                        ErrorCode::TransportFailure,
                        format!("failed to write spool encryption tag: {err}"),
                        ErrorContext::new(stage),
                    )
                })?;
                file.flush().map_err(|err| {
                    AsxError::new(
                        ErrorCode::TransportFailure,
                        format!("failed to flush encrypted spooled payload: {err}"),
                        ErrorContext::new(stage),
                    )
                })?;
            }
        }
        let path = spool_path.ok_or_else(|| {
            AsxError::new(
                ErrorCode::TransportFailure,
                "internal spool invariant violated: missing spool path after writer finalization",
                ErrorContext::new(stage),
            )
        })?;
        let encryption = spool_encryption.ok_or_else(|| {
            AsxError::new(
                ErrorCode::TransportFailure,
                "internal spool invariant violated: missing spool encryption state after writer finalization",
                ErrorContext::new(stage),
            )
        })?;
        return Ok((
            ReceivedBodyHandle::Spooled {
                path,
                encryption,
                lifecycle: body_policy.spool_lifecycle.clone(),
            },
            metrics,
        ));
    }

    Ok((
        ReceivedBodyHandle::InMemory(std::sync::Arc::from(in_memory)),
        metrics,
    ))
}
