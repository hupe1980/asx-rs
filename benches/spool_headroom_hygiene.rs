use std::sync::atomic::{AtomicU64, Ordering};

use asx_rs::core::{ReceivedBodyHandle, SpoolEncryption, SpoolLifecyclePolicy};
use asx_rs::wire::{StreamBodyPolicy, StreamLimits, read_bounded_stream_into_handle_async};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

static DIR_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn unique_spool_dir(label: &str) -> std::path::PathBuf {
    let seq = DIR_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "asx-spool-hygiene-bench-{label}-{}-{nanos}-{seq}",
        std::process::id()
    ))
}

fn bench_startup_hygiene(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let payload = vec![0xABu8; 64];
    let limits = StreamLimits {
        max_body_bytes: 1024,
        chunk_bytes: 64,
    };

    let mut group = c.benchmark_group("spool_headroom_hygiene");

    group.bench_function("startup_checks_enabled_unique_dir", |b| {
        b.iter(|| {
            let spool_dir = unique_spool_dir("enabled");
            let policy = StreamBodyPolicy {
                spool_threshold_bytes: usize::MAX,
                spool_dir: Some(spool_dir.clone()),
                spool_encryption: SpoolEncryption::Plaintext,
                spool_lifecycle: SpoolLifecyclePolicy::default(),
                spool_retention_ttl_secs: Some(0),
                spool_min_free_bytes: Some(1),
                startup_hygiene_checks: true,
            };

            let outcome = runtime
                .block_on(read_bounded_stream_into_handle_async(
                    payload.as_slice(),
                    limits,
                    &policy,
                    "spool_hygiene_bench_enabled",
                ))
                .expect("startup checks should pass");
            black_box(outcome.1);
            if let ReceivedBodyHandle::Spooled { path, .. } = outcome.0 {
                let _ = std::fs::remove_file(path);
            }
            let _ = std::fs::remove_dir_all(&spool_dir);
        });
    });

    group.bench_function("startup_checks_disabled_unique_dir", |b| {
        b.iter(|| {
            let spool_dir = unique_spool_dir("disabled");
            let policy = StreamBodyPolicy {
                spool_threshold_bytes: usize::MAX,
                spool_dir: Some(spool_dir.clone()),
                spool_encryption: SpoolEncryption::Plaintext,
                spool_lifecycle: SpoolLifecyclePolicy::default(),
                spool_retention_ttl_secs: Some(0),
                spool_min_free_bytes: Some(1),
                startup_hygiene_checks: false,
            };

            let outcome = runtime
                .block_on(read_bounded_stream_into_handle_async(
                    payload.as_slice(),
                    limits,
                    &policy,
                    "spool_hygiene_bench_disabled",
                ))
                .expect("baseline path should pass");
            black_box(outcome.1);
            if let ReceivedBodyHandle::Spooled { path, .. } = outcome.0 {
                let _ = std::fs::remove_file(path);
            }
            let _ = std::fs::remove_dir_all(&spool_dir);
        });
    });

    let steady_spool_dir = unique_spool_dir("steady-state");
    let steady_state_policy = StreamBodyPolicy {
        spool_threshold_bytes: usize::MAX,
        spool_dir: Some(steady_spool_dir.clone()),
        spool_encryption: SpoolEncryption::Plaintext,
        spool_lifecycle: SpoolLifecyclePolicy::default(),
        spool_retention_ttl_secs: Some(0),
        spool_min_free_bytes: Some(1),
        startup_hygiene_checks: true,
    };

    // Prime the directory once so startup hygiene checks are marked completed
    // and subsequent iterations represent steady-state behavior.
    let _ = runtime
        .block_on(read_bounded_stream_into_handle_async(
            payload.as_slice(),
            limits,
            &steady_state_policy,
            "spool_hygiene_bench_steady_prime",
        ))
        .expect("steady-state prime should pass");

    group.bench_function("startup_checks_enabled_reused_dir_steady_state", |b| {
        b.iter(|| {
            let outcome = runtime
                .block_on(read_bounded_stream_into_handle_async(
                    payload.as_slice(),
                    limits,
                    &steady_state_policy,
                    "spool_hygiene_bench_steady",
                ))
                .expect("steady-state path should pass");
            black_box(outcome.1);
            if let ReceivedBodyHandle::Spooled { path, .. } = outcome.0 {
                let _ = std::fs::remove_file(path);
            }
        });
    });

    group.finish();

    let _ = std::fs::remove_dir_all(&steady_spool_dir);
}

criterion_group!(benches, bench_startup_hygiene);
criterion_main!(benches);
