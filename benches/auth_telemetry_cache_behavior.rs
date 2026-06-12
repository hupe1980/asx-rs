use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use asx_rs::as2::{As2RegulatedSpoolKeyProvider, compute_http_spool_key_auth_telemetry_labels};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

fn write_file(path: &PathBuf, bytes: &[u8]) {
    fs::write(path, bytes).expect("write benchmark file");
}

fn bench_auth_telemetry_cache_behavior(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth_telemetry_cache_behavior");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = std::env::temp_dir().join(format!("asx-bench-auth-telemetry-{nanos}"));
    fs::create_dir_all(&temp).expect("create benchmark temp dir");
    let cert_path = temp.join("client.cert.pem");
    let anchor_path = temp.join("anchor.ca.pem");

    write_file(
        &cert_path,
        b"-----BEGIN CERTIFICATE-----\nbench-client\n-----END CERTIFICATE-----\n",
    );
    write_file(
        &anchor_path,
        b"-----BEGIN CERTIFICATE-----\nbench-anchor\n-----END CERTIFICATE-----\n",
    );

    group.bench_function("steady_state_cached", |b| {
        b.iter(|| {
            let labels = compute_http_spool_key_auth_telemetry_labels(
                As2RegulatedSpoolKeyProvider::KmsHttp,
                Some(cert_path.to_string_lossy().to_string()),
                vec![anchor_path.to_string_lossy().to_string()],
            );
            black_box(labels);
        });
    });

    let mut sequence = 0u64;
    group.bench_function("rotation_churn", |b| {
        b.iter(|| {
            sequence = sequence.wrapping_add(1);
            // Force metadata signature changes so cache misses are measurable.
            let mut cert_bytes = b"-----BEGIN CERTIFICATE-----\nbench-client-".to_vec();
            cert_bytes.extend_from_slice(sequence.to_string().as_bytes());
            cert_bytes.extend_from_slice(b"\n-----END CERTIFICATE-----\n");
            write_file(&cert_path, &cert_bytes);

            let mut anchor_bytes = b"-----BEGIN CERTIFICATE-----\nbench-anchor-".to_vec();
            anchor_bytes.extend_from_slice(sequence.to_string().as_bytes());
            anchor_bytes.extend_from_slice(b"\n-----END CERTIFICATE-----\n");
            write_file(&anchor_path, &anchor_bytes);

            let labels = compute_http_spool_key_auth_telemetry_labels(
                As2RegulatedSpoolKeyProvider::KmsHttp,
                Some(cert_path.to_string_lossy().to_string()),
                vec![anchor_path.to_string_lossy().to_string()],
            );
            black_box(labels);
        });
    });

    group.bench_with_input(
        BenchmarkId::new("multi_anchor_cached", 4),
        &4usize,
        |b, _| {
            let mut anchors = Vec::new();
            for i in 0..4usize {
                let path = temp.join(format!("anchor-{i}.ca.pem"));
                write_file(
                    &path,
                    format!(
                        "-----BEGIN CERTIFICATE-----\nbench-anchor-{i}\n-----END CERTIFICATE-----\n"
                    )
                    .as_bytes(),
                );
                anchors.push(path.to_string_lossy().to_string());
            }

            b.iter(|| {
                let labels = compute_http_spool_key_auth_telemetry_labels(
                    As2RegulatedSpoolKeyProvider::KmsHttp,
                    Some(cert_path.to_string_lossy().to_string()),
                    anchors.clone(),
                );
                black_box(labels);
            });
        },
    );

    group.finish();
}

criterion_group!(benches, bench_auth_telemetry_cache_behavior);
criterion_main!(benches);
