# Benchmark Baseline (2026-05-21)

## Scope

Criterion benchmark run for:

- `as4_streaming_vs_buffer`

This baseline was captured after adding `black_box` barriers in the benchmark code to avoid optimizer-elided measurements (especially for MIME boundary scan microbenchmarks).

## Environment

- Host OS: macOS
- CPU: Apple M4 Pro
- Logical CPUs: 14
- Rust: `rustc 1.92.0 (ded5c06cf 2025-12-08)`
- Cargo: `cargo 1.92.0 (344c4567c 2025-10-21)`
- Repository revision: `fe98820`
- Worktree state at run time: dirty (`12` changed paths)

## Command

```bash
cargo bench --bench as4_streaming_vs_buffer --features "as4"
```

## Results

Reported values are Criterion confidence intervals from this run.

### XML Parse (`xml_parse`)

- `roxmltree_parse/1097`
  - time: `[3.1817 us, 3.3935 us, 3.6512 us]`
  - throughput: `[286.53 MiB/s, 308.29 MiB/s, 328.82 MiB/s]`
- `roxmltree_parse/1502`
  - time: `[6.7241 us, 8.7400 us, 11.252 us]`
  - throughput: `[127.30 MiB/s, 163.89 MiB/s, 213.03 MiB/s]`
- `roxmltree_parse/3382`
  - time: `[9.4168 us, 9.4702 us, 9.5512 us]`
  - throughput: `[337.69 MiB/s, 340.58 MiB/s, 342.51 MiB/s]`

### WS-Security (`wssec`)

- `parse_signature_references`
  - time: `[2.2977 us, 2.3090 us, 2.3241 us]`
  - throughput: `[310.62 MiB/s, 312.66 MiB/s, 314.19 MiB/s]`

### Canonicalization (`wssec_c14n`)

- `canonicalize_body_strict`
  - time: `[2.1485 us, 2.1556 us, 2.1654 us]`

### MIME Boundary Scan (`mime_boundary_scan`)

- `synthetic_envelope_kb/1`
  - time: `[433.74 ns, 435.24 ns, 436.58 ns]`
  - throughput: `[2.7881 GiB/s, 2.7967 GiB/s, 2.8064 GiB/s]`
- `synthetic_envelope_kb/64`
  - time: `[22.554 us, 22.601 us, 22.660 us]`
  - throughput: `[2.7052 GiB/s, 2.7122 GiB/s, 2.7179 GiB/s]`
- `synthetic_envelope_kb/512`
  - time: `[180.61 us, 181.58 us, 182.91 us]`
  - throughput: `[2.6709 GiB/s, 2.6905 GiB/s, 2.7050 GiB/s]`
- `synthetic_envelope_kb/1024`
  - time: `[421.95 us, 446.05 us, 471.85 us]`
  - throughput: `[2.0702 GiB/s, 2.1899 GiB/s, 2.3150 GiB/s]`

## Analysis

- The previous picosecond-scale MIME results were invalid due to dead-code-elimination effects in the benchmark body. After `black_box` hardening, MIME throughput is now physically plausible.
- MIME scan throughput is roughly stable around `~2.7 GiB/s` from `1 KiB` through `512 KiB`, then drops at `1024 KiB` (`~2.19 GiB/s` center), indicating cache/memory-bandwidth pressure at larger envelope sizes.
- `parse_signature_references` and `canonicalize_body_strict` are both around `~2.15-2.31 us`; these remain low-latency hot-path primitives.
- XML parse at `1502` bytes shows wider variance than adjacent sizes in this run; this likely reflects noise/outliers rather than a structural cliff and should be rechecked in CI with repeated runs.

## Baseline Usage

Use this document as the reference baseline for future performance gates.

Suggested comparison workflow:

```bash
# Optional: keep local baseline data isolated
rm -rf target/criterion
cargo bench --bench as4_streaming_vs_buffer --features "as4"
```

Then compare new intervals against this file and flag regressions exceeding expected variance.

---

## Addendum: Spool Hygiene Startup Overhead (2026-05-29)

### Scope

Criterion benchmark run for:

- `spool_headroom_hygiene`

This benchmark targets startup-heavy paths that force unique spool directories
per iteration, comparing startup hygiene/headroom checks enabled vs disabled.

### Command

```bash
cargo bench --bench spool_headroom_hygiene --features "as4" -- \
  --sample-size 20 --warm-up-time 0.2 --measurement-time 0.6
```

### Results

- `spool_headroom_hygiene/startup_checks_enabled_unique_dir`
  - time: `[222.13 us, 228.53 us, 235.31 us]`
- `spool_headroom_hygiene/startup_checks_disabled_unique_dir`
  - time: `[4.1408 us, 4.1888 us, 4.2329 us]`
- `spool_headroom_hygiene/startup_checks_enabled_reused_dir_steady_state`
  - time: `[279.03 ns, 280.91 ns, 282.81 ns]`

### Interpretation

- Enabling startup hygiene/headroom checks in a startup-heavy model (fresh spool
  directory each call) adds approximately `~224 us` median overhead per call.
- Relative overhead in this synthetic startup-heavy scenario is approximately
  `~54.6x` versus the no-check baseline path.
- Steady-state (reused spool directory after the first successful hygiene pass)
  dropped to approximately `~0.281 us` median.
- Startup-heavy enabled path vs steady-state enabled path differs by
  approximately `~813x`, confirming hygiene-check amortization is substantial
  once the directory is marked completed.
