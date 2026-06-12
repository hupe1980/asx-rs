/// M7 Performance Benchmarks: AS4 receive and WS-Security hot paths.
///
/// Measures:
/// - SOAP XML parsing cost at various payload sizes
/// - WS-Security signature reference parsing
/// - Exclusive C14N canonicalization cost
/// - MIME multipart boundary scanning
///
/// Run with: `cargo bench --bench as4_streaming_vs_buffer --features "as4"`
use asx_rs::crypto::wssec::{
    WsSecCanonicalizationProfile, canonicalize_reference, parse_signature_references,
};
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use memchr::memmem;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SOAP_ENVELOPE_SMALL: &str = include_str!("../tests/fixtures/as4_push_user_message.golden");
const SIGNED_MESSAGE: &str = include_str!("../tests/fixtures/wssec/signed_message.xml.golden");

/// Build a synthetic MIME multipart envelope of `payload_bytes` bytes.
fn synthetic_mime_envelope(payload_bytes: usize) -> Vec<u8> {
    let boundary = "MIMEBoundary_xxxx";
    let payload = "X".repeat(payload_bytes);
    format!(
        "--{boundary}\r\nContent-Type: application/soap+xml; charset=UTF-8\r\n\r\n\
         <S12:Envelope xmlns:S12=\"http://www.w3.org/2003/05/soap-envelope\"><S12:Body/></S12:Envelope>\r\n\
         --{boundary}\r\nContent-Type: application/octet-stream\r\nContent-ID: <payload@bench>\r\n\r\n\
         {payload}\r\n--{boundary}--",
        boundary = boundary,
        payload = payload,
    )
    .into_bytes()
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_xml_parse(c: &mut Criterion) {
    let mut g = c.benchmark_group("xml_parse");

    for size_factor in [1usize, 10, 50] {
        // Build an envelope with repeated eb:MessageProperties children
        let extra: String = (0..size_factor)
            .map(|i| format!("<eb:Property name=\"key{i}\">value{i}</eb:Property>", i = i))
            .collect();
        let xml = SOAP_ENVELOPE_SMALL.replace(
            "</eb:Messaging>",
            &format!("<eb:MessageProperties>{extra}</eb:MessageProperties></eb:Messaging>"),
        );
        let bytes = xml.len();
        g.throughput(Throughput::Bytes(bytes as u64));
        g.bench_with_input(
            BenchmarkId::new("roxmltree_parse", bytes),
            &xml,
            |b, xml| {
                b.iter(|| {
                    let doc = roxmltree::Document::parse(black_box(xml)).unwrap();
                    black_box(doc)
                });
            },
        );
    }
    g.finish();
}

fn bench_signature_ref_parse(c: &mut Criterion) {
    let mut g = c.benchmark_group("wssec");
    let bytes = SIGNED_MESSAGE.len();
    g.throughput(Throughput::Bytes(bytes as u64));
    g.bench_function("parse_signature_references", |b| {
        b.iter(|| {
            let refs = parse_signature_references(black_box(SIGNED_MESSAGE)).unwrap();
            black_box(refs)
        });
    });
    g.finish();
}

fn bench_canonicalize(c: &mut Criterion) {
    let mut g = c.benchmark_group("wssec_c14n");
    // Canonicalize the body element of the signed message
    g.bench_function("canonicalize_body_strict", |b| {
        b.iter(|| {
            let out = canonicalize_reference(
                black_box(SIGNED_MESSAGE),
                "#body",
                WsSecCanonicalizationProfile::default(),
            )
            .ok();
            black_box(out)
        });
    });
    g.finish();
}

fn bench_mime_scan(c: &mut Criterion) {
    let mut g = c.benchmark_group("mime_boundary_scan");
    for kb in [1usize, 64, 512, 1024] {
        let payload_bytes = kb * 1024;
        let envelope = synthetic_mime_envelope(payload_bytes);
        g.throughput(Throughput::Bytes(envelope.len() as u64));
        g.bench_with_input(
            BenchmarkId::new("synthetic_envelope_kb", kb),
            &envelope,
            |b, envelope| {
                b.iter(|| {
                    // Scan for all boundaries using linear-time substring search.
                    let boundary = black_box(b"MIMEBoundary_xxxx");
                    let count = memmem::find_iter(black_box(envelope), boundary).count();
                    black_box(count)
                });
            },
        );
    }
    g.finish();
}

fn bench_as4_precheck_markers(c: &mut Criterion) {
    let mut g = c.benchmark_group("as4_precheck_markers");
    const REQUIRED: [&[u8]; 5] = [
        b"Envelope",
        b"Header",
        b"Body",
        b"Messaging",
        b"UserMessage",
    ];

    for kb in [4usize, 64, 512] {
        let filler = "X".repeat(kb * 1024);
        let xml = format!(
            "<soap:Envelope><soap:Header><eb:Messaging><eb:UserMessage>{}</eb:UserMessage></eb:Messaging></soap:Header><soap:Body/></soap:Envelope>",
            filler
        );
        let raw = xml.into_bytes();
        g.throughput(Throughput::Bytes(raw.len() as u64));
        g.bench_with_input(
            BenchmarkId::new("all_required_markers", kb),
            &raw,
            |b, raw| {
                b.iter(|| {
                    let all_present = REQUIRED
                        .iter()
                        .all(|marker| memmem::find(black_box(raw), marker).is_some());
                    black_box(all_present)
                });
            },
        );
    }

    g.finish();
}

criterion_group!(
    benches,
    bench_xml_parse,
    bench_signature_ref_parse,
    bench_canonicalize,
    bench_mime_scan,
    bench_as4_precheck_markers,
);
criterion_main!(benches);
