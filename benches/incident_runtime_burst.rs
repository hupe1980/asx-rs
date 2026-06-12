use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use asx::core::ErrorCode;
use asx::incident_channels::{
    As2ProviderHealthWebhookIncidentChannel, IncidentDeliveryConfig, IncidentQueueOverflowPolicy,
};
use asx::observability::{
    As2ProviderHealthAlertCategory, As2ProviderHealthAlertIncident, As2ProviderHealthAlertSeverity,
    As2ProviderHealthIncidentChannel,
};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

struct HttpStubServer {
    endpoint: String,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl HttpStubServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub server");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let addr = listener.local_addr().expect("stub local addr");

        let stop = Arc::new(AtomicBool::new(false));
        let stop_worker = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_worker.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = handle_connection(stream);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            endpoint: format!("http://{addr}"),
            stop,
            handle: Some(handle),
        }
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

impl Drop for HttpStubServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.endpoint.trim_start_matches("http://"));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn handle_connection(mut stream: TcpStream) -> std::io::Result<()> {
    let mut header = Vec::new();
    let mut byte = [0u8; 1];

    loop {
        match stream.read_exact(&mut byte) {
            Ok(()) => {
                header.push(byte[0]);
                if header.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        }
    }

    let header_text = String::from_utf8_lossy(&header);
    let content_length = header_text
        .lines()
        .find_map(|line| {
            let lower = line.to_ascii_lowercase();
            lower
                .strip_prefix("content-length: ")
                .and_then(|value| value.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);

    if content_length > 0 {
        let mut body = vec![0u8; content_length];
        let _ = stream.read_exact(&mut body);
    }

    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")?;
    Ok(())
}

fn make_incident(sequence: u64) -> As2ProviderHealthAlertIncident {
    As2ProviderHealthAlertIncident {
        dedup_key: format!("as2:provider-health:bench:{sequence}"),
        signal: "as2",
        severity: As2ProviderHealthAlertSeverity::Critical,
        category: As2ProviderHealthAlertCategory::TransitionToFailingRate,
        observed_rate_ppm: 700_000,
        sample_size: 200,
        runbook_hint: "benchmark",
    }
}

fn bench_incident_burst_backpressure(c: &mut Criterion) {
    let server = HttpStubServer::start();
    let mut group = c.benchmark_group("incident_runtime_backpressure");

    for queue_capacity in [8usize, 16, 32] {
        group.bench_with_input(
            BenchmarkId::new("enqueue_burst_until_backpressure", queue_capacity),
            &queue_capacity,
            |b, queue_capacity| {
                b.iter(|| {
                    let mut channel = As2ProviderHealthWebhookIncidentChannel::with_raw_config(
                        server.endpoint(),
                        IncidentDeliveryConfig {
                            queue_capacity: *queue_capacity,
                            request_timeout_secs: 1,
                            enqueue_backpressure_wait_millis: 25,
                            queue_overflow: IncidentQueueOverflowPolicy::FailClosed,
                        },
                    )
                    .expect("construct channel");

                    let mut accepted = 0u64;
                    let mut saturated = 0u64;
                    for i in 0..(*queue_capacity as u64 * 6) {
                        let incident = make_incident(i);
                        match channel.send_incident(&incident) {
                            Ok(()) => accepted += 1,
                            Err(err) if err.code == ErrorCode::CapacityExhausted => {
                                saturated += 1;
                            }
                            Err(err) => panic!("unexpected incident enqueue error: {err:?}"),
                        }
                    }

                    channel
                        .shutdown_and_drain(Duration::from_secs(2))
                        .expect("shutdown and drain");

                    black_box((accepted, saturated));
                });
            },
        );
    }

    group.finish();
}

fn bench_incident_shutdown_and_drain(c: &mut Criterion) {
    let server = HttpStubServer::start();
    let mut group = c.benchmark_group("incident_runtime_shutdown");

    for queue_capacity in [32usize, 128] {
        group.bench_with_input(
            BenchmarkId::new("shutdown_and_drain_after_burst", queue_capacity),
            &queue_capacity,
            |b, queue_capacity| {
                b.iter(|| {
                    let mut channel = As2ProviderHealthWebhookIncidentChannel::with_raw_config(
                        server.endpoint(),
                        IncidentDeliveryConfig {
                            queue_capacity: *queue_capacity,
                            request_timeout_secs: 1,
                            enqueue_backpressure_wait_millis: 25,
                            queue_overflow: IncidentQueueOverflowPolicy::FailClosed,
                        },
                    )
                    .expect("construct channel");

                    for i in 0..(*queue_capacity as u64 / 2) {
                        let incident = make_incident(i);
                        let _ = channel.send_incident(&incident);
                    }

                    channel
                        .shutdown_and_drain(Duration::from_secs(2))
                        .expect("shutdown and drain");
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_incident_burst_backpressure,
    bench_incident_shutdown_and_drain
);
criterion_main!(benches);
