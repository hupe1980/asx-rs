use asx::core::SessionContext;
use asx::observability::{AsxEvent, BackpressurePolicy, EventBus, EventEmissionMode};
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

struct BenchState {
    bus: EventBus,
    session: SessionContext,
    broadcast: asx::observability::ScopedEventSubscription,
    runtime: tokio::runtime::Runtime,
    subscriptions: Vec<asx::observability::SessionEventSubscription>,
}

fn build_bus_with_subscribers(
    emission_mode: EventEmissionMode,
    session_subscribers: usize,
    events_per_sample: usize,
) -> BenchState {
    let capacity = events_per_sample.saturating_mul(2).max(1024);
    let per_session_capacity = events_per_sample.saturating_mul(2).max(1024);
    let bus = EventBus::new_with_config_and_mode(
        capacity,
        None,
        BackpressurePolicy {
            session_channel_capacity: per_session_capacity,
            ..BackpressurePolicy::default()
        },
        emission_mode,
    )
    .expect("event bus");

    // Keep one broadcast subscriber active so strict modes can emit.
    let broadcast = bus.subscribe_scoped_events();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("benchmark runtime");
    let mut subscriptions = Vec::with_capacity(session_subscribers);
    for _ in 0..session_subscribers {
        let subscription = bus
            .subscribe_session_events("bench-session")
            .expect("session subscription");
        subscriptions.push(subscription);
    }

    let session =
        SessionContext::new("bench-session", "bench-partner", "strict").expect("session context");

    BenchState {
        bus,
        session,
        broadcast,
        runtime,
        subscriptions,
    }
}

fn bench_event_bus_emit_modes(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_bus_emit_modes");
    let fanouts = [1usize, 16, 64, 256];
    let events_per_sample = 1usize;

    for fanout in fanouts {
        for (name, mode) in [
            ("best_effort", EventEmissionMode::BestEffort),
            (
                "strict_transactional",
                EventEmissionMode::StrictTransactional,
            ),
        ] {
            let mut state = build_bus_with_subscribers(mode, fanout, events_per_sample);
            group.throughput(Throughput::Elements(events_per_sample as u64));
            group.bench_with_input(
                BenchmarkId::new(name, format!("fanout_{fanout}")),
                &fanout,
                |b, _| {
                    let mut sequence = 0u64;
                    b.iter(|| {
                        for _ in 0..events_per_sample {
                            sequence = sequence.wrapping_add(1);
                            let event = AsxEvent::MessageSigned {
                                message_id: format!("m-{sequence}").into(),
                            };
                            state
                                .bus
                                .emit(black_box(&state.session), black_box(event))
                                .expect("emit must succeed");
                            let _ = state.runtime.block_on(state.broadcast.recv());
                            for subscription in &mut state.subscriptions {
                                let _ = state.runtime.block_on(subscription.recv());
                            }
                        }
                    });
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_event_bus_emit_modes);
criterion_main!(benches);
