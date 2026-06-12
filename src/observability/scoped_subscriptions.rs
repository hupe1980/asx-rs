use std::sync::Arc;
use std::sync::atomic::Ordering;

use dashmap::DashMap;
use tokio::sync::mpsc;

use super::{EventBus, ScopedAsxEvent};

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct ScopedRouteStats {
    pub(super) delivered_count: u64,
    pub(super) lagged_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopedEventTryRecvError {
    Empty,
    Closed,
}

pub struct ScopedEventSubscription {
    receiver: mpsc::Receiver<ScopedAsxEvent>,
    senders: Arc<DashMap<u64, mpsc::Sender<ScopedAsxEvent>>>,
    subscription_id: u64,
    closed: bool,
}

impl ScopedEventSubscription {
    pub async fn recv(&mut self) -> Option<ScopedAsxEvent> {
        if self.closed {
            return None;
        }
        self.receiver.recv().await
    }

    pub fn try_recv(&mut self) -> std::result::Result<ScopedAsxEvent, ScopedEventTryRecvError> {
        if self.closed {
            return Err(ScopedEventTryRecvError::Closed);
        }

        match self.receiver.try_recv() {
            Ok(event) => Ok(event),
            Err(mpsc::error::TryRecvError::Empty) => Err(ScopedEventTryRecvError::Empty),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(ScopedEventTryRecvError::Closed),
        }
    }

    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.receiver.close();
        self.senders.remove(&self.subscription_id);
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

impl Drop for ScopedEventSubscription {
    fn drop(&mut self) {
        self.close();
    }
}

pub(super) fn subscribe_scoped_events_impl(bus: &EventBus) -> ScopedEventSubscription {
    let subscription_id = bus
        .next_scoped_subscription_id
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    let (tx, rx) = mpsc::channel::<ScopedAsxEvent>(bus.scoped_channel_capacity);
    bus.scoped_senders.insert(subscription_id, tx);

    ScopedEventSubscription {
        receiver: rx,
        senders: Arc::clone(&bus.scoped_senders),
        subscription_id,
        closed: false,
    }
}

pub(super) fn collect_active_scoped_senders(bus: &EventBus) -> Vec<mpsc::Sender<ScopedAsxEvent>> {
    let mut closed_ids = Vec::new();
    let mut senders = Vec::new();

    for entry in bus.scoped_senders.iter() {
        if entry.value().is_closed() {
            closed_ids.push(*entry.key());
            continue;
        }
        senders.push(entry.value().clone());
    }

    for id in closed_ids {
        bus.scoped_senders.remove(&id);
    }

    senders
}

pub(super) fn route_event_to_scoped_subscribers(
    bus: &EventBus,
    scoped_event: &ScopedAsxEvent,
) -> ScopedRouteStats {
    let mut stats = ScopedRouteStats::default();
    let mut closed_ids = Vec::new();

    for entry in bus.scoped_senders.iter() {
        match entry.value().try_send(scoped_event.clone()) {
            Ok(()) => {
                stats.delivered_count += 1;
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                stats.lagged_count += 1;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                closed_ids.push(*entry.key());
            }
        }
    }

    for id in closed_ids {
        bus.scoped_senders.remove(&id);
    }

    if stats.lagged_count > 0 {
        bus.metrics.inc_lagged(stats.lagged_count);
    }

    stats
}
