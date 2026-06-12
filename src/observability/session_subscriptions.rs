use std::sync::Arc;

use dashmap::DashMap;
use std::sync::atomic::Ordering;
use tokio::sync::mpsc;

use super::{EventBus, Result, SharedAsxEvent};

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct SessionRouteStats {
    pub(super) delivered_count: u64,
    pub(super) lagged_count: u64,
}

#[derive(Debug, Clone)]
pub(super) struct SessionSenderEntry {
    pub(super) id: u64,
    pub(super) sender: mpsc::Sender<SharedAsxEvent>,
}

pub struct SessionEventSubscription {
    receiver: mpsc::Receiver<SharedAsxEvent>,
    senders: Arc<DashMap<String, Vec<SessionSenderEntry>>>,
    session_id: String,
    subscription_id: u64,
    closed: bool,
}

impl SessionEventSubscription {
    pub async fn recv(&mut self) -> Option<SharedAsxEvent> {
        if self.closed {
            return None;
        }
        self.receiver.recv().await
    }

    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.receiver.close();

        if let Some(mut txs) = self.senders.get_mut(&self.session_id) {
            txs.retain(|entry| entry.id != self.subscription_id);
            if txs.is_empty() {
                drop(txs);
                self.senders.remove(&self.session_id);
            }
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

impl Drop for SessionEventSubscription {
    fn drop(&mut self) {
        self.close();
    }
}

pub(super) fn subscribe_session_events_impl(
    bus: &EventBus,
    session_id: String,
) -> Result<SessionEventSubscription> {
    let subscription_id = bus
        .next_session_subscription_id
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    let (tx, rx) = mpsc::channel::<SharedAsxEvent>(bus.session_channel_capacity);
    bus.session_senders
        .entry(session_id.clone())
        .or_default()
        .push(SessionSenderEntry {
            id: subscription_id,
            sender: tx,
        });
    Ok(SessionEventSubscription {
        receiver: rx,
        senders: Arc::clone(&bus.session_senders),
        session_id,
        subscription_id,
        closed: false,
    })
}

pub(super) fn route_event_to_session_subscribers(
    bus: &EventBus,
    session_id: &str,
    shared_event: &SharedAsxEvent,
) -> SessionRouteStats {
    let mut stats = SessionRouteStats::default();
    if let Some(mut txs) = bus.session_senders.get_mut(session_id) {
        txs.retain(
            |entry| match entry.sender.try_send(Arc::clone(shared_event)) {
                Ok(()) => {
                    stats.delivered_count += 1;
                    true
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    stats.lagged_count += 1;
                    true
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            },
        );
        if stats.lagged_count > 0 {
            bus.metrics.inc_lagged(stats.lagged_count);
        }
        if txs.is_empty() {
            drop(txs);
            bus.session_senders.remove(session_id);
        }
    }
    stats
}

pub(super) fn collect_active_session_senders(
    bus: &EventBus,
    session_id: &str,
) -> Vec<mpsc::Sender<SharedAsxEvent>> {
    if let Some(mut txs) = bus.session_senders.get_mut(session_id) {
        txs.retain(|entry| !entry.sender.is_closed());
        let senders = txs
            .iter()
            .map(|entry| entry.sender.clone())
            .collect::<Vec<_>>();
        if txs.is_empty() {
            drop(txs);
            bus.session_senders.remove(session_id);
        }
        return senders;
    }
    Vec::new()
}
