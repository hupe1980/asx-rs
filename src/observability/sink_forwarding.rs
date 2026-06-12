use std::sync::Arc;

use tokio::sync::mpsc;

use super::AsxEvent;

pub trait EventSink {
    fn emit(
        &self,
        event: AsxEvent,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;
}

pub async fn forward_to_sink(
    mut receiver: mpsc::Receiver<AsxEvent>,
    sink: Arc<dyn EventSink + Send + Sync>,
) {
    while let Some(event) = receiver.recv().await {
        sink.emit(event).await;
    }
}
