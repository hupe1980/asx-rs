use super::stream::normalize_mpc;
use super::{As4QueuedPullMessage, As4ReceivePushOutput};
use crate::as4::As4TopologyCoordination;
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

const AS4_PULL_STORE_SNAPSHOT_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct PullQueueKey {
    pub(super) session_id: Arc<str>,
    pub(super) mpc: Arc<str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct PullRequestKey {
    pub(super) session_id: Arc<str>,
    pub(super) mpc: Arc<str>,
    pub(super) pull_message_id: Arc<str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedPulledMessage {
    pulled: Arc<As4ReceivePushOutput>,
}

/// Served-cache state protected by a dedicated mutex.
///
/// Queue operations are sharded by MPC via `DashMap<PullQueueKey, Mutex<VecDeque<_>>>`
/// to avoid serializing unrelated pull partitions.  The served cache remains
/// centralized to preserve deterministic max-entry eviction ordering.
#[derive(Debug, Default)]
struct As4PullServedState {
    served: HashMap<PullRequestKey, CachedPulledMessage>,
    served_order: VecDeque<PullRequestKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum As4PullQueueOverflowPolicy {
    /// Reject newly enqueued messages once the queue reaches capacity.
    RejectNew,
    /// Drop the oldest queued message and accept the new one.
    EvictOldest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum As4PullEnqueueOutcome {
    Enqueued,
    EvictedOldestAndEnqueued { dropped: As4QueuedPullMessage },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct As4PullStoreLimits {
    pub max_queue_per_mpc: usize,
    pub max_served_entries: usize,
    pub queue_overflow_policy: As4PullQueueOverflowPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct As4PullStoreSnapshot {
    pub version: u8,
    pub queues: Vec<As4PullQueueSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct As4PullQueueSnapshot {
    pub session_id: String,
    pub mpc: String,
    pub messages: Vec<As4QueuedPullMessageSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct As4QueuedPullMessageSnapshot {
    pub message_id: String,
    pub http_content_type: String,
    pub payload: Vec<u8>,
}

impl Default for As4PullStoreLimits {
    fn default() -> Self {
        Self {
            max_queue_per_mpc: 1024,
            max_served_entries: 4096,
            queue_overflow_policy: As4PullQueueOverflowPolicy::RejectNew,
        }
    }
}

/// In-memory AS4 pull-mode message store.
///
/// `As4PullStore` holds enqueued outbound pull messages indexed by MPC (Message
/// Partition Channel) URI.  When an initiator sends a `PullRequest`, the
/// matching message is dequeued from the relevant MPC and returned.
///
/// ## ⚠ Single-process limitation
///
/// `As4PullStore` is an **in-process, in-memory** store.  Its queues are not
/// shared across process replicas.  If your deployment runs multiple instances
/// (e.g. behind a Kubernetes load balancer), a `PullRequest` may arrive at a
/// different replica than the one that enqueued the payload, resulting in empty
/// responses.
///
/// For clustered deployments replace `As4PullStore` with a distributed queue
/// backend (e.g. Redis Lists, AWS SQS, or a database-backed queue) that all
/// replicas share.  The `cluster_safe()` method returns `false` to signal that
/// this implementation is single-process only.
#[derive(Debug)]
pub struct As4PullStore {
    queues: DashMap<PullQueueKey, Arc<Mutex<VecDeque<As4QueuedPullMessage>>>>,
    served: Mutex<As4PullServedState>,
    limits: As4PullStoreLimits,
    snapshot_json_path: Option<std::path::PathBuf>,
}

impl Default for As4PullStore {
    fn default() -> Self {
        Self {
            queues: DashMap::new(),
            served: Mutex::new(As4PullServedState::default()),
            limits: As4PullStoreLimits::default(),
            snapshot_json_path: None,
        }
    }
}

impl As4PullStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limits(limits: As4PullStoreLimits) -> Result<Self> {
        if limits.max_queue_per_mpc == 0 || limits.max_served_entries == 0 {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "AS4 pull store limits must be greater than zero",
                ErrorContext::new("as4_pull_store_limits"),
            ));
        }

        Ok(Self {
            queues: DashMap::new(),
            served: Mutex::new(As4PullServedState::default()),
            limits,
            snapshot_json_path: None,
        })
    }

    /// Whether this pull store implementation is safe for clustered deployments.
    ///
    /// `As4PullStore` is process-local and therefore not cluster-safe.
    #[inline]
    pub fn cluster_safe(&self) -> bool {
        false
    }

    pub async fn new_durable_json<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::with_limits_durable_json(As4PullStoreLimits::default(), path).await
    }

    pub async fn with_limits_durable_json<P: AsRef<Path>>(
        limits: As4PullStoreLimits,
        path: P,
    ) -> Result<Self> {
        let path = path.as_ref();
        let mut store = Self::with_limits(limits)?;
        store.snapshot_json_path = Some(path.to_path_buf());

        if path.exists() {
            store.restore_snapshot_json(path).await?;
        }

        Ok(store)
    }

    async fn persist_snapshot_if_configured(&self) -> Result<()> {
        if let Some(path) = &self.snapshot_json_path {
            self.persist_snapshot_json(path).await?;
        }
        Ok(())
    }

    pub(crate) async fn enqueue(
        &self,
        session: &SessionContext,
        mpc: impl Into<String>,
        message: As4QueuedPullMessage,
    ) -> Result<As4PullEnqueueOutcome> {
        if message.message_id.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "queued pull message id must not be empty",
                ErrorContext::new("as4_pull_enqueue")
                    .with_session_and_partner(session.session_id(), session.partner_id()),
            ));
        }

        if message.payload.is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "queued pull message payload must not be empty",
                ErrorContext::new("as4_pull_enqueue")
                    .with_session_and_partner(session.session_id(), session.partner_id()),
            ));
        }

        let mpc = mpc.into();
        let mpc = normalize_mpc(&mpc);
        if mpc.is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "pull queue MPC must not be empty",
                ErrorContext::new("as4_pull_enqueue")
                    .with_session_and_partner(session.session_id(), session.partner_id()),
            ));
        }

        let key = PullQueueKey {
            session_id: Arc::from(session.session_id()),
            mpc: Arc::from(mpc),
        };
        let queue = self
            .queues
            .entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(VecDeque::new())))
            .clone();
        let outcome = {
            let mut queue = queue.lock().await;

            let mut outcome = As4PullEnqueueOutcome::Enqueued;
            if queue.len() >= self.limits.max_queue_per_mpc {
                match self.limits.queue_overflow_policy {
                    As4PullQueueOverflowPolicy::RejectNew => {
                        return Err(AsxError::new(
                            ErrorCode::CapacityExhausted,
                            "AS4 pull queue reached configured max_queue_per_mpc; enqueue rejected",
                            ErrorContext::new("as4_pull_enqueue").with_session_and_partner(
                                session.session_id(),
                                session.partner_id(),
                            ),
                        ));
                    }
                    As4PullQueueOverflowPolicy::EvictOldest => {
                        if let Some(dropped) = queue.pop_front() {
                            outcome = As4PullEnqueueOutcome::EvictedOldestAndEnqueued { dropped };
                        }
                    }
                }
            }

            queue.push_back(message);
            outcome
        };

        self.persist_snapshot_if_configured().await.map_err(|err| {
            AsxError::new(
                err.code,
                format!(
                    "failed to persist AS4 pull queue snapshot after enqueue: {}",
                    err
                ),
                ErrorContext::new("as4_pull_enqueue")
                    .with_session_and_partner(session.session_id(), session.partner_id()),
            )
        })?;

        Ok(outcome)
    }

    /// Atomically check the served cache and — on a cache miss — dequeue the
    /// next pending message.  Both operations happen under a single mutex
    /// acquisition, eliminating the TOCTOU window that arises when the two
    /// maps are protected by separate locks.
    ///
    /// Returns `(Some(cached), None)` on a cache hit or `(None, Some(queued))`
    /// on a cache miss with a queued message available, or `(None, None)` when
    /// the queue is empty.
    pub(super) async fn atomic_take(
        &self,
        pull_key: &PullRequestKey,
        queue_key: &PullQueueKey,
    ) -> Result<(
        Option<Arc<As4ReceivePushOutput>>,
        Option<As4QueuedPullMessage>,
    )> {
        {
            let st = self.served.lock().await;
            if let Some(cached) = st.served.get(pull_key) {
                return Ok((Some(Arc::clone(&cached.pulled)), None));
            }
        }

        let queue = self
            .queues
            .get(queue_key)
            .map(|entry| Arc::clone(entry.value()));
        let Some(queue) = queue else {
            return Ok((None, None));
        };

        let mut queue = queue.lock().await;
        let queued = queue.pop_front();
        drop(queue);

        if queued.is_some() {
            self.persist_snapshot_if_configured().await.map_err(|err| {
                AsxError::new(
                    err.code,
                    format!(
                        "failed to persist AS4 pull queue snapshot after dequeue: {}",
                        err
                    ),
                    ErrorContext::new("as4_pull_dequeue")
                        .with_session_id(queue_key.session_id.as_ref().to_string()),
                )
            })?;
        }

        Ok((None, queued))
    }

    pub(super) async fn cache_pulled(
        &self,
        pull_key: PullRequestKey,
        push_out: Arc<As4ReceivePushOutput>,
    ) {
        let mut st = self.served.lock().await;

        st.served.insert(
            pull_key.clone(),
            CachedPulledMessage {
                pulled: Arc::clone(&push_out),
            },
        );
        st.served_order.push_back(pull_key);
        while st.served_order.len() > self.limits.max_served_entries {
            if let Some(expired_key) = st.served_order.pop_front() {
                st.served.remove(&expired_key);
            }
        }
    }

    /// Requeue a previously dequeued message at the front of the queue.
    ///
    /// Used by pull receive flows to fail-safe on downstream parse/verify
    /// errors after dequeue, so messages are not lost from in-memory queues.
    pub(super) async fn requeue_front(
        &self,
        queue_key: &PullQueueKey,
        message: As4QueuedPullMessage,
    ) -> Result<()> {
        let queue = self
            .queues
            .entry(queue_key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(VecDeque::new())))
            .clone();
        let mut queue = queue.lock().await;
        queue.push_front(message);
        drop(queue);

        self.persist_snapshot_if_configured().await.map_err(|err| {
            AsxError::new(
                err.code,
                format!(
                    "failed to persist AS4 pull queue snapshot after requeue: {}",
                    err
                ),
                ErrorContext::new("as4_pull_requeue_front")
                    .with_session_id(queue_key.session_id.as_ref().to_string()),
            )
        })
    }

    /// Export queue state as an in-memory snapshot for durable storage.
    pub async fn snapshot(&self) -> As4PullStoreSnapshot {
        let queue_handles: Vec<(PullQueueKey, Arc<Mutex<VecDeque<As4QueuedPullMessage>>>)> = self
            .queues
            .iter()
            .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
            .collect();

        let mut queues = Vec::with_capacity(queue_handles.len());
        for (key, queue) in queue_handles {
            let queue = queue.lock().await;
            if queue.is_empty() {
                continue;
            }

            let messages = queue
                .iter()
                .map(|msg| As4QueuedPullMessageSnapshot {
                    message_id: msg.message_id.to_string(),
                    http_content_type: msg.http_content_type.to_string(),
                    payload: msg.payload.to_vec(),
                })
                .collect();

            queues.push(As4PullQueueSnapshot {
                session_id: key.session_id.to_string(),
                mpc: key.mpc.to_string(),
                messages,
            });
        }

        queues.sort_by(|a, b| {
            (a.session_id.as_str(), a.mpc.as_str()).cmp(&(b.session_id.as_str(), b.mpc.as_str()))
        });

        As4PullStoreSnapshot {
            version: AS4_PULL_STORE_SNAPSHOT_VERSION,
            queues,
        }
    }

    /// Replace in-memory queue state with a validated snapshot.
    pub async fn restore_snapshot(&self, snapshot: &As4PullStoreSnapshot) -> Result<()> {
        if snapshot.version != AS4_PULL_STORE_SNAPSHOT_VERSION {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                format!(
                    "unsupported AS4 pull store snapshot version {} (expected {})",
                    snapshot.version, AS4_PULL_STORE_SNAPSHOT_VERSION
                ),
                ErrorContext::new("as4_pull_restore_snapshot"),
            ));
        }

        self.queues.clear();

        for queue in &snapshot.queues {
            let session_id = queue.session_id.trim();
            let mpc = normalize_mpc(&queue.mpc);
            if session_id.is_empty() || mpc.is_empty() {
                return Err(AsxError::new(
                    ErrorCode::InvalidInput,
                    "snapshot queue session_id and mpc must not be empty",
                    ErrorContext::new("as4_pull_restore_snapshot"),
                ));
            }

            if queue.messages.len() > self.limits.max_queue_per_mpc {
                return Err(AsxError::new(
                    ErrorCode::CapacityExhausted,
                    format!(
                        "snapshot queue exceeds max_queue_per_mpc ({} > {}) for session={} mpc={}",
                        queue.messages.len(),
                        self.limits.max_queue_per_mpc,
                        session_id,
                        mpc
                    ),
                    ErrorContext::new("as4_pull_restore_snapshot")
                        .with_session_id(session_id.to_string()),
                ));
            }

            let mut messages = VecDeque::with_capacity(queue.messages.len());
            for msg in &queue.messages {
                if msg.message_id.trim().is_empty()
                    || msg.http_content_type.trim().is_empty()
                    || msg.payload.is_empty()
                {
                    return Err(AsxError::new(
                        ErrorCode::InvalidInput,
                        "snapshot queued pull message fields must be non-empty",
                        ErrorContext::new("as4_pull_restore_snapshot")
                            .with_session_id(session_id.to_string())
                            .with_message_id(msg.message_id.to_string()),
                    ));
                }

                messages.push_back(As4QueuedPullMessage {
                    message_id: Arc::from(msg.message_id.as_str()),
                    http_content_type: Arc::from(msg.http_content_type.as_str()),
                    payload: Arc::<[u8]>::from(msg.payload.as_slice()),
                });
            }

            self.queues.insert(
                PullQueueKey {
                    session_id: Arc::from(session_id),
                    mpc: Arc::from(mpc),
                },
                Arc::new(Mutex::new(messages)),
            );
        }

        let mut served = self.served.lock().await;
        *served = As4PullServedState::default();
        Ok(())
    }

    /// Persist queue state to a JSON snapshot file.
    pub async fn persist_snapshot_json<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|err| {
                AsxError::new(
                    ErrorCode::ReliabilityFailure,
                    format!(
                        "failed to create AS4 pull snapshot directory {}: {err}",
                        parent.display()
                    ),
                    ErrorContext::new("as4_pull_persist_snapshot"),
                )
            })?;
        }

        let snapshot = self.snapshot().await;
        let bytes = serde_json::to_vec_pretty(&snapshot).map_err(|err| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!("failed to encode AS4 pull snapshot JSON: {err}"),
                ErrorContext::new("as4_pull_persist_snapshot"),
            )
        })?;

        std::fs::write(path, bytes).map_err(|err| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!(
                    "failed to write AS4 pull snapshot file {}: {err}",
                    path.display()
                ),
                ErrorContext::new("as4_pull_persist_snapshot"),
            )
        })
    }

    /// Load queue state from a JSON snapshot file.
    pub async fn restore_snapshot_json<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|err| {
            let code = if err.kind() == std::io::ErrorKind::NotFound {
                ErrorCode::NotFound
            } else {
                ErrorCode::ReliabilityFailure
            };
            AsxError::new(
                code,
                format!(
                    "failed to read AS4 pull snapshot file {}: {err}",
                    path.display()
                ),
                ErrorContext::new("as4_pull_restore_snapshot_json"),
            )
        })?;

        let snapshot: As4PullStoreSnapshot = serde_json::from_slice(&bytes).map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("failed to parse AS4 pull snapshot JSON: {err}"),
                ErrorContext::new("as4_pull_restore_snapshot_json"),
            )
        })?;

        self.restore_snapshot(&snapshot).await
    }
}

impl As4TopologyCoordination for As4PullStore {
    fn cluster_safe(&self) -> bool {
        self.cluster_safe()
    }

    fn topology_component(&self) -> &'static str {
        "pull-store"
    }
}

#[cfg(test)]
mod tests {
    use super::{As4PullStore, PullQueueKey, PullRequestKey};
    use crate::as4::As4QueuedPullMessage;
    use crate::core::SessionContext;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_snapshot_path() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("asx-pull-store-snapshot-{nanos}.json"))
    }

    #[tokio::test]
    async fn pull_store_snapshot_roundtrip_restores_queued_message() {
        let session =
            SessionContext::new("pull-snapshot-session", "partner-a", "strict").expect("session");
        let store = As4PullStore::new();

        store
            .enqueue(
                &session,
                "urn:example:mpc",
                As4QueuedPullMessage {
                    message_id: Arc::from("msg-1"),
                    http_content_type: Arc::from("application/xml"),
                    payload: Arc::<[u8]>::from(b"queued-payload".as_slice()),
                },
            )
            .await
            .expect("enqueue");

        let path = unique_snapshot_path();
        store
            .persist_snapshot_json(&path)
            .await
            .expect("persist snapshot");

        let restored = As4PullStore::new();
        restored
            .restore_snapshot_json(&path)
            .await
            .expect("restore snapshot");

        let pull_key = PullRequestKey {
            session_id: Arc::from(session.session_id()),
            mpc: Arc::from("urn:example:mpc"),
            pull_message_id: Arc::from("pull-1"),
        };
        let queue_key = PullQueueKey {
            session_id: Arc::from(session.session_id()),
            mpc: Arc::from("urn:example:mpc"),
        };

        let (_cached, queued) = restored
            .atomic_take(&pull_key, &queue_key)
            .await
            .expect("atomic take");
        let queued = queued.expect("restored queued message");
        assert_eq!(queued.message_id.as_ref(), "msg-1");
        assert_eq!(queued.http_content_type.as_ref(), "application/xml");
        assert_eq!(queued.payload.as_ref(), b"queued-payload");

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn durable_json_store_recovers_without_manual_restore_wiring() {
        let session =
            SessionContext::new("pull-durable-session", "partner-a", "strict").expect("session");
        let path = unique_snapshot_path();

        let store = As4PullStore::new_durable_json(&path)
            .await
            .expect("durable store");
        store
            .enqueue(
                &session,
                "urn:example:mpc",
                As4QueuedPullMessage {
                    message_id: Arc::from("msg-durable"),
                    http_content_type: Arc::from("application/xml"),
                    payload: Arc::<[u8]>::from(b"durable-payload".as_slice()),
                },
            )
            .await
            .expect("enqueue");

        let recovered = As4PullStore::new_durable_json(&path)
            .await
            .expect("recovered durable store");
        let pull_key = PullRequestKey {
            session_id: Arc::from(session.session_id()),
            mpc: Arc::from("urn:example:mpc"),
            pull_message_id: Arc::from("pull-1"),
        };
        let queue_key = PullQueueKey {
            session_id: Arc::from(session.session_id()),
            mpc: Arc::from("urn:example:mpc"),
        };

        let (_cached, queued) = recovered
            .atomic_take(&pull_key, &queue_key)
            .await
            .expect("atomic take");
        let queued = queued.expect("queued");
        assert_eq!(queued.message_id.as_ref(), "msg-durable");

        let emptied = As4PullStore::new_durable_json(&path)
            .await
            .expect("reopen after dequeue");
        let (_cached, queued) = emptied
            .atomic_take(&pull_key, &queue_key)
            .await
            .expect("atomic take after dequeue");
        assert!(queued.is_none(), "dequeue should be persisted to disk");

        let _ = std::fs::remove_file(path);
    }
}
