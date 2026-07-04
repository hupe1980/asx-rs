/// Durable audit sink abstraction for pluggable audit event storage backends.
///
/// This module provides trait-based audit sink interfaces to support pluggable backends
/// (syslog, database, file, etc.) with ordered delivery and replay cursor semantics.
/// Enables future integration of external audit systems beyond in-memory broadcast.
use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Audit event that will be persisted to durable sink
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event ID (typically a sequence number or UUID)
    pub event_id: String,
    /// Session ID for correlation
    pub session_id: Option<String>,
    /// Partner ID for this interaction
    pub partner_id: Option<String>,
    /// Event code/classification
    pub code: String,
    /// Event timestamp as Unix seconds since epoch
    pub timestamp: u64,
    /// Detailed event message
    pub message: String,
    /// Additional structured metadata
    pub metadata: AuditMetadata,
}

/// Structured metadata for audit events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditMetadata {
    /// Protocol stage (e.g., "as2_receive", "as4_push_verify")
    pub stage: Option<String>,
    /// Severity level
    pub severity: AuditSeverity,
    /// Action performed
    pub action: Option<String>,
    /// Result/outcome
    pub result: Option<String>,
}

/// Audit event severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AuditSeverity {
    /// Critical security event
    Critical,
    /// High-priority event requiring attention
    High,
    /// Medium-priority informational event
    Medium,
    /// Low-priority diagnostic event
    Low,
}

impl fmt::Display for AuditSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "CRITICAL"),
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::Low => write!(f, "LOW"),
        }
    }
}

/// Cursor position for audit event replay
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayCursor {
    /// Last event ID successfully processed
    pub last_event_id: String,
    /// Position in event stream
    pub position: u64,
    /// Timestamp of last replayed event (Unix seconds since epoch)
    pub last_timestamp: u64,
    /// Base64(HMAC-SHA256) over the cursor payload.
    ///
    /// This protects replay cursors against tampering when persisted in
    /// untrusted storage. Empty for bootstrap cursor (`last_event_id == "0"`).
    #[serde(default)]
    pub integrity_tag_b64: String,
}

impl ReplayCursor {
    pub fn unsigned_start() -> Self {
        Self {
            last_event_id: "0".to_string(),
            position: 0,
            last_timestamp: 0,
            integrity_tag_b64: String::new(),
        }
    }

    fn signing_payload(&self) -> String {
        format!(
            "asx-replay-cursor-v1\0{}\0{}\0{}",
            self.last_event_id, self.position, self.last_timestamp
        )
    }
}

/// Trait for durable audit event storage backends.
///
/// ## Concurrency contract (important)
///
/// Implementations of [`DurableAuditSink`] must keep `store_event` non-reentrant
/// and free of callback cycles into the event bus. In particular, `store_event`
/// must **not** call `EventBus::emit`, `emit_audit_event`, or any API path that
/// can synchronously invoke `DurableAuditSink::store_event` again on the same
/// thread.
///
/// Implementations must also avoid holding sink-internal locks while invoking
/// user callbacks or bus-facing APIs. Violating this lock-ordering rule can
/// create deadlocks under strict fail-closed audit emission.
pub trait DurableAuditSink: Send + Sync {
    /// Return whether this sink provides production-grade durability semantics.
    ///
    /// Implementations should return [`AuditSinkDurability::Durable`] only when
    /// events survive process restarts and host failures (for example, replicated
    /// database or write-ahead-logged file backends).
    fn durability(&self) -> AuditSinkDurability {
        AuditSinkDurability::Durable
    }

    /// Whether replay cursors produced by this sink are integrity-protected.
    fn has_replay_cursor_integrity_protection(&self) -> bool {
        false
    }

    /// Store an audit event durably
    fn store_event(&self, event: &AuditEvent) -> Result<()>;

    /// Retrieve events starting from a replay cursor
    fn retrieve_events_from(&self, cursor: &ReplayCursor, limit: usize) -> Result<Vec<AuditEvent>>;

    /// Get the current position/cursor for this sink
    fn current_cursor(&self) -> Result<ReplayCursor>;

    /// Verify replay cursor integrity before read/ack operations.
    fn verify_replay_cursor_integrity(&self, _cursor: &ReplayCursor) -> Result<()> {
        Ok(())
    }

    /// Acknowledge processing of events up to a given cursor
    fn acknowledge_cursor(&self, cursor: &ReplayCursor) -> Result<()>;

    /// Clear all events (for testing only; implementations may restrict this)
    fn clear(&self) -> Result<()>;
}

/// Durability classification for audit sink implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AuditSinkDurability {
    /// Production-grade persistence (restart and host-failure resilient).
    Durable,
    /// Ephemeral sink (in-memory/test-only); unsuitable for production guarantees.
    Ephemeral,
}

/// In-memory audit sink for testing
pub struct InMemoryAuditSink {
    events: parking_lot::Mutex<Vec<AuditEvent>>,
    acknowledged_cursor: parking_lot::Mutex<ReplayCursor>,
    cursor_hmac_key: [u8; 32],
}

impl InMemoryAuditSink {
    /// Create a new in-memory audit sink
    pub fn new() -> Self {
        let mut cursor_hmac_key = [0_u8; 32];
        if getrandom::fill(&mut cursor_hmac_key).is_err() {
            cursor_hmac_key
                .copy_from_slice(Sha256::digest(b"asx-replay-cursor-fallback-key").as_slice());
        }
        Self {
            events: parking_lot::Mutex::new(Vec::new()),
            acknowledged_cursor: parking_lot::Mutex::new(ReplayCursor::unsigned_start()),
            cursor_hmac_key,
        }
    }

    fn sign_replay_cursor(&self, mut cursor: ReplayCursor) -> ReplayCursor {
        if cursor.last_event_id == "0" {
            cursor.integrity_tag_b64.clear();
            return cursor;
        }

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.cursor_hmac_key)
            .expect("HMAC accepts fixed-size key");
        mac.update(cursor.signing_payload().as_bytes());
        cursor.integrity_tag_b64 = STANDARD.encode(mac.finalize().into_bytes());
        cursor
    }

    fn verify_replay_cursor_integrity_inner(&self, cursor: &ReplayCursor) -> Result<()> {
        if cursor.last_event_id == "0" {
            if cursor.position == 0 && cursor.last_timestamp == 0 {
                return Ok(());
            }

            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "bootstrap replay cursor must have position=0 and last_timestamp=0",
                ErrorContext::new("audit_sink_cursor_integrity"),
            ));
        }

        if cursor.integrity_tag_b64.is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "replay cursor integrity tag is required",
                ErrorContext::new("audit_sink_cursor_integrity"),
            ));
        }

        let supplied_tag = STANDARD
            .decode(cursor.integrity_tag_b64.as_bytes())
            .map_err(|_| {
                AsxError::new(
                    ErrorCode::InvalidInput,
                    "replay cursor integrity tag is not valid base64",
                    ErrorContext::new("audit_sink_cursor_integrity"),
                )
            })?;

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.cursor_hmac_key)
            .expect("HMAC accepts fixed-size key");
        mac.update(cursor.signing_payload().as_bytes());

        mac.verify_slice(&supplied_tag).map_err(|_| {
            AsxError::new(
                ErrorCode::InvalidInput,
                "replay cursor integrity verification failed",
                ErrorContext::new("audit_sink_cursor_integrity"),
            )
        })
    }
}

impl Default for InMemoryAuditSink {
    fn default() -> Self {
        Self::new()
    }
}

impl DurableAuditSink for InMemoryAuditSink {
    fn durability(&self) -> AuditSinkDurability {
        AuditSinkDurability::Ephemeral
    }

    fn has_replay_cursor_integrity_protection(&self) -> bool {
        true
    }

    fn store_event(&self, event: &AuditEvent) -> Result<()> {
        let mut events = self.events.lock();
        events.push(event.clone());
        Ok(())
    }

    fn retrieve_events_from(&self, cursor: &ReplayCursor, limit: usize) -> Result<Vec<AuditEvent>> {
        self.verify_replay_cursor_integrity_inner(cursor)?;
        let events = self.events.lock();

        // E4 fix: anchor on `last_event_id`, not on `position` as a raw Vec index.
        // Using an integer position as an index breaks silently after compaction
        // because indices shift when earlier events are removed.
        //
        // Sentinel "0" means "start from the very beginning of the stream".
        // Any other ID means "start from the event *after* the one with this ID".
        // If the ID is no longer present (e.g. compacted away), we start from the
        // beginning so replayers are never permanently stuck.
        let start_pos = if cursor.last_event_id == "0" {
            0
        } else {
            events
                .iter()
                .position(|e| e.event_id == cursor.last_event_id)
                .map(|idx| idx + 1)
                .unwrap_or(0) // ID compacted away → replay from start (safe)
        };
        let end_pos = (start_pos + limit).min(events.len());
        Ok(events[start_pos..end_pos].to_vec())
    }

    fn current_cursor(&self) -> Result<ReplayCursor> {
        let events = self.events.lock();

        if let Some(last) = events.last() {
            Ok(self.sign_replay_cursor(ReplayCursor {
                last_event_id: last.event_id.clone(),
                position: events.len() as u64,
                last_timestamp: last.timestamp,
                integrity_tag_b64: String::new(),
            }))
        } else {
            Ok(ReplayCursor::unsigned_start())
        }
    }

    fn verify_replay_cursor_integrity(&self, cursor: &ReplayCursor) -> Result<()> {
        self.verify_replay_cursor_integrity_inner(cursor)
    }

    fn acknowledge_cursor(&self, cursor: &ReplayCursor) -> Result<()> {
        self.verify_replay_cursor_integrity_inner(cursor)?;
        let events = self.events.lock();

        // Zero cursor always valid (acknowledges "nothing yet").
        if cursor.last_event_id != "0" {
            let found = events.iter().any(|e| e.event_id == cursor.last_event_id);
            if !found {
                return Err(AsxError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "acknowledged cursor event_id '{}' not found in event stream",
                        cursor.last_event_id
                    ),
                    ErrorContext::new("audit_sink_ack"),
                ));
            }
        }

        drop(events);

        let mut ack = self.acknowledged_cursor.lock();
        *ack = cursor.clone();
        Ok(())
    }

    fn clear(&self) -> Result<()> {
        let mut events = self.events.lock();
        events.clear();

        let mut cursor = self.acknowledged_cursor.lock();
        *cursor = ReplayCursor::unsigned_start();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retrieve_events_anchors_on_event_id_not_position() {
        // E4: Verify that retrieve_events_from uses last_event_id as anchor,
        // not position as a raw Vec index.  Simulates compaction by directly
        // building a sink whose internal stream no longer starts at index 0
        // relative to the original sequence.
        let sink = InMemoryAuditSink::new();
        let make = |id: &str, code: &str| AuditEvent {
            event_id: id.to_string(),
            session_id: None,
            partner_id: None,
            code: code.to_string(),
            timestamp: 1,
            message: id.to_string(),
            metadata: AuditMetadata {
                stage: None,
                severity: AuditSeverity::Low,
                action: None,
                result: None,
            },
        };
        sink.store_event(&make("e1", "c1")).unwrap();
        sink.store_event(&make("e2", "c2")).unwrap();
        sink.store_event(&make("e3", "c3")).unwrap();

        // Caller has consumed up through "e1"; cursor says position=1.
        // Now simulate compaction: clear and re-insert only e2, e3
        // (e1 has been archived/removed).
        {
            let mut events = sink.events.lock();
            events.retain(|e| e.event_id != "e1");
        }

        // With an integer-index approach, cursor.position=1 would still point
        // at index 1 (which is now "e3", skipping "e2"). With ID-based anchor,
        // we scan for "e1", don't find it (compacted away), and restart from 0,
        // delivering both "e2" and "e3".
        let err = sink
            .retrieve_events_from(
                &ReplayCursor {
                    last_event_id: "e1".to_string(),
                    position: 1, // stale; must be ignored
                    last_timestamp: 0,
                    integrity_tag_b64: String::new(),
                },
                10,
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);

        let signed_cursor = sink.sign_replay_cursor(ReplayCursor {
            last_event_id: "e1".to_string(),
            position: 1,
            last_timestamp: 0,
            integrity_tag_b64: String::new(),
        });
        let replay = sink.retrieve_events_from(&signed_cursor, 10).unwrap();
        assert_eq!(replay.len(), 2);
        assert_eq!(replay[0].event_id, "e2");
        assert_eq!(replay[1].event_id, "e3");
    }

    #[test]
    fn retrieve_events_resumes_correctly_after_known_anchor() {
        let sink = InMemoryAuditSink::new();
        let make = |id: &str| AuditEvent {
            event_id: id.to_string(),
            session_id: None,
            partner_id: None,
            code: "c".to_string(),
            timestamp: 1,
            message: id.to_string(),
            metadata: AuditMetadata {
                stage: None,
                severity: AuditSeverity::Low,
                action: None,
                result: None,
            },
        };
        for id in &["e1", "e2", "e3", "e4"] {
            sink.store_event(&make(id)).unwrap();
        }
        // Anchor at e2 → should return e3, e4
        let err = sink
            .retrieve_events_from(
                &ReplayCursor {
                    last_event_id: "e2".into(),
                    position: 99,
                    last_timestamp: 0,
                    integrity_tag_b64: String::new(),
                },
                10,
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);

        let page = sink
            .retrieve_events_from(
                &sink.sign_replay_cursor(ReplayCursor {
                    last_event_id: "e2".into(),
                    position: 99,
                    last_timestamp: 0,
                    integrity_tag_b64: String::new(),
                }),
                10,
            )
            .unwrap();
        assert_eq!(
            page.iter().map(|e| e.event_id.as_str()).collect::<Vec<_>>(),
            vec!["e3", "e4"]
        );
    }

    #[test]
    fn acknowledge_cursor_rejects_unknown_event_id() {
        let sink = InMemoryAuditSink::new();
        sink.store_event(&AuditEvent {
            event_id: "evt-1".into(),
            session_id: None,
            partner_id: None,
            code: "c1".into(),
            timestamp: 1,
            message: "m1".into(),
            metadata: AuditMetadata {
                stage: None,
                severity: AuditSeverity::Low,
                action: None,
                result: None,
            },
        })
        .unwrap();

        let err = sink
            .acknowledge_cursor(&ReplayCursor {
                last_event_id: "wrong".into(),
                position: 1,
                last_timestamp: 1,
                integrity_tag_b64: String::new(),
            })
            .expect_err("unknown event_id must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn in_memory_sink_stores_and_retrieves_events() {
        let sink = InMemoryAuditSink::new();
        let event = AuditEvent {
            event_id: "evt-1".to_string(),
            session_id: Some("sess-1".to_string()),
            partner_id: Some("partner-1".to_string()),
            code: "security_check_passed".to_string(),
            timestamp: 1747476000,
            message: "AS4 signature verified".to_string(),
            metadata: AuditMetadata {
                stage: Some("as4_verify".to_string()),
                severity: AuditSeverity::High,
                action: Some("verify_signature".to_string()),
                result: Some("success".to_string()),
            },
        };

        sink.store_event(&event).unwrap();

        let retrieved = sink
            .retrieve_events_from(
                &ReplayCursor {
                    last_event_id: "0".to_string(),
                    position: 0,
                    last_timestamp: 0,
                    integrity_tag_b64: String::new(),
                },
                10,
            )
            .unwrap();

        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].event_id, "evt-1");
    }

    #[test]
    fn audit_severity_display() {
        assert_eq!(AuditSeverity::Critical.to_string(), "CRITICAL");
        assert_eq!(AuditSeverity::High.to_string(), "HIGH");
        assert_eq!(AuditSeverity::Medium.to_string(), "MEDIUM");
        assert_eq!(AuditSeverity::Low.to_string(), "LOW");
    }

    #[test]
    fn in_memory_sink_clear() {
        let sink = InMemoryAuditSink::new();
        let event = AuditEvent {
            event_id: "evt-1".to_string(),
            session_id: None,
            partner_id: None,
            code: "test".to_string(),
            timestamp: 1747476000,
            message: "test event".to_string(),
            metadata: AuditMetadata {
                stage: None,
                severity: AuditSeverity::Low,
                action: None,
                result: None,
            },
        };

        sink.store_event(&event).unwrap();
        sink.clear().unwrap();

        let retrieved = sink
            .retrieve_events_from(
                &ReplayCursor {
                    last_event_id: "0".to_string(),
                    position: 0,
                    last_timestamp: 0,
                    integrity_tag_b64: String::new(),
                },
                10,
            )
            .unwrap();

        assert!(retrieved.is_empty());
    }

    #[test]
    fn current_cursor_tracks_stream_head() {
        let sink = InMemoryAuditSink::new();
        sink.store_event(&AuditEvent {
            event_id: "evt-1".into(),
            session_id: None,
            partner_id: None,
            code: "c1".into(),
            timestamp: 1,
            message: "m1".into(),
            metadata: AuditMetadata {
                stage: None,
                severity: AuditSeverity::Low,
                action: None,
                result: None,
            },
        })
        .unwrap();
        sink.store_event(&AuditEvent {
            event_id: "evt-2".into(),
            session_id: None,
            partner_id: None,
            code: "c2".into(),
            timestamp: 2,
            message: "m2".into(),
            metadata: AuditMetadata {
                stage: None,
                severity: AuditSeverity::Low,
                action: None,
                result: None,
            },
        })
        .unwrap();

        let cursor = sink.current_cursor().unwrap();
        assert_eq!(cursor.position, 2);
        assert_eq!(cursor.last_event_id, "evt-2");
        assert!(!cursor.integrity_tag_b64.is_empty());
    }

    #[test]
    fn replay_cursor_integrity_rejects_tampering() {
        let sink = InMemoryAuditSink::new();
        sink.store_event(&AuditEvent {
            event_id: "evt-1".into(),
            session_id: None,
            partner_id: None,
            code: "c1".into(),
            timestamp: 1,
            message: "m1".into(),
            metadata: AuditMetadata {
                stage: None,
                severity: AuditSeverity::Low,
                action: None,
                result: None,
            },
        })
        .unwrap();

        let mut cursor = sink.current_cursor().expect("cursor");
        cursor.position = 99;

        let err = sink
            .retrieve_events_from(&cursor, 10)
            .expect_err("tampered cursor must fail");
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }
}
