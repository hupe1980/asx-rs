//! Two-phase replay protection: claim, then accept or abandon under the
//! claim's lease token.

use crate::error::{BoxError, BoxFuture};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::Instant;

/// Two-phase replay protection. The key is an opaque fixed-length hex
/// digest. Infrastructure failure must return `Err` (fail closed).
///
/// The library calls `claim` after the message verified and decrypted, the
/// handler only for [`Claim::Claimed`], and then exactly one of `accept`
/// (handler `Ok`, audit written) or `abandon` (handler `Err`, panic, audit
/// failure) with the token the claim returned.
///
/// An accepted key must be remembered for at least 24 hours: an inbound AS4
/// message is refused by its `eb:Timestamp` only beyond that, so a replay
/// within it must be answered as [`Claim::Duplicate`].
pub trait DedupStore: Send + Sync + std::fmt::Debug + 'static {
    /// Atomically take the key, or report `Duplicate` / `InFlight`. A
    /// successful claim carries a fresh lease token (a new value per claim,
    /// never reused for the key). An unsettled claim must expire (lease);
    /// after expiry the key can be claimed again under a new token.
    fn claim<'a>(
        &'a self,
        key: &'a str,
    ) -> BoxFuture<'a, std::result::Result<Claim, Box<dyn std::error::Error + Send + Sync>>>;

    /// The message was handled durably: answer replays as duplicates from now
    /// on. Must succeed only if `token` is the key's *current* lease; a stale
    /// holder (its lease expired and the key was re-claimed, or already
    /// settled) gets `Err` and changes nothing.
    fn accept<'a>(
        &'a self,
        key: &'a str,
        token: &'a ClaimToken,
    ) -> BoxFuture<'a, std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>>;

    /// The message was not handled: release an *unsettled* claim held under
    /// `token` (never an accepted one, never another holder's). A stale token
    /// gets `Err` and changes nothing.
    fn abandon<'a>(
        &'a self,
        key: &'a str,
        token: &'a ClaimToken,
    ) -> BoxFuture<'a, std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>>;
}

/// The answer to [`DedupStore::claim`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// The key is now held under this lease token.
    Claimed(ClaimToken),
    /// The message was already accepted.
    Duplicate,
    /// Another delivery holds an unexpired lease on the key.
    InFlight,
}

/// The lease id of one successful `claim`, opaque to the library. Stores
/// create it (a UUID, a row version, a fencing counter) and compare it in
/// `accept`/`abandon`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClaimToken(String);

impl ClaimToken {
    /// Wrap a store's lease id.
    pub fn new(lease: impl Into<String>) -> ClaimToken {
        ClaimToken(lease.into())
    }

    /// The lease id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// In-process, **non-durable**: forgets everything on restart and is not
/// shared between processes. Lease 5 min, retention 24 h.
///
/// Use it for tests, examples and single-process deployments that accept
/// redelivery after a restart; implement [`DedupStore`] over your database
/// otherwise.
#[derive(Debug, Default)]
pub struct MemoryDedup {
    entries: Mutex<HashMap<String, Entry>>,
}

#[derive(Debug)]
enum Entry {
    Held { token: ClaimToken, until: Instant },
    Accepted { until: Instant },
}

const LEASE: Duration = Duration::from_secs(5 * 60);
const RETENTION: Duration = MIN_RETENTION;

/// How long a [`DedupStore`] must remember an accepted key: the inbound AS4
/// `eb:Timestamp` window reaches this far back (a replay within it is a
/// duplicate; one beyond it is refused by its timestamp).
pub(crate) const MIN_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

impl MemoryDedup {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn claim_now(&self, key: &str) -> std::result::Result<Claim, BoxError> {
        let now = Instant::now();
        let mut entries = self.lock();
        entries.retain(|_, entry| match entry {
            Entry::Held { until, .. } | Entry::Accepted { until } => *until > now,
        });
        match entries.get(key) {
            Some(Entry::Accepted { .. }) => Ok(Claim::Duplicate),
            Some(Entry::Held { .. }) => Ok(Claim::InFlight),
            None => {
                let token = ClaimToken(fresh_token()?);
                entries.insert(
                    key.to_string(),
                    Entry::Held {
                        token: token.clone(),
                        until: now + LEASE,
                    },
                );
                Ok(Claim::Claimed(token))
            }
        }
    }

    fn settle(
        &self,
        key: &str,
        token: &ClaimToken,
        accept: bool,
    ) -> std::result::Result<(), BoxError> {
        let now = Instant::now();
        let mut entries = self.lock();
        match entries.get(key) {
            Some(Entry::Held { token: held, until }) if held == token && *until > now => {
                if accept {
                    entries.insert(
                        key.to_string(),
                        Entry::Accepted {
                            until: now + RETENTION,
                        },
                    );
                } else {
                    entries.remove(key);
                }
                Ok(())
            }
            _ => Err("the claim is not held under this token (lease expired or settled)".into()),
        }
    }
}

fn fresh_token() -> std::result::Result<String, BoxError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|err| format!("no randomness for a claim token: {err}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

impl DedupStore for MemoryDedup {
    fn claim<'a>(&'a self, key: &'a str) -> BoxFuture<'a, std::result::Result<Claim, BoxError>> {
        Box::pin(std::future::ready(self.claim_now(key)))
    }

    fn accept<'a>(
        &'a self,
        key: &'a str,
        token: &'a ClaimToken,
    ) -> BoxFuture<'a, std::result::Result<(), BoxError>> {
        Box::pin(std::future::ready(self.settle(key, token, true)))
    }

    fn abandon<'a>(
        &'a self,
        key: &'a str,
        token: &'a ClaimToken,
    ) -> BoxFuture<'a, std::result::Result<(), BoxError>> {
        Box::pin(std::future::ready(self.settle(key, token, false)))
    }
}

/// The protocol a dedup key belongs to.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(dead_code))]
pub(crate) enum DedupProtocol {
    As4,
    As2,
}

/// The dedup key: `hex(SHA-256("asx-dedup-v1" ‖ 0 ‖ protocol ‖ 0 ‖
/// sender_type ‖ 0 ‖ sender_id ‖ 0 ‖ message_id))`, 64 lowercase hex
/// characters. Stable across releases: a change is a wire CHANGELOG entry.
#[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(dead_code))]
pub(crate) fn dedup_key(
    protocol: DedupProtocol,
    sender_type: &str,
    sender_id: &str,
    message_id: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"asx-dedup-v1");
    for part in [
        match protocol {
            DedupProtocol::As4 => "as4",
            DedupProtocol::As2 => "as2",
        },
        sender_type,
        sender_id,
        message_id,
    ] {
        hasher.update([0u8]);
        hasher.update(part.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Test hook for `tests/dedup_conformance.rs` and the key vector.
#[doc(hidden)]
pub fn __dedup_key(protocol: &str, sender_type: &str, sender_id: &str, message_id: &str) -> String {
    let protocol = if protocol == "as2" {
        DedupProtocol::As2
    } else {
        DedupProtocol::As4
    };
    dedup_key(protocol, sender_type, sender_id, message_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_vector_is_pinned() {
        let key = dedup_key(
            DedupProtocol::As4,
            "urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW",
            "9900000000002",
            "abc@example.org",
        );
        assert_eq!(key.len(), 64);
        assert!(
            key.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        // Pinned against the conformance suite's vector (tests/dedup_conformance.rs).
        assert_eq!(
            key,
            "761dc421ef8588b1802121c3032ce539af1a6c8c3cfb1e21c6fdf1674f1398dd"
        );
    }

    #[test]
    fn senders_do_not_collide() {
        let a = dedup_key(DedupProtocol::As4, "t", "sender-a", "m@x");
        let b = dedup_key(DedupProtocol::As4, "t", "sender-b", "m@x");
        let c = dedup_key(DedupProtocol::As2, "t", "sender-a", "m@x");
        assert_ne!(a, b);
        assert_ne!(a, c);
        // Concatenation is unambiguous.
        assert_ne!(
            dedup_key(DedupProtocol::As4, "ab", "c", "m"),
            dedup_key(DedupProtocol::As4, "a", "bc", "m")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stale_holder_cannot_settle() {
        let store = MemoryDedup::default();
        let Claim::Claimed(first) = store.claim("k").await.unwrap() else {
            panic!("first claim")
        };
        assert_eq!(store.claim("k").await.unwrap(), Claim::InFlight);
        tokio::time::advance(LEASE + Duration::from_secs(1)).await;
        let Claim::Claimed(second) = store.claim("k").await.unwrap() else {
            panic!("re-claim after lease expiry")
        };
        assert_ne!(first, second);
        assert!(store.accept("k", &first).await.is_err());
        assert!(store.abandon("k", &first).await.is_err());
        store.accept("k", &second).await.unwrap();
        assert_eq!(store.claim("k").await.unwrap(), Claim::Duplicate);
    }

    #[tokio::test]
    async fn abandon_releases() {
        let store = MemoryDedup::default();
        let Claim::Claimed(token) = store.claim("k").await.unwrap() else {
            panic!()
        };
        store.abandon("k", &token).await.unwrap();
        assert!(matches!(store.claim("k").await.unwrap(), Claim::Claimed(_)));
    }
}
