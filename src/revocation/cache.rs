//! The revocation cache seam: opaque entries the library writes, under keys
//! the library computes, re-verified on every read.
//!
//! The trait is crate-private; every client uses the bounded in-process
//! [`MemoryRevocationCache`].

use crate::clock::SharedClock;
use crate::error::{BoxError, BoxFuture};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A cache for CRLs and OCSP responses. An entry read back is verified again
/// as if just fetched; an `Err` is a miss.
pub(crate) trait RevocationCache: Send + Sync + std::fmt::Debug + 'static {
    /// The entry stored under `key`, if any.
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Bytes>, BoxError>>;
    /// Store `entry` under `key`; after `expires_at` the backend may forget it.
    fn put<'a>(
        &'a self,
        key: &'a str,
        entry: Bytes,
        expires_at: SystemTime,
    ) -> BoxFuture<'a, Result<(), BoxError>>;
}

/// At most this many entries in the default cache.
pub(crate) const MEMORY_CACHE_ENTRIES: usize = 1024;

/// The default cache: in-process, one per client, LRU-bounded, expiring on
/// the client's clock.
#[derive(Debug)]
pub(crate) struct MemoryRevocationCache {
    entries: Mutex<lru::LruCache<String, (Bytes, SystemTime)>>,
    clock: SharedClock,
}

impl MemoryRevocationCache {
    pub(crate) fn new(clock: SharedClock) -> Self {
        Self {
            entries: Mutex::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(MEMORY_CACHE_ENTRIES).expect("non-zero"),
            )),
            clock,
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl RevocationCache for MemoryRevocationCache {
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Bytes>, BoxError>> {
        let now = self.clock.now();
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let found = match entries.get(key) {
            Some((entry, expires_at)) if *expires_at > now => Some(entry.clone()),
            Some(_) => {
                entries.pop(key);
                None
            }
            None => None,
        };
        Box::pin(std::future::ready(Ok(found)))
    }

    fn put<'a>(
        &'a self,
        key: &'a str,
        entry: Bytes,
        expires_at: SystemTime,
    ) -> BoxFuture<'a, Result<(), BoxError>> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(key.to_string(), (entry, expires_at));
        Box::pin(std::future::ready(Ok(())))
    }
}

/// The envelope version prefix; an entry without it is a miss.
const ENVELOPE_V1: &[u8] = b"asx-rev-v1";

/// `v1 ‖ fetched_at (u64 BE seconds) ‖ DER`.
pub(crate) fn seal(fetched_at: SystemTime, der: &[u8]) -> Bytes {
    let secs = fetched_at
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut out = Vec::with_capacity(ENVELOPE_V1.len() + 8 + der.len());
    out.extend_from_slice(ENVELOPE_V1);
    out.extend_from_slice(&secs.to_be_bytes());
    out.extend_from_slice(der);
    Bytes::from(out)
}

/// The fetch time and DER of an entry; `None` for anything else.
pub(crate) fn open(entry: &Bytes) -> Option<(SystemTime, Bytes)> {
    let rest = entry.strip_prefix(ENVELOPE_V1)?;
    let (secs, _) = rest.split_first_chunk::<8>()?;
    let fetched_at = UNIX_EPOCH + Duration::from_secs(u64::from_be_bytes(*secs));
    let start = ENVELOPE_V1.len() + 8;
    (entry.len() > start).then(|| (fetched_at, entry.slice(start..)))
}

/// `prefix ‖ hex(SHA-256(parts joined by 0x00))`: fixed length, computed by
/// the library only.
pub(crate) fn key(prefix: &str, parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            hasher.update([0u8]);
        }
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(prefix.len() + 64);
    out.push_str(prefix);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;

    #[test]
    fn envelope_round_trips_and_refuses_other_bytes() {
        let at = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let sealed = seal(at, b"\x30\x03der");
        let (fetched, der) = open(&sealed).expect("opens");
        assert_eq!(fetched, at);
        assert_eq!(&der[..], b"\x30\x03der");
        assert!(open(&Bytes::from_static(b"asx-rev-v2........der")).is_none());
        assert!(open(&Bytes::from_static(b"asx-rev-v1\0\0")).is_none());
        assert!(open(&seal(at, b"")).is_none(), "an empty DER is no entry");
    }

    #[test]
    fn keys_are_fixed_length_and_separate_their_parts() {
        let a = key("crl:", &[b"ab", b"c"]);
        let b = key("crl:", &[b"a", b"bc"]);
        assert_ne!(a, b);
        assert_eq!(a.len(), 4 + 64);
        assert_eq!(key("ocsp:", &[b"x"]).len(), 5 + 64);
    }

    #[tokio::test]
    async fn memory_cache_expires_on_the_client_clock_and_is_bounded() {
        let manual = ManualClock::at(UNIX_EPOCH + Duration::from_secs(1_800_000_000));
        let clock: SharedClock = manual.clone();
        let cache = MemoryRevocationCache::new(clock.clone());
        let expires = clock.now() + Duration::from_secs(60);
        cache
            .put("k", Bytes::from_static(b"v"), expires)
            .await
            .unwrap();
        assert_eq!(cache.get("k").await.unwrap().as_deref(), Some(&b"v"[..]));
        manual.advance(Duration::from_secs(60));
        assert_eq!(cache.get("k").await.unwrap(), None);
        for i in 0..(MEMORY_CACHE_ENTRIES + 10) {
            cache
                .put(
                    &format!("k{i}"),
                    Bytes::from_static(b"v"),
                    expires + Duration::from_secs(600),
                )
                .await
                .unwrap();
        }
        assert_eq!(cache.len(), MEMORY_CACHE_ENTRIES);
    }
}
