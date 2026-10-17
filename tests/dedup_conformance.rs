//! The `DedupStore` conformance suite against `MemoryDedup`, its negative
//! controls, and the pinned dedup-key vector.

use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::time::Duration;

use asx_testkit::dedup::{self, DedupHarness, broken, conformance};

#[derive(Debug)]
struct Fresh<S>(PhantomData<fn() -> S>);

impl<S: asx::DedupStore + Default> DedupHarness for Fresh<S> {
    type Store = S;

    fn open(&self) -> S {
        S::default()
    }

    fn lease(&self) -> Duration {
        broken::LEASE
    }
}

async fn failing_checks<S: asx::DedupStore + Default>() -> BTreeSet<&'static str> {
    let failures = conformance(&Fresh::<S>(PhantomData)).await;
    for failure in &failures {
        eprintln!("{failure}");
    }
    failures.iter().map(|f| f.check).collect()
}

fn set(checks: &[&'static str]) -> BTreeSet<&'static str> {
    checks.iter().copied().collect()
}

#[tokio::test(start_paused = true)]
async fn memory_dedup_conforms() {
    let failures = conformance(&Fresh::<asx::MemoryDedup>(PhantomData)).await;
    assert!(failures.is_empty(), "{failures:#?}");
}

#[tokio::test(start_paused = true)]
async fn key_only_store_fails_exactly_the_token_checks() {
    assert_eq!(
        failing_checks::<broken::KeyOnlyDedup>().await,
        set(&[
            dedup::STALE_HOLDER_CANNOT_ACCEPT,
            dedup::STALE_HOLDER_CANNOT_ABANDON,
            dedup::TOKENS_ARE_FRESH_PER_CLAIM,
        ])
    );
}

#[tokio::test(start_paused = true)]
async fn non_atomic_store_fails_the_race() {
    assert_eq!(
        failing_checks::<broken::NonAtomicDedup>().await,
        set(&[dedup::CONCURRENT_CLAIM_ADMITS_EXACTLY_ONE])
    );
}

#[tokio::test(start_paused = true)]
async fn duplicate_while_in_flight_store_fails_the_in_flight_checks() {
    assert_eq!(
        failing_checks::<broken::DuplicateWhileInFlightDedup>().await,
        set(&[
            dedup::DISTINCT_KEYS_ARE_INDEPENDENT,
            dedup::UNSETTLED_CLAIM_REPORTS_IN_FLIGHT,
            dedup::LEASE_EXPIRY_ALLOWS_RECLAIM,
            dedup::STALE_HOLDER_CANNOT_ACCEPT,
            dedup::STALE_HOLDER_CANNOT_ABANDON,
        ])
    );
}

#[tokio::test(start_paused = true)]
async fn abandon_reopens_store_fails_the_late_abandon_check() {
    assert_eq!(
        failing_checks::<broken::AbandonReopensDedup>().await,
        set(&[dedup::ABANDON_NEVER_REOPENS_AN_ACCEPTED_KEY])
    );
}

#[tokio::test(start_paused = true)]
async fn no_lease_store_fails_the_lease_checks() {
    assert_eq!(
        failing_checks::<broken::NoLeaseDedup>().await,
        set(&[
            dedup::LEASE_EXPIRY_ALLOWS_RECLAIM,
            dedup::STALE_HOLDER_CANNOT_ACCEPT,
            dedup::STALE_HOLDER_CANNOT_ABANDON,
        ])
    );
}

#[tokio::test(start_paused = true)]
async fn failing_store_fails_every_check() {
    assert_eq!(
        failing_checks::<broken::FailingDedup>().await,
        set(dedup::CHECKS)
    );
}

#[test]
fn key_vector_is_pinned() {
    let key = asx::__dedup_key(
        "as4",
        "urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW",
        "9900000000002",
        "abc@example.org",
    );
    assert_eq!(key.len(), 64);
    assert!(key.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    assert_eq!(
        key,
        "761dc421ef8588b1802121c3032ce539af1a6c8c3cfb1e21c6fdf1674f1398dd"
    );
}

#[test]
fn senders_with_the_same_message_id_get_different_keys() {
    let a = asx::__dedup_key("as4", "type", "sender-a", "m@example.org");
    let b = asx::__dedup_key("as4", "type", "sender-b", "m@example.org");
    assert_ne!(a, b);
}
