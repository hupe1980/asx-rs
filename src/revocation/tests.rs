//! The revocation module in isolation: a `ManualClock`, a
//! scripted fetcher, and test-CA material (bytes only) from the testkit.
//! Every boundary is tested at ± 1 s so a mutated comparison fails.

use super::*;
use crate::clock::ManualClock;
use crate::error::{BoxError, BoxFuture};
use asx_testkit::pki::{Cdp, Idp, IssueOptions, KeyAlg, KeyPair, TestCa};
use std::sync::atomic::AtomicUsize;

const HOUR: Duration = Duration::from_secs(3600);
const S: Duration = Duration::from_secs(1);

/// URL → body (`None`: unreachable); counts requests per URL.
#[derive(Debug, Default)]
struct Scripted {
    bodies: Mutex<HashMap<String, Option<Vec<u8>>>>,
    asked: Mutex<Vec<String>>,
    /// Hold every response until released (single-flight).
    gate: Option<Arc<tokio::sync::Semaphore>>,
}

impl Scripted {
    fn serve(&self, url: &str, body: Vec<u8>) {
        self.bodies.lock().unwrap().insert(url.into(), Some(body));
    }
    fn fail(&self, url: &str) {
        self.bodies.lock().unwrap().insert(url.into(), None);
    }
    fn count(&self, url: &str) -> usize {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .filter(|u| *u == url)
            .count()
    }
    fn total(&self) -> usize {
        self.asked.lock().unwrap().len()
    }
}

#[derive(Debug, Clone)]
struct Http(Arc<Scripted>);

impl HttpClient for Http {
    fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> BoxFuture<'_, Result<http::Response<Bytes>, BoxError>> {
        let this = self.0.clone();
        Box::pin(async move {
            assert!(
                request.extensions().get::<RevocationFetch>().is_some(),
                "every revocation request is marked"
            );
            let url = request.uri().to_string();
            this.asked.lock().unwrap().push(url.clone());
            if let Some(gate) = &this.gate {
                let _permit = gate.acquire().await.unwrap();
            }
            let body = this.bodies.lock().unwrap().get(&url).cloned();
            match body {
                Some(Some(body)) => Ok(http::Response::builder()
                    .status(200)
                    .body(Bytes::from(body))
                    .unwrap()),
                Some(None) => Err("unreachable".into()),
                None => Ok(http::Response::builder()
                    .status(404)
                    .body(Bytes::new())
                    .unwrap()),
            }
        })
    }
}

fn x509(pem: &[u8]) -> X509 {
    X509::from_pem(pem).unwrap()
}

struct World {
    manual: Arc<ManualClock>,
    t0: SystemTime,
    http: Arc<Scripted>,
    root: TestCa,
}

impl World {
    fn new() -> World {
        // Whole seconds, as DER times and the cache envelope carry them, so
        // the exact boundaries are reachable.
        let secs = crate::clock::system()
            .now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let t0 = std::time::UNIX_EPOCH + Duration::from_secs(secs);
        World {
            manual: ManualClock::at(t0),
            t0,
            http: Arc::new(Scripted::default()),
            root: TestCa::new("rev root", KeyAlg::EcP256),
        }
    }

    fn revocation(&self, rule: RevocationRule) -> Arc<Revocation> {
        self.revocation_with(rule, Vec::new(), None)
    }

    fn revocation_with(
        &self,
        rule: RevocationRule,
        signers: Vec<X509>,
        cache: Option<Arc<dyn RevocationCache>>,
    ) -> Arc<Revocation> {
        Arc::new(Revocation::new(
            rule,
            Arc::new(Http(self.http.clone())),
            self.manual.clone(),
            vec![x509(self.root.cert_pem())],
            signers,
            cache,
        ))
    }

    fn at(&self, offset: Duration) {
        self.manual.set(self.t0 + offset);
    }

    /// A CRL of `ca` issued at t0 with `next` after t0.
    fn crl(&self, ca: &TestCa, revoked: &[&KeyPair], next: Duration) -> Vec<u8> {
        let mut b = ca
            .crl_builder()
            .this_update(self.t0 - HOUR)
            .next_update(Some(self.t0 + next));
        for pair in revoked {
            b = b.revoke(pair);
        }
        b.build()
    }

    fn path(&self, leaf: &KeyPair) -> Vec<X509> {
        vec![x509(&leaf.cert_pem), x509(self.root.cert_pem())]
    }
}

fn distrusted(outcome: &Outcome) -> Option<DistrustReason> {
    match outcome {
        Outcome::Distrusted { reason, .. } => Some(*reason),
        _ => None,
    }
}

// ── refused from the CDP ────────────────────────────────────────────────────

#[tokio::test]
async fn bdew_refuses_a_leaf_listed_in_its_issuers_crl_and_caches_the_crl() {
    let w = World::new();
    let leaf = w.root.issue("leaf", KeyAlg::EcP256);
    let good = w.root.issue("good", KeyAlg::EcP256);
    w.http
        .serve(w.root.crl_url(), w.crl(&w.root, &[&leaf], 7 * DAY));
    let rev = w.revocation(RevocationRule::bdew());
    let outcome = rev.check(&w.path(&leaf)).await;
    assert!(outcome.is_revoked() && outcome.refused(), "{outcome:?}");
    assert_eq!(rev.check(&w.path(&good)).await, Outcome::Good);
    assert_eq!(
        w.http.count(w.root.crl_url()),
        1,
        "one fetch, then the cache"
    );
}

#[tokio::test]
async fn bdew_refuses_a_certificate_without_a_distribution_point() {
    let w = World::new();
    let leaf = w.root.issue_with_options(
        "no cdp",
        KeyAlg::EcP256,
        IssueOptions {
            cdp: Cdp::None,
            ..IssueOptions::default()
        },
    );
    let outcome = w
        .revocation(RevocationRule::bdew())
        .check(&w.path(&leaf))
        .await;
    assert!(
        matches!(
            outcome,
            Outcome::NoSource {
                accepted: false,
                ..
            }
        ),
        "{outcome:?}"
    );
    assert!(outcome.describe().contains("no CRL distribution point"));
    assert_eq!(w.http.total(), 0);
}

#[tokio::test]
async fn a_crl_that_does_not_verify_or_does_not_apply_counts_as_not_obtainable() {
    let w = World::new();
    let leaf = w.root.issue("leaf", KeyAlg::EcP256);
    let stranger = TestCa::new("rev root", KeyAlg::EcP256);
    let rev = w.revocation(RevocationRule::bdew());
    for bad in [
        w.crl(&stranger, &[], 7 * DAY),
        w.root.crl_builder().delta().build(),
        w.root
            .crl_builder()
            .idp(Idp {
                only_ca_certs: true,
                ..Idp::default()
            })
            .build(),
        w.root.crl_builder().unknown_critical_extension().build(),
        w.root.crl_builder().next_update(None).build(),
    ] {
        w.http.serve(w.root.crl_url(), bad);
        let outcome = rev.check(&w.path(&leaf)).await;
        assert!(
            matches!(
                outcome,
                Outcome::NotObtainable {
                    accepted: false,
                    ..
                }
            ),
            "{outcome:?}"
        );
    }
}

#[tokio::test]
async fn ldap_only_distribution_points_are_skipped_and_not_obtainable() {
    let w = World::new();
    let leaf = w.root.issue_with_options(
        "ldap",
        KeyAlg::EcP256,
        IssueOptions {
            cdp: Cdp::Points(vec![vec!["ldap://dir.example/cn=root".into()]]),
            ..IssueOptions::default()
        },
    );
    let outcome = w
        .revocation(RevocationRule::bdew())
        .check(&w.path(&leaf))
        .await;
    assert!(
        matches!(outcome, Outcome::NotObtainable { .. }),
        "{outcome:?}"
    );
    assert_eq!(w.http.total(), 0, "no ldap request");
}

#[tokio::test]
async fn several_distribution_points_are_tried_in_order() {
    let w = World::new();
    let leaf = w.root.issue_with_options(
        "two dps",
        KeyAlg::EcP256,
        IssueOptions {
            cdp: Cdp::Points(vec![
                vec!["http://down.example/a.crl".into()],
                vec!["http://up.example/b.crl".into()],
            ]),
            ..IssueOptions::default()
        },
    );
    w.http.fail("http://down.example/a.crl");
    w.http
        .serve("http://up.example/b.crl", w.crl(&w.root, &[], 7 * DAY));
    let outcome = w
        .revocation(RevocationRule::bdew())
        .check(&w.path(&leaf))
        .await;
    assert_eq!(outcome, Outcome::Good);
    assert_eq!(w.http.count("http://down.example/a.crl"), 1);
}

#[tokio::test]
async fn an_indirect_root_crl_from_the_configured_signer_refuses_a_sub_ca() {
    let w = World::new();
    let signer = w.root.crl_signer("CCRL-S(Root)", KeyAlg::EcP256);
    let url = "http://crl.example/root-indirect.crl";
    let sub = w.root.sub_ca_with_options(
        "sub ca",
        KeyAlg::EcP256,
        IssueOptions {
            cdp: Cdp::Indirect {
                uris: vec![url.into()],
                crl_issuer: signer.clone(),
            },
            ..IssueOptions::default()
        },
    );
    let leaf = sub.issue("leaf under sub", KeyAlg::EcP256);
    w.http.serve(sub.crl_url(), w.crl(&sub, &[], 7 * DAY));
    let indirect = |revoked: bool| {
        let mut b = signer.crl_builder().idp(Idp {
            uris: vec![url.into()],
            indirect: true,
            ..Idp::default()
        });
        if revoked {
            b = b.revoke_ca_issued_by(&sub, &w.root);
        }
        b.build()
    };
    let path = vec![
        x509(&leaf.cert_pem),
        x509(sub.cert_pem()),
        x509(w.root.cert_pem()),
    ];
    let signers = vec![x509(signer.cert_pem())];

    w.http.serve(url, indirect(false));
    let rev = w.revocation_with(RevocationRule::bdew(), signers.clone(), None);
    assert_eq!(rev.check(&path).await, Outcome::Good);

    w.http.serve(url, indirect(true));
    let rev = w.revocation_with(RevocationRule::bdew(), signers, None);
    let outcome = rev.check(&path).await;
    assert!(outcome.is_revoked(), "{outcome:?}");
    assert_eq!(
        w.http.count(sub.crl_url()),
        1,
        "the walk stops at the revoked Sub-CA (only the first client fetched the leaf CRL)"
    );

    // Without the configured signer nothing can verify the root CRL.
    let rev = w.revocation_with(RevocationRule::bdew(), Vec::new(), None);
    assert!(matches!(
        rev.check(&path).await,
        Outcome::NotObtainable { .. }
    ));
}

// ── the three-day rule ──────────────────────────────────────────────────────

#[tokio::test]
async fn the_three_day_window_is_measured_from_the_last_successful_fetch() {
    let w = World::new();
    let leaf = w.root.issue("leaf", KeyAlg::EcP256);
    w.http.serve(w.root.crl_url(), w.crl(&w.root, &[], 7 * DAY));
    let rev = w.revocation(RevocationRule::bdew());
    assert_eq!(rev.check(&w.path(&leaf)).await, Outcome::Good);
    w.http.fail(w.root.crl_url());

    // Day 1: the refresh (background) fails; the last known CRL is used.
    w.at(DAY + HOUR);
    assert_eq!(rev.check(&w.path(&leaf)).await, Outcome::Good);
    rev.settle().await;
    assert_eq!(w.http.count(w.root.crl_url()), 2);
    assert!(rev.failing_since(&scope_key(&w.root)).is_some());

    w.at(3 * DAY - S);
    assert_eq!(rev.check(&w.path(&leaf)).await, Outcome::Good, "72 h − 1 s");
    rev.settle().await;
    w.at(3 * DAY);
    assert_eq!(
        rev.check(&w.path(&leaf)).await,
        Outcome::Good,
        "exactly 72 h"
    );
    rev.settle().await;

    w.at(3 * DAY + S);
    let outcome = rev.check(&w.path(&leaf)).await;
    assert_eq!(
        distrusted(&outcome),
        Some(DistrustReason::NotObtainable),
        "72 h + 1 s"
    );
    let text = outcome.describe();
    assert!(
        text.contains("CRL not obtainable for more than 3 days"),
        "{text}"
    );
    assert!(text.contains("CN=rev root"), "{text}");
    assert!(
        matches!(outcome, Outcome::Distrusted { since, .. }
            if crate::time_utils::unix_secs(since) == crate::time_utils::unix_secs(w.t0)),
        "since = the last successful fetch: {outcome:?}"
    );
    // Nothing about the distrust is stored: a current CRL ends it.
    w.http.serve(
        w.root.crl_url(),
        w.root
            .crl_builder()
            .this_update(w.t0 + 3 * DAY)
            .next_update(Some(w.t0 + 10 * DAY))
            .build(),
    );
    assert_eq!(rev.check(&w.path(&leaf)).await, Outcome::Good);
}

fn scope_key(ca: &TestCa) -> String {
    cache::key(
        "crl:",
        &[&spki_hash(&x509(ca.cert_pem())), ca.crl_url().as_bytes()],
    )
}

#[tokio::test]
async fn a_crl_past_next_update_without_renewal_distrusts_its_ca_at_once() {
    let w = World::new();
    let leaf = w.root.issue("leaf", KeyAlg::EcP256);
    w.http
        .serve(w.root.crl_url(), w.crl(&w.root, &[], 10 * HOUR));
    let rev = w.revocation(RevocationRule::bdew());
    assert_eq!(rev.check(&w.path(&leaf)).await, Outcome::Good);
    w.at(10 * HOUR - S);
    assert_eq!(
        rev.check(&w.path(&leaf)).await,
        Outcome::Good,
        "nextUpdate − 1 s"
    );
    assert_eq!(w.http.count(w.root.crl_url()), 1);
    w.at(10 * HOUR);
    assert_eq!(
        rev.check(&w.path(&leaf)).await,
        Outcome::Good,
        "exactly nextUpdate"
    );
    assert_eq!(
        w.http.count(w.root.crl_url()),
        2,
        "due at nextUpdate: refetched inline"
    );
    w.at(10 * HOUR + S);
    // The CDP still serves the same (expired) CRL: obtainable, not renewed.
    let outcome = rev.check(&w.path(&leaf)).await;
    assert_eq!(
        distrusted(&outcome),
        Some(DistrustReason::NotRenewed),
        "nextUpdate + 1 s"
    );
    assert!(
        outcome
            .describe()
            .contains("not renewed within its validity period")
    );
}

#[tokio::test]
async fn outside_bdew_an_expired_crl_is_not_obtainable_never_distrust() {
    let w = World::new();
    let leaf = w.root.issue("leaf", KeyAlg::EcP256);
    w.http
        .serve(w.root.crl_url(), w.crl(&w.root, &[], 10 * HOUR));
    let rev = w.revocation(RevocationRule::crl_then_ocsp(MissingSource::AcceptRecorded));
    w.at(11 * HOUR);
    let outcome = rev.check(&w.path(&leaf)).await;
    assert!(
        matches!(
            outcome,
            Outcome::NotObtainable {
                accepted: false,
                ..
            }
        ),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a_stale_root_crl_distrusts_everything_under_the_root() {
    let w = World::new();
    let sub = w.root.sub_ca("sub", KeyAlg::EcP256);
    let leaf = sub.issue("leaf", KeyAlg::EcP256);
    w.http
        .serve(w.root.crl_url(), w.crl(&w.root, &[], 10 * HOUR));
    w.http.serve(sub.crl_url(), w.crl(&sub, &[], 7 * DAY));
    let path = vec![
        x509(&leaf.cert_pem),
        x509(sub.cert_pem()),
        x509(w.root.cert_pem()),
    ];
    let rev = w.revocation(RevocationRule::bdew());
    assert_eq!(rev.check(&path).await, Outcome::Good);
    w.at(11 * HOUR);
    let outcome = rev.check(&path).await;
    assert!(
        matches!(&outcome, Outcome::Distrusted { ca, .. } if ca.contains("rev root")),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a_clock_moving_backwards_forces_a_refetch_and_never_extends_trust() {
    let w = World::new();
    let leaf = w.root.issue("leaf", KeyAlg::EcP256);
    w.http.serve(w.root.crl_url(), w.crl(&w.root, &[], 7 * DAY));
    let rev = w.revocation(RevocationRule::bdew());
    w.at(4 * DAY);
    assert_eq!(rev.check(&w.path(&leaf)).await, Outcome::Good);
    assert_eq!(w.http.count(w.root.crl_url()), 1);
    // Back to t0: the stored fetch time (t0 + 4 d) lies in the future.
    w.at(Duration::ZERO);
    w.http.fail(w.root.crl_url());
    assert_eq!(rev.check(&w.path(&leaf)).await, Outcome::Good);
    assert_eq!(w.http.count(w.root.crl_url()), 2, "refetch forced");
    // Judged from thisUpdate (t0 − 1 h), not the future fetch time: the
    // window ends at t0 + 71 h.
    w.at(3 * DAY - HOUR - S);
    assert_eq!(rev.check(&w.path(&leaf)).await, Outcome::Good);
    w.at(3 * DAY - HOUR + S);
    assert_eq!(
        distrusted(&rev.check(&w.path(&leaf)).await),
        Some(DistrustReason::NotObtainable)
    );
}

#[tokio::test]
async fn two_clients_sharing_a_cache_share_the_crl_and_its_fetch_time() {
    let w = World::new();
    let leaf = w.root.issue("leaf", KeyAlg::EcP256);
    w.http.serve(w.root.crl_url(), w.crl(&w.root, &[], 7 * DAY));
    let shared: Arc<dyn RevocationCache> = Arc::new(MemoryRevocationCache::new(w.manual.clone()));
    let a = w.revocation_with(RevocationRule::bdew(), Vec::new(), Some(shared.clone()));
    let b = w.revocation_with(RevocationRule::bdew(), Vec::new(), Some(shared));
    assert_eq!(a.check(&w.path(&leaf)).await, Outcome::Good);
    w.http.fail(w.root.crl_url());
    w.at(2 * DAY);
    assert_eq!(
        b.check(&w.path(&leaf)).await,
        Outcome::Good,
        "B uses A's CRL"
    );
    b.settle().await;
    w.at(3 * DAY + S);
    assert_eq!(
        distrusted(&b.check(&w.path(&leaf)).await),
        Some(DistrustReason::NotObtainable),
        "and A's fetch time"
    );
}

#[tokio::test]
async fn a_due_refresh_runs_in_the_background_while_the_cached_crl_is_used() {
    let w = World::new();
    let leaf = w.root.issue("leaf", KeyAlg::EcP256);
    w.http.serve(w.root.crl_url(), w.crl(&w.root, &[], 7 * DAY));
    let rev = w.revocation(RevocationRule::bdew());
    assert_eq!(rev.check(&w.path(&leaf)).await, Outcome::Good);
    w.at(DAY - S);
    assert_eq!(rev.check(&w.path(&leaf)).await, Outcome::Good);
    rev.settle().await;
    assert_eq!(w.http.count(w.root.crl_url()), 1, "not due before 24 h");
    w.at(DAY);
    // The refreshed CRL lists the leaf; the current check still answers
    // from the cached one.
    w.http.serve(
        w.root.crl_url(),
        w.root
            .crl_builder()
            .this_update(w.t0 + DAY - HOUR)
            .next_update(Some(w.t0 + 8 * DAY))
            .revoke(&leaf)
            .build(),
    );
    assert_eq!(rev.check(&w.path(&leaf)).await, Outcome::Good);
    rev.settle().await;
    assert_eq!(w.http.count(w.root.crl_url()), 2);
    assert!(rev.check(&w.path(&leaf)).await.is_revoked());
}

#[tokio::test]
async fn concurrent_checks_of_one_ca_make_one_fetch() {
    let mut w = World::new();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let scripted = Scripted {
        gate: Some(gate.clone()),
        ..Scripted::default()
    };
    w.http = Arc::new(scripted);
    let leaf = w.root.issue("leaf", KeyAlg::EcP256);
    w.http.serve(w.root.crl_url(), w.crl(&w.root, &[], 7 * DAY));
    let rev = w.revocation(RevocationRule::bdew());
    let path = w.path(&leaf);
    let done = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let (rev, path, done) = (rev.clone(), path.clone(), done.clone());
        tasks.push(tokio::spawn(async move {
            let outcome = rev.check(&path).await;
            done.fetch_add(1, Ordering::SeqCst);
            outcome
        }));
    }
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    assert_eq!(done.load(Ordering::SeqCst), 0);
    gate.add_permits(100);
    for task in tasks {
        assert_eq!(task.await.unwrap(), Outcome::Good);
    }
    assert_eq!(w.http.count(w.root.crl_url()), 1);
}

#[tokio::test]
async fn a_failed_fetch_is_shared_by_concurrent_waiters_too() {
    let mut w = World::new();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    w.http = Arc::new(Scripted {
        gate: Some(gate.clone()),
        ..Scripted::default()
    });
    let leaf = w.root.issue("leaf", KeyAlg::EcP256);
    w.http.fail(w.root.crl_url());
    let rev = w.revocation(RevocationRule::bdew());
    let path = w.path(&leaf);
    let tasks: Vec<_> = (0..5)
        .map(|_| {
            let (rev, path) = (rev.clone(), path.clone());
            tokio::spawn(async move { rev.check(&path).await })
        })
        .collect();
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    gate.add_permits(100);
    for task in tasks {
        assert!(matches!(task.await.unwrap(), Outcome::NotObtainable { .. }));
    }
    assert_eq!(w.http.count(w.root.crl_url()), 1);
}

// ── CRL-DP, then OCSP ───────────────────────────────────────────────────────

fn ocsp_leaf(w: &World, cdp: Cdp) -> KeyPair {
    w.root.issue_with_options(
        "ocsp leaf",
        KeyAlg::EcP256,
        IssueOptions {
            cdp,
            ocsp: vec!["http://ocsp.example/".into()],
            ..IssueOptions::default()
        },
    )
}

#[tokio::test]
async fn crl_then_ocsp_falls_back_to_ocsp_only_when_the_crl_is_not_obtainable() {
    let w = World::new();
    let rule = RevocationRule::crl_then_ocsp(MissingSource::Refuse);
    let leaf = ocsp_leaf(&w, Cdp::Issuer);
    let now = w.t0;
    w.http.fail(w.root.crl_url());

    w.http.serve(
        "http://ocsp.example/",
        w.root.ocsp(&leaf, false, now - HOUR, now + HOUR),
    );
    assert_eq!(
        w.revocation(rule).check(&w.path(&leaf)).await,
        Outcome::Good
    );

    w.http.serve(
        "http://ocsp.example/",
        w.root.ocsp(&leaf, true, now - HOUR, now + HOUR),
    );
    let outcome = w.revocation(rule).check(&w.path(&leaf)).await;
    assert!(
        matches!(
            outcome,
            Outcome::Revoked {
                method: Method::Ocsp,
                ..
            }
        ),
        "{outcome:?}"
    );

    w.http.fail("http://ocsp.example/");
    assert!(matches!(
        w.revocation(rule).check(&w.path(&leaf)).await,
        Outcome::NotObtainable {
            accepted: false,
            ..
        }
    ));
}

#[tokio::test]
async fn a_revoked_crl_is_final_and_a_good_crl_asks_no_responder() {
    let w = World::new();
    let rule = RevocationRule::crl_then_ocsp(MissingSource::Refuse);
    let leaf = ocsp_leaf(&w, Cdp::Issuer);
    let now = w.t0;
    w.http.serve(
        "http://ocsp.example/",
        w.root.ocsp(&leaf, false, now - HOUR, now + HOUR),
    );
    w.http
        .serve(w.root.crl_url(), w.crl(&w.root, &[&leaf], 7 * DAY));
    let outcome = w.revocation(rule).check(&w.path(&leaf)).await;
    assert!(
        matches!(
            outcome,
            Outcome::Revoked {
                method: Method::Crl,
                ..
            }
        ),
        "{outcome:?}"
    );
    w.http.serve(w.root.crl_url(), w.crl(&w.root, &[], 7 * DAY));
    assert_eq!(
        w.revocation(rule).check(&w.path(&leaf)).await,
        Outcome::Good
    );
    assert_eq!(w.http.count("http://ocsp.example/"), 0, "no OCSP request");
}

#[tokio::test]
async fn a_certificate_without_any_source_follows_the_profile() {
    let w = World::new();
    let leaf = w.root.issue_with_options(
        "bare",
        KeyAlg::EcP256,
        IssueOptions {
            cdp: Cdp::None,
            ..IssueOptions::default()
        },
    );
    let accept = w
        .revocation(RevocationRule::crl_then_ocsp(MissingSource::AcceptRecorded))
        .check(&w.path(&leaf))
        .await;
    assert!(matches!(accept, Outcome::NoSource { accepted: true, .. }) && !accept.refused());
    let refuse = w
        .revocation(RevocationRule::crl_then_ocsp(MissingSource::Refuse))
        .check(&w.path(&leaf))
        .await;
    assert!(refuse.refused());
    assert!(
        refuse
            .describe()
            .contains("neither a CRL distribution point nor an OCSP")
    );
}

#[tokio::test]
async fn a_cached_ocsp_response_answers_without_a_request() {
    let w = World::new();
    let rule = RevocationRule::crl_then_ocsp(MissingSource::Refuse);
    let leaf = ocsp_leaf(&w, Cdp::None);
    let now = w.t0;
    w.http.serve(
        "http://ocsp.example/",
        w.root.ocsp(&leaf, false, now - HOUR, now + 2 * HOUR),
    );
    let rev = w.revocation(rule);
    assert_eq!(rev.check(&w.path(&leaf)).await, Outcome::Good);
    assert_eq!(rev.check(&w.path(&leaf)).await, Outcome::Good);
    assert_eq!(w.http.count("http://ocsp.example/"), 1);
    // Re-verified on read: stale an hour after nextUpdate.
    w.at(4 * HOUR);
    w.http.fail("http://ocsp.example/");
    assert!(rev.check(&w.path(&leaf)).await.refused());
}

// ── the cache cannot lie ────────────────────────────────────────────────────

#[derive(Debug)]
struct Lying {
    entry: Mutex<Option<(String, Bytes)>>,
    error: bool,
}

impl RevocationCache for Lying {
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Bytes>, BoxError>> {
        let entry = self.entry.lock().unwrap().clone();
        Box::pin(async move {
            if self.error {
                return Err("backend down".into());
            }
            // Answers every key with its one entry.
            Ok(entry.map(|(_, e)| e).filter(|_| !key.is_empty()))
        })
    }
    fn put<'a>(
        &'a self,
        _key: &'a str,
        _entry: Bytes,
        _expires_at: SystemTime,
    ) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move {
            if self.error {
                Err("backend down".into())
            } else {
                Ok(())
            }
        })
    }
}

#[tokio::test]
async fn a_lying_cache_is_refused_or_falls_back_to_a_fetch() {
    let w = World::new();
    let leaf = w.root.issue("leaf", KeyAlg::EcP256);
    let other = TestCa::new("other issuer", KeyAlg::EcP256);
    // Another issuer's valid CRL, under every key.
    let lying = Arc::new(Lying {
        entry: Mutex::new(Some((
            String::new(),
            cache::seal(w.t0, &w.crl(&other, &[], 7 * DAY)),
        ))),
        error: false,
    });
    w.http
        .serve(w.root.crl_url(), w.crl(&w.root, &[&leaf], 7 * DAY));
    let rev = w.revocation_with(RevocationRule::bdew(), Vec::new(), Some(lying.clone()));
    assert!(
        rev.check(&w.path(&leaf)).await.is_revoked(),
        "refused on read, fetched"
    );
    assert_eq!(w.http.count(w.root.crl_url()), 1);

    // A tampered CRL of the right issuer.
    let mut tampered = w.crl(&w.root, &[], 7 * DAY);
    let at = tampered.len() - 10;
    tampered[at] ^= 0x01;
    *lying.entry.lock().unwrap() = Some((String::new(), cache::seal(w.t0, &tampered)));
    let rev = w.revocation_with(RevocationRule::bdew(), Vec::new(), Some(lying.clone()));
    assert!(rev.check(&w.path(&leaf)).await.is_revoked());
    assert_eq!(w.http.count(w.root.crl_url()), 2);

    // A genuine CRL stored with a fetch time in the future: clamped, refetched.
    *lying.entry.lock().unwrap() = Some((
        String::new(),
        cache::seal(w.t0 + 30 * DAY, &w.crl(&w.root, &[], 7 * DAY)),
    ));
    w.http.fail(w.root.crl_url());
    let rev = w.revocation_with(RevocationRule::bdew(), Vec::new(), Some(lying.clone()));
    assert_eq!(rev.check(&w.path(&leaf)).await, Outcome::Good);
    assert_eq!(w.http.count(w.root.crl_url()), 3, "refetch forced");
    w.at(3 * DAY);
    assert!(
        rev.check(&w.path(&leaf)).await.refused(),
        "trust ends 72 h after thisUpdate"
    );

    // An erroring cache: a miss; with the fetch failing too, not obtainable.
    w.at(Duration::ZERO);
    let erroring = Arc::new(Lying {
        entry: Mutex::new(None),
        error: true,
    });
    let rev = w.revocation_with(RevocationRule::bdew(), Vec::new(), Some(erroring.clone()));
    assert!(matches!(
        rev.check(&w.path(&leaf)).await,
        Outcome::NotObtainable { .. }
    ));
    w.http.serve(w.root.crl_url(), w.crl(&w.root, &[], 7 * DAY));
    let rev = w.revocation_with(RevocationRule::bdew(), Vec::new(), Some(erroring));
    assert_eq!(rev.check(&w.path(&leaf)).await, Outcome::Good);
}

// ── the fetch ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_oversized_body_from_any_client_is_refused_before_parsing() {
    let w = World::new();
    let leaf = w.root.issue("leaf", KeyAlg::EcP256);
    w.http
        .serve(w.root.crl_url(), vec![0x30; MAX_CRL_BYTES + 1]);
    let outcome = w
        .revocation(RevocationRule::bdew())
        .check(&w.path(&leaf))
        .await;
    assert!(matches!(outcome, Outcome::NotObtainable { .. }));
}

#[tokio::test]
async fn a_pem_crl_is_accepted() {
    let w = World::new();
    let leaf = w.root.issue("leaf", KeyAlg::EcP256);
    let der = w.crl(&w.root, &[&leaf], 7 * DAY);
    let pem = {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        format!("-----BEGIN X509 CRL-----\n{b64}\n-----END X509 CRL-----\n").into_bytes()
    };
    w.http.serve(w.root.crl_url(), pem);
    assert!(
        w.revocation(RevocationRule::bdew())
            .check(&w.path(&leaf))
            .await
            .is_revoked()
    );
}

#[tokio::test]
async fn the_trust_anchor_is_never_checked() {
    let w = World::new();
    let outcome = w
        .revocation(RevocationRule::bdew())
        .check(&[x509(w.root.cert_pem())])
        .await;
    assert_eq!(outcome, Outcome::Good);
    assert_eq!(w.http.total(), 0);
}

// ── The CA WARN events ──────────────────────────────────────────────────────

/// Await `body` under a fresh capture (the current-thread test runtime keeps
/// background tasks on this thread); return the `asx` events with `message`.
async fn warn_events(
    message: &str,
    body: impl std::future::Future<Output = ()>,
) -> Vec<asx_testkit::trace::CapturedEvent> {
    let capture = asx_testkit::trace::TraceCapture::new();
    {
        let _guard = capture.set_default();
        // Callsites first hit by a parallel test may have cached "never".
        tracing::callsite::rebuild_interest_cache();
        body.await;
    }
    capture
        .events()
        .into_iter()
        .filter(|e| e.target == "asx" && e.message() == message)
        .collect()
}

fn fingerprint_of(ca: &TestCa) -> String {
    crate::telemetry::fingerprint(&x509(ca.cert_pem()).to_der().unwrap())
}

#[tokio::test]
async fn a_failing_refresh_warns_with_the_ca_fingerprint() {
    let w = World::new();
    let leaf = w.root.issue("leaf", KeyAlg::EcP256);
    let events = warn_events("CRL refresh failing", async {
        w.http.serve(w.root.crl_url(), w.crl(&w.root, &[], 7 * DAY));
        let rev = w.revocation(RevocationRule::bdew());
        assert_eq!(rev.check(&w.path(&leaf)).await, Outcome::Good);
        w.http.fail(w.root.crl_url());
        // The background refresh fails, then the next check warns inline.
        w.at(DAY + HOUR);
        assert_eq!(rev.check(&w.path(&leaf)).await, Outcome::Good);
        rev.settle().await;
        assert_eq!(rev.check(&w.path(&leaf)).await, Outcome::Good);
        rev.settle().await;
    })
    .await;
    assert!(events.len() >= 2, "background and inline: {events:?}");
    let ca = fingerprint_of(&w.root);
    for e in &events {
        assert_eq!(e.level, tracing::Level::WARN);
        assert_eq!(e.fields.get("ca.fingerprint"), Some(&ca), "{e:?}");
        assert_eq!(
            e.fields.get("reason").map(String::as_str),
            Some("refresh_failing")
        );
        assert!(
            e.fields.get("since").is_some_and(|s| !s.is_empty()),
            "{e:?}"
        );
        assert!(!e.fields.contains_key("url"), "only contract fields: {e:?}");
    }
}

#[tokio::test]
async fn a_distrusted_ca_warns_with_its_fingerprint() {
    let w = World::new();
    let leaf = w.root.issue("leaf", KeyAlg::EcP256);
    let events = warn_events("issuing CA distrusted", async {
        w.http
            .serve(w.root.crl_url(), w.crl(&w.root, &[], 10 * HOUR));
        let rev = w.revocation(RevocationRule::bdew());
        assert_eq!(rev.check(&w.path(&leaf)).await, Outcome::Good);
        w.at(10 * HOUR + S);
        assert!(distrusted(&rev.check(&w.path(&leaf)).await).is_some());
    })
    .await;
    // The inline check always warns; a background refresh may warn as well,
    // depending on scheduling. Every warning must carry the contract fields.
    // The inline check always warns, inside the request's span; a background
    // refresh may warn as well, outside any request.
    assert!(
        events.iter().any(|e| e.span == Some("asx.revocation")),
        "inline check must warn inside asx.revocation: {events:?}"
    );
    let ca = fingerprint_of(&w.root);
    for e in &events {
        assert_eq!(e.fields.get("ca.fingerprint"), Some(&ca), "{e:?}");
        assert_eq!(
            e.fields.get("reason").map(String::as_str),
            Some("ca_distrusted"),
            "{e:?}"
        );
        assert!(e.fields.contains_key("since"), "{e:?}");
    }
}
