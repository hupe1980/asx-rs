//! The one revocation validator: every non-anchor certificate of
//! a validated path is checked against the CRL its distribution point names
//! and, outside BDEW, against OCSP from its AIA — by the profile's
//! [`RevocationRule`], fetched through the client's [`HttpClient`], cached
//! through one [`RevocationCache`] whose entries are verified again on every
//! read, and judged at the client clock's `now`.
//!
//! Nothing here blocks: the check is async and runs *after* the signature
//! and the signer's authorization, outside the crypto pool, so
//! only an authenticated, authorized sender can make the client fetch.
//!
//! BDEW (RzÜ AS4 2.6 §5.4): "Wenn die CRL einer CA über die im Zertifikat
//! eingetragene Certificate Revocation List Distribution Point (CRL-DP) von
//! einer CA über 3 Tage nicht abrufbar ist oder im Gültigkeitszeitraum nicht
//! verlängert wurde, dann ist der ausstellenden CA und aller darunter
//! gelisteten Zertifikate bis zur Veröffentlichung einer aktuellen CRL nach
//! den Regelungen der CP zu misstrauen." Read here as: distrusted when the
//! newest valid CRL's `nextUpdate` has passed, or when a fetch fails and the
//! last successful fetch is more than 72 h ago. Distrust is
//! derived per check and never stored.

mod cache;
mod crl;
mod ocsp;
#[cfg(test)]
mod tests;

pub(crate) use cache::{MemoryRevocationCache, RevocationCache};

use crate::clock::SharedClock;
use crate::http_client::HttpClient;
use bytes::Bytes;
use crl::{DistributionPoint, ParsedCrl, Subject};
use openssl::x509::{X509, X509NameRef, X509Ref};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// The largest CRL read.
pub(crate) const MAX_CRL_BYTES: usize = 10 * 1024 * 1024;
/// The largest OCSP response read.
pub(crate) const MAX_OCSP_BYTES: usize = 64 * 1024;

/// Marks a request as a revocation fetch: the built-in client then allows
/// plain `http` (signed objects, RFC 5280 §4.2.1.13), presents no client
/// identity (CP SM-PKI §2.4), times out at 3 s / 10 s and reads at most
/// `max_bytes`. Crate-private, so an embedder cannot build a message
/// request that passes as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RevocationFetch {
    pub(crate) max_bytes: usize,
}

/// Which sources a profile consults, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sources {
    /// CRL-DP only (BDEW; the SM-PKI has no OCSP, CP §4.9).
    CrlOnly,
    /// CRL-DP, then OCSP from the AIA (the other profiles).
    CrlThenOcsp,
}

/// What a certificate that publishes no revocation source gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MissingSource {
    Refuse,
    /// Accepted and recorded as `outcome=unknown, reason=no_source`
    /// (pin-based profiles only).
    AcceptRecorded,
}

/// A profile's revocation rule. No public item reads or writes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RevocationRule {
    pub(crate) sources: Sources,
    /// A CRL without `nextUpdate` is invalid (TR-03109-4 Anhang B).
    pub(crate) next_update_required: bool,
    /// Refetch a CRL this long after the last successful fetch (CP Tab. 10).
    pub(crate) refresh_after: Duration,
    /// Distrust a CA whose CRL could not be fetched for longer (RzÜ §5.4).
    pub(crate) distrust_after: Option<Duration>,
    pub(crate) missing_source: MissingSource,
    /// A status that cannot be obtained is accepted (and recorded). Only the
    /// SMP signer rule sets it; no profile does.
    pub(crate) unobtainable_accepted: bool,
}

const DAY: Duration = Duration::from_secs(86_400);

impl RevocationRule {
    /// BDEW: CRL-DP only, `nextUpdate` required, refresh after 24 h,
    /// distrust after 72 h, a certificate without CDP refused.
    pub(crate) const fn bdew() -> Self {
        Self {
            sources: Sources::CrlOnly,
            next_update_required: true,
            refresh_after: DAY,
            distrust_after: Some(Duration::from_secs(3 * 86_400)),
            missing_source: MissingSource::Refuse,
            unobtainable_accepted: false,
        }
    }

    /// CRL-DP, then OCSP; `missing` decides certificates without a source.
    pub(crate) const fn crl_then_ocsp(missing: MissingSource) -> Self {
        Self {
            sources: Sources::CrlThenOcsp,
            next_update_required: false,
            refresh_after: DAY,
            distrust_after: None,
            missing_source: missing,
            unobtainable_accepted: false,
        }
    }

    /// The Peppol SMP signer: CRL-DP then OCSP, and a status that cannot be
    /// obtained is accepted with a WARN. A revoked signer is refused.
    #[cfg(feature = "peppol")]
    pub(crate) const fn smp() -> Self {
        Self {
            unobtainable_accepted: true,
            ..Self::crl_then_ocsp(MissingSource::AcceptRecorded)
        }
    }
}

/// Which source decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    Crl,
    Ocsp,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Method::Crl => "crl",
            Method::Ocsp => "ocsp",
        }
    }
}

/// Where the deciding data came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    Cache,
    Network,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Source::Cache => "cache",
            Source::Network => "network",
        }
    }
}

/// Why a CA is distrusted (RzÜ §5.4's two branches).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DistrustReason {
    /// "über 3 Tage nicht abrufbar".
    NotObtainable,
    /// "im Gültigkeitszeitraum nicht verlängert".
    NotRenewed,
}

/// The outcome of a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    Good,
    Revoked {
        subject: String,
        method: Method,
    },
    NotObtainable {
        subject: String,
        accepted: bool,
    },
    Distrusted {
        ca: String,
        reason: DistrustReason,
        since: SystemTime,
    },
    NoSource {
        subject: String,
        accepted: bool,
        /// Whether the profile also consults OCSP.
        ocsp: bool,
    },
}

impl Outcome {
    /// Whether the certificate is refused.
    pub(crate) fn refused(&self) -> bool {
        match self {
            Outcome::Good => false,
            Outcome::Revoked { .. } | Outcome::Distrusted { .. } => true,
            Outcome::NotObtainable { accepted, .. } | Outcome::NoSource { accepted, .. } => {
                !accepted
            }
        }
    }

    /// Whether the refusal is a revocation (the certificate itself is
    /// listed) rather than a missing or untrusted status.
    pub(crate) fn is_revoked(&self) -> bool {
        matches!(self, Outcome::Revoked { .. })
    }

    /// The operator-facing reason (never on the wire).
    pub(crate) fn describe(&self) -> String {
        match self {
            Outcome::Good => "revocation status good".into(),
            Outcome::Revoked { subject, method } => format!(
                "certificate {subject} is revoked (from its {})",
                match method {
                    Method::Crl => "CRL",
                    Method::Ocsp => "OCSP responder",
                }
            ),
            Outcome::NotObtainable { subject, .. } => {
                format!("the revocation status of {subject} is not obtainable")
            }
            Outcome::Distrusted { ca, reason, since } => match reason {
                DistrustReason::NotObtainable => format!(
                    "issuing CA distrusted: CRL not obtainable for more than 3 days (CA {ca}, \
                     last obtained {})",
                    crate::time_utils::format_rfc3339_secs(*since)
                ),
                DistrustReason::NotRenewed => format!(
                    "issuing CA distrusted: CRL not renewed within its validity period (CA {ca}, \
                     nextUpdate {})",
                    crate::time_utils::format_rfc3339_secs(*since)
                ),
            },
            Outcome::NoSource { subject, ocsp, .. } => {
                if *ocsp {
                    format!(
                        "certificate {subject} publishes neither a CRL distribution point nor an \
                         OCSP responder"
                    )
                } else {
                    format!(
                        "certificate {subject} has no CRL distribution point (BSI TR-03109-4 \
                         Anhang A item 10)"
                    )
                }
            }
        }
    }
}

/// The status one source gives for one certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Status {
    Good(Source),
    Revoked(Source),
    Distrusted {
        reason: DistrustReason,
        since: SystemTime,
        source: Source,
    },
    /// The certificate names the source, but no valid answer was obtained.
    NotObtainable(Source),
    /// The certificate names no such source.
    Absent,
}

/// One single-flight slot per cache key (one fetch per key per client).
#[derive(Debug, Default)]
struct Flight {
    generation: AtomicU64,
    /// Whether the last attempt succeeded.
    last: tokio::sync::Mutex<Option<bool>>,
    /// When the refresh of this key started failing (cleared on success).
    failing_since: Mutex<Option<SystemTime>>,
}

/// A verified CRL as last seen under one key.
#[derive(Debug, Clone)]
struct Seen {
    der: Bytes,
    crl: Arc<ParsedCrl>,
    fetched_at: SystemTime,
}

/// The revocation validator of one client.
pub(crate) struct Revocation {
    rule: RevocationRule,
    cache: Arc<dyn RevocationCache>,
    http: Arc<dyn HttpClient>,
    clock: SharedClock,
    anchors: Vec<X509>,
    crl_signers: Vec<X509>,
    flights: Mutex<HashMap<String, Arc<Flight>>>,
    /// The last verified CRL per key: a cached entry with the same bytes is
    /// not parsed or verified again (the serial index is built once per
    /// fetch); different bytes are.
    seen: Mutex<lru::LruCache<String, Seen>>,
    #[cfg(test)]
    background: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for Revocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Revocation")
            .field("rule", &self.rule)
            .field("cache", &self.cache)
            .field("crl_signers", &self.crl_signers.len())
            .finish_non_exhaustive()
    }
}

impl Revocation {
    pub(crate) fn new(
        rule: RevocationRule,
        http: Arc<dyn HttpClient>,
        clock: SharedClock,
        anchors: Vec<X509>,
        crl_signers: Vec<X509>,
        cache: Option<Arc<dyn RevocationCache>>,
    ) -> Self {
        let cache = cache.unwrap_or_else(|| Arc::new(MemoryRevocationCache::new(clock.clone())));
        Self {
            rule,
            cache,
            http,
            clock,
            anchors,
            crl_signers,
            flights: Mutex::default(),
            seen: Mutex::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(256).expect("non-zero"),
            )),
            #[cfg(test)]
            background: Mutex::default(),
        }
    }

    /// Check every non-anchor certificate of `path` (leaf first, the trust
    /// anchor last), top-down: a distrusted or revoked CA refuses
    /// everything below it, so the walk stops at the first refusal.
    ///
    /// Boxed: its state stays off the caller's stack (the send and inbound
    /// futures embed it).
    pub(crate) fn check<'a>(
        self: &'a Arc<Self>,
        path: &'a [X509],
    ) -> crate::error::BoxFuture<'a, Outcome> {
        Box::pin(self.check_path(path))
    }

    async fn check_path(self: &Arc<Self>, path: &[X509]) -> Outcome {
        let mut outcome = Outcome::Good;
        if path.len() < 2 {
            return outcome;
        }
        for i in (0..path.len() - 1).rev() {
            let one = Box::pin(self.check_one(&path[i], &path[i + 1], &path[i + 1..])).await;
            if one.refused() {
                return one;
            }
            if one != Outcome::Good {
                outcome = one;
            }
        }
        outcome
    }

    async fn check_one(self: &Arc<Self>, cert: &X509, issuer: &X509, upper: &[X509]) -> Outcome {
        let der = cert.to_der().ok();
        let span = crate::telemetry::revocation_span(der.as_deref());
        let (outcome, method, source, warning) =
            tracing::Instrument::instrument(self.decide(cert, issuer, upper), span.clone()).await;
        let (value, reason) = match &outcome {
            Outcome::Good => ("good", warning.as_ref().map(|_| "refresh_failing")),
            Outcome::Revoked { .. } => ("revoked", None),
            Outcome::NotObtainable { .. } => ("error", Some("not_obtainable")),
            Outcome::Distrusted { .. } => ("error", Some("ca_distrusted")),
            Outcome::NoSource { .. } => ("unknown", Some("no_source")),
        };
        // The CA is named by its certificate fingerprint: no certificate
        // subject appears in telemetry; the subject is in
        // the refusal's message.
        let ca = issuer
            .to_der()
            .map(|der| crate::telemetry::fingerprint(&der))
            .unwrap_or_default();
        span.in_scope(|| {
            if let Some(since) = &warning {
                let since = crate::time_utils::format_rfc3339_secs(*since);
                tracing::warn!(
                    target: "asx",
                    { ca.fingerprint = ca.as_str(), since = since.as_str(), reason = "refresh_failing" },
                    "CRL refresh failing"
                );
            }
            if let Outcome::Distrusted { since, .. } = &outcome {
                let since = crate::time_utils::format_rfc3339_secs(*since);
                tracing::warn!(
                    target: "asx",
                    { ca.fingerprint = ca.as_str(), since = since.as_str(), reason = "ca_distrusted" },
                    "issuing CA distrusted"
                );
            }
        });
        crate::telemetry::finish_revocation(&span, method.as_str(), source.as_str(), value, reason);
        outcome
    }

    /// The outcome for `cert` (issued by `issuer`), the method and source
    /// that decided, and a failing refresh to warn about.
    async fn decide(
        self: &Arc<Self>,
        cert: &X509,
        issuer: &X509,
        upper: &[X509],
    ) -> (Outcome, Method, Source, Option<SystemTime>) {
        let name = display_name(cert.subject_name());
        let not_obtainable = |source| {
            (
                Outcome::NotObtainable {
                    subject: name.clone(),
                    accepted: self.rule.unobtainable_accepted,
                },
                Method::Crl,
                source,
                None,
            )
        };
        let Ok(subject) = Subject::of(cert) else {
            return not_obtainable(Source::Network);
        };
        let (crl, warning) = self.crl_status(cert, issuer, &subject).await;
        let decided = |status: &Status, method| match status {
            Status::Good(source) => Some((Outcome::Good, method, *source)),
            Status::Revoked(source) => Some((
                Outcome::Revoked {
                    subject: name.clone(),
                    method,
                },
                method,
                *source,
            )),
            Status::Distrusted {
                reason,
                since,
                source,
            } => Some((
                Outcome::Distrusted {
                    ca: display_name(issuer.subject_name()),
                    reason: *reason,
                    since: *since,
                },
                method,
                *source,
            )),
            _ => None,
        };
        if let Some((outcome, method, source)) = decided(&crl, Method::Crl) {
            return (outcome, method, source, warning);
        }
        let ocsp = match self.rule.sources {
            Sources::CrlOnly => Status::Absent,
            Sources::CrlThenOcsp => self.ocsp_status(cert, issuer, upper).await,
        };
        if let Some((outcome, method, source)) = decided(&ocsp, Method::Ocsp) {
            return (outcome, method, source, None);
        }
        match (&crl, &ocsp) {
            (Status::Absent, Status::Absent) => (
                Outcome::NoSource {
                    subject: name.clone(),
                    accepted: self.rule.missing_source == MissingSource::AcceptRecorded,
                    ocsp: self.rule.sources == Sources::CrlThenOcsp,
                },
                Method::Crl,
                Source::Network,
                None,
            ),
            (_, Status::NotObtainable(source)) => {
                let (outcome, _, _, _) = not_obtainable(*source);
                (outcome, Method::Ocsp, *source, None)
            }
            (Status::NotObtainable(source), _) => not_obtainable(*source),
            _ => not_obtainable(Source::Network),
        }
    }

    // ── CRL ─────────────────────────────────────────────────────────────────

    /// The CRL status of `cert` over every distribution point and URI, in
    /// order: the first good or revoked answer decides; a distrust is kept
    /// unless another point yields a current CRL.
    async fn crl_status(
        self: &Arc<Self>,
        cert: &X509,
        issuer: &X509,
        subject: &Subject,
    ) -> (Status, Option<SystemTime>) {
        let points = match crl::distribution_points(cert) {
            Ok(Some(points)) if !points.is_empty() => points,
            Ok(_) => return (Status::Absent, None),
            Err(_) => return (Status::NotObtainable(Source::Network), None),
        };
        let mut fallback = Status::NotObtainable(Source::Network);
        let mut warning = None;
        for point in &points {
            let signer = match &point.crl_issuer {
                None => Some(issuer.clone()),
                Some(name) => self.crl_signer(name),
            };
            let Some(signer) = signer else {
                tracing::debug!(
                    target: "asx",
                    "the CRL issuer of an indirect distribution point is not a configured CRL signer"
                );
                continue;
            };
            for url in &point.uris {
                let (status, warn) = self.crl_scope(issuer, subject, point, &signer, url).await;
                if warn.is_some() {
                    warning = warn;
                }
                match status {
                    Status::Good(_) | Status::Revoked(_) => return (status, warning),
                    Status::Distrusted { .. } => fallback = status,
                    _ => {}
                }
            }
        }
        (fallback, warning)
    }

    /// A configured CRL signer named `name` (DER), valid now.
    fn crl_signer(&self, name: &[u8]) -> Option<X509> {
        let now =
            openssl::asn1::Asn1Time::from_unix(crate::time_utils::unix_secs(self.clock.now()))
                .ok()?;
        self.crl_signers
            .iter()
            .find(|s| {
                s.subject_name().to_der().ok().as_deref() == Some(name)
                    && s.not_before() <= now
                    && s.not_after() >= now
            })
            .cloned()
    }

    /// One CRL scope (issuing key, or indirect CRL issuer, + URI).
    async fn crl_scope(
        self: &Arc<Self>,
        issuer: &X509,
        subject: &Subject,
        point: &DistributionPoint,
        signer: &X509,
        url: &str,
    ) -> (Status, Option<SystemTime>) {
        let scope = match &point.crl_issuer {
            None => spki_hash(issuer),
            Some(name) => {
                let mut id = b"indirect".to_vec();
                id.extend_from_slice(name);
                id
            }
        };
        let key = cache::key("crl:", &[&scope, url.as_bytes()]);
        let now = self.clock.now();
        let rule = self.rule;
        let applies =
            |crl: &ParsedCrl| crl.covers(subject, point).is_ok() && crl.check_time(now).is_ok();
        let effective_next = |crl: &ParsedCrl, fetched_at| {
            crl.next_update.unwrap_or(fetched_at + rule.refresh_after)
        };
        let age = |fetched_at: SystemTime| now.duration_since(fetched_at).unwrap_or(Duration::ZERO);
        let in_window = |fetched_at| rule.distrust_after.is_none_or(|w| age(fetched_at) <= w);

        let mut current = None;
        let mut forced = false;
        if let Some((seen, stored_at)) = self.cached_crl(&key, signer).await {
            // A fetch time is unsigned: clamp it into [thisUpdate, now]. One
            // in the future (the clock went back, or a lying cache) is
            // unknown: refetch, and judge by thisUpdate.
            let fetched_at = if stored_at > now {
                forced = true;
                seen.crl.this_update
            } else {
                stored_at.max(seen.crl.this_update)
            };
            if applies(&seen.crl) {
                current = Some((seen.crl, fetched_at));
            }
        }
        let mut source = Source::Cache;
        let mut fetch_failed = false;
        let fresh = current.as_ref().is_some_and(|(crl, fetched_at)| {
            !forced && now < effective_next(crl, *fetched_at) && in_window(*fetched_at)
        });
        if fresh {
            let (_, fetched_at) = current.as_ref().expect("fresh");
            if age(*fetched_at) >= rule.refresh_after {
                self.refresh_in_background(key.clone(), url.to_string(), signer.clone(), issuer);
            }
        } else {
            match self.fetch_crl(&key, url, signer).await {
                Some(seen) if applies(&seen.crl) => {
                    current = Some((seen.crl, seen.fetched_at));
                    source = Source::Network;
                }
                Some(_) => fetch_failed = true,
                None => fetch_failed = true,
            }
        }
        let warning = self.failing_since(&key);
        let Some((crl, fetched_at)) = current else {
            return (Status::NotObtainable(source), warning);
        };
        let next = effective_next(&crl, fetched_at);
        if now > next {
            return match rule.distrust_after {
                Some(_) => (
                    Status::Distrusted {
                        reason: DistrustReason::NotRenewed,
                        since: next,
                        source,
                    },
                    None,
                ),
                None => (Status::NotObtainable(source), warning),
            };
        }
        if fetch_failed && !in_window(fetched_at) {
            return (
                Status::Distrusted {
                    reason: DistrustReason::NotObtainable,
                    since: fetched_at,
                    source,
                },
                None,
            );
        }
        if crl.lists(subject) {
            (Status::Revoked(source), None)
        } else {
            (Status::Good(source), warning)
        }
    }

    /// The cached CRL under `key`, verified as if just fetched, and
    /// its stored fetch time. A cache error, an unknown envelope or a CRL
    /// that does not verify is a miss.
    async fn cached_crl(&self, key: &str, signer: &X509) -> Option<(Seen, SystemTime)> {
        let entry = match self.cache.get(key).await {
            Ok(Some(entry)) => entry,
            Ok(None) => return None,
            Err(err) => {
                tracing::debug!(target: "asx", error = %err, "revocation cache read failed; treated as a miss");
                return None;
            }
        };
        let (stored_at, der) = cache::open(&entry)?;
        let known = self
            .seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .filter(|seen| seen.der == der)
            .cloned();
        let crl = match known {
            Some(seen) => seen.crl,
            None => match crl::parse_and_verify(&der, signer, self.rule.next_update_required) {
                Ok(crl) => {
                    let crl = Arc::new(crl);
                    self.remember(key, &der, &crl, stored_at);
                    crl
                }
                Err(err) => {
                    tracing::debug!(target: "asx", error = %err, "a cached CRL does not verify; treated as a miss");
                    return None;
                }
            },
        };
        Some((
            Seen {
                der,
                crl,
                fetched_at: stored_at,
            },
            stored_at,
        ))
    }

    fn remember(&self, key: &str, der: &Bytes, crl: &Arc<ParsedCrl>, fetched_at: SystemTime) {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).put(
            key.to_string(),
            Seen {
                der: der.clone(),
                crl: crl.clone(),
                fetched_at,
            },
        );
    }

    fn flight(&self, key: &str) -> Arc<Flight> {
        self.flights
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.to_string())
            .or_default()
            .clone()
    }

    fn failing_since(&self, key: &str) -> Option<SystemTime> {
        let flight = self
            .flights
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned()?;
        *flight
            .failing_since
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Fetch the CRL under `key` once, however many checks wait for it: a
    /// waiter whose fetch another task performed takes that result.
    async fn fetch_crl(self: &Arc<Self>, key: &str, url: &str, signer: &X509) -> Option<Seen> {
        let flight = self.flight(key);
        let started = flight.generation.load(Ordering::Acquire);
        let mut last = flight.last.lock().await;
        if flight.generation.load(Ordering::Acquire) != started {
            return match *last {
                Some(true) => self
                    .seen
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(key)
                    .cloned(),
                _ => None,
            };
        }
        let result = self.fetch_and_store(key, url, signer).await;
        let now = self.clock.now();
        {
            let mut failing = flight
                .failing_since
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            match &result {
                Ok(_) => *failing = None,
                Err(err) => {
                    tracing::debug!(target: "asx", url, error = %err, "CRL fetch failed");
                    failing.get_or_insert(now);
                }
            }
        }
        *last = Some(result.is_ok());
        flight.generation.fetch_add(1, Ordering::AcqRel);
        result.ok()
    }

    /// GET `url`, verify the CRL against `signer`, keep the newest valid CRL
    /// and store it with the fetch time.
    async fn fetch_and_store(&self, key: &str, url: &str, signer: &X509) -> Result<Seen, String> {
        let request = http::Request::get(url)
            .header(http::header::ACCEPT, "application/pkix-crl")
            .body(Bytes::new())
            .map_err(|e| e.to_string())?;
        let body = self.fetch(request, MAX_CRL_BYTES).await?;
        let der = pem_or_der(body)?;
        let crl = crl::parse_and_verify(&der, signer, self.rule.next_update_required)?;
        let now = self.clock.now();
        crl.check_time(now)?;
        // The newest valid CRL wins: an older one fetched from a
        // lagging mirror does not replace it.
        let previous = self
            .seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned();
        let (der, crl) = match previous {
            Some(seen) if seen.crl.this_update > crl.this_update => (seen.der, seen.crl),
            _ => (der, Arc::new(crl)),
        };
        let expires_at = (crl.next_update.unwrap_or(now + self.rule.refresh_after)
            + self.rule.distrust_after.unwrap_or(Duration::ZERO))
        .min(now + 7 * DAY);
        if let Err(err) = self
            .cache
            .put(key, cache::seal(now, &der), expires_at)
            .await
        {
            tracing::debug!(target: "asx", error = %err, "revocation cache write failed");
        }
        self.remember(key, &der, &crl, now);
        Ok(Seen {
            der,
            crl,
            fetched_at: now,
        })
    }

    /// Stale-while-revalidate: refetch in the background; the current check
    /// uses the cached CRL. Without a Tokio runtime the next check past the
    /// window fetches inline.
    fn refresh_in_background(
        self: &Arc<Self>,
        key: String,
        url: String,
        signer: X509,
        issuer: &X509,
    ) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let ca = issuer
            .to_der()
            .map(|der| crate::telemetry::fingerprint(&der))
            .unwrap_or_default();
        let this = Arc::clone(self);
        let span = tracing::Span::current();
        let task = handle.spawn(tracing::Instrument::instrument(
            async move {
                let flight = this.flight(&key);
                // Another refresh of this key is running: let it finish.
                if flight.last.try_lock().is_err() {
                    return;
                }
                if this.fetch_crl(&key, &url, &signer).await.is_none() {
                    let since = this
                        .failing_since(&key)
                        .map(crate::time_utils::format_rfc3339_secs)
                        .unwrap_or_default();
                    tracing::warn!(
                        target: "asx",
                        { ca.fingerprint = ca.as_str(), since = since.as_str(), reason = "refresh_failing" },
                        "CRL refresh failing"
                    );
                }
            },
            span,
        ));
        #[cfg(test)]
        self.background
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(task);
        #[cfg(not(test))]
        drop(task);
    }

    /// Wait for every background refresh started so far (unit tests).
    #[cfg(test)]
    pub(crate) async fn settle(&self) {
        let tasks: Vec<_> = std::mem::take(&mut *self.background.lock().unwrap());
        for task in tasks {
            let _ = task.await;
        }
    }

    // ── OCSP ────────────────────────────────────────────────────────────────

    async fn ocsp_status(&self, cert: &X509, issuer: &X509, upper: &[X509]) -> Status {
        let (urls, named) = ocsp::responders(cert);
        if named == 0 {
            return Status::Absent;
        }
        let Ok(request) = ocsp::request(cert, issuer) else {
            return Status::NotObtainable(Source::Network);
        };
        let key = cache::key("ocsp:", &[&request.cert_id]);
        let verify =
            |der: &[u8]| ocsp::verify(der, cert, issuer, upper, &self.anchors, self.clock.now());
        if let Ok(Some(entry)) = self.cache.get(&key).await
            && let Some((_, der)) = cache::open(&entry)
            && let Ok(verified) = verify(&der)
        {
            match verified.status {
                ocsp::Status::Good => return Status::Good(Source::Cache),
                ocsp::Status::Revoked => return Status::Revoked(Source::Cache),
                ocsp::Status::Unknown => {}
            }
        }
        let flight = self.flight(&key);
        let _one = flight.last.lock().await;
        for url in urls {
            let Ok(http_request) = http::Request::post(url.as_str())
                .header(http::header::CONTENT_TYPE, "application/ocsp-request")
                .header(http::header::ACCEPT, "application/ocsp-response")
                .body(Bytes::from(request.der.clone()))
            else {
                continue;
            };
            let body = match self.fetch(http_request, MAX_OCSP_BYTES).await {
                Ok(body) => body,
                Err(err) => {
                    tracing::debug!(target: "asx", url = %url, error = %err, "OCSP fetch failed");
                    continue;
                }
            };
            let verified = match verify(&body) {
                Ok(verified) => verified,
                Err(err) => {
                    tracing::debug!(target: "asx", url = %url, error = %err, "OCSP response refused");
                    continue;
                }
            };
            let now = self.clock.now();
            let expires_at = verified
                .next_update
                .unwrap_or(verified.this_update + DAY)
                .min(verified.this_update + DAY);
            if let Err(err) = self
                .cache
                .put(&key, cache::seal(now, &body), expires_at)
                .await
            {
                tracing::debug!(target: "asx", error = %err, "revocation cache write failed");
            }
            match verified.status {
                ocsp::Status::Good => return Status::Good(Source::Network),
                ocsp::Status::Revoked => return Status::Revoked(Source::Network),
                ocsp::Status::Unknown => {}
            }
        }
        Status::NotObtainable(Source::Network)
    }

    // ── Fetching ────────────────────────────────────────────────────────────

    /// One revocation fetch through the client's `HttpClient`, marked
    /// [`RevocationFetch`]; a body over `max_bytes` from any client is
    /// refused before it is parsed.
    async fn fetch(
        &self,
        mut request: http::Request<Bytes>,
        max_bytes: usize,
    ) -> Result<Bytes, String> {
        request
            .extensions_mut()
            .insert(RevocationFetch { max_bytes });
        let response = self
            .http
            .send(request)
            .await
            .map_err(|e| format!("the fetch failed: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("HTTP {}", response.status().as_u16()));
        }
        let body = response.into_body();
        if body.len() > max_bytes {
            return Err(format!("the response exceeds {max_bytes} bytes"));
        }
        Ok(body)
    }
}

/// A CRL body as DER, or PEM (`X509 CRL`) converted to DER.
fn pem_or_der(body: Bytes) -> Result<Bytes, String> {
    if body.starts_with(b"-----BEGIN") {
        let crl = openssl::x509::X509Crl::from_pem(&body).map_err(|e| e.to_string())?;
        return crl.to_der().map(Bytes::from).map_err(|e| e.to_string());
    }
    Ok(body)
}

/// SHA-256 of the certificate's `SubjectPublicKeyInfo`: the issuing key a
/// CRL scope is bound to (TR-03109-4 §4.2.1.2 key changeover).
fn spki_hash(cert: &X509Ref) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let spki = cert
        .public_key()
        .and_then(|k| k.public_key_to_der())
        .unwrap_or_default();
    Sha256::digest(spki).to_vec()
}

/// `CN=…, OU=…, O=…` for messages and WARN events (a subject, never a body).
pub(crate) fn display_name(name: &X509NameRef) -> String {
    let parts: Vec<String> = name
        .entries()
        .map(|entry| {
            let key = entry.object().nid().short_name().unwrap_or("?");
            let value = String::from_utf8_lossy(entry.data().as_slice()).into_owned();
            format!("{key}={value}")
        })
        .collect();
    parts.join(", ")
}

/// Entry points of the vector and oracle suites (`tests/pkix_revocation_vectors.rs`,
/// `tests/revocation_openssl_oracle.rs`): the module's decision on static
/// material at a fixed instant. Re-exported as `asx::__fuzz::revocation`;
/// not part of the API.
pub mod vectors {
    use super::*;

    /// A fixed instant (vector suites only; the clients read the system
    /// clock).
    #[derive(Debug)]
    struct At(SystemTime);

    impl crate::clock::Clock for At {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    /// Serves `URL → body`; anything else is unreachable.
    #[derive(Debug)]
    struct Served(HashMap<String, Vec<u8>>);

    impl HttpClient for Served {
        fn send(
            &self,
            request: http::Request<Bytes>,
        ) -> crate::error::BoxFuture<
            '_,
            Result<http::Response<Bytes>, Box<dyn std::error::Error + Send + Sync>>,
        > {
            let body = self.0.get(&request.uri().to_string()).cloned();
            Box::pin(async move {
                match body {
                    Some(body) => Ok(http::Response::builder()
                        .status(200)
                        .body(Bytes::from(body))
                        .map_err(|e| e.to_string())?),
                    None => Err("unreachable".into()),
                }
            })
        }
    }

    fn certs(ders: &[Vec<u8>]) -> Result<Vec<X509>, String> {
        ders.iter()
            .map(|d| X509::from_der(d).map_err(|e| e.to_string()))
            .collect()
    }

    /// The decision of `profile`'s rule on `path` (DER, leaf first, trust
    /// anchor last) at `now`, with `served` as the only reachable URLs:
    /// `Ok(())` accepted, `Err(reason)` refused.
    pub async fn decide(
        profile: &crate::Profile,
        path: &[Vec<u8>],
        crl_signers: &[Vec<u8>],
        served: Vec<(String, Vec<u8>)>,
        now: SystemTime,
    ) -> Result<(), String> {
        let path = certs(path)?;
        let anchors = path.last().cloned().into_iter().collect();
        let revocation = Arc::new(Revocation::new(
            profile.revocation(),
            Arc::new(Served(served.into_iter().collect())),
            Arc::new(At(now)),
            anchors,
            certs(crl_signers)?,
            None,
        ));
        let outcome = revocation.check(&path).await;
        if outcome.refused() {
            Err(outcome.describe())
        } else {
            Ok(())
        }
    }

    /// The status (`good`, `revoked`, `unknown`) an OCSP response gives for
    /// `cert` (issued by `issuer`, which is the trust anchor) at `now`, or why
    /// it is refused.
    pub fn ocsp_status(
        response: &[u8],
        cert: &[u8],
        issuer: &[u8],
        now: SystemTime,
    ) -> Result<&'static str, String> {
        let (cert, issuer) = (
            X509::from_der(cert).map_err(|e| e.to_string())?,
            X509::from_der(issuer).map_err(|e| e.to_string())?,
        );
        let verified = ocsp::verify(
            response,
            &cert,
            &issuer,
            &[],
            std::slice::from_ref(&issuer),
            now,
        )?;
        Ok(match verified.status {
            ocsp::Status::Good => "good",
            ocsp::Status::Revoked => "revoked",
            ocsp::Status::Unknown => "unknown",
        })
    }
}
