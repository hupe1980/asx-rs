//! Building blocks for suites that need more control over an AS4 pair than
//! `peers::pair` gives: a client with a chosen audit sink (or none), an
//! inbound with a chosen dedup store, direct posts of captured requests, and
//! audit sinks that fail or log.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use asx::as4::{As4, UserMessage};
use asx::{AuditDurability, AuditRecord, AuditSink, BoxFuture, Builder, Reject, Verified};
use asx_testkit::loopback::Loopback;
use asx_testkit::pki::{TestCa, TestParty};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// An AS4 client for `local`, trusting `ca`, talking to `partner` through
/// `loopback`; `configure` adds the rest (an audit sink, for instance).
pub fn client(
    profile: asx::Profile,
    ca: &TestCa,
    local: &TestParty,
    partner: asx::Partner,
    loopback: &Loopback,
    configure: impl FnOnce(Builder<As4>) -> Builder<As4>,
) -> As4 {
    configure(
        As4::builder(profile)
            .local(local.local())
            .trust_anchor(ca.anchor())
            .partner(partner)
            .http_client(loopback.clone()),
    )
    .build()
    .expect("client builds")
}

/// An inbound of `receiver` over `dedup` whose handler accepts everything.
pub fn accepting_inbound(receiver: &As4, dedup: impl asx::DedupStore) -> asx::Inbound {
    receiver.inbound(dedup, |_m: Verified<UserMessage>| async {
        Ok::<(), Reject>(())
    })
}

/// A copy of a captured request (the loopback keeps the original).
pub fn clone_request(r: &http::Request<bytes::Bytes>) -> http::Request<bytes::Bytes> {
    let mut copy = http::Request::new(r.body().clone());
    *copy.uri_mut() = r.uri().clone();
    *copy.headers_mut() = r.headers().clone();
    *copy.method_mut() = http::Method::POST;
    copy
}

/// Hand `request` to `inbound` as an HTTP server would.
pub async fn post(
    inbound: &asx::Inbound,
    request: http::Request<bytes::Bytes>,
) -> (http::StatusCode, Vec<u8>) {
    use tower_service::Service;
    let mut inbound = inbound.clone();
    let response = inbound
        .call(request.map(http_body_util::Full::new))
        .await
        .unwrap_or_else(|never| match never {});
    let status = response.status();
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("body")
        .to_bytes();
    (status, body.to_vec())
}

/// A sink that fails every write, with the durability it is told to declare.
#[derive(Debug, Clone, Copy)]
pub struct FailingSink(pub AuditDurability);

impl AuditSink for FailingSink {
    fn durability(&self) -> AuditDurability {
        self.0
    }
    fn record<'a>(&'a self, _record: &'a AuditRecord) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(std::future::ready(Err("audit store unavailable".into())))
    }
}

/// One log shared by a dedup store and a sink, to see their relative order.
pub type Log = Arc<Mutex<Vec<&'static str>>>;

/// A `MemoryDedup` that logs every call.
#[derive(Debug, Clone)]
pub struct LoggingDedup(pub Arc<asx::MemoryDedup>, pub Log);

impl asx::DedupStore for LoggingDedup {
    fn claim<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<asx::Claim, BoxError>> {
        self.1.lock().unwrap().push("claim");
        self.0.claim(key)
    }
    fn accept<'a>(
        &'a self,
        key: &'a str,
        token: &'a asx::ClaimToken,
    ) -> BoxFuture<'a, Result<(), BoxError>> {
        self.1.lock().unwrap().push("accept");
        self.0.accept(key, token)
    }
    fn abandon<'a>(
        &'a self,
        key: &'a str,
        token: &'a asx::ClaimToken,
    ) -> BoxFuture<'a, Result<(), BoxError>> {
        self.1.lock().unwrap().push("abandon");
        self.0.abandon(key, token)
    }
}

/// A durable in-memory sink that logs every write.
#[derive(Debug, Clone)]
pub struct LoggingSink(pub asx_testkit::audit::MemoryAuditSink, pub Log);

impl AuditSink for LoggingSink {
    fn durability(&self) -> AuditDurability {
        AuditDurability::Durable
    }
    fn record<'a>(&'a self, record: &'a AuditRecord) -> BoxFuture<'a, Result<(), BoxError>> {
        self.1.lock().unwrap().push("record");
        self.0.record(record)
    }
}
