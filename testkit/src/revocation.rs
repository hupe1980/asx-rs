//! Revocation data for tests: an [`asx::HttpClient`] that serves
//! CRLs and OCSP responses by URL, counts what it was asked for, and fails on
//! request.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

type Response =
    std::result::Result<http::Response<bytes::Bytes>, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Default)]
struct State {
    served: HashMap<String, Vec<u8>>,
    failing: HashSet<String>,
    asked: Vec<String>,
}

/// An [`asx::HttpClient`] for revocation fetches.
///
/// A URL answers, in order: an error when [`fail`](Self::fail)ed; the bytes
/// given to [`serve`](Self::serve); the current CRL a
/// [`TestCa`](crate::pki::TestCa) publishes there
/// ([`published_crl`](crate::pki::published_crl)); the
/// [`with_fallback`](Self::with_fallback) client (e.g. a
/// [`Loopback`](crate::loopback::Loopback) carrying the messages); else HTTP
/// 404. Every request except those handed to the fallback is recorded.
/// Clones share their state.
#[derive(Clone, Default)]
pub struct RevocationHttp {
    state: Arc<Mutex<State>>,
    fallback: Option<Arc<dyn asx::HttpClient>>,
}

impl std::fmt::Debug for RevocationHttp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.lock().expect("state");
        f.debug_struct("RevocationHttp")
            .field("served", &state.served.len())
            .field("asked", &state.asked.len())
            .finish_non_exhaustive()
    }
}

impl RevocationHttp {
    /// A client serving only what the test CAs publish.
    pub fn new() -> RevocationHttp {
        RevocationHttp::default()
    }

    /// Hand every URL this client does not serve to `client`.
    pub fn with_fallback(mut self, client: impl asx::HttpClient) -> RevocationHttp {
        self.fallback = Some(Arc::new(client));
        self
    }

    /// Answer `url` with `body` (HTTP 200).
    pub fn serve(&self, url: &str, body: Vec<u8>) {
        self.state
            .lock()
            .expect("state")
            .served
            .insert(url.to_string(), body);
    }

    /// Fail every request to `url` (as an unreachable host).
    pub fn fail(&self, url: &str) {
        self.state
            .lock()
            .expect("state")
            .failing
            .insert(url.to_string());
    }

    /// Stop failing `url`.
    pub fn heal(&self, url: &str) {
        self.state.lock().expect("state").failing.remove(url);
    }

    /// How many requests were recorded.
    pub fn requests(&self) -> usize {
        self.state.lock().expect("state").asked.len()
    }

    /// How many recorded requests went to `url`.
    pub fn requests_to(&self, url: &str) -> usize {
        self.state
            .lock()
            .expect("state")
            .asked
            .iter()
            .filter(|u| *u == url)
            .count()
    }

    /// Every recorded request URL, in order.
    pub fn urls(&self) -> Vec<String> {
        self.state.lock().expect("state").asked.clone()
    }

    async fn answer(&self, request: http::Request<bytes::Bytes>) -> Response {
        let url = request.uri().to_string();
        let local = {
            let state = self.state.lock().expect("state");
            if state.failing.contains(&url) {
                Some(Err(()))
            } else {
                state.served.get(&url).cloned().map(Ok)
            }
        };
        let local = match local {
            Some(answer) => Some(answer),
            None => crate::pki::published_crl(&url).map(Ok),
        };
        match local {
            Some(answer) => {
                self.state.lock().expect("state").asked.push(url.clone());
                match answer {
                    Ok(body) => Ok(http::Response::builder()
                        .status(200)
                        .body(bytes::Bytes::from(body))
                        .expect("response")),
                    Err(()) => Err(Box::new(Unreachable(url))),
                }
            }
            None => match &self.fallback {
                Some(fallback) => fallback.send(request).await,
                None => {
                    self.state.lock().expect("state").asked.push(url);
                    Ok(http::Response::builder()
                        .status(404)
                        .body(bytes::Bytes::new())
                        .expect("response"))
                }
            },
        }
    }
}

/// The error of a failing URL.
#[derive(Debug)]
pub struct Unreachable(pub String);

impl std::fmt::Display for Unreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "revocation test client: {} is unreachable", self.0)
    }
}

impl std::error::Error for Unreachable {}

impl asx::HttpClient for RevocationHttp {
    fn send(&self, request: http::Request<bytes::Bytes>) -> asx::BoxFuture<'_, Response> {
        Box::pin(self.answer(request))
    }
}
