//! An in-process [`asx::HttpClient`] over a partner's [`asx::Inbound`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

type Hook = Arc<dyn Fn(&mut http::Response<bytes::Bytes>) + Send + Sync>;

/// An in-process [`asx::HttpClient`]: a request to a mounted URL is handed to
/// that URL's [`asx::Inbound`] — a real partner client's receive endpoint —
/// with no socket and no TLS. An unmounted URL where a
/// [`TestCa`](crate::pki::TestCa) publishes its CRL answers that CRL; other
/// unmounted URLs fail like an unreachable host.
///
/// Clones share their routes, so the sender's client and the test can hold
/// the same loopback.
#[derive(Clone, Default)]
pub struct Loopback {
    routes: Arc<Mutex<HashMap<String, asx::Inbound>>>,
    hook: Arc<Mutex<Option<Hook>>>,
    requests: Arc<AtomicUsize>,
    last_request: Arc<Mutex<Option<http::Request<bytes::Bytes>>>>,
}

impl std::fmt::Debug for Loopback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Loopback")
            .field("routes", &self.routes.lock().map(|r| r.len()).unwrap_or(0))
            .field("requests", &self.requests.load(Ordering::SeqCst))
            .finish()
    }
}

/// The error of an unmounted URL.
#[derive(Debug)]
pub struct Unreachable(pub String);

impl std::fmt::Display for Unreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "loopback: nothing is mounted at {}", self.0)
    }
}

impl std::error::Error for Unreachable {}

impl Loopback {
    /// An empty loopback.
    pub fn new() -> Loopback {
        Loopback::default()
    }

    /// Serve `url` with `inbound`.
    pub fn mount(&self, url: &str, inbound: asx::Inbound) {
        self.routes
            .lock()
            .expect("routes")
            .insert(url.to_string(), inbound);
    }

    /// Rewrite every response before the sender sees it (tampering tests).
    pub fn intercept(
        &self,
        hook: impl Fn(&mut http::Response<bytes::Bytes>) + Send + Sync + 'static,
    ) {
        *self.hook.lock().expect("hook") = Some(Arc::new(hook));
    }

    /// Stop rewriting responses.
    pub fn clear_intercept(&self) {
        *self.hook.lock().expect("hook") = None;
    }

    /// How many requests reached a mounted endpoint.
    pub fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    /// The last request that reached a mounted endpoint.
    pub fn last_request(&self) -> Option<http::Request<bytes::Bytes>> {
        let guard = self.last_request.lock().expect("last request");
        guard.as_ref().map(|r| {
            let mut copy = http::Request::new(r.body().clone());
            *copy.uri_mut() = r.uri().clone();
            *copy.method_mut() = r.method().clone();
            *copy.headers_mut() = r.headers().clone();
            copy
        })
    }

    /// Hand `request` to the endpoint mounted at its URL.
    pub async fn exchange(
        &self,
        request: http::Request<bytes::Bytes>,
    ) -> std::result::Result<http::Response<bytes::Bytes>, Box<dyn std::error::Error + Send + Sync>>
    {
        use http_body_util::BodyExt;
        use tower_service::Service;
        let url = request.uri().to_string();
        let inbound = self.routes.lock().expect("routes").get(&url).cloned();
        let Some(mut inbound) = inbound else {
            // The CRL a test CA publishes at its distribution point:
            // revocation checks find it without configuration.
            if let Some(crl) = crate::pki::published_crl(&url) {
                return Ok(http::Response::builder()
                    .status(200)
                    .body(bytes::Bytes::from(crl))
                    .expect("response"));
            }
            return Err(Box::new(Unreachable(url)));
        };
        self.requests.fetch_add(1, Ordering::SeqCst);
        {
            let mut copy = http::Request::new(request.body().clone());
            *copy.method_mut() = request.method().clone();
            *copy.uri_mut() = request.uri().clone();
            *copy.headers_mut() = request.headers().clone();
            *self.last_request.lock().expect("last request") = Some(copy);
        }
        let response = match inbound.call(request.map(http_body_util::Full::new)).await {
            Ok(response) => response,
            Err(never) => match never {},
        };
        let (parts, body) = response.into_parts();
        let body = body
            .collect()
            .await
            .map(|c| c.to_bytes())
            .unwrap_or_default();
        let mut response = http::Response::from_parts(parts, body);
        let hook = self.hook.lock().expect("hook").clone();
        if let Some(hook) = hook {
            hook(&mut response);
        }
        Ok(response)
    }
}

impl asx::HttpClient for Loopback {
    fn send(
        &self,
        request: http::Request<bytes::Bytes>,
    ) -> asx::BoxFuture<
        '_,
        std::result::Result<http::Response<bytes::Bytes>, Box<dyn std::error::Error + Send + Sync>>,
    > {
        Box::pin(self.exchange(request))
    }
}
