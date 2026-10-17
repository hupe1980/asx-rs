//! The crate's receiver for phase4's pushes: `As4::inbound` mounted on a
//! local axum listener exactly as `examples/as4_receive_axum.rs` does, plus a
//! `/capture` route that stores a request (for the tampered replays).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use asx::as4::{As4, UserMessage};
use asx::{Inbound, MemoryDedup, Reject, Verified};
use bytes::Bytes;
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

use super::{HarnessError, sha256_hex};

/// One handler call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivered {
    pub message_id: String,
    pub from: String,
    pub service: String,
    pub action: String,
    /// SHA-256 of the signer certificate's DER (`Verified::signer`).
    pub signer_sha256: String,
    /// SHA-256 of each delivered (decrypted, decompressed) payload.
    pub payload_sha256: Vec<String>,
}

/// A request phase4 sent to `/capture`.
#[derive(Debug, Clone)]
pub struct Captured {
    pub headers: http::HeaderMap,
    pub body: Bytes,
}

/// The crate's answer to a fed request.
#[derive(Debug, Clone)]
pub struct RawResponse {
    pub status: http::StatusCode,
    pub content_type: Option<String>,
    pub body: Bytes,
}

impl RawResponse {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// An ebMS error signal (`eb:Error`) and no receipt.
    pub fn is_ebms_error(&self) -> bool {
        let t = self.text();
        t.contains(":Error ") || t.contains(":Error>") || t.contains("<Error ")
    }

    pub fn is_receipt(&self) -> bool {
        self.text().contains(":Receipt")
    }

    /// The first `errorCode="…"` value, if any.
    pub fn ebms_error_code(&self) -> Option<String> {
        let t = self.text();
        let i = t.find("errorCode=\"")? + "errorCode=\"".len();
        let j = t[i..].find('"')? + i;
        Some(t[i..j].to_string())
    }
}

#[derive(Debug)]
pub struct CrateInbound {
    inbound: Inbound,
    port: u16,
    delivered: Arc<Mutex<Vec<Delivered>>>,
    captured: Arc<Mutex<Vec<Captured>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for CrateInbound {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl CrateInbound {
    /// Serve `POST /as4` → `as4.inbound(MemoryDedup::default(), recording
    /// handler)` and `POST /capture` (stores the request, answers 500) on
    /// `0.0.0.0:<ephemeral>`.
    pub async fn start(as4: &As4) -> Result<CrateInbound, HarnessError> {
        let delivered: Arc<Mutex<Vec<Delivered>>> = Arc::default();
        let captured: Arc<Mutex<Vec<Captured>>> = Arc::default();
        let record = delivered.clone();
        let handler = move |msg: Verified<UserMessage>| {
            let record = record.clone();
            async move {
                let entry = Delivered {
                    message_id: msg.message_id().to_string(),
                    from: msg.from().to_string(),
                    service: msg.service().to_string(),
                    action: msg.action().to_string(),
                    signer_sha256: sha256_hex(msg.signer().der()),
                    payload_sha256: msg
                        .payloads()
                        .iter()
                        .map(|p| sha256_hex(p.bytes()))
                        .collect(),
                };
                record.lock().unwrap().push(entry);
                Ok::<(), Reject>(())
            }
        };
        let inbound = as4.inbound(MemoryDedup::default(), handler);
        let store = captured.clone();
        let app = axum::Router::new()
            .route_service("/as4", inbound.clone())
            .route(
                "/capture",
                axum::routing::post(move |headers: http::HeaderMap, body: Bytes| {
                    let store = store.clone();
                    async move {
                        store.lock().unwrap().push(Captured { headers, body });
                        (http::StatusCode::INTERNAL_SERVER_ERROR, "captured")
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0")
            .await
            .map_err(|e| HarnessError::infra(format!("bind crate inbound: {e}")))?;
        let port = listener
            .local_addr()
            .map_err(|e| HarnessError::infra(e.to_string()))?
            .port();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(CrateInbound {
            inbound,
            port,
            delivered,
            captured,
            task,
        })
    }

    /// The URL phase4 pushes to from inside the container.
    pub fn container_url(&self) -> String {
        format!("http://host.docker.internal:{}/as4", self.port)
    }

    pub fn capture_url(&self) -> String {
        format!("http://host.docker.internal:{}/capture", self.port)
    }

    pub fn handler_calls(&self) -> usize {
        self.delivered.lock().unwrap().len()
    }

    pub fn delivered(&self) -> Vec<Delivered> {
        self.delivered.lock().unwrap().clone()
    }

    /// The oldest captured request, waiting up to `timeout`.
    pub async fn take_capture(&self, timeout: Duration) -> Option<Captured> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            {
                let mut captured = self.captured.lock().unwrap();
                if !captured.is_empty() {
                    return Some(captured.remove(0));
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Feed bytes to the same `Inbound` (tower `oneshot`); status and body.
    pub async fn feed(&self, captured: &Captured) -> RawResponse {
        let mut request = http::Request::post("/as4")
            .body(http_body_util::Full::new(captured.body.clone()))
            .expect("request");
        for (name, value) in &captured.headers {
            if name != http::header::CONTENT_LENGTH && name != http::header::HOST {
                request.headers_mut().append(name, value.clone());
            }
        }
        let response = self
            .inbound
            .clone()
            .oneshot(request)
            .await
            .unwrap_or_else(|never| match never {});
        let status = response.status();
        let content_type = response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = response
            .into_body()
            .collect()
            .await
            .map(|c| c.to_bytes())
            .unwrap_or_default();
        RawResponse {
            status,
            content_type,
            body,
        }
    }
}
