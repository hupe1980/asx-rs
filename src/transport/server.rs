//! Axum server integration for AS2 and AS4.
//!
//! Requires the `server` feature flag.
//!
//! This module provides ready-to-use axum [`Router`] builders for the AS2 and
//! AS4 receive paths.  HTTP-level validation (required headers, method, SOAP
//! `Content-Type`) is performed before your handler is invoked, so your handler
//! works with pre-validated [`As2HttpIngress`] / [`As4HttpIngress`] structs.
//!
//! # Architecture
//!
//! The routers are framework-composable: combine them with a larger axum
//! `Router` using [`Router::merge`].  Each router creates one `POST` endpoint
//! at the path you supply.
//!
//! ```ignore
//! use std::sync::Arc;
//! use axum::Router;
//! use asx::transport::server::{As2AxumHandler, as2_router, HandlerOutcome};
//! use asx::transport::As2HttpIngress;
//!
//! struct MyAs2Handler;
//!
//! impl As2AxumHandler for MyAs2Handler {
//!     async fn handle(&self, ingress: As2HttpIngress) -> HandlerOutcome {
//!         // Feed `ingress.body` into as2::receive_from_ingress(…) here.
//!         HandlerOutcome::ok()
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     let app: Router = as2_router(Arc::new(MyAs2Handler), "/as2/inbox");
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:4080").await.unwrap();
//!     axum::serve(listener, app).await.unwrap();
//! }
//! ```
//!
//! # AS4 synchronous receipt
//!
//! For AS4, return `HandlerOutcome::ok_with_body(receipt_xml, "application/soap+xml")`
//! to send a synchronous SOAP receipt/signal back to the MSH on the same HTTP
//! connection.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::post,
};

use crate::core::DEFAULT_MAX_BODY_BYTES;
use crate::http::{HttpHeaders, HttpRequest};
#[cfg(feature = "as2")]
use crate::transport::ingress::as2_ingress_from_http;
use crate::transport::ingress::as4_ingress_from_http;

/// Per-router configuration for the AS2/AS4 Axum server integration.
///
/// Passed to [`as2_router`] / [`as4_router`] at construction time.
/// Use [`RouterConfig::default()`] for typical enterprise LAN/VPN deployments
/// and override individual fields as needed.
///
/// # Example — large-payload WAN deployment
///
/// ```ignore
/// use std::time::Duration;
/// use asx::transport::server::RouterConfig;
///
/// let config = RouterConfig {
///     // 256 MiB EDIFACT Fahrplan payloads over a 100 Mbit/s uplink need ~20 s;
///     // add headroom for WAN jitter and TCP slow-start.
///     body_read_timeout: Duration::from_secs(300),
///     // Accept up to 256 MiB (the protocol default).
///     ..RouterConfig::default()
/// };
/// ```
#[derive(Debug, Clone)]
pub struct RouterConfig {
    /// Maximum time allowed to read the full inbound request body.
    ///
    /// Clients that stall mid-upload are disconnected with HTTP 408 after
    /// this interval, freeing the connection and preventing slow-loris
    /// attacks.
    ///
    /// **Default: 30 seconds.** Appropriate for payloads up to ~10–20 MiB on
    /// a 10 Mbit/s uplink.  Increase for large EDIFACT/X12 payloads over slow
    /// WAN links (e.g. `Duration::from_secs(300)` for 256 MiB files).
    pub body_read_timeout: Duration,

    /// Maximum accepted request body size in bytes.
    ///
    /// Requests that exceed this limit are rejected with HTTP 413
    /// Payload Too Large before the body is fully buffered.
    ///
    /// **Default: 256 MiB** (matches `wire::DEFAULT_MAX_BODY_BYTES`).
    pub max_body_bytes: usize,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            body_read_timeout: Duration::from_secs(30),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }
}

/// Internal per-router state: handler + config bundled for Axum's state system.
///
/// Stored in the Axum router as `State<RouterState<H>>`; cloned cheaply for
/// each request because both fields are behind `Arc`.
struct RouterState<H> {
    handler: Arc<H>,
    config: Arc<RouterConfig>,
}

/// Manual `Clone` impl so that we don't impose an unnecessary `H: Clone` bound
/// — `Arc<H>` is always `Clone` regardless.
impl<H> Clone for RouterState<H> {
    fn clone(&self) -> Self {
        Self {
            handler: Arc::clone(&self.handler),
            config: Arc::clone(&self.config),
        }
    }
}

pub use crate::transport::ingress::{As2HttpIngress, As4HttpIngress};

// ── Handler outcome ─────────────────────────────────────────────────────────

/// Outcome returned by an [`As2AxumHandler`] or [`As4AxumHandler`].
///
/// The HTTP response is derived from the variant:
/// - `Accepted` → 200 OK, optionally with a response body.
/// - `Rejected` → 4xx/5xx with a plain-text message.
#[derive(Debug)]
#[non_exhaustive]
pub enum HandlerOutcome {
    /// The message was accepted.  Optionally include a synchronous response
    /// body — for AS2 this is a synchronous MDN; for AS4 a SOAP receipt.
    Accepted {
        /// Optional synchronous response body.
        body: Option<Vec<u8>>,
        /// MIME `Content-Type` for the synchronous response body, if any.
        content_type: Option<String>,
    },
    /// The message was rejected.  The HTTP response carries the given status
    /// code and message text.
    Rejected {
        /// HTTP status code.  Must be 4xx or 5xx.
        status: u16,
        /// Human-readable rejection reason sent as response body.
        message: String,
    },
}

impl HandlerOutcome {
    /// 200 OK with no response body.
    #[inline]
    pub fn ok() -> Self {
        Self::Accepted {
            body: None,
            content_type: None,
        }
    }

    /// 200 OK with a synchronous response body.
    #[inline]
    pub fn ok_with_body(body: Vec<u8>, content_type: impl Into<String>) -> Self {
        Self::Accepted {
            body: Some(body),
            content_type: Some(content_type.into()),
        }
    }

    /// 400 Bad Request rejection.
    #[inline]
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::Rejected {
            status: 400,
            message: message.into(),
        }
    }

    /// 500 Internal Server Error rejection.
    #[inline]
    pub fn server_error(message: impl Into<String>) -> Self {
        Self::Rejected {
            status: 500,
            message: message.into(),
        }
    }
}

// ── Handler traits ──────────────────────────────────────────────────────────

/// Implement this trait to receive AS2 messages via the axum server integration.
///
/// The implementation is called once per validated HTTP POST.  Required AS2
/// headers (`AS2-From`, `AS2-To`, `Content-Type`) are pre-validated before
/// `handle` is invoked, so the ingress struct always contains non-empty values
/// for those fields.
///
/// The handler is shared across concurrent requests via [`Arc<H>`]; it must be
/// `Send + Sync + 'static`.
pub trait As2AxumHandler: Send + Sync + 'static {
    /// Process an incoming AS2 message and return the desired HTTP outcome.
    fn handle(
        &self,
        ingress: As2HttpIngress,
    ) -> impl std::future::Future<Output = HandlerOutcome> + Send;
}

/// Implement this trait to receive AS4 SOAP messages via the axum server integration.
///
/// The implementation is called once per validated HTTP POST.  The
/// `Content-Type` is pre-validated to be `application/soap+xml` before
/// `handle` is invoked.
///
/// The handler is shared across concurrent requests via [`Arc<H>`]; it must be
/// `Send + Sync + 'static`.
pub trait As4AxumHandler: Send + Sync + 'static {
    /// Process an incoming AS4 SOAP message and return the desired HTTP outcome.
    fn handle(
        &self,
        ingress: As4HttpIngress,
    ) -> impl std::future::Future<Output = HandlerOutcome> + Send;
}

// ── Router builders ─────────────────────────────────────────────────────────

/// Build an axum [`Router`] that mounts an AS2 ingress handler at `path`.
///
/// The returned router accepts `POST {path}` requests.  HTTP-level validation
/// is performed before your handler is called (method check, AS2-From, AS2-To,
/// Content-Type).
///
/// # Example
///
/// ```ignore
/// let app = axum::Router::new()
///     .merge(as2_router(Arc::new(MyAs2Handler), "/as2/inbox"));
/// axum::serve(listener, app).await?;
/// ```
#[cfg(feature = "as2")]
pub fn as2_router<H: As2AxumHandler>(handler: Arc<H>, path: &str, config: RouterConfig) -> Router {
    let state = RouterState {
        handler,
        config: Arc::new(config),
    };
    Router::new()
        .route(path, post(as2_axum_handler::<H>))
        .with_state(state)
}

/// Build an axum [`Router`] that mounts an AS4 ingress handler at `path`.
///
/// The returned router accepts `POST {path}` requests with SOAP content types
/// (`application/soap+xml`).
///
/// # Example
///
/// ```ignore
/// let app = axum::Router::new()
///     .merge(as4_router(Arc::new(MyAs4Handler), "/as4/inbox"));
/// axum::serve(listener, app).await?;
/// ```
#[cfg(feature = "as4")]
pub fn as4_router<H: As4AxumHandler>(handler: Arc<H>, path: &str, config: RouterConfig) -> Router {
    let state = RouterState {
        handler,
        config: Arc::new(config),
    };
    Router::new()
        .route(path, post(as4_axum_handler::<H>))
        .with_state(state)
}

// ── Internal: request conversion ────────────────────────────────────────────

/// Convert an axum [`Request`] into our framework-agnostic [`HttpRequest`].
///
/// Reads the full body, bounded by `config.max_body_bytes`, within
/// `config.body_read_timeout`.  Returns an appropriate 4xx/408 response on
/// failure.
async fn read_http_request(req: Request, config: &RouterConfig) -> Result<HttpRequest, Response> {
    let (parts, body) = req.into_parts();

    let headers: HttpHeaders = parts
        .headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let bytes = tokio::time::timeout(
        config.body_read_timeout,
        axum::body::to_bytes(body, config.max_body_bytes),
    )
    .await
    .map_err(|_| (StatusCode::REQUEST_TIMEOUT, "request body read timed out").into_response())?
    .map_err(|e| (StatusCode::PAYLOAD_TOO_LARGE, e.to_string()).into_response())?;

    Ok(HttpRequest {
        method: parts.method.as_str().to_string(),
        uri: parts.uri.to_string(),
        headers,
        body: bytes.to_vec().into(),
    })
}

// ── Internal: outcome → axum Response ───────────────────────────────────────

fn outcome_to_response(outcome: HandlerOutcome) -> Response {
    match outcome {
        HandlerOutcome::Accepted {
            body: None,
            content_type: _,
        } => StatusCode::OK.into_response(),

        HandlerOutcome::Accepted {
            body: Some(bytes),
            content_type,
        } => {
            let ct = content_type.unwrap_or_else(|| "application/octet-stream".to_string());
            axum::response::Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, ct)
                .body(Body::from(bytes))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }

        HandlerOutcome::Rejected { status, message } => {
            let code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, message).into_response()
        }
    }
}

// ── Internal: axum handler functions ────────────────────────────────────────

#[cfg(feature = "as2")]
async fn as2_axum_handler<H: As2AxumHandler>(
    State(state): State<RouterState<H>>,
    req: Request,
) -> Response {
    let http_req = match read_http_request(req, &state.config).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match as2_ingress_from_http(http_req) {
        Ok(ingress) => outcome_to_response(state.handler.handle(ingress).await),
        Err(e) => (StatusCode::BAD_REQUEST, e.message).into_response(),
    }
}

#[cfg(feature = "as4")]
async fn as4_axum_handler<H: As4AxumHandler>(
    State(state): State<RouterState<H>>,
    req: Request,
) -> Response {
    let http_req = match read_http_request(req, &state.config).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match as4_ingress_from_http(http_req) {
        Ok(ingress) => outcome_to_response(state.handler.handle(ingress).await),
        Err(e) => (StatusCode::BAD_REQUEST, e.message).into_response(),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use tower::ServiceExt; // for .oneshot()

    // ── AS2 helpers ──────────────────────────────────────────────────────────

    #[cfg(feature = "as2")]
    fn minimal_as2_post(body: &'static [u8]) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri("/as2/inbox")
            .header("AS2-From", "sender-id")
            .header("AS2-To", "receiver-id")
            .header(
                "Content-Type",
                "application/pkcs7-mime; smime-type=enveloped-data",
            )
            .body(Body::from(body))
            .unwrap()
    }

    #[cfg(feature = "as2")]
    struct EchoAcceptAs2;

    #[cfg(feature = "as2")]
    impl As2AxumHandler for EchoAcceptAs2 {
        async fn handle(&self, _: As2HttpIngress) -> HandlerOutcome {
            HandlerOutcome::ok()
        }
    }

    // ── AS4 helpers ──────────────────────────────────────────────────────────

    #[cfg(feature = "as4")]
    fn minimal_as4_post(body: &'static [u8]) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri("/as4/inbox")
            .header("Content-Type", "application/soap+xml; charset=UTF-8")
            .body(Body::from(body))
            .unwrap()
    }

    #[cfg(feature = "as4")]
    struct EchoAcceptAs4;

    #[cfg(feature = "as4")]
    impl As4AxumHandler for EchoAcceptAs4 {
        async fn handle(&self, _: As4HttpIngress) -> HandlerOutcome {
            HandlerOutcome::ok()
        }
    }

    // ── AS2 tests ─────────────────────────────────────────────────────────────

    #[cfg(feature = "as2")]
    #[tokio::test]
    async fn as2_valid_post_returns_200() {
        let app = as2_router(
            Arc::new(EchoAcceptAs2),
            "/as2/inbox",
            RouterConfig::default(),
        );
        let resp = app.oneshot(minimal_as2_post(b"hello")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[cfg(feature = "as2")]
    #[tokio::test]
    async fn as2_missing_as2_from_returns_400() {
        let app = as2_router(
            Arc::new(EchoAcceptAs2),
            "/as2/inbox",
            RouterConfig::default(),
        );
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/as2/inbox")
            .header("AS2-To", "receiver-id")
            .header("Content-Type", "application/pkcs7-mime")
            .body(Body::from("payload"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[cfg(feature = "as2")]
    #[tokio::test]
    async fn as2_get_method_returns_405() {
        // axum automatically returns 405 when the method doesn't match the registered route
        let app = as2_router(
            Arc::new(EchoAcceptAs2),
            "/as2/inbox",
            RouterConfig::default(),
        );
        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/as2/inbox")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[cfg(feature = "as2")]
    #[tokio::test]
    async fn as2_handler_sync_mdn_response_carries_content_type() {
        struct MdnAs2Handler;
        impl As2AxumHandler for MdnAs2Handler {
            async fn handle(&self, _: As2HttpIngress) -> HandlerOutcome {
                HandlerOutcome::ok_with_body(
                    b"--boundary\r\nContent-Type: message/disposition-notification\r\n\r\n"
                        .to_vec(),
                    "multipart/report; report-type=disposition-notification; boundary=boundary",
                )
            }
        }
        let app = as2_router(
            Arc::new(MdnAs2Handler),
            "/as2/inbox",
            RouterConfig::default(),
        );
        let resp = app.oneshot(minimal_as2_post(b"payload")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("Content-Type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.starts_with("multipart/report"));
    }

    #[cfg(feature = "as2")]
    #[tokio::test]
    async fn as2_handler_rejected_propagates_status_code() {
        struct RejectAs2;
        impl As2AxumHandler for RejectAs2 {
            async fn handle(&self, _: As2HttpIngress) -> HandlerOutcome {
                HandlerOutcome::server_error("crypto verification failed")
            }
        }
        let app = as2_router(Arc::new(RejectAs2), "/as2/inbox", RouterConfig::default());
        let resp = app.oneshot(minimal_as2_post(b"bad")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[cfg(feature = "as2")]
    #[tokio::test]
    async fn as2_handler_receives_correct_ingress_fields() {
        use std::sync::{Arc as StdArc, Mutex};

        struct CaptureAs2Handler {
            captured: Mutex<Option<As2HttpIngress>>,
        }
        impl As2AxumHandler for CaptureAs2Handler {
            async fn handle(&self, ingress: As2HttpIngress) -> HandlerOutcome {
                *self.captured.lock().unwrap() = Some(ingress);
                HandlerOutcome::ok()
            }
        }

        let cap = StdArc::new(CaptureAs2Handler {
            captured: Mutex::new(None),
        });
        let app = as2_router(cap.clone(), "/as2/inbox", RouterConfig::default());
        app.oneshot(minimal_as2_post(b"body-content"))
            .await
            .unwrap();

        let ingress = cap.captured.lock().unwrap().take().unwrap();
        assert_eq!(ingress.as2_from, "sender-id");
        assert_eq!(ingress.as2_to, "receiver-id");
        assert_eq!(ingress.body.as_ref(), b"body-content");
    }

    // ── AS4 tests ─────────────────────────────────────────────────────────────

    #[cfg(feature = "as4")]
    #[tokio::test]
    async fn as4_valid_post_returns_200() {
        let app = as4_router(
            Arc::new(EchoAcceptAs4),
            "/as4/inbox",
            RouterConfig::default(),
        );
        let resp = app.oneshot(minimal_as4_post(b"<soap/>")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[cfg(feature = "as4")]
    #[tokio::test]
    async fn as4_wrong_content_type_returns_400() {
        let app = as4_router(
            Arc::new(EchoAcceptAs4),
            "/as4/inbox",
            RouterConfig::default(),
        );
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/as4/inbox")
            .header("Content-Type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[cfg(feature = "as4")]
    #[tokio::test]
    async fn as4_handler_with_receipt_body_carries_soap_content_type() {
        struct ReceiptAs4;
        impl As4AxumHandler for ReceiptAs4 {
            async fn handle(&self, _: As4HttpIngress) -> HandlerOutcome {
                HandlerOutcome::ok_with_body(
                    b"<soap:Envelope/>".to_vec(),
                    "application/soap+xml; charset=UTF-8",
                )
            }
        }
        let app = as4_router(Arc::new(ReceiptAs4), "/as4/inbox", RouterConfig::default());
        let resp = app.oneshot(minimal_as4_post(b"<soap/>")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("Content-Type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.starts_with("application/soap+xml"));
    }

    #[cfg(feature = "as4")]
    #[tokio::test]
    async fn as4_handler_extracts_action_from_content_type() {
        use parking_lot::Mutex;

        struct CaptureAs4Handler {
            action: Mutex<Option<String>>,
        }
        impl As4AxumHandler for CaptureAs4Handler {
            async fn handle(&self, ingress: As4HttpIngress) -> HandlerOutcome {
                *self.action.lock() = ingress.action;
                HandlerOutcome::ok()
            }
        }

        let cap = Arc::new(CaptureAs4Handler {
            action: Mutex::new(None),
        });
        let app = as4_router(cap.clone(), "/as4/inbox", RouterConfig::default());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/as4/inbox")
            .header(
                "Content-Type",
                "application/soap+xml; charset=UTF-8; action=\"urn:acme:SubmitOrder\"",
            )
            .body(Body::from("<soap/>"))
            .unwrap();
        app.oneshot(req).await.unwrap();
        assert_eq!(cap.action.lock().as_deref(), Some("urn:acme:SubmitOrder"),);
    }

    #[cfg(feature = "as4")]
    #[tokio::test]
    async fn as4_text_xml_content_type_rejected() {
        let app = as4_router(
            Arc::new(EchoAcceptAs4),
            "/as4/inbox",
            RouterConfig::default(),
        );
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/as4/inbox")
            .header("Content-Type", "text/xml; charset=UTF-8")
            .body(Body::from("<soap:Envelope/>"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── HandlerOutcome convenience constructors ─────────────────────────────

    #[test]
    fn router_config_default_has_30s_timeout_and_256mib_limit() {
        let cfg = RouterConfig::default();
        assert_eq!(cfg.body_read_timeout, Duration::from_secs(30));
        assert_eq!(cfg.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
    }

    #[cfg(feature = "as2")]
    #[tokio::test]
    async fn as2_router_with_custom_config_applies_settings() {
        // Build with a generous timeout and a tiny max body (1 KiB).
        let config = RouterConfig {
            body_read_timeout: Duration::from_secs(120),
            max_body_bytes: 1024,
        };
        // Payload under the limit → 200.
        let app = as2_router(Arc::new(EchoAcceptAs2), "/as2/inbox", config.clone());
        let resp = app.oneshot(minimal_as2_post(b"small")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // Payload over the 1 KiB limit → 413.
        let oversized = vec![b'x'; 2048];
        let app2 = as2_router(Arc::new(EchoAcceptAs2), "/as2/inbox", config);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/as2/inbox")
            .header("AS2-From", "sender-id")
            .header("AS2-To", "receiver-id")
            .header(
                "Content-Type",
                "application/pkcs7-mime; smime-type=enveloped-data",
            )
            .body(Body::from(oversized))
            .unwrap();
        let resp2 = app2.oneshot(req).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn handler_outcome_constructors_build_expected_variants() {
        matches!(
            HandlerOutcome::ok(),
            HandlerOutcome::Accepted { body: None, .. }
        );
        matches!(
            HandlerOutcome::ok_with_body(b"x".to_vec(), "text/plain"),
            HandlerOutcome::Accepted { body: Some(_), .. }
        );
        matches!(
            HandlerOutcome::bad_request("msg"),
            HandlerOutcome::Rejected { status: 400, .. }
        );
        matches!(
            HandlerOutcome::server_error("err"),
            HandlerOutcome::Rejected { status: 500, .. }
        );
    }
}
