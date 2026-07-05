# HTTP Transport

The `transport` module provides three independent layers for HTTP integration. Each can be used without the others.

## Layer Overview

| Layer | Module | Feature | Description |
|---|---|---|---|
| Ingress | `transport::ingress` | *(always available)* | Framework-agnostic header validation |
| Egress | `transport::egress` | `client` | Async HTTP send via reqwest |
| Server | `transport::server` | `server` | Axum 0.7 router builders |

---

## Ingress (Framework-Agnostic)

`src/transport/ingress.rs` — available without any optional feature. Validates incoming HTTP requests against RFC 4130 §6 (AS2) and eDelivery AS4 SOAP requirements, independent of any web framework.

### AS2 ingress

```rust
use asx_rs::transport::ingress::{As2HttpIngress, as2_ingress_from_http};
use asx_rs::http::HttpRequest;

let ingress: As2HttpIngress = as2_ingress_from_http(http_request)?;
```

`as2_ingress_from_http` fails with `AsxError` if:
- Method is not `POST`
- `Content-Type` is absent
- `AS2-From` or `AS2-To` headers are absent

`As2HttpIngress` fields:

```rust
pub struct As2HttpIngress {
    pub body: Vec<u8>,
    pub content_type: String,
    pub as2_from: String,
    pub as2_to: String,
    pub message_id: Option<String>,
    pub as2_version: Option<String>,
    pub mime_version: Option<String>,
    pub raw_headers: Vec<(String, String)>,
}
```

In non-testing builds with strict interop sessions, bind strict runtime once
and use the standard ingress helper APIs:

1. `session_with_strict_runtime_bootstrap_token(...)`
2. `receive_and_generate_mdn(...)` or `receive_and_generate_mdn_with_signing(...)`

### Breaking-Change Migration (Strict Runtime Default Enforcement)

When strict interop entry points are fail-closed by default, migrate helper-path
calls as follows.

Before (no explicit startup-bound session):

```rust
let ingress = as2_ingress_from_http(req)?;
let out = ingress.receive_and_generate_mdn(&session, verifier)?;
```

After (default strict enforcement):

```rust
let ingress = as2_ingress_from_http(req)?;
let strict_session = asx_rs::presets::session_with_strict_runtime_bootstrap_token(
    "transport_as2_ingress",
    &bootstrap_token,
    &session,
)?;
let out = ingress.receive_and_generate_mdn(&strict_session, verifier)?;
```

For AS4 push ingress helpers:

```rust
let ingress = as4_ingress_from_http(req)?;
let strict_session = asx_rs::presets::session_with_strict_runtime_bootstrap_token(
    "transport_as4_ingress",
    &bootstrap_token,
    &session,
)?;
let out = ingress.receive_push_with_dedup_sync(
    asx_rs::transport::ingress::As4IngressReceivePushSyncRequest {
        session: &strict_session,
        event_bus: &event_bus,
        policy: push_policy,
        dedup_backend,
        receipt_payload: None,
    },
)?;
```

### AS4 ingress

```rust
use asx_rs::transport::ingress::{As4HttpIngress, as4_ingress_from_http};

let ingress: As4HttpIngress = as4_ingress_from_http(&http_request)?;
```

`as4_ingress_from_http` fails if:
- Method is not `POST`
- `Content-Type` is not SOAP-aware (`application/soap+xml` or
    `multipart/related` carrying SOAP/XOP root content; XOP root requires
    `start-info="application/soap+xml"`)

Parameter matching is case-insensitive; quoted and whitespace-padded `type` /
`start-info` values are normalized for interoperability, and duplicate
multipart parameters are rejected fail closed.

`As4HttpIngress` fields:

```rust
pub struct As4HttpIngress {
    pub body: Arc<[u8]>,
    pub content_type: String,
    pub action: Option<String>,      // From Content-Type action=... parameter
    pub traceparent: Option<String>,
    pub raw_headers: HttpHeaders,
}
```

---

## Egress / HTTP Client (`client` feature)

```toml
asx-rs = { version = "0.5", features = ["as2", "as4", "client"] }
```

### AS2 send

```rust
use asx_rs::transport::egress::{As2HttpTransport, TransportConfig, HttpSendOutcome};

let transport = As2HttpTransport::new(TransportConfig {
    timeout_secs: 30,
    max_idle_connections: 10,
    user_agent: "MyApp/1.0".to_string(),
});

let outcome: HttpSendOutcome = transport.send_sync(
    "https://partner.example.com/as2/receive",
    &send_output,       // As2SendOutput from asx_rs::as2::send_sync
).await?;

if outcome.is_sync_mdn() {
    // outcome.body contains the synchronous MDN bytes
    // outcome.content_type identifies it as multipart/report
}
```

### AS4 send

```rust
use asx_rs::transport::egress::{As4HttpTransport, TransportConfig, HttpSendOutcome};

let transport = As4HttpTransport::new(TransportConfig { ... });

let outcome: HttpSendOutcome = transport.send_sync(
    "https://partner.example.com/as4/receive",
    &send_output,       // As4SendOutput from asx_rs::as4::send_sync
).await?;
```

### `TransportConfig`

```rust
pub struct TransportConfig {
    pub timeout_secs: u64,           // HTTP request timeout (default: 30)
    pub max_idle_connections: usize, // Connection pool size (default: 10)
    pub user_agent: String,          // User-Agent header value
}
```

Default: `TransportConfig::default()` — 30s timeout, 10 idle connections, `asx/<version>`.

### `HttpSendOutcome`

```rust
pub struct HttpSendOutcome {
    pub status: u16,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
    pub headers: Vec<(String, String)>,
}

impl HttpSendOutcome {
    /// Returns true when the response Content-Type is multipart/report (sync MDN).
    pub fn is_sync_mdn(&self) -> bool { ... }
}
```

---

## Server / Axum Integration (`server` feature)

```toml
asx-rs = { version = "0.5", features = ["as2", "as4", "server"] }
```

The server layer provides axum 0.7 router builders with typed handler traits. It is built on top of the framework-agnostic ingress layer — the same validation logic runs regardless of how the request arrives.

### `HandlerOutcome`

The return type from all handler implementations:

```rust
pub enum HandlerOutcome {
    Accepted {
        body: Option<Vec<u8>>,          // Optional synchronous response body (sync MDN, receipt)
        content_type: Option<String>,   // Content-Type of response body
    },
    Rejected {
        status: u16,                    // HTTP status code (400, 415, 500, …)
        message: String,                // Error description
    },
}
```

Convenience constructors:

```rust
HandlerOutcome::ok()                             // 200, no body
HandlerOutcome::ok_with_body(body, content_type) // 200 with sync MDN or receipt body
HandlerOutcome::bad_request(msg)                 // 400
HandlerOutcome::server_error(msg)                // 500
```

### AS2 server

```rust
use asx_rs::transport::server::{as2_router, As2AxumHandler, HandlerOutcome};
use asx_rs::transport::ingress::As2HttpIngress;
use std::sync::Arc;

struct MyAs2Handler { /* your state */ }

#[async_trait::async_trait]
impl As2AxumHandler for MyAs2Handler {
    async fn handle(&self, ingress: As2HttpIngress) -> HandlerOutcome {
        // ingress.body, ingress.as2_from, ingress.as2_to, ingress.message_id, …
        match process(ingress).await {
            Ok(mdn_bytes) => HandlerOutcome::ok_with_body(
                mdn_bytes,
                "multipart/report; report-type=disposition-notification".to_string(),
            ),
            Err(e) => HandlerOutcome::bad_request(e.to_string()),
        }
    }
}

// Mount the router at a path:
let app = as2_router(Arc::new(MyAs2Handler { /* ... */ }), "/as2/receive");
```

`as2_router` produces an `axum::Router` with a single `POST` route at the given path. Non-POST requests receive a `405 Method Not Allowed` response automatically.

### AS4 server

```rust
use asx_rs::transport::server::{as4_router, As4AxumHandler, HandlerOutcome};
use asx_rs::transport::ingress::As4HttpIngress;
use std::sync::Arc;

struct MyAs4Handler;

#[async_trait::async_trait]
impl As4AxumHandler for MyAs4Handler {
    async fn handle(&self, ingress: As4HttpIngress) -> HandlerOutcome {
        // ingress.body, ingress.action, ingress.content_type, …
        HandlerOutcome::ok()
    }
}

let app = as4_router(Arc::new(MyAs4Handler), "/as4/receive");
```

### Combining routes

Multiple routers can be merged with `axum::Router::merge`:

```rust
let as2_app = as2_router(Arc::new(As2Handler), "/as2/receive");
let as4_app = as4_router(Arc::new(As4Handler), "/as4/receive");
let app = as2_app.merge(as4_app);
```

### Request limits

The server layer enforces a **256 MiB** body limit on all inbound requests. Requests exceeding this limit are rejected with `413 Payload Too Large` before the handler is called.

### Integration testing

Test handlers without a network using `tower::ServiceExt::oneshot`:

```toml
[dev-dependencies]
tower = { version = "0.4", features = ["util"] }
```

```rust
use tower::ServiceExt;
use axum::http::{Request, StatusCode};

let app = as2_router(Arc::new(MyAs2Handler), "/as2/receive");

let response = app
    .oneshot(
        Request::builder()
            .method("POST")
            .uri("/as2/receive")
            .header("Content-Type", "application/pkcs7-mime")
            .header("AS2-From", "sender")
            .header("AS2-To", "receiver")
            .body(axum::body::Body::from(b"test".to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();

assert_eq!(response.status(), StatusCode::OK);
```

---

## Full Integration Example

AS2 + AS4 dual-protocol axum server:

```rust
use asx_rs::transport::server::{as2_router, as4_router, As2AxumHandler, As4AxumHandler, HandlerOutcome};
use asx_rs::transport::ingress::{As2HttpIngress, As4HttpIngress};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let as2_handler = Arc::new(MyAs2Handler::new());
    let as4_handler = Arc::new(MyAs4Handler::new());

    let app = as2_router(as2_handler, "/as2/receive")
        .merge(as4_router(as4_handler, "/as4/receive"));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("Listening on :8080");
    axum::serve(listener, app).await.unwrap();
}
```
