//! In-process AS4 mock endpoint for integration testing without PKI certificates.
//!
//! **Feature gates:** requires `as4 + testing + server`.
//!
//! `MockAs4Endpoint` binds to a local TCP address, accepts any inbound AS4 push
//! message (no signature verification), records payloads for test assertions, and
//! returns a synchronous AS4 receipt.  This removes the need for BDEW WIRK
//! certificates or any other PKI during early development and CI.
//!
//! # Quick start
//!
//! ```rust,no_run
//! # #[cfg(all(feature = "as4", feature = "testing", feature = "server"))]
//! # async fn example() {
//! use asx_rs::as4::mock_endpoint::MockAs4Endpoint;
//! use tokio::time::{Duration, timeout};
//!
//! // Bind to a random OS-assigned port.
//! let endpoint = MockAs4Endpoint::bind("127.0.0.1:0").await.expect("bind");
//! let url = endpoint.local_url(); // e.g. "http://127.0.0.1:54321/as4/inbox"
//!
//! // Send an AS4 message to `url` with any AS4 client library...
//!
//! // Wait up to 5 s for the first message.
//! let msg = timeout(Duration::from_secs(5), endpoint.next_received())
//!     .await
//!     .expect("timed out")
//!     .expect("endpoint closed");
//!
//! assert_eq!(msg.action, "urn:example:action");
//! # }
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Router,
    extract::{Request, State},
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::post,
};
use tokio::sync::mpsc;

use crate::as4::{
    As4PushPolicyBuilder, As4ReceiveOutcome, As4ReceivePushRequest, FragmentScopePolicy,
    InsecureBypassAs4Verifier, receive_push_with_dedup_async_with_custom_verifier,
};
use crate::core::{DEFAULT_MAX_BODY_BYTES, SessionContext};
use crate::http::{HttpHeaders, HttpRequest};
use crate::observability::EventBus;
use crate::reliability::InMemoryDedupBackend;
use crate::storage::{BoxFuture, DedupStorage};
use crate::transport::ingress::as4_ingress_from_http;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A message recorded by [`MockAs4Endpoint`].
///
/// All fields are extracted from the parsed ebMS3 `<eb:UserMessage>`.
/// The `payload` is the decrypted, de-SBDH-unwrapped business payload bytes.
#[derive(Debug, Clone)]
pub struct MockReceivedMessage {
    /// `<eb:Action>` from `<eb:CollaborationInfo>`.
    pub action: String,
    /// `<eb:Service>` value, when present.
    pub service: Option<String>,
    /// `<eb:MessageId>` from `<eb:MessageInfo>`.
    pub message_id: String,
    /// All `<eb:From>/<eb:PartyId>` values.
    pub from_party_ids: Vec<String>,
    /// All `<eb:To>/<eb:PartyId>` values.
    pub to_party_ids: Vec<String>,
    /// `<eb:ConversationId>`, if present.
    pub conversation_id: Option<String>,
    /// `<eb:RefToMessageId>` (Two-Way/Push-and-Push MEP correlation), if present.
    pub ref_to_message_id: Option<String>,
    /// Business payload bytes (verified, decrypted, de-SBDH-stripped).
    pub payload: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Internal — durable-flagged in-memory dedup for the mock
// ---------------------------------------------------------------------------

struct MockDedup(InMemoryDedupBackend);

impl DedupStorage for MockDedup {
    fn is_durable(&self) -> bool {
        true // test-only: claim durability so strict guards pass
    }
    fn first_seen<'a>(&'a self, key: &'a str) -> BoxFuture<'a, crate::core::Result<bool>> {
        self.0.first_seen(key)
    }
}

// ---------------------------------------------------------------------------
// Internal — shared Axum handler state
// ---------------------------------------------------------------------------

struct MockEndpointState {
    tx: mpsc::UnboundedSender<MockReceivedMessage>,
    dedup: Arc<MockDedup>,
    session: Arc<SessionContext>,
    event_bus: Arc<EventBus>,
    policy: crate::as4::types::As4PushPolicy,
}

// ---------------------------------------------------------------------------
// Public — MockAs4Endpoint
// ---------------------------------------------------------------------------

/// In-process HTTP AS4 endpoint for integration testing.
///
/// Accepts any inbound AS4 push (signed or unsigned, encrypted or plain)
/// using [`InsecureBypassAs4Verifier`], records each message in an internal
/// channel, and replies with a synchronous AS4 receipt.
///
/// Drop the `MockAs4Endpoint` to shut down the server.
pub struct MockAs4Endpoint {
    local_addr: SocketAddr,
    rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<MockReceivedMessage>>,
    _server: tokio::task::JoinHandle<()>,
}

impl MockAs4Endpoint {
    /// Bind to `addr` and start serving.
    ///
    /// Pass `"127.0.0.1:0"` to let the OS pick a random available port.
    pub async fn bind(addr: impl tokio::net::ToSocketAddrs) -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;

        let (tx, rx) = mpsc::unbounded_channel();

        let session = Arc::new(
            SessionContext::new("mock-as4-endpoint", "mock-partner", "strict")
                .expect("mock session must always construct"),
        );
        let event_bus = Arc::new(EventBus::new(128).expect("mock event bus must always construct"));

        // Relaxed policy for testing: the InsecureBypassAs4Verifier handles all
        // verification regardless of these settings, but we still configure
        // sensible test defaults.  require_signed_receipt is kept at the default
        // (true) because strict mode requires it; since receipt_payload is always
        // None in mock requests, this check never fires at runtime.
        let policy = As4PushPolicyBuilder::new()
            .fail_closed_audit_events(false)
            .timestamp_freshness_window(None)
            .fragment_scope_policy(FragmentScopePolicy::UseSoapSenderId)
            .allow_unsigned_push(true)
            .build()
            .expect("mock policy must always construct");

        let state = Arc::new(MockEndpointState {
            tx,
            dedup: Arc::new(MockDedup(InMemoryDedupBackend::new(
                std::time::Duration::from_secs(3600),
            ))),
            session,
            event_bus,
            policy,
        });

        let router: Router = Router::new()
            .route("/as4/inbox", post(mock_as4_handler))
            .with_state(state);

        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });

        Ok(Self {
            local_addr,
            rx: tokio::sync::Mutex::new(rx),
            _server: server,
        })
    }

    /// Returns the HTTP URL of the AS4 inbox, e.g. `http://127.0.0.1:PORT/as4/inbox`.
    pub fn local_url(&self) -> String {
        format!("http://{}/as4/inbox", self.local_addr)
    }

    /// Returns the bound [`SocketAddr`].
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Wait for the next received message.
    ///
    /// Returns `None` when the endpoint has been dropped (unlikely in tests).
    /// Wrap with `tokio::time::timeout` to avoid hanging on unexpected failures:
    ///
    /// ```rust,ignore
    /// let msg = tokio::time::timeout(
    ///     std::time::Duration::from_secs(5),
    ///     endpoint.next_received(),
    /// ).await.expect("timed out").expect("endpoint closed");
    /// ```
    pub async fn next_received(&self) -> Option<MockReceivedMessage> {
        self.rx.lock().await.recv().await
    }

    /// Drain all messages that have already arrived without waiting.
    pub async fn drain_received(&self) -> Vec<MockReceivedMessage> {
        let mut rx = self.rx.lock().await;
        let mut msgs = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            msgs.push(msg);
        }
        msgs
    }

    /// Alias for [`next_received`](Self::next_received) matching the feedback API.
    pub async fn next_message(&self) -> Option<MockReceivedMessage> {
        self.next_received().await
    }
}

impl Drop for MockAs4Endpoint {
    fn drop(&mut self) {
        self._server.abort();
    }
}

// ---------------------------------------------------------------------------
// Internal — Axum handler
// ---------------------------------------------------------------------------

async fn mock_as4_handler(State(state): State<Arc<MockEndpointState>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();

    let headers: HttpHeaders = parts
        .headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body_bytes = match axum::body::to_bytes(body, DEFAULT_MAX_BODY_BYTES).await {
        Ok(b) => b.to_vec(),
        Err(e) => return (StatusCode::PAYLOAD_TOO_LARGE, e.to_string()).into_response(),
    };

    let http_req = HttpRequest {
        method: parts.method.as_str().to_string(),
        uri: parts.uri.to_string(),
        headers,
        body: body_bytes.into(),
    };

    let ingress = match as4_ingress_from_http(http_req) {
        Ok(i) => i,
        Err(e) => return (StatusCode::BAD_REQUEST, e.message).into_response(),
    };

    let push_req = As4ReceivePushRequest {
        http_content_type: ingress.content_type.clone(),
        payload: ingress.body.clone(),
        receipt_payload: None,
        policy: state.policy.clone(),
        authenticated_sender_scope: None,
    };

    let dedup: Arc<dyn DedupStorage> = state.dedup.clone();

    let outcome = receive_push_with_dedup_async_with_custom_verifier(
        &state.session,
        &state.event_bus,
        push_req,
        dedup,
        InsecureBypassAs4Verifier,
    )
    .await;

    match outcome {
        Ok(As4ReceiveOutcome::FirstSeen(output)) => {
            let ref_id = output.user_message.message_id.clone();
            let msg = MockReceivedMessage {
                action: output.user_message.action.clone(),
                service: output.user_message.service.clone(),
                message_id: output.user_message.message_id.clone(),
                from_party_ids: output.user_message.from_party_ids.clone(),
                to_party_ids: output.user_message.to_party_ids.clone(),
                conversation_id: output.user_message.conversation_id.clone(),
                ref_to_message_id: output.user_message.ref_to_message_id.clone(),
                payload: output.payload.as_ref().as_ref().to_vec(),
            };
            tracing::debug!(
                target: "asx_rs::as4::mock_endpoint",
                message_id = %msg.message_id,
                action = %msg.action,
                from = ?msg.from_party_ids,
                payload_len = msg.payload.len(),
                "MockAs4Endpoint: recorded first-seen message"
            );
            let _ = state.tx.send(msg);
            generate_receipt_response(&state.session, &ref_id)
        }
        Ok(As4ReceiveOutcome::Duplicate { ref message_id }) => {
            // Still return an acknowledgement — the sender may not have received the first one.
            tracing::debug!(
                target: "asx_rs::as4::mock_endpoint",
                message_id = %message_id,
                "MockAs4Endpoint: duplicate message (replay)"
            );
            generate_receipt_response(&state.session, message_id)
        }
        Err(e) => {
            use crate::core::ErrorCode;
            let status = match e.code {
                ErrorCode::ParseFailed
                | ErrorCode::DecryptionFailed
                | ErrorCode::InteropViolation
                | ErrorCode::SecurityVerificationFailed => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            tracing::debug!(
                target: "asx_rs::as4::mock_endpoint",
                error = %e.message,
                status = %status,
                "MockAs4Endpoint: receive failed"
            );
            (status, e.message).into_response()
        }
    }
}

fn generate_receipt_response(session: &SessionContext, ref_to_message_id: &str) -> Response {
    let receipt_id = format!("mock-receipt-{}@mock.endpoint", uuid::Uuid::new_v4());
    match crate::as4::signals::generate_receipt(session, &receipt_id, ref_to_message_id) {
        Ok(bytes) => (
            StatusCode::OK,
            [(CONTENT_TYPE, "application/soap+xml")],
            bytes,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(
                target: "asx_rs::as4::mock_endpoint",
                error = %e.message,
                ref_to_message_id = %ref_to_message_id,
                "MockAs4Endpoint: receipt generation failed"
            );
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    fn simple_as4_soap_payload() -> Vec<u8> {
        br#"<S12:Envelope
            xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
            xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
            xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
          <S12:Header>
            <wsse:Security/>
            <eb:Messaging S12:mustUnderstand="true">
              <eb:UserMessage>
                <eb:MessageInfo>
                  <eb:MessageId>mock-test-001@example</eb:MessageId>
                </eb:MessageInfo>
                <eb:CollaborationInfo>
                  <eb:Action>urn:test:mock:action</eb:Action>
                  <eb:Service>urn:test:mock:service</eb:Service>
                  <eb:ConversationId>conv-mock-001</eb:ConversationId>
                </eb:CollaborationInfo>
                <eb:PartyInfo>
                  <eb:From><eb:PartyId>sender-a</eb:PartyId></eb:From>
                  <eb:To><eb:PartyId>receiver-b</eb:PartyId></eb:To>
                </eb:PartyInfo>
                <eb:MessageProperties>
                  <eb:Property name="originalSender">sender-a</eb:Property>
                  <eb:Property name="finalRecipient">receiver-b</eb:Property>
                  <eb:Property name="trackingIdentifier">track-001</eb:Property>
                </eb:MessageProperties>
              </eb:UserMessage>
            </eb:Messaging>
          </S12:Header>
          <S12:Body>
            <payload>hello from mock test</payload>
          </S12:Body>
        </S12:Envelope>"#
            .to_vec()
    }

    fn multipart_as4_body(soap: &[u8]) -> (Vec<u8>, String) {
        let boundary = "mock-boundary-001";
        let cid = "body@mock.example";

        // Inject an XOP Include into the soap so the MIME parser finds a payload.
        let soap_with_xop = String::from_utf8_lossy(soap).replace(
            "<S12:Body>",
            &format!(
                "<S12:Body xmlns:xop=\"http://www.w3.org/2004/08/xop/include\"><xop:Include href=\"cid:{cid}\"/>"
            ),
        );
        let soap_bytes = soap_with_xop.as_bytes();

        let mut body = Vec::new();
        // Part 1: SOAP root
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            b"Content-Type: application/xop+xml; charset=UTF-8; type=\"application/soap+xml\"\r\n",
        );
        body.extend_from_slice(b"Content-ID: <soap-root@mock.example>\r\n\r\n");
        body.extend_from_slice(soap_bytes);
        body.extend_from_slice(b"\r\n");
        // Part 2: payload attachment
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
        body.extend_from_slice(format!("Content-ID: <{cid}>\r\n\r\n").as_bytes());
        body.extend_from_slice(b"mock-payload-bytes");
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

        let ct = format!(
            "multipart/related; boundary=\"{boundary}\"; type=\"application/xop+xml\"; start-info=\"application/soap+xml\""
        );
        (body, ct)
    }

    #[tokio::test]
    async fn mock_endpoint_binds_and_records_message() {
        let endpoint = MockAs4Endpoint::bind("127.0.0.1:0")
            .await
            .expect("bind mock endpoint");
        let url = endpoint.local_url();
        assert!(url.starts_with("http://127.0.0.1:"), "url = {url}");

        let (body, content_type) = multipart_as4_body(&simple_as4_soap_payload());

        let client = reqwest::Client::new();
        let resp = client
            .post(&url)
            .header("Content-Type", content_type)
            .body(body)
            .send()
            .await
            .expect("POST to mock endpoint");

        assert!(
            resp.status().is_success(),
            "expected 2xx, got {}",
            resp.status()
        );

        let msg = timeout(Duration::from_secs(3), endpoint.next_received())
            .await
            .expect("timed out waiting for message")
            .expect("no message received");

        assert_eq!(msg.action, "urn:test:mock:action");
        assert_eq!(msg.service.as_deref(), Some("urn:test:mock:service"));
        assert_eq!(msg.message_id, "mock-test-001@example");
        assert_eq!(msg.conversation_id.as_deref(), Some("conv-mock-001"));
        assert!(!msg.payload.is_empty(), "payload must not be empty");
    }

    #[tokio::test]
    async fn mock_endpoint_returns_soap_receipt() {
        let endpoint = MockAs4Endpoint::bind("127.0.0.1:0").await.expect("bind");
        let url = endpoint.local_url();

        let (body, ct) = multipart_as4_body(&simple_as4_soap_payload());

        let client = reqwest::Client::new();
        let resp = client
            .post(&url)
            .header("Content-Type", ct)
            .body(body)
            .send()
            .await
            .expect("POST");

        assert_eq!(resp.status(), 200);
        let ct_resp = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct_resp.contains("application/soap+xml"),
            "receipt must be SOAP, got {ct_resp}"
        );
        let receipt_body = resp.text().await.expect("receipt body");
        assert!(
            receipt_body.contains("eb:Receipt"),
            "response must contain AS4 Receipt"
        );
        assert!(
            receipt_body.contains("mock-test-001@example"),
            "receipt must reference the original message ID"
        );
    }

    #[tokio::test]
    async fn mock_endpoint_drain_received_returns_all() {
        let endpoint = MockAs4Endpoint::bind("127.0.0.1:0").await.expect("bind");
        let url = endpoint.local_url();
        let (body, ct) = multipart_as4_body(&simple_as4_soap_payload());

        let client = reqwest::Client::new();
        // Send twice — the second is a duplicate (same message_id) so only one recorded.
        for _ in 0..2 {
            client
                .post(&url)
                .header("Content-Type", &ct)
                .body(body.clone())
                .send()
                .await
                .expect("POST");
        }

        // Give the server a moment to process both requests.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let msgs = endpoint.drain_received().await;
        assert_eq!(msgs.len(), 1, "duplicate must not be recorded twice");
    }
}
