//! The receive endpoint: [`Inbound`] (a tower `Service`), the application's
//! [`Handler`] and its refusal [`Reject`].

use crate::error::{BoxError, BoxFuture};
use crate::verified::Verified;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Application code for one verified inbound message. `Ok` accepts (receipt
/// / MDN `processed`), `Err` refuses (EBMS:0202 / `processed/error:
/// unexpected-processing-error`) and releases the dedup claim. Must be
/// idempotent on the message id (delivery is at-least-once). Object-safe.
pub trait Handler<M>: Send + Sync + 'static {
    /// Handle one verified message.
    fn handle(&self, message: Verified<M>) -> BoxFuture<'_, std::result::Result<(), Reject>>;
}

impl<M, F, Fut> Handler<M> for F
where
    M: Send + 'static,
    F: Fn(Verified<M>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = std::result::Result<(), Reject>> + Send + 'static,
{
    fn handle(&self, message: Verified<M>) -> BoxFuture<'_, std::result::Result<(), Reject>> {
        Box::pin(self(message))
    }
}

/// Why a handler refused a message. Like `anyhow::Error`: `?` converts any
/// error into it, and it therefore does not implement `std::error::Error`
/// itself.
#[derive(Debug)]
pub struct Reject {
    pub(crate) fault: Fault,
    #[allow(dead_code)]
    source: Option<BoxError>,
}

/// What the peer is told about a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault {
    /// EBMS:0202 DeliveryFailure / `unexpected-processing-error`: the sender
    /// may retry.
    DeliveryFailure,
    /// EBMS:0004 Other (AS4): the message will never be accepted, so the
    /// sender does not retry. AS2 has no such disposition and answers
    /// `unexpected-processing-error`.
    Permanent,
    /// Peppol "not serviced": EBMS:0004 with `PEPPOL:NOT_SERVICED` (Peppol
    /// AS4 §4.4).
    #[cfg_attr(not(feature = "peppol"), allow(dead_code))]
    NotServiced,
}

impl Reject {
    /// Refuse the message because of `source`; the sender may retry
    /// (AS4: EBMS:0202 DeliveryFailure).
    pub fn new(source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Reject {
        Reject {
            fault: Fault::DeliveryFailure,
            source: Some(source.into()),
        }
    }

    /// Refuse the message for good, e.g. after dead-lettering it: the
    /// sender does not retry (AS4: EBMS:0004 Other). The claim is released,
    /// not accepted, so a retransmission is never answered with a receipt.
    pub fn permanent(source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Reject {
        Reject {
            fault: Fault::Permanent,
            source: Some(source.into()),
        }
    }

    #[cfg_attr(not(feature = "peppol"), allow(dead_code))]
    pub(crate) fn with_fault(fault: Fault) -> Reject {
        Reject {
            fault,
            source: None,
        }
    }

    pub(crate) fn panicked() -> Reject {
        Reject {
            fault: Fault::DeliveryFailure,
            source: Some("the handler panicked".into()),
        }
    }
}

impl<E: std::error::Error + Send + Sync + 'static> From<E> for Reject {
    fn from(err: E) -> Reject {
        Reject::new(err)
    }
}

/// The protocol side of an [`Inbound`]: one request in, one response out.
pub(crate) trait InboundCore: Send + Sync + 'static {
    /// The size limit (`Profile::max_message_bytes`).
    fn max_bytes(&self) -> u64;

    /// Process one fully read request.
    fn process(
        &self,
        request: http::Request<Bytes>,
    ) -> BoxFuture<'static, http::Response<Full<Bytes>>>;
}

/// A receive endpoint: verifies, settles dedup, calls the handler, answers
/// with receipt / error / MDN. Mount with
/// `axum::Router::route_service(path, inbound)` or call it as a tower
/// `Service`.
#[derive(Clone)]
pub struct Inbound {
    core: Arc<dyn InboundCore>,
}

impl std::fmt::Debug for Inbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inbound")
            .field("max_bytes", &self.core.max_bytes())
            .finish_non_exhaustive()
    }
}

impl Inbound {
    #[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(dead_code))]
    pub(crate) fn new(core: Arc<dyn InboundCore>) -> Self {
        Self { core }
    }
}

pub(crate) fn empty(status: http::StatusCode) -> http::Response<Full<Bytes>> {
    let mut response = http::Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status;
    response
}

pub(crate) fn with_body(
    status: http::StatusCode,
    content_type: &str,
    body: impl Into<Bytes>,
) -> http::Response<Full<Bytes>> {
    let mut response = http::Response::new(Full::new(body.into()));
    *response.status_mut() = status;
    if let Ok(value) = http::HeaderValue::from_str(content_type) {
        response
            .headers_mut()
            .insert(http::header::CONTENT_TYPE, value);
    }
    response
}

impl<B> tower_service::Service<http::Request<B>> for Inbound
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = http::Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = BoxFuture<'static, std::result::Result<Self::Response, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let core = self.core.clone();
        Box::pin(async move {
            let limit = usize::try_from(core.max_bytes()).unwrap_or(usize::MAX);
            let (parts, body) = request.into_parts();
            if let Some(declared) = parts
                .headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                && declared > core.max_bytes()
            {
                return Ok(empty(http::StatusCode::PAYLOAD_TOO_LARGE));
            }
            let collected = match Limited::new(body, limit).collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(err) => {
                    let too_large = err
                        .downcast_ref::<http_body_util::LengthLimitError>()
                        .is_some();
                    return Ok(empty(if too_large {
                        http::StatusCode::PAYLOAD_TOO_LARGE
                    } else {
                        http::StatusCode::BAD_REQUEST
                    }));
                }
            };
            let request = http::Request::from_parts(parts, collected);
            Ok(core.process(request).await)
        })
    }
}

/// Run the handler on its own task: a panic becomes a refusal, never an
/// aborted connection.
#[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(dead_code))]
pub(crate) async fn run_handler<M: Send + 'static>(
    handler: Arc<dyn Handler<M>>,
    message: Verified<M>,
) -> std::result::Result<(), Reject> {
    match tokio::task::spawn(async move { handler.handle(message).await }).await {
        Ok(result) => result,
        Err(_) => Err(Reject::panicked()),
    }
}
