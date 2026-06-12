//! HTTP transport adapters for AS2 and AS4.
//!
//! ## Server-side ingress (always available)
//!
//! Convert an incoming [`crate::http::HttpRequest`] into protocol-level
//! message data, validating required headers and method.
//!
//! | Function | Input | Purpose |
//! |---|---|---|
//! | [`as2_ingress_from_http`] | `HttpRequest` | Extract AS2 message data per RFC 4130 §6 |
//! | [`as4_ingress_from_http`] | `HttpRequest` | Extract AS4 SOAP data per eDelivery HTTP binding |
//!
//! ### Example — AS2 server
//! ```ignore
//! use asx_rs::http::HttpRequest;
//! use asx_rs::transport::{as2_ingress_from_http};
//!
//! let http_req = /* incoming HTTP request from your framework */;
//! let ingress = as2_ingress_from_http(http_req)?;
//! // ingress.body → feed into as2::receive_sync or as2::receive_async
//! // ingress.as2_from / ingress.as2_to → routing
//! ```
//!
//! ## Client-side egress (requires `client` feature)
//!
//! Async HTTP transports for sending AS2 and AS4 messages.
//!
//! | Type | Purpose |
//! |---|---|
//! | `As2HttpTransport` | Send AS2 messages with RFC 4130 §6 headers |
//! | `As4HttpTransport` | Send AS4 SOAP envelopes with eDelivery HTTP headers |
//! | `TransportConfig` | Configure timeouts, user-agent, connection pool |
//! | `HttpSendOutcome` | HTTP response wrapping status, headers, body |

pub mod ingress;
pub mod trace_context;

#[cfg(feature = "client")]
pub mod egress;

#[cfg(feature = "server")]
pub mod server;

pub use ingress::{As2HttpIngress, As4HttpIngress, as2_ingress_from_http, as4_ingress_from_http};

#[cfg(feature = "client")]
pub use egress::{HttpSendOutcome, TransportConfig};

#[cfg(all(feature = "client", feature = "as2"))]
pub use egress::As2HttpTransport;

#[cfg(all(feature = "client", feature = "as4"))]
pub use egress::As4HttpTransport;

#[cfg(feature = "server")]
pub use server::{HandlerOutcome, RouterConfig};

#[cfg(all(feature = "server", feature = "as2"))]
pub use server::{As2AxumHandler, as2_router};

#[cfg(all(feature = "server", feature = "as4"))]
pub use server::{As4AxumHandler, as4_router};
