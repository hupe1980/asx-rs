//! The HTTP egress internals behind the built-in [`crate::HttpClient`]: the
//! address filter, the connector and the TLS policy.

#[cfg(feature = "http-client")]
pub(crate) mod connector;
#[cfg(feature = "http-client")]
pub(crate) mod egress;
#[cfg(feature = "http-client")]
pub(crate) mod tls;
