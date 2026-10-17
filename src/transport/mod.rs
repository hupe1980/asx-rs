//! The HTTP egress internals behind the built-in [`crate::HttpClient`], the
//! SMP client and the OCSP fetcher.

#[cfg(feature = "http-client")]
pub(crate) mod egress;
