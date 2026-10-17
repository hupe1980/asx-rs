//! Small shared helpers: body limit, secret redaction, constant-time compare, payload input.

/// Default inbound payload ceiling (256 MiB).
///
/// Production EDI batch files routinely exceed 50–100 MB; this default
/// accommodates X12, EDIFACT, and Peppol BIS payloads without operator
/// intervention.
pub const DEFAULT_MAX_BODY_BYTES: usize = 256 * 1024 * 1024;

/// Render secret material for `Debug` without printing it.
///
/// Every type in this crate that holds a private key or a shared secret writes
/// its `Debug` by hand and routes the secret-bearing fields through here. A
/// `#[derive(Debug)]` on such a type writes the key into whatever consumed the
/// output — a log line, a panic message, a `tracing` field, a bug report.
#[must_use]
#[cfg(any(feature = "as2", feature = "as4"))]
pub(crate) fn redact_present(present: bool) -> &'static str {
    if present { "<redacted>" } else { "<none>" }
}

/// Constant-time byte-slice equality.
///
/// The single implementation in the crate: digest comparison, fingerprint pins
/// and shared-secret checks all route through it. Backed by
/// [`subtle::ConstantTimeEq`], which is written to survive the optimiser — a
/// hand-rolled XOR-accumulate loop is not, because nothing stops LLVM from
/// turning it back into an early-exit `memcmp`.
///
/// Length is compared first and therefore leaks: constant-time equality is
/// undefined for differing lengths, and in every use here the length is already
/// public (a digest's length is fixed by its algorithm; an `AuthorizationInfo`
/// value's length is visible on the wire).
#[must_use]
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
