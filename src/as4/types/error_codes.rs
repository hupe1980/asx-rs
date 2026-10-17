//! ebMS3 error codes and severities.

/// AS4 error signal error codes per ebMS3 specification §6.7.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum As4ErrorCode {
    /// EBMS:0001 — Value not recognised.
    ValueNotRecognized,
    /// EBMS:0002 — Feature not supported.
    FeatureNotSupported,
    /// EBMS:0003 — Value inconsistent.
    ValueInconsistent,
    /// EBMS:0004 — Other.
    Other,
    /// EBMS:0301 — Missing receipt.
    MissingReceipt,
    /// EBMS:0302 — Invalid receipt.
    InvalidReceipt,
    /// EBMS:0303 — Decompression failure.
    DecompressionFailure,
}

impl As4ErrorCode {
    /// Returns the OASIS-defined `errorCode` attribute string, e.g. `"EBMS:0001"`.
    pub fn ebms_code(self) -> &'static str {
        match self {
            As4ErrorCode::ValueNotRecognized => "EBMS:0001",
            As4ErrorCode::FeatureNotSupported => "EBMS:0002",
            As4ErrorCode::ValueInconsistent => "EBMS:0003",
            As4ErrorCode::Other => "EBMS:0004",
            As4ErrorCode::MissingReceipt => "EBMS:0301",
            As4ErrorCode::InvalidReceipt => "EBMS:0302",
            As4ErrorCode::DecompressionFailure => "EBMS:0303",
        }
    }

    /// Map an `errorCode` attribute received from a counterparty back onto the
    /// modelled variants, or `None` for any code outside this subset.
    ///
    /// The ebMS3 registry is larger than what this crate generates; callers
    /// receiving an unmodelled code should keep the raw
    /// [`As4ReceivedError::error_code`](super::As4ReceivedError::error_code) string rather than discarding it.
    /// Matching is ASCII case-insensitive on the `EBMS:` prefix.
    pub fn from_ebms_code(code: &str) -> Option<Self> {
        let code = code.trim();
        let (prefix, digits) = code.split_at_checked(5)?;
        if !prefix.eq_ignore_ascii_case("EBMS:") {
            return None;
        }
        match digits {
            "0001" => Some(As4ErrorCode::ValueNotRecognized),
            "0002" => Some(As4ErrorCode::FeatureNotSupported),
            "0003" => Some(As4ErrorCode::ValueInconsistent),
            "0004" => Some(As4ErrorCode::Other),
            "0301" => Some(As4ErrorCode::MissingReceipt),
            "0302" => Some(As4ErrorCode::InvalidReceipt),
            "0303" => Some(As4ErrorCode::DecompressionFailure),
            _ => None,
        }
    }
}

/// Error severity for AS4 Error signal messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum As4ErrorSeverity {
    /// Processing must stop; the message cannot be delivered.
    Failure,
    /// Processing may continue but the sender should be aware.
    Warning,
}

impl As4ErrorSeverity {
    /// The `severity` attribute value written on outbound `eb:Error` signals.
    pub fn as_str(self) -> &'static str {
        match self {
            As4ErrorSeverity::Failure => "Failure",
            As4ErrorSeverity::Warning => "Warning",
        }
    }

    /// Parse a received `severity` attribute, ASCII case-insensitively.
    ///
    /// Returns `None` for any value outside the ebMS3 vocabulary; callers
    /// should treat an unrecognised severity as a failure rather than assuming
    /// it is benign.
    pub fn from_ebms_severity(severity: &str) -> Option<Self> {
        let severity = severity.trim();
        if severity.eq_ignore_ascii_case("failure") {
            Some(As4ErrorSeverity::Failure)
        } else if severity.eq_ignore_ascii_case("warning") {
            Some(As4ErrorSeverity::Warning)
        } else {
            None
        }
    }
}
