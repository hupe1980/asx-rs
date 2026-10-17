//! The internal-error → `ErrorKind` mapping: one test per table row, driven
//! through the doc-hidden `asx::__mapping` hook.

use asx::__fuzz::ErrorCode;
use asx::__mapping::{backend, map, partner_ebms, partner_mdn};
use asx::ErrorKind;

#[track_caller]
fn assert_row(stage: &str, codes: &[ErrorCode], kind: ErrorKind, retryable: bool) {
    for code in codes {
        let err = map(stage, *code).unwrap_or_else(|| panic!("unknown stage {stage:?}"));
        assert_eq!(err.kind(), kind, "{stage} / {code:?}: {err}");
        assert_eq!(
            err.is_retryable(),
            retryable,
            "{stage} / {code:?}: is_retryable"
        );
    }
}

#[test]
fn unknown_stage_is_none() {
    assert!(map("no-such-stage", ErrorCode::InvalidInput).is_none());
}

/// build / send-validate → Config, not retryable.
#[test]
fn build_and_send_validate_is_config() {
    assert_row(
        "config",
        &[
            ErrorCode::InvalidInput,
            ErrorCode::PolicyViolation,
            ErrorCode::InteropViolation,
            ErrorCode::PayloadTooLarge,
            ErrorCode::NotFound,
            ErrorCode::CertificateExpired,
            ErrorCode::CertificateRevoked,
        ],
        ErrorKind::Config,
        false,
    );
}

/// sign / decrypt via an embedder trait → Backend, retryable.
#[test]
fn embedder_backend_failure_is_backend() {
    let err = backend();
    assert_eq!(err.kind(), ErrorKind::Backend);
    assert!(err.is_retryable());
}

/// Local admission (`crypto_permit`) → Transport, retryable, at any stage.
#[test]
fn capacity_exhausted_is_transport() {
    for stage in ["config", "http_not_written", "http_after_write", "inbound"] {
        assert_row(
            stage,
            &[ErrorCode::CapacityExhausted],
            ErrorKind::Transport,
            true,
        );
    }
}

/// HTTP, request not written → Transport, retryable.
#[test]
fn http_not_written_is_transport() {
    assert_row(
        "http_not_written",
        &[ErrorCode::TransportFailure],
        ErrorKind::Transport,
        true,
    );
}

/// HTTP, request not written, address-pin refusal → not retryable.
/// The mapping says kind `Transport`; the address pin is refused before
/// anything is sent, so only `is_retryable == false` is pinned here (see
/// `address_pin_refusal_kind`).
#[test]
fn address_pin_refusal_is_not_retryable() {
    for code in [ErrorCode::PolicyViolation, ErrorCode::InvalidInput] {
        let err = map("http_not_written", code).expect("stage");
        assert!(!err.is_retryable(), "{code:?}: {err}");
    }
}

/// The table row: address-pin refusal is `Transport` (not retryable).
#[test]
fn address_pin_refusal_kind() {
    let err = map("http_not_written", ErrorCode::PolicyViolation).expect("stage");
    assert_eq!(err.kind(), ErrorKind::Transport, "{err}");
}

/// HTTP after write (timeout, reset) → Indeterminate, retryable.
#[test]
fn http_after_write_is_indeterminate() {
    assert_row(
        "http_after_write",
        &[ErrorCode::Timeout, ErrorCode::TransportFailure],
        ErrorKind::Indeterminate,
        true,
    );
}

/// `eb:Error` → PartnerError; only EBMS:0202 is retryable.
#[test]
fn partner_ebms_error() {
    let err = partner_ebms("EBMS:0202");
    assert_eq!(err.kind(), ErrorKind::PartnerError);
    assert_eq!(err.ebms_code(), Some("EBMS:0202"));
    assert!(err.is_retryable());
    for code in ["EBMS:0004", "EBMS:0101", "EBMS:0102", "EBMS:0303"] {
        let err = partner_ebms(code);
        assert_eq!(err.kind(), ErrorKind::PartnerError);
        assert_eq!(err.ebms_code(), Some(code));
        assert!(!err.is_retryable(), "{code}");
    }
}

/// MDN `processed/error` or `failed` → PartnerError; only
/// `unexpected-processing-error` is retryable.
#[test]
fn partner_negative_mdn() {
    let retry = "processed/error: unexpected-processing-error";
    let err = partner_mdn(retry);
    assert_eq!(err.kind(), ErrorKind::PartnerError);
    assert_eq!(err.mdn_disposition(), Some(retry));
    assert!(err.is_retryable());
    for disposition in [
        "processed/error: decryption-failed",
        "processed/error: authentication-failed",
        "failed/failure: unsupported format",
    ] {
        let err = partner_mdn(disposition);
        assert_eq!(err.kind(), ErrorKind::PartnerError);
        assert_eq!(err.mdn_disposition(), Some(disposition));
        assert!(!err.is_retryable(), "{disposition}");
    }
}

const VERIFY_CODES: &[ErrorCode] = &[
    ErrorCode::SecurityVerificationFailed,
    ErrorCode::ParseFailed,
    ErrorCode::InteropViolation,
    ErrorCode::DecryptionFailed,
];

/// Receipt / MDN fails verification → Indeterminate, retryable.
#[test]
fn response_verification_failure_is_indeterminate() {
    assert_row(
        "response_verify",
        VERIFY_CODES,
        ErrorKind::Indeterminate,
        true,
    );
}

/// `verify_async_mdn`: not an MDN for this `PendingMdn` → Rejected.
#[test]
fn async_mdn_mismatch_is_rejected() {
    assert_row(
        "async_mdn_match",
        &[ErrorCode::ParseFailed, ErrorCode::InvalidInput],
        ErrorKind::Rejected,
        false,
    );
}

/// `verify_async_mdn`: the matching MDN fails verification → Indeterminate
/// (the response-verification stage).
#[test]
fn async_mdn_verification_failure_is_indeterminate() {
    assert_row(
        "response_verify",
        VERIFY_CODES,
        ErrorKind::Indeterminate,
        true,
    );
}

/// `Smp::lookup`: signature does not chain, ambiguous endpoint → Rejected.
#[test]
fn smp_untrusted_is_rejected() {
    assert_row(
        "smp_lookup",
        &[
            ErrorCode::SecurityVerificationFailed,
            ErrorCode::InteropViolation,
        ],
        ErrorKind::Rejected,
        false,
    );
}

/// `Smp::lookup`: DNS or HTTP failure → Transport, retryable.
#[test]
fn smp_network_failure_is_transport() {
    assert_row(
        "smp_lookup",
        &[ErrorCode::TransportFailure, ErrorCode::Timeout],
        ErrorKind::Transport,
        true,
    );
}

/// `Smp::lookup`: participant not registered → Config.
#[test]
fn smp_not_registered_is_config() {
    assert_row(
        "smp_lookup",
        &[ErrorCode::NotFound],
        ErrorKind::Config,
        false,
    );
}

/// `Certificate::from_pem`, `KeyPair::from_pem` → Config (through the hook
/// and through the real constructors).
#[test]
fn key_material_parse_failure_is_config() {
    assert_row(
        "config",
        &[ErrorCode::ParseFailed, ErrorCode::InvalidInput],
        ErrorKind::Config,
        false,
    );
    #[cfg(any(feature = "as2", feature = "as4"))]
    {
        let err = asx::Certificate::from_pem(b"not a certificate").expect_err("garbage");
        assert_eq!(err.kind(), ErrorKind::Config);
        assert!(!err.is_retryable());
        let err = asx::KeyPair::from_pem(b"not a chain", b"not a key").expect_err("garbage");
        assert_eq!(err.kind(), ErrorKind::Config);
        assert!(!err.is_retryable());
    }
}

/// An inbound message we refused → Rejected.
#[test]
fn inbound_refusal_is_rejected() {
    assert_row(
        "inbound",
        &[
            ErrorCode::SecurityVerificationFailed,
            ErrorCode::DecryptionFailed,
            ErrorCode::ParseFailed,
        ],
        ErrorKind::Rejected,
        false,
    );
}
