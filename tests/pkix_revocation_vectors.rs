#![cfg(feature = "as4")]

use asx_rs::core::{OcspFailureMode, OcspMode};
use asx_rs::crypto::wssec::{RevocationPolicy, validate_certificate_chain_with_revocation_vectors};

fn leaf_chain_der() -> Vec<Vec<u8>> {
    vec![
        include_bytes!("fixtures/pki/leaf.cert.der").to_vec(),
        include_bytes!("fixtures/pki/intermediate.cert.der").to_vec(),
    ]
}

fn root_anchor_pem() -> Vec<String> {
    vec![
        String::from_utf8(include_bytes!("fixtures/pki/root.cert.pem").to_vec())
            .expect("root pem utf8"),
    ]
}

#[test]
fn vector_positive_anchor_present_without_revocation_sources_passes() {
    let result = validate_certificate_chain_with_revocation_vectors(
        &leaf_chain_der(),
        &RevocationPolicy {
            trust_anchor_pems: &root_anchor_pem(),
            revocation_crl_pems: &[],
            ocsp_mode: OcspMode::Disabled,
            ocsp_failure_mode: OcspFailureMode::HardFail,
            stapled_ocsp_responses_der: &[],
            responder_ocsp_responses_der: &[],
            ocsp_cache_namespace: "tests",
            require_chain_validation: true,
            pre_parsed_trust_anchors: None,
            pre_built_x509_store: None,
        },
    );

    assert!(
        result.is_ok(),
        "expected PKIX chain to validate: {result:?}"
    );
}

#[test]
fn vector_negative_anchor_missing_fails_closed() {
    let err = validate_certificate_chain_with_revocation_vectors(
        &leaf_chain_der(),
        &RevocationPolicy {
            trust_anchor_pems: &[],
            revocation_crl_pems: &[],
            ocsp_mode: OcspMode::Disabled,
            ocsp_failure_mode: OcspFailureMode::HardFail,
            stapled_ocsp_responses_der: &[],
            responder_ocsp_responses_der: &[],
            ocsp_cache_namespace: "tests",
            require_chain_validation: true,
            pre_parsed_trust_anchors: None,
            pre_built_x509_store: None,
        },
    )
    .expect_err("missing trust anchors must fail");

    assert_eq!(err.code, asx_rs::ErrorCode::SecurityVerificationFailed);
}

#[test]
fn vector_negative_revoked_leaf_by_crl_fails() {
    let crls = vec![
        String::from_utf8(include_bytes!("fixtures/pki/intermediate.crl.pem").to_vec())
            .expect("intermediate crl pem utf8"),
    ];

    let err = validate_certificate_chain_with_revocation_vectors(
        &leaf_chain_der(),
        &RevocationPolicy {
            trust_anchor_pems: &root_anchor_pem(),
            revocation_crl_pems: &crls,
            ocsp_mode: OcspMode::Disabled,
            ocsp_failure_mode: OcspFailureMode::HardFail,
            stapled_ocsp_responses_der: &[],
            responder_ocsp_responses_der: &[],
            ocsp_cache_namespace: "tests",
            require_chain_validation: true,
            pre_parsed_trust_anchors: None,
            pre_built_x509_store: None,
        },
    )
    .expect_err("revoked leaf must fail");

    assert_eq!(err.code, asx_rs::ErrorCode::SecurityVerificationFailed);
}

#[test]
fn vector_negative_revoked_intermediate_by_crl_fails() {
    let crls = vec![
        String::from_utf8(include_bytes!("fixtures/pki/root.crl.pem").to_vec())
            .expect("root crl pem utf8"),
    ];

    let err = validate_certificate_chain_with_revocation_vectors(
        &leaf_chain_der(),
        &RevocationPolicy {
            trust_anchor_pems: &root_anchor_pem(),
            revocation_crl_pems: &crls,
            ocsp_mode: OcspMode::Disabled,
            ocsp_failure_mode: OcspFailureMode::HardFail,
            stapled_ocsp_responses_der: &[],
            responder_ocsp_responses_der: &[],
            ocsp_cache_namespace: "tests",
            require_chain_validation: true,
            pre_parsed_trust_anchors: None,
            pre_built_x509_store: None,
        },
    )
    .expect_err("revoked intermediate must fail");

    assert_eq!(err.code, asx_rs::ErrorCode::SecurityVerificationFailed);
}

#[test]
fn ocsp_policy_hard_fail_requires_usable_stapled_response() {
    let err = validate_certificate_chain_with_revocation_vectors(
        &leaf_chain_der(),
        &RevocationPolicy {
            trust_anchor_pems: &root_anchor_pem(),
            revocation_crl_pems: &[],
            ocsp_mode: OcspMode::StapledOnly,
            ocsp_failure_mode: OcspFailureMode::HardFail,
            stapled_ocsp_responses_der: &[],
            responder_ocsp_responses_der: &[],
            ocsp_cache_namespace: "tests",
            require_chain_validation: true,
            pre_parsed_trust_anchors: None,
            pre_built_x509_store: None,
        },
    )
    .expect_err("hard-fail OCSP policy must fail when no response is available");

    assert_eq!(err.code, asx_rs::ErrorCode::SecurityVerificationFailed);
}

#[test]
fn ocsp_policy_soft_fail_allows_missing_stapled_response() {
    let result = validate_certificate_chain_with_revocation_vectors(
        &leaf_chain_der(),
        &RevocationPolicy {
            trust_anchor_pems: &root_anchor_pem(),
            revocation_crl_pems: &[],
            ocsp_mode: OcspMode::StapledOnly,
            ocsp_failure_mode: OcspFailureMode::SoftFail,
            stapled_ocsp_responses_der: &[],
            responder_ocsp_responses_der: &[],
            ocsp_cache_namespace: "tests",
            require_chain_validation: true,
            pre_parsed_trust_anchors: None,
            pre_built_x509_store: None,
        },
    );

    assert!(
        result.is_ok(),
        "soft-fail OCSP should allow missing responses: {result:?}"
    );
}

#[test]
fn ocsp_stapled_mode_rejects_revoked_leaf() {
    let stapled = vec![include_bytes!("fixtures/pki/leaf_revoked.ocsp.der").to_vec()];

    let err = validate_certificate_chain_with_revocation_vectors(
        &leaf_chain_der(),
        &RevocationPolicy {
            trust_anchor_pems: &root_anchor_pem(),
            revocation_crl_pems: &[],
            ocsp_mode: OcspMode::StapledOnly,
            ocsp_failure_mode: OcspFailureMode::HardFail,
            stapled_ocsp_responses_der: &stapled,
            responder_ocsp_responses_der: &[],
            ocsp_cache_namespace: "tests",
            require_chain_validation: true,
            pre_parsed_trust_anchors: None,
            pre_built_x509_store: None,
        },
    )
    .expect_err("revoked OCSP stapled response must fail");

    assert_eq!(err.code, asx_rs::ErrorCode::SecurityVerificationFailed);
}

#[test]
fn ocsp_responder_mode_rejects_revoked_leaf() {
    let responder = vec![include_bytes!("fixtures/pki/leaf_revoked.ocsp.der").to_vec()];

    let err = validate_certificate_chain_with_revocation_vectors(
        &leaf_chain_der(),
        &RevocationPolicy {
            trust_anchor_pems: &root_anchor_pem(),
            revocation_crl_pems: &[],
            ocsp_mode: OcspMode::ResponderOnly,
            ocsp_failure_mode: OcspFailureMode::HardFail,
            stapled_ocsp_responses_der: &[],
            responder_ocsp_responses_der: &responder,
            ocsp_cache_namespace: "tests",
            require_chain_validation: true,
            pre_parsed_trust_anchors: None,
            pre_built_x509_store: None,
        },
    )
    .expect_err("revoked responder OCSP response must fail");

    assert_eq!(err.code, asx_rs::ErrorCode::SecurityVerificationFailed);
}

#[test]
fn ocsp_disabled_still_rejects_supplied_revoked_response() {
    let stapled = vec![include_bytes!("fixtures/pki/leaf_revoked.ocsp.der").to_vec()];

    let err = validate_certificate_chain_with_revocation_vectors(
        &leaf_chain_der(),
        &RevocationPolicy {
            trust_anchor_pems: &root_anchor_pem(),
            revocation_crl_pems: &[],
            ocsp_mode: OcspMode::Disabled,
            ocsp_failure_mode: OcspFailureMode::HardFail,
            stapled_ocsp_responses_der: &stapled,
            responder_ocsp_responses_der: &[],
            ocsp_cache_namespace: "tests",
            require_chain_validation: true,
            pre_parsed_trust_anchors: None,
            pre_built_x509_store: None,
        },
    )
    .expect_err("disabled OCSP mode must not ignore supplied revoked responses");

    assert_eq!(err.code, asx_rs::ErrorCode::SecurityVerificationFailed);
}
