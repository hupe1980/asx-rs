use super::*;

#[test]
fn error_code_strings_are_stable() {
    assert_eq!(ErrorCode::TransportFailure.as_str(), "transport_failure");
    assert_eq!(ErrorCode::InteropViolation.as_str(), "interop_violation");
}

#[test]
fn session_context_validation_rejects_empty_values() {
    assert!(SessionContext::new("", "p", "strict").is_err());
    assert!(SessionContext::new("s", "", "strict").is_err());
    assert!(SessionContext::new("s", "p", "").is_err());
}

#[test]
fn session_context_has_deterministic_default_handles() {
    let session = SessionContext::new("s1", "partner-a", "strict").expect("session");
    assert_eq!(session.cert_handle().key_id, "cert:partner-a");
    assert_eq!(session.correlation_scope().root_id, "corr:s1");
}

#[test]
fn session_context_builder_supports_incremental_configuration() {
    let cert = CertHandle {
        trust_anchor_pems: vec!["anchor-pem".into()],
        ..CertHandle::new("partner-key")
    };

    let session = SessionContext::builder("s-builder", "partner-z")
        .profile_name("peppol")
        .cert_handle(cert)
        .correlation_scope("corr-custom", Some("parent-1".into()))
        .build()
        .expect("builder session");

    assert_eq!(session.session_id(), "s-builder");
    assert_eq!(session.partner_id(), "partner-z");
    assert_eq!(session.profile_name(), "peppol");
    assert_eq!(session.cert_handle().key_id, "partner-key");
    assert_eq!(session.correlation_scope().root_id, "corr-custom");
    assert_eq!(
        session.correlation_scope().parent_message_id.as_deref(),
        Some("parent-1")
    );
}

#[test]
fn session_context_builder_rejects_blank_correlation_root() {
    let err = SessionContext::builder("s-builder", "partner-z")
        .correlation_scope("  ", None)
        .build()
        .expect_err("must reject blank correlation root");
    assert_eq!(err.code, ErrorCode::InvalidInput);
}

#[test]
fn cert_handle_new_has_expected_defaults() {
    let h = CertHandle::new("my-key");
    assert_eq!(h.key_id, "my-key");
    assert!(h.trust_anchor_pems.is_empty());
}

#[test]
fn cert_handle_struct_update_syntax_works() {
    let base = CertHandle::new("base-key");
    let updated = CertHandle {
        trust_anchor_pems: vec!["fake-pem".into()],
        ..base
    };
    assert_eq!(updated.key_id, "base-key");
    assert_eq!(updated.trust_anchor_pems, vec!["fake-pem".to_string()]);
}

#[test]
fn rotate_cert_handle_preserves_session_identity() {
    let mut session =
        SessionContext::new("rotate-session", "partner-b", "strict").expect("session");
    let original_session_id = session.session_id().to_string();
    let original_partner_id = session.partner_id().to_string();
    let original_root_id = session.correlation_scope().root_id.clone();

    let new_cert = CertHandle {
        trust_anchor_pems: vec!["new-anchor-pem".into()],
        ..CertHandle::new("new-key")
    };
    session.rotate_cert_handle(new_cert).expect("rotate");

    assert_eq!(session.session_id(), original_session_id);
    assert_eq!(session.partner_id(), original_partner_id);
    assert_eq!(session.correlation_scope().root_id, original_root_id);
    assert_eq!(session.cert_handle().key_id, "new-key");
    assert_eq!(
        session.cert_handle().trust_anchor_pems,
        vec!["new-anchor-pem".to_string()]
    );
}

#[test]
fn rotate_cert_handle_rejects_empty_key_id() {
    let mut session = SessionContext::new("s1", "p1", "strict").expect("session");
    let bad_cert = CertHandle::new("");
    assert!(session.rotate_cert_handle(bad_cert).is_err());
}

#[test]
fn arc_cert_handle_clone_shares_same_pointer() {
    let session = SessionContext::new("s1", "p1", "strict").expect("session");
    let clone = session.clone();
    // Both sessions share the same Arc<CertHandle> pointer — O(1) clone.
    assert!(Arc::ptr_eq(&session.cert_handle, &clone.cert_handle));
}

#[test]
#[cfg(any(feature = "as2", feature = "as4"))]
fn with_cert_handle_resets_trust_anchor_cache() {
    // Verify that replacing cert_handle on a session resets the caches so
    // the new anchor PEMs are parsed fresh on next access.
    let session = SessionContext::new("s-cache", "partner-cache", "strict").expect("session");
    // The initial session has empty trust_anchor_pems — caches default.
    assert!(session.trust_anchors_cache.0.get().is_none());

    let new_handle = CertHandle::new("partner-cache-cert");
    // with_cert_handle always installs a fresh default cache, irrespective
    // of what was in the provided CertHandle.
    let session = session.with_cert_handle(new_handle).expect("set handle");
    assert!(session.trust_anchors_cache.0.get().is_none());

    // Struct update syntax works: CertHandle has no private fields.
    let handle2 = CertHandle {
        trust_anchor_pems: vec!["some-pem".into()],
        ..CertHandle::new("partner-cache-cert-2")
    };
    let _ = session.with_cert_handle(handle2);
}

// ── builder convenience setters must derive key_id ────────────────────────

#[test]
fn builder_with_trust_anchor_pem_does_not_leave_empty_key_id() {
    // Any convenience builder setter should auto-derive key_id from partner_id,
    // so build() must not fail with "cert handle key_id must not be empty".
    let result = SessionContextBuilder::new("s1", "partner-xyz")
        .with_trust_anchor_pem("fake-pem")
        .build();
    assert!(result.is_ok(), "build() must not fail: {:?}", result);
    let session = result.unwrap();
    assert_eq!(
        session.cert_handle().key_id,
        "cert:partner-xyz",
        "key_id should be auto-derived from partner_id"
    );
}

#[test]
fn builder_with_signing_cert_and_key_pem_do_not_leave_empty_key_id() {
    // with_signing_cert_pem / with_signing_key_pem must not leave key_id
    // empty. No real PEM material here: only check that key_id is derived
    // from partner_id.
    let builder =
        SessionContextBuilder::new("s1", "partner-abc").with_signing_cert_pem("not-real-pem");
    assert_eq!(
        builder.cert_handle.as_ref().expect("handle").key_id,
        "cert:partner-abc",
    );
}

#[test]
fn builder_rejects_malformed_fingerprint() {
    let err = SessionContextBuilder::new("s1", "partner-fp")
        .with_fingerprint_sha256("aabbcc")
        .build()
        .expect_err("a malformed signer pin must be refused at build()");
    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert!(err.message.contains("malformed"), "{}", err.message);
}

#[test]
fn rotate_cert_handle_rejects_malformed_fingerprint() {
    let mut session = SessionContext::new("s1", "p1", "strict").expect("session");
    let err = session
        .rotate_cert_handle(CertHandle {
            fingerprint_sha256: "zz-not-a-pin".into(),
            ..CertHandle::new("k1")
        })
        .expect_err("a malformed signer pin must be refused on rotation");
    assert_eq!(err.code, ErrorCode::InvalidInput);
    let err = SessionContext::new("s2", "p1", "strict")
        .expect("session")
        .with_cert_handle(CertHandle {
            fingerprint_sha256: "aabbcc".into(),
            ..CertHandle::new("k1")
        })
        .expect_err("a malformed signer pin must be refused by with_cert_handle");
    assert_eq!(err.code, ErrorCode::InvalidInput);
}

#[test]
fn colon_separated_uppercase_fingerprint_is_accepted() {
    let pin = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:\
               AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
    let session = SessionContextBuilder::new("s1", "partner-fp")
        .with_fingerprint_sha256(pin)
        .build()
        .expect("a colon-separated upper-case pin is valid");
    assert_eq!(session.cert_handle().fingerprint_sha256, pin);
}

#[test]
fn builder_with_signing_material_sets_both_fields() {
    let builder = SessionContextBuilder::new("s1", "partner-mat")
        .with_signing_material("cert-pem-value", "key-pem-value");
    let ch = builder.cert_handle.as_ref().expect("handle");
    assert_eq!(ch.signing_cert_pem.as_deref(), Some("cert-pem-value"));
    assert!(ch.signing_key_pem.is_some());
    assert_eq!(
        ch.signing_key_pem.as_ref().map(|s| s.as_str()),
        Some("key-pem-value")
    );
}

#[test]
fn cert_handle_set_signing_key_pem_avoids_zeroize_dep() {
    let mut ch = CertHandle::new("key");
    ch.set_signing_key_pem("my-private-key");
    assert!(ch.signing_key_pem.is_some());
    assert_eq!(
        ch.signing_key_pem.as_ref().map(|s| s.as_str()),
        Some("my-private-key")
    );
}
