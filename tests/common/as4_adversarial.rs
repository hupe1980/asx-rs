#[inline]
#[cfg(feature = "as4")]
pub fn as4_strict_push_policy() -> asx_rs::as4::As4PushPolicy {
    asx_rs::as4::As4PushPolicyBuilder::new()
        .require_signed_receipt(true)
        .fail_closed_audit_events(false)
        .build()
        .expect("as4_strict_push_policy")
}

#[inline]
#[cfg(feature = "as4")]
pub fn as4_unsigned_push_policy() -> asx_rs::as4::As4PushPolicy {
    asx_rs::as4::As4PushPolicyBuilder::new()
        .allow_unsigned_push(true)
        .require_signed_receipt(true)
        .fail_closed_audit_events(false)
        .build()
        .expect("as4_unsigned_push_policy")
}
