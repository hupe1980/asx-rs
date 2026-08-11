//! Profile-derived spooling thresholds.

pub(super) fn as2_spool_threshold_for_profile(profile_name: &str) -> usize {
    match profile_name {
        "as2_default" => 1024 * 1024,
        "as4_openpeppol_strict" | "as4_cef_strict" => 512 * 1024,
        "as4_general_b2b" => 2 * 1024 * 1024,
        "bulk_or_archive_profile" => 8 * 1024 * 1024,
        _ => 1024 * 1024,
    }
}

pub(super) fn profile_requires_encrypted_spool(profile_name: &str) -> bool {
    matches!(
        profile_name,
        "as4_openpeppol_strict"
            | "as4_cef_strict"
            | "peppol-edelivery-as4-v2.0"
            | "bdew-marktkommunikation-as4-v1.1"
    )
}
