#![cfg(feature = "as4")]
//! Preset × use site: every pipeline reads the policy view resolved from the
//! profile. The views are read through the
//! `#[doc(hidden)]` probe.

#[path = "common/peers.rs"]
mod peers;

use peers::{AS4_PRESETS, Preset, pair};

#[tokio::test]
async fn every_as4_use_site_reads_the_resolved_view() {
    asx::__profile_probe::enable();
    for preset in AS4_PRESETS {
        let _ = asx::__profile_probe::take();
        let p = pair(preset);
        p.sender
            .send(preset.message(&p.to_b, b"x"))
            .await
            .unwrap_or_else(|e| panic!("{preset:?}: {e}"));
        let seen = asx::__profile_probe::take();
        let view = |site: &str| -> String {
            seen.iter()
                .find(|(s, _)| *s == site)
                .unwrap_or_else(|| panic!("{preset:?}: {site} read no view"))
                .1
                .clone()
        };
        let send = view("as4.send");
        assert!(
            send.contains("sign: true") && send.contains("encrypt: true"),
            "{send}"
        );
        let token = if preset == Preset::Bdew {
            "X509PKIPathv1"
        } else {
            "BinarySecurityTokenX509v3"
        };
        assert!(send.contains(token), "{preset:?}: {send}");
        assert!(send.contains("compress: true"), "{preset:?}");
        let receive = view("as4.receive");
        assert!(receive.contains("require_signed_push: true"), "{receive}");
        assert!(
            receive.contains("require_encrypted_inbound: true"),
            "{receive}"
        );
        let receipt = view("as4.receipt_verify");
        assert!(
            receipt.contains("require_signed_receipt: true"),
            "{receipt}"
        );
        assert!(
            receipt.contains("require_non_repudiation: true"),
            "{receipt}"
        );
    }
}
