#![cfg(feature = "as2")]
//! `Profile::as2()` × use site: send, receive and MDN verification read the
//! policy view resolved from the profile. The views are read through the
//! `#[doc(hidden)]` probe.

#[path = "common/as2_peers.rs"]
mod as2_peers;

use as2_peers::{B_URL, pair, pair_with};
use asx::Quirk;

fn view(seen: &[(&'static str, String)], site: &str) -> String {
    seen.iter()
        .find(|(s, _)| *s == site)
        .unwrap_or_else(|| panic!("{site} read no view: {seen:?}"))
        .1
        .clone()
}

#[tokio::test]
async fn every_as2_use_site_reads_the_resolved_view() {
    asx::__profile_probe::enable();
    // The probe is process-wide: run the two partners in one test.
    let _ = asx::__profile_probe::take();
    let p = pair();
    p.sender.send(p.message(b"x")).await.expect("verified MDN");
    let seen = asx::__profile_probe::take();

    let send = view(&seen, "as2.send");
    for expected in [
        "sign: true",
        "encrypt: true",
        "compress: false",
        "mic_algorithm: Sha256",
        "encryption_cipher: Aes256Cbc",
        &format!("as2_from_id: \"{}\"", as2_peers::A_ID),
    ] {
        assert!(send.contains(expected), "{expected}: {send}");
    }
    let receive = view(&seen, "as2.receive");
    for expected in [
        "require_signed: true",
        "require_encrypted: true",
        "mdn_signed: true",
        "detect_duplicates: true",
    ] {
        assert!(receive.contains(expected), "{expected}: {receive}");
    }
    let mdn = view(&seen, "as2.mdn_verify");
    for expected in [
        "require_signed_mdn: true",
        "mic_algorithm: Sha256",
        "require_mic: true",
        "bind_original_message_id: true",
        "pins: 1",
    ] {
        assert!(mdn.contains(expected), "{expected}: {mdn}");
    }

    // The partner's quirk reaches the MDN-verification view, and only it.
    let _ = asx::__profile_probe::take();
    let q = pair_with(
        |b| b.partner(B_URL).quirk(Quirk::UnsignedMdn),
        |a| a.partner(as2_peers::A_URL),
    );
    q.sender.send(q.message(b"x")).await.expect("verified MDN");
    let seen = asx::__profile_probe::take();
    let mdn = view(&seen, "as2.mdn_verify");
    assert!(mdn.contains("require_signed_mdn: false"), "{mdn}");
    let send = view(&seen, "as2.send");
    assert!(
        send.contains("sign: true") && send.contains("encrypt: true"),
        "{send}"
    );
}
