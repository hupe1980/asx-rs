//! `example-pki [DIR]`: the files the golden-path examples read, issued by
//! the testkit: a BDEW pair under an SM-PKI-like root for the AS4 examples
//! and an AS2 pair for the AS2 example.

use asx_testkit::pki::TestCa;
use std::path::Path;

pub(crate) fn run(args: &[String]) -> Result<(), String> {
    let dir = Path::new(args.first().map(String::as_str).unwrap_or("examples/pki"));
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let write = |name: &str, bytes: &[u8]| {
        std::fs::write(dir.join(name), bytes).map_err(|e| format!("{name}: {e}"))
    };
    let sm_pki = TestCa::sm_pki();
    let me = sm_pki.bdew_party("9900000000001");
    let partner = sm_pki.bdew_party("9900000000002");
    write("sm-pki-root.crt", sm_pki.cert_pem())?;
    write("sig.crt", &me.signing.cert_pem)?;
    write("sig.key", &me.signing.key_pem)?;
    write("enc.crt", &me.encryption.cert_pem)?;
    write("enc.key", &me.encryption.key_pem)?;
    write("partner-sig.crt", &partner.signing.cert_pem)?;
    write("partner-enc.crt", &partner.encryption.cert_pem)?;
    write(
        "UTILMD.edi",
        b"UNA:+.? 'UNB+UNOC:3+9900000000001:500+9900000000002:500+261016:1200+1'",
    )?;
    let as2_ca = TestCa::new("asx example AS2 root", asx_testkit::pki::KeyAlg::Rsa2048);
    let ours = as2_ca.as2_party("OURAS2ID");
    let theirs = as2_ca.as2_party("THEIRAS2ID");
    write("ca.crt", as2_ca.cert_pem())?;
    write("me.crt", &ours.signing.cert_pem)?;
    write("me.key", &ours.signing.key_pem)?;
    write("partner.crt", &theirs.signing.cert_pem)?;
    write("po.x12", b"ISA*00*          *00*          *ZZ*OURAS2ID       *ZZ*THEIRAS2ID     *261016*1200*U*00401*000000001*0*T*>~")?;
    std::fs::create_dir_all(dir.join("inbox")).map_err(|e| e.to_string())?;
    println!("example PKI written to {}", dir.display());
    Ok(())
}
