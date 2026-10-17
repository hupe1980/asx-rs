#![cfg(feature = "as4")]
//! Foreign witness for the revocation module:
//! on every static vector the module's accept/refuse decision under
//! `Profile::bdew()` equals `openssl verify -crl_check_all` on the same
//! certificates and CRLs. The 72 h fetch branch has no foreign
//! implementation (boundary tests are in `src/revocation/tests.rs`).
//!
//! Requires the `openssl` CLI; a missing CLI fails the
//! test loudly instead of skipping it.

use asx::__fuzz::revocation::decide;
use asx::Profile;
use asx_testkit::pki::{Cdp, Idp, IssueOptions, KeyAlg, KeyPair, TestCa};
use openssl::x509::{X509, X509Crl};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

const HOUR: Duration = Duration::from_secs(3600);
const INDIRECT: &str = "http://crl.oracle.example/root-indirect.crl";

fn der(pem: &[u8]) -> Vec<u8> {
    X509::from_pem(pem).unwrap().to_der().unwrap()
}

fn crl_pem(der: &[u8]) -> Vec<u8> {
    X509Crl::from_der(der).unwrap().to_pem().unwrap()
}

/// root → sub (CDP: the root's CRL, or the indirect root CRL) → leaf.
struct Vector {
    name: &'static str,
    root: TestCa,
    sub: TestCa,
    leaf: KeyPair,
    signer: Option<TestCa>,
    /// `(URL, DER)` of every CRL, as the CDPs name them.
    crls: Vec<(String, Vec<u8>)>,
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "asx-revocation-oracle-{}-{name}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &Path, file: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(file);
    std::fs::write(&path, bytes).unwrap();
    path
}

impl Vector {
    fn module_accepts(&self) -> bool {
        let path = vec![
            der(&self.leaf.cert_pem),
            der(self.sub.cert_pem()),
            der(self.root.cert_pem()),
        ];
        let signers: Vec<Vec<u8>> = self.signer.iter().map(|s| der(s.cert_pem())).collect();
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(decide(
                &Profile::bdew(),
                &path,
                &signers,
                self.crls.clone(),
                SystemTime::now(),
            ))
            .is_ok()
    }

    /// `openssl verify`'s decision and its output.
    fn openssl_accepts(&self) -> (bool, String) {
        let dir = scratch(self.name);
        let root = write(&dir, "root.pem", self.root.cert_pem());
        let mut untrusted = self.sub.cert_pem().to_vec();
        if let Some(signer) = &self.signer {
            untrusted.extend_from_slice(signer.cert_pem());
        }
        let untrusted = write(&dir, "untrusted.pem", &untrusted);
        let leaf = write(&dir, "leaf.pem", &self.leaf.cert_pem);
        let crls: Vec<u8> = self.crls.iter().flat_map(|(_, d)| crl_pem(d)).collect();
        let crls = write(&dir, "crls.pem", &crls);
        let mut command = Command::new("openssl");
        command
            .arg("verify")
            .arg("-crl_check_all")
            .arg("-CAfile")
            .arg(&root)
            .arg("-untrusted")
            .arg(&untrusted)
            .arg("-CRLfile")
            .arg(&crls);
        if self.signer.is_some() {
            command.arg("-extended_crl");
        }
        let output = command
            .arg(&leaf)
            .output()
            .expect("the openssl CLI is required for the revocation oracle");
        let _ = std::fs::remove_dir_all(&dir);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        (output.status.success(), text)
    }
}

fn vector(name: &'static str, indirect: bool) -> Vector {
    let root = TestCa::new(&format!("oracle root {name}"), KeyAlg::EcP256);
    let signer =
        indirect.then(|| root.crl_signer(&format!("oracle CCRL-S {name}"), KeyAlg::EcP256));
    let sub = match &signer {
        Some(signer) => root.sub_ca_with_options(
            &format!("oracle sub {name}"),
            KeyAlg::EcP256,
            IssueOptions {
                cdp: Cdp::Indirect {
                    uris: vec![INDIRECT.into()],
                    crl_issuer: signer.clone(),
                },
                ..IssueOptions::default()
            },
        ),
        None => root.sub_ca(&format!("oracle sub {name}"), KeyAlg::EcP256),
    };
    let leaf = sub.issue(&format!("oracle leaf {name}"), KeyAlg::EcP256);
    Vector {
        name,
        root,
        sub,
        leaf,
        signer,
        crls: Vec::new(),
    }
}

fn assert_agree(v: &Vector, expect_accept: bool) {
    let (module, (openssl, output)) = (v.module_accepts(), v.openssl_accepts());
    assert_eq!(
        module, openssl,
        "{}: module {module} vs openssl verify -crl_check_all {openssl}: {output}",
        v.name
    );
    assert_eq!(module, expect_accept, "{}", v.name);
}

#[test]
fn current_crls_listing_nothing_are_accepted_by_both() {
    let mut v = vector("good", false);
    v.crls = vec![
        (v.root.crl_url().into(), v.root.crl_builder().build()),
        (v.sub.crl_url().into(), v.sub.crl_builder().build()),
    ];
    assert_agree(&v, true);
}

#[test]
fn a_revoked_leaf_is_refused_by_both() {
    let mut v = vector("revoked-leaf", false);
    v.crls = vec![
        (v.root.crl_url().into(), v.root.crl_builder().build()),
        (
            v.sub.crl_url().into(),
            v.sub.crl_builder().revoke(&v.leaf).build(),
        ),
    ];
    assert_agree(&v, false);
}

#[test]
fn a_sub_ca_revoked_in_an_indirect_root_crl_is_refused_by_both() {
    let mut v = vector("revoked-sub-indirect", true);
    let signer = v.signer.clone().unwrap();
    let indirect = |revoked: bool| {
        let b = signer.crl_builder().idp(Idp {
            uris: vec![INDIRECT.into()],
            indirect: true,
            ..Idp::default()
        });
        if revoked {
            b.revoke_ca_issued_by(&v.sub, &v.root)
        } else {
            b
        }
        .build()
    };
    // OpenSSL also checks the CRL signer's own certificate (issued by the
    // root, no CDP) against a root-signed CRL, here one scoped to end-entity
    // certificates so the Sub-CA is judged by the indirect CRL alone; the
    // module trusts a configured signer and never fetches that CRL.
    let signer_crl = v
        .root
        .crl_builder()
        .idp(Idp {
            only_user_certs: true,
            ..Idp::default()
        })
        .build();
    v.crls = vec![
        (INDIRECT.into(), indirect(false)),
        (v.sub.crl_url().into(), v.sub.crl_builder().build()),
        (v.root.crl_url().into(), signer_crl),
    ];
    assert_agree(&v, true);
    v.crls[0].1 = indirect(true);
    assert_agree(&v, false);
}

#[test]
fn a_crl_with_a_bad_signature_is_refused_by_both() {
    let mut v = vector("bad-signature", false);
    let impostor = TestCa::new("oracle sub bad-signature", KeyAlg::EcP256);
    v.crls = vec![
        (v.root.crl_url().into(), v.root.crl_builder().build()),
        (v.sub.crl_url().into(), impostor.crl_builder().build()),
    ];
    assert_agree(&v, false);
}

#[test]
fn a_crl_past_next_update_is_refused_by_both() {
    let mut v = vector("expired-crl", false);
    let now = SystemTime::now();
    v.crls = vec![
        (v.root.crl_url().into(), v.root.crl_builder().build()),
        (
            v.sub.crl_url().into(),
            v.sub
                .crl_builder()
                .this_update(now - 72 * HOUR)
                .next_update(Some(now - 24 * HOUR))
                .build(),
        ),
    ];
    assert_agree(&v, false);
}
