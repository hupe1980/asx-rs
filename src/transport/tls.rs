//! The built-in client's TLS (D92): OpenSSL, because BDEW's transport is
//! BrainpoolP256r1 end to end and no other stack in reach speaks it.
//!
//! - **BDEW** (BDEW AS4-Profil 1.2 §2.2.6.1, §2.3.4.4; BSI TR-03116-3 §4):
//!   TLS ≥ 1.2, the ECDHE-ECDSA AES-GCM/CBC suites, ECDSA signature
//!   schemes only (Brainpool's RFC 8734 schemes in TLS 1.3), Brainpool groups first,
//!   the server chain verified against the builder's trust anchors (the
//!   SM-PKI root) and no wildcard host names (CP SM-PKI Anhang A.7.1).
//!   Brainpool in TLS 1.3 (RFC 8734) exists from OpenSSL 3.2; below that the
//!   policy caps at TLS 1.2, because a TLS 1.3 handshake with a Brainpool
//!   certificate has no signature scheme and fails instead of downgrading.
//! - **Every other profile**: TLS ≥ 1.2 with OpenSSL's defaults and the
//!   platform's roots.
//!
//! The client identity is loaded into the context here, at `build()`, so an
//! unusable key fails configuration rather than the first send.

use crate::keys::{Certificate, KeyPair};
use openssl::ssl::{SslConnector, SslMethod, SslVersion};
use openssl::x509::X509;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509CheckFlags;
use std::sync::OnceLock;

/// TR-03116-3 §4 (Tabelle 7): the TLS 1.2 suites for EC certificates.
const BDEW_TLS12_CIPHERS: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:\
                                  ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384";
/// TR-03116-3 §4 (TLS 1.3): the AES-GCM suites.
const BDEW_TLS13_SUITES: &str = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384";
/// TR-03116-3 §4 (Tabelle 8): Brainpool first, then the NIST curves.
const BDEW_GROUPS_TLS12: &str =
    "brainpoolP256r1:brainpoolP384r1:brainpoolP512r1:prime256v1:secp384r1";
/// TR-03116-3 §4 (Tabelle 11): the RFC 8734 TLS 1.3 Brainpool groups.
const BDEW_GROUPS_TLS13: &str = "brainpoolP256r1tls13:brainpoolP384r1tls13:brainpoolP512r1tls13";
/// TR-03116-3 §4 (Tabelle 15): the server-signature schemes. In TLS 1.2 the
/// `ecdsa_secp*` code points mean ECDSA with that hash on any offered curve,
/// so they cover Brainpool certificates there too.
const BDEW_SIGALGS_TLS12: &str =
    "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512";
/// TR-03116-3 §4 (Tabelle 15): the RFC 8734 Brainpool schemes for TLS 1.3.
const BDEW_SIGALGS_TLS13: &str = "ecdsa_brainpoolP256r1tls13_sha256:\
                                  ecdsa_brainpoolP384r1tls13_sha384:\
                                  ecdsa_brainpoolP512r1tls13_sha512";
/// OpenSSL 3.2.0: the first release with RFC 8734.
const OPENSSL_3_2: i64 = 0x3020_0000;
/// ALPN: HTTP/2, then HTTP/1.1 (RFC 7301 wire format).
const ALPN: &[u8] = b"\x02h2\x08http/1.1";

/// Which TLS rules a connection follows; chosen by the profile, never by
/// the peer.
#[derive(Clone)]
pub(crate) enum TlsPolicy {
    /// BDEW: TR-03116-3, trust only these anchors (the SM-PKI root).
    Bdew { anchors: Vec<Certificate> },
    /// Everything else: the platform's roots.
    Platform,
}

impl std::fmt::Debug for TlsPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsPolicy::Bdew { anchors } => f
                .debug_struct("Bdew")
                .field("anchors", &anchors.len())
                .finish(),
            TlsPolicy::Platform => f.write_str("Platform"),
        }
    }
}

impl TlsPolicy {
    /// Whether host names may be matched by a wildcard. SM-PKI certificates
    /// carry none (CP SM-PKI Anhang A.7.1: "Zertifikate DÜRFEN KEINE
    /// Wildcards im SubjectAltName enthalten").
    pub(crate) fn hostname_flags(&self) -> X509CheckFlags {
        match self {
            TlsPolicy::Bdew { .. } => X509CheckFlags::NO_WILDCARDS,
            TlsPolicy::Platform => X509CheckFlags::NO_PARTIAL_WILDCARDS,
        }
    }

    pub(crate) fn is_bdew(&self) -> bool {
        matches!(self, TlsPolicy::Bdew { .. })
    }
}

/// Whether the linked OpenSSL speaks Brainpool in TLS 1.3.
pub(crate) fn brainpool_tls13() -> bool {
    openssl::version::number() >= OPENSSL_3_2
}

/// The platform's trust roots, read once per process. Certificates the
/// platform store holds but OpenSSL cannot parse are skipped, as every
/// verifier does.
fn platform_roots() -> &'static [X509] {
    static ROOTS: OnceLock<Vec<X509>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        rustls_native_certs::load_native_certs()
            .certs
            .iter()
            .filter_map(|der| X509::from_der(der.as_ref()).ok())
            .collect()
    })
}

/// Build the connector for `policy`, presenting `identity` when the server
/// asks for a client certificate. `with_alpn` is off for revocation
/// fetches (HTTP/1.1 CDPs).
///
/// # Errors
///
/// A description for `Error::config`: the identity cannot be loaded (key
/// and certificate do not match, an unsupported key) or the policy cannot be
/// applied by the linked OpenSSL.
pub(crate) fn connector(
    policy: &TlsPolicy,
    identity: Option<&KeyPair>,
    with_alpn: bool,
) -> Result<SslConnector, String> {
    let ssl_err = |what: &str, err: openssl::error::ErrorStack| format!("{what}: {err}");
    let mut builder =
        SslConnector::builder(SslMethod::tls_client()).map_err(|e| ssl_err("TLS context", e))?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|e| ssl_err("minimum TLS version", e))?;

    let mut store = X509StoreBuilder::new().map_err(|e| ssl_err("trust store", e))?;
    match policy {
        TlsPolicy::Bdew { anchors } => {
            builder
                .set_cipher_list(BDEW_TLS12_CIPHERS)
                .map_err(|e| ssl_err("TR-03116-3 TLS 1.2 suites", e))?;
            builder
                .set_ciphersuites(BDEW_TLS13_SUITES)
                .map_err(|e| ssl_err("TR-03116-3 TLS 1.3 suites", e))?;
            let (groups, sigalgs) = if brainpool_tls13() {
                (
                    format!("{BDEW_GROUPS_TLS12}:{BDEW_GROUPS_TLS13}"),
                    format!("{BDEW_SIGALGS_TLS13}:{BDEW_SIGALGS_TLS12}"),
                )
            } else {
                builder
                    .set_max_proto_version(Some(SslVersion::TLS1_2))
                    .map_err(|e| ssl_err("maximum TLS version", e))?;
                (
                    BDEW_GROUPS_TLS12.to_string(),
                    BDEW_SIGALGS_TLS12.to_string(),
                )
            };
            builder
                .set_groups_list(&groups)
                .map_err(|e| ssl_err("TR-03116-3 groups", e))?;
            // "Andere Signaturalgorithmen … DÜRFEN NICHT … unterstützt
            // werden" (TR-03116-3 §4.3.2.1): no RSA, no EdDSA.
            builder
                .set_sigalgs_list(&sigalgs)
                .map_err(|e| ssl_err("TR-03116-3 signature algorithms", e))?;
            for anchor in anchors {
                store
                    .add_cert(anchor.x509().clone())
                    .map_err(|e| ssl_err("trust anchor", e))?;
            }
        }
        TlsPolicy::Platform => {
            for root in platform_roots() {
                // A duplicate in the platform store is not an error.
                let _ = store.add_cert(root.clone());
            }
        }
    }
    builder.set_cert_store(store.build());

    if with_alpn {
        builder
            .set_alpn_protos(ALPN)
            .map_err(|e| ssl_err("ALPN", e))?;
    }

    if let Some(identity) = identity {
        let chain = identity.chain();
        let leaf = chain.first().ok_or("the TLS identity has no certificate")?;
        builder
            .set_certificate(leaf.x509())
            .map_err(|e| ssl_err("TLS certificate", e))?;
        for intermediate in &chain[1..] {
            builder
                .add_extra_chain_cert(intermediate.x509().clone())
                .map_err(|e| ssl_err("TLS certificate chain", e))?;
        }
        builder
            .set_private_key(identity.private_key())
            .map_err(|e| ssl_err("TLS private key (unsupported by the linked OpenSSL)", e))?;
        builder
            .check_private_key()
            .map_err(|e| ssl_err("TLS private key does not match its certificate", e))?;
    }
    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bdew_policy_applies_on_the_linked_openssl() {
        // The cipher, suite and group strings must all be accepted: a name
        // the linked OpenSSL does not know fails here, not at a partner.
        let policy = TlsPolicy::Bdew {
            anchors: Vec::new(),
        };
        connector(&policy, None, true).expect("BDEW policy");
        connector(&TlsPolicy::Platform, None, true).expect("platform policy");
    }

    #[test]
    fn bdew_forbids_wildcards() {
        let bdew = TlsPolicy::Bdew {
            anchors: Vec::new(),
        };
        assert!(bdew.hostname_flags().contains(X509CheckFlags::NO_WILDCARDS));
        assert!(
            !TlsPolicy::Platform
                .hostname_flags()
                .contains(X509CheckFlags::NO_WILDCARDS)
        );
    }
}
