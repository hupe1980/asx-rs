//! OCSP (RFC 6960): the responder URLs a certificate names (RFC 5280
//! §4.2.2.1), the request, and the one response verifier —
//! responder signature and authorization (the issuer, or a responder it
//! delegated with `id-kp-OCSPSigning`), `CertID` binding and freshness, all
//! judged at the client clock's `now`.

use openssl::hash::MessageDigest;
use openssl::ocsp::OcspResponseStatus;
use openssl::ocsp::{OcspCertId, OcspCertStatus, OcspFlag, OcspRequest, OcspResponse};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyParam;
use openssl::x509::{X509, X509Ref};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The `id-ad-ocsp` URIs of the certificate's Authority Information Access
/// extension, read from the X.509 structure (`X509_get1_ocsp`) — never a
/// `caIssuers` or subject-alternative-name URI. `(fetchable, all)`: only
/// `http`/`https` URIs are fetched; `all` says whether the
/// certificate names a responder at all.
pub(crate) fn responders(cert: &X509Ref) -> (Vec<String>, usize) {
    let Ok(responders) = cert.ocsp_responders() else {
        return (Vec::new(), 0);
    };
    let mut urls: Vec<String> = Vec::new();
    let mut all = 0;
    for responder in &responders {
        all += 1;
        let url = responder.to_string();
        if super::crl::is_http(&url) && !urls.contains(&url) {
            urls.push(url);
        }
    }
    (urls, all)
}

/// One OCSP request: its DER and the `CertID` it asks about.
pub(crate) struct Request {
    pub(crate) der: Vec<u8>,
    /// The SHA-1 `CertID` (DER), the cache scope.
    pub(crate) cert_id: Vec<u8>,
}

/// A request for `cert` (issued by `issuer`) with a SHA-1 `CertID` (RFC 5019
/// §2.1.1: what responders index by) and no nonce, so responses are
/// cacheable.
pub(crate) fn request(cert: &X509Ref, issuer: &X509Ref) -> Result<Request, String> {
    let id =
        OcspCertId::from_cert(MessageDigest::sha1(), cert, issuer).map_err(|e| e.to_string())?;
    let mut req = OcspRequest::new().map_err(|e| e.to_string())?;
    req.add_id(id).map_err(|e| e.to_string())?;
    let der = req.to_der().map_err(|e| e.to_string())?;
    let cert_id = cert_id_der(cert, issuer)?;
    Ok(Request { der, cert_id })
}

/// The DER of the SHA-1 `CertID` (hash algorithm, issuer name hash, issuer
/// key hash, serial).
fn cert_id_der(cert: &X509Ref, issuer: &X509Ref) -> Result<Vec<u8>, String> {
    let name = issuer.subject_name().to_der().map_err(|e| e.to_string())?;
    let key = issuer.public_key().map_err(|e| e.to_string())?;
    let spki = key.public_key_to_der().map_err(|e| e.to_string())?;
    let serial = cert
        .serial_number()
        .to_bn()
        .map_err(|e| e.to_string())?
        .to_vec();
    let sha1 = |data: &[u8]| {
        openssl::hash::hash(MessageDigest::sha1(), data)
            .map(|d| d.to_vec())
            .map_err(|e| e.to_string())
    };
    let mut out = Vec::new();
    out.extend(sha1(&name)?);
    out.extend(sha1(&spki)?);
    out.extend(serial);
    Ok(out)
}

/// The status a verified response gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    Good,
    Revoked,
    Unknown,
}

/// A response that verified for one certificate.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Verified {
    pub(crate) status: Status,
    pub(crate) this_update: SystemTime,
    pub(crate) next_update: Option<SystemTime>,
}

/// Verify `der` as the answer about `cert` (issued by `issuer`): a
/// successful basic response, signed by the issuer or by a responder the
/// issuer authorized (OpenSSL `OCSP_basic_verify`, with the responder's path
/// built to `anchors` through `untrusted` at `now`), with a `SingleResponse`
/// for exactly this `CertID`, fresh at `now` ([`check_freshness`]).
pub(crate) fn verify(
    der: &[u8],
    cert: &X509Ref,
    issuer: &X509Ref,
    untrusted: &[X509],
    anchors: &[X509],
    now: SystemTime,
) -> Result<Verified, String> {
    let response =
        OcspResponse::from_der(der).map_err(|e| format!("unparseable OCSP response: {e}"))?;
    if response.status() != OcspResponseStatus::SUCCESSFUL {
        return Err(format!(
            "the responder answered status {:?}",
            response.status()
        ));
    }
    let basic = response.basic().map_err(|e| e.to_string())?;
    let mut store = X509StoreBuilder::new().map_err(|e| e.to_string())?;
    let mut param = X509VerifyParam::new().map_err(|e| e.to_string())?;
    param.set_time(crate::time_utils::unix_secs(now) as _);
    store.set_param(&param).map_err(|e| e.to_string())?;
    for anchor in anchors {
        store.add_cert(anchor.clone()).map_err(|e| e.to_string())?;
    }
    let store = store.build();
    let mut certs = Stack::new().map_err(|e| e.to_string())?;
    certs.push(issuer.to_owned()).map_err(|e| e.to_string())?;
    for cert in untrusted {
        certs.push(cert.clone()).map_err(|e| e.to_string())?;
    }
    basic
        .verify(&certs, &store, OcspFlag::empty())
        .map_err(|e| format!("the OCSP response signature or responder is not trusted: {e}"))?;
    let sha1 =
        OcspCertId::from_cert(MessageDigest::sha1(), cert, issuer).map_err(|e| e.to_string())?;
    let sha256 =
        OcspCertId::from_cert(MessageDigest::sha256(), cert, issuer).map_err(|e| e.to_string())?;
    let single = basic
        .find_status(&sha1)
        .or_else(|| basic.find_status(&sha256))
        .ok_or("the OCSP response has no status for this certificate")?;
    let read = |t: &openssl::asn1::Asn1GeneralizedTimeRef| {
        crate::time_utils::parse_openssl_print_time(&t.to_string())
            .map(|secs| UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64))
            .ok_or_else(|| format!("unreadable OCSP time {t}"))
    };
    check_freshness(single.this_update, single.next_update(), now)?;
    let status = if single.status == OcspCertStatus::GOOD {
        Status::Good
    } else if single.status == OcspCertStatus::REVOKED {
        Status::Revoked
    } else {
        Status::Unknown
    };
    Ok(Verified {
        status,
        this_update: read(single.this_update)?,
        next_update: single.next_update().map(read).transpose()?,
    })
}

/// Tolerated clock skew and maximum age of an OCSP response, as OpenSSL's
/// `OCSP_check_validity(resp, 300, 86400)` (RFC 6960 §4.2.2.1, §3.2 item 6).
const SKEW_SECS: i64 = 300;
const MAX_AGE_SECS: i64 = 86_400;

/// `thisUpdate`/`nextUpdate` freshness of one single response at `now`
/// (the client clock's).
pub(crate) fn check_freshness(
    this_update: &openssl::asn1::Asn1GeneralizedTimeRef,
    next_update: Option<&openssl::asn1::Asn1GeneralizedTimeRef>,
    now: SystemTime,
) -> Result<(), String> {
    let read = |t: &openssl::asn1::Asn1GeneralizedTimeRef, what: &str| {
        crate::time_utils::parse_openssl_print_time(&t.to_string())
            .ok_or_else(|| format!("unreadable {what} {t}"))
    };
    let now = crate::time_utils::unix_secs(now);
    let this = read(this_update, "thisUpdate")?;
    if this > now + SKEW_SECS {
        return Err("status not yet valid (thisUpdate in the future)".into());
    }
    if this < now - MAX_AGE_SECS {
        return Err("status too old (thisUpdate older than 24 h)".into());
    }
    if let Some(next_update) = next_update {
        let next = read(next_update, "nextUpdate")?;
        if next < now - SKEW_SECS {
            return Err("status expired (nextUpdate in the past)".into());
        }
        if next < this {
            return Err("nextUpdate before thisUpdate".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use asx_testkit::pki::{IssueOptions, KeyAlg, TestCa};
    use openssl::asn1::Asn1GeneralizedTime;

    const NOW: u64 = 1_780_000_000;

    fn at(offset: i64) -> Asn1GeneralizedTime {
        let t = UNIX_EPOCH + Duration::from_secs(NOW.saturating_add_signed(offset));
        let rfc = crate::time_utils::format_rfc3339_secs(t);
        let compact: String = rfc.chars().filter(char::is_ascii_digit).collect();
        Asn1GeneralizedTime::from_str(&format!("{compact}Z")).unwrap()
    }

    fn fixed_now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(NOW)
    }

    #[test]
    fn freshness_is_judged_at_the_given_instant() {
        let fresh = check_freshness(&at(-60), Some(&at(3600)), fixed_now());
        assert_eq!(fresh, Ok(()));
        assert_eq!(check_freshness(&at(-60), None, fixed_now()), Ok(()));
        assert_eq!(
            check_freshness(&at(299), Some(&at(3600)), fixed_now()),
            Ok(())
        );
        assert_eq!(
            check_freshness(&at(-3600), Some(&at(-299)), fixed_now()),
            Ok(())
        );
        let err = |this, next: Option<i64>| {
            check_freshness(&at(this), next.map(at).as_deref(), fixed_now()).unwrap_err()
        };
        assert!(err(301, Some(3600)).contains("not yet valid"));
        assert!(err(-86_401, None).contains("too old"));
        assert!(err(-3600, Some(-301)).contains("expired"));
        assert!(err(0, Some(-1)).contains("before thisUpdate"));
        let later = fixed_now() + Duration::from_secs(3600 + 301);
        assert!(check_freshness(&at(-60), Some(&at(3600)), later).is_err());
    }

    fn x509(pem: &[u8]) -> X509 {
        X509::from_pem(pem).unwrap()
    }

    #[test]
    fn responder_urls_come_from_aia_only_and_ldap_is_not_fetched() {
        let ca = TestCa::new("aia ca", KeyAlg::EcP256);
        let leaf = ca.issue_with_options(
            "aia leaf",
            KeyAlg::EcP256,
            IssueOptions {
                ocsp: vec![
                    "ldap://dir.example/ocsp".into(),
                    "http://ocsp.example/".into(),
                ],
                ..IssueOptions::default()
            },
        );
        let (urls, all) = responders(&x509(&leaf.cert_pem));
        assert_eq!(urls, vec!["http://ocsp.example/".to_string()]);
        assert_eq!(all, 2);
        let plain = ca.issue("no aia", KeyAlg::EcP256);
        assert_eq!(responders(&x509(&plain.cert_pem)), (Vec::new(), 0));
    }

    #[test]
    fn a_response_is_verified_for_signature_cert_id_and_freshness() {
        let ca = TestCa::new("ocsp ca", KeyAlg::EcP256);
        let leaf = ca.issue("ocsp leaf", KeyAlg::EcP256);
        let other = ca.issue("other leaf", KeyAlg::EcP256);
        let (cert, issuer) = (x509(&leaf.cert_pem), x509(ca.cert_pem()));
        let now = crate::clock::system().now();
        let hour = Duration::from_secs(3600);
        let anchors = [issuer.clone()];
        let good = ca.ocsp(&leaf, false, now - hour, now + hour);
        let v = verify(&good, &cert, &issuer, &[], &anchors, now).expect("good");
        assert_eq!(v.status, Status::Good);
        let revoked = ca.ocsp(&leaf, true, now - hour, now + hour);
        assert_eq!(
            verify(&revoked, &cert, &issuer, &[], &anchors, now)
                .unwrap()
                .status,
            Status::Revoked
        );
        // Another certificate's response.
        let foreign = ca.ocsp(&other, false, now - hour, now + hour);
        assert!(verify(&foreign, &cert, &issuer, &[], &anchors, now).is_err());
        // Stale at a later instant (the client clock, not the system one).
        assert!(verify(&good, &cert, &issuer, &[], &anchors, now + 2 * hour).is_err());
        // Signed by another CA.
        let stranger = TestCa::new("ocsp ca", KeyAlg::EcP256);
        let forged = stranger.ocsp(
            &stranger.issue("x", KeyAlg::EcP256),
            false,
            now - hour,
            now + hour,
        );
        assert!(verify(&forged, &cert, &issuer, &[], &anchors, now).is_err());
        // The request names the same CertID.
        let req = request(&cert, &issuer).unwrap();
        assert!(!req.der.is_empty() && req.cert_id.len() > 40);
    }
}
