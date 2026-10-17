//! CRLs (RFC 5280 §5): the distribution points a certificate
//! names, and the one CRL parser — `x509-parser` for the TBS, OpenSSL for
//! the signature. A CRL is parsed and its signature verified once per fetch
//! into a serial index ([`ParsedCrl`]); whether it covers a given
//! certificate and whether it is current are decided per check.

use openssl::x509::{X509Crl, X509Ref};
use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_parser::extensions::{DistributionPointName, GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;
use x509_parser::revocation_list::CertificateRevocationList;

/// One `DistributionPoint` of a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DistributionPoint {
    /// The `http`/`https` URIs of its `fullName`, in order.
    pub(crate) uris: Vec<String>,
    /// Every URI of its `fullName` (for the IDP name match).
    pub(crate) all_uris: Vec<String>,
    /// The `cRLIssuer` directory name (DER) of an indirect CRL.
    pub(crate) crl_issuer: Option<Vec<u8>>,
}

/// The certificate's `cRLDistributionPoints`; `None` when it has none.
pub(crate) fn distribution_points(
    cert: &X509Ref,
) -> Result<Option<Vec<DistributionPoint>>, String> {
    let der = cert.to_der().map_err(|e| e.to_string())?;
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(&der)
        .map_err(|e| format!("unparseable certificate: {e}"))?;
    for ext in parsed.extensions() {
        if let ParsedExtension::CRLDistributionPoints(points) = ext.parsed_extension() {
            let mut out = Vec::new();
            for point in points.iter() {
                let mut all = Vec::new();
                if let Some(DistributionPointName::FullName(names)) = &point.distribution_point {
                    for name in names {
                        if let GeneralName::URI(uri) = name {
                            all.push((*uri).to_string());
                        }
                    }
                }
                let crl_issuer = point.crl_issuer.as_ref().and_then(|names| {
                    names.iter().find_map(|n| match n {
                        GeneralName::DirectoryName(name) => Some(name.as_raw().to_vec()),
                        _ => None,
                    })
                });
                let uris = all.iter().filter(|u| is_http(u)).cloned().collect();
                out.push(DistributionPoint {
                    uris,
                    all_uris: all,
                    crl_issuer,
                });
            }
            return Ok(Some(out));
        }
    }
    Ok(None)
}

/// `http` or `https`: everything else (`ldap://`, `file:`) is
/// skipped.
pub(crate) fn is_http(uri: &str) -> bool {
    let lower = uri.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// What a check needs to know about the certificate it checks.
#[derive(Debug, Clone)]
pub(crate) struct Subject {
    /// The serial, without leading zero octets.
    pub(crate) serial: Vec<u8>,
    /// The issuer name, DER.
    pub(crate) issuer: Vec<u8>,
    pub(crate) is_ca: bool,
}

impl Subject {
    pub(crate) fn of(cert: &X509Ref) -> Result<Subject, String> {
        let der = cert.to_der().map_err(|e| e.to_string())?;
        let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(&der)
            .map_err(|e| format!("unparseable certificate: {e}"))?;
        let is_ca = parsed
            .basic_constraints()
            .ok()
            .flatten()
            .is_some_and(|bc| bc.value.ca);
        Ok(Subject {
            serial: trim(parsed.raw_serial()).to_vec(),
            issuer: parsed.issuer().as_raw().to_vec(),
            is_ca,
        })
    }
}

fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    &bytes[start..]
}

/// The `IssuingDistributionPoint` of a CRL.
#[derive(Debug, Clone, Default)]
struct Idp {
    /// `fullName` URIs; `None` when the IDP names no distribution point.
    uris: Option<Vec<String>>,
    /// A `nameRelativeToCRLIssuer`, which this module does not resolve.
    relative_name: bool,
    only_user: bool,
    only_ca: bool,
    only_some_reasons: bool,
    only_attribute: bool,
    indirect: bool,
}

/// A CRL whose structure and signature verified: what every later check
/// reads, without the DER being parsed again.
#[derive(Debug, Clone)]
pub(crate) struct ParsedCrl {
    pub(crate) this_update: SystemTime,
    pub(crate) next_update: Option<SystemTime>,
    idp: Option<Idp>,
    /// `(entry issuer name DER, serial)` of every entry: the CRL issuer, or
    /// the `CertificateIssuer` in force (RFC 5280 §5.3.3).
    revoked: BTreeSet<(Vec<u8>, Vec<u8>)>,
}

/// CRL extensions this module processes (RFC 5280 §5.2): authority key
/// identifier, issuer alternative name, CRL number, issuing distribution
/// point, freshest CRL (ignored; never critical). `DeltaCRLIndicator` is
/// known and refused.
const KNOWN_CRL_EXTENSIONS: &[&str] = &[
    "2.5.29.35",
    "2.5.29.18",
    "2.5.29.20",
    "2.5.29.28",
    "2.5.29.46",
];
const DELTA_CRL_INDICATOR: &str = "2.5.29.27";
/// Entry extensions (RFC 5280 §5.3): reason code, hold instruction code,
/// invalidity date, certificate issuer.
const KNOWN_ENTRY_EXTENSIONS: &[&str] = &["2.5.29.21", "2.5.29.23", "2.5.29.24", "2.5.29.29"];
const CERTIFICATE_ISSUER: &str = "2.5.29.29";

fn time(t: x509_parser::time::ASN1Time) -> SystemTime {
    let secs = t.timestamp();
    if secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(secs as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs())
    }
}

/// Parse `der` and verify it as a complete CRL signed by `signer` (the
/// issuing CA, or a configured CRL signer for an indirect CRL): signature,
/// issuer name, authority key identifier, the signer's `cRLSign` usage, no
/// delta indicator, no unknown critical extension, `nextUpdate` present
/// when `next_update_required` and not before `thisUpdate`. Time is not
/// judged here: see [`ParsedCrl::check_time`].
pub(crate) fn parse_and_verify(
    der: &[u8],
    signer: &X509Ref,
    next_update_required: bool,
) -> Result<ParsedCrl, String> {
    let openssl_crl = X509Crl::from_der(der).map_err(|e| format!("unparseable CRL: {e}"))?;
    let key = signer.public_key().map_err(|e| e.to_string())?;
    if !openssl_crl.verify(&key).unwrap_or(false) {
        return Err("the CRL signature does not verify with the issuing key".into());
    }
    let (rest, crl) =
        CertificateRevocationList::from_der(der).map_err(|e| format!("unparseable CRL: {e}"))?;
    if !rest.is_empty() {
        return Err("trailing bytes after the CRL".into());
    }
    let signer_der = signer.to_der().map_err(|e| e.to_string())?;
    let (_, signer_parsed) = x509_parser::certificate::X509Certificate::from_der(&signer_der)
        .map_err(|e| format!("unparseable CRL signer: {e}"))?;
    if crl.issuer().as_raw() != signer_parsed.subject().as_raw() {
        return Err("the CRL issuer is not the signing certificate's subject".into());
    }
    if let Ok(Some(usage)) = signer_parsed.key_usage()
        && !usage.value.crl_sign()
    {
        return Err("the CRL signer's keyUsage does not permit cRLSign".into());
    }
    let signer_ski = signer_parsed
        .extensions()
        .iter()
        .find_map(|e| match e.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0.to_vec()),
            _ => None,
        });

    let mut idp = None;
    for ext in crl.extensions() {
        let oid = ext.oid.to_id_string();
        if oid == DELTA_CRL_INDICATOR {
            return Err("a delta CRL is not a complete CRL".into());
        }
        match ext.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(aki) => {
                if let (Some(id), Some(ski)) = (&aki.key_identifier, &signer_ski)
                    && id.0 != ski.as_slice()
                {
                    return Err("the CRL's authority key identifier names another key".into());
                }
            }
            ParsedExtension::IssuingDistributionPoint(point) => {
                let mut parsed = Idp {
                    only_user: point.only_contains_user_certs,
                    only_ca: point.only_contains_ca_certs,
                    only_some_reasons: point.only_some_reasons.is_some(),
                    only_attribute: point.only_contains_attribute_certs,
                    indirect: point.indirect_crl,
                    ..Idp::default()
                };
                match &point.distribution_point {
                    Some(DistributionPointName::FullName(names)) => {
                        parsed.uris = Some(
                            names
                                .iter()
                                .filter_map(|n| match n {
                                    GeneralName::URI(u) => Some((*u).to_string()),
                                    _ => None,
                                })
                                .collect(),
                        );
                    }
                    Some(DistributionPointName::NameRelativeToCRLIssuer(_)) => {
                        parsed.relative_name = true;
                    }
                    None => {}
                }
                idp = Some(parsed);
            }
            ParsedExtension::ParseError { .. } if ext.critical => {
                return Err(format!("unparseable critical CRL extension {oid}"));
            }
            _ if ext.critical && !KNOWN_CRL_EXTENSIONS.contains(&oid.as_str()) => {
                return Err(format!("unknown critical CRL extension {oid}"));
            }
            _ => {}
        }
    }

    let this_update = time(crl.last_update());
    let next_update = crl.next_update().map(time);
    match next_update {
        None if next_update_required => {
            return Err("the CRL has no nextUpdate (BSI TR-03109-4 Anhang B)".into());
        }
        Some(next) if next < this_update => {
            return Err("the CRL's nextUpdate is before its thisUpdate".into());
        }
        _ => {}
    }

    let crl_issuer = crl.issuer().as_raw().to_vec();
    let mut entry_issuer = crl_issuer.clone();
    let mut revoked = BTreeSet::new();
    for entry in crl.iter_revoked_certificates() {
        for ext in entry.extensions() {
            let oid = ext.oid.to_id_string();
            if oid == CERTIFICATE_ISSUER {
                entry_issuer = certificate_issuer(ext.value)
                    .ok_or("an unreadable CertificateIssuer entry extension")?;
            } else if ext.critical && !KNOWN_ENTRY_EXTENSIONS.contains(&oid.as_str()) {
                return Err(format!("unknown critical CRL entry extension {oid}"));
            }
        }
        revoked.insert((entry_issuer.clone(), trim(entry.raw_serial()).to_vec()));
    }
    Ok(ParsedCrl {
        this_update,
        next_update,
        idp,
        revoked,
    })
}

/// The directory name of a `CertificateIssuer` value (`GeneralNames`).
fn certificate_issuer(value: &[u8]) -> Option<Vec<u8>> {
    // SEQUENCE header, then GeneralName entries.
    let (tag, content) = der_content(value)?;
    if tag != 0x30 {
        return None;
    }
    let mut rest = content;
    while !rest.is_empty() {
        let (next, name) = GeneralName::from_der(rest).ok()?;
        if let GeneralName::DirectoryName(name) = name {
            return Some(name.as_raw().to_vec());
        }
        rest = next;
    }
    None
}

/// `(tag, content)` of one DER TLV that spans all of `bytes`.
fn der_content(bytes: &[u8]) -> Option<(u8, &[u8])> {
    let (&tag, rest) = bytes.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | *b as usize);
        (len, &rest[n..])
    };
    (rest.len() == len).then_some((tag, rest))
}

/// Tolerated clock skew on a CRL's `thisUpdate`.
pub(crate) const THIS_UPDATE_SKEW: Duration = Duration::from_secs(300);

impl ParsedCrl {
    /// Whether this CRL's scope covers `subject`, found through `point`:
    /// an indirect CRL must say so, and an
    /// `IssuingDistributionPoint` must name the point and include the
    /// certificate's kind and every reason.
    pub(crate) fn covers(
        &self,
        subject: &Subject,
        point: &DistributionPoint,
    ) -> Result<(), String> {
        let indirect = point.crl_issuer.is_some();
        let Some(idp) = &self.idp else {
            if indirect {
                return Err("an indirect CRL without IssuingDistributionPoint.indirectCRL".into());
            }
            return Ok(());
        };
        if indirect && !idp.indirect {
            return Err("an indirect CRL without IssuingDistributionPoint.indirectCRL".into());
        }
        if idp.only_attribute {
            return Err("the CRL covers attribute certificates only".into());
        }
        if idp.only_user && subject.is_ca {
            return Err("the CRL covers end-entity certificates only".into());
        }
        if idp.only_ca && !subject.is_ca {
            return Err("the CRL covers CA certificates only".into());
        }
        if idp.only_some_reasons {
            return Err("the CRL covers some revocation reasons only".into());
        }
        if idp.relative_name {
            return Err("the CRL names its distribution point relative to its issuer".into());
        }
        if let Some(uris) = &idp.uris
            && !uris.iter().any(|u| point.all_uris.contains(u))
        {
            return Err("the CRL's distribution point is not the certificate's".into());
        }
        Ok(())
    }

    /// `thisUpdate` at most [`THIS_UPDATE_SKEW`] ahead of `now`.
    pub(crate) fn check_time(&self, now: SystemTime) -> Result<(), String> {
        if self.this_update > now + THIS_UPDATE_SKEW {
            return Err("the CRL's thisUpdate is in the future".into());
        }
        Ok(())
    }

    /// Whether `subject` is listed (CertificateIssuer-aware).
    pub(crate) fn lists(&self, subject: &Subject) -> bool {
        self.revoked
            .contains(&(subject.issuer.clone(), subject.serial.clone()))
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.revoked.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asx_testkit::pki::{Cdp, Idp as TkIdp, IssueOptions, KeyAlg, TestCa};
    use openssl::x509::X509;

    fn x509(pem: &[u8]) -> X509 {
        X509::from_pem(pem).expect("certificate")
    }

    fn ca_x509(ca: &TestCa) -> X509 {
        x509(ca.cert_pem())
    }

    fn now() -> SystemTime {
        crate::clock::system().now()
    }

    fn point(ca: &TestCa) -> DistributionPoint {
        DistributionPoint {
            uris: vec![ca.crl_url().to_string()],
            all_uris: vec![ca.crl_url().to_string()],
            crl_issuer: None,
        }
    }

    #[test]
    fn distribution_points_are_read_in_order_and_ldap_is_skipped() {
        let ca = TestCa::new("dp root", KeyAlg::EcP256);
        let leaf = ca.issue_with_options(
            "dp leaf",
            KeyAlg::EcP256,
            IssueOptions {
                cdp: Cdp::Points(vec![
                    vec![
                        "ldap://dir.example/cn=ca".into(),
                        "http://a.example/1.crl".into(),
                    ],
                    vec!["https://b.example/2.crl".into()],
                ]),
                ..IssueOptions::default()
            },
        );
        let points = distribution_points(&x509(&leaf.cert_pem)).unwrap().unwrap();
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].uris, vec!["http://a.example/1.crl".to_string()]);
        assert_eq!(points[0].all_uris.len(), 2);
        assert_eq!(points[1].uris, vec!["https://b.example/2.crl".to_string()]);
        let none = ca.issue_with_options(
            "no dp",
            KeyAlg::EcP256,
            IssueOptions {
                cdp: Cdp::None,
                ..IssueOptions::default()
            },
        );
        assert_eq!(distribution_points(&x509(&none.cert_pem)).unwrap(), None);
    }

    #[test]
    fn a_crl_is_bound_to_the_issuing_key_not_the_name() {
        let ca = TestCa::new("changeover ca", KeyAlg::EcP256);
        let leaf = ca.issue("leaf", KeyAlg::EcP256);
        let crl = ca.crl_builder().revoke(&leaf).build();
        let parsed = parse_and_verify(&crl, &ca_x509(&ca), true).expect("valid");
        let subject = Subject::of(&x509(&leaf.cert_pem)).unwrap();
        assert!(parsed.lists(&subject));
        assert_eq!(parsed.len(), 1);
        // The same name, another key (TR-03109-4 §4.2.1.2 key changeover).
        let twin = TestCa::new("changeover ca", KeyAlg::EcP256);
        let err = parse_and_verify(&crl, &ca_x509(&twin), true).unwrap_err();
        assert!(err.contains("signature"), "{err}");
    }

    #[test]
    fn indirect_crl_from_a_crl_signer_lists_a_sub_ca_by_certificate_issuer() {
        let root = TestCa::new("sm root", KeyAlg::EcBrainpoolP256r1);
        let signer = root.crl_signer("CCRL-S(Root)", KeyAlg::EcBrainpoolP256r1);
        let sub = root.sub_ca_with_options(
            "sub ca",
            KeyAlg::EcBrainpoolP256r1,
            IssueOptions {
                cdp: Cdp::Indirect {
                    uris: vec!["http://crl.example/root.crl".into()],
                    crl_issuer: signer.clone(),
                },
                ..IssueOptions::default()
            },
        );
        let crl = signer
            .crl_builder()
            .revoke_ca_issued_by(&sub, &root)
            .idp(TkIdp {
                uris: vec!["http://crl.example/root.crl".into()],
                indirect: true,
                ..TkIdp::default()
            })
            .build();
        let sub_x509 = ca_x509(&sub);
        let points = distribution_points(&sub_x509).unwrap().unwrap();
        assert_eq!(
            points[0].crl_issuer.as_deref(),
            Some(&signer.name_der()[..])
        );
        let parsed = parse_and_verify(&crl, &ca_x509(&signer), true).expect("valid");
        parsed
            .covers(&Subject::of(&sub_x509).unwrap(), &points[0])
            .expect("covers the sub-CA");
        assert!(parsed.lists(&Subject::of(&sub_x509).unwrap()));
        // The root's key did not sign it.
        assert!(parse_and_verify(&crl, &ca_x509(&root), true).is_err());
        // Without indirectCRL in the IDP an entry's CertificateIssuer is
        // malformed (RFC 5280 §5.3.3): refused.
        let plain = signer
            .crl_builder()
            .revoke_ca_issued_by(&sub, &root)
            .build();
        assert!(parse_and_verify(&plain, &ca_x509(&signer), true).is_err());
    }

    #[test]
    fn delta_unknown_critical_and_missing_next_update_are_refused() {
        let ca = TestCa::new("ext ca", KeyAlg::EcP256);
        let signer = ca_x509(&ca);
        let leaf = ca.issue("leaf", KeyAlg::EcP256);
        let delta = ca.crl_builder().delta().build();
        assert!(
            parse_and_verify(&delta, &signer, false)
                .unwrap_err()
                .contains("delta")
        );
        let unknown = ca.crl_builder().unknown_critical_extension().build();
        assert!(
            parse_and_verify(&unknown, &signer, false)
                .unwrap_err()
                .contains("unknown critical CRL extension")
        );
        let unknown_entry = ca
            .crl_builder()
            .revoke(&leaf)
            .unknown_critical_entry_extension()
            .build();
        assert!(
            parse_and_verify(&unknown_entry, &signer, false)
                .unwrap_err()
                .contains("entry extension")
        );
        let open_ended = ca.crl_builder().next_update(None).build();
        assert!(
            parse_and_verify(&open_ended, &signer, true)
                .unwrap_err()
                .contains("nextUpdate")
        );
        parse_and_verify(&open_ended, &signer, false).expect("allowed outside bdew");
    }

    #[test]
    fn idp_scope_must_cover_the_certificate_both_ways() {
        let ca = TestCa::new("scope ca", KeyAlg::EcP256);
        let signer = ca_x509(&ca);
        let leaf = Subject::of(&x509(&ca.issue("leaf", KeyAlg::EcP256).cert_pem)).unwrap();
        let sub = Subject::of(&ca_x509(&ca.sub_ca("sub", KeyAlg::EcP256))).unwrap();
        assert!(leaf.serial.first() != Some(&0));
        let only = |idp: TkIdp| {
            parse_and_verify(&ca.crl_builder().idp(idp).build(), &signer, true).unwrap()
        };
        let users = only(TkIdp {
            only_user_certs: true,
            ..TkIdp::default()
        });
        assert!(users.covers(&leaf, &point(&ca)).is_ok());
        assert!(users.covers(&sub, &point(&ca)).is_err());
        let cas = only(TkIdp {
            only_ca_certs: true,
            ..TkIdp::default()
        });
        assert!(cas.covers(&sub, &point(&ca)).is_ok());
        assert!(cas.covers(&leaf, &point(&ca)).is_err());
        let reasons = only(TkIdp {
            only_some_reasons: true,
            ..TkIdp::default()
        });
        assert!(reasons.covers(&leaf, &point(&ca)).is_err());
        let elsewhere = only(TkIdp {
            uris: vec!["http://elsewhere.example/x.crl".into()],
            ..TkIdp::default()
        });
        assert!(elsewhere.covers(&leaf, &point(&ca)).is_err());
        let here = only(TkIdp {
            uris: vec![ca.crl_url().to_string()],
            ..TkIdp::default()
        });
        assert!(here.covers(&leaf, &point(&ca)).is_ok());
    }

    #[test]
    fn this_update_beyond_the_skew_is_refused() {
        let ca = TestCa::new("skew ca", KeyAlg::EcP256);
        let t = now();
        let crl = ca
            .crl_builder()
            .this_update(t + Duration::from_secs(600))
            .next_update(Some(t + Duration::from_secs(86_400)))
            .build();
        let parsed = parse_and_verify(&crl, &ca_x509(&ca), true).unwrap();
        assert!(parsed.check_time(t).is_err());
        assert!(parsed.check_time(t + Duration::from_secs(300)).is_ok());
        assert!(parsed.check_time(t + Duration::from_secs(299)).is_err());
    }
}
