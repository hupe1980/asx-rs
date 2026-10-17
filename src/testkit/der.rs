//! A minimal DER writer (and the one reader step the OCSP `CertID` needs) for
//! the CRLs and OCSP responses the test CA signs. OpenSSL's Rust binding
//! builds neither, and the CLI cannot set `thisUpdate`.

use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(content);
    out
}

pub(crate) fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// `[n] EXPLICIT` (constructed context tag).
pub(crate) fn explicit(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, content)
}

pub(crate) fn small_int(value: u8) -> Vec<u8> {
    integer(&[value])
}

/// An INTEGER from big-endian magnitude bytes (non-negative).
pub(crate) fn integer(magnitude: &[u8]) -> Vec<u8> {
    let trimmed: Vec<u8> = magnitude.iter().copied().skip_while(|b| *b == 0).collect();
    let mut content = if trimmed.is_empty() { vec![0] } else { trimmed };
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    tlv(0x02, &content)
}

pub(crate) fn enumerated(value: u8) -> Vec<u8> {
    tlv(0x0a, &[value])
}

pub(crate) fn octets(bytes: &[u8]) -> Vec<u8> {
    tlv(0x04, bytes)
}

pub(crate) fn bits(bytes: &[u8]) -> Vec<u8> {
    let mut content = vec![0];
    content.extend_from_slice(bytes);
    tlv(0x03, &content)
}

pub(crate) const NULL: [u8; 2] = [0x05, 0x00];

/// An OBJECT IDENTIFIER from its encoded content bytes.
pub(crate) fn oid(content: &[u8]) -> Vec<u8> {
    tlv(0x06, content)
}

/// 1.3.14.3.2.26
pub(crate) const SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
/// 1.2.840.113549.1.1.11
pub(crate) const SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
/// 1.2.840.10045.4.3.2
pub(crate) const ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/// 2.5.29.21 id-ce-cRLReasons
pub(crate) const CRL_REASON: &[u8] = &[0x55, 0x1d, 0x15];
/// 2.5.29.20 id-ce-cRLNumber
pub(crate) const CRL_NUMBER: &[u8] = &[0x55, 0x1d, 0x14];
/// 2.5.29.35 id-ce-authorityKeyIdentifier
pub(crate) const AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1d, 0x23];
/// 1.3.6.1.5.5.7.48.1.1 id-pkix-ocsp-basic
pub(crate) const OCSP_BASIC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
/// 1.3.6.1.5.5.7.48.1 id-ad-ocsp
pub(crate) const AD_OCSP: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
/// 2.5.29.28 id-ce-issuingDistributionPoint
pub(crate) const ISSUING_DISTRIBUTION_POINT: &[u8] = &[0x55, 0x1d, 0x1c];
/// 2.5.29.27 id-ce-deltaCRLIndicator
pub(crate) const DELTA_CRL_INDICATOR: &[u8] = &[0x55, 0x1d, 0x1b];
/// 2.5.29.29 id-ce-certificateIssuer
pub(crate) const CERTIFICATE_ISSUER: &[u8] = &[0x55, 0x1d, 0x1d];
/// 1.3.6.1.4.1.55555.1 — a private arc no implementation knows.
pub(crate) const UNKNOWN_EXTENSION: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xb2, 0x03, 0x01];

/// One `Extension` (RFC 5280 §4.1): `extnID`, `critical` (only when true),
/// `extnValue`.
pub(crate) fn extension(oid_content: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut parts: Vec<Vec<u8>> = vec![oid(oid_content)];
    if critical {
        parts.push(vec![0x01, 0x01, 0xff]);
    }
    parts.push(octets(value));
    tlv(0x30, &parts.concat())
}

/// `GeneralNames` of `uniformResourceIdentifier [6]` entries, as the content
/// of an implicitly tagged `[tag]` (constructed).
fn uri_names(tag: u8, uris: &[String]) -> Vec<u8> {
    let names: Vec<u8> = uris.iter().flat_map(|u| tlv(0x86, u.as_bytes())).collect();
    tlv(tag, &names)
}

/// `GeneralNames` with one `directoryName [4]` (EXPLICIT Name).
pub(crate) fn directory_names(name_der: &[u8]) -> Vec<u8> {
    seq(&[&tlv(0xa4, name_der)])
}

/// `CRLDistributionPoints` (RFC 5280 §4.2.1.13): one `DistributionPoint`
/// per entry of `points`, each a `fullName` of URIs and, for an indirect
/// CRL, a `cRLIssuer` directory name.
pub(crate) fn crl_distribution_points(points: &[(Vec<String>, Option<Vec<u8>>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (uris, crl_issuer) in points {
        let mut dp = Vec::new();
        if !uris.is_empty() {
            // distributionPoint [0] { fullName [0] GeneralNames }
            dp.extend(tlv(0xa0, &uri_names(0xa0, uris)));
        }
        if let Some(name) = crl_issuer {
            // cRLIssuer [2] IMPLICIT GeneralNames
            dp.extend(tlv(0xa2, &tlv(0xa4, name)));
        }
        out.extend(tlv(0x30, &dp));
    }
    tlv(0x30, &out)
}

/// `AuthorityInfoAccessSyntax` with one `id-ad-ocsp` URI per entry.
pub(crate) fn authority_info_access(ocsp: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for uri in ocsp {
        out.extend(seq(&[&oid(AD_OCSP), &tlv(0x86, uri.as_bytes())]));
    }
    tlv(0x30, &out)
}

/// `IssuingDistributionPoint` (RFC 5280 §5.2.5).
pub(crate) fn issuing_distribution_point(
    uris: &[String],
    only_user: bool,
    only_ca: bool,
    only_some_reasons: bool,
    indirect: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    if !uris.is_empty() {
        out.extend(tlv(0xa0, &uri_names(0xa0, uris)));
    }
    if only_user {
        out.extend([0x81, 0x01, 0xff]);
    }
    if only_ca {
        out.extend([0x82, 0x01, 0xff]);
    }
    if only_some_reasons {
        // ReasonFlags { keyCompromise }
        out.extend([0x83, 0x02, 0x06, 0x40]);
    }
    if indirect {
        out.extend([0x84, 0x01, 0xff]);
    }
    tlv(0x30, &out)
}

/// `(year, month, day, hour, minute, second)` of `t` (UTC).
fn civil(t: SystemTime) -> (i64, u32, u32, u32, u32, u32) {
    let secs = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    };
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        month,
        day,
        (tod / 3600) as u32,
        ((tod % 3600) / 60) as u32,
        (tod % 60) as u32,
    )
}

pub(crate) fn generalized_time(t: SystemTime) -> Vec<u8> {
    let (y, mo, d, h, mi, s) = civil(t);
    tlv(
        0x18,
        format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z").as_bytes(),
    )
}

/// RFC 5280 §4.1.2.5 `Time`: UTCTime through 2049, GeneralizedTime after.
pub(crate) fn time(t: SystemTime) -> Vec<u8> {
    let (y, mo, d, h, mi, s) = civil(t);
    if (1950..2050).contains(&y) {
        tlv(
            0x17,
            format!("{:02}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z", y % 100).as_bytes(),
        )
    } else {
        generalized_time(t)
    }
}

/// The content of the BIT STRING of a DER `SubjectPublicKeyInfo` (without
/// the unused-bits octet): what an OCSP `issuerKeyHash` hashes.
pub(crate) fn spki_key_bits(spki: &[u8]) -> &[u8] {
    fn header(bytes: &[u8]) -> (usize, usize) {
        let first = bytes[1];
        if first < 0x80 {
            (2, first as usize)
        } else {
            let n = (first & 0x7f) as usize;
            let len = bytes[2..2 + n]
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | *b as usize);
            (2 + n, len)
        }
    }
    let (outer_head, _) = header(spki);
    let inner = &spki[outer_head..];
    let (alg_head, alg_len) = header(inner);
    let bit_string = &inner[alg_head + alg_len..];
    assert_eq!(
        bit_string[0], 0x03,
        "SubjectPublicKeyInfo without a BIT STRING"
    );
    let (bits_head, bits_len) = header(bit_string);
    &bit_string[bits_head + 1..bits_head + bits_len]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn lengths_use_the_short_and_long_forms() {
        assert_eq!(tlv(0x04, &[1, 2]), vec![0x04, 2, 1, 2]);
        let long = tlv(0x04, &[0u8; 300]);
        assert_eq!(&long[..4], &[0x04, 0x82, 0x01, 0x2c]);
    }

    #[test]
    fn integers_are_minimal_and_non_negative() {
        assert_eq!(integer(&[0, 0, 5]), vec![0x02, 1, 5]);
        assert_eq!(integer(&[0x80]), vec![0x02, 2, 0, 0x80]);
        assert_eq!(integer(&[]), vec![0x02, 1, 0]);
    }

    #[test]
    fn times_pick_utc_or_generalized() {
        let t = UNIX_EPOCH + Duration::from_secs(1_767_225_600); // 2026-01-01
        assert_eq!(time(t), tlv(0x17, b"260101000000Z"));
        assert_eq!(generalized_time(t), tlv(0x18, b"20260101000000Z"));
        let late = UNIX_EPOCH + Duration::from_secs(2_556_144_000); // 2051-01-01
        assert_eq!(time(late), tlv(0x18, b"20510101000000Z"));
    }
}
