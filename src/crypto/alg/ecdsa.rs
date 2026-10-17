//! ECDSA signature values: ASN.1 DER at the key seam, `r ‖ s` on the wire.
//!
//! XMLDSig 1.1 §6.4.3 (and RFC 9231 §2.3.6 for every `ecdsa-*` URI): the
//! `ds:SignatureValue` is `I2OSP(r, l) ‖ I2OSP(s, l)`, `l` the octet length of
//! the base-point order of the signer's curve — 32 on P-256 and
//! brainpoolP256r1, 48 on P-384, 66 on P-521. Key seams (OpenSSL, PKCS#11,
//! AWS/Azure/GCP KMS) return the DER `ECDSA-Sig-Value`; this module converts,
//! strictly, in both directions.

use openssl::bn::BigNum;
use openssl::ec::EcGroupRef;
use openssl::ecdsa::EcdsaSig;

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

/// Octet length `l` of the base-point order of `group`.
pub(crate) fn order_len(group: &EcGroupRef) -> usize {
    (group.order_bits() as usize).div_ceil(8)
}

fn malformed() -> AsxError {
    AsxError::new(
        ErrorCode::SecurityVerificationFailed,
        "signing key returned a malformed ECDSA signature: the key seam must return one \
         ASN.1 DER ECDSA-Sig-Value (SEQUENCE of two minimal non-negative INTEGERs)",
        ErrorContext::new("xmldsig_ecdsa_der_to_wire"),
    )
}

/// DER `ECDSA-Sig-Value` from a key seam → `r ‖ s` of `2·l` octets.
///
/// Strict: the input must re-encode to itself (one `SEQUENCE` of two minimal
/// `INTEGER`s, nothing trailing), both integers non-negative and at most `l`
/// octets. A seam that returns `r ‖ s` (or anything else) fails signing —
/// nothing is sent.
pub(crate) fn der_to_wire(der: &[u8], l: usize) -> Result<Vec<u8>> {
    let sig = EcdsaSig::from_der(der).map_err(|_| malformed())?;
    if sig.to_der().map_err(|_| malformed())? != der {
        return Err(malformed());
    }
    let (r, s) = (sig.r(), sig.s());
    if r.is_negative() || s.is_negative() {
        return Err(malformed());
    }
    let (r_len, s_len) = (r.num_bytes() as usize, s.num_bytes() as usize);
    if r_len > l || s_len > l {
        return Err(malformed());
    }
    let l_i32 = i32::try_from(l).map_err(|_| malformed())?;
    let mut wire = r.to_vec_padded(l_i32).map_err(|_| malformed())?;
    wire.extend_from_slice(&s.to_vec_padded(l_i32).map_err(|_| malformed())?);
    Ok(wire)
}

/// Wire `r ‖ s` → DER for OpenSSL's verifier. The value must be exactly
/// `2·l` octets; nothing else is read (DER is never parsed inbound).
pub(crate) fn wire_to_der(value: &[u8], l: usize) -> Result<Vec<u8>> {
    if value.len() != 2 * l {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!(
                "ECDSA SignatureValue is {} octets; {} required (r ‖ s, XMLDSig 1.1 §6.4.3)",
                value.len(),
                2 * l
            ),
            ErrorContext::new("xmldsig_ecdsa_wire_to_der"),
        ));
    }
    let to_err = |_| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "ECDSA SignatureValue could not be decoded",
            ErrorContext::new("xmldsig_ecdsa_wire_to_der"),
        )
    };
    let (r, s) = value.split_at(l);
    EcdsaSig::from_private_components(
        BigNum::from_slice(r).map_err(to_err)?,
        BigNum::from_slice(s).map_err(to_err)?,
    )
    .and_then(|sig| sig.to_der())
    .map_err(to_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::sign::Signer;

    fn der_int(bytes: &[u8]) -> Vec<u8> {
        let mut v = vec![0x02, bytes.len() as u8];
        v.extend_from_slice(bytes);
        v
    }

    fn der_seq(parts: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = parts.concat();
        let mut v = vec![0x30];
        if body.len() < 128 {
            v.push(body.len() as u8);
        } else {
            v.extend_from_slice(&[0x81, body.len() as u8]);
        }
        v.extend_from_slice(&body);
        v
    }

    #[test]
    fn order_lengths_follow_the_curve_not_the_hash() {
        for (nid, l) in [
            (Nid::X9_62_PRIME256V1, 32),
            (Nid::BRAINPOOL_P256R1, 32),
            (Nid::SECP384R1, 48),
            (Nid::BRAINPOOL_P384R1, 48),
            (Nid::BRAINPOOL_P512R1, 64),
            (Nid::SECP521R1, 66),
        ] {
            let group = EcGroup::from_curve_name(nid).unwrap();
            assert_eq!(order_len(&group), l, "{nid:?}");
        }
    }

    /// A 31-octet `r` is left-padded to 32; an `s` with its high bit set
    /// carries a DER sign octet that the wire form drops.
    #[test]
    fn short_r_and_high_bit_s_known_answer_p256() {
        let r: Vec<u8> = (1..=31).collect();
        let s: Vec<u8> = (0..32).map(|i| 0x80 | i).collect();
        let mut s_der = vec![0x00];
        s_der.extend_from_slice(&s);
        let der = der_seq(&[der_int(&r), der_int(&s_der)]);

        let wire = der_to_wire(&der, 32).unwrap();
        assert_eq!(wire.len(), 64);
        assert_eq!(wire[0], 0x00, "r is left-padded to l");
        assert_eq!(&wire[1..32], r.as_slice());
        assert_eq!(&wire[32..], s.as_slice(), "no DER sign octet on the wire");
        assert_eq!(wire_to_der(&wire, 32).unwrap(), der);
    }

    #[test]
    fn p521_width_is_66() {
        let r = vec![0x01; 66];
        let s = vec![0x01; 65];
        let der = der_seq(&[der_int(&r), der_int(&s)]);
        let wire = der_to_wire(&der, 66).unwrap();
        assert_eq!(wire.len(), 132);
        assert_eq!(&wire[..66], r.as_slice());
        assert_eq!(wire[66], 0x00);
    }

    #[test]
    fn der_wire_der_identity_for_openssl_signatures() {
        for nid in [
            Nid::X9_62_PRIME256V1,
            Nid::BRAINPOOL_P256R1,
            Nid::SECP384R1,
            Nid::SECP521R1,
            Nid::BRAINPOOL_P384R1,
            Nid::BRAINPOOL_P512R1,
        ] {
            let group = EcGroup::from_curve_name(nid).unwrap();
            let l = order_len(&group);
            let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
            for i in 0u32..200 {
                let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
                signer.update(&i.to_be_bytes()).unwrap();
                let der = signer.sign_to_vec().unwrap();
                let wire = der_to_wire(&der, l).unwrap();
                assert_eq!(wire.len(), 2 * l, "{nid:?}");
                assert_eq!(wire_to_der(&wire, l).unwrap(), der, "{nid:?} #{i}");
            }
        }
    }

    #[test]
    fn malformed_der_is_rejected() {
        let good = der_seq(&[der_int(&[0x01; 32]), der_int(&[0x02; 32])]);
        assert!(der_to_wire(&good, 32).is_ok());

        let mut trailing = good.clone();
        trailing.push(0x00);
        let non_minimal = der_seq(&[der_int(&[0x00, 0x01]), der_int(&[0x02; 32])]);
        let negative = der_seq(&[der_int(&[0x81; 32]), der_int(&[0x02; 32])]);
        let r_too_long = der_seq(&[der_int(&[0x01; 33]), der_int(&[0x02; 32])]);
        let raw_r_s = [0x01u8; 64].to_vec();
        for (name, bad) in [
            ("trailing octet", trailing),
            ("non-minimal INTEGER", non_minimal),
            ("negative INTEGER", negative),
            ("r longer than l", r_too_long),
            ("r ‖ s instead of DER", raw_r_s),
        ] {
            let err = der_to_wire(&bad, 32).expect_err(name);
            assert_eq!(err.code, ErrorCode::SecurityVerificationFailed, "{name}");
            assert!(
                err.message.contains("malformed ECDSA signature"),
                "{name}: {}",
                err.message
            );
        }
    }

    #[test]
    fn wrong_wire_lengths_are_rejected_naming_both_lengths() {
        for len in [63usize, 65, 0, 512] {
            let err = wire_to_der(&vec![0x01; len], 32).expect_err("wrong length");
            assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
            assert!(
                err.message.contains(&format!("{len} octets")) && err.message.contains("64"),
                "{len}: {}",
                err.message
            );
        }
    }
}
