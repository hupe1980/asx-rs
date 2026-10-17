//! ECDH-ES key agreement (XML Encryption 1.1 §5.6.4) with full originator
//! public-key validation (SP 800-56A r3 §5.6.2.3.3; XMLDSig 1.1 §4.5.2.3).

use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::pkey::PKey;
use zeroize::Zeroizing;

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::crypto::alg::NamedCurve;

fn rejected(curve: NamedCurve, reason: &str) -> AsxError {
    AsxError::new(
        ErrorCode::InteropViolation,
        format!("originator public key on {curve:?} rejected: {reason}"),
        ErrorContext::new("wssec_decrypt_payload"),
    )
}

/// Decode and validate the `dsig11:PublicKey` of the originator:
/// exactly `0x04 || X || Y` of `1 + 2·field_len` octets (XMLDSig 1.1 §4.5.2.3:
/// the uncompressed form), a point on `curve`, not the point at infinity, and
/// accepted by `EC_KEY_check_key` (on-curve, not infinity, `n·Q = O`).
pub(crate) fn validate_originator_point(
    curve: NamedCurve,
    encoded: &[u8],
) -> Result<(EcGroup, EcPoint)> {
    let expected = 1 + 2 * curve.field_len();
    match encoded.first() {
        None | Some(0x00) => return Err(rejected(curve, "the point at infinity")),
        Some(0x02 | 0x03) => {
            return Err(rejected(
                curve,
                "compressed point form (only the uncompressed 0x04 form is accepted)",
            ));
        }
        Some(0x04) => {}
        Some(other) => {
            return Err(rejected(
                curve,
                &format!("unknown point form 0x{other:02x}"),
            ));
        }
    }
    if encoded.len() != expected {
        return Err(rejected(
            curve,
            &format!("{} octets; {expected} required", encoded.len()),
        ));
    }
    let group =
        EcGroup::from_curve_name(curve.nid()).map_err(|_| rejected(curve, "curve unavailable"))?;
    let mut ctx = BigNumContext::new().map_err(|_| rejected(curve, "no BN context"))?;
    let point = EcPoint::from_bytes(&group, encoded, &mut ctx)
        .map_err(|_| rejected(curve, "not a point on the curve"))?;
    if point.is_infinity(&group) {
        return Err(rejected(curve, "the point at infinity"));
    }
    let key = EcKey::from_public_key(&group, &point)
        .map_err(|_| rejected(curve, "not a valid public key"))?;
    key.check_key()
        .map_err(|_| rejected(curve, "fails public-key validation"))?;
    Ok((group, point))
}

/// The ECDH shared secret `Z` of a private key and a validated peer point.
pub(crate) fn shared_secret(
    private: &PKey<openssl::pkey::Private>,
    group: &openssl::ec::EcGroupRef,
    peer: &openssl::ec::EcPointRef,
) -> Result<Zeroizing<Vec<u8>>> {
    let fail = || {
        AsxError::new(
            ErrorCode::DecryptionFailed,
            "ECDH key agreement failed",
            ErrorContext::new("wssec_ecdh"),
        )
    };
    let peer_key = EcKey::from_public_key(group, peer).map_err(|_| fail())?;
    let peer_key = PKey::from_ec_key(peer_key).map_err(|_| fail())?;
    let mut deriver = openssl::derive::Deriver::new(private).map_err(|_| fail())?;
    deriver.set_peer(&peer_key).map_err(|_| fail())?;
    deriver
        .derive_to_vec()
        .map(Zeroizing::new)
        .map_err(|_| fail())
}

/// A fresh ephemeral key on `group` and its uncompressed public point (the
/// originator side).
pub(crate) fn ephemeral(
    group: &openssl::ec::EcGroupRef,
) -> Result<(PKey<openssl::pkey::Private>, Vec<u8>)> {
    let fail = |what: &str| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("ephemeral EC key: {what}"),
            ErrorContext::new("wssec_encrypt_payload"),
        )
    };
    let key = EcKey::generate(group).map_err(|_| fail("generation failed"))?;
    let mut ctx = BigNumContext::new().map_err(|_| fail("no BN context"))?;
    let point = key
        .public_key()
        .to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .map_err(|_| fail("encoding failed"))?;
    let pkey = PKey::from_ec_key(key).map_err(|_| fail("wrapping failed"))?;
    Ok((pkey, point))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_point(curve: NamedCurve) -> Vec<u8> {
        let group = EcGroup::from_curve_name(curve.nid()).unwrap();
        ephemeral(&group).unwrap().1
    }

    fn assert_rejected(curve: NamedCurve, encoded: &[u8], needle: &str) {
        let Err(err) = validate_originator_point(curve, encoded) else {
            panic!("{needle}: the point was accepted");
        };
        assert_eq!(err.code, ErrorCode::InteropViolation);
        assert!(
            err.message.contains("originator public key") && err.message.contains(needle),
            "{}",
            err.message
        );
    }

    #[test]
    fn valid_point_accepted() {
        for curve in [NamedCurve::P256, NamedCurve::BrainpoolP256r1] {
            validate_originator_point(curve, &valid_point(curve)).expect("valid point");
        }
    }

    #[test]
    fn originator_point_infinity_rejected() {
        for curve in [NamedCurve::P256, NamedCurve::BrainpoolP256r1] {
            assert_rejected(curve, &[0x00], "infinity");
        }
    }

    #[test]
    fn originator_point_compressed_rejected() {
        for curve in [NamedCurve::P256, NamedCurve::BrainpoolP256r1] {
            let mut compressed = valid_point(curve)[..33].to_vec();
            compressed[0] = 0x02;
            assert_rejected(curve, &compressed, "compressed");
        }
    }

    #[test]
    fn originator_point_wrong_length_rejected() {
        for curve in [NamedCurve::P256, NamedCurve::BrainpoolP256r1] {
            let mut long = valid_point(curve);
            long.push(0x00);
            assert_rejected(curve, &long, "66 octets; 65 required");
            assert_rejected(curve, &valid_point(curve)[..64], "64 octets; 65 required");
        }
    }

    #[test]
    fn originator_point_off_curve_rejected() {
        for curve in [NamedCurve::P256, NamedCurve::BrainpoolP256r1] {
            let mut point = valid_point(curve);
            let last = point.len() - 1;
            point[last] ^= 0x01;
            assert_rejected(curve, &point, "point on the curve");
        }
    }
}
