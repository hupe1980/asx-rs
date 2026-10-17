//! RFC 3394 AES Key Wrap on the vetted RustCrypto `aes-kw` implementation.

use aes_kw::{KeyInit, KwAes128, KwAes192, KwAes256};
use zeroize::Zeroizing;

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::crypto::alg::KeyWrapAlg;

fn failure(detail: &str) -> AsxError {
    AsxError::new(
        ErrorCode::DecryptionFailed,
        format!("AES key wrap: {detail}"),
        ErrorContext::new("wssec_aes_kw"),
    )
}

fn kek_length(alg: KeyWrapAlg, kek: &[u8]) -> Result<()> {
    if kek.len() == alg.kek_len() {
        Ok(())
    } else {
        Err(failure("KEK length does not match the declared key wrap"))
    }
}

/// Wrap `cek` under `kek` (`alg` fixes the KEK length).
pub(crate) fn wrap(alg: KeyWrapAlg, kek: &[u8], cek: &[u8]) -> Result<Vec<u8>> {
    kek_length(alg, kek)?;
    let mut out = vec![0u8; cek.len() + aes_kw::IV_LEN];
    let len = match alg {
        KeyWrapAlg::Aes128 => KwAes128::new_from_slice(kek)
            .map_err(|_| failure("bad KEK"))?
            .wrap_key(cek, &mut out)
            .map(<[u8]>::len),
        KeyWrapAlg::Aes192 => KwAes192::new_from_slice(kek)
            .map_err(|_| failure("bad KEK"))?
            .wrap_key(cek, &mut out)
            .map(<[u8]>::len),
        KeyWrapAlg::Aes256 => KwAes256::new_from_slice(kek)
            .map_err(|_| failure("bad KEK"))?
            .wrap_key(cek, &mut out)
            .map(<[u8]>::len),
    }
    .map_err(|_| failure("the key to wrap is not a multiple of 8 octets"))?;
    out.truncate(len);
    Ok(out)
}

/// Unwrap `wrapped` under `kek`; the RFC 3394 integrity value is checked.
pub(crate) fn unwrap(alg: KeyWrapAlg, kek: &[u8], wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    kek_length(alg, kek)?;
    if wrapped.len() < 2 * aes_kw::IV_LEN {
        return Err(failure("wrapped key too short"));
    }
    let mut out = Zeroizing::new(vec![0u8; wrapped.len()]);
    let len = match alg {
        KeyWrapAlg::Aes128 => KwAes128::new_from_slice(kek)
            .map_err(|_| failure("bad KEK"))?
            .unwrap_key(wrapped, &mut out)
            .map(<[u8]>::len),
        KeyWrapAlg::Aes192 => KwAes192::new_from_slice(kek)
            .map_err(|_| failure("bad KEK"))?
            .unwrap_key(wrapped, &mut out)
            .map(<[u8]>::len),
        KeyWrapAlg::Aes256 => KwAes256::new_from_slice(kek)
            .map_err(|_| failure("bad KEK"))?
            .unwrap_key(wrapped, &mut out)
            .map(<[u8]>::len),
    }
    .map_err(|_| failure("integrity check failed"))?;
    out.truncate(len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 3394 §4.1–4.6 test vectors.
    #[test]
    fn rfc3394_vectors_wrap_and_unwrap() {
        let kek128 = "000102030405060708090A0B0C0D0E0F";
        let kek192 = "000102030405060708090A0B0C0D0E0F1011121314151617";
        let kek256 = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
        let data128 = "00112233445566778899AABBCCDDEEFF";
        let data192 = "00112233445566778899AABBCCDDEEFF0001020304050607";
        let data256 = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F";
        let vectors = [
            // 4.1 Wrap 128 bits of Key Data with a 128-bit KEK
            (
                KeyWrapAlg::Aes128,
                kek128,
                data128,
                "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
            ),
            // 4.2 Wrap 128 bits of Key Data with a 192-bit KEK
            (
                KeyWrapAlg::Aes192,
                kek192,
                data128,
                "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
            ),
            // 4.3 Wrap 128 bits of Key Data with a 256-bit KEK
            (
                KeyWrapAlg::Aes256,
                kek256,
                data128,
                "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
            ),
            // 4.4 Wrap 192 bits of Key Data with a 192-bit KEK
            (
                KeyWrapAlg::Aes192,
                kek192,
                data192,
                "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
            ),
            // 4.5 Wrap 192 bits of Key Data with a 256-bit KEK
            (
                KeyWrapAlg::Aes256,
                kek256,
                data192,
                "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
            ),
            // 4.6 Wrap 256 bits of Key Data with a 256-bit KEK
            (
                KeyWrapAlg::Aes256,
                kek256,
                data256,
                "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
            ),
        ];
        for (alg, kek, data, wrapped) in vectors {
            let (kek, data, wrapped) = (hex(kek), hex(data), hex(wrapped));
            assert_eq!(wrap(alg, &kek, &data).unwrap(), wrapped, "{alg:?} wrap");
            assert_eq!(
                unwrap(alg, &kek, &wrapped).unwrap().as_slice(),
                data,
                "{alg:?} unwrap"
            );
        }
    }

    #[test]
    fn corrupted_integrity_fails_unwrap() {
        let kek = hex("000102030405060708090A0B0C0D0E0F");
        let mut wrapped = hex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
        wrapped[3] ^= 0x01;
        let err = unwrap(KeyWrapAlg::Aes128, &kek, &wrapped).unwrap_err();
        assert_eq!(err.code, ErrorCode::DecryptionFailed);
        assert!(
            unwrap(KeyWrapAlg::Aes256, &kek, &wrapped).is_err(),
            "wrong KEK length"
        );
    }
}
