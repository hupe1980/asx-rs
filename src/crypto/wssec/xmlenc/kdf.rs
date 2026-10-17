//! ConcatKDF — the single-step Concatenation Key Derivation Function of NIST
//! SP 800-56A §5.8.1, as referenced by W3C XML Encryption 1.1 §5.4.1.
//!
//! ```text
//! K(i) = H( counter(4B BE) || Z || OtherInfo )
//! OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo || SuppPrivInfo
//! ```
//!
//! `OtherInfo` is the **raw concatenation** of the fixed-info bit strings —
//! no embedded `keydatalen` and no length prefixes (those belong to the JOSE
//! Concat KDF, RFC 7518 §4.6.2, a different scheme). Adding them derives a
//! KEK no conformant ECDH-ES peer (BDEW / BSI TR-03116-3 / eDelivery) could
//! reproduce.

use zeroize::Zeroizing;

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::crypto::wssec::WsSecDigestMethod;

/// The five `xenc11:ConcatKDFParams` fixed-info fields, decoded. All five
/// reach the derivation: dropping one silently yields a different KEK from
/// the peer's, which surfaces as an unexplained unwrap failure.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ConcatKdfParams {
    pub(crate) algorithm_id: Vec<u8>,
    pub(crate) party_u_info: Vec<u8>,
    pub(crate) party_v_info: Vec<u8>,
    pub(crate) supp_pub_info: Vec<u8>,
    pub(crate) supp_priv_info: Vec<u8>,
}

impl ConcatKdfParams {
    /// Read all five attributes off a `ConcatKDFParams` element.
    pub(crate) fn from_node(node: roxmltree::Node<'_, '_>) -> Result<Self> {
        let read = |name: &str| -> Result<Vec<u8>> {
            node.attribute(name).map_or(Ok(Vec::new()), |raw| {
                decode_concat_kdf_param_bits(raw.as_bytes())
            })
        };
        Ok(Self {
            algorithm_id: read("AlgorithmID")?,
            party_u_info: read("PartyUInfo")?,
            party_v_info: read("PartyVInfo")?,
            supp_pub_info: read("SuppPubInfo")?,
            supp_priv_info: read("SuppPrivInfo")?,
        })
    }

    fn other_info(&self) -> impl Iterator<Item = &[u8]> {
        [
            self.algorithm_id.as_slice(),
            self.party_u_info.as_slice(),
            self.party_v_info.as_slice(),
            self.supp_pub_info.as_slice(),
            self.supp_priv_info.as_slice(),
        ]
        .into_iter()
    }
}

/// Derive `keydatalen_bits / 8` octets of key material from the shared
/// secret `z` with the declared digest.
pub(crate) fn concat_kdf(
    digest: WsSecDigestMethod,
    z: &[u8],
    keydatalen_bits: u32,
    params: &ConcatKdfParams,
) -> Zeroizing<Vec<u8>> {
    let wanted = (keydatalen_bits as usize).div_ceil(8);
    let mut out = Zeroizing::new(Vec::with_capacity(wanted + digest.output_len()));
    let mut counter: u32 = 1;
    while out.len() < wanted {
        let mut hasher =
            openssl::hash::Hasher::new(digest.message_digest()).expect("digest is available");
        hasher.update(&counter.to_be_bytes()).expect("hash update");
        hasher.update(z).expect("hash update");
        for field in params.other_info() {
            hasher.update(field).expect("hash update");
        }
        let block = Zeroizing::new(hasher.finish().expect("hash finish").to_vec());
        out.extend_from_slice(&block);
        counter += 1;
    }
    out.truncate(wanted);
    out
}

/// Decode a `ConcatKDFParams` attribute value per XML Encryption 1.1 §5.4.1:
/// `xs:hexBinary` **bit strings** whose first octet is the number of padding
/// bits (W3C xmlenc-core1 Example 25: `AlgorithmID="0000"` is the 8-bit value
/// `00000000`); an empty attribute is the empty bit string. Only byte-aligned
/// values are accepted. Decoding it as base64 is the plausible reading and
/// the wrong one: hex characters are a subset of the base64 alphabet.
pub(crate) fn decode_concat_kdf_param_bits(raw: &[u8]) -> Result<Vec<u8>> {
    let trimmed: Vec<u8> = raw
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let invalid = |detail: String| {
        AsxError::new(
            ErrorCode::InteropViolation,
            format!("invalid ConcatKDFParams attribute: {detail}"),
            ErrorContext::new("wssec_decrypt_payload"),
        )
    };
    if !trimmed.len().is_multiple_of(2) {
        return Err(invalid(format!(
            "hexBinary value has odd length {}",
            trimmed.len()
        )));
    }
    let nibble = |b: u8| -> Result<u8> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            other => Err(invalid(format!(
                "non-hex character 0x{other:02x} in hexBinary value"
            ))),
        }
    };
    let mut octets = Vec::with_capacity(trimmed.len() / 2);
    for pair in trimmed.as_chunks::<2>().0 {
        octets.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    let padding_bits = octets[0];
    if padding_bits != 0 {
        return Err(invalid(format!(
            "bit strings with {padding_bits} padding bits are not supported \
             (only byte-aligned KDF parameters are accepted)"
        )));
    }
    octets.remove(0);
    Ok(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_kdf(z: &[u8], bits: u32, params: &ConcatKdfParams) -> Vec<u8> {
        concat_kdf(WsSecDigestMethod::Sha256, z, bits, params).to_vec()
    }

    fn hex_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn concat_kdf_params_decode_as_hex_binary_bit_strings() {
        assert_eq!(decode_concat_kdf_param_bits(b"").unwrap(), Vec::<u8>::new());
        assert_eq!(
            decode_concat_kdf_param_bits(b"  \t").unwrap(),
            Vec::<u8>::new()
        );
        assert_eq!(decode_concat_kdf_param_bits(b"0000").unwrap(), vec![0x00]);
        assert_eq!(
            decode_concat_kdf_param_bits(b"00A1b2C3").unwrap(),
            vec![0xA1, 0xB2, 0xC3]
        );
    }

    #[test]
    fn concat_kdf_params_reject_invalid_encodings() {
        assert!(decode_concat_kdf_param_bits(b"000").is_err());
        assert!(decode_concat_kdf_param_bits(b"AAA=").is_err());
        let err = decode_concat_kdf_param_bits(b"03D8").unwrap_err();
        assert!(err.message.contains("padding bits"), "{}", err.message);
    }

    /// With empty `ConcatKDFParams` (the AS4 default) `OtherInfo` is empty, so
    /// the KEK is `SHA-256(counter=1 || Z)[..keydatalen/8]`.
    #[test]
    fn concat_kdf_empty_otherinfo_matches_sp800_56a_single_step() {
        let z = b"\x01\x02\x03\x04\x05\x06\x07\x08 shared-secret bytes";
        let mut input = 1u32.to_be_bytes().to_vec();
        input.extend_from_slice(z);
        let expected = openssl::sha::sha256(&input);
        assert_eq!(sha256_kdf(z, 256, &ConcatKdfParams::default()), expected);
        assert_eq!(
            sha256_kdf(z, 128, &ConcatKdfParams::default()),
            expected[..16]
        );
    }

    /// Golden: the BDEW shape (`AlgorithmID="" PartyUInfo="" PartyVInfo=""`,
    /// SHA-256) for a fixed Z must derive the same KEK forever.
    #[test]
    fn concat_kdf_bdew_golden_is_unchanged() {
        let z: Vec<u8> = (0u8..32).collect();
        assert_eq!(
            hex_lower(&sha256_kdf(&z, 128, &ConcatKdfParams::default())),
            "22b288a146b89e364069f6f367618a0e",
            "aes128 KEK"
        );
        assert_eq!(
            hex_lower(&sha256_kdf(&z, 256, &ConcatKdfParams::default())),
            "22b288a146b89e364069f6f367618a0ebeb5b83e5462685ab127b8edf8d2690a",
            "aes256 KEK"
        );
    }

    #[test]
    fn concat_kdf_includes_the_supplementary_info_fields() {
        let z = b"shared-secret";
        let without = sha256_kdf(z, 128, &ConcatKdfParams::default());
        let with_pub = sha256_kdf(
            z,
            128,
            &ConcatKdfParams {
                supp_pub_info: b"\x00\x00\x00\x80".to_vec(),
                ..ConcatKdfParams::default()
            },
        );
        let with_priv = sha256_kdf(
            z,
            128,
            &ConcatKdfParams {
                supp_priv_info: b"\x00\x00\x00\x80".to_vec(),
                ..ConcatKdfParams::default()
            },
        );
        assert_ne!(without, with_pub);
        assert_ne!(without, with_priv);
        let a = sha256_kdf(
            z,
            128,
            &ConcatKdfParams {
                supp_pub_info: b"AAA".to_vec(),
                supp_priv_info: b"BB".to_vec(),
                ..ConcatKdfParams::default()
            },
        );
        let b = sha256_kdf(
            z,
            128,
            &ConcatKdfParams {
                supp_pub_info: b"BB".to_vec(),
                supp_priv_info: b"AAA".to_vec(),
                ..ConcatKdfParams::default()
            },
        );
        assert_ne!(a, b, "SuppPubInfo precedes SuppPrivInfo in OtherInfo");
    }

    #[test]
    fn concat_kdf_otherinfo_is_raw_concatenation() {
        let z = b"Z-secret";
        let combined = sha256_kdf(
            z,
            128,
            &ConcatKdfParams {
                algorithm_id: b"ABCDEF".to_vec(),
                ..ConcatKdfParams::default()
            },
        );
        let split = sha256_kdf(
            z,
            128,
            &ConcatKdfParams {
                algorithm_id: b"ABC".to_vec(),
                party_u_info: b"DEF".to_vec(),
                ..ConcatKdfParams::default()
            },
        );
        assert_eq!(combined, split);
    }

    #[test]
    fn concat_kdf_longer_than_one_block_iterates_the_counter() {
        let z = b"Z";
        let long = sha256_kdf(z, 512, &ConcatKdfParams::default());
        let mut second = 2u32.to_be_bytes().to_vec();
        second.extend_from_slice(z);
        assert_eq!(&long[32..], openssl::sha::sha256(&second));
    }
}
