//! Payload compression for AS2 (RFC 5402) and AS4.
//!
//! The two protocols compress differently, and conflating them is a common
//! source of messages no partner can decode:
//!
//! - **AS2** — RFC 5402 wraps the payload in a CMS `CompressedData` structure
//!   (RFC 3274) using **ZLIB** (RFC 1950), carried as
//!   `application/pkcs7-mime; smime-type=compressed-data`. A bare gzip stream
//!   is *not* AS2 compression and no conformant partner will unwrap it.
//! - **AS4** — the payload attachment is a plain **gzip** stream, and the
//!   `eb:PartInfo` must advertise it with a `CompressionType` part property.
//!   See [`crate::as4`] for the property wiring.
//!
//! Both directions are implemented here: a library that can compress but not
//! decompress can only talk to itself.

#[cfg(feature = "compression")]
use flate2::Compression;
#[cfg(feature = "compression")]
use flate2::read::{GzDecoder, ZlibDecoder};
#[cfg(feature = "compression")]
use flate2::write::{GzEncoder, ZlibEncoder};
#[cfg(feature = "compression")]
use std::io::{Read, Write};

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

/// Media type RFC 5402 assigns to an AS2 compressed entity.
pub const AS2_COMPRESSED_CONTENT_TYPE: &str =
    "application/pkcs7-mime; smime-type=compressed-data; name=\"smime.p7z\"";

/// `CompressionType` value the AS4 profile requires for compressed payloads.
pub const AS4_COMPRESSION_TYPE: &str = "application/gzip";

#[cfg(feature = "compression")]
/// Upper bound on decompressed output, guarding against compression bombs.
///
/// A 100:1 ratio is far beyond what EDI or XML achieves in practice, so this
/// only trips on hostile input.
const MAX_DECOMPRESSED_BYTES: usize = 128 * 1024 * 1024;

// ── AS4: raw gzip ───────────────────────────────────────────────────────────

/// Compress an AS4 payload attachment with gzip.
#[cfg(feature = "compression")]
pub fn compress_gzip(payload: &[u8], compression_level: u32) -> Result<Vec<u8>> {
    let level = match compression_level {
        1..=9 => Compression::new(compression_level),
        _ => Compression::default(),
    };

    let mut encoder = GzEncoder::new(Vec::new(), level);
    encoder.write_all(payload).map_err(|err| {
        AsxError::new(
            ErrorCode::InvalidInput,
            format!("failed to compress payload: {err}"),
            ErrorContext::new("compression_gzip"),
        )
    })?;

    encoder.finish().map_err(|err| {
        AsxError::new(
            ErrorCode::InvalidInput,
            format!("failed to finalize gzip compression: {err}"),
            ErrorContext::new("compression_gzip_finalize"),
        )
    })
}

/// Decompress an AS4 gzip payload attachment.
#[cfg(feature = "compression")]
pub fn decompress_gzip(compressed: &[u8]) -> Result<Vec<u8>> {
    read_bounded(
        GzDecoder::new(compressed),
        "decompression_gzip",
        "failed to decompress gzip payload",
    )
}

/// Detect a gzip stream by its magic header (`1f 8b`).
pub fn is_gzip_compressed(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

// ── AS2: RFC 5402 CMS CompressedData ────────────────────────────────────────

// DER object identifiers (RFC 3274 §1, RFC 5652 §4).
#[cfg(feature = "compression")]
/// `id-ct-compressedData` — 1.2.840.113549.1.9.16.1.9
const OID_CT_COMPRESSED_DATA: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x09,
];
#[cfg(feature = "compression")]
/// `id-alg-zlibCompress` — 1.2.840.113549.1.9.16.3.8
const OID_ALG_ZLIB_COMPRESS: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x08,
];
#[cfg(feature = "compression")]
/// `id-data` — 1.2.840.113549.1.7.1
const OID_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];

#[cfg(feature = "compression")]
const TAG_OID: u8 = 0x06;
#[cfg(feature = "compression")]
const TAG_OCTET_STRING: u8 = 0x04;
#[cfg(feature = "compression")]
const TAG_SEQUENCE: u8 = 0x30;
#[cfg(feature = "compression")]
const TAG_CONTEXT_0: u8 = 0xa0;

/// Wrap an AS2 payload in a CMS `CompressedData` structure (RFC 5402 / RFC 3274).
///
/// The output is the DER-encoded `ContentInfo` that belongs in a
/// `application/pkcs7-mime; smime-type=compressed-data` entity.
#[cfg(feature = "compression")]
pub fn compress_cms_zlib(payload: &[u8], compression_level: u32) -> Result<Vec<u8>> {
    let level = match compression_level {
        1..=9 => Compression::new(compression_level),
        _ => Compression::default(),
    };

    let mut encoder = ZlibEncoder::new(Vec::new(), level);
    encoder.write_all(payload).map_err(|err| {
        AsxError::new(
            ErrorCode::InvalidInput,
            format!("failed to compress AS2 payload: {err}"),
            ErrorContext::new("compression_cms_zlib"),
        )
    })?;
    let deflated = encoder.finish().map_err(|err| {
        AsxError::new(
            ErrorCode::InvalidInput,
            format!("failed to finalize AS2 compression: {err}"),
            ErrorContext::new("compression_cms_zlib_finalize"),
        )
    })?;

    // EncapsulatedContentInfo ::= SEQUENCE { eContentType id-data,
    //                                        eContent [0] EXPLICIT OCTET STRING }
    let mut encap = der_tlv(TAG_OID, OID_DATA);
    encap.extend_from_slice(&der_tlv(
        TAG_CONTEXT_0,
        &der_tlv(TAG_OCTET_STRING, &deflated),
    ));
    let encap = der_tlv(TAG_SEQUENCE, &encap);

    // CompressedData ::= SEQUENCE { version 0, compressionAlgorithm, encapContentInfo }
    let mut compressed_data = vec![0x02, 0x01, 0x00]; // INTEGER 0
    compressed_data.extend_from_slice(&der_tlv(
        TAG_SEQUENCE,
        &der_tlv(TAG_OID, OID_ALG_ZLIB_COMPRESS),
    ));
    compressed_data.extend_from_slice(&encap);
    let compressed_data = der_tlv(TAG_SEQUENCE, &compressed_data);

    // ContentInfo ::= SEQUENCE { contentType id-ct-compressedData,
    //                            content [0] EXPLICIT CompressedData }
    let mut content_info = der_tlv(TAG_OID, OID_CT_COMPRESSED_DATA);
    content_info.extend_from_slice(&der_tlv(TAG_CONTEXT_0, &compressed_data));
    Ok(der_tlv(TAG_SEQUENCE, &content_info))
}

/// Unwrap a CMS `CompressedData` structure produced by an AS2 partner.
#[cfg(feature = "compression")]
pub fn decompress_cms_zlib(der: &[u8]) -> Result<Vec<u8>> {
    let stage = "decompression_cms_zlib";
    let fail = |msg: String| AsxError::new(ErrorCode::ParseFailed, msg, ErrorContext::new(stage));

    let content_info = der_expect(der, TAG_SEQUENCE, stage)?;
    let (content_type, rest) = der_take(content_info, TAG_OID, stage)?;
    if content_type != OID_CT_COMPRESSED_DATA {
        return Err(fail(
            "AS2 compressed entity is not a CMS CompressedData structure (RFC 3274)".to_string(),
        ));
    }

    let (compressed_data, _) = der_take(rest, TAG_CONTEXT_0, stage)?;
    let compressed_data = der_expect(compressed_data, TAG_SEQUENCE, stage)?;

    // version INTEGER
    let (_version, rest) = der_take(compressed_data, 0x02, stage)?;
    // compressionAlgorithm AlgorithmIdentifier
    let (algorithm, rest) = der_take(rest, TAG_SEQUENCE, stage)?;
    let (algorithm_oid, _) = der_take(algorithm, TAG_OID, stage)?;
    if algorithm_oid != OID_ALG_ZLIB_COMPRESS {
        return Err(fail(
            "unsupported CMS compression algorithm; RFC 5402 requires id-alg-zlibCompress"
                .to_string(),
        ));
    }

    // encapContentInfo
    let (encap, _) = der_take(rest, TAG_SEQUENCE, stage)?;
    let (_econtent_type, rest) = der_take(encap, TAG_OID, stage)?;
    let (econtent, _) = der_take(rest, TAG_CONTEXT_0, stage)?;
    let (deflated, _) = der_take(econtent, TAG_OCTET_STRING, stage)?;

    read_bounded(
        ZlibDecoder::new(deflated),
        stage,
        "failed to decompress AS2 CMS CompressedData payload",
    )
}

/// Whether an entity's `Content-Type` marks it as RFC 5402 compressed.
pub fn is_as2_compressed_content_type(content_type: &str) -> bool {
    let lower = content_type.to_ascii_lowercase();
    (lower.contains("application/pkcs7-mime") || lower.contains("application/x-pkcs7-mime"))
        && lower.contains("compressed-data")
}

// ── shared helpers ──────────────────────────────────────────────────────────

#[cfg(feature = "compression")]
fn read_bounded<R: Read>(mut reader: R, stage: &'static str, message: &str) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let read = (&mut reader)
        .take(MAX_DECOMPRESSED_BYTES as u64 + 1)
        .read_to_end(&mut output)
        .map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("{message}: {err}"),
                ErrorContext::new(stage),
            )
        })?;

    if read > MAX_DECOMPRESSED_BYTES {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            format!(
                "{message}: decompressed output exceeds {MAX_DECOMPRESSED_BYTES} byte limit \
                 (possible decompression bomb)"
            ),
            ErrorContext::new(stage),
        ));
    }

    Ok(output)
}

/// Encode one DER tag-length-value.
#[cfg(feature = "compression")]
fn der_tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(contents.len() + 6);
    out.push(tag);
    let len = contents.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        let significant = &bytes[first..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(contents);
    out
}

/// Read the value of the next DER element, requiring it to carry `tag`.
/// Returns `(value, remaining-input)`.
#[cfg(feature = "compression")]
fn der_take<'a>(input: &'a [u8], tag: u8, stage: &'static str) -> Result<(&'a [u8], &'a [u8])> {
    let fail = |msg: String| AsxError::new(ErrorCode::ParseFailed, msg, ErrorContext::new(stage));

    let (&actual_tag, rest) = input
        .split_first()
        .ok_or_else(|| fail("truncated DER: missing tag".to_string()))?;
    if actual_tag != tag {
        return Err(fail(format!(
            "unexpected DER tag 0x{actual_tag:02x} (expected 0x{tag:02x})"
        )));
    }

    let (&first_len, rest) = rest
        .split_first()
        .ok_or_else(|| fail("truncated DER: missing length".to_string()))?;

    let (len, rest) = if first_len < 0x80 {
        (first_len as usize, rest)
    } else {
        let count = (first_len & 0x7f) as usize;
        if count == 0 {
            return Err(fail(
                "indefinite-length DER is not accepted in strict CMS parsing".to_string(),
            ));
        }
        if count > std::mem::size_of::<usize>() || rest.len() < count {
            return Err(fail("DER length field is out of range".to_string()));
        }
        let mut len = 0usize;
        for &b in &rest[..count] {
            len = (len << 8) | b as usize;
        }
        (len, &rest[count..])
    };

    if rest.len() < len {
        return Err(fail(format!(
            "truncated DER: declared length {len} exceeds {} remaining bytes",
            rest.len()
        )));
    }
    Ok((&rest[..len], &rest[len..]))
}

/// Read a DER element that must span the whole input.
#[cfg(feature = "compression")]
fn der_expect<'a>(input: &'a [u8], tag: u8, stage: &'static str) -> Result<&'a [u8]> {
    let (value, rest) = der_take(input, tag, stage)?;
    if !rest.is_empty() {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            format!("trailing bytes after DER element ({} bytes)", rest.len()),
            ErrorContext::new(stage),
        ));
    }
    Ok(value)
}

#[cfg(not(feature = "compression"))]
pub fn compress_gzip(_payload: &[u8], _level: u32) -> Result<Vec<u8>> {
    Err(feature_disabled())
}

#[cfg(not(feature = "compression"))]
pub fn decompress_gzip(_compressed: &[u8]) -> Result<Vec<u8>> {
    Err(feature_disabled())
}

#[cfg(not(feature = "compression"))]
pub fn compress_cms_zlib(_payload: &[u8], _level: u32) -> Result<Vec<u8>> {
    Err(feature_disabled())
}

#[cfg(not(feature = "compression"))]
pub fn decompress_cms_zlib(_der: &[u8]) -> Result<Vec<u8>> {
    Err(feature_disabled())
}

#[cfg(not(feature = "compression"))]
fn feature_disabled() -> AsxError {
    AsxError::new(
        ErrorCode::InvalidInput,
        "compression not available; enable the 'compression' feature",
        ErrorContext::new("compression_disabled"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "compression")]
    fn gzip_roundtrips() {
        let original = b"EDI segment. ".repeat(64);
        let compressed = compress_gzip(&original, 6).expect("compress");
        assert!(is_gzip_compressed(&compressed));
        assert!(compressed.len() < original.len());
        assert_eq!(decompress_gzip(&compressed).expect("decompress"), original);
    }

    #[test]
    fn gzip_magic_detection() {
        assert!(!is_gzip_compressed(&[]));
        assert!(!is_gzip_compressed(&[0x1f]));
        assert!(is_gzip_compressed(&[0x1f, 0x8b]));
    }

    #[test]
    #[cfg(feature = "compression")]
    fn cms_compressed_data_roundtrips() {
        let original = b"ISA*00*          *00*          *ZZ*SENDER~".repeat(32);
        let der = compress_cms_zlib(&original, 6).expect("compress");
        assert!(der.len() < original.len(), "compression must shrink EDI");
        assert_eq!(decompress_cms_zlib(&der).expect("decompress"), original);
    }

    /// The wrapper must be a real CMS structure, not a bare deflate stream —
    /// this is exactly what distinguishes RFC 5402 from "we ran gzip".
    #[test]
    #[cfg(feature = "compression")]
    fn cms_output_is_a_content_info_with_the_rfc3274_oids() {
        let der = compress_cms_zlib(b"payload", 6).expect("compress");
        assert_eq!(der[0], TAG_SEQUENCE, "outermost element is a SEQUENCE");
        assert!(
            der.windows(OID_CT_COMPRESSED_DATA.len())
                .any(|w| w == OID_CT_COMPRESSED_DATA),
            "id-ct-compressedData OID must be present"
        );
        assert!(
            der.windows(OID_ALG_ZLIB_COMPRESS.len())
                .any(|w| w == OID_ALG_ZLIB_COMPRESS),
            "id-alg-zlibCompress OID must be present"
        );
    }

    #[test]
    #[cfg(feature = "compression")]
    fn a_bare_gzip_stream_is_rejected_as_cms() {
        let gzip = compress_gzip(b"payload", 6).expect("compress");
        let err = decompress_cms_zlib(&gzip).expect_err("gzip is not CMS CompressedData");
        assert_eq!(err.code, ErrorCode::ParseFailed);
    }

    #[test]
    #[cfg(feature = "compression")]
    fn truncated_cms_input_fails_closed() {
        let der = compress_cms_zlib(b"payload here", 6).expect("compress");
        for cut in [1usize, der.len() / 2, der.len() - 1] {
            assert!(
                decompress_cms_zlib(&der[..cut]).is_err(),
                "truncated CMS at {cut} bytes must not decode"
            );
        }
    }

    #[test]
    fn compressed_content_type_detection() {
        assert!(is_as2_compressed_content_type(AS2_COMPRESSED_CONTENT_TYPE));
        assert!(is_as2_compressed_content_type(
            "Application/PKCS7-Mime; smime-type=Compressed-Data"
        ));
        assert!(!is_as2_compressed_content_type(
            "application/pkcs7-mime; smime-type=enveloped-data"
        ));
        assert!(!is_as2_compressed_content_type("application/edi-x12"));
    }

    /// Lengths ≥ 128 use DER long form; a payload that crosses the boundary
    /// exercises it.
    #[test]
    #[cfg(feature = "compression")]
    fn long_form_der_lengths_roundtrip() {
        for size in [100usize, 200, 5000, 70_000] {
            let original: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let der = compress_cms_zlib(&original, 1).expect("compress");
            assert_eq!(
                decompress_cms_zlib(&der).expect("decompress"),
                original,
                "roundtrip failed at {size} bytes"
            );
        }
    }

    #[test]
    #[cfg(feature = "compression")]
    fn der_tlv_encodes_short_and_long_forms() {
        assert_eq!(der_tlv(0x04, &[1, 2, 3]), vec![0x04, 0x03, 1, 2, 3]);
        let long = der_tlv(0x04, &vec![0u8; 300]);
        assert_eq!(&long[..4], &[0x04, 0x82, 0x01, 0x2c]);
    }
}
