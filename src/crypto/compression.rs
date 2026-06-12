//! Payload compression support (RFC 5402)
//!
//! This module implements gzip compression for AS2 and AS4 payloads,
//! following RFC 5402 which defines compression for AS2 messages.

#[cfg(feature = "compression")]
use flate2::Compression;
#[cfg(feature = "compression")]
use flate2::read::GzDecoder;
#[cfg(feature = "compression")]
use flate2::write::GzEncoder;
use std::io::{Read, Write};

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

/// Compress payload using gzip (RFC 5402)
///
/// Returns compressed bytes prefixed with gzip magic header.
/// Only available when `compression` feature is enabled.
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

/// Decompress gzip payload (RFC 5402)
///
/// Expects gzip-encoded input with magic header (0x1f 0x8b).
/// Only available when `compression` feature is enabled.
#[cfg(feature = "compression")]
pub fn decompress_gzip(compressed: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(compressed);
    let mut output = Vec::new();

    decoder.read_to_end(&mut output).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("failed to decompress gzip payload: {err}"),
            ErrorContext::new("decompression_gzip"),
        )
    })?;

    Ok(output)
}

/// Detect if payload is gzip-compressed by checking magic header (0x1f 0x8b)
pub fn is_gzip_compressed(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

#[cfg(not(feature = "compression"))]
pub fn compress_gzip(_payload: &[u8], _level: u32) -> Result<Vec<u8>> {
    Err(AsxError::new(
        ErrorCode::InvalidInput,
        "gzip compression not available; enable 'compression' feature",
        ErrorContext::new("compression_disabled"),
    ))
}

#[cfg(not(feature = "compression"))]
pub fn decompress_gzip(_compressed: &[u8]) -> Result<Vec<u8>> {
    Err(AsxError::new(
        ErrorCode::InvalidInput,
        "gzip decompression not available; enable 'compression' feature",
        ErrorContext::new("compression_disabled"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "compression")]
    fn test_compress_decompress_roundtrip() {
        // Use larger payload to ensure compression is effective (gzip has overhead for small data)
        let original = b"This is a test payload for compression. It should compress and decompress correctly. \
                         This is a test payload for compression. It should compress and decompress correctly. \
                         This is a test payload for compression. It should compress and decompress correctly.";
        let compressed = compress_gzip(original, 6).expect("compress");
        assert!(is_gzip_compressed(&compressed));
        assert!(compressed.len() < original.len()); // Should be smaller

        let decompressed = decompress_gzip(&compressed).expect("decompress");
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_gzip_magic_detection() {
        assert!(!is_gzip_compressed(&[]));
        assert!(!is_gzip_compressed(&[0x1f]));
        assert!(is_gzip_compressed(&[0x1f, 0x8b]));
        assert!(is_gzip_compressed(&[0x1f, 0x8b, 0x08, 0x00]));
    }
}
