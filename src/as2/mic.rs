use base64::{Engine as _, engine::general_purpose::STANDARD};

use super::As2MicAlgorithm;

pub(crate) fn compute_rfc4130_mic(
    payload: &[u8],
    content_type: &str,
    algorithm: As2MicAlgorithm,
) -> (String, &'static str) {
    // RFC 4130 §7.3.1 MIC input is octet-exact over:
    // "Content-Type: {content_type}\r\n\r\n" + payload-bytes.
    // Feed each slice directly into the hasher to avoid an extra O(payload) allocation.
    let header = b"Content-Type: ";
    let crlf = b"\r\n\r\n";

    match algorithm {
        As2MicAlgorithm::Sha256 => {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            h.update(header);
            h.update(content_type.as_bytes());
            h.update(crlf);
            h.update(payload);
            (STANDARD.encode(h.finalize()), "sha-256")
        }
        As2MicAlgorithm::Sha384 => {
            use sha2::Digest;
            let mut h = sha2::Sha384::new();
            h.update(header);
            h.update(content_type.as_bytes());
            h.update(crlf);
            h.update(payload);
            (STANDARD.encode(h.finalize()), "sha-384")
        }
        As2MicAlgorithm::Sha512 => {
            use sha2::Digest;
            let mut h = sha2::Sha512::new();
            h.update(header);
            h.update(content_type.as_bytes());
            h.update(crlf);
            h.update(payload);
            (STANDARD.encode(h.finalize()), "sha-512")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mic_sha256_matches_rfc4130_octet_boundary() {
        let payload = b"ABC\r\nDEF";
        let content_type = "application/edi-x12; charset=utf-8";

        let (mic, alg) = compute_rfc4130_mic(payload, content_type, As2MicAlgorithm::Sha256);

        use sha2::Digest;
        let expected_input = b"Content-Type: application/edi-x12; charset=utf-8\r\n\r\nABC\r\nDEF";
        let expected = STANDARD.encode(sha2::Sha256::digest(expected_input));

        assert_eq!(alg, "sha-256");
        assert_eq!(mic, expected);
    }

    #[test]
    fn mic_is_sensitive_to_content_type_octets() {
        let payload = b"payload";
        let (a, _) = compute_rfc4130_mic(payload, "application/xml", As2MicAlgorithm::Sha256);
        let (b, _) = compute_rfc4130_mic(payload, "application/xml ", As2MicAlgorithm::Sha256);

        assert_ne!(a, b, "MIC must change when Content-Type octets differ");
    }
}
