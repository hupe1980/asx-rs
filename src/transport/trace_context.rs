//! W3C Trace Context (`traceparent`) helpers.

use sha2::{Digest, Sha256};

fn is_lower_hex_ascii(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_all_zeros_ascii(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| *b == b'0')
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Normalize and validate a W3C `traceparent` header value.
///
/// Returns a normalized lowercase value when valid, otherwise `None`.
#[must_use]
pub fn normalize_traceparent(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();

    let mut parts = lower.split('-');
    let version = parts.next()?;
    let trace_id = parts.next()?;
    let parent_id = parts.next()?;
    let flags = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    if version.len() != 2 || trace_id.len() != 32 || parent_id.len() != 16 || flags.len() != 2 {
        return None;
    }
    if version == "ff" {
        return None;
    }

    let version_b = version.as_bytes();
    let trace_b = trace_id.as_bytes();
    let parent_b = parent_id.as_bytes();
    let flags_b = flags.as_bytes();

    if !is_lower_hex_ascii(version_b)
        || !is_lower_hex_ascii(trace_b)
        || !is_lower_hex_ascii(parent_b)
        || !is_lower_hex_ascii(flags_b)
    {
        return None;
    }

    if is_all_zeros_ascii(trace_b) || is_all_zeros_ascii(parent_b) {
        return None;
    }

    Some(lower)
}

/// Deterministically derive a W3C-compliant `traceparent` value from
/// correlation scope and message identity.
#[must_use]
pub fn generate_traceparent(correlation_root_id: &str, message_id: &str) -> String {
    let mut trace_hasher = Sha256::new();
    trace_hasher.update(b"asx-trace-id\0");
    trace_hasher.update(correlation_root_id.as_bytes());
    trace_hasher.update(b"\0");
    trace_hasher.update(message_id.as_bytes());
    let trace_digest = trace_hasher.finalize();

    let mut parent_hasher = Sha256::new();
    parent_hasher.update(b"asx-parent-id\0");
    parent_hasher.update(message_id.as_bytes());
    parent_hasher.update(b"\0");
    parent_hasher.update(correlation_root_id.as_bytes());
    let parent_digest = parent_hasher.finalize();

    let mut trace_id = [0u8; 16];
    trace_id.copy_from_slice(&trace_digest[..16]);
    if trace_id.iter().all(|b| *b == 0) {
        trace_id[0] = 1;
    }

    let mut parent_id = [0u8; 8];
    parent_id.copy_from_slice(&parent_digest[..8]);
    if parent_id.iter().all(|b| *b == 0) {
        parent_id[0] = 1;
    }

    format!("00-{}-{}-01", hex_lower(&trace_id), hex_lower(&parent_id))
}

#[cfg(test)]
mod tests {
    use super::{generate_traceparent, normalize_traceparent};

    #[test]
    fn normalize_traceparent_accepts_valid_and_lowercases() {
        let input = "00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01";
        let normalized = normalize_traceparent(input).expect("valid traceparent");
        assert_eq!(
            normalized,
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        );
    }

    #[test]
    fn normalize_traceparent_rejects_invalid_shapes() {
        assert!(normalize_traceparent("00-xyz-00f067aa0ba902b7-01").is_none());
        assert!(
            normalize_traceparent("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
                .is_none()
        );
        assert!(
            normalize_traceparent("00-00000000000000000000000000000000-00f067aa0ba902b7-01")
                .is_none()
        );
    }

    #[test]
    fn generate_traceparent_is_stable_and_valid() {
        let a = generate_traceparent("corr:s1", "msg-1");
        let b = generate_traceparent("corr:s1", "msg-1");
        assert_eq!(a, b);
        assert!(normalize_traceparent(&a).is_some());
    }
}
