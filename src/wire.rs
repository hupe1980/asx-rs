//! The inbound size bound shared by the AS2 and AS4 receive paths.

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

/// Refuse a payload larger than `max_body_bytes`.
pub fn enforce_payload_limit(
    stage: &'static str,
    payload_len: usize,
    max_body_bytes: usize,
) -> Result<()> {
    if payload_len > max_body_bytes {
        return Err(AsxError::new(
            // `PayloadTooLarge` maps to HTTP 413, which is what an ingress
            // handler must return here.
            ErrorCode::PayloadTooLarge,
            format!(
                "payload exceeds configured max bytes: {} > {}",
                payload_len, max_body_bytes
            ),
            ErrorContext::new(stage),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversize_payload_is_payload_too_large() {
        enforce_payload_limit("t", 10, 10).expect("at the limit");
        let err = enforce_payload_limit("t", 11, 10).expect_err("over the limit");
        assert_eq!(err.code, ErrorCode::PayloadTooLarge);
    }
}
