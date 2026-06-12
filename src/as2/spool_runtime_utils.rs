use super::{
    As2RegulatedSpoolKeyProvider, AsxError, ErrorCode, ErrorContext, Result, SessionContext,
};
use openssl::symm::{Cipher, Crypter, Mode};
use std::sync::Arc;

pub(super) fn as2_spool_threshold_for_profile(profile_name: &str) -> usize {
    match profile_name {
        "as2_default" => 1024 * 1024,
        "as4_openpeppol_strict" | "as4_cef_strict" => 512 * 1024,
        "as4_general_b2b" => 2 * 1024 * 1024,
        "bulk_or_archive_profile" => 8 * 1024 * 1024,
        _ => 1024 * 1024,
    }
}

pub(super) fn profile_requires_encrypted_spool(profile_name: &str) -> bool {
    matches!(
        profile_name,
        "as4_openpeppol_strict"
            | "as4_cef_strict"
            | "peppol-edelivery-as4-v2.0"
            | "bdew-marktkommunikation-as4-v1.1"
    )
}

pub(super) fn parse_spool_encryption_key_hex(hex_key: &str) -> Result<Arc<[u8; 32]>> {
    let hex_key = hex_key.trim();
    if hex_key.len() != 64 {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "spool encryption key must contain exactly 64 hex characters",
            ErrorContext::new("as2_spool_encryption_key_parse"),
        ));
    }

    let mut out = [0u8; 32];
    for (idx, chunk) in hex_key.as_bytes().chunks_exact(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16).ok_or_else(|| {
            AsxError::new(
                ErrorCode::InvalidInput,
                "spool encryption key contains non-hex characters",
                ErrorContext::new("as2_spool_encryption_key_parse"),
            )
        })?;
        let lo = (chunk[1] as char).to_digit(16).ok_or_else(|| {
            AsxError::new(
                ErrorCode::InvalidInput,
                "spool encryption key contains non-hex characters",
                ErrorContext::new("as2_spool_encryption_key_parse"),
            )
        })?;
        out[idx] = ((hi << 4) | lo) as u8;
    }

    Ok(Arc::new(out))
}

pub(super) fn validate_spool_encryption_key_startup_self_test(
    provider_kind: As2RegulatedSpoolKeyProvider,
    session: &SessionContext,
    key: &[u8; 32],
) -> Result<()> {
    if key.iter().all(|b| *b == 0) {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            format!(
                "{} provider startup self-test failed: resolved key is all zeros",
                provider_kind.as_str()
            ),
            ErrorContext::for_session("as2_receive_stream_policy", session),
        ));
    }

    let cipher = Cipher::aes_256_gcm();
    let nonce = [0xA5; 12];
    let plaintext = b"asx_spool_key_self_test_v1";

    let mut encryptor = Crypter::new(cipher, Mode::Encrypt, key, Some(&nonce)).map_err(|err| {
        AsxError::new(
            ErrorCode::PolicyViolation,
            format!(
                "{} provider startup self-test failed: encryptor init error: {err}",
                provider_kind.as_str()
            ),
            ErrorContext::for_session("as2_receive_stream_policy", session),
        )
    })?;
    encryptor.pad(false);

    let mut ciphertext = vec![0u8; plaintext.len() + cipher.block_size()];
    let mut encrypted_len = encryptor
        .update(plaintext, &mut ciphertext)
        .map_err(|err| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                format!(
                    "{} provider startup self-test failed: encryption update error: {err}",
                    provider_kind.as_str()
                ),
                ErrorContext::for_session("as2_receive_stream_policy", session),
            )
        })?;
    encrypted_len += encryptor
        .finalize(&mut ciphertext[encrypted_len..])
        .map_err(|err| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                format!(
                    "{} provider startup self-test failed: encryption finalize error: {err}",
                    provider_kind.as_str()
                ),
                ErrorContext::for_session("as2_receive_stream_policy", session),
            )
        })?;
    ciphertext.truncate(encrypted_len);

    let mut tag = [0u8; 16];
    encryptor.get_tag(&mut tag).map_err(|err| {
        AsxError::new(
            ErrorCode::PolicyViolation,
            format!(
                "{} provider startup self-test failed: encryption tag error: {err}",
                provider_kind.as_str()
            ),
            ErrorContext::for_session("as2_receive_stream_policy", session),
        )
    })?;

    let mut decryptor = Crypter::new(cipher, Mode::Decrypt, key, Some(&nonce)).map_err(|err| {
        AsxError::new(
            ErrorCode::PolicyViolation,
            format!(
                "{} provider startup self-test failed: decryptor init error: {err}",
                provider_kind.as_str()
            ),
            ErrorContext::for_session("as2_receive_stream_policy", session),
        )
    })?;
    decryptor.pad(false);
    decryptor.set_tag(&tag).map_err(|err| {
        AsxError::new(
            ErrorCode::PolicyViolation,
            format!(
                "{} provider startup self-test failed: decryptor tag setup error: {err}",
                provider_kind.as_str()
            ),
            ErrorContext::for_session("as2_receive_stream_policy", session),
        )
    })?;

    let mut recovered = vec![0u8; ciphertext.len() + cipher.block_size()];
    let mut recovered_len = decryptor
        .update(&ciphertext, &mut recovered)
        .map_err(|err| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                format!(
                    "{} provider startup self-test failed: decryption update error: {err}",
                    provider_kind.as_str()
                ),
                ErrorContext::for_session("as2_receive_stream_policy", session),
            )
        })?;
    recovered_len += decryptor
        .finalize(&mut recovered[recovered_len..])
        .map_err(|err| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                format!(
                    "{} provider startup self-test failed: decryption finalize error: {err}",
                    provider_kind.as_str()
                ),
                ErrorContext::for_session("as2_receive_stream_policy", session),
            )
        })?;
    recovered.truncate(recovered_len);

    if recovered.as_slice() != plaintext {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            format!(
                "{} provider startup self-test failed: decrypted payload mismatch",
                provider_kind.as_str()
            ),
            ErrorContext::for_session("as2_receive_stream_policy", session),
        ));
    }

    Ok(())
}
