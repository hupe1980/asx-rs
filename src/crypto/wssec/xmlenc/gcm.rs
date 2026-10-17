//! AES-GCM content encryption (XML Encryption 1.1 §5.2.4): the wire form is
//! `nonce (12) || ciphertext || tag (16)`. The **declared** cipher fixes the
//! key length; a key of any other length is refused here — the
//! decrypt pipeline never passes one (it substitutes a random CEK of the
//! declared length first).

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit};

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::crypto::alg::XmlEncPayloadAlgorithm;

pub(crate) const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

fn failure(detail: &str) -> AsxError {
    AsxError::new(
        ErrorCode::DecryptionFailed,
        format!("AES-GCM: {detail}"),
        ErrorContext::new("wssec_aes_gcm"),
    )
}

/// A fresh random nonce (96 bits, NIST SP 800-38D §8.2.2).
pub(crate) fn fresh_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| failure("no randomness for the nonce"))?;
    Ok(nonce)
}

/// Encrypt under `nonce` (one fresh nonce per part and key).
pub(crate) fn encrypt(
    cipher: XmlEncPayloadAlgorithm,
    cek: &[u8],
    nonce: [u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if cek.len() != cipher.key_len() {
        return Err(failure("content key length does not match the cipher"));
    }
    let nonce_array = aes_gcm::Nonce::from(nonce);
    let sealed = match cipher {
        XmlEncPayloadAlgorithm::Aes128Gcm => Aes128Gcm::new_from_slice(cek)
            .map_err(|_| failure("bad key"))?
            .encrypt(&nonce_array, plaintext),
        XmlEncPayloadAlgorithm::Aes256Gcm => Aes256Gcm::new_from_slice(cek)
            .map_err(|_| failure("bad key"))?
            .encrypt(&nonce_array, plaintext),
    }
    .map_err(|_| failure("encryption failed"))?;
    let mut blob = Vec::with_capacity(NONCE_LEN + sealed.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&sealed);
    Ok(blob)
}

/// Decrypt `nonce || ciphertext || tag`; the tag is checked.
pub(crate) fn decrypt(cipher: XmlEncPayloadAlgorithm, cek: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    #[cfg(test)]
    probe::reached();
    if cek.len() != cipher.key_len() {
        return Err(failure("content key length does not match the cipher"));
    }
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(failure("ciphertext shorter than nonce and tag"));
    }
    let nonce = aes_gcm::Nonce::from(
        <[u8; NONCE_LEN]>::try_from(&blob[..NONCE_LEN]).expect("length checked"),
    );
    match cipher {
        XmlEncPayloadAlgorithm::Aes128Gcm => Aes128Gcm::new_from_slice(cek)
            .map_err(|_| failure("bad key"))?
            .decrypt(&nonce, &blob[NONCE_LEN..]),
        XmlEncPayloadAlgorithm::Aes256Gcm => Aes256Gcm::new_from_slice(cek)
            .map_err(|_| failure("bad key"))?
            .decrypt(&nonce, &blob[NONCE_LEN..]),
    }
    .map_err(|_| failure("authentication tag mismatch"))
}

/// How often content decryption ran on this thread (the GCM step is reached
/// in every failure class).
#[cfg(test)]
pub(crate) mod probe {
    use std::cell::Cell;

    thread_local! {
        static REACHED: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) fn reached() {
        REACHED.with(|c| c.set(c.get() + 1));
    }

    pub(crate) fn take() -> usize {
        REACHED.with(|c| c.replace(0))
    }
}
