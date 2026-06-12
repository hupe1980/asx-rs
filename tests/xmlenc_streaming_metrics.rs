#![cfg(feature = "as4")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use asx_rs::crypto::wssec::{decrypt_payload_xmlenc, encrypt_payload_xmlenc};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use openssl::encrypt::Decrypter;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::symm::{Cipher, decrypt_aead};
use roxmltree::Document;

static ALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

fn reset_alloc_stats() {
    ALLOC_CALLS.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
}

fn alloc_stats() -> (usize, usize) {
    (
        ALLOC_CALLS.load(Ordering::Relaxed),
        ALLOC_BYTES.load(Ordering::Relaxed),
    )
}

fn decrypt_payload_xmlenc_dom_baseline(
    encrypted_payload_xml: &[u8],
    recipient_key_pem: &[u8],
) -> asx_rs::core::Result<Vec<u8>> {
    let xml = std::str::from_utf8(encrypted_payload_xml).map_err(|_| {
        asx_rs::core::AsxError::new(
            asx_rs::core::ErrorCode::ParseFailed,
            "XML Encryption payload is not valid UTF-8",
            asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
        )
    })?;
    let doc = Document::parse(xml).map_err(|err| {
        asx_rs::core::AsxError::new(
            asx_rs::core::ErrorCode::ParseFailed,
            format!("failed to parse XML Encryption payload: {err}"),
            asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
        )
    })?;

    let encrypted_data = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "EncryptedData")
        .ok_or_else(|| {
            asx_rs::core::AsxError::new(
                asx_rs::core::ErrorCode::ParseFailed,
                "XML Encryption payload is missing xenc:EncryptedData",
                asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
            )
        })?;

    let data_algo = encrypted_data
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "EncryptionMethod")
        .and_then(|n| n.attribute("Algorithm"))
        .ok_or_else(|| {
            asx_rs::core::AsxError::new(
                asx_rs::core::ErrorCode::ParseFailed,
                "XML Encryption payload is missing xenc:EncryptedData/xenc:EncryptionMethod",
                asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
            )
        })?;
    if data_algo != "http://www.w3.org/2009/xmlenc11#aes128-gcm"
        && data_algo != "http://www.w3.org/2009/xmlenc11#aes256-gcm"
    {
        return Err(asx_rs::core::AsxError::new(
            asx_rs::core::ErrorCode::DecryptionFailed,
            format!(
                "unsupported XML Encryption data algorithm: {data_algo} (only xmlenc11 AES-GCM is accepted)"
            ),
            asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
        ));
    }

    let key_algo = encrypted_data
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "EncryptedKey")
        .and_then(|ek| {
            ek.children()
                .find(|n| n.is_element() && n.tag_name().name() == "EncryptionMethod")
        })
        .and_then(|n| n.attribute("Algorithm"))
        .ok_or_else(|| {
            asx_rs::core::AsxError::new(
                asx_rs::core::ErrorCode::ParseFailed,
                "XML Encryption payload is missing xenc:EncryptedKey/xenc:EncryptionMethod",
                asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
            )
        })?;
    if key_algo != "http://www.w3.org/2009/xmlenc11#rsa-oaep" {
        return Err(asx_rs::core::AsxError::new(
            asx_rs::core::ErrorCode::DecryptionFailed,
            format!(
                "unsupported XML Encryption key transport algorithm: {key_algo} (only xmlenc11 RSA-OAEP is accepted)"
            ),
            asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
        ));
    }

    let encrypted_key_b64 = encrypted_data
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "EncryptedKey")
        .and_then(|n| {
            n.descendants()
                .find(|c| c.is_element() && c.tag_name().name() == "CipherValue")
        })
        .and_then(|n| n.text())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            asx_rs::core::AsxError::new(
                asx_rs::core::ErrorCode::ParseFailed,
                "XML Encryption payload is missing wrapped xenc:EncryptedKey/xenc:CipherValue",
                asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
            )
        })?;

    let encrypted_data_b64 = encrypted_data
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "CipherData")
        .and_then(|n| {
            n.children()
                .find(|c| c.is_element() && c.tag_name().name() == "CipherValue")
        })
        .and_then(|n| n.text())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            asx_rs::core::AsxError::new(
                asx_rs::core::ErrorCode::ParseFailed,
                "XML Encryption payload is missing xenc:EncryptedData/xenc:CipherData/xenc:CipherValue",
                asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
            )
        })?;

    let wrapped_key = BASE64_STANDARD.decode(encrypted_key_b64).map_err(|err| {
        asx_rs::core::AsxError::new(
            asx_rs::core::ErrorCode::ParseFailed,
            format!("failed to decode wrapped XML Encryption key: {err}"),
            asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
        )
    })?;

    let cipher_blob = BASE64_STANDARD.decode(encrypted_data_b64).map_err(|err| {
        asx_rs::core::AsxError::new(
            asx_rs::core::ErrorCode::ParseFailed,
            format!("failed to decode XML Encryption ciphertext: {err}"),
            asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
        )
    })?;

    let pkey = PKey::private_key_from_pem(recipient_key_pem).map_err(|err| {
        asx_rs::core::AsxError::new(
            asx_rs::core::ErrorCode::DecryptionFailed,
            format!("failed to parse XML Encryption recipient private key: {err}"),
            asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
        )
    })?;

    let mut decrypter = Decrypter::new(&pkey).map_err(|err| {
        asx_rs::core::AsxError::new(
            asx_rs::core::ErrorCode::DecryptionFailed,
            format!("failed to create RSA decrypter: {err}"),
            asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
        )
    })?;
    decrypter
        .set_rsa_padding(Padding::PKCS1_OAEP)
        .map_err(|err| {
            asx_rs::core::AsxError::new(
                asx_rs::core::ErrorCode::DecryptionFailed,
                format!("failed to set RSA-OAEP padding: {err}"),
                asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
            )
        })?;
    decrypter
        .set_rsa_oaep_md(MessageDigest::sha256())
        .map_err(|err| {
            asx_rs::core::AsxError::new(
                asx_rs::core::ErrorCode::DecryptionFailed,
                format!("failed to set RSA-OAEP SHA-256 digest: {err}"),
                asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
            )
        })?;
    decrypter
        .set_rsa_mgf1_md(MessageDigest::sha256())
        .map_err(|err| {
            asx_rs::core::AsxError::new(
                asx_rs::core::ErrorCode::DecryptionFailed,
                format!("failed to set RSA MGF1-SHA-256 digest: {err}"),
                asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
            )
        })?;
    let buf_len = decrypter.decrypt_len(&wrapped_key).map_err(|err| {
        asx_rs::core::AsxError::new(
            asx_rs::core::ErrorCode::DecryptionFailed,
            format!("failed to compute decrypted key buffer length: {err}"),
            asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
        )
    })?;
    let mut aes_key = vec![0u8; buf_len];
    let key_len = decrypter
        .decrypt(&wrapped_key, &mut aes_key)
        .map_err(|err| {
            asx_rs::core::AsxError::new(
                asx_rs::core::ErrorCode::DecryptionFailed,
                format!("failed to unwrap XML Encryption content key (OAEP/MGF1-SHA256): {err}"),
                asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
            )
        })?;
    let aes_key = aes_key[..key_len].to_vec();

    if cipher_blob.len() < 28 {
        return Err(asx_rs::core::AsxError::new(
            asx_rs::core::ErrorCode::DecryptionFailed,
            "AES-GCM ciphertext blob is too short (need nonce + tag)",
            asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
        ));
    }
    let nonce = &cipher_blob[..12];
    let tag_start = cipher_blob.len() - 16;
    let ciphertext = &cipher_blob[12..tag_start];
    let tag = &cipher_blob[tag_start..];
    let gcm_cipher = match aes_key.len() {
        16 => Cipher::aes_128_gcm(),
        32 => Cipher::aes_256_gcm(),
        other => {
            return Err(asx_rs::core::AsxError::new(
                asx_rs::core::ErrorCode::DecryptionFailed,
                format!(
                    "unsupported XML Encryption content key length: {other} (expected 16 or 32)"
                ),
                asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
            ));
        }
    };
    decrypt_aead(gcm_cipher, &aes_key, Some(nonce), &[], ciphertext, tag).map_err(|err| {
        asx_rs::core::AsxError::new(
            asx_rs::core::ErrorCode::DecryptionFailed,
            format!("failed to decrypt AES-GCM ciphertext: {err}"),
            asx_rs::core::ErrorContext::new("wssec_decrypt_payload"),
        )
    })
}

fn benchmark_payload() -> Vec<u8> {
    vec![b'X'; 128 * 1024]
}

fn measure<F>(label: &str, iterations: usize, mut f: F) -> (usize, usize, u128)
where
    F: FnMut() -> asx_rs::core::Result<Vec<u8>>,
{
    reset_alloc_stats();
    let start = Instant::now();
    let mut total = 0usize;
    for _ in 0..iterations {
        let out = black_box(f()).expect("decrypt");
        total += black_box(out.len());
    }
    let elapsed = start.elapsed().as_nanos();
    let (calls, bytes) = alloc_stats();
    println!(
        "{label}: iterations={iterations} total_output_bytes={total} alloc_calls={calls} alloc_bytes={bytes} elapsed_ns={elapsed}",
    );
    (calls, bytes, elapsed)
}

#[test]
#[ignore]
fn xmlenc_streaming_decrypt_metrics() {
    let cert_pem = include_bytes!("../tests/fixtures/pki/receipt_signing.cert.pem");
    let key_pem = include_bytes!("../tests/fixtures/pki/receipt_signing.key.pem");
    let payload = benchmark_payload();
    let ciphertext = encrypt_payload_xmlenc(
        &payload,
        cert_pem,
        asx_rs::crypto::wssec::XmlEncPayloadAlgorithm::Aes128Gcm,
    )
    .expect("encrypt");

    let warm_stream = decrypt_payload_xmlenc(&ciphertext, key_pem).expect("stream decrypt");
    assert_eq!(warm_stream, payload);
    let warm_dom = decrypt_payload_xmlenc_dom_baseline(&ciphertext, key_pem).expect("dom decrypt");
    assert_eq!(warm_dom, payload);

    let iterations = 64usize;
    let (stream_calls, stream_bytes, stream_ns) = measure("streaming", iterations, || {
        decrypt_payload_xmlenc(black_box(&ciphertext), black_box(key_pem))
    });
    let (dom_calls, dom_bytes, dom_ns) = measure("dom_baseline", iterations, || {
        decrypt_payload_xmlenc_dom_baseline(black_box(&ciphertext), black_box(key_pem))
    });

    let calls_delta = dom_calls.saturating_sub(stream_calls);
    let bytes_delta = dom_bytes.saturating_sub(stream_bytes);
    let ns_delta = dom_ns.saturating_sub(stream_ns);

    println!(
        "delta_per_run: alloc_calls={calls_delta} alloc_bytes={bytes_delta} elapsed_ns={ns_delta}",
    );
}
