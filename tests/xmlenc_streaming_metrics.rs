#![cfg(feature = "as4")]
//! Decrypting an attachment reads
//! the ciphertext from the MIME slice — no base64, no XML pass over payload
//! bytes — and allocates about one plaintext-sized buffer per part.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use asx::__fuzz::wssec::{XmlEncPayloadAlgorithm, decrypt_swa, encrypt_swa};

static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_BYTES.fetch_add(new_size, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[test]
fn decrypting_a_part_allocates_one_plaintext_buffer() {
    const SIZE: usize = 4 * 1024 * 1024;
    let cert_pem = include_bytes!("../tests/fixtures/pki/receipt_signing.cert.pem");
    let key_pem = include_bytes!("../tests/fixtures/pki/receipt_signing.key.pem");
    let payload = vec![b'X'; SIZE];
    let (header, bodies) = encrypt_swa(
        &[("big@asx.test", "application/gzip", &payload)],
        cert_pem,
        XmlEncPayloadAlgorithm::Aes128Gcm,
    )
    .expect("encrypt");
    let parts = [("big@asx.test", bodies[0].as_slice())];

    ALLOC_BYTES.store(0, Ordering::SeqCst);
    let plain = decrypt_swa(header.as_bytes(), &parts, key_pem).expect("decrypt");
    let allocated = ALLOC_BYTES.load(Ordering::SeqCst);

    assert_eq!(plain[0].len(), SIZE);
    assert!(plain[0] == payload);
    // One plaintext buffer plus the header parse and key material; a base64
    // or XML pass over the part would add at least another part size.
    assert!(
        allocated < SIZE + SIZE / 2,
        "decrypting a {SIZE}-byte part allocated {allocated} bytes"
    );
}
