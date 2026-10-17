//! External-key stand-ins: [`CountingKeys`] wraps a key pair behind the
//! library's `Signer`/`Decrypter` seams, counts every private-key operation
//! and exposes no accessor to the key — what an HSM or KMS looks like to the
//! library.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// A `Signer` and `Decrypter` that is not an `asx::KeyPair` to the library,
/// so every key operation goes through the asynchronous trait.
#[derive(Debug, Clone)]
pub struct CountingKeys {
    inner: asx::KeyPair,
    chain: Vec<asx::Certificate>,
    signs: Arc<AtomicUsize>,
    decrypts: Arc<AtomicUsize>,
    failing: Arc<AtomicBool>,
}

impl CountingKeys {
    /// Wrap `pair` (its PEM stays inside).
    pub fn new(pair: &super::pki::KeyPair) -> CountingKeys {
        CountingKeys {
            inner: pair.key_pair(),
            chain: vec![pair.certificate()],
            signs: Arc::default(),
            decrypts: Arc::default(),
            failing: Arc::default(),
        }
    }

    /// Signatures produced so far (clones share the counters).
    pub fn signs(&self) -> usize {
        self.signs.load(Ordering::SeqCst)
    }

    /// Private-key decryptions performed so far.
    pub fn decrypts(&self) -> usize {
        self.decrypts.load(Ordering::SeqCst)
    }

    /// From now on every operation fails, as a backend outage would.
    pub fn fail(&self) {
        self.failing.store(true, Ordering::SeqCst);
    }
}

impl asx::Signer for CountingKeys {
    fn certificate_chain(&self) -> &[asx::Certificate] {
        &self.chain
    }

    fn sign<'a>(
        &'a self,
        algorithm: asx::SignatureAlgorithm,
        message: &'a [u8],
    ) -> asx::BoxFuture<'a, Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            if self.failing.load(Ordering::SeqCst) {
                return Err("the signing service is unavailable".into());
            }
            self.signs.fetch_add(1, Ordering::SeqCst);
            // Yield once: a real KMS call is not immediate.
            tokio::task::yield_now().await;
            asx::Signer::sign(&self.inner, algorithm, message).await
        })
    }
}

impl asx::Decrypter for CountingKeys {
    fn certificate(&self) -> &asx::Certificate {
        &self.chain[0]
    }

    fn decrypt<'a>(
        &'a self,
        operation: asx::KeyOp<'a>,
    ) -> asx::BoxFuture<
        'a,
        Result<zeroize::Zeroizing<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>>,
    > {
        Box::pin(async move {
            if self.failing.load(Ordering::SeqCst) {
                return Err("the decryption service is unavailable".into());
            }
            self.decrypts.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            asx::Decrypter::decrypt(&self.inner, operation).await
        })
    }
}
