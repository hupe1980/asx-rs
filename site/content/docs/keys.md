+++
title = "Keys and certificates"
description = "In-memory keys, HSM and KMS keys, key rollover and the mTLS identity."
+++

The library does everything around a private-key operation (XMLDSig and CMS
structures, ConcatKDF, key unwrap, content decryption). The key only signs
prepared bytes or performs one
[`KeyOp`](https://docs.rs/asx-rs/latest/asx/enum.KeyOp.html), so it can live
in an HSM or KMS.

## Certificates

`Certificate::from_pem` parses exactly one PEM certificate. `Debug` prints
subject, issuer, serial and SHA-256 fingerprint; equality and hashing compare
the DER (`der()`).

## `KeyPair`: keys in memory

```rust
use asx::{KeyPair, LocalParty};
use std::fs::read;

fn local_party() -> Result<LocalParty, Box<dyn std::error::Error>> {
    // chain: leaf first, then intermediates. key: PKCS#8, SEC1 or PKCS#1.
    let sig = KeyPair::from_pem(&read("sig.crt")?, &read("sig.key")?)?;
    let enc = KeyPair::from_pem(&read("enc.crt")?, &read("enc.key")?)?;
    let tls = KeyPair::from_pem(&read("tls.crt")?, &read("tls.key")?)?;
    Ok(LocalParty::new("9900000000001")
        .party_type("urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW")
        .signer(sig)
        .decrypter(enc)
        .tls_identity(tls))
}
```

`from_pem` refuses a key that does not match the leaf. A `KeyPair` is both
`Signer` and `Decrypter`, zeroizes its key on drop and `Debug`-prints only the
certificate. BDEW requires three different BrainpoolP256r1 key pairs for
signing, decryption and TLS (§2.3.4.4).

## HSM and KMS: implementing `Signer` and `Decrypter`

Both traits are object-safe and async, returning a
[`BoxFuture`](https://docs.rs/asx-rs/latest/asx/type.BoxFuture.html). An error
fails the operation with `ErrorKind::Backend`.

| Trait | Method | Contract |
|---|---|---|
| `Signer` | `certificate_chain()` | leaf first; BDEW emits the chain in its `#X509PKIPathv1` token |
| `Signer` | `sign(algorithm, message)` | sign the **unhashed** `message`. `SignatureAlgorithm::RsaSha256`: PKCS #1 v1.5 signature octets. `SignatureAlgorithm::EcdsaSha256`: an ASN.1 DER `ECDSA-Sig-Value` (what HSMs and KMS return); the library converts it to XMLDSig 1.1 `r ‖ s`; any other encoding fails signing |
| `Decrypter` | `certificate()` | identifies the key for inbound key-reference matching (SKI, BST, issuer-serial) |
| `Decrypter` | `decrypt(op)` | `KeyOp::RsaOaep(wrapped)`: RSA-OAEP with SHA-256, MGF1-SHA-256, empty label; return the content key. `KeyOp::RsaPkcs1v15(wrapped)`: RSAES-PKCS1-v1_5 (CMS, AS2); return the content key and do not distinguish padding failures. `KeyOp::Ecdh(peer_spki_der)`: ECDH with the originator's ephemeral public key (SubjectPublicKeyInfo DER); return the shared secret Z |

Both enums are `#[non_exhaustive]`: return an error for an operation your key
cannot perform.

```rust
use asx::{BoxFuture, Certificate, Decrypter, KeyOp, SignatureAlgorithm, Signer};
use zeroize::Zeroizing;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A key held by a KMS. `key_id` names it there; the chain is exported once.
#[derive(Debug)]
struct KmsKey {
    key_id: String,
    chain: Vec<Certificate>,
}

impl Signer for KmsKey {
    fn certificate_chain(&self) -> &[Certificate] {
        &self.chain
    }

    fn sign<'a>(&'a self, algorithm: SignatureAlgorithm, message: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>, BoxError>> {
        Box::pin(async move {
            let kms_algorithm = match algorithm {
                SignatureAlgorithm::EcdsaSha256 => "ECDSA_SHA_256", // returns DER
                SignatureAlgorithm::RsaSha256 => "RSASSA_PKCS1_V1_5_SHA_256",
                _ => return Err("unsupported signature algorithm".into()),
            };
            kms_sign(&self.key_id, kms_algorithm, message).await
        })
    }
}

impl Decrypter for KmsKey {
    fn certificate(&self) -> &Certificate {
        &self.chain[0]
    }

    fn decrypt<'a>(&'a self, op: KeyOp<'a>) -> BoxFuture<'a, Result<Zeroizing<Vec<u8>>, BoxError>> {
        Box::pin(async move {
            match op {
                KeyOp::Ecdh(peer_spki_der) => kms_derive_shared_secret(&self.key_id, peer_spki_der).await,
                KeyOp::RsaOaep(wrapped) => kms_decrypt(&self.key_id, "RSAES_OAEP_SHA_256", wrapped).await,
                _ => Err("unsupported key operation".into()),
            }
        })
    }
}

// Your KMS client goes here.
async fn kms_sign(_key: &str, _alg: &str, _msg: &[u8]) -> Result<Vec<u8>, BoxError> {
    Err("not connected".into())
}
async fn kms_decrypt(_key: &str, _alg: &str, _wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, BoxError> {
    Err("not connected".into())
}
async fn kms_derive_shared_secret(_key: &str, _peer: &[u8]) -> Result<Zeroizing<Vec<u8>>, BoxError> {
    Err("not connected".into())
}
```

Expect one `sign` per outbound message, receipt or MDN, and one `decrypt` per
inbound encrypted message, only after the sender authenticated and the key
reference selected this key. A failing decrypter gives the same uniform
decryption failure as a wrong key. For tests,
`asx_testkit::keys::CountingKeys` counts operations.

## Key rollover

- **Your decryption key.** Call `LocalParty::decrypter` once per key; inbound
  messages select it by the `xenc:EncryptedKey` reference (SKI, BST or
  issuer-serial), and no match is refused without trying any. Keep the old key
  until partners use the new certificate.
- **Your signing key.** Exactly one signer (a second is refused). Partners pin your certificate, so
  send them the new one first.
- **A partner's signing key.** Call `Partner::signing_cert` for old and new.
- **A partner's encryption key.** Replace `Partner::encryption_cert`.

Rebuilding a client is cheap: build a new one and swap the shared value.

## The mTLS identity

`LocalParty::tls_identity(KeyPair)` is the client certificate the built-in
HTTP client presents; only the TLS stack uses it. Inbound TLS terminates in
front of the `Inbound` service (reverse proxy or your server's acceptor); the
library has no listener.
