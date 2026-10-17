# ECDSA XMLDSig fixtures

Foreign witness for the ECDSA `ds:SignatureValue` form: XMLDSig 1.1 §6.4.3
(RFC 9231 §2.3.6) defines it as `I2OSP(r, l) ‖ I2OSP(s, l)`, `l` the octet
length of the curve order. BDEW AS4-Profil 1.2 §2.2.6.2.1 signs `ecdsa-sha256`
on brainpoolP256r1. `tests/wssec_ecdsa_signature_value.rs` checks these files in
the normal test suite.

| File | What |
|---|---|
| `{p256,bp256,p384,p521}.{key,cert}.pem` | PKCS #8 keys and self-signed certificates (prime256v1, brainpoolP256r1, secp384r1, secp521r1; `CA:FALSE`, `keyUsage=digitalSignature`, valid 36,500 days) |
| `template.xml` | SOAP 1.2 envelope, one `#body` reference, Exc-C14N, `ecdsa-sha256`, `ds:X509Data`: the xmlsec1 signing template |
| `envelope.xml` | the same envelope with an empty `wsse:Security` (what this crate signs) |
| `xmlsec1-<curve>.xml` | signed by xmlsec1 1.3.11; this crate must verify them |
| `asx-<curve>.xml` | signed by this crate; xmlsec1 1.3.11 verified them; the suite re-verifies them and asserts the signer still emits the same `ds:SignedInfo` bytes |

Decoded `ds:SignatureValue` lengths: 64 / 64 / 96 / 132 octets (P-256 /
brainpoolP256r1 / P-384 / P-521). The suite also re-encodes each `(r, s)` as an
ASN.1 DER `ECDSA-Sig-Value` and asserts it is refused.

## Provenance

- Tool: `alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6`,
  `apk add xmlsec` → `xmlsec1 1.3.11 (openssl)`. `tests/interop_xmlsec_oracle.rs`
  pins the same image and asserts ≥ 1.3.11 (1.3.6 zero-pads P-256 values to 512
  octets).
- Keys (OpenSSL 4.0.3):
  `openssl ecparam -name <curve> -genkey -noout | openssl pkcs8 -topk8 -nocrypt`;
  `openssl req -new -x509 -key <curve>.key.pem -subj /CN=asx-ecdsa-<curve> -days 36500 -sha256
  -addext basicConstraints=critical,CA:FALSE -addext keyUsage=critical,digitalSignature`.
- Captured 2026-10-16 with:

```sh
ID='--id-attr:Id http://www.w3.org/2003/05/soap-envelope:Body'
xmlsec1 --sign --lax-key-search --privkey-pem <c>.key.pem,<c>.cert.pem $ID --output xmlsec1-<c>.xml template.xml
xmlsec1 --verify --lax-key-search --trusted-pem <c>.cert.pem $ID <file>.xml
```

| Input (every curve) | xmlsec1 1.3.11 |
|---|---|
| `xmlsec1-<c>.xml` | `Verification status: OK` |
| `asx-<c>.xml` | `Verification status: OK` |
| DER rewrite of either | `ERROR` or `FAILED` (not verified) |

## Regenerating

```sh
cargo test --all-features --test wssec_ecdsa_signature_value -- --ignored capture_asx_fixtures
```

Then verify the new `asx-<curve>.xml` with xmlsec1 in the pinned image.
