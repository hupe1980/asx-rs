+++
title = "Security model"
description = "What asx checks, in which order, and the test that fails when a check is removed."
+++

Each claim names the test that fails when the check is removed (in `tests/`,
run with `cargo test --all-features --test <file> <name>`) or the section it
implements. Foreign-implementation evidence is on the
[conformance page](@/docs/conformance.md).

## Design principles

- **The profile is the only source of security settings.** No public item
  selects or relaxes an algorithm, a signature requirement or a trust rule
  outside `Profile` and `Quirk` (`tests/source_gates.rs`:
  `internal_policies_are_built_only_by_the_profile_views`). No test feature, no
  interop mode (`no_testing_feature_and_no_interop_mode`).
- **Verification is a type.** `Verified<T>` has no public constructor; exactly
  four pipelines create one (`verified_new_has_exactly_four_call_sites`), and
  a forged one does not compile (the `compile_fail` doctest on `Verified`).
- **Algorithms come from the profile, never from the message.** Another
  declared algorithm is refused, not negotiated.

## Configuration is validated once

`build()` refuses anything the profile does not allow with `ErrorKind::Config`
naming the setting and section (`tests/build_rejections.rs`; [summary](@/docs/profiles.md#what-build-refuses)).
`send` checks the message before anything is signed
(`tests/as4_send.rs::invalid_message_is_config_and_nothing_is_sent`,
`tests/as2_send.rs::invalid_messages_are_refused_before_sending`).
Certificates are re-checked for validity at use.

## Verification order

Inbound AS4, in order; a failing step stops the pipeline:

1. size limit (HTTP 413) and structure: one parser with per-class limits
   (bytes, nodes, depth, attributes), `DOCTYPE` and every `<!` declaration
   refused (`tests/xml_limits.rs`; ebMS header rules in
   `tests/as4_ebms_adversarial.rs`);
2. the signer chains to a trust anchor offline and is authorized for the
   claimed sender (pinned certificate, or the profile's identity rule) (`tests/as4_receive.rs`:
   `unpinned_signer_of_a_configured_partner_is_refused`,
   `unconfigured_bdew_sender_with_matching_subject_is_accepted`,
   `bdew_mp_id_must_be_in_the_ou`, `unconfigured_edelivery_sender_is_refused`);
3. the `SignatureValue`, then the digests of `eb:Messaging` and the Body; the
   signature must be a child of the targeted `wsse:Security`, references
   resolve only through `wsu:Id`, `Id` or `xml:id`, at most 19 references and
   two transforms each (`tests/wssec_strict_matrix.rs`,
   `tests/as4_swa_encryption_inbound.rs::messaging_digest_failure_is_pre_key`);
4. `eb:To` is the local party (`message_for_another_party_is_refused`);
5. revocation (below);
6. `eb:Timestamp`: at most 300 s in the future, at most 24 h in the past;
7. the ebMS3 test service is receipted here and never delivered
   (`ping_is_receipted_without_a_claim`);
8. the payload set equals the signed `eb:PartInfo` set (a part property
   repeated in one `eb:PartInfo` is refused; each payload carries its
   `MimeType`), the encryption envelope is well-formed and uses the profile's
   suite, and every part is encrypted (`tests/as4_swa_encryption_inbound.rs`,
   `undeclared_mime_part_is_refused`, `declared_part_missing_is_refused`,
   `suite_outside_partner_set_is_rejected_before_unwrap`);
9. **one** private-key operation by the decrypter the reference selects, then
   AES-GCM per part (`genuine_message_decrypts_with_one_key_operation`,
   `unauthenticated_message_makes_no_key_operation`,
   `second_decrypter_selected_by_reference`, `ambiguous_reference_refused`);
10. the `cid:` digests over the decrypted bytes, then decompression
    (`cid_digest_mismatch_over_the_decrypted_bytes`,
    `tampered_payload_is_refused_without_a_claim`);
11. the dedup claim, the handler, the audit record, `accept`
    (`accepted_message_is_delivered_once_and_receipted`,
    `in_flight_is_503_and_a_stale_holder_cannot_settle`).

An unauthenticated sender never causes a key operation, a dedup write or an
audit record. AS2 follows the same order with S/MIME
(`tests/as2_receive.rs::unknown_sender_is_refused_before_any_private_key_operation`);
its payload carries the Content-Type of the signed entity, or of the inner MIME
entity when RFC 5402-compressed.

## What is refused

| Check | Answer | Test |
|---|---|---|
| Unsigned or unencrypted AS4 message under a profile that requires both | `EBMS:0103` | `tests/as4_swa_encryption_inbound.rs::plaintext_xml_mentioning_encrypted_data_is_refused`; phase4 `bdew_unencrypted_push_phase4_to_crate_is_refused` |
| Unsigned or unencrypted AS2 message | `insufficient-message-security` | `tests/as2_receive.rs::unsigned_or_unencrypted_is_insufficient_message_security` |
| Bad AS2 signature | `authentication-failed` | `bad_signature_is_authentication_failed` |
| Any decryption failure (wrong key, bad padding, bad tag) | one indistinguishable answer: `EBMS:0102` / `decryption-failed` (RFC 3218 §2.3.2: a random content key is substituted) | `one_identical_decryption_failure`; `every_decryption_failure_is_the_same_decryption_failed`, `padding_and_content_failures_produce_identical_mdns` |
| A receipt that is unsigned, from an unpinned signer, for another message, or with NRR digests that differ | `Indeterminate` | `tests/as4_send.rs`: `unsigned_receipt_is_indeterminate`, `receipt_from_an_unpinned_signer_is_indeterminate`, `receipt_for_another_message_is_indeterminate`, `tampered_receipt_digest_is_indeterminate`; `tests/as4_receipt_verification.rs::nrr_missing_a_reference_is_indeterminate` |
| An MDN with a wrong MIC, a wrong `Original-Message-ID`, another signer, or no signature without the quirk | `Indeterminate` | `tests/as2_send.rs`: `wrong_mic_is_indeterminate`, `wrong_original_message_id_is_indeterminate`, `mdn_signed_by_another_certificate_is_indeterminate`, `unsigned_mdn_is_indeterminate_without_the_quirk`, `unsigned_mdn_quirk_still_refuses_a_failing_signature` |
| ECDSA signature value that is DER or the wrong length | refused naming the lengths (XMLDSig 1.1 §6.4.3) | `tests/wssec_ecdsa_signature_value.rs::wrong_length_rejected`, `ecdsa_receipt_verifies_as_nrr_evidence_and_der_is_rejected` |
| Encryption parameters outside the profile's suite (`rsa-1_5`, `rsa-oaep-mgf1p`, CBC, another KDF or curve) | refused before the key is used | `suite_outside_partner_set_is_rejected_before_unwrap`; `tests/wssec_key_transport_identifiers.rs` |
| AS2 compressed content that is not a MIME entity | `decompression-failed` | `tests/as2_receive.rs::a_compressed_entity_without_mime_headers_is_decompression_failed` |
| Body above the size limit | HTTP 413 before parsing | `oversized_body_is_413` (AS4 and AS2) |

## Algorithms

Per preset ([profiles](@/docs/profiles.md#what-each-preset-fixes)): ECDSA-SHA256 on
BrainpoolP256r1 with ECDH-ES + ConcatKDF + AES-KW and AES-128-GCM for BDEW;
RSA-SHA256 with RSA-OAEP (SHA-256, MGF1-SHA-256) and AES-128-GCM for Peppol,
eDelivery and ENTSOG; S/MIME with SHA-256 and AES-256-CBC for AS2. Reference
digests are always SHA-256. Signer and verifier share one identifier
registry.

## Revocation

Every non-anchor certificate of a verified signer's path is checked (AS4 and
AS2 inbound, AS4 receipts, AS2 MDNs) after the signature and the sender rule,
so an unauthenticated sender cannot make the client fetch anything (`tests/revocation.rs::an_unauthorized_signer_triggers_no_revocation_request`,
`::a_broken_signature_triggers_no_revocation_request`). The check is async
and runs outside the crypto pool.

- **CRL-DP.** The CRL comes from the distribution point each certificate names
  (RFC 5280 §4.2.1.13), over `http` or `https` only. A CRL counts only if its
  signature verifies with the issuing key (or, for the indirect SM-PKI Root-CA
  CRL, with a `Builder::crl_signer` certificate that chains to an anchor and
  asserts `cRLSign`, TR-03109-4 §4.2.1), it is complete (no delta), its
  `IssuingDistributionPoint` scope covers the certificate, it carries no
  unknown critical extension and its `thisUpdate` is at most 300 s ahead.
  `CertificateIssuer` entries of indirect CRLs are honoured. Decisions on static
  vectors agree with `openssl verify -crl_check_all`
  (`tests/revocation_openssl_oracle.rs`).
- **The three-day rule (BDEW, RzÜ AS4 2.6 §5.4).** A CA whose newest valid CRL
  is past its `nextUpdate`, or whose CRL could not be fetched for more than
  72 h after the last successful fetch, is distrusted with everything below it
  until a current CRL is obtained; the distrust is not stored. Boundaries are
  tested at ± 1 s and at equality (`src/revocation/tests.rs`).
- **OCSP** (every profile but BDEW, after the CRL): responder signature and
  authorization (the issuer or a delegated `id-kp-OCSPSigning` responder),
  `CertID`, `thisUpdate` within 300 s and at most 24 h old, `nextUpdate` not
  passed — all judged at the client clock's instant.
- **Fetching.** Through the client's `HttpClient`; the built-in client allows
  plain `http` for these signed objects only, applies the private-address
  filter and pinning, follows no redirect, presents no client certificate,
  times out at 3 s / 10 s and reads at most 10 MiB (CRL) / 64 KiB (OCSP); a
  larger body from any client is refused before parsing.
- **Cache.** One bounded in-process cache per client (1 024 entries); every
  entry is verified again on read and its unsigned fetch time clamped into
  `[thisUpdate, now]`. Concurrent checks of one CA make one fetch.

## Outbound HTTP

The built-in client (feature `http-client`):

- accepts only `https` endpoints without userinfo (`partner_endpoint_invalid`);
- refuses private, loopback, link-local and transition-mechanism addresses,
  and connects to the addresses it validated (no second DNS lookup);
- follows no redirects; connects within 10 s, completes within 300 s;
- reads at most 16 MiB of response (SMP 1 MiB, OCSP 64 KiB).

An error from an `HttpClient` you supply is `Indeterminate`: the request may
have been written; resending is safe because receivers detect duplicates.

## Limits

| Limit | Value |
|---|---|
| Message size, inbound and outbound | the preset ceiling (256 MiB), lowered by `Profile::max_message_bytes` |
| SOAP envelope | 4 MiB, 20 000 nodes, depth 64, 64 attributes per element (`tests/xml_limits.rs`) |
| SMP document | 2 MiB (XML), 1 MiB (HTTP) |
| Canonicalization depth | 256 |
| Signature references | 19 per user message, 3 per signal, 1 per SMP document |
| Receipt and MDN freshness on send | 300 s |

## Secrets

`KeyPair` zeroizes its key on drop and prints only its certificate; builders,
clients and endpoints redact keys in `Debug`, and key errors never echo the key
(`tests/secret_debug_redaction.rs`). Telemetry carries no payload, key or
certificate subject ([observability](@/docs/observability.md)), and observers
cannot change an outcome
(`tests/no_observer.rs::exchanges_succeed_unobserved_and_an_idle_observer_changes_nothing`).

## What the library does not protect against

- **A compromised trust anchor.** The network CA can issue for any party; pin
  partner certificates if you need more than network membership.
- **Inbound TLS.** There is no listener: terminate TLS (and mTLS) in front of
  the `Inbound`.
- **Replay across a non-durable store.** Use a durable
  [`DedupStore`](@/docs/persistence.md).
- **Host memory.** Zeroization covers owned buffers only: disable core dumps
  (`ulimit -c 0`, systemd `LimitCORE=0`), restrict ptrace, encrypt or disable
  swap, or keep keys in an HSM/KMS ([keys](@/docs/keys.md)).

## Crypto backends

OpenSSL (the `openssl` crate, system or vendored) performs RSA, ECDSA, ECDH,
X.509 chain validation and CMS; AES-GCM and AES key wrap are RustCrypto
`aes-gcm` and `aes-kw`. There is no FIPS-validated configuration. No `unsafe`
code (`#![forbid(unsafe_code)]`).
