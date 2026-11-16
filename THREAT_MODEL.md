# Threat model

This document defines what asx-rs is meant to defend against, what it trusts and where it
stops. It lists every known threat class with its status and evidence, including the open
ones. Report a suspected vulnerability privately as described in [SECURITY.md](https://github.com/hupe1980/asx-rs/blob/main/SECURITY.md).

## Release status

This describes asx-rs 0.17.0, a pre-release. The model was built with
[ThreatSpec](https://github.com/hupe1980/spec-kit-threatspec) (STRIDE per element). Every
status below is checked against the code and its tests.

asx-rs is a library. It parses MIME, SOAP, XML and CMS straight off the network inside the
embedding process, with `#![forbid(unsafe_code)]`. One `Profile` per network fixes every
security setting; `build()` validates the whole configuration once; a receive runs one fixed
verification order (size, structure, signer, signature, recipient, revocation, freshness,
payload set, decryption, digests, decompression, dedup claim) before the handler sees a
`Verified` value. Private-key operations go through the `Signer` and `Decrypter` traits, so keys
can live in an HSM or KMS.

Under `Profile::bdew()` the built-in client speaks SM-PKI mutual TLS (BSI TR-03116-3,
BrainpoolP256r1), trusts only the configured anchors, sends SNI and checks the server chain's
revocation before writing; `build()` enforces the RzÜ AS4 2.6 certificate-triple rules.

It does **not**, in this release:

- terminate inbound TLS: there is no listener, and the server the embedder mounts `Inbound` in
  owns TLS and mTLS;
- authenticate an `eb:Error` answer: it is reported as `PartnerError`, not as evidence (A-23);
- protect against replay across a `DedupStore` that forgets (A-06);
- implement AS4 pull, split/join, asynchronous AS2 MDN delivery or streaming receive (see
  Not supported).

## Adversary

- **An internet sender**: anyone who can reach the embedder's `Inbound` endpoint. It sends
  arbitrary bytes, replays captured messages and adapts to the answers.
- **A network member**: the holder of a valid certificate of the network's CA (SM-PKI, Peppol
  PKI) who is not a configured partner, or who claims another party's identity.
- **A rogue partner**: a configured partner, compromised or malicious, with its genuine keys.
- **A network attacker** on the path between asx-rs and a partner, a CRL distribution point, an
  OCSP responder or an SMP.
- **A hostile service**: the CRL, OCSP, SMP or DNS endpoint named by a certificate or a lookup,
  under the attacker's control.
- **A local reader** of the embedder's logs, traces, metrics or storage.
- **The supply chain**: a compromised dependency, toolchain or release credential.

## Assets

- Private signing, decryption and TLS keys.
- Inbound and outbound business payloads and their signed metadata.
- Non-repudiation evidence: signed AS4 receipts, signed AS2 MDNs, and the audit records that
  carry them.
- Trust configuration: trust anchors, `crl_signer` certificates, partner certificate pins,
  endpoints and profile settings.
- Dedup claims, and the revocation state (CRLs, OCSP responses, the distrust of a CA).
- Private networks and metadata endpoints reachable from the embedder's host.
- Memory, CPU and private-key operations of the embedding process.
- The published crate and its dependency graph.

## Trusted

- The embedder and its operator, and the configuration they pass to `build()`: profile,
  local party, partners, trust anchors, quirks.
- The network's certificate authorities, configured as trust anchors. A trust anchor can issue
  for any party.
- The `Signer` and `Decrypter` implementations, and the `DedupStore`, `AuditSink` and
  `HttpClient` the embedder supplies, for doing what their traits document.
- OpenSSL, the RustCrypto crates, the Rust toolchain, the operating system and the host.

## In scope

- Everything an internet sender, a network member or a rogue partner can do through the bytes
  of an inbound message, a receipt, an MDN or a signal.
- Everything a hostile service can do through a CRL, an OCSP response, an SMP document, a DNS
  answer or a URL taken from a certificate.
- Forged, replayed or partial delivery evidence.
- Leaks of key material through `Debug`, errors, logs, spans and metrics.
- Resource exhaustion and panics reachable from network input.
- A setting, feature or quirk that weakens a profile's security floor.

## Out of scope

- A malicious embedder. The `#[doc(hidden)]` hooks (`asx::__fuzz` and others) exist for the
  crate's own test suites and bypass the profile; calling them leaves the security model.
- Host memory: core dumps, swap and ptrace. Zeroization covers owned buffers only.
- A compromised trust anchor or network CA.
- Authorization of business content. The handler decides; it sees the authenticated sender.
- Durability and access control of the embedder's storage backends.
- Bugs in OpenSSL, the RustCrypto crates or the operating system.

## Strength

The verification order holds whatever the inbound bytes say: nothing reaches the handler, a
`Decrypter`, the `DedupStore` or the `AuditSink` before the signer is bound to the claimed
sender and the signature verifies. Algorithms come from the profile, never from the message.
Delivery evidence is a type: `send` returns a receipt or MDN only as a `Verified` value, which
has no public constructor. These controls do not make a network member harmless under the
`bdew()` and `peppol()` presets: by profile rule an unconfigured sender whose verified
certificate carries the claimed identity is admitted, and a handler that must refuse such
senders checks the sender itself. The egress filter is the hard boundary against SSRF only for
the built-in `HttpClient`; an embedder that supplies its own client owns those guards.

## Threat classes

Ids are stable and never reused. The fields are:

- **Disposition**: `mitigate` (asx-rs is designed to prevent it), `embedder` (the embedder
  must handle it, with help from asx-rs), `accept` (a recorded risk).
- **Status**: `mitigated` only with test evidence and no known open variant; `partial` when
  variants are open (listed under Open variants); `open` when no control covers it;
  `documented` when the embedder owns it or the risk is accepted and described.
- **Evidence**: tests in the repository (`file::test`) that attempt the attack and assert the
  refusal, or the code that enforces it.

| Id | Class | Description | Sev | Disposition | Status | Evidence |
|---|---|---|---|---|---|---|
| A-01 | XML signature wrapping and ID ambiguity | A genuinely signed element stays in place while an unsigned `eb:Messaging`, Body, reference target or receipt signal is added for the pipeline to act on. One targeted `wsse:Security`, one signature, exactly one `eb:Messaging` whose `wsu:Id` is in the verified set; IDs only from `wsu:Id`, `Id` or `xml:id`; repeated IDs, Messaging blocks, signatures and `eb:MessageInfo` children refused; the receipt signal acted on must be signature-covered. | high | mitigate | mitigated | `tests/as4_ebms_adversarial.rs::signed_messaging_moved_into_a_wrapper_is_refused`, `::duplicate_messaging_before_the_signed_one_is_refused`, `::duplicate_messaging_after_the_signed_one_is_refused`, `::duplicate_wsu_id_is_refused`, `::body_reusing_the_messaging_id_is_refused`, `::multiple_signatures_are_refused`; `tests/wssec_strict_matrix.rs::strict_mode_rejects_wrapped_reference_uri` |
| A-02 | Canonicalization divergence | The Exclusive C14N implementation disagrees with a signer's, so a tampered document verifies or a genuine one does not. It is bespoke; foreign implementations witness it. | medium | mitigate | partial | `tests/wssec_c14n_vectors.rs`; `tests/interop_xmlsec_oracle.rs`; `tests/interop_phase4_counterparty.rs` |
| A-03 | Decryption before authentication | An unauthenticated sender makes the receiver run private-key and bulk decryption operations at scale. AS4 verifies signer, signature, same-document digests, recipient and suite before one `Decrypter` call; AS2 refuses an unknown `AS2-From` before any key operation. | critical | mitigate | partial | `tests/as4_swa_encryption_inbound.rs::unauthenticated_message_makes_no_key_operation`, `::messaging_digest_failure_is_pre_key`, `::genuine_message_decrypts_with_one_key_operation`; `tests/as2_receive.rs::unknown_sender_is_refused_before_any_private_key_operation` |
| A-04 | Decryption-failure oracle | Distinguishable OAEP, PKCS#1 v1.5, key-unwrap, padding or tag failures let an attacker run a Bleichenbacher or padding oracle. Every failure is one answer (`EBMS:0102` / `decryption-failed`); a random content key is substituted on any unwrap failure (RFC 3218 §2.3.2), so no failure returns before a tag check. | high | mitigate | mitigated | `tests/as4_swa_encryption_inbound.rs::one_identical_decryption_failure`; `tests/as2_receive.rs::every_decryption_failure_is_the_same_decryption_failed`, `::padding_and_content_failures_produce_identical_mdns` |
| A-05 | Timing side channels | Secret-dependent timing in digest, MIC or pin comparison, or in a private-key operation. Comparisons go through `subtle::ConstantTimeEq`. | medium | mitigate | partial | `src/core/util.rs` (`constant_time_eq`), used by `src/as4/receipt_verify.rs`, `src/as2/mdn.rs`, `src/crypto/wssec/verify.rs`; `src/as4/tests.rs::constant_time_eq_returns_false_for_differing_slices` |
| A-06 | Replay | A captured signed message is sent again and processed twice. Per-sender dedup claim with lease and token before the handler; `eb:Timestamp` at most 300 s ahead and no older than the 7-day dedup retention; a conformance suite for backends. | high | mitigate, embedder | partial | `tests/as4_receive.rs::duplicate_is_receipted_without_handler`, `::in_flight_is_503_and_a_stale_holder_cannot_settle`; `tests/as2_receive.rs::duplicate_is_answered_duplicate_document_without_calling_the_handler`; `tests/dedup_conformance.rs::non_atomic_store_fails_the_race`, `::senders_with_the_same_message_id_get_different_keys`; `src/as4/receive/tests.rs::timestamp_older_than_the_dedup_retention_is_refused` |
| A-07 | Sender spoofing | A network member or a partner signs a message claiming another sender. The signer chains to an anchor offline and matches the partner's pinned certificate or the profile's identity rule (BDEW: the MP-ID is an OU of the subject, RzÜ AS4 2.6 Kap. 5.2; Peppol: CN = `eb:From/PartyId`). | high | mitigate | mitigated | `tests/as4_receive.rs::unpinned_signer_of_a_configured_partner_is_refused`, `::bdew_mp_id_must_be_in_the_ou`, `::unconfigured_edelivery_sender_is_refused`; `tests/as4_ebms_adversarial.rs::messaging_resigned_by_another_key_is_refused`; `tests/peppol_smp_lookup.rs::access_point_whose_cn_is_not_its_party_id_is_refused`; `tests/as2_receive.rs::bad_signature_is_authentication_failed` |
| A-08 | Wrong recipient | A message addressed to another party (`eb:To`, `AS2-To`) is delivered to the local handler. | high | mitigate | mitigated | `tests/as4_receive.rs::message_for_another_party_is_refused`; `tests/as4_ebms_adversarial.rs::message_for_another_recipient_is_refused`; `tests/as2_receive.rs::as2_to_other_than_the_local_party_is_refused` |
| A-09 | Forged delivery evidence | A forged, unsigned, foreign, stale or partial receipt or MDN is returned as proof of delivery. A receipt counts only when signed by a pinned, unrevoked partner certificate, bound to the sent id, echoing every sent digest, fresh within 300 s; an MDN only with the computed MIC and the sent `Original-Message-ID` (RFC 4130 §7.3.1). | high | mitigate | mitigated | `tests/as4_send.rs::unsigned_receipt_is_indeterminate`, `::receipt_from_an_unpinned_signer_is_indeterminate`, `::receipt_for_another_message_is_indeterminate`, `::tampered_receipt_digest_is_indeterminate`; `tests/as4_receipt_verification.rs::nrr_missing_a_reference_is_indeterminate`; `tests/as2_send.rs::wrong_mic_is_indeterminate`, `::mdn_signed_by_another_certificate_is_indeterminate`; `tests/revocation.rs::a_revoked_receipt_signer_leaves_the_delivery_indeterminate` |
| A-10 | Audit evidence gaps | An exchange leaves no audit record, a record for an unauthenticated message, or a second record for a retransmission. One record per authenticated leg, carrying the raw evidence; a failing durable sink fails the exchange. | high | mitigate | mitigated | `tests/audit_records.rs::an_invalid_signature_leaves_no_record`, `::a_retransmission_after_accept_leaves_no_second_record`, `::a_failing_durable_sink_fails_the_receive_and_leaves_the_claim_unsettled`, `::a_failing_durable_sink_fails_the_send_with_the_evidence`; `tests/testkit_audit_conformance.rs` |
| A-11 | Tampering with stored claims and records | Whoever can write the dedup or audit backend deletes claims (re-enabling replay) or alters records. Audit records carry the signed receipt or MDN, which verifies on its own; the records themselves are not signed or chained. | medium | embedder | documented | `src/audit.rs` (`AuditRecord`); `tests/audit_records.rs::json_form_matches_the_golden_shape_and_round_trips` |
| A-12 | Server-side request forgery | A URL chosen by an attacker (a certificate's CRL distribution point or OCSP responder, an SMP endpoint, an asynchronous-MDN URL) makes the client reach a private address or a metadata endpoint. The built-in client's connector refuses private, loopback, link-local and transition-mechanism addresses in every DNS answer for every new connection, follows no redirect, and exempts only a host pinned exactly with `Builder::resolve`; revocation is fetched only after the signature and the sender rule. | high | mitigate | partial | `tests/revocation.rs::an_unauthorized_signer_triggers_no_revocation_request`, `::a_broken_signature_triggers_no_revocation_request`; `src/transport/egress.rs::tests::private_and_reserved_ranges_are_private`; `src/transport/connector.rs::tests::a_pinned_host_reaches_its_address_and_nothing_else_does`, `::an_unpinned_loopback_host_is_refused`; `src/http_client.rs::tests::revocation_fetch_to_a_private_address_makes_no_connection`; `tests/egress_mtls.rs::without_the_pin_the_loopback_msh_is_unreachable` |
| A-13 | DNS rebinding | A host validated as public resolves to a private address at connect time. The connector resolves once per new connection, checks every answer and connects to the address it checked; pooled connections exist only through it. | high | mitigate | partial | `src/transport/connector.rs::tests::an_unpinned_loopback_host_is_refused`, `::a_pinned_host_reaches_its_address_and_nothing_else_does`; `src/transport/egress.rs` (`is_private_ip`) |
| A-14 | XML bombs and entity expansion | An oversized, deep, wide or entity-expanding document exhausts memory or CPU before authentication. One parser with per-class limits on bytes, nodes, depth and attributes; `DOCTYPE` and every `<!` declaration refused. | high | mitigate | mitigated | `tests/xml_limits.rs::push_envelope_limits`, `::sync_signal_limits`, `::receipt_limits`, `::error_signal_limits`, `::smp_response_limits`, `::sbdh_document_limits`, `::encrypted_payload_limits` |
| A-15 | Oversized bodies and compression bombs | An oversized body, or a small gzip or zlib part that expands without bound, exhausts memory. The body limit answers 413 before parsing; decompression runs after authentication and stops at `Profile::max_message_bytes` for the whole message (one budget across its parts). | medium | mitigate | mitigated | `tests/as4_receive.rs::oversized_body_is_413`; `tests/as2_receive.rs::oversized_body_is_413`; `src/crypto/compression.rs::tests::a_bomb_is_refused_at_the_limit` |
| A-16 | MIME and HTTP header ambiguity | A repeated header, an undeclared or missing part, or a boundary trick makes asx-rs and a signer or intermediary see different content. A repeated AS2 header the receiver acts on, a repeated AS4 `Content-Type`, a MIME part with a repeated `Content-ID` or `Content-Type`, a signed AS2 entity with a repeated `Content-Type` or `Content-Transfer-Encoding`, and any part property repeated in one `eb:PartInfo` are refused; the payload set must equal the signed `eb:PartInfo` set. | high | mitigate | mitigated | `tests/as2_receive.rs::a_repeated_as2_header_is_400_and_never_delivered`; `tests/as4_ebms_adversarial.rs::a_repeated_content_type_header_is_refused`, `::a_repeated_mime_part_header_is_refused`; `src/crypto/as2_smime.rs::tests::a_repeated_entity_header_is_refused`; `tests/as4_swa_encryption_inbound.rs::undeclared_mime_part_is_refused`, `::declared_part_missing_is_refused`, `::plaintext_xml_mentioning_encrypted_data_is_refused`; `src/as4/parser.rs::duplicate_four_corner_properties_are_rejected`; `tests/as2_receive_mdn.rs::duplicate_disposition_fields_are_indeterminate` |
| A-17 | Algorithm downgrade | A message or receipt declares another algorithm (`rsa-1_5`, `rsa-oaep-mgf1p`, CBC, another KDF, digest or curve, a DER ECDSA value) and it is negotiated instead of refused. The inbound algorithm tuple must equal the partner's profile suite before any key is used (eDelivery AS4 1.15 §3.2.6; BDEW AS4-Profil 1.2 §2.2.6.2.2). | high | mitigate | mitigated | `tests/as4_swa_encryption_inbound.rs::suite_outside_partner_set_is_rejected_before_unwrap`; `tests/wssec_key_transport_identifiers.rs`; `tests/wssec_ecdsa_signature_value.rs::wrong_length_rejected`; `tests/as4_receipt_verification.rs::ecdsa_receipt_verifies_as_nrr_evidence_and_der_is_rejected` |
| A-18 | Revocation fail-open | A revoked certificate is accepted because its status could not be obtained, did not verify or had no source. Under `bdew()`: CRL only, `nextUpdate` required, a certificate without a distribution point refused, a CA distrusted when its CRL is past `nextUpdate` or unobtainable for 72 h (RzÜ AS4 2.6 Kap. 5.4). CRLs are verified for signature, scope, completeness and freshness (RFC 5280 §4.2.1.13, §5.2.5). | high | mitigate | partial | `tests/revocation.rs::bdew_refuses_when_the_crl_does_not_verify`, `::bdew_refuses_a_chain_certificate_without_a_distribution_point`, `::bdew_refuses_a_sub_ca_listed_in_the_indirect_root_crl`, `::a_revoked_crl_is_final_whatever_ocsp_says`, `::a_certificate_without_any_source_follows_the_profile`; `tests/revocation_openssl_oracle.rs`; `src/revocation/tests.rs` |
| A-19 | Key material in output | Private keys appear in `Debug`, errors, logs, spans or metrics. Every secret-bearing type writes its `Debug` by hand; `KeyPair` prints its certificate only and zeroizes on drop; telemetry carries no payload, key or certificate subject. | high | mitigate | mitigated | `tests/secret_debug_redaction.rs::key_pair_debug_prints_the_certificate_only`, `::parties_builders_clients_and_inbounds_redact_their_keys`, `::key_errors_never_echo_the_key`; `tests/telemetry_contract.rs`; `tests/external_keys.rs::no_private_key_leaves_keys_rs` |
| A-20 | Weakened security configuration | A public setting, cargo feature, test mode or quirk lowers a profile's floor. Security settings exist only in `Profile` and named per-partner `Quirk`s, which accept an absent element, never a wrong one; there is no test feature and no interop mode. | medium | mitigate | mitigated | `tests/source_gates.rs::internal_policies_are_built_only_by_the_profile_views`, `::no_testing_feature_and_no_interop_mode`, `::test_util_gates_only_the_testkit_module`, `::verified_new_has_exactly_four_call_sites`; `tests/build_rejections.rs`; `tests/as2_send.rs::unsigned_mdn_quirk_still_refuses_a_failing_signature` |
| A-21 | Panics on malformed input | Malformed bytes panic or hang the receive pipeline. No `unsafe` code; mutated messages get a well-formed answer; a panicking handler is treated as a refusal. | medium | mitigate | partial | `src/lib.rs` (`#![forbid(unsafe_code)]`); `tests/fuzz_protocol_ingress.rs::fuzz_smoke_as4_inbound_does_not_panic`, `::fuzz_smoke_as2_inbound_does_not_panic`, `::mutated_as4_messages_get_a_well_formed_answer`; `tests/as4_receive.rs::handler_panic_is_treated_as_err` |
| A-22 | Discovery redirection | A forged SMP document or a spoofed BDXL answer sends a Peppol message to an attacker's endpoint and certificate. The SMP document must carry a verifying enveloped signature that chains to the SMP anchor; a non-`https` U-NAPTR replacement is refused. | medium | mitigate | partial | `tests/smp_enveloped_signature.rs::a_document_without_a_signature_is_rejected`, `::a_well_formed_reference_with_an_untrusted_signer_fails_before_the_digest`; `tests/peppol_smp_lookup.rs::smp_signature_not_chaining_to_the_anchor_is_rejected`; `tests/interop_peppol_smp_oracle.rs` |
| A-23 | Unauthenticated error signals | An unsigned `eb:Error` in the HTTP response is reported as the partner's refusal and steers the sender's retry decision. It must refer to the sent message id, is never delivery evidence, and `ErrorKind::PartnerError` documents it as a routing hint; under `bdew()` the SM-PKI-verified mutual TLS narrows its source to the partner's endpoint. | low | accept, embedder | documented | `tests/as4_receipt_verification.rs::ebms_error_signal_is_partner_error`; `src/as4/receipt_verify.rs::error_signal_for_a_different_message_is_rejected`; `src/error.rs` (`ErrorKind::PartnerError`) |
| A-24 | Supply chain | A compromised or vulnerable dependency (OpenSSL through C FFI, the RustCrypto crates, the XML and DNS crates) or a hijacked release credential reaches embedders. | medium | mitigate | partial | `Cargo.lock` with `--locked` builds and `cargo deny check advisories licenses bans sources` (`.github/workflows/ci.yml`, `deny.toml`); crates.io trusted publishing from the CI-gated workflow (`.github/workflows/release.yml`) |
| A-25 | Encryption envelope ambiguity | Two `EncryptedData` for one `cid:`, a dangling or orphan `DataReference`, a second `EncryptedKey`, a `KeyInfo` naming another key, an `xenc:` element outside the targeted `wsse:Security`, or another `Type` or transform makes the receiver decrypt something other than the signed parts (WSS SwA 1.1.1 §5.5). Every defect is refused before a key is used. | high | mitigate | mitigated | `tests/as4_swa_encryption_inbound.rs::two_encrypted_data_for_one_cid`, `::dangling_data_reference`, `::orphan_encrypted_data`, `::second_encrypted_key`, `::key_info_naming_another_key`, `::xenc_outside_the_security_header`, `::type_other_than_content_only`, `::transform_list_not_exactly_the_ciphertext_transform` |
| A-26 | Unencrypted or sniffed parts | A plaintext part is delivered under a profile that requires encryption, or a part is "decrypted" because its bytes mention `xenc:EncryptedData`. Decryption is driven only by the security header; every declared part must be encrypted. | high | mitigate | mitigated | `tests/as4_swa_encryption_inbound.rs::part_without_encrypted_data`, `::plaintext_xml_mentioning_encrypted_data_is_refused` |
| A-27 | Evidence over ciphertext | Signature digests taken over ciphertext make receipts useless as evidence about the content. asx-rs compresses, signs, then encrypts; `cid:` digests cover the pre-encryption bytes and are checked after decryption. | high | mitigate | mitigated | `tests/as4_swa_encryption_shape.rs::cid_digests_cover_pre_encryption_bytes`; `tests/as4_receipt_verification.rs::encrypted_send_receipt_echoes_plaintext_digests`; `tests/as4_swa_encryption_inbound.rs::cid_digest_mismatch_over_the_decrypted_bytes`; `tests/interop_phase4_encryption.rs::tampered_from_phase4_is_refused` |
| A-28 | Content key and nonce reuse | A content key or an AES-GCM nonce repeats across messages or parts, or the implicit-rejection key is predictable. One fresh key per message, one fresh 96-bit nonce per part (BSI TR-03116-3 §9.2.1); without randomness the rejection key fails closed (an empty key content decryption refuses). | medium | mitigate | mitigated | `src/crypto/wssec/xmlenc/mod.rs::tests::content_keys_nonces_and_rejection_keys_are_fresh`, `::an_empty_rejection_key_fails_uniformly` |
| A-29 | XML attachment digest divergence | For an uncompressed XML-typed attachment, asx-rs digests raw octets where WSS SwA 1.1.1 §5.4.2 says Exclusive C14N; a foreign sender's digest then disagrees. Every preset compresses outbound, so only inbound uncompressed XML parts are affected. | low | mitigate | open | none (no foreign witness yet) |
| A-30 | Partner impersonation over TLS | An on-path attacker impersonates the partner's MSH because the server certificate is not verified against the configured anchors, host name and EKU. Under `bdew()` the client trusts only the builder's SM-PKI anchors, checks the DNS name (RFC 6125, no wildcards) and `serverAuth`, sends SNI and presents the local TLS identity (BDEW AS4-Profil 1.2 §2.2.6.1, §2.3.4.4). | critical | mitigate | mitigated | `tests/egress_mtls.rs::bdew_mutual_tls_with_brainpool_delivers_and_presents_the_tls_identity`, `::a_server_certificate_from_an_unknown_ca_is_refused`, `::a_server_certificate_for_another_host_is_refused`, `::a_server_certificate_without_server_auth_is_refused`; `tests/interop_openssl_tls_oracle.rs::openssl_s_server_accepts_our_brainpool_client_certificate` |
| A-31 | Revoked server certificate | A partner TLS certificate revoked in the SM-PKI is still used. The server chain is checked through the client's revocation validator (with the three-day rule) before the request is written. | high | mitigate | mitigated | `tests/egress_mtls.rs::a_revoked_server_certificate_is_refused_before_writing` |
| A-32 | TLS downgrade | The handshake negotiates a protocol version, cipher suite, group or signature scheme outside BSI TR-03116-3 §4 under `bdew()`. | high | mitigate | mitigated | `tests/egress_mtls.rs::a_server_outside_tr_03116_is_refused`, `::bdew_mutual_tls_over_tls_1_2`; `src/transport/tls.rs::tests::bdew_policy_applies_on_the_linked_openssl`, `::bdew_forbids_wildcards` |
| A-33 | Endpoint not bound to the certificate | Messages go to an endpoint the partner's certificate does not name, through misconfiguration or a tampered partner record. Under `bdew()` the endpoint must equal the encryption certificate's URI subjectAltName (or is taken from it) and its host must be a DNS name (RzÜ AS4 2.6 Kap. 2, Kap. 3, Kap. 5.2). | high | mitigate | mitigated | `tests/build_rejections.rs::bdew_partner_endpoint_is_the_encryption_certificates_uri`, `::bdew_endpoint_must_be_a_dns_name` |
| A-34 | Wrong market-partner triple | A certificate of the local or partner triple belongs to another MP-ID or carries no single URI subjectAltName, and is used anyway (RzÜ AS4 2.6 Kap. 5.2). | high | mitigate | mitigated | `tests/build_rejections.rs::bdew_partner_encryption_cert_ou_and_uri_san`, `::bdew_partner_signing_cert_uri_san`, `::bdew_local_triple_ou_and_uri_san` |
| A-35 | Unusable TLS identity | A TLS identity passes `build()` and every send then fails. The identity is loaded into the TLS context at `build()`; under `bdew()` it is required and must be EC. | critical | mitigate | mitigated | `tests/egress_mtls.rs::bdew_mutual_tls_with_brainpool_delivers_and_presents_the_tls_identity`; `tests/build_rejections.rs::bdew_builtin_client_requires_a_tls_identity`, `::bdew_tls_identity_must_be_ec` |
| A-36 | Part property injection | A caller-supplied part property forges or duplicates a header property (`MimeType`, `CompressionType`), carries CR/LF or an empty or whitespace name, or repeats a name in one part. Refused at `send` under every profile; values are escaped by the XML writer. | low | mitigate | mitigated | `tests/as4_send.rs::invalid_part_properties_are_refused_under_every_profile`, `::part_properties_round_trip_signed_in_order`; `tests/xml_emission_roundtrip.rs::soap_envelope_values_round_trip` |
| A-37 | TLS key disclosure | The TLS private key appears in `Debug` output or an unzeroized copy. Pins are shown, key bytes never; the TLS context takes the key object, not a PEM copy. | medium | mitigate | mitigated | `tests/build_rejections.rs::builder_debug_shows_pins_but_no_key_material`; `tests/egress_mtls.rs::the_pin_is_visible_in_debug`; `tests/secret_debug_redaction.rs::parties_builders_clients_and_inbounds_redact_their_keys` |
| A-38 | BDEW signer without URI SAN | An inbound BDEW signing certificate without exactly one URI subjectAltName is accepted (RzÜ AS4 2.6 Kap. 5.2). Refused as `EBMS:0101` (Kap. 9, Verstoßvariante 2). | low | mitigate | mitigated | `tests/as4_receive.rs::bdew_signer_uri_san_required` |
| A-39 | Handshake and fetch stalls | A slow or hostile server stalls a TLS handshake or a CRL fetch and holds the send path. TCP plus handshake is bounded by the connect timeout (not written), the exchange by the request timeout; CRL fetches by 3 s / 10 s. | medium | mitigate | mitigated | `src/transport/connector.rs::tests::a_stalled_handshake_times_out_not_written` |

### Open variants

- **A-02** Exclusive C14N is one implementation of this crate; the W3C vectors, xmlsec1 and phase4
  witness it but cannot find a defect they were not written for.
- **A-03** S/MIME puts the signature inside the encryption (RFC 4130), so a stranger that claims a
  configured `AS2-From` makes one private-key operation per request before the signature can be
  checked.
- **A-05** Nothing measures timing. RSA and EC timing are the backend's (OpenSSL, or the
  embedder's `Decrypter`).
- **A-06**
  - `MemoryDedup` is not durable: replay protection across a restart needs a durable store.
  - AS2 carries no signed timestamp, so an AS2 message replayed after the store dropped its
    key is new.
- **A-12, A-13** An `HttpClient` the embedder supplies is not filtered by asx-rs.
- **A-17** AS2 accepts RSA PKCS#1 v1.5 key transport and AES-CBC (128, 192, 256), which RFC 4130
  partners send; its answers are uniform (A-04).
- **A-18**
  - Outside `bdew()`, a certificate with no CRL distribution point and no OCSP responder is
    accepted and recorded.
  - The SMP signer's revocation is soft-fail: a status that cannot be obtained is accepted.
  - The distrust of a CA is not persisted across restarts.
- **A-21** Coverage-guided fuzzing does not run in CI; the fuzz tests are smoke tests.
- **A-22** BDXL answers are not DNSSEC-validated by asx-rs; validation is the resolver's.
- **A-23** `is_retryable` is false for codes other than `EBMS:0202`, so an injected
  `eb:Error` can make a sender stop retrying; keep the message and resend it (duplicates are
  detected) before dead-lettering.
- **A-24** OpenSSL is a C dependency; advisories published between changes are found at the
  next CI run.
- **A-29** The digest rule for uncompressed XML attachments has no foreign witness.
- **A-30, A-32** Below OpenSSL 3.2 the BDEW client speaks TLS 1.2 only (no RFC 8734 schemes);
  an OpenSSL built without Brainpool curves cannot speak BDEW at all.

### Embedder responsibilities

- **A-06** Use a durable `DedupStore` that passes `asx::testkit::dedup::conformance` and keeps
  keys for at least 7 days.
- **A-07** Under `bdew()` and `peppol()`, unconfigured senders whose certificate carries the
  claimed identity are admitted. A deployment that must refuse them checks the sender in its
  handler.
- **A-11** Protect the dedup and audit backends; only the embedder can make records durable and
  tamper-evident.
- **A-12, A-13** If you supply your own `HttpClient`, refuse private addresses and redirects
  and pin the connection to the validated addresses, as the built-in client does.
- **A-19** Keep keys out of core dumps, swap and ptrace (`ulimit -c 0`, `LimitCORE=0`), or keep
  them in an HSM or KMS behind `Signer` and `Decrypter`.
- **A-23** Treat `PartnerError` from an AS4 send as a routing hint, not as proof of the
  partner's decision; only a `Verified` receipt is evidence.
- Terminate inbound TLS, and mTLS where the network requires it, in the server that mounts
  `Inbound`.
- Pin partner certificates when network membership is not enough: a network CA can issue for
  any party.

## Not supported

- **AS4 pull** (ebMS3 One-Way/Pull).
- **AS4 split/join** (ebMS3 Part 2): a fragment is refused, never buffered or delivered
  (`tests/as4_ebms_adversarial.rs::fragment_message_is_refused`).
- **Asynchronous AS2 MDN delivery**: answered with a synchronous MDN; asx-rs never posts to
  the `Receipt-Delivery-Option` URL
  (`tests/as2_receive.rs::an_async_mdn_request_is_answered_synchronously`).
- **Streaming receive**: payloads are buffered up to the body limit (A-15).

Report a suspected vulnerability privately as described in [SECURITY.md](https://github.com/hupe1980/asx-rs/blob/main/SECURITY.md).
