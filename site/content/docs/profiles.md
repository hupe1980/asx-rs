+++
title = "Profiles"
description = "What each network preset fixes, partner quirks, and what build() refuses."
aliases = ["/docs/interop/"]
+++

A [`Profile`](https://docs.rs/asx-rs/latest/asx/struct.Profile.html) is the
only source of security and wire settings. It is opaque, has no `Default` and
no method that loosens a value: pick the preset your network publishes.

## Choosing a preset

| Network | Preset | Protocol |
|---|---|---|
| German energy market (MaKo): BDEW AS4-Profil 1.2 with *Regelungen zum Übertragungsweg AS4* 2.6 | `Profile::bdew()` | AS4 |
| Peppol AS4 Profile 2.0.3 | `Profile::peppol()` | AS4 |
| eDelivery AS4 1.15 Common Profile | `Profile::edelivery_1_15()` | AS4 |
| ENTSOG AS4 Usage Profile 3.6 | `Profile::entsog()` | AS4 |
| AS2 (RFC 4130) | `Profile::as2()` | AS2 |

`build()` refuses an AS2 preset on `As4::builder` and vice versa.

## What each preset fixes

Sources: **B** BDEW AS4-Profil 1.2 (01.04.2026); **RzÜ** Regelungen zum
Übertragungsweg AS4 2.6; **TR** BSI TR-03116-3; **P** Peppol AS4 Profile
2.0.3; **E** eDelivery AS4 1.15; **G4** ENTSOG AS4 Usage Profile 4.0;
**G-FAQ** ENTSOG AS4 FAQ 2025 §2.4 (the sections changed between 3.6 and 4.0;
a row citing G4 is unchanged in 3.6); **AS4** OASIS AS4 Profile 1.0;
**R4130** RFC 4130. Each preset's rustdoc carries the same table.

### AS4 presets

| Setting | `bdew()` | `peppol()` | `edelivery_1_15()` | `entsog()` |
|---|---|---|---|---|
| MEP | One-Way/Push, receipts and errors synchronous (B §2.2.1, §2.2.2, §2.2.4, §2.2.5) | One-Way/Push (P §4.1) | One-Way/Push, signed receipt synchronous (E §3.2.1, §3.3.2) | One-Way/Push (G4 §2.2.1–2.2.2) |
| Packaging | SwA, one MIME part per payload, empty Body, part type `application/octet-stream` (B §2.2.3.2) | attachments only (P §4.10) | SwA (E §3.2.3) | SwA (G4 §2.2.3) |
| Compression | gzip, always (B §2.2.3.3 "MUSS") | gzip (P §4.10) | gzip (E §3.3.1 "SHOULD compress") | gzip, always (3.6 "Mandatory", G-FAQ §2.4) |
| File name (`Payload::named`) | allowed (BDEW file names) | **refused** (P §4.10 "SHALL NOT be used") | allowed | allowed |
| Signature | `ecdsa-sha256` on BrainpoolP256r1, SHA-256 digests (B §2.2.6.2.1; TR §9.1) | `rsa-sha256`, RSA ≥ 2048 (P §3 → E §3.2.6) | `rsa-sha256`, RSA ≥ 2048 (E §3.2.6) | `rsa-sha256`, RSA ≥ 2048 (G-FAQ §2.4 on §2.2.6.2) |
| Signing token | BST `#X509PKIPathv1` with the chain (B §2.2.6.2.1) | BST `#X509v3` (P §4.7) | BST `#X509v3` (E §3.2.6) | BST `#X509v3` |
| Key transport | ECDH-ES + ConcatKDF (SHA-256) + `kw-aes128` (B §2.2.6.2.2; TR §9.2) | RSA-OAEP, MGF1-SHA-256, SHA-256 (E §3.2.6) | RSA-OAEP, MGF1-SHA-256, SHA-256 (E §3.2.6) | RSA-OAEP (G-FAQ §2.4 on §2.2.6.3) |
| Recipient reference | `X509SKI` (B §2.2.6.2.2, §2.3.4.3) | BST `#X509v3` (P §4.7) | BST (E §3.2.6) | BST |
| Keys | separate EC BrainpoolP256r1 pairs for signing, encryption and TLS (B §2.3.4.4) | one AP certificate for both (P §4.7) | not required to differ | not required to differ |
| Party id | the 13-digit MP-ID; type one of `urn:oasis:names:tc:ebcore:partyid-type:iso6523:0088`, `…:unregistered:BDEW`, `…:unregistered:DVGW`, `…:unregistered:BAHN` (B §2.3.1.1) | fixed type `urn:fdc:peppol.eu:2017:identifiers:ap`; id = the AP certificate's CN (P §4.5) | caller-set (E §3.4.1) | caller-set |
| Service | one of `https://www.bdew.de/as4/communication/services/{MP,FP,RD,KW,SO}` (B §2.3.1.2.1) | the process id (P §4.6) | caller-set, required (E §3.4.4) | caller-set, required |
| Action | fixed `http://docs.oasis-open.org/ebxml-msg/as4/200902/action` (B §2.3.1.2.2) | the document type id (P §4.6) | caller-set (E §3.4.4) | caller-set |
| Roles | fixed initiator / responder (B §2.3.1.2.3) | fixed, same (P §4.5) | default, same | default, same |
| ConversationId | always empty; setting one fails (B §2.3.1.2.4) | caller-set | caller-set | caller-set |
| AgreementRef | `https://www.bdew.de/as4/communication/agreement`, no `pmode`/`type` (B §2.3.2) | `urn:fdc:peppol.eu:2017:agreements:tia:ap_provider` (P §4.3) | none | per G4 §2.3.2 |
| Who may send to you | any sender whose verified certificate chains to an anchor and carries the claimed MP-ID as the subject's OU, plus the pins of a configured partner (B §2.3.2, §2.3.4.4; RzÜ §5.2) | any AP whose certificate chains to an anchor and whose CN equals `eb:From/PartyId`, plus pins (P §4.5, §4.7) | configured partners with pinned certificates only | configured partners with pinned certificates only |
| Test service | receipted, never delivered (B §2.3.6) | as eDelivery | receipted, never delivered (E §3.2.4, §3.4.3) | as eDelivery |
| Path switch | requestSwitch / confirmSwitch, payload-less (B §2.2.8, §2.3.7) | — | — | — |

Common to all four: sign, then encrypt, `eb:Messaging` never encrypted
(B §2.2.6.2; E §3.2.6; AS4 §5.1.6); content encryption `aes128-gcm`
(B §2.2.6.2.2; E §3.2.6); uncompressed inbound accepted (E §3.3.1); duplicate
detection required (B §2.2.5; E §3.3.2; AS4 §3.2); size ceiling 256 MiB.

**Revocation** of every non-anchor certificate of a verified signer's path
(inbound senders, receipt and MDN signers), per preset. The mechanics are on
the [security page](@/docs/security.md#revocation).

| | BDEW | Peppol, eDelivery, ENTSOG, AS2 |
|---|---|---|
| Sources | CRL distribution point only (the SM-PKI has no OCSP, CP §4.9) | CRL-DP, then OCSP from the AIA |
| CRL without `nextUpdate` | refused (TR-03109-4 Anhang B) | valid 24 h after the fetch |
| Refetch | after 24 h, in the background (CP Tabelle 10) | same |
| CRL not obtainable | last known CRL used for 72 h after its last successful fetch, then the CA and everything below it is refused (RzÜ §5.4) | OCSP decides; neither → refused |
| CRL past `nextUpdate`, no newer | CA refused at once (RzÜ §5.4) | OCSP decides |
| No CDP and no OCSP responder | refused (TR Anhang A item 10) | Peppol: refused; others: accepted, recorded (`reason=no_source`) |

Under BDEW, pass the SM-PKI Root-CA CRL signer to `Builder::crl_signer`
(TR-03109-4 §4.2.1). Revoked from either source is final. A refusal is
`EBMS:0101` / `authentication-failed` inbound and `Indeterminate` for a
receipt or MDN signer.

**Not supported**: Peppol G3-only anchors and MLS; the ENTSOG ebCore Agreement
Update.

### `as2()`

| Setting | Value |
|---|---|
| Outbound | signed (SHA-256, RFC 5751/5754) and encrypted (AES-256-CBC), not compressed (R4130 §2.4) |
| MDN request | synchronous unless `send_async_mdn`, signed, `signed-receipt-micalg=sha-256` (R4130 §7.3) |
| MDN verification | signed by a pinned partner certificate (absent only with `Quirk::UnsignedMdn`); `Original-Message-ID` = the sent id; MIC = the computed MIC; disposition `processed`, warnings allowed (R4130 §7.3.1, §7.4.3, §7.5) |
| Inbound | must be signed and encrypted, else `processed/error: insufficient-message-security` (R4130 §7.5.3); compressed accepted |
| Inbound duplicates | `(AS2-From, Message-ID)` claimed; a duplicate is answered `processed/warning: duplicate-document` (R4130 §9.3, §7.5.6) |
| Inbound asynchronous-MDN request | answered synchronously |
| Senders | configured partners with pinned certificates |
| Signer key | RSA ≥ 2048 or EC P-256/P-384 |

## Tightening

`max_message_bytes` lowers the inbound and outbound size limit. Zero or a
value above the preset's ceiling is refused by `build()`, never clamped.

```rust
use asx::Profile;

fn bdew_with_a_64_mib_limit() -> Profile {
    Profile::bdew().max_message_bytes(64 << 20)
}
```

An inbound body above the limit gets HTTP 413 before parsing. Timeouts and
rate limits are tower layers on the route (for example
`tower_http::timeout::RequestBodyTimeoutLayer`).

## Partners and quirks

A [`Quirk`](https://docs.rs/asx-rs/latest/asx/enum.Quirk.html) tolerates one
**absent** element from one partner, never a wrong value. Every acceptance it
enables is recorded in the audit record's `quirks`; a quirk of the other
protocol is refused by `build()`.

| Quirk | Protocol | Tolerates | Still refused |
|---|---|---|---|
| `Quirk::ReceiptWithoutNonRepudiation` | AS4 | a signed receipt without `ebbp:NonRepudiationInformation` | an unsigned receipt; a receipt signed by an unpinned certificate; NRR digests that are present and differ |
| `Quirk::UnsignedMdn` | AS2 | an MDN without a signature although a signed one was requested | a signature that is present and fails; a wrong MIC or `Original-Message-ID` |

```rust
use asx::{Certificate, Partner, Quirk};

fn legacy_partner(cert: Certificate) -> Partner {
    Partner::new("9900000000003")
        .party_type("urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW")
        .endpoint("https://legacy.partner.example/as4")
        .signing_cert(cert.clone())
        .encryption_cert(cert)
        .quirk(Quirk::ReceiptWithoutNonRepudiation)
}
```

## What `build()` refuses

Every refusal is `ErrorKind::Config`, naming the setting and the profile
section (tested in `tests/build_rejections.rs`).

| Area | Refused |
|---|---|
| Local party | missing; no signer; no decrypter (every preset encrypts inbound); signer or decrypter key type not allowed by the profile; empty signer chain or a leaf not valid now; signer not chaining to a trust anchor; two decrypters with the same certificate |
| BDEW local party | signer certificate equal to a decrypter certificate; TLS identity equal to either; party id not a 13-digit MP-ID; party type missing or not one of the four of B §2.3.1.1 |
| Peppol local party | a party type set (the profile fixes it) |
| Trust | no trust anchor |
| Partners | endpoint not `https`, unparseable or carrying userinfo; an endpoint without an encryption certificate (except BDEW, where the path switch needs none); a registered partner without a signing certificate (eDelivery, ENTSOG, AS2); a certificate key type the profile does not allow; an expired or not-yet-valid certificate; two partners with the same (type, id); a partner id equal to the local id |
| BDEW partners | a signing certificate whose subject OU does not carry the partner's MP-ID (RzÜ §5.2) |
| Peppol partners | a signing certificate whose CN is not the partner id |
| Other | `max_message_bytes` zero or above the ceiling; a profile of the other protocol; a quirk of the other protocol; an AS2 id that is not 1–128 printable ASCII characters (RFC 4130 §6.2); no HTTP client with `http-client` off |

`send` refuses with `Config`, before signing anything: a missing or disallowed
service; an action or conversation id where BDEW fixes them; zero payloads
(except a path switch); a file name under Peppol or an unsafe one; a media
type that is not RFC 2045 `type/subtype`; a message id that is not RFC 2822
`id-left@id-right`; a partner without endpoint or encryption certificate; a
message above `max_message_bytes`. Certificate validity is checked again at
use.
