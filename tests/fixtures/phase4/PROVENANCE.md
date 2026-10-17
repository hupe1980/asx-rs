# asx-phase4-peer

A minimal AS4 counterparty built only from phase4's public API (Maven Central
artefacts). `tests/interop_phase4_*.rs` drive it through the harness in
`tests/common/phase4/`.

## Build and run

```sh
just interop                                  # builds the image, runs every interop suite
ASX_PHASE4_IMAGE=$(docker build -q tests/fixtures/phase4) \
  cargo test --all-features --test interop_phase4_counterparty -- --ignored --nocapture
```

The image is not published. CI (`interop` job in `.github/workflows/ci.yml`)
builds it from this directory with a layer cache and passes its id in
`ASX_PHASE4_IMAGE`. Image ids are not reproducible across cold caches, so
`PHASE4_PEER_IMAGE` in `tests/common/phase4/image.rs` is only a default: the
local id of revision 4.8.1-r3
(`sha256:5d343139a158d5270f143819b9a3545664bd24070229399d22e0be25a32b8bc7`,
macOS arm64, Docker 29.8.0, `docker build --provenance=false`).

## Inputs

| Input | Pin |
|---|---|
| phase4 | 4.8.1 (`phase4-lib`, `phase4-profile-bdew`, `phase4-bdew-client`, `phase4-profile-cef`, `phase4-cef-client`), dependency management from `phase4-parent-pom:4.8.1` |
| Build image | `maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237` |
| Runtime image | `eclipse-temurin:21.0.8_9-jre@sha256:66bb900643426ad01996d25bada7d56751913f9cec3b827fcb715d2ec9a0fbfc` |
| Resolved at build | BouncyCastle 1.86, WSS4J 4.0.2, Santuario 4.0.4, ph-commons 12.5.1, log4j 2.26.1, Jackson 2.18.2, Jakarta Servlet API 6.1.0 |

Every build runs `maven-enforcer-plugin` `requireReleaseDeps` and `--strict-checksums`.

## How the peer works

- **No servlet container.** `/as4/{variant}` and `/control/*` are served by the
  JDK's `HttpServer` around phase4's `AS4RequestHandler`; the global scope is
  opened with `WebScopeManager.onGlobalBegin(MockServletContext.create())`.
- **P-Mode** is phase4's `AS4DefaultPModeResolver(profile)`; no security
  setting is overridden. `application.properties` keeps
  `phase4.incoming.signature.requirefullcoverage=true` and
  `phase4.compatibility.domibus=false`.
- **PEM keys.** The harness hands over PEM certificates and PKCS#8 keys; the
  peer builds BouncyCastle in-memory PKCS#12 stores (the JDK's SunEC does not
  implement brainpoolP256r1).
- **`/control/send`** implements the `bdew` profile only (`Phase4BDEWSender`).
  `"service"`/`"action"` replace the ping/business defaults; with
  `"payloads": []` and the BDEW path-switch URIs phase4 sends a signed,
  payload-less UserMessage.
- **BDEW encryption.** `Phase4BDEWSender` 4.8.1 alone configures no key
  agreement, so `ControlHandler` sets `ECDH_ES` + `CONCAT_KDF` + `AES_128` key
  wrap + encrypted session key + X509 SKI on `cryptParams()`. Wire result: one
  `xenc:EncryptedKey` carrying the `ReferenceList`, one SwA `EncryptedData`
  (aes128-gcm, `Attachment-Content-Only`) per part.
- **Clock.** `/control/version` reports `nowEpochMillis`; the harness refuses a
  peer more than 30 s off the host clock as `INFRA:` (`MAX_CLOCK_SKEW`,
  `tests/common/phase4/peer.rs`), since WSS4J would answer `EBMS:0102`.

## phase4 behaviour the harness relies on

- BDEW pings are handed to the application (`bInvokeSPIForPingMessage = true`);
  the inbox records them.
- `Phase4BDEWSender` requires a payload except for `requestSwitch`/
  `confirmSwitch`, so pings carry one payload in both directions.
- The BDEW compatibility validator requires `EMT.MAK` in the signing and TLS
  certificate CN and the first OU equal to the From party id; the harness
  issues leaves as `CN=<label> <role> <MP-ID>.EMT.MAK, OU=<MP-ID>`.
- Every WS-Security failure (signature or decryption) is answered `EBMS:0102`.
- A `wsse:SecurityTokenReference` to an `#X509PKIPathv1` token must carry
  `wsse11:TokenType` (WS-I BSP R5215).
- phase4's MIME messages start with `CRLF--boundary` (empty preamble).
