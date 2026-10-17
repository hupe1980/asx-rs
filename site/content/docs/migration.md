+++
title = "Migrating from 0.15"
description = "Every 0.15 to 0.16 wire change and API replacement, grouped by task."
+++

0.16 replaces the public API in one step, without deprecation shims. The new
shape: a `Profile` preset is the only source of security settings; `As4` and
`As2` clients (built with `LocalParty`, `Partner`s and trust anchors) return
`Verified<Receipt>`; one `Inbound` tower `Service` receives, verifies,
deduplicates and answers; keys sit behind the async `Signer` and `Decrypter`
traits; there is one `Error`.

**0.15 and 0.16 cannot exchange encrypted AS4 messages**: upgrade every asx
instance in a trading relationship together.

## Wire changes a 0.15 peer will see

| Change | 0.15 | 0.16 | Consequence |
|---|---|---|---|
| **SwA encryption shape** | a standalone `xenc:EncryptedData` document per MIME part, outside `wsse:Security` | WSS SwA 1.1 §5.5: `xenc:EncryptedKey` and one `xenc:EncryptedData` per part (`Attachment-Content-Only`, `CipherReference` to the `cid:`) in `wsse:Security`; parts are `application/octet-stream` IV ‖ ciphertext ‖ tag | **lockstep**: neither side decrypts the other (0.16 answers `EBMS:0103`); WSS4J peers (phase4, Holodeck, Domibus) interoperate |
| **Order** | compress → encrypt → sign (the `cid:` digests covered ciphertext) | compress → **sign → encrypt** (digests cover the compressed plaintext); inbound decrypts only after verifying | resends reproduce every digest |
| **Every AS4 preset encrypts** | sign-only possible (default `encrypt: false`) | always sign and encrypt (eDelivery 1.15 §3.2.6, BDEW §2.2.6.2.2) | sign-only partners have no equivalent |
| **ECDSA `ds:SignatureValue`** | ASN.1 DER | XMLDSig 1.1 `r ‖ s` (64 octets on P-256 and BrainpoolP256r1); DER is refused | **lockstep** for EC (BDEW) peers; RSA unchanged |
| **`eb:MessageId`** | carried `wsu:Id="as4-message-id"` (invalid per the ebMS3 schema) | no attribute | `eb:Messaging` digest changes; phase4 no longer answers `EBMS:0009` |
| **PKIPath token reference** | STR to the `#X509PKIPathv1` token without a token type | `wsse11:TokenType="…#X509PKIPathv1"` (WS-I BSP R5215); the last certificate of the path is the signer | WSS4J accepts BDEW signatures |
| **`eb:Property`** | value in a `value` attribute; compression properties read from `eb:Properties` | value as element text; compression properties from the signed `eb:PartProperties` only; a `value` attribute or a part property repeated in one `eb:PartInfo` is refused | |
| **Message ids** | AS2 sent `Message-ID: <id@asx>` | AS2 `<id>` with your RFC 2822 `id-left@id-right`; AS4 ids are RFC 2822 msg-ids too | build ids as `"{id}@{your-domain}"` |
| **Unsigned AS4 message** | answered `EBMS:0101` | answered `EBMS:0103` PolicyNoncompliance | |
| **BDEW unconfigured senders** | refused unless pinned | accepted when the verified SM-PKI certificate carries the claimed MP-ID as subject **OU** (BDEW 1.2 §2.3.2, §2.3.4.4; RzÜ AS4 2.6 §5.2) | MP-ID only in the CN is refused, also at `build()` |
| **`eb:Timestamp` window** | 300 s both ways | 300 s ahead, 24 h behind (the dedup retention) | a retry within a day is a duplicate, not a replay |
| **BDEW header** | caller-set action, roles, conversation id, agreement | always gzip; fixed Action, roles and `AgreementRef` ([profiles](@/docs/profiles.md#what-each-preset-fixes)); empty `ConversationId`; no `eb:MessageProperties`; PKIPath token | setting a conversation id is refused |
| **Content-IDs** | random | `part<N>.<hash>@asx` from message id and part index; deterministic gzip | identical resends |
| **Duplicates** | returned to the embedder | AS4: fresh signed receipt; AS2: `processed/warning: duplicate-document` | |
| **In flight** | embedder-chosen status | HTTP 503 | |
| **Handler refusal** | embedder-chosen | AS4 `EBMS:0202` DeliveryFailure; AS2 `processed/error: unexpected-processing-error` | |
| **Test service** | delivered like a business message | receipted, never delivered | |
| **AS2 inbound** | unsigned or unencrypted accepted, verifier-dependent | refused: `insufficient-message-security`; RFC 5402-compressed content that is not a MIME entity: `decompression-failed` | |
| **AS2 MDN request** | configurable | always a signed MDN with `sha-256`, synchronous unless `send_async_mdn` | |
| **Peppol file names** | `Content-Disposition` allowed | not written; `Payload::named` refused (Peppol AS4 §4.10) | |
| **Decryption failures** | distinguishable errors | one indistinguishable answer (`EBMS:0102` / `decryption-failed`) | |
| **Inbound XML Encryption parameters** | KDF, curve and OAEP parameters ignored | required and checked before the key is used; `rsa-1_5`, `rsa-oaep-mgf1p`, `mgf1sha1`, CBC refused | |
| **BDEW path switch** | not implemented | `requestSwitch`/`confirmSwitch` sent and accepted (BDEW 1.2 §2.2.8) | |
| **Revocation** | OCSP modes, failure modes, static CRL lists (`revocation_crl_pems`); AS2 checked the signer only | the profile's rule (BDEW: CRL-DP with the RzÜ §5.4 three-day rule; others: CRL-DP then OCSP) over the signer's whole path, via the client's `HttpClient`; `Builder::crl_signer` for indirect CRLs ([security](@/docs/security.md#revocation)) | no revocation settings, no stapled responses |

## Cargo

| 0.15 | 0.16 |
|---|---|
| `asx-rs = { version = "0.15", features = ["as4", "client", "server", "interop-strict"] }` | `asx-rs = "0.16"` (default `as2`, `as4`, `http-client`), or `default-features = false, features = ["as4", "http-client"]` |
| `use asx_rs::…` | `use asx::…` (the package is still `asx-rs`) |
| feature `crypto`, `compression` | part of `as2`/`as4` |
| feature `client`, `async-ocsp` | `http-client` |
| feature `server` (and the `axum` dependency) | removed: `Inbound` is a tower `Service`; mount it with `Router::route_service` |
| feature `dns` | part of `peppol` |
| feature `trace`, `prometheus`, `opentelemetry` | spans are always on; `metrics` for counters, an exporter in your application |
| feature `testing` | removed: the additive `test-util` feature (`asx::testkit`) in dev-dependencies |
| feature `interop-strict`, `interop-relaxed` | removed: strict only; per-partner `Quirk`s |

## Configure

| 0.15 | 0.16 |
|---|---|
| `SessionContext`, `SessionContextBuilder`, `SessionMetadata`, `CorrelationScope`, `CertHandle`, `PartnerCredentials` (`credentials`) | `LocalParty` (id, party type, signer, decrypters, TLS identity), `Partner` (id, type, endpoint, signing and encryption certificates), `Builder::trust_anchor`; the internal session is built by the client |
| `As4SendPolicy`, `As4PushPolicy`, `As4ReceiptPolicy`, `As4PullPolicy`, `As2SendPolicy`, `As2ReceivePolicy`, `As2SignaturePolicy`, `As2MicAlgorithm`, `SmimeCipher`, `WsSecOutboundKeyInfoProfile`, `FragmentScopePolicy`, `OcspMode`, `OcspFailureMode` | `Profile::bdew()`, `peppol()`, `edelivery_1_15()`, `entsog()`, `as2()`; `Profile::max_message_bytes` to tighten |
| `pmode` (`PMode`, `PModeRegistry`, `PModeSecurity`, `MepType`, `PayloadPackagingMode`) | `Profile` + `Partner` + `Message` |
| `interop` (`ProfileStack` and the profile-stack types), `InteropMode`, `InteropExceptionPolicy`, `InteropExceptionCode`, `InteropDecision`, `enforce_exception`, `evaluate_exception_guardrail` | `Profile`; `Partner::quirk(Quirk::…)` for one absent element (see [quirks](@/docs/profiles.md#partners-and-quirks)) |
| `As4ReceiptPolicy::relaxed()` | `Partner::quirk(Quirk::ReceiptWithoutNonRepudiation)`; an unsigned receipt is never accepted |
| relaxed AS2 MDN acceptance | `Partner::quirk(Quirk::UnsignedMdn)` |
| `presets` (`StrictRuntimeBootstrap`, `StrictRuntimeBootstrapToken`, `DeploymentTopology`) | `build()`: every configuration is validated once against the profile |
| `As4SignerPins`, `As4SignerPinMap`, `signer_pins` | `Partner::signing_cert`, repeated for rollover |
| `DEFAULT_MAX_BODY_BYTES`, `enforce_payload_limit`, `RouterConfig` (body limit) | `Profile::max_message_bytes`; a body timeout is a `tower_http` layer on the route |
| `CryptoAdmissionControl`, `ASX_BLOCKING_CRYPTO_CONCURRENCY` | removed: the blocking pool is sized from available parallelism |

## Keys

| 0.15 | 0.16 |
|---|---|
| PEM fields on `CertHandle`, `with_signing_material(cert, key)` | `KeyPair::from_pem(chain, key)` as `LocalParty::signer` |
| decryption key PEM on the push policy | `LocalParty::decrypter(KeyPair)`, repeatable for rollover; mandatory (every preset encrypts) |
| `signing` (`SigningKeyProvider`, `PemSigningKeyProvider`) | the async `Signer` trait (ECDSA returns DER; the library converts) |
| no public decryption seam | the async `Decrypter` trait with `KeyOp` |
| `ClientIdentity`, `TransportConfig::with_client_identity` | `LocalParty::tls_identity(KeyPair)` |
| `crypto`, `wssec`, `soap_builder`, `as2_smime`, `ocsp_client`, `ocsp_discovery`, `fingerprint`, `compression` modules | crate-private; `Certificate`, `KeyPair`, `Signer`, `Decrypter` are the public surface |

See [keys and certificates](@/docs/keys.md).

## Send

| 0.15 | 0.16 |
|---|---|
| `as4::send_sync`, `send_async`, `send_sync_fragmented`, `As4SendRequest`, `As4SendCredentials`, `As4AdditionalPayload`, `As4SendOutput`, `package_as_mime`, `MimePackageBuilder`, `MimeAttachment`, `mime_packaging` | `As4::send(Message::to(&partner).service(..).payload(Payload::new(..)))` |
| `As4HttpTransport`, `TransportConfig`, `HttpSendOutcome`, `As4SendAndVerifyOutcome`, `verify_sync_response`, `As4SyncSignal`, `As4VerifiedReceipt`, `As4NonRepudiation`, `As4NriReference`, `As4ReceivedError`, `As4ErrorSignal`, `As4ErrorCode`, `As4ErrorSeverity`, `ParsedAs4Receipt`, `DEFAULT_MAX_RECEIPT_BYTES` | inside `As4::send`, which returns `Verified<Receipt>`; a partner `eb:Error` is `ErrorKind::PartnerError` with `ebms_code()` |
| `PayloadFilename`, `PayloadFilenameError`, `PayloadInput` | `Payload::named`; an invalid name now fails the send |
| `as2::send_sync`, `send_async`, `As2SendRequest`, `As2SendCredentials`, `As2SendOutput`, `MimeEnvelope`, `payload_content_type`, `As2HttpTransport` | `As2::send(as2::Message::to(&partner, payload))` → `Verified<Receipt>` |
| `receive_with_mdn_with_reliability`, `As2ReceiveMdnRequest`, `As2ReceiveMdnOutput`, `As2MdnMode`, `As2MdnDedup`, `ParsedMdn`, `correlate_async_mdn` | synchronous MDNs: inside `As2::send`; asynchronous: `send_async_mdn` → `PendingMdn`, then `verify_async_mdn` |
| `trace_context`, `output.traceparent` | removed: propagate from your tracing layer |
| `RetryScheduler`, `DeliveryOutcome`, `RetryDecision`, `reliability` | the application schedules retries from `Error::kind()` and `is_retryable()`, resending the same `Message` (same id and timestamp) |
| `smp` (`SmpClient`, `SmpConfig`, `SmpEndpoint`, `SmpLookupRequest`, `SmpSignaturePolicy`), `bdxl` (`SmlDiscovery`, `NaptrRecord`, `BdxlResolver`, `StaticBdxlResolver`, `HickoryBdxlResolver`, `bdxl_dns_name`, `legacy_cname_host`, `select_smp_base_url`) | `peppol::Smp::{production, test}(http, anchor).lookup(..)` → `Partner`; the SMP signature is always verified |
| `sbdh`, `mls` | crate-private: put the complete document in the `Payload` |

## Receive

| 0.15 | 0.16 |
|---|---|
| `receive_push`, `receive_push_sync`, `receive_push_fragment_aware`, `receive_push_sync_fragment_aware`, `As4ReceivePush`, `As4ReceivePushSync`, `As4ReceivePushRequest`, `As4ReceivePushOutput`, `As4ReceivePushProgress`, `As4ReceiveOutcome`, `As4ReceivedPayload`, `As4Ordered`, `ParsedAs4UserMessage`, `ParsedWsAddressingHeaders`, `SoapEnvelope` | `As4::inbound(dedup, handler)`; the handler receives `Verified<UserMessage>` (`message_id`, `from`, `service`, `action`, `payloads`, `path_switch`) |
| `generate_receipt`, `generate_receipt_with_nri`, `generate_signed_receipt_with_nri`, `generate_receipt_for_output`, `generate_signed_receipt_for_output`, `generate_error_signal`, `As4ReceiptCredentials` | automatic: the `Inbound` answers with a receipt signed by the local signer in the profile's token form, or the error of the [response table](@/docs/as4.md#what-the-sender-is-told) |
| `As4Verifier`, `As4WsSecVerifier`, `InsecureBypassAs4Verifier`, `*_with_custom_verifier`, `verifier_seal` | removed: there is one verifier, and it cannot be replaced or bypassed |
| `test_service` helpers | `Message::ping`; inbound pings are answered automatically |
| `receive_sync`, `receive_async`, `receive_from_ingress`, `As2IngressReceiveRequest`, `As2InboundResult`, `validate_as2_version_header` | `As2::inbound(dedup, handler)` with `Verified<Received>` |
| `generate_mdn`, `As2GeneratedMdn`, `As2MdnSigningCredentials` | automatic: the `Inbound` answers with a signed MDN |
| `As2TrustVerifier`, `AsyncAs2TrustVerifier`, `CmsSmimeTrustVerifier`, `SyncToAsyncTrustVerifier`, `TrustResult`, `TrustVerifierSeal` | `Partner::signing_cert` + `Builder::trust_anchor` |
| `receive_stream`, `receive_stream_with_metrics`, `receive_stream_with_metrics_and_audit`, `stream_receive`, `spool_key` (`SpoolEncryptionKeyProvider`, `StaticSpoolKey`), `spool_policy`, `spool_runtime_utils` (`profile_name`), `SpoolEncryption`, `SpoolLifecyclePolicy`, `ReceivedBodyHandle`, `wire` (`StreamBodyPolicy`, `StreamLimits`, `StreamReadMetrics`) | removed: the `Inbound` reads the body up to `max_message_bytes` |
| `transport` (`As2HttpIngress`, `As4HttpIngress`, `as2_ingress_from_http`, `as4_ingress_from_http`, `As4IngressReceivePushSyncRequest`, `HttpRequest`, `HttpHeaders`) | `Inbound` takes an `http::Request<B>` |
| `server` (`as2_router`, `as4_router`, `RouterConfig`, `As2AxumHandler`, `As4AxumHandler`, `HandlerOutcome`) | `axum::Router::new().route_service(path, inbound)`; handler `Ok`/`Err(Reject)` |
| `lifecycle` (`UntrustedBytes`, `StructurallyParsed`, `CryptographicallyVerified`, `ContentDecrypted`, `DomainReady`, `TrustEvidence`, `SignatureVerification`, `DecryptionMaterial`) | `Verified<T>`, which only the library constructs |
| pull: `pull`, `pull_store`, `As4PullStore`, `As4PullAuthorization`, `As4PullRequestCredentials`, `As4GeneratePullRequestPolicy`, `As4ReceivePullRequest`, `As4ReceivePullOutput`, `As4QueuedPullMessage`, `enqueue_pull_with_reliability`, `receive_pull_with_reliability`, `As4PullEnqueueOutcome`, `As4PullQueueOverflowPolicy`, `generate_pull_request` | removed: no One-Way/Pull |
| split/join: `large_message`, `As4FragmentJoiner`, `As4JoinProgress`, `As4JoinedLargeMessage`, `As4SplitFragmentOutput` | removed: no split/join |
| ordering: `conversation_gate`, `coordination`, `As4ConversationOrderGate`, `ConversationGuard`, `ConversationTurnHandle`, `ConversationOrderGate`, `As4TopologyCoordination` | removed: order in the application if your process needs it |

## Store

| 0.15 | 0.16 |
|---|---|
| `storage` (`DedupStorage` with `is_durable`/`cluster_safe`, `claim → DedupVerdict`, `accept`/`abandon(key)`), `DedupClaim` | `DedupStore`: `claim(key) → Claim::{Claimed(ClaimToken), Duplicate, InFlight}`, `accept(key, &token)`, `abandon(key, &token)`; settle only when the token still matches (compare-and-set) |
| `TtlDedupStorage`, `reliability::InMemoryDedupBackend` | `MemoryDedup` (not durable) |
| `drive_dedup_future`, `drive_sync_future`, `BoxFuture` in `storage` | `asx::BoxFuture`; settlement is internal |
| `ReconciliationStorage` and the reconciliation types, `DeadLetterSink` | removed: the application's outbox decides |
| dedup keys of your own format | 64-hex digests of a stable format; existing rows do not carry over |

See [persistence](@/docs/persistence.md).

## Observe

| 0.15 | 0.16 |
|---|---|
| `observability` (`EventBus`, subscriptions, `AsxEvent`, `MetricsSink`, `PrometheusMetricsSink`, `OtelMetricsSink`) | `tracing` spans under target `asx`; feature `metrics` with an exporter in your application ([observability](@/docs/observability.md)) |
| `DurableAuditSink`, `AuditEvent`, replay cursors | `AuditSink` (`durability`, async `record(&AuditRecord)`) installed with `Builder::audit` |
| `fail_closed_audit_events` | the sink's declared `AuditDurability` |
| `AsxError`, `ErrorCode`, `ErrorContext` | `Error`: `kind()`, `is_retryable()`, `ebms_code()`, `mdn_disposition()`, `evidence()` |

## Test

| 0.15 | 0.16 |
|---|---|
| `features = ["testing"]` | `features = ["test-util"]` in dev-dependencies ([testing](@/docs/testing.md)) |
| `fixtures::generate_self_signed_*` | `asx::testkit::pki::TestCa` (`sm_pki().bdew_party(mp_id)` puts the MP-ID in the OU) |
| `as4::mock_endpoint::MockAs4Endpoint`, `As4HttpTransport::new_for_localhost_testing` | `asx::testkit::loopback::Loopback` mounting a real partner client's `Inbound` |
| `storage::conformance`, `DurableInMemoryDedupBackend` | `asx::testkit::dedup::conformance`, `asx::testkit::audit::conformance` |
| `EventBus::new_for_testing` | `asx::testkit::trace::TraceCapture`, `asx::testkit::audit::MemoryAuditSink` |

## Internal helpers that became private

`escape_xml`, `constant_time_eq` and `crypto_permit`: crate-private, no
replacement needed.

## Recipes and tooling

Removed: `just interop-matrix`, `just fuzz-gate`, `profile-lint`,
`profile-diff`, `profile-coverage`, `fixtures-validate`.
`cargo run -p xtask -- example-pki examples/pki` writes the README examples'
key material.
