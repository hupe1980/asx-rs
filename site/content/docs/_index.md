+++
title = "Documentation"
description = "Guides for embedding AS2 and AS4 messaging with asx-rs."
sort_by = "title"
template = "section.html"
page_template = "page.html"
aliases = ["/docs/architecture/"]
+++

Guides for embedding `asx-rs` in a service you operate. They assume you know
AS2 or AS4 and cover how this crate implements it: what is fixed, where the
trust boundaries are, and what you decide.

1. [Getting started](@/docs/getting-started.md): install, send, receive, handle errors.
2. [Profiles](@/docs/profiles.md): what each network preset fixes and what `build()` refuses.
3. [AS4](@/docs/as4.md) and [AS2](@/docs/as2.md): protocol details you act on.
4. [Keys and certificates](@/docs/keys.md): `KeyPair`, HSM/KMS keys, rollover.
5. [Persistence](@/docs/persistence.md): duplicate detection and the audit sink.
6. [Observability](@/docs/observability.md): spans, metrics, audit records.
7. [Security model](@/docs/security.md): what is checked, in which order.
8. [Testing](@/docs/testing.md) and [Conformance](@/docs/conformance.md).
9. [Migrating from 0.15](@/docs/migration.md).

Every Rust sample here is compiled in CI. For type-level detail see the
[API documentation](https://docs.rs/asx-rs).
