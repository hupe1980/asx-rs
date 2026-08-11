+++
title = "Interoperability"
description = "Strict and relaxed interop modes, partner profiles and overlays, exception policies, and the deviations real AS2 and AS4 partners exhibit."
+++

## Overview

The `interop` module manages protocol policy behavior through a four-layer profile stack. Each layer narrows or specializes the effective policy for a session without modifying the layers below it.

```
base profile → extension profile → global override → partner overlay
```

---

## Interop Modes

```rust
pub enum InteropMode {
    Strict,   // Default. RFC/spec behavior enforced at every point.
  Relaxed,  // Scoped tolerances for known non-compliant partner edge cases.
}
```

Selected in profile policy:
```rust
let session = SessionContext::new("sess-1", "partner-a", "profile-a")?;
```

`interop-strict` is in the default Cargo feature set. `interop-relaxed` is optional and must be explicitly enabled:
```toml
asx-rs = { version = "0.13", features = ["as2", "interop-relaxed"] }
```

### Interop mode does not govern message security

Neither `InteropMode::Strict` nor the `interop-strict` feature implies a strict
*security* policy. The two axes are independent:

| Axis | Controlled by | Governs |
|---|---|---|
| Interop | `InteropMode` / `interop-strict` | Header parsing, ambiguity tolerance, scoped exception guardrails |
| Security | `SecurityPolicy` / `BaseProfile::security_floor` | Whether signature and encryption are required |

A profile can be `InteropMode::Strict` and still resolve to
`require_encryption: false`. Enforce the security axis with a
[security floor](#security-floor), not by selecting a strict interop mode.

---

## Profile Stack

A profile stack is built by composing layers:

```rust
use asx_rs::core::InteropMode;
use asx_rs::interop::{
  BaseProfile, CanonicalizationPolicy, PartnerProfileOverlay, ProfileExtension,
  ProfilePolicyOverrides, ProfileStack, ProfileOverride, SecurityPolicy, ValidationPolicy,
};

let stack = ProfileStack {
  // `BaseProfile::new(name, version)` fills the rest from `BaseProfile::default()`:
  // strict mode, sign-and-encrypt required, and a matching sign-and-encrypt floor.
  base: BaseProfile::new("strict-edelivery", "2.0"),
  extensions: vec![ProfileExtension {
    name: "peppol-bis".into(),
    overrides: ProfilePolicyOverrides {
      mode: Some(InteropMode::Relaxed),
      ..Default::default()
    },
  }],
  overrides: vec![ProfileOverride {
    name: "deployment-global".into(),
    overrides: ProfilePolicyOverrides {
      mode: Some(InteropMode::Strict),
      ..Default::default()
    },
  }],
  partner_overrides: vec![PartnerProfileOverlay {
    name: "partner-acme".into(),
    partner_id: "partner-acme".into(),
    overrides: ProfilePolicyOverrides::default(),
  }],
};
```

Every field of `BaseProfile` is spelled out below; construct it directly when you
need to depart from the fail-closed defaults:

```rust
let base = BaseProfile {
  name: "strict-edelivery".into(),
  version: "2.0".into(),
  mode: InteropMode::Strict,
  canonicalization: CanonicalizationPolicy::default(),
  security: SecurityPolicy::default(),        // require_signature + require_encryption
  security_floor: SecurityPolicy::default(),  // no layer may go below this
  validation: ValidationPolicy::default(),
  as2_validation: Default::default(),
};
```

Resolution is deterministic: the last applicable partner overlay wins for any given field. `ProfileStack::validate()` checks the resolved policy for every partner before any message processing, and returns structured errors and lint findings.

### Resolution precedence (highest to lowest)

1. Partner overlay (per-partner configuration)
2. Global override (deployment-wide configuration)
3. Extension profile (protocol or regional extension)
4. Base profile (protocol defaults)

`security_floor` is deliberately **not** in this list: it lives on the base
profile only, because it is the invariant the other layers are checked against.

---

## Effective Policy Snapshot

After profile resolution, the effective policy for a session is captured in an `EffectivePolicySnapshot`. This snapshot is the authoritative record of what policy was applied for a given message exchange.

```rust
let resolved = stack.resolve_for_session(&session)?;
let json = resolved.effective_profile.snapshot.to_json_pretty()?;
```

`resolve_for_session` returns a `ResolvedSessionProfile` carrying both the
`effective_profile` and a `session` clone with the snapshot JSON attached.

### Snapshot schema

```json
{
  "session_id": "sess-1",
  "partner_id": "partner-acme",
  "profile_name": "strict-edelivery+peppol-bis",
  "resolved_mode": "Strict",
  "canonicalization": {
    "wssec": { "kind": "Exclusive", "include_comments": false, "strip_blank_text": false },
    "normalize_mime_headers": true
  },
  "security": {
    "require_signature": true,
    "require_encryption": true
  },
  "security_floor": {
    "require_signature": true,
    "require_encryption": true
  },
  "validation": {
    "reject_ambiguous_headers": true,
    "enforce_payload_limits": true
  },
  "as2_validation": {
    "require_mic": true
  },
  "resolution_trace": ["base", "extension:peppol-bis", "partner:partner-acme"]
}
```

Snapshots are round-trippable: `EffectivePolicySnapshot::from_json(&json)?`.

### Protocol-neutral vs AS2-only validation

`ValidationPolicy` carries only knobs that apply to both protocols
(`reject_ambiguous_headers`, `enforce_payload_limits`). AS2-only settings live in
`As2ValidationPolicy`, so an AS4 profile never has to carry — or explicitly
disable — a setting that cannot apply to it:

| Type | Field | Applies to |
|---|---|---|
| `ValidationPolicy` | `reject_ambiguous_headers` | AS2 + AS4 |
| `ValidationPolicy` | `enforce_payload_limits` | AS2 + AS4 |
| `As2ValidationPolicy` | `require_mic` | AS2 only (RFC 4130 §7.3 `Received-Content-MIC`) |

AS4 integrity is carried by the WS-Security XML Signature, not by an AS2 MIC, so
AS4-only profiles can leave `as2_validation` at its default and ignore it.

`as2_validation` is `#[serde(default)]` on both `ProfilePolicyOverrides` and
`EffectivePolicySnapshot`, so JSON written before the split still deserializes; a
stale `require_as2_mic` key inside `validation` is ignored. Override it like any
other layer:

```json
{
  "pack_id": "de-as2",
  "version": "1.0.0",
  "applies_to_base_profile": "base",
  "overrides": { "as2_validation": { "require_mic": false } }
}
```

---

## Profile Diff and Impact Analysis

Compare two profile snapshots to detect security-relevant changes before a release:

```rust
use asx_rs::interop::diff_effective_policy_snapshots;

let report = diff_effective_policy_snapshots(&before_snapshot, &after_snapshot);
println!("{}", report.to_json_pretty()?);
```

`ProfileImpactReport` fields:
- `changes[]` — list of changed fields with `previous_value`, `new_value`, `risk` (`Low`/`Medium`/`High`), and `rationale`.
- `highest_risk` — highest risk across all changes.
- `release_blocked` — `true` if any change is `High` risk.

**High risk** (blocks release):
- Removing a signature or encryption requirement
- **Lowering `security_floor`** — flagged even when the resolved policy is unchanged, because it is precisely the change that lets a later overlay relax security without validation objecting
- Disabling payload limit enforcement

**Medium risk** (reported, does not block):
- Interop mode changes
- Canonicalization changes
- Raising `security_floor`
- Strengthening the security policy
- AS2 `require_mic` changes

Run via CI gate:
```bash
cargo run -p xtask -- profile-diff-gate before_snapshot.json after_snapshot.json
```
Exits non-zero for high-risk diffs.

---

## Security Floor

`ProfileStack.overrides` and `ProfileStack.partner_overrides` are public `Vec`
fields, so any overlay can rewrite `SecurityPolicy`. `BaseProfile::security_floor`
is the invariant that survives that: **no layer may resolve below it.**

It defaults to `SecurityPolicy::SIGN_AND_ENCRYPT`, which is what PEPPOL, CEF
eDelivery and BDEW AS4-Profil v1.2 §2.2.6.2.2 all mandate. A partner overlay that
keeps signing but turns encryption off is therefore rejected:

```rust
stack.partner_overrides.push(PartnerProfileOverlay {
  name: "legacy-partner".into(),
  partner_id: "9900000000001".into(),
  overrides: ProfilePolicyOverrides {
    security: Some(SecurityPolicy::SIGN_ONLY),
    ..Default::default()
  },
});

let failure = stack.validate().unwrap_err();
assert!(failure.has_code(ProfileValidationCode::SecurityFloorViolation));
assert_eq!(failure.affected_partners(), vec!["9900000000001"]);
```

`SecurityPolicy` is a two-element lattice with named constants and ordering
helpers:

| Item | Meaning |
|---|---|
| `SecurityPolicy::SIGN_AND_ENCRYPT` | Both required — the default, and the default floor |
| `SecurityPolicy::SIGN_ONLY` / `ENCRYPT_ONLY` | One required |
| `SecurityPolicy::UNCONSTRAINED` | Neither required; valid as a *floor*, rejected as an effective policy |
| `a.satisfies(floor)` | `a` is at least as strong as `floor` |
| `floor.unmet_by(a)` | Which requirements `a` is missing, as `Vec<SecurityRequirement>` |
| `a.strengthen(b)` / `a.weaken(b)` | Lattice join / meet |

### Enforcing a floor the profile does not declare

A host with its own mandate should not have to trust the profile's floor.
`validate_with_floor` combines the two by taking the stronger of each
requirement, so it can only tighten validation:

```rust
// Fails if any partner resolves below sign-and-encrypt, regardless of
// what BaseProfile::security_floor says.
stack.validate_with_floor(SecurityPolicy::SIGN_AND_ENCRYPT)?;
```

For full control, use `validate_with`:

```rust
use asx_rs::interop::ProfileValidationOptions;

stack.validate_with(
  &ProfileValidationOptions::default()
    .with_security_floor(SecurityPolicy::SIGN_AND_ENCRYPT)
    // Any overlay that weakens security fails, even above the floor.
    .forbidding_security_relaxation(),
)?;
```

---

## Profile Validation and Linting

`ProfileStack::validate()` runs before any message processing. It resolves the
stack **once per scope** — the deployment baseline, then a fork of it for every
partner in `partner_overrides` — so one partner's overlay never contaminates
another's findings, and every finding names the scope it came from.

```rust
match stack.validate() {
    Ok(report) => {
        for lint in &report.lints {
            eprintln!("{lint}");   // [info/dead_override] override:x: … — hint: …
        }
    }
    Err(failure) => {
        // Multi-line operator rendering, every error and lint.
        eprintln!("{}", failure.report());
    }
}
```

### Errors (block validation)

| Code | Raised when |
|---|---|
| `SecurityFloorViolation` | A scope's **resolved** policy is below the effective floor |
| `NoCriticalSecurityInvariant` | A scope resolves with neither signature nor encryption (only reachable when the floor is permissive) |
| `SecurityRelaxation` | A layer weakened security while `forbid_security_relaxation` was set |

Errors are raised against the *resolved* policy per scope, not per layer: a dip
that a later overlay restores has no runtime effect and is not an error.

### Lints (never block; carry a severity)

| Code | Severity | Raised when |
|---|---|---|
| `SecurityRelaxation` | `Critical` | Any layer drops a requirement a lower layer had enabled — including a dip that is later restored |
| `DeadOverride` | `Info` | A layer sets a field to the value already in effect |

```rust
let report = stack.validate()?;
if report.highest_lint_severity() >= Some(ProfileLintSeverity::Critical) {
    for lint in report.lints_at_least(ProfileLintSeverity::Critical) {
        eprintln!("blocking: {lint}");
    }
}
```

### Error handling

`ProfileValidationFailure` implements `Display` and `std::error::Error`, so it
composes with `thiserror`, `anyhow`, and `Box<dyn Error>`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error(transparent)]
    Profile(#[from] asx_rs::interop::ProfileValidationFailure),
}
```

`?` also works directly in any function returning the crate's `Result`, via
`From<ProfileValidationFailure> for AsxError` (`ErrorCode::PolicyViolation`).

| Rendering | Shape | Use for |
|---|---|---|
| `Display` / `to_string()` | One line, first 3 errors, then `(+N more)` | Error chains, log fields |
| `report()` | Multi-line, every error and lint with hints | Startup failure logs |
| `Debug` | Struct dump | Test assertions only |

Programmatic access stays available: `errors`, `lints`, `first_error()`,
`has_code(code)`, and `affected_partners()`.

Validation is enforced as a hard release gate (`scripts/check_profile_coverage.sh`).

---

## Partner Profile Overlays

Partner overlays apply per-partner policy specializations on top of the global profile without code changes:

```rust
use asx_rs::interop::PartnerProfileOverlay;

let overlay = PartnerProfileOverlay {
  name: "partner-acme-overlay".into(),
  partner_id: "partner-acme".into(),
  overrides: ProfilePolicyOverrides {
    mode: Some(InteropMode::Relaxed),
    ..Default::default()
  },
};
```

Overlays are composable: multiple overlays for the same partner are merged in declaration order, with later entries winning.

### Auditing overlays without a session

`ProfileStack::resolve(&SessionContext)` needs a live session, which startup
validation does not have. The session-free counterparts answer "what will
partner X actually get?" before the first message:

| Method | Returns |
|---|---|
| `resolve_baseline()` | `ResolvedPolicyView` for base + extensions + global overrides |
| `resolve_partner(id)` | `ResolvedPolicyView` for one partner |
| `resolve_all_partners()` | Baseline first, then one view per distinct partner |
| `partner_ids()` | Distinct partner ids carrying an overlay, in declaration order |

All of them go through the same resolution path as `resolve()`, so a
session-free view can never drift from what a live session receives.

```rust
let weak: Vec<_> = stack
    .resolve_all_partners()
    .into_iter()
    .filter(|view| !view.satisfies(SecurityPolicy::SIGN_AND_ENCRYPT))
    .map(|view| view.scope_label().to_string())  // "<baseline>" or the partner id
    .collect();
```

Prefer `validate_with_floor` when the assertion is a plain security floor; use
`resolve_all_partners()` when it is over other policy fields.

---

## Regional Profile Packs

Regional profile packs provide data-driven policy overlays loadable from JSON without code changes. They are designed for EU eDelivery network variants (Peppol, CEF, ENTSOG, BDEW) and other regional specifications.

```rust
use asx_rs::interop::RegionalProfilePack;

let pack = RegionalProfilePack::from_json(json_str)?;
let stack = base_stack.apply_regional_pack(&pack)?;   // or apply_regional_packs(&[…])
```

A pack is applied as an additional extension layer, so it sits above the base
profile and below global and partner overrides. A pack whose
`applies_to_base_profile` does not match the active base is rejected with
`ErrorCode::PolicyViolation`.

A regional pack can define override values for `mode`, `canonicalization`,
`security`, `validation`, and `as2_validation`. It cannot raise or lower
`security_floor` — the floor is base-only, so a data-driven pack can never
loosen the invariant a pack-applying deployment relies on.

Packs are validated on load: the JSON is capped at
`RegionalProfilePack::MAX_PACK_JSON_BYTES` (512 KiB), `pack_id` and
`applies_to_base_profile` must be non-empty, and `version` must be semver-like
`x.y.z`.

---

## Interop Exception Policies

Exception policies define a bounded allow-list for known non-compliant partner behaviors:

```rust
use asx_rs::interop::{InteropExceptionCode, InteropExceptionPolicy};

let exceptions = InteropExceptionPolicy::scoped(
  "profile-a",
  vec![InteropExceptionCode::As2AllowMissingMdnBoundary],
);
```

Each allowed exception emits an `AuditEvent` with a reason code so that exception usage is traceable. Exceptions are partner-scoped and do not affect sessions with other partners.

---

## WS-Security Strict Behavior

WS-Security verification is strict-only in runtime APIs.

- Canonicalization and reference verification use strict defaults only.
- `InteropMode::Relaxed` controls scoped interop exception guardrails only.
- Relaxed mode does not enable WS-Security canonicalization/profile fallback behavior.

---

## Bounded Streaming and Wire Limits

`wire::StreamLimits` is the central configuration point for all I/O bounds:

```rust
pub struct StreamLimits {
  pub max_body_bytes: usize, // Default: 256 MiB
  pub chunk_bytes: usize,    // Default: 64 KiB
}
```

`read_bounded_stream_into_memory_async`, `read_bounded_stream_into_handle_async`, and `copy_bounded_stream_async` all enforce `max_body_bytes` and return `Err` if the limit is exceeded.
