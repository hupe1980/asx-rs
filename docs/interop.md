# Interoperability

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
asx = { version = "0.1", features = ["as2", "interop-relaxed"] }
```

---

## Profile Stack

A profile stack is built by composing layers:

```rust
use asx::core::InteropMode;
use asx::interop::{
  BaseProfile, CanonicalizationPolicy, PartnerProfileOverlay, ProfileExtension,
  ProfilePolicyOverrides, ProfileStack, ProfileOverride, SecurityPolicy, ValidationPolicy,
};

let stack = ProfileStack {
  base: BaseProfile {
    name: "strict-edelivery".into(),
    version: "2.0".into(),
    mode: InteropMode::Strict,
    canonicalization: CanonicalizationPolicy::default(),
    security: SecurityPolicy::default(),
    validation: ValidationPolicy::default(),
  },
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

Resolution is deterministic: the last applicable partner overlay wins for any given field. `ProfileStack::validate()` checks for malformed or conflicting policy combinations and returns structured lint findings before any message processing.

### Resolution precedence (highest to lowest)

1. Partner overlay (per-partner configuration)
2. Global override (deployment-wide configuration)
3. Extension profile (protocol or regional extension)
4. Base profile (protocol defaults)

---

## Effective Policy Snapshot

After profile resolution, the effective policy for a session is captured in an `EffectivePolicySnapshot`. This snapshot is the authoritative record of what policy was applied for a given message exchange.

```rust
let snapshot = stack.resolve_for_session(&session)?;
let json = snapshot.to_json_pretty()?;
```

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
  "validation": {
    "reject_ambiguous_headers": true,
    "enforce_payload_limits": true,
    "require_as2_mic": true
  },
  "resolution_trace": ["base", "extension:peppol-bis", "partner:partner-acme"]
}
```

Snapshots are round-trippable: `EffectivePolicySnapshot::from_json(&json)?`.

---

## Profile Diff and Impact Analysis

Compare two profile snapshots to detect security-relevant changes before a release:

```rust
use asx::interop::diff_effective_policy_snapshots;

let report = diff_effective_policy_snapshots(&before_snapshot, &after_snapshot)?;
println!("{}", report.to_json_pretty()?);
```

`ProfileImpactReport` fields:
- `changes[]` — list of changed fields with `previous_value`, `new_value`, `risk` (`Low`/`Medium`/`High`), and `rationale`.
- `highest_risk` — highest risk across all changes.
- `release_blocked` — `true` if any change is `High` risk.

**High-risk changes** (block release):
- Removing a signature or encryption requirement
- Broad relaxed-mode overrides outside scoped partner overlays
- Disabling payload limit enforcement
- Downgrading message validation or canonicalization strictness

Run via CI gate:
```bash
cargo run -p xtask -- profile-diff-gate before_snapshot.json after_snapshot.json
```
Exits non-zero for high-risk diffs.

---

## Profile Validation and Linting

`ProfileStack::validate()` runs before any message processing and surfaces actionable findings:

```rust
let findings = stack.validate()?;
for finding in &findings {
    eprintln!("[{}] {}", finding.severity, finding.message);
}
```

Lint findings include:
- Conflicting policy combinations (e.g., `require_signature = false` + `require_encryption = true`)
- Missing required fields for a given base profile
- Partner overlay keys that do not match any known partner
- Dead overrides that do not affect the resolved effective policy

Validation is enforced as a hard release gate (`scripts/check_profile_coverage.sh`).

---

## Partner Profile Overlays

Partner overlays apply per-partner policy specializations on top of the global profile without code changes:

```rust
use asx::interop::PartnerProfileOverlay;

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

---

## Regional Profile Packs

Regional profile packs provide data-driven policy overlays loadable from JSON without code changes. They are designed for EU eDelivery network variants (Peppol, CEF, ENTSOG, BDEW) and other regional specifications.

```rust
use asx::interop::RegionalProfilePack;

let pack = RegionalProfilePack::from_json(json_str)?;
let stack = ProfileStack::builder()
    .base(BaseProfile::default())
    .regional_pack(pack)
    .build()?;
```

A regional pack can define:
- Override values for any `EffectivePolicySnapshot` field
- Partner-specific sub-overrides
- Required feature flags (e.g., `"require_sbdh": true` for Peppol)

Packs are validated on load: unknown field names and type mismatches fail fast with diagnostics.

---

## Interop Exception Policies

Exception policies define a bounded allow-list for known non-compliant partner behaviors:

```rust
use asx::interop::{InteropExceptionCode, InteropExceptionPolicy};

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
