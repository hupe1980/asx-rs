# Releasing asx-rs

Two workflows, mirrored by two `just` recipes:

| Local | CI |
|---|---|
| `just ci` | `.github/workflows/ci.yml` jobs `check`, `features`, `msrv`, `deny` |
| `just interop` | `.github/workflows/ci.yml` job `interop` |
| — | `.github/workflows/release.yml` on a `v*` tag |

## CI workflows

`ci.yml` runs on every push to `main` and every pull request. Every job blocks.

| Job | Runs |
|---|---|
| `check` | `cargo fmt --check`; clippy (workspace, all features, all targets, `-D warnings`); rustdoc with `-D warnings`; `scripts/check-docs.sh` and `scripts/concepts-check.sh`; `cargo test --workspace --all-features` — this includes the doctests, so every Rust block of the README and the site compiles (`src/docs.rs`) |
| `features` | `cargo hack check --each-feature --lib --tests` with `-D warnings`: no default features, each feature alone, all features |
| `msrv` | `cargo +1.88 check --workspace --all-features` |
| `deny` | `cargo deny check advisories licenses bans sources` (`deny.toml`) |
| `interop` | the `#[ignore]`d oracle suites: openssl CLI (AS2 S/MIME), xmlsec1, Redis, and phase4 4.8.1 as the BDEW counterparty. The phase4 peer is built in the job from `tests/fixtures/phase4` (GitHub Actions layer cache) and passed in `ASX_PHASE4_IMAGE` |

Not in CI: `just public-api` (needs nightly and `cargo-public-api`; run it on
every API change, the snapshot is `tests/public-api.txt`, budget 160 items) and
Holodeck B2B (`tests/interop_holodeck_counterparty.rs`, arm64-only image).

`site.yml` builds the documentation site on pull requests that touch `site/`
and deploys it from `main`.

Tools for the local recipes: `cargo-hack`, `cargo-deny`, the 1.88 toolchain,
Docker and `openssl` for `just interop`, `zola` for `just site`.

## Cutting a release

1. On a branch: bump `version` in `Cargo.toml` per the
   [SemVer policy](CHANGELOG.md#semver-policy); rename `## [Unreleased]` in
   `CHANGELOG.md` to `## [X.Y.Z] — YYYY-MM-DD` and open a new empty
   `## [Unreleased]`.
2. Run `just ci`, `just interop`, `just package` and, if the API changed,
   `just public-api`.
3. Merge to `main` and wait for CI.
4. Tag and push:

   ```bash
   git tag -s vX.Y.Z -m "asx-rs X.Y.Z" && git push origin vX.Y.Z
   ```

`release.yml` then runs CI for the tagged commit, checks that the tag equals
`v` + the `Cargo.toml` version and that `CHANGELOG.md` has a `## [X.Y.Z]`
section, publishes `asx-rs` through crates.io Trusted
Publishing (`rust-lang/crates-io-auth-action`; no stored token), and creates the
GitHub release with that CHANGELOG section as its notes.

A failed run publishes nothing before the `cargo publish` step. If it failed
after publishing, create the GitHub release by hand
(`gh release create vX.Y.Z --notes-file <section>`); never re-tag a published
version — fix forward with X.Y.Z+1.

## Owner setup (once)

- crates.io → `asx-rs` → Settings → Trusted Publishing: GitHub publisher,
  owner `hupe1980`, repository `asx-rs`, workflow `release.yml`, environment
  `crates-io`.
- GitHub → Settings → Environments → `crates-io`: a required reviewer, only
  `v*` tags.
- GitHub → branch protection for `main`: require `check`, `features`, `msrv`,
  `deny` and `interop`.
- GitHub → Settings → Code security: private vulnerability reporting
  (`SECURITY.md` points there).

If OIDC is down and a release cannot wait, an owner publishes from a clean
checkout of the tag with a short-lived API token
(`cargo publish --locked`), revokes the token, and creates the GitHub release
by hand.
