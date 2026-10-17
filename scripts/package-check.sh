#!/usr/bin/env bash
# Build the published package, not the working tree: unpack the .crate
# outside the workspace and check it with every feature. Fails when a file a
# feature needs is left out of the package (an `exclude` pattern, a path).
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
cargo package --locked --no-verify --allow-dirty -p asx-rs >/dev/null
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
tar -xzf "target/package/asx-rs-$version.crate" -C "$dir"
CARGO_TARGET_DIR="$dir/target" cargo check --locked --all-features \
    --manifest-path "$dir/asx-rs-$version/Cargo.toml"
echo "package: asx-rs $version builds from its .crate with every feature"
