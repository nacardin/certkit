#!/usr/bin/env bash
# Builds certkit across a representative set of feature combinations to ensure
# every cryptographic algorithm can be enabled and disabled independently.
# `set -e` makes the script fail on the first combination that does not compile.
set -euo pipefail

# Default feature set (all algorithms) and the all-features superset.
cargo build
cargo build --all-features

# Each algorithm on its own.
cargo build --no-default-features --features rsa
cargo build --no-default-features --features p256
cargo build --no-default-features --features p384
cargo build --no-default-features --features p521
cargo build --no-default-features --features ed25519

# A spread of pairings across algorithm families.
cargo build --no-default-features --features rsa,p256
cargo build --no-default-features --features rsa,ed25519
cargo build --no-default-features --features p256,ed25519
cargo build --no-default-features --features p521,p256
cargo build --no-default-features --features rsa,p521
cargo build --no-default-features --features p384,p521
cargo build --no-default-features --features p521,ed25519

echo "All feature combinations compiled successfully."
