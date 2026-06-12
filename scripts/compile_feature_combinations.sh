#!/usr/bin/env bash
set -euo pipefail

cargo check

cargo check --no-default-features --features rsa
cargo check --no-default-features --features p256
cargo check --no-default-features --features p384
cargo check --no-default-features --features p521
cargo check --no-default-features --features ed25519

cargo check --no-default-features --features rsa,p256
cargo check --no-default-features --features rsa,ed25519
cargo check --no-default-features --features p256,ed25519
cargo check --no-default-features --features p521,p256
cargo check --no-default-features --features rsa,p521
cargo check --no-default-features --features p384,p521
cargo check --no-default-features --features p521,ed25519

echo "All feature combinations checked successfully."
