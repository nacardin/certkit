#/usr/bin/env bash
cargo build

cargo build --no-default-features --features rsa
cargo build --no-default-features --features p256
cargo build --no-default-features --features p384
cargo build --no-default-features --features p521
cargo build --no-default-features --features ed25519

cargo build --no-default-features --features rsa,p256
cargo build --no-default-features --features rsa,ed25519
cargo build --no-default-features --features p256,ed25519
cargo build --no-default-features --features p521,p256
cargo build --no-default-features --features rsa,p521
cargo build --no-default-features --features rsa,ed25519
cargo build --no-default-features --features p521,ed25519


