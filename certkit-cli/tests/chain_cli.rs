//! Validates `certkit`-generated certificate chains with the system `openssl`
//! and `botan` CLIs.
//!
//! For each case we build a full `root -> intermediate -> leaf` chain with the
//! `certkit` binary and then have both tools verify the whole chain. A chain
//! verification exercises every signature in the path plus issuer linking
//! (Authority/Subject Key Identifiers), so it subsumes per-certificate parsing
//! and field checks. The mixed-algorithm case additionally proves a CA of one
//! algorithm can sign a subject of another.

mod common;

use std::process::Command;

use common::{Chain, build_chain, have_tool};
use tempfile::tempdir;

/// Verifies the chain with `openssl verify` (root trusted, intermediate supplied
/// as an untrusted intermediate). A non-zero exit means a signature or path
/// failure.
fn openssl_verify(chain: &Chain) {
    let output = Command::new("openssl")
        .arg("verify")
        .arg("-CAfile")
        .arg(&chain.root)
        .arg("-untrusted")
        .arg(&chain.intermediate)
        .arg(&chain.leaf)
        .output()
        .expect("failed to run openssl verify");
    assert!(
        output.status.success(),
        "openssl failed to verify the chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Verifies the chain with `botan cert_verify`. botan exits 0 even on failure,
/// so success is asserted on its stdout instead of the exit status.
fn botan_verify(chain: &Chain) {
    let output = Command::new("botan")
        .arg("cert_verify")
        .arg(&chain.leaf)
        .arg(&chain.intermediate)
        .arg(&chain.root)
        .output()
        .expect("failed to run botan cert_verify");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("passes validation checks"),
        "botan failed to verify the chain:\n{text}"
    );
}

/// Builds a chain with the given per-level algorithms and verifies it with every
/// available tool. A missing tool is skipped so local runs stay green; CI
/// installs both so the checks actually execute there.
fn assert_chain_validates(root_alg: &str, intermediate_alg: &str, leaf_alg: &str) {
    let dir = tempdir().unwrap();
    let chain = build_chain(dir.path(), root_alg, intermediate_alg, leaf_alg);

    if have_tool("openssl") {
        openssl_verify(&chain);
    } else {
        eprintln!("skipping openssl verification: openssl CLI not found");
    }

    if have_tool("botan") {
        botan_verify(&chain);
    } else {
        eprintln!("skipping botan verification: botan CLI not found");
    }
}

#[test]
fn chain_p256() {
    assert_chain_validates("p256", "p256", "p256");
}

#[test]
fn chain_p384() {
    assert_chain_validates("p384", "p384", "p384");
}

#[test]
fn chain_p521() {
    assert_chain_validates("p521", "p521", "p521");
}

#[test]
fn chain_ed25519() {
    assert_chain_validates("ed25519", "ed25519", "ed25519");
}

#[test]
fn chain_rsa() {
    assert_chain_validates("rsa", "rsa", "rsa");
}

#[test]
fn chain_mixed_algorithms() {
    assert_chain_validates("rsa", "p256", "ed25519");
}
