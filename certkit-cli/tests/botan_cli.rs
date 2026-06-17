//! Validates `certkit`-generated certificates with the system `botan` CLI.
//!
//! Replaces the former `tests/botan.rs` in the library crate, which parsed
//! certificates with the `botan` Rust crate. Those tests were `#[ignore]`d and
//! feature-gated per algorithm; because the CLI is built with every algorithm
//! enabled, these run unconditionally and cover all of them.
//!
//! Note: `botan cert_info` exits 0 even when it fails to parse, so correctness
//! is asserted on its stdout, not the exit status.

mod common;

use std::process::Command;

use common::{certkit, have_tool};
use tempfile::tempdir;

/// Generates a self-signed certificate for `algorithm`, parses it with
/// `botan cert_info`, and asserts the subject and key type are reported.
fn check_algorithm(algorithm: &str, expected_key: &str) {
    let dir = tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("cert.key");

    let status = certkit()
        .args([
            "self-signed",
            "--common-name",
            "crabs.crabs",
            "--organization",
            "Crab widgits SE",
            "--algorithm",
            algorithm,
        ])
        .arg("--key-out")
        .arg(&key)
        .arg("--out")
        .arg(&cert)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "certkit self-signed --algorithm {algorithm} failed"
    );

    let output = Command::new("botan")
        .arg("cert_info")
        .arg(&cert)
        .output()
        .expect("failed to run botan cert_info");
    let text = String::from_utf8_lossy(&output.stdout);

    assert!(
        text.contains(r#"CN="crabs.crabs""#),
        "botan did not parse the subject for {algorithm}:\n{text}"
    );
    assert!(
        text.contains(expected_key),
        "botan reported an unexpected key type for {algorithm} (wanted {expected_key}):\n{text}"
    );
}

macro_rules! botan_test {
    ($name:ident, $algorithm:literal, $expected_key:literal) => {
        #[test]
        fn $name() {
            if !have_tool("botan") {
                eprintln!(concat!(
                    "skipping ",
                    stringify!($name),
                    ": botan CLI not found"
                ));
                return;
            }
            check_algorithm($algorithm, $expected_key);
        }
    };
}

botan_test!(botan_parses_ecdsa_p256, "p256", "Public Key [ECDSA-256]");
botan_test!(botan_parses_ecdsa_p384, "p384", "Public Key [ECDSA-384]");
botan_test!(botan_parses_ecdsa_p521, "p521", "Public Key [ECDSA-521]");
botan_test!(botan_parses_ed25519, "ed25519", "Public Key [Ed25519-255]");
botan_test!(botan_parses_rsa, "rsa", "Public Key [RSA-2048]");
