//! Checks `keygen`'s Botan-style `--algorithm`/`--params` handling: valid
//! combinations succeed, and mismatched or unparseable `--params` are rejected
//! with a helpful message.

pub mod common;

use common::certkit;

/// Runs `keygen <args>`, asserts it failed, and returns its stderr.
fn keygen_fails(args: &[&str]) -> String {
    let out = certkit().arg("keygen").args(args).output().unwrap();
    assert!(
        !out.status.success(),
        "expected `keygen {args:?}` to fail, but it succeeded"
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Runs `keygen <args>`, asserts success, and that a PEM key lands on stdout.
fn keygen_ok(args: &[&str]) {
    let out = certkit().arg("keygen").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "`keygen {args:?}` failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stdout.starts_with(b"-----BEGIN"),
        "expected a PEM private key on stdout for `keygen {args:?}`"
    );
}

#[test]
fn rejects_unparseable_params() {
    let err = keygen_fails(&["--algo", "ECDSA", "--params", "bogus"]);
    assert!(err.contains("secp256r1"), "stderr: {err}");
}

#[test]
fn rejects_curve_for_rsa() {
    let err = keygen_fails(&["--algo", "RSA", "--params", "secp256r1"]);
    assert!(err.to_lowercase().contains("rsa"), "stderr: {err}");
}

#[test]
fn rejects_bits_for_ecdsa() {
    let err = keygen_fails(&["--algo", "ECDSA", "--params", "2048"]);
    assert!(err.to_lowercase().contains("ecdsa"), "stderr: {err}");
}

#[test]
fn accepts_valid_combinations() {
    keygen_ok(&["--algo", "RSA", "--params", "2048"]);
    keygen_ok(&["--algo", "ECDSA", "--params", "secp384r1"]);
    keygen_ok(&["--algo", "Ed25519"]);
}
