//! Validates `certkit`-generated certificates with the system `openssl` CLI.
//!
//! Replaces the former `tests/openssl.rs` in the library crate, which validated
//! certificates produced by the library API. Here we exercise the actual CLI:
//! generate a CA, issue a leaf, then both parse (`x509 -text`) and
//! cryptographically verify the chain (`verify`).

mod common;

use std::process::Command;

use common::{certkit, have_tool};
use tempfile::tempdir;

/// Runs `openssl x509 -text` on `cert` and returns the textual dump.
fn openssl_text(cert: &std::path::Path) -> String {
    let output = Command::new("openssl")
        .arg("x509")
        .arg("-in")
        .arg(cert)
        .arg("-noout")
        .arg("-text")
        // Force the C locale so field labels aren't localized.
        .env("LANG", "C")
        .output()
        .expect("failed to run openssl x509");
    assert!(
        output.status.success(),
        "openssl x509 failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn openssl_parses_and_verifies_issued_cert() {
    if !have_tool("openssl") {
        eprintln!("skipping openssl_parses_and_verifies_issued_cert: openssl CLI not found");
        return;
    }

    let dir = tempdir().unwrap();
    let ca_cert = dir.path().join("ca.pem");
    let ca_key = dir.path().join("ca.key");
    let leaf = dir.path().join("server.pem");
    let leaf_key = dir.path().join("server.key");

    // Self-signed CA.
    let status = certkit()
        .args(["self-signed", "--common-name", "myca.local", "--ca"])
        .arg("--key-out")
        .arg(&ca_key)
        .arg("--out")
        .arg(&ca_cert)
        .status()
        .unwrap();
    assert!(status.success(), "certkit self-signed failed");

    // Leaf certificate issued by the CA.
    let status = certkit()
        .args([
            "issue",
            "--common-name",
            "server.myca.local",
            "--eku",
            "server-auth",
        ])
        .arg("--ca-cert")
        .arg(&ca_cert)
        .arg("--ca-key")
        .arg(&ca_key)
        .arg("--key-out")
        .arg(&leaf_key)
        .arg("--out")
        .arg(&leaf)
        .status()
        .unwrap();
    assert!(status.success(), "certkit issue failed");

    // Field-level checks. Different openssl versions print the DN with or
    // without spaces around '=', so accept both forms.
    let text = openssl_text(&leaf);
    assert!(
        text.contains("Issuer: C=, ST=, L=, O=, OU=, CN=myca.local")
            || text.contains("Issuer: C = , ST = , L = , O = , OU = , CN = myca.local"),
        "unexpected issuer:\n{text}"
    );
    assert!(
        text.contains("Subject: C=, ST=, L=, O=, OU=, CN=server.myca.local")
            || text.contains("Subject: C = , ST = , L = , O = , OU = , CN = server.myca.local"),
        "unexpected subject:\n{text}"
    );
    assert!(
        text.contains("Version: 3 (0x2)"),
        "unexpected version:\n{text}"
    );
    assert!(
        text.contains("Serial Number: 1 (0x1)"),
        "unexpected serial:\n{text}"
    );
    assert!(
        text.contains("Signature Algorithm: ecdsa-with-SHA256"),
        "unexpected signature algorithm:\n{text}"
    );
    assert!(text.contains("Not Before:"), "missing Not Before:\n{text}");
    assert!(text.contains("Not After :"), "missing Not After:\n{text}");

    // Cryptographic chain verification: confirms the leaf's signature actually
    // checks out against the CA's public key.
    let verify = Command::new("openssl")
        .arg("verify")
        .arg("-CAfile")
        .arg(&ca_cert)
        .arg(&leaf)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "openssl verify failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr),
    );
}

/// The signature OID must match the curve's hash (RFC 5480): P-256/SHA-256,
/// P-384/SHA-384, P-521/SHA-512. A mismatch makes `openssl verify` fail, so a
/// passing chain verification across all algorithms guards against regressions.
fn verify_chain_for(algorithm: &str, expected_sig_alg: &str) {
    let dir = tempdir().unwrap();
    let ca_cert = dir.path().join("ca.pem");
    let ca_key = dir.path().join("ca.key");
    let leaf = dir.path().join("leaf.pem");
    let leaf_key = dir.path().join("leaf.key");

    let status = certkit()
        .args([
            "self-signed",
            "--common-name",
            "ca.local",
            "--ca",
            "--algorithm",
            algorithm,
        ])
        .arg("--key-out")
        .arg(&ca_key)
        .arg("--out")
        .arg(&ca_cert)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "certkit self-signed --algorithm {algorithm} failed"
    );

    let status = certkit()
        .args([
            "issue",
            "--common-name",
            "leaf.local",
            "--algorithm",
            algorithm,
        ])
        .arg("--ca-cert")
        .arg(&ca_cert)
        .arg("--ca-key")
        .arg(&ca_key)
        .arg("--key-out")
        .arg(&leaf_key)
        .arg("--out")
        .arg(&leaf)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "certkit issue --algorithm {algorithm} failed"
    );

    let text = openssl_text(&leaf);
    assert!(
        text.contains(expected_sig_alg),
        "expected signature algorithm {expected_sig_alg} for {algorithm}:\n{text}"
    );

    let verify = Command::new("openssl")
        .arg("verify")
        .arg("-CAfile")
        .arg(&ca_cert)
        .arg(&leaf)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "openssl verify failed for {algorithm}:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr),
    );
}

#[test]
fn openssl_verifies_chain_all_algorithms() {
    if !have_tool("openssl") {
        eprintln!("skipping openssl_verifies_chain_all_algorithms: openssl CLI not found");
        return;
    }
    verify_chain_for("p256", "Signature Algorithm: ecdsa-with-SHA256");
    verify_chain_for("p384", "Signature Algorithm: ecdsa-with-SHA384");
    verify_chain_for("p521", "Signature Algorithm: ecdsa-with-SHA512");
    verify_chain_for("ed25519", "Signature Algorithm: ED25519");
    verify_chain_for("rsa", "Signature Algorithm: sha256WithRSAEncryption");
}
