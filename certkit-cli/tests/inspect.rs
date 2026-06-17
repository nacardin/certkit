//! Drives the built `certkit` binary to produce certificates and checks that
//! `certkit inspect` reports their fields. The fingerprint is cross-checked
//! against `openssl` when it is installed, so the two tools must agree.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use tempfile::tempdir;

/// A `Command` for the `certkit` binary under test.
fn certkit() -> Command {
    Command::new(env!("CARGO_BIN_EXE_certkit"))
}

/// Writes a self-signed P-256 leaf (with SANs and EKUs) to `dir`, returning its path.
fn write_leaf(dir: &Path) -> std::path::PathBuf {
    let cert = dir.join("leaf.pem");
    let key = dir.join("leaf.key");
    let status = certkit()
        .args([
            "self-signed",
            "--common-name",
            "leaf.example.com",
            "--san",
            "leaf.example.com",
            "--san",
            "www.example.com",
            "--eku",
            "server-auth",
            "--eku",
            "client-auth",
            "--days",
            "30",
            "--algorithm",
            "p256",
        ])
        .arg("--key-out")
        .arg(&key)
        .arg("--out")
        .arg(&cert)
        .status()
        .expect("failed to run certkit self-signed");
    assert!(status.success(), "certkit self-signed failed");
    cert
}

#[test]
fn inspect_reports_core_fields() {
    let dir = tempdir().unwrap();
    let cert = write_leaf(dir.path());

    let out = certkit().arg("inspect").arg(&cert).output().unwrap();
    assert!(
        out.status.success(),
        "inspect failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);

    assert!(text.contains("CN=leaf.example.com"), "subject CN: {text}");
    assert!(text.contains("ECDSA (P-256)"), "public key: {text}");
    assert!(text.contains("ecdsa-with-SHA256"), "sig alg: {text}");
    assert!(
        text.contains("(expires in 30 days)"),
        "validity note: {text}"
    );
    assert!(
        text.contains("Subject Alternative Name"),
        "SAN label: {text}"
    );
    assert!(text.contains("DNS:www.example.com"), "SAN value: {text}");
    assert!(text.contains("Extended Key Usage"), "EKU label: {text}");
    assert!(text.contains("serverAuth, clientAuth"), "EKU value: {text}");
    assert!(text.contains("Basic Constraints"), "BC label: {text}");
    assert!(text.contains("CA=false"), "BC value: {text}");
}

#[test]
fn inspect_ca_reports_cert_sign() {
    let dir = tempdir().unwrap();
    let cert = dir.path().join("ca.pem");
    let key = dir.path().join("ca.key");
    let status = certkit()
        .args([
            "self-signed",
            "--common-name",
            "Example Root CA",
            "--ca",
            "--algorithm",
            "rsa",
            "--rsa-bits",
            "2048",
        ])
        .arg("--key-out")
        .arg(&key)
        .arg("--out")
        .arg(&cert)
        .status()
        .expect("failed to run certkit self-signed");
    assert!(status.success());

    let out = certkit().arg("inspect").arg(&cert).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("RSA (2048 bit)"), "rsa size: {text}");
    assert!(text.contains("CA=true"), "BC value: {text}");
    assert!(text.contains("keyCertSign"), "key usage: {text}");
}

#[test]
fn inspect_json_and_fingerprint() {
    let dir = tempdir().unwrap();
    let cert = write_leaf(dir.path());

    let out = certkit()
        .arg("inspect")
        .arg(&cert)
        .args(["--json", "--fingerprint"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);

    assert!(text.trim_start().starts_with('{'), "json object: {text}");
    assert!(text.contains("\"subject\":\"CN=leaf.example.com"), "{text}");
    assert!(text.contains("\"public_key\":\"ECDSA (P-256)\""), "{text}");
    assert!(text.contains("\"fingerprint_sha256\":\""), "{text}");
    assert!(text.contains("\"extensions\":["), "{text}");

    // The fingerprint must agree with openssl when it is available.
    if Command::new("openssl").arg("version").output().is_ok() {
        let ssl = Command::new("openssl")
            .args(["x509", "-noout", "-fingerprint", "-sha256", "-in"])
            .arg(&cert)
            .output()
            .unwrap();
        let ssl_fp = String::from_utf8_lossy(&ssl.stdout)
            .split('=')
            .nth(1)
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        assert!(!ssl_fp.is_empty());
        assert!(
            text.contains(&ssl_fp),
            "fingerprint mismatch:\ncertkit json: {text}\nopenssl: {ssl_fp}"
        );
    }
}

#[test]
fn inspect_reads_der_from_stdin() {
    let dir = tempdir().unwrap();
    let cert = dir.path().join("leaf.der");
    let key = dir.path().join("leaf.key");
    let status = certkit()
        .args([
            "self-signed",
            "--common-name",
            "stdin.example.com",
            "--format",
            "der",
            "--algorithm",
            "ed25519",
        ])
        .arg("--key-out")
        .arg(&key)
        .arg("--out")
        .arg(&cert)
        .status()
        .unwrap();
    assert!(status.success());
    let der = std::fs::read(&cert).unwrap();

    let mut child = certkit()
        .args(["inspect", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&der).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("CN=stdin.example.com"), "{text}");
    assert!(text.contains("Ed25519"), "{text}");
}
