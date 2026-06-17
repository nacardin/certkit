//! Drives the built `certkit` binary to produce certificates and checks that
//! `certkit inspect` reports their fields. The fingerprint is cross-checked
//! against `botan` when it is installed, so the two tools must agree.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use tempfile::tempdir;

/// A `Command` for the `certkit` binary under test.
///
/// Defaults the binary's logging to `error` for quiet output, while still
/// honoring an explicit `RUST_LOG` so `RUST_LOG=debug cargo test` surfaces logs.
fn certkit() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_certkit"));
    if std::env::var_os("RUST_LOG").is_none() {
        cmd.env("RUST_LOG", "error");
    }
    cmd
}

/// Writes a self-signed P-256 leaf (with SANs and EKUs) to `dir`, returning its path.
fn write_leaf(dir: &Path) -> std::path::PathBuf {
    let cert = dir.join("leaf.pem");
    let key = dir.join("leaf.key");
    let status = certkit()
        .args([
            "gen_self_signed",
            "leaf.example.com",
            "--dns",
            "leaf.example.com",
            "--dns",
            "www.example.com",
            "--email",
            "admin@example.com",
            "--eku",
            "server-auth",
            "--eku",
            "client-auth",
            "--days",
            "30",
            "--algorithm",
            "ECDSA",
            "--params",
            "secp256r1",
        ])
        .arg("--key-out")
        .arg(&key)
        .arg("--out")
        .arg(&cert)
        .status()
        .expect("failed to run certkit gen_self_signed");
    assert!(status.success(), "certkit gen_self_signed failed");
    cert
}

#[test]
fn inspect_reports_core_fields() {
    let dir = tempdir().unwrap();
    let cert = write_leaf(dir.path());

    let out = certkit().arg("cert_info").arg(&cert).output().unwrap();
    assert!(
        out.status.success(),
        "cert_info failed: {}",
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
    assert!(
        text.contains("email:admin@example.com"),
        "email SAN: {text}"
    );
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
            "gen_self_signed",
            "Example Root CA",
            "--ca",
            "--algorithm",
            "RSA",
            "--params",
            "2048",
        ])
        .arg("--key-out")
        .arg(&key)
        .arg("--out")
        .arg(&cert)
        .status()
        .expect("failed to run certkit gen_self_signed");
    assert!(status.success());

    let out = certkit().arg("cert_info").arg(&cert).output().unwrap();
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
        .arg("cert_info")
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

    // The fingerprint must agree with botan when it is available.
    if Command::new("botan").arg("version").output().is_ok() {
        let botan = Command::new("botan")
            .args(["cert_info", "--fingerprint"])
            .arg(&cert)
            .output()
            .unwrap();
        let botan_out = String::from_utf8_lossy(&botan.stdout);
        let botan_fp = botan_out
            .lines()
            .find(|l| l.starts_with("Fingerprint:"))
            .and_then(|l| l.split_once(": "))
            .map(|(_, fp)| fp.trim().to_lowercase())
            .expect("botan did not print a Fingerprint line");
        assert!(!botan_fp.is_empty());
        assert!(
            text.contains(&botan_fp),
            "fingerprint mismatch:\ncertkit json: {text}\nbotan: {botan_fp}"
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
            "gen_self_signed",
            "stdin.example.com",
            "--format",
            "der",
            "--algorithm",
            "Ed25519",
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
        .args(["cert_info", "-"])
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
