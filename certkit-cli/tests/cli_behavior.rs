//! Behavioural checks for the CLI's handling of private key material, invalid
//! flag combinations, and error reporting.

pub mod common;

use std::path::Path;

use common::certkit;
use tempfile::tempdir;

/// Runs a certkit command, asserts it failed, and returns its stderr.
fn fails(args: &[&str]) -> String {
    let out = certkit().args(args).output().unwrap();
    assert!(
        !out.status.success(),
        "expected `{args:?}` to fail, but it succeeded"
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Generates a self-signed cert and key into `dir`, returning `(cert, key)`.
fn self_signed(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let cert = dir.join("c.pem");
    let key = dir.join("c.key");
    let status = certkit()
        .args(["gen_self_signed", "example.com"])
        .arg("--key-out")
        .arg(&key)
        .arg("--out")
        .arg(&cert)
        .status()
        .unwrap();
    assert!(status.success());
    (cert, key)
}

/// Private keys must never be left group/world readable.
#[cfg(unix)]
#[test]
fn private_keys_are_written_with_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();

    let keygen_out = dir.path().join("k.pem");
    let status = certkit()
        .args(["keygen"])
        .arg("--out")
        .arg(&keygen_out)
        .status()
        .unwrap();
    assert!(status.success());

    let (cert, key) = self_signed(dir.path());

    for path in [&keygen_out, &key] {
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode,
            0o600,
            "{} should be 0600, was {mode:o}",
            path.display()
        );
    }

    // Certificates are public; they should not be restricted.
    let cert_mode = std::fs::metadata(&cert).unwrap().permissions().mode() & 0o777;
    assert_ne!(cert_mode, 0o600, "certificate should not be owner-only");
}

/// An existing, world-readable key file gets tightened rather than left as-is.
#[cfg(unix)]
#[test]
fn overwriting_an_existing_key_tightens_its_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let path = dir.path().join("k.pem");
    std::fs::write(&path, b"placeholder").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let status = certkit()
        .args(["keygen"])
        .arg("--out")
        .arg(&path)
        .status()
        .unwrap();
    assert!(status.success());

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "expected 0600, was {mode:o}");
}

/// A validity period that cannot be represented must be a clean error, not a panic.
#[test]
fn out_of_range_days_is_an_error_not_a_panic() {
    let dir = tempdir().unwrap();
    let (ca_cert, ca_key) = self_signed(dir.path());

    for days in ["999999999", "9223372036854775807"] {
        let err = fails(&["gen_self_signed", "example.com", "--days", days]);
        assert!(
            !err.contains("panicked"),
            "gen_self_signed panicked on --days {days}: {err}"
        );
        assert!(
            err.contains("out of the representable range"),
            "stderr: {err}"
        );
    }

    let out = certkit()
        .args(["issue", "leaf", "--days", "999999999"])
        .arg("--ca-cert")
        .arg(&ca_cert)
        .arg("--ca-key")
        .arg(&ca_key)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "issue should reject the period");
    assert!(!err.contains("panicked"), "issue panicked: {err}");
    assert!(
        err.contains("out of the representable range"),
        "stderr: {err}"
    );
}

/// `--key-out` used to be silently ignored alongside `--key`.
#[test]
fn key_out_conflicts_with_key() {
    let dir = tempdir().unwrap();
    let (_, key) = self_signed(dir.path());
    let out = certkit()
        .args(["gen_self_signed", "example.com"])
        .arg("--key")
        .arg(&key)
        .arg("--key-out")
        .arg(dir.path().join("ignored.key"))
        .output()
        .unwrap();
    assert!(!out.status.success(), "the combination should be rejected");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("cannot be used with"), "stderr: {err}");
}

/// Errors must name the file that failed and keep the underlying cause.
#[test]
fn file_errors_name_the_file_and_the_cause() {
    let dir = tempdir().unwrap();
    let (ca_cert, ca_key) = self_signed(dir.path());

    let err = fails(&[
        "issue",
        "leaf",
        "--ca-cert",
        "missing_ca.pem",
        "--ca-key",
        ca_key.to_str().unwrap(),
    ]);
    assert!(err.contains("missing_ca.pem"), "stderr: {err}");
    assert!(err.contains("CA certificate"), "stderr: {err}");
    assert!(err.contains("No such file"), "cause missing: {err}");

    let err = fails(&[
        "issue",
        "leaf",
        "--ca-cert",
        ca_cert.to_str().unwrap(),
        "--ca-key",
        "missing_key.pem",
    ]);
    assert!(err.contains("missing_key.pem"), "stderr: {err}");
    assert!(err.contains("private key"), "stderr: {err}");

    // A file that exists but does not parse still names itself.
    let junk = dir.path().join("junk.pem");
    std::fs::write(&junk, b"not a certificate").unwrap();
    let err = fails(&[
        "issue",
        "leaf",
        "--ca-cert",
        junk.to_str().unwrap(),
        "--ca-key",
        ca_key.to_str().unwrap(),
    ]);
    assert!(err.contains("junk.pem"), "stderr: {err}");
    assert!(err.contains("parse"), "stderr: {err}");
}
