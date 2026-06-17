//! Shared helpers for the CLI integration tests.
//!
//! These tests drive the built `certkit` binary to produce certificate chains
//! and then validate them with the system `openssl` and `botan` command-line
//! tools. Cargo exposes the binary path through `CARGO_BIN_EXE_certkit`, so no
//! extra dependency is needed to locate it.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// A `Command` for the `certkit` binary under test.
pub fn certkit() -> Command {
    Command::new(env!("CARGO_BIN_EXE_certkit"))
}

/// Returns `true` when an external CLI tool is installed and runnable.
///
/// Both `openssl version` and `botan version` exit successfully, so this is a
/// cheap presence check. Tests skip (rather than fail) when the validator is
/// missing, which keeps local runs green on machines without botan installed;
/// CI installs both tools so the checks actually execute there.
pub fn have_tool(tool: &str) -> bool {
    Command::new(tool)
        .arg("version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Paths to the PEM certificates of a generated chain.
pub struct Chain {
    pub root: PathBuf,
    pub intermediate: PathBuf,
    pub leaf: PathBuf,
}

/// Builds a `root -> intermediate -> leaf` certificate chain with the `certkit`
/// binary, writing all files under `dir`. Each level uses the given algorithm,
/// so callers can exercise a single algorithm or a mixed chain.
pub fn build_chain(dir: &Path, root_alg: &str, intermediate_alg: &str, leaf_alg: &str) -> Chain {
    let root = dir.join("root.pem");
    let root_key = dir.join("root.key");
    let intermediate = dir.join("intermediate.pem");
    let intermediate_key = dir.join("intermediate.key");
    let leaf = dir.join("leaf.pem");
    let leaf_key = dir.join("leaf.key");

    // Self-signed root CA.
    run(certkit()
        .args(["self-signed", "--common-name", "Test Root CA", "--ca"])
        .args(["--algorithm", root_alg])
        .arg("--key-out")
        .arg(&root_key)
        .arg("--out")
        .arg(&root));

    // Intermediate CA, signed by the root.
    run(certkit()
        .args(["issue", "--common-name", "Test Intermediate CA", "--ca"])
        .args(["--algorithm", intermediate_alg])
        .arg("--ca-cert")
        .arg(&root)
        .arg("--ca-key")
        .arg(&root_key)
        .arg("--key-out")
        .arg(&intermediate_key)
        .arg("--out")
        .arg(&intermediate));

    // Leaf, signed by the intermediate.
    run(certkit()
        .args([
            "issue",
            "--common-name",
            "leaf.example.com",
            "--eku",
            "server-auth",
        ])
        .args(["--algorithm", leaf_alg])
        .arg("--ca-cert")
        .arg(&intermediate)
        .arg("--ca-key")
        .arg(&intermediate_key)
        .arg("--key-out")
        .arg(&leaf_key)
        .arg("--out")
        .arg(&leaf));

    Chain {
        root,
        intermediate,
        leaf,
    }
}

/// Runs a `certkit` command and asserts it succeeded.
fn run(command: &mut Command) {
    let status = command.status().expect("failed to run certkit");
    assert!(status.success(), "certkit command failed: {command:?}");
}
