//! Shared helpers for the CLI integration tests.
//!
//! These tests drive the built `certkit` binary to produce certificates and
//! then validate them with the system `openssl` and `botan` command-line
//! tools. Cargo exposes the binary path through `CARGO_BIN_EXE_certkit`, so no
//! extra dependency is needed to locate it.

#![allow(dead_code)]

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
