//! Command-line interface for [`certkit`].
//!
//! Subcommand names follow Botan's CLI:
//! - `keygen` — generate a private key and emit it as PKCS#8 PEM.
//! - `gen_self_signed` — create a self-signed certificate (optionally a CA).
//! - `issue` — issue a certificate signed by an existing CA certificate/key.
//! - `cert_info` — parse a certificate and print its fields.
//!
//! Certificate data is written to `--out` (or stdout); a freshly generated
//! private key is written to `--key-out` (or stdout). Informational messages go
//! to stderr so stdout stays clean for piping.
//!
//! The crate is organized into:
//! - [`cli`] — argument parsing types (clap derive definitions).
//! - [`commands`] — one handler per subcommand.
//! - [`keys`] — generating or loading the subject key pair.
//! - [`certs`] — assembling and parsing certificates.
//! - [`io`] — reading input and writing certificates/keys to files or stdout.
//! - [`report`] — decoding a parsed certificate and rendering it as text or JSON.

mod certs;
mod cli;
mod commands;
mod io;
mod keys;
mod report;

use std::process;

use clap::Parser;

use cli::{Cli, Command};

/// Error type shared across the CLI; any error is boxed and printed by `main`.
pub(crate) type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::GenerateKey(args) => commands::generate_key(args),
        Command::SelfSigned(args) => commands::self_signed(args),
        Command::Issue(args) => commands::issue(args),
        Command::Inspect(args) => commands::inspect(args),
    }
}
