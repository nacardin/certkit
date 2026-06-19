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
//! - [`cmd`] — one module per subcommand, each an options struct with an
//!   `execute` method.
//! - [`args`] — argument types (value enums and `Args` groups) shared between
//!   subcommands.
//! - [`keys`] — generating or loading the subject key pair.
//! - [`certs`] — assembling and parsing certificates.
//! - [`io`] — reading input and writing certificates/keys to files or stdout.
//! - [`report`] — decoding a parsed certificate and rendering it as text or JSON.

mod args;
mod certs;
mod cmd;
mod io;
mod keys;
mod report;

use std::process;

use clap::{Parser, Subcommand};

use cmd::inspect::InspectOpt;
use cmd::issue::IssueOpt;
use cmd::keygen::KeygenOpt;
use cmd::self_signed::SelfSignedOpt;

/// Error type shared across the CLI; any error is boxed and printed by `main`.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(
    name = "certkit",
    version,
    about = "Generate keys and X.509 certificates with certkit"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new private key (PKCS#8 PEM).
    #[command(name = "keygen")]
    GenerateKey(KeygenOpt),
    /// Create a self-signed certificate.
    #[command(name = "gen_self_signed")]
    SelfSigned(SelfSignedOpt),
    /// Issue a certificate signed by an existing CA.
    #[command(name = "issue")]
    Issue(IssueOpt),
    /// Parse a certificate and print its fields.
    #[command(name = "cert_info")]
    Inspect(InspectOpt),
}

fn main() {
    // Logs go to stderr (keeping stdout clean for piping). The default level is `info`.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .init();

    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::GenerateKey(opt) => opt.execute(),
        Command::SelfSigned(opt) => opt.execute(),
        Command::Issue(opt) => opt.execute(),
        Command::Inspect(opt) => opt.execute(),
    }
}
