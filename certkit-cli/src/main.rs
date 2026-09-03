mod args;
mod cmd;
mod io;
mod keys;
mod params;
mod report;

use std::process;

use anyhow::Result;
use clap::{Parser, Subcommand};

use cmd::inspect::InspectOpt;
use cmd::issue::IssueOpt;
use cmd::keygen::KeygenOpt;
use cmd::self_signed::SelfSignedOpt;

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
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .init();

    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("error: {err:#}");
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
