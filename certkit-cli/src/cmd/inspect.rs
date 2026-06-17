//! `cert_info` — parse a certificate and print its fields.

use std::io::Write;
use std::path::PathBuf;

use clap::Args;

use crate::Result;
use crate::certs::parse_x509;
use crate::io::read_cert_input;
use crate::report::CertReport;

#[derive(Args)]
pub struct InspectOpt {
    /// Certificate to read (PEM or DER, auto-detected). Omit or `-` for stdin.
    pub input: Option<PathBuf>,
    /// Also print the SHA-256 fingerprint of the DER encoding.
    #[arg(long)]
    pub fingerprint: bool,
    /// Emit machine-readable JSON instead of text.
    #[arg(long)]
    pub json: bool,
}

impl InspectOpt {
    pub fn execute(&self) -> Result<()> {
        let bytes = read_cert_input(&self.input)?;
        let cert = parse_x509(&bytes)?;
        let report = CertReport::from_cert(&cert, self.fingerprint)?;

        let out = if self.json {
            report.to_json()
        } else {
            report.to_text()
        };
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(out.as_bytes())?;
        stdout.flush()?;
        Ok(())
    }
}
