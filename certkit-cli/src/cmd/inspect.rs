use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use certkit::cert::Certificate;

use crate::io::read_cert_input;
use crate::report::CertReport;

#[derive(Args)]
pub struct InspectOpt {
    /// Certificate file to read (PEM or DER, auto-detected). Use `-` for stdin.
    pub input: PathBuf,
    /// Also print the SHA-256 fingerprint of the DER encoding.
    #[arg(long)]
    pub fingerprint: bool,
    /// Emit machine-readable JSON instead of text.
    #[arg(long)]
    pub json: bool,
}

impl InspectOpt {
    pub fn execute(&self) -> Result<()> {
        log::debug!("inspecting certificate from {}", self.input.display());

        let bytes = read_cert_input(&self.input)?;
        let cert = Certificate::from_bytes(&bytes)?;
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
