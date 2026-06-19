//! `keygen` — generate a private key and write it as PKCS#8 PEM.

use std::path::PathBuf;

use clap::Args;

use crate::Result;
use crate::args::{Algorithm, KeyParams};
use crate::io::write_bytes;
use crate::keys::generate;

#[derive(Args)]
pub struct KeygenOpt {
    /// Key algorithm (RSA, ECDSA, or Ed25519).
    #[arg(short, long, alias = "algo", value_enum, ignore_case = true, default_value_t = Algorithm::Ecdsa)]
    pub algorithm: Algorithm,
    /// Key parameters: RSA size in bits (default 2048) or ECDSA curve
    /// (secp256r1, secp384r1, secp521r1; default secp256r1). Ignored for Ed25519.
    #[arg(long)]
    pub params: Option<KeyParams>,
    /// Write the key here instead of stdout.
    #[arg(short, long)]
    pub out: Option<PathBuf>,
}

impl KeygenOpt {
    pub fn execute(&self) -> Result<()> {
        let key = generate(self.algorithm, self.params)?;
        let pem = key.encode_private_key_pem()?;
        write_bytes(&self.out, pem.as_bytes())?;
        if let Some(path) = &self.out {
            log::info!("wrote private key to {}", path.display());
        }
        Ok(())
    }
}
