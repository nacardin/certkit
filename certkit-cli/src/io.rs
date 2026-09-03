use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{Result, bail};
use certkit::cert::Certificate;
use certkit::key::KeyPair;

use crate::args::{CertFormat, CertOptArgs};

pub fn read_cert_input(path: &std::path::Path) -> Result<Vec<u8>> {
    if path.as_os_str() == "-" {
        let mut buf = Vec::new();
        std::io::stdin().lock().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        Ok(fs::read(path)?)
    }
}

pub fn emit(
    cert: &Certificate,
    key: Option<&KeyPair>,
    key_out: &Option<PathBuf>,
    opts: &CertOptArgs,
) -> Result<()> {
    if let Some(key) = key {
        let pem = key.encode_private_key_pem()?;
        write_bytes(key_out, pem.as_bytes())?;
        if let Some(path) = key_out {
            log::info!("wrote private key to {}", path.display());
        }
    }

    let bytes = match opts.format {
        CertFormat::Pem => cert.to_pem()?.into_bytes(),
        CertFormat::Der => cert.to_der()?,
    };
    write_bytes(&opts.out, &bytes)?;
    if let Some(path) = &opts.out {
        log::info!("wrote certificate to {}", path.display());
    }
    Ok(())
}

/// Rejects binary DER cert + PEM key both going to stdout (would corrupt output).
pub fn guard_stdout_clash(
    generated: bool,
    key_out: &Option<PathBuf>,
    cert_out: &Option<PathBuf>,
    format: CertFormat,
) -> Result<()> {
    if generated && key_out.is_none() && cert_out.is_none() && format == CertFormat::Der {
        bail!(
            "refusing to write a binary DER certificate and a PEM private key both to stdout; pass --out and/or --key-out"
        );
    }
    Ok(())
}

pub fn load_ca_cert(path: &std::path::Path) -> Result<Certificate> {
    Ok(Certificate::from_bytes(&fs::read(path)?)?)
}

pub fn write_bytes(out: &Option<PathBuf>, bytes: &[u8]) -> Result<()> {
    match out {
        Some(path) => fs::write(path, bytes)?,
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(bytes)?;
            stdout.flush()?;
        }
    }
    Ok(())
}
