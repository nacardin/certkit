//! Reading input and writing certificates and keys.
//!
//! Output goes to the path given on the command line, or to stdout when none is
//! given; informational "wrote ..." messages go to stderr so stdout stays clean
//! for piping. [`guard_stdout_clash`] refuses the one combination that would
//! corrupt stdout: a binary DER certificate and a PEM key both written there.

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use certkit::cert::Certificate;
use certkit::key::KeyPair;

use crate::Result;
use crate::cli::{CertFormat, CertOptArgs};

/// Reads certificate bytes from a file, or from stdin when the path is absent or `-`.
pub(crate) fn read_cert_input(path: &Option<PathBuf>) -> Result<Vec<u8>> {
    match path.as_deref().filter(|p| p.as_os_str() != "-") {
        Some(path) => Ok(fs::read(path)?),
        None => {
            let mut buf = Vec::new();
            std::io::stdin().lock().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

/// Writes the certificate and, when one was generated, the private key.
pub(crate) fn emit(
    cert: &Certificate,
    key: Option<&KeyPair>,
    key_out: &Option<PathBuf>,
    opts: &CertOptArgs,
) -> Result<()> {
    if let Some(key) = key {
        let pem = key.encode_private_key_pem()?;
        write_bytes(key_out, pem.as_bytes())?;
        if let Some(path) = key_out {
            eprintln!("Wrote private key to {}", path.display());
        }
    }

    let bytes = match opts.format {
        CertFormat::Pem => cert.to_pem()?.into_bytes(),
        CertFormat::Der => cert.to_der()?,
    };
    write_bytes(&opts.out, &bytes)?;
    if let Some(path) = &opts.out {
        eprintln!("Wrote certificate to {}", path.display());
    }
    Ok(())
}

/// Refuses to interleave a binary DER certificate and a PEM key on stdout.
pub(crate) fn guard_stdout_clash(
    generated: bool,
    key_out: &Option<PathBuf>,
    cert_out: &Option<PathBuf>,
    format: CertFormat,
) -> Result<()> {
    if generated && key_out.is_none() && cert_out.is_none() && format == CertFormat::Der {
        return Err("refusing to write a binary DER certificate and a PEM private key both to stdout; pass --out and/or --key-out".into());
    }
    Ok(())
}

/// Writes bytes to a file when a path is given, otherwise to stdout.
pub(crate) fn write_bytes(out: &Option<PathBuf>, bytes: &[u8]) -> Result<()> {
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
