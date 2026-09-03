use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use certkit::cert::Certificate;
use certkit::key::KeyPair;

use crate::args::{CertFormat, CertOptArgs};

pub fn read_cert_input(path: &Path) -> Result<Vec<u8>> {
    if path.as_os_str() == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .lock()
            .read_to_end(&mut buf)
            .context("failed to read certificate from stdin")?;
        Ok(buf)
    } else {
        fs::read(path).with_context(|| format!("failed to read certificate {}", path.display()))
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
        write_secret_bytes(key_out, pem.as_bytes())?;
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

pub fn load_ca_cert(path: &Path) -> Result<Certificate> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read CA certificate {}", path.display()))?;
    Certificate::from_bytes(&bytes)
        .with_context(|| format!("failed to parse CA certificate {}", path.display()))
}

pub fn load_key(path: &Path) -> Result<KeyPair> {
    let pem = fs::read_to_string(path)
        .with_context(|| format!("failed to read private key {}", path.display()))?;
    KeyPair::import_from_pkcs8_pem(&pem)
        .with_context(|| format!("failed to parse private key {}", path.display()))
}

pub fn write_bytes(out: &Option<PathBuf>, bytes: &[u8]) -> Result<()> {
    match out {
        Some(path) => {
            fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))?
        }
        None => write_stdout(bytes)?,
    }
    Ok(())
}

/// Writes private key material. Files are created `0600` on Unix so a freshly
/// generated key is never left world-readable; stdout is passed through as-is.
pub fn write_secret_bytes(out: &Option<PathBuf>, bytes: &[u8]) -> Result<()> {
    match out {
        Some(path) => create_private_file(path)
            .and_then(|mut file| file.write_all(bytes))
            .with_context(|| format!("failed to write {}", path.display()))?,
        None => write_stdout(bytes)?,
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> std::io::Result<fs::File> {
    fs::File::create(path)
}

fn write_stdout(bytes: &[u8]) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(bytes).context("failed to write stdout")?;
    stdout.flush().context("failed to flush stdout")?;
    Ok(())
}
