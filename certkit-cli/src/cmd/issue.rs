//! `issue` — issue a certificate signed by an existing CA.

use std::fs;
use std::path::PathBuf;

use clap::Args;

use certkit::cert::CertificateWithPrivateKey;
use certkit::cert::params::Validity;
use certkit::issuer::Issuer;
use certkit::key::KeyPair;

use crate::Result;
use crate::args::{CertOptArgs, DnArgs, KeySourceArgs};
use crate::certs::{cert_info, load_ca_cert};
use crate::io::{emit, guard_stdout_clash};
use crate::keys::key_pair;

#[derive(Args)]
pub struct IssueOpt {
    #[command(flatten)]
    pub dn: DnArgs,
    #[command(flatten)]
    pub key: KeySourceArgs,
    #[command(flatten)]
    pub opts: CertOptArgs,
    /// CA certificate to sign with (PEM or DER).
    #[arg(long)]
    pub ca_cert: PathBuf,
    /// CA private key to sign with (PKCS#8 PEM).
    #[arg(long)]
    pub ca_key: PathBuf,
}

impl IssueOpt {
    pub fn execute(&self) -> Result<()> {
        let (key, generated) = key_pair(&self.key)?;
        guard_stdout_clash(
            generated,
            &self.key.key_out,
            &self.opts.out,
            self.opts.format,
        )?;

        log::debug!(
            "loading CA certificate from {} and key from {}",
            self.ca_cert.display(),
            self.ca_key.display()
        );
        let ca_cert = load_ca_cert(&self.ca_cert)?;
        let ca_key = KeyPair::import_from_pkcs8_pem(&fs::read_to_string(&self.ca_key)?)?;
        let ca = CertificateWithPrivateKey {
            cert: ca_cert,
            key: ca_key,
        };

        let cert_info = cert_info(&self.dn, &key, &self.opts)?;
        let cert = ca.issue(&cert_info, Validity::for_days(self.opts.days))?;

        emit(
            &cert,
            generated.then_some(&key),
            &self.key.key_out,
            &self.opts,
        )
    }
}
