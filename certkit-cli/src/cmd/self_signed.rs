use anyhow::Result;
use clap::Args;

use certkit::cert::Certificate;
use certkit::cert::params::Validity;

use crate::args::{CertOptArgs, DnArgs, KeySourceArgs};
use crate::io::{emit, guard_stdout_clash};
use crate::keys::key_pair;
use crate::params::cert_info;

#[derive(Args)]
pub struct SelfSignedOpt {
    #[command(flatten)]
    pub dn: DnArgs,
    #[command(flatten)]
    pub key: KeySourceArgs,
    #[command(flatten)]
    pub opts: CertOptArgs,
}

impl SelfSignedOpt {
    pub fn execute(&self) -> Result<()> {
        let (key, generated) = key_pair(&self.key)?;
        guard_stdout_clash(
            generated,
            &self.key.key_out,
            &self.opts.out,
            self.opts.format,
        )?;

        let cert_info = cert_info(&self.dn, &key, &self.opts)?;
        let validity = Validity::for_days(self.opts.days)?;
        let cert = Certificate::new_self_signed_with_expiration(
            &cert_info,
            &key,
            validity.not_before().to_system_time().into(),
            validity.not_after().to_system_time().into(),
        )?;

        emit(
            &cert,
            generated.then_some(&key),
            &self.key.key_out,
            &self.opts,
        )
    }
}
