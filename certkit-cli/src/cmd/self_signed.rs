use anyhow::Result;
use clap::Args;
use time::{Duration, OffsetDateTime};

use certkit::cert::Certificate;

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
        let now = OffsetDateTime::now_utc();
        let cert = Certificate::new_self_signed_with_expiration(
            &cert_info,
            &key,
            now,
            now + Duration::days(self.opts.days),
        )?;

        emit(
            &cert,
            generated.then_some(&key),
            &self.key.key_out,
            &self.opts,
        )
    }
}
