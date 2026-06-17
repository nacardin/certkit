//! One handler per subcommand, dispatched from [`crate::run`].
//!
//! Each handler wires together the [`keys`](crate::keys),
//! [`certs`](crate::certs), [`io`](crate::io), and [`report`](crate::report)
//! modules: obtain a key, build or parse a certificate, then write or render it.

use std::fs;
use std::io::Write;

use time::{Duration, OffsetDateTime};

use certkit::cert::params::Validity;
use certkit::cert::{Certificate, CertificateWithPrivateKey};
use certkit::issuer::Issuer;
use certkit::key::KeyPair;

use crate::Result;
use crate::certs::{cert_info, load_ca_cert, parse_x509};
use crate::cli::{GenerateKeyArgs, InspectArgs, IssueArgs, SelfSignedArgs};
use crate::io::{emit, guard_stdout_clash, read_cert_input, write_bytes};
use crate::keys::{generate, key_pair};
use crate::report::CertReport;

pub(crate) fn generate_key(args: GenerateKeyArgs) -> Result<()> {
    let key = generate(args.algorithm, args.params)?;
    let pem = key.encode_private_key_pem()?;
    write_bytes(&args.out, pem.as_bytes())?;
    if let Some(path) = &args.out {
        eprintln!("Wrote private key to {}", path.display());
    }
    Ok(())
}

pub(crate) fn self_signed(args: SelfSignedArgs) -> Result<()> {
    let (key, generated) = key_pair(&args.key)?;
    guard_stdout_clash(
        generated,
        &args.key.key_out,
        &args.opts.out,
        args.opts.format,
    )?;

    let cert_info = cert_info(&args.dn, &key, &args.opts)?;
    let now = OffsetDateTime::now_utc();
    let cert = Certificate::new_self_signed_with_expiration(
        &cert_info,
        &key,
        now,
        now + Duration::days(args.opts.days),
    );

    emit(
        &cert,
        generated.then_some(&key),
        &args.key.key_out,
        &args.opts,
    )
}

pub(crate) fn issue(args: IssueArgs) -> Result<()> {
    let (key, generated) = key_pair(&args.key)?;
    guard_stdout_clash(
        generated,
        &args.key.key_out,
        &args.opts.out,
        args.opts.format,
    )?;

    let ca_cert = load_ca_cert(&args.ca_cert)?;
    let ca_key = KeyPair::import_from_pkcs8_pem(&fs::read_to_string(&args.ca_key)?)?;
    let ca = CertificateWithPrivateKey {
        cert: ca_cert,
        key: ca_key,
    };

    let cert_info = cert_info(&args.dn, &key, &args.opts)?;
    let cert = ca.issue(&cert_info, Validity::for_days(args.opts.days));

    emit(
        &cert,
        generated.then_some(&key),
        &args.key.key_out,
        &args.opts,
    )
}

pub(crate) fn inspect(args: InspectArgs) -> Result<()> {
    let bytes = read_cert_input(&args.input)?;
    let cert = parse_x509(&bytes)?;
    let report = CertReport::from_cert(&cert, args.fingerprint)?;

    let out = if args.json {
        report.to_json()
    } else {
        report.to_text()
    };
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(out.as_bytes())?;
    stdout.flush()?;
    Ok(())
}
