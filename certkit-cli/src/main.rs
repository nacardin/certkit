//! Command-line interface for [`certkit`].
//!
//! Provides three subcommands:
//! - `generate-key` — generate a private key and emit it as PKCS#8 PEM.
//! - `self-signed` — create a self-signed certificate (optionally a CA).
//! - `issue` — issue a certificate signed by an existing CA certificate/key.
//!
//! Certificate data is written to `--out` (or stdout); a freshly generated
//! private key is written to `--key-out` (or stdout). Informational messages go
//! to stderr so stdout stays clean for piping.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::{fs, process};

use clap::{Args, Parser, Subcommand, ValueEnum};
use der::{Decode, DecodePem};
use time::{Duration, OffsetDateTime};
use x509_cert::Certificate as X509Certificate;

use certkit::cert::extensions::{ExtendedKeyUsageOption, SubjectAltName};
use certkit::cert::params::{
    CertificationRequestInfo, DistinguishedName, ExtensionParam, Validity,
};
use certkit::cert::{Certificate, CertificateWithPrivateKey};
use certkit::issuer::Issuer;
use certkit::key::{KeyPair, PublicKey};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(
    name = "certkit",
    version,
    about = "Generate keys and X.509 certificates with certkit"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new private key (PKCS#8 PEM).
    GenerateKey(GenerateKeyArgs),
    /// Create a self-signed certificate.
    SelfSigned(SelfSignedArgs),
    /// Issue a certificate signed by an existing CA.
    Issue(IssueArgs),
}

/// Cryptographic algorithm for a generated key.
#[derive(Copy, Clone, Debug, ValueEnum)]
enum Algorithm {
    Rsa,
    P256,
    P384,
    P521,
    Ed25519,
}

/// Output encoding for certificates.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum CertFormat {
    Pem,
    Der,
}

/// Extended Key Usage purposes that can be requested for a certificate.
#[derive(Copy, Clone, Debug, ValueEnum)]
enum EkuOpt {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
}

impl From<EkuOpt> for ExtendedKeyUsageOption {
    fn from(value: EkuOpt) -> Self {
        match value {
            EkuOpt::ServerAuth => ExtendedKeyUsageOption::ServerAuth,
            EkuOpt::ClientAuth => ExtendedKeyUsageOption::ClientAuth,
            EkuOpt::CodeSigning => ExtendedKeyUsageOption::CodeSigning,
            EkuOpt::EmailProtection => ExtendedKeyUsageOption::EmailProtection,
            EkuOpt::TimeStamping => ExtendedKeyUsageOption::TimeStamping,
            EkuOpt::OcspSigning => ExtendedKeyUsageOption::OcspSigning,
        }
    }
}

#[derive(Args)]
struct GenerateKeyArgs {
    /// Key algorithm.
    #[arg(short, long, value_enum, default_value_t = Algorithm::P256)]
    algorithm: Algorithm,
    /// RSA key size in bits (only used with `--algorithm rsa`).
    #[arg(long, default_value_t = 2048)]
    rsa_bits: usize,
    /// Write the key here instead of stdout.
    #[arg(short, long)]
    out: Option<PathBuf>,
}

/// Subject distinguished name fields, shared by the certificate subcommands.
#[derive(Args)]
struct DnArgs {
    /// Subject common name (CN).
    #[arg(long)]
    common_name: String,
    /// Subject country (C).
    #[arg(long)]
    country: Option<String>,
    /// Subject state or province (ST).
    #[arg(long)]
    state: Option<String>,
    /// Subject locality (L).
    #[arg(long)]
    locality: Option<String>,
    /// Subject organization (O).
    #[arg(long)]
    organization: Option<String>,
    /// Subject organizational unit (OU).
    #[arg(long)]
    organization_unit: Option<String>,
}

/// How to obtain the subject key pair, shared by the certificate subcommands.
#[derive(Args)]
struct KeySourceArgs {
    /// Algorithm for a freshly generated key (ignored when `--key` is given).
    #[arg(short, long, value_enum, default_value_t = Algorithm::P256)]
    algorithm: Algorithm,
    /// RSA key size in bits (only used with `--algorithm rsa`).
    #[arg(long, default_value_t = 2048)]
    rsa_bits: usize,
    /// Use an existing private key (PKCS#8 PEM) instead of generating one.
    #[arg(long)]
    key: Option<PathBuf>,
    /// Write a freshly generated private key here instead of stdout.
    #[arg(long)]
    key_out: Option<PathBuf>,
}

/// Extension, validity, and output options, shared by the certificate subcommands.
#[derive(Args)]
struct CertOptArgs {
    /// DNS Subject Alternative Name (repeatable).
    #[arg(long = "san")]
    san: Vec<String>,
    /// Extended Key Usage purpose (repeatable).
    #[arg(long = "eku", value_enum)]
    eku: Vec<EkuOpt>,
    /// Mark the certificate as a CA (Basic Constraints CA=true).
    #[arg(long)]
    ca: bool,
    /// Validity period in days from now.
    #[arg(long, default_value_t = 365)]
    days: i64,
    /// Certificate output encoding.
    #[arg(long, value_enum, default_value_t = CertFormat::Pem)]
    format: CertFormat,
    /// Write the certificate here instead of stdout.
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
struct SelfSignedArgs {
    #[command(flatten)]
    dn: DnArgs,
    #[command(flatten)]
    key: KeySourceArgs,
    #[command(flatten)]
    opts: CertOptArgs,
}

#[derive(Args)]
struct IssueArgs {
    #[command(flatten)]
    dn: DnArgs,
    #[command(flatten)]
    key: KeySourceArgs,
    #[command(flatten)]
    opts: CertOptArgs,
    /// CA certificate to sign with (PEM or DER).
    #[arg(long)]
    ca_cert: PathBuf,
    /// CA private key to sign with (PKCS#8 PEM).
    #[arg(long)]
    ca_key: PathBuf,
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::GenerateKey(args) => generate_key(args),
        Command::SelfSigned(args) => self_signed(args),
        Command::Issue(args) => issue(args),
    }
}

fn generate_key(args: GenerateKeyArgs) -> Result<()> {
    let key = generate(args.algorithm, args.rsa_bits)?;
    let pem = key.encode_private_key_pem()?;
    write_bytes(&args.out, pem.as_bytes())?;
    if let Some(path) = &args.out {
        eprintln!("Wrote private key to {}", path.display());
    }
    Ok(())
}

fn self_signed(args: SelfSignedArgs) -> Result<()> {
    let (key, generated) = key_pair(&args.key)?;
    guard_stdout_clash(
        generated,
        &args.key.key_out,
        &args.opts.out,
        args.opts.format,
    )?;

    let cert_info = cert_info(&args.dn, &key, &args.opts);
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

fn issue(args: IssueArgs) -> Result<()> {
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

    let cert_info = cert_info(&args.dn, &key, &args.opts);
    let cert = ca.issue(&cert_info, Validity::for_days(args.opts.days));

    emit(
        &cert,
        generated.then_some(&key),
        &args.key.key_out,
        &args.opts,
    )
}

/// Generates a key pair for the requested algorithm.
fn generate(algorithm: Algorithm, rsa_bits: usize) -> Result<KeyPair> {
    Ok(match algorithm {
        Algorithm::Rsa => KeyPair::generate_rsa(rsa_bits)?,
        Algorithm::P256 => KeyPair::generate_ecdsa_p256(),
        Algorithm::P384 => KeyPair::generate_ecdsa_p384(),
        Algorithm::P521 => KeyPair::generate_ecdsa_p521(),
        Algorithm::Ed25519 => KeyPair::generate_ed25519(),
    })
}

/// Loads the key from `--key`, or generates one. Returns `(key, generated)`.
fn key_pair(args: &KeySourceArgs) -> Result<(KeyPair, bool)> {
    match &args.key {
        Some(path) => Ok((
            KeyPair::import_from_pkcs8_pem(&fs::read_to_string(path)?)?,
            false,
        )),
        None => Ok((generate(args.algorithm, args.rsa_bits)?, true)),
    }
}

/// Builds the certification request info from the DN, key, and options.
fn cert_info(dn: &DnArgs, key: &KeyPair, opts: &CertOptArgs) -> CertificationRequestInfo {
    let subject = DistinguishedName::builder()
        .common_name(dn.common_name.clone())
        .maybe_country(dn.country.clone())
        .maybe_state(dn.state.clone())
        .maybe_locality(dn.locality.clone())
        .maybe_organization(dn.organization.clone())
        .maybe_organization_unit(dn.organization_unit.clone())
        .build();

    let usages: Vec<ExtendedKeyUsageOption> = opts.eku.iter().map(|e| (*e).into()).collect();

    let mut extensions = Vec::new();
    if !opts.san.is_empty() {
        extensions.push(ExtensionParam::from_extension(
            SubjectAltName {
                names: opts.san.clone(),
            },
            false,
        ));
    }

    CertificationRequestInfo::builder()
        .subject(subject)
        .subject_public_key(PublicKey::from_key_pair(key))
        .is_ca(opts.ca)
        .usages(usages)
        .extensions(extensions)
        .build()
}

/// Loads a CA certificate from a PEM or DER file (auto-detected).
fn load_ca_cert(path: &Path) -> Result<Certificate> {
    let bytes = fs::read(path)?;
    let inner = if bytes.starts_with(b"-----BEGIN") {
        X509Certificate::from_pem(&bytes)?
    } else {
        X509Certificate::from_der(&bytes)?
    };
    Ok(Certificate { inner })
}

/// Writes the certificate and, when one was generated, the private key.
fn emit(
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
fn guard_stdout_clash(
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
fn write_bytes(out: &Option<PathBuf>, bytes: &[u8]) -> Result<()> {
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
