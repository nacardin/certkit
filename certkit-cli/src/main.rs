//! Command-line interface for [`certkit`].
//!
//! Subcommand names follow Botan's CLI:
//! - `keygen` — generate a private key and emit it as PKCS#8 PEM.
//! - `gen_self_signed` — create a self-signed certificate (optionally a CA).
//! - `issue` — issue a certificate signed by an existing CA certificate/key.
//! - `cert_info` — parse a certificate and print its fields.
//!
//! Certificate data is written to `--out` (or stdout); a freshly generated
//! private key is written to `--key-out` (or stdout). Informational messages go
//! to stderr so stdout stays clean for piping.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::{fs, process};

use clap::{Args, Parser, Subcommand, ValueEnum};
use der::asn1::Ia5String;
use der::{Decode, DecodePem, Encode};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use x509_cert::Certificate as X509Certificate;
use x509_cert::ext::pkix;
use x509_cert::ext::pkix::name::GeneralName;

use certkit::cert::extensions::{ExtendedKeyUsageOption, SubjectAltName, ToAndFromX509Extension};
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
    #[command(name = "keygen")]
    GenerateKey(GenerateKeyArgs),
    /// Create a self-signed certificate.
    #[command(name = "gen_self_signed")]
    SelfSigned(SelfSignedArgs),
    /// Issue a certificate signed by an existing CA.
    #[command(name = "issue")]
    Issue(IssueArgs),
    /// Parse a certificate and print its fields.
    #[command(name = "cert_info")]
    Inspect(InspectArgs),
}

/// Key algorithm, named as Botan's `keygen --algo` expects.
///
/// The key shape (RSA size, ECDSA curve) is selected with `--params`, also
/// following Botan: `--params 2048` for RSA, `--params secp256r1` for ECDSA.
#[derive(Copy, Clone, Debug, ValueEnum)]
enum Algorithm {
    #[value(name = "RSA")]
    Rsa,
    #[value(name = "ECDSA")]
    Ecdsa,
    #[value(name = "Ed25519")]
    Ed25519,
}

/// Key parameters chosen with `--params`, disambiguated by value: a bare number
/// is an RSA key size, anything else is an ECDSA curve name (as in Botan).
#[derive(Copy, Clone, Debug)]
enum KeyParams {
    /// RSA modulus size in bits.
    Bits(u32),
    /// ECDSA curve.
    Curve(Curve),
}

/// A NIST/SECG curve certkit can generate.
#[derive(Copy, Clone, Debug)]
enum Curve {
    P256,
    P384,
    P521,
}

impl std::str::FromStr for KeyParams {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Ok(bits) = s.parse::<u32>() {
            return Ok(KeyParams::Bits(bits));
        }
        let curve = match s.to_ascii_lowercase().as_str() {
            "secp256r1" | "prime256v1" | "p256" | "p-256" => Curve::P256,
            "secp384r1" | "p384" | "p-384" => Curve::P384,
            "secp521r1" | "p521" | "p-521" => Curve::P521,
            _ => {
                return Err(format!(
                    "expected an RSA key size or an ECDSA curve \
                     (secp256r1, secp384r1, secp521r1); got '{s}'"
                ));
            }
        };
        Ok(KeyParams::Curve(curve))
    }
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
    /// Key algorithm (RSA, ECDSA, or Ed25519).
    #[arg(short, long, alias = "algo", value_enum, ignore_case = true, default_value_t = Algorithm::Ecdsa)]
    algorithm: Algorithm,
    /// Key parameters: RSA size in bits (default 2048) or ECDSA curve
    /// (secp256r1, secp384r1, secp521r1; default secp256r1). Ignored for Ed25519.
    #[arg(long)]
    params: Option<KeyParams>,
    /// Write the key here instead of stdout.
    #[arg(short, long)]
    out: Option<PathBuf>,
}

/// Subject distinguished name fields, shared by the certificate subcommands.
#[derive(Args)]
struct DnArgs {
    /// Subject common name (CN), given positionally (as in Botan).
    #[arg(value_name = "COMMON_NAME")]
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
    #[arg(short, long, alias = "algo", value_enum, ignore_case = true, default_value_t = Algorithm::Ecdsa)]
    algorithm: Algorithm,
    /// Key parameters for a freshly generated key: RSA size in bits (default
    /// 2048) or ECDSA curve (secp256r1, secp384r1, secp521r1; default
    /// secp256r1). Ignored for Ed25519 and when `--key` is given.
    #[arg(long)]
    params: Option<KeyParams>,
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
    #[arg(long)]
    dns: Vec<String>,
    /// Email (rfc822) Subject Alternative Name (repeatable).
    #[arg(long)]
    email: Vec<String>,
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

#[derive(Args)]
struct InspectArgs {
    /// Certificate to read (PEM or DER, auto-detected). Omit or `-` for stdin.
    input: Option<PathBuf>,
    /// Also print the SHA-256 fingerprint of the DER encoding.
    #[arg(long)]
    fingerprint: bool,
    /// Emit machine-readable JSON instead of text.
    #[arg(long)]
    json: bool,
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
        Command::Inspect(args) => inspect(args),
    }
}

fn generate_key(args: GenerateKeyArgs) -> Result<()> {
    let key = generate(args.algorithm, args.params)?;
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

    let cert_info = cert_info(&args.dn, &key, &args.opts)?;
    let cert = ca.issue(&cert_info, Validity::for_days(args.opts.days));

    emit(
        &cert,
        generated.then_some(&key),
        &args.key.key_out,
        &args.opts,
    )
}

fn inspect(args: InspectArgs) -> Result<()> {
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

/// Reads certificate bytes from a file, or from stdin when the path is absent or `-`.
fn read_cert_input(path: &Option<PathBuf>) -> Result<Vec<u8>> {
    match path.as_deref().filter(|p| p.as_os_str() != "-") {
        Some(path) => Ok(fs::read(path)?),
        None => {
            let mut buf = Vec::new();
            std::io::stdin().lock().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

/// A decoded extension, ready to render in either output format.
struct ExtReport {
    oid: String,
    name: &'static str,
    critical: bool,
    summary: String,
}

/// The fields of a certificate that `inspect` reports.
struct CertReport {
    subject: String,
    issuer: String,
    serial: String,
    not_before: String,
    not_after: String,
    expired: bool,
    not_yet_valid: bool,
    days_remaining: i64,
    public_key: String,
    signature_algorithm: String,
    fingerprint_sha256: Option<String>,
    extensions: Vec<ExtReport>,
}

impl CertReport {
    fn from_cert(cert: &X509Certificate, want_fingerprint: bool) -> Result<Self> {
        let tbs = &cert.tbs_certificate;

        let not_before = tbs.validity.not_before.to_unix_duration().as_secs() as i64;
        let not_after = tbs.validity.not_after.to_unix_duration().as_secs() as i64;
        let now = OffsetDateTime::now_utc().unix_timestamp();

        let fingerprint_sha256 = want_fingerprint
            .then(|| cert.to_der().map(|der| hex_colons(&Sha256::digest(der))))
            .transpose()?;

        let extensions = tbs
            .extensions
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(describe_extension)
            .collect();

        Ok(Self {
            subject: tbs.subject.to_string(),
            issuer: tbs.issuer.to_string(),
            serial: hex_colons(tbs.serial_number.as_bytes()),
            not_before: tbs.validity.not_before.to_string(),
            not_after: tbs.validity.not_after.to_string(),
            expired: not_after < now,
            not_yet_valid: not_before > now,
            days_remaining: (not_after - now).div_euclid(86_400),
            public_key: describe_public_key(&tbs.subject_public_key_info),
            signature_algorithm: describe_oid(&cert.signature_algorithm.oid.to_string()),
            fingerprint_sha256,
            extensions,
        })
    }

    fn validity_note(&self) -> String {
        if self.expired {
            "(expired)".to_string()
        } else if self.not_yet_valid {
            "(not yet valid)".to_string()
        } else {
            format!("(expires in {} days)", self.days_remaining)
        }
    }

    fn to_text(&self) -> String {
        let mut out = String::new();
        let mut field = |label: &str, value: &str| {
            out.push_str(&format!("{label:<22}{value}\n"));
        };
        field("Subject:", &self.subject);
        field("Issuer:", &self.issuer);
        field("Serial:", &self.serial);
        field("Not Before:", &self.not_before);
        field(
            "Not After:",
            &format!("{} {}", self.not_after, self.validity_note()),
        );
        field("Public Key:", &self.public_key);
        field("Signature Algorithm:", &self.signature_algorithm);
        if let Some(fp) = &self.fingerprint_sha256 {
            field("SHA-256 Fingerprint:", fp);
        }

        if self.extensions.is_empty() {
            out.push_str("Extensions:           (none)\n");
        } else {
            out.push_str("Extensions:\n");
            for ext in &self.extensions {
                let label = if ext.name.is_empty() {
                    ext.oid.clone()
                } else {
                    ext.name.to_string()
                };
                let crit = if ext.critical { " (critical)" } else { "" };
                out.push_str(&format!("  {label}{crit}: {}\n", ext.summary));
            }
        }
        out
    }

    fn to_json(&self) -> String {
        let fingerprint = match &self.fingerprint_sha256 {
            Some(fp) => json_string(fp),
            None => "null".to_string(),
        };
        let extensions: Vec<String> = self
            .extensions
            .iter()
            .map(|ext| {
                format!(
                    "{{\"oid\":{},\"name\":{},\"critical\":{},\"summary\":{}}}",
                    json_string(&ext.oid),
                    json_string(ext.name),
                    ext.critical,
                    json_string(&ext.summary),
                )
            })
            .collect();

        format!(
            concat!(
                "{{\"subject\":{},\"issuer\":{},\"serial\":{},",
                "\"not_before\":{},\"not_after\":{},\"expired\":{},",
                "\"not_yet_valid\":{},\"days_remaining\":{},\"public_key\":{},",
                "\"signature_algorithm\":{},\"fingerprint_sha256\":{},",
                "\"extensions\":[{}]}}\n"
            ),
            json_string(&self.subject),
            json_string(&self.issuer),
            json_string(&self.serial),
            json_string(&self.not_before),
            json_string(&self.not_after),
            self.expired,
            self.not_yet_valid,
            self.days_remaining,
            json_string(&self.public_key),
            json_string(&self.signature_algorithm),
            fingerprint,
            extensions.join(","),
        )
    }
}

/// Names the subject's public key algorithm (and size, for RSA).
fn describe_public_key(spki: &x509_cert::spki::SubjectPublicKeyInfoOwned) -> String {
    match PublicKey::from_x509spki(spki) {
        Ok(PublicKey::Rsa(key)) => {
            use rsa::traits::PublicKeyParts;
            format!("RSA ({} bit)", key.n().bits())
        }
        Ok(PublicKey::EcdsaP256(_)) => "ECDSA (P-256)".to_string(),
        Ok(PublicKey::EcdsaP384(_)) => "ECDSA (P-384)".to_string(),
        Ok(PublicKey::EcdsaP521(_)) => "ECDSA (P-521)".to_string(),
        Ok(PublicKey::Ed25519(_)) => "Ed25519".to_string(),
        Err(_) => format!("unrecognized (OID {})", spki.algorithm.oid),
    }
}

/// Decodes a single extension into a renderable summary.
fn describe_extension(ext: &x509_cert::ext::Extension) -> ExtReport {
    let value = ext.extn_value.as_bytes();
    let (name, summary) = match ext.extn_id.to_string().as_str() {
        "2.5.29.19" => ("Basic Constraints", basic_constraints_summary(value)),
        "2.5.29.15" => ("Key Usage", key_usage_summary(value)),
        "2.5.29.37" => ("Extended Key Usage", extended_key_usage_summary(value)),
        "2.5.29.17" => ("Subject Alternative Name", san_summary(value)),
        "2.5.29.14" => ("Subject Key Identifier", ski_summary(value)),
        "2.5.29.35" => ("Authority Key Identifier", aki_summary(value)),
        _ => ("", format!("{} bytes", value.len())),
    };
    ExtReport {
        oid: ext.extn_id.to_string(),
        name,
        critical: ext.critical,
        summary,
    }
}

fn basic_constraints_summary(value: &[u8]) -> String {
    match pkix::BasicConstraints::from_der(value) {
        Ok(bc) => match bc.path_len_constraint {
            Some(len) => format!("CA={}, pathLen={len}", bc.ca),
            None => format!("CA={}", bc.ca),
        },
        Err(_) => UNDECODABLE.to_string(),
    }
}

fn key_usage_summary(value: &[u8]) -> String {
    match pkix::KeyUsage::from_der(value) {
        Ok(ku) => {
            let names: Vec<&str> = ku.0.into_iter().map(key_usage_name).collect();
            join_or_none(&names)
        }
        Err(_) => UNDECODABLE.to_string(),
    }
}

fn extended_key_usage_summary(value: &[u8]) -> String {
    match pkix::ExtendedKeyUsage::from_der(value) {
        Ok(eku) => {
            let names: Vec<String> = eku
                .0
                .iter()
                .map(|oid| describe_oid(&oid.to_string()))
                .collect();
            join_or_none(&names)
        }
        Err(_) => UNDECODABLE.to_string(),
    }
}

fn san_summary(value: &[u8]) -> String {
    match pkix::SubjectAltName::from_der(value) {
        Ok(san) => {
            let names: Vec<String> = san.0.iter().map(general_name).collect();
            join_or_none(&names)
        }
        Err(_) => UNDECODABLE.to_string(),
    }
}

fn ski_summary(value: &[u8]) -> String {
    match pkix::SubjectKeyIdentifier::from_der(value) {
        Ok(ski) => hex_colons(ski.0.as_bytes()),
        Err(_) => UNDECODABLE.to_string(),
    }
}

fn aki_summary(value: &[u8]) -> String {
    match pkix::AuthorityKeyIdentifier::from_der(value) {
        Ok(aki) => match aki.key_identifier {
            Some(id) => format!("keyid:{}", hex_colons(id.as_bytes())),
            None => "(no key identifier)".to_string(),
        },
        Err(_) => UNDECODABLE.to_string(),
    }
}

/// Renders a `GeneralName` for the SAN summary.
fn general_name(name: &GeneralName) -> String {
    match name {
        GeneralName::DnsName(s) => format!("DNS:{s}"),
        GeneralName::Rfc822Name(s) => format!("email:{s}"),
        GeneralName::UniformResourceIdentifier(s) => format!("URI:{s}"),
        GeneralName::IpAddress(octets) => format!("IP:{}", format_ip(octets.as_bytes())),
        GeneralName::DirectoryName(name) => format!("dirName:{name}"),
        GeneralName::RegisteredId(oid) => format!("registeredID:{oid}"),
        other => format!("{other:?}"),
    }
}

/// Formats raw IP-address octets: dotted-quad for v4, colon-hex for v6.
fn format_ip(octets: &[u8]) -> String {
    match octets.len() {
        4 => octets
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join("."),
        16 => octets
            .chunks(2)
            .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
            .collect::<Vec<_>>()
            .join(":"),
        _ => hex_colons(octets),
    }
}

fn key_usage_name(usage: pkix::KeyUsages) -> &'static str {
    use pkix::KeyUsages;
    match usage {
        KeyUsages::DigitalSignature => "digitalSignature",
        KeyUsages::NonRepudiation => "nonRepudiation",
        KeyUsages::KeyEncipherment => "keyEncipherment",
        KeyUsages::DataEncipherment => "dataEncipherment",
        KeyUsages::KeyAgreement => "keyAgreement",
        KeyUsages::KeyCertSign => "keyCertSign",
        KeyUsages::CRLSign => "cRLSign",
        KeyUsages::EncipherOnly => "encipherOnly",
        KeyUsages::DecipherOnly => "decipherOnly",
    }
}

/// Maps a dotted OID string to a friendly name, falling back to the OID itself.
fn describe_oid(oid: &str) -> String {
    let name = match oid {
        // Extended Key Usage purposes.
        "1.3.6.1.5.5.7.3.1" => "serverAuth",
        "1.3.6.1.5.5.7.3.2" => "clientAuth",
        "1.3.6.1.5.5.7.3.3" => "codeSigning",
        "1.3.6.1.5.5.7.3.4" => "emailProtection",
        "1.3.6.1.5.5.7.3.8" => "timeStamping",
        "1.3.6.1.5.5.7.3.9" => "OCSPSigning",
        // Signature algorithms.
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.3.101.112" => "Ed25519",
        other => return other.to_string(),
    };
    name.to_string()
}

/// Joins parts with commas, or reports `(none)` when empty.
fn join_or_none<S: AsRef<str>>(parts: &[S]) -> String {
    if parts.is_empty() {
        "(none)".to_string()
    } else {
        parts
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Lowercase hex with colon separators, e.g. `9f:86:d0`.
fn hex_colons(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Encodes a string as a JSON string literal (quotes + minimal escaping).
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

const UNDECODABLE: &str = "(undecodable)";

/// Generates a key pair for the requested algorithm and `--params`.
///
/// `--params` is parsed (and curve names normalized) when the arguments are
/// read, so here it only remains to reject a parameter that doesn't match the
/// chosen algorithm — e.g. a curve for RSA, or a key size for ECDSA.
fn generate(algorithm: Algorithm, params: Option<KeyParams>) -> Result<KeyPair> {
    match algorithm {
        Algorithm::Rsa => {
            let bits = match params {
                Some(KeyParams::Bits(bits)) => bits as usize,
                Some(KeyParams::Curve(_)) => {
                    return Err("RSA takes a key size, not a curve; e.g. --params 2048".into());
                }
                None => 2048,
            };
            Ok(KeyPair::generate_rsa(bits)?)
        }
        Algorithm::Ecdsa => {
            let curve = match params {
                Some(KeyParams::Curve(curve)) => curve,
                Some(KeyParams::Bits(_)) => {
                    return Err(
                        "ECDSA takes a curve, not a key size; e.g. --params secp256r1".into(),
                    );
                }
                None => Curve::P256,
            };
            Ok(match curve {
                Curve::P256 => KeyPair::generate_ecdsa_p256(),
                Curve::P384 => KeyPair::generate_ecdsa_p384(),
                Curve::P521 => KeyPair::generate_ecdsa_p521(),
            })
        }
        Algorithm::Ed25519 => Ok(KeyPair::generate_ed25519()),
    }
}

/// Loads the key from `--key`, or generates one. Returns `(key, generated)`.
fn key_pair(args: &KeySourceArgs) -> Result<(KeyPair, bool)> {
    match &args.key {
        Some(path) => Ok((
            KeyPair::import_from_pkcs8_pem(&fs::read_to_string(path)?)?,
            false,
        )),
        None => Ok((generate(args.algorithm, args.params)?, true)),
    }
}

/// Builds the certification request info from the DN, key, and options.
fn cert_info(dn: &DnArgs, key: &KeyPair, opts: &CertOptArgs) -> Result<CertificationRequestInfo> {
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
    if let Some(san) = build_san(&opts.dns, &opts.email)? {
        extensions.push(san);
    }

    Ok(CertificationRequestInfo::builder()
        .subject(subject)
        .subject_public_key(PublicKey::from_key_pair(key))
        .is_ca(opts.ca)
        .usages(usages)
        .extensions(extensions)
        .build())
}

/// Builds a Subject Alternative Name extension from DNS and email entries.
///
/// certkit's own `SubjectAltName` only models DNS names, so the extension is
/// assembled directly from `x509_cert` general names to also carry rfc822
/// (email) entries, then wrapped as a raw `ExtensionParam`.
fn build_san(dns: &[String], email: &[String]) -> Result<Option<ExtensionParam>> {
    if dns.is_empty() && email.is_empty() {
        return Ok(None);
    }

    let mut names = Vec::new();
    for name in dns {
        let ia5 =
            Ia5String::try_from(name.clone()).map_err(|_| format!("invalid DNS name: {name}"))?;
        names.push(GeneralName::DnsName(ia5));
    }
    for addr in email {
        let ia5 = Ia5String::try_from(addr.clone())
            .map_err(|_| format!("invalid email address: {addr}"))?;
        names.push(GeneralName::Rfc822Name(ia5));
    }

    let san = pkix::SubjectAltName(names);
    Ok(Some(ExtensionParam {
        oid: SubjectAltName::OID,
        critical: false,
        value: san.to_der()?,
    }))
}

/// Loads a CA certificate from a PEM or DER file (auto-detected).
fn load_ca_cert(path: &Path) -> Result<Certificate> {
    Ok(Certificate {
        inner: parse_x509(&fs::read(path)?)?,
    })
}

/// Parses an X.509 certificate from PEM or DER bytes (auto-detected).
fn parse_x509(bytes: &[u8]) -> Result<X509Certificate> {
    Ok(if bytes.starts_with(b"-----BEGIN") {
        X509Certificate::from_pem(bytes)?
    } else {
        X509Certificate::from_der(bytes)?
    })
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
