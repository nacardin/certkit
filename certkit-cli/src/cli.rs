//! Command-line argument definitions.
//!
//! These are the clap derive types: the top-level [`Cli`]/[`Command`], the
//! value enums describing algorithms and output formats, and the `Args` groups
//! shared between the certificate-issuing subcommands. Fields are `pub(crate)`
//! so the [`commands`](crate::commands) handlers and their helpers can read them.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use certkit::cert::extensions::ExtendedKeyUsageOption;

#[derive(Parser)]
#[command(
    name = "certkit",
    version,
    about = "Generate keys and X.509 certificates with certkit"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
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
pub(crate) enum Algorithm {
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
pub(crate) enum KeyParams {
    /// RSA modulus size in bits.
    Bits(u32),
    /// ECDSA curve.
    Curve(Curve),
}

/// A NIST/SECG curve certkit can generate.
#[derive(Copy, Clone, Debug)]
pub(crate) enum Curve {
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
pub(crate) enum CertFormat {
    Pem,
    Der,
}

/// Extended Key Usage purposes that can be requested for a certificate.
#[derive(Copy, Clone, Debug, ValueEnum)]
pub(crate) enum EkuOpt {
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
pub(crate) struct GenerateKeyArgs {
    /// Key algorithm (RSA, ECDSA, or Ed25519).
    #[arg(short, long, alias = "algo", value_enum, ignore_case = true, default_value_t = Algorithm::Ecdsa)]
    pub(crate) algorithm: Algorithm,
    /// Key parameters: RSA size in bits (default 2048) or ECDSA curve
    /// (secp256r1, secp384r1, secp521r1; default secp256r1). Ignored for Ed25519.
    #[arg(long)]
    pub(crate) params: Option<KeyParams>,
    /// Write the key here instead of stdout.
    #[arg(short, long)]
    pub(crate) out: Option<PathBuf>,
}

/// Subject distinguished name fields, shared by the certificate subcommands.
#[derive(Args)]
pub(crate) struct DnArgs {
    /// Subject common name (CN), given positionally (as in Botan).
    #[arg(value_name = "COMMON_NAME")]
    pub(crate) common_name: String,
    /// Subject country (C).
    #[arg(long)]
    pub(crate) country: Option<String>,
    /// Subject state or province (ST).
    #[arg(long)]
    pub(crate) state: Option<String>,
    /// Subject locality (L).
    #[arg(long)]
    pub(crate) locality: Option<String>,
    /// Subject organization (O).
    #[arg(long)]
    pub(crate) organization: Option<String>,
    /// Subject organizational unit (OU).
    #[arg(long)]
    pub(crate) organization_unit: Option<String>,
}

/// How to obtain the subject key pair, shared by the certificate subcommands.
#[derive(Args)]
pub(crate) struct KeySourceArgs {
    /// Algorithm for a freshly generated key (ignored when `--key` is given).
    #[arg(short, long, alias = "algo", value_enum, ignore_case = true, default_value_t = Algorithm::Ecdsa)]
    pub(crate) algorithm: Algorithm,
    /// Key parameters for a freshly generated key: RSA size in bits (default
    /// 2048) or ECDSA curve (secp256r1, secp384r1, secp521r1; default
    /// secp256r1). Ignored for Ed25519 and when `--key` is given.
    #[arg(long)]
    pub(crate) params: Option<KeyParams>,
    /// Use an existing private key (PKCS#8 PEM) instead of generating one.
    #[arg(long)]
    pub(crate) key: Option<PathBuf>,
    /// Write a freshly generated private key here instead of stdout.
    #[arg(long)]
    pub(crate) key_out: Option<PathBuf>,
}

/// Extension, validity, and output options, shared by the certificate subcommands.
#[derive(Args)]
pub(crate) struct CertOptArgs {
    /// DNS Subject Alternative Name (repeatable).
    #[arg(long)]
    pub(crate) dns: Vec<String>,
    /// Email (rfc822) Subject Alternative Name (repeatable).
    #[arg(long)]
    pub(crate) email: Vec<String>,
    /// Extended Key Usage purpose (repeatable).
    #[arg(long = "eku", value_enum)]
    pub(crate) eku: Vec<EkuOpt>,
    /// Mark the certificate as a CA (Basic Constraints CA=true).
    #[arg(long)]
    pub(crate) ca: bool,
    /// Validity period in days from now.
    #[arg(long, default_value_t = 365)]
    pub(crate) days: i64,
    /// Certificate output encoding.
    #[arg(long, value_enum, default_value_t = CertFormat::Pem)]
    pub(crate) format: CertFormat,
    /// Write the certificate here instead of stdout.
    #[arg(short, long)]
    pub(crate) out: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct SelfSignedArgs {
    #[command(flatten)]
    pub(crate) dn: DnArgs,
    #[command(flatten)]
    pub(crate) key: KeySourceArgs,
    #[command(flatten)]
    pub(crate) opts: CertOptArgs,
}

#[derive(Args)]
pub(crate) struct IssueArgs {
    #[command(flatten)]
    pub(crate) dn: DnArgs,
    #[command(flatten)]
    pub(crate) key: KeySourceArgs,
    #[command(flatten)]
    pub(crate) opts: CertOptArgs,
    /// CA certificate to sign with (PEM or DER).
    #[arg(long)]
    pub(crate) ca_cert: PathBuf,
    /// CA private key to sign with (PKCS#8 PEM).
    #[arg(long)]
    pub(crate) ca_key: PathBuf,
}

#[derive(Args)]
pub(crate) struct InspectArgs {
    /// Certificate to read (PEM or DER, auto-detected). Omit or `-` for stdin.
    pub(crate) input: Option<PathBuf>,
    /// Also print the SHA-256 fingerprint of the DER encoding.
    #[arg(long)]
    pub(crate) fingerprint: bool,
    /// Emit machine-readable JSON instead of text.
    #[arg(long)]
    pub(crate) json: bool,
}
