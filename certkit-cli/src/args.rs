//! Shared command-line argument types.
//!
//! These are the clap derive pieces reused across subcommands: the value enums
//! describing algorithms and output formats, and the `Args` groups
//! ([`DnArgs`], [`KeySourceArgs`], [`CertOptArgs`]) flattened into the
//! certificate subcommands. Each subcommand's own options struct lives with its
//! handler under [`cmd`](crate::cmd). Fields are `pub` so those handlers
//! and their helpers can read them.

use std::path::PathBuf;

use clap::{Args, ValueEnum};

use certkit::cert::extensions::ExtendedKeyUsageOption;

/// Key algorithm, named as Botan's `keygen --algo` expects.
///
/// The key shape (RSA size, ECDSA curve) is selected with `--params`, also
/// following Botan: `--params 2048` for RSA, `--params secp256r1` for ECDSA.
#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Algorithm {
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
pub enum KeyParams {
    /// RSA modulus size in bits.
    Bits(u32),
    /// ECDSA curve.
    Curve(Curve),
}

/// A NIST/SECG curve certkit can generate.
#[derive(Copy, Clone, Debug)]
pub enum Curve {
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
pub enum CertFormat {
    Pem,
    Der,
}

/// Extended Key Usage purposes that can be requested for a certificate.
#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum EkuOpt {
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

/// Subject distinguished name fields, shared by the certificate subcommands.
#[derive(Args)]
pub struct DnArgs {
    /// Subject common name (CN), given positionally (as in Botan).
    #[arg(value_name = "COMMON_NAME")]
    pub common_name: String,
    /// Subject country (C).
    #[arg(long)]
    pub country: Option<String>,
    /// Subject state or province (ST).
    #[arg(long)]
    pub state: Option<String>,
    /// Subject locality (L).
    #[arg(long)]
    pub locality: Option<String>,
    /// Subject organization (O).
    #[arg(long)]
    pub organization: Option<String>,
    /// Subject organizational unit (OU).
    #[arg(long)]
    pub organization_unit: Option<String>,
}

/// How to obtain the subject key pair, shared by the certificate subcommands.
#[derive(Args)]
pub struct KeySourceArgs {
    /// Algorithm for a freshly generated key (ignored when `--key` is given).
    #[arg(short, long, alias = "algo", value_enum, ignore_case = true, default_value_t = Algorithm::Ecdsa)]
    pub algorithm: Algorithm,
    /// Key parameters for a freshly generated key: RSA size in bits (default
    /// 2048) or ECDSA curve (secp256r1, secp384r1, secp521r1; default
    /// secp256r1). Ignored for Ed25519 and when `--key` is given.
    #[arg(long)]
    pub params: Option<KeyParams>,
    /// Use an existing private key (PKCS#8 PEM) instead of generating one.
    #[arg(long)]
    pub key: Option<PathBuf>,
    /// Write a freshly generated private key here instead of stdout.
    #[arg(long)]
    pub key_out: Option<PathBuf>,
}

/// Extension, validity, and output options, shared by the certificate subcommands.
#[derive(Args)]
pub struct CertOptArgs {
    /// DNS Subject Alternative Name (repeatable).
    #[arg(long)]
    pub dns: Vec<String>,
    /// Email (rfc822) Subject Alternative Name (repeatable).
    #[arg(long)]
    pub email: Vec<String>,
    /// Extended Key Usage purpose (repeatable).
    #[arg(long = "eku", value_enum)]
    pub eku: Vec<EkuOpt>,
    /// Mark the certificate as a CA (Basic Constraints CA=true).
    #[arg(long)]
    pub ca: bool,
    /// Validity period in days from now.
    #[arg(long, default_value_t = 365)]
    pub days: i64,
    /// Certificate output encoding.
    #[arg(long, value_enum, default_value_t = CertFormat::Pem)]
    pub format: CertFormat,
    /// Write the certificate here instead of stdout.
    #[arg(short, long)]
    pub out: Option<PathBuf>,
}
