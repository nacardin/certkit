//! Obtaining the subject key pair from the command line.
//!
//! [`generate`] turns an [`Algorithm`] plus `--params` into a fresh [`KeyPair`],
//! and [`key_pair`] either loads an existing key (`--key`) or generates one.

use std::fs;

use certkit::key::KeyPair;

use crate::Result;
use crate::cli::{Algorithm, Curve, KeyParams, KeySourceArgs};

/// Generates a key pair for the requested algorithm and `--params`.
///
/// `--params` is parsed (and curve names normalized) when the arguments are
/// read, so here it only remains to reject a parameter that doesn't match the
/// chosen algorithm — e.g. a curve for RSA, or a key size for ECDSA.
pub(crate) fn generate(algorithm: Algorithm, params: Option<KeyParams>) -> Result<KeyPair> {
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
pub(crate) fn key_pair(args: &KeySourceArgs) -> Result<(KeyPair, bool)> {
    match &args.key {
        Some(path) => Ok((
            KeyPair::import_from_pkcs8_pem(&fs::read_to_string(path)?)?,
            false,
        )),
        None => Ok((generate(args.algorithm, args.params)?, true)),
    }
}
