use std::fs;

use anyhow::{Result, bail};
use certkit::key::KeyPair;

use crate::args::{Algorithm, Curve, KeyParams, KeySourceArgs};

pub fn generate(algorithm: Algorithm, params: Option<KeyParams>) -> Result<KeyPair> {
    match algorithm {
        Algorithm::Rsa => {
            let bits = match params {
                Some(KeyParams::Bits(bits)) => bits as usize,
                Some(KeyParams::Curve(_)) => {
                    bail!("RSA takes a key size, not a curve; e.g. --params 2048");
                }
                None => 2048,
            };
            Ok(KeyPair::generate_rsa(bits)?)
        }
        Algorithm::Ecdsa => {
            let curve = match params {
                Some(KeyParams::Curve(curve)) => curve,
                Some(KeyParams::Bits(_)) => {
                    bail!("ECDSA takes a curve, not a key size; e.g. --params secp256r1");
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

/// Returns `(key, generated)` where `generated` is true when the key was freshly created.
pub fn key_pair(args: &KeySourceArgs) -> Result<(KeyPair, bool)> {
    match &args.key {
        Some(path) => Ok((
            KeyPair::import_from_pkcs8_pem(&fs::read_to_string(path)?)?,
            false,
        )),
        None => Ok((generate(args.algorithm, args.params)?, true)),
    }
}
