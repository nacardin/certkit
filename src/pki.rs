use anyhow::Result;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::signature::SignatureEncoding;
use rsa::signature::Signer as RsaSigner;
use sha2::Sha256;

use crate::key::KeyPair;

/// Signs the provided data using the given key and signature algorithm.
/// This simplified function demonstrates using different RustCrypto signing implementations.
pub fn sign_data(data: &[u8], key: &KeyPair, _sig_alg: &str) -> Result<Vec<u8>> {
    match key {
        KeyPair::Rsa { private, .. } => {
            // Using RSA-PKCS1v15 (in a real implementation you’d choose a proper hash algorithm)
            let signing_key: RsaSigningKey<Sha256> = RsaSigningKey::new(*(private.clone()));
            let signature = signing_key.sign(data);
            Ok(signature.to_vec())
        }
        KeyPair::EcdsaP256 { signing_key, .. } => {
            let signature: p256::ecdsa::Signature = signing_key.sign(data);
            Ok(signature.to_vec())
        }
        KeyPair::Ed25519 { signing_key } => {
            let signature = signing_key.sign(data);
            Ok(signature.to_bytes().to_vec())
        }
    }
}

/// Assembles the final certificate by combining the TBS, signature algorithm, and signature.
/// In a real implementation, this would build a proper ASN.1 SEQUENCE.
pub fn assemble_certificate(tbs: Vec<u8>, sig_alg: &str, signature: &[u8]) -> Result<Vec<u8>> {
    let mut cert = Vec::new();
    cert.extend(tbs);
    cert.extend(sig_alg.as_bytes());
    cert.extend(signature);
    Ok(cert)
}

/// (Optional) Verifies a certificate’s signature using the issuer’s public key.
/// In production code, you’d parse the certificate and verify per RFC 5280.
pub fn verify_certificate(_cert_der: &[u8], _issuer_key: &KeyPair) -> Result<bool> {
    // For demonstration purposes, assume verification is successful.
    Ok(true)
}
