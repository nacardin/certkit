use anyhow::Result;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPublicKey},
};

/// Supported key types for certificate operations.
pub enum KeyPair {
    Rsa {
        private: Box<RsaPrivateKey>,
        public: RsaPublicKey,
    },
    EcdsaP256 {
        signing_key: P256SigningKey,
        verifying_key: P256VerifyingKey,
    },
    Ed25519 {
        signing_key: Ed25519SigningKey,
    },
}

impl KeyPair {
    /// Generate an RSA key pair with the specified number of bits.
    pub fn generate_rsa(bits: usize) -> Result<Self> {
        let mut rng = rand_core::OsRng;
        let private = RsaPrivateKey::new(&mut rng, bits)?;
        let public = RsaPublicKey::from(&private);
        Ok(KeyPair::Rsa {
            private: Box::new(private),
            public,
        })
    }

    /// Generate an ECDSA P-256 key pair.
    pub fn generate_ecdsa_p256() -> Self {
        let mut rng = rand_core::OsRng;
        let signing_key = P256SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key().to_owned();
        KeyPair::EcdsaP256 {
            signing_key,
            verifying_key,
        }
    }

    /// Generate an Ed25519 key pair.
    pub fn generate_ed25519() -> Self {
        let mut rng = rand_core::OsRng;
        let signing_key: Ed25519SigningKey = Ed25519SigningKey::generate(&mut rng);
        KeyPair::Ed25519 { signing_key }
    }

    pub fn get_public_key_der(&self) -> Vec<u8> {
        match self {
            KeyPair::Rsa { public, .. } => public.to_pkcs1_der().unwrap().as_bytes().to_vec(),
            KeyPair::EcdsaP256 { verifying_key, .. } => {
                verifying_key.to_pkcs1_der().unwrap().as_bytes().to_vec()
            }
            KeyPair::Ed25519 { signing_key, .. } => signing_key.verifying_key().to_bytes().to_vec(),
        }
    }

    pub fn import_from_der(der: &[u8]) -> Result<Self> {
        let public = RsaPublicKey::from_pkcs1_der(der)?;
        let private = RsaPrivateKey::from_pkcs1_der(der)?;
        Ok(KeyPair::Rsa {
            private: Box::new(private),
            public,
        })
    }

    // (Additional methods for signing data or converting to/from PEM could be added here.)
}
