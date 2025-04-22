use crate::error::CertKitError;
pub type Result<T> = std::result::Result<T, CertKitError>;

use ecdsa::VerifyingKey;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;
use p256::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use p384::ecdsa::{SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey};
use p521::NistP521;
use p521::ecdsa::SigningKey as P521SigningKey;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::signature::SignatureEncoding;
use rsa::signature::Signer as RsaSigner;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPublicKey},
};
use sha2::Sha256;

/// Supported key types for certificate operations.
///
/// This enum represents different types of key pairs, including RSA, ECDSA P-256, and Ed25519.
#[derive(Debug, Clone)]
pub enum KeyPair {
    /// RSA key pair.
    ///
    /// # Fields
    /// * `private` - The private key.
    /// * `public` - The public key.
    Rsa {
        private: Box<RsaPrivateKey>,
        public: RsaPublicKey,
    },
    /// ECDSA P-256 key pair.
    ///
    /// # Fields
    /// * `signing_key` - The signing key.
    /// * `verifying_key` - The verifying key.
    EcdsaP256 {
        signing_key: P256SigningKey,
        verifying_key: P256VerifyingKey,
    },
    /// ECDSA P-384 key pair.
    ///
    /// # Fields
    /// * `signing_key` - The signing key.
    /// * `verifying_key` - The verifying key.
    EcdsaP384 {
        signing_key: P384SigningKey,
        verifying_key: P384VerifyingKey,
    },
    /// ECDSA P-521 key pair.
    ///
    /// # Fields
    /// * `signing_key` - The signing key.
    /// * `verifying_key` - The verifying key.
    EcdsaP521 {
        signing_key: ecdsa::SigningKey<NistP521>,
        verifying_key: ecdsa::VerifyingKey<NistP521>,
    },
    /// Ed25519 key pair.
    ///
    /// # Fields
    /// * `signing_key` - The signing key.
    Ed25519 { signing_key: Ed25519SigningKey },
}
use p256::pkcs8::DecodePrivateKey;

impl KeyPair {
    /// Generate an RSA key pair with the specified number of bits.
    ///
    /// # Arguments
    /// * `bits` - The number of bits for the RSA key.
    ///
    /// # Returns
    /// A `KeyPair` object containing the RSA key pair.
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
    ///
    /// # Returns
    /// A `KeyPair` object containing the ECDSA P-256 key pair.
    pub fn generate_ecdsa_p256() -> Self {
        let mut rng = rand_core::OsRng;
        let signing_key = P256SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key().to_owned();
        KeyPair::EcdsaP256 {
            signing_key,
            verifying_key,
        }
    }

    /// Generate an ECDSA P-384 key pair.
    ///
    /// # Returns
    /// A `KeyPair` object containing the ECDSA P-384 key pair.
    pub fn generate_ecdsa_p384() -> Self {
        let mut rng = rand_core::OsRng;
        let signing_key = P384SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key().to_owned();
        KeyPair::EcdsaP384 {
            signing_key,
            verifying_key,
        }
    }

    /// Generate an ECDSA P-521 key pair.
    ///
    /// # Returns
    /// A `KeyPair` object containing the ECDSA P-521 key pair.
    pub fn generate_ecdsa_p521() -> Self {
        let mut rng = rand_core::OsRng;
        let signing_key: ecdsa::SigningKey<NistP521> =
            ecdsa::SigningKey::<NistP521>::random(&mut rng);
        let verifying_key = signing_key.verifying_key().to_owned();
        KeyPair::EcdsaP521 {
            signing_key,
            verifying_key,
        }
    }

    /// Generate an Ed25519 key pair.
    ///
    /// # Returns
    /// A `KeyPair` object containing the Ed25519 key pair.
    pub fn generate_ed25519() -> Self {
        let mut rng = rand_core::OsRng;
        let signing_key: Ed25519SigningKey = Ed25519SigningKey::generate(&mut rng);
        KeyPair::Ed25519 { signing_key }
    }

    /// Retrieves the public key in DER format.
    ///
    /// # Returns
    /// A byte vector containing the DER-encoded public key.
    pub fn get_public_key_der(&self) -> Vec<u8> {
        match self {
            KeyPair::Rsa { public, .. } => public.to_pkcs1_der().unwrap().as_bytes().to_vec(),
            KeyPair::EcdsaP256 { verifying_key, .. } => verifying_key.to_sec1_bytes().to_vec(),
            KeyPair::EcdsaP384 { verifying_key, .. } => verifying_key.to_sec1_bytes().to_vec(),
            KeyPair::EcdsaP521 { verifying_key, .. } => verifying_key.to_sec1_bytes().to_vec(),
            KeyPair::Ed25519 { signing_key } => signing_key.verifying_key().to_bytes().to_vec(),
        }
    }
    /// Imports a key pair from DER-encoded data.
    ///
    /// # Arguments
    /// * `der` - A byte slice containing the DER-encoded key data.
    ///
    /// # Returns
    /// A `KeyPair` object.
    pub fn import_from_der(der: &[u8]) -> Result<Self> {
        // Try RSA PKCS#1 first
        if let (Ok(private), Ok(public)) = (
            RsaPrivateKey::from_pkcs1_der(der),
            RsaPublicKey::from_pkcs1_der(der),
        ) {
            return Ok(KeyPair::Rsa {
                private: Box::new(private),
                public,
            });
        }
        // Try RSA PKCS#8
        if let Ok(private) = RsaPrivateKey::from_pkcs8_der(der) {
            let public = RsaPublicKey::from(&private);
            return Ok(KeyPair::Rsa {
                private: Box::new(private),
                public,
            });
        }

        // Try ECDSA P-256 PKCS#8
        if let Ok(signing_key) = P256SigningKey::from_pkcs8_der(der) {
            let verifying_key = signing_key.verifying_key().to_owned();
            return Ok(KeyPair::EcdsaP256 {
                signing_key,
                verifying_key,
            });
        }
        // Try ECDSA P-384 PKCS#8
        if let Ok(signing_key) = P384SigningKey::from_pkcs8_der(der) {
            let verifying_key = signing_key.verifying_key().to_owned();
            return Ok(KeyPair::EcdsaP384 {
                signing_key,
                verifying_key,
            });
        }
        // Try ECDSA P-521 PKCS#8
        if let Ok(signing_key) = ecdsa::SigningKey::<NistP521>::from_pkcs8_der(der) {
            let verifying_key = signing_key.verifying_key().to_owned();
            return Ok(KeyPair::EcdsaP521 {
                signing_key,
                verifying_key,
            });
        }

        // Try Ed25519
        if let Ok(signing_key) = Ed25519SigningKey::from_pkcs8_der(der) {
            return Ok(KeyPair::Ed25519 { signing_key });
        }
        Err(CertKitError::DecodingError(
            "Unsupported or invalid key DER encoding".to_string(),
        ))
    }

    /// Imports a key pair from PEM-encoded data.
    ///
    /// # Arguments
    /// * `pem_str` - A string slice containing the PEM-encoded key data.
    ///
    /// # Returns
    /// A `KeyPair` object.
    pub fn import_from_pkcs8_pem(pem_str: &str) -> Result<Self> {
        let pemd = pem::parse(pem_str)
            .map_err(|_| CertKitError::DecodingError("Failed to parse PEM".to_string()))?;

        if pemd.tag() == "PRIVATE KEY" {
            Self::import_from_der(pemd.contents())
        } else {
            Err(CertKitError::InvalidInput(format!(
                "Unsupported PEM tag: {}",
                pemd.tag()
            )))
        }
    }

    /// Converts the key pair to an X.509 SubjectPublicKeyInfo format.
    ///
    /// # Returns
    /// An `x509_cert::spki::SubjectPublicKeyInfoOwned` object.
    pub fn as_spki(&self) -> x509_cert::spki::SubjectPublicKeyInfoOwned {
        match self {
            KeyPair::Rsa { public, .. } => {
                x509_cert::spki::SubjectPublicKeyInfoOwned::from_key(public.clone()).unwrap()
            }
            KeyPair::EcdsaP256 { verifying_key, .. } => {
                x509_cert::spki::SubjectPublicKeyInfoOwned::from_key(*verifying_key).unwrap()
            }
            KeyPair::EcdsaP384 { verifying_key, .. } => {
                x509_cert::spki::SubjectPublicKeyInfoOwned::from_key(*verifying_key).unwrap()
            }
            KeyPair::EcdsaP521 { verifying_key, .. } => {
                x509_cert::spki::SubjectPublicKeyInfoOwned::from_key(*verifying_key).unwrap()
            }
            KeyPair::Ed25519 { signing_key } => {
                let pk_bytes = signing_key.verifying_key().to_bytes();
                x509_cert::spki::SubjectPublicKeyInfoOwned {
                    algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                        oid: const_oid::ObjectIdentifier::new_unwrap("1.3.101.112"),
                        parameters: None,
                    },
                    subject_public_key: der::asn1::BitString::from_bytes(&pk_bytes).unwrap(),
                }
            }
        }
    }

    /// Signs the provided data using the given key and signature algorithm.
    ///
    /// # Arguments
    /// * `data` - A byte slice containing the data to sign.
    ///
    /// # Returns
    /// A byte vector containing the signature.
    pub fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
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
            KeyPair::EcdsaP384 { signing_key, .. } => {
                let signature: p384::ecdsa::Signature = signing_key.sign(data);
                Ok(signature.to_vec())
            }
            KeyPair::EcdsaP521 { signing_key, .. } => {
                let skey: P521SigningKey = signing_key.clone().into();

                let signature: p521::ecdsa::Signature = skey.sign(data);
                Ok(signature.to_vec())
            }
            KeyPair::Ed25519 { signing_key } => {
                let signature = signing_key.sign(data);
                Ok(signature.to_bytes().to_vec())
            }
        }
    }
}

/// Represents a public key.
///
/// This enum supports RSA, ECDSA P-256, and Ed25519 public keys.
#[derive(Debug, Clone)]
pub enum PublicKey {
    /// RSA public key.
    Rsa(RsaPublicKey),
    /// ECDSA P-256 public key.
    EcdsaP256(P256VerifyingKey),
    /// ECDSA P-384 public key.
    EcdsaP384(P384VerifyingKey),
    /// ECDSA P-521 public key.
    EcdsaP521(VerifyingKey<NistP521>),
    /// Ed25519 public key.
    Ed25519(Ed25519VerifyingKey),
}

impl PublicKey {
    /// Converts the public key to DER format.
    ///
    /// # Returns
    /// A byte vector containing the DER-encoded public key.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        match self {
            PublicKey::Rsa(public) => Ok(public.to_pkcs1_der()?.as_bytes().to_vec()),
            PublicKey::EcdsaP256(verifying_key) => {
                Ok(verifying_key.to_pkcs1_der()?.as_bytes().to_vec())
            }
            PublicKey::EcdsaP384(verifying_key) => Ok(verifying_key.to_sec1_bytes().to_vec()),
            PublicKey::EcdsaP521(verifying_key) => Ok(verifying_key.to_sec1_bytes().to_vec()),
            PublicKey::Ed25519(verifying_key) => Ok(verifying_key.to_bytes().to_vec()),
        }
    }

    /// Creates a public key from DER-encoded data.
    ///
    /// # Arguments
    /// * `der` - A byte slice containing the DER-encoded public key.
    ///
    /// # Returns
    /// A `PublicKey` object.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let public = RsaPublicKey::from_pkcs1_der(der)?;
        Ok(PublicKey::Rsa(public))
    }

    /// Creates a public key from a key pair.
    ///
    /// # Arguments
    /// * `key_pair` - A reference to a `KeyPair` object.
    ///
    /// # Returns
    /// A `PublicKey` object.
    pub fn from_key_pair(key_pair: &KeyPair) -> Self {
        match key_pair {
            KeyPair::Rsa { public, .. } => PublicKey::Rsa(public.clone()),
            KeyPair::EcdsaP256 { verifying_key, .. } => PublicKey::EcdsaP256(*verifying_key),
            KeyPair::EcdsaP384 { verifying_key, .. } => PublicKey::EcdsaP384(*verifying_key),
            KeyPair::EcdsaP521 { verifying_key, .. } => PublicKey::EcdsaP521(*verifying_key),
            KeyPair::Ed25519 { signing_key, .. } => PublicKey::Ed25519(signing_key.verifying_key()),
        }
    }

    /// Creates a public key from an X.509 SubjectPublicKeyInfo object.
    ///
    /// # Arguments
    /// * `spki` - A reference to an `x509_cert::spki::SubjectPublicKeyInfoOwned` object.
    ///
    /// # Returns
    /// A `PublicKey` object.
    pub fn from_x509spki(spki: &x509_cert::spki::SubjectPublicKeyInfoOwned) -> Result<Self> {
        use const_oid::db::{
            rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_256_R_1, SECP_384_R_1, SECP_521_R_1},
            rfc8410::ID_ED_25519,
        };
        use der::asn1::ObjectIdentifier;
        match spki.algorithm.oid {
            RSA_ENCRYPTION => {
                let pk_bytes = spki.subject_public_key.as_bytes().ok_or_else(|| {
                    CertKitError::DecodingError("Invalid RSA public key bitstring".to_string())
                })?;
                let public_key = RsaPublicKey::from_pkcs1_der(pk_bytes)?;
                Ok(PublicKey::Rsa(public_key))
            }
            ID_EC_PUBLIC_KEY => {
                let params = spki.algorithm.parameters.as_ref().ok_or_else(|| {
                    CertKitError::DecodingError("Missing EC parameters".to_string())
                })?;
                let params_oid: ObjectIdentifier = params.decode_as().map_err(|_| {
                    CertKitError::DecodingError("Invalid EC parameters OID".to_string())
                })?;
                let raw_bytes = spki.subject_public_key.as_bytes().ok_or_else(|| {
                    CertKitError::DecodingError("Invalid EC public key bitstring".to_string())
                })?;
                if params_oid == SECP_256_R_1 {
                    let verifying_key =
                        P256VerifyingKey::from_sec1_bytes(raw_bytes).map_err(|_| {
                            CertKitError::DecodingError(
                                "Invalid P-256 public key bytes".to_string(),
                            )
                        })?;
                    Ok(PublicKey::EcdsaP256(verifying_key))
                } else if params_oid == SECP_384_R_1 {
                    let verifying_key =
                        P384VerifyingKey::from_sec1_bytes(raw_bytes).map_err(|_| {
                            CertKitError::DecodingError(
                                "Invalid P-384 public key bytes".to_string(),
                            )
                        })?;
                    Ok(PublicKey::EcdsaP384(verifying_key))
                } else if params_oid == SECP_521_R_1 {
                    let verifying_key = ecdsa::VerifyingKey::<NistP521>::from_sec1_bytes(raw_bytes)
                        .map_err(|_| {
                            CertKitError::DecodingError(
                                "Invalid P-521 public key bytes".to_string(),
                            )
                        })?;
                    Ok(PublicKey::EcdsaP521(verifying_key))
                } else {
                    Err(CertKitError::DecodingError(format!(
                        "Unsupported EC curve OID: {}",
                        params_oid
                    )))
                }
            }
            ID_ED_25519 => {
                let bytes = spki.subject_public_key.as_bytes().ok_or_else(|| {
                    CertKitError::DecodingError("Invalid Ed25519 public key bitstring".to_string())
                })?;
                let bytes_array: &[u8; 32] = bytes.try_into().map_err(|_| {
                    CertKitError::DecodingError("Invalid Ed25519 public key length".to_string())
                })?;
                let verifying_key = Ed25519VerifyingKey::from_bytes(bytes_array).map_err(|_| {
                    CertKitError::DecodingError("Invalid Ed25519 public key bytes".to_string())
                })?;
                Ok(PublicKey::Ed25519(verifying_key))
            }
            _ => Err(CertKitError::DecodingError(format!(
                "Unsupported algorithm: {}",
                spki.algorithm.oid
            ))),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn pem_encode_decode_rsa() {
        let rsa = KeyPair::generate_rsa(2048).unwrap();
        let rsa_der = rsa::pkcs8::EncodePrivateKey::to_pkcs8_der(match &rsa {
            KeyPair::Rsa { private, .. } => &**private,
            _ => unreachable!(),
        })
        .unwrap();
        let rsa_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", rsa_der.as_bytes()));
        let rsa_decoded = KeyPair::import_from_pkcs8_pem(&rsa_pem);
        assert!(rsa_decoded.is_ok(), "RSA PEM decode should succeed");
    }

    #[test]
    fn pem_encode_decode_ecdsa_p256() {
        let p256 = KeyPair::generate_ecdsa_p256();
        let p256_der = p256::pkcs8::EncodePrivateKey::to_pkcs8_der(match &p256 {
            KeyPair::EcdsaP256 { signing_key, .. } => signing_key,
            _ => unreachable!(),
        })
        .unwrap();
        let p256_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", p256_der.as_bytes()));
        let p256_decoded = KeyPair::import_from_pkcs8_pem(&p256_pem);
        assert!(p256_decoded.is_ok(), "P-256 PEM decode should succeed");
    }

    #[test]
    fn pem_encode_decode_ecdsa_p384() {
        let p384 = KeyPair::generate_ecdsa_p384();
        let p384_der = p384::pkcs8::EncodePrivateKey::to_pkcs8_der(match &p384 {
            KeyPair::EcdsaP384 { signing_key, .. } => signing_key,
            _ => unreachable!(),
        })
        .unwrap();
        let p384_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", p384_der.as_bytes()));
        let p384_decoded = KeyPair::import_from_pkcs8_pem(&p384_pem);
        assert!(p384_decoded.is_ok(), "P-384 PEM decode should succeed");
    }

    #[test]
    fn pem_encode_decode_ecdsa_p521() {
        let p521 = KeyPair::generate_ecdsa_p521();
        let p521_der = p521::pkcs8::EncodePrivateKey::to_pkcs8_der(match &p521 {
            KeyPair::EcdsaP521 { signing_key, .. } => signing_key,
            _ => unreachable!(),
        })
        .unwrap();
        let p521_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", p521_der.as_bytes()));
        let p521_decoded = KeyPair::import_from_pkcs8_pem(&p521_pem);
        assert!(p521_decoded.is_ok(), "P-521 PEM decode should succeed");
    }

    #[test]
    fn pem_encode_decode_ed25519() {
        let ed = KeyPair::generate_ed25519();
        let ed_der = ed25519_dalek::pkcs8::EncodePrivateKey::to_pkcs8_der(match &ed {
            KeyPair::Ed25519 { signing_key } => signing_key,
            _ => unreachable!(),
        })
        .unwrap();
        let ed_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", ed_der.as_bytes()));
        let ed_decoded = KeyPair::import_from_pkcs8_pem(&ed_pem);
        assert!(ed_decoded.is_ok(), "Ed25519 PEM decode should succeed");
    }
}
