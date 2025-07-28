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
/// This enum represents different types of cryptographic key pairs supported by CertKit.
/// Each variant contains the necessary cryptographic primitives for signing and verification
/// operations.
///
/// # Supported Algorithms
///
/// - **RSA**: Variable key sizes (typically 2048, 3072, or 4096 bits)
/// - **ECDSA P-256**: NIST P-256 curve (secp256r1)
/// - **ECDSA P-384**: NIST P-384 curve (secp384r1)  
/// - **ECDSA P-521**: NIST P-521 curve (secp521r1)
/// - **Ed25519**: Edwards curve digital signature algorithm
///
/// # Examples
///
/// ```rust,no_run
/// use certkit::key::KeyPair;
///
/// # fn main() -> Result<(), certkit::error::CertKitError> {
/// // Generate different types of key pairs
/// let rsa_key = KeyPair::generate_rsa(2048)?;
/// let p256_key = KeyPair::generate_ecdsa_p256();
/// let p384_key = KeyPair::generate_ecdsa_p384();
/// let p521_key = KeyPair::generate_ecdsa_p521();
/// let ed25519_key = KeyPair::generate_ed25519();
///
/// // All key types can be used for signing
/// let data = b"Hello, world!";
/// let signature = rsa_key.sign_data(data)?;
/// println!("Signature length: {} bytes", signature.len());
/// # Ok(())
/// # }
/// ```
///
/// # Security Considerations
///
/// - RSA keys should be at least 2048 bits for security
/// - ECDSA keys provide equivalent security with smaller key sizes
/// - Ed25519 provides high security and performance
/// - Choose the appropriate algorithm based on your security requirements and compatibility needs
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
    /// Creates a new RSA key pair using cryptographically secure random number generation.
    /// The key size directly affects both security and performance characteristics.
    ///
    /// # Arguments
    /// * `bits` - The number of bits for the RSA key (recommended: 2048, 3072, or 4096)
    ///
    /// # Returns
    /// A `Result` containing the `KeyPair` on success, or a `CertKitError` on failure.
    ///
    /// # Errors
    /// Returns `CertKitError::KeyGenerationError` if key generation fails due to:
    /// - Invalid key size
    /// - Insufficient entropy
    /// - System resource constraints
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use certkit::key::KeyPair;
    ///
    /// # fn main() -> Result<(), certkit::error::CertKitError> {
    /// // Generate a 2048-bit RSA key (recommended minimum)
    /// let key_2048 = KeyPair::generate_rsa(2048)?;
    ///
    /// // Generate a 4096-bit RSA key (higher security)
    /// let key_4096 = KeyPair::generate_rsa(4096)?;
    ///
    /// // Get the public key in DER format
    /// let public_der = key_2048.get_public_key_der();
    /// println!("Public key size: {} bytes", public_der.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Security Notes
    /// - 2048-bit keys are considered secure for most applications
    /// - 3072-bit keys provide additional security margin
    /// - 4096-bit keys offer maximum security but with performance trade-offs
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
    /// Creates a new ECDSA key pair using the NIST P-256 curve (secp256r1).
    /// This curve provides approximately 128 bits of security and is widely supported.
    ///
    /// # Returns
    /// A `KeyPair` containing the ECDSA P-256 key pair.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use certkit::key::KeyPair;
    ///
    /// # fn main() -> Result<(), certkit::error::CertKitError> {
    /// // Generate a P-256 ECDSA key pair
    /// let key_pair = KeyPair::generate_ecdsa_p256();
    ///
    /// // Sign some data
    /// let data = b"Message to sign";
    /// let signature = key_pair.sign_data(data)?;
    /// println!("P-256 signature length: {} bytes", signature.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Security Notes
    /// - P-256 provides ~128 bits of security
    /// - Widely supported across different systems and libraries
    /// - Smaller key and signature sizes compared to RSA
    /// - Fast signature generation and verification
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
    /// Creates a new ECDSA key pair using the NIST P-384 curve (secp384r1).
    /// This curve provides approximately 192 bits of security, offering a higher
    /// security level than P-256.
    ///
    /// # Returns
    /// A `KeyPair` containing the ECDSA P-384 key pair.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use certkit::key::KeyPair;
    ///
    /// // Generate a P-384 ECDSA key pair
    /// let key_pair = KeyPair::generate_ecdsa_p384();
    ///
    /// // Convert to SPKI format for certificate use
    /// let spki = key_pair.as_spki();
    /// println!("Generated P-384 key pair");
    /// ```
    ///
    /// # Security Notes
    /// - P-384 provides ~192 bits of security
    /// - Higher security level than P-256
    /// - Suitable for high-security applications
    /// - Slightly larger signatures than P-256
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
    /// Creates a new ECDSA key pair using the NIST P-521 curve (secp521r1).
    /// This curve provides approximately 256 bits of security, the highest
    /// security level among the NIST curves.
    ///
    /// # Returns
    /// A `KeyPair` containing the ECDSA P-521 key pair.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use certkit::key::KeyPair;
    ///
    /// // Generate a P-521 ECDSA key pair
    /// let key_pair = KeyPair::generate_ecdsa_p521();
    ///
    /// // Get public key in DER format
    /// let public_der = key_pair.get_public_key_der();
    /// println!("P-521 public key size: {} bytes", public_der.len());
    /// ```
    ///
    /// # Security Notes
    /// - P-521 provides ~256 bits of security
    /// - Highest security level among NIST curves
    /// - Suitable for applications requiring maximum security
    /// - Larger key and signature sizes than P-256/P-384
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
    /// Creates a new Ed25519 key pair using the Edwards curve digital signature algorithm.
    /// Ed25519 provides high security, fast performance, and resistance to side-channel attacks.
    ///
    /// # Returns
    /// A `KeyPair` containing the Ed25519 key pair.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use certkit::key::KeyPair;
    ///
    /// # fn main() -> Result<(), certkit::error::CertKitError> {
    /// // Generate an Ed25519 key pair
    /// let key_pair = KeyPair::generate_ed25519();
    ///
    /// // Sign data (Ed25519 is very fast)
    /// let data = b"Fast signing with Ed25519";
    /// let signature = key_pair.sign_data(data)?;
    /// println!("Ed25519 signature length: {} bytes", signature.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Security Notes
    /// - Provides ~128 bits of security (equivalent to P-256)
    /// - Extremely fast signature generation and verification
    /// - Resistant to side-channel attacks
    /// - Fixed 32-byte public keys and 64-byte signatures
    /// - Deterministic signatures (no random nonce required)
    pub fn generate_ed25519() -> Self {
        let mut rng = rand_core::OsRng;
        let signing_key: Ed25519SigningKey = Ed25519SigningKey::generate(&mut rng);
        KeyPair::Ed25519 { signing_key }
    }

    /// Retrieves the public key in DER format.
    ///
    /// Extracts the public key component and encodes it in Distinguished Encoding Rules (DER) format.
    /// The encoding format varies by key type:
    /// - RSA: PKCS#1 RSAPublicKey format
    /// - ECDSA: SEC1 uncompressed point format
    /// - Ed25519: Raw 32-byte public key
    ///
    /// # Returns
    /// A byte vector containing the DER-encoded public key.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use certkit::key::KeyPair;
    ///
    /// # fn main() -> Result<(), certkit::error::CertKitError> {
    /// let rsa_key = KeyPair::generate_rsa(2048)?;
    /// let p256_key = KeyPair::generate_ecdsa_p256();
    /// let ed25519_key = KeyPair::generate_ed25519();
    ///
    /// // Get public keys in DER format
    /// let rsa_der = rsa_key.get_public_key_der();
    /// let p256_der = p256_key.get_public_key_der();
    /// let ed25519_der = ed25519_key.get_public_key_der();
    ///
    /// println!("RSA public key: {} bytes", rsa_der.len());
    /// println!("P-256 public key: {} bytes", p256_der.len());
    /// println!("Ed25519 public key: {} bytes", ed25519_der.len());
    /// # Ok(())
    /// # }
    /// ```
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
    /// Attempts to decode DER-encoded private key data and create a `KeyPair`.
    /// The function automatically detects the key type and format by trying
    /// different decoding methods in order.
    ///
    /// # Supported Formats
    /// - RSA: PKCS#1 and PKCS#8 formats
    /// - ECDSA (P-256, P-384, P-521): PKCS#8 format
    /// - Ed25519: PKCS#8 format
    ///
    /// # Arguments
    /// * `der` - A byte slice containing the DER-encoded private key data
    ///
    /// # Returns
    /// A `Result` containing the `KeyPair` on success, or a `CertKitError` on failure.
    ///
    /// # Errors
    /// Returns `CertKitError::DecodingError` if:
    /// - The DER data is malformed
    /// - The key type is unsupported
    /// - The key format is not recognized
    ///
    /// # Examples
    ///
    /// ```rust
    /// use certkit::key::KeyPair;
    ///
    /// // Generate a key and export to DER
    /// let original_key = KeyPair::generate_ecdsa_p256();
    /// // Note: In practice, you'd get DER data from external sources
    ///
    /// // Import from DER data (example with hypothetical DER bytes)
    /// let der_data = &[/* DER-encoded key bytes */];
    /// match KeyPair::import_from_der(der_data) {
    ///     Ok(imported_key) => println!("Key imported successfully"),
    ///     Err(e) => println!("Import failed: {}", e),
    /// }
    /// ```
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
    /// Parses PEM-encoded private key data and creates a `KeyPair`. The function
    /// expects PKCS#8 format private keys with the "PRIVATE KEY" label.
    ///
    /// # Arguments
    /// * `pem_str` - A string slice containing the PEM-encoded private key data
    ///
    /// # Returns
    /// A `Result` containing the `KeyPair` on success, or a `CertKitError` on failure.
    ///
    /// # Errors
    /// Returns `CertKitError::DecodingError` if:
    /// - The PEM format is invalid
    /// - The PEM label is not "PRIVATE KEY"
    /// - The underlying DER data cannot be decoded
    ///
    /// # Examples
    ///
    /// ```rust
    /// use certkit::key::KeyPair;
    ///
    /// let pem_data = r#"-----BEGIN PRIVATE KEY-----
    /// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...
    /// -----END PRIVATE KEY-----"#;
    ///
    /// match KeyPair::import_from_pkcs8_pem(pem_data) {
    ///     Ok(key_pair) => {
    ///         println!("Successfully imported key from PEM");
    ///         let signature = key_pair.sign_data(b"test data")?;
    ///         println!("Signature created: {} bytes", signature.len());
    ///     }
    ///     Err(e) => println!("Failed to import key: {}", e),
    /// }
    /// # Ok::<(), certkit::error::CertKitError>(())
    /// ```
    ///
    /// # Format Requirements
    /// The PEM data must:
    /// - Use the "PRIVATE KEY" label (PKCS#8 format)
    /// - Contain valid base64-encoded DER data
    /// - Represent a supported key type (RSA, ECDSA P-256/P-384/P-521, Ed25519)
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
    /// Creates a SubjectPublicKeyInfo (SPKI) structure containing the public key
    /// and its algorithm identifier. This format is used in X.509 certificates
    /// and certificate signing requests.
    ///
    /// # Returns
    /// An `x509_cert::spki::SubjectPublicKeyInfoOwned` object containing:
    /// - Algorithm identifier with appropriate OID
    /// - Public key data in the correct format
    /// - Algorithm parameters (if required)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use certkit::key::KeyPair;
    ///
    /// let key_pair = KeyPair::generate_ecdsa_p256();
    /// let spki = key_pair.as_spki();
    ///
    /// println!("Algorithm OID: {}", spki.algorithm.oid);
    /// println!("Public key bits: {} bytes", spki.subject_public_key.raw_bytes().len());
    /// ```
    ///
    /// # Algorithm Identifiers
    /// - RSA: rsaEncryption (1.2.840.113549.1.1.1)
    /// - ECDSA P-256: id-ecPublicKey with secp256r1 parameters
    /// - ECDSA P-384: id-ecPublicKey with secp384r1 parameters  
    /// - ECDSA P-521: id-ecPublicKey with secp521r1 parameters
    /// - Ed25519: id-Ed25519 (1.3.101.112)
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

    /// Signs the provided data using the private key.
    ///
    /// Creates a digital signature over the provided data using the appropriate
    /// signature algorithm for the key type. The signature can be verified using
    /// the corresponding public key.
    ///
    /// # Signature Algorithms Used
    /// - RSA: RSASSA-PKCS1-v1_5 with SHA-256
    /// - ECDSA (all curves): ECDSA with SHA-256
    /// - Ed25519: Pure Ed25519 (no hash function needed)
    ///
    /// # Arguments
    /// * `data` - A byte slice containing the data to sign
    ///
    /// # Returns
    /// A `Result` containing the signature bytes on success, or a `CertKitError` on failure.
    ///
    /// # Errors
    /// Returns `CertKitError` if:
    /// - The signing operation fails
    /// - The key is invalid or corrupted
    /// - System resources are insufficient
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use certkit::key::KeyPair;
    ///
    /// # fn main() -> Result<(), certkit::error::CertKitError> {
    /// // Sign data with different key types
    /// let rsa_key = KeyPair::generate_rsa(2048)?;
    /// let ecdsa_key = KeyPair::generate_ecdsa_p256();
    /// let ed25519_key = KeyPair::generate_ed25519();
    ///
    /// let message = b"Important message to sign";
    ///
    /// let rsa_sig = rsa_key.sign_data(message)?;
    /// let ecdsa_sig = ecdsa_key.sign_data(message)?;
    /// let ed25519_sig = ed25519_key.sign_data(message)?;
    ///
    /// println!("RSA signature: {} bytes", rsa_sig.len());
    /// println!("ECDSA signature: {} bytes", ecdsa_sig.len());
    /// println!("Ed25519 signature: {} bytes", ed25519_sig.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Security Notes
    /// - RSA signatures are deterministic with PKCS#1 v1.5 padding
    /// - ECDSA signatures include randomness and vary between calls
    /// - Ed25519 signatures are deterministic and consistent
    /// - All algorithms provide strong security when used properly
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

/// Represents a public key for cryptographic operations.
///
/// This enum encapsulates public keys from various cryptographic algorithms
/// supported by CertKit. Public keys are used for signature verification,
/// encryption (in the case of RSA), and inclusion in X.509 certificates.
///
/// # Supported Key Types
/// - **RSA**: Variable key sizes, commonly 2048-4096 bits
/// - **ECDSA P-256**: NIST P-256 curve public keys
/// - **ECDSA P-384**: NIST P-384 curve public keys
/// - **ECDSA P-521**: NIST P-521 curve public keys
/// - **Ed25519**: Edwards curve public keys (32 bytes)
///
/// # Examples
///
/// ```rust,no_run
/// use certkit::key::{KeyPair, PublicKey};
///
/// # fn main() -> Result<(), certkit::error::CertKitError> {
/// // Extract public key from a key pair
/// let key_pair = KeyPair::generate_ecdsa_p256();
/// let public_key = PublicKey::from_key_pair(&key_pair);
///
/// // Convert to DER format for storage or transmission
/// let der_bytes = public_key.to_der()?;
/// println!("Public key DER size: {} bytes", der_bytes.len());
///
/// // Note: from_der currently only supports RSA keys
/// // let restored_key = PublicKey::from_der(&der_bytes)?;
/// # Ok(())
/// # }
/// ```
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
    /// Encodes the public key in Distinguished Encoding Rules (DER) format.
    /// The specific encoding depends on the key type:
    /// - RSA: PKCS#1 RSAPublicKey format
    /// - ECDSA: SEC1 uncompressed point format
    /// - Ed25519: Raw 32-byte public key
    ///
    /// # Returns
    /// A `Result` containing the DER-encoded public key bytes, or a `CertKitError` on failure.
    ///
    /// # Errors
    /// Returns `CertKitError::EncodingError` if the key cannot be encoded to DER format.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use certkit::key::{KeyPair, PublicKey};
    ///
    /// # fn main() -> Result<(), certkit::error::CertKitError> {
    /// let key_pair = KeyPair::generate_rsa(2048)?;
    /// let public_key = PublicKey::from_key_pair(&key_pair);
    ///
    /// let der_bytes = public_key.to_der()?;
    /// println!("RSA public key DER: {} bytes", der_bytes.len());
    /// # Ok(())
    /// # }
    /// ```
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
    /// Attempts to decode DER-encoded public key data. Currently supports
    /// RSA public keys in PKCS#1 format. Support for other key types may
    /// be added in future versions.
    ///
    /// # Arguments
    /// * `der` - A byte slice containing the DER-encoded public key data
    ///
    /// # Returns
    /// A `Result` containing the `PublicKey` on success, or a `CertKitError` on failure.
    ///
    /// # Errors
    /// Returns `CertKitError::DecodingError` if:
    /// - The DER data is malformed
    /// - The key type is not supported
    /// - The key format is not recognized
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use certkit::key::{KeyPair, PublicKey};
    ///
    /// # fn main() -> Result<(), certkit::error::CertKitError> {
    /// // Generate a key pair and extract public key DER
    /// let key_pair = KeyPair::generate_rsa(2048)?;
    /// let public_key = PublicKey::from_key_pair(&key_pair);
    /// let der_bytes = public_key.to_der()?;
    ///
    /// // Recreate public key from DER
    /// let restored_key = PublicKey::from_der(&der_bytes)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Limitations
    /// Currently only supports RSA public keys. ECDSA and Ed25519 support
    /// will be added in future versions.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let public = RsaPublicKey::from_pkcs1_der(der)?;
        Ok(PublicKey::Rsa(public))
    }

    /// Creates a public key from a key pair.
    ///
    /// Extracts the public key component from a `KeyPair` and creates a
    /// corresponding `PublicKey` instance. This is useful when you need
    /// to work with just the public key portion.
    ///
    /// # Arguments
    /// * `key_pair` - A reference to a `KeyPair` object
    ///
    /// # Returns
    /// A `PublicKey` containing the public key component.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use certkit::key::{KeyPair, PublicKey};
    ///
    /// # fn main() -> Result<(), certkit::error::CertKitError> {
    /// // Generate different types of key pairs
    /// let rsa_pair = KeyPair::generate_rsa(2048)?;
    /// let ecdsa_pair = KeyPair::generate_ecdsa_p256();
    /// let ed25519_pair = KeyPair::generate_ed25519();
    ///
    /// // Extract public keys
    /// let rsa_public = PublicKey::from_key_pair(&rsa_pair);
    /// let ecdsa_public = PublicKey::from_key_pair(&ecdsa_pair);
    /// let ed25519_public = PublicKey::from_key_pair(&ed25519_pair);
    ///
    /// println!("Extracted public keys from all key pair types");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Use Cases
    /// - Creating certificates (public key goes into the certificate)
    /// - Sharing public keys for verification
    /// - Storing public keys separately from private keys
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
    /// Parses a SubjectPublicKeyInfo (SPKI) structure and extracts the public key.
    /// This is commonly used when parsing X.509 certificates or certificate
    /// signing requests.
    ///
    /// # Supported Algorithms
    /// - RSA (rsaEncryption OID)
    /// - ECDSA P-256 (id-ecPublicKey with secp256r1 parameters)
    /// - ECDSA P-384 (id-ecPublicKey with secp384r1 parameters)
    /// - ECDSA P-521 (id-ecPublicKey with secp521r1 parameters)
    /// - Ed25519 (id-Ed25519 OID)
    ///
    /// # Arguments
    /// * `spki` - A reference to an `x509_cert::spki::SubjectPublicKeyInfoOwned` object
    ///
    /// # Returns
    /// A `Result` containing the `PublicKey` on success, or a `CertKitError` on failure.
    ///
    /// # Errors
    /// Returns `CertKitError::DecodingError` if:
    /// - The algorithm OID is not supported
    /// - The public key data is malformed
    /// - Required algorithm parameters are missing
    /// - The key format is invalid for the specified algorithm
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use certkit::key::{KeyPair, PublicKey};
    ///
    /// # fn main() -> Result<(), certkit::error::CertKitError> {
    /// // Generate a key pair and convert to SPKI
    /// let key_pair = KeyPair::generate_ecdsa_p384();
    /// let spki = key_pair.as_spki();
    ///
    /// // Recreate public key from SPKI
    /// let public_key = PublicKey::from_x509spki(&spki)?;
    /// println!("Successfully parsed public key from SPKI");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Use Cases
    /// - Parsing public keys from X.509 certificates
    /// - Processing certificate signing requests
    /// - Validating certificate chains
    /// - Interoperability with other X.509 implementations
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
                        "Unsupported EC curve OID: {params_oid}"
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
