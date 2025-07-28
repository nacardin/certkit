pub mod extensions;
pub mod params;

use crate::error::CertKitError;
pub type Result<T> = std::result::Result<T, CertKitError>;
use der::{Encode, EncodePem};
use extensions::ToAndFromX509Extension;
use params::{CertificationRequestInfo, ExtensionParam};
use time::OffsetDateTime;
use x509_cert::certificate::CertificateInner;

use crate::issuer::Issuer;
use crate::key::KeyPair;

// use crate::{key::KeyPair, pki::sign_data};

// #[derive(Debug, Clone, Builder)]
// pub struct TbsCertificate {
//     pub serial_number: Vec<u8>,
//     pub issuer_dn: DistinguishedName,
//     pub validity: Validity,
//     pub subject_dn: DistinguishedName,
//     pub subject_public_key: PublicKey,
//     pub extensions: Vec<ExtensionParam>,
// }

/// Represents the supported signature algorithms for certificates.
///
/// This enum defines the cryptographic signature algorithms that can be used
/// for signing X.509 certificates. Each algorithm combines a hash function
/// with a signature scheme and maps to a specific Object Identifier (OID)
/// as defined in various RFCs.
///
/// # Algorithm Selection
///
/// The signature algorithm is typically chosen based on:
/// - **Key Type**: RSA keys use RSA algorithms, ECDSA keys use ECDSA algorithms
/// - **Security Requirements**: Different hash functions provide different security levels
/// - **Compatibility**: Some systems may not support all algorithms
/// - **Performance**: Different algorithms have varying computational costs
///
/// # Examples
///
/// ```rust
/// use certkit::cert::SignatureAlgorithm;
/// use certkit::key::KeyPair;
///
/// // Algorithm selection is typically automatic based on key type
/// let rsa_key = KeyPair::generate_rsa(2048)?;
/// // Would use SignatureAlgorithm::Sha256WithRSA
///
/// let ecdsa_key = KeyPair::generate_ecdsa_p256();
/// // Would use SignatureAlgorithm::Sha256WithECDSA
///
/// let ed25519_key = KeyPair::generate_ed25519();
/// // Would use SignatureAlgorithm::Sha256WithEdDSA
/// # Ok::<(), certkit::error::CertKitError>(())
/// ```
///
/// # Security Considerations
///
/// - **SHA-256**: Minimum recommended hash function for new certificates
/// - **SHA-384/SHA-512**: Higher security for sensitive applications
/// - **Algorithm Deprecation**: SHA-1 is deprecated and not supported
/// - **Key Size Matching**: Hash function strength should match key strength
#[derive(Debug, Clone)]
pub enum SignatureAlgorithm {
    /// SHA-256 with RSA encryption.
    ///
    /// Uses RSASSA-PKCS1-v1_5 signature scheme with SHA-256 hash function.
    /// This is the most commonly used signature algorithm for RSA keys.
    ///
    /// - **OID**: 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
    /// - **Security**: ~128 bits (with 2048-bit RSA key)
    /// - **Compatibility**: Widely supported
    Sha256WithRSA,
    /// SHA-256 with ECDSA.
    ///
    /// Uses ECDSA signature scheme with SHA-256 hash function.
    /// Suitable for P-256 curves and provides good security with smaller signatures.
    ///
    /// - **OID**: 1.2.840.10045.4.3.2 (ecdsa-with-SHA256)
    /// - **Security**: ~128 bits (with P-256 curve)
    /// - **Compatibility**: Widely supported in modern systems
    Sha256WithECDSA,
    /// SHA-384 with ECDSA.
    ///
    /// Uses ECDSA signature scheme with SHA-384 hash function.
    /// Recommended for P-384 curves to match security levels.
    ///
    /// - **OID**: 1.2.840.10045.4.3.3 (ecdsa-with-SHA384)
    /// - **Security**: ~192 bits (with P-384 curve)
    /// - **Compatibility**: Supported in modern systems
    Sha384WithECDSA,
    /// SHA-512 with ECDSA.
    ///
    /// Uses ECDSA signature scheme with SHA-512 hash function.
    /// Recommended for P-521 curves to match security levels.
    ///
    /// - **OID**: 1.2.840.10045.4.3.4 (ecdsa-with-SHA512)
    /// - **Security**: ~256 bits (with P-521 curve)
    /// - **Compatibility**: Supported in modern systems
    Sha512WithECDSA,
    /// SHA-256 with EdDSA (Ed25519).
    ///
    /// Uses Ed25519 signature scheme. Note that Ed25519 doesn't actually
    /// use SHA-256 internally (it uses SHA-512 and other functions), but
    /// this enum variant represents the Ed25519 algorithm identifier.
    ///
    /// - **OID**: 1.3.101.112 (id-Ed25519)
    /// - **Security**: ~128 bits
    /// - **Compatibility**: Supported in newer systems (RFC 8410)
    Sha256WithEdDSA,
}

impl From<SignatureAlgorithm> for x509_cert::spki::AlgorithmIdentifierOwned {
    /// Converts a `SignatureAlgorithm` into an `AlgorithmIdentifierOwned`.
    ///
    /// # Returns
    /// An `AlgorithmIdentifierOwned` object containing the OID and parameters for the algorithm.
    fn from(value: SignatureAlgorithm) -> Self {
        match value {
            SignatureAlgorithm::Sha256WithRSA => x509_cert::spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
                parameters: None,
            },
            SignatureAlgorithm::Sha256WithECDSA => x509_cert::spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
                parameters: None,
            },
            SignatureAlgorithm::Sha384WithECDSA => x509_cert::spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_384,
                parameters: None,
            },
            SignatureAlgorithm::Sha512WithECDSA => x509_cert::spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_512,
                parameters: None,
            },
            SignatureAlgorithm::Sha256WithEdDSA => x509_cert::spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc8410::ID_ED_25519,
                parameters: None,
            },
        }
    }
}

/// Represents an X.509 certificate.
///
/// This struct encapsulates a complete X.509 certificate and provides methods
/// for encoding, decoding, and extracting certificate information. Certificates
/// can be created as self-signed root certificates or issued by certificate
/// authorities.
///
/// # Certificate Components
/// - **Subject**: The entity the certificate identifies
/// - **Issuer**: The entity that signed the certificate
/// - **Public Key**: The subject's public key
/// - **Validity Period**: When the certificate is valid (not before/not after)
/// - **Extensions**: Additional certificate attributes and constraints
/// - **Signature**: Digital signature from the issuer
///
/// # Examples
///
/// ## Creating a Self-Signed Certificate
///
/// ```rust
/// use certkit::{
///     key::KeyPair,
///     cert::{Certificate, params::{CertificationRequestInfo, DistinguishedName}},
/// };
///
/// // Generate a key pair
/// let key_pair = KeyPair::generate_ecdsa_p256();
///
/// // Define the certificate subject
/// let subject = DistinguishedName::builder()
///     .common_name("example.com".to_string())
///     .organization("Example Corp".to_string())
///     .country("US".to_string())
///     .build();
///
/// // Create certificate request info
/// let cert_info = CertificationRequestInfo::builder()
///     .subject(subject)
///     .subject_public_key(certkit::key::PublicKey::from_key_pair(&key_pair))
///     .build();
///
/// // Generate the self-signed certificate
/// let certificate = Certificate::new_self_signed(&cert_info, &key_pair);
///
/// // Export to different formats
/// let der_bytes = certificate.to_der()?;
/// let pem_string = certificate.to_pem()?;
///
/// println!("Certificate created: {} bytes DER, {} bytes PEM",
///          der_bytes.len(), pem_string.len());
/// # Ok::<(), certkit::error::CertKitError>(())
/// ```
///
/// ## Extracting Certificate Information
///
/// ```rust
/// use certkit::cert::Certificate;
/// # use certkit::{key::KeyPair, cert::params::{CertificationRequestInfo, DistinguishedName}};
/// # let key_pair = KeyPair::generate_ecdsa_p256();
/// # let subject = DistinguishedName::builder().common_name("test".to_string()).build();
/// # let cert_info = CertificationRequestInfo::builder()
/// #     .subject(subject).subject_public_key(certkit::key::PublicKey::from_key_pair(&key_pair)).build();
/// # let certificate = Certificate::new_self_signed(&cert_info, &key_pair);
///
/// // Extract certificate information
/// let cert_info = certificate.to_cert_info()?;
/// println!("Subject: {}", cert_info.subject.common_name);
/// println!("Is CA: {}", cert_info.is_ca);
/// println!("Extensions: {}", cert_info.extensions.len());
/// # Ok::<(), certkit::error::CertKitError>(())
/// ```
#[derive(Debug, Clone)]
pub struct Certificate {
    /// The inner representation of the certificate.
    pub inner: CertificateInner,
}

impl Certificate {
    /// Encodes the certificate into DER format.
    ///
    /// Converts the certificate to Distinguished Encoding Rules (DER) format,
    /// which is a binary encoding commonly used for certificate storage and
    /// transmission in protocols like TLS.
    ///
    /// # Returns
    /// A `Result` containing the DER-encoded certificate bytes, or a `CertKitError` on failure.
    ///
    /// # Errors
    /// Returns `CertKitError::EncodingError` if the certificate cannot be encoded,
    /// typically due to malformed internal structures.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use certkit::{key::KeyPair, cert::{Certificate, params::{CertificationRequestInfo, DistinguishedName}}};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let key_pair = KeyPair::generate_rsa(2048)?;
    /// let subject = DistinguishedName::builder().common_name("test.com".to_string()).build();
    /// let cert_info = CertificationRequestInfo::builder()
    ///     .subject(subject)
    ///     .subject_public_key(certkit::key::PublicKey::from_key_pair(&key_pair))
    ///     .build();
    ///
    /// let certificate = Certificate::new_self_signed(&cert_info, &key_pair);
    /// let der_bytes = certificate.to_der()?;
    ///
    /// // Save to file or transmit over network
    /// std::fs::write("certificate.der", &der_bytes)?;
    /// println!("Certificate saved as DER: {} bytes", der_bytes.len());
    /// # Ok(())
    /// # }
    /// ```
    /// ```
    pub fn to_der(&self) -> Result<Vec<u8>> {
        self.inner
            .to_der()
            .map_err(|e| CertKitError::EncodingError(e.to_string()))
    }

    /// Encodes the certificate into PEM format.
    ///
    /// Converts the certificate to Privacy-Enhanced Mail (PEM) format, which
    /// is a base64-encoded text format commonly used for certificate storage
    /// in configuration files and human-readable contexts.
    ///
    /// # Returns
    /// A `Result` containing the PEM-encoded certificate string, or a `CertKitError` on failure.
    ///
    /// # Errors
    /// Returns `CertKitError::EncodingError` if the certificate cannot be encoded.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use certkit::{key::KeyPair, cert::{Certificate, params::{CertificationRequestInfo, DistinguishedName}}};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let key_pair = KeyPair::generate_ed25519();
    /// let subject = DistinguishedName::builder().common_name("server.example.com".to_string()).build();
    /// let cert_info = CertificationRequestInfo::builder()
    ///     .subject(subject)
    ///     .subject_public_key(certkit::key::PublicKey::from_key_pair(&key_pair))
    ///     .build();
    ///
    /// let certificate = Certificate::new_self_signed(&cert_info, &key_pair);
    /// let pem_string = certificate.to_pem()?;
    ///
    /// println!("Certificate in PEM format:\n{}", pem_string);
    ///
    /// // Save to configuration file
    /// std::fs::write("server.crt", &pem_string)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// The PEM format includes:
    ///
    /// - "-----BEGIN CERTIFICATE-----" header
    /// - Base64-encoded DER data (64 characters per line)
    /// - "-----END CERTIFICATE-----" footer
    pub fn to_pem(&self) -> Result<String> {
        self.inner
            .to_pem(pkcs8::LineEnding::LF)
            .map_err(|e| CertKitError::EncodingError(e.to_string()))
    }

    /// Extracts certificate information into a `CertificationRequestInfo` object.
    ///
    /// Parses the certificate and extracts key information including the subject,
    /// public key, extensions, and CA status. This is useful for certificate
    /// analysis, validation, and creating derived certificates.
    ///
    /// # Returns
    /// A `Result` containing the `CertificationRequestInfo` with extracted details,
    /// or a `CertKitError` on failure.
    ///
    /// # Errors
    /// Returns `CertKitError::DecodingError` if:
    /// - The certificate structure is malformed
    /// - Required fields are missing
    /// - Extensions cannot be parsed
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use certkit::{key::KeyPair, cert::{Certificate, params::{CertificationRequestInfo, DistinguishedName}}};
    ///
    /// # fn main() -> Result<(), certkit::error::CertKitError> {
    /// // Create a certificate
    /// let key_pair = KeyPair::generate_ecdsa_p384();
    /// let subject = DistinguishedName::builder()
    ///     .common_name("CA Certificate".to_string())
    ///     .organization("Example CA".to_string())
    ///     .build();
    ///
    /// let cert_info = CertificationRequestInfo::builder()
    ///     .subject(subject)
    ///     .subject_public_key(certkit::key::PublicKey::from_key_pair(&key_pair))
    ///     .is_ca(true)
    ///     .build();
    ///
    /// let certificate = Certificate::new_self_signed(&cert_info, &key_pair);
    ///
    /// // Extract information back from the certificate
    /// let extracted_info = certificate.to_cert_info()?;
    /// println!("Subject CN: {}", extracted_info.subject.common_name);
    /// println!("Is CA: {}", extracted_info.is_ca);
    /// println!("Number of extensions: {}", extracted_info.extensions.len());
    /// println!("Key usages: {:?}", extracted_info.usages);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// The extracted information includes:
    ///
    /// - **Subject**: Distinguished name of the certificate holder
    /// - **Public Key**: The public key of the subject
    /// - **CA Status**: Whether this is a CA certificate
    /// - **Key Usages**: Extended key usage extensions
    /// - **Extensions**: All X.509 extensions present in the certificate
    pub fn to_cert_info(&self) -> Result<CertificationRequestInfo> {
        let inner_tbs_cert = self.inner.tbs_certificate.clone();

        let subject = params::DistinguishedName::from_x509_name(&inner_tbs_cert.subject);

        let subject_public_key =
            crate::key::PublicKey::from_x509spki(&inner_tbs_cert.subject_public_key_info)?;

        let extensions: Vec<ExtensionParam> = inner_tbs_cert
            .extensions
            .unwrap()
            .iter()
            .map(|ext| ExtensionParam {
                oid: ext.extn_id,
                critical: ext.critical,
                value: ext.extn_value.as_bytes().to_vec(),
            })
            .collect();

        let usages = extensions
            .iter()
            .filter_map(|ext| {
                if ext.oid == crate::cert::extensions::ExtendedKeyUsage::OID {
                    let eku: crate::cert::extensions::ExtendedKeyUsage =
                        ext.to_extension().unwrap_or_default();
                    Some(eku.usage)
                } else {
                    None
                }
            })
            .next()
            .unwrap_or_default();

        let is_ca = extensions
            .iter()
            .filter_map(|ext| {
                if ext.oid == crate::cert::extensions::BasicConstraints::OID {
                    let basic_constraints: crate::cert::extensions::BasicConstraints =
                        ext.to_extension().unwrap_or_default();
                    Some(basic_constraints.is_ca)
                } else {
                    None
                }
            })
            .next()
            .unwrap_or(false);

        Ok(CertificationRequestInfo {
            subject: subject.clone(),
            subject_public_key,
            usages,
            is_ca,
            extensions,
        })
    }

    /// Creates a new self-signed certificate.
    ///
    /// Generates a self-signed X.509 certificate where the issuer and subject
    /// are the same entity. This is commonly used for root CA certificates
    /// or for testing purposes.
    ///
    /// # Certificate Properties
    /// - **Validity**: 365 days from creation time
    /// - **Serial Number**: Fixed value of 1
    /// - **Version**: X.509 v3
    /// - **Signature Algorithm**: Automatically selected based on key type
    ///
    /// # Arguments
    /// * `cert_info` - The certification request information containing subject details,
    ///   public key, extensions, and other certificate parameters
    /// * `key` - The key pair used to sign the certificate (private key for signing,
    ///   public key typically matches the one in cert_info)
    ///
    /// # Returns
    /// A `Certificate` object representing the self-signed certificate.
    ///
    /// # Examples
    ///
    /// ## Basic Self-Signed Certificate
    ///
    /// ```rust,no_run
    /// use certkit::{
    ///     key::KeyPair,
    ///     cert::{Certificate, params::{CertificationRequestInfo, DistinguishedName}},
    /// };
    ///
    /// # fn main() -> Result<(), certkit::error::CertKitError> {
    /// let key_pair = KeyPair::generate_rsa(2048)?;
    ///
    /// let subject = DistinguishedName::builder()
    ///     .common_name("My Root CA".to_string())
    ///     .organization("My Organization".to_string())
    ///     .country("US".to_string())
    ///     .build();
    ///
    /// let cert_info = CertificationRequestInfo::builder()
    ///     .subject(subject)
    ///     .subject_public_key(certkit::key::PublicKey::from_key_pair(&key_pair))
    ///     .is_ca(true)  // Mark as CA certificate
    ///     .build();
    ///
    /// let root_cert = Certificate::new_self_signed(&cert_info, &key_pair);
    /// println!("Root CA certificate created");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Self-Signed Certificate with Extensions
    ///
    /// ```rust,no_run
    /// use certkit::{
    ///     key::KeyPair,
    ///     cert::{
    ///         Certificate,
    ///         params::{CertificationRequestInfo, DistinguishedName, ExtensionParam},
    ///         extensions::{SubjectAltName, ToAndFromX509Extension},
    ///     },
    /// };
    ///
    /// # fn main() -> Result<(), certkit::error::CertKitError> {
    /// let key_pair = KeyPair::generate_ecdsa_p256();
    ///
    /// // Create Subject Alternative Name extension
    /// let san = SubjectAltName {
    ///     names: vec!["localhost".to_string(), "127.0.0.1".to_string()],
    /// };
    ///
    /// let subject = DistinguishedName::builder()
    ///     .common_name("localhost".to_string())
    ///     .build();
    ///
    /// let cert_info = CertificationRequestInfo::builder()
    ///     .subject(subject)
    ///     .subject_public_key(certkit::key::PublicKey::from_key_pair(&key_pair))
    ///     .extensions(vec![ExtensionParam::from_extension(san, false)])
    ///     .build();
    ///
    /// let cert = Certificate::new_self_signed(&cert_info, &key_pair);
    /// println!("Self-signed certificate with SAN created");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Use Cases
    /// - **Root CA certificates**: Top-level certificates in a PKI hierarchy
    /// - **Development/testing**: Quick certificate generation for testing
    /// - **Internal services**: Certificates for internal-only applications
    /// - **Bootstrap certificates**: Initial certificates for certificate enrollment
    pub fn new_self_signed(cert_info: &CertificationRequestInfo, key: &KeyPair) -> Self {
        let subject_dn = cert_info.subject.clone();

        // For self-signed certificates, the issuer is the same as the subject
        let self_issuer = SelfIssuer {
            name: subject_dn,
            key,
        };

        let validity = params::Validity {
            not_before: OffsetDateTime::now_utc(),
            not_after: OffsetDateTime::now_utc() + time::Duration::days(365),
        };
        self_issuer.issue(cert_info, validity)
    }
}

// Helper struct for self-signed certificates
struct SelfIssuer<'a> {
    name: params::DistinguishedName,
    key: &'a KeyPair,
}

impl Issuer for SelfIssuer<'_> {
    fn issuer_name(&self) -> params::DistinguishedName {
        self.name.clone()
    }

    fn signing_key(&self) -> &KeyPair {
        self.key
    }

    fn serial_number(&self) -> Vec<u8> {
        vec![1]
    }
}

/// A certificate paired with its corresponding private key.
///
/// This struct combines an X.509 certificate with the private key that corresponds
/// to the public key in the certificate. This pairing is essential for certificate
/// authorities that need to issue new certificates, as they require both the CA
/// certificate (for the issuer name and extensions) and the private key (for signing).
///
/// # Use Cases
///
/// - **Certificate Authorities**: CA certificates with their signing keys
/// - **Intermediate CAs**: Intermediate certificates that can issue end-entity certificates
/// - **Server Certificates**: Web server certificates with their private keys
/// - **Client Certificates**: Client authentication certificates with private keys
///
/// # Examples
///
/// ## Creating a CA Certificate with Private Key
///
/// ```rust
/// use certkit::{
///     key::KeyPair,
///     cert::{Certificate, CertificateWithPrivateKey, params::{CertificationRequestInfo, DistinguishedName}},
/// };
///
/// // Generate CA key pair
/// let ca_key = KeyPair::generate_ecdsa_p256();
///
/// // Create CA certificate
/// let ca_subject = DistinguishedName::builder()
///     .common_name("Example Root CA".to_string())
///     .organization("Example Corp".to_string())
///     .build();
///
/// let ca_cert_info = CertificationRequestInfo::builder()
///     .subject(ca_subject)
///     .subject_public_key(certkit::key::PublicKey::from_key_pair(&ca_key))
///     .is_ca(true)
///     .build();
///
/// let ca_cert = Certificate::new_self_signed(&ca_cert_info, &ca_key);
///
/// // Combine certificate and private key
/// let ca_with_key = CertificateWithPrivateKey {
///     cert: ca_cert,
///     key: ca_key,
/// };
///
/// println!("CA certificate with private key created");
/// # Ok::<(), certkit::error::CertKitError>(())
/// ```
///
/// ## Using CA to Issue End-Entity Certificates
///
/// ```rust
/// use certkit::{
///     key::KeyPair,
///     cert::{Certificate, CertificateWithPrivateKey, params::{CertificationRequestInfo, DistinguishedName, Validity}},
///     issuer::Issuer,
/// };
///
/// # let ca_key = KeyPair::generate_ecdsa_p256();
/// # let ca_subject = DistinguishedName::builder().common_name("CA".to_string()).build();
/// # let ca_cert_info = CertificationRequestInfo::builder()
///     .subject(ca_subject).subject_public_key(certkit::key::PublicKey::from_key_pair(&ca_key)).is_ca(true).build();
/// # let ca_cert = Certificate::new_self_signed(&ca_cert_info, &ca_key);
/// # let ca_with_key = CertificateWithPrivateKey { cert: ca_cert, key: ca_key };
///
/// // Generate end-entity key pair
/// let server_key = KeyPair::generate_rsa(2048)?;
///
/// // Create server certificate request
/// let server_subject = DistinguishedName::builder()
///     .common_name("server.example.com".to_string())
///     .build();
///
/// let server_cert_info = CertificationRequestInfo::builder()
///     .subject(server_subject)
///     .subject_public_key(certkit::key::PublicKey::from_key_pair(&server_key))
///     .build();
///
/// // Issue the server certificate using the CA
/// let validity = Validity::for_days(365);
/// let server_cert = ca_with_key.issue(&server_cert_info, validity);
///
/// println!("Server certificate issued by CA");
/// # Ok::<(), certkit::error::CertKitError>(())
/// ```
///
/// # Security Considerations
///
/// - **Private Key Protection**: The private key should be stored securely
/// - **Key Rotation**: Consider regular key rotation for long-lived CAs
/// - **Access Control**: Limit access to certificate/key pairs
/// - **Backup and Recovery**: Ensure secure backup of CA key material
#[derive(Debug, Clone)]
pub struct CertificateWithPrivateKey {
    /// The X.509 certificate
    pub cert: Certificate,
    /// The private key corresponding to the public key in the certificate
    pub key: crate::key::KeyPair,
}

impl Issuer for CertificateWithPrivateKey {
    fn issuer_name(&self) -> params::DistinguishedName {
        // The name of the issuer is the subject of the certificate
        let cert_info = self
            .cert
            .to_cert_info()
            .expect("Failed to extract cert info");
        cert_info.subject
    }

    fn signing_key(&self) -> &KeyPair {
        &self.key
    }

    fn serial_number(&self) -> Vec<u8> {
        self.cert
            .inner
            .tbs_certificate
            .serial_number
            .as_bytes()
            .to_vec()
    }
}
