use std::vec;

use der::Encode;
use der::flagset::FlagSet;
use sha1::Sha1;
use x509_cert::certificate::CertificateInner;

use crate::cert::Certificate;
use crate::cert::SignatureAlgorithm;
use crate::cert::extensions::AuthorityKeyIdentifier;
use crate::cert::extensions::BasicConstraints;
use crate::cert::extensions::ExtendedKeyUsage;
use crate::cert::extensions::ExtendedKeyUsageOption;
use crate::cert::extensions::KeyUsage;
use crate::cert::extensions::KeyUsages;
use crate::cert::params::Validity;
use crate::cert::params::{CertificationRequestInfo, DistinguishedName, ExtensionParam};
use crate::key::KeyPair;
use crate::tbs_certificate::TbsCertificate;

/// Represents an entity capable of issuing X.509 certificates.
///
/// This trait defines the interface for certificate authorities (CAs) and other
/// entities that can sign and issue certificates. Implementors must provide
/// the issuer's identity, signing key, and serial number generation.
///
/// # Certificate Issuance Process
///
/// 1. **Validation**: Verify the certificate request information
/// 2. **Extension Processing**: Add appropriate extensions based on request and CA policy
/// 3. **Signature Algorithm Selection**: Choose algorithm based on CA's key type
/// 4. **TBS Certificate Creation**: Build the "To Be Signed" certificate structure
/// 5. **Signing**: Create digital signature using the CA's private key
/// 6. **Certificate Assembly**: Combine TBS certificate with signature
///
/// # Implementations
///
/// CertKit provides implementations for:
/// - **Self-signed certificates**: Internal `SelfIssuer` for root CAs
/// - **Certificate authorities**: `CertificateWithPrivateKey` for intermediate and root CAs
///
/// # Examples
///
/// ## Using a CA to Issue Certificates
///
/// ```rust
/// use certkit::{
///     key::KeyPair,
///     cert::{Certificate, CertificateWithPrivateKey, params::{CertificationRequestInfo, DistinguishedName, Validity}},
///     issuer::Issuer,
/// };
///
/// // Create a CA certificate with private key
/// let ca_key = KeyPair::generate_ecdsa_p384();
/// let ca_subject = DistinguishedName::builder()
///     .common_name("Example CA".to_string())
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
/// let ca_issuer = CertificateWithPrivateKey {
///     cert: ca_cert,
///     key: ca_key,
/// };
///
/// // Issue an end-entity certificate
/// let end_entity_key = KeyPair::generate_rsa(2048)?;
/// let end_entity_subject = DistinguishedName::builder()
///     .common_name("client.example.com".to_string())
///     .build();
///
/// let end_entity_info = CertificationRequestInfo::builder()
///     .subject(end_entity_subject)
///     .subject_public_key(certkit::key::PublicKey::from_key_pair(&end_entity_key))
///     .build();
///
/// let validity = Validity::for_days(90);
/// let issued_cert = ca_issuer.issue(&end_entity_info, validity);
///
/// println!("Certificate issued successfully");
/// # Ok::<(), certkit::error::CertKitError>(())
/// ```
///
/// ## Custom Issuer Implementation
///
/// ```rust
/// use certkit::{
///     issuer::Issuer,
///     key::KeyPair,
///     cert::params::{DistinguishedName, CertificationRequestInfo, Validity},
/// };
///
/// struct CustomCA {
///     name: DistinguishedName,
///     key: KeyPair,
///     next_serial: std::cell::Cell<u64>,
/// }
///
/// impl Issuer for CustomCA {
///     fn issuer_name(&self) -> DistinguishedName {
///         self.name.clone()
///     }
///
///     fn signing_key(&self) -> &KeyPair {
///         &self.key
///     }
///
///     fn serial_number(&self) -> Vec<u8> {
///         let serial = self.next_serial.get();
///         self.next_serial.set(serial + 1);
///         serial.to_be_bytes().to_vec()
///     }
/// }
/// ```
pub trait Issuer {
    /// Returns the distinguished name of the issuer.
    ///
    /// This name will appear in the "Issuer" field of issued certificates
    /// and should uniquely identify the certificate authority.
    ///
    /// # Returns
    /// A `DistinguishedName` representing the issuer's identity.
    fn issuer_name(&self) -> DistinguishedName;

    /// Returns the signing key of the issuer.
    ///
    /// This private key is used to create digital signatures on issued certificates.
    /// The corresponding public key should be present in the issuer's own certificate.
    ///
    /// # Returns
    /// A reference to the `KeyPair` used for signing certificates.
    ///
    /// # Security Note
    /// This key must be kept secure as compromise would allow unauthorized certificate issuance.
    fn signing_key(&self) -> &KeyPair;

    /// Returns the serial number for the next certificate to be issued.
    ///
    /// Each certificate issued by a CA must have a unique serial number.
    /// This method should return a different value for each certificate issued.
    ///
    /// # Returns
    /// A byte vector containing the serial number for the next certificate.
    ///
    /// # Implementation Notes
    /// - Serial numbers should be unique within the CA's scope
    /// - Consider using incrementing counters or random values
    /// - Avoid predictable patterns that could aid attacks
    fn serial_number(&self) -> Vec<u8>;

    /// Issues a certificate based on the provided certification request information.
    ///
    /// This method performs the complete certificate issuance process, including:
    /// - Selecting the appropriate signature algorithm based on the CA's key type
    /// - Adding standard extensions (Basic Constraints, Authority Key Identifier, Key Usage)
    /// - Combining request extensions with CA-generated extensions
    /// - Creating and signing the certificate
    ///
    /// # Arguments
    /// * `cert_request` - The certification request information containing:
    ///   - Subject distinguished name
    ///   - Subject's public key
    ///   - Requested extensions
    ///   - CA flag and key usage requirements
    /// * `validity` - The validity period for the issued certificate
    ///
    /// # Returns
    /// A `Certificate` object representing the issued certificate.
    ///
    /// # Extension Processing
    /// The method automatically adds several extensions:
    /// - **Basic Constraints**: Set to CA=true for the issuer
    /// - **Authority Key Identifier**: Links to the issuing CA
    /// - **Key Usage**: Based on the certificate type (CA vs end-entity)
    /// - **Extended Key Usage**: Based on requested usage types
    ///
    /// # Examples
    ///
    /// ```rust
    /// use certkit::{
    ///     key::KeyPair,
    ///     cert::{Certificate, CertificateWithPrivateKey, params::{CertificationRequestInfo, DistinguishedName, Validity}},
    ///     issuer::Issuer,
    /// };
    ///
    /// // Set up CA
    /// let ca_key = KeyPair::generate_rsa(2048)?;
    /// let ca_subject = DistinguishedName::builder().common_name("Test CA".to_string()).build();
    /// let ca_cert_info = CertificationRequestInfo::builder()
    ///     .subject(ca_subject).subject_public_key(certkit::key::PublicKey::from_key_pair(&ca_key)).is_ca(true).build();
    /// let ca_cert = Certificate::new_self_signed(&ca_cert_info, &ca_key);
    /// let ca_issuer = CertificateWithPrivateKey { cert: ca_cert, key: ca_key };
    ///
    /// // Create certificate request
    /// let end_key = KeyPair::generate_ecdsa_p256();
    /// let end_subject = DistinguishedName::builder().common_name("end-entity.com".to_string()).build();
    /// let cert_request = CertificationRequestInfo::builder()
    ///     .subject(end_subject).subject_public_key(certkit::key::PublicKey::from_key_pair(&end_key)).build();
    ///
    /// // Issue the certificate
    /// let validity = Validity::for_days(365);
    /// let issued_cert = ca_issuer.issue(&cert_request, validity);
    /// println!("Certificate issued with {} extensions",
    ///          issued_cert.to_cert_info()?.extensions.len());
    /// # Ok::<(), certkit::error::CertKitError>(())
    /// ```
    fn issue(&self, cert_request: &CertificationRequestInfo, validity: Validity) -> Certificate {
        let signature_algo = match self.signing_key() {
            KeyPair::Rsa { .. } => SignatureAlgorithm::Sha256WithRSA,
            KeyPair::EcdsaP256 { .. } => SignatureAlgorithm::Sha256WithECDSA,
            KeyPair::EcdsaP384 { .. } => SignatureAlgorithm::Sha256WithECDSA,
            KeyPair::EcdsaP521 { .. } => SignatureAlgorithm::Sha256WithECDSA,
            KeyPair::Ed25519 { .. } => SignatureAlgorithm::Sha256WithEdDSA,
        };

        let public_key_info = self.signing_key().as_spki();
        let key_id = <Sha1 as sha1::Digest>::digest(public_key_info.subject_public_key.raw_bytes());
        let issuer_dn = self.issuer_name();

        let authority_key_id = AuthorityKeyIdentifier {
            key_identifier: key_id.to_vec(),
            authority_cert_issuer: issuer_dn.clone(),
            authority_cert_serial_number: self.serial_number(),
        };

        let basic_constraints = BasicConstraints {
            is_ca: true,
            max_path_length: None,
        };

        let mut extensions: Vec<ExtensionParam> = vec![
            ExtensionParam::from_extension(basic_constraints, true),
            ExtensionParam::from_extension(authority_key_id, false),
        ];

        let mut key_usage_flags: FlagSet<KeyUsages> = FlagSet::empty();

        if cert_request.is_ca {
            key_usage_flags |= KeyUsages::KeyCertSign;
            key_usage_flags |= KeyUsages::CRLSign;
        }

        for usage in &cert_request.usages {
            match usage {
                ExtendedKeyUsageOption::ClientAuth
                | ExtendedKeyUsageOption::ServerAuth
                | ExtendedKeyUsageOption::EmailProtection => {
                    key_usage_flags |= KeyUsages::KeyEncipherment;
                }
                ExtendedKeyUsageOption::CodeSigning
                | ExtendedKeyUsageOption::TimeStamping
                | ExtendedKeyUsageOption::OcspSigning => {
                    key_usage_flags |= KeyUsages::DigitalSignature;
                }
            }
        }

        if !key_usage_flags.is_empty() {
            let key_usage = KeyUsage(key_usage_flags);
            extensions.push(ExtensionParam::from_extension(key_usage, true));
        }

        if !cert_request.usages.is_empty() {
            let extended_key_usage = ExtendedKeyUsage {
                usage: cert_request.usages.clone(),
            };
            extensions.push(ExtensionParam::from_extension(extended_key_usage, true));
        }

        let combined_extensions = cert_request
            .extensions
            .iter()
            .cloned()
            .chain(extensions)
            .collect();

        let tbs_cert = TbsCertificate {
            serial_number: vec![1],
            signature_algorithm: signature_algo.clone(),
            issuer: issuer_dn,
            not_before: validity.not_before,
            not_after: validity.not_after,
            subject: cert_request.subject.clone(),
            subject_public_key: cert_request.subject_public_key.clone(),
            extensions: combined_extensions,
        };

        let tbs_cert_inner = tbs_cert.to_tbs_certificate_inner();

        let signature = self
            .signing_key()
            .sign_data(&tbs_cert_inner.to_der().unwrap())
            .unwrap();

        let cert_inner = CertificateInner {
            tbs_certificate: tbs_cert_inner,
            signature_algorithm: public_key_info.algorithm,
            signature: der::asn1::BitString::from_bytes(&signature).unwrap(),
        };

        Certificate { inner: cert_inner }
    }
}
