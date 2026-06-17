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
use crate::cert::extensions::SubjectKeyIdentifier;
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
/// 1. **Extension Processing**: Add appropriate extensions based on request and CA policy
/// 2. **Signature Algorithm Selection**: Choose algorithm based on CA's key type
/// 3. **TBS Certificate Creation**: Build the "To Be Signed" certificate structure
/// 4. **Signing**: Create digital signature using the CA's private key
/// 5. **Certificate Assembly**: Combine TBS certificate with signature
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
/// let ca_cert = Certificate::new_self_signed(&ca_cert_info, &ca_key)?;
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
/// let issued_cert = ca_issuer.issue(&end_entity_info, validity)?;
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
///     fn issuer_name(&self) -> Result<DistinguishedName, certkit::error::CertKitError> {
///         Ok(self.name.clone())
///     }
///
///     fn signing_key(&self) -> &KeyPair {
///         &self.key
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
    /// A `Result` containing the `DistinguishedName` representing the issuer's
    /// identity, or a `CertKitError` if the name cannot be extracted.
    fn issuer_name(&self) -> Result<DistinguishedName, crate::error::CertKitError>;

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
    /// A 20-byte vector containing a CSPRNG-generated serial number that
    /// conforms to RFC 5280 §4.1.2.2 (positive, non-zero, at most 20 octets).
    ///
    /// # Default Implementation
    /// Generates 20 random bytes via [`rand_core::OsRng`], clears the leading
    /// bit (so the DER INTEGER is positive), and sets the trailing bit (so the
    /// value is never zero). Override this if you need deterministic or
    /// counter-based serial numbers.
    fn serial_number(&self) -> Vec<u8> {
        use rand_core::RngCore;
        let mut buf = [0u8; 20];
        rand_core::OsRng.fill_bytes(&mut buf);
        // Ensure leading bit is 0 so the DER INTEGER is positive.
        buf[0] &= 0x7F;
        // Ensure non-zero.
        buf[19] |= 0x01;
        buf.to_vec()
    }

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
    /// - **Basic Constraints**: Set according to the request's `is_ca` flag
    /// - **Authority Key Identifier**: Links to the issuing CA
    /// - **Subject Key Identifier**: SHA-1 hash of the subject's public key
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
    /// let ca_cert = Certificate::new_self_signed(&ca_cert_info, &ca_key)?;
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
    /// let issued_cert = ca_issuer.issue(&cert_request, validity)?;
    /// println!("Certificate issued with {} extensions",
    ///          issued_cert.to_cert_info()?.extensions.len());
    /// # Ok::<(), certkit::error::CertKitError>(())
    /// ```
    fn issue(&self, cert_request: &CertificationRequestInfo, validity: Validity) -> Result<Certificate, crate::error::CertKitError> {
        let signature_algo = match self.signing_key() {
            #[cfg(feature = "rsa")]
            KeyPair::Rsa { .. } => SignatureAlgorithm::Sha256WithRSA,
            #[cfg(feature = "p256")]
            KeyPair::EcdsaP256 { .. } => SignatureAlgorithm::Sha256WithECDSA,
            #[cfg(feature = "p384")]
            KeyPair::EcdsaP384 { .. } => SignatureAlgorithm::Sha384WithECDSA,
            #[cfg(feature = "p521")]
            KeyPair::EcdsaP521 { .. } => SignatureAlgorithm::Sha512WithECDSA,
            #[cfg(feature = "ed25519")]
            KeyPair::Ed25519 { .. } => SignatureAlgorithm::Sha256WithEdDSA,
        };

        log::debug!(
            "issuing certificate for \"{}\" (CA: {}, signature algorithm: {:?})",
            cert_request.subject.common_name,
            cert_request.is_ca,
            signature_algo
        );

        // Authority Key Identifier: SHA-1 of the signing (issuer) key, so issued
        // certs point back to this CA.
        //
        // SHA-1 is used here per RFC 5280 §4.2.1.2 Method 1 (the de facto
        // standard for key identifier computation). This is NOT a collision-
        // resistance application — the hash simply provides a short, stable
        // identifier for path building, so SHA-1 is appropriate.
        let issuer_spki = self.signing_key().as_spki();
        let authority_key_id = AuthorityKeyIdentifier {
            key_identifier: <Sha1 as sha1::Digest>::digest(
                issuer_spki.subject_public_key.raw_bytes(),
            )
            .to_vec(),
            // PKIX profile: identify the issuer by key id only.
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        };

        // Subject Key Identifier: SHA-1 of the subject's own key, computed the
        // same way, so a child's AKI matches this cert's SKI during path building.
        let subject_spki = cert_request.subject_public_key.as_spki();
        let subject_key_id = SubjectKeyIdentifier {
            key_identifier: <Sha1 as sha1::Digest>::digest(
                subject_spki.subject_public_key.raw_bytes(),
            )
            .to_vec(),
        };

        let issuer_dn = self.issuer_name()?;

        let basic_constraints = BasicConstraints {
            is_ca: cert_request.is_ca,
            max_path_length: None,
        };

        let mut extensions: Vec<ExtensionParam> = vec![
            ExtensionParam::from_extension(basic_constraints, true)?,
            ExtensionParam::from_extension(authority_key_id, false)?,
            ExtensionParam::from_extension(subject_key_id, false)?,
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
                    // TLS 1.3 with ECDSA/Ed25519 requires DigitalSignature.
                    // KeyEncipherment is only needed for RSA key transport
                    // (TLS ≤1.2), so set it conditionally.
                    key_usage_flags |= KeyUsages::DigitalSignature;
                    if matches!(
                        cert_request.subject_public_key,
                        crate::key::PublicKey::Rsa(_)
                    ) {
                        key_usage_flags |= KeyUsages::KeyEncipherment;
                    }
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
            extensions.push(ExtensionParam::from_extension(key_usage, true)?);
        }

        if !cert_request.usages.is_empty() {
            let extended_key_usage = ExtendedKeyUsage {
                usage: cert_request.usages.clone(),
            };
            extensions.push(ExtensionParam::from_extension(extended_key_usage, true)?);
        }

        let combined_extensions: Vec<ExtensionParam> = cert_request
            .extensions
            .iter()
            .cloned()
            .chain(extensions)
            .collect();
        log::trace!("certificate has {} extension(s)", combined_extensions.len());

        let tbs_cert = TbsCertificate {
            serial_number: self.serial_number(),
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
            .sign_data(&tbs_cert_inner.to_der()?)
            .map_err(|e| crate::error::CertKitError::CertificateError(
                format!("signing failed: {e}"),
            ))?;
        log::trace!("certificate signed ({} byte signature)", signature.len());

        let cert_inner = CertificateInner {
            signature_algorithm: tbs_cert_inner.signature.clone(),
            tbs_certificate: tbs_cert_inner,
            signature: der::asn1::BitString::from_bytes(&signature)?,
        };

        Ok(Certificate { inner: cert_inner })
    }
}

#[cfg(test)]
mod tests {
    use super::Issuer;
    use crate::cert::extensions::{
        AuthorityKeyIdentifier, SubjectKeyIdentifier, ToAndFromX509Extension,
    };
    use crate::cert::params::{CertificationRequestInfo, DistinguishedName, Validity};
    use crate::cert::{Certificate, CertificateWithPrivateKey};
    use crate::key::{KeyPair, PublicKey};

    fn request(common_name: &str, key: &KeyPair, is_ca: bool) -> CertificationRequestInfo {
        crate::init_test_logger();
        CertificationRequestInfo::builder()
            .subject(
                DistinguishedName::builder()
                    .common_name(common_name.to_string())
                    .build(),
            )
            .subject_public_key(PublicKey::from_key_pair(key))
            .is_ca(is_ca)
            .build()
    }

    /// Returns the first extension of type `E` carried by `cert`, if present.
    fn extension<E: ToAndFromX509Extension>(cert: &Certificate) -> Option<E> {
        let info = cert.to_cert_info().unwrap();
        info.extensions
            .iter()
            .find(|ext| ext.oid == E::OID)
            .map(|ext| ext.to_extension::<E>().unwrap())
    }

    // The signature algorithm OID must match the curve's hash (RFC 5480): the
    // signer uses SHA-256/384/512 for P-256/384/521, so the declared OID must
    // agree or external verifiers reject the certificate.

    #[cfg(feature = "p256")]
    #[test]
    fn p256_signature_algorithm_is_ecdsa_with_sha256() {
        let key = KeyPair::generate_ecdsa_p256();
        let cert = Certificate::new_self_signed(&request("p256.ca", &key, true), &key).unwrap();
        let expected = const_oid::db::rfc5912::ECDSA_WITH_SHA_256;
        assert_eq!(cert.inner.signature_algorithm.oid, expected);
        assert_eq!(cert.inner.tbs_certificate.signature.oid, expected);
    }

    #[cfg(feature = "p384")]
    #[test]
    fn p384_signature_algorithm_is_ecdsa_with_sha384() {
        let key = KeyPair::generate_ecdsa_p384();
        let cert = Certificate::new_self_signed(&request("p384.ca", &key, true), &key).unwrap();
        let expected = const_oid::db::rfc5912::ECDSA_WITH_SHA_384;
        assert_eq!(cert.inner.signature_algorithm.oid, expected);
        assert_eq!(cert.inner.tbs_certificate.signature.oid, expected);
    }

    #[cfg(feature = "p521")]
    #[test]
    fn p521_signature_algorithm_is_ecdsa_with_sha512() {
        let key = KeyPair::generate_ecdsa_p521();
        let cert = Certificate::new_self_signed(&request("p521.ca", &key, true), &key).unwrap();
        let expected = const_oid::db::rfc5912::ECDSA_WITH_SHA_512;
        assert_eq!(cert.inner.signature_algorithm.oid, expected);
        assert_eq!(cert.inner.tbs_certificate.signature.oid, expected);
    }

    /// Issued certificates carry a Subject Key Identifier, and their Authority
    /// Key Identifier holds only the key id (no issuer name/serial) and matches
    /// the issuer's SKI — so a chain links up during path building.
    #[cfg(feature = "p256")]
    #[test]
    fn issued_chain_links_aki_to_issuer_ski() {
        let root_key = KeyPair::generate_ecdsa_p256();
        let root = Certificate::new_self_signed(&request("Root CA", &root_key, true), &root_key).unwrap();
        let root_ca = CertificateWithPrivateKey {
            cert: root,
            key: root_key,
        };

        let int_key = KeyPair::generate_ecdsa_p256();
        let int = root_ca.issue(
            &request("Intermediate CA", &int_key, true),
            Validity::for_days(365),
        ).unwrap();
        let int_ca = CertificateWithPrivateKey {
            cert: int,
            key: int_key,
        };

        let leaf_key = KeyPair::generate_ecdsa_p256();
        let leaf = int_ca.issue(&request("leaf", &leaf_key, false), Validity::for_days(365)).unwrap();

        let root_ski = extension::<SubjectKeyIdentifier>(&root_ca.cert).expect("root SKI");
        let int_ski = extension::<SubjectKeyIdentifier>(&int_ca.cert).expect("intermediate SKI");
        assert!(
            extension::<SubjectKeyIdentifier>(&leaf).is_some(),
            "leaf must carry a Subject Key Identifier"
        );

        let int_aki = extension::<AuthorityKeyIdentifier>(&int_ca.cert).expect("intermediate AKI");
        let leaf_aki = extension::<AuthorityKeyIdentifier>(&leaf).expect("leaf AKI");

        // keyId-only AKI (PKIX profile).
        assert!(int_aki.authority_cert_issuer.is_none());
        assert!(int_aki.authority_cert_serial_number.is_none());
        assert!(leaf_aki.authority_cert_issuer.is_none());
        assert!(leaf_aki.authority_cert_serial_number.is_none());

        // Each cert's AKI key id equals its issuer's SKI key id.
        assert_eq!(int_aki.key_identifier, root_ski.key_identifier);
        assert_eq!(leaf_aki.key_identifier, int_ski.key_identifier);
    }
}
