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
/// This enum provides a mapping to the corresponding OIDs for each algorithm.
#[derive(Debug, Clone)]
pub enum SignatureAlgorithm {
    /// SHA-256 with RSA encryption.
    Sha256WithRSA,
    /// SHA-256 with ECDSA.
    Sha256WithECDSA,
    /// SHA-384 with ECDSA.
    Sha384WithECDSA,
    /// SHA-512 with ECDSA.
    Sha512WithECDSA,
    /// SHA-256 with EdDSA (Ed25519).
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
/// This struct provides methods to encode the certificate into DER or PEM formats.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// The inner representation of the certificate.
    pub inner: CertificateInner,
}

impl Certificate {
    /// Encodes the certificate into DER format.
    ///
    /// # Returns
    /// A byte vector containing the DER-encoded certificate.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        self.inner
            .to_der()
            .map_err(|e| CertKitError::EncodingError(e.to_string()))
    }

    /// Encodes the certificate into PEM format.
    ///
    /// # Returns
    /// A string containing the PEM-encoded certificate.
    pub fn to_pem(&self) -> Result<String> {
        self.inner
            .to_pem(pkcs8::LineEnding::LF)
            .map_err(|e| CertKitError::EncodingError(e.to_string()))
    }

    /// Extracts certificate information into a `CertificationRequestInfo` object.
    ///
    /// # Returns
    /// A `CertificationRequestInfo` object containing the certificate details.
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
    /// # Arguments
    /// * `cert_info` - The certification request information.
    /// * `key` - The key pair used to sign the certificate.
    ///
    /// # Returns
    /// A `Certificate` object representing the self-signed certificate.
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

#[derive(Debug, Clone)]
pub struct CertificateWithPrivateKey {
    pub cert: Certificate,
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
