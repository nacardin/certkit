use crate::error::CertKitError;
use der::Encode;
use der::asn1::OctetString;
use x509_cert::Version;
use x509_cert::certificate::TbsCertificateInner;
use x509_cert::serial_number::SerialNumber;

use crate::cert::SignatureAlgorithm;
use crate::cert::params::{DistinguishedName, ExtensionParam};
use crate::key::PublicKey;

/// Represents the "To Be Signed" (TBS) portion of an X.509 certificate.
/// This struct contains all the fields required to generate a valid X.509 certificate.
///
/// # Fields
/// * `serial_number` - The unique identifier for the certificate.
/// * `signature_algorithm` - The algorithm used to sign the certificate.
/// * `issuer` - The distinguished name of the certificate issuer.
/// * `not_before` - The start of the certificate's validity period.
/// * `not_after` - The end of the certificate's validity period.
/// * `subject` - The distinguished name of the certificate subject.
/// * `subject_public_key` - The public key of the certificate subject.
/// * `extensions` - Additional X.509 extensions for the certificate.
pub struct TbsCertificate {
    /// Certificate serial number
    pub serial_number: Vec<u8>,
    /// Certificate signature algorithm
    pub signature_algorithm: SignatureAlgorithm,
    /// Certificate issuer distinguished name
    pub issuer: DistinguishedName,
    /// Not before time (in seconds since Unix epoch)
    pub not_before: time::OffsetDateTime,
    /// Not after time (in seconds since Unix epoch)
    pub not_after: time::OffsetDateTime,
    /// Certificate subject distinguished name
    pub subject: DistinguishedName,
    /// Subject's public key
    pub subject_public_key: PublicKey,
    /// Certificate extensions
    pub extensions: Vec<ExtensionParam>,
}

impl TbsCertificate {
    /// Creates a new `TbsCertificate` with default values.
    ///
    /// # Arguments
    /// * `issuer` - The distinguished name of the certificate issuer.
    /// * `subject` - The distinguished name of the certificate subject.
    /// * `subject_public_key` - The public key of the certificate subject.
    /// * `signature_algorithm` - The algorithm used to sign the certificate.
    /// * `extensions` - Additional X.509 extensions for the certificate.
    pub fn new(
        issuer: DistinguishedName,
        subject: DistinguishedName,
        subject_public_key: PublicKey,
        signature_algorithm: SignatureAlgorithm,
        extensions: Vec<ExtensionParam>,
    ) -> Self {
        let not_before = time::OffsetDateTime::now_utc();
        let not_after = not_before + time::Duration::days(365);

        Self {
            serial_number: vec![1],
            signature_algorithm,
            issuer,
            not_before,
            not_after,
            subject,
            subject_public_key,
            extensions,
        }
    }

    /// Converts the `TbsCertificate` into a `TbsCertificateInner` for DER encoding.
    ///
    /// # Returns
    /// A `TbsCertificateInner` object suitable for DER encoding.
    pub fn to_tbs_certificate_inner(&self) -> TbsCertificateInner {
        // Convert to x509_cert's format
        let algorithm_id: x509_cert::spki::AlgorithmIdentifierOwned =
            self.signature_algorithm.clone().into();

        // Convert extensions
        let extensions = self
            .extensions
            .iter()
            .map(|ext| x509_cert::ext::Extension {
                extn_id: ext.oid,
                critical: ext.critical,
                extn_value: OctetString::new(ext.value.clone()).unwrap(),
            })
            .collect::<Vec<_>>();

        // Create validity
        let not_before = x509_cert::time::Time::UtcTime(
            der::asn1::UtcTime::from_system_time(self.not_before.into()).unwrap(),
        );
        let not_after = x509_cert::time::Time::UtcTime(
            der::asn1::UtcTime::from_system_time(self.not_after.into()).unwrap(),
        );

        let validity = x509_cert::time::Validity {
            not_before,
            not_after,
        };

        // Create SerialNumber
        let serial_number = SerialNumber::new(self.serial_number.as_slice()).unwrap();

        // Convert the subject public key to SPKI format
        let subject_public_key_info = match &self.subject_public_key {
            PublicKey::Rsa(public) => {
                x509_cert::spki::SubjectPublicKeyInfoOwned::from_key(public.clone()).unwrap()
            }
            PublicKey::EcdsaP256(verifying_key) => {
                x509_cert::spki::SubjectPublicKeyInfoOwned::from_key(*verifying_key).unwrap()
            }
            PublicKey::EcdsaP384(verifying_key) => {
                x509_cert::spki::SubjectPublicKeyInfoOwned::from_key(*verifying_key).unwrap()
            }
            PublicKey::EcdsaP521(verifying_key) => {
                x509_cert::spki::SubjectPublicKeyInfoOwned::from_key(*verifying_key).unwrap()
            }
            PublicKey::Ed25519(verifying_key) => {
                let pk_bytes = verifying_key.to_bytes();
                x509_cert::spki::SubjectPublicKeyInfoOwned {
                    algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                        oid: const_oid::ObjectIdentifier::new_unwrap("1.3.101.112"),
                        parameters: None,
                    },
                    subject_public_key: der::asn1::BitString::from_bytes(&pk_bytes).unwrap(),
                }
            }
        };

        TbsCertificateInner {
            version: Version::V3,
            serial_number,
            signature: algorithm_id,
            issuer: self.issuer.as_x509_name(),
            validity,
            subject: self.subject.as_x509_name(),
            subject_public_key_info,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        }
    }

    /// Creates a `TbsCertificate` from a `TbsCertificateInner`.
    ///
    /// # Arguments
    /// * `inner` - The `TbsCertificateInner` object to convert from.
    ///
    /// # Returns
    /// A `TbsCertificate` object.
    pub fn from_tbs_certificate_inner(inner: TbsCertificateInner) -> Result<Self, CertKitError> {
        // Convert from x509_cert's format
        let issuer = DistinguishedName::from_x509_name(&inner.issuer);
        let subject = DistinguishedName::from_x509_name(&inner.subject);
        let subject_public_key = PublicKey::from_x509spki(&inner.subject_public_key_info)?;

        // Convert extensions
        let extensions = inner
            .extensions
            .unwrap_or_default()
            .iter()
            .map(|ext| ExtensionParam {
                oid: ext.extn_id,
                critical: ext.critical,
                value: ext.extn_value.as_bytes().to_vec(),
            })
            .collect::<Vec<_>>();

        // Get timestamps from validity
        let not_before = match inner.validity.not_before {
            x509_cert::time::Time::UtcTime(ut) => time::OffsetDateTime::from(ut.to_system_time()),
            x509_cert::time::Time::GeneralTime(gt) => {
                time::OffsetDateTime::from(gt.to_system_time())
            }
        };

        let not_after = match inner.validity.not_after {
            x509_cert::time::Time::UtcTime(ut) => time::OffsetDateTime::from(ut.to_system_time()),
            x509_cert::time::Time::GeneralTime(gt) => {
                time::OffsetDateTime::from(gt.to_system_time())
            }
        };

        // Determine signature algorithm based on OID
        let signature_algorithm = match inner.signature.oid {
            const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION => {
                SignatureAlgorithm::Sha256WithRSA
            }
            const_oid::db::rfc5912::ECDSA_WITH_SHA_256 => SignatureAlgorithm::Sha256WithECDSA,
            const_oid::db::rfc8410::ID_ED_25519 => SignatureAlgorithm::Sha256WithEdDSA,
            _ => {
                return Err(CertKitError::DecodingError(
                    "Unsupported signature algorithm".to_string(),
                ));
            }
        };

        Ok(Self {
            serial_number: inner.serial_number.as_bytes().into(),
            signature_algorithm,
            issuer,
            not_before,
            not_after,
            subject,
            subject_public_key,
            extensions,
        })
    }

    /// Encodes the `TbsCertificate` into DER format.
    ///
    /// # Returns
    /// A byte vector containing the DER-encoded certificate.
    pub fn to_der(&self) -> Result<Vec<u8>, der::Error> {
        self.to_tbs_certificate_inner().to_der()
    }
}
