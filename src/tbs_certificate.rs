//! Low-level "To Be Signed" certificate structure.

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
    /// Start of the certificate's validity period
    pub not_before: x509_cert::time::Time,
    /// End of the certificate's validity period
    pub not_after: x509_cert::time::Time,
    /// Certificate subject distinguished name
    pub subject: DistinguishedName,
    /// Subject's public key
    pub subject_public_key: PublicKey,
    /// Certificate extensions
    pub extensions: Vec<ExtensionParam>,
}

impl TbsCertificate {
    /// Converts the `TbsCertificate` into a `TbsCertificateInner` for DER encoding.
    pub fn to_tbs_certificate_inner(&self) -> Result<TbsCertificateInner, CertKitError> {
        // Convert to x509_cert's format
        let algorithm_id: x509_cert::spki::AlgorithmIdentifierOwned =
            self.signature_algorithm.clone().into();

        // Convert extensions
        let extensions = self
            .extensions
            .iter()
            .map(|ext| {
                Ok(x509_cert::ext::Extension {
                    extn_id: ext.oid,
                    critical: ext.critical,
                    extn_value: OctetString::new(ext.value.clone()).map_err(|e| {
                        CertKitError::EncodingError(format!("extension value: {e}"))
                    })?,
                })
            })
            .collect::<Result<Vec<_>, CertKitError>>()?;

        let validity = x509_cert::time::Validity {
            not_before: self.not_before,
            not_after: self.not_after,
        };

        let serial_number = SerialNumber::new(self.serial_number.as_slice())
            .map_err(|e| CertKitError::InvalidInput(format!("invalid serial number: {e}")))?;

        // Convert the subject public key to SPKI format
        let subject_public_key_info = self.subject_public_key.as_spki();

        Ok(TbsCertificateInner {
            version: Version::V3,
            serial_number,
            signature: algorithm_id,
            issuer: self.issuer.as_x509_name()?,
            validity,
            subject: self.subject.as_x509_name()?,
            subject_public_key_info,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        })
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
        let issuer = DistinguishedName::from_x509_name(&inner.issuer)?;
        let subject = DistinguishedName::from_x509_name(&inner.subject)?;
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

        // Determine signature algorithm based on OID
        let signature_algorithm = match inner.signature.oid {
            const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION => {
                SignatureAlgorithm::Sha256WithRSA
            }
            const_oid::db::rfc5912::ECDSA_WITH_SHA_256 => SignatureAlgorithm::Sha256WithECDSA,
            const_oid::db::rfc5912::ECDSA_WITH_SHA_384 => SignatureAlgorithm::Sha384WithECDSA,
            const_oid::db::rfc5912::ECDSA_WITH_SHA_512 => SignatureAlgorithm::Sha512WithECDSA,
            const_oid::db::rfc8410::ID_ED_25519 => SignatureAlgorithm::Ed25519,
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
            not_before: inner.validity.not_before,
            not_after: inner.validity.not_after,
            subject,
            subject_public_key,
            extensions,
        })
    }

    /// Encodes the `TbsCertificate` into DER format.
    ///
    /// # Returns
    /// A byte vector containing the DER-encoded certificate.
    pub fn to_der(&self) -> Result<Vec<u8>, CertKitError> {
        self.to_tbs_certificate_inner()?
            .to_der()
            .map_err(|e| CertKitError::EncodingError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Certificate;
    use crate::cert::params::{CertificateParams, DistinguishedName};
    use crate::key::{KeyPair, PublicKey};

    fn self_signed(key: &KeyPair) -> Certificate {
        let request = CertificateParams::builder()
            .subject(
                DistinguishedName::builder()
                    .common_name("parse.test".to_string())
                    .build(),
            )
            .subject_public_key(PublicKey::from_key_pair(key))
            .build();
        Certificate::new_self_signed(&request, key).unwrap()
    }

    // The OID -> SignatureAlgorithm parse path must recognize the per-curve ECDSA
    // OIDs; P-384/P-521 certificates previously failed to parse with
    // "Unsupported signature algorithm".

    #[cfg(feature = "p384")]
    #[test]
    fn parses_ecdsa_p384_signature_algorithm() {
        let cert = self_signed(&KeyPair::generate_ecdsa_p384());
        let parsed =
            TbsCertificate::from_tbs_certificate_inner(cert.inner().tbs_certificate.clone())
                .expect("a P-384 certificate must parse");
        assert!(matches!(
            parsed.signature_algorithm,
            SignatureAlgorithm::Sha384WithECDSA
        ));
    }

    #[cfg(feature = "p521")]
    #[test]
    fn parses_ecdsa_p521_signature_algorithm() {
        let cert = self_signed(&KeyPair::generate_ecdsa_p521());
        let parsed =
            TbsCertificate::from_tbs_certificate_inner(cert.inner().tbs_certificate.clone())
                .expect("a P-521 certificate must parse");
        assert!(matches!(
            parsed.signature_algorithm,
            SignatureAlgorithm::Sha512WithECDSA
        ));
    }
}
