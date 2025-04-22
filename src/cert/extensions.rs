use const_oid::AssociatedOid;
use der::{
    Decode, Encode,
    asn1::{Ia5String, OctetString},
    oid::ObjectIdentifier,
};
use x509_cert::ext::pkix::name::GeneralName;

/// Trait for converting to and from X.509 extensions.
///
/// This trait provides methods to encode and decode X.509 extension values.
///
/// # Example
/// ```
/// use certkit::cert::extensions::SubjectAltName;
/// use crate::certkit::cert::extensions::ToAndFromX509Extension;
/// let san = SubjectAltName { names: vec!["example.com".to_string()] };
/// let encoded = san.to_x509_extension_value().unwrap();
/// let decoded = SubjectAltName::from_x509_extension_value(&encoded).unwrap();
/// assert_eq!(san.names, decoded.names);
/// ```
pub trait ToAndFromX509Extension {
    /// The Object Identifier (OID) for the extension.
    const OID: ObjectIdentifier;

    /// Encodes the extension into a DER-encoded byte vector.
    fn to_x509_extension_value(&self) -> Result<Vec<u8>, CertKitError>;

    /// Decodes the extension from a DER-encoded byte slice.
    fn from_x509_extension_value(extension: &[u8]) -> Result<Self, CertKitError>
    where
        Self: Sized;
}

/// Represents the Subject Alternative Name (SAN) extension.
///
/// This extension specifies additional identities for the subject of the certificate.
///
/// # Fields
/// * `names` - A list of DNS names.
#[derive(Debug, Clone)]
pub struct SubjectAltName {
    pub names: Vec<String>,
}

impl ToAndFromX509Extension for SubjectAltName {
    const OID: ObjectIdentifier = x509_cert::ext::pkix::SubjectAltName::OID;

    fn to_x509_extension_value(&self) -> Result<Vec<u8>, CertKitError> {
        let san = x509_cert::ext::pkix::SubjectAltName(
            self.names
                .iter()
                .map(|name| {
                    Ia5String::try_from(name.clone())
                        .map(GeneralName::DnsName)
                        .map_err(|e| CertKitError::InvalidInput(e.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?,
        );

        Ok(san.to_der()?)
    }

    fn from_x509_extension_value(extension: &[u8]) -> Result<Self, CertKitError> {
        let san = x509_cert::ext::pkix::SubjectAltName::from_der(extension)?;
        let names = san
            .0
            .iter()
            .map(|name| match name {
                GeneralName::DnsName(dns) => Ok(dns.to_string()),
                _ => Err(CertKitError::InvalidInput(
                    "Unsupported general name type".to_string(),
                )),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { names })
    }
}

/// Represents the Basic Constraints extension.
///
/// This extension indicates whether the certificate is a CA certificate and its path length.
///
/// # Fields
/// * `is_ca` - Indicates if the certificate is a CA.
/// * `max_path_length` - The maximum number of intermediate CAs allowed.
#[derive(Default)]
pub struct BasicConstraints {
    pub is_ca: bool,
    pub max_path_length: Option<u32>,
}

impl ToAndFromX509Extension for BasicConstraints {
    const OID: ObjectIdentifier = x509_cert::ext::pkix::BasicConstraints::OID;

    fn to_x509_extension_value(&self) -> Result<Vec<u8>, CertKitError> {
        let bc = x509_cert::ext::pkix::BasicConstraints {
            ca: self.is_ca,
            path_len_constraint: self.max_path_length.map(|v| v as u8),
        };

        Ok(bc.to_der()?)
    }

    fn from_x509_extension_value(der_bytes: &[u8]) -> Result<Self, CertKitError> {
        let bc = x509_cert::ext::pkix::BasicConstraints::from_der(der_bytes)?;
        Ok(Self {
            is_ca: bc.ca,
            max_path_length: bc.path_len_constraint.map(|v| v as u32),
        })
    }
}

pub use der::flagset::FlagSet;
use x509_cert::ext::pkix::KeyUsage as X509KeyUsage;
pub use x509_cert::ext::pkix::KeyUsages;

/// Represents the Key Usage extension.
///
/// This extension defines the purpose of the key contained in the certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUsage(pub FlagSet<KeyUsages>);

use crate::error::CertKitError;

use super::params::DistinguishedName;

impl ToAndFromX509Extension for KeyUsage {
    const OID: ObjectIdentifier = <X509KeyUsage as AssociatedOid>::OID;

    fn to_x509_extension_value(&self) -> Result<Vec<u8>, CertKitError> {
        let ku = X509KeyUsage::from(self.0);
        Ok(ku.to_der()?)
    }

    fn from_x509_extension_value(extension: &[u8]) -> Result<Self, CertKitError> {
        let ku = X509KeyUsage::from_der(extension)?;
        Ok(Self(ku.0))
    }
}

/// Represents the Extended Key Usage extension.
///
/// This extension indicates purposes for which the public key may be used.
#[derive(Debug, Clone, Default)]
pub struct ExtendedKeyUsage {
    pub usage: Vec<ExtendedKeyUsageOption>,
}

impl ToAndFromX509Extension for ExtendedKeyUsage {
    const OID: ObjectIdentifier = x509_cert::ext::pkix::ExtendedKeyUsage::OID;

    fn to_x509_extension_value(&self) -> Result<Vec<u8>, CertKitError> {
        let oids: Vec<ObjectIdentifier> = self.usage.iter().map(|v| (*v).into()).collect();
        let eku = x509_cert::ext::pkix::ExtendedKeyUsage(oids);
        Ok(eku.to_der()?)
    }

    fn from_x509_extension_value(extension: &[u8]) -> Result<Self, CertKitError> {
        let eku = x509_cert::ext::pkix::ExtendedKeyUsage::from_der(extension)?;
        let usage = eku
            .0
            .iter()
            .map(|v| match *v {
                const_oid::db::rfc5912::ID_KP_OCSP_SIGNING => {
                    Ok(ExtendedKeyUsageOption::OcspSigning)
                }
                const_oid::db::rfc5912::ID_KP_SERVER_AUTH => Ok(ExtendedKeyUsageOption::ServerAuth),
                const_oid::db::rfc5912::ID_KP_CLIENT_AUTH => Ok(ExtendedKeyUsageOption::ClientAuth),
                const_oid::db::rfc5912::ID_KP_CODE_SIGNING => {
                    Ok(ExtendedKeyUsageOption::CodeSigning)
                }
                const_oid::db::rfc5912::ID_KP_EMAIL_PROTECTION => {
                    Ok(ExtendedKeyUsageOption::EmailProtection)
                }
                const_oid::db::rfc5912::ID_KP_TIME_STAMPING => {
                    Ok(ExtendedKeyUsageOption::TimeStamping)
                }
                _ => Err(CertKitError::InvalidInput(
                    "Unsupported extended key usage option".to_string(),
                )),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { usage })
    }
}

/// Represents an option for the Extended Key Usage extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExtendedKeyUsageOption {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
}

impl From<ExtendedKeyUsageOption> for ObjectIdentifier {
    fn from(value: ExtendedKeyUsageOption) -> Self {
        match value {
            ExtendedKeyUsageOption::OcspSigning => const_oid::db::rfc5912::ID_KP_OCSP_SIGNING,
            ExtendedKeyUsageOption::ServerAuth => const_oid::db::rfc5912::ID_KP_SERVER_AUTH,
            ExtendedKeyUsageOption::ClientAuth => const_oid::db::rfc5912::ID_KP_CLIENT_AUTH,
            ExtendedKeyUsageOption::CodeSigning => const_oid::db::rfc5912::ID_KP_CODE_SIGNING,
            ExtendedKeyUsageOption::EmailProtection => {
                const_oid::db::rfc5912::ID_KP_EMAIL_PROTECTION
            }
            ExtendedKeyUsageOption::TimeStamping => const_oid::db::rfc5912::ID_KP_TIME_STAMPING,
        }
    }
}

/// Represents the Authority Key Identifier (AKI) extension.
///
/// This extension identifies the public key corresponding to the private key used to sign the certificate.
///
/// # Fields
/// * `key_identifier` - The key identifier.
/// * `authority_cert_issuer` - The issuer's distinguished name.
/// * `authority_cert_serial_number` - The issuer's certificate serial number.
pub struct AuthorityKeyIdentifier {
    pub key_identifier: Vec<u8>,
    pub authority_cert_issuer: DistinguishedName,
    pub authority_cert_serial_number: Vec<u8>,
}

impl ToAndFromX509Extension for AuthorityKeyIdentifier {
    const OID: ObjectIdentifier = x509_cert::ext::pkix::AuthorityKeyIdentifier::OID;

    fn to_x509_extension_value(&self) -> Result<Vec<u8>, CertKitError> {
        let general_names = vec![GeneralName::DirectoryName(
            self.authority_cert_issuer.as_x509_name(),
        )];

        let aki = x509_cert::ext::pkix::AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(self.key_identifier.as_slice())?),
            authority_cert_issuer: Some(general_names),
            authority_cert_serial_number: Some(x509_cert::serial_number::SerialNumber::new(
                self.authority_cert_serial_number.as_slice(),
            )?),
        };

        Ok(aki.to_der()?)
    }

    fn from_x509_extension_value(extension: &[u8]) -> Result<Self, CertKitError> {
        let aki = x509_cert::ext::pkix::AuthorityKeyIdentifier::from_der(extension)?;

        let authority_cert_issuer = aki
            .authority_cert_issuer
            .as_ref()
            .and_then(|names| {
                names.iter().find_map(|name| match name {
                    GeneralName::DirectoryName(dn) => Some(DistinguishedName::from_x509_name(dn)),
                    _ => None,
                })
            })
            .unwrap_or_default();

        Ok(Self {
            key_identifier: aki
                .key_identifier
                .map(|id| id.as_bytes().to_vec())
                .unwrap_or_default(),
            authority_cert_issuer,
            authority_cert_serial_number: aki
                .authority_cert_serial_number
                .map(|sn| sn.as_bytes().to_vec())
                .unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_constraints_encoding_decoding() {
        let original = BasicConstraints {
            is_ca: true,
            max_path_length: Some(3),
        };
        let encoded = original.to_x509_extension_value().unwrap();
        let decoded = BasicConstraints::from_x509_extension_value(&encoded).unwrap();
        assert_eq!(original.is_ca, decoded.is_ca);
        assert_eq!(original.max_path_length, decoded.max_path_length);
    }

    #[test]
    fn test_authority_key_identifier_encoding_decoding() {
        let original = AuthorityKeyIdentifier {
            key_identifier: vec![1, 2, 3, 4, 5],
            authority_cert_issuer: DistinguishedName {
                common_name: "Test CA".to_string(),
                country: Some("US".to_string()),
                state: Some("California".to_string()),
                locality: Some("San Francisco".to_string()),
                organization: Some("Test Org".to_string()),
                organization_unit: Some("Test Unit".to_string()),
            },
            authority_cert_serial_number: vec![6, 7, 8, 9, 10],
        };
        let encoded = original.to_x509_extension_value().unwrap();
        let decoded = AuthorityKeyIdentifier::from_x509_extension_value(&encoded).unwrap();
        assert_eq!(original.key_identifier, decoded.key_identifier);
        assert_eq!(
            original.authority_cert_issuer.common_name,
            decoded.authority_cert_issuer.common_name
        );
        assert_eq!(
            original.authority_cert_serial_number,
            decoded.authority_cert_serial_number
        );
    }

    #[test]
    fn test_key_usage_encoding_decoding() {
        let original = KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment);
        let encoded = original.to_x509_extension_value().unwrap();
        let decoded = KeyUsage::from_x509_extension_value(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_extended_key_usage_encoding_decoding() {
        let original = ExtendedKeyUsage {
            usage: vec![
                ExtendedKeyUsageOption::ServerAuth,
                ExtendedKeyUsageOption::ClientAuth,
            ],
        };
        let encoded = original.to_x509_extension_value().unwrap();
        let decoded = ExtendedKeyUsage::from_x509_extension_value(&encoded).unwrap();
        assert_eq!(original.usage, decoded.usage);
    }
}
