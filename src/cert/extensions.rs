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
/// let san = SubjectAltName {
///     dns_names: vec!["example.com".to_string()],
///     ..Default::default()
/// };
/// let encoded = san.to_x509_extension_value().unwrap();
/// let decoded = SubjectAltName::from_x509_extension_value(&encoded).unwrap();
/// assert_eq!(san.dns_names, decoded.dns_names);
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
/// This extension specifies additional identities for the subject of the
/// certificate. Each identity is carried as the correct `GeneralName` kind:
/// DNS names as `dNSName`, IP addresses as `iPAddress` (4 or 16 octets), and
/// email addresses as `rfc822Name`. Encoding an IP as a DNS name (as an earlier
/// version did) is rejected by TLS verifiers, so the kinds are kept distinct.
///
/// # Fields
/// * `dns_names` - DNS names (`dNSName`).
/// * `ip_addresses` - IP addresses (`iPAddress`).
/// * `email_addresses` - RFC 822 email addresses (`rfc822Name`).
#[derive(Debug, Clone, Default)]
pub struct SubjectAltName {
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<std::net::IpAddr>,
    pub email_addresses: Vec<String>,
}

impl ToAndFromX509Extension for SubjectAltName {
    const OID: ObjectIdentifier = x509_cert::ext::pkix::SubjectAltName::OID;

    fn to_x509_extension_value(&self) -> Result<Vec<u8>, CertKitError> {
        let mut names: Vec<GeneralName> = Vec::new();

        for dns in &self.dns_names {
            let ia5 = Ia5String::try_from(dns.clone())
                .map_err(|e| CertKitError::InvalidInput(format!("invalid DNS SAN '{dns}': {e}")))?;
            names.push(GeneralName::DnsName(ia5));
        }

        for ip in &self.ip_addresses {
            let octets: Vec<u8> = match ip {
                std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
            };
            let os = OctetString::new(octets)
                .map_err(|e| CertKitError::EncodingError(format!("invalid IP SAN: {e}")))?;
            names.push(GeneralName::IpAddress(os));
        }

        for email in &self.email_addresses {
            let ia5 = Ia5String::try_from(email.clone()).map_err(|e| {
                CertKitError::InvalidInput(format!("invalid email SAN '{email}': {e}"))
            })?;
            names.push(GeneralName::Rfc822Name(ia5));
        }

        let san = x509_cert::ext::pkix::SubjectAltName(names);
        Ok(san.to_der()?)
    }

    fn from_x509_extension_value(extension: &[u8]) -> Result<Self, CertKitError> {
        let san = x509_cert::ext::pkix::SubjectAltName::from_der(extension)?;
        let mut out = SubjectAltName::default();

        for name in san.0.iter() {
            match name {
                GeneralName::DnsName(dns) => out.dns_names.push(dns.as_str().to_string()),
                GeneralName::Rfc822Name(email) => {
                    out.email_addresses.push(email.as_str().to_string())
                }
                GeneralName::IpAddress(os) => {
                    let bytes = os.as_bytes();
                    let ip = match bytes.len() {
                        4 => std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                            bytes[0], bytes[1], bytes[2], bytes[3],
                        )),
                        16 => {
                            let mut octets = [0u8; 16];
                            octets.copy_from_slice(bytes);
                            std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
                        }
                        n => {
                            return Err(CertKitError::DecodingError(format!(
                                "invalid IP address length in SAN: {n} bytes"
                            )));
                        }
                    };
                    out.ip_addresses.push(ip);
                }
                // Other GeneralName kinds (URI, directoryName, ...) are not
                // modelled here; skip them so parsing a real-world certificate
                // never fails on an unrecognised name type.
                _ => {}
            }
        }

        Ok(out)
    }
}

/// Represents the Basic Constraints extension.
///
/// This extension indicates whether the certificate is a CA certificate and its path length.
///
/// # Fields
/// * `is_ca` - Indicates if the certificate is a CA.
/// * `max_path_length` - The maximum number of intermediate CAs allowed below
///   this one. `None` means unconstrained. The `pathLenConstraint` field is a
///   small non-negative integer (X.509 caps it well within a `u8`), so this is
///   stored as `Option<u8>` rather than a wider type that would truncate.
#[derive(Default)]
pub struct BasicConstraints {
    pub is_ca: bool,
    pub max_path_length: Option<u8>,
}

impl ToAndFromX509Extension for BasicConstraints {
    const OID: ObjectIdentifier = x509_cert::ext::pkix::BasicConstraints::OID;

    fn to_x509_extension_value(&self) -> Result<Vec<u8>, CertKitError> {
        let bc = x509_cert::ext::pkix::BasicConstraints {
            ca: self.is_ca,
            path_len_constraint: self.max_path_length,
        };

        Ok(bc.to_der()?)
    }

    fn from_x509_extension_value(der_bytes: &[u8]) -> Result<Self, CertKitError> {
        let bc = x509_cert::ext::pkix::BasicConstraints::from_der(der_bytes)?;
        Ok(Self {
            is_ca: bc.ca,
            max_path_length: bc.path_len_constraint,
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
/// Identifies the public key of the CA that signed the certificate.
///
/// The `authorityCertIssuer`/`authorityCertSerialNumber` fields are optional in
/// X.509 and faithfully preserved when decoding. When CertKit *issues* a
/// certificate it follows the common PKIX profile (RFC 5280 §4.2.1.1) and emits
/// only the key identifier, leaving those fields `None`; path building then
/// relies on matching this key identifier against the issuer's
/// [`SubjectKeyIdentifier`].
///
/// # Fields
/// * `key_identifier` - Identifies the issuer's public key (the SHA-1 digest of
///   the issuer's `subjectPublicKey`).
/// * `authority_cert_issuer` - Optional issuer name of the CA's own certificate.
/// * `authority_cert_serial_number` - Optional serial number of the CA's own
///   certificate.
pub struct AuthorityKeyIdentifier {
    pub key_identifier: Vec<u8>,
    pub authority_cert_issuer: Option<DistinguishedName>,
    pub authority_cert_serial_number: Option<Vec<u8>>,
}

impl ToAndFromX509Extension for AuthorityKeyIdentifier {
    const OID: ObjectIdentifier = x509_cert::ext::pkix::AuthorityKeyIdentifier::OID;

    fn to_x509_extension_value(&self) -> Result<Vec<u8>, CertKitError> {
        let authority_cert_issuer = match self.authority_cert_issuer.as_ref() {
            Some(dn) => Some(vec![GeneralName::DirectoryName(dn.as_x509_name()?)]),
            None => None,
        };

        let authority_cert_serial_number = self
            .authority_cert_serial_number
            .as_ref()
            .map(|sn| x509_cert::serial_number::SerialNumber::new(sn.as_slice()))
            .transpose()?;

        let aki = x509_cert::ext::pkix::AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(self.key_identifier.as_slice())?),
            authority_cert_issuer,
            authority_cert_serial_number,
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
            .transpose()?;

        Ok(Self {
            key_identifier: aki
                .key_identifier
                .map(|id| id.as_bytes().to_vec())
                .unwrap_or_default(),
            authority_cert_issuer,
            authority_cert_serial_number: aki
                .authority_cert_serial_number
                .map(|sn| sn.as_bytes().to_vec()),
        })
    }
}

/// Represents the Subject Key Identifier (SKI) extension.
///
/// Identifies certificates that contain a particular public key (RFC 5280
/// §4.2.1.2). Issuing CAs publish it so that the [`AuthorityKeyIdentifier`] of
/// the certificates they sign can be matched back to them during path building.
///
/// # Fields
/// * `key_identifier` - Identifies the subject's public key (the SHA-1 digest of
///   the subject's `subjectPublicKey`).
pub struct SubjectKeyIdentifier {
    pub key_identifier: Vec<u8>,
}

impl ToAndFromX509Extension for SubjectKeyIdentifier {
    const OID: ObjectIdentifier = x509_cert::ext::pkix::SubjectKeyIdentifier::OID;

    fn to_x509_extension_value(&self) -> Result<Vec<u8>, CertKitError> {
        let ski = x509_cert::ext::pkix::SubjectKeyIdentifier(OctetString::new(
            self.key_identifier.as_slice(),
        )?);

        Ok(ski.to_der()?)
    }

    fn from_x509_extension_value(extension: &[u8]) -> Result<Self, CertKitError> {
        let ski = x509_cert::ext::pkix::SubjectKeyIdentifier::from_der(extension)?;

        Ok(Self {
            key_identifier: ski.0.as_bytes().to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_alt_name_round_trips_dns_ip_and_email() {
        // Each identity must encode as its proper GeneralName kind and decode
        // back into the matching field (DNS as dNSName, IP as iPAddress, email
        // as rfc822Name) — an IP must NOT be smuggled into a DNS name.
        let original = SubjectAltName {
            dns_names: vec!["example.com".to_string(), "www.example.com".to_string()],
            ip_addresses: vec!["127.0.0.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            email_addresses: vec!["admin@example.com".to_string()],
        };
        let encoded = original.to_x509_extension_value().unwrap();
        let decoded = SubjectAltName::from_x509_extension_value(&encoded).unwrap();
        assert_eq!(original.dns_names, decoded.dns_names);
        assert_eq!(original.ip_addresses, decoded.ip_addresses);
        assert_eq!(original.email_addresses, decoded.email_addresses);
    }

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
    fn test_authority_key_identifier_key_id_only() {
        // The form CertKit issues: key identifier only, optional fields absent.
        let original = AuthorityKeyIdentifier {
            key_identifier: vec![1, 2, 3, 4, 5],
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        };
        let encoded = original.to_x509_extension_value().unwrap();
        let decoded = AuthorityKeyIdentifier::from_x509_extension_value(&encoded).unwrap();
        assert_eq!(original.key_identifier, decoded.key_identifier);
        assert!(decoded.authority_cert_issuer.is_none());
        assert!(decoded.authority_cert_serial_number.is_none());
    }

    #[test]
    fn test_authority_key_identifier_with_issuer_and_serial() {
        // A full AKI (e.g. parsed from a third-party cert) round-trips faithfully.
        let original = AuthorityKeyIdentifier {
            key_identifier: vec![1, 2, 3, 4, 5],
            authority_cert_issuer: Some(DistinguishedName {
                common_name: "Test CA".to_string(),
                country: Some("US".to_string()),
                state: Some("California".to_string()),
                locality: Some("San Francisco".to_string()),
                organization: Some("Test Org".to_string()),
                organization_unit: Some("Test Unit".to_string()),
            }),
            authority_cert_serial_number: Some(vec![6, 7, 8, 9, 10]),
        };
        let encoded = original.to_x509_extension_value().unwrap();
        let decoded = AuthorityKeyIdentifier::from_x509_extension_value(&encoded).unwrap();
        assert_eq!(original.key_identifier, decoded.key_identifier);
        assert_eq!(
            original.authority_cert_issuer.unwrap().common_name,
            decoded.authority_cert_issuer.unwrap().common_name
        );
        assert_eq!(
            original.authority_cert_serial_number,
            decoded.authority_cert_serial_number
        );
    }

    #[test]
    fn test_subject_key_identifier_encoding_decoding() {
        let original = SubjectKeyIdentifier {
            key_identifier: vec![1, 2, 3, 4, 5],
        };
        let encoded = original.to_x509_extension_value().unwrap();
        let decoded = SubjectKeyIdentifier::from_x509_extension_value(&encoded).unwrap();
        assert_eq!(original.key_identifier, decoded.key_identifier);
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
