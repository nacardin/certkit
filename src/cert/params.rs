use bon::Builder;
use const_oid::ObjectIdentifier;
use time::Duration;
use time::OffsetDateTime;
use x509_cert::name::RdnSequence;

use super::extensions::ToAndFromX509Extension;
pub use crate::cert::extensions::ExtendedKeyUsage;
pub use crate::cert::extensions::ExtendedKeyUsageOption;
use crate::error::CertKitError;
use crate::key::PublicKey;

// use super::extensions::{Extension};

/// Parameters for building an X.509 certificate.
///
/// This struct contains the subject, public key, and optional extensions for the certificate.
///
/// # Fields
/// * `subject` - The distinguished name of the certificate subject.
/// * `subject_public_key` - The public key of the certificate subject.
/// * `usages` - A list of extended key usage options.
/// * `is_ca` - Indicates if the certificate is a CA.
/// * `extensions` - Additional X.509 extensions.
#[derive(Clone, Debug, Builder)]
pub struct CertificationRequestInfo {
    pub subject: DistinguishedName,
    pub subject_public_key: PublicKey,
    #[builder(default)]
    pub usages: Vec<ExtendedKeyUsageOption>,
    #[builder(default)]
    pub is_ca: bool,
    #[builder(default)]
    pub extensions: Vec<ExtensionParam>,
}

/// Distinguished name parameters for building an X.509 certificate.
///
/// This struct represents the subject or issuer name in a certificate.
///
/// # Fields
/// * `common_name` - The common name (CN).
/// * `country` - The country (C).
/// * `state` - The state or province (ST).
/// * `locality` - The locality or city (L).
/// * `organization` - The organization (O).
/// * `organization_unit` - The organizational unit (OU).
#[derive(Clone, Debug, Builder, Default)]
pub struct DistinguishedName {
    pub common_name: String,
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
    pub organization: Option<String>,
    pub organization_unit: Option<String>,
}

impl DistinguishedName {
    /// Converts the distinguished name to an X.509-compatible format.
    ///
    /// # Returns
    /// An `x509_cert::name::DistinguishedName` object.
    pub fn as_x509_name(&self) -> x509_cert::name::DistinguishedName {
        use core::str::FromStr;

        // Build the RDN sequence from only the attributes that are actually set,
        // so we don't emit empty `OU=`/`O=`/`L=`/`ST=`/`C=` attributes for fields
        // the caller left unset. Attribute ordering is preserved.
        let mut rdns = vec![format!("CN={}", self.common_name)];

        let optional_attrs = [
            ("OU", &self.organization_unit),
            ("O", &self.organization),
            ("L", &self.locality),
            ("ST", &self.state),
            ("C", &self.country),
        ];

        for (key, value) in optional_attrs {
            match value {
                Some(value) if !value.is_empty() => rdns.push(format!("{key}={value}")),
                _ => {}
            }
        }

        let rfc4514_name = rdns.join(",");
        RdnSequence::from_str(&rfc4514_name).unwrap()
    }

    /// Creates a `DistinguishedName` from an X.509-compatible format.
    ///
    /// # Arguments
    /// * `x509dn` - An `x509_cert::name::DistinguishedName` object.
    ///
    /// # Returns
    /// A `DistinguishedName` object.
    pub fn from_x509_name(x509dn: &x509_cert::name::DistinguishedName) -> Self {
        let mut common_name = String::new();

        // Extract the common name from subject if available
        for rdn in x509dn.0.iter() {
            for attr in rdn.0.iter() {
                if attr.oid.to_string() == "2.5.4.3" {
                    // Common Name OID
                    if let Ok(s) = attr.value.decode_as::<String>() {
                        common_name = s.to_string();
                    } else {
                        panic!("Common name is not a PrintableString");
                    }
                }
            }
        }

        DistinguishedName {
            common_name,
            organization_unit: None,
            organization: None,
            locality: None,
            state: None,
            country: None,
        }
    }
}

/// Certificate validity period.
///
/// This struct represents the `notBefore` and `notAfter` fields in a certificate.
///
/// # Fields
/// * `not_before` - The start of the validity period.
/// * `not_after` - The end of the validity period.
#[derive(Clone, Debug)]
pub struct Validity {
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

impl Validity {
    /// Creates a validity period starting now for the given number of days.
    ///
    /// # Arguments
    /// * `days` - The number of days for the validity period.
    ///
    /// # Returns
    /// A `Validity` object.
    pub fn for_days(days: i64) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            not_before: now,
            not_after: now + Duration::days(days),
        }
    }
}

/// Represents an X.509 extension.
///
/// This struct contains the OID, criticality, and value of an extension.
///
/// # Fields
/// * `oid` - The object identifier of the extension.
/// * `critical` - Indicates if the extension is critical.
/// * `value` - The DER-encoded value of the extension.
#[derive(Clone, Debug)]
pub struct ExtensionParam {
    pub oid: ObjectIdentifier,
    pub critical: bool,
    /// DER-encoded extension value
    pub value: Vec<u8>,
}

impl ExtensionParam {
    /// Creates an `ExtensionParam` from a specific extension.
    ///
    /// # Arguments
    /// * `extension` - The extension to encode.
    /// * `critical` - Indicates if the extension is critical.
    ///
    /// # Returns
    /// An `ExtensionParam` object.
    pub fn from_extension<E: ToAndFromX509Extension>(extension: E, critical: bool) -> Self {
        let value = extension
            .to_x509_extension_value()
            .unwrap_or_else(|_| vec![]);
        Self {
            oid: E::OID,
            critical,
            value,
        }
    }

    /// Decodes an `ExtensionParam` into a specific extension.
    ///
    /// # Returns
    /// A decoded extension object.
    pub fn to_extension<E: ToAndFromX509Extension>(&self) -> Result<E, CertKitError> {
        E::from_x509_extension_value(&self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Object identifier for the Common Name (CN) attribute.
    const CN_OID: &str = "2.5.4.3";

    #[test]
    fn common_name_only_produces_single_rdn() {
        let dn = DistinguishedName {
            common_name: "leaf.example.com".to_string(),
            ..Default::default()
        };

        let x509_name = dn.as_x509_name();

        // Exactly one RDN holding exactly one attribute (the CN) — no empty
        // OU/O/L/ST/C attributes for the fields the caller left unset.
        assert_eq!(x509_name.0.len(), 1, "expected a single RDN");
        let attrs: Vec<_> = x509_name.0.iter().flat_map(|rdn| rdn.0.iter()).collect();
        assert_eq!(attrs.len(), 1, "expected a single attribute");
        assert_eq!(attrs[0].oid.to_string(), CN_OID);
        assert_eq!(x509_name.to_string(), "CN=leaf.example.com");

        // And it round-trips back to the original common name with no other fields.
        let round_tripped = DistinguishedName::from_x509_name(&x509_name);
        assert_eq!(round_tripped.common_name, "leaf.example.com");
        assert!(round_tripped.organization_unit.is_none());
        assert!(round_tripped.organization.is_none());
        assert!(round_tripped.locality.is_none());
        assert!(round_tripped.state.is_none());
        assert!(round_tripped.country.is_none());
    }

    #[test]
    fn only_populated_attributes_are_emitted_in_order() {
        let dn = DistinguishedName {
            common_name: "leaf.example.com".to_string(),
            organization: Some("Example Corp".to_string()),
            country: Some("US".to_string()),
            ..Default::default()
        };

        let x509_name = dn.as_x509_name();

        // Two RDNs were skipped (OU, L, ST were unset) leaving CN, O, C in order.
        assert_eq!(x509_name.to_string(), "CN=leaf.example.com,O=Example Corp,C=US");
    }

    #[test]
    fn empty_string_attributes_are_skipped() {
        let dn = DistinguishedName {
            common_name: "leaf.example.com".to_string(),
            organization_unit: Some(String::new()),
            country: Some("US".to_string()),
            ..Default::default()
        };

        // An explicitly empty `OU` is treated the same as `None` and dropped.
        let x509_name = dn.as_x509_name();
        assert_eq!(x509_name.to_string(), "CN=leaf.example.com,C=US");
    }
}
