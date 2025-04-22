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
        let rfc4514_name = format!(
            "CN={},OU={},O={},L={},ST={},C={}",
            self.common_name,
            self.organization_unit.clone().unwrap_or_default(),
            self.organization.clone().unwrap_or_default(),
            self.locality.clone().unwrap_or_default(),
            self.state.clone().unwrap_or_default(),
            self.country.clone().unwrap_or_default()
        );
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
