//! Certificate parameters and builder types.

use bon::Builder;
use const_oid::ObjectIdentifier;
use const_oid::db::rfc4519;
use log::warn;
use time::Duration;
use time::OffsetDateTime;

use crate::error::CertKitError;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::name::{RdnSequence, RelativeDistinguishedName};

use super::extensions::ToAndFromX509Extension;
pub use crate::cert::extensions::ExtendedKeyUsage;
pub use crate::cert::extensions::ExtendedKeyUsageOption;
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
/// * `max_path_length` - For a CA, the maximum number of intermediate CAs that
///   may appear below it. Ignored when `is_ca` is `false`.
/// * `extensions` - Additional X.509 extensions.
#[derive(Clone, Debug, Builder)]
pub struct CertificateParams {
    pub subject: DistinguishedName,
    pub subject_public_key: PublicKey,
    #[builder(default)]
    pub usages: Vec<ExtendedKeyUsageOption>,
    #[builder(default)]
    pub is_ca: bool,
    pub max_path_length: Option<u8>,
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

/// Builds a single-attribute RDN carrying `value` as a DER `UTF8String`.
fn dn_rdn(oid: ObjectIdentifier, value: &str) -> Result<RelativeDistinguishedName, CertKitError> {
    let any = der::Any::new(der::Tag::Utf8String, value.as_bytes())
        .map_err(|e| CertKitError::EncodingError(format!("DN attribute value: {e}")))?;
    let atv = AttributeTypeAndValue { oid, value: any };
    let set = der::asn1::SetOfVec::try_from(vec![atv])
        .map_err(|e| CertKitError::EncodingError(format!("DN attribute set: {e}")))?;
    Ok(RelativeDistinguishedName(set))
}

impl DistinguishedName {
    /// Converts the distinguished name to an X.509-compatible format.
    ///
    /// The RDN sequence is built structurally: each attribute value is placed in
    /// the certificate verbatim as a `UTF8String`.
    ///
    /// Only attributes that are actually set are emitted. They are encoded in
    /// conventional most-significant-first order (C, ST, L, O, OU, CN), which
    /// RFC 4514 renders in reverse as `CN=...,...,C=...`.
    ///
    /// # Errors
    /// Returns `CertKitError::EncodingError` only if an attribute value cannot be
    /// encoded as a DER `UTF8String` This will never happen with a Rust `&str`.
    pub fn as_x509_name(&self) -> Result<x509_cert::name::DistinguishedName, CertKitError> {
        let mut rdns: Vec<RelativeDistinguishedName> = Vec::new();

        let optional_attrs = [
            (rfc4519::C, &self.country),
            (rfc4519::ST, &self.state),
            (rfc4519::L, &self.locality),
            (rfc4519::O, &self.organization),
            (rfc4519::OU, &self.organization_unit),
        ];

        for (oid, value) in optional_attrs {
            if let Some(value) = value {
                if !value.is_empty() {
                    rdns.push(dn_rdn(oid, value)?);
                }
            }
        }

        // Common Name is the most specific attribute, therefore it is encoded last.
        rdns.push(dn_rdn(rfc4519::CN, &self.common_name)?);

        Ok(RdnSequence(rdns))
    }

    /// Creates a `DistinguishedName` from an X.509-compatible format.
    ///
    /// Parses all standard DN attributes: CN (2.5.4.3), OU (2.5.4.11),
    /// O (2.5.4.10), L (2.5.4.7), ST (2.5.4.8), and C (2.5.4.6).
    ///
    /// # Arguments
    /// * `x509dn` - An `x509_cert::name::DistinguishedName` object.
    ///
    /// # Errors
    /// Returns `CertKitError::DecodingError` if the certificate is malformed
    /// and an attribute value cannot be decoded as a string.
    pub fn from_x509_name(
        x509dn: &x509_cert::name::DistinguishedName,
    ) -> Result<Self, CertKitError> {
        let mut common_name = String::new();
        let mut organization_unit = None;
        let mut organization = None;
        let mut locality = None;
        let mut state = None;
        let mut country = None;

        for rdn in x509dn.0.iter() {
            for attr in rdn.0.iter() {
                // DN attributes may be encoded as Utf8String, PrintableString,
                // or other ASN.1 string types depending on the issuer and
                // attribute (e.g. Country is typically PrintableString per X.520).
                let value = attr
                    .value
                    .decode_as::<der::asn1::Utf8StringRef<'_>>()
                    .map(|s| s.as_str().to_owned())
                    .or_else(|_| {
                        attr.value
                            .decode_as::<der::asn1::PrintableStringRef<'_>>()
                            .map(|s| s.as_str().to_owned())
                    })
                    .or_else(|_| {
                        attr.value
                            .decode_as::<der::asn1::Ia5StringRef<'_>>()
                            .map(|s| s.as_str().to_owned())
                    })
                    .map_err(|_| {
                        CertKitError::DecodingError(format!(
                            "DN attribute {} value cannot be decoded as a string",
                            attr.oid
                        ))
                    })?;
                match attr.oid {
                    oid if oid == rfc4519::CN => common_name = value,
                    oid if oid == rfc4519::OU => organization_unit = Some(value),
                    oid if oid == rfc4519::O => organization = Some(value),
                    oid if oid == rfc4519::L => locality = Some(value),
                    oid if oid == rfc4519::ST => state = Some(value),
                    oid if oid == rfc4519::C => country = Some(value),
                    _ => {
                        warn!("Unknown DN attribute {} value {}", attr.oid, value);
                    }
                }
            }
        }

        Ok(DistinguishedName {
            common_name,
            organization_unit,
            organization,
            locality,
            state,
            country,
        })
    }
}

/// Certificate validity period.
///
/// This struct represents the `notBefore` and `notAfter` fields in a certificate.
#[derive(Copy, Clone, Debug)]
pub struct Validity {
    not_before: x509_cert::time::Time,
    not_after: x509_cert::time::Time,
}

/// Encodes an [`OffsetDateTime`] as the correct X.509 `Time` variant per
/// RFC 5280 §4.1.2.5: `UTCTime` for years 1970–2049, `GeneralizedTime` for 2050+.
fn encode_x509_time(dt: OffsetDateTime) -> Result<x509_cert::time::Time, CertKitError> {
    let sys_time: std::time::SystemTime = dt.into();
    // Try UTCTime first (covers 1970–2049 per the `der` crate's UtcTime bounds)
    match der::asn1::UtcTime::from_system_time(sys_time) {
        Ok(ut) => Ok(x509_cert::time::Time::UtcTime(ut)),
        Err(_) => {
            // If outside UTCTime range, use GeneralizedTime
            let gt = der::asn1::GeneralizedTime::from_system_time(sys_time).map_err(|e| {
                CertKitError::EncodingError(format!("timestamp out of GeneralizedTime range: {e}"))
            })?;
            Ok(x509_cert::time::Time::GeneralTime(gt))
        }
    }
}

impl Validity {
    /// Creates a validity period from explicit [`OffsetDateTime`] bounds.
    ///
    /// The timestamps are encoded per RFC 5280 §4.1.2.5 (UTCTime through
    /// 2049, GeneralizedTime from 2050 onward).
    ///
    /// # Errors
    /// Returns [`CertKitError::EncodingError`] if either timestamp cannot be
    /// represented as an ASN.1 time value.
    pub fn new(
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> Result<Self, CertKitError> {
        Ok(Self {
            not_before: encode_x509_time(not_before)?,
            not_after: encode_x509_time(not_after)?,
        })
    }

    /// Creates a validity period starting now for the given number of days.
    ///
    /// # Arguments
    /// * `days` - The number of days for the validity period.
    ///
    /// # Errors
    /// Returns [`CertKitError::EncodingError`] if the resulting timestamps
    /// cannot be represented as ASN.1 time values (practically infallible
    /// for real-world dates).
    pub fn for_days(days: i64) -> Result<Self, CertKitError> {
        let now = OffsetDateTime::now_utc();
        Self::new(now, now + Duration::days(days))
    }

    /// Returns the start of the validity period, as a pre-encoded
    /// [`x509_cert::time::Time`].
    pub fn not_before(&self) -> x509_cert::time::Time {
        self.not_before
    }

    /// Returns the end of the validity period, as a pre-encoded
    /// [`x509_cert::time::Time`].
    pub fn not_after(&self) -> x509_cert::time::Time {
        self.not_after
    }

    /// Returns the total duration of the validity period.
    pub fn duration(&self) -> std::time::Duration {
        let nb: std::time::SystemTime = self.not_before.to_system_time();
        let na: std::time::SystemTime = self.not_after.to_system_time();
        na.duration_since(nb).unwrap_or_default()
    }

    /// Returns the time remaining until the certificate expires, relative to now.
    ///
    /// Returns `None` if the certificate has already expired (i.e. `not_after`
    /// is in the past).
    pub fn remaining(&self) -> Option<std::time::Duration> {
        let na: std::time::SystemTime = self.not_after.to_system_time();
        na.duration_since(std::time::SystemTime::now()).ok()
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
    pub fn from_extension<E: ToAndFromX509Extension>(
        extension: E,
        critical: bool,
    ) -> Result<Self, CertKitError> {
        let value = extension.to_x509_extension_value()?;
        Ok(Self {
            oid: E::OID,
            critical,
            value,
        })
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

    #[test]
    fn common_name_only_produces_single_rdn() {
        let dn = DistinguishedName {
            common_name: "leaf.example.com".to_string(),
            ..Default::default()
        };

        let x509_name = dn.as_x509_name().unwrap();

        // Exactly one RDN holding the CN, OU/O/L/ST/C attributes are left unset.
        assert_eq!(x509_name.0.len(), 1, "expected a single RDN");
        let attrs: Vec<_> = x509_name.0.iter().flat_map(|rdn| rdn.0.iter()).collect();
        assert_eq!(attrs.len(), 1, "expected a single attribute");
        assert_eq!(attrs[0].oid, rfc4519::CN);
        assert_eq!(x509_name.to_string(), "CN=leaf.example.com");

        // And it round-trips back to the original common name with no other fields.
        let round_tripped = DistinguishedName::from_x509_name(&x509_name).unwrap();
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

        let x509_name = dn.as_x509_name().unwrap();

        // Two RDNs were skipped (OU, L, ST were unset) leaving CN, O, C in order.
        assert_eq!(
            x509_name.to_string(),
            "CN=leaf.example.com,O=Example Corp,C=US"
        );
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
        let x509_name = dn.as_x509_name().unwrap();
        assert_eq!(x509_name.to_string(), "CN=leaf.example.com,C=US");
    }

    #[test]
    fn metacharacters_in_values_do_not_panic_or_inject() {
        // A value containing RFC 4514 metacharacters used to either panic.
        // It must now produce exactly one CN attribute carrying the literal value.
        let dn = DistinguishedName {
            common_name: "Acme, Inc.+O=Evil".to_string(),
            ..Default::default()
        };

        let x509_name = dn.as_x509_name().unwrap();

        // Exactly one RDN, one attribute (the CN), no injected O/other RDNs.
        assert_eq!(x509_name.0.len(), 1, "expected a single RDN");
        let attrs: Vec<_> = x509_name.0.iter().flat_map(|rdn| rdn.0.iter()).collect();
        assert_eq!(attrs.len(), 1, "expected a single attribute");
        assert_eq!(attrs[0].oid, rfc4519::CN);

        // The literal value survives a round-trip unchanged.
        let round_tripped = DistinguishedName::from_x509_name(&x509_name).unwrap();
        assert_eq!(round_tripped.common_name, "Acme, Inc.+O=Evil");
        assert!(round_tripped.organization.is_none());
    }
}
