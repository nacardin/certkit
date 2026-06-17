//! Assembling and parsing certificates.
//!
//! [`cert_info`] builds the certification request info (subject, key, and
//! extensions) from the parsed arguments; [`build_san`] is its Subject
//! Alternative Name helper. [`load_ca_cert`] and [`parse_x509`] read existing
//! certificates from PEM or DER.

use std::fs;
use std::path::Path;

use der::asn1::Ia5String;
use der::{Decode, DecodePem, Encode};
use x509_cert::Certificate as X509Certificate;
use x509_cert::ext::pkix;
use x509_cert::ext::pkix::name::GeneralName;

use certkit::cert::Certificate;
use certkit::cert::extensions::{ExtendedKeyUsageOption, SubjectAltName, ToAndFromX509Extension};
use certkit::cert::params::{CertificationRequestInfo, DistinguishedName, ExtensionParam};
use certkit::key::{KeyPair, PublicKey};

use crate::Result;
use crate::args::{CertOptArgs, DnArgs};

/// Builds the certification request info from the DN, key, and options.
pub fn cert_info(
    dn: &DnArgs,
    key: &KeyPair,
    opts: &CertOptArgs,
) -> Result<CertificationRequestInfo> {
    let subject = DistinguishedName::builder()
        .common_name(dn.common_name.clone())
        .maybe_country(dn.country.clone())
        .maybe_state(dn.state.clone())
        .maybe_locality(dn.locality.clone())
        .maybe_organization(dn.organization.clone())
        .maybe_organization_unit(dn.organization_unit.clone())
        .build();

    let usages: Vec<ExtendedKeyUsageOption> = opts.eku.iter().map(|e| (*e).into()).collect();

    let mut extensions = Vec::new();
    if let Some(san) = build_san(&opts.dns, &opts.email)? {
        extensions.push(san);
    }

    Ok(CertificationRequestInfo::builder()
        .subject(subject)
        .subject_public_key(PublicKey::from_key_pair(key))
        .is_ca(opts.ca)
        .usages(usages)
        .extensions(extensions)
        .build())
}

/// Builds a Subject Alternative Name extension from DNS and email entries.
///
/// certkit's own `SubjectAltName` only models DNS names, so the extension is
/// assembled directly from `x509_cert` general names to also carry rfc822
/// (email) entries, then wrapped as a raw `ExtensionParam`.
fn build_san(dns: &[String], email: &[String]) -> Result<Option<ExtensionParam>> {
    if dns.is_empty() && email.is_empty() {
        return Ok(None);
    }

    let mut names = Vec::new();
    for name in dns {
        let ia5 =
            Ia5String::try_from(name.clone()).map_err(|_| format!("invalid DNS name: {name}"))?;
        names.push(GeneralName::DnsName(ia5));
    }
    for addr in email {
        let ia5 = Ia5String::try_from(addr.clone())
            .map_err(|_| format!("invalid email address: {addr}"))?;
        names.push(GeneralName::Rfc822Name(ia5));
    }

    let san = pkix::SubjectAltName(names);
    Ok(Some(ExtensionParam {
        oid: SubjectAltName::OID,
        critical: false,
        value: san.to_der()?,
    }))
}

/// Loads a CA certificate from a PEM or DER file (auto-detected).
pub fn load_ca_cert(path: &Path) -> Result<Certificate> {
    Ok(Certificate {
        inner: parse_x509(&fs::read(path)?)?,
    })
}

/// Parses an X.509 certificate from PEM or DER bytes (auto-detected).
pub fn parse_x509(bytes: &[u8]) -> Result<X509Certificate> {
    Ok(if bytes.starts_with(b"-----BEGIN") {
        X509Certificate::from_pem(bytes)?
    } else {
        X509Certificate::from_der(bytes)?
    })
}
