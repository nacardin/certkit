use std::net::IpAddr;

use anyhow::Result;

use certkit::cert::extensions::{ExtendedKeyUsageOption, SubjectAltName, ToAndFromX509Extension};
use certkit::cert::params::{CertificateParams, DistinguishedName, ExtensionParam};
use certkit::key::{KeyPair, PublicKey};

use crate::args::{CertOptArgs, DnArgs};

pub fn cert_info(dn: &DnArgs, key: &KeyPair, opts: &CertOptArgs) -> Result<CertificateParams> {
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
    if let Some(san) = build_san(&opts.dns, &opts.email, &opts.ip)? {
        extensions.push(san);
    }

    Ok(CertificateParams::builder()
        .subject(subject)
        .subject_public_key(PublicKey::from_key_pair(key))
        .is_ca(opts.ca)
        .usages(usages)
        .extensions(extensions)
        .build())
}

/// Builds the SAN extension from the repeatable `--dns`, `--email` and `--ip`
/// flags, or `None` when none were given.
fn build_san(dns: &[String], email: &[String], ip: &[IpAddr]) -> Result<Option<ExtensionParam>> {
    if dns.is_empty() && email.is_empty() && ip.is_empty() {
        return Ok(None);
    }

    let san = SubjectAltName {
        dns_names: dns.to_vec(),
        email_addresses: email.to_vec(),
        ip_addresses: ip.to_vec(),
    };

    Ok(Some(ExtensionParam {
        oid: SubjectAltName::OID,
        critical: false,
        value: san.to_x509_extension_value()?,
    }))
}
