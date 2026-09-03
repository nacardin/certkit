use anyhow::{Result, anyhow};
use der::Encode;
use der::asn1::Ia5String;
use x509_cert::ext::pkix;
use x509_cert::ext::pkix::name::GeneralName;

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
    if let Some(san) = build_san(&opts.dns, &opts.email)? {
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

/// certkit's `SubjectAltName` only models DNS names, so we assemble the extension
/// directly from x509_cert GeneralNames to also carry rfc822 (email) entries.
fn build_san(dns: &[String], email: &[String]) -> Result<Option<ExtensionParam>> {
    if dns.is_empty() && email.is_empty() {
        return Ok(None);
    }

    let mut names = Vec::new();
    for name in dns {
        let ia5 =
            Ia5String::try_from(name.clone()).map_err(|_| anyhow!("invalid DNS name: {name}"))?;
        names.push(GeneralName::DnsName(ia5));
    }
    for addr in email {
        let ia5 = Ia5String::try_from(addr.clone())
            .map_err(|_| anyhow!("invalid email address: {addr}"))?;
        names.push(GeneralName::Rfc822Name(ia5));
    }

    let san = pkix::SubjectAltName(names);
    Ok(Some(ExtensionParam {
        oid: SubjectAltName::OID,
        critical: false,
        value: san.to_der()?,
    }))
}
