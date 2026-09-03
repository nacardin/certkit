use der::Decode;
use der::oid::AssociatedOid;
use x509_cert::ext::pkix;
use x509_cert::ext::pkix::name::GeneralName;

use super::ExtReport;
use super::fmt::{UNDECODABLE, describe_oid, format_ip, hex_colons, join_or_none};

/// Each arm matches via `AssociatedOid::OID` so the OID and its decoder stay in
/// sync. `ObjectIdentifier` isn't usable in match patterns, hence the if/else chain.
pub(super) fn describe_extension(ext: &x509_cert::ext::Extension) -> ExtReport {
    let value = ext.extn_value.as_bytes();
    let oid = ext.extn_id;
    let (name, summary) = if oid == pkix::BasicConstraints::OID {
        ("Basic Constraints", basic_constraints_summary(value))
    } else if oid == pkix::KeyUsage::OID {
        ("Key Usage", key_usage_summary(value))
    } else if oid == pkix::ExtendedKeyUsage::OID {
        ("Extended Key Usage", extended_key_usage_summary(value))
    } else if oid == pkix::SubjectAltName::OID {
        ("Subject Alternative Name", san_summary(value))
    } else if oid == pkix::SubjectKeyIdentifier::OID {
        ("Subject Key Identifier", ski_summary(value))
    } else if oid == pkix::AuthorityKeyIdentifier::OID {
        ("Authority Key Identifier", aki_summary(value))
    } else {
        ("", format!("{} bytes", value.len()))
    };
    ExtReport {
        oid: oid.to_string(),
        name,
        critical: ext.critical,
        summary,
    }
}

fn basic_constraints_summary(value: &[u8]) -> String {
    match pkix::BasicConstraints::from_der(value) {
        Ok(bc) => match bc.path_len_constraint {
            Some(len) => format!("CA={}, pathLen={len}", bc.ca),
            None => format!("CA={}", bc.ca),
        },
        Err(_) => UNDECODABLE.to_string(),
    }
}

fn key_usage_summary(value: &[u8]) -> String {
    match pkix::KeyUsage::from_der(value) {
        Ok(ku) => {
            let names: Vec<&str> = ku.0.into_iter().map(key_usage_name).collect();
            join_or_none(&names)
        }
        Err(_) => UNDECODABLE.to_string(),
    }
}

fn extended_key_usage_summary(value: &[u8]) -> String {
    match pkix::ExtendedKeyUsage::from_der(value) {
        Ok(eku) => {
            let names: Vec<String> = eku.0.iter().map(|oid| describe_oid(*oid)).collect();
            join_or_none(&names)
        }
        Err(_) => UNDECODABLE.to_string(),
    }
}

fn san_summary(value: &[u8]) -> String {
    match pkix::SubjectAltName::from_der(value) {
        Ok(san) => {
            let names: Vec<String> = san.0.iter().map(general_name).collect();
            join_or_none(&names)
        }
        Err(_) => UNDECODABLE.to_string(),
    }
}

fn ski_summary(value: &[u8]) -> String {
    match pkix::SubjectKeyIdentifier::from_der(value) {
        Ok(ski) => hex_colons(ski.0.as_bytes()),
        Err(_) => UNDECODABLE.to_string(),
    }
}

fn aki_summary(value: &[u8]) -> String {
    match pkix::AuthorityKeyIdentifier::from_der(value) {
        Ok(aki) => match aki.key_identifier {
            Some(id) => format!("keyid:{}", hex_colons(id.as_bytes())),
            None => "(no key identifier)".to_string(),
        },
        Err(_) => UNDECODABLE.to_string(),
    }
}

fn general_name(name: &GeneralName) -> String {
    match name {
        GeneralName::DnsName(s) => format!("DNS:{s}"),
        GeneralName::Rfc822Name(s) => format!("email:{s}"),
        GeneralName::UniformResourceIdentifier(s) => format!("URI:{s}"),
        GeneralName::IpAddress(octets) => format!("IP:{}", format_ip(octets.as_bytes())),
        GeneralName::DirectoryName(name) => format!("dirName:{name}"),
        GeneralName::RegisteredId(oid) => format!("registeredID:{oid}"),
        other => format!("{other:?}"),
    }
}

fn key_usage_name(usage: pkix::KeyUsages) -> &'static str {
    use pkix::KeyUsages;
    match usage {
        KeyUsages::DigitalSignature => "digitalSignature",
        KeyUsages::NonRepudiation => "nonRepudiation",
        KeyUsages::KeyEncipherment => "keyEncipherment",
        KeyUsages::DataEncipherment => "dataEncipherment",
        KeyUsages::KeyAgreement => "keyAgreement",
        KeyUsages::KeyCertSign => "keyCertSign",
        KeyUsages::CRLSign => "cRLSign",
        KeyUsages::EncipherOnly => "encipherOnly",
        KeyUsages::DecipherOnly => "decipherOnly",
    }
}
