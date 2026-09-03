use const_oid::ObjectIdentifier;
use const_oid::db::{rfc5280, rfc5912, rfc8410};

pub(super) const UNDECODABLE: &str = "(undecodable)";

pub(super) fn hex_colons(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub(super) fn format_ip(octets: &[u8]) -> String {
    match octets.len() {
        4 => octets
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join("."),
        16 => octets
            .chunks(2)
            .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
            .collect::<Vec<_>>()
            .join(":"),
        _ => hex_colons(octets),
    }
}

/// OID-to-name mapping. Uses const-oid named constants so OID values and their
/// decoders can never drift apart. Falls back to const-oid's DB, then bare OID.
pub(super) fn describe_oid(oid: ObjectIdentifier) -> String {
    let name = if oid == rfc5280::ID_KP_SERVER_AUTH {
        "serverAuth"
    } else if oid == rfc5280::ID_KP_CLIENT_AUTH {
        "clientAuth"
    } else if oid == rfc5280::ID_KP_CODE_SIGNING {
        "codeSigning"
    } else if oid == rfc5280::ID_KP_EMAIL_PROTECTION {
        "emailProtection"
    } else if oid == rfc5280::ID_KP_TIME_STAMPING {
        "timeStamping"
    } else if oid == rfc5280::ID_KP_OCSP_SIGNING {
        "OCSPSigning"
    } else if oid == rfc5912::ECDSA_WITH_SHA_256 {
        "ecdsa-with-SHA256"
    } else if oid == rfc5912::ECDSA_WITH_SHA_384 {
        "ecdsa-with-SHA384"
    } else if oid == rfc5912::ECDSA_WITH_SHA_512 {
        "ecdsa-with-SHA512"
    } else if oid == rfc5912::SHA_1_WITH_RSA_ENCRYPTION {
        "sha1WithRSAEncryption"
    } else if oid == rfc5912::SHA_256_WITH_RSA_ENCRYPTION {
        "sha256WithRSAEncryption"
    } else if oid == rfc5912::SHA_384_WITH_RSA_ENCRYPTION {
        "sha384WithRSAEncryption"
    } else if oid == rfc5912::SHA_512_WITH_RSA_ENCRYPTION {
        "sha512WithRSAEncryption"
    } else if oid == rfc8410::ID_ED_25519 {
        "Ed25519"
    } else {
        return const_oid::db::DB
            .by_oid(&oid)
            .map_or_else(|| oid.to_string(), str::to_string);
    };
    name.to_string()
}

pub(super) fn join_or_none<S: AsRef<str>>(parts: &[S]) -> String {
    if parts.is_empty() {
        "(none)".to_string()
    } else {
        parts
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>()
            .join(", ")
    }
}
