//! Low-level formatting primitives shared by the report renderers.
//!
//! These turn raw bytes, OIDs, and strings into the human- and JSON-friendly
//! fragments that [`super`] and [`super::extensions`] assemble into output.

use const_oid::ObjectIdentifier;
use const_oid::db::{rfc5280, rfc5912, rfc8410};

/// Placeholder shown when an extension's value cannot be DER-decoded.
pub(super) const UNDECODABLE: &str = "(undecodable)";

/// Lowercase hex with colon separators, e.g. `9f:86:d0`.
pub(super) fn hex_colons(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Formats raw IP-address octets: dotted-quad for v4, colon-hex for v6.
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

/// Maps an OID to a friendly name.
///
/// Known Extended Key Usage purposes and signature algorithms get a curated
/// short name; the OID identity comes from const-oid's named constants rather
/// than dotted-string literals. For anything else, we fall back to const-oid's
/// name database (e.g. `id-ecPublicKey`), and finally to the bare OID.
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

/// Joins parts with commas, or reports `(none)` when empty.
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

/// Encodes a string as a JSON string literal (quotes + minimal escaping).
pub(super) fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
