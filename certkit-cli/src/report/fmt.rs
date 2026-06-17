//! Low-level formatting primitives shared by the report renderers.
//!
//! These turn raw bytes, OIDs, and strings into the human- and JSON-friendly
//! fragments that [`super`] and [`super::extensions`] assemble into output.

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

/// Maps a dotted OID string to a friendly name, falling back to the OID itself.
pub(super) fn describe_oid(oid: &str) -> String {
    let name = match oid {
        // Extended Key Usage purposes.
        "1.3.6.1.5.5.7.3.1" => "serverAuth",
        "1.3.6.1.5.5.7.3.2" => "clientAuth",
        "1.3.6.1.5.5.7.3.3" => "codeSigning",
        "1.3.6.1.5.5.7.3.4" => "emailProtection",
        "1.3.6.1.5.5.7.3.8" => "timeStamping",
        "1.3.6.1.5.5.7.3.9" => "OCSPSigning",
        // Signature algorithms.
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.3.101.112" => "Ed25519",
        other => return other.to_string(),
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
