mod extensions;
mod fmt;

use anyhow::Result;
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use x509_cert::Certificate as X509Certificate;

use certkit::cert::Certificate;
use certkit::key::PublicKey;

use extensions::describe_extension;
use fmt::{describe_oid, hex_colons};

#[derive(Serialize)]
struct ExtReport {
    oid: String,
    /// Human-readable extension name, or empty when the OID is unknown to
    /// both the explicit table and const-oid's database.
    name: String,
    critical: bool,
    summary: String,
}

#[derive(Serialize)]
pub struct CertReport {
    subject: String,
    issuer: String,
    serial: String,
    not_before: String,
    not_after: String,
    expired: bool,
    not_yet_valid: bool,
    days_remaining: i64,
    public_key: String,
    signature_algorithm: String,
    fingerprint_sha256: Option<String>,
    extensions: Vec<ExtReport>,
}

impl CertReport {
    pub fn from_cert(cert: &Certificate, want_fingerprint: bool) -> Result<Self> {
        use der::Decode;
        let der_bytes = cert.to_der()?;
        let raw = X509Certificate::from_der(&der_bytes)?;
        let tbs = &raw.tbs_certificate;

        let not_before = tbs.validity.not_before.to_unix_duration().as_secs() as i64;
        let not_after = tbs.validity.not_after.to_unix_duration().as_secs() as i64;
        let now = OffsetDateTime::now_utc().unix_timestamp();

        let fingerprint_sha256 = want_fingerprint.then(|| hex_colons(&Sha256::digest(&der_bytes)));

        let extensions = tbs
            .extensions
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(describe_extension)
            .collect();

        Ok(Self {
            subject: tbs.subject.to_string(),
            issuer: tbs.issuer.to_string(),
            serial: hex_colons(tbs.serial_number.as_bytes()),
            not_before: tbs.validity.not_before.to_string(),
            not_after: tbs.validity.not_after.to_string(),
            expired: not_after < now,
            not_yet_valid: not_before > now,
            days_remaining: (not_after - now).div_euclid(86_400),
            public_key: describe_public_key(&tbs.subject_public_key_info),
            signature_algorithm: describe_oid(raw.signature_algorithm.oid),
            fingerprint_sha256,
            extensions,
        })
    }

    fn validity_note(&self) -> String {
        if self.expired {
            "(expired)".to_string()
        } else if self.not_yet_valid {
            "(not yet valid)".to_string()
        } else {
            format!("(expires in {} days)", self.days_remaining)
        }
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let mut field = |label: &str, value: &str| {
            out.push_str(&format!("{label:<22}{value}\n"));
        };
        field("Subject:", &self.subject);
        field("Issuer:", &self.issuer);
        field("Serial:", &self.serial);
        field("Not Before:", &self.not_before);
        field(
            "Not After:",
            &format!("{} {}", self.not_after, self.validity_note()),
        );
        field("Public Key:", &self.public_key);
        field("Signature Algorithm:", &self.signature_algorithm);
        if let Some(fp) = &self.fingerprint_sha256 {
            field("SHA-256 Fingerprint:", fp);
        }

        if self.extensions.is_empty() {
            out.push_str("Extensions:           (none)\n");
        } else {
            out.push_str("Extensions:\n");
            for ext in &self.extensions {
                let label = if ext.name.is_empty() {
                    &ext.oid
                } else {
                    &ext.name
                };
                let crit = if ext.critical { " (critical)" } else { "" };
                out.push_str(&format!("  {label}{crit}: {}\n", ext.summary));
            }
        }
        out
    }

    pub fn to_json(&self) -> String {
        let mut out = serde_json::to_string(self).expect("CertReport is always serializable");
        out.push('\n');
        out
    }
}

fn describe_public_key(spki: &x509_cert::spki::SubjectPublicKeyInfoOwned) -> String {
    match PublicKey::from_x509spki(spki) {
        Ok(PublicKey::Rsa(key)) => {
            use rsa::traits::PublicKeyParts;
            format!("RSA ({} bit)", key.n().bits())
        }
        Ok(PublicKey::EcdsaP256(_)) => "ECDSA (P-256)".to_string(),
        Ok(PublicKey::EcdsaP384(_)) => "ECDSA (P-384)".to_string(),
        Ok(PublicKey::EcdsaP521(_)) => "ECDSA (P-521)".to_string(),
        Ok(PublicKey::Ed25519(_)) => "Ed25519".to_string(),
        Err(_) => format!("unrecognized (OID {})", spki.algorithm.oid),
    }
}
