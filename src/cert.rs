use std::collections::BTreeMap;

use anyhow::Result;
use time::{Duration, OffsetDateTime};

use crate::key::KeyPair;

/// Represents a custom X.509 extension.
/// (oid is a string like "2.5.29.19" for BasicConstraints, etc.)
#[derive(Clone, Debug)]
pub struct Extension {
    pub oid: String,
    pub critical: bool,
    pub value: Vec<u8>, // DER-encoded extension value
}

/// Certificate validity period.
#[derive(Clone, Debug)]
pub struct Validity {
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

impl Validity {
    /// Creates a validity period starting now for the given number of days.
    pub fn for_days(days: i64) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            not_before: now,
            not_after: now + Duration::days(days),
        }
    }
}

/// A builder for constructing X.509 certificates.
#[derive(Clone, Debug)]
pub struct CertificateBuilder {
    pub subject: BTreeMap<String, String>,
    pub issuer: BTreeMap<String, String>,
    pub serial_number: u64,
    pub validity: Validity,
    pub public_key_der: Vec<u8>,
    pub extensions: Vec<Extension>,
    /// Signature algorithm identifier (e.g. "1.2.840.10045.4.3.2" for ecdsa-with-SHA256)
    pub signature_algorithm: String,
}

impl Default for CertificateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CertificateBuilder {
    /// Create a new certificate builder with default values.
    pub fn new() -> Self {
        Self {
            subject: BTreeMap::new(),
            issuer: BTreeMap::new(),
            serial_number: 0,
            validity: Validity::for_days(365),
            public_key_der: Vec::new(),
            extensions: Vec::new(),
            signature_algorithm: String::new(),
        }
    }

    /// Set the subject distinguished name.
    pub fn subject(mut self, attrs: BTreeMap<String, String>) -> Self {
        self.subject = attrs;
        self
    }

    /// Set the issuer distinguished name.
    pub fn issuer(mut self, attrs: BTreeMap<String, String>) -> Self {
        self.issuer = attrs;
        self
    }

    /// Set the serial number.
    pub fn serial_number(mut self, serial: u64) -> Self {
        self.serial_number = serial;
        self
    }

    /// Set the validity period.
    pub fn validity(mut self, validity: Validity) -> Self {
        self.validity = validity;
        self
    }

    /// Set the DER‑encoded public key.
    pub fn public_key(mut self, key_der: Vec<u8>) -> Self {
        self.public_key_der = key_der;
        self
    }

    /// Set the signature algorithm (by OID).
    pub fn signature_algorithm(mut self, oid: &str) -> Self {
        self.signature_algorithm = oid.to_string();
        self
    }

    /// Add a custom extension.
    pub fn add_extension(mut self, ext: Extension) -> Self {
        self.extensions.push(ext);
        self
    }

    /// Sign the certificate with the provided issuer key.
    /// Returns a DER‑encoded certificate.
    pub fn sign(self, issuer_key: &KeyPair) -> Result<Vec<u8>> {
        // In a full implementation you would:
        // 1. Build the TBS (to‑be‑signed) portion (subject, issuer, validity, public key, extensions, etc.)
        // 2. DER‑encode the TBS portion.
        // 3. Sign the DER‑encoded TBS with the issuer’s key.
        // 4. Assemble the final certificate (TBS, signature algorithm, signature value) as an ASN.1 SEQUENCE.
        // For demonstration, we use a simplified (dummy) implementation.

        let tbs_cert = self.build_tbs()?;
        let signature = crate::pki::sign_data(&tbs_cert, issuer_key, &self.signature_algorithm)?;
        let certificate =
            crate::pki::assemble_certificate(tbs_cert, &self.signature_algorithm, &signature)?;
        Ok(certificate)
    }

    /// Constructs the TBS portion.
    /// (This is a placeholder; a real implementation must follow the X.509 spec.)
    fn build_tbs(&self) -> Result<Vec<u8>> {
        let mut tbs = Vec::new();
        tbs.extend(&self.serial_number.to_be_bytes());
        // Append additional fields (validity, subject, issuer, public key, and extensions) as DER‑encoded data.
        // This example is oversimplified and does not produce a valid X.509 TBS structure.
        tbs.extend(self.public_key_der.clone());
        Ok(tbs)
    }
}
