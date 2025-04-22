use std::vec;

use der::Encode;
use der::flagset::FlagSet;
use sha1::Sha1;
use x509_cert::certificate::CertificateInner;

use crate::cert::Certificate;
use crate::cert::SignatureAlgorithm;
use crate::cert::extensions::AuthorityKeyIdentifier;
use crate::cert::extensions::BasicConstraints;
use crate::cert::extensions::ExtendedKeyUsage;
use crate::cert::extensions::ExtendedKeyUsageOption;
use crate::cert::extensions::KeyUsage;
use crate::cert::extensions::KeyUsages;
use crate::cert::params::Validity;
use crate::cert::params::{CertificationRequestInfo, DistinguishedName, ExtensionParam};
use crate::key::KeyPair;
use crate::tbs_certificate::TbsCertificate;

/// Represents an entity capable of issuing certificates.
///
/// This trait provides methods to retrieve issuer details and issue certificates.
pub trait Issuer {
    /// Returns the distinguished name of the issuer.
    fn issuer_name(&self) -> DistinguishedName;

    /// Returns the signing key of the issuer.
    fn signing_key(&self) -> &KeyPair;

    /// Returns the serial number of the issuer.
    fn serial_number(&self) -> Vec<u8>;

    /// Issues a certificate based on the provided certification request information.
    ///
    /// # Arguments
    /// * `cert_request` - The certification request information containing details about the certificate to be issued.
    ///
    /// # Returns
    /// A `Certificate` object representing the issued certificate.
    fn issue(&self, cert_request: &CertificationRequestInfo, validity: Validity) -> Certificate {
        let signature_algo = match self.signing_key() {
            KeyPair::Rsa { .. } => SignatureAlgorithm::Sha256WithRSA,
            KeyPair::EcdsaP256 { .. } => SignatureAlgorithm::Sha256WithECDSA,
            KeyPair::EcdsaP384 { .. } => SignatureAlgorithm::Sha256WithECDSA,
            KeyPair::EcdsaP521 { .. } => SignatureAlgorithm::Sha256WithECDSA,
            KeyPair::Ed25519 { .. } => SignatureAlgorithm::Sha256WithEdDSA,
        };

        let public_key_info = self.signing_key().as_spki();
        let key_id = <Sha1 as sha1::Digest>::digest(public_key_info.subject_public_key.raw_bytes());
        let issuer_dn = self.issuer_name();

        let authority_key_id = AuthorityKeyIdentifier {
            key_identifier: key_id.to_vec(),
            authority_cert_issuer: issuer_dn.clone(),
            authority_cert_serial_number: self.serial_number(),
        };

        let basic_constraints = BasicConstraints {
            is_ca: true,
            max_path_length: None,
        };

        let mut extensions: Vec<ExtensionParam> = vec![
            ExtensionParam::from_extension(basic_constraints, true),
            ExtensionParam::from_extension(authority_key_id, false),
        ];

        let mut key_usage_flags: FlagSet<KeyUsages> = FlagSet::empty();

        if cert_request.is_ca {
            key_usage_flags |= KeyUsages::KeyCertSign;
            key_usage_flags |= KeyUsages::CRLSign;
        }

        for usage in &cert_request.usages {
            match usage {
                ExtendedKeyUsageOption::ClientAuth
                | ExtendedKeyUsageOption::ServerAuth
                | ExtendedKeyUsageOption::EmailProtection => {
                    key_usage_flags |= KeyUsages::KeyEncipherment;
                }
                ExtendedKeyUsageOption::CodeSigning
                | ExtendedKeyUsageOption::TimeStamping
                | ExtendedKeyUsageOption::OcspSigning => {
                    key_usage_flags |= KeyUsages::DigitalSignature;
                }
            }
        }

        if !key_usage_flags.is_empty() {
            let key_usage = KeyUsage(key_usage_flags);
            extensions.push(ExtensionParam::from_extension(key_usage, true));
        }

        if !cert_request.usages.is_empty() {
            let extended_key_usage = ExtendedKeyUsage {
                usage: cert_request.usages.clone(),
            };
            extensions.push(ExtensionParam::from_extension(extended_key_usage, true));
        }

        let combined_extensions = cert_request
            .extensions
            .iter()
            .cloned()
            .chain(extensions)
            .collect();

        let tbs_cert = TbsCertificate {
            serial_number: vec![1],
            signature_algorithm: signature_algo.clone(),
            issuer: issuer_dn,
            not_before: validity.not_before,
            not_after: validity.not_after,
            subject: cert_request.subject.clone(),
            subject_public_key: cert_request.subject_public_key.clone(),
            extensions: combined_extensions,
        };

        let tbs_cert_inner = tbs_cert.to_tbs_certificate_inner();

        let signature = self
            .signing_key()
            .sign_data(&tbs_cert_inner.to_der().unwrap())
            .unwrap();

        let cert_inner = CertificateInner {
            tbs_certificate: tbs_cert_inner,
            signature_algorithm: public_key_info.algorithm,
            signature: der::asn1::BitString::from_bytes(&signature).unwrap(),
        };

        Certificate { inner: cert_inner }
    }
}
