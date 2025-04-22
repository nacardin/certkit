use certkit::cert::extensions::ExtendedKeyUsageOption;
use certkit::cert::params::{CertificationRequestInfo, DistinguishedName};
use certkit::cert::{Certificate, CertificateWithPrivateKey};
use certkit::key::{KeyPair, PublicKey};

pub fn generate_ca_cert() -> CertificateWithPrivateKey {
    let ca_key = KeyPair::generate_ecdsa_p256();

    let subject_dn = DistinguishedName::builder()
        .common_name("myca.local".to_string())
        .build();

    let subject_public_key = PublicKey::from_key_pair(&ca_key);

    let ca_cert_info = CertificationRequestInfo::builder()
        .subject(subject_dn.clone())
        .subject_public_key(subject_public_key)
        .usages(vec![
            ExtendedKeyUsageOption::ServerAuth,
            ExtendedKeyUsageOption::ClientAuth,
        ])
        .extensions(vec![])
        .build();

    CertificateWithPrivateKey {
        cert: Certificate::new_self_signed(&ca_cert_info, &ca_key),
        key: ca_key,
    }
}
