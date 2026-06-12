use botan::Certificate as BotanCertificate;

use certkit::cert::Certificate;
use certkit::cert::params::{CertificationRequestInfo, DistinguishedName};
use certkit::key::{KeyPair, PublicKey};

/// Builds a self-signed certificate request for the given key pair. Kept generic
/// over the algorithm so each test can supply its own (feature-gated) key.
fn build_cert_info(key_pair: &KeyPair) -> CertificationRequestInfo {
    let subject = DistinguishedName::builder()
        .common_name("crabs.crabs".to_string())
        .organization("Crab widgits SE".to_string())
        .build();
    CertificationRequestInfo::builder()
        .subject(subject)
        .subject_public_key(PublicKey::from_key_pair(key_pair))
        .build()
}

fn check_cert(cert_der: &[u8]) {
    // Use botan crate to parse the DER and assert it succeeds
    BotanCertificate::load(cert_der).expect("Botan failed to parse certificate");
}

fn check_self_signed(key_pair: &KeyPair) {
    let params = build_cert_info(key_pair);
    let cert = Certificate::new_self_signed(&params, key_pair);
    check_cert(&cert.to_der().unwrap());
}

#[test]
#[ignore]
#[cfg(feature = "p256")]
fn test_botan_ecdsa_p256() {
    check_self_signed(&KeyPair::generate_ecdsa_p256());
}

#[test]
#[ignore]
#[cfg(feature = "ed25519")]
fn test_botan_ed25519() {
    check_self_signed(&KeyPair::generate_ed25519());
}

#[test]
#[ignore]
#[cfg(feature = "p384")]
fn test_botan_ecdsa_p384() {
    check_self_signed(&KeyPair::generate_ecdsa_p384());
}

#[test]
#[ignore]
#[cfg(feature = "p521")]
fn test_botan_ecdsa_p521() {
    check_self_signed(&KeyPair::generate_ecdsa_p521());
}

#[test]
#[ignore]
#[cfg(feature = "rsa")]
fn test_botan_rsa() {
    check_self_signed(&KeyPair::generate_rsa(2048).unwrap());
}
