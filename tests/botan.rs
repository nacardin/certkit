use botan::Certificate as BotanCertificate;

use certkit::cert::Certificate;
use certkit::cert::params::{CertificationRequestInfo, DistinguishedName};
use certkit::key::KeyPair;

fn default_params() -> (CertificationRequestInfo, KeyPair) {
    let key_pair = KeyPair::generate_ecdsa_p256();
    let subject = DistinguishedName::builder()
        .common_name("crabs.crabs".to_string())
        .organization("Crab widgits SE".to_string())
        .build();
    let cert_info = CertificationRequestInfo::builder()
        .subject(subject)
        .subject_public_key(certkit::key::PublicKey::from_key_pair(&key_pair))
        .build();
    (cert_info, key_pair)
}

fn check_cert(cert_der: &[u8]) {
    // Use botan crate to parse the DER and assert it succeeds
    BotanCertificate::load(cert_der).expect("Botan failed to parse certificate");
}

#[test]
#[ignore]
fn test_botan_ecdsa_p256() {
    let (params, key_pair) = default_params();
    let cert = Certificate::new_self_signed(&params, &key_pair);
    check_cert(&cert.to_der().unwrap());
}

#[test]
#[ignore]
fn test_botan_ed25519() {
    let mut params = default_params().0;
    let key_pair = KeyPair::generate_ed25519();
    params.subject_public_key = certkit::key::PublicKey::from_key_pair(&key_pair);
    let cert = Certificate::new_self_signed(&params, &key_pair);
    check_cert(&cert.to_der().unwrap());
}

#[test]
#[ignore]
fn test_botan_ecdsa_p384() {
    let mut params = default_params().0;
    let key_pair = KeyPair::generate_ecdsa_p384();
    params.subject_public_key = certkit::key::PublicKey::from_key_pair(&key_pair);
    let cert = Certificate::new_self_signed(&params, &key_pair);
    check_cert(&cert.to_der().unwrap());
}

#[test]
#[ignore]
fn test_botan_ecdsa_p521() {
    let mut params = default_params().0;
    let key_pair = KeyPair::generate_ecdsa_p521();
    params.subject_public_key = certkit::key::PublicKey::from_key_pair(&key_pair);
    let cert = Certificate::new_self_signed(&params, &key_pair);
    check_cert(&cert.to_der().unwrap());
}

#[test]
#[ignore]
fn test_botan_rsa() {
    let mut params = default_params().0;
    let key_pair = KeyPair::generate_rsa(2048).unwrap();
    params.subject_public_key = certkit::key::PublicKey::from_key_pair(&key_pair);
    let cert = Certificate::new_self_signed(&params, &key_pair);
    check_cert(&cert.to_der().unwrap());
}
