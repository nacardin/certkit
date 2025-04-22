mod util;

use certkit::cert::params;
use certkit::error::CertKitError;
use certkit::{
    cert::params::{CertificationRequestInfo, DistinguishedName},
    issuer::Issuer,
    key::KeyPair,
};
pub type Result<T> = std::result::Result<T, CertKitError>;
use time::OffsetDateTime;

/// Generates a Certificate Authority (CA) certificate and saves it as a PEM file.
/// This test ensures the CA certificate generation process works as expected.
#[test]
fn generate_ca_cert() -> Result<()> {
    let ca_cert_with_key = util::generate_ca_cert();

    use std::io::Write;
    std::fs::create_dir_all(".debug_certs").unwrap();
    std::fs::File::create(".debug_certs/ca_cert.pem")
        .unwrap()
        .write_all(ca_cert_with_key.cert.to_pem().unwrap().as_bytes())
        .unwrap();

    eprintln!("CA Certificate: {:?}", ca_cert_with_key.cert);
    Ok(())
}

/// Generates a server certificate signed by the CA and saves it as a PEM file.
/// This test ensures the server certificate generation and signing process works as expected.
#[test]
fn generate_server_cert() -> Result<()> {
    let ca_cert_with_key = util::generate_ca_cert();

    let server_key = KeyPair::generate_ecdsa_p256();
    let server_dn = DistinguishedName::builder()
        .common_name("server.myca.local".to_string())
        .build();

    let server_public_key = certkit::key::PublicKey::from_key_pair(&server_key);
    let server_cert_info = CertificationRequestInfo::builder()
        .subject(server_dn)
        .subject_public_key(server_public_key)
        .usages(vec![
            certkit::cert::extensions::ExtendedKeyUsageOption::ServerAuth,
        ])
        .build();

    let validity = params::Validity {
        not_before: OffsetDateTime::now_utc(),
        not_after: OffsetDateTime::now_utc() + time::Duration::days(365),
    };
    let server_cert = ca_cert_with_key.issue(&server_cert_info, validity);

    eprintln!("Server Certificate: {:?}", server_cert);
    let server_cert_pem = server_cert.to_pem().unwrap();

    use std::io::Write;
    std::fs::create_dir_all(".debug_certs").unwrap();
    std::fs::File::create(".debug_certs/server_cert.pem")
        .unwrap()
        .write_all(server_cert_pem.as_bytes())
        .unwrap();

    Ok(())
}

/// Generates a client certificate signed by the CA and saves it as a PEM file.
/// This test ensures the client certificate generation and signing process works as expected.
#[test]
fn generate_client_cert() -> Result<()> {
    let ca_cert_with_key = util::generate_ca_cert();

    let client_key = KeyPair::generate_ecdsa_p256();
    let client_dn = DistinguishedName::builder()
        .common_name("client.myca.local".to_string())
        .build();

    let client_public_key = certkit::key::PublicKey::from_key_pair(&client_key);
    let client_cert_info = CertificationRequestInfo::builder()
        .subject(client_dn)
        .subject_public_key(client_public_key)
        .usages(vec![
            certkit::cert::extensions::ExtendedKeyUsageOption::ClientAuth,
        ])
        .build();

    let validity = params::Validity {
        not_before: OffsetDateTime::now_utc(),
        not_after: OffsetDateTime::now_utc() + time::Duration::days(365),
    };
    let client_cert = ca_cert_with_key.issue(&client_cert_info, validity);

    eprintln!("Client Certificate: {:?}", client_cert);
    let client_cert_pem = client_cert.to_pem().unwrap();

    use std::io::Write;
    std::fs::create_dir_all(".debug_certs").unwrap();
    std::fs::File::create(".debug_certs/client_cert.pem")
        .unwrap()
        .write_all(client_cert_pem.as_bytes())
        .unwrap();

    Ok(())
}
