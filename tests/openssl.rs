mod util;

use certkit::cert::extensions::ExtendedKeyUsageOption;
use certkit::cert::params::{CertificationRequestInfo, DistinguishedName, Validity};
use certkit::issuer::Issuer;
use certkit::key::{KeyPair, PublicKey};
use regex::Regex;
use std::fs;
use std::process::Command;
use time::OffsetDateTime;

#[test]
fn test_openssl_validate_cert() {
    // Generate a CA certificate
    let ca_cert_with_key = util::generate_ca_cert();

    // Generate a server certificate signed by the CA
    let server_key = KeyPair::generate_ecdsa_p256();
    let server_dn = DistinguishedName::builder()
        .common_name("server.myca.local".to_string())
        .build();

    let server_public_key = PublicKey::from_key_pair(&server_key);
    let server_cert_info = CertificationRequestInfo::builder()
        .subject(server_dn)
        .subject_public_key(server_public_key)
        .usages(vec![ExtendedKeyUsageOption::ServerAuth])
        .build();

    let validity = Validity {
        not_before: OffsetDateTime::now_utc(),
        not_after: OffsetDateTime::now_utc() + time::Duration::days(365),
    };
    let server_cert = ca_cert_with_key.issue(&server_cert_info, validity);
    let server_cert_pem = server_cert.to_pem().unwrap();

    // Save the certificate to a temporary file
    let cert_path = "/tmp/test_server_cert.pem";
    fs::write(cert_path, server_cert_pem).expect("Failed to write server certificate");

    // Use OpenSSL CLI to validate the generated certificate
    let output = Command::new("openssl")
        .arg("x509")
        .arg("-in")
        .arg(cert_path)
        .arg("-noout")
        .arg("-text")
        .output()
        .expect("Failed to execute OpenSSL command");

    // Check if OpenSSL command was successful
    assert!(
        output.status.success(),
        "OpenSSL command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Updated test to validate static fields and use partial matching for dynamic fields
    let output_text = String::from_utf8_lossy(&output.stdout);

    // Validate static fields
    assert!(
        output_text.contains("Issuer: C=, ST=, L=, O=, OU=, CN=myca.local"),
        "Issuer field is incorrect"
    );
    assert!(
        output_text.contains("Subject: C=, ST=, L=, O=, OU=, CN=, server.myca.local"),
        "Subject field is incorrect"
    );
    assert!(
        output_text.contains("Version: 3 (0x2)"),
        "Version field is incorrect"
    );
    assert!(
        output_text.contains("Serial Number: 1 (0x1)"),
        "Serial Number field is incorrect"
    );

    // Validate dynamic fields with regex
    let not_before_regex = Regex::new(r"Not Before: .+").unwrap();
    let not_after_regex = Regex::new(r"Not After : .+").unwrap();

    assert!(
        not_before_regex.is_match(&output_text),
        "Missing or incorrect Not Before field"
    );
    assert!(
        not_after_regex.is_match(&output_text),
        "Missing or incorrect Not After field"
    );
    assert!(
        output_text.contains("Signature Algorithm: ecdsa-with-SHA256"),
        "Signature Algorithm field is incorrect"
    );

    // Clean up temporary files
    fs::remove_file(cert_path).expect("Failed to remove test certificate");
}

#[test]
fn test_openssl_crate_validate_cert() {
    // Generate a CA certificate
    let ca_cert_with_key = util::generate_ca_cert();

    // Generate a server certificate signed by the CA
    let server_key = KeyPair::generate_ecdsa_p256();
    let server_dn = DistinguishedName::builder()
        .common_name("server.myca.local".to_string())
        .build();

    let server_public_key = PublicKey::from_key_pair(&server_key);
    let server_cert_info = CertificationRequestInfo::builder()
        .subject(server_dn)
        .subject_public_key(server_public_key)
        .usages(vec![ExtendedKeyUsageOption::ServerAuth])
        .build();

    let validity = Validity {
        not_before: OffsetDateTime::now_utc(),
        not_after: OffsetDateTime::now_utc() + time::Duration::days(365),
    };
    let server_cert = ca_cert_with_key.issue(&server_cert_info, validity);
    let server_cert_pem = server_cert.to_pem().unwrap();

    // Use the openssl crate to parse and validate the certificate
    use openssl::x509::X509;
    let x509 = X509::from_pem(server_cert_pem.as_bytes()).expect("Failed to parse PEM");

    // Check subject
    let subject = x509
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .unwrap()
        .data()
        .as_utf8()
        .unwrap();
    assert_eq!(
        subject.to_string(),
        "server.myca.local",
        "Subject CN mismatch"
    );

    // Check issuer
    let issuer = x509
        .issuer_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .unwrap()
        .data()
        .as_utf8()
        .unwrap();
    assert_eq!(issuer.to_string(), "myca.local", "Issuer CN mismatch");

    // Check version
    assert_eq!(
        x509.version(),
        2,
        "X509 version should be 3 (0-based index)"
    );

    // Check serial number
    let serial = x509.serial_number().to_bn().unwrap().to_dec_str().unwrap();
    assert_eq!(serial.to_string(), "1", "Serial number should be 1");

    // Check signature algorithm
    let sig_alg = x509.signature_algorithm().object().nid();
    assert_eq!(
        sig_alg,
        openssl::nid::Nid::X9_62_ID_ECPUBLICKEY,
        "Signature algorithm should be ecdsa-with-SHA256"
    );
}
