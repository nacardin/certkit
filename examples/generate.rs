use std::collections::BTreeMap;

use certkit::cert::{CertificateBuilder, Extension, Validity};
use certkit::key::KeyPair;
use certkit::pem_utils::der_to_pem;

fn main() -> anyhow::Result<()> {
    // Generate a key pair for the CA using ECDSA (or choose RSA/Ed25519)
    let ca_key = KeyPair::generate_ecdsa_p256();
    // (In a complete implementation you would extract the DER‑encoded public key from the key.)
    let ca_pub_der = b"dummy-ca-public-key".to_vec();

    // Build the CA certificate (self‑signed)
    let mut ca_subject = BTreeMap::new();
    ca_subject.insert("CN".to_string(), "My Test CA".to_string());

    let ca_cert_der = CertificateBuilder::new()
        .subject(ca_subject.clone())
        .issuer(ca_subject) // self-signed
        .serial_number(1)
        .validity(Validity::for_days(3650))
        .public_key(ca_pub_der)
        .signature_algorithm("1.2.840.10045.4.3.2")
        // Optionally add extensions (e.g. BasicConstraints)
        .add_extension(Extension {
            oid: "2.5.29.19".to_string(), // BasicConstraints
            critical: true,
            value: vec![], // DER‑encoded value
        })
        .sign(&ca_key)?;

    println!(
        "CA Certificate PEM:\n{}",
        der_to_pem(&ca_cert_der, "CERTIFICATE")
    );

    // Generate a key pair for the server
    let server_key = KeyPair::generate_ed25519();
    let server_pub_der = server_key.get_public_key_der();

    let mut server_subject = BTreeMap::new();
    server_subject.insert("CN".to_string(), "myserver.local".to_string());

    let server_cert_der = CertificateBuilder::new()
        .subject(server_subject)
        .issuer({
            // The issuer is the CA.
            let mut map = BTreeMap::new();
            map.insert("CN".to_string(), "My Test CA".to_string());
            map
        })
        .serial_number(2)
        .validity(Validity::for_days(825))
        .public_key(server_pub_der)
        .signature_algorithm("1.2.840.10045.4.3.2")
        .sign(&ca_key)?; // sign with CA key

    println!(
        "Server Certificate PEM:\n{}",
        der_to_pem(&server_cert_der, "CERTIFICATE")
    );

    Ok(())
}
