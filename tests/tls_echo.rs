//! End-to-end integration test: builds a full PKI chain with `certkit`, then
//! stands up a sync rustls echo server (with mTLS) and a rustls client, and
//! verifies a successful echo round-trip over the encrypted channel.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};

use certkit::cert::extensions::{ExtendedKeyUsageOption, SubjectAltName};
use certkit::cert::params::{CertificateParams, DistinguishedName, ExtensionParam, Validity};
use certkit::cert::{Certificate, CertificateWithPrivateKey};
use certkit::issuer::Issuer;
use certkit::key::{KeyPair, PublicKey};

/// Generate a self-signed root CA certificate.
fn generate_ca(gen_key: &dyn Fn() -> KeyPair) -> CertificateWithPrivateKey {
    let key = gen_key();
    let params = CertificateParams::builder()
        .subject(
            DistinguishedName::builder()
                .common_name("Test Root CA".to_string())
                .build(),
        )
        .subject_public_key(PublicKey::from_key_pair(&key))
        .is_ca(true)
        .build();
    let cert = Certificate::new_self_signed(&params, &key).unwrap();
    CertificateWithPrivateKey::new(cert, key)
}

/// Issue an intermediate CA certificate signed by `parent`.
fn generate_intermediate(
    parent: &CertificateWithPrivateKey,
    gen_key: &dyn Fn() -> KeyPair,
) -> CertificateWithPrivateKey {
    let key = gen_key();
    let params = CertificateParams::builder()
        .subject(
            DistinguishedName::builder()
                .common_name("Test Intermediate CA".to_string())
                .build(),
        )
        .subject_public_key(PublicKey::from_key_pair(&key))
        .is_ca(true)
        .build();
    let cert = parent
        .issue(&params, Validity::for_days(1).unwrap())
        .unwrap();
    CertificateWithPrivateKey::new(cert, key)
}

/// Issue an end-entity certificate from an issuing CA.
///
/// `dns_name` is used as both the Subject CN and the sole SAN DNS entry,
/// matching the modern convention where CN mirrors the primary SAN.
fn issue_end_entity(
    issuer: &CertificateWithPrivateKey,
    gen_key: &dyn Fn() -> KeyPair,
    dns_name: &str,
    usage: ExtendedKeyUsageOption,
) -> CertificateWithPrivateKey {
    let key = gen_key();
    let san = SubjectAltName {
        dns_names: vec![dns_name.to_string()],
        ..Default::default()
    };
    let params = CertificateParams::builder()
        .subject(
            DistinguishedName::builder()
                .common_name(dns_name.to_string())
                .build(),
        )
        .subject_public_key(PublicKey::from_key_pair(&key))
        .usages(vec![usage])
        .extensions(vec![ExtensionParam::from_extension(san, false).unwrap()])
        .build();
    let cert = issuer
        .issue(&params, Validity::for_days(1).unwrap())
        .unwrap();
    CertificateWithPrivateKey::new(cert, key)
}

/// Core mTLS echo test parameterised by key generation function.
///
/// Builds: Root CA → Intermediate CA → Server cert + Client cert,
/// then runs a TLS echo server and client on localhost.
fn run_mtls_echo(gen_key: impl Fn() -> KeyPair) {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("error"))
        .is_test(true)
        .try_init();

    let keygen = &gen_key;

    // 1. Build the PKI chain
    let root_ca = generate_ca(keygen);
    let intermediate_ca = generate_intermediate(&root_ca, keygen);

    let server = issue_end_entity(
        &intermediate_ca,
        keygen,
        "localhost",
        ExtendedKeyUsageOption::ServerAuth,
    );
    let client = issue_end_entity(
        &intermediate_ca,
        keygen,
        "client.local",
        ExtendedKeyUsageOption::ClientAuth,
    );

    // 2. Prepare DER materials for rustls
    let root_der = CertificateDer::from(root_ca.cert().to_der().unwrap());
    let int_der = CertificateDer::from(intermediate_ca.cert().to_der().unwrap());
    let server_der = CertificateDer::from(server.cert().to_der().unwrap());
    let client_der = CertificateDer::from(client.cert().to_der().unwrap());

    let server_chain = vec![server_der, int_der.clone()];
    let client_chain = vec![client_der, int_der];

    let server_key =
        PrivateKeyDer::try_from(server.key().encode_private_key_der().unwrap()).unwrap();
    let client_key =
        PrivateKeyDer::try_from(client.key().encode_private_key_der().unwrap()).unwrap();

    // 3. Configure rustls server (mTLS)
    let mut root_store = RootCertStore::empty();
    root_store.add(root_der).expect("add root CA");

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store.clone()))
        .build()
        .expect("build client verifier");

    let server_config = Arc::new(
        ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_chain, server_key)
            .expect("build server config"),
    );

    // 4. Configure rustls client
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_chain, client_key)
            .expect("build client config"),
    );

    // 5. Bind TCP listener
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local addr");

    // 6. Spawn server thread
    let server_cfg = server_config.clone();
    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let conn = ServerConnection::new(server_cfg).expect("server conn");
        let mut tls = StreamOwned::new(conn, stream);

        let mut buf = vec![0u8; 1024];
        let n = tls.read(&mut buf).expect("server read");
        tls.write_all(&buf[..n]).expect("server write");
        tls.conn.send_close_notify();
        tls.conn.write_tls(&mut tls.sock).ok();
    });

    // 7. Client: connect, send, receive, assert
    let stream = TcpStream::connect(addr).expect("connect");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let conn = ClientConnection::new(client_config, server_name).expect("client conn");
    let mut tls = StreamOwned::new(conn, stream);

    let message = b"certkit echo test";
    tls.write_all(message).expect("client write");
    tls.flush().expect("client flush");

    let mut response = vec![0u8; message.len()];
    tls.read_exact(&mut response).expect("client read");

    assert_eq!(
        &response, message,
        "echo mismatch: expected {:?}, got {:?}",
        message, response
    );

    server_handle.join().expect("server thread panicked");
}

// Per-algorithm test variants
// rustls/webpki does not support ECDSA-P521 verification.

#[cfg(feature = "p256")]
#[test]
fn mtls_echo_p256() {
    run_mtls_echo(KeyPair::generate_ecdsa_p256);
}

#[cfg(feature = "p384")]
#[test]
fn mtls_echo_p384() {
    run_mtls_echo(KeyPair::generate_ecdsa_p384);
}

#[cfg(feature = "ed25519")]
#[test]
fn mtls_echo_ed25519() {
    run_mtls_echo(KeyPair::generate_ed25519);
}

#[cfg(feature = "rsa")]
#[test]
fn mtls_echo_rsa() {
    run_mtls_echo(|| KeyPair::generate_rsa(2048).expect("rsa keygen"));
}
