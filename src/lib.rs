//! # CertKit - A Pure Rust Certificate Management Library
//!
//! CertKit is a comprehensive certificate management library built entirely with rustcrypto libraries,
//! providing an alternative to rcgen without dependencies on ring or openssl (except for testing).
//! It supports creating and managing X.509 certificate chains, including loading intermediate CAs
//! and generating server and client certificates.
//!
//! ## Supported Key Types
//!
//! CertKit supports the following cryptographic key types:
//! - **RSA**: 2048, 3072, and 4096-bit keys
//! - **ECDSA**: P-256, P-384, and P-521 curves
//! - **Ed25519**: Edwards curve digital signature algorithm
//!
//! ## Supported Certificate Formats
//!
//! - **DER**: Distinguished Encoding Rules (binary format)
//! - **PEM**: Privacy-Enhanced Mail (base64-encoded text format)
//!
//! ## Key Features
//!
//! - **Pure Rust**: Built entirely with rustcrypto libraries
//! - **Certificate Chain Management**: Create and validate certificate hierarchies
//! - **Self-Signed Certificates**: Generate root CA certificates
//! - **Intermediate CAs**: Support for multi-level certificate authorities
//! - **X.509 Extensions**: Comprehensive support for standard extensions
//! - **Format Flexibility**: Import/export in both PEM and DER formats
//!
//! ## Quick Start
//!
//! ### Generating a Self-Signed Certificate
//!
//! ```rust,no_run
//! use certkit::{
//!     key::KeyPair,
//!     cert::{Certificate, params::{CertificationRequestInfo, DistinguishedName}},
//! };
//!
//! # fn main() -> Result<(), certkit::error::CertKitError> {
//! // Generate an RSA key pair
//! let key_pair = KeyPair::generate_rsa(2048)?;
//!
//! // Create certificate parameters
//! let subject = DistinguishedName::builder()
//!     .common_name("example.com".to_string())
//!     .organization("Example Corp".to_string())
//!     .country("US".to_string())
//!     .build();
//!
//! let cert_info = CertificationRequestInfo::builder()
//!     .subject(subject)
//!     .subject_public_key(certkit::key::PublicKey::from_key_pair(&key_pair))
//!     .build();
//!
//! // Generate the self-signed certificate
//! let certificate = Certificate::new_self_signed(&cert_info, &key_pair);
//!
//! // Export to PEM format
//! let pem_cert = certificate.to_pem()?;
//! println!("Certificate:\n{}", pem_cert);
//! # Ok(())
//! # }
//! ```
//!
//! ### Creating a Certificate Chain
//!
//! ```rust,no_run
//! use certkit::{
//!     key::KeyPair,
//!     cert::{Certificate, CertificateWithPrivateKey, params::{CertificationRequestInfo, DistinguishedName, Validity}},
//!     issuer::Issuer,
//! };
//!
//! # fn main() -> Result<(), certkit::error::CertKitError> {
//! // Generate keys for CA and end-entity
//! let ca_key = KeyPair::generate_ecdsa_p256();
//! let server_key = KeyPair::generate_ecdsa_p256();
//!
//! // Create CA certificate
//! let ca_subject = DistinguishedName::builder()
//!     .common_name("Example CA".to_string())
//!     .organization("Example Corp".to_string())
//!     .build();
//!
//! let ca_cert_info = CertificationRequestInfo::builder()
//!     .subject(ca_subject)
//!     .subject_public_key(certkit::key::PublicKey::from_key_pair(&ca_key))
//!     .is_ca(true)
//!     .build();
//!
//! let ca_cert = Certificate::new_self_signed(&ca_cert_info, &ca_key);
//! let ca_with_key = CertificateWithPrivateKey {
//!     cert: ca_cert,
//!     key: ca_key,
//! };
//!
//! // Create server certificate signed by CA
//! let server_subject = DistinguishedName::builder()
//!     .common_name("server.example.com".to_string())
//!     .build();
//!
//! let server_cert_info = CertificationRequestInfo::builder()
//!     .subject(server_subject)
//!     .subject_public_key(certkit::key::PublicKey::from_key_pair(&server_key))
//!     .build();
//!
//! let validity = Validity::for_days(365);
//! let server_cert = ca_with_key.issue(&server_cert_info, validity);
//!
//! println!("Server certificate issued successfully!");
//! # Ok(())
//! # }
//! ```
//!
//! ### Working with Certificate Extensions
//!
//! ```rust,no_run
//! use certkit::{
//!     key::KeyPair,
//!     cert::{
//!         Certificate,
//!         params::{CertificationRequestInfo, DistinguishedName, ExtensionParam},
//!         extensions::{SubjectAltName, ExtendedKeyUsage, ExtendedKeyUsageOption, ToAndFromX509Extension},
//!     },
//! };
//!
//! # fn main() -> Result<(), certkit::error::CertKitError> {
//! let key_pair = KeyPair::generate_ed25519();
//!
//! // Create Subject Alternative Name extension
//! let san = SubjectAltName {
//!     names: vec!["example.com".to_string(), "www.example.com".to_string()],
//! };
//!
//! // Create Extended Key Usage extension
//! let eku = ExtendedKeyUsage {
//!     usage: vec![ExtendedKeyUsageOption::ServerAuth, ExtendedKeyUsageOption::ClientAuth],
//! };
//!
//! let subject = DistinguishedName::builder()
//!     .common_name("example.com".to_string())
//!     .build();
//!
//! let cert_info = CertificationRequestInfo::builder()
//!     .subject(subject)
//!     .subject_public_key(certkit::key::PublicKey::from_key_pair(&key_pair))
//!     .extensions(vec![
//!         ExtensionParam::from_extension(san, false),
//!         ExtensionParam::from_extension(eku, true),
//!     ])
//!     .build();
//!
//! let certificate = Certificate::new_self_signed(&cert_info, &key_pair);
//! println!("Certificate with extensions created successfully!");
//! # Ok(())
//! # }
//! ```
//!
//! ## Error Handling
//!
//! CertKit uses a comprehensive error system that provides detailed information about failures:
//!
//! ```rust
//! use certkit::{key::KeyPair, error::CertKitError};
//!
//! match KeyPair::import_from_pkcs8_pem("invalid pem data") {
//!     Ok(key_pair) => println!("Key imported successfully"),
//!     Err(CertKitError::DecodingError(msg)) => println!("Failed to decode key: {}", msg),
//!     Err(CertKitError::InvalidInput(msg)) => println!("Invalid input: {}", msg),
//!     Err(e) => println!("Other error: {}", e),
//! }
//! ```
//!
//! ## Module Organization
//!
//! - [`key`]: Key generation, import/export, and cryptographic operations
//! - [`cert`]: Certificate creation, encoding/decoding, and management
//! - [`issuer`]: Certificate issuing functionality and CA operations
//! - [`error`]: Comprehensive error types and handling
//! - [`tbs_certificate`]: Low-level certificate structure manipulation

pub mod cert;
pub mod error;
pub mod issuer;
pub mod key;
pub mod tbs_certificate;
