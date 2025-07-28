//! Error types and handling for the CertKit library.
//!
//! This module defines the comprehensive error system used throughout CertKit,
//! providing detailed error information for debugging and error handling.
//!
//! # Error Categories
//!
//! - **Encoding/Decoding**: Issues with data format conversion
//! - **Input Validation**: Problems with user-provided data
//! - **Cryptographic Operations**: Key generation and signing failures
//! - **Certificate Operations**: Certificate creation and validation issues
//!
//! # Examples
//!
//! ```rust
//! use certkit::{key::KeyPair, error::CertKitError};
//!
//! // Handle different error types
//! match KeyPair::import_from_pkcs8_pem("invalid pem") {
//!     Ok(key) => println!("Key imported successfully"),
//!     Err(CertKitError::DecodingError(msg)) => {
//!         eprintln!("Failed to decode PEM: {}", msg);
//!     }
//!     Err(CertKitError::InvalidInput(msg)) => {
//!         eprintln!("Invalid input provided: {}", msg);
//!     }
//!     Err(e) => eprintln!("Other error: {}", e),
//! }
//! ```

use thiserror::Error;

/// Represents errors that can occur in the CertKit library.
///
/// This enum provides comprehensive error reporting for all operations
/// in CertKit, with detailed error messages and context information
/// to help with debugging and error handling.
///
/// # Error Handling Strategy
///
/// CertKit uses a centralized error type that covers all possible failure
/// scenarios. Each error variant includes a descriptive message and,
/// where appropriate, the underlying cause of the error.
///
/// # Examples
///
/// ## Basic Error Handling
///
/// ```rust
/// use certkit::{key::KeyPair, error::CertKitError};
///
/// fn handle_key_generation() -> Result<(), CertKitError> {
///     let key = KeyPair::generate_rsa(2048)?;
///     println!("Key generated successfully");
///     Ok(())
/// }
///
/// match handle_key_generation() {
///     Ok(()) => println!("Success!"),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
///
/// ## Specific Error Type Matching
///
/// ```rust
/// use certkit::{key::KeyPair, error::CertKitError};
///
/// let result = KeyPair::import_from_pkcs8_pem("invalid data");
/// match result {
///     Ok(key) => println!("Key imported"),
///     Err(CertKitError::DecodingError(msg)) => {
///         eprintln!("Decoding failed: {}", msg);
///         // Handle decoding-specific error
///     }
///     Err(CertKitError::InvalidInput(msg)) => {
///         eprintln!("Invalid input: {}", msg);
///         // Handle input validation error
///     }
///     Err(e) => eprintln!("Unexpected error: {}", e),
/// }
/// ```
#[derive(Debug, Error, Clone)]
pub enum CertKitError {
    /// Error during data encoding operations.
    ///
    /// This error occurs when CertKit fails to encode data into a specific format,
    /// such as converting certificates to DER or PEM format.
    ///
    /// # Common Causes
    /// - Malformed internal certificate structures
    /// - Invalid extension data
    /// - Memory allocation failures during encoding
    #[error("Failed to encode data: {0}")]
    EncodingError(String),

    /// Error during data decoding operations.
    ///
    /// This error occurs when CertKit fails to decode data from external formats,
    /// such as parsing PEM/DER encoded keys or certificates.
    ///
    /// # Common Causes
    /// - Malformed PEM or DER data
    /// - Unsupported key or certificate formats
    /// - Corrupted or truncated input data
    /// - Invalid ASN.1 structures
    #[error("Failed to decode data: {0}")]
    DecodingError(String),

    /// Error due to invalid input parameters.
    ///
    /// This error occurs when user-provided input doesn't meet the requirements
    /// for the requested operation.
    ///
    /// # Common Causes
    /// - Invalid key sizes (e.g., RSA keys smaller than 1024 bits)
    /// - Malformed distinguished names
    /// - Invalid extension parameters
    /// - Unsupported algorithm combinations
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Error during cryptographic key generation.
    ///
    /// This error occurs when the system fails to generate cryptographic keys,
    /// typically due to insufficient entropy or system resource constraints.
    ///
    /// # Common Causes
    /// - Insufficient system entropy
    /// - Invalid key parameters
    /// - System resource exhaustion
    /// - Hardware security module failures
    #[error("Key generation error: {0}")]
    KeyGenerationError(String),

    /// Error related to certificate operations.
    ///
    /// This error covers general certificate-related failures that don't fit
    /// into more specific categories.
    ///
    /// # Common Causes
    /// - Certificate validation failures
    /// - Invalid certificate chains
    /// - Expired or not-yet-valid certificates
    /// - Certificate format inconsistencies
    #[error("Certificate error: {0}")]
    CertificateError(String),

    /// Error from RSA cryptographic operations.
    ///
    /// This error occurs when RSA-specific operations fail, such as key
    /// generation, signing, or verification.
    ///
    /// # Common Causes
    /// - Invalid RSA key parameters
    /// - RSA signature verification failures
    /// - Key size limitations
    /// - Padding scheme errors
    #[error("RSA error: {0}")]
    RsaError(String),

    /// Error from RSA PKCS#1 operations.
    ///
    /// This error occurs when PKCS#1 format operations fail, such as
    /// encoding or decoding RSA keys in PKCS#1 format.
    ///
    /// # Common Causes
    /// - Invalid PKCS#1 key format
    /// - Corrupted PKCS#1 data
    /// - Unsupported PKCS#1 variants
    #[error("RSA PKCS1 error: {0}")]
    RsaPkcs1Error(String),

    /// An unknown or unexpected error occurred.
    ///
    /// This error is used as a fallback for unexpected conditions that
    /// don't fit into other error categories.
    ///
    /// # When This Occurs
    /// - Internal library inconsistencies
    /// - Unexpected system conditions
    /// - Unhandled edge cases
    #[error("Unknown error occurred")]
    Unknown,
}

impl From<der::Error> for CertKitError {
    /// Converts a `der::Error` into a `CertKitError`.
    fn from(err: der::Error) -> Self {
        CertKitError::DecodingError(err.to_string())
    }
}

impl From<rsa::Error> for CertKitError {
    fn from(err: rsa::Error) -> Self {
        CertKitError::RsaError(err.to_string())
    }
}

impl From<rsa::pkcs1::Error> for CertKitError {
    fn from(err: rsa::pkcs1::Error) -> Self {
        CertKitError::RsaPkcs1Error(err.to_string())
    }
}
