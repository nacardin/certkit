//! use certkit::error::CertKitError;

use thiserror::Error;

/// Represents errors that can occur in the CertKit library.
///
/// This enum provides detailed error messages for various failure scenarios.
#[derive(Debug, Error, Clone)]
pub enum CertKitError {
    /// Error during data encoding.
    #[error("Failed to encode data: {0}")]
    EncodingError(String),

    /// Error during data decoding.
    #[error("Failed to decode data: {0}")]
    DecodingError(String),

    /// Error due to invalid input.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Error during key generation.
    #[error("Key generation error: {0}")]
    KeyGenerationError(String),

    /// Error related to certificate operations.
    #[error("Certificate error: {0}")]
    CertificateError(String),

    /// Error from RSA operations.
    #[error("RSA error: {0}")]
    RsaError(String),

    /// Error from RSA PKCS1 operations.
    #[error("RSA PKCS1 error: {0}")]
    RsaPkcs1Error(String),

    /// An unknown error occurred.
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
