//! Error types for the crypto module

use thiserror::Error;

/// Result type for crypto operations
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Errors that can occur in crypto operations
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Error during encryption
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Error during decryption
    #[error("Decryption error: {0}")]
    Decryption(String),

    /// Error with the key
    #[error("Key error: {0}")]
    Key(String),

    /// Error with the algorithm
    #[error("Algorithm error: {0}")]
    Algorithm(String),

    /// Error from an HSM
    #[error("HSM error: {0}")]
    Hsm(String),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization or deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<&str> for CryptoError {
    fn from(message: &str) -> Self {
        CryptoError::Internal(message.to_string())
    }
}

impl From<String> for CryptoError {
    fn from(message: String) -> Self {
        CryptoError::Internal(message)
    }
}

impl From<aes_gcm::Error> for CryptoError {
    fn from(err: aes_gcm::Error) -> Self {
        CryptoError::Encryption(format!("AES-GCM error: {:?}", err))
    }
}

impl From<ring::error::Unspecified> for CryptoError {
    fn from(err: ring::error::Unspecified) -> Self {
        CryptoError::Internal(format!("Ring crypto error: {:?}", err))
    }
}

impl From<argon2::Error> for CryptoError {
    fn from(err: argon2::Error) -> Self {
        CryptoError::Key(format!("Argon2 error: {}", err))
    }
}

impl From<serde_json::Error> for CryptoError {
    fn from(err: serde_json::Error) -> Self {
        CryptoError::Serialization(format!("JSON error: {}", err))
    }
}

#[cfg(feature = "hsm")]
impl From<pkcs11::Error> for CryptoError {
    fn from(err: pkcs11::Error) -> Self {
        CryptoError::Hsm(format!("PKCS#11 error: {:?}", err))
    }
}
