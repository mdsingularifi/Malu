//! Error types for the HSM module

use thiserror::Error;

/// Result type for HSM operations
pub type Result<T> = std::result::Result<T, HsmError>;

/// HSM-specific errors
#[derive(Error, Debug)]
pub enum HsmError {
    /// Error related to HSM configuration or operation
    #[error("HSM error: {0}")]
    Hsm(String),
    
    /// Error related to key operations
    #[error("Key error: {0}")]
    Key(String),

    /// Error related to cryptographic operations
    #[error("Crypto error: {0}")]
    Crypto(String),
    
    /// Error from crypto provider
    #[error("Provider error: {0}")]
    Provider(String),
    
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    /// Generic error with message
    #[error("{0}")]
    Generic(String),
}

// Note: We don't need a From implementation for Box<dyn Error> because the standard library
// already provides a blanket implementation for any type that implements Error
