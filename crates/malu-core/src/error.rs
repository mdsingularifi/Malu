//! Error types for the Malu system

use thiserror::Error;

/// Error type for Malu operations
#[derive(Error, Debug)]
pub enum MaluError {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    /// Authentication error
    #[error("Authentication error: {0}")]
    Authentication(String),
    
    /// Cryptographic error
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    
    /// Storage error
    #[error("Storage error: {0}")]
    Storage(String),
    
    /// Not found error
    #[error("Not found: {0}")]
    NotFound(String),
    
    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),
    
    /// Not implemented
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    
    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    /// Version mismatch
    #[error("Version mismatch: {0}")]
    VersionMismatch(String),
}

/// Result type for Malu operations
pub type Result<T> = std::result::Result<T, MaluError>;

/// Implement From<&str> for MaluError to allow using the ? operator with string literals
impl From<&str> for MaluError {
    fn from(message: &str) -> Self {
        MaluError::Configuration(message.to_string())
    }
}
