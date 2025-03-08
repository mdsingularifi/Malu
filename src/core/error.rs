use thiserror::Error;
use std::sync::PoisonError;

/// Main error type for the Secret Storage Service
#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Authentication error: {0}")]
    AuthError(String),
    
    #[error("Authorization error: {0}")]
    #[allow(dead_code)]
    AuthorizationError(String),
    
    #[error("Crypto error: {0}")]
    CryptoError(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    /// Alias for ConfigError to maintain backward compatibility
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Secret not found: {0}")]
    NotFound(String),
    
    #[error("Internal error: {0}")]
    #[allow(dead_code)]
    InternalError(String),
    
    #[error("Lock error: {0}")]
    LockError(String),
    
    #[error("External service error: {0}")]
    ExternalServiceError(String),
    
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

impl<T> From<PoisonError<T>> for ServiceError {
    fn from(err: PoisonError<T>) -> Self {
        ServiceError::LockError(err.to_string())
    }
}

/// Result type for the Secret Storage Service
pub type Result<T> = std::result::Result<T, ServiceError>;
