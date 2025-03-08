//! Error types for the auth component

use thiserror::Error;

/// Result type for auth operations
pub type Result<T> = std::result::Result<T, AuthError>;

/// Errors that may occur during auth operations
#[derive(Debug, Error)]
pub enum AuthError {
    /// Authentication failed
    #[error("Authentication failed: {0}")]
    Authentication(String),
    
    /// MFA verification failed
    #[error("MFA verification failed: {0}")]
    MfaVerification(String),
    
    /// User not found
    #[error("User not found: {0}")]
    UserNotFound(String),
    
    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    /// OIDC error 
    #[error("OIDC error: {0}")]
    Oidc(String),
    
    /// LDAP error
    #[error("LDAP error: {0}")]
    Ldap(String),
    
    /// External provider error
    #[error("External provider error: {0}")]
    External(String),
}
