//! Error types for the governance module

use std::fmt;

/// Custom result type for governance operations
pub type Result<T> = std::result::Result<T, GovernanceError>;

/// Error types for governance operations
#[derive(Debug)]
pub enum GovernanceError {
    /// Error with configuration
    ConfigurationError(String),
    
    /// Policy error
    PolicyError(String),
    
    /// Storage error
    StorageError(String),
    
    /// Operation is not supported
    UnsupportedOperation(String),
    
    /// Policy not found
    PolicyNotFound(String),
    
    /// Principal not found
    PrincipalNotFound(String),
    
    /// Permission denied
    PermissionDenied(String),
    
    /// Other error
    Other(String),
}

impl fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GovernanceError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            GovernanceError::PolicyError(msg) => write!(f, "Policy error: {}", msg),
            GovernanceError::StorageError(msg) => write!(f, "Storage error: {}", msg),
            GovernanceError::UnsupportedOperation(msg) => write!(f, "Unsupported operation: {}", msg),
            GovernanceError::PolicyNotFound(msg) => write!(f, "Policy not found: {}", msg),
            GovernanceError::PrincipalNotFound(msg) => write!(f, "Principal not found: {}", msg),
            GovernanceError::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            GovernanceError::Other(msg) => write!(f, "Other error: {}", msg),
        }
    }
}

impl std::error::Error for GovernanceError {}

impl From<serde_json::Error> for GovernanceError {
    fn from(err: serde_json::Error) -> Self {
        GovernanceError::PolicyError(format!("JSON error: {}", err))
    }
}

impl From<std::io::Error> for GovernanceError {
    fn from(err: std::io::Error) -> Self {
        GovernanceError::StorageError(format!("IO error: {}", err))
    }
}
