//! Error types for storage operations


use thiserror::Error;

/// Result type for storage operations
pub type Result<T> = std::result::Result<T, StorageError>;

/// Errors that can occur in storage operations
#[derive(Error, Debug)]
pub enum StorageError {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    /// Path error
    #[error("Path error: {0}")]
    Path(String),
    
    /// Not found error
    #[error("Not found: {0}")]
    NotFound(String),
    
    /// Already exists error
    #[error("Already exists: {0}")]
    AlreadyExists(String),
    
    /// Lock error
    #[error("Lock error: {0}")]
    Lock(String),
    
    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
    
    /// S3 error
    #[cfg(feature = "s3-storage")]
    #[error("S3 error: {0}")]
    S3(String),
}

impl From<StorageError> for malu_interfaces::Result<()> {
    fn from(error: StorageError) -> Self {
        Err(Box::new(error))
    }
}

impl From<StorageError> for malu_interfaces::Result<Vec<u8>> {
    fn from(error: StorageError) -> Self {
        Err(Box::new(error))
    }
}

impl From<StorageError> for malu_interfaces::Result<Vec<String>> {
    fn from(error: StorageError) -> Self {
        Err(Box::new(error))
    }
}

impl From<StorageError> for malu_interfaces::Result<bool> {
    fn from(error: StorageError) -> Self {
        Err(Box::new(error))
    }
}
