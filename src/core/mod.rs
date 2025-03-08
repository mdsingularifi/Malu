pub mod error;
pub mod crypto;
pub mod storage;
pub mod auth;
pub mod store;

use async_trait::async_trait;
use std::sync::Arc;
use error::Result;

/// Provider for storage operations
#[async_trait]
pub trait StorageProvider: Send + Sync {
    /// Store data at the specified path
    async fn store(&self, path: &str, data: &[u8]) -> Result<()>;
    
    /// Retrieve data from the specified path
    async fn retrieve(&self, path: &str) -> Result<Vec<u8>>;
    
    /// Delete data at the specified path
    async fn delete(&self, path: &str) -> Result<()>;
    
    /// List all paths with an optional prefix
    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>>;
    
    /// Check if a path exists
    async fn exists(&self, path: &str) -> Result<bool>;
}

/// Provider for cryptographic operations
#[async_trait]
pub trait CryptoProvider: Send + Sync {
    /// Encrypt data
    async fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
    
    /// Decrypt data
    async fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>>;
    
    /// Generate a random nonce/iv of specified length
    async fn generate_nonce(&self, length: usize) -> Result<Vec<u8>>;
    
    /// Derive a key from input material
    #[allow(dead_code)]
    async fn derive_key(&self, input: &[u8]) -> Result<Vec<u8>>;
    
    /// Hash a value
    #[allow(dead_code)]
    async fn hash(&self, data: &[u8]) -> Result<Vec<u8>>;
}

/// Provider for authentication operations
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Authenticate a user with username and password
    async fn authenticate(&self, username: &str, password: &str) -> Result<bool>;
    
    /// Verify if a token is valid
    async fn verify_token(&self, token: &str) -> Result<bool>;
    
    /// Get user ID from token
    #[allow(dead_code)]
    async fn get_user_id_from_token(&self, token: &str) -> Result<String>;
}

/// Type aliases for provider instances
pub type StorageProviderInstance = Arc<dyn StorageProvider>;
pub type CryptoProviderInstance = Arc<dyn CryptoProvider>;
pub type AuthProviderInstance = Arc<dyn AuthProvider>;
