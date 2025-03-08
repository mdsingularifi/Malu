//! Common interfaces for the Malu secure storage system

use async_trait::async_trait;
use std::error::Error;
use std::fmt::Debug;

/// Common result type for all Malu operations
pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

/// Storage engine interface
#[async_trait]
pub trait StorageEngine: Send + Sync + Debug {
    /// Store data with the given key
    async fn store(&self, key: &str, data: &[u8]) -> Result<()>;
    
    /// Retrieve data for the given key
    async fn retrieve(&self, key: &str) -> Result<Vec<u8>>;
    
    /// Check if a key exists
    async fn exists(&self, key: &str) -> Result<bool>;
    
    /// Delete data for the given key
    async fn delete(&self, key: &str) -> Result<()>;
    
    /// List keys with optional prefix
    async fn list_keys(&self, prefix: Option<&str>) -> Result<Vec<String>>;
}

/// Cryptographic provider interface
#[async_trait]
pub trait CryptoProvider: Send + Sync + Debug {
    /// Encrypt data
    async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    
    /// Decrypt data
    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
    
    /// Generate a secure random nonce
    fn generate_nonce(&self, size: usize) -> Result<Vec<u8>>;
    
    /// Derive a key from a password
    fn derive_key(&self, password: &str, salt: &[u8], iterations: u32) -> Result<Vec<u8>>;
}

/// Authentication provider interface
#[async_trait]
pub trait AuthProvider: Send + Sync + Debug {
    /// Authenticate a user
    async fn authenticate(&self, username: &str, password: &str) -> Result<bool>;
    
    /// Verify MFA if required
    async fn verify_mfa(&self, username: &str, token: &str) -> Result<bool>;
    
    /// Check if a user exists
    async fn user_exists(&self, username: &str) -> Result<bool>;
    
    /// Get user information
    async fn get_user_info(&self, username: &str) -> Result<serde_json::Value>;
}

/// Defines versioned entities that support migration
pub trait VersionedEntity {
    /// Get the current version
    fn version(&self) -> u32;
    
    /// Migrate to the latest version
    fn migrate_to_latest(self) -> Self;
}
