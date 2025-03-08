//! Encrypted storage wrapper for StorageEngine implementations
//! 
//! This module provides a wrapper around any StorageEngine implementation
//! that automatically handles encryption and decryption using a CryptoProvider.

use std::sync::Arc;
use std::fmt::{self, Debug, Formatter};
use async_trait::async_trait;
use malu_interfaces::{StorageEngine, CryptoProvider, Result};
use malu_crypto::SoftwareCryptoProvider;

/// Provides encrypted storage capabilities by wrapping any storage engine implementation
/// and encrypting/decrypting data using the provided crypto provider
pub struct EncryptedStorage {
    storage_engine: Box<dyn StorageEngine>,
    crypto_provider: Arc<dyn CryptoProvider>,
    key_derivation_salt: Vec<u8>,
}

// Implement Debug trait for EncryptedStorage
impl Debug for EncryptedStorage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedStorage")
            .field("key_derivation_salt_length", &self.key_derivation_salt.len())
            .finish()
    }
}

impl EncryptedStorage {
    /// Create a new encrypted storage wrapper with the provided storage engine and crypto provider
    pub fn new(
        storage_engine: Box<dyn StorageEngine>,
        crypto_provider: Arc<dyn CryptoProvider>,
        key_derivation_salt: Vec<u8>,
    ) -> Self {
        Self {
            storage_engine,
            crypto_provider,
            key_derivation_salt,
        }
    }
    
    /// Derive an encryption key based on the path and salt
    async fn derive_key(&self, path: &str) -> Result<Vec<u8>> {
        // Use path as the input for key derivation
        let passphrase = path.as_bytes();
        
        // Derive a unique key for this path
        self.crypto_provider.derive_key(passphrase, &self.key_derivation_salt, None).await
    }
}

#[async_trait]
impl StorageEngine for EncryptedStorage {
    async fn store(&self, key: &str, data: &[u8]) -> Result<()> {
        // Derive encryption key for this path
        let encryption_key = self.derive_key(key).await?;
        
        // Use path as context for encryption
        let context = key;
        
        // Encrypt the data
        let encrypted_data = self.crypto_provider.encrypt(context, data, &encryption_key).await?;
        
        // Store the encrypted data
        self.storage_engine.store(key, &encrypted_data).await
    }
    
    async fn retrieve(&self, key: &str) -> Result<Vec<u8>> {
        // Retrieve the encrypted data
        let encrypted_data = self.storage_engine.retrieve(key).await?;
        
        // Derive the same key used for encryption
        let encryption_key = self.derive_key(key).await?;
        
        // Use path as context for decryption
        let context = key;
        
        // Decrypt the data
        self.crypto_provider.decrypt(context, &encrypted_data, &encryption_key).await
    }
    
    async fn exists(&self, key: &str) -> Result<bool> {
        // Use the underlying storage engine to check existence
        self.storage_engine.exists(key).await
    }
    
    async fn delete(&self, key: &str) -> Result<()> {
        // Use the underlying storage engine to delete
        self.storage_engine.delete(key).await
    }
    
    async fn list_keys(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        // Use the underlying storage engine to list keys
        self.storage_engine.list_keys(prefix).await
    }
}

/// Create an encrypted wrapper around any storage engine
pub fn create_encrypted_storage(
    storage_engine: Box<dyn StorageEngine>,
    crypto_provider: Arc<dyn CryptoProvider>,
    salt: &[u8],
) -> Box<dyn StorageEngine> {
    Box::new(EncryptedStorage::new(
        storage_engine,
        crypto_provider,
        salt.to_vec(),
    ))
}

/// Create a default crypto provider implementation
pub fn create_default_crypto_provider() -> Arc<dyn CryptoProvider> {
    Arc::new(SoftwareCryptoProvider::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStorage;
    
    #[tokio::test]
    async fn test_encrypted_storage() {
        // Create a memory storage engine
        let storage = Box::new(MemoryStorage::new());
        
        // Create a crypto provider
        let crypto = create_default_crypto_provider();
        
        // Create a salt
        let salt = b"test-salt-for-encryption".to_vec();
        
        // Create an encrypted storage wrapper
        let encrypted_storage = EncryptedStorage::new(storage, crypto, salt);
        
        // Test data
        let key = "test/key";
        let data = b"This is a secret message!";
        
        // Store the data
        encrypted_storage.store(key, data).await.unwrap();
        
        // Retrieve the data
        let retrieved = encrypted_storage.retrieve(key).await.unwrap();
        
        // Verify the data is the same
        assert_eq!(retrieved, data);
    }
}
