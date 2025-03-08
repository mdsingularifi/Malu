//! Core functionality for the Malu secure storage system

mod config;
mod error;
// Other modules will go here

pub use config::{
    MaluConfig, ConfigVersion, AuthConfig, CryptoConfig, 
    AuthProviderType, CryptoProviderType, OidcConfig,
    MaluConfigBuilder
};
pub use error::{MaluError, Result};

use malu_interfaces::{StorageEngine, CryptoProvider, AuthProvider};
use std::sync::Arc;

/// Main entry point for the Malu system
pub struct MaluStore {
    #[allow(dead_code)]
    config: Arc<MaluConfig>,
    storage_engine: Box<dyn StorageEngine>,
    crypto_provider: Box<dyn CryptoProvider>,
    auth_provider: Box<dyn AuthProvider>,
}

impl MaluStore {
    /// Create a new MaluStore with the provided components
    pub fn new(
        config: MaluConfig,
        storage_engine: Box<dyn StorageEngine>,
        crypto_provider: Box<dyn CryptoProvider>,
        auth_provider: Box<dyn AuthProvider>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            storage_engine,
            crypto_provider,
            auth_provider,
        }
    }
    
    /// Create a builder for constructing a MaluStore
    pub fn builder() -> MaluStoreBuilder {
        MaluStoreBuilder::new()
    }
    
    /// Store a secret in the secure store
    pub async fn store_secret(&self, path: &str, secret: &[u8]) -> malu_interfaces::Result<()> {
        // Encrypt the secret
        let encrypted = self.crypto_provider.encrypt(secret).await?;
        
        // Store the encrypted data
        self.storage_engine.store(path, &encrypted).await?;
        
        Ok(())
    }
    
    /// Retrieve a secret from the secure store
    pub async fn retrieve_secret(&self, path: &str) -> malu_interfaces::Result<Vec<u8>> {
        // Retrieve the encrypted data
        let encrypted = self.storage_engine.retrieve(path).await?;
        
        // Decrypt the data
        let decrypted = self.crypto_provider.decrypt(&encrypted).await?;
        
        Ok(decrypted)
    }
    
    /// Authenticate a user
    pub async fn authenticate(&self, username: &str, password: &str) -> malu_interfaces::Result<bool> {
        self.auth_provider.authenticate(username, password).await
    }
}

/// Builder for MaluStore to facilitate flexible construction
pub struct MaluStoreBuilder {
    config: Option<MaluConfig>,
    storage_engine: Option<Box<dyn StorageEngine>>,
    crypto_provider: Option<Box<dyn CryptoProvider>>,
    auth_provider: Option<Box<dyn AuthProvider>>,
}

impl Default for MaluStoreBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MaluStoreBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: None,
            storage_engine: None,
            crypto_provider: None,
            auth_provider: None,
        }
    }
    
    /// Set the configuration
    pub fn with_config(mut self, config: MaluConfig) -> Self {
        self.config = Some(config);
        self
    }
    
    /// Set the storage engine
    pub fn with_storage_engine(mut self, storage_engine: Box<dyn StorageEngine>) -> Self {
        self.storage_engine = Some(storage_engine);
        self
    }
    
    /// Set the crypto provider
    pub fn with_crypto_provider(mut self, crypto_provider: Box<dyn CryptoProvider>) -> Self {
        self.crypto_provider = Some(crypto_provider);
        self
    }
    
    /// Set the auth provider
    pub fn with_auth_provider(mut self, auth_provider: Box<dyn AuthProvider>) -> Self {
        self.auth_provider = Some(auth_provider);
        self
    }
    
    /// Build the MaluStore
    pub fn build(self) -> Result<MaluStore> {
        let config = self.config.ok_or("Configuration is required")?;
        let storage_engine = self.storage_engine.ok_or("Storage engine is required")?;
        let crypto_provider = self.crypto_provider.ok_or("Crypto provider is required")?;
        let auth_provider = self.auth_provider.ok_or("Auth provider is required")?;
        
        Ok(MaluStore::new(
            config,
            storage_engine,
            crypto_provider,
            auth_provider,
        ))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
