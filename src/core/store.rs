use crate::core::{
    StorageProviderInstance,
    CryptoProviderInstance,
    AuthProviderInstance,
    error::{Result, ServiceError}
};
use std::sync::Arc;
use std::path::Path;
use tokio::fs;
use zeroize::Zeroize;

/// A secure container for sensitive data that is automatically zeroed when dropped
pub struct SecretBytes {
    data: Vec<u8>,
}

impl SecretBytes {
    /// Create a new secure bytes container
    #[allow(dead_code)]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
    
    /// Get reference to the underlying data
    #[allow(dead_code)]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
    
    /// Take ownership of the data, zeroing the original
    #[allow(dead_code)]
    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.data)
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// Configuration for MaluStore
pub struct MaluConfig {
    #[allow(dead_code)]
    pub storage_path: String,
    pub master_key_path: Option<String>,
    pub salt_path: Option<String>,
}

impl MaluConfig {
    pub fn new(storage_path: String) -> Self {
        Self {
            storage_path,
            master_key_path: None,
            salt_path: None,
        }
    }
    
    pub fn with_master_key_path(mut self, path: String) -> Self {
        self.master_key_path = Some(path);
        self
    }
    
    pub fn with_salt_path(mut self, path: String) -> Self {
        self.salt_path = Some(path);
        self
    }
}

/// Main entry point for the MaluStore secure storage system
pub struct MaluStore {
    #[allow(dead_code)]
    config: Arc<MaluConfig>,
    storage_provider: StorageProviderInstance,
    crypto_provider: CryptoProviderInstance,
    auth_provider: AuthProviderInstance,
}

impl MaluStore {
    /// Create a new MaluStore with the provided components
    pub fn new(
        config: MaluConfig,
        storage_provider: StorageProviderInstance,
        crypto_provider: CryptoProviderInstance,
        auth_provider: AuthProviderInstance,
    ) -> Self {
        Self {
            config: Arc::new(config),
            storage_provider,
            crypto_provider,
            auth_provider,
        }
    }
    
    /// Create a builder for constructing a MaluStore
    pub fn builder() -> MaluStoreBuilder {
        MaluStoreBuilder::default()
    }
    
    /// Store a secret in the secure store
    pub async fn store_secret(&self, path: &str, secret: &[u8]) -> Result<()> {
        // Check authentication/authorization here if needed
        
        // Encrypt the secret using the CryptoProvider
        let encrypted = self.crypto_provider.encrypt(secret).await?;
        
        // Store the encrypted data using the StorageProvider
        self.storage_provider.store(path, &encrypted).await?;
        
        Ok(())
    }
    
    /// Retrieve a secret from the secure store
    pub async fn retrieve_secret(&self, path: &str) -> Result<Vec<u8>> {
        // Check authentication/authorization here if needed
        
        // Retrieve the encrypted data using the StorageProvider
        let encrypted = self.storage_provider.retrieve(path).await?;
        
        // Decrypt the data using the CryptoProvider
        let decrypted = self.crypto_provider.decrypt(&encrypted).await?;
        
        Ok(decrypted)
    }
    
    /// Delete a secret from the secure store
    pub async fn delete_secret(&self, path: &str) -> Result<()> {
        // Check authentication/authorization here if needed
        
        // Delete the data using the StorageProvider
        self.storage_provider.delete(path).await?;
        
        Ok(())
    }
    
    /// List all secrets with optional prefix
    pub async fn list_secrets(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        // Check authentication/authorization here if needed
        
        // List all paths using the StorageProvider
        let paths = self.storage_provider.list(prefix).await?;
        
        Ok(paths)
    }
    
    /// Get the system salt for key derivation
    #[allow(dead_code)]
    async fn get_key_derivation_salt(&self) -> Result<Vec<u8>> {
        // Path to the salt file
        let salt_path = match &self.config.salt_path {
            Some(path) => Path::new(path).to_path_buf(),
            None => Path::new(&self.config.storage_path).join("malu-system-salt"),
        };
        
        // Try to read existing salt from file
        if salt_path.exists() {
            match fs::read(&salt_path).await {
                Ok(salt) if !salt.is_empty() => {
                    return Ok(salt);
                }
                _ => {
                    // Fall through to regenerate if file is empty or couldn't be read
                }
            }
        }
        
        // If no salt exists or it couldn't be read, generate a new one
        let salt_length = 32; // 32 bytes = 256 bits
        let salt = self.crypto_provider.generate_nonce(salt_length).await?;
        
        // Create parent directories if they don't exist
        if let Some(parent) = salt_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        
        // Store the salt for future use
        fs::write(&salt_path, &salt).await.map_err(|e| {
            ServiceError::IoError(e)
        })?;
        
        Ok(salt)
    }
    
    /// Authenticate a user
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<bool> {
        self.auth_provider.authenticate(username, password).await
    }
    
    /// Verify a token is valid
    #[allow(dead_code)]
    pub async fn verify_token(&self, token: &str) -> Result<bool> {
        self.auth_provider.verify_token(token).await
    }
}

/// Builder for MaluStore to facilitate flexible construction
pub struct MaluStoreBuilder {
    config: Option<MaluConfig>,
    storage_provider: Option<StorageProviderInstance>,
    crypto_provider: Option<CryptoProviderInstance>,
    auth_provider: Option<AuthProviderInstance>,
}

impl Default for MaluStoreBuilder {
    fn default() -> Self {
        Self {
            config: None,
            storage_provider: None,
            crypto_provider: None,
            auth_provider: None,
        }
    }
}

impl MaluStoreBuilder {
    /// Create a new builder
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Set the configuration
    pub fn with_config(mut self, config: MaluConfig) -> Self {
        self.config = Some(config);
        self
    }
    
    /// Set the storage provider
    pub fn with_storage_provider(mut self, storage_provider: StorageProviderInstance) -> Self {
        self.storage_provider = Some(storage_provider);
        self
    }
    
    /// Set the crypto provider
    pub fn with_crypto_provider(mut self, crypto_provider: CryptoProviderInstance) -> Self {
        self.crypto_provider = Some(crypto_provider);
        self
    }
    
    /// Set the auth provider
    pub fn with_auth_provider(mut self, auth_provider: AuthProviderInstance) -> Self {
        self.auth_provider = Some(auth_provider);
        self
    }
    
    /// Build the MaluStore
    pub fn build(self) -> Result<MaluStore> {
        let config = self.config.ok_or_else(|| {
            ServiceError::ConfigError("Configuration is required".to_string())
        })?;
        
        let storage_provider = self.storage_provider.ok_or_else(|| {
            ServiceError::ConfigError("Storage provider is required".to_string())
        })?;
        
        let crypto_provider = self.crypto_provider.ok_or_else(|| {
            ServiceError::ConfigError("Crypto provider is required".to_string())
        })?;
        
        let auth_provider = self.auth_provider.ok_or_else(|| {
            ServiceError::ConfigError("Auth provider is required".to_string())
        })?;
        
        Ok(MaluStore::new(
            config,
            storage_provider,
            crypto_provider,
            auth_provider,
        ))
    }
}
