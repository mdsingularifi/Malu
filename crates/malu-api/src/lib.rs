//! API component for the Malu system
//!
//! This module provides a high-level API for interacting with the Malu secure storage system.
//! It abstracts away the details of working with the various providers and configurations.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use malu_interfaces::{AuthProvider, CryptoProvider, Result, StorageEngine};
use malu_core::{MaluConfigBuilder, MaluStore};

/// High-level API for interacting with the Malu secure storage system
pub struct MaluApi {
    store: Arc<MaluStore>,
}

impl MaluApi {
    /// Create a new MaluApi instance with the provided MaluStore
    pub fn new(store: MaluStore) -> Self {
        Self {
            store: Arc::new(store),
        }
    }

    /// Create a builder for configuring and constructing a MaluApi instance
    pub fn builder() -> MaluApiBuilder {
        MaluApiBuilder::new()
    }

    /// Store a secret at the specified path
    pub async fn store_secret(&self, path: &str, secret: &[u8]) -> Result<()> {
        self.store.store_secret(path, secret).await
    }

    /// Retrieve a secret from the specified path
    pub async fn retrieve_secret(&self, path: &str) -> Result<Vec<u8>> {
        self.store.retrieve_secret(path).await
    }

    /// Authenticate a user with the configured auth provider
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<bool> {
        self.store.authenticate(username, password).await
    }

    /// Get the underlying MaluStore instance
    pub fn store(&self) -> Arc<MaluStore> {
        self.store.clone()
    }
}

/// Builder for configuring and constructing a MaluApi instance
pub struct MaluApiBuilder {
    config_builder: MaluConfigBuilder,
    storage_engine: Option<Box<dyn StorageEngine>>,
    crypto_provider: Option<Box<dyn CryptoProvider>>,
    auth_provider: Option<Box<dyn AuthProvider>>,
}

impl Default for MaluApiBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MaluApiBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self {
            config_builder: MaluConfigBuilder::new(),
            storage_engine: None,
            crypto_provider: None,
            auth_provider: None,
        }
    }

    /// Set the storage path for the Malu system
    pub fn with_storage_path(mut self, path: impl Into<PathBuf>) -> Self {
        let path_buf = path.into();
        self.config_builder = self.config_builder.with_storage_path(path_buf);
        self
    }

    /// Set the storage engine implementation
    pub fn with_storage_engine(mut self, storage_engine: Box<dyn StorageEngine>) -> Self {
        self.storage_engine = Some(storage_engine);
        self
    }

    /// Set the crypto provider implementation
    pub fn with_crypto_provider(mut self, crypto_provider: Box<dyn CryptoProvider>) -> Self {
        self.crypto_provider = Some(crypto_provider);
        self
    }

    /// Set the auth provider implementation
    pub fn with_auth_provider(mut self, auth_provider: Box<dyn AuthProvider>) -> Self {
        self.auth_provider = Some(auth_provider);
        self
    }

    /// Build the MaluApi instance with the configured settings
    pub fn build(self) -> std::result::Result<MaluApi, String> {
        let config = self.config_builder.build();

        let storage_engine = self.storage_engine
            .ok_or_else(|| "Storage engine is required".to_string())?;

        let crypto_provider = self.crypto_provider
            .ok_or_else(|| "Crypto provider is required".to_string())?;

        let auth_provider = self.auth_provider
            .ok_or_else(|| "Auth provider is required".to_string())?;

        let store = MaluStore::new(
            config,
            storage_engine,
            crypto_provider,
            auth_provider,
        );

        Ok(MaluApi::new(store))
    }
}

/// Factory trait for creating MaluApi instances with a specific configuration
#[async_trait]
pub trait MaluApiFactory {
    /// Create a new MaluApi instance
    async fn create_api(&self) -> Result<MaluApi>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use malu_interfaces::{self, Error};
    use std::collections::HashMap;
    use std::sync::Mutex;

    // Mock implementations for testing
    struct MockStorageEngine {
        data: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl MockStorageEngine {
        fn new() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl StorageEngine for MockStorageEngine {
        async fn store(&self, path: &str, data: &[u8]) -> Result<()> {
            let mut storage = self.data.lock().unwrap();
            storage.insert(path.to_string(), data.to_vec());
            Ok(())
        }

        async fn retrieve(&self, path: &str) -> Result<Vec<u8>> {
            let storage = self.data.lock().unwrap();
            storage.get(path)
                .cloned()
                .ok_or_else(|| malu_interfaces::Error::NotFound(format!("{} not found", path)).into())
        }

        async fn exists(&self, path: &str) -> Result<bool> {
            let storage = self.data.lock().unwrap();
            Ok(storage.contains_key(path))
        }

        async fn delete(&self, path: &str) -> Result<()> {
            let mut storage = self.data.lock().unwrap();
            storage.remove(path);
            Ok(())
        }

        async fn list_keys(&self, prefix: Option<&str>) -> Result<Vec<String>> {
            let storage = self.data.lock().unwrap();
            let results: Vec<String> = storage.keys()
                .filter(|k| prefix.map_or(true, |p| k.starts_with(p)))
                .cloned()
                .collect();
            Ok(results)
        }
    }

    struct MockCryptoProvider;

    #[async_trait]
    impl CryptoProvider for MockCryptoProvider {
        async fn generate_nonce(&self, length: usize) -> Result<Vec<u8>> {
            // Just return zeroes for testing
            Ok(vec![0u8; length])
        }

        async fn encrypt(&self, _context: &str, data: &[u8], _key: &[u8]) -> Result<Vec<u8>> {
            // Simulate encryption by appending a marker
            let mut result = Vec::with_capacity(data.len() + 9);
            result.extend_from_slice(b"ENCRYPTED");
            result.extend_from_slice(data);
            Ok(result)
        }

        async fn decrypt(&self, _context: &str, data: &[u8], _key: &[u8]) -> Result<Vec<u8>> {
            // Simulate decryption by removing the marker
            if data.len() < 9 || &data[0..9] != b"ENCRYPTED" {
                return Err(malu_interfaces::Error::Crypto("Invalid encrypted data".into()).into());
            }
            Ok(data[9..].to_vec())
        }

        async fn derive_key(&self, passphrase: &[u8], salt: &[u8], _info: Option<&[u8]>) -> Result<Vec<u8>> {
            // Combine passphrase and salt for a deterministic key
            let mut key = Vec::with_capacity(passphrase.len() + salt.len());
            key.extend_from_slice(passphrase);
            key.extend_from_slice(salt);
            Ok(key)
        }

        async fn generate_random(&self, length: usize) -> Result<Vec<u8>> {
            // Just return zeroes for testing
            Ok(vec![0u8; length])
        }

        async fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
            // Simulate hashing (just return the data for testing)
            Ok(data.to_vec())
        }

        async fn sign(&self, message: &[u8], _key: &[u8]) -> Result<Vec<u8>> {
            // For testing, just add a signature prefix
            let mut result = Vec::with_capacity(message.len() + 4);
            result.extend_from_slice(b"SIG-");
            result.extend_from_slice(message);
            Ok(result)
        }

        async fn verify(&self, message: &[u8], signature: &[u8], _key: &[u8]) -> Result<bool> {
            // Check if signature starts with 'SIG-' and contains the message
            if signature.len() < 4 || &signature[0..4] != b"SIG-" {
                return Ok(false);
            }
            Ok(&signature[4..] == message)
        }
    }

    struct MockAuthProvider;

    #[async_trait]
    impl AuthProvider for MockAuthProvider {
        async fn authenticate(&self, username: &str, password: &str) -> Result<bool> {
            // Simple mock authentication
            Ok(username == "test_user" && password == "test_password")
        }

        async fn verify_mfa(&self, username: &str, token: &str) -> Result<bool> {
            // Simple mock MFA verification
            Ok(username == "test_user" && token == "123456")
        }

        async fn user_exists(&self, username: &str) -> Result<bool> {
            // Check if the user exists
            Ok(username == "test_user")
        }

        async fn get_user_info(&self, username: &str) -> Result<serde_json::Value> {
            // Mock user info
            if username == "test_user" {
                Ok(serde_json::json!({
                    "username": "test_user",
                    "email": "test@example.com",
                    "roles": ["user"]
                }))
            } else {
                Err("User not found".into())
            }
        }
    }

    #[tokio::test]
    async fn test_store_and_retrieve() {
        // Create a MaluApi with mock implementations
        let api = MaluApi::builder()
            .with_storage_path("/tmp/malu_test")
            .with_storage_engine(Box::new(MockStorageEngine::new()))
            .with_crypto_provider(Box::new(MockCryptoProvider))
            .with_auth_provider(Box::new(MockAuthProvider))
            .build()
            .unwrap();

        // Store a secret
        let secret = b"my secret data";
        api.store_secret("test/secret1", secret).await.unwrap();

        // Retrieve the secret
        let retrieved = api.retrieve_secret("test/secret1").await.unwrap();
        assert_eq!(retrieved, secret);
    }

    #[tokio::test]
    async fn test_authentication() {
        // Create a MaluApi with mock implementations
        let api = MaluApi::builder()
            .with_storage_path("/tmp/malu_test")
            .with_storage_engine(Box::new(MockStorageEngine::new()))
            .with_crypto_provider(Box::new(MockCryptoProvider))
            .with_auth_provider(Box::new(MockAuthProvider))
            .build()
            .unwrap();

        // Test valid credentials
        let result = api.authenticate("test_user", "test_password").await.unwrap();
        assert!(result);

        // Test invalid credentials
        let result = api.authenticate("test_user", "wrong_password").await.unwrap();
        assert!(!result);
    }
}
