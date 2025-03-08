//! Integration tests for the malu-storage module

use std::sync::Arc;
use malu_interfaces::AuthProvider;
use malu_core::{MaluStore, MaluConfigBuilder};
use malu_crypto::SoftwareCryptoProvider;
use crate::{MemoryStorage, create_encrypted_storage, create_default_crypto_provider};

// Simple mock auth provider for testing
#[derive(Debug)]
struct MockAuthProvider;

#[async_trait::async_trait]
impl AuthProvider for MockAuthProvider {
    async fn authenticate(&self, _username: &str, _password: &str) -> malu_interfaces::Result<bool> {
        Ok(true)
    }
    
    async fn verify_mfa(&self, _username: &str, _token: &str) -> malu_interfaces::Result<bool> {
        Ok(true)
    }
    
    async fn user_exists(&self, _username: &str) -> malu_interfaces::Result<bool> {
        Ok(true)
    }
    
    async fn get_user_info(&self, _username: &str) -> malu_interfaces::Result<serde_json::Value> {
        Ok(serde_json::json!({"username": _username}))
    }
}

#[tokio::test]
async fn test_encrypted_storage_with_malu_store() {
    // Create a memory storage engine
    let storage = Box::new(MemoryStorage::new());
    
    // Create a crypto provider
    let crypto_provider = create_default_crypto_provider();
    
    // Create a salt for key derivation
    let salt = b"test-salt-for-key-derivation".to_vec();
    
    // Create an encrypted storage wrapper
    let encrypted_storage = create_encrypted_storage(
        storage,
        Arc::clone(&crypto_provider),
        &salt
    );
    
    // Create a basic config
    let config = MaluConfigBuilder::new()
        .build();
    
    // Create a mock auth provider
    let auth_provider = Box::new(MockAuthProvider);
    
    // Create a new crypto provider for MaluStore
    // We need to create a concrete implementation, not just an Arc wrapper
    let crypto_for_store = Box::new(SoftwareCryptoProvider::new());
    
    // Create MaluStore using our components
    let malu_store = MaluStore::new(
        config,
        encrypted_storage,
        crypto_for_store,
        auth_provider
    );
    
    // Test data
    let secret_path = "test/secret";
    let secret_data = b"This is a secret value that should be encrypted";
    
    // Store the secret
    malu_store.store_secret(secret_path, secret_data).await
        .expect("Failed to store secret");
    
    // Retrieve the secret
    let retrieved = malu_store.retrieve_secret(secret_path).await
        .expect("Failed to retrieve secret");
    
    // Verify the secret is intact
    assert_eq!(retrieved, secret_data);
    
    // This demonstrates the successful integration of:
    // 1. Our new crypto implementation
    // 2. The storage module with encryption capability
    // 3. The MaluStore pattern (instead of the old Vault pattern)
}
