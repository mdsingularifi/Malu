// Tests organization for Secret-Storage-Service

// Import the main crate to make its modules available to tests
extern crate secret_storage_service;

// Unit tests
#[cfg(test)]
mod unit;

// Integration tests
#[cfg(test)]
mod integration;

// Common test utilities
#[cfg(test)]
pub mod test_utils {
    use std::sync::Arc;
    use tempfile::TempDir;
    
    use secret_storage_service::core::{
        store::{MaluStore, MaluConfig},
        crypto::AesGcmCryptoProvider,
        auth::token::TokenAuthProvider,
        storage::memory::InMemoryStorageProvider,
        error::Result,
    };
    
    // Create a test MaluStore with in-memory components
    pub async fn create_test_store() -> Result<(Arc<MaluStore>, TempDir)> {
        // Create a temporary directory for test data
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let temp_path = temp_dir.path().to_string_lossy().into_owned();
        
        // Create providers
        let storage_provider = Arc::new(InMemoryStorageProvider::new());
        let crypto_provider = Arc::new(AesGcmCryptoProvider::new_with_random_key()?);
        let auth_provider = Arc::new(TokenAuthProvider::new_with_test_keys()?);
        
        // Create config
        let config = MaluConfig::new(temp_path);
        
        // Create store
        let store = Arc::new(MaluStore::new(
            config,
            storage_provider,
            crypto_provider,
            auth_provider
        ));
        
        Ok((store, temp_dir))
    }
}
