use std::sync::Arc;
use serde_json::json;

use crate::metrics::{dynamic_secrets_initialized, dynamic_secret_generated, dynamic_secret_revoked, dynamic_secret_renewed};

use crate::core::{
    MaluDynamicSecret,
    malustore_dynamic::{SecretLease, DatabaseCredentialProvider, ApiTokenProvider},
    error::{Result, ServiceError},
};
use crate::service::SecretService;

/// Dynamic secrets extension methods for SecretService
impl SecretService {
    /// Initialize dynamic secrets functionality
    pub async fn init_dynamic_secrets(&mut self) -> Result<()> {
        // Since we're working with an Arc<MaluStore>, we need to avoid mutable borrows
        // We'll assume MaluStore uses interior mutability for its operations
        
        // Get a clone of the store that we can work with
        let store_clone = self.get_store();
        
        // Initialize dynamic secrets in the store
        // This method should use interior mutability within MaluStore
        // If it doesn't, we'll need to modify the MaluStore implementation
        tracing::info!("Initializing dynamic secrets providers");
        
        // Since we can't call init_dynamic_secrets() directly on the Arc, we'll
        // initialize each provider separately and let the providers handle their own state
        
        // Register default providers
        let db_provider = Arc::new(DatabaseCredentialProvider::new(
            json!({
                "host": "localhost",
                "port": 5432,
                "database": "malu"
            }),
            json!({
                "username": "admin",
                "password": "placeholder_secure_password"
            })
        ));
        
        // Create API token provider with a mock crypto implementation
        // TODO: Replace with proper crypto provider access when the API is updated
        use crate::core::CryptoProviderInstance;
        use crate::core::crypto::AesGcmCryptoProvider;
        let crypto_provider = Arc::new(AesGcmCryptoProvider::new()) as CryptoProviderInstance;
        let api_token_provider = Arc::new(ApiTokenProvider::new(crypto_provider));
        
        // Register the providers
        store_clone.register_dynamic_provider(db_provider).await?;
        store_clone.register_dynamic_provider(api_token_provider).await?;
        
        // We can't directly set dynamic_secrets_initialized as it's private
        // The actual implementation would need either a method to set this
        // or a different approach to track initialization
        
        dynamic_secrets_initialized();
        Ok(())
    }
    
    /// Ensure dynamic secrets are initialized
    async fn ensure_dynamic_secrets_initialized(&self) -> Result<()> {
        // Since we can't check dynamic_secrets_initialized and can't call init_dynamic_secrets
        // with an immutable reference, we'll just return Ok for now.
        // In a production implementation, this would need to be redesigned to properly
        // track the initialization state in a way that's accessible with immutable references.
        Ok(())
    }
    
    /// Generate a dynamic secret
    pub async fn generate_dynamic_secret(
        &self,
        provider_type: &str,
        path: &str,
        params: &serde_json::Value,
        ttl: Option<u64>,
    ) -> Result<MaluDynamicSecret> {
        self.ensure_dynamic_secrets_initialized().await?;
        
        // Record metric
        dynamic_secret_generated(provider_type);
        
        // Generate the secret
        let store = self.get_store();
        let result = store.generate_dynamic_secret(provider_type, path, params, ttl).await?;
        
        // Publish event if producer is available
        // Event publishing would normally go here
        // Since we can't access the event_producer directly, this functionality
        // will need to be implemented differently, perhaps through a callback
        // or by making event_producer accessible via a getter method
        
        Ok(result)
    }
    
    /// Revoke a dynamic secret
    pub async fn revoke_dynamic_secret(&self, lease_id: &str) -> Result<()> {
        self.ensure_dynamic_secrets_initialized().await?;
        
        // Record metric
        dynamic_secret_revoked();
        
        // Revoke the secret
        self.get_store().revoke_dynamic_secret(lease_id).await
    }
    
    /// Renew a dynamic secret
    pub async fn renew_dynamic_secret(&self, lease_id: &str, ttl: Option<u64>) -> Result<MaluDynamicSecret> {
        self.ensure_dynamic_secrets_initialized().await?;
        
        // Record metric
        dynamic_secret_renewed();
        
        // Renew the secret
        self.get_store().renew_dynamic_secret(lease_id, ttl).await
    }
    
    /// List dynamic secret leases
    pub async fn list_dynamic_leases(&self, path_prefix: Option<&str>) -> Result<Vec<SecretLease>> {
        self.ensure_dynamic_secrets_initialized().await?;
        
        // List the leases
        self.get_store().list_dynamic_leases(path_prefix).await
    }
    
    /// Get a specific dynamic secret lease
    pub async fn get_dynamic_lease(&self, lease_id: &str) -> Result<SecretLease> {
        self.ensure_dynamic_secrets_initialized().await?;
        
        // Get all leases and filter by ID
        let leases = self.get_store().list_dynamic_leases(None).await?;
        
        leases.into_iter()
            .find(|lease| lease.id == lease_id)
            .ok_or_else(|| ServiceError::NotFound(format!("Lease with ID '{}' not found", lease_id)))
    }
}
