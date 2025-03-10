use std::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::core::{
    error::{Result, ServiceError},
    MaluDynamicSecret,
    MaluDynamicSecretProvider,
    StorageProviderInstance,
    CryptoProviderInstance,
};

/// Registry for managing dynamic secret providers
pub struct DynamicSecretRegistry {
    /// Map of provider types to provider instances
    providers: RwLock<HashMap<String, Arc<dyn MaluDynamicSecretProvider>>>,
    
    /// Storage for leases
    leases: RwLock<HashMap<String, SecretLease>>,
    
    /// Storage provider for persisting leases
    storage_provider: StorageProviderInstance,
    
    /// Crypto provider for securing leases
    crypto_provider: CryptoProviderInstance,
}

/// A lease for a dynamic secret
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretLease {
    /// Unique identifier for this lease
    pub id: String,
    
    /// The path this lease was created for
    pub path: String,
    
    /// When the lease was created
    pub created_at: DateTime<Utc>,
    
    /// When the lease expires
    pub expires_at: Option<DateTime<Utc>>,
    
    /// Time-to-live in seconds
    pub ttl: Option<u64>,
    
    /// Provider type that generated this secret
    pub provider_type: String,
    
    /// Secret ID
    pub secret_id: String,
    
    /// Additional metadata for the lease
    pub metadata: serde_json::Value,
}

impl DynamicSecretRegistry {
    /// Create a new dynamic secret registry
    pub fn new(
        storage_provider: StorageProviderInstance,
        crypto_provider: CryptoProviderInstance,
    ) -> Self {
        Self {
            providers: RwLock::new(HashMap::new()),
            leases: RwLock::new(HashMap::new()),
            storage_provider,
            crypto_provider,
        }
    }
    
    /// Register a dynamic secret provider
    pub async fn register_provider(&self, provider: Arc<dyn MaluDynamicSecretProvider>) -> Result<()> {
        let provider_type = provider.provider_type().to_string();
        let mut providers = self.providers.write().await;
        
        if providers.contains_key(&provider_type) {
            return Err(ServiceError::InvalidInput(
                format!("Provider with type '{}' already registered", provider_type)
            ));
        }
        
        providers.insert(provider_type, provider);
        Ok(())
    }
    
    /// Get a provider by type
    pub async fn get_provider(&self, provider_type: &str) -> Result<Arc<dyn MaluDynamicSecretProvider>> {
        let providers = self.providers.read().await;
        
        providers.get(provider_type).cloned().ok_or_else(|| {
            ServiceError::NotFound(
                format!("Provider with type '{}' not found", provider_type)
            )
        })
    }
    
    /// Generate a new dynamic secret
    pub async fn generate_secret(
        &self, 
        provider_type: &str, 
        path: &str, 
        params: &serde_json::Value,
        ttl: Option<u64>,
    ) -> Result<MaluDynamicSecret> {
        // Get the provider
        let provider = self.get_provider(provider_type).await?;
        
        // Generate the secret
        let secret = provider.generate(path, params).await?;
        
        // Create a lease
        let lease_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = ttl.map(|ttl_secs| now + Duration::seconds(ttl_secs as i64));
        
        let lease = SecretLease {
            id: lease_id.clone(),
            path: path.to_string(),
            created_at: now,
            expires_at,
            ttl,
            provider_type: provider_type.to_string(),
            secret_id: secret.id.clone(),
            metadata: serde_json::json!({
                "path": path,
                "provider": provider_type,
            }),
        };
        
        // Store the lease
        self.leases.write().await.insert(lease_id, lease);
        self.persist_leases().await?;
        
        Ok(secret)
    }
    
    /// Revoke a secret by lease ID
    pub async fn revoke_secret(&self, lease_id: &str) -> Result<()> {
        let mut leases = self.leases.write().await;
        
        // Find the lease
        let lease = leases.get(lease_id).cloned().ok_or_else(|| {
            ServiceError::NotFound(format!("Lease with ID '{}' not found", lease_id))
        })?;
        
        // Get the provider
        let provider = self.get_provider(&lease.provider_type).await?;
        
        // Revoke the secret
        provider.revoke(&lease.secret_id).await?;
        
        // Remove the lease
        leases.remove(lease_id);
        self.persist_leases().await?;
        
        Ok(())
    }
    
    /// Renew a secret lease
    pub async fn renew_secret(&self, lease_id: &str, ttl: Option<u64>) -> Result<MaluDynamicSecret> {
        let mut leases = self.leases.write().await;
        
        // Find the lease
        let lease = leases.get(lease_id).cloned().ok_or_else(|| {
            ServiceError::NotFound(format!("Lease with ID '{}' not found", lease_id))
        })?;
        
        // Get the provider
        let provider = self.get_provider(&lease.provider_type).await?;
        
        // Renew the secret
        let secret = provider.renew(&lease.secret_id, ttl).await?;
        
        // Update the lease
        let now = Utc::now();
        let expires_at = ttl.map(|ttl_secs| now + Duration::seconds(ttl_secs as i64));
        
        let updated_lease = SecretLease {
            id: lease.id,
            path: lease.path,
            created_at: lease.created_at,
            expires_at,
            ttl,
            provider_type: lease.provider_type,
            secret_id: secret.id.clone(),
            metadata: lease.metadata,
        };
        
        // Store the updated lease
        leases.insert(lease_id.to_string(), updated_lease);
        self.persist_leases().await?;
        
        Ok(secret)
    }
    
    /// List all active leases, optionally filtered by path prefix
    pub async fn list_leases(&self, path_prefix: Option<&str>) -> Result<Vec<SecretLease>> {
        let leases = self.leases.read().await;
        
        let now = Utc::now();
        let filtered_leases = leases
            .values()
            .filter(|lease| {
                // Filter by expiration
                match lease.expires_at {
                    Some(expires) if expires < now => false,
                    _ => true,
                }
            })
            .filter(|lease| {
                // Filter by path prefix if provided
                match path_prefix {
                    Some(prefix) => lease.path.starts_with(prefix),
                    None => true,
                }
            })
            .cloned()
            .collect();
        
        Ok(filtered_leases)
    }
    
    /// Revoke all expired leases
    pub async fn cleanup_expired_leases(&self) -> Result<usize> {
        let leases = self.leases.read().await;
        let now = Utc::now();
        
        let expired_lease_ids: Vec<String> = leases
            .iter()
            .filter(|(_, lease)| {
                match lease.expires_at {
                    Some(expires) if expires < now => true,
                    _ => false,
                }
            })
            .map(|(id, _)| id.clone())
            .collect();
        
        let count = expired_lease_ids.len();
        
        // Revoke each expired lease
        for lease_id in expired_lease_ids {
            if let Err(err) = self.revoke_secret(&lease_id).await {
                eprintln!("Error revoking expired lease {}: {}", lease_id, err);
            }
        }
        
        Ok(count)
    }
    
    /// Persist leases to storage
    async fn persist_leases(&self) -> Result<()> {
        let leases = self.leases.read().await;
        let serialized = serde_json::to_vec(&(*leases)).map_err(|e| {
            ServiceError::InternalError(format!("Failed to serialize leases: {}", e))
        })?;
        
        // Encrypt and store leases
        self.storage_provider.store("dynamic/leases", &serialized).await?;
        
        Ok(())
    }
    
    /// Load leases from storage
    pub async fn load_leases(&self) -> Result<()> {
        match self.storage_provider.retrieve("dynamic/leases").await {
            Ok(data) => {
                let deserialized: HashMap<String, SecretLease> = serde_json::from_slice(&data)
                    .map_err(|e| {
                        ServiceError::InternalError(format!("Failed to deserialize leases: {}", e))
                    })?;
                
                let mut leases = self.leases.write().await;
                *leases = deserialized;
                
                Ok(())
            },
            Err(ServiceError::NotFound(_)) => {
                // No leases found, which is fine for a new system
                Ok(())
            },
            Err(e) => Err(e),
        }
    }
    
    /// Start the lease cleanup task
    pub async fn start_cleanup_task(&self, interval_secs: u64) -> Result<()> {
        let registry = self.clone();
        
        tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(interval_secs);
            let mut ticker = tokio::time::interval(interval);
            
            loop {
                ticker.tick().await;
                
                if let Err(e) = registry.cleanup_expired_leases().await {
                    eprintln!("Error cleaning up expired leases: {}", e);
                }
            }
        });
        
        Ok(())
    }
}

impl Clone for DynamicSecretRegistry {
    fn clone(&self) -> Self {
        // Note: This only clones the references to the inner data, not the data itself
        Self {
            providers: RwLock::new(HashMap::new()),  // Start with empty providers
            leases: RwLock::new(HashMap::new()),     // Start with empty leases
            storage_provider: self.storage_provider.clone(),
            crypto_provider: self.crypto_provider.clone(),
        }
    }
}

/// Database credential provider for dynamic secrets
pub struct DatabaseCredentialProvider {
    /// Provider type identifier
    provider_type: &'static str,
    
    /// Database connection info
    connection_info: serde_json::Value,
    
    /// Admin credentials
    admin_credentials: serde_json::Value,
}

impl DatabaseCredentialProvider {
    /// Create a new database credential provider
    pub fn new(
        connection_info: serde_json::Value,
        admin_credentials: serde_json::Value,
    ) -> Self {
        Self {
            provider_type: "database",
            connection_info,
            admin_credentials,
        }
    }
    
    /// Generate a random username
    fn generate_username(&self, prefix: &str) -> String {
        format!("{}_{}", prefix, Uuid::new_v4().to_string().split('-').next().unwrap())
    }
    
    /// Generate a random password
    fn generate_password(&self) -> String {
        let uuid = Uuid::new_v4();
        format!("p@ss_{}", uuid.to_string().replace("-", ""))
    }
}

#[async_trait]
impl MaluDynamicSecretProvider for DatabaseCredentialProvider {
    fn provider_type(&self) -> &'static str {
        self.provider_type
    }
    
    async fn generate(&self, path: &str, params: &serde_json::Value) -> Result<MaluDynamicSecret> {
        // Extract parameters for database credentials
        let prefix = params.get("username_prefix")
            .and_then(|v| v.as_str())
            .unwrap_or("db_user");
            
        let role = params.get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("readonly");
            
        // Generate credentials
        let username = self.generate_username(prefix);
        let password = self.generate_password();
        
        // In a real implementation, we would connect to the database and create
        // the user with appropriate permissions. For now, we'll simulate this.
        
        // Generate unique ID for this secret
        let secret_id = Uuid::new_v4().to_string();
        
        // Create the secret response
        let secret = MaluDynamicSecret {
            id: secret_id,
            data: serde_json::json!({
                "username": username,
                "password": password,
                "connection_string": format!("postgresql://{}:{}@localhost:5432/mydb", username, password),
            }),
            created_at: Utc::now(),
            expires_at: None,  // Set by the registry based on TTL
            ttl: None,         // Set by the registry
            provider_type: self.provider_type.to_string(),
            metadata: serde_json::json!({
                "database": "postgres",
                "role": role,
                "path": path,
            }),
        };
        
        Ok(secret)
    }
    
    async fn revoke(&self, secret_id: &str) -> Result<()> {
        // In a real implementation, we would connect to the database and remove
        // the user. For now, we'll simulate this.
        
        // Log the revocation
        println!("Revoked database credentials with ID: {}", secret_id);
        
        Ok(())
    }
    
    async fn renew(&self, secret_id: &str, ttl: Option<u64>) -> Result<MaluDynamicSecret> {
        // In a real implementation, we might extend the user's permissions or 
        // rotate the password. For now, we'll simulate this by returning a 
        // modified version of the original secret.
        
        // Generate unique ID for the renewed secret
        let new_secret_id = Uuid::new_v4().to_string();
        
        // Create the secret response
        let secret = MaluDynamicSecret {
            id: new_secret_id,
            data: serde_json::json!({
                "username": format!("renewed_user_{}", secret_id.split('-').next().unwrap()),
                "password": format!("renewed_p@ss_{}", Uuid::new_v4().to_string().replace("-", "")),
                "connection_string": "postgresql://renewed_user:password@localhost:5432/mydb",
            }),
            created_at: Utc::now(),
            expires_at: ttl.map(|t| Utc::now() + Duration::seconds(t as i64)),
            ttl,
            provider_type: self.provider_type.to_string(),
            metadata: serde_json::json!({
                "database": "postgres",
                "original_secret_id": secret_id,
                "renewed": true,
            }),
        };
        
        Ok(secret)
    }
}

/// API token provider for dynamic secrets
pub struct ApiTokenProvider {
    /// Provider type identifier
    provider_type: &'static str,
    
    /// Crypto provider for token generation
    crypto_provider: CryptoProviderInstance,
}

impl ApiTokenProvider {
    /// Create a new API token provider
    pub fn new(crypto_provider: CryptoProviderInstance) -> Self {
        Self {
            provider_type: "api_token",
            crypto_provider,
        }
    }
}

#[async_trait]
impl MaluDynamicSecretProvider for ApiTokenProvider {
    fn provider_type(&self) -> &'static str {
        self.provider_type
    }
    
    async fn generate(&self, path: &str, params: &serde_json::Value) -> Result<MaluDynamicSecret> {
        // Extract parameters for token generation
        let service = params.get("service")
            .and_then(|v| v.as_str())
            .unwrap_or("default");
            
        let scopes = params.get("scopes")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                   .filter_map(|v| v.as_str())
                   .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["read"]);
            
        // Generate a secure random token
        let token_bytes = self.crypto_provider.generate_nonce(32).await?;
        let token = BASE64.encode(&token_bytes);
        
        // Generate unique ID for this secret
        let secret_id = Uuid::new_v4().to_string();
        
        // Create the secret response
        let secret = MaluDynamicSecret {
            id: secret_id,
            data: serde_json::json!({
                "token": token,
                "service": service,
                "scopes": scopes,
            }),
            created_at: Utc::now(),
            expires_at: None,  // Set by the registry based on TTL
            ttl: None,         // Set by the registry
            provider_type: self.provider_type.to_string(),
            metadata: serde_json::json!({
                "service": service,
                "scopes": scopes,
                "path": path,
            }),
        };
        
        Ok(secret)
    }
    
    async fn revoke(&self, secret_id: &str) -> Result<()> {
        // In a real implementation, we would add the token to a revocation list
        // or call an external API to invalidate it. For now, we'll simulate this.
        
        // Log the revocation
        println!("Revoked API token with ID: {}", secret_id);
        
        Ok(())
    }
    
    async fn renew(&self, secret_id: &str, ttl: Option<u64>) -> Result<MaluDynamicSecret> {
        // In a real implementation, we might extend the token's validity or
        // issue a new token. For now, we'll simulate by returning a new token.
        
        // Generate a secure random token
        let token_bytes = self.crypto_provider.generate_nonce(32).await?;
        let token = BASE64.encode(&token_bytes);
        
        // Generate unique ID for the renewed secret
        let new_secret_id = Uuid::new_v4().to_string();
        
        // Create the secret response
        let secret = MaluDynamicSecret {
            id: new_secret_id,
            data: serde_json::json!({
                "token": token,
                "renewed_from": secret_id,
            }),
            created_at: Utc::now(),
            expires_at: ttl.map(|t| Utc::now() + Duration::seconds(t as i64)),
            ttl,
            provider_type: self.provider_type.to_string(),
            metadata: serde_json::json!({
                "original_secret_id": secret_id,
                "renewed": true,
            }),
        };
        
        Ok(secret)
    }
}
