//! Common interfaces for the Malu secure storage system

// Import async-trait with specific version to avoid build issues
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
    /// Generate a cryptographically secure nonce
    async fn generate_nonce(&self, length: usize) -> Result<Vec<u8>>;

    /// Encrypt data with authentication context and key
    async fn encrypt(&self, context: &str, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>>;
    
    /// Decrypt data with authentication context and key
    async fn decrypt(&self, context: &str, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>>;
    
    /// Derive a key from the given inputs
    async fn derive_key(&self, passphrase: &[u8], salt: &[u8], info: Option<&[u8]>) -> Result<Vec<u8>>;
    
    /// Generate cryptographically secure random bytes
    async fn generate_random(&self, length: usize) -> Result<Vec<u8>>;
    
    /// Hash data using the default hash algorithm
    async fn hash(&self, data: &[u8]) -> Result<Vec<u8>>;
    
    /// Sign a message using the given key
    async fn sign(&self, message: &[u8], key: &[u8]) -> Result<Vec<u8>>;
    
    /// Verify a signature using the given key
    async fn verify(&self, message: &[u8], signature: &[u8], key: &[u8]) -> Result<bool>;
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

/// Governance provider interface for policy management and access control
#[async_trait]
pub trait GovernanceProvider: Send + Sync + Debug {
    /// Check if a user has permission to perform an action on a resource
    async fn check_permission(&self, user_id: &str, action: &str, resource: &str) -> Result<bool>;
    
    /// Create or update a policy
    async fn set_policy(&self, policy_id: &str, policy_definition: &str) -> Result<()>;
    
    /// Get a policy by ID
    async fn get_policy(&self, policy_id: &str) -> Result<String>;
    
    /// Delete a policy by ID
    async fn delete_policy(&self, policy_id: &str) -> Result<()>;
    
    /// List policies with optional prefix
    async fn list_policies(&self, prefix: Option<&str>) -> Result<Vec<String>>;
    
    /// Assign a policy to a user or group
    async fn assign_policy(&self, policy_id: &str, principal_id: &str, principal_type: PrincipalType) -> Result<()>;
    
    /// Revoke a policy from a user or group
    async fn revoke_policy(&self, policy_id: &str, principal_id: &str, principal_type: PrincipalType) -> Result<()>;
    
    /// List policies assigned to a principal
    async fn list_principal_policies(&self, principal_id: &str, principal_type: PrincipalType) -> Result<Vec<String>>;
}

/// Type of principal for governance operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrincipalType {
    /// Individual user
    User,
    
    /// Group of users
    Group,
    
    /// Role that can be assigned to users or groups
    Role,
}
