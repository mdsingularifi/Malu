use std::sync::Arc;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;
use std::str::FromStr;
use cron::Schedule;
use async_trait::async_trait;
use sha2::{Sha256, Digest};

// Standard mutex for thread safety
use std::sync::Mutex as StdMutex;

// Export the rotation handler modules
pub mod api_token;
pub mod database;
pub mod encryption_key;
pub mod key_value;
pub mod ssh_key;
pub mod tls_certificate;

// Re-export the handlers directly for easier access
pub use api_token::ApiTokenRotationHandler;
pub use database::DatabaseRotationHandler;
pub use encryption_key::EncryptionKeyRotationHandler;
pub use key_value::KeyValueRotationHandler;
pub use ssh_key::SshKeyRotationHandler;
pub use tls_certificate::TlsCertificateRotationHandler;

use crate::core::{
    error::{Result, ServiceError},
    store::MaluStore,
};


/// Helper function to create a hash string representation of input data
/// Used for logging and verification purposes
pub fn hash_string(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    format!("sha256:{}", hex::encode(&result[..8])) // Just first 8 bytes for brevity
}

/// Data structure for secrets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretData {
    /// Key-value pairs that make up the secret
    pub data: HashMap<String, String>,
    /// Optional binary data (for certificates, keys, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_data: Option<Vec<u8>>,
    /// Optional metadata about the secret
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
}

impl SecretData {
    /// Create a new SecretData instance
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
            binary_data: None,
            metadata: None,
        }
    }
    
    /// Convert SecretData to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| ServiceError::SerializationError(format!("Failed to serialize secret data: {}", e)))
    }
    
    /// Create SecretData from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| ServiceError::DeserializationError(format!("Failed to deserialize secret data: {}", e)))
    }
}

/// Secret rotation schedule types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RotationSchedule {
    /// Rotate on a fixed interval (in days)
    Interval { days: u32 },
    /// Rotate on a cron schedule
    Cron { expression: String },
    /// Rotate on a specific date and time
    FixedTime { datetime: DateTime<Utc> },
    /// Rotate manually only (no automatic rotation)
    Manual,
}

/// Secret type enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SecretType {
    KeyValue,
    Database { db_type: String },
    ApiToken { token_type: String },
    SshKey,
    TlsCertificate,
    EncryptionKey { key_type: String },
}

impl SecretType {
    /// Create an appropriate rotation handler for this secret type
    pub fn create_handler(&self, store: Arc<MaluStore>) -> Box<dyn RotationHandler> {
        match self {
            SecretType::KeyValue => Box::new(KeyValueRotationHandler::new(Arc::clone(&store))),
            SecretType::Database { db_type } => Box::new(DatabaseRotationHandler::new(Arc::clone(&store), db_type.clone())),
            SecretType::ApiToken { token_type } => Box::new(ApiTokenRotationHandler::new(Arc::clone(&store), token_type.clone())),
            SecretType::SshKey => Box::new(SshKeyRotationHandler::new(Arc::clone(&store))),
            SecretType::TlsCertificate => Box::new(TlsCertificateRotationHandler::new(Arc::clone(&store))),
            SecretType::EncryptionKey { key_type } => Box::new(EncryptionKeyRotationHandler::new(Arc::clone(&store), key_type.clone())),
        }
    }
}

/// Trait defining common behavior for secret rotation handlers
#[async_trait]
pub trait RotationHandler: Send + Sync + std::fmt::Debug + 'static {
    /// Generate a new version of the secret
    async fn generate_new_version(&self, current_secret: &[u8], path: &str, namespace: &str) -> Result<Vec<u8>>;
    
    /// Validate the secret structure and required fields
    async fn validate(&self, secret: &[u8]) -> Result<()>;
    
    /// Format the secret for output (e.g., adding helpful formatting, documentation)
    async fn format_for_output(&self, secret: &[u8]) -> Result<Vec<u8>>;
    
    /// Perform any actions needed after rotation (e.g. deploying certs, updating configs)
    async fn post_rotation_actions(&self, old_secret: &[u8], new_secret: &[u8], path: &str, namespace: &str) -> Result<()>;
}

/// Secret rotation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// Unique name for the policy
    pub name: String,
    /// Rotation schedule
    pub schedule: RotationSchedule,
    /// Path pattern for secrets that this policy applies to (glob format)
    pub path_pattern: String,
    /// Namespace this policy applies to
    pub namespace: String,
    /// Whether rotation happens automatically or requires manual trigger
    pub automatic: bool,
    /// How many previous versions to keep
    pub versions_to_keep: u32,
    /// Type of secret (to determine rotation handler)
    pub secret_type: SecretType,
    /// When this secret was last rotated
    pub last_rotated: Option<DateTime<Utc>>,
    /// When this secret should next be rotated
    pub next_rotation: Option<DateTime<Utc>>,
}

impl RotationPolicy {
    /// Create a new rotation policy
    pub fn new(
        name: String,
        schedule: RotationSchedule,
        path_pattern: String,
        namespace: String,
        automatic: bool,
        versions_to_keep: u32,
        secret_type: SecretType,
    ) -> Self {
        let mut policy = Self {
            name,
            schedule,
            path_pattern,
            namespace,
            automatic,
            versions_to_keep,
            secret_type,
            last_rotated: None,
            next_rotation: None,
        };
        
        // Calculate the next rotation time
        policy.next_rotation = policy.calculate_next_rotation();
        
        policy
    }
    
    /// Calculate the next rotation time based on this policy
    pub fn calculate_next_rotation(&self) -> Option<DateTime<Utc>> {
        match &self.schedule {
            RotationSchedule::Manual => None, // Manual rotation has no schedule
            RotationSchedule::Interval { days } => {
                let now = Utc::now();
                
                // If we have a last rotation time, base it off that
                if let Some(last) = self.last_rotated {
                    Some(last + chrono::Duration::days(*days as i64))
                } else {
                    // Otherwise, schedule from now
                    Some(now + chrono::Duration::days(*days as i64))
                }
            },
            RotationSchedule::FixedTime { datetime } => {
                let now = Utc::now();
                
                // If the fixed time is in the future, use it
                if datetime > &now {
                    Some(*datetime)
                } else {
                    // Otherwise, the fixed time has passed, so no future rotation
                    None
                }
            },
            RotationSchedule::Cron { expression } => {
                // Parse the cron expression
                match Schedule::from_str(expression) {
                    Ok(schedule) => {
                        let _now = Utc::now();
                        
                        // Get the next occurrence after now
                        match schedule.upcoming(Utc).next() {
                            Some(next) => Some(next),
                            None => None,
                        }
                    },
                    Err(_) => None, // Invalid cron expression
                }
            },
        }
    }
    
    /// Check if it's time to rotate based on this policy
    pub fn should_rotate(&self) -> bool {
        if !self.automatic {
            return false; // Never automatically rotate if not set to automatic
        }
        
        if let Some(next) = self.next_rotation {
            let now = Utc::now();
            next <= now
        } else {
            false
        }
    }
}

/// Status of a secret lease
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LeaseStatus {
    /// Lease is active and valid
    Active,
    /// Lease is expired
    Expired,
    /// Lease was explicitly revoked
    Revoked,
}

/// Secret lease tracking information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretLease {
    /// Unique ID for the lease
    pub id: String,
    /// Path to the secret
    pub path: String,
    /// Namespace of the secret
    pub namespace: String,
    /// Version of the secret
    pub version: u32,
    /// TTL in seconds for this lease
    pub ttl: Option<u64>,
    /// When the lease was created
    pub created_at: DateTime<Utc>,
    /// When the lease expires
    pub expires_at: Option<DateTime<Utc>>,
    /// When the lease was last renewed
    pub last_renewed: Option<DateTime<Utc>>,
    /// Current status of the lease
    pub status: LeaseStatus,
    /// Who created this lease
    pub created_by: Option<String>,
    /// Consumers of this secret (services, apps, etc.)
    pub consumers: Vec<String>,
}

impl SecretLease {
    /// Create a new secret lease
    pub fn new(
        path: String,
        namespace: String,
        version: u32,
        ttl: Option<u64>,
        created_by: Option<String>,
    ) -> Self {
        let id = Uuid::new_v4().to_string();
        let created_at = Utc::now();
        
        // Calculate expiration time if TTL is provided
        let expires_at = ttl.map(|seconds| {
            created_at + chrono::Duration::seconds(seconds as i64)
        });
        
        SecretLease {
            id,
            path,
            namespace,
            version,
            ttl,
            created_at,
            expires_at,
            last_renewed: None,
            status: LeaseStatus::Active,
            created_by,
            consumers: Vec::new(),
        }
    }
    
    /// Check if the lease is expired
    pub fn is_expired(&self) -> bool {
        if self.status != LeaseStatus::Active {
            return true;
        }
        
        if let Some(expires_at) = self.expires_at {
            let now = Utc::now();
            now > expires_at
        } else {
            false // No expiration = never expires
        }
    }
    
    /// Renew the lease
    pub fn renew(&mut self) -> Result<DateTime<Utc>> {
        if self.status != LeaseStatus::Active {
            return Err(ServiceError::InvalidInput(
                format!("Cannot renew lease with status {:?}", self.status)
            ));
        }
        
        let now = Utc::now();
        self.last_renewed = Some(now);
        
        // Update expiration time if TTL is set
        if let Some(ttl) = self.ttl {
            let new_expires = now + chrono::Duration::seconds(ttl as i64);
            self.expires_at = Some(new_expires);
            Ok(new_expires)
        } else {
            Ok(now) // No expiration
        }
    }
    
    /// Add a consumer to this lease
    pub fn add_consumer(&mut self, consumer_id: String) {
        if !self.consumers.contains(&consumer_id) {
            self.consumers.push(consumer_id);
        }
    }
}

/// Secret version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    /// Version number
    pub version: u32,
    /// When this version was created
    pub created_at: DateTime<Utc>,
    /// Who created this version
    pub created_by: Option<String>,
    /// Whether this is the current active version
    pub active: bool,
    /// Secret data for this version
    pub data: Vec<u8>,
    /// Metadata about this version
    pub metadata: Option<HashMap<String, String>>,
    /// Leases for this version
    pub leases: Vec<String>,
}
