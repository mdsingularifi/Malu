// Models for the Secret Storage Service API
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Request for creating or updating a secret
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSecretRequest {
    /// The path where the secret will be stored
    pub path: String,
    
    /// The secret data, encoded as base64
    pub data: String,
    
    /// Optional namespace for the secret, defaults to "default" if not provided
    #[serde(default)]
    pub namespace: Option<String>,
    
    /// Optional metadata for the secret
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Response for create/update secret operations
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSecretResponse {
    /// The path where the secret is stored
    pub path: String,
    
    /// When the secret was created/updated
    pub created_at: DateTime<Utc>,
}

/// Request for retrieving a secret
#[derive(Debug, Serialize, Deserialize)]
pub struct GetSecretRequest {
    /// The path of the secret to retrieve
    pub path: String,
}

/// Response for retrieving a secret
#[derive(Debug, Serialize, Deserialize)]
pub struct GetSecretResponse {
    /// The path of the secret
    pub path: String,
    
    /// The secret data, encoded as base64
    pub data: String,
    
    /// Optional metadata for the secret
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    
    /// When the secret was created
    pub created_at: DateTime<Utc>,
    
    /// When the secret was last updated
    pub updated_at: DateTime<Utc>,
}

/// Request for listing secrets
#[derive(Debug, Serialize, Deserialize)]
pub struct ListSecretsRequest {
    /// Optional prefix to filter secrets by
    #[serde(default)]
    pub prefix: Option<String>,
    
    /// Optional namespace to filter secrets by (defaults to "default")
    #[serde(default)]
    pub namespace: Option<String>,
}

/// Response for listing secrets
#[derive(Debug, Serialize, Deserialize)]
pub struct ListSecretsResponse {
    /// List of secret paths
    pub paths: Vec<String>,
}

/// Request for deleting a secret
#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteSecretRequest {
    /// The path of the secret to delete
    pub path: String,
}

/// Response for deleting a secret
#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteSecretResponse {
    /// The path of the deleted secret
    pub path: String,
    
    /// Whether the delete operation was successful
    pub success: bool,
}

/// Authentication request
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    /// Username for authentication
    pub username: String,
    
    /// Password for authentication
    pub password: String,
}

/// Authentication response
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    /// Authentication token
    pub token: String,
    
    /// When the token expires
    pub expires_at: DateTime<Utc>,
}

/// Error response
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Error message
    pub message: String,
    
    /// Error code
    pub code: String,
    
    /// Error ID for tracking
    pub error_id: Uuid,
    
    /// Timestamp of when the error occurred
    pub timestamp: DateTime<Utc>,
}
