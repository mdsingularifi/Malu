// Models for the Secret Storage Service API
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use axum::http::StatusCode;
use crate::core::error::ServiceError;

/// Rotation configuration for secrets
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RotationConfig {
    /// The type of rotation schedule (interval, daily, weekly, cron)
    #[serde(default)]
    pub schedule_type: Option<String>,
    
    /// Interval in seconds for interval-based schedules
    #[serde(default)]
    pub interval_seconds: Option<u64>,
    
    /// Cron expression for cron-based schedules
    #[serde(default)]
    pub cron_expression: Option<String>,
    
    /// Day of week (0-6, Sunday is 0) for specific day schedules
    #[serde(default)]
    pub day_of_week: Option<u8>,
    
    /// Hour of day (0-23) for specific day schedules
    #[serde(default)]
    pub hour_of_day: Option<u8>,
    
    /// Minute (0-59) for specific day schedules
    #[serde(default)]
    pub minute: Option<u8>,
    
    /// Number of versions to keep (default: 5)
    #[serde(default)]
    pub versions_to_keep: Option<usize>,
}

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

    /// Whether to automatically set up rotation for this secret
    #[serde(default)]
    pub auto_rotate: Option<bool>,

    /// Rotation schedule parameters when auto_rotate is true
    #[serde(default)]
    pub rotation_config: Option<RotationConfig>,
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
    
    /// Status code for HTTP response
    #[serde(skip)]
    pub status_code: StatusCode,
}

impl From<ServiceError> for ErrorResponse {
    fn from(err: ServiceError) -> Self {
        let (code, status_code) = match &err {
            ServiceError::AuthError(_) => ("AUTH_ERROR", StatusCode::UNAUTHORIZED),
            ServiceError::AuthorizationError(_) => ("AUTHORIZATION_ERROR", StatusCode::FORBIDDEN),
            ServiceError::NotFound(_) => ("NOT_FOUND", StatusCode::NOT_FOUND),
            ServiceError::InvalidInput(_) => ("INVALID_INPUT", StatusCode::BAD_REQUEST),
            ServiceError::NotImplemented(_) => ("NOT_IMPLEMENTED", StatusCode::NOT_IMPLEMENTED),
            ServiceError::AlreadyExists(_) => ("ALREADY_EXISTS", StatusCode::CONFLICT),
            _ => ("INTERNAL_ERROR", StatusCode::INTERNAL_SERVER_ERROR),
        };
        
        ErrorResponse {
            message: err.to_string(),
            code: code.to_string(),
            error_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            status_code,
        }
    }
}
