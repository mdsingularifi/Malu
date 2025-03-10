use axum::{
    extract::{Json, Path, Query, State},
    response::IntoResponse,
    http::StatusCode,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
// use std::collections::HashMap;
use chrono::{DateTime, Utc};

use crate::service::AppState;
use crate::models::ErrorResponse;

// Define ApiResponse locally until the models module is updated
#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: T,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data,
        }
    }
    
    pub fn error(error: T) -> Self {
        Self {
            success: false,
            data: error,
        }
    }
}

// Create a wrapper for either success or error responses
#[derive(Debug)]
pub enum ApiResult<T> {
    Success(StatusCode, ApiResponse<T>),
    Error(StatusCode, ApiResponse<ErrorResponse>)
}

impl<T> IntoResponse for ApiResult<T> 
where
    T: Serialize,
{
    fn into_response(self) -> axum::response::Response {
        match self {
            ApiResult::Success(status, data) => {
                (status, Json(data)).into_response()
            },
            ApiResult::Error(status, error) => {
                (status, Json(error)).into_response()
            }
        }
    }
}

impl<T> ApiResult<T> {
    pub fn success(data: T) -> Self {
        ApiResult::Success(StatusCode::OK, ApiResponse::success(data))
    }
    
    pub fn success_with_status(status: StatusCode, data: T) -> Self {
        ApiResult::Success(status, ApiResponse::success(data))
    }
    
    pub fn error(message: String, status: StatusCode) -> Self {
        ApiResult::Error(
            status,
            ApiResponse {
                success: false,
                data: ErrorResponse {
                    message,
                    code: "API_ERROR".to_string(),
                    error_id: uuid::Uuid::new_v4(),
                    timestamp: chrono::Utc::now(),
                    status_code: status,
                },
            }
        )
    }
    
    pub fn from_service_error(err: crate::core::error::ServiceError) -> Self {
        let error = ErrorResponse::from(err);
        ApiResult::Error(error.status_code, ApiResponse {
            success: false,
            data: error,
        })
    }
}

// Using the generic error method instead
// use crate::core::MaluDynamicSecret;

/// Query parameters for listing secrets
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Optional path prefix to filter results
    pub prefix: Option<String>,
}

/// Request for generating a dynamic secret
#[derive(Debug, Deserialize)]
pub struct GenerateDynamicSecretRequest {
    /// Provider type to use
    pub provider_type: String,
    
    /// The path to store the secret at
    pub path: String,
    
    /// Parameters for the secret generation
    pub parameters: serde_json::Value,
    
    /// Time to live in seconds
    pub ttl: Option<u64>,
}

/// Request for renewing a secret lease
#[derive(Debug, Deserialize)]
pub struct RenewDynamicSecretRequest {
    /// New time to live in seconds
    pub ttl: Option<u64>,
}

/// Lease information response
#[derive(Debug, Serialize)]
pub struct LeaseInfoResponse {
    /// Lease ID
    pub id: String,
    
    /// Path the lease is for
    pub path: String,
    
    /// When the lease was created
    pub created_at: DateTime<Utc>,
    
    /// When the lease expires
    pub expires_at: Option<DateTime<Utc>>,
    
    /// Time to live in seconds
    pub ttl: Option<u64>,
    
    /// Provider type that generated this secret
    pub provider_type: String,
}

/// Dynamic secret response
#[derive(Debug, Serialize)]
pub struct DynamicSecretResponse {
    /// Secret lease ID
    pub lease_id: String,
    
    /// Dynamic secret data
    pub data: serde_json::Value,
    
    /// When the secret expires
    pub expires_at: Option<DateTime<Utc>>,
    
    /// Provider type that generated this secret
    pub provider_type: String,
    
    /// Secret metadata
    pub metadata: serde_json::Value,
}

/// Generate a new dynamic secret
pub async fn generate_dynamic_secret(
    State(app_state): State<Arc<AppState>>,
    Json(request): Json<GenerateDynamicSecretRequest>,
) -> impl IntoResponse {
    match app_state.secret_service.generate_dynamic_secret(
        &request.provider_type,
        &request.path,
        &request.parameters,
        request.ttl,
    ).await {
        Ok(secret) => {
            let response = DynamicSecretResponse {
                lease_id: secret.id,
                data: secret.data,
                expires_at: secret.expires_at,
                provider_type: secret.provider_type,
                metadata: secret.metadata,
            };
            
            ApiResult::success_with_status(StatusCode::CREATED, response)
        },
        Err(err) => {
            // Convert service error to match the success case type
            let error = ErrorResponse::from(err);
            ApiResult::<DynamicSecretResponse>::Error(error.status_code, ApiResponse {
                success: false,
                data: error,
            })
        }
    }
}

/// List dynamic secret leases
pub async fn list_dynamic_leases(
    State(app_state): State<Arc<AppState>>,
    Query(query): Query<ListQuery>,
) -> impl IntoResponse {
    match app_state.secret_service.list_dynamic_leases(query.prefix.as_deref()).await {
        Ok(leases) => {
            let responses: Vec<LeaseInfoResponse> = leases.into_iter()
                .map(|lease| {
                    LeaseInfoResponse {
                        id: lease.id,
                        path: lease.path,
                        created_at: lease.created_at,
                        expires_at: lease.expires_at,
                        ttl: lease.ttl,
                        provider_type: lease.provider_type,
                    }
                })
                .collect();
            
            ApiResult::success(responses)
        },
        Err(err) => {
            // Convert service error to match the success case type
            let error = ErrorResponse::from(err);
            ApiResult::<Vec<LeaseInfoResponse>>::Error(error.status_code, ApiResponse {
                success: false,
                data: error,
            })
        }
    }
}

/// Get a specific dynamic secret lease
pub async fn get_dynamic_lease(
    State(app_state): State<Arc<AppState>>,
    Path(lease_id): Path<String>,
) -> impl IntoResponse {
    match app_state.secret_service.get_dynamic_lease(&lease_id).await {
        Ok(lease) => {
            let response = LeaseInfoResponse {
                id: lease.id,
                path: lease.path,
                created_at: lease.created_at,
                expires_at: lease.expires_at,
                ttl: lease.ttl,
                provider_type: lease.provider_type,
            };
            
            ApiResult::success(response)
        },
        Err(err) => {
            // Convert service error to match the success case type
            let error = ErrorResponse::from(err);
            ApiResult::<LeaseInfoResponse>::Error(error.status_code, ApiResponse {
                success: false,
                data: error,
            })
        }
    }
}

/// Revoke a dynamic secret
pub async fn revoke_dynamic_secret(
    State(app_state): State<Arc<AppState>>,
    Path(lease_id): Path<String>,
) -> impl IntoResponse {
    match app_state.secret_service.revoke_dynamic_secret(&lease_id).await {
        Ok(_) => {
            ApiResult::success_with_status(StatusCode::NO_CONTENT, ())
        },
        Err(err) => {
            // Match the response type with the success case
            ApiResult::<()>::from_service_error(err)
        }
    }
}

/// Renew a dynamic secret
pub async fn renew_dynamic_secret(
    State(app_state): State<Arc<AppState>>,
    Path(lease_id): Path<String>,
    Json(request): Json<RenewDynamicSecretRequest>,
) -> impl IntoResponse {
    match app_state.secret_service.renew_dynamic_secret(&lease_id, request.ttl).await {
        Ok(secret) => {
            let response = DynamicSecretResponse {
                lease_id: secret.id,
                data: secret.data,
                expires_at: secret.expires_at,
                provider_type: secret.provider_type,
                metadata: secret.metadata,
            };
            
            ApiResult::success(response)
        },
        Err(err) => {
            // Convert service error to match the success case type
            let error = ErrorResponse::from(err);
            ApiResult::<DynamicSecretResponse>::Error(error.status_code, ApiResponse {
                success: false,
                data: error,
            })
        }
    }
}

/// Create a router for dynamic secrets endpoints
pub fn dynamic_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/dynamic", post(generate_dynamic_secret))
        .route("/api/v1/dynamic", get(list_dynamic_leases))
        .route("/api/v1/dynamic/:lease_id", get(get_dynamic_lease))
        .route("/api/v1/dynamic/:lease_id/revoke", post(revoke_dynamic_secret))
        .route("/api/v1/dynamic/:lease_id/renew", post(renew_dynamic_secret))
}
