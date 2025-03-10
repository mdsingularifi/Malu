use axum::{
    extract::{Path, State},
    Json,
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;
use uuid::Uuid;
use chrono::Utc;

use crate::models::{
    CreateSecretRequest, CreateSecretResponse,
    GetSecretResponse,
    DeleteSecretResponse,
    ListSecretsRequest, ListSecretsResponse,
    ErrorResponse
};
use crate::service::AppState;

/// Create a new secret
pub async fn create_secret(
    State(app_state): State<Arc<AppState>>,
    Json(request): Json<CreateSecretRequest>,
) -> impl IntoResponse {
    // Use default namespace if not provided, and no username
    let namespace = request.namespace.as_deref().unwrap_or("default");
    // Pass None for username for now
    let username: Option<&str> = None;
    // Check if a rotation policy should be created for this secret
    let result = if let Some(true) = request.auto_rotate {
        match app_state.secret_service.store_secret_with_rotation(&request.path, namespace, &request.data, username).await {
            Ok(result) => Ok(result),
            Err(err) => Err(err),
        }
    } else {
        match app_state.secret_service.store_secret(&request.path, namespace, &request.data, username).await {
            Ok(()) => Ok(()),
            Err(err) => Err(err),
        }
    };

    // Track API request
    tracing::info!("Secret API request: endpoint=create_secret status_code=201");
    
    // In the future, consider adding a specialized function to metrics.rs
    // for tracking API requests
    
    match result {
        Ok(_) => {
            let response = CreateSecretResponse {
                path: request.path.clone(),
                created_at: Utc::now(),
            };
            
            (StatusCode::CREATED, Json(response)).into_response()
        },
        Err(err) => {
            let error_response = ErrorResponse {
                message: err.to_string(),
                code: "SECRET_CREATE_ERROR".to_string(),
                error_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
            };
            
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

/// Get a secret by path
pub async fn get_secret(
    State(app_state): State<Arc<AppState>>,
    Path(path): Path<String>,
) -> impl IntoResponse {
    // Use default namespace and no authentication for now
    let namespace = "default";
    let username: Option<&str> = None;
    match app_state.secret_service.retrieve_secret(&path, namespace, username).await {
        Ok(data) => {
            let response = GetSecretResponse {
                path: path.clone(),
                data,
                metadata: None, // We could enhance this in the future
                created_at: Utc::now(), // This should ideally come from storage
                updated_at: Utc::now(), // This should ideally come from storage
            };
            
            (StatusCode::OK, Json(response)).into_response()
        },
        Err(err) => {
            let error_response = ErrorResponse {
                message: err.to_string(),
                code: "SECRET_RETRIEVE_ERROR".to_string(),
                error_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                status_code: StatusCode::NOT_FOUND,
            };
            
            (StatusCode::NOT_FOUND, Json(error_response)).into_response()
        }
    }
}

/// Delete a secret by path
pub async fn delete_secret(
    State(app_state): State<Arc<AppState>>,
    Path(path): Path<String>,
) -> impl IntoResponse {
    // Use default namespace for deletion
    let namespace = "default";
    let username: Option<&str> = None;
    match app_state.secret_service.delete_secret(&path, namespace, username).await {
        Ok(_) => {
            let response = DeleteSecretResponse {
                path: path.clone(),
                success: true,
            };
            
            (StatusCode::OK, Json(response)).into_response()
        },
        Err(err) => {
            let error_response = ErrorResponse {
                message: err.to_string(),
                code: "SECRET_DELETE_ERROR".to_string(),
                error_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
            };
            
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

/// List secrets (optionally filtered by prefix)
pub async fn list_secrets(
    State(app_state): State<Arc<AppState>>,
    Json(request): Json<ListSecretsRequest>,
) -> impl IntoResponse {
    // Use default namespace for listing
    let namespace = request.namespace.as_deref().unwrap_or("default");
    let prefix = request.prefix.as_deref();
    let username: Option<&str> = None;
    match app_state.secret_service.list_secrets(namespace, prefix, username).await {
        Ok(paths) => {
            let response = ListSecretsResponse {
                paths,
            };
            
            (StatusCode::OK, Json(response)).into_response()
        },
        Err(err) => {
            let error_response = ErrorResponse {
                message: err.to_string(),
                code: "SECRET_LIST_ERROR".to_string(),
                error_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
            };
            
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}
