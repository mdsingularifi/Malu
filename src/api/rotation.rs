use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},

    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    metrics,
    models::ErrorResponse,
    service::{
        rotation_service::{RotationPolicy, RotationSchedule, SecretType},
        AppState,
    },
};

/// Struct for creating a new rotation policy
#[derive(Debug, Deserialize)]
pub struct CreateRotationPolicyRequest {
    /// Path for the secret that will be rotated
    pub secret_path: String,
    
    /// Optional description for the rotation policy
    #[serde(default)]
    pub description: Option<String>,
    
    /// Rotation schedule configuration
    pub schedule: RotationScheduleRequest,
    
    /// Optional - number of versions to keep. Default is 5.
    #[serde(default)]
    pub versions_to_keep: Option<usize>,
    
    /// Optional - rotate the secret immediately after policy is created
    #[serde(default)]
    pub auto_rotate_on_create: Option<bool>,
}

/// Rotation schedule configuration for API
#[derive(Debug, Deserialize, Clone)]
pub struct RotationScheduleRequest {
    /// Type of schedule (interval, daily, weekly, monthly, cron)
    pub schedule_type: String,
    
    /// For interval schedules, seconds between rotations
    pub interval_seconds: Option<u64>,
    
    /// For daily schedules, hour of day to rotate (0-23)
    pub hour_of_day: Option<u8>,
    
    /// For weekly schedules, day of week (0-6, where 0 is Sunday)
    pub day_of_week: Option<u8>,
    
    /// Cron expression for advanced schedules
    pub cron_expression: Option<String>,
}

/// Struct for rotation policy response
#[derive(Debug, Serialize)]
pub struct RotationPolicyResponse {
    /// Unique ID for the rotation policy
    pub id: Uuid,
    
    /// Path for the secret that will be rotated
    pub secret_path: String,
    
    /// Description for the rotation policy
    pub description: Option<String>,
    
    /// Rotation schedule configuration
    pub schedule: RotationScheduleResponse,
    
    /// Number of versions to keep before pruning
    pub versions_to_keep: usize,
    
    /// Whether to rotate the secret immediately after policy creation
    pub auto_rotate_on_create: bool,
    
    /// When the policy was created
    pub created_at: DateTime<Utc>,
    
    /// When the secret was last rotated
    pub last_rotated: Option<DateTime<Utc>>,
    
    /// When the next rotation is scheduled for
    pub next_rotation: Option<DateTime<Utc>>,
}

/// Rotation schedule response
#[derive(Debug, Serialize)]
pub struct RotationScheduleResponse {
    /// Type of schedule as a string
    pub schedule_type: String,
    
    /// Human-readable description of the schedule
    pub description: String,
}

impl From<RotationScheduleRequest> for RotationSchedule {
    fn from(req: RotationScheduleRequest) -> Self {
        match req.schedule_type.to_lowercase().as_str() {
            "interval" => {
                if let Some(seconds) = req.interval_seconds {
                    RotationSchedule::Interval { seconds }
                } else {
                    // Default to 24 hours if no interval specified
                    RotationSchedule::Interval { seconds: 86400 }
                }
            }
            "daily" => {
                let hour = req.hour_of_day.unwrap_or(0);
                // Single day at specified hour
                RotationSchedule::DaysOfWeek { 
                    days: vec![0], // Sunday
                    hour 
                }
            }
            "weekly" => {
                let day = req.day_of_week.unwrap_or(0);
                let hour = req.hour_of_day.unwrap_or(0);
                RotationSchedule::DaysOfWeek { 
                    days: vec![day],
                    hour 
                }
            }
            "monthly" => {
                let day = req.day_of_week.unwrap_or(1); // Default to 1st day of month
                let hour = req.hour_of_day.unwrap_or(0);
                RotationSchedule::DaysOfMonth {
                    days: vec![day as u8],
                    hour
                }
            }
            "cron" => {
                if let Some(cron) = req.cron_expression {
                    RotationSchedule::Cron { expression: cron }
                } else {
                    // Default to daily at midnight if no cron specified
                    RotationSchedule::Cron { expression: "0 0 * * *".to_string() }
                }
            }
            _ => RotationSchedule::Interval { seconds: 86400 }, // Default to 24 hours
        }
    }
}



/// Create the rotation routes
pub fn rotation_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/rotation/policies", get(list_policies).post(create_policy))
        .route("/api/v1/rotation/policies/:id", get(get_policy).delete(delete_policy))
        .route("/api/v1/rotation/policies/:id/execute", post(execute_rotation))
}

/// List all rotation policies
async fn list_policies(State(state): State<Arc<AppState>>) -> (StatusCode, Json<serde_json::Value>) {
    metrics::record_request("list_policies", 200);
    let service = &state.secret_service;
    
    // Get rotation policies with proper error handling
    let policies_result = service.get_rotation_policies().await;
    
    match policies_result {
        Ok(policies) => {
            let response: Vec<RotationPolicyResponse> = policies
                .into_iter()
                .map(|policy| RotationPolicyResponse {
                    id: Uuid::parse_str(&policy.id).unwrap_or_else(|_| Uuid::new_v4()),
                    secret_path: policy.path_pattern.clone(),
                    description: Some(policy.name.clone()),
                    schedule: RotationScheduleResponse {
                        schedule_type: format!("{:?}", policy.schedule).split_whitespace().next().unwrap_or("Unknown").to_string(),
                        description: format!("{:?}", policy.schedule),
                    },
                    versions_to_keep: policy.versions_to_keep as usize,
                    auto_rotate_on_create: policy.automatic,
                    created_at: policy.created_at,
                    last_rotated: policy.last_rotated,
                    next_rotation: policy.calculate_next_rotation(),
                })
                .collect();
            
            // Return successful response
            (StatusCode::OK, Json(serde_json::to_value(response).unwrap()))
        },
        Err(err) => {
            // Return error response
            let error_response = ErrorResponse {
                message: format!("Failed to retrieve rotation policies: {}", err),
                code: "POLICY_LIST_ERROR".to_string(),
                error_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::to_value(error_response).unwrap()))
        }
    }
}

/// Get a specific rotation policy by ID
async fn get_policy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> (StatusCode, Json<serde_json::Value>) {
    metrics::record_request("get_policy", 200);
    let service = &state.secret_service;
    
    // Get all policies and find the one with the matching ID
    let policies_result = service.get_rotation_policies().await;
    
    match policies_result {
        Ok(policies) => {
            let policy = policies.iter().find(|p| p.id == id.to_string());
            
            match policy {
                Some(policy) => {
                    let response = RotationPolicyResponse {
                        id: Uuid::parse_str(&policy.id).unwrap_or_else(|_| Uuid::new_v4()),
                        secret_path: policy.path_pattern.clone(),
                        description: Some(policy.name.clone()),
                        schedule: RotationScheduleResponse {
                            schedule_type: format!("{:?}", policy.schedule).split_whitespace().next().unwrap_or("Unknown").to_string(),
                            description: format!("{:?}", policy.schedule),
                        },
                        versions_to_keep: policy.versions_to_keep as usize,
                        auto_rotate_on_create: policy.automatic,
                        created_at: policy.created_at,
                        last_rotated: policy.last_rotated,
                        next_rotation: policy.calculate_next_rotation(),
                    };
                    
                    (StatusCode::OK, Json(serde_json::to_value(response).unwrap()))
                },
                None => {
                    // Policy not found
                    let error_response = ErrorResponse {
                        message: format!("Rotation policy with ID {} not found", id),
                        code: "POLICY_NOT_FOUND".to_string(),
                        error_id: Uuid::new_v4(),
                        timestamp: Utc::now(),
                        status_code: StatusCode::NOT_FOUND,
                    };
                    (StatusCode::NOT_FOUND, Json(serde_json::to_value(error_response).unwrap()))
                }
            }
        },
        Err(err) => {
            // Error retrieving policies
            let error_response = ErrorResponse {
                message: format!("Failed to retrieve rotation policies: {}", err),
                code: "POLICY_LIST_ERROR".to_string(),
                error_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::to_value(error_response).unwrap()))
        }
    }
}

/// Create a new rotation policy
async fn create_policy(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateRotationPolicyRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    metrics::record_request("create_policy", 201);
    let service = &state.secret_service;
    
    // Convert the request schedule to a RotationSchedule
    let rotation_schedule = request.schedule.clone();
    let schedule = RotationSchedule::from(rotation_schedule);
    
    // Create a new RotationPolicy
    let policy = RotationPolicy {
        id: Uuid::new_v4().to_string(),
        name: format!("rotation-{}", Uuid::new_v4()),
        schedule,
        path_pattern: request.secret_path.clone(),
        namespace: "default".to_string(),
        automatic: true,
        versions_to_keep: request.versions_to_keep.unwrap_or(5) as u32,
        secret_type: SecretType::KeyValue,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_rotated: None
    };
    
    // Add the policy with proper error handling
    let result = service
        .add_rotation_policy(policy.clone())
        .await;
        
    match result {
        Ok(_) => {
            // Successfully added the policy
            let response = RotationPolicyResponse {
                id: Uuid::parse_str(&policy.id).unwrap_or_else(|_| Uuid::nil()),
                secret_path: policy.path_pattern.clone(),
                description: Some(policy.name.clone()),
                schedule: RotationScheduleResponse {
                    schedule_type: format!("{:?}", policy.schedule).split_whitespace().next().unwrap_or("Unknown").to_string(),
                    description: format!("{:?}", policy.schedule),
                },
                versions_to_keep: policy.versions_to_keep as usize,
                auto_rotate_on_create: policy.automatic,
                created_at: policy.created_at,
                last_rotated: policy.last_rotated,
                next_rotation: policy.calculate_next_rotation(),
            };
            
            (StatusCode::CREATED, Json(serde_json::to_value(response).unwrap()))
        },
        Err(err) => {
            // Failed to add the policy
            let error_response = ErrorResponse {
                message: format!("Failed to add rotation policy: {}", err),
                code: "POLICY_CREATE_ERROR".to_string(),
                error_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
            };
            
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::to_value(error_response).unwrap()))
        }
    }
}

/// Delete a rotation policy
async fn delete_policy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> (StatusCode, Json<serde_json::Value>) {
    metrics::record_request("delete_policy", 204);
    let service = &state.secret_service;
    
    // First, check if the policy exists
    let policies_result = service.get_rotation_policies().await;
    
    match policies_result {
        Ok(policies) => {
            let policy = policies.into_iter().find(|p| p.id == id.to_string());
            
            if policy.is_none() {
                // Policy not found
                let error_response = ErrorResponse {
                    message: format!("Rotation policy with ID {} not found", id),
                    code: "POLICY_NOT_FOUND".to_string(),
                    error_id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    status_code: StatusCode::NOT_FOUND,
                };
                return (StatusCode::NOT_FOUND, Json(serde_json::to_value(error_response).unwrap()));
            }
            
            // Currently there's no direct method to remove a policy by ID
            // This would need to be implemented in the RotationService
            // Return a clear error message for now
            let error_response = ErrorResponse {
                message: format!("Deletion of rotation policy with ID {} is not yet implemented", id),
                code: "NOT_IMPLEMENTED".to_string(),
                error_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                status_code: StatusCode::NOT_IMPLEMENTED,
            };
            (StatusCode::NOT_IMPLEMENTED, Json(serde_json::to_value(error_response).unwrap()))
        },
        Err(err) => {
            // Error retrieving policies
            let error_response = ErrorResponse {
                message: format!("Failed to retrieve rotation policies: {}", err),
                code: "POLICY_LIST_ERROR".to_string(),
                error_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::to_value(error_response).unwrap()))
        }
    }
}

/// Execute a rotation manually
async fn execute_rotation(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> (StatusCode, Json<serde_json::Value>) {
    metrics::record_request("execute_rotation", 200);
    let service = &state.secret_service;
    
    // Rotate the secret
    // Get all policies and find the one with the matching ID
    let policies_result = service.get_rotation_policies().await;
    
    // Handle potential error from getting policies
    let policies = match policies_result {
        Ok(policies) => policies,
        Err(err) => {
            let error_response = ErrorResponse {
                message: format!("Failed to get rotation policies: {}", err),
                code: "POLICY_LIST_ERROR".to_string(),
                error_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::to_value(error_response).unwrap()));
        }
    };
    
    // Find the policy with matching ID
    let policy = policies.into_iter()
        .find(|p| p.id == id.to_string());
        
    let policy = match policy {
        Some(p) => p,
        None => {
            let error_response = ErrorResponse {
                message: format!("Rotation policy with ID {} not found", id),
                code: "POLICY_NOT_FOUND".to_string(),
                error_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                status_code: StatusCode::NOT_FOUND,
            };
            return (StatusCode::NOT_FOUND, Json(serde_json::to_value(error_response).unwrap()));
        }
    };
    
    // Policy is now handled in the previous block
    
    let rotation_result = service.rotate_secret(&policy.path_pattern, "default", None).await;
    if let Err(err) = rotation_result {
        // Return error response
        let error_response = ErrorResponse {
            message: format!("Failed to rotate secret: {}", err),
            code: "ROTATION_ERROR".to_string(),
            error_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
        };
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::to_value(error_response).unwrap()));
    }
    
    // Get the updated policy to return
    // Get all policies again after rotation to get the updated policy
    let policies_result = service.get_rotation_policies().await;
    
    match policies_result {
        Ok(policies) => {
            let updated_policy = policies.into_iter().find(|p| p.id == id.to_string());
            
            match updated_policy {
                Some(updated_policy) => {
                    let response = RotationPolicyResponse {
                        id: Uuid::parse_str(&updated_policy.id).unwrap_or_else(|_| Uuid::nil()),
                        secret_path: updated_policy.path_pattern.clone(),
                        description: Some(updated_policy.name.clone()),
                        schedule: RotationScheduleResponse {
                            schedule_type: format!("{:?}", updated_policy.schedule).split_whitespace().next().unwrap_or("Unknown").to_string(),
                            description: format!("{:?}", updated_policy.schedule),
                        },
                        versions_to_keep: updated_policy.versions_to_keep as usize,
                        auto_rotate_on_create: updated_policy.automatic,
                        created_at: updated_policy.created_at,
                        last_rotated: updated_policy.last_rotated,
                        next_rotation: updated_policy.calculate_next_rotation(),
                    };
                    
                    (StatusCode::OK, Json(serde_json::to_value(response).unwrap()))
                },
                None => {
                    // Handle case where rotation succeeded but policy couldn't be found afterwards
                    let error_response = ErrorResponse {
                        message: format!("Secret rotated but policy with ID {} not found after rotation", id),
                        code: "POLICY_NOT_FOUND_AFTER_ROTATION".to_string(),
                        error_id: Uuid::new_v4(),
                        timestamp: Utc::now(),
                        status_code: StatusCode::NOT_FOUND,
                    };
                    (StatusCode::NOT_FOUND, Json(serde_json::to_value(error_response).unwrap()))
                }
            }
        },
        Err(err) => {
            // Return error if policy retrieval fails
            let error_response = ErrorResponse {
                message: format!("Policy rotation succeeded but failed to retrieve updated policy: {}", err),
                code: "POLICY_RETRIEVAL_ERROR".to_string(),
                error_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::to_value(error_response).unwrap()))
        }
    }
}
