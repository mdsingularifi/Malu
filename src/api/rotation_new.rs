use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, delete},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    core::error::{Result, ServiceError},
    metrics,
    service::{rotation_service::RotationSchedule, AppState},
    models::ErrorResponse,
};
