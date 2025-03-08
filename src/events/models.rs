//! Event models for the Kafka integration
//!
//! This module defines the event types that are produced and consumed
//! by the Secret Storage Service.

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::fmt;

/// The type of action performed on a secret
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecretAction {
    /// A secret was created
    Create,
    
    /// A secret was retrieved
    Retrieve,
    
    /// A secret was updated
    Update,
    
    /// A secret was deleted
    Delete,
    
    /// Metadata for a secret was retrieved
    GetMetadata,
    
    /// A list of secrets was retrieved
    List,
}

/// Event related to a secret operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEvent {
    /// Unique identifier for the event
    pub event_id: Uuid,
    
    /// The action that was performed
    pub action: SecretAction,
    
    /// The ID of the secret involved
    pub secret_id: String,
    
    /// The namespace of the secret
    pub namespace: Option<String>,
    
    /// The time when the event occurred
    pub timestamp: DateTime<Utc>,
    
    /// The username of the user who performed the action
    pub username: Option<String>,
    
    /// Additional metadata about the event
    pub metadata: Option<serde_json::Value>,
    
    /// The status of the event (success or error with message)
    pub status: EventStatus,
}

/// Status of an event
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EventStatus {
    /// The event was processed successfully
    Success,
    
    /// The event resulted in an error
    Error(String),
}

impl fmt::Display for EventStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventStatus::Success => write!(f, "Success"),
            EventStatus::Error(e) => write!(f, "Error: {}", e),
        }
    }
}

/// The type of audit event
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuditEventType {
    /// Authentication event
    Authentication,
    
    /// Authorization event
    Authorization,
    
    /// System event (startup, shutdown, configuration change)
    System,
    
    /// Admin action
    Admin,
}

/// Audit event for security and compliance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique identifier for the event
    pub event_id: Uuid,
    
    /// The type of audit event
    pub event_type: AuditEventType,
    
    /// A descriptive message about the event
    pub message: String,
    
    /// The time when the event occurred
    pub timestamp: DateTime<Utc>,
    
    /// The username of the user involved (if applicable)
    pub username: Option<String>,
    
    /// The IP address of the client (if applicable)
    pub ip_address: Option<String>,
    
    /// Additional metadata about the event
    pub metadata: Option<serde_json::Value>,
    
    /// The status of the event (success or error with message)
    pub status: EventStatus,
}

impl SecretEvent {
    /// Create a new secret event
    pub fn new(action: SecretAction, secret_id: &str, username: Option<&str>) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            action,
            secret_id: secret_id.to_string(),
            namespace: None,
            timestamp: Utc::now(),
            username: username.map(|u| u.to_string()),
            metadata: None,
            status: EventStatus::Success,
        }
    }
    
    /// Set an error status for the event
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.status = EventStatus::Error(error.into());
        self
    }
    
    /// Set metadata for the event
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
    
    /// Set namespace for the event
    pub fn with_namespace(mut self, namespace: &str) -> Self {
        self.namespace = Some(namespace.to_string());
        self
    }
}

impl AuditEvent {
    /// Create a new audit event
    pub fn new(event_type: AuditEventType, message: &str, username: Option<&str>) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            event_type,
            message: message.to_string(),
            timestamp: Utc::now(),
            username: username.map(|u| u.to_string()),
            ip_address: None,
            metadata: None,
            status: EventStatus::Success,
        }
    }
    
    /// Set an error status for the event
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.status = EventStatus::Error(error.into());
        self
    }
    
    /// Set metadata for the event
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
    
    /// Set IP address for the event
    pub fn with_ip_address(mut self, ip_address: &str) -> Self {
        self.ip_address = Some(ip_address.to_string());
        self
    }
}
