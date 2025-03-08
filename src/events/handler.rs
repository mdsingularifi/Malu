//! Event handler implementation for the Secret Storage Service
//!
//! This module provides the event handler functionality for processing
//! events received from Kafka.

use std::sync::Arc;

use crate::core::error::Result;
use crate::service::secret_service::SecretService;
use super::models::{SecretEvent, AuditEvent, SecretAction, EventStatus};

/// Handler for processing events
#[derive(Clone)]
pub struct EventHandler {
    /// Reference to the secret service
    service: Arc<SecretService>,
}

impl EventHandler {
    /// Create a new event handler
    pub fn new(service: Arc<SecretService>) -> Self {
        Self { service }
    }
    
    /// Handle an incoming event (dispatch to the appropriate handler)
    pub async fn handle_event<T>(&mut self, event: T) -> Result<()> 
    where 
        T: EventPayload,
    {
        event.process(self).await
    }
    
    /// Process a secret event
    pub async fn handle_secret_event(&self, event: SecretEvent) -> Result<()> {
        tracing::info!("Processing secret event: {:?} for secret_id={}, status={:?}", 
            event.action, event.secret_id, event.status);
        
        // Skip processing if the event already has an error status
        if let EventStatus::Error(err) = &event.status {
            tracing::warn!("Skipping event with error status: {}", err);
            return Ok(());
        }

        match event.action {
            // Handle Create/Update operations from other nodes
            SecretAction::Create | SecretAction::Update => {
                if let Some(metadata) = &event.metadata {
                    if let Some(secret_data) = metadata.get("secret_data") {
                        if let Some(secret_str) = secret_data.as_str() {
                            let namespace = event.namespace.as_deref().unwrap_or("default");
                            
                            // Store the secret from the event
                            match self.service.store_secret(
                                &event.secret_id,
                                namespace,
                                secret_str,
                                event.username.as_deref()
                            ).await {
                                Ok(_) => {
                                    tracing::info!("Successfully processed Create/Update event for secret_id={}", event.secret_id);
                                },
                                Err(e) => {
                                    tracing::error!("Failed to process Create/Update event for secret_id={}: {}", event.secret_id, e);
                                    return Err(e);
                                }
                            }
                        } else {
                            tracing::error!("Missing or invalid secret_data in event metadata");
                        }
                    } else {
                        tracing::error!("Missing secret_data field in event metadata");
                    }
                } else {
                    tracing::error!("Missing metadata in Create/Update event");
                }
            }
            
            // Handle Delete operations from other nodes
            SecretAction::Delete => {
                let namespace = event.namespace.as_deref().unwrap_or("default");
                
                // Delete the secret 
                match self.service.delete_secret(
                    &event.secret_id,
                    namespace,
                    event.username.as_deref()
                ).await {
                    Ok(_) => {
                        tracing::info!("Successfully processed Delete event for secret_id={}", event.secret_id);
                    },
                    Err(e) => {
                        tracing::error!("Failed to process Delete event for secret_id={}: {}", event.secret_id, e);
                        return Err(e);
                    }
                }
            }
            
            // For other actions, we don't need to take any action
            _ => {
                tracing::debug!("Ignoring non-actionable secret event: {:?}", event.action);
            }
        }
        
        Ok(())
    }
    
    /// Process an audit event
    pub async fn handle_audit_event(&self, event: AuditEvent) -> Result<()> {
        tracing::info!("Processing audit event: {:?} - {} (status={:?})", 
            event.event_type, event.message, event.status);
        
        // Currently just log the audit event
        // In a production environment, you might want to store these events
        // in a separate database or forward them to a security monitoring system
        
        Ok(())
    }
}

/// Trait for event payloads that can be processed by the handler
pub trait EventPayload {
    /// Process the event using the handler
    async fn process(&self, handler: &EventHandler) -> Result<()>;
}

impl EventPayload for SecretEvent {
    async fn process(&self, handler: &EventHandler) -> Result<()> {
        handler.handle_secret_event(self.clone()).await
    }
}

impl EventPayload for AuditEvent {
    async fn process(&self, handler: &EventHandler) -> Result<()> {
        handler.handle_audit_event(self.clone()).await
    }
}
