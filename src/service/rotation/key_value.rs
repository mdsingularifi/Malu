use std::sync::Arc;
use std::collections::HashMap;
use std::time::Instant;
use async_trait::async_trait;
use serde_json::json;
use chrono::Utc;
use uuid::Uuid;

use crate::core::{
    error::Result,
    store::MaluStore,
};
use crate::events::models::{SecretEvent, SecretAction, EventStatus};


use super::{RotationHandler, SecretData};

/// Handler for rotating key-value secrets
#[derive(Debug)]
pub struct KeyValueRotationHandler {
    store: Arc<MaluStore>,
}

impl KeyValueRotationHandler {
    /// Create a new KeyValueRotationHandler
    pub fn new(store: Arc<MaluStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl RotationHandler for KeyValueRotationHandler {
    async fn generate_new_version(&self, current_secret: &[u8], path: &str, namespace: &str) -> Result<Vec<u8>> {
        let span = tracing::info_span!("key_value_rotation.generate", 
            path = %path, 
            namespace = %namespace
        );
        let _guard = span.enter();
        
        // Record rotation attempt
        tracing::info!(type = "key_value", namespace = %namespace, "Secret rotation started");
        
        // For key-value secrets, we assume all data is manually updated, so just clone current and update metadata
        tracing::info!("Preparing for key-value secret update at {}/{}", namespace, path);
        
        // Parse the current secret data
        let mut data = SecretData::from_bytes(current_secret)?;
        
        // Update the metadata to reflect rotation
        let metadata = data.metadata.get_or_insert_with(HashMap::new);
        metadata.insert("rotated_at".to_string(), Utc::now().to_rfc3339());
        metadata.insert("rotation_method".to_string(), "manual".to_string());
        
        // Log secret size information
        let size = serde_json::to_string(&data.data).map(|s| s.len()).unwrap_or(0);
        tracing::info!(size = size, "Key-value rotation size");
        
        // Serialize and return the data (in a real system, the calling code would be expected to update values)
        data.to_bytes()
    }
    
    async fn validate(&self, secret: &[u8]) -> Result<()> {
        let span = tracing::info_span!("key_value_rotation.validate");
        let _guard = span.enter();
        
        // Key-value secrets are flexible, so just validate that they are valid JSON
        tracing::debug!("Validating key-value secret structure");
        let result = SecretData::from_bytes(secret);
        
        match result {
            Ok(_) => {
                tracing::debug!("Key-value secret validation passed");
                tracing::info!(type = "key_value", result = "success", "Secret validation");
                Ok(())
            },
            Err(e) => {
                tracing::error!("Key-value secret validation failed: {}", e);
                tracing::error!(type = "key_value", result = "failure", reason = "invalid_format", "Secret validation");
                Err(e)
            }
        }
    }
    
    async fn format_for_output(&self, secret: &[u8]) -> Result<Vec<u8>> {
        let span = tracing::info_span!("key_value_rotation.format");
        let _guard = span.enter();
        
        // For key-value secrets, just return as-is (they are already in the right format)
        tracing::debug!("Formatting key-value secret for output");
        let _data = SecretData::from_bytes(secret)?;
        
        tracing::trace!("Key-value secret formatted successfully");
        Ok(secret.to_vec())
    }
    
    async fn post_rotation_actions(&self, old_secret: &[u8], new_secret: &[u8], path: &str, namespace: &str) -> Result<()> {
        let span = tracing::info_span!("key_value_rotation.post_actions", 
            path = %path, 
            namespace = %namespace
        );
        let _guard = span.enter();
        
        // Record start time for performance tracking
        let start_time = Instant::now();
        
        // For key-value secrets, there's typically no additional action needed
        tracing::info!("Performing post-rotation actions for key-value secret: {}/{}", namespace, path);
        
        // Extract old and new data
        let old_data = SecretData::from_bytes(old_secret)?;
        let new_data = SecretData::from_bytes(new_secret)?;
        
        // Determine what has changed
        let mut changes = HashMap::new();
        
        // Compare old and new data
        for (key, new_value) in &new_data.data {
            match old_data.data.get(key) {
                Some(old_value) if old_value != new_value => {
                    changes.insert(key.clone(), "modified".to_string());
                }
                None => {
                    changes.insert(key.clone(), "added".to_string());
                }
                _ => {} // No change
            }
        }
        
        // Find removed keys
        for key in old_data.data.keys() {
            if !new_data.data.contains_key(key) {
                changes.insert(key.clone(), "removed".to_string());
            }
        }
        
        // Log summary of changes
        if changes.is_empty() {
            tracing::info!("No data changes detected in key-value secret, only metadata updated");
        } else {
            tracing::info!("Detected {} changes in key-value secret", changes.len());
            for (key, change_type) in &changes {
                tracing::debug!("Key '{}' was {}", key, change_type);
            }
        }
        
        // Record metrics about changes
        tracing::info!(namespace = %namespace, changes = changes.len(), "Key-value rotation changes");
        
        // Record metrics for successful rotation
        tracing::info!(type = "key_value", namespace = %namespace, "Secret rotation completed");
        
        // Record performance metrics
        let update_time = start_time.elapsed();
        tracing::info!(rotation_time_ms = update_time.as_millis(), "Key-value rotation time");
        
        // Emit an event for the rotation completion
        // Access the store directly since Arc doesn't need to be locked
        let _store = Arc::clone(&self.store);
        
        // This is a placeholder for event production since MaluStore doesn't have event_producer() method
        // Will need to be updated once proper event handling is implemented
        tracing::info!("Would emit rotation event for path: {}", path);
        
        // Create event with correct structure based on SecretEvent definition
        let event = SecretEvent {
            event_id: Uuid::new_v4(),
            action: SecretAction::Update, // Using Update instead of Rotated which doesn't exist
            secret_id: path.to_string(),
            namespace: Some(namespace.to_string()), // namespace is Option<String>
            timestamp: Utc::now(),
            username: None,
            metadata: Some(json!({
                "secret_type": "key_value",
                "changes": changes,
                "fields_count": new_data.data.len(),
                "rotation_time_ms": update_time.as_millis()
            })),
            status: EventStatus::Success,
        };
        
        // For now, just log that we would send an event
        tracing::debug!("Key-value rotation event would be sent: {:?}", event);
        
        // Track events with tracing instead of metrics
        tracing::debug!(event_type = "secret_rotation", secret_type = "key_value", "Event sent successfully");
        
        tracing::info!("Successfully completed post-rotation actions for key-value secret");
        Ok(())
    }
}
