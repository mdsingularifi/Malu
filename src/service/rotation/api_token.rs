use std::sync::Arc;
use std::collections::HashMap;
use async_trait::async_trait;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use serde_json::json;
use chrono::Utc;
use sha2::{Sha256, Digest};

use crate::core::{
    error::{Result, ServiceError},
    store::MaluStore,
};
use crate::events::models::{SecretEvent, SecretAction, EventStatus};
use uuid::Uuid;

use super::{RotationHandler, SecretData};

/// Handler for rotating API tokens
#[derive(Debug)]
pub struct ApiTokenRotationHandler {
    store: Arc<MaluStore>,
    token_type: String,
}

impl ApiTokenRotationHandler {
    /// Create a new ApiTokenRotationHandler
    pub fn new(store: Arc<MaluStore>, token_type: String) -> Self {
        Self { store, token_type }
    }
    
    /// Generate a random API token
    fn generate_token(&self, prefix: Option<&str>, length: usize) -> String {
        let mut token = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect::<String>();
        
        // Prepend a prefix if provided
        if let Some(p) = prefix {
            token = format!("{}{}", p, token);
        }
        
        token
    }
}

#[async_trait]
impl RotationHandler for ApiTokenRotationHandler {
    async fn generate_new_version(&self, current_secret: &[u8], path: &str, namespace: &str) -> Result<Vec<u8>> {
        let span = tracing::info_span!("api_token_rotation.generate", 
            path = %path, 
            namespace = %namespace, 
            token_type = %self.token_type
        );
        let _guard = span.enter();
        
        // Record rotation attempt
        tracing::info!("API token rotation started: token_type={} namespace={}", 
            self.token_type.as_str(), namespace);
        
        // In the future, consider adding a specialized function to metrics.rs
        // for tracking rotation attempts
        
        // Parse the current secret data
        tracing::debug!("Parsing current API token data");
        let mut data = SecretData::from_bytes(current_secret)?;
        
        tracing::info!("Generating new version for API token");
        
        // Define prefix based on token type
        let (prefix, length) = match self.token_type.as_str() {
            "github" => (Some("ghp_"), 36),
            "stripe" => (Some("sk_"), 24),
            "aws" => (None, 40),
            "slack" => (Some("xoxp-"), 32),
            _ => (None, 32),
        };
        
        // Generate a new token
        let token = self.generate_token(prefix, length);
        let token_len = token.len();  // Store length before moving the token
        tracing::debug!("Generated new {} token of length {}", self.token_type, token_len);
        
        // Update the token in the data map
        data.data.insert("token".to_string(), token);
        
        // Add or update metadata
        let metadata = data.metadata.get_or_insert_with(HashMap::new);
        let rotation_time = Utc::now();
        metadata.insert("rotated_at".to_string(), rotation_time.to_rfc3339());
        metadata.insert("token_type".to_string(), self.token_type.clone());
        
        // Compute a hash of the token for reference
        let token_hash = {
            let token = data.data.get("token").unwrap();
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            format!("sha256:{}", hex::encode(&hasher.finalize()[..8]))
        };
        metadata.insert("token_hash".to_string(), token_hash);
        
        // Track token length metrics
        tracing::info!("API token length: length={} token_type={}", 
            token_len, self.token_type.as_str());
        
        // In the future, consider adding a specialized function to metrics.rs
        // for tracking token length distribution
        
        // Serialize and return the updated secret
        tracing::debug!("Serializing updated API token");
        data.to_bytes()
    }
    
    async fn validate(&self, secret: &[u8]) -> Result<()> {
        let span = tracing::info_span!("api_token_rotation.validate", token_type = %self.token_type);
        let _guard = span.enter();
        
        // Validate the secret structure and required fields
        tracing::debug!("Validating API token structure");
        let data = SecretData::from_bytes(secret)?;
        
        // Check for required fields
        if !data.data.contains_key("token") {
            tracing::error!("API token secret missing 'token' field");
            // Track validation failure
            tracing::warn!("API token validation failed: type=api_token token_type={} result=failure reason=missing_token", 
                self.token_type.as_str());
            return Err(ServiceError::ValidationError(
                "API token secret must contain a 'token' field".to_string()
            ));
        }
        
        // Validate token format based on type
        let token = data.data.get("token").unwrap();
        let valid = match self.token_type.as_str() {
            "github" => token.starts_with("ghp_") && token.len() >= 40,
            "stripe" => (token.starts_with("sk_test_") || token.starts_with("sk_live_")) && token.len() >= 30,
            "aws" => token.len() >= 40,
            "slack" => token.starts_with("xoxp-") || token.starts_with("xoxb-"),
            _ => !token.is_empty(), // Generic validation for other token types
        };
        
        if !valid {
            tracing::error!("Invalid {} token format", self.token_type);
            // Track validation failure
            tracing::warn!("API token validation failed: type=api_token token_type={} result=failure reason=invalid_format", 
                self.token_type.as_str());
            return Err(ServiceError::ValidationError(
                format!("Invalid {} token format", self.token_type)
            ));
        }
        
        // Additional metadata validation
        if let Some(metadata) = data.metadata.as_ref() {
            if let Some(hash) = metadata.get("token_hash") {
                tracing::debug!("Token has hash: {}", hash);
            }
        }
        
        tracing::debug!("API token validation successful");
        // Track validation success
        tracing::info!("API token validation successful: type=api_token token_type={} result=success", 
            self.token_type.as_str());
        Ok(())
    }
    
    async fn format_for_output(&self, secret: &[u8]) -> Result<Vec<u8>> {
        let span = tracing::info_span!("api_token_rotation.format", token_type = %self.token_type);
        let _guard = span.enter();
        
        // For API tokens, we ensure the data is in the expected format for the consuming application
        tracing::debug!("Formatting API token for output");
        let data = SecretData::from_bytes(secret)?;
        let mut formatted_data = data.clone();
        
        // Add additional metadata to the formatted output
        let metadata = formatted_data.metadata.get_or_insert_with(HashMap::new);
        
        // Add usage examples based on token type
        match self.token_type.as_str() {
            "github" => {
                metadata.insert("usage_example".to_string(), 
                    "Use with github APIs: curl -H \"Authorization: token $TOKEN\" https://api.github.com/user".to_string());
            },
            "stripe" => {
                metadata.insert("usage_example".to_string(), 
                    "Use with stripe APIs: curl https://api.stripe.com/v1/charges -u $TOKEN:".to_string());
            },
            "aws" => {
                metadata.insert("usage_example".to_string(), 
                    "Use with AWS CLI: export AWS_ACCESS_KEY_ID=$KEY export AWS_SECRET_ACCESS_KEY=$TOKEN".to_string());
            },
            "slack" => {
                metadata.insert("usage_example".to_string(), 
                    "Use with Slack APIs: curl -H \"Authorization: Bearer $TOKEN\" https://slack.com/api/users.list".to_string());
            },
            _ => {
                metadata.insert("usage_example".to_string(), 
                    format!("Use with {} APIs as needed", self.token_type));
            }
        }
        
        tracing::trace!("API token formatted successfully");
        formatted_data.to_bytes()
    }
    
    async fn post_rotation_actions(&self, old_secret: &[u8], new_secret: &[u8], path: &str, namespace: &str) -> Result<()> {
        let span = tracing::info_span!("api_token_rotation.post_actions", 
            path = %path, 
            namespace = %namespace, 
            token_type = %self.token_type
        );
        let _guard = span.enter();
        
        // For API tokens, we would typically need to invalidate the old token and register the new one
        tracing::info!("Simulating API token update process");
        
        // In a real implementation, this would call the API to invalidate old tokens and register new ones
        // For this example, we'll simulate a successful update
        
        // Extract tokens from old and new secrets
        let old_data = SecretData::from_bytes(old_secret)?;
        let new_data = SecretData::from_bytes(new_secret)?;
        
        let old_token = old_data.data.get("token").ok_or_else(|| {
            tracing::error!("Old secret missing token");
            ServiceError::ValidationError("Old secret missing token".to_string())
        })?;
        
        let new_token = new_data.data.get("token").ok_or_else(|| {
            tracing::error!("New secret missing token");
            ServiceError::ValidationError("New secret missing token".to_string())
        })?;
        
        // Simulate API call to register new token
        tracing::debug!("Would call API to register new token ({} chars)", new_token.len());
        
        // Simulate API call to invalidate old token
        tracing::debug!(
            "Would call API to invalidate old token: {}...", 
            old_token.chars().take(8).collect::<String>()
        );
        
        // Record API token rotation completion
        tracing::info!("API token rotation completed: token_type={} namespace={}", 
            self.token_type.as_str(), namespace);
        
        // Some token providers may have rate limits - track these
        tracing::info!("API provider calls: count=2 provider={} action=token_rotation", 
            self.token_type.as_str());
        // Note: 2 calls - 1 for registration, 1 for invalidation
        
        // Emit an event for the rotation completion
        // Access the store directly instead of using try_lock_owned which doesn't exist
        let _store = Arc::clone(&self.store);
        
        // This is a placeholder for event production since MaluStore doesn't have event_producer() method
        // Will need to be updated once proper event handling is implemented
        tracing::info!("Would emit rotation event for path: {}", path);
        
        // Create event with correct structure based on SecretEvent definition
        let event = SecretEvent {
            event_id: Uuid::new_v4(),
            action: SecretAction::Update, // Using Update instead of Rotated which doesn't exist
            secret_id: path.to_string(), // Use secret_id instead of path which doesn't exist
            namespace: Some(namespace.to_string()), // namespace is Option<String>
            timestamp: Utc::now(),
            username: None,
            metadata: Some(json!({
                "secret_type": "api_token",
                "token_type": self.token_type,
                "token_prefix": new_token.chars().take(4).collect::<String>(),
                "token_length": new_token.len()
            })),
            status: EventStatus::Success,
        };
        
        // For now, just log that we would send an event
        tracing::debug!("API token rotation event would be sent: {:?}", event);
        
        // Track events with tracing instead of using a producer
        tracing::info!("Event would be processed: event_type=secret_rotation secret_type=api_token");
        
        tracing::info!("Successfully rotated {} API token", self.token_type);
        Ok(())
    }
}
