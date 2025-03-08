use std::sync::Arc;
use std::path::Path;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::json;
use tokio::sync::Mutex;

use crate::core::{
    store::{MaluStore, MaluConfig},
    error::{Result, ServiceError},
    crypto::AesGcmCryptoProvider,
    storage::{FileStorageProvider, MemoryStorageProvider},
    auth::{SimpleAuthProvider},
};
use crate::events::{producer::KafkaProducer, consumer::KafkaConsumer, handler::EventHandler};
use crate::events::models::{SecretEvent, AuditEvent, SecretAction, AuditEventType, EventStatus};
use crate::config::AppConfig;

/// Secret Storage Service main service implementation
pub struct SecretService {
    /// Core storage engine
    store: Arc<MaluStore>,
    /// Kafka producer for event publishing
    event_producer: Option<Arc<KafkaProducer>>,
    /// Configuration
    config: AppConfig,
}

impl SecretService {
    /// Create a new SecretService with the provided MaluStore and optional event producer
    pub fn new(store: Arc<MaluStore>, event_producer: Option<Arc<KafkaProducer>>, config: AppConfig) -> Self {
        Self { store, event_producer, config }
    }
    
    /// Store a secret with optional namespace and username
    pub async fn store_secret(&self, path: &str, namespace: &str, data: &str, username: Option<&str>) -> Result<()> {
        // Decode base64 data
        let decoded = BASE64.decode(data).map_err(|e| {
            ServiceError::InvalidInput(format!("Invalid base64 data: {}", e))
        })?;
        
        let namespaced_path = format!("{}/{}", namespace, path);
        
        // Store the secret using MaluStore
        let result = self.store.store_secret(&namespaced_path, &decoded).await;
        
        // Publish event
        if let Some(producer) = &self.event_producer {
            // Create a secret event for this action
            let action = if self.store.secret_exists(&namespaced_path).await.unwrap_or(false) {
                SecretAction::Update
            } else {
                SecretAction::Create
            };
            
            let mut event = SecretEvent::new(action, path, username)
                .with_namespace(namespace);
            
            // Only include the result status, not the actual data in the event
            // This prevents sensitive data from appearing in logs
            if let Err(ref e) = result {
                event = event.with_error(e.to_string());
            }
            
            // Send the event asynchronously - don't wait for it to complete
            // and don't let event errors affect the main operation
            tokio::spawn(async move {
                if let Err(e) = producer.send_secret_event(&event).await {
                    tracing::error!("Failed to publish secret event: {}", e);
                }
            });
        }
        
        result
    }
    
    /// Retrieve a secret with optional namespace and username
    pub async fn retrieve_secret(&self, path: &str, namespace: &str, username: Option<&str>) -> Result<String> {
        let namespaced_path = format!("{}/{}", namespace, path);
        
        // Retrieve the secret using MaluStore
        let result = self.store.retrieve_secret(&namespaced_path).await;
        
        // Publish event
        if let Some(producer) = &self.event_producer {
            // Create a secret event for this action
            let mut event = SecretEvent::new(SecretAction::Retrieve, path, username)
                .with_namespace(namespace);
            
            if let Err(ref e) = result {
                event = event.with_error(e.to_string());
            }
            
            // Send the event asynchronously
            tokio::spawn(async move {
                if let Err(e) = producer.send_secret_event(&event).await {
                    tracing::error!("Failed to publish secret event: {}", e);
                }
            });
        }
        
        // If retrieving the secret was successful, encode it as base64
        match result {
            Ok(data) => {
                let encoded = BASE64.encode(&data);
                Ok(encoded)
            },
            Err(e) => Err(e),
        }
    }
    
    /// Delete a secret with optional namespace and username
    pub async fn delete_secret(&self, path: &str, namespace: &str, username: Option<&str>) -> Result<()> {
        let namespaced_path = format!("{}/{}", namespace, path);
        
        // Delete the secret
        let result = self.store.delete_secret(&namespaced_path).await;
        
        // Publish event
        if let Some(producer) = &self.event_producer {
            // Create a secret event for this action
            let mut event = SecretEvent::new(SecretAction::Delete, path, username)
                .with_namespace(namespace);
            
            if let Err(ref e) = result {
                event = event.with_error(e.to_string());
            }
            
            // Send the event asynchronously
            tokio::spawn(async move {
                if let Err(e) = producer.send_secret_event(&event).await {
                    tracing::error!("Failed to publish secret event: {}", e);
                }
            });
        }
        
        result
    }
    
    /// List secrets with optional namespace and username
    pub async fn list_secrets(&self, namespace: &str, prefix: Option<&str>, username: Option<&str>) -> Result<Vec<String>> {
        let namespaced_prefix = prefix
            .map(|p| format!("{}/{}", namespace, p))
            .or_else(|| Some(format!("{}/", namespace)));
        
        // List the secrets
        let result = self.store.list_secrets(namespaced_prefix.as_deref()).await;
        
        // Publish event
        if let Some(producer) = &self.event_producer {
            // Create a secret event for this action
            let mut event = SecretEvent::new(SecretAction::List, namespace, username);
            
            if let Err(ref e) = result {
                event = event.with_error(e.to_string());
            } else if let Ok(ref secrets) = result {
                // Include the count of secrets in the metadata
                event = event.with_metadata(json!({
                    "count": secrets.len(),
                    "prefix": prefix,
                }));
            }
            
            // Send the event asynchronously
            tokio::spawn(async move {
                if let Err(e) = producer.send_secret_event(&event).await {
                    tracing::error!("Failed to publish secret event: {}", e);
                }
            });
        }
        
        // If listing was successful, strip the namespace prefix from the results
        match result {
            Ok(secrets) => {
                let namespace_prefix = format!("{}/", namespace);
                let stripped_secrets = secrets.into_iter()
                    .filter_map(|s| {
                        if s.starts_with(&namespace_prefix) {
                            Some(s[namespace_prefix.len()..].to_string())
                        } else {
                            None
                        }
                    })
                    .collect();
                Ok(stripped_secrets)
            },
            Err(e) => Err(e),
        }
    }
    
    /// Authenticate a user and optionally log the attempt
    pub async fn authenticate(&self, username: &str, password: &str, ip_address: Option<&str>) -> Result<bool> {
        // Authenticate the user
        let result = self.store.authenticate(username, password).await;
        
        // Publish audit event
        if let Some(producer) = &self.event_producer {
            // Create an audit event for this action
            let mut event = AuditEvent::new(
                AuditEventType::Authentication,
                &format!("Authentication attempt for user {}", username),
                Some(username)
            );
            
            if let Some(ip) = ip_address {
                event = event.with_ip_address(ip);
            }
            
            // Add result to the event
            match &result {
                Ok(success) => {
                    let message = if *success {
                        "Authentication successful"
                    } else {
                        "Authentication failed"
                    };
                    
                    event = event.with_metadata(json!({
                        "success": success,
                        "message": message,
                    }));
                },
                Err(e) => {
                    event = event.with_error(e.to_string());
                }
            }
            
            // Send the event asynchronously
            tokio::spawn(async move {
                if let Err(e) = producer.send_audit_event(&event).await {
                    tracing::error!("Failed to publish audit event: {}", e);
                }
            });
        }
        
        result
    }
    
    /// Get the secret store
    pub fn get_store(&self) -> Arc<MaluStore> {
        self.store.clone()
    }
    
    /// Get configuration
    pub fn get_config(&self) -> &AppConfig {
        &self.config
    }
}

/// Initialize the secret service with configuration from environment
pub async fn init_secret_service() -> Result<(SecretService, Option<KafkaConsumer>)> {
    // Get configuration from environment
    let config = AppConfig::from_env()?;
    
    // Print configuration (with sensitive values masked)
    config.print_config();
    
    // Create data and keys directories if they don't exist
    tokio::fs::create_dir_all(&config.data_dir).await.map_err(|e| {
        ServiceError::StorageError(format!("Failed to create data directory: {}", e))
    })?;
    
    let secrets_dir = config.data_dir.join("secrets");
    tokio::fs::create_dir_all(&secrets_dir).await.map_err(|e| {
        ServiceError::StorageError(format!("Failed to create secrets directory: {}", e))
    })?;
    
    tokio::fs::create_dir_all(&config.keys_dir).await.map_err(|e| {
        ServiceError::StorageError(format!("Failed to create keys directory: {}", e))
    })?;
    
    // Create a new MaluConfig for the store
    let malu_config = MaluConfig::new(secrets_dir.to_string_lossy().to_string())
        .with_master_key_path(config.master_key_path.clone())
        .with_salt_path(config.salt_path.clone());
    
    // Initialize storage provider based on configuration
    let storage_provider: Box<dyn crate::core::StorageProvider + Send + Sync> = if config.use_memory_storage {
        tracing::info!("Using in-memory storage provider");
        Box::new(*crate::core::storage::create_memory_storage_provider().await?)
    } else if let Some(db_url) = &config.database_url {
        tracing::info!("Using SQL storage provider");
        Box::new(*crate::core::storage::create_sql_storage_provider(db_url).await?)
    } else if let Some(redis_url) = &config.redis_url {
        tracing::info!("Using Redis storage provider");
        Box::new(*crate::core::storage::create_redis_storage_provider(redis_url).await?)
    } else {
        tracing::info!("Using file storage provider");
        Box::new(*crate::core::storage::create_file_storage_provider(
            &secrets_dir.to_string_lossy().to_string()
        ).await?)
    };
    
    // Initialize crypto provider
    tracing::info!("Initializing crypto provider with master key at {}", config.master_key_path);
    let mut crypto_provider = Box::new(
        AesGcmCryptoProvider::new()
            .with_master_key_path(config.master_key_path)
    );
    crypto_provider.init().await?;
    
    // Create auth provider with default admin user
    tracing::info!("Initializing auth provider with admin user: {}", config.admin_username);
    let auth_provider = Box::new(
        *crate::core::auth::create_simple_auth_provider(vec![(config.admin_username, config.admin_password)])?    
    );
    
    // Build the MaluStore
    let store = MaluStore::builder()
        .with_config(malu_config)
        .with_storage_provider(storage_provider)
        .with_crypto_provider(crypto_provider)
        .with_auth_provider(auth_provider)
        .build()?;
    
    // Create the service
    let store = Arc::new(store);
    
    // Initialize Kafka producer if enabled
    let event_producer = if config.kafka_enable_producer {
        tracing::info!("Initializing Kafka producer");
        match KafkaProducer::new(&config).await {
            Ok(producer) => {
                tracing::info!("Kafka producer successfully initialized");
                Some(Arc::new(producer))
            },
            Err(e) => {
                tracing::error!("Failed to initialize Kafka producer: {}", e);
                None
            }
        }
    } else {
        tracing::info!("Kafka producer disabled");
        None
    };
    
    // Create the service
    let service = SecretService::new(store.clone(), event_producer.clone(), config.clone());
    tracing::info!("Secret service successfully initialized");
    
    // Initialize Kafka consumer if enabled
    let consumer = if config.kafka_enable_consumer {
        tracing::info!("Initializing Kafka consumer");
        let service_arc = Arc::new(service.clone());
        let handler = Arc::new(Mutex::new(EventHandler::new(service_arc)));
        
        match KafkaConsumer::new(&config, handler).await {
            Ok(consumer) => {
                tracing::info!("Kafka consumer successfully initialized");
                Some(consumer)
            },
            Err(e) => {
                tracing::error!("Failed to initialize Kafka consumer: {}", e);
                None
            }
        }
    } else {
        tracing::info!("Kafka consumer disabled");
        None
    };
    
    Ok((service, consumer))
}
