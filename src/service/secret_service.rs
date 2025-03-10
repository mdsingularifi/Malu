use std::sync::Arc;
use serde_json::json;
use tokio::sync::Mutex;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

use crate::service::rotation_service::{RotationService, RotationPolicy, RotationSchedule, SecretType};

use crate::core::{
    store::{MaluStore, MaluConfig},
    error::{Result, ServiceError},
    crypto::AesGcmCryptoProvider,
};
use crate::events::{producer::KafkaProducer, consumer::KafkaConsumer, handler::EventHandler};
use crate::events::models::{SecretEvent, AuditEvent, SecretAction, AuditEventType};
use crate::config::AppConfig;
use crate::metrics;

/// Secret Storage Service main service implementation
#[derive(Clone)]
pub struct SecretService {
    /// Core storage engine
    store: Arc<MaluStore>,
    /// Kafka producer for event publishing
    event_producer: Option<Arc<KafkaProducer>>,
    /// Configuration
    #[allow(dead_code)]
    config: AppConfig,
    /// Secret rotation service
    rotation_service: Option<Arc<RotationService>>,
    /// Dynamic secrets initialized flag
    dynamic_secrets_initialized: bool,
}

impl SecretService {
    /// Create a new SecretService with the provided MaluStore and optional event producer
    pub fn new(store: Arc<MaluStore>, event_producer: Option<Arc<KafkaProducer>>, config: AppConfig) -> Self {
        // Create rotation service if secret rotation is enabled in config
        let rotation_service = if config.features.secret_rotation {
            Some(Arc::new(RotationService::new(store.clone(), event_producer.clone())))
        } else {
            None
        };
        
        Self { 
            store, 
            event_producer, 
            config, 
            rotation_service,
            dynamic_secrets_initialized: false,
        }
    }
    
    /// Initialize the service and dependent services based on configuration settings
    pub async fn initialize(&mut self) -> Result<()> {
        // Initialize dynamic secrets if enabled in configuration
        if self.config.features.dynamic_secrets {
            tracing::info!("Initializing dynamic secrets functionality");
            self.init_dynamic_secrets().await?;
            tracing::info!("Dynamic secrets functionality initialized successfully");
        } else {
            tracing::info!("Dynamic secrets feature is disabled, skipping initialization");
        }
        
        // Initialize any other features
        
        Ok(())
    }
    
    /// Store a secret with optional namespace and username
    pub async fn store_secret(&self, path: &str, namespace: &str, data: &str, username: Option<&str>) -> Result<()> {
        // Decode base64 data
        let decoded = BASE64.decode(data).map_err(|e| {
            ServiceError::InvalidInput(format!("Invalid base64 data: {}", e))
        })?;
        
        let namespaced_path = format!("{}/{}", namespace, path);
        
        // Create a timer to measure operation duration
        let _timer = metrics::Timer::new("store_secret");
        
        // Store the secret using MaluStore
        let result = self.store.store_secret(&namespaced_path, &decoded).await;
        
        // Record the operation result for metrics
        metrics::record_storage_operation("store", if result.is_ok() { "success" } else { "failure" });
        metrics::record_operation_result("store_secret", result.is_ok());
        
        // Publish event
        if let Some(producer) = &self.event_producer {
            // Create a secret event for this action
            // Check if the secret exists by trying to retrieve it (MaluStore API doesn't have secret_exists)
            let exists = self.store.retrieve_secret(&namespaced_path).await.is_ok();
            let action = if exists {
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
            
            // Clone what we need to move into the tokio::spawn
            let producer = producer.clone();
            let event = event.clone();
            
            // Send the event asynchronously - don't wait for it to complete
            // and don't let event errors affect the main operation
            tokio::spawn(async move {
                let result = producer.produce_secret_event(event).await;
                if let Err(e) = &result {
                    tracing::error!("Failed to publish secret event: {}", e);
                }
                // Record Kafka event metrics
                metrics::record_kafka_event("secret_events", 
                    if result.is_ok() { "success" } else { "failure" });
            });
        }
        
        result
    }
    
    /// Retrieve a secret with optional namespace and username
    pub async fn retrieve_secret(&self, path: &str, namespace: &str, username: Option<&str>) -> Result<String> {
        let namespaced_path = format!("{}/{}", namespace, path);
        
        // Create a timer to measure operation duration
        let _timer = metrics::Timer::new("retrieve_secret");
        
        // Retrieve the secret using MaluStore
        let result = self.store.retrieve_secret(&namespaced_path).await;
        
        // Record the operation result for metrics
        metrics::record_storage_operation("retrieve", if result.is_ok() { "success" } else { "failure" });
        metrics::record_operation_result("retrieve_secret", result.is_ok());
        
        // Publish event
        if let Some(producer) = &self.event_producer {
            // Create a secret event for this action
            let mut event = SecretEvent::new(SecretAction::Retrieve, path, username)
                .with_namespace(namespace);
            
            if let Err(ref e) = result {
                event = event.with_error(e.to_string());
            }
            
            // Clone what we need to move into the tokio::spawn
            let producer = producer.clone();
            let event = event.clone();
            
            // Clone what we need to move into the tokio::spawn
            let producer = producer.clone();
            let event = event.clone();
            
            // Send the event asynchronously
            tokio::spawn(async move {
                let result = producer.produce_secret_event(event).await;
                if let Err(e) = &result {
                    tracing::error!("Failed to publish secret event: {}", e);
                }
                // Record Kafka event metrics
                metrics::record_kafka_event("secret_events", 
                    if result.is_ok() { "success" } else { "failure" });
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
        
        // Create a timer to measure operation duration
        let _timer = metrics::Timer::new("delete_secret");
        
        // Delete the secret
        let result = self.store.delete_secret(&namespaced_path).await;
        
        // Record the operation result for metrics
        metrics::record_storage_operation("delete", if result.is_ok() { "success" } else { "failure" });
        metrics::record_operation_result("delete_secret", result.is_ok());
        
        // Publish event
        if let Some(producer) = &self.event_producer {
            // Create a secret event for this action
            let mut event = SecretEvent::new(SecretAction::Delete, path, username)
                .with_namespace(namespace);
            
            if let Err(ref e) = result {
                event = event.with_error(e.to_string());
            }
            
            // Clone what we need to move into the tokio::spawn
            let producer = producer.clone();
            let event = event.clone();
            
            // Clone what we need to move into the tokio::spawn
            let producer = producer.clone();
            let event = event.clone();
            
            // Send the event asynchronously
            tokio::spawn(async move {
                let result = producer.produce_secret_event(event).await;
                if let Err(e) = &result {
                    tracing::error!("Failed to publish secret event: {}", e);
                }
                // Record Kafka event metrics
                metrics::record_kafka_event("secret_events", 
                    if result.is_ok() { "success" } else { "failure" });
            });
        }
        
        result
    }
    
    /// List secrets with optional namespace and username
    pub async fn list_secrets(&self, namespace: &str, prefix: Option<&str>, username: Option<&str>) -> Result<Vec<String>> {
        let namespaced_prefix = prefix
            .map(|p| format!("{}/{}", namespace, p))
            .or_else(|| Some(format!("{}/", namespace)));
        
        // Create a timer to measure operation duration
        let _timer = metrics::Timer::new("list_secrets");
        
        // List the secrets
        let result = self.store.list_secrets(namespaced_prefix.as_deref()).await;
        
        // Record the operation result for metrics
        metrics::record_storage_operation("list", if result.is_ok() { "success" } else { "failure" });
        metrics::record_operation_result("list_secrets", result.is_ok());
        
        // If the operation was successful, record the count of secrets
        if let Ok(ref secrets) = result {
            metrics::record_secret_count(secrets.len());
        }
        
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
            
            // Clone what we need to move into the tokio::spawn
            let producer = producer.clone();
            let event = event.clone();
            
            // Send the event asynchronously
            tokio::spawn(async move {
                let result = producer.produce_secret_event(event).await;
                if let Err(e) = &result {
                    tracing::error!("Failed to publish secret event: {}", e);
                }
                // Record Kafka event metrics
                metrics::record_kafka_event("secret_events", 
                    if result.is_ok() { "success" } else { "failure" });
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
    #[allow(dead_code)]
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
            
            // Clone what we need to move into the tokio::spawn
            let producer = producer.clone();
            let event = event.clone();
            
            // Send the event asynchronously
            tokio::spawn(async move {
                if let Err(e) = producer.produce_audit_event(event).await {
                    tracing::error!("Failed to publish audit event: {}", e);
                }
            });
        }
        
        result
    }
    
    /// Get the secret store
    #[allow(dead_code)]
    pub fn get_store(&self) -> Arc<MaluStore> {
        self.store.clone()
    }
    
    /// Get configuration
    #[allow(dead_code)]
    pub fn get_config(&self) -> &AppConfig {
        &self.config
    }
    
    /// Check storage health by attempting a simple operation
    /// 
    /// Returns:
    /// - Ok(true) if the storage is healthy and can be accessed
    /// - Ok(false) if the storage is unhealthy or cannot be accessed
    /// - Err if an unexpected error occurs
    pub async fn check_storage_health(&self) -> Result<bool> {
        // Try to list secrets with a non-existent path to check connectivity
        // We use a random path to avoid any potential cache effects
        let test_path = format!("_health_check_{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos());
        
        // Create a timer to measure health check duration
        let _timer = metrics::Timer::new("check_storage_health");
            
        let health_result = match self.store.list_secrets(Some(&test_path)).await {
            // Storage is accessible (empty list is fine)
            Ok(_) => Ok(true),
            // If we get a not found error, that's actually good - means we connected to storage
            Err(e) if e.to_string().contains("not found") => Ok(true),
            // Any other error indicates a problem
            Err(_) => Ok(false),
        };
        
        // Record the health check result in metrics
        if let Ok(is_healthy) = health_result {
            metrics::record_operation_result("storage_health_check", is_healthy);
        }
        
        health_result
    }
    
    /// Add a rotation policy for secrets
    pub async fn add_rotation_policy(&self, policy: RotationPolicy) -> Result<()> {
        if let Some(rotation_service) = &self.rotation_service {
            rotation_service.add_policy(policy).await
        } else {
            Err(ServiceError::NotImplemented("Secret rotation is not enabled".to_string()))
        }
    }
    
    /// Get all rotation policies
    pub async fn get_rotation_policies(&self) -> Result<Vec<RotationPolicy>> {
        if let Some(rotation_service) = &self.rotation_service {
            rotation_service.get_policies().await
        } else {
            Err(ServiceError::NotImplemented("Secret rotation is not enabled".to_string()))
        }
    }
    
    /// Rotate a secret immediately
    pub async fn rotate_secret(&self, path: &str, namespace: &str, username: Option<&str>) -> Result<()> {
        if let Some(rotation_service) = &self.rotation_service {
            // Create a timer to measure operation duration
            let _timer = metrics::Timer::new("rotate_secret");
            
            let result = rotation_service.rotate_secret(path, namespace, username).await;
            
            // Record the operation result for metrics
            metrics::record_operation_result("rotate_secret", result.is_ok());
            
            result
        } else {
            Err(ServiceError::NotImplemented("Secret rotation is not enabled".to_string()))
        }
    }
    
    /// Store a secret and set up rotation for it based on the provided configuration
    pub async fn store_secret_with_rotation(&self, path: &str, namespace: &str, data: &str, username: Option<&str>) -> Result<()> {
        // First store the secret normally
        self.store_secret(path, namespace, data, username).await?;
        
        // Check if rotation service is available
        if let Some(rotation_service) = &self.rotation_service {
            // Create a timer to measure operation duration
            let _timer = metrics::Timer::new("store_secret_with_rotation");
            
            // Create a policy based on default parameters
            // In a real implementation, we would use the rotation_config from the request
            let policy = RotationPolicy::new(
                format!("auto_rotation_for_{}", path),
                RotationSchedule::Interval { seconds: 86400 }, // Daily rotation
                path.to_string(),
                namespace.to_string(),
                true,  // automatic
                5,     // versions to keep
                SecretType::KeyValue,
            );
            
            // Add the rotation policy
            let result = rotation_service.add_policy(policy).await;
            
            // Record the operation result for metrics
            metrics::record_operation_result("store_secret_with_rotation", result.is_ok());
            
            result
        } else {
            Err(ServiceError::NotImplemented("Secret rotation is not enabled".to_string()))
        }
    }
    
    /// Start the rotation scheduler
    pub async fn start_rotation_scheduler(&self) -> Result<()> {
        if let Some(rotation_service) = &self.rotation_service {
            rotation_service.start_scheduler().await
        } else {
            Err(ServiceError::NotImplemented("Secret rotation is not enabled".to_string()))
        }
    }
    
    /// Stop the rotation scheduler
    pub async fn stop_rotation_scheduler(&self) -> Result<()> {
        if let Some(rotation_service) = &self.rotation_service {
            rotation_service.stop_scheduler().await
        } else {
            Err(ServiceError::NotImplemented("Secret rotation is not enabled".to_string()))
        }
    }
}

/// Initialize the secret service with configuration from environment
/// 
/// This creates a new SecretService instance with the appropriate configuration
/// and starts the rotation scheduler if secret rotation is enabled
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
    
    // Clone the config fields we'll need later to avoid partial moves
    let config_clone = AppConfig {
        master_key_path: config.master_key_path.clone(),
        admin_username: config.admin_username.clone(),
        admin_password: config.admin_password.clone(),
        kafka_enable_producer: config.kafka_enable_producer,
        kafka_bootstrap_servers: config.kafka_bootstrap_servers.clone(),
        kafka_client_id: config.kafka_client_id.clone(),
        kafka_consumer_group_id: config.kafka_consumer_group_id.clone(),
        kafka_topic_secrets: config.kafka_topic_secrets.clone(),
        kafka_topic_audit: config.kafka_topic_audit.clone(),
        ..config
    };
    
    // Initialize storage provider based on configuration
    let storage_provider: Arc<dyn crate::core::StorageProvider + Send + Sync> = if config_clone.use_memory_storage {
        tracing::info!("Using in-memory storage provider");
        crate::core::storage::create_memory_storage_provider()
    } else if let Some(db_url) = &config_clone.database_url {
        tracing::info!("Using SQL storage provider");
        crate::core::storage::create_sql_storage_provider(db_url, None).await?
    } else if let Some(redis_url) = &config_clone.redis_url {
        tracing::info!("Using Redis storage provider");
        crate::core::storage::create_redis_storage_provider(redis_url, None).await?
    } else {
        tracing::info!("Using file storage provider");
        crate::core::storage::create_file_storage_provider(
            &secrets_dir.to_string_lossy().to_string()
        ).await?
    };
    
    // Initialize crypto provider
    tracing::info!("Initializing crypto provider with master key at {}", config.master_key_path);
    let mut crypto_provider = AesGcmCryptoProvider::new()
        .with_master_key_path(config_clone.master_key_path.clone());
    crypto_provider.init().await?;
    let crypto_provider = Arc::new(crypto_provider);
    
    // Create auth provider with default admin user
    tracing::info!("Initializing auth provider with admin user: {}", config_clone.admin_username);
    let auth_provider = crate::core::auth::create_simple_auth_provider(
        vec![(config_clone.admin_username.clone(), config_clone.admin_password.clone())]
    )?;
    
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
    let event_producer = if config_clone.kafka_enable_producer {
        tracing::info!("Initializing Kafka producer");
        match KafkaProducer::new(&config_clone).await {
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
    let mut service = SecretService::new(store.clone(), event_producer.clone(), config_clone.clone());
    
    // Initialize the service components based on configuration
    if let Err(e) = service.initialize().await {
        tracing::error!("Failed to initialize service components: {}", e);
        return Err(e);
    }
    tracing::info!("Secret service successfully initialized");
    
    // Start the rotation scheduler if secret rotation is enabled
    if config_clone.features.secret_rotation {
        tracing::info!("Starting secret rotation scheduler");
        if let Err(e) = service.start_rotation_scheduler().await {
            tracing::error!("Failed to start rotation scheduler: {}", e);
        } else {
            tracing::info!("Secret rotation scheduler started successfully");
        }
    }
    
    // Initialize Kafka consumer if enabled
    let consumer = if config.kafka_enable_consumer {
        tracing::info!("Initializing Kafka consumer");
        let service_arc = Arc::new(service.clone());
        let handler = Arc::new(Mutex::new(EventHandler::new(service_arc.clone())));
        
        match KafkaConsumer::new(&config_clone).await {
            Ok(consumer) => {
                tracing::info!("Kafka consumer successfully initialized");
                // Start the consumer with the event handler
                if let Err(e) = consumer.start(handler.lock().await.clone()).await {
                    tracing::error!("Failed to start Kafka consumer: {}", e);
                }
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
