use std::env;
use std::path::PathBuf;
use std::time::Duration;

use crate::core::error::{Result, ServiceError};

/// Configuration for the Secret Storage Service
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// The port to listen on
    pub port: u16,
    
    /// The host to bind to
    pub host: String,
    
    /// The directory to store secrets in
    pub data_dir: PathBuf,
    
    /// The directory to store keys in
    pub keys_dir: PathBuf,
    
    /// The master key path
    pub master_key_path: String,
    
    /// The salt path
    pub salt_path: String,
    
    /// The default admin username
    pub admin_username: String,
    
    /// The default admin password
    pub admin_password: String,
    
    /// The log level
    pub log_level: String,
    
    /// Request timeout in seconds
    pub request_timeout: Duration,
    
    /// Request body size limit in bytes
    pub request_body_limit: usize,
    
    /// Whether to use in-memory storage (for testing)
    pub use_memory_storage: bool,
    
    /// SQL database URL (if using SQL storage)
    pub database_url: Option<String>,
    
    /// Redis URL (if using Redis storage)
    pub redis_url: Option<String>,
    
    /// Kafka bootstrap servers (comma-separated list)
    pub kafka_bootstrap_servers: String,
    
    /// Kafka topic for secret events
    pub kafka_topic_secrets: String,
    
    /// Kafka topic for audit events
    pub kafka_topic_audit: String,
    
    /// Kafka client ID for this service instance
    pub kafka_client_id: String,
    
    /// Kafka consumer group ID
    pub kafka_consumer_group_id: String,
    
    /// Whether to enable Kafka event production
    pub kafka_enable_producer: bool,
    
    /// Whether to enable Kafka event consumption
    pub kafka_enable_consumer: bool,
    
    /// Optional Kafka security protocol (PLAINTEXT, SSL, SASL_PLAINTEXT, SASL_SSL)
    pub kafka_security_protocol: Option<String>,
    
    /// Optional Kafka SASL mechanism (PLAIN, SCRAM-SHA-256, SCRAM-SHA-512)
    pub kafka_sasl_mechanism: Option<String>,
    
    /// Optional Kafka SASL username
    pub kafka_sasl_username: Option<String>,
    
    /// Optional Kafka SASL password
    pub kafka_sasl_password: Option<String>,
}

impl AppConfig {
    /// Creates a new configuration from environment variables
    pub fn from_env() -> Result<Self> {
        // Get the data directory
        let data_dir_str = env::var("SECRET_SERVICE_DATA_DIR")
            .unwrap_or_else(|_| "./data".to_string());
        let data_dir = PathBuf::from(&data_dir_str);
        
        // Create the keys directory inside the data directory
        let keys_dir = data_dir.join("keys");
        
        // Get the master key path and salt path
        let master_key_path = keys_dir.join("master.key").to_string_lossy().to_string();
        let salt_path = keys_dir.join("salt").to_string_lossy().to_string();
        
        // Get admin credentials
        let admin_username = env::var("SECRET_SERVICE_ADMIN_USER")
            .unwrap_or_else(|_| "admin".to_string());
        let admin_password = env::var("SECRET_SERVICE_ADMIN_PASS")
            .unwrap_or_else(|_| "password".to_string());
            
        // Get port and host
        let port = env::var("PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse::<u16>()
            .map_err(|_| ServiceError::ConfigurationError("Invalid PORT value".to_string()))?;
            
        let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        
        // Get log level
        let log_level = env::var("LOG_LEVEL")
            .unwrap_or_else(|_| "info,tower_http=debug".to_string());
            
        // Get request timeout
        let request_timeout_secs = env::var("REQUEST_TIMEOUT_SECS")
            .unwrap_or_else(|_| "30".to_string())
            .parse::<u64>()
            .map_err(|_| ServiceError::ConfigurationError(
                "Invalid REQUEST_TIMEOUT_SECS value".to_string()
            ))?;
        
        // Get request body limit
        let request_body_limit = env::var("REQUEST_BODY_LIMIT_BYTES")
            .unwrap_or_else(|_| "10485760".to_string()) // 10MB default
            .parse::<usize>()
            .map_err(|_| ServiceError::ConfigurationError(
                "Invalid REQUEST_BODY_LIMIT_BYTES value".to_string()
            ))?;
            
        // Get storage type
        let use_memory_storage = env::var("USE_MEMORY_STORAGE")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .map_err(|_| ServiceError::ConfigurationError(
                "Invalid USE_MEMORY_STORAGE value".to_string()
            ))?;
            
        // Get database URL if present
        let database_url = env::var("DATABASE_URL").ok();
        
        // Get Redis URL if present
        let redis_url = env::var("REDIS_URL").ok();
        
        // Get Kafka configuration
        let kafka_bootstrap_servers = env::var("KAFKA_BOOTSTRAP_SERVERS")
            .unwrap_or_else(|_| "localhost:9092".to_string());
            
        let kafka_topic_secrets = env::var("KAFKA_TOPIC_SECRETS")
            .unwrap_or_else(|_| "secret-events".to_string());
            
        let kafka_topic_audit = env::var("KAFKA_TOPIC_AUDIT")
            .unwrap_or_else(|_| "audit-events".to_string());
            
        let kafka_client_id = env::var("KAFKA_CLIENT_ID")
            .unwrap_or_else(|_| format!("secret-service-{}", uuid::Uuid::new_v4()));
            
        let kafka_consumer_group_id = env::var("KAFKA_CONSUMER_GROUP_ID")
            .unwrap_or_else(|_| "secret-service-group".to_string());
            
        let kafka_enable_producer = env::var("KAFKA_ENABLE_PRODUCER")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .map_err(|_| ServiceError::ConfigurationError(
                "Invalid KAFKA_ENABLE_PRODUCER value".to_string()
            ))?;
            
        let kafka_enable_consumer = env::var("KAFKA_ENABLE_CONSUMER")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .map_err(|_| ServiceError::ConfigurationError(
                "Invalid KAFKA_ENABLE_CONSUMER value".to_string()
            ))?;
            
        // Get optional Kafka security settings
        let kafka_security_protocol = env::var("KAFKA_SECURITY_PROTOCOL").ok();
        let kafka_sasl_mechanism = env::var("KAFKA_SASL_MECHANISM").ok();
        let kafka_sasl_username = env::var("KAFKA_SASL_USERNAME").ok();
        let kafka_sasl_password = env::var("KAFKA_SASL_PASSWORD").ok();
        
        Ok(Self {
            port,
            host,
            data_dir,
            keys_dir,
            master_key_path,
            salt_path,
            admin_username,
            admin_password,
            log_level,
            request_timeout: Duration::from_secs(request_timeout_secs),
            request_body_limit,
            use_memory_storage,
            database_url,
            redis_url,
            kafka_bootstrap_servers,
            kafka_topic_secrets,
            kafka_topic_audit,
            kafka_client_id,
            kafka_consumer_group_id,
            kafka_enable_producer,
            kafka_enable_consumer,
            kafka_security_protocol,
            kafka_sasl_mechanism,
            kafka_sasl_username,
            kafka_sasl_password,
        })
    }
    
    /// Prints the configuration (with sensitive values masked)
    pub fn print_config(&self) {
        tracing::info!("=== Secret Storage Service Configuration ===");
        tracing::info!("Host: {}", self.host);
        tracing::info!("Port: {}", self.port);
        tracing::info!("Data directory: {:?}", self.data_dir);
        tracing::info!("Keys directory: {:?}", self.keys_dir);
        tracing::info!("Admin username: {}", self.admin_username);
        tracing::info!("Admin password: {}", if self.admin_password.is_empty() { 
            "<not set>" 
        } else { 
            "********" 
        });
        tracing::info!("Log level: {}", self.log_level);
        tracing::info!("Request timeout: {:?}", self.request_timeout);
        tracing::info!("Request body limit: {} bytes", self.request_body_limit);
        tracing::info!("Storage type: {}", if self.use_memory_storage { 
            "In-memory" 
        } else { 
            "File-based" 
        });
        
        if let Some(ref db_url) = self.database_url {
            let masked_url = mask_connection_string(db_url);
            tracing::info!("Database URL: {}", masked_url);
        }
        
        if let Some(ref redis_url) = self.redis_url {
            let masked_url = mask_connection_string(redis_url);
            tracing::info!("Redis URL: {}", masked_url);
        }
        
        // Print Kafka configuration
        tracing::info!("Kafka bootstrap servers: {}", self.kafka_bootstrap_servers);
        tracing::info!("Kafka secret events topic: {}", self.kafka_topic_secrets);
        tracing::info!("Kafka audit events topic: {}", self.kafka_topic_audit);
        tracing::info!("Kafka client ID: {}", self.kafka_client_id);
        tracing::info!("Kafka consumer group ID: {}", self.kafka_consumer_group_id);
        tracing::info!("Kafka producer enabled: {}", self.kafka_enable_producer);
        tracing::info!("Kafka consumer enabled: {}", self.kafka_enable_consumer);
        
        if let Some(ref protocol) = self.kafka_security_protocol {
            tracing::info!("Kafka security protocol: {}", protocol);
        }
        
        if let Some(ref mechanism) = self.kafka_sasl_mechanism {
            tracing::info!("Kafka SASL mechanism: {}", mechanism);
        }
        
        if let Some(ref username) = self.kafka_sasl_username {
            tracing::info!("Kafka SASL username: {}", username);
            tracing::info!("Kafka SASL password: ********");
        }
        
        tracing::info!("===========================================");
    }
}

/// Masks a connection string to hide sensitive information
fn mask_connection_string(connection_string: &str) -> String {
    // For URLs, mask the password portion
    if connection_string.contains("://") {
        let parts: Vec<&str> = connection_string.split("://").collect();
        if parts.len() == 2 {
            let protocol = parts[0];
            let rest = parts[1];
            
            // Check if there's an @ symbol (indicating auth info)
            if rest.contains('@') {
                let auth_parts: Vec<&str> = rest.split('@').collect();
                if auth_parts.len() == 2 {
                    let auth = auth_parts[0];
                    let host_part = auth_parts[1];
                    
                    // Check if there's a username:password structure
                    if auth.contains(':') {
                        let auth_elements: Vec<&str> = auth.split(':').collect();
                        if auth_elements.len() >= 2 {
                            let username = auth_elements[0];
                            return format!("{}://{}:******@{}", protocol, username, host_part);
                        }
                    }
                    
                    // Just mask the entire auth part if we can't parse it
                    return format!("{}://******@{}", protocol, host_part);
                }
            }
        }
    }
    
    // For connection strings with key=value;
    if connection_string.contains("Password=") || connection_string.contains("password=") {
        let mut masked = String::new();
        let segments: Vec<&str> = connection_string.split(';').collect();
        
        for (i, segment) in segments.iter().enumerate() {
            if segment.to_lowercase().contains("password=") {
                let key_val: Vec<&str> = segment.split('=').collect();
                if key_val.len() >= 2 {
                    masked.push_str(&format!("{}=******", key_val[0]));
                } else {
                    masked.push_str(segment);
                }
            } else {
                masked.push_str(segment);
            }
            
            if i < segments.len() - 1 {
                masked.push(';');
            }
        }
        
        return masked;
    }
    
    // If we can't parse it, just return a generic mask
    format!("{}...{}", 
        &connection_string[0..std::cmp::min(10, connection_string.len())],
        &connection_string[connection_string.len() - std::cmp::min(5, connection_string.len())..]
    )
}
