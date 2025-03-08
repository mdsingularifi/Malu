//! Valkey/Redis storage implementation

use std::sync::Arc;
use async_trait::async_trait;
use redis::{Client, AsyncCommands, ConnectionManager, RedisError};
use tracing::{debug, error, info};

use malu_interfaces::{StorageEngine, Result};
use crate::error::StorageError;

/// Configuration for Valkey/Redis storage
#[derive(Debug, Clone)]
pub struct ValkeyConfig {
    /// Connection URL (redis://)
    pub url: String,
    /// Optional namespace/prefix for all keys
    pub namespace: Option<String>,
    /// Connection read timeout in seconds
    pub read_timeout: Option<u64>,
    /// Connection write timeout in seconds
    pub write_timeout: Option<u64>,
}

impl ValkeyConfig {
    /// Parse a connection string into a ValkeyConfig
    /// Format: "url=redis://127.0.0.1:6379;namespace=malu;read_timeout=5;write_timeout=5"
    pub fn from_connection_string(conn_string: &str) -> Result<Self> {
        let mut url = None;
        let mut namespace = None;
        let mut read_timeout = None;
        let mut write_timeout = None;
        
        for part in conn_string.split(';') {
            let kv: Vec<&str> = part.splitn(2, '=').collect();
            if kv.len() != 2 {
                continue;
            }
            
            match kv[0].trim() {
                "url" => url = Some(kv[1].trim().to_string()),
                "namespace" => namespace = Some(kv[1].trim().to_string()),
                "read_timeout" => {
                    if let Ok(timeout) = kv[1].trim().parse::<u64>() {
                        read_timeout = Some(timeout);
                    }
                },
                "write_timeout" => {
                    if let Ok(timeout) = kv[1].trim().parse::<u64>() {
                        write_timeout = Some(timeout);
                    }
                },
                _ => {}
            }
        }
        
        let url = url.ok_or_else(|| {
            Box::new(StorageError::Internal("Valkey/Redis connection string must contain 'url'".to_string())) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        Ok(ValkeyConfig {
            url,
            namespace,
            read_timeout,
            write_timeout,
        })
    }
    
    /// Apply namespace to a key
    fn namespaced_key(&self, key: &str) -> String {
        match &self.namespace {
            Some(ns) => format!("{}:{}", ns, key),
            None => key.to_string(),
        }
    }
    
    /// Extract original key from namespaced key
    fn extract_key(&self, namespaced_key: &str) -> String {
        match &self.namespace {
            Some(ns) => {
                let prefix = format!("{}:", ns);
                if namespaced_key.starts_with(&prefix) {
                    namespaced_key[prefix.len()..].to_string()
                } else {
                    namespaced_key.to_string()
                }
            },
            None => namespaced_key.to_string(),
        }
    }
}

/// Valkey/Redis storage implementation
#[derive(Debug, Clone)]
pub struct ValkeyStorage {
    config: ValkeyConfig,
    connection: ConnectionManager,
}

impl ValkeyStorage {
    /// Create a new Valkey/Redis storage from a connection string
    pub fn new(connection_string: &str) -> Self {
        let config = ValkeyConfig::from_connection_string(connection_string)
            .expect("Failed to parse Valkey/Redis connection string");
        
        // Create client
        let client = Client::open(config.url.clone())
            .expect("Failed to create Valkey/Redis client");
        
        // This is blocking, but it's only called once during initialization
        let runtime = tokio::runtime::Runtime::new().unwrap();
        
        // Create a connection manager for automatic reconnections
        let connection = runtime.block_on(ConnectionManager::new(client))
            .expect("Failed to connect to Valkey/Redis");
        
        Self {
            config,
            connection,
        }
    }
    
    /// Convert RedisError to StorageError
    fn handle_redis_error(&self, err: RedisError, context: &str) -> Box<dyn std::error::Error + Send + Sync> {
        error!("Redis error {}: {}", context, err);
        Box::new(StorageError::Internal(format!("Redis error {}: {}", context, err))) as Box<dyn std::error::Error + Send + Sync>
    }
}

#[async_trait]
impl StorageEngine for ValkeyStorage {
    async fn store(&self, key: &str, data: &[u8]) -> Result<()> {
        let namespaced_key = self.config.namespaced_key(key);
        
        // Store data
        let mut conn = self.connection.clone();
        conn.set(namespaced_key, data).await
            .map_err(|e| self.handle_redis_error(e, "storing data"))?;
        
        Ok(())
    }
    
    async fn retrieve(&self, key: &str) -> Result<Vec<u8>> {
        let namespaced_key = self.config.namespaced_key(key);
        
        // Retrieve data
        let mut conn = self.connection.clone();
        let result: Option<Vec<u8>> = conn.get(namespaced_key).await
            .map_err(|e| self.handle_redis_error(e, "retrieving data"))?;
        
        match result {
            Some(data) => Ok(data),
            None => Err(Box::new(StorageError::NotFound(key.to_string())) as Box<dyn std::error::Error + Send + Sync>),
        }
    }
    
    async fn exists(&self, key: &str) -> Result<bool> {
        let namespaced_key = self.config.namespaced_key(key);
        
        // Check if key exists
        let mut conn = self.connection.clone();
        let result: bool = conn.exists(namespaced_key).await
            .map_err(|e| self.handle_redis_error(e, "checking if key exists"))?;
        
        Ok(result)
    }
    
    async fn delete(&self, key: &str) -> Result<()> {
        let namespaced_key = self.config.namespaced_key(key);
        
        // First check if the key exists
        if !self.exists(key).await? {
            return Err(Box::new(StorageError::NotFound(key.to_string())) as Box<dyn std::error::Error + Send + Sync>);
        }
        
        // Delete key
        let mut conn = self.connection.clone();
        let deleted: i32 = conn.del(namespaced_key).await
            .map_err(|e| self.handle_redis_error(e, "deleting key"))?;
        
        if deleted == 0 {
            return Err(Box::new(StorageError::NotFound(key.to_string())) as Box<dyn std::error::Error + Send + Sync>);
        }
        
        Ok(())
    }
    
    async fn list_keys(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        let mut conn = self.connection.clone();
        
        // Create the pattern for SCAN
        let pattern = match (prefix, &self.config.namespace) {
            (Some(prefix), Some(namespace)) => format!("{}:{}*", namespace, prefix),
            (Some(prefix), None) => format!("{}*", prefix),
            (None, Some(namespace)) => format!("{}:*", namespace),
            (None, None) => "*".to_string(),
        };
        
        // Use SCAN to get keys
        let mut cursor = 0;
        let mut keys = Vec::new();
        
        loop {
            // Each SCAN operation returns a cursor and a list of keys
            let (next_cursor, mut batch): (i64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100) // Retrieve 100 keys at a time
                .query_async(&mut conn)
                .await
                .map_err(|e| self.handle_redis_error(e, "listing keys"))?;
            
            // Extract original keys by removing the namespace
            if self.config.namespace.is_some() {
                batch = batch.iter()
                    .map(|k| self.config.extract_key(k))
                    .collect();
            }
            
            // Add this batch to our results
            keys.extend(batch);
            
            // Update the cursor for the next iteration
            cursor = next_cursor;
            
            // If the cursor is 0, we've iterated through all keys
            if cursor == 0 {
                break;
            }
        }
        
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_valkey_config_from_connection_string() {
        // Full config
        let config = ValkeyConfig::from_connection_string(
            "url=redis://127.0.0.1:6379;namespace=malu;read_timeout=5;write_timeout=5"
        ).unwrap();
        
        assert_eq!(config.url, "redis://127.0.0.1:6379");
        assert_eq!(config.namespace, Some("malu".to_string()));
        assert_eq!(config.read_timeout, Some(5));
        assert_eq!(config.write_timeout, Some(5));
        
        // Minimal config
        let config = ValkeyConfig::from_connection_string(
            "url=redis://127.0.0.1:6379"
        ).unwrap();
        
        assert_eq!(config.url, "redis://127.0.0.1:6379");
        assert_eq!(config.namespace, None);
        assert_eq!(config.read_timeout, None);
        assert_eq!(config.write_timeout, None);
        
        // Invalid config (missing url)
        let config = ValkeyConfig::from_connection_string(
            "namespace=malu;read_timeout=5"
        );
        assert!(config.is_err());
    }
    
    #[test]
    fn test_namespaced_key() {
        // With namespace
        let config = ValkeyConfig {
            url: "redis://localhost".to_string(),
            namespace: Some("malu".to_string()),
            read_timeout: None,
            write_timeout: None,
        };
        assert_eq!(config.namespaced_key("test"), "malu:test");
        
        // Without namespace
        let config = ValkeyConfig {
            url: "redis://localhost".to_string(),
            namespace: None,
            read_timeout: None,
            write_timeout: None,
        };
        assert_eq!(config.namespaced_key("test"), "test");
    }
    
    #[test]
    fn test_extract_key() {
        // With namespace
        let config = ValkeyConfig {
            url: "redis://localhost".to_string(),
            namespace: Some("malu".to_string()),
            read_timeout: None,
            write_timeout: None,
        };
        assert_eq!(config.extract_key("malu:test"), "test");
        
        // Without namespace or with unrelated key
        assert_eq!(config.extract_key("other:test"), "other:test");
        
        // Without namespace
        let config = ValkeyConfig {
            url: "redis://localhost".to_string(),
            namespace: None,
            read_timeout: None,
            write_timeout: None,
        };
        assert_eq!(config.extract_key("test"), "test");
    }
}
