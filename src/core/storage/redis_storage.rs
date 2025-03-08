use crate::core::{StorageProvider, error::{Result, ServiceError}};
use async_trait::async_trait;
use std::sync::Arc;
use redis::{aio::Connection, AsyncCommands, Client};

/// Storage provider that stores secrets in Redis
pub struct RedisStorageProvider {
    client: Client,
    prefix: String,
}

impl RedisStorageProvider {
    /// Create a new RedisStorageProvider with the given connection URL
    pub fn new(redis_url: &str, prefix: &str) -> Result<Self> {
        let client = Client::open(redis_url).map_err(|e| {
            ServiceError::StorageError(format!("Failed to create Redis client: {}", e))
        })?;
        
        Ok(Self {
            client,
            prefix: prefix.to_string(),
        })
    }
    
    /// Get the full key with prefix
    fn get_key(&self, key: &str) -> String {
        format!("{}:{}", self.prefix, key)
    }
    
    /// Get a fresh connection to Redis for each operation
    async fn get_connection(&self) -> Result<Connection> {
        // Always create a fresh connection instead of trying to reuse/clone one
        self.client.get_async_connection().await.map_err(|e| {
            ServiceError::StorageError(format!("Failed to connect to Redis: {}", e))
        })
    }
}

#[async_trait]
impl StorageProvider for RedisStorageProvider {
    async fn store(&self, path: &str, data: &[u8]) -> Result<()> {
        let key = self.get_key(path);
        let mut conn = self.get_connection().await?;
        
        let _: () = conn.set(&key, data).await.map_err(|e| {
            ServiceError::StorageError(format!("Failed to store data in Redis: {}", e))
        })?;
        
        Ok(())
    }
    
    async fn retrieve(&self, path: &str) -> Result<Vec<u8>> {
        let key = self.get_key(path);
        let mut conn = self.get_connection().await?;
        
        let data: Option<Vec<u8>> = conn.get(&key).await.map_err(|e| {
            ServiceError::StorageError(format!("Failed to retrieve data from Redis: {}", e))
        })?;
        
        match data {
            Some(bytes) => Ok(bytes),
            None => Err(ServiceError::NotFound(format!("Secret not found: {}", path))),
        }
    }
    
    async fn delete(&self, path: &str) -> Result<()> {
        let key = self.get_key(path);
        let mut conn = self.get_connection().await?;
        
        let deleted: i64 = conn.del(&key).await.map_err(|e| {
            ServiceError::StorageError(format!("Failed to delete data from Redis: {}", e))
        })?;
        
        if deleted == 0 {
            return Err(ServiceError::NotFound(format!("Secret not found: {}", path)));
        }
        
        Ok(())
    }
    
    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        let search_pattern = match prefix {
            Some(p) => format!("{}:{}*", self.prefix, p),
            None => format!("{}:*", self.prefix),
        };
        
        let mut conn = self.get_connection().await?;
        
        let keys: Vec<String> = conn.keys(&search_pattern).await.map_err(|e| {
            ServiceError::StorageError(format!("Failed to list keys from Redis: {}", e))
        })?;
        
        // Strip the prefix from the keys
        let prefix_len = self.prefix.len() + 1; // +1 for the colon
        let stripped_keys = keys.into_iter()
            .filter_map(|k| {
                if k.len() > prefix_len {
                    Some(k[prefix_len..].to_string())
                } else {
                    None
                }
            })
            .collect();
        
        Ok(stripped_keys)
    }
    
    async fn exists(&self, path: &str) -> Result<bool> {
        let key = self.get_key(path);
        let mut conn = self.get_connection().await?;
        
        let exists: bool = conn.exists(&key).await.map_err(|e| {
            ServiceError::StorageError(format!("Failed to check key existence in Redis: {}", e))
        })?;
        
        Ok(exists)
    }
}

// Factory function to create a new Redis storage provider
pub async fn create_redis_storage_provider(
    redis_url: &str,
    prefix: Option<&str>
) -> Result<Arc<RedisStorageProvider>> {
    // Use "secrets" as the default prefix if none is provided
    let prefix = prefix.unwrap_or("secrets");
    let provider = RedisStorageProvider::new(redis_url, prefix)?;
    
    // Test the connection
    let conn = provider.get_connection().await?;
    drop(conn);
    
    tracing::info!("Created Redis storage provider with prefix: {}", prefix);
    Ok(Arc::new(provider))
}
