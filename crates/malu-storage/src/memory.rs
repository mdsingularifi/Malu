//! In-memory storage implementation for testing

use async_trait::async_trait;
use malu_interfaces::{StorageEngine, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::error::StorageError;

/// In-memory storage implementation
#[derive(Debug, Clone)]
pub struct MemoryStorage {
    store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl MemoryStorage {
    /// Create a new in-memory storage
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl StorageEngine for MemoryStorage {
    async fn store(&self, key: &str, data: &[u8]) -> Result<()> {
        let mut store = self.store.lock()
            .map_err(|e| Box::new(StorageError::Lock(format!("Lock error: {}", e))) as Box<dyn std::error::Error + Send + Sync>)?;
        
        store.insert(key.to_string(), data.to_vec());
        Ok(())
    }
    
    async fn retrieve(&self, key: &str) -> Result<Vec<u8>> {
        let store = self.store.lock()
            .map_err(|e| Box::new(StorageError::Lock(format!("Lock error: {}", e))) as Box<dyn std::error::Error + Send + Sync>)?;
        
        store.get(key)
            .cloned()
            .ok_or_else(|| Box::new(StorageError::NotFound(key.to_string())) as Box<dyn std::error::Error + Send + Sync>)
    }
    
    async fn exists(&self, key: &str) -> Result<bool> {
        let store = self.store.lock()
            .map_err(|e| Box::new(StorageError::Lock(format!("Lock error: {}", e))) as Box<dyn std::error::Error + Send + Sync>)?;
        
        Ok(store.contains_key(key))
    }
    
    async fn delete(&self, key: &str) -> Result<()> {
        let mut store = self.store.lock()
            .map_err(|e| Box::new(StorageError::Lock(format!("Lock error: {}", e))) as Box<dyn std::error::Error + Send + Sync>)?;
        
        if !store.contains_key(key) {
            return Err(Box::new(StorageError::NotFound(key.to_string())) as Box<dyn std::error::Error + Send + Sync>);
        }
        
        store.remove(key);
        Ok(())
    }
    
    async fn list_keys(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        let store = self.store.lock()
            .map_err(|e| Box::new(StorageError::Lock(format!("Lock error: {}", e))) as Box<dyn std::error::Error + Send + Sync>)?;
        
        let keys = match prefix {
            Some(prefix) => store.keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect(),
            None => store.keys().cloned().collect(),
        };
        
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_memory_storage() {
        let storage = MemoryStorage::new();
        
        // Store a secret
        storage.store("test/path", b"secret data").await.unwrap();
        
        // Verify it exists
        assert!(storage.exists("test/path").await.unwrap());
        
        // Retrieve it
        let data = storage.retrieve("test/path").await.unwrap();
        assert_eq!(data, b"secret data");
        
        // List keys
        let keys = storage.list_keys(Some("test/")).await.unwrap();
        assert_eq!(keys, vec!["test/path"]);
        
        // Delete it
        storage.delete("test/path").await.unwrap();
        
        // Verify it's gone
        assert!(!storage.exists("test/path").await.unwrap());
        assert!(storage.retrieve("test/path").await.is_err());
    }
}
