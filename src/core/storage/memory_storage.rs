use crate::core::{StorageProvider, error::{Result, ServiceError}};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Storage provider that stores secrets in memory (for testing and development)
pub struct MemoryStorageProvider {
    storage: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryStorageProvider {
    /// Create a new empty MemoryStorageProvider
    pub fn new() -> Self {
        Self {
            storage: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MemoryStorageProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl StorageProvider for MemoryStorageProvider {
    async fn store(&self, path: &str, data: &[u8]) -> Result<()> {
        let mut storage = self.storage.lock()?;
        storage.insert(path.to_string(), data.to_vec());
        Ok(())
    }
    
    async fn retrieve(&self, path: &str) -> Result<Vec<u8>> {
        let storage = self.storage.lock()?;
        
        match storage.get(path) {
            Some(data) => Ok(data.clone()),
            None => Err(ServiceError::NotFound(format!("Secret not found: {}", path))),
        }
    }
    
    async fn delete(&self, path: &str) -> Result<()> {
        let mut storage = self.storage.lock()?;
        
        if storage.remove(path).is_none() {
            return Err(ServiceError::NotFound(format!("Secret not found: {}", path)));
        }
        
        Ok(())
    }
    
    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        let storage = self.storage.lock()?;
        
        let keys = match prefix {
            Some(prefix) => storage.keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect(),
            None => storage.keys().cloned().collect(),
        };
        
        Ok(keys)
    }
    
    async fn exists(&self, path: &str) -> Result<bool> {
        let storage = self.storage.lock()?;
        Ok(storage.contains_key(path))
    }
}

// Factory function to create a new memory storage provider
pub fn create_memory_storage_provider() -> Arc<MemoryStorageProvider> {
    Arc::new(MemoryStorageProvider::new())
}
