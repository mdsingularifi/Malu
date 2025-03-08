//! Repository pattern for storage

use malu_interfaces::{StorageEngine, Result};
use std::sync::Arc;

/// Repository provides a higher-level API on top of the storage engine
#[derive(Debug, Clone)]
pub struct Repository {
    storage: Arc<dyn StorageEngine>,
    prefix: String,
}

impl Repository {
    /// Create a new repository with the given storage engine and prefix
    pub fn new(storage: Arc<dyn StorageEngine>, prefix: &str) -> Self {
        Self {
            storage,
            prefix: prefix.to_string(),
        }
    }
    
    /// Store an item by ID
    pub async fn store_item(&self, id: &str, data: &[u8]) -> Result<()> {
        let path = self.get_full_path(id);
        self.storage.store(&path, data).await
    }
    
    /// Retrieve an item by ID
    pub async fn get_item(&self, id: &str) -> Result<Vec<u8>> {
        let path = self.get_full_path(id);
        self.storage.retrieve(&path).await
    }
    
    /// Check if an item exists by ID
    pub async fn item_exists(&self, id: &str) -> Result<bool> {
        let path = self.get_full_path(id);
        self.storage.exists(&path).await
    }
    
    /// Delete an item by ID
    pub async fn delete_item(&self, id: &str) -> Result<()> {
        let path = self.get_full_path(id);
        self.storage.delete(&path).await
    }
    
    /// List all items in this repository
    pub async fn list_items(&self) -> Result<Vec<String>> {
        // Convert &String to &str for the prefix
        let prefix = Some(self.prefix.as_str());
        
        let full_paths = self.storage.list_keys(prefix).await?;
        
        // Convert full paths back to IDs by removing the prefix
        let prefix_len = self.prefix.len() + 1; // +1 for the separator
        let ids = full_paths
            .into_iter()
            .filter_map(|path| {
                if path.len() > prefix_len {
                    Some(path[prefix_len..].to_string())
                } else {
                    None
                }
            })
            .collect();
        
        Ok(ids)
    }
    
    /// Get the full path for an item ID
    fn get_full_path(&self, id: &str) -> String {
        format!("{}/{}", self.prefix, id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStorage;
    
    #[tokio::test]
    async fn test_repository() {
        // Create a storage engine
        let storage = Arc::new(MemoryStorage::new());
        
        // Create a repository
        let repo = Repository::new(storage, "test_repo");
        
        // Store an item
        repo.store_item("item1", b"data1").await.unwrap();
        
        // Check if it exists
        assert!(repo.item_exists("item1").await.unwrap());
        
        // Retrieve it
        let data = repo.get_item("item1").await.unwrap();
        assert_eq!(data, b"data1");
        
        // Store another item
        repo.store_item("item2", b"data2").await.unwrap();
        
        // List items
        let items = repo.list_items().await.unwrap();
        assert_eq!(items.len(), 2);
        assert!(items.contains(&"item1".to_string()));
        assert!(items.contains(&"item2".to_string()));
        
        // Delete an item
        repo.delete_item("item1").await.unwrap();
        
        // Verify it's gone
        assert!(!repo.item_exists("item1").await.unwrap());
        
        // List again
        let items = repo.list_items().await.unwrap();
        assert_eq!(items.len(), 1);
        assert!(items.contains(&"item2".to_string()));
    }
}
