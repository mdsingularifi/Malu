//! File system storage implementation

use std::path::{Path, PathBuf};
use std::fs;
use async_trait::async_trait;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::wrappers::ReadDirStream;
use futures::stream::StreamExt;


use malu_interfaces::{StorageEngine, Result};
use crate::error::StorageError;
use crate::utils::{normalize_path, ensure_dir_exists};

/// File system storage implementation
#[derive(Debug)]
pub struct FileSystemStorage {
    base_path: PathBuf,
}

impl FileSystemStorage {
    /// Create a new file system storage with the specified base path
    pub fn new(base_path: &str) -> Self {
        let path = PathBuf::from(base_path);
        Self {
            base_path: path,
        }
    }
    
    /// Initialize the storage by ensuring the base directory exists
    pub async fn init(&self) -> Result<()> {
        // Ensure base directory exists
        ensure_dir_exists(&self.base_path).map_err(|e| {
            Box::new(e) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        Ok(())
    }
    
    /// Get the absolute path for a key
    fn get_path(&self, key: &str) -> Result<PathBuf> {
        // Normalize path to prevent traversal attacks
        let path = normalize_path(&self.base_path, key).map_err(|e| {
            Box::new(e) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        // Get the parent directory
        let _parent = path.parent().ok_or_else(|| {
            Box::new(StorageError::Path(format!("Invalid path: {}", key))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        Ok(path)
    }
}

#[async_trait]
impl StorageEngine for FileSystemStorage {
    async fn store(&self, key: &str, data: &[u8]) -> Result<()> {
        // Get the absolute path
        let path = self.get_path(key)?;
        
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            ensure_dir_exists(parent).map_err(|e| {
                Box::new(e) as Box<dyn std::error::Error + Send + Sync>
            })?;
        }
        
        // Create or overwrite the file
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .await
            .map_err(|e| {
                Box::new(StorageError::Io(e)) as Box<dyn std::error::Error + Send + Sync>
            })?;
        
        // Write the data
        file.write_all(data).await.map_err(|e| {
            Box::new(StorageError::Io(e)) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        // Ensure data is flushed to disk
        file.flush().await.map_err(|e| {
            Box::new(StorageError::Io(e)) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        Ok(())
    }
    
    async fn retrieve(&self, key: &str) -> Result<Vec<u8>> {
        // Get the absolute path
        let path = self.get_path(key)?;
        
        // Check if the file exists
        if !path.exists() {
            return Err(Box::new(StorageError::NotFound(key.to_string())) as Box<dyn std::error::Error + Send + Sync>);
        }
        
        // Open the file
        let mut file = File::open(&path).await.map_err(|e| {
            Box::new(StorageError::Io(e)) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        // Read the data
        let mut data = Vec::new();
        file.read_to_end(&mut data).await.map_err(|e| {
            Box::new(StorageError::Io(e)) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        Ok(data)
    }
    
    async fn exists(&self, key: &str) -> Result<bool> {
        // Get the absolute path
        let path = self.get_path(key)?;
        
        // Check if the file exists
        Ok(path.exists())
    }
    
    async fn delete(&self, key: &str) -> Result<()> {
        // Get the absolute path
        let path = self.get_path(key)?;
        
        // Check if the file exists
        if !path.exists() {
            return Err(Box::new(StorageError::NotFound(key.to_string())) as Box<dyn std::error::Error + Send + Sync>);
        }
        
        // Delete the file
        fs::remove_file(&path).map_err(|e| {
            Box::new(StorageError::Io(e)) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        Ok(())
    }
    
    async fn list_keys(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        // Initialize the storage
        self.init().await?;
        
        // Get base path for listing
        let list_path = match prefix {
            Some(p) => {
                let path = normalize_path(&self.base_path, p).map_err(|e| {
                    Box::new(e) as Box<dyn std::error::Error + Send + Sync>
                })?;
                
                // If the prefix doesn't exist, return empty list
                if !path.exists() {
                    return Ok(Vec::new());
                }
                
                path
            },
            None => self.base_path.clone(),
        };
        
        // Function to collect files recursively
        async fn collect_files(dir: PathBuf, base: &Path, prefix: Option<&str>) -> Result<Vec<String>> {
            let mut keys = Vec::new();
            
            let dir_entries = tokio::fs::read_dir(&dir).await.map_err(|e| {
                Box::new(StorageError::Io(e)) as Box<dyn std::error::Error + Send + Sync>
            })?;
            
            let mut entries = ReadDirStream::new(dir_entries);
            
            while let Some(entry) = entries.next().await {
                let entry = entry.map_err(|e| {
                    Box::new(StorageError::Io(e)) as Box<dyn std::error::Error + Send + Sync>
                })?;
                
                let path = entry.path();
                let metadata = entry.metadata().await.map_err(|e| {
                    Box::new(StorageError::Io(e)) as Box<dyn std::error::Error + Send + Sync>
                })?;
                
                if metadata.is_dir() {
                    // Recursively collect files from subdirectories
                    // Box::pin is needed for recursive async functions to avoid infinite type sizes
                    let mut sub_keys = Box::pin(collect_files(path, base, prefix)).await?;
                    keys.append(&mut sub_keys);
                } else {
                    // Get relative path from base
                    let rel_path = path.strip_prefix(base).map_err(|_| {
                        Box::new(StorageError::Path(format!("Failed to strip prefix from {:?}", path))) as Box<dyn std::error::Error + Send + Sync>
                    })?;
                    
                    let key = rel_path.to_string_lossy().to_string();
                    
                    // Filter by prefix if provided
                    if let Some(prefix) = prefix {
                        if key.starts_with(prefix) {
                            keys.push(key);
                        }
                    } else {
                        keys.push(key);
                    }
                }
            }
            
            Ok(keys)
        }
        
        // Collect files recursively
        collect_files(list_path, &self.base_path, prefix).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use uuid::Uuid;
    
    // Helper to create a temporary directory for testing
    fn temp_dir() -> PathBuf {
        let temp = env::temp_dir();
        let uuid = Uuid::new_v4().to_string();
        let path = temp.join(format!("malu_test_{}", uuid));
        std::fs::create_dir_all(&path).unwrap();
        path
    }
    
    // Helper to clean up after tests
    fn cleanup(path: &Path) {
        let _ = std::fs::remove_dir_all(path);
    }
    
    #[tokio::test]
    async fn test_file_system_storage() {
        let temp = temp_dir();
        let storage = FileSystemStorage::new(temp.to_str().unwrap());
        
        // Initialize
        storage.init().await.unwrap();
        
        // Store a file
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
        
        // Clean up
        cleanup(&temp);
    }
    
    #[tokio::test]
    async fn test_path_normalization() {
        let temp = temp_dir();
        let storage = FileSystemStorage::new(temp.to_str().unwrap());
        
        // Initialize
        storage.init().await.unwrap();
        
        // Should fail with path traversal attempt
        assert!(storage.store("../test/path", b"secret data").await.is_err());
        assert!(storage.store("test/../path", b"secret data").await.is_err());
        assert!(storage.store("/test/path", b"secret data").await.is_err());
        
        // Clean up
        cleanup(&temp);
    }
}
