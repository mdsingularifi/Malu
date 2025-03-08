use crate::core::{StorageProvider, error::{Result, ServiceError}};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;

/// Storage provider that stores secrets in the file system
pub struct FileStorageProvider {
    base_path: PathBuf,
}

impl FileStorageProvider {
    /// Create a new FileStorageProvider with the specified base path
    pub fn new<P: AsRef<Path>>(base_path: P) -> Self {
        Self {
            base_path: base_path.as_ref().to_path_buf(),
        }
    }
    
    /// Get the full path for a given key
    fn get_path(&self, key: &str) -> PathBuf {
        let sanitized_key = key.replace('/', "_").replace('\\', "_");
        self.base_path.join(sanitized_key)
    }
}

#[async_trait]
impl StorageProvider for FileStorageProvider {
    async fn store(&self, path: &str, data: &[u8]) -> Result<()> {
        let file_path = self.get_path(path);
        
        // Create the parent directory if it doesn't exist
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                ServiceError::StorageError(format!("Failed to create directory: {}", e))
            })?;
        }
        
        // Write the data to the file
        fs::write(&file_path, data).await.map_err(|e| {
            ServiceError::StorageError(format!("Failed to write file {}: {}", file_path.display(), e))
        })?;
        
        Ok(())
    }
    
    async fn retrieve(&self, path: &str) -> Result<Vec<u8>> {
        let file_path = self.get_path(path);
        
        // Check if the file exists
        if !file_path.exists() {
            return Err(ServiceError::NotFound(format!("Secret not found: {}", path)));
        }
        
        // Read the data from the file
        let data = fs::read(&file_path).await.map_err(|e| {
            ServiceError::StorageError(format!("Failed to read file {}: {}", file_path.display(), e))
        })?;
        
        Ok(data)
    }
    
    async fn delete(&self, path: &str) -> Result<()> {
        let file_path = self.get_path(path);
        
        // Check if the file exists
        if !file_path.exists() {
            return Err(ServiceError::NotFound(format!("Secret not found: {}", path)));
        }
        
        // Delete the file
        fs::remove_file(&file_path).await.map_err(|e| {
            ServiceError::StorageError(format!("Failed to delete file {}: {}", file_path.display(), e))
        })?;
        
        Ok(())
    }
    
    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        // Ensure the base directory exists
        if !self.base_path.exists() {
            fs::create_dir_all(&self.base_path).await.map_err(|e| {
                ServiceError::StorageError(format!("Failed to create base directory: {}", e))
            })?;
            return Ok(Vec::new());
        }
        
        // Read the directory
        let mut entries = fs::read_dir(&self.base_path).await.map_err(|e| {
            ServiceError::StorageError(format!("Failed to read directory: {}", e))
        })?;
        
        let mut result = Vec::new();
        
        // Process each entry
        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            ServiceError::StorageError(format!("Failed to read directory entry: {}", e))
        })? {
            if let Ok(file_type) = entry.file_type().await {
                if file_type.is_file() {
                    if let Ok(file_name) = entry.file_name().into_string() {
                        // Apply prefix filtering if specified
                        if let Some(prefix) = prefix {
                            if file_name.starts_with(prefix) {
                                result.push(file_name);
                            }
                        } else {
                            result.push(file_name);
                        }
                    }
                }
            }
        }
        
        Ok(result)
    }
    
    async fn exists(&self, path: &str) -> Result<bool> {
        let file_path = self.get_path(path);
        Ok(file_path.exists())
    }
}

// Factory function to create a new file storage provider
pub async fn create_file_storage_provider(base_path: &str) -> Result<Arc<FileStorageProvider>> {
    let path = Path::new(base_path);
    
    // Create the base directory if it doesn't exist
    if !path.exists() {
        fs::create_dir_all(path).await.map_err(|e| {
            ServiceError::StorageError(format!("Failed to create storage directory: {}", e))
        })?;
    }
    
    Ok(Arc::new(FileStorageProvider::new(path)))
}
