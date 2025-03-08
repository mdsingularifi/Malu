//! LevelDB storage implementation

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use async_trait::async_trait;
use leveldb::database::Database;
use leveldb::options::{Options, ReadOptions, WriteOptions};
use leveldb::iterator::Iter;
use leveldb::kv::KV;
use tracing::{debug, error, info};

use malu_interfaces::{StorageEngine, Result};
use crate::error::StorageError;
use crate::utils::ensure_dir_exists;

/// Configuration for LevelDB storage
#[derive(Debug, Clone)]
pub struct LevelDBConfig {
    /// Path to the LevelDB directory
    pub path: PathBuf,
    /// Optional prefix for all keys
    pub prefix: Option<String>,
    /// Create if the database doesn't exist
    pub create_if_missing: bool,
}

impl LevelDBConfig {
    /// Parse a connection string into a LevelDBConfig
    /// Format: "path=/path/to/leveldb;prefix=malu;create_if_missing=true"
    pub fn from_connection_string(conn_string: &str) -> Result<Self> {
        let mut path = None;
        let mut prefix = None;
        let mut create_if_missing = true; // Default to true
        
        for part in conn_string.split(';') {
            let kv: Vec<&str> = part.splitn(2, '=').collect();
            if kv.len() != 2 {
                continue;
            }
            
            match kv[0].trim() {
                "path" => path = Some(PathBuf::from(kv[1].trim())),
                "prefix" => prefix = Some(kv[1].trim().to_string()),
                "create_if_missing" => {
                    create_if_missing = match kv[1].trim().to_lowercase().as_str() {
                        "true" | "1" | "yes" => true,
                        "false" | "0" | "no" => false,
                        _ => true, // Default to true for invalid values
                    };
                },
                _ => {}
            }
        }
        
        let path = path.ok_or_else(|| {
            Box::new(StorageError::Internal("LevelDB connection string must contain 'path'".to_string())) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        Ok(LevelDBConfig {
            path,
            prefix,
            create_if_missing,
        })
    }
    
    /// Apply prefix to a key
    fn prefixed_key(&self, key: &str) -> Vec<u8> {
        match &self.prefix {
            Some(prefix) => format!("{}:{}", prefix, key).into_bytes(),
            None => key.as_bytes().to_vec(),
        }
    }
    
    /// Extract original key from prefixed key
    fn extract_key(&self, prefixed_key: &[u8]) -> String {
        let key_str = String::from_utf8_lossy(prefixed_key).to_string();
        
        match &self.prefix {
            Some(prefix) => {
                let prefix_str = format!("{}:", prefix);
                if key_str.starts_with(&prefix_str) {
                    key_str[prefix_str.len()..].to_string()
                } else {
                    key_str
                }
            },
            None => key_str,
        }
    }
}

/// LevelDB storage implementation
#[derive(Debug)]
pub struct LevelDBStorage {
    config: LevelDBConfig,
    db: Arc<Mutex<Database<Vec<u8>>>>,
}

impl LevelDBStorage {
    /// Create a new LevelDB storage from a connection string
    pub fn new(connection_string: &str) -> Self {
        let config = LevelDBConfig::from_connection_string(connection_string)
            .expect("Failed to parse LevelDB connection string");
        
        // Ensure directory exists
        if let Some(parent) = config.path.parent() {
            ensure_dir_exists(parent)
                .expect("Failed to create parent directory for LevelDB");
        }
        
        // Open or create the database
        let mut options = Options::new();
        options.create_if_missing = config.create_if_missing;
        
        let db = Database::open(&config.path, options)
            .expect("Failed to open LevelDB database");
        
        Self {
            config,
            db: Arc::new(Mutex::new(db)),
        }
    }
}

#[async_trait]
impl StorageEngine for LevelDBStorage {
    async fn store(&self, key: &str, data: &[u8]) -> Result<()> {
        let prefixed_key = self.config.prefixed_key(key);
        
        // Get database handle
        let db = self.db.lock().map_err(|e| {
            Box::new(StorageError::Lock(format!("Failed to acquire LevelDB lock: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        // Write options
        let write_opts = WriteOptions::new();
        
        // Store data
        db.put(write_opts, prefixed_key, data.to_vec()).map_err(|e| {
            Box::new(StorageError::Internal(format!("Failed to store data in LevelDB: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        Ok(())
    }
    
    async fn retrieve(&self, key: &str) -> Result<Vec<u8>> {
        let prefixed_key = self.config.prefixed_key(key);
        
        // Get database handle
        let db = self.db.lock().map_err(|e| {
            Box::new(StorageError::Lock(format!("Failed to acquire LevelDB lock: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        // Read options
        let read_opts = ReadOptions::new();
        
        // Retrieve data
        match db.get(read_opts, prefixed_key) {
            Ok(Some(data)) => Ok(data),
            Ok(None) => Err(Box::new(StorageError::NotFound(key.to_string())) as Box<dyn std::error::Error + Send + Sync>),
            Err(e) => Err(Box::new(StorageError::Internal(format!("Failed to retrieve data from LevelDB: {}", e))) as Box<dyn std::error::Error + Send + Sync>),
        }
    }
    
    async fn exists(&self, key: &str) -> Result<bool> {
        let prefixed_key = self.config.prefixed_key(key);
        
        // Get database handle
        let db = self.db.lock().map_err(|e| {
            Box::new(StorageError::Lock(format!("Failed to acquire LevelDB lock: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        // Read options
        let read_opts = ReadOptions::new();
        
        // Check if key exists
        match db.get(read_opts, prefixed_key) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(Box::new(StorageError::Internal(format!("Failed to check if key exists in LevelDB: {}", e))) as Box<dyn std::error::Error + Send + Sync>),
        }
    }
    
    async fn delete(&self, key: &str) -> Result<()> {
        let prefixed_key = self.config.prefixed_key(key);
        
        // First check if the key exists
        if !self.exists(key).await? {
            return Err(Box::new(StorageError::NotFound(key.to_string())) as Box<dyn std::error::Error + Send + Sync>);
        }
        
        // Get database handle
        let db = self.db.lock().map_err(|e| {
            Box::new(StorageError::Lock(format!("Failed to acquire LevelDB lock: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        // Write options
        let write_opts = WriteOptions::new();
        
        // Delete key
        db.delete(write_opts, prefixed_key).map_err(|e| {
            Box::new(StorageError::Internal(format!("Failed to delete data from LevelDB: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        Ok(())
    }
    
    async fn list_keys(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        // Get database handle
        let db = self.db.lock().map_err(|e| {
            Box::new(StorageError::Lock(format!("Failed to acquire LevelDB lock: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        // Read options
        let read_opts = ReadOptions::new();
        
        // Prepare iterator
        let mut iter = db.iter(read_opts);
        iter.seek_to_first();
        
        // Collect keys
        let mut keys = Vec::new();
        
        for (key_bytes, _) in iter {
            let key = self.config.extract_key(&key_bytes);
            
            // Apply additional filtering if a prefix is specified
            match prefix {
                Some(prefix_str) if key.starts_with(prefix_str) => keys.push(key),
                None => keys.push(key),
                _ => {} // Skip keys that don't match the prefix
            }
        }
        
        Ok(keys)
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
        let path = temp.join(format!("malu_leveldb_test_{}", uuid));
        std::fs::create_dir_all(&path).unwrap();
        path
    }
    
    // Helper to clean up after tests
    fn cleanup(path: &Path) {
        let _ = std::fs::remove_dir_all(path);
    }
    
    #[test]
    fn test_leveldb_config_from_connection_string() {
        // Full config
        let config = LevelDBConfig::from_connection_string(
            "path=/tmp/leveldb;prefix=malu;create_if_missing=false"
        ).unwrap();
        
        assert_eq!(config.path, PathBuf::from("/tmp/leveldb"));
        assert_eq!(config.prefix, Some("malu".to_string()));
        assert_eq!(config.create_if_missing, false);
        
        // Minimal config
        let config = LevelDBConfig::from_connection_string(
            "path=/tmp/leveldb"
        ).unwrap();
        
        assert_eq!(config.path, PathBuf::from("/tmp/leveldb"));
        assert_eq!(config.prefix, None);
        assert_eq!(config.create_if_missing, true); // Default
        
        // Invalid config (missing path)
        let config = LevelDBConfig::from_connection_string(
            "prefix=malu;create_if_missing=true"
        );
        assert!(config.is_err());
    }
    
    #[test]
    fn test_prefixed_key() {
        // With prefix
        let config = LevelDBConfig {
            path: PathBuf::from("/tmp/leveldb"),
            prefix: Some("malu".to_string()),
            create_if_missing: true,
        };
        assert_eq!(config.prefixed_key("test"), b"malu:test");
        
        // Without prefix
        let config = LevelDBConfig {
            path: PathBuf::from("/tmp/leveldb"),
            prefix: None,
            create_if_missing: true,
        };
        assert_eq!(config.prefixed_key("test"), b"test");
    }
    
    #[test]
    fn test_extract_key() {
        // With prefix
        let config = LevelDBConfig {
            path: PathBuf::from("/tmp/leveldb"),
            prefix: Some("malu".to_string()),
            create_if_missing: true,
        };
        assert_eq!(config.extract_key(b"malu:test"), "test");
        
        // Without prefix or with unrelated key
        assert_eq!(config.extract_key(b"other:test"), "other:test");
        
        // Without prefix
        let config = LevelDBConfig {
            path: PathBuf::from("/tmp/leveldb"),
            prefix: None,
            create_if_missing: true,
        };
        assert_eq!(config.extract_key(b"test"), "test");
    }
}
