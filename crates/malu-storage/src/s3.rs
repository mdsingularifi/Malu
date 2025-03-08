//! S3 storage implementation
//! This module is only enabled when the "s3-storage" feature is enabled

use std::sync::Arc;
use async_trait::async_trait;
use aws_sdk_s3::{Client, config::Region};
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Error;

use malu_interfaces::{StorageEngine, Result};
use crate::error::StorageError;

/// S3 storage configuration
#[derive(Debug, Clone)]
pub struct S3Config {
    /// S3 bucket name
    pub bucket: String,
    /// Optional AWS region (defaults to us-west-2)
    pub region: Option<String>,
    /// Optional prefix for all keys
    pub prefix: Option<String>,
}

impl S3Config {
    /// Parse a connection string into an S3Config
    /// Format: "bucket=my-bucket;region=us-west-2;prefix=my/prefix"
    pub fn from_connection_string(conn_string: &str) -> Result<Self> {
        let mut bucket = None;
        let mut region = None;
        let mut prefix = None;
        
        for part in conn_string.split(';') {
            let kv: Vec<&str> = part.splitn(2, '=').collect();
            if kv.len() != 2 {
                continue;
            }
            
            match kv[0].trim() {
                "bucket" => bucket = Some(kv[1].trim().to_string()),
                "region" => region = Some(kv[1].trim().to_string()),
                "prefix" => prefix = Some(kv[1].trim().to_string()),
                _ => {}
            }
        }
        
        let bucket = bucket.ok_or_else(|| {
            Box::new(StorageError::Internal("S3 connection string must contain 'bucket'".to_string())) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        Ok(S3Config {
            bucket,
            region,
            prefix,
        })
    }
    
    /// Get the prefixed key
    fn prefixed_key(&self, key: &str) -> String {
        match &self.prefix {
            Some(prefix) => format!("{}/{}", prefix, key),
            None => key.to_string(),
        }
    }
}

/// S3 storage implementation
#[derive(Debug)]
pub struct S3Storage {
    config: S3Config,
    client: Arc<Client>,
}

impl S3Storage {
    /// Create a new S3 storage from a connection string
    pub fn new(connection_string: &str) -> Self {
        let config = S3Config::from_connection_string(connection_string)
            .expect("Failed to parse S3 connection string");
        
        let region = config.region.clone()
            .unwrap_or_else(|| "us-west-2".to_string());
        
        // Create the S3 client
        let s3_config = aws_config::from_env()
            .region(Region::new(region))
            .load();
            
        // This is blocking, but it's only called once during initialization
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let s3_config = runtime.block_on(s3_config);
        let client = Client::new(&s3_config);
        
        Self {
            config,
            client: Arc::new(client),
        }
    }
}

#[async_trait]
impl StorageEngine for S3Storage {
    async fn store(&self, key: &str, data: &[u8]) -> Result<()> {
        let prefixed_key = self.config.prefixed_key(key);
        
        // Upload to S3
        self.client.put_object()
            .bucket(&self.config.bucket)
            .key(&prefixed_key)
            .body(data.to_vec().into())
            .send()
            .await
            .map_err(|e| {
                Box::new(StorageError::S3(format!("Failed to store object: {}", e))) as Box<dyn std::error::Error + Send + Sync>
            })?;
        
        Ok(())
    }
    
    async fn retrieve(&self, key: &str) -> Result<Vec<u8>> {
        let prefixed_key = self.config.prefixed_key(key);
        
        // Get from S3
        let response = self.client.get_object()
            .bucket(&self.config.bucket)
            .key(&prefixed_key)
            .send()
            .await
            .map_err(|e: SdkError<GetObjectError>| {
                match e.into_service_error() {
                    GetObjectError::NoSuchKey(_) => Box::new(StorageError::NotFound(key.to_string())) as Box<dyn std::error::Error + Send + Sync>,
                    e => Box::new(StorageError::S3(format!("Failed to retrieve object: {}", e))) as Box<dyn std::error::Error + Send + Sync>,
                }
            })?;
        
        // Read the data
        let data = response.body.collect().await.map_err(|e| {
            Box::new(StorageError::S3(format!("Failed to read object body: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        Ok(data.into_bytes().to_vec())
    }
    
    async fn exists(&self, key: &str) -> Result<bool> {
        let prefixed_key = self.config.prefixed_key(key);
        
        // Check if object exists
        let result = self.client.head_object()
            .bucket(&self.config.bucket)
            .key(&prefixed_key)
            .send()
            .await;
        
        // If the result is Ok, the object exists
        Ok(result.is_ok())
    }
    
    async fn delete(&self, key: &str) -> Result<()> {
        let prefixed_key = self.config.prefixed_key(key);
        
        // Check if object exists first
        if !self.exists(key).await? {
            return Err(Box::new(StorageError::NotFound(key.to_string())) as Box<dyn std::error::Error + Send + Sync>);
        }
        
        // Delete from S3
        self.client.delete_object()
            .bucket(&self.config.bucket)
            .key(&prefixed_key)
            .send()
            .await
            .map_err(|e| {
                Box::new(StorageError::S3(format!("Failed to delete object: {}", e))) as Box<dyn std::error::Error + Send + Sync>
            })?;
        
        Ok(())
    }
    
    async fn list_keys(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        let list_prefix = match (prefix, &self.config.prefix) {
            (Some(p), Some(base_prefix)) => format!("{}/{}", base_prefix, p),
            (Some(p), None) => p.to_string(),
            (None, Some(base_prefix)) => base_prefix.clone(),
            (None, None) => "".to_string(),
        };
        
        // List objects in S3
        let mut result = Vec::new();
        let mut continuation_token = None;
        
        loop {
            let mut request = self.client.list_objects_v2()
                .bucket(&self.config.bucket);
                
            if !list_prefix.is_empty() {
                request = request.prefix(&list_prefix);
            }
            
            if let Some(token) = continuation_token {
                request = request.continuation_token(token);
            }
            
            let response = request.send().await.map_err(|e: SdkError<ListObjectsV2Error>| {
                Box::new(StorageError::S3(format!("Failed to list objects: {}", e))) as Box<dyn std::error::Error + Send + Sync>
            })?;
            
            // Process objects
            if let Some(contents) = response.contents() {
                for object in contents {
                    if let Some(key) = &object.key {
                        // Remove the base prefix if present
                        let mut final_key = key.clone();
                        if let Some(base_prefix) = &self.config.prefix {
                            if final_key.starts_with(base_prefix) {
                                final_key = final_key[base_prefix.len() + 1..].to_string();
                            }
                        }
                        
                        result.push(final_key);
                    }
                }
            }
            
            // Check if there are more results
            match response.next_continuation_token() {
                Some(token) => continuation_token = Some(token.to_string()),
                None => break,
            }
        }
        
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_s3_config_from_connection_string() {
        // Basic config
        let config = S3Config::from_connection_string("bucket=my-bucket;region=us-west-2;prefix=my/prefix").unwrap();
        assert_eq!(config.bucket, "my-bucket");
        assert_eq!(config.region, Some("us-west-2".to_string()));
        assert_eq!(config.prefix, Some("my/prefix".to_string()));
        
        // Minimal config
        let config = S3Config::from_connection_string("bucket=my-bucket").unwrap();
        assert_eq!(config.bucket, "my-bucket");
        assert_eq!(config.region, None);
        assert_eq!(config.prefix, None);
        
        // Invalid config (missing bucket)
        let config = S3Config::from_connection_string("region=us-west-2");
        assert!(config.is_err());
    }
    
    #[test]
    fn test_prefixed_key() {
        // With prefix
        let config = S3Config {
            bucket: "my-bucket".to_string(),
            region: None,
            prefix: Some("my/prefix".to_string()),
        };
        assert_eq!(config.prefixed_key("test/key"), "my/prefix/test/key");
        
        // Without prefix
        let config = S3Config {
            bucket: "my-bucket".to_string(),
            region: None,
            prefix: None,
        };
        assert_eq!(config.prefixed_key("test/key"), "test/key");
    }
}
