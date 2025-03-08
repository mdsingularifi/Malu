//! PostgreSQL storage implementation

use std::str::FromStr;
use std::sync::Arc;
use async_trait::async_trait;
use deadpool_postgres::{Config, Pool, PoolConfig, Manager, Runtime};
use tokio_postgres::{NoTls, Row, types::Type};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use tracing::{debug, error, info};

use malu_interfaces::{StorageEngine, Result};
use crate::error::StorageError;

/// Configuration for Postgres storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresConfig {
    /// Connection string or URL for PostgreSQL
    pub connection_string: String,
    /// Table name to use for storage
    pub table_name: String,
    /// Schema name (optional)
    pub schema_name: Option<String>,
    /// Max connections in the pool (default: 10)
    pub max_connections: Option<u32>,
}

impl PostgresConfig {
    /// Parse a connection string into a PostgresConfig
    /// Format: "url=postgres://user:pass@host/dbname;table=malu_data;schema=public;max_connections=20"
    pub fn from_connection_string(conn_string: &str) -> Result<Self> {
        let mut url = None;
        let mut table_name = None;
        let mut schema_name = None;
        let mut max_connections = None;
        
        for part in conn_string.split(';') {
            let kv: Vec<&str> = part.splitn(2, '=').collect();
            if kv.len() != 2 {
                continue;
            }
            
            match kv[0].trim() {
                "url" => url = Some(kv[1].trim().to_string()),
                "table" => table_name = Some(kv[1].trim().to_string()),
                "schema" => schema_name = Some(kv[1].trim().to_string()),
                "max_connections" => {
                    if let Ok(mc) = kv[1].trim().parse::<u32>() {
                        max_connections = Some(mc);
                    }
                }
                _ => {}
            }
        }
        
        let connection_string = url.ok_or_else(|| {
            Box::new(StorageError::Internal("PostgreSQL connection string must contain 'url'".to_string())) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        let table_name = table_name.unwrap_or_else(|| "malu_data".to_string());
        
        Ok(PostgresConfig {
            connection_string,
            table_name,
            schema_name,
            max_connections,
        })
    }
    
    /// Get the fully qualified table name
    pub fn full_table_name(&self) -> String {
        match &self.schema_name {
            Some(schema) => format!("\"{}\".\"{}\"", schema, self.table_name),
            None => format!("\"{}\"", self.table_name),
        }
    }
}

/// PostgreSQL storage implementation
#[derive(Debug, Clone)]
pub struct PostgresStorage {
    config: PostgresConfig,
    pool: Pool,
}

impl PostgresStorage {
    /// Create a new PostgreSQL storage from a connection string
    pub fn new(connection_string: &str) -> Self {
        let config = PostgresConfig::from_connection_string(connection_string)
            .expect("Failed to parse PostgreSQL connection string");
        
        let mut pg_config = Config::new();
        
        // Parse the connection string to configure the pool
        // We assume that connection_string is a PostgreSQL URL
        if config.connection_string.starts_with("postgres://") {
            pg_config = Config::from_str(&config.connection_string)
                .expect("Invalid PostgreSQL connection URL");
        } else {
            // Or just set the application name if it's a complex connection string
            pg_config.application_name = Some("malu_storage".to_string());
            pg_config.dbname = Some("malu".to_string());
            pg_config.host = Some("localhost".to_string());
            // Keep other defaults
        }
        
        // Configure pool settings
        pg_config.pool = Some(PoolConfig {
            max_size: config.max_connections.unwrap_or(10),
            ..Default::default()
        });
        
        // Create the connection pool
        let pool = pg_config.create_pool(Some(Runtime::Tokio1), NoTls)
            .expect("Failed to create PostgreSQL connection pool");
        
        let storage = Self {
            config,
            pool,
        };
        
        // This is blocking, but it's only called once during initialization
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(storage.init())
            .expect("Failed to initialize PostgreSQL storage");
        
        storage
    }
    
    /// Initialize the database by creating the storage table if it doesn't exist
    async fn init(&self) -> Result<()> {
        let table_name = self.config.full_table_name();
        
        // Create schema if specified and doesn't exist
        if let Some(schema) = &self.config.schema_name {
            let schema_query = format!("CREATE SCHEMA IF NOT EXISTS \"{}\"", schema);
            
            let conn = self.pool.get().await.map_err(|e| {
                Box::new(StorageError::Internal(format!("Failed to get PostgreSQL connection: {}", e))) as Box<dyn std::error::Error + Send + Sync>
            })?;
            
            conn.execute(&schema_query, &[]).await.map_err(|e| {
                Box::new(StorageError::Internal(format!("Failed to create schema: {}", e))) as Box<dyn std::error::Error + Send + Sync>
            })?;
        }
        
        // Create table if doesn't exist
        let create_table_query = format!(
            "CREATE TABLE IF NOT EXISTS {} (
                id UUID PRIMARY KEY,
                key TEXT UNIQUE NOT NULL,
                data BYTEA NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )",
            table_name
        );
        
        let conn = self.pool.get().await.map_err(|e| {
            Box::new(StorageError::Internal(format!("Failed to get PostgreSQL connection: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        conn.execute(&create_table_query, &[]).await.map_err(|e| {
            Box::new(StorageError::Internal(format!("Failed to create table: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        // Create index on key column
        let create_index_query = format!(
            "CREATE INDEX IF NOT EXISTS {}_key_idx ON {} (key)",
            self.config.table_name, table_name
        );
        
        conn.execute(&create_index_query, &[]).await.map_err(|e| {
            Box::new(StorageError::Internal(format!("Failed to create index: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        Ok(())
    }
}

#[async_trait]
impl StorageEngine for PostgresStorage {
    async fn store(&self, key: &str, data: &[u8]) -> Result<()> {
        let table_name = self.config.full_table_name();
        
        // Upsert query using ON CONFLICT DO UPDATE
        let query = format!(
            "INSERT INTO {} (id, key, data, updated_at) 
             VALUES ($1, $2, $3, NOW()) 
             ON CONFLICT (key) 
             DO UPDATE SET data = $3, updated_at = NOW()",
            table_name
        );
        
        let conn = self.pool.get().await.map_err(|e| {
            Box::new(StorageError::Internal(format!("Failed to get PostgreSQL connection: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        // Generate a UUID for new entries
        let id = Uuid::new_v4();
        
        conn.execute(&query, &[&id, &key, &data]).await.map_err(|e| {
            Box::new(StorageError::Internal(format!("Failed to store data: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        Ok(())
    }
    
    async fn retrieve(&self, key: &str) -> Result<Vec<u8>> {
        let table_name = self.config.full_table_name();
        
        let query = format!(
            "SELECT data FROM {} WHERE key = $1",
            table_name
        );
        
        let conn = self.pool.get().await.map_err(|e| {
            Box::new(StorageError::Internal(format!("Failed to get PostgreSQL connection: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        let row = conn.query_opt(&query, &[&key]).await.map_err(|e| {
            Box::new(StorageError::Internal(format!("Failed to retrieve data: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        match row {
            Some(row) => {
                let data: Vec<u8> = row.get("data");
                Ok(data)
            },
            None => Err(Box::new(StorageError::NotFound(key.to_string())) as Box<dyn std::error::Error + Send + Sync>),
        }
    }
    
    async fn exists(&self, key: &str) -> Result<bool> {
        let table_name = self.config.full_table_name();
        
        let query = format!(
            "SELECT 1 FROM {} WHERE key = $1 LIMIT 1",
            table_name
        );
        
        let conn = self.pool.get().await.map_err(|e| {
            Box::new(StorageError::Internal(format!("Failed to get PostgreSQL connection: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        let row = conn.query_opt(&query, &[&key]).await.map_err(|e| {
            Box::new(StorageError::Internal(format!("Failed to check if key exists: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        Ok(row.is_some())
    }
    
    async fn delete(&self, key: &str) -> Result<()> {
        let table_name = self.config.full_table_name();
        
        // First check if the key exists
        if !self.exists(key).await? {
            return Err(Box::new(StorageError::NotFound(key.to_string())) as Box<dyn std::error::Error + Send + Sync>);
        }
        
        let query = format!(
            "DELETE FROM {} WHERE key = $1",
            table_name
        );
        
        let conn = self.pool.get().await.map_err(|e| {
            Box::new(StorageError::Internal(format!("Failed to get PostgreSQL connection: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        conn.execute(&query, &[&key]).await.map_err(|e| {
            Box::new(StorageError::Internal(format!("Failed to delete data: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        Ok(())
    }
    
    async fn list_keys(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        let table_name = self.config.full_table_name();
        
        let (query, params) = match prefix {
            Some(prefix) => {
                let query = format!(
                    "SELECT key FROM {} WHERE key LIKE $1 ORDER BY key",
                    table_name
                );
                let like_pattern = format!("{}%", prefix);
                (query, vec![like_pattern])
            },
            None => {
                let query = format!(
                    "SELECT key FROM {} ORDER BY key",
                    table_name
                );
                (query, vec![])
            }
        };
        
        let conn = self.pool.get().await.map_err(|e| {
            Box::new(StorageError::Internal(format!("Failed to get PostgreSQL connection: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        let stmt = conn.prepare(&query).await.map_err(|e| {
            Box::new(StorageError::Internal(format!("Failed to prepare statement: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        let rows = match prefix {
            Some(_) => conn.query(&stmt, &[&params[0]]).await,
            None => conn.query(&stmt, &[]).await,
        }.map_err(|e| {
            Box::new(StorageError::Internal(format!("Failed to list keys: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        let keys = rows.iter()
            .map(|row| row.get::<_, String>("key"))
            .collect();
        
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_postgres_config_from_connection_string() {
        // Full config
        let config = PostgresConfig::from_connection_string(
            "url=postgres://user:pass@localhost:5432/malu;table=malu_data;schema=public;max_connections=20"
        ).unwrap();
        
        assert_eq!(config.connection_string, "postgres://user:pass@localhost:5432/malu");
        assert_eq!(config.table_name, "malu_data");
        assert_eq!(config.schema_name, Some("public".to_string()));
        assert_eq!(config.max_connections, Some(20));
        
        // Minimal config
        let config = PostgresConfig::from_connection_string(
            "url=postgres://user:pass@localhost:5432/malu"
        ).unwrap();
        
        assert_eq!(config.connection_string, "postgres://user:pass@localhost:5432/malu");
        assert_eq!(config.table_name, "malu_data"); // Default
        assert_eq!(config.schema_name, None);
        assert_eq!(config.max_connections, None);
        
        // Invalid config (missing url)
        let config = PostgresConfig::from_connection_string(
            "table=malu_data;schema=public"
        );
        assert!(config.is_err());
    }
    
    #[test]
    fn test_full_table_name() {
        // With schema
        let config = PostgresConfig {
            connection_string: "postgres://localhost/malu".to_string(),
            table_name: "malu_data".to_string(),
            schema_name: Some("public".to_string()),
            max_connections: None,
        };
        assert_eq!(config.full_table_name(), "\"public\".\"malu_data\"");
        
        // Without schema
        let config = PostgresConfig {
            connection_string: "postgres://localhost/malu".to_string(),
            table_name: "malu_data".to_string(),
            schema_name: None,
            max_connections: None,
        };
        assert_eq!(config.full_table_name(), "\"malu_data\"");
    }
}
