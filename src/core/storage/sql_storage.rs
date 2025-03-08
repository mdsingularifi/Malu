use crate::core::{StorageProvider, error::{Result, ServiceError}};
use async_trait::async_trait;
use std::sync::Arc;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

/// Storage provider that stores secrets in a SQL database
pub struct SqlStorageProvider {
    pool: Pool<Postgres>,
    table_name: String,
}

impl SqlStorageProvider {
    /// Create a new SqlStorageProvider with the given database pool
    pub fn new(pool: Pool<Postgres>, table_name: String) -> Self {
        Self {
            pool,
            table_name,
        }
    }
    
    /// Initialize the database schema
    pub async fn init_schema(&self) -> Result<()> {
        // Create the secrets table if it doesn't exist
        let query = format!(
            "CREATE TABLE IF NOT EXISTS {} (
                id UUID PRIMARY KEY,
                path TEXT UNIQUE NOT NULL,
                data BYTEA NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )",
            self.table_name
        );
        
        sqlx::query(&query)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                ServiceError::StorageError(format!("Failed to create schema: {}", e))
            })?;
        
        // Create an index on the path column for faster lookups
        let index_query = format!(
            "CREATE INDEX IF NOT EXISTS {}_path_idx ON {} (path)",
            self.table_name, self.table_name
        );
        
        sqlx::query(&index_query)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                ServiceError::StorageError(format!("Failed to create index: {}", e))
            })?;
        
        Ok(())
    }
}

#[async_trait]
impl StorageProvider for SqlStorageProvider {
    async fn store(&self, path: &str, data: &[u8]) -> Result<()> {
        // Check if the path already exists
        let exists = self.exists(path).await?;
        
        if exists {
            // Update existing record
            let query = format!(
                "UPDATE {} SET data = $1, updated_at = NOW() WHERE path = $2",
                self.table_name
            );
            
            sqlx::query(&query)
                .bind(data)
                .bind(path)
                .execute(&self.pool)
                .await
                .map_err(|e| {
                    ServiceError::StorageError(format!("Failed to update secret: {}", e))
                })?;
        } else {
            // Insert new record
            let query = format!(
                "INSERT INTO {} (id, path, data) VALUES ($1, $2, $3)",
                self.table_name
            );
            
            sqlx::query(&query)
                .bind(Uuid::new_v4())
                .bind(path)
                .bind(data)
                .execute(&self.pool)
                .await
                .map_err(|e| {
                    ServiceError::StorageError(format!("Failed to store secret: {}", e))
                })?;
        }
        
        Ok(())
    }
    
    async fn retrieve(&self, path: &str) -> Result<Vec<u8>> {
        let query = format!(
            "SELECT data FROM {} WHERE path = $1",
            self.table_name
        );
        
        let result: Option<(Vec<u8>,)> = sqlx::query_as(&query)
            .bind(path)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                ServiceError::StorageError(format!("Failed to retrieve secret: {}", e))
            })?;
        
        match result {
            Some((data,)) => Ok(data),
            None => Err(ServiceError::NotFound(format!("Secret not found: {}", path))),
        }
    }
    
    async fn delete(&self, path: &str) -> Result<()> {
        let query = format!(
            "DELETE FROM {} WHERE path = $1",
            self.table_name
        );
        
        let result = sqlx::query(&query)
            .bind(path)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                ServiceError::StorageError(format!("Failed to delete secret: {}", e))
            })?;
        
        if result.rows_affected() == 0 {
            return Err(ServiceError::NotFound(format!("Secret not found: {}", path)));
        }
        
        Ok(())
    }
    
    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        let query = match prefix {
            Some(_prefix) => {
                format!(
                    "SELECT path FROM {} WHERE path LIKE $1 ORDER BY path",
                    self.table_name
                )
            },
            None => {
                format!(
                    "SELECT path FROM {} ORDER BY path",
                    self.table_name
                )
            }
        };
        
        let paths: Vec<(String,)> = match prefix {
            Some(prefix) => {
                sqlx::query_as(&query)
                    .bind(format!("{}%", prefix))
                    .fetch_all(&self.pool)
                    .await
                    .map_err(|e| {
                        ServiceError::StorageError(format!("Failed to list secrets: {}", e))
                    })?
            },
            None => {
                sqlx::query_as(&query)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(|e| {
                        ServiceError::StorageError(format!("Failed to list secrets: {}", e))
                    })?
            }
        };
        
        Ok(paths.into_iter().map(|(path,)| path).collect())
    }
    
    async fn exists(&self, path: &str) -> Result<bool> {
        let query = format!(
            "SELECT COUNT(*) FROM {} WHERE path = $1",
            self.table_name
        );
        
        let count: (i64,) = sqlx::query_as(&query)
            .bind(path)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| {
                ServiceError::StorageError(format!("Failed to check if secret exists: {}", e))
            })?;
        
        Ok(count.0 > 0)
    }
}

// Factory function to create a new SQL storage provider
pub async fn create_sql_storage_provider(
    database_url: &str,
    table_name: Option<&str>
) -> Result<Arc<SqlStorageProvider>> {
    // Use "secrets" as the default table name if none is provided
    let table_name = table_name.unwrap_or("secrets");
    
    // Connect to the database
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .map_err(|e| {
            ServiceError::StorageError(format!("Failed to connect to database: {}", e))
        })?;
    
    let provider = SqlStorageProvider::new(pool, table_name.to_string());
    
    // Initialize the schema
    provider.init_schema().await?;
    
    tracing::info!("Created SQL storage provider with table: {}", table_name);
    Ok(Arc::new(provider))
}
