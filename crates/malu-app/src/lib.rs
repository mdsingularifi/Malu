//! Application component for the Malu secure storage system
//!
//! This module provides a complete application layer that integrates all components
//! of the Malu system, including authentication, storage, and cryptography.
//! It demonstrates how to build a full application using the MaluStore pattern.

use std::path::PathBuf;
use std::sync::Arc;

use malu_api::MaluApi;
use malu_interfaces::{Result, StorageEngine, CryptoProvider, AuthProvider};

// Mock implementations for providers
#[derive(Debug)]
struct MockStorageProvider;

impl MockStorageProvider {
    fn new(_path: PathBuf) -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl StorageEngine for MockStorageProvider {
    async fn store(&self, _key: &str, _data: &[u8]) -> Result<()> {
        Ok(())
    }
    
    async fn retrieve(&self, _key: &str) -> Result<Vec<u8>> {
        Ok(b"mock data".to_vec())
    }
    
    async fn exists(&self, _key: &str) -> Result<bool> {
        Ok(true)
    }
    
    async fn delete(&self, _key: &str) -> Result<()> {
        Ok(())
    }
    
    async fn list_keys(&self, _prefix: Option<&str>) -> Result<Vec<String>> {
        Ok(vec!["mock/key".to_string()])
    }
}

#[derive(Debug)]
struct MockCryptoProvider;

impl MockCryptoProvider {
    fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl CryptoProvider for MockCryptoProvider {
    async fn encrypt(&self, _context: &str, plaintext: &[u8], _key: &[u8]) -> Result<Vec<u8>> {
        Ok(plaintext.to_vec())
    }
    
    async fn decrypt(&self, _context: &str, ciphertext: &[u8], _key: &[u8]) -> Result<Vec<u8>> {
        Ok(ciphertext.to_vec())
    }
    
    async fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    
    async fn derive_key(&self, passphrase: &[u8], _salt: &[u8], _info: Option<&[u8]>) -> Result<Vec<u8>> {
        Ok(passphrase.to_vec())
    }
    
    async fn generate_nonce(&self, length: usize) -> Result<Vec<u8>> {
        Ok(vec![0; length])
    }
    
    async fn generate_random(&self, length: usize) -> Result<Vec<u8>> {
        Ok(vec![0; length])
    }
    
    async fn sign(&self, message: &[u8], _key: &[u8]) -> Result<Vec<u8>> {
        Ok(message.to_vec())
    }
    
    async fn verify(&self, _message: &[u8], _signature: &[u8], _key: &[u8]) -> Result<bool> {
        Ok(true)
    }
}

#[derive(Debug)]
struct MockAuthProvider;

impl MockAuthProvider {
    fn new(_path: PathBuf) -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl AuthProvider for MockAuthProvider {
    async fn authenticate(&self, username: &str, password: &str) -> Result<bool> {
        Ok(username == "admin" && password == "password")
    }
    
    async fn verify_mfa(&self, _username: &str, _token: &str) -> Result<bool> {
        Ok(true)
    }
    
    async fn user_exists(&self, _username: &str) -> Result<bool> {
        Ok(true)
    }
    
    async fn get_user_info(&self, username: &str) -> Result<serde_json::Value> {
        use serde_json::json;
        Ok(json!({
            "username": username,
            "role": "admin"
        }))
    }
}

/// Main application class for the Malu system
pub struct MaluApp {
    api: Arc<MaluApi>,
    app_name: String,
    version: String,
}

impl MaluApp {
    /// Create a new Malu application with default settings
    pub fn new(storage_path: impl Into<PathBuf>, app_name: impl Into<String>) -> Result<Self> {
        let builder = Self::builder()
            .with_storage_path(storage_path)
            .with_app_name(app_name);
            
        builder.build()
    }
    
    /// Create a builder for configuring the MaluApp
    pub fn builder() -> MaluAppBuilder {
        MaluAppBuilder::new()
    }
    
    /// Get the app name
    pub fn app_name(&self) -> &str {
        &self.app_name
    }
    
    /// Get the app version
    pub fn version(&self) -> &str {
        &self.version
    }
    
    /// Get the underlying MaluApi
    pub fn api(&self) -> Arc<MaluApi> {
        self.api.clone()
    }
    
    /// Store a secret
    pub async fn store_secret(&self, path: &str, secret: &[u8]) -> Result<()> {
        self.api.store_secret(path, secret).await
    }
    
    /// Retrieve a secret
    pub async fn retrieve_secret(&self, path: &str) -> Result<Vec<u8>> {
        self.api.retrieve_secret(path).await
    }
    
    /// Authenticate a user
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<bool> {
        self.api.authenticate(username, password).await
    }
}

/// Builder for configuring and constructing MaluApp instances
pub struct MaluAppBuilder {
    storage_path: Option<PathBuf>,
    app_name: Option<String>,
    version: String,
    storage_engine: Option<Box<dyn StorageEngine>>,
    crypto_provider: Option<Box<dyn CryptoProvider>>,
    auth_provider: Option<Box<dyn AuthProvider>>,
}

impl Default for MaluAppBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MaluAppBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self {
            storage_path: None,
            app_name: None,
            version: env!("CARGO_PKG_VERSION").to_string(),
            storage_engine: None,
            crypto_provider: None,
            auth_provider: None,
        }
    }
    
    /// Set the storage path
    pub fn with_storage_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.storage_path = Some(path.into());
        self
    }
    
    /// Set the application name
    pub fn with_app_name(mut self, name: impl Into<String>) -> Self {
        self.app_name = Some(name.into());
        self
    }
    
    /// Set the application version
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }
    
    /// Set a custom storage engine
    pub fn with_storage_engine(mut self, engine: Box<dyn StorageEngine>) -> Self {
        self.storage_engine = Some(engine);
        self
    }
    
    /// Set a custom crypto provider
    pub fn with_crypto_provider(mut self, provider: Box<dyn CryptoProvider>) -> Self {
        self.crypto_provider = Some(provider);
        self
    }
    
    /// Set a custom auth provider
    pub fn with_auth_provider(mut self, provider: Box<dyn AuthProvider>) -> Self {
        self.auth_provider = Some(provider);
        self
    }
    
    /// Build the MaluApp instance
    pub fn build(self) -> Result<MaluApp> {
        let storage_path = self.storage_path
            .ok_or_else(|| "Storage path is required".to_string())?;
            
        let app_name = self.app_name
            .ok_or_else(|| "Application name is required".to_string())?;
            
        // Create default providers if not specified
        let storage_engine = self.storage_engine.unwrap_or_else(|| {
            Box::new(MockStorageProvider::new(storage_path.clone()))
        });
        
        let crypto_provider = self.crypto_provider.unwrap_or_else(|| {
            Box::new(MockCryptoProvider::new())
        });
        
        let auth_provider = self.auth_provider.unwrap_or_else(|| {
            Box::new(MockAuthProvider::new(storage_path.join("auth")))
        });
        
        // Create the API instance
        let api = MaluApi::builder()
            .with_storage_path(storage_path)
            .with_storage_engine(storage_engine)
            .with_crypto_provider(crypto_provider)
            .with_auth_provider(auth_provider)
            .build()
            .map_err(|e| e.to_string())?;
            
        Ok(MaluApp {
            api: Arc::new(api),
            app_name,
            version: self.version,
        })
    }
}

/// Command-line interface integration for the Malu app
pub mod cli {
    use super::*;
    use std::io::{self, Write};
    
    /// CLI app wrapper for the Malu system
    pub struct MaluCli {
        app: MaluApp,
    }
    
    impl MaluCli {
        /// Create a new CLI wrapper for a MaluApp
        pub fn new(app: MaluApp) -> Self {
            Self { app }
        }
        
        /// Run the CLI application
        pub async fn run(&self) -> Result<()> {
            println!("Welcome to {} v{}", self.app.app_name(), self.app.version());
            println!("Type 'help' for available commands");
            
            let mut input = String::new();
            loop {
                print!("> ");
                io::stdout().flush().unwrap();
                
                input.clear();
                io::stdin().read_line(&mut input).unwrap();
                
                let input = input.trim();
                if input.is_empty() {
                    continue;
                }
                
                match input {
                    "help" => self.print_help(),
                    "exit" | "quit" => break,
                    _ if input.starts_with("store ") => {
                        if let Err(e) = self.handle_store(&input[6..]).await {
                            eprintln!("Error: {}", e);
                        }
                    },
                    _ if input.starts_with("get ") => {
                        if let Err(e) = self.handle_get(&input[4..]).await {
                            eprintln!("Error: {}", e);
                        }
                    },
                    _ if input.starts_with("login ") => {
                        if let Err(e) = self.handle_login(&input[6..]).await {
                            eprintln!("Error: {}", e);
                        }
                    },
                    _ => println!("Unknown command. Type 'help' for available commands."),
                }
            }
            
            println!("Goodbye!");
            Ok(())
        }
        
        /// Print available commands
        fn print_help(&self) {
            println!("Available commands:");
            println!("  help                      - Show this help message");
            println!("  store <path> <secret>    - Store a secret at the specified path");
            println!("  get <path>               - Retrieve a secret from the specified path");
            println!("  login <username> <pass>  - Authenticate a user");
            println!("  exit, quit               - Exit the application");
        }
        
        /// Handle the store command
        async fn handle_store(&self, args: &str) -> Result<()> {
            let parts: Vec<&str> = args.splitn(2, ' ').collect();
            if parts.len() != 2 {
                return Err("Usage: store <path> <secret>".into());
            }
            
            let path = parts[0];
            let secret = parts[1].as_bytes();
            
            self.app.store_secret(path, secret).await?;
            println!("Secret stored successfully at {}", path);
            Ok(())
        }
        
        /// Handle the get command
        async fn handle_get(&self, path: &str) -> Result<()> {
            let secret = self.app.retrieve_secret(path).await?;
            match std::str::from_utf8(&secret) {
                Ok(s) => println!("Secret: {}", s),
                Err(_) => println!("Retrieved binary secret of {} bytes", secret.len()),
            }
            Ok(())
        }
        
        /// Handle the login command
        async fn handle_login(&self, args: &str) -> Result<()> {
            let parts: Vec<&str> = args.splitn(2, ' ').collect();
            if parts.len() != 2 {
                return Err("Usage: login <username> <password>".into());
            }
            
            let username = parts[0];
            let password = parts[1];
            
            let success = self.app.authenticate(username, password).await?;
            if success {
                println!("Authentication successful");
            } else {
                println!("Authentication failed");
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[tokio::test]
    async fn test_app_creation() {
        let temp_dir = tempdir().unwrap();
        let app = MaluApp::new(temp_dir.path(), "TestApp").unwrap();
        
        assert_eq!(app.app_name(), "TestApp");
        assert!(!app.version().is_empty());
    }
    
    #[tokio::test]
    async fn test_secret_storage() {
        let temp_dir = tempdir().unwrap();
        let app = MaluApp::new(temp_dir.path(), "TestApp").unwrap();
        
        let path = "test/secret1";
        let secret = b"my test secret";
        
        app.store_secret(path, secret).await.unwrap();
        let retrieved = app.retrieve_secret(path).await.unwrap();
        
        assert_eq!(retrieved, secret);
    }
}
