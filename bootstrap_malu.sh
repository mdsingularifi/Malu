#!/bin/bash

# Set the root directory for the Malu project
MALU_ROOT="/Users/mdegraw/Coding/Malu"

# Create crates directory
mkdir -p "$MALU_ROOT/crates"

# Create all crate directories with src subdirectories
CRATES=(
  "malu-interfaces"
  "malu-core"
  "malu-storage"
  "malu-crypto"
  "malu-auth"
  "malu-api"
  "malu-app"
  "malu-cli"
  "malu-event"
  "malu-governance"
  "malu-hsm"
  "malu-k8s"
  "malu-observability"
  "malu-recovery"
)

for crate in "${CRATES[@]}"; do
  mkdir -p "$MALU_ROOT/crates/$crate/src"
  echo "Created directory: $MALU_ROOT/crates/$crate/src"
done

# Create workspace Cargo.toml
cat > "$MALU_ROOT/Cargo.toml" << 'EOL'
[workspace]
members = [
    "crates/malu-interfaces",
    "crates/malu-core",
    "crates/malu-storage",
    "crates/malu-crypto",
    "crates/malu-auth",
    "crates/malu-api",
    "crates/malu-app",
    "crates/malu-cli",
    "crates/malu-event",
    "crates/malu-governance",
    "crates/malu-hsm",
    "crates/malu-k8s",
    "crates/malu-observability",
    "crates/malu-recovery",
]

[workspace.dependencies]
tokio = { version = "1.32.0", features = ["full"] }
tracing = "0.1.37"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "1.0"
anyhow = "1.0"
async-trait = "0.1"
log = "0.4"
futures = "0.3"
uuid = { version = "1.4", features = ["v4", "serde"] }
EOL
echo "Created workspace Cargo.toml"

# Create Cargo.toml for malu-interfaces
cat > "$MALU_ROOT/crates/malu-interfaces/Cargo.toml" << 'EOL'
[package]
name = "malu_interfaces"
version = "0.1.0"
edition = "2021"
description = "Common interfaces for the Malu secure storage system"
authors = ["Malu Team"]
license = "PROPRIETARY"

[dependencies]
async-trait = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
EOL
echo "Created malu-interfaces Cargo.toml"

# Create malu-interfaces lib.rs
cat > "$MALU_ROOT/crates/malu-interfaces/src/lib.rs" << 'EOL'
//! Common interfaces for the Malu secure storage system

use async_trait::async_trait;
use std::error::Error;
use std::fmt::Debug;

/// Common result type for all Malu operations
pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

/// Storage engine interface
#[async_trait]
pub trait StorageEngine: Send + Sync + Debug {
    /// Store data with the given key
    async fn store(&self, key: &str, data: &[u8]) -> Result<()>;
    
    /// Retrieve data for the given key
    async fn retrieve(&self, key: &str) -> Result<Vec<u8>>;
    
    /// Check if a key exists
    async fn exists(&self, key: &str) -> Result<bool>;
    
    /// Delete data for the given key
    async fn delete(&self, key: &str) -> Result<()>;
    
    /// List keys with optional prefix
    async fn list_keys(&self, prefix: Option<&str>) -> Result<Vec<String>>;
}

/// Cryptographic provider interface
#[async_trait]
pub trait CryptoProvider: Send + Sync + Debug {
    /// Encrypt data
    async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    
    /// Decrypt data
    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
    
    /// Generate a secure random nonce
    fn generate_nonce(&self, size: usize) -> Result<Vec<u8>>;
    
    /// Derive a key from a password
    fn derive_key(&self, password: &str, salt: &[u8], iterations: u32) -> Result<Vec<u8>>;
}

/// Authentication provider interface
#[async_trait]
pub trait AuthProvider: Send + Sync + Debug {
    /// Authenticate a user
    async fn authenticate(&self, username: &str, password: &str) -> Result<bool>;
    
    /// Verify MFA if required
    async fn verify_mfa(&self, username: &str, token: &str) -> Result<bool>;
    
    /// Check if a user exists
    async fn user_exists(&self, username: &str) -> Result<bool>;
    
    /// Get user information
    async fn get_user_info(&self, username: &str) -> Result<serde_json::Value>;
}

/// Defines versioned entities that support migration
pub trait VersionedEntity {
    /// Get the current version
    fn version(&self) -> u32;
    
    /// Migrate to the latest version
    fn migrate_to_latest(self) -> Self;
}
EOL
echo "Created malu-interfaces lib.rs"

# Create Cargo.toml for malu-core
cat > "$MALU_ROOT/crates/malu-core/Cargo.toml" << 'EOL'
[package]
name = "malu_core"
version = "0.1.0"
edition = "2021"
description = "Core component for the Malu storage system"
authors = ["Malu Team"]
license = "PROPRIETARY"

[dependencies]
tokio = { workspace = true }
tracing = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
anyhow = { workspace = true }
async-trait = { workspace = true }
uuid = { workspace = true }

# Common interfaces
malu_interfaces = { path = "../malu-interfaces" }

[features]
default = []
with_events = []
EOL
echo "Created malu-core Cargo.toml"

# Create config.rs for malu-core
cat > "$MALU_ROOT/crates/malu-core/src/config.rs" << 'EOL'
//! Configuration for the Malu system with versioning and upgrade support

use malu_interfaces::VersionedEntity;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;
use std::io;

/// Configuration version for migration support
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigVersion {
    V1,
    V2,
    // Future versions will be added here
}

impl Default for ConfigVersion {
    fn default() -> Self {
        ConfigVersion::V2 // Current version
    }
}

/// Configuration for the Malu system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaluConfig {
    /// Version tag for upgrade support
    #[serde(default)]
    pub version: ConfigVersion,
    
    /// Base path for storage
    pub storage_path: PathBuf,
    
    /// Authentication configuration
    pub auth: AuthConfig,
    
    /// Cryptographic configuration
    pub crypto: CryptoConfig,
    
    /// Additional settings that may vary by version
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<ConfigExtension>,
}

/// Extension point for future config additions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigExtension {
    pub extension_type: String,
    pub data: serde_json::Value,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Authentication provider type
    pub provider_type: AuthProviderType,
    
    /// MFA required flag
    pub require_mfa: bool,
    
    /// OIDC configuration if applicable
    pub oidc: Option<OidcConfig>,
}

/// Authentication provider types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AuthProviderType {
    /// Local authentication
    Local,
    
    /// OIDC authentication
    Oidc,
    
    /// LDAP authentication
    Ldap,
}

/// OIDC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// Client ID
    pub client_id: String,
    
    /// Client secret
    pub client_secret: String,
    
    /// Issuer URL
    pub issuer_url: String,
    
    /// Redirect URL
    pub redirect_url: String,
}

/// Cryptographic configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Provider type
    pub provider_type: CryptoProviderType,
    
    /// Key derivation iterations
    pub kdf_iterations: u32,
}

/// Cryptographic provider types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CryptoProviderType {
    /// Software-based cryptography
    Software,
    
    /// HSM-based cryptography
    Hsm,
}

impl MaluConfig {
    /// Create a new configuration with default settings and current version
    pub fn new() -> Self {
        Self {
            version: ConfigVersion::default(),
            storage_path: PathBuf::from("/var/lib/malu"),
            auth: AuthConfig {
                provider_type: AuthProviderType::Local,
                require_mfa: true,
                oidc: None,
            },
            crypto: CryptoConfig {
                provider_type: CryptoProviderType::Software,
                kdf_iterations: 100000,
            },
            extensions: Vec::new(),
        }
    }
    
    /// Load configuration from a file with automatic version migration
    pub fn from_file(path: &PathBuf) -> Result<Self, io::Error> {
        let file_content = fs::read_to_string(path)?;
        let config: MaluConfig = serde_json::from_str(&file_content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            
        // Perform version upgrades if needed
        Ok(config.migrate_to_latest())
    }
    
    /// Save configuration to a file
    pub fn to_file(&self, path: &PathBuf) -> Result<(), io::Error> {
        let serialized = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, serialized)
    }
    
    /// Create a backwards compatibility version (if needed for legacy systems)
    pub fn to_v1_compat(&self) -> V1CompatConfig {
        V1CompatConfig {
            storage_path: self.storage_path.clone(),
            auth: V1AuthConfig {
                provider_type: match self.auth.provider_type {
                    AuthProviderType::Local => "local".to_string(),
                    AuthProviderType::Oidc => "oidc".to_string(),
                    AuthProviderType::Ldap => "ldap".to_string(),
                },
                require_mfa: self.auth.require_mfa,
                oidc: self.auth.oidc.clone(),
            },
            crypto: V1CryptoConfig {
                provider_type: match self.crypto.provider_type {
                    CryptoProviderType::Software => "software".to_string(),
                    CryptoProviderType::Hsm => "hsm".to_string(),
                },
                kdf_iterations: self.crypto.kdf_iterations,
            },
        }
    }
}

impl VersionedEntity for MaluConfig {
    fn version(&self) -> u32 {
        match self.version {
            ConfigVersion::V1 => 1,
            ConfigVersion::V2 => 2,
        }
    }
    
    fn migrate_to_latest(self) -> Self {
        match self.version {
            ConfigVersion::V1 => self.migrate_v1_to_v2().migrate_to_latest(),
            ConfigVersion::V2 => self, // Already at latest version
        }
    }
}

impl MaluConfig {
    /// Migrate from V1 to V2 format
    fn migrate_v1_to_v2(mut self) -> Self {
        // Example migration logic
        self.version = ConfigVersion::V2;
        
        // Migration-specific transformations would go here
        // For example, if V2 added a new field with a default value:
        // self.new_field = Some(default_value);
        
        self
    }
}

/// V1 compatible configuration (for backwards compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct V1CompatConfig {
    pub storage_path: PathBuf,
    pub auth: V1AuthConfig,
    pub crypto: V1CryptoConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct V1AuthConfig {
    pub provider_type: String,
    pub require_mfa: bool,
    pub oidc: Option<OidcConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct V1CryptoConfig {
    pub provider_type: String,
    pub kdf_iterations: u32,
}

/// Configuration builder for more flexible construction
pub struct MaluConfigBuilder {
    config: MaluConfig,
}

impl MaluConfigBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self {
            config: MaluConfig::new(),
        }
    }
    
    /// Set the storage path
    pub fn with_storage_path(mut self, path: PathBuf) -> Self {
        self.config.storage_path = path;
        self
    }
    
    /// Configure local authentication
    pub fn with_local_auth(mut self, require_mfa: bool) -> Self {
        self.config.auth.provider_type = AuthProviderType::Local;
        self.config.auth.require_mfa = require_mfa;
        self.config.auth.oidc = None;
        self
    }
    
    /// Configure OIDC authentication
    pub fn with_oidc_auth(
        mut self, 
        client_id: String,
        client_secret: String,
        issuer_url: String,
        redirect_url: String,
        require_mfa: bool,
    ) -> Self {
        self.config.auth.provider_type = AuthProviderType::Oidc;
        self.config.auth.require_mfa = require_mfa;
        self.config.auth.oidc = Some(OidcConfig {
            client_id,
            client_secret,
            issuer_url,
            redirect_url,
        });
        self
    }
    
    /// Configure software-based cryptography
    pub fn with_software_crypto(mut self, kdf_iterations: u32) -> Self {
        self.config.crypto.provider_type = CryptoProviderType::Software;
        self.config.crypto.kdf_iterations = kdf_iterations;
        self
    }
    
    /// Configure HSM-based cryptography
    pub fn with_hsm_crypto(mut self) -> Self {
        self.config.crypto.provider_type = CryptoProviderType::Hsm;
        self
    }
    
    /// Add a config extension for future compatibility
    pub fn with_extension(mut self, extension_type: String, data: serde_json::Value) -> Self {
        self.config.extensions.push(ConfigExtension {
            extension_type,
            data,
        });
        self
    }
    
    /// Build the final configuration
    pub fn build(self) -> MaluConfig {
        self.config
    }
}
EOL
echo "Created malu-core config.rs"

# Create error.rs for malu-core
cat > "$MALU_ROOT/crates/malu-core/src/error.rs" << 'EOL'
//! Error types for the Malu system

use thiserror::Error;

/// Error type for Malu operations
#[derive(Error, Debug)]
pub enum MaluError {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    /// Authentication error
    #[error("Authentication error: {0}")]
    Authentication(String),
    
    /// Cryptographic error
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    
    /// Storage error
    #[error("Storage error: {0}")]
    Storage(String),
    
    /// Not found error
    #[error("Not found: {0}")]
    NotFound(String),
    
    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),
    
    /// Not implemented
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    
    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    /// Version mismatch
    #[error("Version mismatch: {0}")]
    VersionMismatch(String),
}

/// Result type for Malu operations
pub type Result<T> = std::result::Result<T, MaluError>;
EOL
echo "Created malu-core error.rs"

# Create lib.rs for malu-core
cat > "$MALU_ROOT/crates/malu-core/src/lib.rs" << 'EOL'
//! Core functionality for the Malu secure storage system

mod config;
mod error;
// Other modules will go here

pub use config::{
    MaluConfig, ConfigVersion, AuthConfig, CryptoConfig, 
    AuthProviderType, CryptoProviderType, OidcConfig,
    MaluConfigBuilder
};
pub use error::{MaluError, Result};

use malu_interfaces::{StorageEngine, CryptoProvider, AuthProvider};
use std::sync::Arc;

/// Main entry point for the Malu system
pub struct MaluStore {
    config: Arc<MaluConfig>,
    storage_engine: Box<dyn StorageEngine>,
    crypto_provider: Box<dyn CryptoProvider>,
    auth_provider: Box<dyn AuthProvider>,
}

impl MaluStore {
    /// Create a new MaluStore with the provided components
    pub fn new(
        config: MaluConfig,
        storage_engine: Box<dyn StorageEngine>,
        crypto_provider: Box<dyn CryptoProvider>,
        auth_provider: Box<dyn AuthProvider>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            storage_engine,
            crypto_provider,
            auth_provider,
        }
    }
    
    /// Create a builder for constructing a MaluStore
    pub fn builder() -> MaluStoreBuilder {
        MaluStoreBuilder::new()
    }
    
    /// Store a secret in the secure store
    pub async fn store_secret(&self, path: &str, secret: &[u8]) -> malu_interfaces::Result<()> {
        // Encrypt the secret
        let encrypted = self.crypto_provider.encrypt(secret).await?;
        
        // Store the encrypted data
        self.storage_engine.store(path, &encrypted).await?;
        
        Ok(())
    }
    
    /// Retrieve a secret from the secure store
    pub async fn retrieve_secret(&self, path: &str) -> malu_interfaces::Result<Vec<u8>> {
        // Retrieve the encrypted data
        let encrypted = self.storage_engine.retrieve(path).await?;
        
        // Decrypt the data
        let decrypted = self.crypto_provider.decrypt(&encrypted).await?;
        
        Ok(decrypted)
    }
    
    /// Authenticate a user
    pub async fn authenticate(&self, username: &str, password: &str) -> malu_interfaces::Result<bool> {
        self.auth_provider.authenticate(username, password).await
    }
}

/// Builder for MaluStore to facilitate flexible construction
pub struct MaluStoreBuilder {
    config: Option<MaluConfig>,
    storage_engine: Option<Box<dyn StorageEngine>>,
    crypto_provider: Option<Box<dyn CryptoProvider>>,
    auth_provider: Option<Box<dyn AuthProvider>>,
}

impl MaluStoreBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: None,
            storage_engine: None,
            crypto_provider: None,
            auth_provider: None,
        }
    }
    
    /// Set the configuration
    pub fn with_config(mut self, config: MaluConfig) -> Self {
        self.config = Some(config);
        self
    }
    
    /// Set the storage engine
    pub fn with_storage_engine(mut self, storage_engine: Box<dyn StorageEngine>) -> Self {
        self.storage_engine = Some(storage_engine);
        self
    }
    
    /// Set the crypto provider
    pub fn with_crypto_provider(mut self, crypto_provider: Box<dyn CryptoProvider>) -> Self {
        self.crypto_provider = Some(crypto_provider);
        self
    }
    
    /// Set the auth provider
    pub fn with_auth_provider(mut self, auth_provider: Box<dyn AuthProvider>) -> Self {
        self.auth_provider = Some(auth_provider);
        self
    }
    
    /// Build the MaluStore
    pub fn build(self) -> Result<MaluStore, &'static str> {
        let config = self.config.ok_or("Configuration is required")?;
        let storage_engine = self.storage_engine.ok_or("Storage engine is required")?;
        let crypto_provider = self.crypto_provider.ok_or("Crypto provider is required")?;
        let auth_provider = self.auth_provider.ok_or("Auth provider is required")?;
        
        Ok(MaluStore::new(
            config,
            storage_engine,
            crypto_provider,
            auth_provider,
        ))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
EOL
echo "Created malu-core lib.rs"

# Create basic Cargo.toml and lib.rs templates for other crates
for crate in "${CRATES[@]}"; do
  # Skip crates we've already created
  if [[ "$crate" == "malu-interfaces" || "$crate" == "malu-core" ]]; then
    continue
  fi
  
  # Create a basic Cargo.toml
  PKG_NAME=$(echo "$crate" | tr '-' '_')
  DESCRIPTION="$(echo "$crate" | sed 's/malu-//' | tr '[:lower:]' '[:upper:]' | cut -c1)$(echo "$crate" | sed 's/malu-//' | cut -c2-) component for the Malu system"
  
  cat > "$MALU_ROOT/crates/$crate/Cargo.toml" << EOL
[package]
name = "$PKG_NAME"
version = "0.1.0"
edition = "2021"
description = "$DESCRIPTION"
authors = ["Malu Team"]
license = "PROPRIETARY"

[dependencies]
tokio = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
async-trait = { workspace = true }

# Common interfaces
malu_interfaces = { path = "../malu-interfaces" }
malu_core = { path = "../malu-core" }
EOL
  echo "Created $crate Cargo.toml"
  
  # Create a basic lib.rs
  cat > "$MALU_ROOT/crates/$crate/src/lib.rs" << EOL
//! $DESCRIPTION

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
EOL
  echo "Created $crate lib.rs"
done

# Create a README.md
cat > "$MALU_ROOT/README.md" << 'EOL'
# Malu Secure Storage System

Malu is a secure storage system designed to provide robust, flexible, and secure data management capabilities.

## Features

- **Extensible Provider Architecture**: Pluggable storage, crypto, and authentication providers
- **Versioned Configuration**: Support for seamless config upgrades
- **Strong Type Safety**: Rust's type system ensures correctness
- **Modular Design**: Independent, upgradeable crate structure

## Project Structure

- **malu-interfaces**: Core trait definitions
- **malu-core**: Central functionality and configuration
- **malu-storage**: Storage provider implementations
- **malu-crypto**: Cryptographic provider implementations
- **malu-auth**: Authentication provider implementations
- **malu-api**: API for external system integration
- **malu-app**: Complete application integration
- And many other specialized crates

## Getting Started

```bash
# Build the project
cargo build

# Run the tests
cargo test