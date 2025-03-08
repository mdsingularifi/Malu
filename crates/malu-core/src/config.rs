//! Configuration for the Malu system with versioning and upgrade support

use malu_interfaces::VersionedEntity;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;
use std::io;

/// Configuration version for migration support
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ConfigVersion {
    V1,
    #[default]
    V2,
    // Future versions will be added here
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

impl Default for MaluConfig {
    fn default() -> Self {
        Self::new()
    }
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

impl Default for MaluConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
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
