//! Governance component for the Malu system
//! 
//! This module provides policy-based access control and governance for the Malu system.
//! It implements the GovernanceProvider interface defined in malu-interfaces.

mod error;
mod policy;
mod providers;

pub use error::{GovernanceError, Result};
pub use policy::{Policy, PolicyBuilder, PolicyEffect, Statement, StatementBuilder};
pub use providers::*;

// Re-export the PrincipalType from interfaces for convenience
pub use malu_interfaces::PrincipalType;

/// A builder for creating governance providers
pub struct GovernanceProviderBuilder {
    provider_type: GovernanceProviderType,
    storage_path: Option<String>,
    config: Option<serde_json::Value>,
}

/// Types of governance providers available
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernanceProviderType {
    /// In-memory provider (for testing)
    Memory,
    
    /// File-based provider
    File,
    
    /// OPA (Open Policy Agent) provider
    OPA,
    
    /// Custom provider
    Custom,
}

impl GovernanceProviderBuilder {
    /// Create a new governance provider builder
    pub fn new(provider_type: GovernanceProviderType) -> Self {
        Self {
            provider_type,
            storage_path: None,
            config: None,
        }
    }
    
    /// Set the storage path for file-based providers
    pub fn with_storage_path(mut self, path: String) -> Self {
        self.storage_path = Some(path);
        self
    }
    
    /// Set additional configuration
    pub fn with_config(mut self, config: serde_json::Value) -> Self {
        self.config = Some(config);
        self
    }
    
    /// Build the governance provider
    pub fn build(self) -> Result<Box<dyn malu_interfaces::GovernanceProvider>> {
        match self.provider_type {
            GovernanceProviderType::Memory => {
                Ok(Box::new(providers::memory::MemoryGovernanceProvider::new()))
            },
            GovernanceProviderType::File => {
                let path = self.storage_path.ok_or_else(|| {
                    GovernanceError::ConfigurationError("Storage path is required for file provider".to_string())
                })?;
                Ok(Box::new(providers::file::FileGovernanceProvider::new(path)))
            },
            GovernanceProviderType::OPA => {
                let config = self.config.ok_or_else(|| {
                    GovernanceError::ConfigurationError("Config is required for OPA provider".to_string())
                })?;
                Ok(Box::new(providers::opa::OpaGovernanceProvider::new(config)))
            },
            GovernanceProviderType::Custom => {
                Err(GovernanceError::UnsupportedOperation("Custom provider requires manual setup".to_string()))
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use malu_interfaces::GovernanceProvider;
    
    #[tokio::test]
    async fn test_memory_provider() {
        let provider = GovernanceProviderBuilder::new(GovernanceProviderType::Memory)
            .build()
            .unwrap();
        
        // Set and get a policy
        let policy_id = "test-policy";
        let policy_def = r#"{"Version":"2021-11-01","Statement":[{"Effect":"Allow","Action":["read"],"Resource":["document:*"],"Principal":["user:alice"]}]}
"#;
        
        provider.set_policy(policy_id, policy_def).await.unwrap();
        let retrieved = provider.get_policy(policy_id).await.unwrap();
        assert_eq!(retrieved, policy_def);
        
        // Test permission check
        let has_perm = provider.check_permission("alice", "read", "document:123").await.unwrap();
        assert!(has_perm);
    }
}
