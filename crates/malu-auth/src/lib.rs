//! Auth component for the Malu system
//!
//! This crate provides authentication functionality for the Malu system,
//! implementing the AuthProvider interface from malu_interfaces.
//!
//! Multiple auth provider implementations are available:
//! - Local: Username/password based authentication against local storage
//! - OIDC: OpenID Connect based authentication
//! - LDAP: Lightweight Directory Access Protocol (placeholder)

mod error;
mod provider;

pub use error::{AuthError, Result};
pub use provider::{LocalAuthProvider, OidcAuthProvider, AuthProviderFactory, AuthProviderCreator};

use malu_interfaces::AuthProvider;
use malu_core::MaluConfig;
use std::sync::Arc;

/// Convenience function to create an auth provider from config
pub fn create_auth_provider(config: &MaluConfig) -> Arc<dyn AuthProvider> {
    AuthProviderFactory::create(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use malu_core::{AuthConfig, AuthProviderType};
    
    #[tokio::test]
    async fn test_local_auth() {
        let mut provider = LocalAuthProvider::new(false);
        provider.add_test_user("testuser", "password123");
        
        // Test successful authentication
        let result = provider.authenticate("testuser", "password123").await;
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Test failed authentication
        let result = provider.authenticate("testuser", "wrongpassword").await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
        
        // Test user existence
        let result = provider.user_exists("testuser").await;
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Test user info
        let result = provider.get_user_info("testuser").await;
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info["username"], "testuser");
    }
}
