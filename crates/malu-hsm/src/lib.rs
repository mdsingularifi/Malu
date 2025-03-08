//! Hardware Security Module (HSM) integration for the Malu system
//!
//! This crate provides integration with hardware security modules (HSMs)
//! for secure key management and cryptographic operations.
//!
//! This crate implements the CryptoProvider interface from malu_interfaces
//! for HSM-based cryptographic operations.

mod error;
pub mod provider;

pub use error::{HsmError, Result};
pub use provider::{HsmConfig, HsmType, HsmCryptoProvider};

use malu_interfaces::CryptoProvider;
use malu_core::MaluConfig;
use std::sync::Arc;
use tracing::debug;

/// Initialize the HSM subsystem
///
/// This function should be called before using any HSM functionality to ensure
/// that the underlying HSM libraries are properly initialized.
pub fn init() {
    debug!("Initializing HSM subsystem");
    
    // Any global initialization for HSM support
    #[cfg(feature = "pkcs11")]
    {
        debug!("PKCS#11 support enabled");
    }
    
    #[cfg(feature = "yubikey")]
    {
        debug!("YubiKey support enabled");
    }
    
    #[cfg(feature = "tpm")]
    {
        debug!("TPM support enabled");
    }
}

/// A factory for creating HSM crypto providers
#[derive(Debug, Clone)]
pub struct HsmCryptoProviderFactory;

impl Default for HsmCryptoProviderFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl HsmCryptoProviderFactory {
    /// Create a new factory
    pub fn new() -> Self {
        Self
    }
    
    /// Create an HSM crypto provider from the given config
    pub fn create_provider(&self, config: &MaluConfig) -> Arc<dyn CryptoProvider> {
        // Extract HSM config from the main config
        let hsm_config = match &config.crypto.hsm_config {
            Some(json_config) => {
                // Try to deserialize the JSON value into HsmConfig
                match serde_json::from_value::<HsmConfig>(json_config.clone()) {
                    Ok(config) => config,
                    Err(e) => {
                        debug!("Failed to deserialize HSM config: {}, using default", e);
                        HsmConfig::default()
                    }
                }
            },
            None => {
                debug!("HSM config not found in MaluConfig, using default");
                HsmConfig::default()
            }
        };
        
        Arc::new(HsmCryptoProvider::new(hsm_config))
    }
}

/// Create an HSM crypto provider from the given config
/// 
/// This is a convenience function that can be used with dependency injection
pub fn create_hsm_provider(config: &MaluConfig) -> Arc<dyn CryptoProvider> {
    HsmCryptoProviderFactory::new().create_provider(config)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_init() {
        super::init();
        // Just tests that init doesn't panic
        assert!(true);
    }
}
