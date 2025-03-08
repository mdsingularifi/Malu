//! Crypto component for the Malu system
//!
//! This crate provides cryptographic functionality for the Malu secure storage system,
//! including encryption, key management, digital signatures, and secure key derivation.
//! For hardware security module (HSM) support, see the `malu_hsm` crate.

mod aead;
mod error;
mod hash;
mod kdf;
mod key_management;
pub mod provider;
mod signature;

pub use error::{CryptoError, Result};
pub use provider::{CryptoProviderType, CryptoProviderFactory, SoftwareCryptoProvider};
#[cfg(feature = "hsm")]
pub use provider::register_hsm_provider_factory;
pub use malu_interfaces::CryptoProvider;
pub use key_management::{KeyManager, MasterKey, KeyId, SecretKey};
// Re-export core types but not the functions to avoid conflicts with trait methods
pub use aead::EncryptionAlgorithm;
pub use hash::HashAlgorithm;
pub use kdf::KdfAlgorithm;
pub use signature::SignatureAlgorithm;

// Re-export utility functions with more specific names to avoid confusion
pub use aead::{encrypt as encrypt_data, decrypt as decrypt_data};
pub use hash::hash as hash_data;
pub use kdf::derive_key as derive_key_from_password;
pub use signature::{sign as sign_data, verify as verify_signature};

// No need to re-export CryptoProvider from interfaces since we're re-exporting it from provider module

/// Initialize the crypto subsystem
///
/// This function should be called before using any crypto functionality to ensure
/// that the underlying cryptographic libraries are properly initialized.
pub fn init() {
    // Note: Removed sodiumoxide initialization as it's not used in the current implementation
    // We're now using standard Rust crypto libraries instead
    tracing::info!("Initializing crypto subsystem");

    // If HSM functionality is needed, initialize malu_hsm separately
}

#[cfg(test)]
mod tests {
    use super::*;
    use malu_interfaces::CryptoProvider;
    
    #[test]
    fn test_init() {
        init();
        // Just testing that init doesn't panic
        assert!(true);
    }

    #[tokio::test]
    async fn test_software_provider() {
        // Create provider with minimum iterations for test speed
        let provider = provider::SoftwareCryptoProvider::new_with_iterations(1);
        let data = b"hello world";
        let context = "test_context";
        
        // Test generating nonce
        let nonce = provider.generate_nonce(12).await.unwrap();
        assert_eq!(nonce.len(), 12);
        
        // Test key derivation with minimal parameters for speed
        let passphrase = b"test password";
        let salt = b"test salt12345";
        let derived_key = provider.derive_key(passphrase, salt, None).await.unwrap();
        assert!(!derived_key.is_empty());
        
        // Use a simple key for encryption/decryption tests to avoid slow derivation
        let key = [0u8; 32].to_vec(); // AES-256 key size
        let encrypted = provider.encrypt(context, data, &key).await.unwrap();
        let decrypted = provider.decrypt(context, &encrypted, &key).await.unwrap();
        assert_eq!(data, decrypted.as_slice());
    }
}
