//! Crypto provider implementations
//!
//! This module contains implementations of the CryptoProvider trait,
//! which is the main interface for cryptographic operations in the Malu system.

use async_trait::async_trait;
use malu_interfaces::{CryptoProvider, Result};
use malu_core::MaluConfig;
use crate::error::CryptoError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::debug;

/// Types of crypto providers available
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoProviderType {
    /// Software-based cryptography (default)
    Software,
    
    /// Hardware Security Module (HSM)
    #[cfg(feature = "hsm")]
    Hsm,
}

/// Factory for creating CryptoProvider instances
pub struct CryptoProviderFactory;

impl CryptoProviderFactory {
    /// Create a new CryptoProvider based on the specified type
    pub fn create(provider_type: CryptoProviderType, config: &MaluConfig) -> Arc<dyn CryptoProvider> {
        match provider_type {
            CryptoProviderType::Software => {
                let kdf_iterations = config.crypto.kdf_iterations;
                Arc::new(SoftwareCryptoProvider::new_with_iterations(kdf_iterations))
            },
            #[cfg(feature = "hsm")]
            CryptoProviderType::Hsm => {
                let hsm_config = &config.crypto.hsm_config;
                Arc::new(crate::hsm::HsmCryptoProvider::new(hsm_config))
            }
        }
    }
}

/// Software-based crypto provider
///
/// This provider implements all cryptographic operations using software libraries.
/// It is the default provider and doesn't require any special hardware.
#[derive(Debug, Clone)]
pub struct SoftwareCryptoProvider {
    kdf_iterations: u32,
}

impl SoftwareCryptoProvider {
    /// Create a new software crypto provider with default settings
    pub fn new() -> Self {
        Self {
            kdf_iterations: 10_000,
        }
    }

    /// Create a new software crypto provider with specified KDF iterations
    pub fn new_with_iterations(kdf_iterations: u32) -> Self {
        Self {
            kdf_iterations,
        }
    }
    
    /// Generate a nonce of specified length
    fn generate_nonce_internal(&self, length: usize) -> Vec<u8> {
        let mut nonce = vec![0u8; length];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        nonce
    }
}

impl Default for SoftwareCryptoProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CryptoProvider for SoftwareCryptoProvider {
    async fn encrypt(&self, context: &str, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        debug!("Encrypting data with context: {}", context);
        
        let nonce = self.generate_nonce_internal(12);
        
        // Use AES-GCM for authenticated encryption
        use aes_gcm::{
            aead::{Aead, KeyInit, Payload},
            Aes256Gcm, Nonce
        };
        
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| Box::new(CryptoError::Key(format!("Invalid key: {}", e))))?;
            
        let payload = Payload {
            msg: plaintext,
            aad: context.as_bytes(),
        };
        
        let nonce = Nonce::from_slice(&nonce);
        
        let ciphertext = cipher.encrypt(nonce, payload)
            .map_err(|e| Box::new(CryptoError::Encryption(format!("Encryption failed: {:?}", e))))?;
            
        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(nonce);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    async fn decrypt(&self, context: &str, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        debug!("Decrypting data with context: {}", context);
        
        if ciphertext.len() < 12 {
            return Err(Box::new(CryptoError::Decryption("Ciphertext too short".into())));
        }
        
        // Extract nonce and actual ciphertext
        let nonce = &ciphertext[..12];
        let actual_ciphertext = &ciphertext[12..];
        
        // Use AES-GCM for authenticated decryption
        use aes_gcm::{
            aead::{Aead, KeyInit, Payload},
            Aes256Gcm, Nonce
        };
        
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| Box::new(CryptoError::Key(format!("Invalid key: {}", e))))?;
            
        let payload = Payload {
            msg: actual_ciphertext,
            aad: context.as_bytes(),
        };
        
        let nonce = Nonce::from_slice(nonce);
        
        let plaintext = cipher.decrypt(nonce, payload)
            .map_err(|e| Box::new(CryptoError::Decryption(format!("Decryption failed: {:?}", e))))?;
            
        Ok(plaintext)
    }

    async fn derive_key(&self, passphrase: &[u8], salt: &[u8], _info: Option<&[u8]>) -> Result<Vec<u8>> {
        debug!("Deriving key from passphrase with optional info");
        
        // Use Argon2id for password-based key derivation
        use argon2::{
            password_hash::{PasswordHasher, SaltString},
            Argon2, Params, Algorithm, Version,
        };
        
        // Ensure salt is at least 16 bytes (if not, extend it)
        let mut extended_salt = salt.to_vec();
        if extended_salt.len() < 16 {
            extended_salt.resize(16, 0);
        }
        
        // Convert salt to SaltString
        let salt_str = SaltString::encode_b64(&extended_salt[..16])
            .map_err(|e| Box::new(CryptoError::Key(format!("Salt encoding error: {}", e))))?;
        
        // Configure Argon2
        let params = Params::new(
            // Memory cost in KB
            1024 * 4,
            // Time cost (iterations)
            self.kdf_iterations,
            // Parallelism factor
            4,
            Some(32), // Output length
        )
        .map_err(|e| Box::new(CryptoError::Algorithm(format!("Invalid Argon2 parameters: {}", e))))?;
        
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            params,
        );
        
        // Derive key
        let password_hash = argon2
            .hash_password(passphrase, &salt_str)
            .map_err(|e| Box::new(CryptoError::Key(format!("Key derivation failed: {}", e))))?;
        
        // Extract hash bytes
        let hash = password_hash.hash.ok_or_else(|| {
            Box::new(CryptoError::Internal("Failed to get hash from password".into()))
        })?;
        
        Ok(hash.as_bytes().to_vec())
    }

    async fn generate_nonce(&self, length: usize) -> Result<Vec<u8>> {
        debug!("Generating nonce of {} bytes", length);
        Ok(self.generate_nonce_internal(length))
    }
    
    async fn generate_random(&self, length: usize) -> Result<Vec<u8>> {
        debug!("Generating {} random bytes", length);
        
        let mut bytes = vec![0u8; length];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        
        Ok(bytes)
    }
    
    async fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        debug!("Hashing data");
        
        // Use SHA-256 for hashing
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        
        Ok(result.to_vec())
    }
    
    async fn sign(&self, message: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        debug!("Signing message");
        
        // Use HMAC-SHA256 for signatures with symmetric keys
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        
        type HmacSha256 = Hmac<Sha256>;
        
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| Box::new(CryptoError::Key(format!("Invalid key for HMAC: {}", e))))?;
            
        mac.update(message);
        let result = mac.finalize();
        
        Ok(result.into_bytes().to_vec())
    }
    
    async fn verify(&self, message: &[u8], signature: &[u8], key: &[u8]) -> Result<bool> {
        debug!("Verifying signature");
        
        // Use HMAC-SHA256 for signatures with symmetric keys
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        
        type HmacSha256 = Hmac<Sha256>;
        
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| Box::new(CryptoError::Key(format!("Invalid key for HMAC: {}", e))))?;
            
        mac.update(message);
        
        // Verify signature
        match mac.verify_slice(signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
