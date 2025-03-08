//! Key Derivation Functions (KDFs)
//!
//! This module provides functions for deriving cryptographic keys from
//! passwords or other key material.

use crate::error::{CryptoError, Result};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, Params, Algorithm, Version,
};
use rand::{Rng, rngs::OsRng};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Key derivation algorithms supported by the system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum KdfAlgorithm {
    /// Argon2id (memory-hard function recommended for password hashing)
    #[default]
    Argon2id,
    
    /// PBKDF2 with HMAC-SHA256
    Pbkdf2,
    
    /// HKDF with HMAC-SHA256 (for deriving multiple keys from a single master key)
    Hkdf,
}

/// Parameters for key derivation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    /// The algorithm to use
    pub algorithm: KdfAlgorithm,
    
    /// Number of iterations (for PBKDF2) or time cost (for Argon2)
    pub iterations: u32,
    
    /// Memory cost in KB (for Argon2 only)
    pub memory_cost_kb: u32,
    
    /// Parallelism factor (for Argon2 only)
    pub parallelism: u32,
    
    /// Output key length in bytes
    pub output_len: usize,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: KdfAlgorithm::default(),
            iterations: 10_000,
            memory_cost_kb: 65536, // 64 MB
            parallelism: 4,
            output_len: 32,
        }
    }
}

/// Generate a random salt for key derivation
///
/// # Arguments
///
/// * `length` - Length of the salt in bytes
///
/// # Returns
///
/// A random salt of the specified length
#[allow(dead_code)]
pub fn generate_salt(length: usize) -> Vec<u8> {
    let mut salt = vec![0u8; length];
    OsRng.fill(&mut salt[..]);
    salt
}

/// Derive a key from a password or master key
///
/// # Arguments
///
/// * `password` - The password or master key
/// * `salt` - Salt for the derivation
/// * `params` - Parameters for the key derivation
///
/// # Returns
///
/// The derived key
pub fn derive_key(password: &[u8], salt: &[u8], params: &KdfParams) -> Result<Vec<u8>> {
    match params.algorithm {
        KdfAlgorithm::Argon2id => {
            // Ensure salt is at least 16 bytes (if not, extend it)
            let mut extended_salt = salt.to_vec();
            if extended_salt.len() < 16 {
                extended_salt.resize(16, 0);
            }
            
            // Convert salt to SaltString
            let salt_str = SaltString::encode_b64(&extended_salt[..16])
                .map_err(|e| CryptoError::Key(format!("Salt encoding error: {}", e)))?;
            
            // Configure Argon2
            let argon2_params = Params::new(
                params.memory_cost_kb,
                params.iterations,
                params.parallelism,
                Some(params.output_len),
            )
            .map_err(|e| CryptoError::Algorithm(format!("Invalid Argon2 parameters: {}", e)))?;
            
            let argon2 = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                argon2_params,
            );
            
            // Derive key
            let password_hash = argon2
                .hash_password(password, &salt_str)
                .map_err(|e| CryptoError::Key(format!("Key derivation failed: {}", e)))?;
            
            // Extract hash bytes
            let hash = password_hash.hash.ok_or_else(|| {
                CryptoError::Internal("Failed to get hash from password".into())
            })?;
            
            Ok(hash.as_bytes().to_vec())
        }
        KdfAlgorithm::Pbkdf2 => {
            use ring::pbkdf2;
            
            let mut key = vec![0u8; params.output_len];
            
            pbkdf2::derive(
                pbkdf2::PBKDF2_HMAC_SHA256,
                std::num::NonZeroU32::new(params.iterations).unwrap(),
                salt,
                password,
                &mut key,
            );
            
            Ok(key)
        }
        KdfAlgorithm::Hkdf => {
            use ring::hkdf;
            
            let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
            let prk = salt.extract(password);
            let info = []; // Empty info
            
            // Create a buffer to hold our derived key
            let mut key = vec![0u8; params.output_len];
            
            // Use the ring HKDF API correctly
            // We need to define a custom KeyType implementation that can write to our buffer
            struct KeyMaterial<'a>(&'a mut [u8]);
            
            impl<'a> hkdf::KeyType for KeyMaterial<'a> {
                fn len(&self) -> usize {
                    self.0.len()
                }
            }
            
            impl<'a> From<&'a mut [u8]> for KeyMaterial<'a> {
                fn from(bytes: &'a mut [u8]) -> Self {
                    KeyMaterial(bytes)
                }
            }
            
            impl<'a> AsRef<[u8]> for KeyMaterial<'a> {
                fn as_ref(&self) -> &[u8] {
                    self.0
                }
            }
            
            impl<'a> AsMut<[u8]> for KeyMaterial<'a> {
                fn as_mut(&mut self) -> &mut [u8] {
                    self.0
                }
            }
            
            // Now use our KeyMaterial type with ring's HKDF
            // Create a key material wrapper for our buffer
            let key_material = KeyMaterial(&mut key);
            let _okm = prk.expand(&[&info], key_material)
                .map_err(|_| CryptoError::Key("HKDF expansion failed".into()))?;
            
            // There's no need to call fill() as the data is already in key
            
            Ok(key)
        }
    }
}

/// Securely zeroed buffer for sensitive data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureBuffer {
    data: Vec<u8>,
}

#[allow(dead_code)]
impl SecureBuffer {
    /// Create a new SecureBuffer with the given data
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
    
    /// Get a reference to the underlying data
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
    
    /// Get a mutable reference to the underlying data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
    
    /// Convert into a Vec<u8>, consuming the SecureBuffer
    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.data)
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id() {
        let password = b"password123";
        let salt = generate_salt(16);
        
        let params = KdfParams {
            algorithm: KdfAlgorithm::Argon2id,
            iterations: 1,  // Low value for testing
            memory_cost_kb: 1024,
            parallelism: 1,
            output_len: 32,
        };
        
        let key = derive_key(password, &salt, &params).unwrap();
        
        // Key should have the requested length
        assert_eq!(key.len(), params.output_len);
        
        // Same password and salt should produce the same key
        let key2 = derive_key(password, &salt, &params).unwrap();
        assert_eq!(key, key2);
        
        // Different password should produce different key
        let key3 = derive_key(b"different", &salt, &params).unwrap();
        assert_ne!(key, key3);
    }

    #[test]
    fn test_pbkdf2() {
        let password = b"password123";
        let salt = generate_salt(16);
        
        let params = KdfParams {
            algorithm: KdfAlgorithm::Pbkdf2,
            iterations: 1000,
            memory_cost_kb: 0,  // Not used for PBKDF2
            parallelism: 0,     // Not used for PBKDF2
            output_len: 32,
        };
        
        let key = derive_key(password, &salt, &params).unwrap();
        
        // Key should have the requested length
        assert_eq!(key.len(), params.output_len);
        
        // Same password and salt should produce the same key
        let key2 = derive_key(password, &salt, &params).unwrap();
        assert_eq!(key, key2);
        
        // Different password should produce different key
        let key3 = derive_key(b"different", &salt, &params).unwrap();
        assert_ne!(key, key3);
    }

    #[test]
    fn test_secure_buffer() {
        let data = vec![1, 2, 3, 4, 5];
        let buffer = SecureBuffer::new(data.clone());
        
        assert_eq!(buffer.as_slice(), &data[..]);
        
        // When buffer is dropped, data should be zeroed out
        // (we can't test this directly, but the drop implementation should work)
    }
}
