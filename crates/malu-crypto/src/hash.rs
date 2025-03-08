//! Cryptographic hash functions
//!
//! This module provides hash functions for data integrity and verification.

use crate::error::{CryptoError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

/// Hash algorithms supported by the system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// SHA-256 (256-bit hash)
    Sha256,
    
    /// SHA-512 (512-bit hash)
    Sha512,
    
    /// BLAKE3 (configurable output length)
    Blake3,
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        HashAlgorithm::Sha256
    }
}

/// Hash data using the specified algorithm
///
/// # Arguments
///
/// * `data` - The data to hash
/// * `algorithm` - The hash algorithm to use
///
/// # Returns
///
/// The computed hash as a byte vector
pub fn hash(data: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>> {
    match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            let result = hasher.finalize();
            Ok(result.to_vec())
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            let result = hasher.finalize();
            Ok(result.to_vec())
        }
        HashAlgorithm::Blake3 => {
            let hash = blake3::hash(data);
            Ok(hash.as_bytes().to_vec())
        }
    }
}

/// Compute a keyed hash (HMAC) for the data
///
/// # Arguments
///
/// * `data` - The data to hash
/// * `key` - The secret key for the HMAC
/// * `algorithm` - The hash algorithm to use
///
/// # Returns
///
/// The computed HMAC as a byte vector
#[allow(dead_code)]
pub fn hmac(data: &[u8], key: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>> {
    match algorithm {
        HashAlgorithm::Sha256 => {
            use hmac::{Hmac, Mac};
            
            type HmacSha256 = Hmac<Sha256>;
            
            let mut mac = HmacSha256::new_from_slice(key)
                .map_err(|e| CryptoError::Key(format!("Invalid key for HMAC: {}", e)))?;
                
            mac.update(data);
            let result = mac.finalize();
            
            Ok(result.into_bytes().to_vec())
        }
        HashAlgorithm::Sha512 => {
            use hmac::{Hmac, Mac};
            
            type HmacSha512 = Hmac<Sha512>;
            
            let mut mac = HmacSha512::new_from_slice(key)
                .map_err(|e| CryptoError::Key(format!("Invalid key for HMAC: {}", e)))?;
                
            mac.update(data);
            let result = mac.finalize();
            
            Ok(result.into_bytes().to_vec())
        }
        HashAlgorithm::Blake3 => {
            // Convert the key hash into a proper key array of correct length
            let key_hash = blake3::hash(key);
            let key_bytes = key_hash.as_bytes();
            // Create a fixed-size array for the key
            let mut key_array = [0u8; blake3::KEY_LEN];
            key_array.copy_from_slice(key_bytes);
            
            // Now use the fixed-size array for keyed_hash
            let hash = blake3::keyed_hash(&key_array, data);
            Ok(hash.as_bytes().to_vec())
        }
    }
}

/// Verify a hash against the original data
///
/// # Arguments
///
/// * `data` - The original data
/// * `hash` - The hash to verify
/// * `algorithm` - The hash algorithm used
///
/// # Returns
///
/// `true` if the hash is valid, `false` otherwise
#[allow(dead_code)]
pub fn verify_hash(data: &[u8], hash_value: &[u8], algorithm: HashAlgorithm) -> Result<bool> {
    // Call the hash function correctly
    let computed_hash = hash(data, algorithm)?;
    Ok(computed_hash.as_slice() == hash_value)
}

/// Verify an HMAC against the original data
///
/// # Arguments
///
/// * `data` - The original data
/// * `hmac_value` - The HMAC to verify
/// * `key` - The secret key used for the HMAC
/// * `algorithm` - The hash algorithm used
///
/// # Returns
///
/// `true` if the HMAC is valid, `false` otherwise
#[allow(dead_code)]
pub fn verify_hmac(data: &[u8], hmac_value: &[u8], key: &[u8], algorithm: HashAlgorithm) -> Result<bool> {
    let computed_hmac = hmac(data, key, algorithm)?;
    Ok(computed_hmac.as_slice() == hmac_value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"hello world";
        let hash_result = hash(data, HashAlgorithm::Sha256).unwrap();
        
        // Known SHA-256 hash of "hello world"
        let expected = hex::decode("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9").unwrap();
        
        assert_eq!(hash_result, expected);
        assert!(verify_hash(data, &hash_result, HashAlgorithm::Sha256).unwrap());
    }

    #[test]
    fn test_hmac_sha256() {
        let data = b"hello world";
        let key = b"secret key";
        
        let hmac_result = hmac(data, key, HashAlgorithm::Sha256).unwrap();
        assert!(verify_hmac(data, &hmac_result, key, HashAlgorithm::Sha256).unwrap());
        
        // Tampered data should not verify
        let tampered_data = b"hello worlD";
        assert!(!verify_hmac(tampered_data, &hmac_result, key, HashAlgorithm::Sha256).unwrap());
    }

    #[test]
    fn test_blake3() {
        let data = b"hello world";
        let hash_result = hash(data, HashAlgorithm::Blake3).unwrap();
        
        // BLAKE3 hash should be 32 bytes
        assert_eq!(hash_result.len(), 32);
        
        assert!(verify_hash(data, &hash_result, HashAlgorithm::Blake3).unwrap());
    }
}
