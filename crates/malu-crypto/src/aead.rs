//! Authenticated Encryption with Associated Data (AEAD) functionality
//!
//! This module provides AEAD encryption and decryption functions,
//! which provide both confidentiality and integrity protection.

use crate::error::{CryptoError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

/// Encryption algorithms supported by the system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    /// AES-256 in Galois/Counter Mode (GCM) with 96-bit nonce
    Aes256Gcm,
    
    /// XChaCha20-Poly1305 with 192-bit nonce
    XChaCha20Poly1305,
}

impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        EncryptionAlgorithm::Aes256Gcm
    }
}

/// Generate a secure random nonce of the specified length
fn generate_nonce(length: usize) -> Vec<u8> {
    let mut nonce = vec![0u8; length];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Encrypt data using the specified algorithm
///
/// # Arguments
///
/// * `plaintext` - The data to encrypt
/// * `key` - The encryption key (must be 32 bytes for AES-256-GCM)
/// * `associated_data` - Additional data that will be authenticated but not encrypted
/// * `algorithm` - The encryption algorithm to use
///
/// # Returns
///
/// A vector containing the nonce followed by the ciphertext
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8],
    associated_data: &[u8],
    algorithm: EncryptionAlgorithm,
) -> Result<Vec<u8>> {
    match algorithm {
        EncryptionAlgorithm::Aes256Gcm => {
            if key.len() != 32 {
                return Err(CryptoError::Key("AES-256-GCM requires a 32-byte key".into()));
            }

            // Generate a 12-byte nonce (96 bits)
            let nonce_bytes = generate_nonce(12);
            let nonce = Nonce::from_slice(&nonce_bytes);

            // Create cipher instance
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| CryptoError::Key(format!("Invalid key: {}", e)))?;

            // Create payload with associated data
            let payload = Payload {
                msg: plaintext,
                aad: associated_data,
            };

            // Encrypt
            let ciphertext = cipher
                .encrypt(nonce, payload)
                .map_err(|e| CryptoError::Encryption(format!("Encryption failed: {:?}", e)))?;

            // Combine nonce and ciphertext
            let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
            result.extend_from_slice(&nonce_bytes);
            result.extend_from_slice(&ciphertext);

            Ok(result)
        }
        EncryptionAlgorithm::XChaCha20Poly1305 => {
            // Use sodium for XChaCha20-Poly1305
            use sodiumoxide::crypto::aead::xchacha20poly1305_ietf as sodium_aead;

            if key.len() != sodium_aead::KEYBYTES {
                return Err(CryptoError::Key(format!(
                    "XChaCha20-Poly1305 requires a {}-byte key",
                    sodium_aead::KEYBYTES
                )));
            }

            // Generate a 24-byte nonce (192 bits)
            let nonce_bytes = generate_nonce(sodium_aead::NONCEBYTES);
            let nonce = sodium_aead::Nonce::from_slice(&nonce_bytes)
                .ok_or_else(|| CryptoError::Internal("Failed to create nonce".into()))?;

            // Create key
            let key = sodium_aead::Key::from_slice(key)
                .ok_or_else(|| CryptoError::Key("Invalid key for XChaCha20-Poly1305".into()))?;

            // Encrypt
            let ciphertext = sodium_aead::seal(plaintext, Some(associated_data), &nonce, &key);

            // Combine nonce and ciphertext
            let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
            result.extend_from_slice(&nonce_bytes);
            result.extend_from_slice(&ciphertext);

            Ok(result)
        }
    }
}

/// Decrypt data using the specified algorithm
///
/// # Arguments
///
/// * `ciphertext` - The encrypted data, including the nonce
/// * `key` - The encryption key (must be 32 bytes for AES-256-GCM)
/// * `associated_data` - Additional data that was authenticated
/// * `algorithm` - The encryption algorithm to use
///
/// # Returns
///
/// The decrypted plaintext
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8],
    associated_data: &[u8],
    algorithm: EncryptionAlgorithm,
) -> Result<Vec<u8>> {
    match algorithm {
        EncryptionAlgorithm::Aes256Gcm => {
            if key.len() != 32 {
                return Err(CryptoError::Key("AES-256-GCM requires a 32-byte key".into()));
            }

            if ciphertext.len() < 12 {
                return Err(CryptoError::Decryption("Ciphertext too short".into()));
            }

            // Split nonce and actual ciphertext
            let nonce = Nonce::from_slice(&ciphertext[..12]);
            let actual_ciphertext = &ciphertext[12..];

            // Create cipher instance
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| CryptoError::Key(format!("Invalid key: {}", e)))?;

            // Create payload with associated data
            let payload = Payload {
                msg: actual_ciphertext,
                aad: associated_data,
            };

            // Decrypt
            let plaintext = cipher
                .decrypt(nonce, payload)
                .map_err(|e| CryptoError::Decryption(format!("Decryption failed: {:?}", e)))?;

            Ok(plaintext)
        }
        EncryptionAlgorithm::XChaCha20Poly1305 => {
            #[cfg(feature = "sodium")]
            {
                // Use sodium for XChaCha20-Poly1305
                use sodiumoxide::crypto::aead::xchacha20poly1305_ietf as sodium_aead;

                if key.len() != sodium_aead::KEYBYTES {
                    return Err(CryptoError::Key(format!(
                        "XChaCha20-Poly1305 requires a {}-byte key",
                        sodium_aead::KEYBYTES
                    )));
                }

                if ciphertext.len() < sodium_aead::NONCEBYTES {
                    return Err(CryptoError::Decryption("Ciphertext too short".into()));
                }

                // Split nonce and actual ciphertext
                let nonce_bytes = &ciphertext[..sodium_aead::NONCEBYTES];
                let actual_ciphertext = &ciphertext[sodium_aead::NONCEBYTES..];

                // Create nonce and key
                let nonce = sodium_aead::Nonce::from_slice(nonce_bytes)
                    .ok_or_else(|| CryptoError::Internal("Failed to create nonce".into()))?;
                let key = sodium_aead::Key::from_slice(key)
                    .ok_or_else(|| CryptoError::Key("Invalid key for XChaCha20-Poly1305".into()))?;

                // Decrypt
                let plaintext = sodium_aead::open(actual_ciphertext, Some(associated_data), &nonce, &key)
                    .map_err(|_| CryptoError::Decryption("Decryption failed".into()))?;

                Ok(plaintext)
            }
            
            #[cfg(not(feature = "sodium"))]
            {
                // Fallback implementation or error when sodium feature is not enabled
                Err(CryptoError::Algorithm("XChaCha20-Poly1305 requires the 'sodium' feature to be enabled".into()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm() {
        // Generate a random key
        let key = generate_nonce(32);
        let plaintext = b"Hello, world!";
        let aad = b"context";

        // Encrypt
        let ciphertext = encrypt(plaintext, &key, aad, EncryptionAlgorithm::Aes256Gcm).unwrap();

        // Decrypt
        let decrypted = decrypt(&ciphertext, &key, aad, EncryptionAlgorithm::Aes256Gcm).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[cfg(feature = "sodium")]
    #[test]
    fn test_xchacha20_poly1305() {
        // Import from sodiumoxide crate
        use sodiumoxide::crypto::aead::xchacha20poly1305_ietf as sodium_aead;
        
        // Generate a random key
        let key = generate_nonce(sodium_aead::KEYBYTES);
        let plaintext = b"Hello, world!";
        let aad = b"context";

        // Encrypt
        let ciphertext = encrypt(plaintext, &key, aad, EncryptionAlgorithm::XChaCha20Poly1305).unwrap();

        // Decrypt
        let decrypted = decrypt(&ciphertext, &key, aad, EncryptionAlgorithm::XChaCha20Poly1305).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_authentication() {
        // Generate a random key
        let key = generate_nonce(32);
        let plaintext = b"Hello, world!";
        let aad = b"context";

        // Encrypt
        let mut ciphertext = encrypt(plaintext, &key, aad, EncryptionAlgorithm::Aes256Gcm).unwrap();

        // Tamper with the ciphertext (after the nonce)
        if ciphertext.len() > 20 {
            ciphertext[15] ^= 0x01;
        }

        // Attempt to decrypt
        let result = decrypt(&ciphertext, &key, aad, EncryptionAlgorithm::Aes256Gcm);
        assert!(result.is_err(), "Decryption should fail with tampered ciphertext");
    }
}
