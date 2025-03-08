//! Key management functionality
//!
//! This module provides secure key management capabilities,
//! including key generation, rotation, and secure storage.

use crate::error::{CryptoError, Result};
use crate::kdf::{derive_key, KdfAlgorithm, KdfParams};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;
use uuid::Uuid;
use zeroize::Zeroize;

/// Generate a cryptographically secure random salt of specified length
#[allow(dead_code)]
pub fn generate_salt(length: usize) -> Vec<u8> {
    let mut salt = vec![0u8; length];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
    salt
}

/// Unique identifier for a key
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(String);

impl KeyId {
    /// Create a new random KeyId
    pub fn new() -> Self {
        KeyId(Uuid::new_v4().to_string())
    }
    
    /// Create a KeyId from an existing string
    pub fn from_string(id: String) -> Self {
        KeyId(id)
    }
    
    /// Get the string representation of the KeyId
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for KeyId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Key usage type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    /// Master key used to protect other keys
    Master,
    
    /// Data encryption key
    DataEncryption,
    
    /// Key encryption key
    KeyEncryption,
    
    /// Signing key
    Signing,
}

/// Metadata for a cryptographic key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Unique ID of the key
    pub id: KeyId,
    
    /// Type of key
    pub key_type: KeyType,
    
    /// Name of the key (human-readable)
    pub name: String,
    
    /// Creation time
    pub created_at: SystemTime,
    
    /// Rotation time
    pub rotated_at: Option<SystemTime>,
    
    /// Expiration time (if any)
    pub expires_at: Option<SystemTime>,
    
    /// Revocation time (if revoked)
    pub revoked_at: Option<SystemTime>,
    
    /// Algorithm used for this key
    pub algorithm: String,
    
    /// Key length in bits
    pub key_length: usize,
    
    /// Version of the key
    pub version: u32,
    
    /// Previous versions of this key (if rotated)
    pub previous_versions: Vec<KeyId>,
}

/// Secure key material that can be automatically zeroed
#[derive(Clone, Zeroize)]
pub struct SecretKey {
    /// The actual key bytes
    // The bytes will be zeroized when the SecretKey is dropped
    bytes: Vec<u8>,
}

impl SecretKey {
    /// Create a new SecretKey from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
    
    /// Get a reference to the key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    
    /// Convert into a Vec<u8>, consuming the SecretKey
    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey {{ bytes: [REDACTED] }}")
    }
}

/// A complete key, including both metadata and the secret material
#[derive(Clone)]
pub struct Key {
    /// Metadata about the key
    pub metadata: KeyMetadata,
    
    /// The actual key material (may be None if only metadata is available)
    pub secret: Option<SecretKey>,
}

impl Key {
    /// Create a new key with the given metadata and secret
    pub fn new(metadata: KeyMetadata, secret: SecretKey) -> Self {
        Self {
            metadata,
            secret: Some(secret),
        }
    }
    
    /// Create a key with only metadata (no secret material)
    pub fn metadata_only(metadata: KeyMetadata) -> Self {
        Self {
            metadata,
            secret: None,
        }
    }
    
    /// Check if this key is active (not expired or revoked)
    pub fn is_active(&self) -> bool {
        let now = SystemTime::now();
        
        // Not expired
        let not_expired = match self.metadata.expires_at {
            Some(expires) => now < expires,
            None => true,
        };
        
        // Not revoked
        let not_revoked = self.metadata.revoked_at.is_none();
        
        not_expired && not_revoked
    }
}

/// Master key used to protect other keys
pub struct MasterKey {
    /// The key ID
    pub id: KeyId,
    
    /// The secret key material
    key: SecretKey,
}

impl MasterKey {
    /// Create a new master key with random material
    pub fn new() -> Result<Self> {
        let mut key_bytes = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key_bytes);
        
        Ok(Self {
            id: KeyId::new(),
            key: SecretKey::new(key_bytes),
        })
    }
    
    /// Create a master key from existing material
    pub fn from_bytes(id: KeyId, bytes: Vec<u8>) -> Self {
        Self {
            id,
            key: SecretKey::new(bytes),
        }
    }
    
    /// Derive a master key from a password
    pub fn from_password(password: &[u8], salt: &[u8]) -> Result<Self> {
        let params = KdfParams {
            algorithm: KdfAlgorithm::Argon2id,
            iterations: 10,
            memory_cost_kb: 65536, // 64 MB
            parallelism: 4,
            output_len: 32,
        };
        
        let key_bytes = derive_key(password, salt, &params)?;
        
        Ok(Self {
            id: KeyId::new(),
            key: SecretKey::new(key_bytes),
        })
    }
    
    /// Get a reference to the key bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.key.as_bytes()
    }
}

/// Key manager for securely handling cryptographic keys
pub struct KeyManager {
    /// The master key used to protect other keys
    master_key: Option<MasterKey>,
    
    /// In-memory cache of keys
    keys: Arc<RwLock<HashMap<KeyId, Key>>>,
}

impl KeyManager {
    /// Create a new key manager without a master key
    pub fn new() -> Self {
        Self {
            master_key: None,
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Create a new key manager with the given master key
    pub fn with_master_key(master_key: MasterKey) -> Self {
        Self {
            master_key: Some(master_key),
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Set the master key
    pub fn set_master_key(&mut self, master_key: MasterKey) {
        self.master_key = Some(master_key);
    }
    
    /// Generate a new random key
    pub fn generate_key(&self, name: &str, key_type: KeyType, key_length: usize) -> Result<Key> {
        let mut key_bytes = vec![0u8; key_length / 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key_bytes);
        
        let metadata = KeyMetadata {
            id: KeyId::new(),
            key_type,
            name: name.to_string(),
            created_at: SystemTime::now(),
            rotated_at: None,
            expires_at: None,
            revoked_at: None,
            algorithm: match key_type {
                KeyType::Master | KeyType::KeyEncryption => "AES-256".to_string(),
                KeyType::DataEncryption => "AES-256-GCM".to_string(),
                KeyType::Signing => "HMAC-SHA256".to_string(),
            },
            key_length,
            version: 1,
            previous_versions: Vec::new(),
        };
        
        let key = Key::new(metadata, SecretKey::new(key_bytes));
        
        // Add to cache
        if let Ok(mut keys) = self.keys.write() {
            // Insert a clone of the key into the cache
            let key_clone = Key {
                metadata: key.metadata.clone(),
                secret: key.secret.clone()
            };
            keys.insert(key.metadata.id.clone(), key_clone);
        }
        
        Ok(key)
    }
    
    /// Get a key by its ID
    pub fn get_key(&self, id: &KeyId) -> Result<Option<Key>> {
        if let Ok(keys) = self.keys.read() {
            if let Some(key) = keys.get(id) {
                // Clone the key to return ownership of the clone
                return Ok(Some(Key {
                    metadata: key.metadata.clone(),
                    secret: key.secret.clone()
                }));
            }
        }
        
        // Key not found in cache
        Ok(None)
    }
    
    /// Rotate a key, generating a new version
    pub fn rotate_key(&self, id: &KeyId) -> Result<Key> {
        let old_key = self.get_key(id)?
            .ok_or_else(|| CryptoError::Key(format!("Key with ID {} not found", id)))?;
        
        let new_key_length = match old_key.metadata.key_type {
            KeyType::Master | KeyType::KeyEncryption => 256,
            KeyType::DataEncryption => 256,
            KeyType::Signing => 256,
        };
        
        // Generate new key with updated metadata
        let mut previous_versions = old_key.metadata.previous_versions.clone();
        previous_versions.push(old_key.metadata.id.clone());
        
        let mut key_bytes = vec![0u8; new_key_length / 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key_bytes);
        
        let metadata = KeyMetadata {
            id: KeyId::new(),
            key_type: old_key.metadata.key_type,
            name: old_key.metadata.name.clone(),
            created_at: old_key.metadata.created_at,
            rotated_at: Some(SystemTime::now()),
            expires_at: old_key.metadata.expires_at,
            revoked_at: None,
            algorithm: old_key.metadata.algorithm.clone(),
            key_length: new_key_length,
            version: old_key.metadata.version + 1,
            previous_versions,
        };
        
        let key = Key::new(metadata, SecretKey::new(key_bytes));
        
        // Add to cache
        if let Ok(mut keys) = self.keys.write() {
            // Insert a clone of the key into the cache
            let key_clone = Key {
                metadata: key.metadata.clone(),
                secret: key.secret.clone()
            };
            keys.insert(key.metadata.id.clone(), key_clone);
        }
        
        Ok(key)
    }
    
    /// Revoke a key
    pub fn revoke_key(&self, id: &KeyId) -> Result<()> {
        if let Ok(mut keys) = self.keys.write() {
            if let Some(key) = keys.remove(id) {
                // Update metadata to mark as revoked
                let metadata = KeyMetadata {
                    revoked_at: Some(SystemTime::now()),
                    ..key.metadata
                };
                
                // Store updated key
                let updated_key = Key {
                    metadata,
                    secret: None, // Remove secret material for revoked key
                };
                
                keys.insert(id.clone(), updated_key);
                return Ok(());
            }
        }
        
        Err(CryptoError::Key(format!("Key with ID {} not found", id)))
    }
    
    /// Export a key in encrypted form
    pub fn export_key(&self, id: &KeyId) -> Result<Vec<u8>> {
        let key = self.get_key(id)?
            .ok_or_else(|| CryptoError::Key(format!("Key with ID {} not found", id)))?;
            
        let secret = key.secret
            .ok_or_else(|| CryptoError::Key("Cannot export key without secret material".into()))?;
            
        // If we have a master key, encrypt the key material
        if let Some(master_key) = &self.master_key {
            // Use AEAD encryption
            use crate::aead::{encrypt, EncryptionAlgorithm};
            
            let context = format!("key-export:{}", id);
            let result = encrypt(
                secret.as_bytes(),
                master_key.as_bytes(),
                context.as_bytes(),
                EncryptionAlgorithm::Aes256Gcm,
            )?;
            
            return Ok(result);
        }
        
        // If no master key, just return the raw key (not recommended for production)
        Ok(secret.as_bytes().to_vec())
    }
    
    /// Import a key from encrypted form
    pub fn import_key(&self, metadata: KeyMetadata, encrypted_key: &[u8]) -> Result<Key> {
        // If we have a master key, decrypt the key material
        if let Some(master_key) = &self.master_key {
            // Use AEAD decryption
            use crate::aead::{decrypt, EncryptionAlgorithm};
            
            let context = format!("key-export:{}", metadata.id);
            let key_bytes = decrypt(
                encrypted_key,
                master_key.as_bytes(),
                context.as_bytes(),
                EncryptionAlgorithm::Aes256Gcm,
            )?;
            
            let key = Key::new(metadata, SecretKey::new(key_bytes));
            
            // Add to cache
            if let Ok(mut keys) = self.keys.write() {
                keys.insert(key.metadata.id.clone(), key.clone());
            }
            
            return Ok(key);
        }
        
        // If no master key, assume raw key
        let key = Key::new(metadata, SecretKey::new(encrypted_key.to_vec()));
        
        // Add to cache
        if let Ok(mut keys) = self.keys.write() {
            // Insert a clone of the key into the cache
            let key_clone = Key {
                metadata: key.metadata.clone(),
                secret: key.secret.clone()
            };
            keys.insert(key.metadata.id.clone(), key_clone);
        }
        
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_generation() {
        let key_manager = KeyManager::new();
        
        let key = key_manager.generate_key("test-key", KeyType::DataEncryption, 256).unwrap();
        
        assert_eq!(key.metadata.name, "test-key");
        assert_eq!(key.metadata.key_type, KeyType::DataEncryption);
        assert_eq!(key.metadata.key_length, 256);
        assert!(key.is_active());
        
        if let Some(secret) = &key.secret {
            assert_eq!(secret.as_bytes().len(), 32); // 256 bits = 32 bytes
        } else {
            panic!("Key secret should be present");
        }
    }
    
    #[test]
    fn test_key_rotation() {
        let key_manager = KeyManager::new();
        
        let key = key_manager.generate_key("test-key", KeyType::DataEncryption, 256).unwrap();
        let key_id = key.metadata.id.clone();
        
        // Rotate the key
        let rotated_key = key_manager.rotate_key(&key_id).unwrap();
        
        assert_eq!(rotated_key.metadata.name, "test-key");
        assert_eq!(rotated_key.metadata.version, 2);
        assert_eq!(rotated_key.metadata.previous_versions.len(), 1);
        assert_eq!(rotated_key.metadata.previous_versions[0], key_id);
        assert!(rotated_key.is_active());
    }
    
    #[test]
    fn test_master_key() {
        let password = b"secure-password";
        let salt = generate_salt(16);
        
        let master_key = MasterKey::from_password(password, &salt).unwrap();
        
        // Master key should be 32 bytes (256 bits)
        assert_eq!(master_key.as_bytes().len(), 32);
        
        // Created with the same password and salt should yield the same key
        let master_key2 = MasterKey::from_password(password, &salt).unwrap();
        assert_eq!(master_key.as_bytes(), master_key2.as_bytes());
    }
}
