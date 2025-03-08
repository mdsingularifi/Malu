use crate::core::{CryptoProvider, error::{Result, ServiceError}};
use async_trait::async_trait;
use aes_gcm::{
    Aes256Gcm, KeyInit, 
    aead::{Aead, Nonce}
};
use std::sync::Arc;
use ring::rand::{SecureRandom, SystemRandom};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::path::Path;
use tokio::fs;
use zeroize::Zeroize;

// Constants for crypto operations
const NONCE_SIZE: usize = 12; // 96 bits for AES-GCM
const KEY_SIZE: usize = 32;   // 256 bits for AES-256
#[allow(dead_code)]
const TAG_SIZE: usize = 16;   // 128 bits for GCM tag
const SALT_SIZE: usize = 16;  // 128 bits for salt
const PBKDF2_ITERATIONS: u32 = 100_000; // Number of iterations for PBKDF2

/// Implementation of CryptoProvider using AES-GCM
pub struct AesGcmCryptoProvider {
    rng: SystemRandom,
    master_key_path: Option<String>,
    master_key: Option<Vec<u8>>,
}

impl AesGcmCryptoProvider {
    /// Create a new AesGcmCryptoProvider
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
            master_key_path: None,
            master_key: None,
        }
    }
    
    /// Create a new AesGcmCryptoProvider with a master key path
    pub fn with_master_key_path(mut self, path: String) -> Self {
        self.master_key_path = Some(path);
        self
    }
    
    /// Initialize the provider, loading the master key if available
    pub async fn init(&mut self) -> Result<()> {
        if let Some(path) = &self.master_key_path {
            let key_path = Path::new(path);
            
            if key_path.exists() {
                // Load existing master key
                let key_data = fs::read(key_path).await.map_err(|e| {
                    ServiceError::CryptoError(format!("Failed to read master key: {}", e))
                })?;
                
                if key_data.len() != KEY_SIZE {
                    return Err(ServiceError::CryptoError(
                        format!("Invalid master key size: expected {} bytes, got {}", 
                                KEY_SIZE, key_data.len())
                    ));
                }
                
                self.master_key = Some(key_data);
            } else {
                // Generate and save a new master key
                let mut key_data = vec![0u8; KEY_SIZE];
                self.rng.fill(&mut key_data).map_err(|e| {
                    ServiceError::CryptoError(format!("Failed to generate master key: {}", e))
                })?;
                
                // Create parent directories if they don't exist
                if let Some(parent) = key_path.parent() {
                    fs::create_dir_all(parent).await.map_err(|e| {
                        ServiceError::IoError(e)
                    })?;
                }
                
                // Save the key
                fs::write(key_path, &key_data).await.map_err(|e| {
                    ServiceError::IoError(e)
                })?;
                
                self.master_key = Some(key_data);
            }
        }
        
        Ok(())
    }
    
    /// Get the master key, or generate a temporary one if not set
    async fn get_master_key(&self) -> Result<Vec<u8>> {
        if let Some(key) = &self.master_key {
            return Ok(key.clone());
        }
        
        // Generate a temporary key
        let mut key = vec![0u8; KEY_SIZE];
        self.rng.fill(&mut key).map_err(|e| {
            ServiceError::CryptoError(format!("Failed to generate temporary key: {}", e))
        })?;
        
        Ok(key)
    }
}

#[async_trait]
impl CryptoProvider for AesGcmCryptoProvider {
    async fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Get the master key
        let key = self.get_master_key().await?;
        
        // Generate a random nonce
        let mut nonce = vec![0u8; NONCE_SIZE];
        self.rng.fill(&mut nonce).map_err(|e| {
            ServiceError::CryptoError(format!("Failed to generate nonce: {}", e))
        })?;
        
        // Initialize AES-GCM cipher
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| ServiceError::CryptoError(format!("Failed to initialize cipher: {}", e)))?;
        
        // Encrypt the data
        let nonce_value = Nonce::<Aes256Gcm>::from_slice(&nonce);
        let ciphertext = cipher.encrypt(nonce_value, data.as_ref())
            .map_err(|e| ServiceError::CryptoError(format!("Encryption failed: {}", e)))?;
        
        // Combine nonce + ciphertext into the final output
        let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        
        Ok(output)
    }
    
    async fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        // Check that the encrypted data is at least as long as the nonce
        if encrypted.len() < NONCE_SIZE {
            return Err(ServiceError::CryptoError("Invalid ciphertext length".to_string()));
        }
        
        // Get the master key
        let key = self.get_master_key().await?;
        
        // Split the input into nonce and ciphertext
        let (nonce, ciphertext) = encrypted.split_at(NONCE_SIZE);
        
        // Initialize AES-GCM cipher
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| ServiceError::CryptoError(format!("Failed to initialize cipher: {}", e)))?;
        
        // Decrypt the data
        let nonce_value = Nonce::<Aes256Gcm>::from_slice(nonce);
        let plaintext = cipher.decrypt(nonce_value, ciphertext.as_ref())
            .map_err(|e| ServiceError::CryptoError(format!("Decryption failed: {}", e)))?;
        
        Ok(plaintext)
    }
    
    async fn generate_nonce(&self, length: usize) -> Result<Vec<u8>> {
        let mut nonce = vec![0u8; length];
        self.rng.fill(&mut nonce).map_err(|e| {
            ServiceError::CryptoError(format!("Failed to generate nonce: {}", e))
        })?;
        
        Ok(nonce)
    }
    
    async fn derive_key(&self, input: &[u8]) -> Result<Vec<u8>> {
        // Generate a salt
        let mut salt = vec![0u8; SALT_SIZE];
        self.rng.fill(&mut salt).map_err(|e| {
            ServiceError::CryptoError(format!("Failed to generate salt: {}", e))
        })?;
        
        // Derive a key using PBKDF2
        let mut output = vec![0u8; KEY_SIZE];
        pbkdf2_hmac::<Sha256>(input, &salt, PBKDF2_ITERATIONS, &mut output);
        
        Ok(output)
    }
    
    async fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Create a SHA-256 hasher
        use sha2::Digest;
        let mut hasher = Sha256::new();
        
        // Update with the input data
        hasher.update(data);
        
        // Get the hash result
        let result = hasher.finalize().to_vec();
        
        Ok(result)
    }
}

impl Drop for AesGcmCryptoProvider {
    fn drop(&mut self) {
        // Zero out the master key when dropping
        if let Some(key) = &mut self.master_key {
            key.zeroize();
        }
    }
}

// Factory function to create and initialize a new provider
#[allow(dead_code)]
pub async fn create_aes_crypto_provider(
    master_key_path: Option<String>
) -> Result<Arc<AesGcmCryptoProvider>> {
    let mut provider = if let Some(path) = master_key_path {
        AesGcmCryptoProvider::new().with_master_key_path(path)
    } else {
        AesGcmCryptoProvider::new()
    };
    
    provider.init().await?;
    
    Ok(Arc::new(provider))
}
