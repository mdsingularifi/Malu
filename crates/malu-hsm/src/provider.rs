//! HSM provider implementation

use async_trait::async_trait;
use malu_interfaces::CryptoProvider as CryptoProviderInterface;
use crate::error::{HsmError, Result};
use serde::{Deserialize, Serialize};
use tracing::debug;

#[cfg(feature = "pkcs11")]
use pkcs11::{
    types::{
        CKA_CLASS, CKA_ENCRYPT, CKA_ID, CKA_KEY_TYPE, CKA_TOKEN, CKA_VALUE,
        CKK_AES, CKM_AES_CBC, CKM_AES_GCM, CKM_AES_KEY_GEN, CKO_SECRET_KEY,
    },
    Ctx, Object, Session, SlotId,
};

/// Configuration for HSM connections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConfig {
    /// Type of HSM
    pub hsm_type: HsmType,
    
    /// Path to the PKCS#11 library
    pub pkcs11_lib_path: Option<String>,
    
    /// Slot ID for the HSM
    pub slot_id: Option<u64>,
    
    /// PIN for the HSM
    pub pin: Option<String>,
    
    /// Token label
    pub token_label: Option<String>,
    
    /// User key ID for operations
    pub key_id: Option<String>,
}

impl Default for HsmConfig {
    fn default() -> Self {
        Self {
            hsm_type: HsmType::Pkcs11,
            pkcs11_lib_path: None,
            slot_id: None,
            pin: None,
            token_label: None,
            key_id: None,
        }
    }
}

/// Types of HSMs supported
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HsmType {
    /// PKCS#11 compatible HSM
    Pkcs11,
    
    /// YubiKey
    YubiKey,
    
    /// TPM (Trusted Platform Module)
    Tpm,
}

/// HSM-based crypto provider
#[derive(Debug)]
pub struct HsmCryptoProvider {
    config: HsmConfig,
    #[cfg(feature = "pkcs11")]
    ctx: Option<Ctx>,
}

impl HsmCryptoProvider {
    /// Create a new HSM crypto provider with the given configuration
    pub fn new(config: HsmConfig) -> Self {
        debug!("Creating new HSM crypto provider");
        
        Self {
            config,
            #[cfg(feature = "pkcs11")]
            ctx: None,
        }
    }
    
    /// Initialize the HSM connection
    #[allow(dead_code)]
    fn initialize(&mut self) -> Result<()> {
        match self.config.hsm_type {
            HsmType::Pkcs11 => {
                #[cfg(feature = "pkcs11")]
                {
                    let lib_path = self.config.pkcs11_lib_path.as_ref()
                        .ok_or_else(|| HsmError::Hsm("PKCS#11 library path not specified".into()))?;
                    
                    debug!("Initializing PKCS#11 with library: {}", lib_path);
                    
                    let ctx = Ctx::new(lib_path)
                        .map_err(|e| HsmError::Hsm(format!("Failed to initialize PKCS#11: {:?}", e)))?;
                    
                    ctx.initialize(None)
                        .map_err(|e| HsmError::Hsm(format!("Failed to initialize PKCS#11 context: {:?}", e)))?;
                    
                    self.ctx = Some(ctx);
                    return Ok(());
                }
                
                #[cfg(not(feature = "pkcs11"))]
                {
                    return Err(HsmError::Hsm("PKCS#11 support not enabled".into()));
                }
            },
            HsmType::YubiKey => {
                #[cfg(feature = "yubikey")]
                {
                    debug!("Initializing YubiKey");
                    // YubiKey initialization code would go here
                    return Ok(());
                }
                
                #[cfg(not(feature = "yubikey"))]
                {
                    return Err(HsmError::Hsm("YubiKey support not enabled".into()));
                }
            },
            HsmType::Tpm => {
                debug!("TPM support not yet implemented");
                return Err(HsmError::Hsm("TPM support not yet implemented".into()));
            }
        }
    }
    
    #[cfg(feature = "pkcs11")]
    fn get_session(&mut self) -> Result<Session> {
        let ctx = self.ctx.as_ref()
            .ok_or_else(|| HsmError::Hsm("PKCS#11 not initialized".into()))?;
        
        let slot_id = self.config.slot_id
            .ok_or_else(|| HsmError::Hsm("Slot ID not specified".into()))?;
        
        let slot_id = SlotId::from(slot_id);
        let pin = self.config.pin.as_ref()
            .ok_or_else(|| HsmError::Hsm("PIN not specified".into()))?;
        
        let session = ctx.open_session(slot_id, pkcs11::types::CKF_SERIAL_SESSION | pkcs11::types::CKF_RW_SESSION, None, None)
            .map_err(|e| HsmError::Hsm(format!("Failed to open session: {:?}", e)))?;
        
        session.login(pkcs11::types::CKU_USER, Some(pin.as_bytes()))
            .map_err(|e| HsmError::Hsm(format!("Failed to login: {:?}", e)))?;
        
        Ok(session)
    }
    
    #[cfg(feature = "pkcs11")]
    fn find_key(&mut self, key_id: &str) -> Result<Object> {
        let session = self.get_session()?;
        
        let template = vec![
            (CKA_CLASS, pkcs11::types::Attribute::from(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, pkcs11::types::Attribute::from(CKK_AES)),
            (CKA_ID, pkcs11::types::Attribute::from(key_id.as_bytes())),
        ];
        
        session.find_objects(&template)
            .map_err(|e| HsmError::Hsm(format!("Failed to find objects: {:?}", e)))?
            .into_iter()
            .next()
            .ok_or_else(|| HsmError::Key(format!("Key with ID {} not found", key_id)))
    }
    
    #[cfg(feature = "pkcs11")]
    fn generate_key(&mut self, key_id: &str, key_len: usize) -> Result<Object> {
        let session = self.get_session()?;
        
        let template = vec![
            (CKA_CLASS, pkcs11::types::Attribute::from(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, pkcs11::types::Attribute::from(CKK_AES)),
            (CKA_ID, pkcs11::types::Attribute::from(key_id.as_bytes())),
            (CKA_TOKEN, pkcs11::types::Attribute::from(true)),
            (CKA_ENCRYPT, pkcs11::types::Attribute::from(true)),
            (pkcs11::types::CKA_DECRYPT, pkcs11::types::Attribute::from(true)),
        ];
        
        let mechanism = pkcs11::types::Mechanism::new(
            CKM_AES_KEY_GEN,
            None,
        );
        
        session.generate_key(&mechanism, &template)
            .map_err(|e| HsmError::Hsm(format!("Failed to generate key: {:?}", e)))
    }
}

impl Drop for HsmCryptoProvider {
    fn drop(&mut self) {
        #[cfg(feature = "pkcs11")]
        if let Some(ctx) = &self.ctx {
            debug!("Finalizing PKCS#11 context");
            if let Err(e) = ctx.finalize() {
                debug!("Failed to finalize PKCS#11 context: {:?}", e);
            }
        }
    }
}

#[async_trait]
impl CryptoProviderInterface for HsmCryptoProvider {
    async fn encrypt(&self, context: &str, _plaintext: &[u8], _key: &[u8]) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        debug!("HSM encrypting data with context: {}", context);
        
        #[cfg(feature = "pkcs11")]
        {
            // HSM encryption would be implemented here
            // For now, we'll use a software fallback from malu_crypto
            use malu_crypto::aead::{encrypt, EncryptionAlgorithm};
            
            let result = encrypt(
                plaintext,
                key,
                context.as_bytes(),
                EncryptionAlgorithm::Aes256Gcm,
            )?;
            
            return Ok(result);
        }
        
        #[cfg(not(feature = "pkcs11"))]
        {
            return Err(Box::new(HsmError::Hsm("PKCS#11 support not enabled".into())));
        }
    }

    async fn decrypt(&self, context: &str, _ciphertext: &[u8], _key: &[u8]) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        debug!("HSM decrypting data with context: {}", context);
        
        #[cfg(feature = "pkcs11")]
        {
            // HSM decryption would be implemented here
            // For now, we'll use a software fallback from malu_crypto
            use malu_crypto::aead::{decrypt, EncryptionAlgorithm};
            
            let result = decrypt(
                ciphertext,
                key,
                context.as_bytes(),
                EncryptionAlgorithm::Aes256Gcm,
            )?;
            
            return Ok(result);
        }
        
        #[cfg(not(feature = "pkcs11"))]
        {
            return Err(Box::new(HsmError::Hsm("PKCS#11 support not enabled".into())));
        }
    }

    async fn derive_key(&self, _passphrase: &[u8], _salt: &[u8], _info: Option<&[u8]>) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        debug!("HSM deriving key from passphrase");
        
        #[cfg(feature = "pkcs11")]
        {
            // HSM key derivation would be implemented here
            // For now, we'll use a software fallback from malu_crypto
            use malu_crypto::kdf::{derive_key, KdfParams, KdfAlgorithm};
            
            let params = KdfParams {
                algorithm: KdfAlgorithm::Argon2id,
                iterations: 10_000,
                memory_cost_kb: 65536, // 64 MB
                parallelism: 4,
                output_len: 32,
            };
            
            let result = derive_key(passphrase, salt, &params)?;
            
            return Ok(result);
        }
        
        #[cfg(not(feature = "pkcs11"))]
        {
            return Err(Box::new(HsmError::Hsm("PKCS#11 support not enabled".into())));
        }
    }

    async fn generate_random(&self, length: usize) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        debug!("HSM generating {} random bytes", length);
        
        #[cfg(feature = "pkcs11")]
        {
            let mut clone = self.clone();
            let session = clone.get_session()
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            
            let mut bytes = vec![0u8; length];
            session.generate_random(&mut bytes)
                .map_err(|e| Box::new(HsmError::Hsm(format!("Failed to generate random: {:?}", e))) as Box<dyn std::error::Error + Send + Sync>)?;
            
            return Ok(bytes);
        }
        
        #[cfg(not(feature = "pkcs11"))]
        {
            return Err(Box::new(HsmError::Hsm("PKCS#11 support not enabled".into())));
        }
    }

    async fn hash(&self, _data: &[u8]) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        debug!("HSM hashing data");
        
        #[cfg(feature = "pkcs11")]
        {
            // HSM hashing would be implemented here
            // For now, we'll use a software fallback from malu_crypto
            use malu_crypto::hash::{hash, HashAlgorithm};
            
            let result = hash(data, HashAlgorithm::Sha256)?;
            
            return Ok(result);
        }
        
        #[cfg(not(feature = "pkcs11"))]
        {
            return Err(Box::new(HsmError::Hsm("PKCS#11 support not enabled".into())));
        }
    }

    async fn sign(&self, _message: &[u8], _key: &[u8]) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        debug!("HSM signing message");
        
        #[cfg(feature = "pkcs11")]
        {
            // HSM signing would be implemented here
            // For now, we'll use a software fallback from malu_crypto
            use malu_crypto::signature::{sign, SignatureAlgorithm};
            
            // In a real implementation, we would use the HSM's signing capabilities
            // and the key would be an identifier rather than the actual key material
            
            // This is just a placeholder for demonstration
            let key_pair = malu_crypto::signature::generate_key_pair(SignatureAlgorithm::Ed25519)?;
            let result = sign(message, key_pair.private_key(), SignatureAlgorithm::Ed25519)?;
            
            return Ok(result);
        }
        
        #[cfg(not(feature = "pkcs11"))]
        {
            return Err(Box::new(HsmError::Hsm("PKCS#11 support not enabled".into())));
        }
    }

    async fn verify(&self, _message: &[u8], _signature: &[u8], _key: &[u8]) -> std::result::Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        debug!("HSM verifying signature");
        
        #[cfg(feature = "pkcs11")]
        {
            // HSM verification would be implemented here
            // For now, we'll use a software fallback from malu_crypto
            use malu_crypto::signature::{verify, SignatureAlgorithm};
            
            // In a real implementation, we would use the HSM's verification capabilities
            // and the key would be an identifier rather than the actual key material
            
            let result = verify(message, signature, key, SignatureAlgorithm::Ed25519)?;
            
            return Ok(result);
        }
        
        #[cfg(not(feature = "pkcs11"))]
        {
            return Err(Box::new(HsmError::Hsm("PKCS#11 support not enabled".into())));
        }
    }

    async fn generate_nonce(&self, length: usize) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Nonces are just random bytes so we can reuse the generate_random implementation
        self.generate_random(length).await
    }
}

impl Clone for HsmCryptoProvider {
    fn clone(&self) -> Self {
        // Create a new instance with the same config but no context
        // Context will be initialized on-demand when needed
        Self {
            config: self.config.clone(),
            #[cfg(feature = "pkcs11")]
            ctx: None,
        }
    }
}

#[cfg(test)]
#[cfg(feature = "pkcs11")]
mod tests {
    use super::*;
    use malu_interfaces::CryptoProvider;
    
    #[tokio::test]
    #[ignore = "Requires an actual HSM"]
    async fn test_hsm_random() {
        let config = HsmConfig {
            hsm_type: HsmType::Pkcs11,
            pkcs11_lib_path: Some("/usr/local/lib/softhsm/libsofthsm2.so".to_string()),
            slot_id: Some(0),
            pin: Some("1234".to_string()),
            token_label: Some("test".to_string()),
            key_id: None,
        };
        
        let hsm = HsmCryptoProvider::new(config);
        
        let random = hsm.generate_random(32).await.unwrap();
        assert_eq!(random.len(), 32);
    }
}
