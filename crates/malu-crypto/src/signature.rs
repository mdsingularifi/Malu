//! Digital signature functionality
//!
//! This module provides functions for creating and verifying digital signatures,
//! which are essential for message authentication and non-repudiation.

use crate::error::{CryptoError, Result};
use ring::{rand as ring_rand, signature as ring_sig};
use serde::{Deserialize, Serialize};
// Import trait to get access to methods like public_key
use ring::signature::KeyPair;

/// Signature algorithms supported by the system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SignatureAlgorithm {
    /// ECDSA with the P-256 curve
    EcdsaP256,
    
    /// ECDSA with the P-384 curve
    EcdsaP384,
    
    /// Ed25519 (Edwards-curve Digital Signature Algorithm)
    #[default]
    Ed25519,
    
    /// RSA with PKCS#1 v1.5 padding and SHA-256
    RsaPkcs1v15,
    
    /// RSA with PSS padding and SHA-256
    RsaPss,
}

/// Key pair for digital signatures
#[allow(dead_code)]
pub struct SignatureKeyPair {
    /// The algorithm used
    pub algorithm: SignatureAlgorithm,
    
    /// The serialized private key
    private_key: Vec<u8>,
    
    /// The serialized public key
    public_key: Vec<u8>,
}

#[allow(dead_code)]
impl SignatureKeyPair {
    /// Get the public key bytes
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    
    /// Get the private key bytes (use with caution)
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }
}

/// Generate a new key pair for digital signatures
///
/// # Arguments
///
/// * `algorithm` - The signature algorithm to use
///
/// # Returns
///
/// A new key pair for the specified algorithm
#[allow(dead_code)]
pub fn generate_key_pair(algorithm: SignatureAlgorithm) -> Result<SignatureKeyPair> {
    let rng = ring_rand::SystemRandom::new();
    
    match algorithm {
        SignatureAlgorithm::Ed25519 => {
            let pkcs8_bytes = ring_sig::Ed25519KeyPair::generate_pkcs8(&rng)
                .map_err(|_| CryptoError::Key("Failed to generate Ed25519 key pair".into()))?;
                
            let key_pair = ring_sig::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
                .map_err(|_| CryptoError::Key("Failed to parse Ed25519 key pair".into()))?;
                
            // Access the public key using the correct method
            let public_key = key_pair.public_key().as_ref().to_vec();
                
            Ok(SignatureKeyPair {
                algorithm,
                private_key: pkcs8_bytes.as_ref().to_vec(),
                public_key,
            })
        },
        SignatureAlgorithm::EcdsaP256 => {
            let pkcs8_bytes = ring_sig::EcdsaKeyPair::generate_pkcs8(
                &ring_sig::ECDSA_P256_SHA256_ASN1_SIGNING,
                &rng
            )
            .map_err(|_| CryptoError::Key("Failed to generate ECDSA P-256 key pair".into()))?;
            
            let key_pair = ring_sig::EcdsaKeyPair::from_pkcs8(
                &ring_sig::ECDSA_P256_SHA256_ASN1_SIGNING,
                pkcs8_bytes.as_ref()
            )
            .map_err(|_| CryptoError::Key("Failed to parse ECDSA P-256 key pair".into()))?;
            
            // Access the public key correctly
            let public_key = key_pair.public_key().as_ref().to_vec();
            
            Ok(SignatureKeyPair {
                algorithm,
                private_key: pkcs8_bytes.as_ref().to_vec(),
                public_key,
            })
        },
        SignatureAlgorithm::EcdsaP384 => {
            let pkcs8_bytes = ring_sig::EcdsaKeyPair::generate_pkcs8(
                &ring_sig::ECDSA_P384_SHA384_ASN1_SIGNING,
                &rng
            )
            .map_err(|_| CryptoError::Key("Failed to generate ECDSA P-384 key pair".into()))?;
            
            let key_pair = ring_sig::EcdsaKeyPair::from_pkcs8(
                &ring_sig::ECDSA_P384_SHA384_ASN1_SIGNING,
                pkcs8_bytes.as_ref()
            )
            .map_err(|_| CryptoError::Key("Failed to parse ECDSA P-384 key pair".into()))?;
            
            // Access the public key correctly
            let public_key = key_pair.public_key().as_ref().to_vec();
            
            Ok(SignatureKeyPair {
                algorithm,
                private_key: pkcs8_bytes.as_ref().to_vec(),
                public_key,
            })
        },
        SignatureAlgorithm::RsaPkcs1v15 | SignatureAlgorithm::RsaPss => {
            // Ring doesn't support RSA key generation, so we use openssl crate
            Err(CryptoError::Algorithm("RSA key generation not supported in this implementation".into()))
        }
    }
}

/// Sign a message using a private key
///
/// # Arguments
///
/// * `message` - The message to sign
/// * `private_key` - The private key to use for signing
/// * `algorithm` - The signature algorithm to use
///
/// # Returns
///
/// The signature bytes
pub fn sign(message: &[u8], private_key: &[u8], algorithm: SignatureAlgorithm) -> Result<Vec<u8>> {
    match algorithm {
        SignatureAlgorithm::Ed25519 => {
            let key_pair = ring_sig::Ed25519KeyPair::from_pkcs8(private_key)
                .map_err(|_| CryptoError::Key("Invalid Ed25519 private key".into()))?;
                
            Ok(key_pair.sign(message).as_ref().to_vec())
        },
        SignatureAlgorithm::EcdsaP256 => {
            let key_pair = ring_sig::EcdsaKeyPair::from_pkcs8(
                &ring_sig::ECDSA_P256_SHA256_ASN1_SIGNING,
                private_key
            )
            .map_err(|_| CryptoError::Key("Invalid ECDSA P-256 private key".into()))?;
            
            let rng = ring_rand::SystemRandom::new();
            
            key_pair.sign(&rng, message)
                .map(|sig| sig.as_ref().to_vec())
                .map_err(|_| CryptoError::Internal("Signing failed".into()))
        },
        SignatureAlgorithm::EcdsaP384 => {
            let key_pair = ring_sig::EcdsaKeyPair::from_pkcs8(
                &ring_sig::ECDSA_P384_SHA384_ASN1_SIGNING,
                private_key
            )
            .map_err(|_| CryptoError::Key("Invalid ECDSA P-384 private key".into()))?;
            
            let rng = ring_rand::SystemRandom::new();
            
            key_pair.sign(&rng, message)
                .map(|sig| sig.as_ref().to_vec())
                .map_err(|_| CryptoError::Internal("Signing failed".into()))
        },
        SignatureAlgorithm::RsaPkcs1v15 | SignatureAlgorithm::RsaPss => {
            Err(CryptoError::Algorithm("RSA signing not supported in this implementation".into()))
        }
    }
}

/// Verify a signature using a public key
///
/// # Arguments
///
/// * `message` - The message that was signed
/// * `signature` - The signature to verify
/// * `public_key` - The public key to use for verification
/// * `algorithm` - The signature algorithm to use
///
/// # Returns
///
/// `true` if the signature is valid, `false` otherwise
pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8], algorithm: SignatureAlgorithm) -> Result<bool> {
    match algorithm {
        SignatureAlgorithm::Ed25519 => {
            let public_key = ring_sig::UnparsedPublicKey::new(
                &ring_sig::ED25519,
                public_key
            );
            
            match public_key.verify(message, signature) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        },
        SignatureAlgorithm::EcdsaP256 => {
            let public_key = ring_sig::UnparsedPublicKey::new(
                &ring_sig::ECDSA_P256_SHA256_ASN1,
                public_key
            );
            
            match public_key.verify(message, signature) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        },
        SignatureAlgorithm::EcdsaP384 => {
            let public_key = ring_sig::UnparsedPublicKey::new(
                &ring_sig::ECDSA_P384_SHA384_ASN1,
                public_key
            );
            
            match public_key.verify(message, signature) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        },
        SignatureAlgorithm::RsaPkcs1v15 => {
            let public_key = ring_sig::UnparsedPublicKey::new(
                &ring_sig::RSA_PKCS1_2048_8192_SHA256,
                public_key
            );
            
            match public_key.verify(message, signature) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        },
        SignatureAlgorithm::RsaPss => {
            let public_key = ring_sig::UnparsedPublicKey::new(
                &ring_sig::RSA_PSS_2048_8192_SHA256,
                public_key
            );
            
            match public_key.verify(message, signature) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519() {
        let key_pair = generate_key_pair(SignatureAlgorithm::Ed25519).unwrap();
        let message = b"Hello, world!";
        
        let signature = sign(message, key_pair.private_key(), SignatureAlgorithm::Ed25519).unwrap();
        
        // Verification with correct key should succeed
        assert!(verify(message, &signature, key_pair.public_key(), SignatureAlgorithm::Ed25519).unwrap());
        
        // Verification with wrong message should fail
        let wrong_message = b"Hello, world";
        assert!(!verify(wrong_message, &signature, key_pair.public_key(), SignatureAlgorithm::Ed25519).unwrap());
        
        // Tampered signature should fail verification
        let mut tampered_signature = signature.clone();
        if tampered_signature.len() > 0 {
            tampered_signature[0] ^= 1;
        }
        assert!(!verify(message, &tampered_signature, key_pair.public_key(), SignatureAlgorithm::Ed25519).unwrap());
    }

    #[test]
    fn test_ecdsa_p256() {
        let key_pair = generate_key_pair(SignatureAlgorithm::EcdsaP256).unwrap();
        let message = b"Hello, world!";
        
        let signature = sign(message, key_pair.private_key(), SignatureAlgorithm::EcdsaP256).unwrap();
        
        // Verification with correct key should succeed
        assert!(verify(message, &signature, key_pair.public_key(), SignatureAlgorithm::EcdsaP256).unwrap());
        
        // Verification with wrong message should fail
        let wrong_message = b"Hello, world";
        assert!(!verify(wrong_message, &signature, key_pair.public_key(), SignatureAlgorithm::EcdsaP256).unwrap());
    }
}
