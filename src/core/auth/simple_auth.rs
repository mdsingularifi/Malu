use crate::core::{AuthProvider, error::{Result, ServiceError}};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

// Constants for password hashing
const PBKDF2_ITERATIONS: u32 = 100_000;
const SALT_SIZE: usize = 16;
const HASH_SIZE: usize = 32;

/// Simple in-memory authentication provider
pub struct SimpleAuthProvider {
    // username -> (salt, hashed_password)
    users: Mutex<HashMap<String, (Vec<u8>, Vec<u8>)>>,
}

impl SimpleAuthProvider {
    /// Create a new empty SimpleAuthProvider
    pub fn new() -> Self {
        Self {
            users: Mutex::new(HashMap::new()),
        }
    }
    
    /// Add a user with the specified username and password
    pub fn add_user(&self, username: &str, password: &str) -> Result<()> {
        let mut users = self.users.lock().map_err(|e| {
            ServiceError::LockError(format!("Failed to acquire lock: {}", e))
        })?;
        
        // Generate a random salt
        let mut salt = vec![0u8; SALT_SIZE];
        let rng = ring::rand::SystemRandom::new();
        ring::rand::SecureRandom::fill(&rng, &mut salt).map_err(|e| {
            ServiceError::AuthError(format!("Failed to generate salt: {}", e))
        })?;
        
        // Hash the password with the salt
        let mut hash = vec![0u8; HASH_SIZE];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut hash);
        
        // Store the user credentials
        users.insert(username.to_string(), (salt, hash));
        
        Ok(())
    }
    
    /// Remove a user
    #[allow(dead_code)]
    pub fn remove_user(&self, username: &str) -> Result<()> {
        let mut users = self.users.lock().map_err(|e| {
            ServiceError::LockError(format!("Failed to acquire lock: {}", e))
        })?;
        
        if users.remove(username).is_none() {
            return Err(ServiceError::NotFound(format!("User not found: {}", username)));
        }
        
        Ok(())
    }
}

impl Default for SimpleAuthProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthProvider for SimpleAuthProvider {
    async fn authenticate(&self, username: &str, password: &str) -> Result<bool> {
        let users = self.users.lock().map_err(|e| {
            ServiceError::LockError(format!("Failed to acquire lock: {}", e))
        })?;
        
        // Look up the user
        if let Some((salt, stored_hash)) = users.get(username) {
            // Hash the provided password with the same salt
            let mut hash = vec![0u8; HASH_SIZE];
            pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut hash);
            
            // Compare the hashes in constant time
            let matched = ring::constant_time::verify_slices_are_equal(&hash, stored_hash).is_ok();
            
            Ok(matched)
        } else {
            // Return false for non-existent users to prevent username enumeration
            Ok(false)
        }
    }
    
    async fn verify_token(&self, _token: &str) -> Result<bool> {
        // Simple auth provider does not support token-based authentication
        Err(ServiceError::AuthError("Token authentication not supported".to_string()))
    }
    
    async fn get_user_id_from_token(&self, _token: &str) -> Result<String> {
        // Simple auth provider does not support token-based authentication
        Err(ServiceError::AuthError("Token authentication not supported".to_string()))
    }
}

// Factory function to create a new simple auth provider with default users
pub fn create_simple_auth_provider(default_users: Vec<(String, String)>) -> Result<Arc<SimpleAuthProvider>> {
    let provider = SimpleAuthProvider::new();
    
    // Add the default users
    for (username, password) in default_users {
        provider.add_user(&username, &password)?;
    }
    
    Ok(Arc::new(provider))
}
