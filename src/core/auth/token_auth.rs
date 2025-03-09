use crate::core::{AuthProvider, error::{Result, ServiceError}};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use hmac::Hmac;
use sha2::Sha256;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;

#[allow(dead_code)]
type HmacSha256 = Hmac<Sha256>;

/// Token information
struct TokenInfo {
    user_id: String,
    expires_at: DateTime<Utc>,
}

/// Token-based authentication provider
pub struct TokenAuthProvider {
    // Secret key used to sign tokens
    #[allow(dead_code)]
    secret_key: Vec<u8>,
    
    // Token storage: token -> (user_id, expiration)
    tokens: Mutex<HashMap<String, TokenInfo>>,
    
    // User credentials: username -> (user_id, hashed_password)
    users: Mutex<HashMap<String, (String, String)>>,
    
    // Token expiration in seconds
    token_expiration_secs: i64,
}

impl TokenAuthProvider {
    /// Create a new TokenAuthProvider with the specified secret key
    pub fn new(secret_key: &[u8], token_expiration_secs: i64) -> Self {
        Self {
            secret_key: secret_key.to_vec(),
            tokens: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            token_expiration_secs,
        }
    }
    
    /// Add a user with the specified username and password
    pub fn add_user(&self, username: &str, password: &str) -> Result<String> {
        let mut users = self.users.lock().map_err(|e| {
            ServiceError::LockError(format!("Failed to acquire lock: {}", e))
        })?;
        
        // Generate a unique user ID
        let user_id = Uuid::new_v4().to_string();
        
        // Hash the password
        let hashed_password = self.hash_password(password)?;
        
        // Store the user credentials
        users.insert(username.to_string(), (user_id.clone(), hashed_password));
        
        Ok(user_id)
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
    
    /// Hash a password
    fn hash_password(&self, password: &str) -> Result<String> {
        use ring::rand::SecureRandom;
        use pbkdf2::pbkdf2_hmac;
        
        // Generate a random salt
        let mut salt = vec![0u8; 16];
        ring::rand::SystemRandom::new().fill(&mut salt).map_err(|e| {
            ServiceError::AuthError(format!("Failed to generate salt: {}", e))
        })?;
        
        // Hash the password with PBKDF2
        let mut hash = vec![0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 100_000, &mut hash);
        
        // Combine salt and hash for storage
        let mut result = Vec::with_capacity(salt.len() + hash.len());
        result.extend_from_slice(&salt);
        result.extend_from_slice(&hash);
        
        // Encode as Base64
        Ok(BASE64.encode(result))
    }
    
    /// Verify a password against a stored hash
    fn verify_password(&self, password: &str, stored_hash: &str) -> Result<bool> {
        // Decode the stored hash from Base64
        let decoded = BASE64.decode(stored_hash).map_err(|e| {
            ServiceError::AuthError(format!("Failed to decode hash: {}", e))
        })?;
        
        // Split into salt and hash
        if decoded.len() < 48 {
            return Err(ServiceError::AuthError("Invalid hash format".to_string()));
        }
        
        let (salt, hash) = decoded.split_at(16);
        
        // Hash the provided password with the same salt
        let mut new_hash = vec![0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100_000, &mut new_hash);
        
        // Compare the hashes in constant time using subtle
        use subtle::ConstantTimeEq;
        let matched = hash.ct_eq(&new_hash).into();
        
        Ok(matched)
    }
    
    /// Generate a new token for a user
    async fn generate_token(&self, username: &str, password: &str) -> Result<String> {
        // Verify the user credentials
        let users = self.users.lock().map_err(|e| {
            ServiceError::LockError(format!("Failed to acquire lock: {}", e))
        })?;
        
        let (user_id, hashed_password) = users.get(username).ok_or_else(|| {
            ServiceError::AuthError("Invalid credentials".to_string())
        })?;
        
        let password_valid = self.verify_password(password, hashed_password)?;
        if !password_valid {
            return Err(ServiceError::AuthError("Invalid credentials".to_string()));
        }
        
        // Generate a unique token
        let token = Uuid::new_v4().to_string();
        
        // Calculate expiration time
        let expires_at = Utc::now() + Duration::seconds(self.token_expiration_secs);
        
        // Store the token
        let mut tokens = self.tokens.lock().map_err(|e| {
            ServiceError::LockError(format!("Failed to acquire lock: {}", e))
        })?;
        
        tokens.insert(token.clone(), TokenInfo {
            user_id: user_id.clone(),
            expires_at,
        });
        
        Ok(token)
    }
    
    /// Clean up expired tokens
    fn cleanup_expired_tokens(&self) -> Result<()> {
        let mut tokens = self.tokens.lock().map_err(|e| {
            ServiceError::LockError(format!("Failed to acquire lock: {}", e))
        })?;
        
        let now = Utc::now();
        tokens.retain(|_, info| info.expires_at > now);
        
        Ok(())
    }
}

#[async_trait]
impl AuthProvider for TokenAuthProvider {
    async fn authenticate(&self, username: &str, password: &str) -> Result<bool> {
        // Clean up expired tokens
        self.cleanup_expired_tokens()?;
        
        // Generate a token (which validates the credentials)
        match self.generate_token(username, password).await {
            Ok(_) => Ok(true),
            Err(ServiceError::AuthError(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }
    
    async fn verify_token(&self, token: &str) -> Result<bool> {
        // Clean up expired tokens
        self.cleanup_expired_tokens()?;
        
        let tokens = self.tokens.lock().map_err(|e| {
            ServiceError::LockError(format!("Failed to acquire lock: {}", e))
        })?;
        
        Ok(tokens.contains_key(token))
    }
    
    async fn get_user_id_from_token(&self, token: &str) -> Result<String> {
        // Clean up expired tokens
        self.cleanup_expired_tokens()?;
        
        let tokens = self.tokens.lock().map_err(|e| {
            ServiceError::LockError(format!("Failed to acquire lock: {}", e))
        })?;
        
        let token_info = tokens.get(token).ok_or_else(|| {
            ServiceError::AuthError("Invalid or expired token".to_string())
        })?;
        
        Ok(token_info.user_id.clone())
    }
}

// Factory function to create a new token auth provider
#[allow(dead_code)]
pub fn create_token_auth_provider(
    secret_key: &str, 
    token_expiration_secs: i64,
    default_users: Vec<(String, String)>
) -> Result<Arc<TokenAuthProvider>> {
    let provider = TokenAuthProvider::new(
        secret_key.as_bytes(),
        token_expiration_secs
    );
    
    // Add the default users
    for (username, password) in default_users {
        provider.add_user(&username, &password)?;
    }
    
    Ok(Arc::new(provider))
}
