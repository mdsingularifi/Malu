//! File-based governance provider implementation

use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tokio::fs::{create_dir_all, read_to_string, write};

use malu_interfaces::{GovernanceProvider, PrincipalType, Result};
use crate::error::{GovernanceError, Result as GovResult};
use crate::policy::Policy;

/// File-based implementation of the GovernanceProvider interface
/// 
/// This provider stores policies and assignments as JSON files in the specified directory.
#[derive(Debug)]
pub struct FileGovernanceProvider {
    base_path: PathBuf,
    policies_path: PathBuf,
    assignments_path: PathBuf,
    // Cache for faster access
    policies_cache: Arc<RwLock<HashMap<String, String>>>,
    assignments_cache: Arc<RwLock<HashMap<(String, PrincipalType), HashSet<String>>>>,
}

impl FileGovernanceProvider {
    /// Create a new file-based governance provider with the given base path
    pub fn new<P: AsRef<Path>>(base_path: P) -> Self {
        let base_path = base_path.as_ref().to_path_buf();
        let policies_path = base_path.join("policies");
        let assignments_path = base_path.join("assignments");
        
        // Create directories if they don't exist
        if !policies_path.exists() {
            fs::create_dir_all(&policies_path).expect("Failed to create policies directory");
        }
        if !assignments_path.exists() {
            fs::create_dir_all(&assignments_path).expect("Failed to create assignments directory");
        }
        
        Self {
            base_path,
            policies_path,
            assignments_path,
            policies_cache: Arc::new(RwLock::new(HashMap::new())),
            assignments_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Get the path for a policy file
    fn policy_path(&self, policy_id: &str) -> PathBuf {
        self.policies_path.join(format!("{}.json", policy_id))
    }
    
    /// Get the path for an assignment file
    fn assignment_path(&self, principal_id: &str, principal_type: PrincipalType) -> PathBuf {
        let type_str = match principal_type {
            PrincipalType::User => "user",
            PrincipalType::Group => "group",
            PrincipalType::Role => "role",
        };
        self.assignments_path.join(format!("{}_{}.json", type_str, principal_id))
    }
    
    /// Load a policy from the file system
    async fn load_policy(&self, policy_id: &str) -> GovResult<String> {
        // Check cache first
        {
            let cache = self.policies_cache.read().map_err(|e| {
                GovernanceError::Other(format!("Lock error: {}", e))
            })?;
            if let Some(policy) = cache.get(policy_id) {
                return Ok(policy.clone());
            }
        }
        
        // Load from file
        let path = self.policy_path(policy_id);
        if !path.exists() {
            return Err(GovernanceError::PolicyNotFound(policy_id.to_string()));
        }
        
        let content = read_to_string(&path).await
            .map_err(|e| GovernanceError::StorageError(format!("Failed to read policy file: {}", e)))?;
        
        // Update cache
        {
            let mut cache = self.policies_cache.write().map_err(|e| {
                GovernanceError::Other(format!("Lock error: {}", e))
            })?;
            cache.insert(policy_id.to_string(), content.clone());
        }
        
        Ok(content)
    }
    
    /// Load assignments for a principal from the file system
    async fn load_assignments(&self, principal_id: &str, principal_type: PrincipalType) -> GovResult<HashSet<String>> {
        // Check cache first
        let key = (principal_id.to_string(), principal_type);
        {
            let cache = self.assignments_cache.read().map_err(|e| {
                GovernanceError::Other(format!("Lock error: {}", e))
            })?;
            if let Some(assignments) = cache.get(&key) {
                return Ok(assignments.clone());
            }
        }
        
        // Load from file
        let path = self.assignment_path(principal_id, principal_type);
        if !path.exists() {
            return Ok(HashSet::new());
        }
        
        let content = read_to_string(&path).await
            .map_err(|e| GovernanceError::StorageError(format!("Failed to read assignments file: {}", e)))?;
        
        let assignments: HashSet<String> = serde_json::from_str(&content)
            .map_err(|e| GovernanceError::StorageError(format!("Failed to parse assignments: {}", e)))?;
        
        // Update cache
        {
            let mut cache = self.assignments_cache.write().map_err(|e| {
                GovernanceError::Other(format!("Lock error: {}", e))
            })?;
            cache.insert(key, assignments.clone());
        }
        
        Ok(assignments)
    }
    
    /// Save assignments for a principal to the file system
    async fn save_assignments(&self, principal_id: &str, principal_type: PrincipalType, assignments: &HashSet<String>) -> GovResult<()> {
        let path = self.assignment_path(principal_id, principal_type);
        let content = serde_json::to_string_pretty(assignments)
            .map_err(|e| GovernanceError::StorageError(format!("Failed to serialize assignments: {}", e)))?;
        
        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            create_dir_all(parent).await
                .map_err(|e| GovernanceError::StorageError(format!("Failed to create directory: {}", e)))?;
        }
        
        // Write to file
        write(&path, &content).await
            .map_err(|e| GovernanceError::StorageError(format!("Failed to write assignments file: {}", e)))?;
        
        // Update cache
        {
            let mut cache = self.assignments_cache.write().map_err(|e| {
                GovernanceError::Other(format!("Lock error: {}", e))
            })?;
            cache.insert((principal_id.to_string(), principal_type), assignments.clone());
        }
        
        Ok(())
    }
}

#[async_trait]
impl GovernanceProvider for FileGovernanceProvider {
    async fn check_permission(&self, user_id: &str, action: &str, resource: &str) -> Result<bool> {
        // List all policies
        let entries = fs::read_dir(&self.policies_path).map_err(|e| {
            Box::new(GovernanceError::StorageError(format!("Failed to read policies directory: {}", e)))
                as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        // Check each policy
        for entry in entries {
            let entry = entry.map_err(|e| {
                Box::new(GovernanceError::StorageError(format!("Failed to read directory entry: {}", e)))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;
            
            let path = entry.path();
            if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
                let policy_id = path.file_stem().unwrap().to_string_lossy().to_string();
                let policy_json = match self.load_policy(&policy_id).await {
                    Ok(json) => json,
                    Err(_) => continue, // Skip invalid policies
                };
                
                let policy = Policy::from_json(&policy_json).map_err(|e| {
                    Box::new(e) as Box<dyn std::error::Error + Send + Sync>
                })?;
                
                if policy.evaluate(user_id, action, resource) {
                    return Ok(true);
                }
            }
        }
        
        // If no policy explicitly allows, deny by default
        Ok(false)
    }
    
    async fn set_policy(&self, policy_id: &str, policy_definition: &str) -> Result<()> {
        // Validate the policy by parsing it
        Policy::from_json(policy_definition).map_err(|e| {
            Box::new(e) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        // Save to file
        let path = self.policy_path(policy_id);
        
        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            create_dir_all(parent).await.map_err(|e| {
                Box::new(GovernanceError::StorageError(format!("Failed to create directory: {}", e)))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;
        }
        
        // Write policy to file
        write(&path, policy_definition).await.map_err(|e| {
            Box::new(GovernanceError::StorageError(format!("Failed to write policy file: {}", e)))
                as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        // Update cache
        {
            let mut cache = self.policies_cache.write().map_err(|e| {
                Box::new(GovernanceError::Other(format!("Lock error: {}", e)))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;
            cache.insert(policy_id.to_string(), policy_definition.to_string());
        }
        
        Ok(())
    }
    
    async fn get_policy(&self, policy_id: &str) -> Result<String> {
        self.load_policy(policy_id).await.map_err(|e| {
            Box::new(e) as Box<dyn std::error::Error + Send + Sync>
        })
    }
    
    async fn delete_policy(&self, policy_id: &str) -> Result<()> {
        let path = self.policy_path(policy_id);
        if !path.exists() {
            return Err(Box::new(GovernanceError::PolicyNotFound(policy_id.to_string())));
        }
        
        // Delete the file
        fs::remove_file(&path).map_err(|e| {
            Box::new(GovernanceError::StorageError(format!("Failed to delete policy file: {}", e)))
                as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        // Update cache
        {
            let mut cache = self.policies_cache.write().map_err(|e| {
                Box::new(GovernanceError::Other(format!("Lock error: {}", e)))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;
            cache.remove(policy_id);
        }
        
        // Remove policy from all assignments
        let entries = fs::read_dir(&self.assignments_path).map_err(|e| {
            Box::new(GovernanceError::StorageError(format!("Failed to read assignments directory: {}", e)))
                as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        for entry in entries {
            let entry = entry.map_err(|e| {
                Box::new(GovernanceError::StorageError(format!("Failed to read directory entry: {}", e)))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;
            
            let path = entry.path();
            if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
                let filename = path.file_stem().unwrap().to_string_lossy();
                let parts: Vec<&str> = filename.splitn(2, '_').collect();
                if parts.len() != 2 {
                    continue;
                }
                
                let principal_type = match parts[0] {
                    "user" => PrincipalType::User,
                    "group" => PrincipalType::Group,
                    "role" => PrincipalType::Role,
                    _ => continue,
                };
                
                let principal_id = parts[1].to_string();
                
                // Load assignments
                let mut assignments = match self.load_assignments(&principal_id, principal_type).await {
                    Ok(assignments) => assignments,
                    Err(_) => continue,
                };
                
                // Remove the policy
                if assignments.remove(policy_id) {
                    // Save updated assignments
                    self.save_assignments(&principal_id, principal_type, &assignments).await.map_err(|e| {
                        Box::new(e) as Box<dyn std::error::Error + Send + Sync>
                    })?;
                }
            }
        }
        
        Ok(())
    }
    
    async fn list_policies(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        let entries = fs::read_dir(&self.policies_path).map_err(|e| {
            Box::new(GovernanceError::StorageError(format!("Failed to read policies directory: {}", e)))
                as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        let mut policy_ids = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| {
                Box::new(GovernanceError::StorageError(format!("Failed to read directory entry: {}", e)))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;
            
            let path = entry.path();
            if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
                let policy_id = path.file_stem().unwrap().to_string_lossy().to_string();
                
                if let Some(prefix) = prefix {
                    if policy_id.starts_with(prefix) {
                        policy_ids.push(policy_id);
                    }
                } else {
                    policy_ids.push(policy_id);
                }
            }
        }
        
        Ok(policy_ids)
    }
    
    async fn assign_policy(&self, policy_id: &str, principal_id: &str, principal_type: PrincipalType) -> Result<()> {
        // Check that the policy exists
        if !self.policy_path(policy_id).exists() {
            return Err(Box::new(GovernanceError::PolicyNotFound(policy_id.to_string())));
        }
        
        // Load assignments
        let mut assignments = self.load_assignments(principal_id, principal_type).await.map_err(|e| {
            Box::new(e) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        // Add the policy
        assignments.insert(policy_id.to_string());
        
        // Save assignments
        self.save_assignments(principal_id, principal_type, &assignments).await.map_err(|e| {
            Box::new(e) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        Ok(())
    }
    
    async fn revoke_policy(&self, policy_id: &str, principal_id: &str, principal_type: PrincipalType) -> Result<()> {
        // Load assignments
        let mut assignments = self.load_assignments(principal_id, principal_type).await.map_err(|e| {
            Box::new(e) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        // Remove the policy
        if !assignments.remove(policy_id) {
            return Err(Box::new(GovernanceError::PolicyNotFound(format!(
                "Policy {} not assigned to principal", policy_id
            ))));
        }
        
        // Save assignments
        self.save_assignments(principal_id, principal_type, &assignments).await.map_err(|e| {
            Box::new(e) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        Ok(())
    }
    
    async fn list_principal_policies(&self, principal_id: &str, principal_type: PrincipalType) -> Result<Vec<String>> {
        let assignments = self.load_assignments(principal_id, principal_type).await.map_err(|e| {
            Box::new(e) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        Ok(assignments.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[cfg(test)]
    fn create_temp_dir() -> std::path::PathBuf {
        use std::env;
        use std::fs;
        
        let mut dir = env::temp_dir();
        dir.push(format!("malu_governance_test_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
    
    #[cfg(test)]
    fn cleanup_temp_dir(dir: &std::path::PathBuf) {
        use std::fs;
        let _ = fs::remove_dir_all(dir);
    }
    
    #[tokio::test]
    async fn test_file_provider() {
        // Create a temporary directory for testing
        let temp_dir = create_temp_dir();
        let provider = FileGovernanceProvider::new(&temp_dir);
        
        // Test creating a policy
        let policy_id = "test-policy";
        let policy_def = r#"{"Version":"2021-11-01","Statement":[{"Effect":"Allow","Action":["read"],"Resource":["document:*"],"Principal":["user:alice"]}]}"#;
        
        provider.set_policy(policy_id, policy_def).await.unwrap();
        
        // Test retrieving a policy
        let retrieved = provider.get_policy(policy_id).await.unwrap();
        assert_eq!(retrieved, policy_def);
        
        // Test listing policies
        let policies = provider.list_policies(None).await.unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0], policy_id);
        
        // Test policy assignment
        let user_id = "alice";
        provider.assign_policy(policy_id, user_id, PrincipalType::User).await.unwrap();
        
        // Test listing assignments
        let assignments = provider.list_principal_policies(user_id, PrincipalType::User).await.unwrap();
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0], policy_id);
        
        // Test permission check
        let result = provider.check_permission("alice", "read", "document:123").await.unwrap();
        assert!(result);
        
        // Test revoking a policy
        provider.revoke_policy(policy_id, user_id, PrincipalType::User).await.unwrap();
        let assignments = provider.list_principal_policies(user_id, PrincipalType::User).await.unwrap();
        assert_eq!(assignments.len(), 0);
        
        // Test deleting a policy
        provider.delete_policy(policy_id).await.unwrap();
        let policies = provider.list_policies(None).await.unwrap();
        assert_eq!(policies.len(), 0);
    }
}
