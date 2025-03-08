//! In-memory governance provider implementation

use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use malu_interfaces::{GovernanceProvider, PrincipalType, Result};
use crate::error::GovernanceError;
use crate::policy::Policy;

/// In-memory implementation of the GovernanceProvider interface
/// 
/// This provider is primarily intended for testing purposes.
#[derive(Debug)]
pub struct MemoryGovernanceProvider {
    policies: Arc<RwLock<HashMap<String, String>>>,
    assignments: Arc<RwLock<HashMap<(String, PrincipalType), HashSet<String>>>>,
}

impl MemoryGovernanceProvider {
    /// Create a new in-memory governance provider
    pub fn new() -> Self {
        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
            assignments: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for MemoryGovernanceProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl GovernanceProvider for MemoryGovernanceProvider {
    async fn check_permission(&self, user_id: &str, action: &str, resource: &str) -> Result<bool> {
        let policies = self.policies.read().map_err(|e| {
            Box::new(GovernanceError::Other(format!("Lock error: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        // Check each policy
        for policy_json in policies.values() {
            let policy = Policy::from_json(policy_json).map_err(|e| {
                Box::new(e) as Box<dyn std::error::Error + Send + Sync>
            })?;
            
            if policy.evaluate(user_id, action, resource) {
                return Ok(true);
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
        
        // Store the policy
        let mut policies = self.policies.write().map_err(|e| {
            Box::new(GovernanceError::Other(format!("Lock error: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        policies.insert(policy_id.to_string(), policy_definition.to_string());
        Ok(())
    }
    
    async fn get_policy(&self, policy_id: &str) -> Result<String> {
        let policies = self.policies.read().map_err(|e| {
            Box::new(GovernanceError::Other(format!("Lock error: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        match policies.get(policy_id) {
            Some(policy) => Ok(policy.clone()),
            None => Err(Box::new(GovernanceError::PolicyNotFound(policy_id.to_string()))),
        }
    }
    
    async fn delete_policy(&self, policy_id: &str) -> Result<()> {
        let mut policies = self.policies.write().map_err(|e| {
            Box::new(GovernanceError::Other(format!("Lock error: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        if policies.remove(policy_id).is_none() {
            return Err(Box::new(GovernanceError::PolicyNotFound(policy_id.to_string())));
        }
        
        // Also remove any assignments of this policy
        let mut assignments = self.assignments.write().map_err(|e| {
            Box::new(GovernanceError::Other(format!("Lock error: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        for policies in assignments.values_mut() {
            policies.remove(policy_id);
        }
        
        Ok(())
    }
    
    async fn list_policies(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        let policies = self.policies.read().map_err(|e| {
            Box::new(GovernanceError::Other(format!("Lock error: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        let policy_ids = match prefix {
            Some(prefix) => policies.keys()
                .filter(|id| id.starts_with(prefix))
                .cloned()
                .collect(),
            None => policies.keys().cloned().collect(),
        };
        
        Ok(policy_ids)
    }
    
    async fn assign_policy(&self, policy_id: &str, principal_id: &str, principal_type: PrincipalType) -> Result<()> {
        // Check that the policy exists
        let policies = self.policies.read().map_err(|e| {
            Box::new(GovernanceError::Other(format!("Lock error: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        if !policies.contains_key(policy_id) {
            return Err(Box::new(GovernanceError::PolicyNotFound(policy_id.to_string())));
        }
        
        // Add the assignment
        let mut assignments = self.assignments.write().map_err(|e| {
            Box::new(GovernanceError::Other(format!("Lock error: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        let principal_key = (principal_id.to_string(), principal_type);
        let policies = assignments.entry(principal_key).or_insert_with(HashSet::new);
        policies.insert(policy_id.to_string());
        
        Ok(())
    }
    
    async fn revoke_policy(&self, policy_id: &str, principal_id: &str, principal_type: PrincipalType) -> Result<()> {
        let mut assignments = self.assignments.write().map_err(|e| {
            Box::new(GovernanceError::Other(format!("Lock error: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        let principal_key = (principal_id.to_string(), principal_type);
        if let Some(policies) = assignments.get_mut(&principal_key) {
            if !policies.remove(policy_id) {
                return Err(Box::new(GovernanceError::PolicyNotFound(format!(
                    "Policy {} not assigned to principal", policy_id
                ))));
            }
        } else {
            return Err(Box::new(GovernanceError::PrincipalNotFound(principal_id.to_string())));
        }
        
        Ok(())
    }
    
    async fn list_principal_policies(&self, principal_id: &str, principal_type: PrincipalType) -> Result<Vec<String>> {
        let assignments = self.assignments.read().map_err(|e| {
            Box::new(GovernanceError::Other(format!("Lock error: {}", e))) as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        let principal_key = (principal_id.to_string(), principal_type);
        match assignments.get(&principal_key) {
            Some(policies) => Ok(policies.iter().cloned().collect()),
            None => Ok(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use malu_interfaces::PrincipalType;
    
    #[tokio::test]
    async fn test_policy_crud() {
        let provider = MemoryGovernanceProvider::new();
        
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
        
        // Test deleting a policy
        provider.delete_policy(policy_id).await.unwrap();
        let policies = provider.list_policies(None).await.unwrap();
        assert_eq!(policies.len(), 0);
    }
    
    #[tokio::test]
    async fn test_policy_assignment() {
        let provider = MemoryGovernanceProvider::new();
        
        // Create a test policy
        let policy_id = "test-policy";
        let policy_def = r#"{"Version":"2021-11-01","Statement":[{"Effect":"Allow","Action":["read"],"Resource":["document:*"],"Principal":["user:alice"]}]}"#;
        provider.set_policy(policy_id, policy_def).await.unwrap();
        
        // Test assigning a policy
        let user_id = "alice";
        provider.assign_policy(policy_id, user_id, PrincipalType::User).await.unwrap();
        
        // Test listing assigned policies
        let policies = provider.list_principal_policies(user_id, PrincipalType::User).await.unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0], policy_id);
        
        // Test revoking a policy
        provider.revoke_policy(policy_id, user_id, PrincipalType::User).await.unwrap();
        let policies = provider.list_principal_policies(user_id, PrincipalType::User).await.unwrap();
        assert_eq!(policies.len(), 0);
    }
    
    #[tokio::test]
    async fn test_permission_check() {
        let provider = MemoryGovernanceProvider::new();
        
        // Create a test policy
        let policy_id = "test-policy";
        let policy_def = r#"{"Version":"2021-11-01","Statement":[{"Effect":"Allow","Action":["read"],"Resource":["document:*"],"Principal":["user:alice"]}]}"#;
        provider.set_policy(policy_id, policy_def).await.unwrap();
        
        // Test permission check
        let result = provider.check_permission("alice", "read", "document:123").await.unwrap();
        assert!(result);
        
        // Test permission denial
        let result = provider.check_permission("bob", "read", "document:123").await.unwrap();
        assert!(!result);
        
        let result = provider.check_permission("alice", "write", "document:123").await.unwrap();
        assert!(!result);
    }
}
