//! OPA (Open Policy Agent) governance provider implementation

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use reqwest::Client;

use malu_interfaces::{GovernanceProvider, PrincipalType, Result};
use crate::error::GovernanceError;

/// OPA request input format
#[derive(Debug, Serialize)]
struct OpaInput<'a> {
    input: OpaInputData<'a>,
}

/// OPA input data structure
#[derive(Debug, Serialize)]
struct OpaInputData<'a> {
    user: &'a str,
    action: &'a str,
    resource: &'a str,
}

/// OPA response format
#[derive(Debug, Deserialize)]
struct OpaResponse {
    result: bool,
}

/// OPA status response format
#[derive(Debug, Deserialize)]
struct OpaStatus {
    #[allow(dead_code)]
    status: String,
}

/// OPA policy response format
#[derive(Debug, Deserialize)]
struct OpaPolicyResponse {
    result: Option<serde_json::Value>,
}

/// OPA (Open Policy Agent) implementation of the GovernanceProvider interface
/// 
/// This provider delegates policy evaluation to an external OPA server.
#[derive(Debug)]
pub struct OpaGovernanceProvider {
    client: Client,
    base_url: String,
    policy_path: String,
    data_path: String,
}

impl OpaGovernanceProvider {
    /// Create a new OPA governance provider with the given configuration
    pub fn new(config: serde_json::Value) -> Self {
        let base_url = config.get("base_url")
            .and_then(|v| v.as_str())
            .unwrap_or("http://localhost:8181")
            .to_string();
        
        let policy_path = config.get("policy_path")
            .and_then(|v| v.as_str())
            .unwrap_or("v1/policies")
            .to_string();
        
        let data_path = config.get("data_path")
            .and_then(|v| v.as_str())
            .unwrap_or("v1/data")
            .to_string();
        
        Self {
            client: Client::new(),
            base_url,
            policy_path,
            data_path,
        }
    }
    
    /// Get the full URL for a policy endpoint
    fn policy_url(&self, policy_id: &str) -> String {
        format!("{}/{}/{}", self.base_url, self.policy_path, policy_id)
    }
    
    /// Get the data URL for permission checks
    fn data_url(&self) -> String {
        format!("{}/{}/malu/authz/allow", self.base_url, self.data_path)
    }
    
    /// Get the data URL for policy assignments
    fn assignments_url(&self, principal_id: &str, principal_type: PrincipalType) -> String {
        let type_str = match principal_type {
            PrincipalType::User => "users",
            PrincipalType::Group => "groups",
            PrincipalType::Role => "roles",
        };
        format!("{}/{}/malu/assignments/{}/{}", self.base_url, self.data_path, type_str, principal_id)
    }
}

#[async_trait]
impl GovernanceProvider for OpaGovernanceProvider {
    async fn check_permission(&self, user_id: &str, action: &str, resource: &str) -> Result<bool> {
        let input = OpaInput {
            input: OpaInputData {
                user: user_id,
                action,
                resource,
            },
        };
        
        let response = self.client.post(&self.data_url())
            .json(&input)
            .send()
            .await
            .map_err(|e| {
                Box::new(GovernanceError::Other(format!("Failed to call OPA server: {}", e)))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;
        
        if !response.status().is_success() {
            return Err(Box::new(GovernanceError::Other(format!(
                "OPA server returned error: {}", response.status()
            ))));
        }
        
        let result: OpaResponse = response.json().await.map_err(|e| {
            Box::new(GovernanceError::Other(format!("Failed to parse OPA response: {}", e)))
                as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        Ok(result.result)
    }
    
    async fn set_policy(&self, policy_id: &str, policy_definition: &str) -> Result<()> {
        // Parse policy to ensure it's valid JSON
        let policy_json: serde_json::Value = serde_json::from_str(policy_definition).map_err(|e| {
            Box::new(GovernanceError::PolicyError(format!("Invalid policy JSON: {}", e)))
                as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        let response = self.client.put(&self.policy_url(policy_id))
            .json(&policy_json)
            .send()
            .await
            .map_err(|e| {
                Box::new(GovernanceError::Other(format!("Failed to call OPA server: {}", e)))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;
        
        if !response.status().is_success() {
            return Err(Box::new(GovernanceError::Other(format!(
                "OPA server returned error: {}", response.status()
            ))));
        }
        
        Ok(())
    }
    
    async fn get_policy(&self, policy_id: &str) -> Result<String> {
        let response = self.client.get(&self.policy_url(policy_id))
            .send()
            .await
            .map_err(|e| {
                Box::new(GovernanceError::Other(format!("Failed to call OPA server: {}", e)))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;
        
        if response.status().is_client_error() {
            return Err(Box::new(GovernanceError::PolicyNotFound(policy_id.to_string())));
        }
        
        if !response.status().is_success() {
            return Err(Box::new(GovernanceError::Other(format!(
                "OPA server returned error: {}", response.status()
            ))));
        }
        
        let policy: OpaPolicyResponse = response.json().await.map_err(|e| {
            Box::new(GovernanceError::Other(format!("Failed to parse OPA response: {}", e)))
                as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        let policy_json = policy.result.ok_or_else(|| {
            Box::new(GovernanceError::PolicyNotFound(policy_id.to_string()))
                as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        serde_json::to_string(&policy_json).map_err(|e| {
            Box::new(GovernanceError::Other(format!("Failed to serialize policy: {}", e)))
                as Box<dyn std::error::Error + Send + Sync>
        })
    }
    
    async fn delete_policy(&self, policy_id: &str) -> Result<()> {
        let response = self.client.delete(&self.policy_url(policy_id))
            .send()
            .await
            .map_err(|e| {
                Box::new(GovernanceError::Other(format!("Failed to call OPA server: {}", e)))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;
        
        if response.status().is_client_error() {
            return Err(Box::new(GovernanceError::PolicyNotFound(policy_id.to_string())));
        }
        
        if !response.status().is_success() {
            return Err(Box::new(GovernanceError::Other(format!(
                "OPA server returned error: {}", response.status()
            ))));
        }
        
        Ok(())
    }
    
    async fn list_policies(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        // OPA doesn't have a direct API to list policies with a prefix
        // We need to get all policies and filter them
        let list_url = format!("{}/{}", self.base_url, self.policy_path);
        
        let response = self.client.get(&list_url)
            .send()
            .await
            .map_err(|e| {
                Box::new(GovernanceError::Other(format!("Failed to call OPA server: {}", e)))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;
        
        if !response.status().is_success() {
            return Err(Box::new(GovernanceError::Other(format!(
                "OPA server returned error: {}", response.status()
            ))));
        }
        
        let policies: serde_json::Value = response.json().await.map_err(|e| {
            Box::new(GovernanceError::Other(format!("Failed to parse OPA response: {}", e)))
                as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        let policy_list = policies["result"].as_object().ok_or_else(|| {
            Box::new(GovernanceError::Other("Invalid response format".to_string()))
                as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        let mut policy_ids = Vec::new();
        for (id, _) in policy_list {
            if let Some(prefix) = prefix {
                if id.starts_with(prefix) {
                    policy_ids.push(id.clone());
                }
            } else {
                policy_ids.push(id.clone());
            }
        }
        
        Ok(policy_ids)
    }
    
    async fn assign_policy(&self, policy_id: &str, principal_id: &str, principal_type: PrincipalType) -> Result<()> {
        // Check if the policy exists
        let _ = self.get_policy(policy_id).await?;
        
        // Assignments in OPA are stored as data
        let url = self.assignments_url(principal_id, principal_type);
        let data = serde_json::json!({
            "policies": [policy_id]
        });
        
        let response = self.client.patch(&url)
            .json(&data)
            .send()
            .await
            .map_err(|e| {
                Box::new(GovernanceError::Other(format!("Failed to call OPA server: {}", e)))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;
        
        if !response.status().is_success() {
            return Err(Box::new(GovernanceError::Other(format!(
                "OPA server returned error: {}", response.status()
            ))));
        }
        
        Ok(())
    }
    
    async fn revoke_policy(&self, policy_id: &str, principal_id: &str, principal_type: PrincipalType) -> Result<()> {
        // Get current policies assigned to the principal
        let current_policies = self.list_principal_policies(principal_id, principal_type).await?;
        
        if !current_policies.contains(&policy_id.to_string()) {
            return Err(Box::new(GovernanceError::PolicyNotFound(format!(
                "Policy {} not assigned to principal", policy_id
            ))));
        }
        
        // Remove the policy from the list
        let updated_policies: Vec<String> = current_policies.into_iter()
            .filter(|p| p != policy_id)
            .collect();
        
        // Update the assignments
        let url = self.assignments_url(principal_id, principal_type);
        let data = serde_json::json!({
            "policies": updated_policies
        });
        
        let response = self.client.put(&url)
            .json(&data)
            .send()
            .await
            .map_err(|e| {
                Box::new(GovernanceError::Other(format!("Failed to call OPA server: {}", e)))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;
        
        if !response.status().is_success() {
            return Err(Box::new(GovernanceError::Other(format!(
                "OPA server returned error: {}", response.status()
            ))));
        }
        
        Ok(())
    }
    
    async fn list_principal_policies(&self, principal_id: &str, principal_type: PrincipalType) -> Result<Vec<String>> {
        let url = self.assignments_url(principal_id, principal_type);
        
        let response = self.client.get(&url)
            .send()
            .await
            .map_err(|e| {
                Box::new(GovernanceError::Other(format!("Failed to call OPA server: {}", e)))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;
        
        if response.status().is_client_error() {
            // Principal not found, return empty list
            return Ok(Vec::new());
        }
        
        if !response.status().is_success() {
            return Err(Box::new(GovernanceError::Other(format!(
                "OPA server returned error: {}", response.status()
            ))));
        }
        
        let result: serde_json::Value = response.json().await.map_err(|e| {
            Box::new(GovernanceError::Other(format!("Failed to parse OPA response: {}", e)))
                as Box<dyn std::error::Error + Send + Sync>
        })?;
        
        // Create empty vec outside to ensure it lives long enough if needed
        let empty_vec = Vec::new();
        let policies = result["result"]["policies"].as_array().unwrap_or(&empty_vec);
        
        let policy_list = policies.iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        
        Ok(policy_list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_check_permission() {
        // This test requires mockito to be running
        // In a real environment, we'd use mockito::mock and server_url
        // For now, we'll just construct the provider without making actual requests
        let config = serde_json::json!({
            "base_url": "http://localhost:8181",
        });
        
        let provider = OpaGovernanceProvider::new(config);
        // In a real test, we'd make assertions on the actual result
        // For now, we're just checking the provider can be constructed
        assert_eq!(provider.base_url, "http://localhost:8181");
    }
    
    #[tokio::test]
    async fn test_policy_url_formatting() {
        let config = serde_json::json!({
            "base_url": "http://localhost:8181",
        });
        
        let provider = OpaGovernanceProvider::new(config);
        assert_eq!(provider.policy_url("test-policy"), "http://localhost:8181/v1/policies/test-policy");
        assert_eq!(provider.data_url(), "http://localhost:8181/v1/data/malu/authz/allow");
    }
}
