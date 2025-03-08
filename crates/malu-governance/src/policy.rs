//! Policy definitions for the governance module

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::error::{GovernanceError, Result};

/// Effect of a policy statement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PolicyEffect {
    /// Allow the action
    Allow,
    
    /// Deny the action
    Deny,
}

/// A policy statement defining permissions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Statement {
    /// Effect of the statement (Allow or Deny)
    pub effect: PolicyEffect,
    
    /// Actions that this statement applies to
    pub action: HashSet<String>,
    
    /// Resources that this statement applies to
    pub resource: HashSet<String>,
    
    /// Principals (users, groups, roles) that this statement applies to
    #[serde(default)]
    pub principal: HashSet<String>,
    
    /// Optional conditions for the statement
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<serde_json::Value>,
}

/// A policy is a collection of statements
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Policy {
    /// Policy version (format: "YYYY-MM-DD")
    pub version: String,
    
    /// Policy statements
    pub statement: Vec<Statement>,
    
    /// Optional policy metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl Policy {
    /// Create a new policy with the given version
    pub fn new(version: &str) -> Self {
        Self {
            version: version.to_string(),
            statement: Vec::new(),
            metadata: None,
        }
    }
    
    /// Add a statement to the policy
    pub fn add_statement(&mut self, statement: Statement) {
        self.statement.push(statement);
    }
    
    /// Set metadata for the policy
    pub fn set_metadata(&mut self, metadata: serde_json::Value) {
        self.metadata = Some(metadata);
    }
    
    /// Evaluate if the policy allows a user to perform an action on a resource
    pub fn evaluate(&self, user_id: &str, action: &str, resource: &str) -> bool {
        let mut allowed = false;
        
        for statement in &self.statement {
            // Check if the statement applies to this user, action, and resource
            let user_match = statement.principal.iter().any(|p| match_principal(p, user_id));
            let action_match = statement.action.iter().any(|a| match_pattern(a, action));
            let resource_match = statement.resource.iter().any(|r| match_pattern(r, resource));
            
            if user_match && action_match && resource_match {
                // Apply the effect (Allow overrides previous Deny, and Deny overrides previous Allow)
                allowed = match statement.effect {
                    PolicyEffect::Allow => true,
                    PolicyEffect::Deny => false,
                };
            }
        }
        
        allowed
    }
    
    /// Convert the policy to a JSON string
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| GovernanceError::PolicyError(format!("Failed to serialize policy: {}", e)))
    }
    
    /// Parse a policy from a JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| GovernanceError::PolicyError(format!("Failed to parse policy: {}", e)))
    }
}

/// Builder for creating policy statements
pub struct StatementBuilder {
    effect: PolicyEffect,
    action: HashSet<String>,
    resource: HashSet<String>,
    principal: HashSet<String>,
    condition: Option<serde_json::Value>,
}

impl StatementBuilder {
    /// Create a new statement builder with the given effect
    pub fn new(effect: PolicyEffect) -> Self {
        Self {
            effect,
            action: HashSet::new(),
            resource: HashSet::new(),
            principal: HashSet::new(),
            condition: None,
        }
    }
    
    /// Add an action to the statement
    pub fn add_action(mut self, action: &str) -> Self {
        self.action.insert(action.to_string());
        self
    }
    
    /// Add multiple actions to the statement
    pub fn add_actions<I, S>(mut self, actions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for action in actions {
            self.action.insert(action.as_ref().to_string());
        }
        self
    }
    
    /// Add a resource to the statement
    pub fn add_resource(mut self, resource: &str) -> Self {
        self.resource.insert(resource.to_string());
        self
    }
    
    /// Add multiple resources to the statement
    pub fn add_resources<I, S>(mut self, resources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for resource in resources {
            self.resource.insert(resource.as_ref().to_string());
        }
        self
    }
    
    /// Add a principal to the statement
    pub fn add_principal(mut self, principal: &str) -> Self {
        self.principal.insert(principal.to_string());
        self
    }
    
    /// Add multiple principals to the statement
    pub fn add_principals<I, S>(mut self, principals: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for principal in principals {
            self.principal.insert(principal.as_ref().to_string());
        }
        self
    }
    
    /// Set a condition for the statement
    pub fn set_condition(mut self, condition: serde_json::Value) -> Self {
        self.condition = Some(condition);
        self
    }
    
    /// Build the statement
    pub fn build(self) -> Statement {
        Statement {
            effect: self.effect,
            action: self.action,
            resource: self.resource,
            principal: self.principal,
            condition: self.condition,
        }
    }
}

/// Builder for creating policies
pub struct PolicyBuilder {
    version: String,
    statements: Vec<Statement>,
    metadata: Option<serde_json::Value>,
}

impl PolicyBuilder {
    /// Create a new policy builder with the default version
    pub fn new() -> Self {
        Self {
            version: "2021-11-01".to_string(),
            statements: Vec::new(),
            metadata: None,
        }
    }
    
    /// Set the policy version
    pub fn version(mut self, version: &str) -> Self {
        self.version = version.to_string();
        self
    }
    
    /// Add a statement to the policy
    pub fn add_statement(mut self, statement: Statement) -> Self {
        self.statements.push(statement);
        self
    }
    
    /// Set metadata for the policy
    pub fn set_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
    
    /// Build the policy
    pub fn build(self) -> Policy {
        Policy {
            version: self.version,
            statement: self.statements,
            metadata: self.metadata,
        }
    }
}

impl Default for PolicyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Match a pattern against a string (with * as wildcard)
fn match_pattern(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    
    let pattern_parts: Vec<&str> = pattern.split('*').collect();
    if pattern_parts.len() == 1 {
        // No wildcard, exact match
        return pattern == value;
    }
    
    // Handle wildcards
    let mut value_idx = 0;
    for (i, part) in pattern_parts.iter().enumerate() {
        if part.is_empty() {
            // Empty part (e.g., * at beginning or multiple *)
            continue;
        }
        
        match value[value_idx..].find(part) {
            Some(pos) => {
                value_idx += pos + part.len();
                if i == 0 && pos != 0 {
                    // If first part doesn't match at beginning and pattern doesn't start with *
                    if !pattern.starts_with('*') {
                        return false;
                    }
                }
            }
            None => return false,
        }
    }
    
    // If last part doesn't end with *, it must match to the end
    if !pattern.ends_with('*') && !pattern_parts.last().unwrap().is_empty() {
        return value.ends_with(pattern_parts.last().unwrap());
    }
    
    true
}

/// Match a principal pattern against a user ID
/// Format: "user:username", "group:groupname", "role:rolename"
fn match_principal(pattern: &str, user_id: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    
    if !pattern.contains(':') {
        // Simple pattern without type, treat as user ID
        return match_pattern(pattern, user_id);
    }
    
    let parts: Vec<&str> = pattern.splitn(2, ':').collect();
    if parts.len() != 2 {
        return false;
    }
    
    let principal_type = parts[0];
    let principal_id = parts[1];
    
    if principal_type == "user" {
        match_pattern(principal_id, user_id)
    } else {
        // For groups and roles, we would need additional context
        // that we don't have here, so we'll always return false
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pattern_matching() {
        assert!(match_pattern("*", "anything"));
        assert!(match_pattern("foo", "foo"));
        assert!(!match_pattern("foo", "bar"));
        assert!(match_pattern("foo*", "foobar"));
        assert!(match_pattern("*bar", "foobar"));
        assert!(match_pattern("foo*bar", "fooXYZbar"));
        assert!(!match_pattern("foo*bar", "foobaz"));
    }
    
    #[test]
    fn test_policy_evaluation() {
        let policy = PolicyBuilder::new()
            .add_statement(
                StatementBuilder::new(PolicyEffect::Allow)
                    .add_action("read")
                    .add_resource("document:*")
                    .add_principal("user:alice")
                    .build()
            )
            .add_statement(
                StatementBuilder::new(PolicyEffect::Deny)
                    .add_action("write")
                    .add_resource("document:secret")
                    .add_principal("*")
                    .build()
            )
            .build();
        
        // Alice can read any document
        assert!(policy.evaluate("alice", "read", "document:123"));
        
        // Bob cannot read any document (not in allowed principals)
        assert!(!policy.evaluate("bob", "read", "document:123"));
        
        // Nobody can write to secret document
        assert!(!policy.evaluate("alice", "write", "document:secret"));
    }
    
    #[test]
    fn test_policy_serialization() {
        let policy = PolicyBuilder::new()
            .add_statement(
                StatementBuilder::new(PolicyEffect::Allow)
                    .add_action("read")
                    .add_resource("document:*")
                    .add_principal("user:alice")
                    .build()
            )
            .build();
        
        let json = policy.to_json().unwrap();
        let parsed = Policy::from_json(&json).unwrap();
        
        assert_eq!(policy, parsed);
    }
}
