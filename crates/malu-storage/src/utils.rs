//! Utility functions for storage operations

use std::path::{Path, PathBuf, Component};
use crate::error::{Result, StorageError};

/// Normalizes and validates a storage path to prevent path traversal attacks
pub fn normalize_path(base_path: &Path, relative_path: &str) -> Result<PathBuf> {
    // Normalize the path to prevent path traversal attacks
    let path = Path::new(relative_path);
    
    // Check for suspicious components
    let has_suspicious_components = path.components().any(|component| {
        matches!(component, Component::ParentDir | Component::RootDir)
    });
    
    if has_suspicious_components {
        return Err(StorageError::Path(format!(
            "Path contains parent directory or root references: {}",
            relative_path
        )));
    }
    
    // Create the full path
    let mut full_path = base_path.to_path_buf();
    for component in path.components() {
        if let Component::Normal(name) = component {
            full_path.push(name)
            // We've already checked for suspicious components
        }
    }
    
    Ok(full_path)
}

/// Properly handles file_name from OsString
#[allow(dead_code)]
pub fn safe_file_name(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|os_str| os_str.to_str())
        .map(|s| s.to_string())
        .ok_or_else(|| StorageError::Path(format!("Invalid file name in path: {:?}", path)))
}

/// Ensures a directory exists, creating it if necessary
pub fn ensure_dir_exists(dir_path: &Path) -> Result<()> {
    if !dir_path.exists() {
        std::fs::create_dir_all(dir_path).map_err(|e| {
            StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to create directory {}: {}", dir_path.display(), e),
            ))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    
    #[test]
    fn test_normalize_path() {
        let base = Path::new("/var/lib/malu");
        
        // Valid paths
        assert_eq!(
            normalize_path(base, "secrets/key1").unwrap(),
            Path::new("/var/lib/malu/secrets/key1")
        );
        
        // Paths with parent references should fail
        assert!(normalize_path(base, "../secrets/key1").is_err());
        assert!(normalize_path(base, "secrets/../key1").is_err());
        
        // Paths with root references should fail
        assert!(normalize_path(base, "/secrets/key1").is_err());
    }
    
    #[test]
    fn test_safe_file_name() {
        // Valid file name
        assert_eq!(
            safe_file_name(Path::new("/path/to/file.txt")).unwrap(),
            "file.txt"
        );
        
        // Directory without a file name should fail
        assert!(safe_file_name(Path::new("/path/to/")).is_err());
    }
}
