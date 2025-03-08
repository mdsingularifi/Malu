//! Provider implementations for the governance module

pub mod file;
pub mod memory;
pub mod opa;

// Re-export providers for easier access
pub use file::FileGovernanceProvider;
pub use memory::MemoryGovernanceProvider;
pub use opa::OpaGovernanceProvider;
