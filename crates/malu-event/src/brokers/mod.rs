// Message broker implementations for the Malu event system

// Re-export broker modules
#[cfg(feature = "kafka")]
pub mod kafka;

#[cfg(feature = "rabbitmq")]
pub mod rabbitmq;

#[cfg(feature = "in-memory")]
pub mod memory;
