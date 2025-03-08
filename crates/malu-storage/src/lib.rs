//! Storage component for the Malu system
//! 
//! This crate provides implementations of the StorageEngine interface
//! for various storage backends:
//! 
//! - FileSystemStorage: Store secrets in the local file system
//! - MemoryStorage: In-memory storage for testing
//! - S3Storage: Store secrets in Amazon S3 (optional)
//! - PostgresStorage: Store secrets in PostgreSQL database (optional)
//! - ValkeyStorage: Store secrets in Valkey/Redis (optional)
//! - LevelDBStorage: Store secrets in LevelDB (optional)
//! - Repository: Higher-level API built on top of storage engines

mod error;
#[cfg(feature = "fs-storage")]
mod file_system;
#[cfg(feature = "memory-storage")]
mod memory;
#[cfg(feature = "s3-storage")]
mod s3;
#[cfg(feature = "postgres-storage")]
mod postgres;
#[cfg(feature = "valkey-storage")]
mod valkey;
#[cfg(feature = "leveldb-storage")]
mod leveldb;
mod repository;
mod utils;

pub use error::{StorageError, Result};
#[cfg(feature = "fs-storage")]
pub use file_system::FileSystemStorage;
#[cfg(feature = "memory-storage")]
pub use memory::MemoryStorage;
#[cfg(feature = "s3-storage")]
pub use s3::S3Storage;
#[cfg(feature = "postgres-storage")]
pub use postgres::PostgresStorage;
#[cfg(feature = "valkey-storage")]
pub use valkey::ValkeyStorage;
#[cfg(feature = "leveldb-storage")]
pub use leveldb::LevelDBStorage;
pub use repository::Repository;

/// Creates a storage engine based on the provided configuration
pub fn create_storage_engine(engine_type: &str, connection_string: &str) -> Box<dyn malu_interfaces::StorageEngine> {
    match engine_type {
        #[cfg(feature = "memory-storage")]
        "memory" => Box::new(MemoryStorage::new()),
        #[cfg(feature = "fs-storage")]
        "filesystem" => Box::new(FileSystemStorage::new(connection_string)),
        #[cfg(feature = "s3-storage")]
        "s3" => Box::new(S3Storage::new(connection_string)),
        #[cfg(feature = "postgres-storage")]
        "postgres" => Box::new(PostgresStorage::new(connection_string)),
        #[cfg(feature = "valkey-storage")]
        "valkey" | "redis" => Box::new(ValkeyStorage::new(connection_string)),
        #[cfg(feature = "leveldb-storage")]
        "leveldb" => Box::new(LevelDBStorage::new(connection_string)),
        _ => panic!("Unsupported storage engine type: {}", engine_type),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
