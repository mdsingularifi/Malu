// Re-export all modules to make them accessible to tests
pub mod api;
pub mod service;
pub mod models;
pub mod core;
pub mod config;
pub mod events;
pub mod metrics;

use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

// This crate is a library that's also built as a binary.
// The binary entry point is in main.rs, while this file
// serves as the library entry point for tests and other crates
// that might want to use our functionality.

/// Secret-Storage-Service library
/// 
/// This library provides a secure way to store, retrieve, and manage secrets
/// with features such as automatic rotation, namespacing, and access control.
///
/// The primary interface is through the SecretService struct in the service module,
/// which provides methods for interacting with secrets.
pub struct SecretStorageService;

impl SecretStorageService {
    /// Get the version of the Secret-Storage-Service
    pub fn version() -> &'static str {
        env!("CARGO_PKG_VERSION")
    }
}

/// Initialize logging for the application
pub fn init_logging(log_level: &str) {
    // Configure the global tracing subscriber
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(log_level)))
        .with(fmt::layer()
            .with_span_events(fmt::format::FmtSpan::CLOSE)
            .with_target(true)
            .compact())
        .init();
}
