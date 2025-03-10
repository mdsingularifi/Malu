pub mod secret_service;
pub mod rotation_service;
pub mod secret_service_dynamic;
pub mod rotation;

// Re-export SecretService for easier access
pub use secret_service::SecretService;

/// Application state that contains shared components
#[derive(Clone)]
pub struct AppState {
    /// Secret service instance
    pub secret_service: SecretService,
}

impl AppState {
    /// Create a new AppState with the provided SecretService
    pub fn new(secret_service: SecretService) -> Self {
        Self { secret_service }
    }
}
