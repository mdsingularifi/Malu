mod api;
mod service;
mod models;
mod core;
mod config;
mod events;

use axum::{
    routing::{get, post, delete},
    Router,
    http::{StatusCode, Method},
    response::IntoResponse,
    Json,
    extract::Extension,
};
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, fmt::format::FmtSpan};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize configuration first (so logging picks up config)
    dotenv::dotenv().ok();
    
    // Get configuration from environment
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()
        .expect("PORT must be a valid port number");
        
    let log_level = std::env::var("LOG_LEVEL")
        .unwrap_or_else(|_| "info,tower_http=debug".to_string());
        
    let request_timeout = std::env::var("REQUEST_TIMEOUT_SECS")
        .unwrap_or_else(|_| "30".to_string())
        .parse::<u64>()
        .expect("REQUEST_TIMEOUT_SECS must be a valid number");
        
    let request_body_limit = std::env::var("REQUEST_BODY_LIMIT_BYTES")
        .unwrap_or_else(|_| "10485760".to_string()) // 10MB default
        .parse::<usize>()
        .expect("REQUEST_BODY_LIMIT_BYTES must be a valid number");
        
    // Initialize structured logging with better format
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(log_level))
        .with(tracing_subscriber::fmt::layer()
            .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
            .compact())
        .init();
        
    tracing::info!("Starting Secret Storage Service");
    
    // Initialize the secret service
    let start_time = std::time::Instant::now();
    let (secret_service, _consumer) = match service::secret_service::init_secret_service().await {
        Ok((service, consumer)) => {
            tracing::info!("Secret service initialized successfully in {:?}", start_time.elapsed());
            (service, consumer)
        },
        Err(err) => {
            tracing::error!("Failed to initialize secret service: {}", err);
            return Err(err.into());
        }
    };
    let service_state = Arc::new(secret_service);
    
    // Get version information
    let version = option_env!("CARGO_PKG_VERSION").unwrap_or("unknown");
    let build_timestamp = option_env!("BUILD_TIMESTAMP").unwrap_or("unknown");
    let build_info = Arc::new(BuildInfo {
        version: version.to_string(),
        build_timestamp: build_timestamp.to_string(),
    });
    
    // Define CORS policy - more restrictive for production
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::PUT, Method::OPTIONS])
        .allow_headers(Any)
        .allow_origin(Any); // In production, you would specify actual allowed origins
        
    // Build our application routes with layers for timeouts, rate limiting, etc.
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/metrics", get(metrics_endpoint))
        .route("/api/v1/secrets", post(api::secrets::create_secret))
        .route("/api/v1/secrets/:path", get(api::secrets::get_secret))
        .route("/api/v1/secrets/:path", delete(api::secrets::delete_secret))
        .route("/api/v1/secrets", get(api::secrets::list_secrets))
        .with_state(service_state)
        .layer(Extension(build_info))
        .layer(TimeoutLayer::new(Duration::from_secs(request_timeout)))
        .layer(RequestBodyLimitLayer::new(request_body_limit))
        .layer(TraceLayer::new_for_http())
        .layer(cors);
        
    // Run the service with graceful shutdown
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Secret Storage Service v{} listening on {}", version, addr);
    
    let server = axum::Server::bind(&addr)
        .serve(app.into_make_service());
        
    // Add graceful shutdown
    let graceful = server.with_graceful_shutdown(shutdown_signal());
    
    // Start the server
    if let Err(err) = graceful.await {
        tracing::error!("Server error: {}", err);
        return Err(err.into());
    }
    
    tracing::info!("Server shutdown complete");
    Ok(())
}

// Build information structure
#[derive(Clone)]
struct BuildInfo {
    version: String,
    build_timestamp: String,
}

/// Enhanced health check with more detailed information
async fn health_check(build_info: axum::extract::Extension<Arc<BuildInfo>>) -> impl IntoResponse {
    let build_info = build_info.0;
    let uptime = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs();
    
    (StatusCode::OK, Json(serde_json::json!({
        "status": "UP",
        "version": build_info.version,
        "buildTimestamp": build_info.build_timestamp,
        "uptime": uptime,
        "memory": {
            // Basic memory info - in production you might use a crate for more detailed metrics
            "rss": "N/A" // In a real implementation, you would provide actual memory stats
        }
    })))
}

/// Metrics endpoint (stub for now - would integrate with prometheus in production)
async fn metrics_endpoint() -> impl IntoResponse {
    (StatusCode::OK, "# HELP api_requests_total The total number of API requests\n# TYPE api_requests_total counter\napi_requests_total 0\n")
}

/// Signal handler for graceful shutdown
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received, starting graceful shutdown");
}
