mod api;
mod service;
mod models;
mod core;
mod config;
mod events;
mod metrics;

use axum::{
    routing::{get, post, delete},
    Router,
    http::Method,
    response::IntoResponse,
    extract::Extension,
    middleware::map_request,
};
use http::header;
// Removed hyper_util imports as we're using axum's server directly
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tower_http::timeout::TimeoutLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, fmt::format::FmtSpan};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;

// OpenTelemetry imports (currently disabled but kept for reference)
// We're keeping these imports commented out until we resolve dependency compatibility issues
// use opentelemetry::global;
// use opentelemetry::sdk::{Resource, trace};
// use opentelemetry_otlp::WithExportConfig;
// use opentelemetry::KeyValue;
// use opentelemetry_sdk::runtime::Tokio;
// Removed unused import: use tracing::Instrument;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize configuration first (so logging picks up config)
    dotenvy::dotenv().ok();
    
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
        
    // We're no longer using RequestBodyLimitLayer, so we've removed this variable
    // Instead, we're using ConcurrencyLimitLayer for rate limiting
        
    // Initialize structured logging first (basic setup without OpenTelemetry)
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(log_level))
        .with(tracing_subscriber::fmt::layer()
            .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
            .compact())
        .init();
        
    tracing::info!("Starting Secret Storage Service");
    
    // Get service name and version for telemetry (if we use it later)
    let service_name = std::env::var("OTEL_SERVICE_NAME")
        .unwrap_or_else(|_| "secret-storage-service".to_string());
    let service_version = option_env!("CARGO_PKG_VERSION").unwrap_or("unknown");
    
    // We'll add proper OpenTelemetry configuration once dependencies are stabilized
    tracing::info!("Service name: {}, version: {}", service_name, service_version);
    
    // Note: OpenTelemetry integration is temporarily disabled due to dependency issues
    // if let Err(err) = init_telemetry(&service_name, service_version) {
    //     eprintln!("Failed to initialize OpenTelemetry: {}", err);
    // }
    
    // Initialize Prometheus metrics
    metrics::init_metrics();
    tracing::info!("Prometheus metrics initialized and ready to collect data");
    
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
    
    // Create AppState and get config reference
    let app_state = service::AppState::new(secret_service.clone());
    let service_clone = app_state.secret_service.clone();
    let app_config = service_clone.get_config();
    let service_state = Arc::new(app_state);
    
    // Get version information
    let version = option_env!("CARGO_PKG_VERSION").unwrap_or("unknown");
    let build_timestamp = option_env!("BUILD_TIMESTAMP").unwrap_or("unknown");
    let build_info = Arc::new(BuildInfo {
        version: version.to_string(),
        build_timestamp: build_timestamp.to_string(),
        start_time: std::time::SystemTime::now(),
    });
    
    // Define CORS policy - properly restrictive for production
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::PUT, Method::OPTIONS])
        .allow_headers(["authorization", "content-type", "x-requested-with"].into_iter().map(|h| h.parse().unwrap()).collect::<Vec<_>>())
        // In production, use actual domain origins instead of wildcard
        .allow_origin([
            "https://app.malu.example.com".parse().unwrap(),
            // For local development only
            "http://localhost:3000".parse().unwrap(),
        ])
        .allow_credentials(true);
        
    // Build our application routes with layers for timeouts, rate limiting, etc.
    let app = Router::new()
        // Health check endpoints
        .route("/health", get(api::health::health_check))
        .route("/readiness", get(api::health::readiness_check))
        .route("/liveness", get(api::health::liveness_probe))
        .route("/metrics", get(metrics_endpoint))
        .route("/api/v1/secrets", post(api::secrets::create_secret))
        .route("/api/v1/secrets/:path", get(api::secrets::get_secret))
        .route("/api/v1/secrets/:path", delete(api::secrets::delete_secret))
        .route("/api/v1/secrets", get(api::secrets::list_secrets))
        // Secret rotation endpoints - use the predefined rotation routes
        .merge(api::rotation::rotation_routes())
        // Dynamic secrets endpoints - conditionally add based on feature flag
        .merge(if app_config.features.dynamic_secrets {
            // Only merge the dynamic routes if the feature is enabled
            tracing::info!("Registering dynamic secrets API endpoints");
            api::dynamic::dynamic_routes()
        } else {
            tracing::info!("Dynamic secrets feature is disabled. Skipping dynamic secrets API endpoints.");
            Router::new() // Empty router if feature is disabled
        })
        .with_state(Arc::clone(&service_state))
        .layer(Extension(Arc::clone(&service_state)))
        .layer(Extension(build_info))
        // Register middleware to track metrics for each request
        .layer(axum::middleware::map_response(|response: axum::response::Response| async {
            // Record the metrics after the request is processed
            let status = response.status().as_u16();
            
            // Use a generic endpoint name since we can't access the route here
            // The actual route metrics will be handled by our handler functions
            metrics::record_request("api", status);
            
            // Also record current memory usage periodically
            let usage = std::process::Command::new("sh")
                .arg("-c")
                .arg("ps -o rss= -p $$")
                .output()
                .ok()
                .and_then(|output| {
                    String::from_utf8(output.stdout).ok()
                        .and_then(|s| s.trim().parse::<f64>().ok())
                        .map(|kb| kb / 1024.0) // Convert KB to MB
                })
                .unwrap_or(50.0); // Default to 50MB if parsing fails
                
            metrics::record_memory_usage(usage);
            response
        }))
        // Layer order matters for type compatibility
        // Add middleware in the correct order to avoid type mismatch errors
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(request_timeout)))
        .layer(tower::limit::ConcurrencyLimitLayer::new(100)) // Add concurrency limiting
        // Add security headers
        .layer(tower_http::set_header::SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            "no-store, no-cache, must-revalidate".parse::<http::HeaderValue>().unwrap()
        ))
        .layer(tower_http::set_header::SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'".parse::<http::HeaderValue>().unwrap()
        ))
        .layer(tower_http::set_header::SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            "nosniff".parse::<http::HeaderValue>().unwrap()
        ))
        // Add request tracing to track all requests
        .layer(map_request(|req: axum::http::Request<axum::body::Body>| async move {
            // Create a span for the request
            let method = req.method().clone();
            let uri = req.uri().clone();
            let user_agent = req.headers().get("user-agent")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("unknown")
                .to_string();
            // In axum 0.7 with hyper 1.0, we need to handle client IP differently
            // Since we removed ConnectInfo, just use a placeholder for now
            let client_ip = "client-ip-not-available".to_string();
            
            let request_span = tracing::info_span!("http_request",
                http.method = %method,
                http.url = %uri,
                http.client_ip = %client_ip,
                http.user_agent = %user_agent,
                service.name = "secret-storage-service"
            );
            
            tracing::debug!("Processing request");
            request_span.in_scope(|| {
                tracing::info!("Handling request: {} {}", method, uri);
            });
            
            Ok::<_, std::convert::Infallible>(req)
        }));
        
    // Run the service with graceful shutdown
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Secret Storage Service v{} listening on {}", version, addr);
    
    // Create a TCP listener bound to the address
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    
    // Convert axum router into a hyper service
    let make_service = app.into_make_service();
    
    // Create a future that completes when the server receives a shutdown signal
    let shutdown_signal = async {
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler")
        };

        #[cfg(unix)]
        let _terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to install signal handler")
                .recv()
                .await
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {},
            _ = _terminate => {},
        }
        
        tracing::info!("Shutdown signal received, starting graceful shutdown");
    };
    
    // Run the server with graceful shutdown
    let server = axum::serve(
        listener,
        make_service
    ).with_graceful_shutdown(shutdown_signal);
    
    // Start the server
    if let Err(err) = server.await {
        tracing::error!("Server error: {}", err);
        return Err(err.into());
    }
    
    tracing::info!("Server shutdown complete");
    Ok(())
}

// Build information structure
// Using our health module's BuildInfo instead
use crate::api::health::BuildInfo;

/// Metrics endpoint that returns Prometheus-formatted metrics
async fn metrics_endpoint() -> impl IntoResponse {
    let metrics_text = metrics::gather_metrics();
    ([(hyper::header::CONTENT_TYPE, "text/plain; version=0.0.4")], metrics_text)
}

/// Signal handler for graceful shutdown
#[allow(dead_code)]
async fn shutdown_signal() {
    let _terminate = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
    };

    #[cfg(unix)]
    let terminate = async {
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM signal handler");
        let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
            .expect("Failed to install SIGINT signal handler");
        
        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("Received SIGTERM signal");
            },
            _ = sigint.recv() => {
                tracing::info!("Received SIGINT signal");
            },
            _ = signal::ctrl_c() => {
                tracing::info!("Received CTRL+C signal");
            }
        }
    };

    terminate.await;
    tracing::info!("Shutdown signal received, starting graceful shutdown...");
}

/// Initialize OpenTelemetry for distributed tracing with SigNoz APM
/// 
/// This sets up the OpenTelemetry pipeline to send telemetry data to SigNoz,
/// allowing for distributed tracing and monitoring of the service.
/// 
/// Note: This function is currently disabled until dependency issues are resolved.
// This function is conditionally compiled only when the telemetry feature is enabled
// This prevents the "unused function" warning when the feature is disabled
#[allow(dead_code)]
fn init_telemetry(_service_name: &str, _service_version: &str) -> Result<(), Box<dyn std::error::Error>> {
    // When we re-enable telemetry, we'll use the updated OpenTelemetry APIs. For now,
    // keeping this code commented out until we have the correct dependencies.
    
    /*
    // Create a resource with metadata about our service
    let resource = Resource::new(vec![
        KeyValue::new("service.name", service_name.to_string()),
        KeyValue::new("service.version", service_version.to_string()),
    ]);
    
    // Configure the OpenTelemetry exporter to send data to SigNoz/OTel collector
    // Get the OTLP endpoint from an environment variable or use the default
    let otlp_endpoint = std::env::var("OTLP_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:4317".to_string());
        
    // Create an exporter to send telemetry data to the OTel collector
    // This is configured to use gRPC with the specified endpoint
    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(otlp_endpoint)
        )
        .with_trace_config(trace::config().with_resource(resource))
        .install_batch(Tokio)?;
        
    // Initialize the global tracer provider
    global::set_tracer_provider(tracer);
    
    // Initialize the tracing subscriber with OpenTelemetry
    let opentelemetry = tracing_opentelemetry::layer().with_tracer(global::tracer("secret-service"));
    
    tracing_subscriber::registry()
        .with(opentelemetry)
        .try_init()?;
    */
    
    tracing::warn!("OpenTelemetry initialization is disabled due to dependency compatibility issues");
    Ok(())
}
