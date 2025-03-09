use lazy_static::lazy_static;
use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use std::time::Instant;

// Define global metrics collector
lazy_static! {
    static ref PROMETHEUS: PrometheusHandle = {
        const EXPONENTIAL_SECONDS: &[f64] = &[
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ];

        PrometheusBuilder::new()
            .set_buckets_for_metric(
                Matcher::Full("api_request_duration_seconds".to_string()),
                EXPONENTIAL_SECONDS,
            )
            .unwrap()
            .install_recorder()
            .unwrap()
    };
}

/// Helper for timing the duration of an operation
///
/// # Usage
/// ```
/// // Method 1: Using underscore prefix to prevent unused variable warning
/// let _timer = metrics::Timer::new("operation_name");
/// // ... your code to time ...
/// // Timer will automatically record when it goes out of scope
///
/// // Method 2: Using the start_timer function which doesn't require a variable
/// metrics::Timer::start_timer("operation_name");
/// // ... your code to time ...
/// ```
pub struct Timer {
    name: String,
    start: Instant,
}

impl Timer {
    /// Creates a new timer that will record metrics when it goes out of scope
    /// Note: Store this in a variable prefixed with underscore to avoid compiler warnings
    /// Example: `let _timer = metrics::Timer::new("operation_name");`
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            start: Instant::now(),
        }
    }
    
    /// Creates and immediately drops a timer, useful when you don't need to keep it in a variable
    /// This helps prevent "unused variable" compiler warnings
    pub fn start_timer(name: &str) {
        let _ = Self::new(name);
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        histogram!("api_request_duration_seconds", duration.as_secs_f64(), "endpoint" => self.name.clone());
    }
}

/// Gather and return Prometheus metrics
pub fn gather_metrics() -> String {
    PROMETHEUS.render()
}

/// Record request count for a specific endpoint
pub fn record_request(endpoint: &str, status_code: u16) {
    counter!("api_requests_total", 1, "endpoint" => endpoint.to_string(), "status" => status_code.to_string());
}

/// Record storage operation metrics
pub fn record_storage_operation(operation: &str, status: &str) {
    counter!("storage_operations_total", 1, "operation" => operation.to_string(), "status" => status.to_string());
}

/// Record current memory usage
pub fn record_memory_usage(usage_mb: f64) {
    gauge!("memory_usage_mb", usage_mb);
}

/// Record secret count
pub fn record_secret_count(count: usize) {
    gauge!("secrets_total", count as f64);
}

/// Record Kafka events
pub fn record_kafka_event(topic: &str, status: &str) {
    counter!("kafka_events_total", 1, "topic" => topic.to_string(), "status" => status.to_string());
}

/// Track success rate for operations
pub fn record_operation_result(operation: &str, success: bool) {
    let status = if success { "success" } else { "failure" };
    counter!("operation_results_total", 1, "operation" => operation.to_string(), "status" => status.to_string());
}

/// Middleware for tracking API request metrics
pub struct MetricsMiddleware {
    pub endpoint: String,
}

impl MetricsMiddleware {
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
        }
    }
}

/// Utility function to initialize metrics system
pub fn init_metrics() {
    // We'll initialize some baseline metrics
    gauge!("service_info", 1.0, 
        "version" => env!("CARGO_PKG_VERSION").to_string()
    );
    
    // Initialize counters with 0 for common API endpoints to ensure they appear in metrics output
    counter!("api_requests_total", 0, "endpoint" => "health", "status" => "200");
    counter!("api_requests_total", 0, "endpoint" => "readiness", "status" => "200");
    counter!("api_requests_total", 0, "endpoint" => "create_secret", "status" => "201");
    counter!("api_requests_total", 0, "endpoint" => "get_secret", "status" => "200");
    counter!("api_requests_total", 0, "endpoint" => "delete_secret", "status" => "204");
    counter!("api_requests_total", 0, "endpoint" => "list_secrets", "status" => "200");
    
    tracing::info!("Metrics system initialized");
}
