//! Kafka consumer implementation for the Secret Storage Service
//!
//! This module provides the Kafka consumer functionality for processing
//! events from Kafka topics.

use std::sync::Arc;
use std::time::Duration;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, StreamConsumer, CommitMode};
use rdkafka::message::Message;
use tokio::spawn;
use tokio::sync::Mutex;
use futures::stream::StreamExt;

use crate::config::AppConfig;
use crate::core::error::{Result, ServiceError};
use crate::metrics;
use super::handler::EventHandler;
use super::models::{SecretEvent, AuditEvent};

/// Kafka consumer for receiving events
#[derive(Clone)]
pub struct KafkaConsumer {
    /// Configuration for the Kafka consumer
    config: AppConfig,
}

impl KafkaConsumer {
    /// Create a new Kafka consumer from configuration
    pub async fn new(config: &AppConfig) -> Result<Self> {
        tracing::info!("Initializing Kafka consumer with bootstrap servers: {}", config.kafka_bootstrap_servers);
        
        // Record Kafka consumer initialization in metrics
        metrics::record_operation_result("kafka_consumer_init", true);
        
        Ok(Self {
            config: config.clone(),
        })
    }
    
    /// Start consuming events from Kafka topics
    pub async fn start(&self, handler: EventHandler) -> Result<()> {
        // Clone these values for logging later
        let secret_topic_log = self.config.kafka_topic_secrets.clone();
        let audit_topic_log = self.config.kafka_topic_audit.clone();
        
        // Clone for use in async blocks
        let secret_topic = self.config.kafka_topic_secrets.clone();
        let audit_topic = self.config.kafka_topic_audit.clone();
        let config1 = self.config.clone(); // Config for first async block
        let config2 = self.config.clone(); // Config for second async block
        
        // Create a handler arc for thread safety
        let handler = Arc::new(Mutex::new(handler));
        
        // Start the secret events consumer in a separate task
        let secret_handler = handler.clone();
        spawn(async move {
            if let Err(e) = Self::consume_topic(&config1, &secret_topic, secret_handler, Self::process_secret_event).await {
                tracing::error!("Error in secret events consumer: {}", e);
                metrics::record_kafka_event("secret_events_consumer", "error");
                metrics::record_operation_result("kafka_consumer", false);
            }
        });
        
        // Start the audit events consumer in a separate task
        let audit_handler = handler.clone();
        spawn(async move {
            if let Err(e) = Self::consume_topic(&config2, &audit_topic, audit_handler, Self::process_audit_event).await {
                tracing::error!("Error in audit events consumer: {}", e);
                metrics::record_kafka_event("audit_events_consumer", "error");
                metrics::record_operation_result("kafka_consumer", false);
            }
        });
        
        tracing::info!("Kafka consumers started successfully for topics: {}, {}", secret_topic_log, audit_topic_log);
        Ok(())
    }
    
    /// Consume events from a specific topic
    async fn consume_topic<F, T>(
        config: &AppConfig,
        topic: &str,
        handler: Arc<Mutex<EventHandler>>,
        process_fn: F
    ) -> Result<()>
    where
        F: Fn(&[u8]) -> Result<T> + Send + 'static,
        T: Send + 'static + super::handler::EventPayload,
    {
        // Use outer loop for reconnection logic
        loop {
            let consumer: StreamConsumer = match Self::create_consumer(config, topic) {
                Ok(c) => {
                    // Record successful consumer creation
                    metrics::record_kafka_event(topic, "consumer_connected");
                    metrics::record_operation_result("kafka_consumer_connection", true);
                    c
                },
                Err(e) => {
                    tracing::error!("Failed to create Kafka consumer: {}", e);
                    // Record failed consumer creation in metrics
                    metrics::record_kafka_event(topic, "consumer_connection_failed");
                    metrics::record_operation_result("kafka_consumer_connection", false);
                    
                    // Get reconnection delay from environment variable or use default
                    let reconnect_delay_secs = std::env::var("KAFKA_CONSUMER_RECONNECT_DELAY_SECS")
                        .ok()
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(5);
                        
                    tracing::info!("Waiting {}s before attempting to reconnect to Kafka...", reconnect_delay_secs);
                    tokio::time::sleep(Duration::from_secs(reconnect_delay_secs)).await;
                    continue;
                }
            };
            
            tracing::info!("Starting to consume from topic: {}", topic);
            
            let message_stream = consumer.stream();
            tokio::pin!(message_stream);
            
            // Inner loop for processing messages
            loop {
                match message_stream.next().await {
                    Some(message_result) => {
                        // Start a timer for message processing
                        let _timer = metrics::Timer::new(format!("kafka_message_processing_{}", topic).as_str());
                        
                        match message_result {
                            Ok(message) => {
                                // Record message received in metrics
                                metrics::record_kafka_event(topic, "message_received");
                                if let Some(payload) = message.payload() {
                                    match process_fn(payload) {
                                        Ok(event) => {
                                            // Lock the handler and process the event
                                            let mut guard = handler.lock().await;
                                            let result = guard.handle_event(event).await;
                                            if let Err(e) = result {
                                                tracing::error!("Error handling event: {}", e);
                                                metrics::record_kafka_event(topic, "event_handling_error");
                                                metrics::record_operation_result("kafka_event_handling", false);
                                            } else {
                                                metrics::record_kafka_event(topic, "event_handling_success");
                                                metrics::record_operation_result("kafka_event_handling", true);
                                            }
                                        },
                                        Err(e) => {
                                            tracing::error!("Error processing event: {}", e);
                                            metrics::record_kafka_event(topic, "event_processing_error");
                                            metrics::record_operation_result("kafka_event_processing", false);
                                        }
                                    }
                                } else {
                                    tracing::warn!("Received message with empty payload");
                                    metrics::record_kafka_event(topic, "empty_payload");
                                }
                                
                                // Commit the message
                                let commit_result = consumer.commit_message(&message, CommitMode::Async);
                                if let Err(e) = commit_result {
                                    tracing::error!("Error committing message: {}", e);
                                    metrics::record_kafka_event(topic, "commit_error");
                                    metrics::record_operation_result("kafka_message_commit", false);
                                } else {
                                    metrics::record_kafka_event(topic, "commit_success");
                                    metrics::record_operation_result("kafka_message_commit", true);
                                }
                            },
                            Err(e) => {
                                tracing::error!("Error receiving Kafka message: {}", e);
                                metrics::record_kafka_event(topic, "message_receive_error");
                                metrics::record_operation_result("kafka_message_receive", false);
                                // Break inner loop to reconnect
                                break;
                            }
                        }
                    },
                    None => {
                        tracing::info!("Kafka consumer stream ended, reconnecting...");
                        metrics::record_kafka_event(topic, "stream_ended");
                        // Break inner loop to reconnect
                        break;
                    }
                }
            }
            
            // If we reach here, the stream has ended or there was an error
            // Wait before attempting to reconnect
            let stream_reconnect_delay_secs = std::env::var("KAFKA_STREAM_RECONNECT_DELAY_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(1);
                
            tracing::info!("Waiting {}s before attempting to reconnect to Kafka...", stream_reconnect_delay_secs);
            tokio::time::sleep(Duration::from_secs(stream_reconnect_delay_secs)).await;
        }
        
        // This code is unreachable because of the infinite loop above,
        // but we need to satisfy the type signature
        #[allow(unreachable_code)]
        Ok(())
    }
    
    /// Create a Kafka consumer for a topic
    fn create_consumer(config: &AppConfig, topic: &str) -> Result<StreamConsumer> {
        use std::env;
        
        // Get consumer configuration from environment variables
        let auto_commit = env::var("KAFKA_AUTO_COMMIT")
            .unwrap_or_else(|_| "false".to_string());
            
        let auto_offset_reset = env::var("KAFKA_AUTO_OFFSET_RESET")
            .unwrap_or_else(|_| "earliest".to_string());
            
        let session_timeout_ms = env::var("KAFKA_SESSION_TIMEOUT_MS")
            .unwrap_or_else(|_| "6000".to_string());
            
        let max_poll_interval_ms = env::var("KAFKA_MAX_POLL_INTERVAL_MS")
            .unwrap_or_else(|_| "300000".to_string());
            
        let fetch_max_bytes = env::var("KAFKA_FETCH_MAX_BYTES")
            .unwrap_or_else(|_| "52428800".to_string()); // 50MB default
            
        let fetch_min_bytes = env::var("KAFKA_FETCH_MIN_BYTES")
            .unwrap_or_else(|_| "1".to_string());
            
        let fetch_max_wait_ms = env::var("KAFKA_FETCH_MAX_WAIT_MS")
            .unwrap_or_else(|_| "500".to_string());
        
        tracing::info!("Creating Kafka consumer with session timeout: {}ms, auto commit: {}, offset reset: {}", 
                      session_timeout_ms, auto_commit, auto_offset_reset);
        
        let mut client_config = ClientConfig::new();
        
        client_config
            .set("bootstrap.servers", &config.kafka_bootstrap_servers)
            .set("group.id", &config.kafka_consumer_group_id)
            .set("client.id", &format!("{}-consumer", config.kafka_client_id))
            .set("enable.auto.commit", &auto_commit)
            .set("auto.offset.reset", &auto_offset_reset)
            .set("session.timeout.ms", &session_timeout_ms)
            .set("max.poll.interval.ms", &max_poll_interval_ms)
            .set("fetch.max.bytes", &fetch_max_bytes)
            .set("fetch.min.bytes", &fetch_min_bytes)
            .set("fetch.wait.max.ms", &fetch_max_wait_ms);
            
        // Configure security if provided
        if let Some(protocol) = &config.kafka_security_protocol {
            client_config.set("security.protocol", protocol);
            
            if let (Some(mechanism), Some(username), Some(password)) = (
                &config.kafka_sasl_mechanism,
                &config.kafka_sasl_username,
                &config.kafka_sasl_password
            ) {
                client_config
                    .set("sasl.mechanism", mechanism)
                    .set("sasl.username", username)
                    .set("sasl.password", password);
            }
        }
        
        let consumer: StreamConsumer = client_config
            .create()
            .map_err(|e| ServiceError::ExternalServiceError(
                format!("Failed to create Kafka consumer: {}", e)
            ))?;
            
        consumer
            .subscribe(&[topic])
            .map_err(|e| ServiceError::ExternalServiceError(
                format!("Failed to subscribe to topics: {}", e)
            ))?;
            
        Ok(consumer)
    }
    
    /// Process a secret event from a Kafka message
    fn process_secret_event(payload: &[u8]) -> Result<SecretEvent> {
        serde_json::from_slice(payload)
            .map_err(|e| ServiceError::DeserializationError(
                format!("Failed to deserialize secret event: {}", e)
            ))
    }
    
    /// Process an audit event from a Kafka message
    fn process_audit_event(payload: &[u8]) -> Result<AuditEvent> {
        serde_json::from_slice(payload)
            .map_err(|e| ServiceError::DeserializationError(
                format!("Failed to deserialize audit event: {}", e)
            ))
    }
}
