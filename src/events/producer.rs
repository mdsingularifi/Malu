//! Kafka producer implementation for the Secret Storage Service
//!
//! This module provides the Kafka producer functionality for publishing
//! events to Kafka topics.

use std::time::Duration;
use rdkafka::config::ClientConfig;
use rdkafka::error::KafkaError;
use rdkafka::producer::{FutureProducer, FutureRecord};
use serde::Serialize;

use crate::config::AppConfig;
use crate::core::error::{Result, ServiceError};
use crate::metrics;
use super::models::{SecretEvent, AuditEvent};

/// Kafka producer for publishing events
#[derive(Clone)]
pub struct KafkaProducer {
    /// Inner Kafka producer
    producer: FutureProducer,
    
    /// Topic for secret events
    secret_topic: String,
    
    /// Topic for audit events
    audit_topic: String,
    
    /// Configuration for reconnection
    #[allow(dead_code)]
    config: AppConfig,
}

impl KafkaProducer {
    /// Create a new Kafka producer from configuration
    pub async fn new(config: &AppConfig) -> Result<Self> {
        tracing::info!("Initializing Kafka producer with bootstrap servers: {}", config.kafka_bootstrap_servers);
        
        // Record Kafka initialization attempt in metrics
        metrics::record_operation_result("kafka_producer_init", true);
        
        // Get additional configuration from environment variables
        let message_timeout_ms = std::env::var("KAFKA_MESSAGE_TIMEOUT_MS")
            .unwrap_or_else(|_| "5000".to_string());
            
        let queue_buffering_max_ms = std::env::var("KAFKA_QUEUE_BUFFERING_MAX_MS")
            .unwrap_or_else(|_| "100".to_string());
            
        let retry_backoff_ms = std::env::var("KAFKA_RETRY_BACKOFF_MS")
            .unwrap_or_else(|_| "100".to_string());
            
        let compression_type = std::env::var("KAFKA_COMPRESSION_TYPE")
            .unwrap_or_else(|_| "none".to_string());
        
        // Configure the Kafka client
        let mut client_config = ClientConfig::new();
        client_config
            .set("bootstrap.servers", &config.kafka_bootstrap_servers)
            .set("client.id", &config.kafka_client_id)
            .set("message.timeout.ms", &message_timeout_ms)
            .set("queue.buffering.max.ms", &queue_buffering_max_ms)
            .set("retry.backoff.ms", &retry_backoff_ms)
            .set("compression.type", &compression_type);
        
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
        
        let producer: FutureProducer = client_config
            .create()
            .map_err(|e| ServiceError::ExternalServiceError(
                format!("Failed to create Kafka producer: {}", e)
            ))?;
        
        Ok(Self {
            producer,
            secret_topic: config.kafka_topic_secrets.clone(),
            audit_topic: config.kafka_topic_audit.clone(),
            config: config.clone(),
        })
    }
    
    /// Produce a secret event to the Kafka topic
    pub async fn produce_secret_event(&self, event: SecretEvent) -> Result<()> {
        self.send_event(&self.secret_topic, &event.event_id.to_string(), &event).await
    }
    
    /// Produce an audit event to the Kafka topic
    pub async fn produce_audit_event(&self, event: AuditEvent) -> Result<()> {
        self.send_event(&self.audit_topic, &event.event_id.to_string(), &event).await
    }
    
    /// Send an event to a Kafka topic
    async fn send_event<T: Serialize>(&self, topic: &str, key: &str, event: &T) -> Result<()> {
        let payload = serde_json::to_string(event)
            .map_err(|e| ServiceError::SerializationError(e.to_string()))?;
        
        // Get max message size from environment or use default
        let max_payload_size = std::env::var("KAFKA_MAX_PAYLOAD_SIZE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(950_000); // Default to 950KB as a safe threshold
        
        // Check payload size (Kafka typically has a default max message size of 1MB)
        if payload.len() > max_payload_size {
            return Err(ServiceError::ValidationError(
                format!("Event payload too large: {} bytes (max {}KB)", 
                       payload.len(), max_payload_size / 1000)
            ));
        }
            
        tracing::debug!("Sending event to topic '{}' with key '{}': {}", topic, key, payload);
        
        // Try to send with retries - get retry settings from environment
        let mut retries = 0;
        let max_retries = std::env::var("KAFKA_MAX_RETRIES")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(3);
        
        loop {
            // Start timing the Kafka send operation
            let _timer = metrics::Timer::new("kafka_send");
            
            // Get message delivery timeout from environment or use default
        let delivery_timeout_secs = std::env::var("KAFKA_DELIVERY_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(5);
            
        match self.producer
                .send(
                    FutureRecord::to(topic)
                        .payload(&payload)
                        .key(key),
                    Duration::from_secs(delivery_timeout_secs),
                )
                .await
            {
                Ok(_) => {
                    tracing::debug!("Successfully sent event to topic '{}'", topic);
                    // Record successful Kafka send in metrics
                    metrics::record_kafka_event(topic, "success");
                    return Ok(());
                },
                Err((KafkaError::MessageProduction(rdkafka::types::RDKafkaErrorCode::QueueFull), _)) => {
                    // Queue is full, wait and retry
                    if retries < max_retries {
                        retries += 1;
                        // Get backoff settings from environment or use defaults
                        let base_backoff_ms = std::env::var("KAFKA_QUEUE_BACKOFF_BASE_MS")
                            .ok()
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(100);
                            
                        let max_backoff_ms = std::env::var("KAFKA_QUEUE_BACKOFF_MAX_MS")
                            .ok()
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(2000);
                            
                        let backoff = std::cmp::min(
                            Duration::from_millis(base_backoff_ms * 2_u64.pow(retries)),
                            Duration::from_millis(max_backoff_ms)
                        );
                        tracing::warn!("Kafka queue full, retrying in {:?} (attempt {}/{})", backoff, retries, max_retries);
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                    
                    // Record failed Kafka send due to queue full in metrics
                    metrics::record_kafka_event(topic, "queue_full");
                    return Err(ServiceError::ExternalServiceError(
                        format!("Failed to send event to Kafka after {} retries: queue full", max_retries)
                    ));
                },
                Err((e, _)) => {
                    // For other errors, retry with backoff
                    if retries < max_retries {
                        retries += 1;
                        // Get backoff settings from environment or use defaults
                        let base_backoff_ms = std::env::var("KAFKA_ERROR_BACKOFF_BASE_MS")
                            .ok()
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(200);
                            
                        let max_backoff_ms = std::env::var("KAFKA_ERROR_BACKOFF_MAX_MS")
                            .ok()
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(3000);
                            
                        let backoff = std::cmp::min(
                            Duration::from_millis(base_backoff_ms * 2_u64.pow(retries)),
                            Duration::from_millis(max_backoff_ms)
                        );
                        tracing::warn!("Error sending to Kafka, retrying in {:?} (attempt {}/{}): {}", 
                            backoff, retries, max_retries, e);
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                    
                    // Record failed Kafka send in metrics with error
                    metrics::record_kafka_event(topic, "error");
                    metrics::record_operation_result("kafka_send", false);
                    return Err(ServiceError::ExternalServiceError(
                        format!("Failed to send event to Kafka after {} retries: {}", max_retries, e)
                    ));
                }
            }
        }
    }
}
