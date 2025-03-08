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
            }
        });
        
        // Start the audit events consumer in a separate task
        let audit_handler = handler.clone();
        spawn(async move {
            if let Err(e) = Self::consume_topic(&config2, &audit_topic, audit_handler, Self::process_audit_event).await {
                tracing::error!("Error in audit events consumer: {}", e);
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
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("Failed to create Kafka consumer: {}", e);
                    tokio::time::sleep(Duration::from_secs(5)).await;
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
                        match message_result {
                            Ok(message) => {
                                if let Some(payload) = message.payload() {
                                    match process_fn(payload) {
                                        Ok(event) => {
                                            // Lock the handler and process the event
                                            let mut guard = handler.lock().await;
                                            if let Err(e) = guard.handle_event(event).await {
                                                tracing::error!("Error handling event: {}", e);
                                            }
                                        },
                                        Err(e) => {
                                            tracing::error!("Error processing event: {}", e);
                                        }
                                    }
                                } else {
                                    tracing::warn!("Received message with empty payload");
                                }
                                
                                // Commit the message
                                if let Err(e) = consumer.commit_message(&message, CommitMode::Async) {
                                    tracing::error!("Error committing message: {}", e);
                                }
                            },
                            Err(e) => {
                                tracing::error!("Error receiving Kafka message: {}", e);
                                // Break inner loop to reconnect
                                break;
                            }
                        }
                    },
                    None => {
                        tracing::info!("Kafka consumer stream ended, reconnecting...");
                        // Break inner loop to reconnect
                        break;
                    }
                }
            }
            
            // If we reach here, the stream has ended or there was an error
            // Wait before attempting to reconnect
            tracing::info!("Waiting before attempting to reconnect to Kafka...");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        
        // This code is unreachable because of the infinite loop above,
        // but we need to satisfy the type signature
        #[allow(unreachable_code)]
        Ok(())
    }
    
    /// Create a Kafka consumer for a topic
    fn create_consumer(config: &AppConfig, topic: &str) -> Result<StreamConsumer> {
        let mut client_config = ClientConfig::new();
        
        client_config
            .set("bootstrap.servers", &config.kafka_bootstrap_servers)
            .set("group.id", &config.kafka_consumer_group_id)
            .set("client.id", &format!("{}-consumer", config.kafka_client_id))
            .set("enable.auto.commit", "false")
            .set("auto.offset.reset", "earliest")
            .set("session.timeout.ms", "6000");
            
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
