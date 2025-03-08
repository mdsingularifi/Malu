//! Event system module for Secret Storage Service
//! 
//! This module provides the event-driven architecture components
//! for the Secret Storage Service, using Kafka for event streaming.

pub mod models;
pub mod producer;
pub mod consumer;
pub mod handler;

pub use models::*;
pub use producer::*;
pub use consumer::*;
pub use handler::*;

use crate::config::AppConfig;
use crate::core::error::Result;

/// Initialize the event system based on configuration
#[allow(dead_code)]
pub async fn init_event_system(config: &AppConfig) -> Result<EventSystem> {
    let producer = if config.kafka_enable_producer {
        Some(KafkaProducer::new(config).await?)
    } else {
        None
    };
    
    let consumer = if config.kafka_enable_consumer {
        Some(KafkaConsumer::new(config).await?)
    } else {
        None
    };
    
    let event_system = EventSystem {
        producer,
        consumer,
        config: config.clone(),
    };
    
    Ok(event_system)
}

/// Main event system for the Secret Storage Service
#[derive(Clone)]
#[allow(dead_code)]
pub struct EventSystem {
    /// Kafka event producer
    pub producer: Option<KafkaProducer>,
    
    /// Kafka event consumer
    pub consumer: Option<KafkaConsumer>,
    
    /// Configuration for the event system
    pub config: AppConfig,
}

impl EventSystem {
    /// Start the event consumers in the background
    #[allow(dead_code)]
    pub async fn start_consumers(&self, handler: EventHandler) -> Result<()> {
        if let Some(consumer) = &self.consumer {
            tracing::info!("Starting Kafka consumers");
            consumer.start(handler).await?;
        }
        
        Ok(())
    }
    
    /// Produce a secret event
    #[allow(dead_code)]
    pub async fn produce_secret_event(&self, event: SecretEvent) -> Result<()> {
        if let Some(producer) = &self.producer {
            producer.produce_secret_event(event).await?;
        }
        
        Ok(())
    }
    
    /// Produce an audit event
    #[allow(dead_code)]
    pub async fn produce_audit_event(&self, event: AuditEvent) -> Result<()> {
        if let Some(producer) = &self.producer {
            producer.produce_audit_event(event).await?;
        }
        
        Ok(())
    }
}
