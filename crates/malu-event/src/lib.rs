//! Event component for the Malu system
//!
//! This crate provides a unified event infrastructure for the Malu platform,
//! enabling event-driven architecture with support for various message brokers
//! including Kafka, RabbitMQ, and an in-memory implementation for testing.
//!
//! The event system is designed to be extensible, type-safe, and to provide
//! consistent behavior across different messaging backends.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

mod brokers;
mod models;

pub use brokers::*;
pub use models::*;

/// Core error type for the event system
#[derive(Error, Debug)]
pub enum EventError {
    #[error("Failed to serialize event: {0}")]
    SerializationError(String),

    #[error("Failed to deserialize event: {0}")]
    DeserializationError(String),

    #[error("Failed to publish event: {0}")]
    PublishError(String),

    #[error("Failed to subscribe to topic: {0}")]
    SubscriptionError(String),

    #[error("Timeout waiting for event: {0}")]
    TimeoutError(String),

    #[error("Broker connection error: {0}")]
    ConnectionError(String),

    #[error("Invalid configuration: {0}")]
    ConfigurationError(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

/// Result type for event operations
pub type EventResult<T> = Result<T, EventError>;

/// Base trait for all events in the system
pub trait Event: Serialize + for<'de> Deserialize<'de> + Clone + Debug + Send + Sync {
    /// Get the unique identifier for this event instance
    fn id(&self) -> &Uuid;

    /// Get the type/name of this event
    fn event_type(&self) -> &str;

    /// Get when this event was created
    fn created_at(&self) -> &DateTime<Utc>;

    /// Get the version of this event schema
    fn schema_version(&self) -> &str;

    /// Get the source system that generated this event
    fn source(&self) -> &str;

    /// Convert the event to a JSON string
    fn to_json(&self) -> EventResult<String> {
        serde_json::to_string(self)
            .map_err(|e| EventError::SerializationError(e.to_string()))
    }

    /// Get any additional metadata associated with this event
    fn metadata(&self) -> &HashMap<String, String>;
}

/// Base struct for all events that provides common functionality
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BaseEvent {
    /// Unique identifier for this event instance
    pub id: Uuid,
    
    /// Type/name of this event
    pub event_type: String,
    
    /// When this event was created
    pub created_at: DateTime<Utc>,
    
    /// Version of this event schema
    pub schema_version: String,
    
    /// Source system that generated this event
    pub source: String,
    
    /// Additional metadata associated with this event
    pub metadata: HashMap<String, String>,
}

/// Configuration for event publisher/subscriber components
#[derive(Clone, Debug, Deserialize)]
pub struct EventConfig {
    /// The type of broker to use
    pub broker_type: BrokerType,
    
    /// Connection string for the broker
    pub connection_string: String,
    
    /// Default timeout for operations in milliseconds
    pub timeout_ms: u64,
    
    /// Client identifier for this application instance
    pub client_id: String,
    
    /// Additional broker-specific configuration options
    pub options: HashMap<String, String>,
}

/// The type of message broker to use
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub enum BrokerType {
    /// Apache Kafka message broker
    Kafka,
    
    /// RabbitMQ message broker
    RabbitMQ,
    
    /// In-memory broker for testing
    InMemory,
}

/// Type-erased event payload
pub type EventPayload = Vec<u8>;

/// Type-erased event handler function for raw event payloads
pub type TypeErasedEventHandler = Box<dyn Fn(EventPayload) -> EventResult<()> + Send + Sync>;

/// Core interface for event publishers (object-safe version)
/// 
/// This trait is intentionally kept minimal to ensure object safety.
/// For type-safe publishing, use the extension trait methods or the free functions.
#[async_trait]
pub trait EventPublisher: Send + Sync {
    /// Publish a raw event payload to the specified topic
    async fn publish_raw(&self, topic: &str, payload: EventPayload, event_type: &str) -> EventResult<()>;
    
    /// Flush any buffered events
    async fn flush(&self) -> EventResult<()> {
        // Default implementation does nothing
        Ok(())
    }
    
    /// Check if the publisher is connected to the broker
    async fn is_connected(&self) -> bool {
        // Default implementation assumes connected
        true
    }
}

/// Extension methods for EventPublisher (non-object-safe)
/// 
/// This trait provides generic methods that cannot be part of the object-safe EventPublisher trait.
/// It is automatically implemented for all types that implement EventPublisher.
#[async_trait]
pub trait EventPublisherExt: EventPublisher {
    /// Publish an event to the specified topic
    async fn publish<E>(&self, topic: &str, event: E) -> EventResult<()>
    where
        E: Event + Send + 'static,
    {
        let event_type = event.event_type().to_string();
        let payload = event.to_json()?;
        self.publish_raw(topic, payload.into(), &event_type).await
    }
    
    /// Publish a batch of events to the specified topic
    async fn publish_batch<E>(&self, topic: &str, events: Vec<E>) -> EventResult<()>
    where
        E: Event + Send + 'static,
    {
        for event in events {
            self.publish(topic, event).await?
        }
        Ok(())
    }
}

// Blanket implementation of the extension trait for all types that implement EventPublisher
impl<T: EventPublisher + ?Sized> EventPublisherExt for T {}


/// Core interface for event subscribers (object-safe version)
/// 
/// This trait is intentionally kept minimal to ensure object safety.
/// For type-safe subscription, use the `subscribe` and `subscribe_batch` free functions.
#[async_trait]
pub trait EventSubscriber: Send + Sync {
    /// Subscribe to events from the specified topic with a type-erased handler function
    async fn subscribe_raw(
        &self,
        topic: &str,
        handler: TypeErasedEventHandler,
        event_type: &str,
    ) -> EventResult<SubscriptionHandle>;
    
    /// Unsubscribe from a topic using the subscription handle
    async fn unsubscribe(&self, handle: SubscriptionHandle) -> EventResult<()>;
    
    /// Check if the subscriber is connected to the broker
    async fn is_connected(&self) -> bool {
        // Default implementation assumes connected
        true
    }
}

/// Extension methods for EventSubscriber (non-object-safe)
/// 
/// This trait provides generic methods that cannot be part of the object-safe EventSubscriber trait.
/// It is automatically implemented for all types that implement EventSubscriber.
#[async_trait]
pub trait EventSubscriberExt: EventSubscriber {
    /// Subscribe to events from the specified topic with a typed handler function
    async fn subscribe<F, E>(
        &self,
        topic: &str,
        handler: F,
    ) -> EventResult<SubscriptionHandle>
    where
        F: Fn(E) -> EventResult<()> + Send + Sync + 'static,
        E: Event + Send + 'static,
    {
        let event_type = std::any::type_name::<E>();
        let type_erased_handler = Box::new(move |payload: EventPayload| {
            let event = serde_json::from_slice::<E>(&payload)
                .map_err(|e| EventError::DeserializationError(e.to_string()))?;
            handler(event)
        });
        
        self.subscribe_raw(topic, type_erased_handler, event_type).await
    }
    
    /// Subscribe to multiple topics with a typed handler function
    async fn subscribe_batch<F, E>(
        &self,
        topics: Vec<String>,
        handler: F,
    ) -> EventResult<Vec<SubscriptionHandle>>
    where
        F: Fn(E) -> EventResult<()> + Send + Sync + Clone + 'static,
        E: Event + Send + 'static,
    {
        let mut handles = Vec::with_capacity(topics.len());
        for topic in topics {
            // Clone the handler for each subscription
            let handler_clone = handler.clone();
            handles.push(self.subscribe(&topic, handler_clone).await?);
        }
        Ok(handles)
    }
}

// Blanket implementation of the extension trait for all types that implement EventSubscriber
impl<T: EventSubscriber + ?Sized> EventSubscriberExt for T {}


/// Type-safe helper function to publish an event via an event publisher
#[inline]
pub async fn publish<E, P>(publisher: &P, topic: &str, event: E) -> EventResult<()>
where
    E: Event + 'static,
    P: EventPublisher + ?Sized,
{
    let payload = serde_json::to_vec(&event)
        .map_err(|e| EventError::SerializationError(e.to_string()))?;
    publisher.publish_raw(topic, payload, event.event_type()).await
}

/// Type-safe helper function to publish a batch of events via an event publisher
#[inline]
pub async fn publish_batch<E, P>(publisher: &P, topic: &str, events: Vec<E>) -> EventResult<()>
where
    E: Event + 'static,
    P: EventPublisher + ?Sized,
{
    for event in events {
        publish(publisher, topic, event).await?
    }
    publisher.flush().await
}

/// Type-safe helper function to subscribe to events via an event subscriber
#[inline]
pub async fn subscribe<F, E, S>(
    subscriber: &S,
    topic: &str,
    handler: F,
) -> EventResult<SubscriptionHandle>
where
    F: Fn(E) -> EventResult<()> + Send + Sync + 'static,
    E: Event + 'static,
    S: EventSubscriber + ?Sized,
{
    // Create a wrapper function that deserializes the raw payload
    let type_erased_handler = Box::new(move |payload: Vec<u8>| -> EventResult<()> {
        let event: E = serde_json::from_slice(&payload)
            .map_err(|e| EventError::DeserializationError(e.to_string()))?;
        handler(event)
    });
    
    // Use the event type name to identify the event type
    let event_type = std::any::type_name::<E>();
    subscriber.subscribe_raw(topic, type_erased_handler, event_type).await
}

/// Type-safe helper function to subscribe to multiple topics via an event subscriber
#[inline]
pub async fn subscribe_batch<F, E, S>(
    subscriber: &S,
    topics: Vec<String>,
    handler: F,
) -> EventResult<Vec<SubscriptionHandle>>
where
    F: Fn(E) -> EventResult<()> + Send + Sync + Clone + 'static,
    E: Event + 'static,
    S: EventSubscriber + ?Sized,
{
    let mut handles = Vec::with_capacity(topics.len());
    
    for topic in topics {
        let handler_clone = handler.clone();
        let handle = subscribe(subscriber, &topic, handler_clone).await?;
        handles.push(handle);
    }
    
    Ok(handles)
}

/// Handle for managing a subscription
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionHandle {
    /// Unique identifier for this subscription
    pub id: Uuid,
    
    /// The topic being subscribed to
    pub topic: String,
}

/// Factory for creating event broker instances based on configuration
pub struct EventBrokerFactory;

impl EventBrokerFactory {
    /// Create a new event broker based on the provided configuration
    pub fn create(
        config: EventConfig,
    ) -> EventResult<(Arc<dyn EventPublisher>, Arc<dyn EventSubscriber>)> {
        match config.broker_type {
            #[cfg(feature = "kafka")]
            BrokerType::Kafka => {
                let broker = brokers::kafka::KafkaBroker::new(config)
                    .map_err(|e| EventError::ConfigurationError(e.to_string()))?;
                Ok((Arc::new(broker.clone()), Arc::new(broker)))
            }
            
            #[cfg(feature = "rabbitmq")]
            BrokerType::RabbitMQ => {
                let broker = brokers::rabbitmq::RabbitMQBroker::new(config)
                    .map_err(|e| EventError::ConfigurationError(e.to_string()))?;
                Ok((Arc::new(broker.clone()), Arc::new(broker)))
            }
            
            #[cfg(feature = "in-memory")]
            BrokerType::InMemory => {
                let broker = brokers::memory::InMemoryBroker::new();
                Ok((Arc::new(broker.clone()), Arc::new(broker)))
            }
            
            _ => Err(EventError::ConfigurationError(format!(
                "Broker type {:?} is not supported or the feature is not enabled",
                config.broker_type
            ))),
        }
    }
}

/// Integration with MaluStore for event-driven operations
pub mod integration {
    use super::*;
    use malu_core::MaluStore;
    use std::sync::Arc;

    /// Extension trait for MaluStore to add event capabilities
    #[async_trait]
    pub trait EventDrivenMaluStore {
        /// Get the event publisher associated with this MaluStore
        fn event_publisher(&self) -> Arc<dyn EventPublisher>;

        /// Get the event subscriber associated with this MaluStore
        fn event_subscriber(&self) -> Arc<dyn EventSubscriber>;

        /// Publish a domain event
        async fn publish_domain_event<E: Event + 'static>(
            &self,
            event: E,
        ) -> EventResult<()>;

        /// Subscribe to domain events
        async fn subscribe_to_domain_events<F, E>(
            &self,
            handler: F,
        ) -> EventResult<SubscriptionHandle>
        where
            F: Fn(E) -> EventResult<()> + Send + Sync + 'static,
            E: Event + 'static;
    }

    /// Implementation of EventDrivenMaluStore for MaluStore
    pub struct EventEnabledMaluStore {
        store: MaluStore,
        publisher: Arc<dyn EventPublisher>,
        subscriber: Arc<dyn EventSubscriber>,
    }

    impl EventEnabledMaluStore {
        /// Create a new EventEnabledMaluStore from an existing MaluStore and event components
        pub fn new(
            store: MaluStore,
            publisher: Arc<dyn EventPublisher>,
            subscriber: Arc<dyn EventSubscriber>,
        ) -> Self {
            Self {
                store,
                publisher,
                subscriber,
            }
        }

        /// Get the underlying MaluStore
        pub fn inner(&self) -> &MaluStore {
            &self.store
        }
    }

    #[async_trait]
    impl EventDrivenMaluStore for EventEnabledMaluStore {
        fn event_publisher(&self) -> Arc<dyn EventPublisher> {
            self.publisher.clone()
        }

        fn event_subscriber(&self) -> Arc<dyn EventSubscriber> {
            self.subscriber.clone()
        }

        async fn publish_domain_event<E: Event + 'static>(
            &self,
            event: E,
        ) -> EventResult<()> {
            let topic = format!("malu.domain.{}", event.event_type());
            // Use the extension trait method
            self.publisher.publish(&topic, event).await
        }

        async fn subscribe_to_domain_events<F, E>(
            &self,
            handler: F,
        ) -> EventResult<SubscriptionHandle>
        where
            F: Fn(E) -> EventResult<()> + Send + Sync + 'static,
            E: Event + 'static,
        {
            let topic = format!("malu.domain.{}", std::any::type_name::<E>());
            // Use the extension trait method
            self.subscriber.subscribe(&topic, handler).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::time::Duration;
    use std::sync::{Arc, Mutex};
    use tokio;
    use uuid::Uuid;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct TestEvent {
        base: BaseEvent,
        data: String,
    }

    impl Event for TestEvent {
        fn id(&self) -> &Uuid {
            &self.base.id
        }

        fn event_type(&self) -> &str {
            &self.base.event_type
        }

        fn created_at(&self) -> &DateTime<Utc> {
            &self.base.created_at
        }

        fn schema_version(&self) -> &str {
            &self.base.schema_version
        }

        fn source(&self) -> &str {
            &self.base.source
        }

        fn metadata(&self) -> &HashMap<String, String> {
            &self.base.metadata
        }
    }

    impl TestEvent {
        fn new(data: &str) -> Self {
            Self {
                base: BaseEvent {
                    id: Uuid::new_v4(),
                    event_type: "test.event".to_string(),
                    created_at: Utc::now(),
                    schema_version: "1.0".to_string(),
                    source: "test".to_string(),
                    metadata: HashMap::new(),
                },
                data: data.to_string(),
            }
        }
    }

    #[cfg(feature = "in-memory")]
    #[tokio::test]
    async fn test_in_memory_broker() -> EventResult<()> {
        // Create a broker with in-memory configuration
        let config = EventConfig {
            broker_type: BrokerType::InMemory,
            client_id: "test-client".to_string(),
            group_id: "test-group".to_string(),
            bootstrap_servers: vec![],
            auth_config: None,
        };
        
        let (publisher, subscriber) = EventBrokerFactory::create(config)?;
        
        // Create a shared collection to store received events
        let received_events = Arc::new(Mutex::new(Vec::new()));
        let received_events_clone = received_events.clone();
        
        // Create a test event
        let event = TestEvent::new("test data");
        let topic = format!("test.events.{}", event.event_type());
        
        // Subscribe to events using the extension trait
        let handle = subscribe::<_, _, TestEvent>(&*subscriber, &topic, move |received_event: TestEvent| {
            // Copy the event data to the received_events Vec
            received_events_clone.lock().unwrap().push(received_event);
            Ok(())
        }).await?;
        
        // Publish the event using the extension trait
        publish::<_, TestEvent>(&*publisher, &topic, event.clone()).await?;
        
        // Wait a moment for the event to be processed
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Verify that the event was received
        let events = received_events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "test data");
        
        // Unsubscribe
        subscriber.unsubscribe(handle).await?;
        
        Ok(())
    }    #[cfg(feature = "in-memory")]
    #[tokio::test]
    async fn test_unsubscribe() -> EventResult<()> {
        // Create a broker with in-memory configuration
        let config = EventConfig {
            broker_type: BrokerType::InMemory,
            client_id: "test-client".to_string(),
            group_id: "test-group".to_string(),
            bootstrap_servers: vec![],
            auth_config: None,
        };
        
        let (publisher, subscriber) = EventBrokerFactory::create(config)?;
        
        // Create a channel to signal when an event is received
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let tx = Arc::new(Mutex::new(Some(tx)));
        
        // Create a test event
        let event = TestEvent::new("test data");
        let topic = "test.events.TestEvent".to_string();
        
        // Subscribe to events
        let handle = subscribe::<_, _, TestEvent>(&*subscriber, &topic, move |received: TestEvent| {
            assert_eq!(received.data, "test data");
            if let Some(tx) = tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
            Ok(())
        }).await?;
        
        // Unsubscribe
        subscriber.unsubscribe(handle).await?;
        
        // Publish an event
        publish::<_, TestEvent>(&*publisher, &topic, event).await?;
        
        // Wait a moment for potential event processing
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // If the rx channel hasn't been completed, then the event wasn't received
        // (which is what we expect after unsubscribing)
        match rx.try_recv() {
            Err(_) => Ok(()), // Channel not completed, which is good
            Ok(_) => Err(EventError::ValidationError("Event was received after unsubscribing".to_string())),
        }
    }

    #[cfg(feature = "in-memory")]
    #[tokio::test]
    async fn test_unsubscribe() -> EventResult<()> {
        let config = EventConfig {
            broker_type: BrokerType::InMemory,
            connection_string: "".to_string(),
            timeout_ms: 1000,
            client_id: "test-client".to_string(),
            options: HashMap::new(),
        };

        let (_, subscriber) = EventBrokerFactory::create(config).unwrap();
        
        // Subscribe to events using the extension trait
        let handle = EventSubscriberExt::subscribe(&*subscriber, "test-topic", |_: TestEvent| {
            Ok(())
        }).await?;

        // Unsubscribe
        subscriber.unsubscribe(handle).await
    }
}
