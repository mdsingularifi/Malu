// RabbitMQ broker implementation for the Malu event system
use crate::{Event, EventConfig, EventError, EventPublisher, EventResult, EventSubscriber, SubscriptionHandle};
use async_trait::async_trait;
use futures::StreamExt;
use lapin::{
    options::{
        BasicAckOptions, BasicConsumeOptions, BasicPublishOptions, ExchangeDeclareOptions,
        QueueBindOptions, QueueDeclareOptions,
    },
    types::FieldTable,
    BasicProperties, Connection, ConnectionProperties, ExchangeKind,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// RabbitMQ implementation of the event broker
#[derive(Clone)]
pub struct RabbitMQBroker {
    connection: Arc<Connection>,
    client_id: String,
    timeout_ms: u64,
    subscriptions: Arc<Mutex<HashMap<Uuid, RabbitMQSubscription>>>,
    connected: Arc<Mutex<bool>>,
    reconnect_signal: Arc<Notify>,
}

struct RabbitMQSubscription {
    id: Uuid,
    topic: String,
    queue_name: String,
    cancel_token: tokio::sync::oneshot::Sender<()>,
}

impl RabbitMQBroker {
    /// Create a new RabbitMQ broker with the specified configuration
    pub fn new(config: EventConfig) -> EventResult<Self> {
        let connection = Self::create_connection(&config)?;
        
        let broker = Self {
            connection: Arc::new(connection),
            client_id: config.client_id.clone(),
            timeout_ms: config.timeout_ms,
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
            connected: Arc::new(Mutex::new(true)),
            reconnect_signal: Arc::new(Notify::new()),
        };
        
        // Start the reconnection monitor
        let broker_clone = broker.clone();
        tokio::spawn(async move {
            broker_clone.monitor_connection().await;
        });
        
        Ok(broker)
    }
    
    /// Create a connection to RabbitMQ
    fn create_connection(config: &EventConfig) -> EventResult<Connection> {
        // Create a tokio runtime for the connection
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| EventError::ConnectionError(format!("Failed to create runtime: {}", e)))?;
        
        // Connect to RabbitMQ
        let connection = runtime.block_on(async {
            Connection::connect(
                &config.connection_string,
                ConnectionProperties::default(),
            )
            .await
        })
        .map_err(|e| EventError::ConnectionError(format!("Failed to connect to RabbitMQ: {}", e)))?;
        
        Ok(connection)
    }
    
    /// Monitor the connection and attempt to reconnect if it drops
    async fn monitor_connection(&self) {
        let connection = self.connection.clone();
        let connected = self.connected.clone();
        let reconnect_signal = self.reconnect_signal.clone();
        
        // Get notified when the connection status changes
        let mut status_listener = connection.status_chan().clone();
        
        loop {
            tokio::select! {
                status = status_listener.recv() => {
                    match status {
                        Some(status) => {
                            match status {
                                lapin::ConnectionStatus::Connected => {
                                    info!("Connected to RabbitMQ");
                                    *connected.lock().unwrap() = true;
                                }
                                _ => {
                                    warn!("Disconnected from RabbitMQ: {:?}", status);
                                    *connected.lock().unwrap() = false;
                                    
                                    // Signal to all waiting operations that we're disconnected
                                    reconnect_signal.notify_waiters();
                                }
                            }
                        }
                        None => {
                            // Channel closed
                            break;
                        }
                    }
                }
            }
        }
    }
}

#[async_trait]
impl EventPublisher for RabbitMQBroker {
    async fn publish<E: Event + 'static>(&self, topic: &str, event: E) -> EventResult<()> {
        let payload = serde_json::to_string(&event)
            .map_err(|e| EventError::SerializationError(e.to_string()))?;
            
        // Create a channel
        let channel = self.connection.create_channel().await
            .map_err(|e| EventError::PublishError(format!("Failed to create RabbitMQ channel: {}", e)))?;
            
        // Declare the exchange
        channel.exchange_declare(
            topic,
            ExchangeKind::Topic,
            ExchangeDeclareOptions {
                durable: true,
                ..ExchangeDeclareOptions::default()
            },
            FieldTable::default(),
        ).await
        .map_err(|e| EventError::PublishError(format!("Failed to declare RabbitMQ exchange: {}", e)))?;
        
        // Create properties with event metadata
        let mut properties = BasicProperties::default()
            .with_message_id(event.id().to_string().into())
            .with_content_type("application/json".into());
            
        // Add headers
        let mut headers = FieldTable::default();
        headers.insert("event-type".into(), event.event_type().into());
        headers.insert("schema-version".into(), event.schema_version().into());
        headers.insert("source".into(), event.source().into());
        
        // Add custom metadata
        for (key, value) in event.metadata() {
            headers.insert(key.clone().into(), value.clone().into());
        }
        
        properties = properties.with_headers(headers);
        
        // Publish the message
        channel.basic_publish(
            topic,
            "", // Routing key (empty for topic exchanges)
            BasicPublishOptions::default(),
            payload.as_bytes(),
            properties,
        ).await
        .map_err(|e| EventError::PublishError(format!("Failed to publish event to RabbitMQ: {}", e)))?;
        
        Ok(())
    }
    
    async fn publish_batch<E: Event + 'static>(
        &self,
        topic: &str,
        events: Vec<E>,
    ) -> EventResult<()> {
        // Create a channel
        let channel = self.connection.create_channel().await
            .map_err(|e| EventError::PublishError(format!("Failed to create RabbitMQ channel: {}", e)))?;
            
        // Declare the exchange
        channel.exchange_declare(
            topic,
            ExchangeKind::Topic,
            ExchangeDeclareOptions {
                durable: true,
                ..ExchangeDeclareOptions::default()
            },
            FieldTable::default(),
        ).await
        .map_err(|e| EventError::PublishError(format!("Failed to declare RabbitMQ exchange: {}", e)))?;
        
        // Publish each event
        for event in events {
            let payload = serde_json::to_string(&event)
                .map_err(|e| EventError::SerializationError(e.to_string()))?;
                
            // Create properties with event metadata
            let mut properties = BasicProperties::default()
                .with_message_id(event.id().to_string().into())
                .with_content_type("application/json".into());
                
            // Add headers
            let mut headers = FieldTable::default();
            headers.insert("event-type".into(), event.event_type().into());
            headers.insert("schema-version".into(), event.schema_version().into());
            headers.insert("source".into(), event.source().into());
            
            // Add custom metadata
            for (key, value) in event.metadata() {
                headers.insert(key.clone().into(), value.clone().into());
            }
            
            properties = properties.with_headers(headers);
            
            // Publish the message
            channel.basic_publish(
                topic,
                "", // Routing key (empty for topic exchanges)
                BasicPublishOptions::default(),
                payload.as_bytes(),
                properties,
            ).await
            .map_err(|e| EventError::PublishError(format!("Failed to publish event to RabbitMQ: {}", e)))?;
        }
        
        Ok(())
    }
    
    async fn flush(&self) -> EventResult<()> {
        // RabbitMQ publishes messages immediately, so no flush is needed
        Ok(())
    }
    
    async fn is_connected(&self) -> bool {
        *self.connected.lock().unwrap()
    }
}

#[async_trait]
impl EventSubscriber for RabbitMQBroker {
    async fn subscribe<F, E>(
        &self,
        topic: &str,
        handler: F,
    ) -> EventResult<SubscriptionHandle>
    where
        F: Fn(E) -> EventResult<()> + Send + Sync + 'static,
        E: Event + 'static,
    {
        let subscription_id = Uuid::new_v4();
        let handler = Arc::new(handler);
        
        // Create a unique queue name for this subscription
        let queue_name = format!("{}-{}-{}", self.client_id, topic.replace('.', "-"), subscription_id);
        
        // Create a channel
        let channel = self.connection.create_channel().await
            .map_err(|e| EventError::SubscriptionError(format!("Failed to create RabbitMQ channel: {}", e)))?;
            
        // Declare the exchange
        channel.exchange_declare(
            topic,
            ExchangeKind::Topic,
            ExchangeDeclareOptions {
                durable: true,
                ..ExchangeDeclareOptions::default()
            },
            FieldTable::default(),
        ).await
        .map_err(|e| EventError::SubscriptionError(format!("Failed to declare RabbitMQ exchange: {}", e)))?;
        
        // Declare the queue
        channel.queue_declare(
            &queue_name,
            QueueDeclareOptions {
                durable: true,
                exclusive: true,
                auto_delete: true,
                ..QueueDeclareOptions::default()
            },
            FieldTable::default(),
        ).await
        .map_err(|e| EventError::SubscriptionError(format!("Failed to declare RabbitMQ queue: {}", e)))?;
        
        // Bind the queue to the exchange
        channel.queue_bind(
            &queue_name,
            topic,
            "#", // Routing key (all messages)
            QueueBindOptions::default(),
            FieldTable::default(),
        ).await
        .map_err(|e| EventError::SubscriptionError(format!("Failed to bind RabbitMQ queue: {}", e)))?;
        
        // Start consuming messages
        let mut consumer = channel.basic_consume(
            &queue_name,
            &format!("consumer-{}", subscription_id),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        ).await
        .map_err(|e| EventError::SubscriptionError(format!("Failed to create RabbitMQ consumer: {}", e)))?;
        
        // Create a cancellation channel
        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel();
        
        // Clone the channel for use in the task
        let channel = Arc::new(channel);
        
        // Start a task to consume messages
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut cancel_rx => {
                        info!("Canceling RabbitMQ subscription to topic {}", topic);
                        break;
                    }
                    
                    delivery_result = consumer.next() => {
                        match delivery_result {
                            Some(Ok(delivery)) => {
                                let data = delivery.data;
                                
                                match serde_json::from_slice::<E>(&data) {
                                    Ok(event) => {
                                        if let Err(e) = handler(event) {
                                            error!("Error handling RabbitMQ event: {}", e);
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to deserialize RabbitMQ message: {}", e);
                                    }
                                }
                                
                                // Acknowledge the message
                                if let Err(e) = channel.basic_ack(
                                    delivery.delivery_tag, 
                                    BasicAckOptions::default()
                                ).await {
                                    error!("Failed to acknowledge RabbitMQ message: {}", e);
                                }
                            }
                            Some(Err(e)) => {
                                error!("Error consuming RabbitMQ message: {}", e);
                            }
                            None => {
                                // End of stream - consumer was canceled
                                break;
                            }
                        }
                    }
                }
            }
        });
        
        // Register the subscription
        let subscription = RabbitMQSubscription {
            id: subscription_id,
            topic: topic.to_string(),
            queue_name,
            cancel_token: cancel_tx,
        };
        
        let handle = SubscriptionHandle {
            id: subscription_id,
            topic: topic.to_string(),
        };
        
        self.subscriptions.lock().unwrap().insert(subscription_id, subscription);
        
        Ok(handle)
    }
    
    async fn subscribe_batch<F, E>(
        &self,
        topic: &str,
        handler: F,
    ) -> EventResult<SubscriptionHandle>
    where
        F: Fn(Vec<E>) -> EventResult<()> + Send + Sync + 'static,
        E: Event + 'static,
    {
        // For simplicity, we'll implement this as a wrapper around the single-message subscribe
        // In a real implementation, you might want to batch messages more efficiently
        
        let handler = Arc::new(handler);
        
        let batch_handler = move |event: E| -> EventResult<()> {
            // Note: This is a simplified batching mechanism.
            // A real implementation would collect events over time and process them in batches.
            let events = vec![event];
            handler(events)
        };
        
        self.subscribe(topic, batch_handler).await
    }
    
    async fn unsubscribe(&self, handle: SubscriptionHandle) -> EventResult<()> {
        let mut subscriptions = self.subscriptions.lock().unwrap();
        
        if let Some(subscription) = subscriptions.remove(&handle.id) {
            // Send cancellation token to stop the consumer task
            let _ = subscription.cancel_token.send(());
            Ok(())
        } else {
            Err(EventError::SubscriptionError(format!("Subscription not found: {}", handle.id)))
        }
    }
    
    async fn is_connected(&self) -> bool {
        // Reuse the publisher's connection check
        EventPublisher::is_connected(self).await
    }
}
