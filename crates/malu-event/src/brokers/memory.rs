// In-memory broker implementation for local testing
use crate::{Event, EventError, EventPublisher, EventResult, EventSubscriber, SubscriptionHandle};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tracing::{debug, error, info};
use uuid::Uuid;

const DEFAULT_CHANNEL_SIZE: usize = 1024;

/// Message type for the in-memory broker
struct InMemoryMessage {
    /// Raw serialized event payload
    payload: String,
    /// Topic the message was published to
    topic: String,
}

/// In-memory implementation of the event broker for testing
#[derive(Clone)]
pub struct InMemoryBroker {
    /// Channels for each topic
    topics: Arc<Mutex<HashMap<String, broadcast::Sender<InMemoryMessage>>>>,
    /// Active subscriptions
    subscriptions: Arc<Mutex<HashMap<Uuid, InMemorySubscription>>>,
}

struct InMemorySubscription {
    id: Uuid,
    topic: String,
    cancel_token: tokio::sync::oneshot::Sender<()>,
}

impl InMemoryBroker {
    /// Create a new in-memory broker
    pub fn new() -> Self {
        Self {
            topics: Arc::new(Mutex::new(HashMap::new())),
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Get or create a channel for a topic
    fn get_or_create_topic(&self, topic: &str) -> broadcast::Sender<InMemoryMessage> {
        let mut topics = self.topics.lock().unwrap();
        
        topics
            .entry(topic.to_string())
            .or_insert_with(|| broadcast::channel(DEFAULT_CHANNEL_SIZE).0)
            .clone()
    }
}

#[async_trait]
impl EventPublisher for InMemoryBroker {
    async fn publish<E: Event + 'static>(&self, topic: &str, event: E) -> EventResult<()> {
        let payload = serde_json::to_string(&event)
            .map_err(|e| EventError::SerializationError(e.to_string()))?;
            
        let message = InMemoryMessage {
            payload,
            topic: topic.to_string(),
        };
        
        let sender = self.get_or_create_topic(topic);
        
        if sender.receiver_count() > 0 {
            // Only send if there are receivers to avoid dropped message warnings
            if let Err(e) = sender.send(message) {
                return Err(EventError::PublishError(format!("Failed to publish event: {}", e)));
            }
        } else {
            debug!("No subscribers for topic {}, message dropped", topic);
        }
        
        Ok(())
    }
    
    async fn publish_batch<E: Event + 'static>(
        &self,
        topic: &str,
        events: Vec<E>,
    ) -> EventResult<()> {
        for event in events {
            self.publish(topic, event).await?;
        }
        
        Ok(())
    }
    
    async fn flush(&self) -> EventResult<()> {
        // No buffering in the in-memory implementation
        Ok(())
    }
    
    async fn is_connected(&self) -> bool {
        // In-memory broker is always connected
        true
    }
}

#[async_trait]
impl EventSubscriber for InMemoryBroker {
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
        
        // Get the topic channel
        let sender = self.get_or_create_topic(topic);
        let mut receiver = sender.subscribe();
        
        // Create a cancellation channel
        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel();
        
        // Start a task to process messages
        let topic_owned = topic.to_string();
        
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut cancel_rx => {
                        info!("Canceling in-memory subscription to topic {}", topic_owned);
                        break;
                    }
                    
                    result = receiver.recv() => {
                        match result {
                            Ok(message) => {
                                if message.topic == topic_owned {
                                    match serde_json::from_str::<E>(&message.payload) {
                                        Ok(event) => {
                                            if let Err(e) = handler(event) {
                                                error!("Error handling in-memory event: {}", e);
                                            }
                                        }
                                        Err(e) => {
                                            error!("Failed to deserialize in-memory message: {}", e);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                if matches!(e, broadcast::error::RecvError::Closed) {
                                    // Channel was closed
                                    break;
                                }
                                // Lagged - we can continue
                                error!("Broadcast channel error: {}", e);
                            }
                        }
                    }
                }
            }
        });
        
        // Register the subscription
        let subscription = InMemorySubscription {
            id: subscription_id,
            topic: topic.to_string(),
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
        // In-memory broker is always connected
        true
    }
}

impl Default for InMemoryBroker {
    fn default() -> Self {
        Self::new()
    }
}
