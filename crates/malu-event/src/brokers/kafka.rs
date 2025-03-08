// Kafka broker implementation for the Malu event system
use crate::{EventConfig, EventError, EventPublisher, EventResult, EventSubscriber, SubscriptionHandle};
use async_trait::async_trait;
use futures::stream::StreamExt;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::message::{Header, Headers, OwnedHeaders};
use rdkafka::producer::{FutureProducer, FutureRecord, Producer};
use rdkafka::Message;
use rdkafka::util::Timeout;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Kafka implementation of the event broker
#[derive(Clone)]
pub struct KafkaBroker {
    producer: Arc<FutureProducer>,
    consumer_config: Arc<ClientConfig>,
    client_id: String,
    timeout_ms: u64,
    subscriptions: Arc<Mutex<HashMap<Uuid, KafkaSubscription>>>,
}

#[allow(dead_code)]
struct KafkaSubscription {
    id: Uuid,
    topic: String,
    cancel_token: tokio::sync::oneshot::Sender<()>,
}

impl KafkaBroker {
    /// Create a new Kafka broker with the specified configuration
    pub fn new(config: EventConfig) -> EventResult<Self> {
        let mut kafka_config = ClientConfig::new();
        
        // Set bootstrap.servers from connection_string
        kafka_config.set("bootstrap.servers", &config.connection_string);
        
        // Set client.id
        kafka_config.set("client.id", &config.client_id);
        
        // Apply additional options
        for (key, value) in &config.options {
            kafka_config.set(key, value);
        }
        
        // Configure producer with defaults if not specified
        if !config.options.contains_key("acks") {
            kafka_config.set("acks", "all");
        }
        
        // Create the producer
        let producer = match kafka_config.create::<FutureProducer>() {
            Ok(p) => Arc::new(p),
            Err(e) => return Err(EventError::ConnectionError(format!("Failed to create Kafka producer: {}", e))),
        };
        
        // Create a consumer config (we'll create consumers per subscription)
        let mut consumer_config = kafka_config.clone();
        consumer_config.set("enable.auto.commit", "true");
        consumer_config.set("auto.offset.reset", "latest");
        consumer_config.set("group.id", &format!("{}-group", config.client_id));
        
        Ok(Self {
            producer,
            consumer_config: Arc::new(consumer_config),
            client_id: config.client_id,
            timeout_ms: config.timeout_ms,
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    
    /// Send a payload to a Kafka topic (internal helper method)
    #[allow(dead_code)]
    async fn send_to_kafka<E>(
        &self,
        topic: &str,
        event: E,
        headers: Option<OwnedHeaders>,
    ) -> EventResult<()> 
    where
        E: serde::Serialize + crate::Event,
    {
        let payload = serde_json::to_string(&event)
            .map_err(|e| EventError::SerializationError(e.to_string()))?;
        
        // Store the key string to ensure it lives long enough
        let key_str = event.id().to_string();
        
        let record = if let Some(hdrs) = headers {
            FutureRecord::to(topic)
                .payload(&payload)
                .key(&key_str)
                .headers(hdrs)
        } else {
            // Create default headers with event metadata
            let event_type = event.event_type();
            let schema_version = event.schema_version();
            let source = event.source();
            
            let headers = OwnedHeaders::new_with_capacity(4)
                .insert(Header {
                    key: "event-id",
                    value: Some(key_str.as_bytes()),
                })
                .insert(Header {
                    key: "event-type",
                    value: Some(event_type.as_bytes()),
                })
                .insert(Header {
                    key: "schema-version",
                    value: Some(schema_version.as_bytes()),
                })
                .insert(Header {
                    key: "source",
                    value: Some(source.as_bytes()),
                });
                
            FutureRecord::to(topic)
                .payload(&payload)
                .key(&key_str)
                .headers(headers)
        };
        
        let timeout = Timeout::After(Duration::from_millis(self.timeout_ms));
        match self.producer.send(record, timeout).await {
            Ok(_) => Ok(()),
            Err((e, _)) => Err(EventError::PublishError(format!("Failed to publish event to Kafka: {}", e))),
        }
    }
}

#[async_trait]
impl EventPublisher for KafkaBroker {
    async fn publish_raw(&self, topic: &str, payload: Vec<u8>, event_type: &str) -> EventResult<()> {
        // Create default headers with event metadata
        let headers = OwnedHeaders::new_with_capacity(1)
            .insert(Header {
                key: "event-type",
                value: Some(event_type.as_bytes()),
            });
            
        let record: FutureRecord<'_, str, Vec<u8>> = FutureRecord::to(topic)
            .payload(&payload)
            .headers(headers);
            
        match self.producer
            .send(record, Timeout::After(Duration::from_millis(self.timeout_ms)))
            .await
        {
            Ok(_) => Ok(()),
            Err((e, _)) => Err(EventError::PublishError(format!("Failed to publish to Kafka: {}", e))),
        }
    }
    
    async fn flush(&self) -> EventResult<()> {
        match self.producer.flush(Timeout::After(Duration::from_millis(self.timeout_ms))) {
            Ok(_) => Ok(()),
            Err(e) => Err(EventError::PublishError(format!("Failed to flush Kafka producer: {}", e))),
        }
    }
    
    async fn is_connected(&self) -> bool {
        // Try to fetch metadata from the Kafka cluster
        match self.producer.client().fetch_metadata(
            None, 
            Timeout::After(Duration::from_millis(self.timeout_ms)),
        ) {
            Ok(_) => true,
            Err(e) => {
                warn!("Kafka connection check failed: {}", e);
                false
            }
        }
    }
}

#[async_trait]
impl EventSubscriber for KafkaBroker {
    async fn subscribe_raw(
        &self,
        topic: &str,
        handler: Box<dyn Fn(Vec<u8>) -> EventResult<()> + Send + Sync>,
        event_type: &str,
    ) -> EventResult<SubscriptionHandle>
    {
        let subscription_id = Uuid::new_v4();
        
        // Create a consumer for this subscription
        let mut consumer_config = (*self.consumer_config).clone();
        consumer_config.set("group.id", &format!("{}-{}", self.client_id, subscription_id));
        
        let consumer: StreamConsumer = consumer_config
            .create()
            .map_err(|e| EventError::SubscriptionError(format!("Failed to create Kafka consumer: {}", e)))?;
        
        // Subscribe to the topic
        consumer
            .subscribe(&[topic])
            .map_err(|e| EventError::SubscriptionError(format!("Failed to subscribe to Kafka topic: {}", e)))?;
            
        // Create a cancellation channel
        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel();
        
        // Start a task to consume messages
        let topic_owned = topic.to_string();
        let event_type_owned = event_type.to_string();
        let consumer = Arc::new(consumer);
        let consumer_clone = consumer.clone();
        // Move the Box handler to the task
        let handler = handler;
        
        tokio::spawn(async move {
            let mut message_stream = consumer_clone.stream();
            
            loop {
                tokio::select! {
                    _ = &mut cancel_rx => {
                        info!("Canceling Kafka subscription to topic {}", topic_owned);
                        break;
                    }
                    
                    message_result = message_stream.next() => {
                        match message_result {
                            Some(Ok(message)) => {
                                if let Some(payload) = message.payload() {
                                    // Check if the message matches our event type
                                    let mut matches_event_type = false;
                                    
                                    if let Some(headers) = message.headers() {
                                        // Iterate through all headers
                                        for i in 0..headers.count() {
                                            let header = headers.get(i);
                                            if header.key == "event-type" {
                                                if let Ok(header_value) = std::str::from_utf8(header.value.unwrap_or_default()) {
                                                    if header_value == event_type_owned {
                                                        matches_event_type = true;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    
                                    // If we're matching all events or this specific event type
                                    if event_type_owned == "*" || matches_event_type {
                                        if let Err(e) = handler(payload.to_vec()) {
                                            error!("Error handling Kafka message: {}", e);
                                        }
                                    }
                                }
                            }
                            Some(Err(e)) => {
                                error!("Error consuming Kafka message: {}", e);
                            }
                            None => {
                                // End of stream - unlikely to happen with Kafka
                                break;
                            }
                        }
                    }
                }
            }
        });
        
        // Register the subscription
        let subscription = KafkaSubscription {
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
