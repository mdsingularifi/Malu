// Event model definitions for the Malu event system

use super::*;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use std::fmt;
use std::marker::PhantomData;

/// A domain event that indicates something significant has happened in the system
#[derive(Clone, Debug, Serialize)]
pub struct DomainEvent<T: Serialize + for<'a> Deserialize<'a> + Clone + Debug + Send + Sync> {
    /// Base event information
    pub base: BaseEvent,
    
    /// The payload data for this event
    pub payload: T,
}

impl<T: Serialize + for<'a> Deserialize<'a> + Clone + Debug + Send + Sync> Event for DomainEvent<T> {
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

impl<T: Serialize + for<'a> Deserialize<'a> + Clone + Debug + Send + Sync> DomainEvent<T> {
    /// Create a new domain event with the specified type and payload
    pub fn new(event_type: &str, payload: T, source: &str) -> Self {
        Self {
            base: BaseEvent {
                id: Uuid::new_v4(),
                event_type: event_type.to_string(),
                created_at: Utc::now(),
                schema_version: "1.0".to_string(),
                source: source.to_string(),
                metadata: HashMap::new(),
            },
            payload,
        }
    }

    /// Add metadata to the event
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.base.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// A command event that requests a change to be made in the system
#[derive(Clone, Debug, Serialize)]
pub struct CommandEvent<T: Serialize + for<'a> Deserialize<'a> + Clone + Debug + Send + Sync> {
    /// Base event information
    pub base: BaseEvent,
    
    /// The command payload data
    pub payload: T,
}

impl<T: Serialize + for<'a> Deserialize<'a> + Clone + Debug + Send + Sync> Event for CommandEvent<T> {
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

impl<T: Serialize + for<'a> Deserialize<'a> + Clone + Debug + Send + Sync> CommandEvent<T> {
    /// Create a new command event with the specified type and payload
    pub fn new(event_type: &str, payload: T, source: &str) -> Self {
        Self {
            base: BaseEvent {
                id: Uuid::new_v4(),
                event_type: event_type.to_string(),
                created_at: Utc::now(),
                schema_version: "1.0".to_string(),
                source: source.to_string(),
                metadata: HashMap::new(),
            },
            payload,
        }
    }

    /// Add metadata to the event
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.base.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

// Manual implementation of Deserialize for DomainEvent
impl<'de, T> Deserialize<'de> for DomainEvent<T>
where
    T: Serialize + for<'a> Deserialize<'a> + Clone + Debug + Send + Sync,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field { Base, Payload }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("`base` or `payload`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "base" => Ok(Field::Base),
                            "payload" => Ok(Field::Payload),
                            _ => Err(de::Error::unknown_field(value, &["base", "payload"])),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct DomainEventVisitor<T: Serialize + for<'a> Deserialize<'a> + Clone + Debug + Send + Sync> {
            marker: PhantomData<fn() -> DomainEvent<T>>,
        }

        impl<T: Serialize + for<'a> Deserialize<'a> + Clone + Debug + Send + Sync> DomainEventVisitor<T> {
            fn new() -> Self {
                DomainEventVisitor {
                    marker: PhantomData,
                }
            }
        }

        impl<'de, T> Visitor<'de> for DomainEventVisitor<T>
        where
            T: Serialize + for<'a> Deserialize<'a> + Clone + Debug + Send + Sync,
        {
            type Value = DomainEvent<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct DomainEvent")
            }

            fn visit_map<V>(self, mut map: V) -> Result<DomainEvent<T>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut base = None;
                let mut payload = None;
                
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Base => {
                            if base.is_some() {
                                return Err(de::Error::duplicate_field("base"));
                            }
                            base = Some(map.next_value()?);
                        }
                        Field::Payload => {
                            if payload.is_some() {
                                return Err(de::Error::duplicate_field("payload"));
                            }
                            payload = Some(map.next_value()?);
                        }
                    }
                }

                let base = base.ok_or_else(|| de::Error::missing_field("base"))?;
                let payload = payload.ok_or_else(|| de::Error::missing_field("payload"))?;
                
                Ok(DomainEvent { base, payload })
            }
        }

        deserializer.deserialize_struct("DomainEvent", &["base", "payload"], DomainEventVisitor::new())
    }
}

// Manual implementation of Deserialize for CommandEvent
impl<'de, T> Deserialize<'de> for CommandEvent<T>
where
    T: Serialize + for<'a> Deserialize<'a> + Clone + Debug + Send + Sync,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field { Base, Payload }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("`base` or `payload`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "base" => Ok(Field::Base),
                            "payload" => Ok(Field::Payload),
                            _ => Err(de::Error::unknown_field(value, &["base", "payload"])),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct CommandEventVisitor<T: Serialize + for<'a> Deserialize<'a> + Clone + Debug + Send + Sync> {
            marker: PhantomData<fn() -> CommandEvent<T>>,
        }

        impl<T: Serialize + for<'a> Deserialize<'a> + Clone + Debug + Send + Sync> CommandEventVisitor<T> {
            fn new() -> Self {
                CommandEventVisitor {
                    marker: PhantomData,
                }
            }
        }

        impl<'de, T> Visitor<'de> for CommandEventVisitor<T>
        where
            T: Serialize + for<'a> Deserialize<'a> + Clone + Debug + Send + Sync,
        {
            type Value = CommandEvent<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct CommandEvent")
            }

            fn visit_map<V>(self, mut map: V) -> Result<CommandEvent<T>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut base = None;
                let mut payload = None;
                
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Base => {
                            if base.is_some() {
                                return Err(de::Error::duplicate_field("base"));
                            }
                            base = Some(map.next_value()?);
                        }
                        Field::Payload => {
                            if payload.is_some() {
                                return Err(de::Error::duplicate_field("payload"));
                            }
                            payload = Some(map.next_value()?);
                        }
                    }
                }

                let base = base.ok_or_else(|| de::Error::missing_field("base"))?;
                let payload = payload.ok_or_else(|| de::Error::missing_field("payload"))?;
                
                Ok(CommandEvent { base, payload })
            }
        }

        deserializer.deserialize_struct("CommandEvent", &["base", "payload"], CommandEventVisitor::new())
    }
}
