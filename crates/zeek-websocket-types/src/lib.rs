use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeSeq};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    error::Error,
    fmt::Display,
    net::IpAddr,
    str::FromStr,
};
use thiserror::Error;

#[doc(no_inline)]
pub use ipnetwork::IpNetwork;
#[doc(no_inline)]
pub use ordered_float::OrderedFloat;
#[doc(no_inline)]
pub use time::{Duration, OffsetDateTime};

/// Enum for all basic types understood by Zeek's WebSocket API.
#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialOrd, Ord, PartialEq, Eq)]
#[serde(tag = "@data-type", rename_all = "lowercase", content = "data")]
pub enum Value {
    #[serde(
        serialize_with = "serialize_none",
        deserialize_with = "deserialize_none"
    )]
    None,
    Boolean(bool),
    Count(u64),
    Integer(i64),
    Real(OrderedFloat<f64>),
    #[serde(with = "timespan")]
    Timespan(Duration),
    #[serde(with = "timestamp")]
    Timestamp(OffsetDateTime),
    String(String),
    #[serde(rename = "enum-value")]
    EnumValue(String),
    Address(IpAddr),
    Subnet(IpNetwork),
    Port(Port),
    Vector(Vec<Value>),
    Set(BTreeSet<Value>),
    Table(
        #[serde(
            serialize_with = "serialize_table",
            deserialize_with = "deserialize_table"
        )]
        BTreeMap<Value, Value>,
    ),
}

macro_rules! impl_from_T {
    ($t:ty, $c:path) => {
        impl From<$t> for Value {
            fn from(value: $t) -> Self {
                $c(value.into())
            }
        }
    };
}

macro_rules! impl_T {
    ($t:ty, $c:path) => {
        impl_from_T!($t, $c);

        impl TryFrom<Value> for $t {
            type Error = ConversionError;

            fn try_from(value: Value) -> Result<Self, Self::Error> {
                let $c(x) = value else {
                    return Err(ConversionError::MismatchedTypes);
                };

                x.try_into()
                    .map_err(|e| ConversionError::Domain(Box::new(e)))
            }
        }
    };
}

impl_T!(bool, Value::Boolean);
impl_T!(u64, Value::Count);
impl_T!(u32, Value::Count);
impl_T!(u16, Value::Count);
impl_T!(u8, Value::Count);
impl_T!(i64, Value::Integer);
impl_T!(i32, Value::Integer);
impl_T!(i16, Value::Integer);
impl_T!(i8, Value::Integer);
impl_T!(f64, Value::Real);
impl_T!(Duration, Value::Timespan);
impl_T!(OffsetDateTime, Value::Timestamp);
impl_T!(String, Value::String);
impl_from_T!(&str, Value::String);
impl_T!(IpAddr, Value::Address);
impl_T!(IpNetwork, Value::Subnet);
impl_T!(Port, Value::Port);

impl From<f32> for Value {
    fn from(value: f32) -> Self {
        let value: f64 = value.into();
        Value::Real(value.into())
    }
}

impl From<()> for Value {
    #[allow(clippy::ignored_unit_patterns)]
    fn from(_: ()) -> Self {
        Value::None
    }
}

impl<T> From<Vec<T>> for Value
where
    T: Into<Value>,
{
    fn from(value: Vec<T>) -> Self {
        Value::Vector(value.into_iter().map(Into::into).collect())
    }
}

impl<T> From<HashSet<T>> for Value
where
    T: Into<Value>,
{
    fn from(value: HashSet<T>) -> Self {
        Value::Set(value.into_iter().map(Into::into).collect())
    }
}

impl<K, V> From<HashMap<K, V>> for Value
where
    K: Into<Value>,
    V: Into<Value>,
{
    fn from(value: HashMap<K, V>) -> Self {
        Value::Table(
            value
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        )
    }
}

/// Error enum for Zeek-related deserialization errors.
#[derive(Error, Debug, PartialEq)]
pub enum ParseError {
    #[error("invalid port '{0}'")]
    InvalidPort(String),

    #[error("invalid port number '{0}'")]
    InvalidPortNumber(String),

    #[error("invalid protocol '{0}'")]
    InvalidProtocol(String),

    #[error("invalid timespan unit '{0}'")]
    InvalidTimespanUnit(String),

    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(String),
}

/// Error enum for Zeek-related serialization errors.
#[derive(Error, Debug, PartialEq)]
pub enum SerializationError {
    #[error("value not representable: {0}")]
    NotRepresentable(String),
}

/// Error enum for errors related to conversions from a Zeek value.
#[derive(Error, Debug)]
pub enum ConversionError {
    #[error("cannot convert value to target type")]
    MismatchedTypes,

    #[error("conversion to target type failed")]
    Domain(Box<dyn Error>),
}

impl PartialEq for ConversionError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            // Not ideal, but just compare stringifications of the errors.
            (Self::Domain(l0), Self::Domain(r0)) => l0.to_string() == r0.to_string(),

            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

/// A Zeek port which holds both a port number and a protocol identifier.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
pub struct Port {
    number: u16,
    protocol: Protocol,
}

impl Port {
    #[must_use]
    pub fn new(number: u16, protocol: Protocol) -> Self {
        Self { number, protocol }
    }

    #[must_use]
    pub fn number(&self) -> u16 {
        self.number
    }

    #[must_use]
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
}

impl<'de> serde::Deserialize<'de> for Port {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <String>::deserialize(deserializer)?;
        Port::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for Port {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.number;
        let p = self.protocol;
        f.write_str(&format!("{n}/{p}"))
    }
}

impl FromStr for Port {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (number, proto) = s
            .split_once('/')
            .ok_or_else(|| ParseError::InvalidPort(s.to_string()))?;
        Ok(Self {
            number: number
                .parse()
                .map_err(|_| ParseError::InvalidPortNumber(number.to_string()))?,
            protocol: proto.parse()?,
        })
    }
}

/// A network protocol understood by Zeek.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    UNKNOWN,
}

mod timestamp {
    use serde::Deserialize;
    use time::{
        OffsetDateTime, PrimitiveDateTime, UtcOffset, format_description::BorrowedFormatItem,
        macros::format_description,
    };

    const FORMAT: &[BorrowedFormatItem<'_>] =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]");

    pub fn serialize<S>(timestamp: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::Error;

        // Timestamps are serialized in local time.
        let offset = UtcOffset::current_local_offset().map_err(S::Error::custom)?;
        let timestamp = timestamp.to_offset(offset);

        let timestamp = PrimitiveDateTime::new(timestamp.date(), timestamp.time());

        let x = timestamp.format(FORMAT).map_err(S::Error::custom)?;

        serializer.serialize_str(&x)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;

        let time = PrimitiveDateTime::parse(&s, FORMAT).map_err(D::Error::custom)?;

        let offset = UtcOffset::current_local_offset().map_err(D::Error::custom)?;
        let time = time.assume_offset(offset);

        Ok(time)
    }
}

mod timespan {
    #![allow(clippy::missing_errors_doc)]

    use super::{ParseError, SerializationError};
    use serde::{Deserialize, de, ser::Error};
    use std::str::FromStr;
    use time::Duration;

    enum Unit {
        NS,
        MS,
        S,
        Min,
        H,
        D,
    }

    impl FromStr for Unit {
        type Err = ParseError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Ok(match s {
                "ns" => Self::NS,
                "ms" => Self::MS,
                "s" => Self::S,
                "min" => Self::Min,
                "h" => Self::H,
                "d" => Self::D,
                _ => Err(ParseError::InvalidTimespanUnit(s.to_string()))?,
            })
        }
    }

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // If we only store seconds format as a seconds value.
        if duration.subsec_nanoseconds() == 0 {
            return serializer.serialize_str(&format!("{}s", duration.whole_seconds()));
        }

        // We have nanoseconds. Since a `timespace` can only represent integer values we must
        // represent the duration as an `i64` of nanos. Should the number of nanos exceed the range
        // of `i64` the value is not representable.
        let num_nanos: i64 = duration.whole_nanoseconds().try_into().map_err(|_| {
            S::Error::custom(SerializationError::NotRepresentable(format!(
                "'{duration}' needs nanosecond accuracy but exceeds its range"
            )))
        })?;
        serializer.serialize_str(&format!("{num_nanos}ns"))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <String>::deserialize(deserializer)?;

        let unit_start = s
            .chars()
            .enumerate()
            .find_map(|(i, c)| {
                if c != '-' && !c.is_ascii_digit() {
                    Some(i)
                } else {
                    None
                }
            })
            .unwrap_or(0);

        let num = s[0..unit_start].parse().map_err(de::Error::custom)?;

        let unit = &s[unit_start..];
        let unit: Unit = unit
            .parse()
            .map_err(|_| de::Error::custom(ParseError::InvalidTimespanUnit(unit.into())))?;

        Ok(match unit {
            Unit::NS => Duration::nanoseconds(num),
            Unit::MS => Duration::milliseconds(num),
            Unit::S => Duration::seconds(num),
            Unit::Min => Duration::minutes(num),
            Unit::H => Duration::hours(num),
            Unit::D => Duration::days(num),
        })
    }
}

impl Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match &self {
            Self::TCP => "tcp",
            Self::UDP => "udp",
            Self::ICMP => "icmp",
            Self::UNKNOWN => "?",
        })
    }
}

impl FromStr for Protocol {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "tcp" => Self::TCP,
            "udp" => Self::UDP,
            "icmp" => Self::ICMP,
            "?" => Self::UNKNOWN,
            _ => Err(ParseError::InvalidProtocol(s.to_string()))?,
        })
    }
}

/// An entry in a table in a serialized [`Value::Table`].
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
pub struct TableEntry {
    pub key: Value,
    pub value: Value,
}

impl TableEntry {
    #[must_use]
    pub fn new<K, V>(key: K, value: V) -> Self
    where
        K: Into<Value>,
        V: Into<Value>,
    {
        let key = key.into();
        let value = value.into();
        TableEntry { key, value }
    }
}
/// Data messages of the Zeek API.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Message {
    /// An ACK message typically sent by the server on successful subscription.
    Ack {
        /// Endpoint ID assigned by the server for this client.
        endpoint: String,
        /// Zeek version of the server.
        version: String,
    },

    /// An error sent by the server.
    Error {
        /// Zeek-assigned kind of the error.
        code: String,
        /// Additional context.
        #[serde(alias = "message")] // See https://github.com/zeek/zeek/issues/4594.
        context: String,
    },

    /// Message received over a topic.
    #[serde(rename = "data-message")]
    DataMessage {
        /// Topic of the message.
        topic: String,

        /// Data payload of the message.
        #[serde(flatten)]
        data: Data,
    },
}

impl Message {
    pub fn new_data<T, D>(topic: T, data: D) -> Self
    where
        T: Into<String>,
        D: Into<Data>,
    {
        Message::DataMessage {
            topic: topic.into(),
            data: data.into(),
        }
    }
}

#[cfg(feature = "tungstenite")]
impl From<Message> for tungstenite::Message {
    fn from(value: Message) -> Self {
        let msg = serde_json::to_string(&value).expect("conversion should never fail");
        msg.into()
    }
}

#[cfg(feature = "tungstenite")]
/// Error enum for Zeek-related deserialization errors.
#[derive(Error, Debug, PartialEq)]
pub enum DeserializationError {
    #[error("unexpected message type: {0}")]
    UnexpectedMessageType(tungstenite::Message),

    #[error("could not parse message JSON: {0}")]
    Json(String),
}

#[cfg(feature = "tungstenite")]
impl TryFrom<tungstenite::Message> for Message {
    type Error = DeserializationError;

    fn try_from(
        value: tungstenite::Message,
    ) -> Result<Self, <Message as TryFrom<tungstenite::Message>>::Error> {
        let msg = match value {
            tungstenite::Message::Text(txt) => serde_json::from_str(&txt),
            tungstenite::Message::Binary(bin) => serde_json::from_slice(&bin),
            x => return Err(DeserializationError::UnexpectedMessageType(x)),
        }
        .map_err(|e| DeserializationError::Json(e.to_string()))?;

        Ok(msg)
    }
}

/// Data payload of a Zeek API message.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(from = "Value", into = "Value")]
pub enum Data {
    /// A Zeek event.
    Event(Event),

    /// Anything else.
    Other(Value),
}

impl From<Event> for Data {
    fn from(value: Event) -> Self {
        Data::Event(value)
    }
}

const EVENT_TYPE: u64 = 1;
const FORMAT_NR: u64 = 1;

impl From<Value> for Data {
    fn from(value: Value) -> Self {
        if let Value::Vector(xs) = &value
          && let Some(Value::Count(EVENT_TYPE)) = xs.get(1) // Events have type `1`.
          && let Some(Value::Vector(data)) = xs.get(2)
          && let Some(Value::String(name)) = data.first().cloned()
          && let Some(Value::Vector(args)) = data.get(1).cloned()
        {
            // Metadata might be present or not. Currently nodes seem to send it, but it is
            // undocumented.
            let metadata = match data.get(2) {
                Some(Value::Vector(xs)) => xs.clone(),
                Some(xs) => vec![xs.clone()],
                None => vec![],
            };

            return Data::Event(Event::new(name, args).with_metadata(metadata));
        };

        Data::Other(value)
    }
}

impl From<Data> for Value {
    fn from(val: Data) -> Self {
        match val {
            Data::Event(event) => {
                let data = vec![
                    Value::String(event.name),
                    Value::Vector(event.args),
                    Value::Vector(event.metadata),
                ];

                Value::Vector(vec![
                    Value::Count(FORMAT_NR),
                    Value::Count(EVENT_TYPE),
                    Value::Vector(data),
                ])
            }

            Data::Other(data) => data,
        }
    }
}

fn serialize_none<S>(s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeMap;
    s.serialize_map(Some(0))?.end()
}

fn deserialize_none<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    let _ = serde::de::IgnoredAny::deserialize(deserializer)?;
    Ok(())
}

fn serialize_table<S>(map: &BTreeMap<Value, Value>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut s = s.serialize_seq(Some(map.len()))?;
    for (k, v) in map {
        let entry = TableEntry::new(k.clone(), v.clone());
        s.serialize_element(&entry)?;
    }
    s.end()
}

fn deserialize_table<'de, D>(d: D) -> Result<BTreeMap<Value, Value>, D::Error>
where
    D: Deserializer<'de>,
{
    let vec = Vec::<TableEntry>::deserialize(d)?;
    Ok(vec.into_iter().map(|e| (e.key, e.value)).collect())
}

/// A Zeek event.
#[derive(Debug, PartialEq, Clone)]
pub struct Event {
    /// Name of the event.
    pub name: String,

    /// Arguments of the event.
    pub args: Vec<Value>,

    /// Event metadata.
    pub metadata: Vec<Value>,
}

impl Event {
    pub fn new<N, I, A>(name: N, args: I) -> Self
    where
        I: IntoIterator<Item = A>,
        N: Into<String>,
        A: Into<Value>,
    {
        Self {
            name: name.into(),
            args: args.into_iter().map(Into::into).collect(),
            metadata: Vec::default(),
        }
    }

    #[must_use]
    pub fn with_metadata<I, M>(mut self, metadata: I) -> Self
    where
        I: IntoIterator<Item = M>,
        M: Into<Value>,
    {
        self.metadata = metadata.into_iter().map(Into::into).collect();
        self
    }
}

/// Topics to subscribe to. This should be the first message sent to the server.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Default)]
pub struct Subscriptions(pub Vec<String>);

impl<T> From<Vec<T>> for Subscriptions
where
    T: ToString,
{
    fn from(value: Vec<T>) -> Self {
        Subscriptions(value.iter().map(ToString::to_string).collect())
    }
}

impl<T> From<&[T]> for Subscriptions
where
    T: ToString,
{
    fn from(value: &[T]) -> Self {
        Subscriptions(value.iter().map(ToString::to_string).collect())
    }
}

impl<T, const N: usize> From<&[T; N]> for Subscriptions
where
    T: ToString,
{
    fn from(value: &[T; N]) -> Self {
        Subscriptions(value.iter().map(ToString::to_string).collect())
    }
}

impl std::fmt::Display for Subscriptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("[{}]", self.0.join(", ")))
    }
}

#[cfg(feature = "tungstenite")]
impl From<Subscriptions> for tungstenite::Message {
    fn from(value: Subscriptions) -> Self {
        let msg = serde_json::to_string(&value).expect("conversion should never fail");
        msg.into()
    }
}

#[cfg(feature = "tungstenite")]
impl TryFrom<tungstenite::Message> for Subscriptions {
    type Error = DeserializationError;

    fn try_from(value: tungstenite::Message) -> Result<Self, Self::Error> {
        let msg = match value {
            tungstenite::Message::Text(txt) => serde_json::from_str(&txt),
            tungstenite::Message::Binary(bin) => serde_json::from_slice(&bin),
            x => return Err(DeserializationError::UnexpectedMessageType(x)),
        }
        .map_err(|e| DeserializationError::Json(e.to_string()))?;

        Ok(msg)
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use std::{
        collections::{BTreeMap, HashMap, HashSet},
        i64,
        net::IpAddr,
        str::FromStr,
    };

    use crate::{ConversionError, Data, Event, Message, ParseError, Port, Protocol, Value};
    use ipnetwork::IpNetwork;
    use serde_json::json;
    use time::{Date, Duration, OffsetDateTime, Time, UtcOffset};

    #[cfg(feature = "tungstenite")]
    use {
        crate::{DeserializationError, Subscriptions},
        tungstenite::Bytes,
    };

    #[test]
    fn from_json() -> Result<(), serde_json::Error> {
        assert_eq!(
            Message::Ack {
                endpoint: "925c9110-5b87-57d9-9d80-b65568e87a44".into(),
                version: "2.2.0-22".into()
            },
            serde_json::from_value(json!({
              "type": "ack",
              "endpoint": "925c9110-5b87-57d9-9d80-b65568e87a44",
              "version": "2.2.0-22"
            }))?
        );

        assert_eq!(
            Message::Error {
                code: "deserialization_failed".into(),
                context: "input #1 contained malformed JSON".into()
            },
            serde_json::from_value(json!({
              "type": "error",
              "code": "deserialization_failed",
              "context": "input #1 contained malformed JSON"
            }))?
        );

        assert_eq!(
            Message::new_data("/foo/bar", Event::new("pong", [42u64]),),
            serde_json::from_value(json!({
                "type": "data-message",
                "topic": "/foo/bar",
                "@data-type": "vector",
                "data": [
                    {"@data-type": "count", "data": 1},
                    {"@data-type": "count", "data": 1},
                    {"@data-type": "vector", "data": [
                        {"@data-type": "string", "data": "pong"},
                        {"@data-type": "vector", "data": [
                            {"@data-type": "count", "data": 42}]
                        }]
                    },
                ]
            }))?
        );

        assert_eq!(
            Message::new_data("/foo/bar", Data::Other(Value::Count(42))),
            serde_json::from_value(json!({
                "type": "data-message",
                "topic": "/foo/bar",
                "@data-type": "count",
                "data": 42
            }))?
        );

        Ok(())
    }

    #[cfg(feature = "tungstenite")]
    #[test]
    fn message_try_from_into_tungstenite() {
        let event = Message::new_data("my_topic", Event::new("my_event", [1]));

        let msg: tungstenite::Message = event.clone().try_into().unwrap();
        let event2: Message = msg.try_into().unwrap();

        assert_eq!(event, event2);

        let ping = tungstenite::Message::Ping(Bytes::new());
        assert_eq!(
            Message::try_from(ping.clone()),
            Err(DeserializationError::UnexpectedMessageType(ping))
        );
    }

    #[cfg(feature = "tungstenite")]
    #[test]
    fn subscriptions_try_from_into_tungstenite() {
        let subscriptions = Subscriptions::from(&["a", "b"]);

        let msg: tungstenite::Message = subscriptions.clone().try_into().unwrap();
        let subscriptions2: Subscriptions = msg.try_into().unwrap();

        assert_eq!(subscriptions, subscriptions2);
    }

    #[test]
    fn value_from_json() {
        assert_eq!(
            Value::from(()),
            serde_json::from_value(json!({"@data-type": "none", "data": {}})).unwrap()
        );
        assert_eq!(
            Value::from(true),
            serde_json::from_value(json!({"@data-type": "boolean", "data": true})).unwrap()
        );
        assert_eq!(
            Value::from(123u64),
            serde_json::from_value(json!({"@data-type": "count", "data": 123})).unwrap()
        );
        assert_eq!(
            Value::from(-7),
            serde_json::from_value(json!({"@data-type": "integer", "data": -7})).unwrap()
        );
        assert_eq!(
            Value::from(7.5),
            serde_json::from_value(json!({"@data-type": "real", "data": 7.5})).unwrap()
        );
        assert_eq!(
            Value::from(Duration::milliseconds(1500)),
            serde_json::from_value(json!({"@data-type": "timespan", "data": "1500ms"})).unwrap()
        );
        assert_eq!(
            Value::from({
                // Change the offset to the local offset since Zeek interprets timestamps in local time.
                OffsetDateTime::new_in_offset(
                    Date::from_calendar_date(2022, time::Month::April, 10).unwrap(),
                    Time::from_hms(7, 0, 0).unwrap(),
                    UtcOffset::current_local_offset().unwrap(),
                )
            }),
            serde_json::from_value(
                json!({"@data-type": "timestamp", "data": "2022-04-10T07:00:00.000"})
            )
            .unwrap()
        );
        assert_eq!(
            Value::from("Hello World!"),
            serde_json::from_value(json!({"@data-type": "string", "data": "Hello World!"}))
                .unwrap()
        );
        assert_eq!(
            Value::EnumValue("foo".into()),
            serde_json::from_value(json!({"@data-type": "enum-value", "data": "foo"})).unwrap()
        );
        assert_eq!(
            Value::from(IpAddr::from_str("2001:db8::").unwrap()),
            serde_json::from_value(json!({"@data-type": "address", "data": "2001:db8::"})).unwrap()
        );
        assert_eq!(
            Value::from(IpNetwork::from_str("255.255.255.0/24").unwrap()),
            serde_json::from_value(json!({"@data-type": "subnet", "data": "255.255.255.0/24"}))
                .unwrap()
        );
        assert_eq!(
            Value::from(Port::from_str("8080/tcp").unwrap()),
            serde_json::from_value(json!({"@data-type": "port", "data": "8080/tcp"})).unwrap()
        );
        assert_eq!(
            Value::from(vec![Value::from(42u8), 23i32.into()]),
            serde_json::from_value(json!({
                "@data-type": "vector",
                "data": [
                  {
                    "@data-type": "count",
                    "data": 42
                  },
                  {
                    "@data-type": "integer",
                    "data": 23
                  }
            ]}))
            .unwrap()
        );
        assert_eq!(
            Value::Set(["foo".into(), "bar".into()].into_iter().collect()),
            serde_json::from_value(json!({
                "@data-type": "set",
                "data": [
                  {
                    "@data-type": "string",
                    "data": "foo"
                  },
                  {
                    "@data-type": "string",
                    "data": "bar"
                  }
            ]}))
            .unwrap()
        );
        assert_eq!(
            Value::Table(
                [
                    ("first-name".into(), "John".into()),
                    ("last-name".into(), "Doe".into())
                ]
                .into_iter()
                .collect()
            ),
            serde_json::from_value(json!({
               "@data-type": "table",
               "data": [
                 {
                   "key": {
                     "@data-type": "string",
                     "data": "first-name"
                   },
                   "value": {
                     "@data-type": "string",
                     "data": "John"
                   }
                 },
                 {
                   "key": {
                     "@data-type": "string",
                     "data": "last-name"
                   },
                   "value": {
                     "@data-type": "string",
                     "data": "Doe"
                   }
                 }
               ]
            }))
            .unwrap()
        );

        let data = Value::Count(42);
        let json = serde_json::to_string(&Data::Other(data.clone())).unwrap();
        assert_eq!(data, serde_json::from_str(&json).unwrap());
    }

    #[test]
    fn try_into() {
        assert_eq!(Value::from(true).try_into(), Ok(true));
        assert_eq!(Value::from(0u64).try_into(), Ok(0u64));
        assert_eq!(Value::from(0u64).try_into(), Ok(0u32));
        assert_eq!(Value::from(0u64).try_into(), Ok(0u16));
        assert_eq!(Value::from(0u64).try_into(), Ok(0u8));
        assert_eq!(Value::from(0).try_into(), Ok(0i64));
        assert_eq!(Value::from(0).try_into(), Ok(0i32));
        assert_eq!(Value::from(0).try_into(), Ok(0i16));
        assert_eq!(Value::from(0).try_into(), Ok(0i8));
        assert_eq!(Value::from(0.).try_into(), Ok(0.));

        assert_eq!(
            Value::from(Duration::seconds(1)).try_into(),
            Ok(Duration::seconds(1))
        );
        let time = OffsetDateTime::new_utc(
            Date::from_calendar_date(2022, time::Month::April, 10).unwrap(),
            Time::from_hms(0, 0, 0).unwrap(),
        );
        assert_eq!(Value::from(time).try_into(), Ok(time));

        let addr = IpAddr::from_str("::0").unwrap();
        assert_eq!(Value::from(addr).try_into(), Ok(addr));

        let network = IpNetwork::new(addr, 8).unwrap();
        assert_eq!(Value::from(network).try_into(), Ok(network));

        let port = Port::new(42, Protocol::TCP);
        assert_eq!(Value::from(port).try_into(), Ok(port));

        let not_string: Result<String, _> = Value::from(0).try_into();
        assert_eq!(not_string, Err(ConversionError::MismatchedTypes));

        let outside_range: Result<i8, _> = Value::from(i64::MAX).try_into();
        let err = i8::try_from(i64::MAX).err().unwrap();
        assert_eq!(outside_range, Err(ConversionError::Domain(Box::new(err))));
    }

    #[test]
    fn port() {
        let p = Port::new(8080, Protocol::TCP);
        assert_eq!(p.number(), 8080);
        assert_eq!(p.protocol(), Protocol::TCP);

        assert_eq!(serde_json::to_string(&p).unwrap(), r#""8080/tcp""#);
        assert_eq!(p, "8080/tcp".parse().unwrap());

        assert_eq!(
            Err(ParseError::InvalidPort("foo".into())),
            "foo".parse::<Port>()
        );
        assert_eq!(
            Err(ParseError::InvalidPortNumber("1234567890".into())),
            "1234567890/tcp".parse::<Port>()
        );
    }

    #[test]
    fn protocol() {
        assert_eq!(Protocol::from_str("tcp"), Ok(Protocol::TCP));
        assert_eq!(Protocol::from_str("udp"), Ok(Protocol::UDP));
        assert_eq!(Protocol::from_str("icmp"), Ok(Protocol::ICMP));
        assert_eq!(Protocol::from_str("?"), Ok(Protocol::UNKNOWN));
        assert_eq!(
            Protocol::from_str("foo"),
            Err(ParseError::InvalidProtocol("foo".into()))
        );

        assert_eq!(Protocol::TCP.to_string(), "tcp");
        assert_eq!(Protocol::UDP.to_string(), "udp");
        assert_eq!(Protocol::ICMP.to_string(), "icmp");
        assert_eq!(Protocol::UNKNOWN.to_string(), "?");
    }

    #[test]
    fn set() {
        let table: HashSet<_, _> = [1, 2, 3].iter().copied().collect();
        let Value::Set(xs) = Value::from(table) else {
            panic!()
        };
        assert_eq!(xs.len(), 3);
    }

    #[test]
    fn table() {
        assert_eq!(
            serde_json::from_value::<Value>(json!({"@data-type":"table", "data": []})).unwrap(),
            Value::Table(BTreeMap::default())
        );

        assert_eq!(
            serde_json::from_value::<Value>(json!({
            "@data-type":"table",
            "data": [{
                "key":{
                    "@data-type":"string",
                    "data": "one",
                },
                "value":{
                    "@data-type":"count",
                    "data": 1,
                }
            }]}))
            .unwrap(),
            Value::Table([("one".into(), 1u8.into())].into_iter().collect())
        );

        let table: HashMap<_, _> = [(1, 11), (2, 22), (3, 33)].iter().copied().collect();
        let Value::Table(xs) = Value::from(table) else {
            panic!()
        };
        assert_eq!(xs.len(), 3);
    }

    #[test]
    fn timespan() {
        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "1ns" }))
                .unwrap(),
            Value::from(Duration::nanoseconds(1))
        );
        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "1ms" }))
                .unwrap(),
            Value::from(Duration::milliseconds(1))
        );
        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "1s" }))
                .unwrap(),
            Value::from(Duration::seconds(1))
        );
        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "1min" }))
                .unwrap(),
            Value::from(Duration::minutes(1))
        );
        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "1h" }))
                .unwrap(),
            Value::from(Duration::hours(1))
        );
        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "1d" }))
                .unwrap(),
            Value::from(Duration::days(1))
        );

        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "-42s" }))
                .unwrap(),
            Value::from(Duration::seconds(-42))
        );

        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "1us" }))
                .err()
                .unwrap()
                .to_string(),
            r"invalid timespan unit 'us'"
        );
        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "-1-1s" }))
                .err()
                .unwrap()
                .to_string(),
            r"invalid digit found in string"
        );

        assert_eq!(
            serde_json::to_string(&Value::from(Duration::nanoseconds(12))).unwrap(),
            serde_json::to_string(&json!({"@data-type": "timespan", "data": "12ns"})).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&Value::from(Duration::seconds(12))).unwrap(),
            serde_json::to_string(&json!({"@data-type": "timespan", "data": "12s"})).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&Value::from(
                Duration::weeks(52 * 100_000_000) + Duration::nanoseconds(1)
            ))
            .err()
            .unwrap()
            .to_string(),
            "value not representable: '36400000000d1ns' needs nanosecond accuracy but exceeds its range"
        );
    }

    #[test]
    fn timestamp() {
        let value = Value::from(OffsetDateTime::new_in_offset(
            Date::from_calendar_date(2014, time::Month::August, 12).unwrap(),
            Time::from_hms_nano(1, 2, 3, 4).unwrap(),
            UtcOffset::current_local_offset().unwrap(),
        ));

        let json = json!(
            {"@data-type": "timestamp", "data":"2014-08-12T01:02:03.000000004"}
        );

        assert_eq!(
            serde_json::to_string(&value).unwrap(),
            serde_json::to_string(&json).unwrap()
        );

        assert_eq!(serde_json::from_value::<Value>(json).unwrap(), value);

        assert_eq!(
            serde_json::from_value::<Value>(
                json!({"@data-type": "timestamp", "data":"2014-99-99T01:02:03.000000004"}),
            )
            .err()
            .unwrap()
            .to_string(),
            "the 'month' component could not be parsed"
        );
    }
}
