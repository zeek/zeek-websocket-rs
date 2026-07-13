//! # Sans I/O-style protocol wrapper for the Zeek API
//!
//! Instead of providing a full-fledged client [`Binding`] encapsulates the Zeek WebSocket
//! protocol [sans I/O style](https://sans-io.readthedocs.io/). It provides the following methods:
//!
//! - [`Binding::handle_incoming`] injects data received over a network connection into the
//!   `Binding` object
//! - [`Binding::receive_event`] gets the next event received from Zeek
//! - [`Binding::publish_event`] to publish an event to Zeek
//! - [`Binding::outgoing`] gets the next data payload for sending to Zeek
//!
//! A full client implementation will typically implement some form of event loop.
//!
//! ## Example
//!
//! ```no_run
//! use zeek_websocket::*;
//!
//! # fn main() -> anyhow::Result<()> {
//! // Open an underlying WebSocket connection to a Zeek endpoint.
//! let (mut socket, _) = tungstenite::connect("ws://127.0.0.1:8080/v1/messages/json")?;
//!
//! // Create a connection.
//! let mut conn = Binding::new(&["/ping"]);
//!
//! // The event loop.
//! loop {
//!     // If we have any outgoing messages send at least one.
//!     if let Some(data) = conn.outgoing() {
//!         socket.send(tungstenite::Message::binary(data))?;
//!     }
//!
//!     // Receive the next message and handle it.
//!     if let Ok(msg) = socket.read()?.try_into() {
//!         conn.handle_incoming(msg);
//!     }
//!
//!     // If we received a `ping` event, respond with a `pong`.
//!     if let Some((topic, event)) = conn.receive_event()? {
//!         if event.name == "ping" {
//!             conn.publish_event(topic, Event::new("pong", event.args));
//!         }
//!     }
//! }
//! # }
//! ```

use std::collections::VecDeque;

use thiserror::Error;
use tungstenite::Bytes;
use zeek_websocket_types::{Data, DeserializationError, Event, Message, Value};

use crate::types::Subscriptions;

/// Protocol wrapper for a Zeek WebSocket connection.
///
/// See the [module documentation](crate::protocol) for an introduction
pub struct Binding {
    state: State,

    inbox: Inbox,
    outbox: Outbox,
}

enum State {
    Subscribing,
    Subscribed,
}

impl Binding {
    /// Create a new `Binding` with the given [`Subscriptions`].
    ///
    /// ```
    /// # use zeek_websocket::Binding;
    /// let conn = Binding::new(&["topic"]);
    /// ```
    #[must_use]
    pub fn new<S>(subscriptions: S) -> Self
    where
        S: Into<Subscriptions>,
    {
        let subscriptions = subscriptions.into();
        Self {
            state: State::Subscribing,
            inbox: Inbox(VecDeque::new()),
            outbox: Outbox(VecDeque::from([subscriptions.into()])),
        }
    }

    /// Handle received message.
    ///
    /// # Errors
    ///
    /// - returns a [`ProtocolError::AlreadySubscribed`] if we saw an unexpected ACK.
    /// - returns a [`ProtocolError::UnexpectedEventPayload`] if an unexpected event payload was seen
    pub fn handle_incoming(&mut self, message: Message) -> Result<(), ProtocolError> {
        match &message {
            Message::Ack { .. } => match self.state {
                State::Subscribing => {
                    self.state = State::Subscribed;
                }
                State::Subscribed => return Err(ProtocolError::AlreadySubscribed),
            },
            Message::DataMessage {
                data: Data::Other(unexpected),
                ..
            } => {
                return Err(ProtocolError::UnexpectedEventPayload(unexpected.clone()));
            }
            _ => {
                self.inbox.handle(message);
            }
        }

        Ok(())
    }

    /// Get next data enqueued for sending.
    pub fn outgoing(&mut self) -> Option<Bytes> {
        self.outbox.next_data()
    }

    /// Get the next incoming event.
    ///
    /// # Errors
    ///
    /// - returns a [`ProtocolError::ZeekError`] if an error was received from Zeek
    pub fn receive_event(&mut self) -> Result<Option<(String, Event)>, ProtocolError> {
        if let Some(message) = self.inbox.next_message() {
            match message {
                Message::DataMessage { topic, data } => {
                    let event = match data {
                        Data::Event(event) => event,
                        Data::Other(..) => unreachable!(), // Rejected in `handle_incoming`.
                    };
                    return Ok(Some((topic, event)));
                }
                Message::Error { code, context } => {
                    return Err(ProtocolError::ZeekError { code, context });
                }
                Message::Ack { .. } => {
                    unreachable!() // Never forwarded from `handle_incoming`.
                }
            }
        }

        Ok(None)
    }

    /// Enqueue a message for sending.
    fn enqueue(&mut self, message: Message) {
        match message {
            Message::DataMessage { topic, data } => {
                self.outbox.enqueue(Message::DataMessage { topic, data });
            }
            _ => self.outbox.enqueue(message),
        }
    }

    /// Enqueue an event for sending.
    pub fn publish_event<S>(&mut self, topic: S, event: Event)
    where
        S: Into<String>,
    {
        self.enqueue(Message::new_data(topic.into(), event));
    }

    /// Split the `Binding` into an [`Inbox`] and [`Outbox`].
    ///
    /// <div class="warning">
    /// The returned <code>Inbox</code> and <code>Outbox</code> do not enforce correct use of the protocol.
    /// </div>
    #[must_use]
    pub fn split(self) -> (Inbox, Outbox) {
        (self.inbox, self.outbox)
    }
}

/// Receiving side of a [`Binding`].
pub struct Inbox(VecDeque<Message>);

impl Inbox {
    /// Handle received message.
    pub fn handle(&mut self, message: Message) {
        self.0.push_back(message);
    }

    /// Get next incoming message.
    #[must_use]
    pub fn next_message(&mut self) -> Option<Message> {
        self.0.pop_front()
    }

    /// Get the next event.
    ///
    /// In contrast to [`Inbox::next_message`] this discards any non-`Event` messages which were received.
    pub fn next_event(&mut self) -> Option<(String, Event)> {
        while let Some(message) = self.next_message() {
            if let Message::DataMessage {
                topic,
                data: Data::Event(event),
            } = message
            {
                return Some((topic, event));
            }
        }

        None
    }
}

/// Sending side of [`Binding`].
pub struct Outbox(VecDeque<tungstenite::Message>);

impl Outbox {
    /// Get next data enqueued for sending.
    pub fn next_data(&mut self) -> Option<Bytes> {
        self.0.pop_front().map(tungstenite::Message::into_data)
    }

    /// Enqueue a new message.
    pub fn enqueue<M>(&mut self, message: M)
    where
        M: Into<tungstenite::Message>,
    {
        self.0.push_back(message.into());
    }

    /// Enqueue an event for sending.
    pub fn enqueue_event<S>(&mut self, topic: S, event: Event)
    where
        S: Into<String>,
    {
        self.enqueue(Message::new_data(topic.into(), event));
    }
}

/// Error enum for protocol-related errors.
#[derive(Error, Debug, PartialEq)]
pub enum ProtocolError {
    #[error("received an ACK while already subscribed")]
    AckExpected,

    #[error("received an ACK while already subscribed")]
    AlreadySubscribed,

    #[error("Zeek error {code}: {context}")]
    ZeekError { code: String, context: String },

    #[error("unexpected event payload received")]
    UnexpectedEventPayload(Value),

    #[error("could not deserialize message: {0}")]
    DeserializationError(#[from] DeserializationError),
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use crate::{
        protocol::{Binding, ProtocolError},
        types::{Data, Event, Message, Subscriptions, Value},
    };

    fn ack() -> Message {
        Message::Ack {
            endpoint: "mock".into(),
            version: "0.1".into(),
        }
    }

    #[test]
    fn recv() {
        let topic = "foo";

        let mut conn = Binding::new(&[topic]);

        // Nothing received yet,
        assert_eq!(conn.inbox.next_message(), None);

        // Handle subscription.
        Subscriptions::try_from(tungstenite::Message::binary(conn.outgoing().unwrap())).unwrap();
        conn.handle_incoming(ack()).unwrap();

        // No new input received.
        assert_eq!(conn.inbox.next_message(), None);
        assert_eq!(conn.receive_event(), Ok(None));

        // Receive a single event.
        conn.handle_incoming(Message::new_data(topic, Event::new("ping", [(); 0])))
            .unwrap();

        assert!(matches!(
            conn.inbox.next_message(),
            Some(Message::DataMessage {
                data: Data::Event(..),
                ..
            })
        ));
    }

    #[test]
    fn send() {
        let mut conn = Binding::new(&["foo"]);

        // Handle subscription.
        Subscriptions::try_from(tungstenite::Message::binary(conn.outgoing().unwrap())).unwrap();
        conn.handle_incoming(ack()).unwrap();

        // Send an event.
        conn.publish_event("foo", Event::new("ping", [(); 0]));

        // Event payload should be in outbox.
        let msg =
            Message::try_from(tungstenite::Message::binary(conn.outgoing().unwrap())).unwrap();
        assert!(matches!(
            msg,
            Message::DataMessage {
                data: Data::Event(..),
                ..
            }
        ));
    }

    #[test]
    fn split() {
        let (mut inbox, mut outbox) = Binding::new(&["foo"]).split();

        // Handle subscription.
        Subscriptions::try_from(tungstenite::Message::binary(outbox.next_data().unwrap())).unwrap();
        inbox.handle(ack());

        assert!(matches!(inbox.next_message(), Some(Message::Ack { .. })));
    }

    #[test]
    fn duplicate_ack() {
        let mut conn = Binding::new(&["foo"]);

        // Handle subscription. The call to `handle_incoming` consumes the ACK.
        Subscriptions::try_from(tungstenite::Message::binary(conn.outgoing().unwrap())).unwrap();
        conn.handle_incoming(ack()).unwrap();

        // Detect if we see another, unexpected ACK.
        assert_eq!(
            conn.handle_incoming(ack()),
            Err(ProtocolError::AlreadySubscribed)
        );
    }

    #[test]
    fn other_event_payload() {
        let mut conn = Binding::new(&["foo"]);
        conn.handle_incoming(ack()).unwrap();

        let other = Message::new_data("foo", Value::Count(42));
        assert_eq!(
            conn.handle_incoming(other),
            Err(ProtocolError::UnexpectedEventPayload(Value::Count(42)))
        );
    }

    #[test]
    fn next_incoming() {
        let mut conn = Binding::new(Subscriptions::default());

        // Put an ACK and an event into the inbox.
        let _ = conn.handle_incoming(ack());
        let _ = conn.handle_incoming(Message::new_data("topic", Event::new("ping", [(); 0])));

        // Event though we have an ACK in the inbox `receive_event`
        // discards it and returns the event.
        let (topic, event) = conn.receive_event().unwrap().unwrap();
        assert_eq!(topic, "topic");
        assert_eq!(event.name, "ping");

        assert_eq!(conn.inbox.next_message(), None);
    }

    #[test]
    fn error() {
        let mut conn = Binding::new(&["foo"]);
        conn.handle_incoming(ack()).unwrap();

        conn.handle_incoming(Message::Error {
            code: "code".to_string(),
            context: "context".to_string(),
        })
        .unwrap();

        assert_eq!(
            conn.receive_event(),
            Err(ProtocolError::ZeekError {
                code: "code".to_string(),
                context: "context".to_string()
            })
        );
    }

    #[test]
    fn publish_event() {
        let mut conn = Binding::new(&["foo"]);
        // Consume the subscription.
        conn.outgoing().unwrap();

        conn.publish_event("foo", Event::new("ping", [(); 0]));
        let message =
            Message::try_from(tungstenite::Message::binary(conn.outgoing().unwrap())).unwrap();
        let Message::DataMessage {
            topic,
            data: Data::Event(event),
        } = message
        else {
            panic!()
        };
        assert_eq!(topic, "foo");
        assert_eq!(event.name, "ping");
    }
}
