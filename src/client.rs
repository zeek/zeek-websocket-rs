//! Client implementation
//!
//! # Tokio-based clients for the Zeek WebSocket API
//!
//! This module provides a trait [`ZeekClient`] and a [`Service`] which can be used to create full
//! asynchronous clients for the Zeek WebSocket API under [`tokio`]. Users implement `ZeekClient`
//! to specify the runtime behavior of the client. After implementing `ZeekClient` for a client
//! type it needs to be wrapped in a `Service`, e.g.,
//!
//! ```
//! # use zeek_websocket::client::*;
//! struct Client {
//!     outbox: Option<Outbox>
//! }
//!
//! impl ZeekClient for Client {
//!     async fn connected(&mut self, _endpoint: String, _version: String) {}
//!     async fn event(&mut self, _topic: String, _event: zeek_websocket::Event) {}
//!     async fn error(&mut self, _error: zeek_websocket::protocol::ProtocolError) {}
//! }
//!
//! let service = Service::new(|outbox| Client {
//!     outbox: Some(outbox)
//! });
//! ```
//!
//! [`Service::new`] passes along an [`Outbox`] which can be used to publish (topic, [`Event`])
//! tuples to Zeek with `Outbox::send`. Clients should store the `Outbox` since after it is
//! dropped the `Service` will close the connection to Zeek; one way to control the lifetime of the
//! API connection is to store an `Option<Outbox>` in the client so it can explicitly be reset to
//! `None`.
//!
//! The service needs to explicitly be started with [`Service::serve`] which will return a `Future`
//! which will become ready once the service has terminated, either due to connection shutdown or a
//! fatal error.
//!
//! ## Example
//!
//! This example implements a client which publishes an event to Zeek and waits for the response
//! before exiting. The hypothetical event here is `echo`,
//!
//! ```zeek
//! global echo: event(message: string);
//! ```
//!
//! and the server will publish back the event on the same topic. Since the client is subscribed on
//! the topic it publishes to it will see the response, and can then reset its internally held
//! `Outbox` to signal to the `Service` that the connection should be closed.
//!
//! ```
//! # use zeek_websocket::client::*;
//! # use zeek_websocket::*;
//! struct Client {
//!     outbox: Option<Outbox>,
//! };
//!
//! impl ZeekClient for Client {
//!     async fn connected(&mut self, endpoint: String, version: String) {
//!         // Once connected send a single echo event. The server will send
//!         // the event back to us.
//!         if let Some(outbox) = &self.outbox {
//!             outbox
//!                 .send("/topic".to_owned(), Event::new("echo", ["hello!"]))
//!                 .await
//!                 .unwrap();
//!         }
//!     }
//!
//!     async fn event(&mut self, topic: String, event: Event) {
//!         // If we see the `echo` event from the server drop our `outbox`.
//!         // This will cause the service to terminate.
//!         if &event.name == "echo" {
//!             self.outbox.take();
//!         }
//!     }
//!
//!     async fn error(&mut self, error: protocol::ProtocolError) {
//!         todo!()
//!     }
//! }
//!
//! # let rt = tokio::runtime::Builder::new_multi_thread()
//! #     .enable_io()
//! #     .build()
//! #     .unwrap();
//! # rt.block_on(async move {
//! let uri = "ws://localhost:8080/v1/messages/json".try_into().unwrap();
//! # let uri: tungstenite::http::Uri = uri;
//! # let zeek = zeek_websocket::test::MockServer::default();
//! # let uri = zeek.endpoint().clone();
//!
//! let service = Service::new(|outbox| Client {
//!     outbox: Some(outbox),
//! });
//!
//! service
//!     .serve(
//!         "my-client",
//!         uri,
//!         Subscriptions::from(&["/topic"]),
//!     )
//!     .await.unwrap();
//! # });
//! ```

use std::num::NonZeroUsize;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc::{self};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{self, http::Uri},
};
use tungstenite::{
    ClientRequestBuilder, Utf8Bytes,
    protocol::{CloseFrame, frame::coding::CloseCode},
};
use zeek_websocket_types::{DeserializationError, Event, Message, Subscriptions};

use crate::{
    Binding,
    protocol::{self},
};

/// Runtime for a [`ZeekClient`].
pub struct Service<S> {
    client: S,
    rx: mpsc::Receiver<(String, Event)>,
}

impl<C: ZeekClient> Service<C> {
    /// Construct a new service which the given configuration. The returned `Service` needs to be
    /// started with [`Service::serve`].
    #[allow(clippy::needless_pass_by_value)]
    pub fn new_with_config<F>(config: ServiceConfig, init: F) -> Self
    where
        F: FnOnce(Outbox) -> C,
    {
        let (tx, rx) = mpsc::channel(config.outbox_size.into());
        let client = init(Outbox(tx));
        Self { client, rx }
    }

    /// Constructs a new service with the default configuration. See
    /// [`Service::new_with_config`] and [`ServiceConfig::default`] for more details.
    pub fn new<F>(init: F) -> Self
    where
        F: FnOnce(Outbox) -> C,
    {
        // We give the client a channel of size `1` for publishing. This prevents the client from
        // overwhelming the service loop with too much data. We could probably also pick a slightly
        // bigger number for less backpressure.

        Self::new_with_config(ServiceConfig::default(), init)
    }

    /// Run the client against the server until either
    ///
    /// - the client drops its event sender, or
    /// - we encounter a fatal error.
    ///
    /// # Errors
    ///
    /// We return errors for
    ///
    /// - transport-related issues which are not recoverable
    /// - errors to deserialize messages
    pub async fn serve<S, T>(mut self, app_name: S, uri: Uri, subscriptions: T) -> Result<(), Error>
    where
        S: Into<String>,
        T: Into<Subscriptions>,
    {
        let request = ClientRequestBuilder::new(uri).with_header("X-Application-Name", app_name);

        let (mut stream, ..) = connect_async(request)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        let mut binding = Binding::new(subscriptions);

        // Handle subscription.
        while let Some(x) = binding.outgoing() {
            stream.send(x.into()).await?;
        }

        loop {
            let Some(ack) = stream.next().await else {
                // The server closed the connection.
                return Ok(());
            };

            let ack = ack.map_err(|e| Error::Transport(e.to_string()))?;
            if ack.is_ping() {
                continue;
            }

            match ack.try_into()? {
                zeek_websocket_types::Message::Ack { endpoint, version } => {
                    self.client.connected(endpoint, version).await;
                    break;
                }
                message => {
                    return Err(Error::Transport(format!("expected ACK, got '{message:?}'")));
                }
            }
        }

        loop {
            tokio::select! {
                s = self.rx.recv() => {
                    let Some((topic, event)) = s else {
                        // Sender closed, graceful exit.
                        stream
                            .send(tungstenite::Message::Close(Some(CloseFrame {
                                code: CloseCode::Normal,
                                reason: Utf8Bytes::default(),
                            })))
                            .await?;
                        break;
                    };

                    binding.publish_event(topic, event);

                    while let Some(x) = binding.outgoing() {
                        stream.send(x.into()).await?;
                    }
                }

                r = stream.next() => {
                    let Some(r) = r else {
                        // Connection closed, graceful exit.
                        break;
                    };

                    let r = r.map_err(|e| Error::Transport(e.to_string()))?;
                    if r.is_ping() {
                        continue;
                    }

                    let m: Message = match r.try_into() {
                        Ok(m) => m,
                        Err(e) => {
                            self.client.error(e.into()).await;
                            continue;
                        }
                    };

                    binding.handle_incoming(m)?;

                    while let Some(received) = binding.receive_event().transpose() {
                        match received {
                            Ok((topic, event)) => self.client.event(topic, event).await,
                            Err(e) => self.client.error(e).await,
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Handle for publishing into a [`Service`].
///
/// This is intended to be held by implementers of [`ZeekClient`] to publish events to Zeek, and
/// is created during e.g., [`Service::new`]. `Service` holds on to the receiving side and will keep
/// checking it. Dropping the `Outbox` indicates to the `Service` that the client is done and will
/// cause it to terminate, so clients should hold the `Outbox` for as long as they intend to stay
/// connected, and explicitly `drop` it.
#[derive(Clone)]
pub struct Outbox(mpsc::Sender<(String, Event)>);

impl Outbox {
    /// Enqueue an event on the given topic.
    ///
    /// # Errors
    ///
    /// Returns back the enqueued event when the outbox has been closed.
    pub async fn send(&self, topic: String, event: Event) -> Result<(), (String, Event)> {
        self.0.send((topic, event)).await.map_err(|e| e.0)
    }
}

/// Configuration for a [`Service`].
#[derive(Debug, PartialEq)]
pub struct ServiceConfig {
    /// The number of entries which can be enqueue in the outbox.
    pub outbox_size: NonZeroUsize,
}

impl Default for ServiceConfig {
    /// Constructs a default service configuration.
    ///
    /// ```
    /// # use std::num::NonZeroUsize;
    /// # use zeek_websocket::client::ServiceConfig;
    /// assert_eq!(
    ///     ServiceConfig::default(),
    ///     ServiceConfig {
    ///         outbox_size: NonZeroUsize::new(256).unwrap(),
    ///     },
    /// );
    /// ```
    fn default() -> Self {
        Self {
            outbox_size: unsafe { NonZeroUsize::new_unchecked(256) },
        }
    }
}

pub trait ZeekClient {
    /// Callback invoked when we have finished the handshake with the server.
    fn connected(
        &mut self,
        endpoint: String,
        version: String,
    ) -> impl std::future::Future<Output = ()> + Send;

    /// Callback invoked when an event is received.
    fn event(
        &mut self,
        topic: String,
        event: Event,
    ) -> impl std::future::Future<Output = ()> + Send;

    /// Callback invoked when an error is received.
    fn error(
        &mut self,
        error: protocol::ProtocolError,
    ) -> impl std::future::Future<Output = ()> + Send;
}

/// Error enum for client-related errors.
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("failure in websocket transport: {0}")]
    Transport(String),

    #[error("protocol-related error: {0}")]
    ProtocolError(#[from] protocol::ProtocolError),
}

impl From<tungstenite::Error> for Error {
    fn from(value: tungstenite::Error) -> Self {
        Self::Transport(value.to_string())
    }
}

impl From<DeserializationError> for Error {
    fn from(value: DeserializationError) -> Self {
        Self::ProtocolError(value.into())
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use tokio::sync::mpsc::{self};
    use zeek_websocket_types::{Event, Subscriptions};

    use crate::{
        client::{Error, Outbox, Service, ZeekClient},
        protocol::ProtocolError,
        test::MockServer,
    };

    #[tokio::test]
    async fn unreachable_remote() {
        struct Client {
            #[allow(unused)]
            outbox: Outbox,
        }

        impl ZeekClient for Client {
            async fn connected(&mut self, _endpoint: String, _version: String) {}
            async fn event(&mut self, _topic: String, _event: Event) {}
            async fn error(&mut self, _error: ProtocolError) {}
        }

        let service = Service::new(|outbox| Client { outbox });

        let status = service
            .serve(
                "foo",
                "ws://localhost:1".try_into().unwrap(),
                Subscriptions::default(),
            )
            .await;
        assert!(matches!(status, Err(Error::Transport(_))), "{status:?}");
    }

    #[tokio::test]
    async fn echo() {
        static TOPIC: &str = "/topic";

        struct C {
            outbox: Outbox,
            seen_events: mpsc::Sender<(String, Event)>,
        }

        impl C {
            fn new(outbox: Outbox, seen_events: mpsc::Sender<(String, Event)>) -> Self {
                Self {
                    outbox,
                    seen_events,
                }
            }
        }

        impl ZeekClient for C {
            async fn connected(&mut self, _endpoint: String, _version: String) {
                self.outbox
                    .send(TOPIC.into(), Event::new("echo", [42]))
                    .await
                    .unwrap();
            }

            async fn event(&mut self, topic: String, event: Event) {
                eprintln!("Event {topic:?}: {event:?}");
                self.seen_events.send((topic, event)).await.unwrap();
            }

            async fn error(&mut self, error: ProtocolError) {
                eprintln!("Error: {error:?}");
            }
        }

        let zeek = MockServer::default();

        let (seen, mut events) = mpsc::channel(1);

        let service = Service::new(|sender| C::new(sender, seen));

        tokio::select! {
            Some((topic, event)) = events.recv() => {
                eprintln!("Event {topic:?}: {event:?}");
            }
            s = service.serve("foo", zeek.endpoint().clone(), Subscriptions::from(&[TOPIC])) => {
                unreachable!("We should have received an event but instead the service returned with {s:?}");
            }
        }
    }
}
