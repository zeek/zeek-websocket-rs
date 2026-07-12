use futures_util::{SinkExt, StreamExt};
use std::{collections::HashSet, thread::JoinHandle};
use tungstenite::http::Uri;
use zeek_websocket_types::Subscriptions;

use tokio::net::TcpListener;

/// A mock server which can accept a single connection.
///
/// The only supported event is `echo` which simply sends back all received data if the client was subscribed to the topic.
pub struct MockServer {
    _handle: JoinHandle<()>,
    endpoint: Uri,
}

impl Default for MockServer {
    #[allow(clippy::missing_panics_doc)]
    fn default() -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);

        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_io()
                .build()
                .expect("could not build runtime");

            rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("could not listen");
                let addr = listener.local_addr().expect("local_addr should be set");
                tx.send(addr).expect("could not broadcast addr");

                while let Ok((stream, _)) = listener.accept().await {
                    if let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await {
                        let mut subscriptions = HashSet::new();

                        while let Some(msg) = ws.next().await {
                            match msg {
                                Ok(msg) => {
                                    if let Ok(Subscriptions(sub)) = msg.clone().try_into() {
                                        subscriptions = sub.into_iter().collect();

                                        if ws
                                            .send(
                                                crate::Message::Ack {
                                                    endpoint: "mock-server".to_owned(),
                                                    version: "0.0.1".to_owned(),
                                                }
                                                .into(),
                                            )
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                    } else if let Ok(crate::Message::DataMessage {
                                        topic,
                                        data: crate::Data::Event(crate::Event { name, args, .. }),
                                    }) = msg.try_into()
                                    {
                                        if !subscriptions.contains(&topic) {
                                            continue;
                                        }

                                        if name == "echo" {
                                            let event = crate::Event::new(name, args);
                                            let data = crate::Message::DataMessage {
                                                topic,
                                                data: event.into(),
                                            };

                                            if ws.send(data.into()).await.is_err() {
                                                break;
                                            }
                                        }
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
            });
        });

        let addr = rx.recv().expect("could not get addr");
        let endpoint = format!("ws://{addr:?}")
            .try_into()
            .expect("uri should be valid");

        Self {
            _handle: handle,
            endpoint,
        }
    }
}

impl MockServer {
    #[must_use]
    pub fn endpoint(&self) -> &Uri {
        &self.endpoint
    }
}

#[allow(clippy::module_inception, clippy::unwrap_used)]
#[cfg(test)]
mod test {
    use zeek_websocket_types::{Event, Message, Subscriptions};

    use crate::test::MockServer;

    #[test]
    fn echo() {
        let mock = MockServer::default();
        let (mut conn, _) = tungstenite::connect(mock.endpoint()).unwrap();

        // Subscribe.
        let topic = "/topic".to_owned();
        conn.send(Subscriptions::from(&[&topic]).into()).unwrap();
        assert!(matches!(
            conn.read().unwrap().try_into(),
            Ok(Message::Ack { .. })
        ));

        // Validate that the server echos data back to us.
        let echo = Event::new("echo", vec![1]);
        let data = Message::new_data(&topic, echo);
        conn.send(data.clone().into()).unwrap();
        assert_eq!(conn.read().unwrap().try_into(), Ok(data));
    }
}
