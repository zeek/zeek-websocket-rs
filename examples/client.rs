#![allow(clippy::unwrap_used)]

use zeek_websocket::{
    Event, Subscriptions,
    client::Outbox,
    client::{Service, ZeekClient},
};

struct Client {
    outbox: Option<Outbox>,
}

impl ZeekClient for Client {
    async fn connected(&mut self, _endpoint: String, _version: String) {
        // Once connected send a single echo event. The server will send the
        // event back to use.
        if let Some(sender) = &self.outbox {
            sender
                .send("/ping".to_owned(), Event::new("ping", ["hi!"]))
                .await
                .unwrap();
        }
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn event(&mut self, _topic: String, event: zeek_websocket::Event) {
        // If we see the `pong` from the `ping` we sent when we connected, drop the sender to
        // indicate we are done.
        if &event.name == "pong" {
            self.outbox.take();
        }
    }

    async fn error(&mut self, _error: zeek_websocket::protocol::ProtocolError) {
        unimplemented!()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let service = Service::new(|sender| Client {
        outbox: Some(sender),
    });

    service
        .serve(
            "example-client",
            "ws://localhost:8080/v1/messages/json".try_into()?,
            Subscriptions::from(&["/ping"]),
        )
        .await?;

    Ok(())
}
