"""Python bindings for Zeek's WebSocket API.

The Zeek-side API wrapped here is
[here](https://docs.zeek.org/projects/broker/en/current/web-socket.html#data-representation).

See the module stub file for documentation for the provided functionality.
"""

from collections.abc import Sequence

import websockets.sync.client

from .zeek_websocket import *  # noqa: F403
from .zeek_websocket import (
    Event,
    Protocol,
    ProtocolBinding,
    Service,
    Value,
    ZeekClient,
    make_value,
)

__all__ = [
    "Client",
    "Event",
    "Protocol",
    "ProtocolBinding",
    "Service",
    "Value",
    "ZeekClient",
    "make_value",
]


class Client:
    """Client for the Zeek WebSocket API."""

    _binding: ProtocolBinding
    _conn: websockets.sync.client.ClientConnection

    def __init__(self, app_name: str, endpoint_uri: str, topics: Sequence[str]) -> None:
        """Create a client instance.

        Args:
            app_name: Identifier for this client. Zeek uses this for logging and metrics.
            endpoint_uri: Zeek endpoint to connect to. This needs to be a full
                          URI including protocol (ws or wss), hostname, and path, e.g.,
                          `ws://localhost:8080/v1/messages/json`.
            topics: Zero or more topics to subscribe to.

        """
        self._binding = ProtocolBinding(topics)

        self._conn = websockets.sync.client.connect(
            endpoint_uri,
            additional_headers={"X-Application-Name": app_name},
            legacy=True,
        )

        # Immediately send out the subscription and handle the ACK.
        while data := self._binding.outgoing():
            self._conn.send(data)

        ack = self._conn.recv(decode=False, timeout=None)
        self._binding.handle_incoming(ack)

    def publish(self, topic: str, event: Event) -> None:
        """Publish an event on a give topic."""
        self._binding.publish_event(topic, event)

        # Flush all outgoing messages.
        while data := self._binding.outgoing():
            self._conn.send(data)

    def receive(self, timeout: float | None = None) -> tuple[str, Event] | None:
        """Try to receive the next event.

        Returns the topic and the event, or `None`, or raises a `TimeoutError`.

        Args:
            timeout: How many seconds to block for the next message.

        If `timeout` is `None`, block until a message is received. If `timeout`
        is set, wait up to `timeout` seconds for a message to be received and
        return it, else raise `TimeoutError`. If `timeout` is `0` or negative,
        check if a message has been received already and return it, else raise
        `TimeoutError`.

        """
        # Forward all messages received over the WebSocket connection to our internal handling.
        data = self._conn.recv(decode=False, timeout=timeout)
        self._binding.handle_incoming(data)

        return self._binding.receive_event()
