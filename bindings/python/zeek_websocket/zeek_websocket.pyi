import datetime
from abc import abstractmethod
from collections.abc import Mapping, Sequence
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, TypeAlias, TypeVar

class ZeekClient:
    """Abstract base class to connect to the Zeek WebSocket API.

    Users are expected to implement the following async methods:

    ```python
    async def connected(self, ack: dict[str, str]) -> None: ...
    async def event(self, topic: str, event: Event) -> None: ...
    async def error(self, error: str) -> None: ...
    ```
    """

    @abstractmethod
    async def connected(self, endpoint: str, version: str) -> None:
        """Handle client subscription.

        Async abstract method which must be implemented by derived classes.
        """
        ...

    @abstractmethod
    async def event(self, topic: str, event: Event) -> None:
        """Handle a received event.

        Async abstract method which must be implemented by derived classes.
        """
        ...

    @abstractmethod
    async def error(self, error: str) -> None:
        """Handle a received error.

        Async abstract method which must be implemented by derived classes.
        """
        ...

    async def publish(self, topic: str, event: Event) -> None:
        """Asynchronously send an event on the given topic.

        This function enqueues the event on a queue which is processed by a
        separate thread. Callers should release the GIL if they plan to enqueue
        many event, e.g., by using a separate task to perform the `publish` call.

        Callers should `await` the result.
        """
        ...

    def disconnect(self) -> None:
        """Disconnect the client."""
        ...

class Service:
    """A service wrapping a concrete `ZeekClient`."""

    @staticmethod
    async def run(
        client: ZeekClient, app_name: str, endpoint: str, subscriptions: list[str]
    ) -> None:
        """Run a client as a service.

        Callers should `await` the result.
        """
        ...

class Event:
    """API representation of Zeek event."""

    def __init__(
        self,
        name: str,
        args: Sequence[_ZeekSupported],
        metadata: Sequence[_ZeekSupported],
    ): ...
    def serialize_json(self) -> str:
        """Serialize to Zeek WebSocket JSON format."""
        ...

    @staticmethod
    def deserialize_json(value: str) -> Event:
        """Deserialize from Zeek WebSocket JSON format."""
        ...

    """Event name."""
    name: str

    """Event arguments."""
    args: list[Value]

    """Event metadata."""
    metadata: list[Value]

_Address: TypeAlias = IPv4Address | IPv6Address | str

_Vector: TypeAlias = list[_ZeekSupported] | Sequence[_ZeekSupported]

_Set: TypeAlias = set[_ZeekSupported] | Sequence[_ZeekSupported]

_Dict: TypeAlias = (
    dict[_ZeekSupported, _ZeekSupported] | Mapping[_ZeekSupported, _ZeekSupported]
)

T = TypeVar("T")

_UnsignedInt: TypeAlias = Annotated[int, "An integer that must be non-negative"]

_ZeekSupportedBase: TypeAlias = (
    bool
    | float
    | datetime.datetime
    | datetime.timedelta
    | _Address
    | tuple[int | Protocol]
    | _Vector
    | _Set
    | _Dict
    | str
    | None
    | Enum
    | Value
)

_ZeekSupported: TypeAlias = _ZeekSupportedBase | int | object

def make_value(data: _ZeekSupportedBase | object) -> Value:
    """Construct a new value and infers its type.

    This often does the right thing, but the mapping from Python types to Zeek
    WebSocket values is not unambiguous, e.g., a Zeek `Count` and `Integer`
    both map onto Python `int` instances, so constructing `Count` or `Integer`
    with this function is unsupported (instead we always return a `Real`). Use
    constructors of concrete types instead, e.g., `Value.Count` and
    `Value.Integer`.
    """
    ...

class Value:
    """Zeek WebSocket API representation of Python values.

    A Python representation of the `Value` can be accessed via to `value`
    attribute, e.g., for a `Value.Count` this would hold a Python `int`. For
    the container types `Value.Vector`, `Value.Set` and `Value.Table` it is a
    native Python container value holding `Value` instances, e.g.,

        x = Value.Vector[1.0, 2.0]
        x.value == [Value.Real(1.0), Value.Real(2.0)]

    Instances of `Value.Enum` hold a Python `str`, and `Value.Record` a Python
    `list[Value]` or `dict[str, Value]`; use `as_enum` and `as_record` to
    create native Python instances.

    Attributes:
        value: A Python value corresponding to the `Value`.

    """

    value: _ZeekSupportedBase

    class Address(Value):
        def __init__(self, data: _Address) -> None: ...

    class Boolean(Value):
        def __init__(self, data: bool) -> None: ...

    class Count(Value):
        def __init__(self, data: _UnsignedInt) -> None: ...

    class Enum(Value):
        def __init__(self, data: str) -> None: ...

    class Integer(Value):
        def __init__(self, data: int) -> None: ...

    class None_(Value):
        def __init__(self) -> None: ...

    class Port(Value):
        def __init__(self, num: int, proto: Protocol) -> None: ...

    class Real(Value):
        def __init__(self, data: float) -> None: ...

    class Set(Value):
        def __init__(self, data: _Set) -> None: ...

    class String(Value):
        def __init__(self, data: str) -> None: ...

    class Subnet(Value):
        def __init__(self, ip: _Address, prefix: int) -> None: ...

    class Table(Value):
        def __init__(self, data: _Dict) -> None: ...

    class Timespan(Value):
        def __init__(self, data: datetime.timedelta) -> None: ...

    class Timestamp(Value):
        def __init__(self, data: datetime.datetime) -> None: ...

    class Vector(Value):
        def __init__(self, data: _Vector) -> None: ...

    class Record(Value):
        def __init__(self, data: Mapping[str, _ZeekSupported]) -> None: ...

    def serialize_json(self) -> str:
        """Serialize to Zeek WebSocket JSON format."""
        ...

    @staticmethod
    def deserialize_json(value: str) -> Value:
        """Deserialize from Zeek WebSocket JSON format."""
        ...

    def as_enum(self, type_: type[T]) -> T | None:
        """Convert to a given target enum instance.

        `T` must refer to a class which derives from `enum.Enum` or similar.
        """
        ...

    def as_record(self, type_: type[T]) -> T | None:
        """Convert a given target class instance.

        `T` must be a dataclass.
        """
        ...

class Protocol(Enum):
    UNKNOWN = 1
    TCP = 2
    UDP = 3
    ICMP = 4

class ProtocolBinding:
    """Sans-I/O wrapper for the Zeek WebSocket protocol."""

    def __init__(self, subscriptions: Sequence[str]) -> None: ...
    def handle_incoming(self, data: bytes) -> None:
        """Handle received message."""
        ...

    def outgoing(self) -> bytes | None:
        """Get next data enqueued for sending."""
        ...

    def publish_event(self, topic: str, event: Event) -> None:
        """Enqueue an event for sending."""
        ...

    def receive_event(self) -> tuple[str, Event] | None:
        """Get the next incoming event."""
        ...
