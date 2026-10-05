from _typeshed import Incomplete
from collections.abc import Sequence
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Final, final

@final
class Event:
    """
    API representation of Zeek event.
    """
    def __eq__(self, value: object, /) -> bool: ...
    def __ne__(self, value: object, /) -> bool: ...
    def __new__(cls, /, name: str, args: Sequence[Incomplete], metadata: Sequence[Incomplete]) -> Event: ...
    def __repr__(self, /) -> str: ...
    @property
    def args(self, /) -> list[Value]:
        """
        Event arguments.
        """
    @staticmethod
    def deserialize_json(data: str) -> Event:
        """
        Deserialize from Zeek WebSocket JSON format.
        """
    @property
    def metadata(self, /) -> list[Value]:
        """
        Event metadata.
        """
    @property
    def name(self, /) -> str:
        """
        Event name.
        """
    def serialize_json(self, /) -> str:
        """
        Serialize to Zeek WebSocket JSON format.
        """

@final
class Protocol:
    ICMP: Final[Protocol]
    TCP: Final[Protocol]
    UDP: Final[Protocol]
    UNKNOWN: Final[Protocol]
    def __eq__(self, value: object, /) -> bool: ...
    def __int__(self, /) -> int: ...
    def __ne__(self, value: object, /) -> bool: ...
    def __repr__(self, /) -> str: ...

@final
class ProtocolBinding:
    """
    Sans-I/O wrapper for the Zeek WebSocket protocol.
    """
    def __new__(cls, /, subscriptions: Sequence[str]) -> ProtocolBinding: ...
    def handle_incoming(self, /, data: bytes) -> None:
        """
        Handle received message.
        """
    def outgoing(self, /) -> bytes |None:
        """
        Get next data enqueued for sending.
        """
    def publish_event(self, /, topic: str, event: Event) -> None:
        """
        Enqueue an event for sending.
        """
    def receive_event(self, /) -> tuple[str, Event] |None:
        """
        Get the next incoming event.
        """

@final
class Service:
    """
    A service wrapping a concrete `ZeekClient`.
    """
    @staticmethod
    async def run(client: ZeekClient, app_name: str, endpoint: str, subscriptions: Sequence[str]) -> None:
        """
        Run a client as a service.
        
        Callers should `await` the result.
        """

class Value:
    """
    Zeek WebSocket API representation of Python values.
    
    A Python representation of the `Value` can be accessed via to `value`
    attribute, e.g., for a `Value.Count` this would hold a Python `int`. For
    the container types `Value.Vector`, `Value.Set` and `Value.Table` it is a
    native Python container value holding `Value` instances, e.g.,
    
    ```python
    x = Value.Vector[1.0, 2.0]
    x.value == [Value.Real(1.0), Value.Real(2.0)]
    ```
    
    Instances of `Value.Enum` hold a Python `str`, and `Value.Record` a Python
    `list[Value]` or `dict[str, Value]`; use `as_enum` and `as_record` to
    create native Python instances.
    
    Attributes:
        value: A Python value corresponding to the `Value`.
    """
    def __eq__(self, value: object, /) -> bool: ...
    def __hash__(self, /) -> int: ...
    def __ne__(self, value: object, /) -> bool: ...
    def __repr__(self, /) -> str: ...
    def as_enum(self, /, target_type: type) -> Any |None:
        """
        Convert to a given target enum instance.
        
        `T` must refer to a class which derives from `enum.Enum` or similar.
        """
    def as_record(self, /, target_type: type) -> Any |None:
        """
        Convert to a given target enum instance.
        
        `T` must refer to a class which derives from `dataclass.dataclass` or similar.
        """
    @staticmethod
    def deserialize_json(data: str) -> Value:
        """
        Deserialize from Zeek WebSocket JSON format.
        """
    def serialize_json(self, /) -> str:
        """
        Serialize to Zeek WebSocket JSON format.
        """
    @property
    def value(self, /) -> Any: ...
    @final
    class Address(Value):
        __match_args__: Final = ("_0",)
        @property
        def _0(self, /) -> IPv4Address |IPv6Address: ...
        def __getitem__(self, key: int, /) -> Any: ...
        def __len__(self, /) -> int: ...
        def __new__(cls, /, _0: IPv4Address |IPv6Address) -> Value.Address: ...
    @final
    class Boolean(Value):
        __match_args__: Final = ("_0",)
        @property
        def _0(self, /) -> bool: ...
        def __getitem__(self, key: int, /) -> Any: ...
        def __len__(self, /) -> int: ...
        def __new__(cls, /, _0: bool) -> Value.Boolean: ...
    @final
    class Count(Value):
        __match_args__: Final = ("_0",)
        @property
        def _0(self, /) -> int: ...
        def __getitem__(self, key: int, /) -> Any: ...
        def __len__(self, /) -> int: ...
        def __new__(cls, /, _0: int) -> Value.Count: ...
    @final
    class Enum(Value):
        __match_args__: Final = ("_0",)
        @property
        def _0(self, /) -> str: ...
        def __getitem__(self, key: int, /) -> Any: ...
        def __len__(self, /) -> int: ...
        def __new__(cls, /, _0: str) -> Value.Enum: ...
    @final
    class Integer(Value):
        __match_args__: Final = ("_0",)
        @property
        def _0(self, /) -> int: ...
        def __getitem__(self, key: int, /) -> Any: ...
        def __len__(self, /) -> int: ...
        def __new__(cls, /, _0: int) -> Value.Integer: ...
    @final
    class None_(Value):
        __match_args__: Final = ()
        def __getitem__(self, key: int, /) -> Any: ...
        def __len__(self, /) -> int: ...
        def __new__(cls, /) -> Value.None_: ...
    @final
    class Port(Value):
        __match_args__: Final = ("_0", "_1")
        @property
        def _0(self, /) -> int: ...
        @property
        def _1(self, /) -> Protocol: ...
        def __getitem__(self, key: int, /) -> Any: ...
        def __len__(self, /) -> int: ...
        def __new__(cls, /, _0: int, _1: Protocol) -> Value.Port: ...
    @final
    class Real(Value):
        __match_args__: Final = ("_0",)
        @property
        def _0(self, /) -> float: ...
        def __getitem__(self, key: int, /) -> Any: ...
        def __len__(self, /) -> int: ...
        def __new__(cls, /, _0: float) -> Value.Real: ...
    @final
    class Record(Value):
        __match_args__: Final = ("_0",)
        @property
        def _0(self, /) -> dict[str, Value]: ...
        def __getitem__(self, key: int, /) -> Any: ...
        def __len__(self, /) -> int: ...
        def __new__(cls, /, _0: dict[str, Incomplete]) -> Value.Record: ...
    @final
    class Set(Value):
        __match_args__: Final = ("_0",)
        @property
        def _0(self, /) -> set[Value]: ...
        def __getitem__(self, key: int, /) -> Any: ...
        def __len__(self, /) -> int: ...
        def __new__(cls, /, _0: set[Incomplete]) -> Value.Set: ...
    @final
    class String(Value):
        __match_args__: Final = ("_0",)
        @property
        def _0(self, /) -> str: ...
        def __getitem__(self, key: int, /) -> Any: ...
        def __len__(self, /) -> int: ...
        def __new__(cls, /, _0: str) -> Value.String: ...
    @final
    class Subnet(Value):
        __match_args__: Final = ("_0", "_1")
        @property
        def _0(self, /) -> IPv4Address |IPv6Address: ...
        @property
        def _1(self, /) -> int: ...
        def __getitem__(self, key: int, /) -> Any: ...
        def __len__(self, /) -> int: ...
        def __new__(cls, /, _0: IPv4Address |IPv6Address, _1: int) -> Value.Subnet: ...
    @final
    class Table(Value):
        __match_args__: Final = ("_0",)
        @property
        def _0(self, /) -> dict[Value, Value]: ...
        def __getitem__(self, key: int, /) -> Any: ...
        def __len__(self, /) -> int: ...
        def __new__(cls, /, _0: dict[Incomplete, Incomplete]) -> Value.Table: ...
    @final
    class Timespan(Value):
        __match_args__: Final = ("_0",)
        @property
        def _0(self, /) -> timedelta: ...
        def __getitem__(self, key: int, /) -> Any: ...
        def __len__(self, /) -> int: ...
        def __new__(cls, /, _0: timedelta) -> Value.Timespan: ...
    @final
    class Timestamp(Value):
        __match_args__: Final = ("_0",)
        @property
        def _0(self, /) -> datetime: ...
        def __getitem__(self, key: int, /) -> Any: ...
        def __len__(self, /) -> int: ...
        def __new__(cls, /, _0: datetime) -> Value.Timestamp: ...
    @final
    class Vector(Value):
        __match_args__: Final = ("_0",)
        @property
        def _0(self, /) -> list[Value]: ...
        def __getitem__(self, key: int, /) -> Any: ...
        def __len__(self, /) -> int: ...
        def __new__(cls, /, _0: Sequence[Incomplete]) -> Value.Vector: ...

class ZeekClient:
    """
    Abstract base class to connect to the Zeek WebSocket API.
    
    Users are expected to implement the following async methods:
    
    ```python
    async def connected(self, endpoint: str, version: str) -> None: ...
    async def event(self, topic: str, event: Event) -> None: ...
    async def error(self, error: str) -> None: ...
    ```
    """
    def __new__(cls, /) -> ZeekClient: ...
    async def connected(self, /, endpoint: str, version: str) -> None:
        """
        Handle client subscription.
        
        Async abstract method which must be implemented by derived classes.
        """
    def disconnect(self, /) -> None:
        """
        Disconnect the client.
        """
    async def error(self, /, error: str) -> None:
        """
        Handle a received error.
        
        Async abstract method which must be implemented by derived classes.
        """
    async def event(self, /, topic: str, event: Event) -> None:
        """
        Handle a received event.
        
        Async abstract method which must be implemented by derived classes.
        """
    async def publish(self, /, topic: str, event: Event) -> None:
        """
        Asynchronously send an event on the given topic.
        
        This function enqueues the event on a queue which is processed by a separate thread.
        Callers should release the GIL if they plan to enqueue many event, e.g., by using a
        separate task to perform the `publish` call.
        
        Callers should `await` the result.
        """

def make_value(data: Incomplete) -> Value:
    """
    Construct a new value and infers its type.
    
    This often does the right thing, but the mapping from Python types to Zeek
    WebSocket values is not unambiguous, e.g., a Zeek `Count` and `Integer`
    both map onto Python `int` instances, so constructing `Count` or `Integer`
    with this function is unsupported (instead we always return a `Real`). Use
    constructors of concrete types instead, e.g., `Value.Count` and
    `Value.Integer`.
    """
