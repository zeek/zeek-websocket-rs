# Rust types for interacting with Zeek over WebSocket

This library provides types for interacting with [Zeek](https://zeek.org)'s
WebSocket API. See the
[docs](https://bbannier.github.io/zeek-websocket-rs/zeek_websocket/index.html)
for more details.

## Language bindings

While this is primarily a Rust library we expose bindings for
[Python](#python-bindings) and [C](#c-bindings).

### Python bindings

Python bindings are generated with [PyO3](https://github.com/PyO3/pyo3) which
makes use of Rust completely transparent to users.

We provide two ways to interact with Zeek:

- [`ZeekClient`](bindings/python/zeek_websocket/zeek_websocket.pyi) for an
  asynchronous interface
- [`Client`](bindings/python/zeek_websocket/__init__.py) for a synchronous
  interface

If possible we suggest to use `ZeekClient`.

Both `ZeekClient` and `Client` allow to receive and send Zeek events as
[`Event`](bindings/python/zeek_websocket/zeek_websocket.pyi) values.

#### Example: Asynchronous API

```python
# Connect an asynchronous client to the Zeek WebSocket API endpoint.
class Client(ZeekClient):
    async def connected(self, endpoint: str, version: str) -> None:
        print(f"Client connected to endpoint {ack}")

        # Once connected publish a "ping" event.
        await self.publish("/ping", Event("ping", ["hi"], ()))

    async def event(self, topic: str, event: Event) -> None:
        print(f"Received {event} on {topic}")

        # Stop the client once we have seen an event.
        self.disconnect()

    async def error(self, error: str) -> None:
        raise NotImplementedError(error)

# Run the client until it either explicitly disconnects, or hits a fatal error.
await Service.run(Client(), "client", mock_server, ["/ping"])
```

#### Example: Synchronous API

```python
# Connect a synchronous client to the Zeek WebSocket API endpoint.
client = Client(
    "client", endpoint_uri="ws://127.0.0.1:80/v1/messages/json", topics=["/topic1"])

# Try to receive an event. Without explicit `timeout` this blocks until some
# data was received, but might still return `None`.
#
# NOTE: This function should be called regularly if we expect Zeek to send us
# _any_ data, e.g., if we subscribed to any topics to ensure that messages
# received by the WebSocket client library are consumed. Otherwise it might
# overflow which would lead to disconnects.
if recv := client.receive():
    topic, event = recv
    print(f"Received {event} on {topic}")

# Publish a `ping` event. This assumes the Zeek-side event is declared as
#
#     global ping: event(n: count);
#
ping = Event(name="ping", args=(4711, ), metadata=())
client.publish(topic="/topic1", ping)
```

#### Mapping data between Python and Zeek WebSocket API types

The types used in the Zeek WebSocket API do not map one-to-one on native Python
types, so explicit type conversions are required. This library exposes the
[`Value`](bindings/python/zeek_websocket/__init__.py) type which represents
data values understood by the Zeek API. `Value` has a number of base classes
representing more specific types, e.g., a Zeek `int` is represented as a
`Value.Integer`,

```python
print(f"{Value.Integer(4711)}")  # Prints 'Integer(4711)'.
```

The full list of supported types is documented in the library's [stub
file](bindings/python/zeek_websocket/zeek_websocket.pyi).

The library provides a convenience function `make_value` which can be used
to automatically infer a matching `Value` variant,

```python
print(f"{make_value("abc")}")  # Prints 'String("abc")'.
```

> [!CAUTION]
> The Python `int` type holds signed values while Zeek distinguishes between
> `count` and `int`. To make behavior predicatable `make_value` will always
> return a `Value.Real` when given a numeric value. Prefer explicit typing if a
> Zeek events expect a Zeek integer type like `int` or `count`.

When creating the `Event` in the previous section we passed arguments `(4711,)`
which also made use of implicit type conversion, and `4711` was implicitly
mapped to a `Value.Integer`,

```python
ping = Event(name="ping", args=(4711, ), metadata=())
print(ping)
# Event { name: "ping", args: [Integer(4711)], metadata: [] }
```

We could have been explicit with

```python
ping = Event(name="ping", args=(Value.Integer(4711), ), metadata=())
print(ping)
# Event { name: "ping", args: [Integer(4711)], metadata: [] }
```

A `Value` can be mapped to a native Python value via the `value` attribute,
e.g.,

```python
x = make_value("abc")  # Creates a `Value.String`.
assert x.value == "abc"
assert type(x.value) == str
```

#### Special handling for Python enums and classes

The Zeek WebSocket API can represent Zeem `enum` and `record` values, but the
schema is not part of the protocol's data payload. This is to support cases
where the client might be on a different version of the schema, or might even
be completely unaware of the concrete Zeek type. With that the Python bindings
can always receive any `enum` or `record` value.

This still makes inspecting and constructing such values cumbersome, so this
library provides functionality to convert Zeek `enum` and `record` values to
native Python types provided a custom Python type exists.

##### Records

While we support constructing a `Value` from any Python class, e.g.,

```python
# NOTE: Discouraged, see below.
class X:
    def __init__(self, a: int, b: str):
        self.a = a
        self.b = b

print(make_value(X(4711, "abc")))  # Prints 'Record({"a": Count(4711), "b": String("abc")})'.
```

we only support converting a `Value` to a Python instances for dataclasses via `as_record`:

```python
# NOTE: Equivalent to example above, but more powerful.
@dataclasses.dataclass
class X:
    a: int
    b: str

x = make_value(X(4711, "abc"))  # Record({"a": Count(4711), "b": String("abc")}).

# Convert to a concrete Python type by providing the target type.
print(x.as_record(X))  # Prints 'X(a=4711, b='abc')'.
```

##### Enums

We support conversion from an to instances of `enum.Enum` values, e.g.,

```python
class E(enum.Enum):
    a = 1
    b = 2

e = E.a

x = Value.Enum(e.name)  # Or `make_value(e)`.

assert x.as_enum(E) == E.a
```

### C bindings

C bindings are dynamically created with
[cbindgen](https://github.com/mozilla/cbindgen/) and automated for consumption
with CMake via [corrosion-rs](https://github.com/corrosion-rs/corrosion). We
provide both a static archive as well as a shared library for building in CMake
`STATIC` or `SHARED` configurations.

A Rust toolchain is required for building the library. We require a fairly
recent Rust version, and we suggest installing Rust with
[rustup](https://rustup.rs/) which is available in many package managers. A
minimal, but sufficient toolchain can be installed with rustup with

```console
rustup toolchain install stable --profile minimal
```

The repository contains a sample CMake configuration in
[`bindings/c/examples/`](bindings/c/examples/CMakeLists.txt). For demonstration
we also provide sample clients in [C](bindings/c/examples/example.c) and
[C++](bindings/c/examples/example.cc).

Both examples include the header file `zeek-websocket.h` provided by the
library which includes additional documentation. Since it is generated when
required by a dependency it is present in the CMake build folder, likely under
the path
`<BUILD>/_deps/zeekwebsocket-build/corrosion_generated/cbindgen/zeek_websocket_c/include/zeek-websocket.h`.
It can be generated by hand by building the target
`_corrosion_cbindgen_zeek_websocket_c_bindings_zeek_websocket_h`.
