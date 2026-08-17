import dataclasses
import enum
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from typing import ClassVar

import pytest
from zeek_websocket import Protocol, Value, make_value


def test_address() -> None:
    x = make_value(IPv4Address("127.0.0.1"))
    assert isinstance(x, Value.Address)
    assert x.value == IPv4Address("127.0.0.1")

    x = make_value("127.0.0.1")
    assert isinstance(x, Value.Address)
    assert x.value == IPv4Address("127.0.0.1")


def test_bool() -> None:
    x = make_value(True)
    assert isinstance(x, Value.Boolean)
    assert x.value == True  # noqa: E712


def test_count() -> None:
    # `make_value` always prefers to construct `Real`, so `Count` would needs
    # to be constructed explicitly.
    pass


def test_enum() -> None:
    class E(enum.Enum):
        a = 1
        b = 2

    e1 = Value.Enum("a")
    assert str(e1) == 'Enum("a")'

    assert e1.value == "a"
    assert e1.as_enum(E) == E.a

    with pytest.raises(KeyError) as err:
        Value.Enum("bogus_string").as_enum(E)
    assert str(err.value) == "'bogus_string'"

    e2 = make_value(E.b)
    assert e2.value == "b"
    assert e2.as_enum(E) == E.b


def test_integer() -> None:
    # `make_value` always prefers to construct `Real`, so `Integer` would needs
    # to be constructed explicitly.
    pass


def test_protocol() -> None:
    x = make_value((8080, Protocol.TCP))
    assert isinstance(x, Value.Port)
    assert x.value == (8080, Protocol.TCP)


def test_real() -> None:
    x = make_value(0.5)
    assert isinstance(x, Value.Real)
    assert x.value == 0.5


def test_set() -> None:
    x = make_value({1.0, 2.0, 3.0})
    assert isinstance(x, Value.Set)
    assert x.value == {Value.Real(i) for i in [1, 2, 3]}

    x = Value.Set({Value.Real(1.0), Value.Real(2.0), Value.Real(3.0)})
    assert str(x) == "Set({Real(1.0), Real(2.0), Real(3.0)})"


def test_string() -> None:
    x = make_value("abc")
    assert isinstance(x, Value.String)
    assert x.value == "abc"


def test_subnet() -> None:
    x = make_value(("127.0.0.1", 8))
    assert isinstance(x, Value.Subnet)
    assert x.value == (IPv4Address("127.0.0.1"), 8)


def test_table() -> None:
    x = make_value({"1": 11.0, "2": 22.0, "3": 33.0})
    assert isinstance(x, Value.Table)
    assert x.value == {
        Value.String(k): Value.Real(v)
        for (k, v) in {"1": 11.0, "2": 22.0, "3": 33.0}.items()
    }

    x = Value.Table(
        {
            Value.Count(1): Value.String("11"),
            Value.Count(2): Value.String("22"),
            Value.Count(3): Value.String("33"),
        }
    )
    assert (
        str(x)
        == 'Table({Count(1): String("11"), Count(2): String("22"), Count(3): String("33")})'
    )


def test_timespan() -> None:
    x = make_value(timedelta(seconds=42))
    assert isinstance(x, Value.Timespan)
    assert x.value == timedelta(seconds=42)


def test_timestamp() -> None:
    x = make_value(datetime(year=2000, month=1, day=2, tzinfo=timezone.utc))
    assert isinstance(x, Value.Timestamp)
    assert x.value == datetime(year=2000, month=1, day=2, tzinfo=timezone.utc)


def test_vector() -> None:
    x = make_value([1.0, 2.0, 3.0])
    assert isinstance(x, Value.Vector)
    assert x.value == [Value.Real(i) for i in [1, 2, 3]]

    x = Value.Vector([Value.Real(1), Value.Real(2), Value.Real(3)])
    assert str(x) == "Vector([Real(1.0), Real(2.0), Real(3.0)])"


def test_record_dataclass() -> None:
    @dataclass
    class X:
        a: float
        b: str

    x = X(1.0, "2")
    value = make_value(x)
    assert str(value) == 'Record({"a": Real(1.0), "b": String("2")})'
    assert Value.Record(dataclasses.asdict(x)) == value

    assert value.value == {"a": Value.Real(1), "b": Value.String("2")}
    x2 = value.as_record(X)
    assert x2 == X(1, "2")


def test_vector_as_record() -> None:
    @dataclass
    class X:
        a: int
        b: str

    value = Value.Vector([1, "2"])
    assert value.as_record(X) == X(1, "2")


def test_as_record_preserves_value_types() -> None:
    @dataclass
    class X:
        a: Value.Integer
        b: Value.Count
        c: str

    value = Value.Record(
        {"a": Value.Integer(-1), "b": Value.Count(2), "c": Value.String("hi")}
    )
    result = value.as_record(X)
    assert result == X(Value.Integer(-1), Value.Count(2), "hi")
    assert type(result.a) is Value.Integer
    assert type(result.b) is Value.Count

    @dataclass
    class Y:
        e: Value.Enum
        s: str

    value2 = Value.Record({"e": Value.Enum("variant"), "s": Value.String("text")})
    result2 = value2.as_record(Y)
    assert result2 == Y(Value.Enum("variant"), "text")
    assert type(result2.e) is Value.Enum


def test_as_record_coerces_to_type_hint() -> None:
    @dataclass
    class X:
        a: float
        b: int
        c: str

    value = Value.Record({"a": 0.5, "b": 42, "c": "hello"})
    result = value.as_record(X)
    assert result == X(0.5, 42, "hello")
    assert type(result.a) is float
    assert type(result.b) is int
    assert type(result.c) is str


def test_as_record_coerces_enum() -> None:
    class Color(enum.Enum):
        RED = 1
        BLUE = 2

    @dataclass
    class X:
        c: Color

    value = Value.Record({"c": Value.Enum("RED")})
    result = value.as_record(X)
    assert result == X(Color.RED)
    assert result.c is Color.RED


def test_as_record_ignores_class_vars() -> None:
    @dataclass
    class X:
        class_level: ClassVar[int] = 42
        a: float = 0.0
        b: str = ""

    value = Value.Vector([Value.Real(1), Value.String("hi")])
    assert value.as_record(X) == X(a=1, b="hi")


def test_as_record_matches_fields_by_name() -> None:
    # Field declaration order deliberately differs from alphabetical to verify
    # that matching is by name, not by position.
    @dataclass
    class X:
        z: float
        a: str

    value = Value.Record({"a": Value.String("hello"), "z": Value.Real(42)})
    assert value.as_record(X) == X(42, "hello")


def test_as_record_skips_missing_fields() -> None:
    @dataclass
    class X:
        a: float
        b: float = 99.0
        c: str = "default"

    value = Value.Record({"a": Value.Real(1), "c": Value.String("hi")})
    assert value.as_record(X) == X(a=1, b=99.0, c="hi")


def test_as_record_nested_dataclass() -> None:
    @dataclass
    class Inner:
        x: int
        y: str

    @dataclass
    class Outer:
        name: str
        inner: Inner

    value = Value.Record(
        {"name": Value.String("hello"), "inner": Value.Record({"x": 42, "y": "world"})}
    )
    result = value.as_record(Outer)
    assert result == Outer("hello", Inner(42, "world"))
    assert type(result.inner) is Inner

    value_bad = Value.Record(
        {"name": Value.String("hello"), "inner": Value.String("not a record")}
    )
    with pytest.raises(
        TypeError,
        match=re.escape(
            'cannot convert value String("not a record") to nested dataclass'
        ),
    ):
        value_bad.as_record(Outer)


def test_as_record_optional() -> None:
    class Color(enum.Enum):
        RED = 1

    @dataclass
    class X:
        a: int | None
        b: Color | None

    present = Value.Record({"a": 42, "b": Value.Enum("RED")})
    result = present.as_record(X)
    assert result == X(42, Color.RED)

    absent = Value.Record({"a": Value.None_(), "b": Value.None_()})
    result = absent.as_record(X)
    assert result == X(None, None)


def test_as_record_generic_list() -> None:
    @dataclass
    class X:
        items: list[int]

    value = Value.Record({"items": Value.Vector([1.0, 2.0, 3.0])})
    result = value.as_record(X)
    assert result == X([1, 2, 3])
    assert all(type(x) is int for x in result.items)


def test_as_record_generic_set() -> None:
    @dataclass
    class X:
        tags: set[str]

    value = Value.Record({"tags": Value.Set({"a", "b"})})
    result = value.as_record(X)
    assert result is not None
    assert result.tags == frozenset({"a", "b"})


def test_as_record_generic_dict() -> None:
    @dataclass
    class X:
        counts: dict[str, int]

    value = Value.Record({"counts": Value.Table({"a": 1, "b": 2})})
    result = value.as_record(X)
    assert result is not None
    assert result.counts == {"a": 1, "b": 2}
    assert all(isinstance(v, int) for v in result.counts.values())


def test_record_other() -> None:
    class Y:
        c: float
        d: str

    y = Y()
    y.c = 1
    y.d = "2"
    value = make_value(y)
    assert type(value) is Value.Record
    assert str(value) == 'Record({"c": Real(1.0), "d": String("2")})'

    assert value.value == {"c": Value.Real(1), "d": Value.String("2")}
    with pytest.raises(ValueError) as err:
        value.as_record(Y)
    assert (
        str(err.value)
        == "<class 'test_make_value.test_record_other.<locals>.Y'> is not a dataclass"
    )


def test_str() -> None:
    assert str(Value.Boolean(True)) == "Boolean(true)"
    assert str(Value.Boolean(False)) == "Boolean(false)"

    assert str(Value.Count(123)) == "Count(123)"
    assert str(Value.Integer(123)) == "Integer(123)"

    assert str(Value.Port(8080, Protocol.TCP)) == "Port(8080, TCP)"
    assert str(Value.Port(8080, Protocol.UDP)) == "Port(8080, UDP)"
    assert str(Value.Port(8080, Protocol.ICMP)) == "Port(8080, ICMP)"
    assert str(Value.Port(8080, Protocol.UNKNOWN)) == "Port(8080, UNKNOWN)"

    assert str(Value.Real(0.5)) == "Real(0.5)"
    assert str(Value.Address("127.0.0.1")) == "Address(127.0.0.1)"
    assert str(Value.Subnet("127.0.0.1", 8)) == "Subnet(127.0.0.1, 8)"
    assert (
        str(Value.Timespan(timedelta(seconds=0.5)))
        == "Timespan(Duration { seconds: 0, nanoseconds: 500000000 })"
    )
    assert (
        str(Value.Timestamp(datetime(2000, 10, 2, 13, 14, 15, 16, timezone.utc)))
        == "Timestamp(2000-10-02 13:14:15.000016 +00:00:00)"
    )
    assert str(Value.None_()) == "None_"
    assert str(Value.String("abc")) == 'String("abc")'
    assert str(Value.Enum("abc")) == 'Enum("abc")'
    assert (
        str(Value.Vector([1.0, 2.0, 3.0]))
        == "Vector([Real(1.0), Real(2.0), Real(3.0)])"
    )
    assert str(Value.Set({1.0, 2.0, 3.0})) == "Set({Real(1.0), Real(2.0), Real(3.0)})"

    assert (
        str(Value.Table({"a": 1.0, "b": 2.0, "c": 3.0}))
        == 'Table({String("a"): Real(1.0), String("b"): Real(2.0), String("c"): Real(3.0)})'
    )
