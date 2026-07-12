#![allow(clippy::unwrap_used)]

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr},
    path::Path,
    process::{Command, Stdio},
    thread::sleep,
};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ipnetwork::Ipv4Network;
use time::{Date, Duration, Time};
use tungstenite::{client::IntoClientRequest, connect};
use zeek_websocket::{
    Data, Event, Message, OffsetDateTime, Subscriptions,
    types::{IpNetwork, Port, Protocol, Value},
};

fn serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialize");
    group.throughput(Throughput::Elements(1));

    group.bench_function("none", |b| {
        b.iter(|| serde_json::to_string(&Value::from(())));
    });
    group.bench_function("bool", |b| {
        b.iter(|| serde_json::to_string(&Value::from(bool::default())));
    });
    group.bench_function("u64", |b| {
        b.iter(|| serde_json::to_string(&Value::from(u64::default())));
    });
    group.bench_function("i64", |b| {
        b.iter(|| serde_json::to_string(&Value::from(i64::default())));
    });
    group.bench_function("f64", |b| {
        b.iter(|| serde_json::to_string(&Value::from(f64::default())));
    });
    group.bench_function("timespan", |b| {
        let timespan = Duration::new(1234, 4567);
        b.iter(|| serde_json::to_string(&Value::from(timespan)));
    });
    group.bench_function("timestamp", |b| {
        let timestamp = OffsetDateTime::new_utc(
            Date::from_calendar_date(2000, time::Month::April, 1).unwrap(),
            Time::from_hms(1, 2, 3).unwrap(),
        );
        b.iter(|| serde_json::to_string(&Value::from(timestamp)));
    });
    group.bench_function("string", |b| {
        let string = "";
        b.iter(|| serde_json::to_string(&Value::from(string)));
    });
    group.bench_function("address", |b| {
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0));
        b.iter(|| serde_json::to_string(&Value::from(addr)));
    });
    group.bench_function("subnet", |b| {
        let subnet = IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        b.iter(|| serde_json::to_string(&Value::from(subnet)));
    });
    group.bench_function("port", |b| {
        let port = Port::new(8080, Protocol::TCP);
        b.iter(|| serde_json::to_string(&Value::from(port)));
    });
    group.bench_function("vector", |b| {
        b.iter(|| serde_json::to_string(&Value::from(Vec::<bool>::new())));
    });
    group.bench_function("set", |b| {
        b.iter(|| serde_json::to_string(&Value::from(HashSet::<bool>::new())));
    });
    group.bench_function("map", |b| {
        b.iter(|| serde_json::to_string(&Value::from(HashMap::<bool, i64>::new())));
    });

    group.bench_function("event", |b| {
        b.iter(|| Message::new_data("ping", Event::new("ping", [1])));
    });

    group.finish();
}

fn zeek_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("zeek_roundtrip");
    group.throughput(Throughput::Elements(1));
    group.sample_size(10);

    if std::env::var("GITHUB_ACTION").is_ok() {
        eprintln!("skipping benchmark in GH action");
        return;
    }

    if Command::new("zeek")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        eprintln!("zeek seems to be unavailable, skipping benchmark");
        return;
    }

    // Benchmark roundtrip time of a ping/pong. This likely doesn't benchmark this
    // library, but instead Zeek's handling of request-response style events.
    group.bench_function("simple_event", |b| {
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join("local.zeek");

        let mut zeek = Command::new(script)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();

        // Wait a little to give Zeek process time to start up.
        sleep(std::time::Duration::from_secs(1));

        let request = "ws://127.0.0.1:8080/v1/messages/json"
            .into_client_request()
            .unwrap();

        let (mut stream, _response) = connect(request).unwrap();

        let topic = "/ping";

        // Subscribe the client.
        stream.send(Subscriptions::from(&[topic]).into()).unwrap();

        b.iter(|| {
            let msg = Message::new_data(topic, Event::new("ping", ["hi!"]));
            stream.write(msg.into()).unwrap();

            while let Ok(resp) = stream.read() {
                // Ignore non-Zeek payloads, most of the time pings, or
                // on the first iteration the ACK of the subscription.
                let Ok(msg) = (resp).try_into() else {
                    continue;
                };

                // Consume any Zeek payloads until we get an event back. This has
                // to be a `pong` response to the `ping` event we sent above.
                if let Message::DataMessage {
                    data: Data::Event(Event { name, .. }),
                    ..
                } = msg
                {
                    assert_eq!(name, "pong");
                    break;
                }
            }
        });

        let _ = zeek.kill();
        let _ = zeek.wait();
    });

    group.finish();
}

criterion_group!(benches, serialize, zeek_roundtrip);
criterion_main!(benches);
