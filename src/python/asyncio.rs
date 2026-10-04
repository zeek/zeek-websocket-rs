use pyo3::{
    exceptions::{PyRuntimeError, PyValueError},
    prelude::*,
};
use pyo3_async_runtimes::tokio::{future_into_py, into_future};

use crate::python::Event;

/// Abstract base class to connect to the Zeek WebSocket API.
///
/// Users are expected to implement the following async methods:
///
/// ```python
/// async def connected(self, endpoint: str, version: str) -> None: ...
/// async def event(self, topic: str, event: Event) -> None: ...
/// async def error(self, error: str) -> None: ...
/// ```
#[derive(Clone)]
#[pyclass(from_py_object, subclass)]
pub struct ZeekClient {
    outbox: Option<crate::client::Outbox>,
}

#[pymethods]
impl ZeekClient {
    #[new]
    fn new() -> Self {
        Self { outbox: None }
    }

    /// Disconnect the client.
    fn disconnect(&mut self) {
        self.outbox.take();
    }

    /// Asynchronously send an event on the given topic.
    ///
    /// This function enqueues the event on a queue which is processed by a separate thread.
    /// Callers should release the GIL if they plan to enqueue many event, e.g., by using a
    /// separate task to perform the `publish` call.
    ///
    /// Callers should `await` the result.
    fn publish<'py>(
        &mut self,
        py: Python<'py>,
        topic: String,
        event: Event,
    ) -> PyResult<Bound<'py, PyAny>> {
        let outbox = self
            .outbox
            .clone()
            .ok_or_else(|| PyRuntimeError::new_err("client is not connected"))?;

        future_into_py(py, async move {
            outbox
                .send(topic, event.0)
                .await
                .map_err(|_e| PyRuntimeError::new_err("could not publish event"))?;
            Ok(())
        })
    }

    /// Handle client subscription.
    ///
    /// Async abstract method which must be implemented by derived classes.
    #[allow(
        clippy::needless_pass_by_value,
        clippy::unused_async_trait_impl,
        clippy::unused_async,
        clippy::unused_self,
        unused_variables
    )]
    async fn connected(&self, endpoint: String, version: String) {
        panic!("derived classes must implement `connected'")
    }

    /// Handle a received event.
    ///
    /// Async abstract method which must be implemented by derived classes.
    #[allow(
        clippy::needless_pass_by_value,
        clippy::unused_async_trait_impl,
        clippy::unused_async,
        clippy::unused_self,
        unused_variables
    )]
    async fn event(&self, topic: String, event: Event) {
        panic!("derived classes must implement `event'")
    }

    /// Handle a received error.
    ///
    /// Async abstract method which must be implemented by derived classes.
    #[allow(
        clippy::needless_pass_by_value,
        clippy::unused_async_trait_impl,
        clippy::unused_async,
        clippy::unused_self,
        unused_variables
    )]
    async fn error(&self, error: String) {
        panic!("derived classes must implement `error'")
    }
}

struct ZeekClientAdapter {
    inner: Py<PyAny>,
}

macro_rules! call_async {
    ($client:expr, $method:literal, $args:expr) => {
        let _ = Python::attach(|py| {
            let self_ = $client.inner.bind(py);

            let x = match self_.call_method1($method, $args) {
                Ok(x) => x,
                Err(e) => {
                    e.print(py);
                    panic!();
                }
            };
            match into_future(x) {
                Ok(x) => x,
                Err(e) => {
                    e.print(py);
                    panic!();
                }
            }
        })
        .await;
    };
}

impl crate::client::ZeekClient for ZeekClientAdapter {
    async fn connected(&mut self, endpoint: String, version: String) {
        call_async!(self, "connected", (endpoint, version));
    }

    async fn event(&mut self, topic: String, event: zeek_websocket_types::Event) {
        call_async!(self, "event", (topic, Event(event)));
    }

    async fn error(&mut self, error: crate::protocol::ProtocolError) {
        call_async!(self, "error", (error.to_string(),));
    }
}

/// A service wrapping a concrete `ZeekClient`.
#[pyclass]
pub struct Service;

#[pymethods]
impl Service {
    /// Run a client as a service.
    ///
    /// Callers should `await` the result.
    #[staticmethod]
    fn run<'py>(
        py: Python<'py>,
        client: Bound<ZeekClient>,
        app_name: String,
        endpoint: String,
        subscriptions: Vec<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let endpoint = endpoint
            .try_into()
            .map_err(|e| PyValueError::new_err(format!("invalid uri: {e}")))?;

        let mut x = client
            .cast::<ZeekClient>()
            .map_err(|e| PyRuntimeError::new_err(format!("invalid client: {e}")))?
            .borrow_mut();

        let service = crate::client::Service::new(|outbox| {
            x.outbox = Some(outbox);
            ZeekClientAdapter {
                inner: client.into(),
            }
        });

        future_into_py(py, async move {
            service
                .serve(app_name, endpoint, subscriptions)
                .await
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            Ok(())
        })
    }
}
