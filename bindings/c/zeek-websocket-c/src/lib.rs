//! C API for interacting with the Zeek WebSocket API.

use std::{
    ffi::{CStr, CString},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroUsize,
    slice,
    time::Duration,
};

use time::OffsetDateTime;
use tokio::{runtime::Runtime, task::JoinHandle};
use zeek_websocket::{
    IpNetwork,
    client::{self, Outbox, ServiceConfig, ZeekClient},
    protocol::ProtocolError,
};

/// A client for interacting with the Zeek WebSocket API.
pub struct Client {
    rt: Runtime,
    _service: JoinHandle<()>,
    outbox: Option<Outbox>,
}

impl Client {
    /// Create a new client.
    ///
    /// @param app_name name of the client
    /// @param uri Zeek full path to the Zeek endpoint to connect to
    /// @params topics pointer to an array of topics to subscribe to
    /// @params num_topics number of elements in `topics`
    /// @param receive_callback callback to invoke when a new event is received
    /// @param error_callback callback to invoke when an error is encounter
    /// @param config if given the `ClientConfig` to use to deviate from the default
    ///
    /// The returned client must be freed by caller with `zws_client_free`.
    ///
    /// Callbacks might be invoked from another thread and must perform their own synchronization
    /// to be free of races.
    ///
    /// # Safety
    ///
    /// All passed strings must be NULL-terminated and point to valid UTF-8 strings.
    ///
    /// `outbox_size` must either be unset, or point to a non-zero integer.
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn zws_client_new(
        app_name: *const libc::c_char,
        uri: *const libc::c_char,
        topics: *const *const libc::c_char,
        num_topics: usize,
        receive_callback: ClientReceiveCallback,
        error_callback: ClientErrorCallback,
        config: Option<&ClientConfig>,
    ) -> Option<Box<Self>> {
        let app_name = unsafe { CStr::from_ptr(app_name) }.to_str().ok()?;

        let topics = unsafe { slice::from_raw_parts(topics, num_topics) };
        let topics: Result<Vec<_>, _> = topics
            .iter()
            .map(|x| unsafe { CStr::from_ptr(*x) }.to_str())
            .collect();
        let Ok(subscriptions) = topics else {
            let error = c"one or more topic names include invalid UTF-8";
            error_callback(ClientError::InvalidTopic, error.as_ptr());

            return None;
        };

        let Ok(uri) = unsafe { CStr::from_ptr(uri) }.to_str() else {
            let error = c"uri cannot contain literal NULL";
            error_callback(ClientError::InvalidUri, error.as_ptr());

            return None;
        };
        let endpoint = match uri.try_into() {
            Ok(x) => x,
            Err(e) => {
                let error = safe_string(&format!("invalid uri: {e}"));
                error_callback(ClientError::InvalidUri, error.as_ptr());

                return None;
            }
        };

        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_io()
            .build()
        {
            Ok(x) => x,
            Err(e) => {
                let error = safe_string(&format!("could not start background thread: {e}"));
                error_callback(ClientError::Runtime, error.as_ptr());

                return None;
            }
        };

        struct Inner {
            receive_callback: ClientReceiveCallback,
            error_callback: ClientErrorCallback,
        }

        impl ZeekClient for Inner {
            async fn event(&mut self, topic: String, event: zeek_websocket::Event) {
                let topic = safe_string(&topic);
                (self.receive_callback)(topic.as_ptr(), &Event(event));
            }

            async fn error(&mut self, error: ProtocolError) {
                let code = (&error).into();
                let context = safe_string(&error.to_string());
                (self.error_callback)(code, context.as_ptr());
            }

            async fn connected(&mut self, _endpoint: String, _version: String) {
                // Nothing.
            }
        }

        let config = config.map(ServiceConfig::from).unwrap_or_default();

        let mut publish = None;

        let service = client::Service::new_with_config(config, |sender| {
            publish = Some(sender);
            Inner {
                receive_callback,
                error_callback,
            }
        });

        let service = rt.spawn(async move {
            match service.serve(app_name, endpoint, subscriptions).await {
                Ok(_) => {
                    // Nothing.
                }
                Err(error) => {
                    let code = match &error {
                        client::Error::Transport(_) => ClientError::Transport,
                        client::Error::ProtocolError(e) => e.into(),
                    };
                    let context = safe_string(&error.to_string());
                    error_callback(code, context.as_ptr());
                }
            }
        });

        Some(Box::new(Self {
            rt,
            _service: service,
            outbox: publish,
        }))
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_client_free(self: Box<Self>) {}

    /// Publish an event on a given topic.
    ///
    /// This operation blocks if more than `outbox_size` already wait to be send.
    ///
    /// The function takes ownership of `event`.
    ///
    /// Either returns `true` on success, or `false` if the client is not connected.
    ///
    /// # Safety
    ///
    /// - event must not be NULL
    /// - `topic` must point to NULL-terminated UTF-8 string.
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn zws_client_publish(
        &mut self,
        topic: *const libc::c_char,
        event: Box<Event>,
    ) -> bool {
        let Ok(topic) = unsafe { CStr::from_ptr(topic) }.to_str() else {
            // We land here if `topic` was not valid UTF-8 which is explicitly diallowed, so no
            // need to set the global error.
            return false;
        };

        let publish = match &self.outbox {
            Some(publish) => publish,
            None => return false,
        };
        match self
            .rt
            .block_on(async { publish.send(topic.to_owned(), event.0).await })
        {
            Ok(()) => true,
            Err(_) => {
                // No need to invoke the error handler as the receiving side would only be closed
                // in case of error which would already invoke it.
                false
            }
        }
    }

    /// Shut down the client.
    ///
    /// The second parameter is the number of seconds to wait for outstanding tasks to finish.
    ///
    /// This function takes ownership of the passed client pointer which must not be NULL or used
    /// by the caller after invocation.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_client_shutdown(self: Box<Self>, timeout_secs: u64) {
        self.rt.shutdown_timeout(Duration::from_secs(timeout_secs));
    }
}

/// Client configuration to be used with `zws_client_new`.
#[repr(C)]
pub struct ClientConfig {
    /// Numbers of entries which can be enqueued before publishing events blocks.
    /// This value *must not* be zero.
    outbox_size: usize,
}

impl ClientConfig {
    #[unsafe(no_mangle)]
    /// Create a new client config with sensible defaults.
    extern "C" fn zws_clientconfig_new() -> Self {
        ClientConfig::default()
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            outbox_size: ServiceConfig::default().outbox_size.into(),
        }
    }
}

impl From<&ClientConfig> for ServiceConfig {
    fn from(value: &ClientConfig) -> Self {
        Self {
            // `ClientConfig::outbox_size` is documented to be non-zero.
            outbox_size: unsafe { NonZeroUsize::new_unchecked(value.outbox_size) },
        }
    }
}

/// Callback invoked when a new event is received.
///
/// The first parameter is a pointer to a NULL-terminated UTF-8 string holding the topic, the
/// second parameter a non-NULL pointer to the received event.
pub type ClientReceiveCallback = extern "C" fn(*const libc::c_char, &Event);

/// Callback invoked when a new error is encountered.
///
/// The first parameter is an error code, and the second a pointer to a NULL-terminated UTF-8
/// string holding additional context. See the definition of the different error codes on how they
/// need to be handled.
pub type ClientErrorCallback = extern "C" fn(ClientError, *const libc::c_char);

/// Error conditions encountered during client processing.
#[derive(Debug)]
#[repr(C)]
pub enum ClientError {
    /// Error starting the client runtime.
    Runtime,
    /// Invalid URI.
    InvalidUri,
    /// Invalid topic.
    InvalidTopic,
    /// Unexpected message received.
    UnexpectedMessage,
    /// Transport-related error. When encountered the client needs to be recreated.
    Transport,
    /// Error received from Zeek, e.g., due to type or signature mismatches or other Zeek
    /// conditions.
    Zeek,
}

impl From<&ProtocolError> for ClientError {
    fn from(value: &ProtocolError) -> Self {
        match value {
            ProtocolError::ZeekError { .. } => ClientError::Zeek,
            ProtocolError::AckExpected
            | ProtocolError::DeserializationError(..)
            | ProtocolError::UnexpectedEventPayload(..) => ClientError::UnexpectedMessage,
            ProtocolError::AlreadySubscribed => ClientError::Transport,
        }
    }
}

/// An encoded event.
pub struct Event(pub zeek_websocket::Event);

impl Event {
    /// Create a new event.
    ///
    /// The returned event must be freed by caller with `zws_event_free`.
    ///
    /// @param name name of the event to publish
    /// @param args arguments to the event invocation, must not be NULL
    /// @param metadata any metadata to attach to the event, can be NULL
    ///
    /// `args` and `metadata` ownership is passed to function.
    ///
    /// # Safety
    ///
    /// * `name` must point to a valid, NULL-terminated UTF-8 string.
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn zws_event_new(
        name: *const libc::c_char,
        args: Box<List>,
        metadata: Option<Box<List>>,
    ) -> Option<Box<Self>> {
        let Ok(name) = unsafe { CStr::from_ptr(name) }.to_str() else {
            return None;
        };

        let args = args.0.into_iter().map(|x| x.0);
        let mut event = zeek_websocket::Event::new(name, args);

        if let Some(metadata) = metadata {
            event = event.with_metadata(metadata.0.iter().map(|x| x.0.clone()));
        }

        Some(Box::new(Self(event)))
    }

    #[unsafe(no_mangle)]
    #[allow(unused_variables)]
    pub extern "C" fn zws_event_free(self: Box<Self>) {}

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_event_name(&self) -> *const libc::c_char {
        self.0.name.as_ptr() as *const libc::c_char
    }

    /// Returned value must be freed by caller with `zws_list_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_event_args(&self) -> Box<List> {
        let xs = self.0.args.iter().cloned().map(Value);
        Box::new(List(xs.collect()))
    }

    /// Returned value must be freed by caller with `zws_list_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_event_metadata(&self) -> Box<List> {
        let xs = self.0.metadata.iter().cloned().map(Value);
        Box::new(List(xs.collect()))
    }
}

/// A type holding a Zeek WebSocket API value variant.
#[derive(Clone, PartialEq)]
pub struct Value(pub zeek_websocket::Value);

impl Value {
    /// Returned value must be freed by caller with `zws_value_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_new_none() -> Box<Self> {
        Box::new(Self(zeek_websocket::Value::None))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_new_boolean(data: bool) -> Box<Self> {
        Box::new(Self(zeek_websocket::Value::Boolean(data)))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_new_count(data: u64) -> Box<Self> {
        Box::new(Self(zeek_websocket::Value::Count(data)))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_new_integer(data: i64) -> Box<Self> {
        Box::new(Self(zeek_websocket::Value::Integer(data)))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_new_real(data: f64) -> Box<Self> {
        Box::new(Self(zeek_websocket::Value::Real(data.into())))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_new_timespan(nanos: i64) -> Box<Self> {
        Box::new(Self(zeek_websocket::Value::Timespan(
            zeek_websocket::Duration::nanoseconds(nanos),
        )))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_new_timestamp(nanos_utc: i64) -> Option<Box<Self>> {
        let Ok(time) = OffsetDateTime::from_unix_timestamp_nanos(nanos_utc.into()) else {
            // This shouldn't really ever happen since all i64 nanos timestamps should be
            // representable.
            return None;
        };

        Some(Box::new(Self(zeek_websocket::Value::Timestamp(time))))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    ///
    /// # Safety
    ///
    /// * `data` must point to a valid, NULL-terminated UTF-8 string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn zws_value_new_string(
        data: *const libc::c_char,
        len: usize,
    ) -> Option<Box<Self>> {
        let data = unsafe { slice::from_raw_parts(data as *const u8, len) };
        let data = str::from_utf8(data).ok()?;

        Some(Box::new(Self(zeek_websocket::Value::String(
            data.to_string(),
        ))))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    ///
    /// # Safety
    ///
    /// * `data` must point to a valid, NULL-terminated UTF-8 string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn zws_value_new_enum(
        data: *const libc::c_char,
        len: usize,
    ) -> Option<Box<Self>> {
        let data = unsafe { slice::from_raw_parts(data as *const u8, len) };
        let data = str::from_utf8(data).ok()?;
        Some(Box::new(Self(zeek_websocket::Value::EnumValue(
            data.to_string(),
        ))))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    ///
    /// `data` ownership is passed to function.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_new_address(data: Box<Address>) -> Box<Self> {
        Box::new(Self(zeek_websocket::Value::Address(data.0)))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    ///
    /// `addr` ownership is passed to function.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_new_subnet(addr: Box<Address>, prefix: u8) -> Option<Box<Self>> {
        Some(Box::new(Self(zeek_websocket::Value::Subnet(
            IpNetwork::new(addr.0, prefix).ok()?,
        ))))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_new_port(port: Port) -> Box<Self> {
        Box::new(Self(zeek_websocket::Value::Port(port.into())))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    ///
    /// # Safety
    ///
    /// * `values` must point to an array of `num_values` `Value` objects.
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn zws_value_new_vector(
        values: *const Box<Self>,
        num_values: usize,
    ) -> Box<Self> {
        let values = unsafe { slice::from_raw_parts(values, num_values) };
        let xs: Vec<_> = values.iter().map(|x| x.0.clone()).collect();
        Box::new(Self(zeek_websocket::Value::Vector(xs)))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    ///
    /// # Safety
    ///
    /// * `values` must point to an array of `num_values` `Value` objects.
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn zws_value_new_set(
        values: *const Box<Self>,
        num_values: usize,
    ) -> Box<Self> {
        let values = unsafe { slice::from_raw_parts(values, num_values) };
        let xs = values.iter().map(|x| x.0.clone()).collect();
        Box::new(Self(zeek_websocket::Value::Set(xs)))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    ///
    /// # Safety
    ///
    /// * `values` must point to an array of `num_values` `Value` objects.
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn zws_value_new_table(
        values: *const Box<TableEntry>,
        num_values: usize,
    ) -> Box<Self> {
        let values = unsafe { slice::from_raw_parts(values, num_values) };
        let xs = values
            .iter()
            .map(|x| (x.key.clone().0, x.value.clone().0))
            .collect();
        Box::new(Self(zeek_websocket::Value::Table(xs)))
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_free(self: Box<Self>) {}

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_type(&self) -> ValueType {
        match self.0 {
            zeek_websocket::Value::None => ValueType::None,
            zeek_websocket::Value::Boolean(_) => ValueType::Boolean,
            zeek_websocket::Value::Count(_) => ValueType::Count,
            zeek_websocket::Value::Integer(_) => ValueType::Integer,
            zeek_websocket::Value::Real(_) => ValueType::Real,
            zeek_websocket::Value::Timespan(_) => ValueType::Timespan,
            zeek_websocket::Value::Timestamp(_) => ValueType::Timestamp,
            zeek_websocket::Value::String(_) => ValueType::String,
            zeek_websocket::Value::EnumValue(_) => ValueType::EnumValue,
            zeek_websocket::Value::Address(_) => ValueType::Address,
            zeek_websocket::Value::Subnet(_) => ValueType::Subnet,
            zeek_websocket::Value::Port(_) => ValueType::Port,
            zeek_websocket::Value::Vector(_) => ValueType::Vector,
            zeek_websocket::Value::Set(_) => ValueType::Set,
            zeek_websocket::Value::Table(_) => ValueType::Table,
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_bool(&self, result: &mut bool) -> bool {
        let zeek_websocket::Value::Boolean(x) = &self.0 else {
            return false;
        };
        *result = *x;
        true
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_count(&self, result: &mut u64) -> bool {
        let zeek_websocket::Value::Count(x) = &self.0 else {
            return false;
        };
        *result = *x;
        true
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_integer(&self, result: &mut i64) -> bool {
        let zeek_websocket::Value::Integer(x) = &self.0 else {
            return false;
        };
        *result = *x;
        true
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_real(&self, result: &mut f64) -> bool {
        let zeek_websocket::Value::Real(x) = &self.0 else {
            return false;
        };
        *result = **x;
        true
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_timespan(&self, result: &mut i64) -> bool {
        let zeek_websocket::Value::Timespan(x) = &self.0 else {
            return false;
        };
        let Ok(nanos) = x.whole_nanoseconds().try_into() else {
            // This shouldn't trigger since Zeek only supports i64 intervals.
            return false;
        };
        *result = nanos;
        true
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_timestamp(&self, result: &mut i64) -> bool {
        let zeek_websocket::Value::Timestamp(x) = &self.0 else {
            return false;
        };

        let Ok(nanos) = x.unix_timestamp_nanos().try_into() else {
            // This shouldn't trigger since Zeek only supports i64 timestamps.
            return false;
        };

        *result = nanos;
        true
    }

    /// If the value represents a string value set the pointer passed as second argument to it and
    /// return the string size.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_string(&self, result: &mut *const libc::c_char) -> usize {
        if let zeek_websocket::Value::String(x) = &self.0 {
            *result = x.as_ptr() as *const libc::c_char;
            x.len()
        } else {
            Default::default()
        }
    }

    /// If the value represents an enum value set the pointer passed as second argument to it and
    /// return the string size.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_enumvalue(&self, result: &mut *const libc::c_char) -> usize {
        if let zeek_websocket::Value::EnumValue(x) = &self.0 {
            *result = x.as_ptr() as *const libc::c_char;
            x.len()
        } else {
            Default::default()
        }
    }

    /// Converts this value into an address and stores the result in the provided pointer.
    ///
    /// Returns `true` if the conversion was successful, `false` otherwise.
    ///
    /// `self` ownership is passed to function.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_address(&self, result: &mut Address) -> bool {
        let zeek_websocket::Value::Address(addr) = &self.0 else {
            return false;
        };
        *result = Address(*addr);
        true
    }

    /// Converts this value into a subnet and stores the result in the provided pointer.
    ///
    /// Returns `true` if the conversion was successful, `false` otherwise.
    ///
    /// `self` ownership is passed to function.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_subnet(&self, result: &mut Subnet) -> bool {
        let zeek_websocket::Value::Subnet(subnet) = &self.0 else {
            return false;
        };
        *result = Subnet {
            addr: Box::new(Address(subnet.ip())),
            prefix: subnet.prefix(),
        };
        true
    }

    /// Converts this value into a vector and stores the result in the provided pointer.
    ///
    /// Returns `true` if the conversion was successful, `false` otherwise.
    ///
    /// `self` ownership is passed to function.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_port(&self, result: &mut Port) -> bool {
        let zeek_websocket::Value::Port(port) = self.0 else {
            return false;
        };
        *result = port.into();
        true
    }

    /// Converts this value into a vector and stores the result in the provided pointer.
    ///
    /// Returns `true` if the conversion was successful, `false` otherwise.
    ///
    /// `self` ownership is passed to function.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_vector(self: Box<Self>, result: &mut List) -> bool {
        let zeek_websocket::Value::Vector(xs) = self.0 else {
            return false;
        };
        result.0 = xs.into_iter().map(Value).collect();
        true
    }

    /// Converts this value into a set and stores the result in the provided pointer.
    ///
    /// Returns `true` if the conversion was successful, `false` otherwise.
    ///
    /// `self` ownership is passed to function.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_set(self: Box<Self>, result: &mut List) -> bool {
        let zeek_websocket::Value::Set(xs) = self.0 else {
            return false;
        };
        result.0 = xs.into_iter().map(Value).collect();
        true
    }

    /// Converts this value into a table and stores the result in the provided pointer.
    ///
    /// Returns `true` if the conversion was successful, `false` otherwise.
    ///
    /// `self` ownership is passed to function.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_table(self: Box<Self>, result: &mut Table) -> bool {
        let zeek_websocket::Value::Table(xs) = self.0 else {
            return false;
        };
        result.0 = xs
            .into_iter()
            .map(|(key, value)| (Value(key), Value(value)))
            .collect();
        true
    }
}

/// An entry in a table.
#[repr(C)]
pub struct TableEntry {
    /// Key for the entry.
    pub key: Box<Value>,

    /// Value for the entry.
    pub value: Box<Value>,
}

impl From<TableEntry> for zeek_websocket::TableEntry {
    fn from(TableEntry { key, value }: TableEntry) -> Self {
        Self::new(key.0, value.0)
    }
}

/// Type held by a value.
#[repr(C)]
pub enum ValueType {
    None,
    Boolean,
    Count,
    Integer,
    Real,
    Timespan,
    Timestamp,
    String,
    EnumValue,
    Address,
    Subnet,
    Port,
    Vector,
    Set,
    Table,
}

/// A list of encoded values.
pub struct List(pub Vec<Value>);

impl List {
    /// `values` ownership is passed to function.
    ///
    /// If either `values=NULL` or `num_values=0` an empty list is created.
    ///
    /// # Safety
    ///
    /// * if set, `values` must point to an array of `num_value` `Value` objects
    ///
    #[unsafe(no_mangle)]
    #[allow(unused_variables)]
    pub unsafe extern "C" fn zws_list_new(values: *mut *mut Value, num_values: usize) -> Box<Self> {
        let values = if !values.is_null() && num_values != 0 {
            let values = unsafe { slice::from_raw_parts_mut(values, num_values) };
            values
                .iter_mut()
                .map(|x| *unsafe { Box::from_raw(*x) })
                .collect()
        } else {
            Vec::new()
        };

        Box::new(Self(values))
    }

    #[unsafe(no_mangle)]
    #[allow(unused_variables)]
    pub extern "C" fn zws_list_size(&self) -> usize {
        self.0.len()
    }

    #[unsafe(no_mangle)]
    #[allow(unused_variables)]
    pub extern "C" fn zws_list_entry(&self, n: usize) -> Option<&Value> {
        self.0.get(n)
    }

    #[unsafe(no_mangle)]
    #[allow(unused_variables)]
    pub extern "C" fn zws_list_free(self: Box<Self>) {}
}

/// An encoded table.
pub struct Table(pub Vec<(Value, Value)>);

impl Table {
    /// Get the a list of keys in the table.
    ///
    /// Returned value must be freed by caller with `zws_list_free`.
    #[unsafe(no_mangle)]
    #[allow(unused_variables)]
    pub extern "C" fn zws_table_keys(&self) -> Box<List> {
        Box::new(List(self.0.iter().map(|(k, _)| k.clone()).collect()))
    }

    /// Get an entry in the table.
    ///
    /// Returns a pointer to the entry's value if present, or `NULL`.
    #[unsafe(no_mangle)]
    #[allow(unused_variables)]
    pub extern "C" fn zws_table_get<'a>(&'a self, key: &Value) -> Option<&'a Value> {
        self.0.iter().find(|(k, v)| k == key).map(|(k, v)| v)
    }

    #[unsafe(no_mangle)]
    #[allow(unused_variables)]
    pub extern "C" fn zws_table_free(data: Box<Self>) {}
}

/// An encoded IP address.
pub struct Address(pub IpAddr);

impl Address {
    /// Returned value must be freed by caller with `zws_address_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_address_new_v4(data: &libc::in_addr) -> Box<Self> {
        Box::new(Self(Ipv4Addr::from(data.s_addr.to_ne_bytes()).into()))
    }

    /// Returned value must be freed by caller with `zws_address_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_address_new_v6(data: &libc::in6_addr) -> Box<Self> {
        Box::new(Self(IpAddr::from(Ipv6Addr::from_octets(data.s6_addr))))
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_address_free(self: Box<Address>) {}

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_address_is_v6(&self) -> bool {
        self.0.is_ipv6()
    }

    /// Converts this value into an IPv4 address and stores the result in the provided pointer.
    ///
    /// Returns `true` if the conversion was successful, `false` otherwise.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_address_as_v4(&self, result: &mut libc::in_addr) -> bool {
        let IpAddr::V4(addr) = &self.0 else {
            return false;
        };
        result.s_addr = addr.to_bits().to_be();
        true
    }

    /// Converts this value into an IPv6 address and stores the result in the provided pointer.
    ///
    /// Returns `true` if the conversion was successful, `false` otherwise.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_address_as_v6(&self, result: &mut libc::in6_addr) -> bool {
        let IpAddr::V6(addr) = &self.0 else {
            return false;
        };
        result.s6_addr.copy_from_slice(&addr.octets());
        true
    }
}

/// An encoded subnet.
#[repr(C)]
pub struct Subnet {
    pub addr: Box<Address>,
    pub prefix: u8,
}

impl Subnet {
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_subnet_free(self: Box<Self>) {}
}

/// Protocol for a port.
#[repr(C)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    UNKNOWN,
}

impl From<Protocol> for zeek_websocket::Protocol {
    fn from(value: Protocol) -> Self {
        match value {
            Protocol::TCP => Self::TCP,
            Protocol::UDP => Self::UDP,
            Protocol::ICMP => Self::ICMP,
            Protocol::UNKNOWN => Self::UNKNOWN,
        }
    }
}

impl From<zeek_websocket::Protocol> for Protocol {
    fn from(value: zeek_websocket::Protocol) -> Self {
        match value {
            zeek_websocket::Protocol::TCP => Self::TCP,
            zeek_websocket::Protocol::UDP => Self::UDP,
            zeek_websocket::Protocol::ICMP => Self::ICMP,
            zeek_websocket::Protocol::UNKNOWN => Self::UNKNOWN,
        }
    }
}

/// An encoded port.
#[repr(C)]
pub struct Port {
    /// Port number.
    pub number: libc::in_port_t,

    /// Protocol for the port.
    pub protocol: Protocol,
}

impl From<Port> for zeek_websocket::Port {
    fn from(value: Port) -> Self {
        Self::new(value.number, value.protocol.into())
    }
}

impl From<zeek_websocket::Port> for Port {
    fn from(value: zeek_websocket::Port) -> Self {
        Self {
            number: value.number(),
            protocol: value.protocol().into(),
        }
    }
}

/// Creates a CString from the give &str. If the input contains any literal `\0` the NULL and
/// any data after it is dropped from the output.
fn safe_string(s: &str) -> CString {
    let s = s.split('\0').next().unwrap_or(s);

    // Safe since we only work on characters up to any possible NULL byte.
    unsafe { CString::from_vec_unchecked(s.into()) }
}

#[cfg(test)]
mod test {
    use std::{
        ffi::{CStr, CString},
        sync::{Arc, Condvar, LazyLock, Mutex},
    };

    use crate::{Client, ClientError, Event};

    #[test]
    fn simple_client() {
        static EVENTS: LazyLock<Arc<(Mutex<Vec<Event>>, Condvar)>> =
            LazyLock::new(Default::default);

        extern "C" fn receive_event_callback(topic: *const libc::c_char, event: &Event) {
            let topic = unsafe { CStr::from_ptr(topic) };
            eprintln!("Event {topic:?}: {:?}", event.0);

            EVENTS.0.lock().unwrap().push(Event(event.0.clone()));
            EVENTS.1.notify_one();
        }

        extern "C" fn receive_error_callback(code: ClientError, context: *const libc::c_char) {
            let context = unsafe { CStr::from_ptr(context) };
            eprintln!("Error {code:?}: {context:?}");
        }

        let zeek = zeek_websocket::test::MockServer::default();
        let uri = CString::new(zeek.endpoint().to_string()).unwrap();

        let app_name = c"myapp".as_ptr();

        let topics: Vec<*const libc::c_char> = vec![c"/ping".as_ptr()];

        let mut client = unsafe {
            Client::zws_client_new(
                app_name,
                uri.as_ptr(),
                topics.as_ptr(),
                topics.len(),
                receive_event_callback,
                receive_error_callback,
                None,
            )
        }
        .unwrap();

        let event = Box::new(Event(zeek_websocket::Event::new("echo", ["hi!"])));
        assert!(unsafe { client.zws_client_publish(topics[0], event) });

        let (events, cvar) = &**EVENTS;

        let mut received_events = false;
        if let Ok(events) = events.try_lock() {
            let xs = cvar.wait(events).unwrap();
            received_events |= xs.iter().any(|event| event.0.name == "echo");
        }

        assert!(received_events);
    }

    #[test]
    fn unreachable_remote() {
        let topics: Vec<_> = vec![c"/ping".as_ptr()];

        let uri = c"ws://localhost:1".as_ptr();

        static COND: LazyLock<Arc<Condvar>> = LazyLock::new(Default::default);

        extern "C" fn receive_event_callback(_: *const libc::c_char, _: &Event) {}

        extern "C" fn receive_error_callback(code: ClientError, context: *const libc::c_char) {
            let context = unsafe { CStr::from_ptr(context) };
            eprintln!("Error {code:?} {context:?}");

            COND.notify_one();
        }

        let mut client = unsafe {
            Client::zws_client_new(
                c"myapp".as_ptr(),
                uri,
                topics.as_ptr(),
                topics.len(),
                receive_event_callback,
                receive_error_callback,
                None,
            )
        }
        .unwrap();

        assert!(unsafe {
            client.zws_client_publish(
                topics[0],
                Box::new(Event(zeek_websocket::Event::new("echo", [1]))),
            )
        });

        let mutex = Mutex::new(());
        let _x = COND.wait(mutex.lock().unwrap()).unwrap();
    }
}
