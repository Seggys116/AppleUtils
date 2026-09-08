use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread;

use plist::{Dictionary, Value};

use super::codec::{self, CodecError, PlistFormat};
use super::dial::{Clock, DialError, DialPlan, GuestDialer, dial_until};
use super::message::{
    self, DataRequest, DeviceMessage, DeviceType, KEY_CHECKPOINT_ERROR, KEY_LOG, KEY_MSG_TYPE,
    KEY_QUERY_KEY, KEY_QUERY_VALUE, KEY_RESTORE_OPTIONS, KEY_RESTORE_PROTOCOL_VERSION, KEY_TYPE,
    MsgType, OptionsError, QueryKey, Request, RestoreOptions,
};
use super::provider::{
    BulkOutcome, BulkTransferService, ProviderError, RestoreDataProvider, SessionObserver,
    StreamedObject, StreamedPayload,
};
use crate::restore::thread_class::{ThreadClass, with_thread_class};

const STREAMED_FILE_MAX_CHUNK: usize = 64 << 20;

pub const RAMROD_PORT: u16 = 62078;

#[derive(Clone, Debug, PartialEq)]
pub enum Inbound {
    Device(DeviceMessage),
    Untyped(Dictionary),
}

impl Inbound {
    fn from_value(value: Value) -> Result<Self, RamrodError> {
        let Value::Dictionary(body) = value else {
            return Err(RamrodError::NotADictionary);
        };
        match body.get(KEY_MSG_TYPE).and_then(Value::as_string) {
            Some(name) => Ok(Self::Device(DeviceMessage {
                msg_type: MsgType::from_wire(name),
                body,
            })),
            None => Ok(Self::Untyped(body)),
        }
    }

    pub fn body(&self) -> &Dictionary {
        match self {
            Self::Device(message) => &message.body,
            Self::Untyped(body) => body,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RestoreSummary {
    pub data_requests: u64,
    pub bulk_transfers: u64,
    pub async_data_requests: u64,
    pub async_waits: u64,
    pub bulk_declined: u64,
    pub bulk_empty: u64,
    pub progress_messages: u64,
    pub status_messages: u64,
    pub final_status_acks_sent: u64,
    pub checkpoints: u64,
    pub checkpoints_begun: u64,
    pub checkpoints_ended: u64,
    pub open_checkpoint: Option<String>,
    pub untyped_messages: u64,
    pub last_status: Option<i64>,
    pub final_status: Option<super::message::FinalStatus>,
    pub guest_echoed_final_status: bool,
    pub crash_logs: u64,
    pub crash_logs_written: u64,
    pub guest_log: Option<String>,
    pub checkpoint_error: Option<String>,
}

impl RestoreSummary {
    pub fn final_status_acknowledged(&self) -> bool {
        self.final_status_acks_sent > 0
    }

    pub fn guest_left_waiting(&self) -> bool {
        self.final_status_acks_sent < self.status_messages
    }
}

pub struct RamrodClient<T> {
    transport: T,
    format: PlistFormat,
    restore_started: bool,
    device_protocol_version: Option<i64>,
    crash_log_directory: PathBuf,
}

#[must_use]
pub fn default_crash_log_directory() -> PathBuf {
    std::env::temp_dir().join(format!(
        "appleutils-restore-crash-logs-{}",
        std::process::id()
    ))
}

fn write_crash_log(directory: &Path, name: &str, data: Option<&[u8]>) -> Result<PathBuf, String> {
    let Some(bytes) = data else {
        return Err(format!(
            "the message carried no {} key, so there was nothing to write",
            message::KEY_CRASH_LOG_DATA
        ));
    };
    std::fs::create_dir_all(directory)
        .map_err(|error| format!("could not create {}: {error}", directory.display()))?;
    let path = directory.join(name);
    std::fs::write(&path, bytes)
        .map_err(|error| format!("could not write {}: {error}", path.display()))?;
    Ok(path)
}

fn crash_log_file_name(filename: Option<&str>, index: u64) -> String {
    let candidate = filename
        .and_then(|name| name.rsplit('/').next())
        .unwrap_or_default();
    let sanitised: String = candidate
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
        .collect();
    if sanitised.is_empty() || sanitised.chars().all(|ch| ch == '.') {
        format!("crash-{index}")
    } else {
        sanitised
    }
}

impl<T> fmt::Debug for RamrodClient<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RamrodClient")
            .field("format", &self.format)
            .field("restore_started", &self.restore_started)
            .finish_non_exhaustive()
    }
}

impl<T> RamrodClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            format: PlistFormat::Binary,
            restore_started: false,
            device_protocol_version: None,
            crash_log_directory: default_crash_log_directory(),
        }
    }

    #[must_use]
    pub fn with_crash_log_directory(mut self, directory: PathBuf) -> Self {
        self.crash_log_directory = directory;
        self
    }

    pub fn with_format(mut self, format: PlistFormat) -> Self {
        self.format = format;
        self
    }

    pub fn restore_started(&self) -> bool {
        self.restore_started
    }

    pub fn device_protocol_version(&self) -> Option<i64> {
        self.device_protocol_version
    }

    pub fn into_inner(self) -> T {
        self.transport
    }
}

type InFlightTransfer<'scope> = (
    thread::ScopedJoinHandle<'scope, Result<BulkOutcome, ProviderError>>,
    DataRequest,
    u16,
);

fn report_bulk_outcome<O>(
    result: Result<BulkOutcome, ProviderError>,
    request: &DataRequest,
    port: u16,
    observer: &mut O,
    summary: &mut RestoreSummary,
) -> Result<(), RamrodError>
where
    O: SessionObserver + ?Sized,
{
    match result {
        Ok(outcome @ BulkOutcome::Served { bytes: 0, .. }) => {
            summary.bulk_empty += 1;
            observer.on_bulk_served_empty(request, port, &outcome);
        }
        Ok(outcome @ BulkOutcome::Served { .. }) => {
            summary.bulk_transfers += 1;
            observer.on_bulk_served(request, port, &outcome);
        }
        Ok(BulkOutcome::Declined { reason }) => {
            summary.bulk_declined += 1;
            observer.on_bulk_declined(request, port, &reason);
        }
        Err(source) => {
            observer.on_data_unanswered(request, &source);
            return Err(RamrodError::Provider {
                data_type: request.data_type.wire_name().to_string(),
                source,
            });
        }
    }
    Ok(())
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "the panic payload could not be read as a string".to_string()
    }
}

fn join_bulk_transfer<O>(
    handle: thread::ScopedJoinHandle<'_, Result<BulkOutcome, ProviderError>>,
    request: &DataRequest,
    port: u16,
    observer: &mut O,
    summary: &mut RestoreSummary,
) -> Result<(), RamrodError>
where
    O: SessionObserver + ?Sized,
{
    let result = match handle.join() {
        Ok(result) => result,
        Err(payload) => Err(ProviderError::Other(format!(
            "the {} transfer on port {port} panicked: {}",
            request.data_type,
            panic_message(&payload)
        ))),
    };
    report_bulk_outcome(result, request, port, observer, summary)
}

impl<T: Read + Write> RamrodClient<T> {
    pub fn send(&mut self, value: &Value) -> Result<(), RamrodError> {
        codec::write_message(&mut self.transport, value, self.format)?;
        Ok(())
    }

    pub fn receive(&mut self) -> Result<Option<Inbound>, RamrodError> {
        match codec::read_message(&mut self.transport)? {
            Some(value) => Ok(Some(Inbound::from_value(value)?)),
            None => Ok(None),
        }
    }

    fn receive_reply(&mut self, to: Request) -> Result<Dictionary, RamrodError> {
        match self.receive()? {
            Some(Inbound::Untyped(body)) => Ok(body),
            Some(Inbound::Device(message)) => Err(RamrodError::UnexpectedDeviceMessage {
                request: to,
                msg_type: message.msg_type.wire_name().to_string(),
            }),
            None => Err(RamrodError::ClosedBeforeReply { request: to }),
        }
    }

    pub fn query_type(&mut self) -> Result<DeviceType, RamrodError> {
        self.send(&Request::QueryType.to_value())?;
        let body = self.receive_reply(Request::QueryType)?;
        let service_type = body
            .get(KEY_TYPE)
            .and_then(Value::as_string)
            .ok_or(RamrodError::MalformedReply {
                request: Request::QueryType,
                reason: "the reply carries no Type string",
            })?
            .to_string();
        let protocol_version = body
            .get(KEY_RESTORE_PROTOCOL_VERSION)
            .and_then(Value::as_signed_integer);
        self.device_protocol_version = protocol_version;
        Ok(DeviceType {
            service_type,
            protocol_version,
            body,
        })
    }

    pub fn query_restored(&mut self) -> Result<DeviceType, RamrodError> {
        let device = self.query_type()?;
        if !device.is_restored() {
            return Err(RamrodError::NotRestored {
                service_type: device.service_type,
            });
        }
        Ok(device)
    }

    pub fn query_value(&mut self, key: QueryKey) -> Result<Value, RamrodError> {
        self.query_value_named(key.wire_name())
    }

    pub fn query_value_named(&mut self, key: &str) -> Result<Value, RamrodError> {
        let mut body = Dictionary::new();
        body.insert(
            super::message::KEY_REQUEST.to_string(),
            Value::String(Request::QueryValue.wire_name().to_string()),
        );
        body.insert(KEY_QUERY_KEY.to_string(), Value::String(key.to_string()));
        self.send(&Value::Dictionary(body))?;

        let reply = self.receive_reply(Request::QueryValue)?;
        reply
            .get(KEY_QUERY_VALUE)
            .cloned()
            .ok_or_else(|| RamrodError::ValueNotAvailable {
                key: key.to_string(),
            })
    }

    pub fn start_restore(&mut self, options: RestoreOptions) -> Result<(), RamrodError> {
        if self.restore_started {
            return Err(RamrodError::RestoreAlreadyStarted);
        }
        let options = options.into_value()?;
        let mut body = Dictionary::new();
        body.insert(
            super::message::KEY_REQUEST.to_string(),
            Value::String(Request::StartRestore.wire_name().to_string()),
        );
        if let Some(version) = self.device_protocol_version {
            body.insert(
                KEY_RESTORE_PROTOCOL_VERSION.to_string(),
                Value::Integer(version.into()),
            );
        }
        body.insert(KEY_RESTORE_OPTIONS.to_string(), options);
        self.send(&Value::Dictionary(body))?;
        self.restore_started = true;
        Ok(())
    }

    pub fn reboot(&mut self) -> Result<(), RamrodError> {
        self.send(&Request::Reboot.to_value())
    }

    pub fn goodbye(&mut self) -> Result<Dictionary, RamrodError> {
        self.send(&Request::Goodbye.to_value())?;
        self.receive_reply(Request::Goodbye)
    }

    pub fn run_restore<P, B, O>(
        &mut self,
        provider: &mut P,
        bulk: &mut B,
        observer: &mut O,
    ) -> Result<RestoreSummary, RamrodError>
    where
        P: RestoreDataProvider + ?Sized,
        B: BulkTransferService + Send + ?Sized,
        O: SessionObserver + ?Sized,
    {
        if !self.restore_started {
            return Err(RamrodError::RestoreNotStarted);
        }
        let bulk = Mutex::new(bulk);
        std::thread::scope(|scope| {
            let mut summary = RestoreSummary::default();
            let mut in_flight: Option<InFlightTransfer<'_>> = None;

            let loop_result = (|| -> Result<(), RamrodError> {
                loop {
                    if let Some((handle, _, _)) = in_flight.as_ref()
                        && handle.is_finished()
                    {
                        let (handle, request, port) =
                            in_flight.take().expect("checked is_finished above");
                        join_bulk_transfer(handle, &request, port, observer, &mut summary)?;
                    }

                    let Some(inbound) = self.receive()? else {
                        return Ok(());
                    };
                    let message = match inbound {
                        Inbound::Device(message) => message,
                        Inbound::Untyped(body) => {
                            summary.untyped_messages += 1;
                            observer.on_message("", &body);
                            continue;
                        }
                    };

                    match message.msg_type {
                        MsgType::DataRequestMsg | MsgType::AsyncDataRequestMsg => {
                            let request = message.as_data_request().ok_or_else(|| {
                                RamrodError::MalformedDataRequest {
                                    msg_type: message.msg_type.wire_name().to_string(),
                                }
                            })?;
                            if request.asynchronous {
                                summary.async_data_requests += 1;
                            }
                            observer.on_data_request(&request);
                            match request.data_port {
                                Some(port) if request.asynchronous => {
                                    if let Some((handle, prior_request, prior_port)) =
                                        in_flight.take()
                                    {
                                        join_bulk_transfer(
                                            handle,
                                            &prior_request,
                                            prior_port,
                                            observer,
                                            &mut summary,
                                        )?;
                                    }
                                    observer.on_bulk_serving(&request, port);
                                    let for_thread = request.clone();
                                    let bulk = &bulk;
                                    let handle = scope.spawn(move || {
                                        let mut guard = bulk
                                            .lock()
                                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                                        guard.serve(port, &for_thread)
                                    });
                                    in_flight = Some((handle, request, port));
                                }
                                _ => {
                                    self.answer_data_request(
                                        &request,
                                        provider,
                                        &bulk,
                                        observer,
                                        &mut summary,
                                    )?;
                                }
                            }
                        }
                        MsgType::AsyncWait => {
                            summary.async_waits += 1;
                            observer.on_async_wait(message.async_context_uuid(), &message.body);
                        }
                        MsgType::ProgressMsg => {
                            summary.progress_messages += 1;
                            let progress =
                                message.as_progress().unwrap_or(super::message::Progress {
                                    operation: None,
                                    fraction: None,
                                });
                            observer.on_progress(progress.operation, progress.fraction);
                        }
                        MsgType::StatusMsg => {
                            summary.status_messages += 1;
                            let status = message.as_status();
                            if let Some(final_status) = message.as_final_status() {
                                summary.final_status = Some(final_status);
                                observer.on_final_status(&final_status, &message.body);
                            }
                            if let Some(log) = message.body.get(KEY_LOG).and_then(Value::as_string)
                            {
                                summary.guest_log = Some(log.to_string());
                            }
                            match status {
                                Some(status) => {
                                    summary.last_status = Some(status);
                                    observer.on_status(status, &message.body);
                                }
                                None => {
                                    observer.on_message(message.msg_type.wire_name(), &message.body)
                                }
                            }
                            acknowledge_final_status(
                                &mut self.transport,
                                self.format,
                                &mut summary,
                                observer,
                                status,
                            )?;
                        }
                        MsgType::CheckpointMsg => {
                            summary.checkpoints += 1;
                            match message.as_checkpoint() {
                                Some(checkpoint) => {
                                    if checkpoint.ends_step() {
                                        summary.checkpoints_ended += 1;
                                    } else {
                                        summary.checkpoints_begun += 1;
                                        let name =
                                            checkpoint.name.map(str::to_string).or_else(|| {
                                                checkpoint.id.map(|id| format!("0x{id:04X}"))
                                            });
                                        if name
                                            .as_deref()
                                            .is_none_or(|name| !name.starts_with("cleanup_"))
                                        {
                                            summary.open_checkpoint = name;
                                        }
                                    }
                                    observer.on_checkpoint(&checkpoint, &message.body);
                                    if let Some(text) = message
                                        .body
                                        .get(KEY_CHECKPOINT_ERROR)
                                        .and_then(checkpoint_error_text)
                                        && summary.checkpoint_error.is_none()
                                    {
                                        summary.checkpoint_error = Some(text);
                                    }
                                    if summary.final_status_acks_sent == 0
                                        && checkpoint_is_final_status_wait(&checkpoint)
                                    {
                                        let status = summary.last_status;
                                        acknowledge_final_status(
                                            &mut self.transport,
                                            self.format,
                                            &mut summary,
                                            observer,
                                            status,
                                        )?;
                                    }
                                }
                                None => {
                                    observer.on_message(message.msg_type.wire_name(), &message.body)
                                }
                            }
                        }
                        MsgType::CrashLog => {
                            summary.crash_logs += 1;
                            let crash = message.as_crash_log().unwrap_or(message::CrashLog {
                                filename: None,
                                data: None,
                            });
                            let name = crash_log_file_name(crash.filename, summary.crash_logs);
                            match write_crash_log(&self.crash_log_directory, &name, crash.data) {
                                Ok(path) => {
                                    summary.crash_logs_written += 1;
                                    observer.on_crash_log(
                                        crash.filename.unwrap_or(&name),
                                        crash.data.map_or(0, <[u8]>::len),
                                        Some(&path),
                                        None,
                                    );
                                }
                                Err(reason) => observer.on_crash_log(
                                    crash.filename.unwrap_or(&name),
                                    crash.data.map_or(0, <[u8]>::len),
                                    None,
                                    Some(&reason),
                                ),
                            }
                        }
                        MsgType::ReceivedFinalStatusMsg => {
                            summary.guest_echoed_final_status = true;
                            observer.on_message(message.msg_type.wire_name(), &message.body);
                            return Ok(());
                        }
                        _ => observer.on_message(message.msg_type.wire_name(), &message.body),
                    }
                }
            })();

            let join_result = match in_flight.take() {
                Some((handle, request, port)) => {
                    join_bulk_transfer(handle, &request, port, observer, &mut summary)
                }
                None => Ok(()),
            };

            match (loop_result, join_result) {
                (Ok(()), Ok(())) => Ok(summary),
                (Err(error), _) if connection_gone_ramrod(&error) => {
                    if summary.final_status_acks_sent == 0 {
                        let status = summary.last_status;
                        let _ = acknowledge_final_status(
                            &mut self.transport,
                            self.format,
                            &mut summary,
                            observer,
                            status,
                        );
                    }
                    Ok(summary)
                }
                (Err(error), _) => Err(error),
                (Ok(()), Err(error)) => Err(error),
            }
        })
    }

    fn answer_data_request<P, B, O>(
        &mut self,
        request: &DataRequest,
        provider: &mut P,
        bulk: &Mutex<&mut B>,
        observer: &mut O,
        summary: &mut RestoreSummary,
    ) -> Result<(), RamrodError>
    where
        P: RestoreDataProvider + ?Sized,
        B: BulkTransferService + ?Sized,
        O: SessionObserver + ?Sized,
    {
        match request.data_port {
            Some(port) => {
                observer.on_bulk_serving(request, port);
                let result = {
                    let mut guard = bulk
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    guard.serve(port, request)
                };
                report_bulk_outcome(result, request, port, observer, summary)?;
            }
            None => {
                if let Some(result) = provider.supply_streamed(request) {
                    let object = match result {
                        Ok(object) => object,
                        Err(source) => {
                            observer.on_data_unanswered(request, &source);
                            return Err(RamrodError::Provider {
                                data_type: request.data_type.wire_name().to_string(),
                                source,
                            });
                        }
                    };
                    let object_bytes = object.len();
                    let (count, framed, bulk_class) = self.write_streamed_object(&object)?;
                    summary.data_requests += 1;
                    if let Some(class) = bulk_class {
                        observer.on_stream_thread_class(request, class);
                    }
                    observer.on_data_streamed(
                        request,
                        usize::try_from(object_bytes).unwrap_or(usize::MAX),
                        count,
                        framed,
                    );
                    return Ok(());
                }
                let body = match provider.supply(request) {
                    Ok(body) => body,
                    Err(source) => {
                        observer.on_data_unanswered(request, &source);
                        return Err(RamrodError::Provider {
                            data_type: request.data_type.wire_name().to_string(),
                            source,
                        });
                    }
                };
                let keys: Vec<String> = body.keys().cloned().collect();
                let bytes = match codec::write_message(
                    &mut self.transport,
                    &Value::Dictionary(body),
                    self.format,
                ) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        observer.on_control_send_failed(request, &error.to_string());
                        return Err(error.into());
                    }
                };
                summary.data_requests += 1;
                let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
                observer.on_data_answered(request, &keys, bytes);
            }
        }
        Ok(())
    }

    fn write_streamed_object(
        &mut self,
        object: &StreamedObject,
    ) -> Result<(usize, usize, Option<ThreadClass>), RamrodError> {
        let total = object.len();
        let stride = message::streamed_stride(total, object.chunk_size);
        let mut count = 0;
        let mut framed = 0;
        let mut bulk_class = None;
        let write = |transport: &mut T, format, chunk: &[u8], size: Option<u64>| {
            let body = message::streamed_chunk_message(chunk, size);
            codec::write_message(transport, &Value::Dictionary(body), format)
        };
        match &object.payload {
            StreamedPayload::Bytes(bytes) => {
                for chunk in bytes.chunks(stride) {
                    let size = (count == 0).then_some(total);
                    framed += write(&mut self.transport, self.format, chunk, size)?;
                    count += 1;
                }
            }
            StreamedPayload::File { path, len } => {
                let stride = stride.min(STREAMED_FILE_MAX_CHUNK);
                let transport = &mut self.transport;
                let format = self.format;
                let ((result, sent_count, sent_framed), bulk) =
                    // Utility, not background: background is also I/O throttling tier 3 on Darwin, which would throttle the reads the guest is blocked on.
                    with_thread_class(ThreadClass::Utility, || {
                        let mut count = 0usize;
                        let mut framed = 0usize;
                        let result = (|| -> Result<(), RamrodError> {
                            let mut file = std::fs::File::open(path).map_err(|error| {
                                RamrodError::Provider {
                                    data_type: path.display().to_string(),
                                    source: ProviderError::Io(error),
                                }
                            })?;
                            let mut buffer = vec![0u8; stride];
                            let mut sent = 0u64;
                            while sent < *len {
                                let want = usize::try_from((*len - sent).min(stride as u64))
                                    .unwrap_or(stride)
                                    .min(stride);
                                file.read_exact(&mut buffer[..want]).map_err(|error| {
                                    RamrodError::Provider {
                                        data_type: path.display().to_string(),
                                        source: ProviderError::Io(error),
                                    }
                                })?;
                                let size = (count == 0).then_some(total);
                                framed += write(transport, format, &buffer[..want], size)?;
                                count += 1;
                                sent += want as u64;
                            }
                            Ok(())
                        })();
                        (result, count, framed)
                    });
                result?;
                count += sent_count;
                framed += sent_framed;
                bulk_class = Some(bulk.class);
            }
        }
        let done = message::streamed_done_message(count == 0);
        framed += codec::write_message(&mut self.transport, &Value::Dictionary(done), self.format)?;
        Ok((count + 1, framed, bulk_class))
    }
}

pub fn connect_and_identify<D, C>(
    dialer: &mut D,
    plan: DialPlan,
    clock: &mut C,
) -> Result<(RamrodClient<D::Stream>, DeviceType), RamrodError>
where
    D: GuestDialer,
    C: Clock,
{
    let outcome = dial_until(dialer, plan, clock)?;
    let mut client = RamrodClient::new(outcome.stream);
    let device = client.query_restored()?;
    Ok((client, device))
}

#[derive(Debug)]
pub enum RamrodError {
    Codec(CodecError),
    Dial(DialError),
    Options(OptionsError),
    Provider {
        data_type: String,
        source: ProviderError,
    },
    NotADictionary,
    ClosedBeforeReply {
        request: Request,
    },
    UnexpectedDeviceMessage {
        request: Request,
        msg_type: String,
    },
    MalformedReply {
        request: Request,
        reason: &'static str,
    },
    ValueNotAvailable {
        key: String,
    },
    NotRestored {
        service_type: String,
    },
    MalformedDataRequest {
        msg_type: String,
    },
    RestoreNotStarted,
    RestoreAlreadyStarted,
}

impl fmt::Display for RamrodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(f, "{error}"),
            Self::Dial(error) => write!(f, "{error}"),
            Self::Options(error) => write!(f, "{error}"),
            Self::Provider { data_type, source } => {
                write!(f, "could not answer a {data_type} request: {source}")
            }
            Self::NotADictionary => {
                f.write_str("a message arrived whose top-level value is not a dictionary")
            }
            Self::ClosedBeforeReply { request } => {
                write!(
                    f,
                    "the guest closed the connection without replying to {request}"
                )
            }
            Self::UnexpectedDeviceMessage { request, msg_type } => write!(
                f,
                "a {msg_type} arrived where the reply to {request} was due"
            ),
            Self::MalformedReply { request, reason } => {
                write!(f, "malformed reply to {request}: {reason}")
            }
            Self::ValueNotAvailable { key } => {
                write!(f, "the guest does not supply a value for {key}")
            }
            Self::NotRestored { service_type } => write!(
                f,
                "the port answered as {service_type}, not {}",
                super::message::SERVICE_TYPE
            ),
            Self::MalformedDataRequest { msg_type } => {
                write!(f, "a {msg_type} arrived with no DataType")
            }
            Self::RestoreNotStarted => f.write_str("run_restore was called before start_restore"),
            Self::RestoreAlreadyStarted => {
                f.write_str("start_restore was called twice on one connection")
            }
        }
    }
}

impl std::error::Error for RamrodError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Codec(error) => Some(error),
            Self::Dial(error) => Some(error),
            Self::Options(error) => Some(error),
            Self::Provider { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<CodecError> for RamrodError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

fn connection_gone(error: &CodecError) -> bool {
    match error {
        CodecError::Io(error) => matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::UnexpectedEof
        ),
        CodecError::Truncated { .. } => true,
        _ => false,
    }
}

fn connection_gone_ramrod(error: &RamrodError) -> bool {
    match error {
        RamrodError::Codec(error) => connection_gone(error),
        _ => false,
    }
}

fn checkpoint_error_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Value::Dictionary(dict) => {
            const DESCRIPTION_KEYS: [&str; 5] = [
                "NSLocalizedDescription",
                "NSLocalizedFailureReason",
                "localizedDescription",
                "description",
                "Description",
            ];
            for key in DESCRIPTION_KEYS {
                if let Some(text) = dict.get(key).and_then(checkpoint_error_text) {
                    return Some(text);
                }
            }
            const NESTED_KEYS: [&str; 5] = [
                "NSUnderlyingError",
                "userInfo",
                "UserInfo",
                "error",
                "Error",
            ];
            for key in NESTED_KEYS {
                if let Some(text) = dict.get(key).and_then(checkpoint_error_text) {
                    return Some(text);
                }
            }
            dict.values().find_map(checkpoint_error_text)
        }
        Value::Array(items) => items.iter().find_map(checkpoint_error_text),
        Value::Data(bytes) => std::str::from_utf8(bytes).ok().and_then(|text| {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }),
        _ => None,
    }
}

fn checkpoint_is_final_status_wait(checkpoint: &super::message::Checkpoint<'_>) -> bool {
    const SEND_FINAL_STATUS: i64 = 0x0648;
    const WAIT_STATUS_RECEIVED: i64 = 0x0649;
    if matches!(
        checkpoint.id,
        Some(SEND_FINAL_STATUS | WAIT_STATUS_RECEIVED)
    ) {
        return true;
    }
    checkpoint.name.is_some_and(|name| {
        name.contains("cleanup_wait_status_received") || name.contains("cleanup_send_final_status")
    })
}

fn acknowledge_final_status<T, O>(
    transport: &mut T,
    format: super::codec::PlistFormat,
    summary: &mut RestoreSummary,
    observer: &mut O,
    status: Option<i64>,
) -> Result<(), RamrodError>
where
    T: Write,
    O: SessionObserver + ?Sized,
{
    match codec::write_message(
        transport,
        &super::message::final_status_acknowledgement(),
        format,
    ) {
        Ok(bytes) => {
            summary.final_status_acks_sent += 1;
            observer.on_final_status_acknowledged(status, bytes);
            Ok(())
        }
        Err(error) if connection_gone(&error) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

impl From<DialError> for RamrodError {
    fn from(error: DialError) -> Self {
        Self::Dial(error)
    }
}

impl From<OptionsError> for RamrodError {
    fn from(error: OptionsError) -> Self {
        Self::Options(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ramrod::message::{
        DataType, KEY_AM_R_ERROR, KEY_ARGUMENTS, KEY_CHECKPOINT_COMPLETE, KEY_CHECKPOINT_ERROR,
        KEY_CHECKPOINT_ID, KEY_CHECKPOINT_NAME, KEY_DATA_PORT, KEY_DATA_TYPE, KEY_LOG,
        KEY_OPERATION, KEY_PROGRESS, KEY_REQUEST, KEY_RESULT, KEY_STATUS, KEY_SUCCESSFUL,
        KEY_SUPPORTED_HOST_PROTOCOLS, KEY_WILL_SEND_EOF, PROTOCOL_MUX_SOCKET, RESULT_SUCCESS,
        SERVICE_TYPE, SystemImageFormat,
    };
    use crate::ramrod::provider::{NoBulkTransfers, PreparedAnswers};
    use plist::Integer;
    use std::io;
    use std::time::{Duration, Instant};

    struct ScriptedTransport {
        inbound: Vec<u8>,
        cursor: usize,
        outbound: Vec<u8>,
        chunk: usize,
    }

    impl ScriptedTransport {
        fn new(messages: &[Value]) -> Self {
            Self::fragmented(messages, usize::MAX)
        }

        fn fragmented(messages: &[Value], chunk: usize) -> Self {
            let mut inbound = Vec::new();
            for message in messages {
                inbound.extend_from_slice(
                    &codec::encode_message(message, PlistFormat::Binary).expect("encodes"),
                );
            }
            Self {
                inbound,
                cursor: 0,
                outbound: Vec::new(),
                chunk,
            }
        }

        fn written(&self) -> Vec<Value> {
            let mut cursor = &self.outbound[..];
            let mut written = Vec::new();
            while let Some(value) = codec::read_message(&mut cursor).expect("decodes") {
                written.push(value);
            }
            written
        }
    }

    impl Read for ScriptedTransport {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let remaining = &self.inbound[self.cursor..];
            let count = remaining.len().min(buf.len()).min(self.chunk);
            buf[..count].copy_from_slice(&remaining[..count]);
            self.cursor += count;
            Ok(count)
        }
    }

    impl Write for ScriptedTransport {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.outbound.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct BrokenPipeAfterStart {
        inner: ScriptedTransport,
        writes: usize,
    }

    impl BrokenPipeAfterStart {
        fn new(messages: &[Value]) -> Self {
            Self {
                inner: ScriptedTransport::new(messages),
                writes: 0,
            }
        }
    }

    impl Read for BrokenPipeAfterStart {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.inner.read(buf)
        }
    }

    impl Write for BrokenPipeAfterStart {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.writes > 1 {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            self.inner.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct BrokenPipeAfterMessages {
        inner: ScriptedTransport,
    }

    impl BrokenPipeAfterMessages {
        fn new(messages: &[Value]) -> Self {
            Self {
                inner: ScriptedTransport::new(messages),
            }
        }
    }

    impl Read for BrokenPipeAfterMessages {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let count = self.inner.read(buf)?;
            if count == 0 {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            Ok(count)
        }
    }

    impl Write for BrokenPipeAfterMessages {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.inner.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn dict(pairs: Vec<(&str, Value)>) -> Value {
        let mut body = Dictionary::new();
        for (key, value) in pairs {
            body.insert(key.to_string(), value);
        }
        Value::Dictionary(body)
    }

    fn query_type_reply() -> Value {
        dict(vec![
            (KEY_TYPE, Value::String(SERVICE_TYPE.into())),
            (KEY_RESULT, Value::String(RESULT_SUCCESS.into())),
            (
                KEY_RESTORE_PROTOCOL_VERSION,
                Value::Integer(Integer::from(15)),
            ),
            ("SerialNumber", Value::String("F4GXXXXXXXXX".into())),
            ("HardwareModel", Value::String("J413AP".into())),
        ])
    }

    fn data_request(data_type: &str, port: Option<i64>) -> Value {
        let mut pairs = vec![
            (KEY_MSG_TYPE, Value::String("DataRequestMsg".into())),
            (KEY_DATA_TYPE, Value::String(data_type.into())),
        ];
        if let Some(port) = port {
            pairs.push((KEY_DATA_PORT, Value::Integer(Integer::from(port))));
        }
        dict(pairs)
    }

    fn async_data_request(data_type: &str, port: Option<i64>) -> Value {
        let mut pairs = vec![
            (KEY_MSG_TYPE, Value::String("AsyncDataRequestMsg".into())),
            (KEY_DATA_TYPE, Value::String(data_type.into())),
        ];
        if let Some(port) = port {
            pairs.push((KEY_DATA_PORT, Value::Integer(Integer::from(port))));
        }
        dict(pairs)
    }

    fn final_status() -> Value {
        dict(vec![(
            KEY_MSG_TYPE,
            Value::String("ReceivedFinalStatusMsg".into()),
        )])
    }

    #[derive(Default)]
    struct Recorder {
        events: Vec<String>,
    }

    impl SessionObserver for Recorder {
        fn on_progress(&mut self, operation: Option<i64>, fraction: Option<f64>) {
            self.events
                .push(format!("progress {operation:?} {fraction:?}"));
        }
        fn on_status(&mut self, status: i64, _body: &Dictionary) {
            self.events.push(format!("status {status}"));
        }
        fn on_final_status_acknowledged(&mut self, status: Option<i64>, bytes: usize) {
            assert!(bytes > 0, "an acknowledgement of no bytes is not one");
            self.events.push(format!("acked {status:?}"));
        }
        fn on_message(&mut self, msg_type: &str, _body: &Dictionary) {
            self.events.push(format!("message {msg_type}"));
        }
        fn on_checkpoint(&mut self, checkpoint: &message::Checkpoint<'_>, _body: &Dictionary) {
            self.events
                .push(format!("checkpoint {}", checkpoint.id_display()));
        }
        fn on_data_request(&mut self, request: &DataRequest) {
            self.events
                .push(format!("request {}", request.data_type.wire_name()));
        }
        fn on_data_answered(&mut self, request: &DataRequest, keys: &[&str], bytes: usize) {
            self.events.push(format!(
                "answered {} keys=[{}] bytes={bytes}",
                request.data_type.wire_name(),
                keys.join(",")
            ));
        }
        fn on_bulk_served(&mut self, request: &DataRequest, port: u16, outcome: &BulkOutcome) {
            let bytes = match outcome {
                BulkOutcome::Served { bytes, .. } => *bytes,
                BulkOutcome::Declined { .. } => 0,
            };
            self.events.push(format!(
                "bulk {} port={port} bytes={bytes}",
                request.data_type.wire_name()
            ));
        }
        fn on_bulk_served_empty(
            &mut self,
            request: &DataRequest,
            port: u16,
            _outcome: &BulkOutcome,
        ) {
            self.events.push(format!(
                "bulk-empty {} port={port}",
                request.data_type.wire_name()
            ));
        }
        fn on_data_unanswered(&mut self, request: &DataRequest, error: &ProviderError) {
            self.events.push(format!(
                "unanswered {} {error}",
                request.data_type.wire_name()
            ));
        }
    }

    #[derive(Default)]
    struct RecordingBulk {
        served: Vec<(u16, String)>,
    }

    impl BulkTransferService for RecordingBulk {
        fn serve(
            &mut self,
            port: u16,
            request: &DataRequest,
        ) -> Result<BulkOutcome, ProviderError> {
            self.served
                .push((port, request.data_type.wire_name().to_string()));
            Ok(BulkOutcome::Served {
                bytes: 4096,
                blocks: 4,
                initiates: 1,
                metadata_requests: 0,
                oob_requests: 0,
                oob_bytes: 0,
            })
        }
    }

    #[derive(Default)]
    struct DecliningBulk {
        declined: Vec<(u16, String)>,
    }

    impl BulkTransferService for DecliningBulk {
        fn serve(
            &mut self,
            port: u16,
            request: &DataRequest,
        ) -> Result<BulkOutcome, ProviderError> {
            self.declined
                .push((port, request.data_type.wire_name().to_string()));
            Ok(BulkOutcome::Declined {
                reason: format!("no image is configured for {}", request.data_type),
            })
        }
    }

    struct ScriptedDialer {
        refusals_remaining: u32,
        script: Vec<Value>,
        attempts: u32,
    }

    impl GuestDialer for ScriptedDialer {
        type Stream = ScriptedTransport;

        fn dial(&mut self, _port: u16, _timeout: Duration) -> io::Result<Self::Stream> {
            self.attempts += 1;
            if self.refusals_remaining > 0 {
                self.refusals_remaining -= 1;
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "guest refused",
                ));
            }
            Ok(ScriptedTransport::new(&self.script))
        }
    }

    struct InstantClock {
        base: Instant,
        elapsed: Duration,
    }

    impl Clock for InstantClock {
        fn now(&self) -> Instant {
            self.base + self.elapsed
        }
        fn sleep(&mut self, duration: Duration) {
            self.elapsed += duration;
        }
    }

    fn virtual_clock() -> InstantClock {
        InstantClock {
            base: Instant::now(),
            elapsed: Duration::ZERO,
        }
    }

    #[test]
    fn the_armed_entry_point_retries_then_identifies_the_service() {
        let mut dialer = ScriptedDialer {
            refusals_remaining: 3,
            script: vec![query_type_reply()],
            attempts: 0,
        };
        let (client, device) =
            connect_and_identify(&mut dialer, DialPlan::default(), &mut virtual_clock()).unwrap();

        assert_eq!(dialer.attempts, 4, "the refusals must have been retried");
        assert!(device.is_restored());
        assert_eq!(device.protocol_version, Some(15));
        assert!(
            !client.restore_started(),
            "identifying must not have started a restore"
        );
        assert_eq!(client.into_inner().written().len(), 1);
    }

    #[test]
    fn the_armed_entry_point_reports_a_closed_window_as_a_dial_failure() {
        let mut dialer = ScriptedDialer {
            refusals_remaining: u32::MAX,
            script: Vec::new(),
            attempts: 0,
        };
        let plan = DialPlan::default().with_window(Duration::from_secs(5));
        match connect_and_identify(&mut dialer, plan, &mut virtual_clock()) {
            Err(RamrodError::Dial(DialError::WindowClosed { port, .. })) => {
                assert_eq!(port, RAMROD_PORT)
            }
            other => panic!("expected a dial failure, got {other:?}"),
        }
        assert!(dialer.attempts > 1);
    }

    #[test]
    fn the_armed_entry_point_refuses_a_port_that_is_not_restored() {
        let mut dialer = ScriptedDialer {
            refusals_remaining: 0,
            script: vec![dict(vec![(
                KEY_TYPE,
                Value::String("com.apple.mobile.lockdown".into()),
            )])],
            attempts: 0,
        };
        assert!(matches!(
            connect_and_identify(&mut dialer, DialPlan::default(), &mut virtual_clock()),
            Err(RamrodError::NotRestored { .. })
        ));
    }

    #[test]
    fn the_default_port_is_the_one_the_guest_binds() {
        assert_eq!(RAMROD_PORT, 62078);
        assert_eq!(RAMROD_PORT, 0xF27E);
    }

    #[test]
    fn query_type_writes_one_request_and_reads_the_identity_out_of_the_reply() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[query_type_reply()]));
        let device = client.query_type().unwrap();

        assert_eq!(device.service_type, SERVICE_TYPE);
        assert!(device.is_restored());
        assert_eq!(device.protocol_version, Some(15));
        assert_eq!(device.string("HardwareModel"), Some("J413AP"));

        let written = client.into_inner().written();
        assert_eq!(written.len(), 1);
        assert_eq!(
            written[0]
                .as_dictionary()
                .unwrap()
                .get(KEY_REQUEST)
                .unwrap()
                .as_string(),
            Some("QueryType")
        );
    }

    #[test]
    fn query_restored_refuses_a_port_that_answers_as_something_else() {
        let reply = dict(vec![(
            KEY_TYPE,
            Value::String("com.apple.mobile.lockdown".into()),
        )]);
        let mut client = RamrodClient::new(ScriptedTransport::new(&[reply]));
        match client.query_restored() {
            Err(RamrodError::NotRestored { service_type }) => {
                assert_eq!(service_type, "com.apple.mobile.lockdown")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_query_type_reply_with_no_type_is_malformed_not_silently_accepted() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[dict(vec![(
            KEY_RESULT,
            Value::String(RESULT_SUCCESS.into()),
        )])]));
        assert!(matches!(
            client.query_type(),
            Err(RamrodError::MalformedReply { .. })
        ));
    }

    #[test]
    fn a_whole_exchange_survives_one_byte_at_a_time_fragmentation() {
        let mut client = RamrodClient::new(ScriptedTransport::fragmented(&[query_type_reply()], 1));
        let device = client.query_type().unwrap();
        assert_eq!(device.protocol_version, Some(15));
    }

    #[test]
    fn query_value_sends_the_key_and_returns_the_answer() {
        let reply = dict(vec![
            (KEY_QUERY_VALUE, Value::String("F4GXXXXXXXXX".into())),
            (KEY_RESULT, Value::String(RESULT_SUCCESS.into())),
        ]);
        let mut client = RamrodClient::new(ScriptedTransport::new(&[reply]));
        let value = client.query_value(QueryKey::SerialNumber).unwrap();
        assert_eq!(value.as_string(), Some("F4GXXXXXXXXX"));

        let written = client.into_inner().written();
        let body = written[0].as_dictionary().unwrap();
        assert_eq!(
            body.get(KEY_REQUEST).unwrap().as_string(),
            Some("QueryValue")
        );
        assert_eq!(
            body.get(KEY_QUERY_KEY).unwrap().as_string(),
            Some("SerialNumber")
        );
    }

    #[test]
    fn a_query_value_reply_without_the_value_is_reported_as_unavailable() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[dict(vec![(
            KEY_RESULT,
            Value::String(RESULT_SUCCESS.into()),
        )])]));
        match client.query_value(QueryKey::Imei) {
            Err(RamrodError::ValueNotAvailable { key }) => assert_eq!(key, "IMEI"),
            other => panic!("expected unavailable, got {other:?}"),
        }
    }

    #[test]
    fn start_restore_emits_mux_socket_and_does_not_wait_for_an_acknowledgement() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[]));
        client
            .start_restore(
                RestoreOptions::new().with_system_image_format(SystemImageFormat::DiskImage),
            )
            .unwrap();
        assert!(client.restore_started());

        let written = client.into_inner().written();
        assert_eq!(written.len(), 1);
        let body = written[0].as_dictionary().unwrap();
        assert_eq!(
            body.get(KEY_REQUEST).unwrap().as_string(),
            Some("StartRestore")
        );
        let options = body
            .get(KEY_RESTORE_OPTIONS)
            .unwrap()
            .as_dictionary()
            .unwrap();
        let protocols = options
            .get(KEY_SUPPORTED_HOST_PROTOCOLS)
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(protocols[0].as_string(), Some(PROTOCOL_MUX_SOCKET));
        assert_eq!(
            options.get("SystemImageFormat").unwrap().as_string(),
            Some("DiskImage")
        );
        assert!(!options.contains_key("SystemImageType"));
        assert!(!body.contains_key(KEY_RESTORE_PROTOCOL_VERSION));
    }

    #[test]
    fn start_restore_carries_the_version_the_guest_reported_at_the_top_level() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[query_type_reply()]));
        let device = client.query_type().unwrap();
        assert_eq!(device.protocol_version, Some(15));
        assert_eq!(client.device_protocol_version(), Some(15));
        client.start_restore(RestoreOptions::new()).unwrap();

        let written = client.into_inner().written();
        let body = written[1].as_dictionary().unwrap();
        assert_eq!(
            body.get(KEY_RESTORE_PROTOCOL_VERSION)
                .unwrap()
                .as_signed_integer(),
            Some(15)
        );
        let options = body
            .get(KEY_RESTORE_OPTIONS)
            .unwrap()
            .as_dictionary()
            .unwrap();
        assert!(!options.contains_key(KEY_RESTORE_PROTOCOL_VERSION));
    }

    #[test]
    fn a_guest_that_reports_no_protocol_version_is_answered_with_none() {
        let reply = dict(vec![
            (KEY_TYPE, Value::String(SERVICE_TYPE.into())),
            (KEY_RESULT, Value::String(RESULT_SUCCESS.into())),
        ]);
        let mut client = RamrodClient::new(ScriptedTransport::new(&[reply]));
        client.query_type().unwrap();
        assert_eq!(client.device_protocol_version(), None);
        client.start_restore(RestoreOptions::new()).unwrap();
        let written = client.into_inner().written();
        assert!(
            !written[1]
                .as_dictionary()
                .unwrap()
                .contains_key(KEY_RESTORE_PROTOCOL_VERSION)
        );
    }

    #[test]
    fn start_restore_twice_on_one_connection_is_refused() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[]));
        client.start_restore(RestoreOptions::new()).unwrap();
        assert!(matches!(
            client.start_restore(RestoreOptions::new()),
            Err(RamrodError::RestoreAlreadyStarted)
        ));
    }

    #[test]
    fn run_restore_before_start_restore_is_refused_rather_than_hanging() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[]));
        assert!(matches!(
            client.run_restore(&mut PreparedAnswers::new(), &mut NoBulkTransfers, &mut ()),
            Err(RamrodError::RestoreNotStarted)
        ));
    }

    #[test]
    fn a_nor_data_reply_is_written_as_a_binary_plist() {
        struct NorAnswers;
        impl RestoreDataProvider for NorAnswers {
            fn supply(&mut self, request: &DataRequest) -> Result<Dictionary, ProviderError> {
                assert_eq!(request.data_type.wire_name(), "NORData");
                let mut body = Dictionary::new();
                body.insert(
                    "RestoreSEPImageData".to_string(),
                    Value::Data(b"rsep-bytes".to_vec()),
                );
                Ok(body)
            }
        }

        let mut client = RamrodClient::new(ScriptedTransport::new(&[
            data_request("NORData", None),
            final_status(),
        ]));
        client.start_restore(RestoreOptions::new()).unwrap();
        client
            .run_restore(&mut NorAnswers, &mut NoBulkTransfers, &mut ())
            .unwrap();
        let outbound = client.into_inner().outbound;
        let first_len = u32::from_be_bytes(outbound[0..4].try_into().unwrap()) as usize;
        let rest = &outbound[4 + first_len..];
        let nor_len = u32::from_be_bytes(rest[0..4].try_into().unwrap()) as usize;
        let nor = &rest[4..4 + nor_len];
        assert!(
            nor.starts_with(b"bplist00"),
            "NORData has no DataPort, so the restored send is a binary property list"
        );
        let decoded = codec::read_message(&mut &rest[..])
            .expect("decodes")
            .unwrap();
        assert_eq!(
            decoded
                .as_dictionary()
                .and_then(|body| body.get("RestoreSEPImageData"))
                .and_then(Value::as_data),
            Some(&b"rsep-bytes"[..])
        );
        let _ = nor_len;
    }

    #[test]
    fn a_control_connection_data_request_is_answered_with_the_prepared_body() {
        let ticket = vec![0x49u8, 0x4D, 0x34, 0x4D];
        let mut client = RamrodClient::new(ScriptedTransport::new(&[
            data_request("RecoveryOSRootTicketData", None),
            final_status(),
        ]));
        client.start_restore(RestoreOptions::new()).unwrap();

        let mut answers =
            PreparedAnswers::new().with_ticket(DataType::RecoveryOSRootTicketData, ticket.clone());
        let summary = client
            .run_restore(&mut answers, &mut NoBulkTransfers, &mut ())
            .unwrap();

        assert_eq!(summary.data_requests, 1);
        assert_eq!(summary.bulk_transfers, 0);
        assert!(summary.guest_echoed_final_status);
        assert!(
            !summary.final_status_acknowledged(),
            "no StatusMsg arrived here, so this host owed no acknowledgement and wrote none"
        );

        let written = client.into_inner().written();
        assert_eq!(written.len(), 2);
        let answer = written[1].as_dictionary().unwrap();
        assert_eq!(
            answer.get("RootTicketData").unwrap().as_data(),
            Some(&ticket[..])
        );
    }

    #[test]
    fn a_data_request_carrying_a_port_is_served_by_dialling_and_gets_no_plist_reply() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[
            data_request("RecoveryOSASRImage", Some(12345)),
            final_status(),
        ]));
        client.start_restore(RestoreOptions::new()).unwrap();

        let mut bulk = RecordingBulk::default();
        let summary = client
            .run_restore(&mut PreparedAnswers::new(), &mut bulk, &mut ())
            .unwrap();

        assert_eq!(summary.bulk_transfers, 1);
        assert_eq!(summary.data_requests, 0);
        assert_eq!(bulk.served, vec![(12345, "RecoveryOSASRImage".to_string())]);
        assert_eq!(
            client.into_inner().written().len(),
            1,
            "only the StartRestore may have been written"
        );
    }

    #[test]
    fn the_port_dialled_is_the_one_in_the_message_and_not_the_synchronous_number() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[
            data_request("RecoveryOSASRImage", Some(12346)),
            final_status(),
        ]));
        client.start_restore(RestoreOptions::new()).unwrap();

        let mut bulk = RecordingBulk::default();
        let summary = client
            .run_restore(&mut PreparedAnswers::new(), &mut bulk, &mut ())
            .unwrap();

        assert_eq!(summary.bulk_transfers, 1);
        assert_eq!(bulk.served, vec![(12346, "RecoveryOSASRImage".to_string())]);
    }

    #[test]
    fn each_asynchronous_request_is_dialled_on_the_port_it_names_as_the_counter_advances() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[
            async_data_request("SystemImageData", Some(12346)),
            async_data_request("StreamedImageDecryptionKey", Some(12347)),
            async_data_request("RecoveryOSASRImage", Some(12348)),
            final_status(),
        ]));
        client.start_restore(RestoreOptions::new()).unwrap();

        let mut bulk = RecordingBulk::default();
        let summary = client
            .run_restore(&mut PreparedAnswers::new(), &mut bulk, &mut ())
            .unwrap();

        assert_eq!(summary.bulk_transfers, 3);
        assert_eq!(
            bulk.served,
            vec![
                (12346, "SystemImageData".to_string()),
                (12347, "StreamedImageDecryptionKey".to_string()),
                (12348, "RecoveryOSASRImage".to_string()),
            ]
        );
        assert_eq!(
            client.into_inner().written().len(),
            1,
            "only the StartRestore may have been written; a bulk request is answered on its own port"
        );
    }

    #[test]
    fn a_control_request_is_answered_while_an_async_bulk_transfer_is_still_blocked() {
        use std::sync::mpsc;
        use std::time::Duration;

        struct BlockingBulk {
            release: mpsc::Receiver<()>,
        }

        impl BulkTransferService for BlockingBulk {
            fn serve(
                &mut self,
                _port: u16,
                _request: &DataRequest,
            ) -> Result<BulkOutcome, ProviderError> {
                self.release
                    .recv()
                    .expect("the test always releases this, whether or not its assertion holds");
                Ok(BulkOutcome::Served {
                    bytes: 4096,
                    blocks: 1,
                    initiates: 1,
                    metadata_requests: 0,
                    oob_requests: 0,
                    oob_bytes: 0,
                })
            }
        }

        struct AnsweredSignal {
            answered: mpsc::Sender<()>,
        }

        impl SessionObserver for AnsweredSignal {
            fn on_data_answered(&mut self, _request: &DataRequest, _keys: &[&str], _bytes: usize) {
                let _ = self.answered.send(());
            }
        }

        let ticket = vec![9u8, 9, 9];
        let mut client = RamrodClient::new(ScriptedTransport::new(&[
            async_data_request("RecoveryOSASRImage", Some(12346)),
            data_request("RecoveryOSRootTicketData", None),
            final_status(),
        ]));
        client.start_restore(RestoreOptions::new()).unwrap();

        let (release_tx, release_rx) = mpsc::channel();
        let (answered_tx, answered_rx) = mpsc::channel();
        let mut bulk = BlockingBulk {
            release: release_rx,
        };
        let mut answers =
            PreparedAnswers::new().with_ticket(DataType::RecoveryOSRootTicketData, ticket.clone());
        let mut observer = AnsweredSignal {
            answered: answered_tx,
        };

        let (answered_in_time, result) = std::thread::scope(|scope| {
            let handle = scope.spawn(|| client.run_restore(&mut answers, &mut bulk, &mut observer));

            let answered_in_time = answered_rx.recv_timeout(Duration::from_secs(5)).is_ok();

            let _ = release_tx.send(());

            let result = handle.join().expect("run_restore must not panic");
            (answered_in_time, result)
        });

        assert!(
            answered_in_time,
            "the control-connection request must be answered while the asynchronous bulk \
             transfer is still blocked in serve(), or the host stops reading the control \
             connection for the whole duration of the transfer"
        );
        let summary = result.unwrap();
        assert_eq!(summary.data_requests, 1);
        assert_eq!(summary.bulk_transfers, 1);
        assert!(summary.guest_echoed_final_status);
    }

    #[test]
    fn a_request_with_no_data_port_is_answered_on_the_control_connection_and_dials_nothing() {
        let ticket = vec![0x11u8, 0x22, 0x33];
        let mut client = RamrodClient::new(ScriptedTransport::new(&[
            data_request("RecoveryOSRootTicketData", None),
            final_status(),
        ]));
        client.start_restore(RestoreOptions::new()).unwrap();

        let mut answers =
            PreparedAnswers::new().with_ticket(DataType::RecoveryOSRootTicketData, ticket.clone());
        let mut bulk = RecordingBulk::default();
        let summary = client
            .run_restore(&mut answers, &mut bulk, &mut ())
            .unwrap();

        assert_eq!(summary.data_requests, 1);
        assert_eq!(summary.bulk_transfers, 0);
        assert!(
            bulk.served.is_empty(),
            "a request with no DataPort must dial nothing at all"
        );

        let written = client.into_inner().written();
        assert_eq!(written.len(), 2);
        let answer = written[1].as_dictionary().unwrap();
        assert_eq!(
            answer.get("RootTicketData").unwrap().as_data(),
            Some(&ticket[..])
        );
    }

    #[test]
    fn a_data_port_of_zero_is_read_as_no_port_rather_than_dialled() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[
            data_request("RecoveryOSRootTicketData", Some(0)),
            final_status(),
        ]));
        client.start_restore(RestoreOptions::new()).unwrap();

        let mut answers =
            PreparedAnswers::new().with_ticket(DataType::RecoveryOSRootTicketData, vec![9]);
        let mut bulk = RecordingBulk::default();
        let summary = client
            .run_restore(&mut answers, &mut bulk, &mut ())
            .unwrap();

        assert_eq!(summary.data_requests, 1);
        assert_eq!(summary.bulk_transfers, 0);
        assert!(bulk.served.is_empty());
    }

    #[test]
    fn an_unanswerable_request_fails_the_session_naming_the_type() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[
            data_request("SourceBootObjectV4", None),
            final_status(),
        ]));
        client.start_restore(RestoreOptions::new()).unwrap();
        match client.run_restore(&mut PreparedAnswers::new(), &mut NoBulkTransfers, &mut ()) {
            Err(RamrodError::Provider { data_type, .. }) => {
                assert_eq!(data_type, "SourceBootObjectV4")
            }
            other => panic!("expected a provider failure, got {other:?}"),
        }
    }

    #[test]
    fn a_bulk_request_with_no_service_configured_fails_loudly() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[data_request(
            "RecoveryOSASRImage",
            Some(12345),
        )]));
        client.start_restore(RestoreOptions::new()).unwrap();
        match client.run_restore(&mut PreparedAnswers::new(), &mut NoBulkTransfers, &mut ()) {
            Err(RamrodError::Provider { source, .. }) => assert!(matches!(
                source,
                ProviderError::BulkTransferNotConfigured { port: 12345, .. }
            )),
            other => panic!("expected a bulk refusal, got {other:?}"),
        }
    }

    #[test]
    fn every_answered_request_is_observed_by_type_keys_and_framed_length() {
        let ticket = vec![7u8; 5449];
        let mut client = RamrodClient::new(ScriptedTransport::new(&[
            data_request("RecoveryOSRootTicketData", None),
            data_request("RootTicket", None),
            final_status(),
        ]));
        client.start_restore(RestoreOptions::new()).unwrap();
        let mut answers = PreparedAnswers::new()
            .with_ticket(DataType::RecoveryOSRootTicketData, ticket.clone())
            .with_ticket(DataType::RootTicket, ticket);

        let mut recorder = Recorder::default();
        let summary = client
            .run_restore(&mut answers, &mut NoBulkTransfers, &mut recorder)
            .unwrap();

        assert_eq!(summary.data_requests, 2);
        let answered: Vec<&String> = recorder
            .events
            .iter()
            .filter(|event| event.starts_with("answered "))
            .collect();
        assert_eq!(answered.len(), 2, "{:?}", recorder.events);
        assert!(
            answered[0]
                .starts_with("answered RecoveryOSRootTicketData keys=[RootTicketData] bytes="),
            "{}",
            answered[0]
        );
        assert!(
            answered[1].starts_with("answered RootTicket keys=[RootTicketData] bytes="),
            "{}",
            answered[1]
        );
        for event in &answered {
            let written: usize = event
                .rsplit_once("bytes=")
                .expect("the framed length is reported")
                .1
                .parse()
                .expect("the framed length is a number");
            assert!(written > 5449, "{event}");
        }
    }

    #[test]
    fn an_unanswerable_request_names_why_before_the_session_unwinds() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[data_request(
            "SourceBootObjectV4",
            None,
        )]));
        client.start_restore(RestoreOptions::new()).unwrap();
        let mut recorder = Recorder::default();
        let error = client
            .run_restore(
                &mut PreparedAnswers::new(),
                &mut NoBulkTransfers,
                &mut recorder,
            )
            .expect_err("an unprepared type fails the session");
        assert!(matches!(error, RamrodError::Provider { .. }));
        assert_eq!(
            recorder.events,
            vec![
                "request SourceBootObjectV4".to_string(),
                "unanswered SourceBootObjectV4 no answer is prepared for a SourceBootObjectV4 request"
                    .to_string(),
            ]
        );
    }

    #[test]
    fn a_refused_bulk_transfer_names_why_and_a_served_one_names_its_port() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[data_request(
            "RecoveryOSASRImage",
            Some(12345),
        )]));
        client.start_restore(RestoreOptions::new()).unwrap();
        let mut recorder = Recorder::default();
        client
            .run_restore(
                &mut PreparedAnswers::new(),
                &mut NoBulkTransfers,
                &mut recorder,
            )
            .expect_err("no bulk service means the transfer is refused");
        assert!(
            recorder.events.iter().any(|event| event
                .starts_with("unanswered RecoveryOSASRImage the guest opened port 12345")),
            "{:?}",
            recorder.events
        );

        let mut client = RamrodClient::new(ScriptedTransport::new(&[
            data_request("RecoveryOSASRImage", Some(12345)),
            final_status(),
        ]));
        client.start_restore(RestoreOptions::new()).unwrap();
        let mut recorder = Recorder::default();
        let mut bulk = RecordingBulk::default();
        client
            .run_restore(&mut PreparedAnswers::new(), &mut bulk, &mut recorder)
            .unwrap();
        assert!(
            recorder
                .events
                .contains(&"bulk RecoveryOSASRImage port=12345 bytes=4096".to_string()),
            "{:?}",
            recorder.events
        );
    }

    #[test]
    fn reports_are_observed_in_order_and_counted_without_being_answered() {
        let messages = vec![
            dict(vec![
                (KEY_MSG_TYPE, Value::String("ProgressMsg".into())),
                (KEY_OPERATION, Value::Integer(Integer::from(28))),
                (KEY_PROGRESS, Value::Integer(Integer::from(10))),
            ]),
            dict(vec![
                (KEY_MSG_TYPE, Value::String("CheckpointMsg".into())),
                (
                    super::super::message::KEY_CHECKPOINT_ID,
                    Value::Integer(Integer::from(0x411)),
                ),
            ]),
            dict(vec![
                (KEY_MSG_TYPE, Value::String("StatusMsg".into())),
                (KEY_STATUS, Value::Integer(Integer::from(0))),
            ]),
            final_status(),
        ];
        let mut client = RamrodClient::new(ScriptedTransport::new(&messages));
        client.start_restore(RestoreOptions::new()).unwrap();

        let mut recorder = Recorder::default();
        let summary = client
            .run_restore(
                &mut PreparedAnswers::new(),
                &mut NoBulkTransfers,
                &mut recorder,
            )
            .unwrap();

        assert_eq!(summary.progress_messages, 1);
        assert_eq!(summary.checkpoints, 1);
        assert_eq!(summary.status_messages, 1);
        assert_eq!(summary.last_status, Some(0));
        assert_eq!(summary.final_status_acks_sent, 1);
        assert!(summary.final_status_acknowledged());
        assert!(!summary.guest_left_waiting());
        assert!(summary.guest_echoed_final_status);
        assert_eq!(
            recorder.events,
            vec![
                "progress Some(28) Some(10.0)".to_string(),
                "checkpoint 0x0411".to_string(),
                "status 0".to_string(),
                "acked Some(0)".to_string(),
                "message ReceivedFinalStatusMsg".to_string(),
            ]
        );
        assert_eq!(
            client.into_inner().written().len(),
            2,
            "only the status is answered"
        );
    }

    #[test]
    fn a_full_session_runs_query_start_answer_and_finish_in_order() {
        let ticket = vec![0u8, 1, 2, 3];
        let mut identity = Dictionary::new();
        identity.insert("Ap,ProductType".to_string(), Value::String("J413AP".into()));

        let mut client = RamrodClient::new(ScriptedTransport::new(&[
            query_type_reply(),
            data_request("RecoveryOSRootTicketData", None),
            data_request("BuildIdentityDict", None),
            data_request("RecoveryOSASRImage", Some(12345)),
            dict(vec![
                (KEY_MSG_TYPE, Value::String("StatusMsg".into())),
                (KEY_STATUS, Value::Integer(Integer::from(0))),
            ]),
            final_status(),
        ]));

        let device = client.query_restored().unwrap();
        assert_eq!(device.protocol_version, Some(15));
        client
            .start_restore(
                RestoreOptions::new().with_system_image_format(SystemImageFormat::DiskImage),
            )
            .unwrap();

        let mut answers = PreparedAnswers::new()
            .with_ticket(DataType::RecoveryOSRootTicketData, ticket)
            .with_build_identity(DataType::BuildIdentityDict, identity, "Customer");
        let mut bulk = RecordingBulk::default();
        let summary = client
            .run_restore(&mut answers, &mut bulk, &mut ())
            .unwrap();

        assert_eq!(summary.data_requests, 2);
        assert_eq!(summary.bulk_transfers, 1);
        assert_eq!(summary.last_status, Some(0));
        assert_eq!(summary.final_status_acks_sent, 1);
        assert!(summary.final_status_acknowledged());
        assert!(summary.guest_echoed_final_status);
        assert_eq!(bulk.served, vec![(12345, "RecoveryOSASRImage".to_string())]);

        let written = client.into_inner().written();
        assert_eq!(written.len(), 5);
        let names: Vec<_> = written
            .iter()
            .map(|value| {
                let body = value.as_dictionary().unwrap();
                body.get(KEY_REQUEST)
                    .and_then(Value::as_string)
                    .map(str::to_string)
                    .unwrap_or_else(|| {
                        let mut keys: Vec<_> = body.keys().cloned().collect();
                        keys.sort();
                        keys.join(",")
                    })
            })
            .collect();
        assert_eq!(
            names,
            vec![
                "QueryType".to_string(),
                "StartRestore".to_string(),
                "RootTicketData".to_string(),
                "BuildIdentityDict,Variant".to_string(),
                "MsgType".to_string(),
            ]
        );
    }

    #[test]
    fn the_session_ends_cleanly_when_the_guest_closes_after_the_final_status() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[dict(vec![
            (KEY_MSG_TYPE, Value::String("StatusMsg".into())),
            (KEY_STATUS, Value::Integer(Integer::from(0xFF))),
        ])]));
        client.start_restore(RestoreOptions::new()).unwrap();
        let summary = client
            .run_restore(&mut PreparedAnswers::new(), &mut NoBulkTransfers, &mut ())
            .unwrap();
        assert_eq!(summary.last_status, Some(0xFF));
        assert_eq!(
            summary.final_status_acks_sent, 1,
            "the status was answered before the guest closed"
        );
        assert!(
            !summary.guest_echoed_final_status,
            "nothing arrived from the guest under that name, and the summary must say so"
        );
        assert!(
            summary.final_status_acknowledged(),
            "the acknowledgement went out, and no absent echo may contradict that"
        );
        assert!(!summary.guest_left_waiting());
    }

    fn failed_final_status(status: i64, log: &str) -> Value {
        dict(vec![
            (KEY_MSG_TYPE, Value::String("StatusMsg".into())),
            (KEY_STATUS, Value::Integer(Integer::from(status))),
            (KEY_AM_R_ERROR, Value::Integer(Integer::from(status))),
            (KEY_SUCCESSFUL, Value::Boolean(false)),
            (KEY_WILL_SEND_EOF, Value::Boolean(true)),
            (KEY_LOG, Value::String(log.into())),
        ])
    }

    fn successful_final_status() -> Value {
        dict(vec![
            (KEY_MSG_TYPE, Value::String("StatusMsg".into())),
            (KEY_STATUS, Value::Integer(Integer::from(0))),
            (KEY_AM_R_ERROR, Value::Integer(Integer::from(0))),
            (KEY_SUCCESSFUL, Value::Boolean(true)),
            (KEY_WILL_SEND_EOF, Value::Boolean(true)),
        ])
    }

    fn assert_is_the_acknowledgement(value: &Value) {
        let body = value
            .as_dictionary()
            .expect("the guest refuses anything that is not a dictionary");
        assert_eq!(
            body.get(KEY_MSG_TYPE).and_then(Value::as_string),
            Some("ReceivedFinalStatusMsg"),
            "only this exact string gets the guest past the wait"
        );
        assert!(
            body.get(KEY_WILL_SEND_EOF).is_none(),
            "asking for EOF makes the guest block until this host closes its own end"
        );
        assert_eq!(
            body.len(),
            1,
            "the guest reads one key off this message and a second one is a claim this host cannot keep"
        );
    }

    #[test]
    fn a_broken_pipe_after_the_guest_sends_status_keeps_the_failure() {
        let mut client = RamrodClient::new(BrokenPipeAfterStart::new(&[failed_final_status(
            78,
            "Storage with invalid GPT header\nPossible blank device. Erase restore may be required.",
        )]));
        client.start_restore(RestoreOptions::new()).unwrap();
        let summary = client
            .run_restore(&mut PreparedAnswers::new(), &mut NoBulkTransfers, &mut ())
            .expect("the guest already declared the outcome");
        assert_eq!(
            summary.final_status.and_then(|status| status.successful),
            Some(false)
        );
        assert!(
            summary
                .guest_log
                .as_deref()
                .is_some_and(|log| log.contains("Erase restore may be required")),
            "{:?}",
            summary.guest_log
        );
    }

    fn checkpoint_begin(name: &str, id: i64) -> Value {
        dict(vec![
            (KEY_MSG_TYPE, Value::String("CheckpointMsg".into())),
            (KEY_CHECKPOINT_NAME, Value::String(name.into())),
            (KEY_CHECKPOINT_ID, Value::Integer(Integer::from(id))),
            (KEY_CHECKPOINT_COMPLETE, Value::Boolean(false)),
        ])
    }

    #[test]
    fn a_broken_pipe_after_restore_starts_still_acks_and_keeps_the_failed_step() {
        let mut client = RamrodClient::new(BrokenPipeAfterMessages::new(&[checkpoint_begin(
            "verify_storage_for_update",
            0x067E,
        )]));
        client.start_restore(RestoreOptions::new()).unwrap();
        let mut recorder = Recorder::default();
        let summary = client
            .run_restore(
                &mut PreparedAnswers::new(),
                &mut NoBulkTransfers,
                &mut recorder,
            )
            .expect(
                "the pipe closing after StartRestore is the guest ending, not a missing restore",
            );
        assert_eq!(
            summary.open_checkpoint.as_deref(),
            Some("verify_storage_for_update")
        );
        assert!(
            summary.final_status_acks_sent >= 1,
            "ReceivedFinalStatusMsg must go out on closure so the guest is not left in cleanup_wait_status_received: {summary:?}"
        );
        assert!(
            recorder
                .events
                .iter()
                .any(|event| event.starts_with("acked ")),
            "{:?}",
            recorder.events
        );
    }

    #[test]
    fn cleanup_wait_is_acknowledged_even_when_status_never_arrives() {
        let messages = vec![
            checkpoint_begin("verify_storage_for_update", 0x067E),
            checkpoint_begin("cleanup_wait_status_received", 0x0649),
        ];
        let mut client = RamrodClient::new(ScriptedTransport::new(&messages));
        client.start_restore(RestoreOptions::new()).unwrap();
        let summary = client
            .run_restore(&mut PreparedAnswers::new(), &mut NoBulkTransfers, &mut ())
            .unwrap();
        assert_eq!(
            summary.open_checkpoint.as_deref(),
            Some("verify_storage_for_update"),
            "cleanup steps must not rename the failed restore step"
        );
        assert_eq!(summary.final_status_acks_sent, 1);
        assert_eq!(summary.status_messages, 0);
    }

    #[test]
    fn cleanup_send_final_status_is_acknowledged_before_the_wait() {
        let messages = vec![checkpoint_begin("cleanup_send_final_status", 0x0648)];
        let mut client = RamrodClient::new(ScriptedTransport::new(&messages));
        client.start_restore(RestoreOptions::new()).unwrap();
        let summary = client
            .run_restore(&mut PreparedAnswers::new(), &mut NoBulkTransfers, &mut ())
            .unwrap();
        assert_eq!(summary.final_status_acks_sent, 1);
        assert_eq!(summary.status_messages, 0);
    }

    #[test]
    fn a_checkpoint_error_is_kept_even_when_status_never_arrives() {
        let messages = vec![
            checkpoint_begin("verify_storage_for_update", 0x067E),
            dict(vec![
                (KEY_MSG_TYPE, Value::String("CheckpointMsg".into())),
                (
                    KEY_CHECKPOINT_NAME,
                    Value::String("verify_storage_for_update".into()),
                ),
                (KEY_CHECKPOINT_ID, Value::Integer(Integer::from(0x067E))),
                (KEY_CHECKPOINT_COMPLETE, Value::Boolean(true)),
                (
                    KEY_CHECKPOINT_ERROR,
                    Value::String(
                        "[0]D(Storage with invalid GPT header 0000000000000000 0000000000000000)[1]D(Possible blank device. Erase restore may be required.)".into(),
                    ),
                ),
            ]),
            checkpoint_begin("cleanup_wait_status_received", 0x0649),
        ];
        let mut client = RamrodClient::new(ScriptedTransport::new(&messages));
        client.start_restore(RestoreOptions::new()).unwrap();
        let summary = client
            .run_restore(&mut PreparedAnswers::new(), &mut NoBulkTransfers, &mut ())
            .unwrap();
        assert_eq!(
            summary.open_checkpoint.as_deref(),
            Some("verify_storage_for_update")
        );
        assert_eq!(
            summary.checkpoint_error.as_deref(),
            Some(
                "[0]D(Storage with invalid GPT header 0000000000000000 0000000000000000)[1]D(Possible blank device. Erase restore may be required.)"
            )
        );
        assert_eq!(summary.final_status_acks_sent, 1);
    }

    #[test]
    fn a_nested_checkpoint_error_dictionary_is_flattened_to_its_description() {
        let mut user_info = Dictionary::new();
        user_info.insert(
            "NSLocalizedDescription".into(),
            Value::String("Possible blank device. Erase restore may be required.".into()),
        );
        let mut error = Dictionary::new();
        error.insert("userInfo".into(), Value::Dictionary(user_info));
        let messages = vec![dict(vec![
            (KEY_MSG_TYPE, Value::String("CheckpointMsg".into())),
            (
                KEY_CHECKPOINT_NAME,
                Value::String("verify_storage_for_update".into()),
            ),
            (KEY_CHECKPOINT_ID, Value::Integer(Integer::from(0x067E))),
            (KEY_CHECKPOINT_COMPLETE, Value::Boolean(true)),
            (KEY_CHECKPOINT_ERROR, Value::Dictionary(error)),
        ])];
        let mut client = RamrodClient::new(ScriptedTransport::new(&messages));
        client.start_restore(RestoreOptions::new()).unwrap();
        let summary = client
            .run_restore(&mut PreparedAnswers::new(), &mut NoBulkTransfers, &mut ())
            .unwrap();
        assert_eq!(
            summary.checkpoint_error.as_deref(),
            Some("Possible blank device. Erase restore may be required.")
        );
    }

    #[test]
    fn a_wait_checkpoint_named_only_by_id_is_still_acknowledged() {
        let messages = vec![dict(vec![
            (KEY_MSG_TYPE, Value::String("CheckpointMsg".into())),
            (KEY_CHECKPOINT_ID, Value::Integer(Integer::from(0x0649))),
            (KEY_CHECKPOINT_COMPLETE, Value::Boolean(false)),
        ])];
        let mut client = RamrodClient::new(ScriptedTransport::new(&messages));
        client.start_restore(RestoreOptions::new()).unwrap();
        let summary = client
            .run_restore(&mut PreparedAnswers::new(), &mut NoBulkTransfers, &mut ())
            .unwrap();
        assert_eq!(summary.final_status_acks_sent, 1);
    }

    #[test]
    fn the_final_status_of_a_failed_restore_is_acknowledged() {
        let messages = vec![failed_final_status(6, "restore failed with CFError:")];
        let mut client = RamrodClient::new(ScriptedTransport::new(&messages));
        client.start_restore(RestoreOptions::new()).unwrap();

        let mut recorder = Recorder::default();
        let summary = client
            .run_restore(
                &mut PreparedAnswers::new(),
                &mut NoBulkTransfers,
                &mut recorder,
            )
            .unwrap();

        assert_eq!(summary.last_status, Some(6));
        assert_eq!(summary.status_messages, 1);
        assert_eq!(summary.final_status_acks_sent, 1);
        assert_eq!(
            recorder.events,
            vec!["status 6".to_string(), "acked Some(6)".to_string()],
            "the status is answered as well as read"
        );

        let written = client.into_inner().written();
        assert_eq!(written.len(), 2, "StartRestore, then the acknowledgement");
        assert_is_the_acknowledgement(&written[1]);
    }

    #[test]
    fn run_seventy_replays_into_a_summary_that_matches_the_wire() {
        struct AnswersAnything;
        impl RestoreDataProvider for AnswersAnything {
            fn supply(&mut self, _request: &DataRequest) -> Result<Dictionary, ProviderError> {
                Ok(Dictionary::new())
            }
        }

        let progress = |operation: i64| {
            dict(vec![
                (KEY_MSG_TYPE, Value::String("ProgressMsg".into())),
                (KEY_OPERATION, Value::Integer(Integer::from(operation))),
            ])
        };
        let messages = vec![
            data_request("RecoveryOSRootTicketData", None),
            data_request("RootTicket", None),
            progress(28),
            progress(58),
            data_request("NORData", None),
            data_request("FDRTrustData", None),
            failed_final_status(6, "restore failed with CFError:"),
        ];
        let mut client = RamrodClient::new(ScriptedTransport::new(&messages));
        client.start_restore(RestoreOptions::new()).unwrap();
        let summary = client
            .run_restore(&mut AnswersAnything, &mut NoBulkTransfers, &mut ())
            .unwrap();

        assert_eq!(
            summary,
            RestoreSummary {
                data_requests: 4,
                bulk_transfers: 0,
                async_data_requests: 0,
                async_waits: 0,
                bulk_declined: 0,
                bulk_empty: 0,
                progress_messages: 2,
                status_messages: 1,
                final_status_acks_sent: 1,
                checkpoints: 0,
                checkpoints_begun: 0,
                checkpoints_ended: 0,
                open_checkpoint: None,
                untyped_messages: 0,
                last_status: Some(6),
                final_status: Some(super::message::FinalStatus {
                    status: Some(6),
                    amr_error: Some(6),
                    successful: Some(false),
                    will_send_eof: Some(true),
                    has_checkpoint_stats: false,
                    has_log: true,
                }),
                guest_echoed_final_status: false,
                crash_logs: 0,
                crash_logs_written: 0,
                guest_log: Some("restore failed with CFError:".into()),
                checkpoint_error: None,
            }
        );
        assert!(
            summary.final_status_acknowledged(),
            "the acknowledgement was written, and no field of this summary may say otherwise"
        );
        assert!(!summary.guest_left_waiting());
    }

    #[test]
    fn the_acknowledgement_is_derived_from_the_write_and_cannot_contradict_it() {
        let mut summary = RestoreSummary::default();
        assert!(!summary.final_status_acknowledged());
        assert!(!summary.guest_left_waiting());

        summary.status_messages = 1;
        assert!(
            summary.guest_left_waiting(),
            "a status with no answer is a guest still in cleanup_wait_status_received"
        );
        assert!(!summary.final_status_acknowledged());

        summary.final_status_acks_sent = 1;
        assert!(summary.final_status_acknowledged());
        assert!(!summary.guest_left_waiting());
        assert!(
            !summary.guest_echoed_final_status,
            "the inbound echo is a separate fact and neither of these implies it"
        );
    }

    #[test]
    fn the_final_status_of_a_successful_restore_is_acknowledged_the_same_way() {
        let messages = vec![successful_final_status()];
        let mut client = RamrodClient::new(ScriptedTransport::new(&messages));
        client.start_restore(RestoreOptions::new()).unwrap();

        let mut recorder = Recorder::default();
        let summary = client
            .run_restore(
                &mut PreparedAnswers::new(),
                &mut NoBulkTransfers,
                &mut recorder,
            )
            .unwrap();

        assert_eq!(summary.last_status, Some(0));
        assert_eq!(summary.final_status_acks_sent, 1);
        assert_eq!(
            recorder.events,
            vec!["status 0".to_string(), "acked Some(0)".to_string()]
        );

        let written = client.into_inner().written();
        assert_eq!(written.len(), 2);
        assert_is_the_acknowledgement(&written[1]);
        let mut failing = RamrodClient::new(ScriptedTransport::new(&[failed_final_status(6, "x")]));
        failing.start_restore(RestoreOptions::new()).unwrap();
        failing
            .run_restore(&mut PreparedAnswers::new(), &mut NoBulkTransfers, &mut ())
            .unwrap();
        assert_eq!(failing.into_inner().written()[1], written[1]);
    }

    #[test]
    fn a_status_message_with_no_readable_status_is_still_acknowledged() {
        let messages = vec![dict(vec![(
            KEY_MSG_TYPE,
            Value::String("StatusMsg".into()),
        )])];
        let mut client = RamrodClient::new(ScriptedTransport::new(&messages));
        client.start_restore(RestoreOptions::new()).unwrap();

        let mut recorder = Recorder::default();
        let summary = client
            .run_restore(
                &mut PreparedAnswers::new(),
                &mut NoBulkTransfers,
                &mut recorder,
            )
            .unwrap();

        assert_eq!(summary.status_messages, 1);
        assert_eq!(summary.last_status, None);
        assert_eq!(summary.final_status_acks_sent, 1);
        assert_eq!(
            recorder.events,
            vec!["message StatusMsg".to_string(), "acked None".to_string()]
        );
        assert_is_the_acknowledgement(&client.into_inner().written()[1]);
    }

    #[test]
    fn the_acknowledgement_reports_the_framed_length_that_was_written() {
        struct Framed(usize);
        impl SessionObserver for Framed {
            fn on_final_status_acknowledged(&mut self, _status: Option<i64>, bytes: usize) {
                self.0 = bytes;
            }
        }

        let mut client = RamrodClient::new(ScriptedTransport::new(&[successful_final_status()]));
        client.start_restore(RestoreOptions::new()).unwrap();
        let mut framed = Framed(0);
        client
            .run_restore(
                &mut PreparedAnswers::new(),
                &mut NoBulkTransfers,
                &mut framed,
            )
            .unwrap();

        let expected = codec::encode_message(
            &crate::ramrod::message::final_status_acknowledgement(),
            PlistFormat::Binary,
        )
        .expect("encodes")
        .len();
        assert_eq!(
            framed.0, expected,
            "the reported length is what went on the wire, prefix included"
        );
    }

    #[test]
    fn an_untyped_message_during_a_restore_is_counted_and_does_not_end_the_session() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[
            dict(vec![(KEY_RESULT, Value::String(RESULT_SUCCESS.into()))]),
            final_status(),
        ]));
        client.start_restore(RestoreOptions::new()).unwrap();
        let summary = client
            .run_restore(&mut PreparedAnswers::new(), &mut NoBulkTransfers, &mut ())
            .unwrap();
        assert_eq!(summary.untyped_messages, 1);
        assert!(summary.guest_echoed_final_status);
    }

    #[test]
    fn an_unmodelled_message_type_is_observed_by_name_and_not_answered() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[
            dict(vec![(
                KEY_MSG_TYPE,
                Value::String("RestoreAttestation".into()),
            )]),
            dict(vec![(KEY_MSG_TYPE, Value::String("SomeFutureMsg".into()))]),
            final_status(),
        ]));
        client.start_restore(RestoreOptions::new()).unwrap();
        let mut recorder = Recorder::default();
        client
            .run_restore(
                &mut PreparedAnswers::new(),
                &mut NoBulkTransfers,
                &mut recorder,
            )
            .unwrap();
        assert_eq!(
            recorder.events,
            vec![
                "message RestoreAttestation".to_string(),
                "message SomeFutureMsg".to_string(),
                "message ReceivedFinalStatusMsg".to_string(),
            ]
        );
        assert_eq!(client.into_inner().written().len(), 1);
    }

    #[test]
    fn a_data_request_with_no_data_type_is_a_protocol_error() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[dict(vec![(
            KEY_MSG_TYPE,
            Value::String("DataRequestMsg".into()),
        )])]));
        client.start_restore(RestoreOptions::new()).unwrap();
        assert!(matches!(
            client.run_restore(&mut PreparedAnswers::new(), &mut NoBulkTransfers, &mut ()),
            Err(RamrodError::MalformedDataRequest { .. })
        ));
    }

    #[test]
    fn a_top_level_value_that_is_not_a_dictionary_is_a_desync_not_a_message() {
        let mut client =
            RamrodClient::new(ScriptedTransport::new(&[Value::String("garbage".into())]));
        assert!(matches!(client.receive(), Err(RamrodError::NotADictionary)));
    }

    #[test]
    fn a_restore_message_arriving_where_a_reply_was_due_is_reported_not_skipped() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[data_request(
            "RecoveryOSASRImage",
            Some(12345),
        )]));
        match client.query_type() {
            Err(RamrodError::UnexpectedDeviceMessage { request, msg_type }) => {
                assert_eq!(request, Request::QueryType);
                assert_eq!(msg_type, "DataRequestMsg");
            }
            other => panic!("expected an unexpected-message error, got {other:?}"),
        }
    }

    #[test]
    fn a_guest_that_closes_instead_of_replying_is_reported_against_the_request() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[]));
        match client.query_type() {
            Err(RamrodError::ClosedBeforeReply { request }) => {
                assert_eq!(request, Request::QueryType)
            }
            other => panic!("expected a closed-before-reply error, got {other:?}"),
        }
    }

    #[test]
    fn goodbye_writes_the_request_and_returns_the_acknowledgement() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[dict(vec![(
            "Response",
            Value::String("Acknowledged".into()),
        )])]));
        let reply = client.goodbye().unwrap();
        assert_eq!(
            reply.get("Response").unwrap().as_string(),
            Some("Acknowledged")
        );
        let written = client.into_inner().written();
        assert_eq!(
            written[0]
                .as_dictionary()
                .unwrap()
                .get(KEY_REQUEST)
                .unwrap()
                .as_string(),
            Some("Goodbye")
        );
    }

    #[test]
    fn reboot_writes_the_request_and_reads_nothing() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[]));
        client.reboot().unwrap();
        let written = client.into_inner().written();
        assert_eq!(written.len(), 1);
        assert_eq!(
            written[0]
                .as_dictionary()
                .unwrap()
                .get(KEY_REQUEST)
                .unwrap()
                .as_string(),
            Some("Reboot")
        );
    }

    #[test]
    fn an_async_wait_is_observed_answered_with_nothing_and_does_not_end_the_session() {
        struct AnswersAnything;
        impl RestoreDataProvider for AnswersAnything {
            fn supply(&mut self, _request: &DataRequest) -> Result<Dictionary, ProviderError> {
                Ok(Dictionary::new())
            }
        }

        #[derive(Default)]
        struct WaitWatcher {
            waits: Vec<Option<String>>,
        }
        impl SessionObserver for WaitWatcher {
            fn on_async_wait(&mut self, uuid: Option<&str>, _body: &Dictionary) {
                self.waits.push(uuid.map(str::to_string));
            }
        }

        let uuid = "1DF2E37C-0000-4000-8000-000000000001";
        let async_wait = dict(vec![
            (KEY_MSG_TYPE, Value::String("AsyncWait".into())),
            (
                super::super::message::KEY_ASYNC_CONTEXT_UUID,
                Value::String(uuid.into()),
            ),
        ]);
        let mut request = async_data_request("SystemImageData", Some(12346));
        request.as_dictionary_mut().unwrap().insert(
            super::super::message::KEY_ASYNC_CONTEXT_UUID.to_string(),
            Value::String(uuid.into()),
        );
        let messages = vec![
            request,
            async_wait,
            data_request("RootTicket", None),
            successful_final_status(),
        ];

        let mut client = RamrodClient::new(ScriptedTransport::new(&messages));
        client.start_restore(RestoreOptions::new()).unwrap();
        let mut bulk = RecordingBulk::default();
        let mut watcher = WaitWatcher::default();
        let summary = client
            .run_restore(&mut AnswersAnything, &mut bulk, &mut watcher)
            .unwrap();

        assert_eq!(bulk.served, vec![(12346, "SystemImageData".to_string())]);
        assert_eq!(summary.async_data_requests, 1);
        assert_eq!(summary.bulk_transfers, 1);
        assert_eq!(summary.async_waits, 1);
        assert_eq!(watcher.waits, vec![Some(uuid.to_string())]);
        assert_eq!(summary.data_requests, 1);
        assert_eq!(summary.final_status_acks_sent, 1);
        let transport = client.into_inner();
        let written = transport.written();
        assert_eq!(
            written.len(),
            3,
            "StartRestore, the RootTicket answer and the acknowledgement only"
        );
        assert!(
            written[1]
                .as_dictionary()
                .unwrap()
                .get(KEY_MSG_TYPE)
                .is_none()
        );
        assert_eq!(
            written[2]
                .as_dictionary()
                .unwrap()
                .get(KEY_MSG_TYPE)
                .and_then(Value::as_string),
            Some("ReceivedFinalStatusMsg")
        );
    }

    #[test]
    fn a_declined_bulk_transfer_does_not_end_the_session() {
        struct AnswersAnything;
        impl RestoreDataProvider for AnswersAnything {
            fn supply(&mut self, _request: &DataRequest) -> Result<Dictionary, ProviderError> {
                Ok(Dictionary::new())
            }
        }

        let messages = vec![
            async_data_request("SystemImageData", Some(12346)),
            data_request("RootTicket", None),
            successful_final_status(),
        ];
        let mut client = RamrodClient::new(ScriptedTransport::new(&messages));
        client.start_restore(RestoreOptions::new()).unwrap();
        let mut bulk = DecliningBulk::default();
        let summary = client
            .run_restore(&mut AnswersAnything, &mut bulk, &mut ())
            .unwrap();

        assert_eq!(bulk.declined, vec![(12346, "SystemImageData".to_string())]);
        assert_eq!(summary.bulk_declined, 1);
        assert_eq!(summary.bulk_transfers, 0);
        assert_eq!(summary.data_requests, 1);
        assert!(summary.final_status_acknowledged());
    }

    #[derive(Default)]
    struct EmptyBulk {
        served: Vec<(u16, String)>,
    }

    impl BulkTransferService for EmptyBulk {
        fn serve(
            &mut self,
            port: u16,
            request: &DataRequest,
        ) -> Result<BulkOutcome, ProviderError> {
            self.served
                .push((port, request.data_type.wire_name().to_string()));
            Ok(BulkOutcome::Served {
                bytes: 0,
                blocks: 0,
                initiates: 1,
                metadata_requests: 1,
                oob_requests: 0,
                oob_bytes: 0,
            })
        }
    }

    #[test]
    fn a_bulk_transfer_that_streamed_nothing_is_not_a_served_one() {
        struct AnswersAnything;
        impl RestoreDataProvider for AnswersAnything {
            fn supply(&mut self, _request: &DataRequest) -> Result<Dictionary, ProviderError> {
                Ok(Dictionary::new())
            }
        }

        let messages = vec![
            async_data_request("RecoveryOSASRImage", Some(12346)),
            successful_final_status(),
        ];
        let mut client = RamrodClient::new(ScriptedTransport::new(&messages));
        client.start_restore(RestoreOptions::new()).unwrap();
        let mut bulk = EmptyBulk::default();
        let mut observer = Recorder::default();
        let summary = client
            .run_restore(&mut AnswersAnything, &mut bulk, &mut observer)
            .unwrap();

        assert_eq!(bulk.served, vec![(12346, "RecoveryOSASRImage".to_string())]);
        assert_eq!(summary.bulk_empty, 1);
        assert_eq!(summary.bulk_transfers, 0);
        assert!(
            observer
                .events
                .iter()
                .any(|event| event == "bulk-empty RecoveryOSASRImage port=12346"),
            "{:?}",
            observer.events
        );
        assert!(summary.final_status_acknowledged());
    }

    #[test]
    fn the_xml_serialisation_is_accepted_by_the_same_reader() {
        let mut client = RamrodClient::new(ScriptedTransport::new(&[query_type_reply()]))
            .with_format(PlistFormat::Xml);
        assert!(client.query_type().unwrap().is_restored());
        let transport = client.into_inner();
        assert!(
            transport.outbound[codec::LENGTH_PREFIX_LEN..].starts_with(b"<?xml"),
            "the client was asked for XML and must have written XML"
        );
        assert_eq!(transport.written().len(), 1);
    }

    #[test]
    fn an_argument_dictionary_reaches_the_provider_intact() {
        let mut arguments = Dictionary::new();
        arguments.insert(
            "ImageName".to_string(),
            Value::String("__GlobalManifest__".into()),
        );
        arguments.insert("Variant".to_string(), Value::String("Customer".into()));
        let request = dict(vec![
            (KEY_MSG_TYPE, Value::String("DataRequestMsg".into())),
            (KEY_DATA_TYPE, Value::String("SourceBootObjectV4".into())),
            (KEY_ARGUMENTS, Value::Dictionary(arguments)),
        ]);

        struct Capturing {
            seen: Vec<DataRequest>,
        }
        impl RestoreDataProvider for Capturing {
            fn supply(&mut self, request: &DataRequest) -> Result<Dictionary, ProviderError> {
                self.seen.push(request.clone());
                Ok(Dictionary::new())
            }
        }

        let mut client = RamrodClient::new(ScriptedTransport::new(&[request, final_status()]));
        client.start_restore(RestoreOptions::new()).unwrap();
        let mut provider = Capturing { seen: Vec::new() };
        client
            .run_restore(&mut provider, &mut NoBulkTransfers, &mut ())
            .unwrap();

        assert_eq!(provider.seen.len(), 1);
        let seen = &provider.seen[0];
        assert_eq!(seen.data_type, DataType::SourceBootObjectV4);
        assert_eq!(
            seen.argument_string("ImageName"),
            Some("__GlobalManifest__")
        );
        assert_eq!(seen.argument_string("Variant"), Some("Customer"));
        assert!(!seen.is_bulk_transfer());
    }
}
