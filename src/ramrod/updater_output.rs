use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::bulk::{
    DEFAULT_DATA_PORT_ATTEMPT_TIMEOUT, DEFAULT_DATA_PORT_RETRY_INTERVAL, DEFAULT_DATA_PORT_WINDOW,
};
use super::cpio::{CPIO_HEADER_BYTES, CPIO_MAGIC, CPIO_TRAILER_PATH};
use super::dial::{
    Clock, DialCancellation, DialPlan, GuestDialer, ShutdownWrite, SystemClock, dial_until,
};
use super::message::{DataRequest, DataType};
use super::provider::{BulkOutcome, BulkTransferService, BulkTransferTask, ProviderError};

pub const UPDATER_OUTPUT_DATA_TYPE: &str = "BasebandUpdaterOutputData";
const RECEIVE_BUFFER_BYTES: usize = 64 * 1024;

pub fn is_updater_output(data_type: &DataType) -> bool {
    data_type.wire_name() == UPDATER_OUTPUT_DATA_TYPE
}

#[derive(Debug)]
pub struct UpdaterOutputError {
    pub port: u16,
    pub path: PathBuf,
    pub bytes: u64,
    pub stage: &'static str,
    source: io::Error,
}

impl std::fmt::Display for UpdaterOutputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{UPDATER_OUTPUT_DATA_TYPE} receive on port {} failed during {} after {} persisted bytes; partial output {}: {}",
            self.port,
            self.stage,
            self.bytes,
            self.path.display(),
            self.source
        )
    }
}

impl std::error::Error for UpdaterOutputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.source.get_ref() {
            Some(source) => Some(source as &(dyn std::error::Error + 'static)),
            None => Some(&self.source),
        }
    }
}

fn failed(
    port: u16,
    path: &Path,
    bytes: u64,
    stage: &'static str,
    source: io::Error,
) -> ProviderError {
    ProviderError::Io(io::Error::new(
        source.kind(),
        UpdaterOutputError {
            port,
            path: path.to_path_buf(),
            bytes,
            stage,
            source,
        },
    ))
}

fn reserve_output(directory: &Path, port: u16) -> Result<(PathBuf, File), ProviderError> {
    std::fs::create_dir_all(directory)
        .map_err(|error| failed(port, directory, 0, "create output directory", error))?;
    let mut index = 1u64;
    loop {
        let path = directory.join(format!("baseband-updater-output-{index}.cpio"));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                index = index.checked_add(1).ok_or_else(|| {
                    failed(
                        port,
                        &path,
                        0,
                        "reserve output",
                        io::Error::other("output filename sequence exhausted"),
                    )
                })?;
            }
            Err(error) => return Err(failed(port, &path, 0, "reserve output", error)),
        }
    }
}

fn invalid_archive(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn odc_field(bytes: &[u8], name: &str) -> io::Result<u64> {
    let mut value = 0u64;
    for byte in bytes {
        if !(b'0'..=b'7').contains(byte) {
            return Err(invalid_archive(format!(
                "invalid ODC CPIO {name} octal field"
            )));
        }
        value = value
            .checked_mul(8)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or_else(|| invalid_archive(format!("ODC CPIO {name} field overflow")))?;
    }
    Ok(value)
}

fn read_archive_bytes<R: Read, F: Fn() -> io::Result<()>>(
    reader: &mut R,
    buffer: &mut [u8],
    remaining: &mut u64,
    cancelled: &F,
) -> io::Result<()> {
    cancelled()?;
    let rest = remaining
        .checked_sub(buffer.len() as u64)
        .ok_or_else(|| invalid_archive("truncated ODC CPIO archive"))?;
    reader.read_exact(buffer)?;
    *remaining = rest;
    Ok(())
}

fn validate_odc_archive<R: Read, F: Fn() -> io::Result<()>>(
    reader: &mut R,
    bytes: u64,
    cancelled: F,
) -> io::Result<()> {
    let mut remaining = bytes;
    let mut buffer = [0u8; RECEIVE_BUFFER_BYTES];
    loop {
        if remaining < CPIO_HEADER_BYTES as u64 {
            return Err(invalid_archive(
                "truncated ODC CPIO header before TRAILER!!!",
            ));
        }
        let mut header = [0u8; CPIO_HEADER_BYTES];
        read_archive_bytes(reader, &mut header, &mut remaining, &cancelled)?;
        if &header[..CPIO_MAGIC.len()] != CPIO_MAGIC {
            return Err(invalid_archive("invalid ODC CPIO magic"));
        }
        let mut offset = CPIO_MAGIC.len();
        for (name, width) in [
            ("dev", 6),
            ("ino", 6),
            ("mode", 6),
            ("uid", 6),
            ("gid", 6),
            ("nlink", 6),
            ("rdev", 6),
            ("mtime", 11),
        ] {
            odc_field(&header[offset..offset + width], name)?;
            offset += width;
        }
        let namesize = odc_field(&header[offset..offset + 6], "namesize")?;
        let filesize = odc_field(&header[offset + 6..], "filesize")?;
        if namesize < 2 {
            return Err(invalid_archive(
                "ODC CPIO name must include a nonempty path and NUL terminator",
            ));
        }
        let member_bytes = namesize
            .checked_add(filesize)
            .ok_or_else(|| invalid_archive("ODC CPIO member length overflow"))?;
        if member_bytes > remaining {
            return Err(invalid_archive("truncated ODC CPIO name or body"));
        }
        let trailer_name = CPIO_TRAILER_PATH.as_bytes();
        let mut trailer = namesize == trailer_name.len() as u64 + 1;
        let mut name_read = 0u64;
        while name_read < namesize {
            let count = (namesize - name_read).min(buffer.len() as u64) as usize;
            read_archive_bytes(reader, &mut buffer[..count], &mut remaining, &cancelled)?;
            for (index, byte) in buffer[..count].iter().enumerate() {
                let position = name_read + index as u64;
                if position == namesize - 1 {
                    if *byte != 0 {
                        return Err(invalid_archive("ODC CPIO name is not NUL terminated"));
                    }
                } else {
                    if *byte == 0 {
                        return Err(invalid_archive("ODC CPIO name contains an embedded NUL"));
                    }
                    trailer &= trailer_name.get(position as usize) == Some(byte);
                }
            }
            name_read += count as u64;
        }
        if trailer {
            if filesize != 0 {
                return Err(invalid_archive("ODC CPIO TRAILER!!! body must be empty"));
            }
            while remaining > 0 {
                let count = remaining.min(buffer.len() as u64) as usize;
                read_archive_bytes(reader, &mut buffer[..count], &mut remaining, &cancelled)?;
                if buffer[..count].iter().any(|byte| *byte != 0) {
                    return Err(invalid_archive("nonzero ODC CPIO padding after TRAILER!!!"));
                }
            }
            return Ok(());
        }
        let mut body_remaining = filesize;
        while body_remaining > 0 {
            let count = body_remaining.min(buffer.len() as u64) as usize;
            read_archive_bytes(reader, &mut buffer[..count], &mut remaining, &cancelled)?;
            body_remaining -= count as u64;
        }
    }
}

pub struct UpdaterOutputTransfer<D, C = SystemClock> {
    dialer: D,
    directory: PathBuf,
    clock: C,
    window: Duration,
    attempt_timeout: Duration,
    retry_interval: Duration,
    stop: Option<Arc<AtomicBool>>,
    cancel: Option<Arc<AtomicBool>>,
}

impl<D> UpdaterOutputTransfer<D> {
    pub fn new(dialer: D, directory: PathBuf) -> Self {
        Self::with_clock(dialer, directory, SystemClock)
    }
}

impl<D, C> UpdaterOutputTransfer<D, C> {
    pub fn with_clock(dialer: D, directory: PathBuf, clock: C) -> Self {
        Self {
            dialer,
            directory,
            clock,
            window: DEFAULT_DATA_PORT_WINDOW,
            attempt_timeout: DEFAULT_DATA_PORT_ATTEMPT_TIMEOUT,
            retry_interval: DEFAULT_DATA_PORT_RETRY_INTERVAL,
            stop: None,
            cancel: None,
        }
    }

    pub fn with_window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    pub fn with_retry(mut self, attempt_timeout: Duration, retry_interval: Duration) -> Self {
        self.attempt_timeout = attempt_timeout;
        self.retry_interval = retry_interval;
        self
    }

    pub fn with_cancellation(mut self, stop: Arc<AtomicBool>, cancel: Arc<AtomicBool>) -> Self {
        self.stop = Some(stop);
        self.cancel = Some(cancel);
        self
    }

    fn check_cancelled(&self) -> io::Result<()> {
        let reason = if self
            .stop
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            Some(DialCancellation::OperatorStopped)
        } else if self
            .cancel
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            Some(DialCancellation::TransferFailed)
        } else {
            None
        };
        match reason {
            Some(reason) => Err(io::Error::new(io::ErrorKind::ConnectionAborted, reason)),
            None => Ok(()),
        }
    }
}

impl<D, C> UpdaterOutputTransfer<D, C>
where
    D: GuestDialer,
    D::Stream: ShutdownWrite,
    C: Clock,
{
    fn receive(&mut self, port: u16) -> Result<BulkOutcome, ProviderError> {
        let (path, mut file) = reserve_output(&self.directory, port)?;
        self.check_cancelled()
            .map_err(|error| failed(port, &path, 0, "dial", error))?;
        let plan = DialPlan {
            port,
            window: self.window,
            attempt_timeout: self.attempt_timeout,
            retry_interval: self.retry_interval,
        };
        let mut connection = dial_until(&mut self.dialer, plan, &mut self.clock)
            .map_err(|error| failed(port, &path, 0, "dial", io::Error::other(error)))?;
        let mut bytes = 0u64;
        let mut reset = None;
        let mut buffer = [0u8; RECEIVE_BUFFER_BYTES];
        loop {
            self.check_cancelled()
                .map_err(|error| failed(port, &path, bytes, "read", error))?;
            let count = match connection.stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => count,
                Err(error)
                    if error.kind() == io::ErrorKind::Interrupted
                        && DialCancellation::from_io_error(&error).is_none() =>
                {
                    continue;
                }
                Err(error)
                    if error.kind() == io::ErrorKind::ConnectionReset
                        && DialCancellation::from_io_error(&error).is_none() =>
                {
                    reset = Some(error);
                    break;
                }
                Err(error) => return Err(failed(port, &path, bytes, "read", error)),
            };
            let mut written = 0;
            while written < count {
                self.check_cancelled()
                    .map_err(|error| failed(port, &path, bytes, "persist", error))?;
                match file.write(&buffer[written..count]) {
                    Ok(0) => {
                        return Err(failed(
                            port,
                            &path,
                            bytes,
                            "persist",
                            io::Error::new(
                                io::ErrorKind::WriteZero,
                                "output file accepted zero bytes",
                            ),
                        ));
                    }
                    Ok(count) => {
                        written += count;
                        bytes = bytes.checked_add(count as u64).ok_or_else(|| {
                            failed(
                                port,
                                &path,
                                bytes,
                                "persist",
                                io::Error::other("persisted byte count overflow"),
                            )
                        })?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(failed(port, &path, bytes, "persist", error)),
                }
            }
        }
        self.check_cancelled()
            .map_err(|error| failed(port, &path, bytes, "finish", error))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| failed(port, &path, bytes, "validate CPIO", error))?;
        validate_odc_archive(&mut file, bytes, || self.check_cancelled()).map_err(|error| {
            let error = match &reset {
                Some(reset)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
                    ) =>
                {
                    io::Error::new(io::ErrorKind::ConnectionReset, format!("{reset}; {error}"))
                }
                _ => error,
            };
            failed(port, &path, bytes, "validate CPIO", error)
        })?;
        self.check_cancelled()
            .map_err(|error| failed(port, &path, bytes, "finish", error))?;
        file.flush()
            .map_err(|error| failed(port, &path, bytes, "flush", error))?;
        file.sync_all()
            .map_err(|error| failed(port, &path, bytes, "sync", error))?;
        self.check_cancelled()
            .map_err(|error| failed(port, &path, bytes, "shutdown write", error))?;
        if reset.is_none() {
            let shutdown = connection.stream.shutdown_write();
            self.check_cancelled()
                .map_err(|error| failed(port, &path, bytes, "shutdown write", error))?;
            match shutdown {
                Ok(()) => {}
                Err(error)
                    if error.kind() == io::ErrorKind::ConnectionReset
                        && DialCancellation::from_io_error(&error).is_none() => {}
                Err(error) => return Err(failed(port, &path, bytes, "shutdown write", error)),
            }
        }
        Ok(BulkOutcome::Received { bytes, path })
    }
}

impl<D, C> BulkTransferService for UpdaterOutputTransfer<D, C>
where
    D: GuestDialer + Clone + Send + 'static,
    D::Stream: ShutdownWrite,
    C: Clock + Clone + Send + 'static,
{
    fn prepare(
        &mut self,
        port: u16,
        request: &DataRequest,
    ) -> Result<BulkTransferTask, ProviderError> {
        if !is_updater_output(&request.data_type) {
            return Err(ProviderError::Unsupported {
                data_type: request.data_type.wire_name().to_string(),
            });
        }
        let mut transfer = Self {
            dialer: self.dialer.clone(),
            directory: self.directory.clone(),
            clock: self.clock.clone(),
            window: self.window,
            attempt_timeout: self.attempt_timeout,
            retry_interval: self.retry_interval,
            stop: self.stop.clone(),
            cancel: self.cancel.clone(),
        };
        Ok(Box::new(move || transfer.receive(port)))
    }
}

pub struct UpdaterOutputRouter<R, F> {
    receiver: R,
    fallback: F,
}

impl<R, F> UpdaterOutputRouter<R, F> {
    pub fn new(receiver: R, fallback: F) -> Self {
        Self { receiver, fallback }
    }

    pub fn fallback(&self) -> &F {
        &self.fallback
    }
}

impl<R: BulkTransferService, F: BulkTransferService> BulkTransferService
    for UpdaterOutputRouter<R, F>
{
    fn prepare(
        &mut self,
        port: u16,
        request: &DataRequest,
    ) -> Result<BulkTransferTask, ProviderError> {
        if is_updater_output(&request.data_type) {
            self.receiver.prepare(port, request)
        } else {
            self.fallback.prepare(port, request)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::time::Instant;

    use plist::Dictionary;

    use super::*;
    use crate::ramrod::{CpioEntry, CpioWriter};

    #[derive(Clone)]
    enum Step {
        Bytes(Vec<u8>),
        Eof,
        Error(io::ErrorKind),
        Cancel,
    }

    #[derive(Default)]
    struct Capture {
        ports: Vec<u16>,
        events: Vec<&'static str>,
        read_buffers: Vec<usize>,
        persisted_at_shutdown: Option<Vec<u8>>,
    }

    struct ScriptedStream {
        steps: VecDeque<Step>,
        capture: Arc<Mutex<Capture>>,
        shutdown_error: Option<io::ErrorKind>,
        output_at_shutdown: Option<PathBuf>,
    }

    impl Read for ScriptedStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.capture.lock().unwrap().read_buffers.push(buffer.len());
            match self
                .steps
                .pop_front()
                .expect("every read has a scripted guest result")
            {
                Step::Bytes(bytes) => {
                    let count = bytes.len().min(buffer.len());
                    buffer[..count].copy_from_slice(&bytes[..count]);
                    if count < bytes.len() {
                        self.steps.push_front(Step::Bytes(bytes[count..].to_vec()));
                    }
                    Ok(count)
                }
                Step::Eof => {
                    self.capture.lock().unwrap().events.push("guest EOF");
                    Ok(0)
                }
                Step::Error(kind) => {
                    if kind == io::ErrorKind::ConnectionReset {
                        self.capture.lock().unwrap().events.push("guest reset");
                    }
                    Err(io::Error::new(kind, "scripted guest read failure"))
                }
                Step::Cancel => Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    DialCancellation::TransferFailed,
                )),
            }
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ShutdownWrite for ScriptedStream {
        fn shutdown_write(&mut self) -> io::Result<()> {
            let mut capture = self.capture.lock().unwrap();
            capture.events.push("host write shutdown");
            if let Some(path) = &self.output_at_shutdown {
                capture.persisted_at_shutdown = Some(std::fs::read(path)?);
            }
            drop(capture);
            match self.shutdown_error {
                Some(kind) => Err(io::Error::new(kind, "scripted shutdown failure")),
                None => Ok(()),
            }
        }
    }

    #[derive(Clone)]
    struct ScriptedDialer {
        steps: Vec<Step>,
        refusals: Arc<Mutex<usize>>,
        capture: Arc<Mutex<Capture>>,
        shutdown_error: Option<io::ErrorKind>,
        output_at_shutdown: Option<PathBuf>,
    }

    impl ScriptedDialer {
        fn new(steps: Vec<Step>) -> Self {
            Self {
                steps,
                refusals: Arc::new(Mutex::new(0)),
                capture: Arc::new(Mutex::new(Capture::default())),
                shutdown_error: None,
                output_at_shutdown: None,
            }
        }
    }

    impl GuestDialer for ScriptedDialer {
        type Stream = ScriptedStream;

        fn dial(&mut self, port: u16, _timeout: Duration) -> io::Result<Self::Stream> {
            self.capture.lock().unwrap().ports.push(port);
            let mut refusals = self.refusals.lock().unwrap();
            if *refusals > 0 {
                *refusals -= 1;
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "guest listener is starting",
                ));
            }
            Ok(ScriptedStream {
                steps: self.steps.clone().into(),
                capture: Arc::clone(&self.capture),
                shutdown_error: self.shutdown_error,
                output_at_shutdown: self.output_at_shutdown.clone(),
            })
        }
    }

    #[derive(Clone)]
    struct TestClock(Instant);

    impl Clock for TestClock {
        fn now(&self) -> Instant {
            self.0
        }

        fn sleep(&mut self, duration: Duration) {
            self.0 += duration;
        }
    }

    fn request(port: u16) -> DataRequest {
        DataRequest {
            data_type: DataType::Other(UPDATER_OUTPUT_DATA_TYPE.to_string()),
            data_port: Some(port),
            arguments: Dictionary::new(),
            asynchronous: false,
            async_context_uuid: None,
        }
    }

    fn archive() -> Vec<u8> {
        let contents = (0..(RECEIVE_BUFFER_BYTES * 3))
            .map(|index| (index % 251) as u8)
            .collect();
        let mut writer = CpioWriter::new(Vec::new());
        writer
            .write_entry(&CpioEntry::regular_file(
                "updater.log",
                contents,
                0o644,
                0,
                0,
                1,
            ))
            .unwrap();
        writer.finish().unwrap();
        writer.into_inner()
    }

    fn partial(error: ProviderError) -> UpdaterOutputError {
        match error {
            ProviderError::Io(error) => *error
                .into_inner()
                .unwrap()
                .downcast::<UpdaterOutputError>()
                .unwrap(),
            other => panic!("expected attributable receive failure, got {other}"),
        }
    }

    #[test]
    fn fragmented_raw_cpio_is_persisted_before_host_write_shutdown() {
        let directory = tempfile::tempdir().unwrap();
        let archive = archive();
        let mut dialer = ScriptedDialer::new(vec![
            Step::Bytes(archive[..1].to_vec()),
            Step::Bytes(archive[1..18].to_vec()),
            Step::Bytes(archive[18..].to_vec()),
            Step::Eof,
        ]);
        dialer.output_at_shutdown = Some(directory.path().join("baseband-updater-output-1.cpio"));
        *dialer.refusals.lock().unwrap() = 2;
        let capture = Arc::clone(&dialer.capture);
        let mut receiver = UpdaterOutputTransfer::with_clock(
            dialer,
            directory.path().to_path_buf(),
            TestClock(Instant::now()),
        );
        let result = receiver.serve(9420, &request(9420)).unwrap();
        let path = directory.path().join("baseband-updater-output-1.cpio");
        assert_eq!(
            result,
            BulkOutcome::Received {
                bytes: archive.len() as u64,
                path: path.clone()
            }
        );
        assert_eq!(std::fs::read(path).unwrap(), archive);
        let capture = capture.lock().unwrap();
        assert_eq!(capture.ports, vec![9420, 9420, 9420]);
        assert_eq!(capture.events, vec!["guest EOF", "host write shutdown"]);
        assert_eq!(
            capture.persisted_at_shutdown.as_deref(),
            Some(archive.as_slice())
        );
        let expected_reads = 3 + (archive.len() - 18).div_ceil(RECEIVE_BUFFER_BYTES);
        assert_eq!(
            capture.read_buffers,
            vec![RECEIVE_BUFFER_BYTES; expected_reads]
        );
    }

    #[test]
    fn complete_fragmented_cpio_on_reset_is_persisted_and_received() {
        let mut directories = CpioWriter::new(Vec::new());
        for path in [".", "./Savage", "./SE"] {
            directories
                .write_entry(&CpioEntry::directory(path, 0o755, 0, 0, 1))
                .unwrap();
        }
        directories.finish().unwrap();
        let mut directory_archive = directories.into_inner();
        assert_eq!(directory_archive.len(), 331);
        directory_archive.resize(512, 0);
        let mut body_archive = archive();
        body_archive.extend_from_slice(&[0; 181]);
        for archive in [directory_archive, body_archive] {
            let directory = tempfile::tempdir().unwrap();
            let mut steps: Vec<Step> = archive
                .chunks(17)
                .map(|bytes| Step::Bytes(bytes.to_vec()))
                .collect();
            steps.push(Step::Error(io::ErrorKind::ConnectionReset));
            let mut dialer = ScriptedDialer::new(steps);
            dialer.shutdown_error = Some(io::ErrorKind::BrokenPipe);
            let capture = Arc::clone(&dialer.capture);
            let mut receiver = UpdaterOutputTransfer::new(dialer, directory.path().to_path_buf());
            let path = directory.path().join("baseband-updater-output-1.cpio");
            assert_eq!(
                receiver.serve(9426, &request(9426)).unwrap(),
                BulkOutcome::Received {
                    bytes: archive.len() as u64,
                    path: path.clone()
                }
            );
            assert_eq!(std::fs::read(path).unwrap(), archive);
            assert_eq!(capture.lock().unwrap().events, vec!["guest reset"]);
        }
    }

    #[test]
    fn invalid_cpio_completion_reports_named_validation_errors() {
        let mut writer = CpioWriter::new(Vec::new());
        writer
            .write_entry(&CpioEntry::regular_file(
                "log",
                b"log body".to_vec(),
                0o644,
                0,
                0,
                1,
            ))
            .unwrap();
        writer.finish().unwrap();
        let archive = writer.into_inner();
        let trailer = CPIO_HEADER_BYTES + 4 + 8;
        let mut invalid_octal = archive.clone();
        invalid_octal[6] = b'8';
        let mut invalid_namesize = archive.clone();
        invalid_namesize[59..65].copy_from_slice(b"000000");
        let mut embedded_nul = archive.clone();
        embedded_nul[CPIO_HEADER_BYTES + 1] = 0;
        let mut missing_nul = archive.clone();
        missing_nul[CPIO_HEADER_BYTES + 3] = b'x';
        let mut trailer_body = archive.clone();
        trailer_body[trailer + 65..trailer + 76].copy_from_slice(b"00000000001");
        trailer_body.push(0);
        let mut nonzero_padding = archive.clone();
        nonzero_padding.extend_from_slice(&[0, 1]);
        let mut wrong_trailer = archive.clone();
        wrong_trailer[trailer + CPIO_HEADER_BYTES] = b't';
        let mut oversized_body = archive.clone();
        oversized_body[65..76].copy_from_slice(b"77777777777");
        for (bytes, reason) in [
            (b"070707".to_vec(), "truncated ODC CPIO header"),
            (
                archive[..CPIO_HEADER_BYTES + 4 + 7].to_vec(),
                "truncated ODC CPIO name or body",
            ),
            (archive[..trailer].to_vec(), "truncated ODC CPIO header"),
            (invalid_octal, "invalid ODC CPIO dev octal field"),
            (
                invalid_namesize,
                "ODC CPIO name must include a nonempty path",
            ),
            (embedded_nul, "ODC CPIO name contains an embedded NUL"),
            (missing_nul, "ODC CPIO name is not NUL terminated"),
            (trailer_body, "ODC CPIO TRAILER!!! body must be empty"),
            (nonzero_padding, "nonzero ODC CPIO padding"),
            (wrong_trailer, "truncated ODC CPIO header"),
            (oversized_body, "truncated ODC CPIO name or body"),
        ] {
            for completion in [Step::Eof, Step::Error(io::ErrorKind::ConnectionReset)] {
                let kind = match &completion {
                    Step::Eof => io::ErrorKind::InvalidData,
                    _ => io::ErrorKind::ConnectionReset,
                };
                let directory = tempfile::tempdir().unwrap();
                let dialer = ScriptedDialer::new(vec![Step::Bytes(bytes.clone()), completion]);
                let mut receiver =
                    UpdaterOutputTransfer::new(dialer, directory.path().to_path_buf());
                let error = partial(receiver.serve(9427, &request(9427)).unwrap_err());
                assert_eq!(error.port, 9427);
                assert_eq!(error.bytes, bytes.len() as u64);
                assert_eq!(error.stage, "validate CPIO");
                assert_eq!(error.source.kind(), kind);
                assert!(
                    error.source.to_string().contains(reason),
                    "{}",
                    error.source
                );
                assert_eq!(std::fs::read(&error.path).unwrap(), bytes);
            }
        }
    }

    #[test]
    fn read_failure_reports_the_persisted_partial_path_and_byte_count() {
        let kind = io::ErrorKind::TimedOut;
        let directory = tempfile::tempdir().unwrap();
        let dialer = ScriptedDialer::new(vec![Step::Bytes(b"070707".to_vec()), Step::Error(kind)]);
        let mut receiver = UpdaterOutputTransfer::new(dialer, directory.path().to_path_buf());
        let error = partial(receiver.serve(9421, &request(9421)).unwrap_err());
        assert_eq!(error.port, 9421);
        assert_eq!(error.bytes, 6);
        assert_eq!(error.stage, "read");
        assert_eq!(error.source.kind(), kind);
        assert_eq!(std::fs::read(&error.path).unwrap(), b"070707");
        assert!(
            error
                .to_string()
                .contains(&error.path.display().to_string())
        );
    }

    #[test]
    fn cancellation_keeps_the_partial_output_and_its_cancellation_source() {
        let directory = tempfile::tempdir().unwrap();
        let dialer = ScriptedDialer::new(vec![Step::Bytes(b"070707".to_vec()), Step::Cancel]);
        let mut receiver = UpdaterOutputTransfer::new(dialer, directory.path().to_path_buf());
        let error = receiver.serve(9422, &request(9422)).unwrap_err();
        match &error {
            ProviderError::Io(error) => assert_eq!(
                DialCancellation::from_io_error(error),
                Some(DialCancellation::TransferFailed)
            ),
            other => panic!("expected I/O cancellation, got {other}"),
        }
        let error = partial(error);
        assert_eq!(error.bytes, 6);
        assert_eq!(std::fs::read(&error.path).unwrap(), b"070707");
    }

    #[test]
    fn complete_cpio_with_eof_then_shutdown_reset_is_received() {
        let directory = tempfile::tempdir().unwrap();
        let archive = archive();
        let path = directory.path().join("baseband-updater-output-1.cpio");
        let mut dialer = ScriptedDialer::new(vec![Step::Bytes(archive.clone()), Step::Eof]);
        dialer.shutdown_error = Some(io::ErrorKind::ConnectionReset);
        dialer.output_at_shutdown = Some(path.clone());
        let capture = Arc::clone(&dialer.capture);
        let mut receiver = UpdaterOutputTransfer::new(dialer, directory.path().to_path_buf());
        assert_eq!(
            receiver.serve(9428, &request(9428)).unwrap(),
            BulkOutcome::Received {
                bytes: archive.len() as u64,
                path: path.clone()
            }
        );
        assert_eq!(std::fs::read(path).unwrap(), archive);
        let capture = capture.lock().unwrap();
        assert_eq!(capture.events, vec!["guest EOF", "host write shutdown"]);
        assert_eq!(
            capture.persisted_at_shutdown.as_deref(),
            Some(archive.as_slice())
        );
    }

    #[test]
    fn shutdown_failure_reports_the_fully_persisted_archive_as_incomplete() {
        let directory = tempfile::tempdir().unwrap();
        let archive = archive();
        let mut dialer = ScriptedDialer::new(vec![Step::Bytes(archive.clone()), Step::Eof]);
        dialer.shutdown_error = Some(io::ErrorKind::BrokenPipe);
        let mut receiver = UpdaterOutputTransfer::new(dialer, directory.path().to_path_buf());
        let error = partial(receiver.serve(9423, &request(9423)).unwrap_err());
        assert_eq!(error.bytes, archive.len() as u64);
        assert_eq!(error.stage, "shutdown write");
        assert_eq!(std::fs::read(&error.path).unwrap(), archive);
    }

    #[test]
    fn repeated_requests_reserve_exclusive_numbered_output_files() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("baseband-updater-output-1.cpio");
        let second = directory.path().join("baseband-updater-output-2.cpio");
        let third = directory.path().join("baseband-updater-output-3.cpio");
        std::fs::write(&first, b"previous guest output").unwrap();
        let archive = archive();
        let dialer = ScriptedDialer::new(vec![Step::Bytes(archive.clone()), Step::Eof]);
        let mut receiver = UpdaterOutputTransfer::new(dialer, directory.path().to_path_buf());
        assert_eq!(
            receiver.serve(9424, &request(9424)).unwrap(),
            BulkOutcome::Received {
                bytes: archive.len() as u64,
                path: second.clone()
            }
        );
        assert_eq!(
            receiver.serve(9424, &request(9424)).unwrap(),
            BulkOutcome::Received {
                bytes: archive.len() as u64,
                path: third.clone()
            }
        );
        assert_eq!(std::fs::read(first).unwrap(), b"previous guest output");
        assert_eq!(std::fs::read(second).unwrap(), archive);
        assert_eq!(std::fs::read(third).unwrap(), archive);
    }

    #[test]
    fn operator_cancellation_reserves_and_reports_its_zero_byte_partial_output() {
        let directory = tempfile::tempdir().unwrap();
        let dialer = ScriptedDialer::new(vec![Step::Eof]);
        let mut receiver = UpdaterOutputTransfer::new(dialer, directory.path().to_path_buf())
            .with_cancellation(
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(false)),
            );
        let error = partial(receiver.serve(9425, &request(9425)).unwrap_err());
        assert_eq!(error.bytes, 0);
        assert_eq!(error.stage, "dial");
        assert_eq!(std::fs::metadata(&error.path).unwrap().len(), 0);
        assert_eq!(
            DialCancellation::from_io_error(&error.source),
            Some(DialCancellation::OperatorStopped)
        );
    }
}
