use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::asr_server::payload::PayloadObserver;
use crate::asr_server::producer::AsrPhase;
use crate::asr_server::session::{AsrServerConfig, AsrSession, SessionSummary};
use crate::asr_server::source::FileImageSource;

use super::dial::{Clock, DialPlan, GuestDialer, SystemClock, dial_until};
use super::images::bulk_image_entry;
use super::message::{DataRequest, DataType};
use super::provider::{BulkOutcome, BulkTransferService, BulkTransferTask, ProviderError};

pub const DEFAULT_DATA_PORT_WINDOW: Duration = Duration::from_secs(30);

pub const DEFAULT_DATA_PORT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);

pub const DEFAULT_DATA_PORT_RETRY_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImageOrigin {
    Configured,
    Manifest {
        entry: String,
        manifest_path: String,
        rule: &'static str,
    },
    Default,
}

impl ImageOrigin {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Manifest { .. } => "manifest",
            Self::Default => "default",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ImageMatch<'a> {
    pub path: &'a Path,
    pub origin: &'a ImageOrigin,
}

#[derive(Clone, Debug, Default)]
pub struct ImageSources {
    default: Option<PathBuf>,
    by_type: BTreeMap<String, (PathBuf, ImageOrigin)>,
}

impl ImageSources {
    #[must_use]
    pub fn with_default(image: impl AsRef<Path>) -> Self {
        Self {
            default: Some(image.as_ref().to_path_buf()),
            by_type: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn and_type(self, data_type: &DataType, image: impl AsRef<Path>) -> Self {
        self.and_origin(data_type, image, ImageOrigin::Configured)
    }

    #[must_use]
    pub fn and_origin(
        mut self,
        data_type: &DataType,
        image: impl AsRef<Path>,
        origin: ImageOrigin,
    ) -> Self {
        self.by_type.insert(
            data_type.wire_name().to_string(),
            (image.as_ref().to_path_buf(), origin),
        );
        self
    }

    #[must_use]
    pub fn names(&self, data_type: &DataType) -> bool {
        self.by_type.contains_key(data_type.wire_name())
    }

    #[must_use]
    pub fn resolve(&self, data_type: &DataType) -> Option<&Path> {
        self.resolve_match(data_type).map(|matched| matched.path)
    }

    #[must_use]
    pub fn resolve_match(&self, data_type: &DataType) -> Option<ImageMatch<'_>> {
        if let Some((path, origin)) = self.by_type.get(data_type.wire_name()) {
            return Some(ImageMatch {
                path: path.as_path(),
                origin,
            });
        }
        if bulk_image_entry(data_type).is_some_and(|entry| !entry.allows_default) {
            return None;
        }
        self.default.as_deref().map(|path| ImageMatch {
            path,
            origin: &ImageOrigin::Default,
        })
    }

    #[must_use]
    pub fn missing_source_hint(data_type: &DataType) -> String {
        match bulk_image_entry(data_type) {
            Some(entry) => format!(
                "this type is answered from the BuildManifest {} component and from nothing else: point --asr-serve-image-root at the directory holding that image, or name the file with {} PATH. It is not answered from --asr-serve-image, because streaming the wrong image here writes the wrong contents and lets the restore report success",
                entry.entry, entry.option
            ),
            None => "pass --asr-serve-image PATH".to_string(),
        }
    }
}

#[derive(Debug)]
struct StoppedImageTransfer {
    port: u16,
    data_type: String,
    bytes: u64,
    size: u64,
    source: std::io::Error,
}

impl std::fmt::Display for StoppedImageTransfer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the {} transfer on port {} stopped after {} of {} image bytes: {}",
            self.data_type, self.port, self.bytes, self.size, self.source
        )
    }
}

impl std::error::Error for StoppedImageTransfer {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.source.get_ref() {
            Some(source) => Some(source as &(dyn std::error::Error + 'static)),
            None => Some(&self.source),
        }
    }
}

pub struct AsrBulkTransfer<D, O, C = SystemClock> {
    dialer: D,
    images: ImageSources,
    config: AsrServerConfig,
    observer: O,
    transfer_started: Option<fn(&mut O)>,
    clock: C,
    attempt_timeout: Duration,
    retry_interval: Duration,
    window: Duration,
    transfers: Arc<Mutex<Vec<SessionSummary>>>,
}

impl<D, O> AsrBulkTransfer<D, O, SystemClock>
where
    D: GuestDialer,
    O: PayloadObserver,
{
    pub fn new(dialer: D, images: ImageSources, config: AsrServerConfig, observer: O) -> Self {
        Self {
            dialer,
            images,
            config,
            observer,
            transfer_started: None,
            clock: SystemClock,
            attempt_timeout: DEFAULT_DATA_PORT_ATTEMPT_TIMEOUT,
            retry_interval: DEFAULT_DATA_PORT_RETRY_INTERVAL,
            window: DEFAULT_DATA_PORT_WINDOW,
            transfers: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl<D, O, C> AsrBulkTransfer<D, O, C>
where
    D: GuestDialer,
    O: PayloadObserver,
    C: Clock,
{
    pub fn with_clock(
        dialer: D,
        images: ImageSources,
        config: AsrServerConfig,
        observer: O,
        clock: C,
    ) -> Self {
        Self {
            dialer,
            images,
            config,
            observer,
            transfer_started: None,
            clock,
            attempt_timeout: DEFAULT_DATA_PORT_ATTEMPT_TIMEOUT,
            retry_interval: DEFAULT_DATA_PORT_RETRY_INTERVAL,
            window: DEFAULT_DATA_PORT_WINDOW,
            transfers: Arc::new(Mutex::new(Vec::new())),
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

    pub fn transfers(&self) -> Vec<SessionSummary> {
        self.transfers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    #[must_use]
    pub fn with_transfer_started(mut self, started: fn(&mut O)) -> Self {
        self.transfer_started = Some(started);
        self
    }

    pub fn observer(&self) -> &O {
        &self.observer
    }

    fn plan(&self, port: u16) -> DialPlan {
        DialPlan {
            port,
            attempt_timeout: self.attempt_timeout,
            retry_interval: self.retry_interval,
            window: self.window,
        }
    }
}

impl<D, O, C> BulkTransferService for AsrBulkTransfer<D, O, C>
where
    D: GuestDialer + Clone + Send + 'static,
    O: PayloadObserver + Clone + Send + 'static,
    C: Clock + Clone + Send + 'static,
{
    fn prepare(
        &mut self,
        port: u16,
        request: &DataRequest,
    ) -> Result<BulkTransferTask, ProviderError> {
        if super::updater_output::is_updater_output(&request.data_type) {
            return Ok(Box::new(move || {
                Ok(BulkOutcome::Declined {
                    reason: format!(
                        "{port}: BasebandUpdaterOutputData is guest-produced output and requires an output receiver"
                    ),
                })
            }));
        }
        let mut transfer = Self {
            dialer: self.dialer.clone(),
            images: self.images.clone(),
            config: self.config.clone(),
            observer: self.observer.clone(),
            transfer_started: self.transfer_started,
            clock: self.clock.clone(),
            attempt_timeout: self.attempt_timeout,
            retry_interval: self.retry_interval,
            window: self.window,
            transfers: Arc::clone(&self.transfers),
        };
        let request = request.clone();
        Ok(Box::new(move || transfer.execute(port, &request)))
    }
}

impl<D, O, C> AsrBulkTransfer<D, O, C>
where
    D: GuestDialer,
    O: PayloadObserver,
    C: Clock,
{
    fn execute(&mut self, port: u16, request: &DataRequest) -> Result<BulkOutcome, ProviderError> {
        if let Some(started) = self.transfer_started {
            started(&mut self.observer);
        }
        let Some(matched) = self.images.resolve_match(&request.data_type) else {
            return Ok(BulkOutcome::Declined {
                reason: format!(
                    "the guest opened port {port} for a {} transfer and this host holds no image for that type; nothing was streamed and no other image was substituted: {}",
                    request.data_type,
                    ImageSources::missing_source_hint(&request.data_type)
                ),
            });
        };
        let origin = matched.origin.label();
        let image = matched.path.to_path_buf();
        self.observer.entered_phase(AsrPhase::OpeningImage, 0);
        let source = FileImageSource::open(&image).map_err(ProviderError::Io)?;
        let mut session = AsrSession::new(source, self.config.clone()).map_err(|error| {
            ProviderError::Other(format!(
                "port {port}: cannot serve a {} request from {}: {error}",
                request.data_type,
                image.display()
            ))
        })?;

        let plan = self.plan(port);
        self.observer.serving_port(port, session.payload_size());
        self.observer.image_matched(
            request.data_type.wire_name(),
            port,
            &image,
            origin,
            session.payload_size(),
        );
        self.observer.entered_phase(AsrPhase::DiallingDataPort, 0);
        let mut outcome = dial_until(&mut self.dialer, plan, &mut self.clock).map_err(|error| {
            ProviderError::Other(format!(
                "the guest named port {port} for its {} request but never accepted: {error}",
                request.data_type
            ))
        })?;

        let served = session.serve(&mut outcome.stream, &mut self.observer);
        self.observer.entered_phase(AsrPhase::Idle, 0);
        let summary = served.map_err(|error| {
            ProviderError::Other(format!(
                "the {} transfer on port {port} failed after {} attempt(s): {error}",
                request.data_type, outcome.attempts
            ))
        })?;

        let Some(payload) = summary.payload.as_ref() else {
            return Err(ProviderError::Other(format!(
                "the {} session on port {port} ended after {} Initiate and {} Metadata request(s) without ever streaming the payload",
                request.data_type, summary.initiates, summary.metadata_requests
            )));
        };

        if payload.stopped_early {
            let source = self.observer.stop_error();
            return Err(ProviderError::Io(std::io::Error::new(
                source.kind(),
                StoppedImageTransfer {
                    port,
                    data_type: request.data_type.wire_name().to_string(),
                    bytes: payload.data_bytes,
                    size: session.payload_size(),
                    source,
                },
            )));
        }

        let outcome = BulkOutcome::Served {
            bytes: payload.data_bytes,
            blocks: payload.blocks,
            initiates: summary.initiates,
            metadata_requests: summary.metadata_requests,
            oob_requests: summary.oob_ranges_requests + summary.oob_single_requests,
            oob_bytes: summary.oob_bytes,
        };
        self.transfers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(summary);
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read, Write};
    use std::time::Instant;

    use plist::Dictionary;

    use crate::asr_server::codec::{Command, Request, encode_plist};
    use crate::asr_server::message::KEY_PAYLOAD;

    use super::super::message::DataType;
    use super::*;

    struct ScriptedStream {
        inbound: Vec<u8>,
        cursor: usize,
        outbound: Vec<u8>,
    }

    impl Read for ScriptedStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let remaining = &self.inbound[self.cursor..];
            let count = remaining.len().min(buf.len());
            buf[..count].copy_from_slice(&remaining[..count]);
            self.cursor += count;
            Ok(count)
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.outbound.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct FlakyDialer {
        refusals: u32,
        attempts: Arc<std::sync::atomic::AtomicU32>,
        ports: Arc<Mutex<Vec<u16>>>,
    }

    impl GuestDialer for FlakyDialer {
        type Stream = ScriptedStream;

        fn dial(&mut self, port: u16, _timeout: Duration) -> io::Result<Self::Stream> {
            let attempts = self
                .attempts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            self.ports.lock().unwrap().push(port);
            if attempts <= self.refusals {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "not listening yet",
                ));
            }
            let mut inbound = encode_plist(&Request::new(Command::Initiate).to_value()).unwrap();
            inbound.extend_from_slice(
                &encode_plist(&Request::new(Command::Payload).to_value()).unwrap(),
            );
            Ok(ScriptedStream {
                inbound,
                cursor: 0,
                outbound: Vec::new(),
            })
        }
    }

    #[derive(Clone)]
    struct DeadDialer;

    impl GuestDialer for DeadDialer {
        type Stream = ScriptedStream;

        fn dial(&mut self, _port: u16, _timeout: Duration) -> io::Result<Self::Stream> {
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "nothing there",
            ))
        }
    }

    #[derive(Clone)]
    struct TestClock {
        now: Instant,
    }

    impl Clock for TestClock {
        fn now(&self) -> Instant {
            self.now
        }
        fn sleep(&mut self, duration: Duration) {
            self.now += duration;
        }
    }

    fn image_request(port: u16) -> DataRequest {
        DataRequest {
            data_type: DataType::RecoveryOSASRImage,
            data_port: Some(port),
            arguments: Dictionary::new(),
            asynchronous: false,
            async_context_uuid: None,
        }
    }

    fn write_image(dir: &Path, len: usize) -> PathBuf {
        let path = dir.join("image.bin");
        let body: Vec<u8> = (0..len).map(|index| (index % 251) as u8).collect();
        std::fs::write(&path, &body).unwrap();
        path
    }

    #[test]
    fn updater_output_is_refused_as_guest_output_even_with_a_default_image() {
        let dir = tempfile::tempdir().unwrap();
        let image = write_image(dir.path(), 4096);
        let mut service = AsrBulkTransfer::with_clock(
            FlakyDialer {
                refusals: 0,
                attempts: Arc::new(std::sync::atomic::AtomicU32::new(0)),
                ports: Arc::new(Mutex::new(Vec::new())),
            },
            ImageSources::with_default(&image),
            AsrServerConfig::default(),
            (),
            TestClock {
                now: Instant::now(),
            },
        );
        let mut request = image_request(9420);
        request.data_type = DataType::Other("BasebandUpdaterOutputData".to_string());
        match service.serve(9420, &request).unwrap() {
            BulkOutcome::Declined { reason } => {
                assert!(reason.contains("BasebandUpdaterOutputData"));
                assert!(reason.contains("guest-produced output"));
                assert!(reason.contains("9420"));
            }
            other => panic!("expected a named output-port refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_data_port_request_is_answered_by_streaming_the_image_over_that_port() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_image(dir.path(), 4096);

        let mut service = AsrBulkTransfer::with_clock(
            FlakyDialer {
                refusals: 0,
                attempts: Arc::new(std::sync::atomic::AtomicU32::new(0)),
                ports: Arc::new(Mutex::new(Vec::new())),
            },
            ImageSources::with_default(&path),
            AsrServerConfig {
                checksum_chunk_size: 0,
                ..AsrServerConfig::default()
            },
            (),
            TestClock {
                now: Instant::now(),
            },
        );

        service.serve(0x9001, &image_request(0x9001)).unwrap();

        assert_eq!(service.transfers().len(), 1);
        let payload = service.transfers()[0].payload.clone().unwrap();
        assert_eq!(payload.data_bytes, 4096);
        assert_eq!(service.transfers()[0].initiates, 1);
    }

    #[test]
    fn the_port_dialled_is_the_one_the_guest_named_and_a_refusal_is_retried() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_image(dir.path(), 1024);

        let mut service = AsrBulkTransfer::with_clock(
            FlakyDialer {
                refusals: 3,
                attempts: Arc::new(std::sync::atomic::AtomicU32::new(0)),
                ports: Arc::new(Mutex::new(Vec::new())),
            },
            ImageSources::with_default(&path),
            AsrServerConfig::default(),
            (),
            TestClock {
                now: Instant::now(),
            },
        );

        service.serve(0x4d2, &image_request(0x4d2)).unwrap();
        assert_eq!(
            service
                .dialer
                .attempts
                .load(std::sync::atomic::Ordering::Relaxed),
            4
        );
        assert!(
            service
                .dialer
                .ports
                .lock()
                .unwrap()
                .iter()
                .all(|port| *port == 0x4d2)
        );
    }

    #[test]
    fn consecutive_transfers_follow_the_guest_counter_rather_than_pinning_the_first_port() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_image(dir.path(), 2048);

        let mut service = AsrBulkTransfer::with_clock(
            FlakyDialer {
                refusals: 0,
                attempts: Arc::new(std::sync::atomic::AtomicU32::new(0)),
                ports: Arc::new(Mutex::new(Vec::new())),
            },
            ImageSources::with_default(&path),
            AsrServerConfig {
                checksum_chunk_size: 0,
                ..AsrServerConfig::default()
            },
            (),
            TestClock {
                now: Instant::now(),
            },
        );

        for port in [12346u16, 12347, 12348] {
            service.serve(port, &image_request(port)).unwrap();
        }

        assert_eq!(
            *service.dialer.ports.lock().unwrap(),
            vec![12346, 12347, 12348]
        );
        assert_eq!(service.transfers().len(), 3);
    }

    #[test]
    fn a_guest_that_never_accepts_fails_the_request_rather_than_reporting_a_transfer() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_image(dir.path(), 512);

        let mut service = AsrBulkTransfer::with_clock(
            DeadDialer,
            ImageSources::with_default(&path),
            AsrServerConfig::default(),
            (),
            TestClock {
                now: Instant::now(),
            },
        )
        .with_window(Duration::from_secs(1));

        let error = service.serve(7000, &image_request(7000)).unwrap_err();
        assert!(error.to_string().contains("7000"), "{error}");
        assert!(service.transfers().is_empty());
    }

    #[test]
    fn an_unreadable_image_fails_before_anything_is_dialled() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("not-here.bin");

        let mut service = AsrBulkTransfer::with_clock(
            FlakyDialer {
                refusals: 0,
                attempts: Arc::new(std::sync::atomic::AtomicU32::new(0)),
                ports: Arc::new(Mutex::new(Vec::new())),
            },
            ImageSources::with_default(&missing),
            AsrServerConfig::default(),
            (),
            TestClock {
                now: Instant::now(),
            },
        );

        assert!(service.serve(6000, &image_request(6000)).is_err());
        assert_eq!(
            service
                .dialer
                .attempts
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "the guest must not be dialled for an image that cannot be opened"
        );
    }

    #[test]
    fn the_size_the_guest_is_told_is_the_size_of_the_file_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_image(dir.path(), 3000);

        let mut service = AsrBulkTransfer::with_clock(
            FlakyDialer {
                refusals: 0,
                attempts: Arc::new(std::sync::atomic::AtomicU32::new(0)),
                ports: Arc::new(Mutex::new(Vec::new())),
            },
            ImageSources::with_default(&path),
            AsrServerConfig {
                checksum_chunk_size: 0,
                ..AsrServerConfig::default()
            },
            (),
            TestClock {
                now: Instant::now(),
            },
        );
        service.serve(5000, &image_request(5000)).unwrap();

        assert_eq!(
            service.transfers()[0].payload.as_ref().unwrap().wire_bytes,
            3000
        );
        // clippy 0.1.90 misevaluates this re-exported constant as always empty; `KEY_PAYLOAD` is `"Payload"`.
        #[allow(clippy::const_is_empty)]
        {
            assert!(!KEY_PAYLOAD.is_empty());
        }
    }

    #[derive(Clone, Default)]
    struct RecordingObserver {
        matches: Arc<Mutex<Vec<(String, u16, PathBuf)>>>,
        origins: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl PayloadObserver for RecordingObserver {
        fn block_sent(&mut self, _offset: u64, _data_len: usize) {}

        fn image_matched(
            &mut self,
            data_type: &str,
            port: u16,
            image: &Path,
            origin: &str,
            _payload_size: u64,
        ) {
            self.matches
                .lock()
                .unwrap()
                .push((data_type.to_string(), port, image.to_path_buf()));
            self.origins
                .lock()
                .unwrap()
                .push((data_type.to_string(), origin.to_string()));
        }
    }

    #[test]
    fn every_served_request_names_which_data_type_it_matched_the_image_to() {
        let dir = tempfile::tempdir().unwrap();
        let recovery = write_image(dir.path(), 1024);
        let system = dir.path().join("system.bin");
        std::fs::write(&system, vec![7u8; 2048]).unwrap();

        let mut service = AsrBulkTransfer::with_clock(
            FlakyDialer {
                refusals: 0,
                attempts: Arc::new(std::sync::atomic::AtomicU32::new(0)),
                ports: Arc::new(Mutex::new(Vec::new())),
            },
            ImageSources::with_default(&recovery).and_type(&DataType::SystemImageData, &system),
            AsrServerConfig {
                checksum_chunk_size: 0,
                ..AsrServerConfig::default()
            },
            RecordingObserver::default(),
            TestClock {
                now: Instant::now(),
            },
        );

        let first = image_request(9500);
        service.serve(9500, &first).unwrap();

        let mut second = image_request(9501);
        second.data_type = DataType::SystemImageData;
        service.serve(9501, &second).unwrap();

        let matches = service.observer().matches.lock().unwrap();
        assert_eq!(matches.len(), 2);
        assert_eq!(
            matches[0],
            ("RecoveryOSASRImage".to_string(), 9500, recovery.clone())
        );
        assert_eq!(
            matches[1],
            ("SystemImageData".to_string(), 9501, system.clone())
        );
        assert_ne!(matches[0].2, matches[1].2);
    }

    #[test]
    fn a_system_image_request_with_no_system_image_is_declined_rather_than_served_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let recovery = write_image(dir.path(), 1024);

        let mut service = AsrBulkTransfer::with_clock(
            FlakyDialer {
                refusals: 0,
                attempts: Arc::new(std::sync::atomic::AtomicU32::new(0)),
                ports: Arc::new(Mutex::new(Vec::new())),
            },
            ImageSources::with_default(&recovery),
            AsrServerConfig {
                checksum_chunk_size: 0,
                ..AsrServerConfig::default()
            },
            RecordingObserver::default(),
            TestClock {
                now: Instant::now(),
            },
        );

        let mut request = image_request(12346);
        request.data_type = DataType::SystemImageData;
        request.asynchronous = true;
        let outcome = service
            .serve(12346, &request)
            .expect("a declined transfer is not a failed session");
        match outcome {
            BulkOutcome::Declined { reason } => {
                assert!(reason.contains("SystemImageData"), "{reason}");
                assert!(reason.contains("--asr-serve-system-image"), "{reason}");
            }
            other => panic!("expected a decline, got {other:?}"),
        }
        assert_eq!(
            service
                .dialer
                .attempts
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert!(service.transfers().is_empty());
        assert!(service.observer().matches.lock().unwrap().is_empty());
    }

    #[test]
    fn every_other_type_still_falls_through_to_the_default_image() {
        let dir = tempfile::tempdir().unwrap();
        let recovery = dir.path().join("rosi.dmg");
        std::fs::write(&recovery, [1u8, 2, 3]).unwrap();
        let sources = ImageSources::with_default(&recovery);
        for data_type in [
            DataType::RecoveryOSASRImage,
            DataType::PersonalizedBootObjectV3,
            DataType::Other("RamdiskFWData".to_string()),
        ] {
            assert_eq!(sources.resolve(&data_type), Some(recovery.as_path()));
        }
        assert_eq!(sources.resolve(&DataType::SystemImageData), None);
    }
    #[test]
    fn asr_waiting_for_its_key_allows_a_second_async_port_and_a_control_answer() {
        use crate::ramrod::codec::{self as control_codec, PlistFormat};
        use crate::ramrod::{
            HttpAssetRouter, HttpAssetTransfer, PreparedAnswers, RamrodClient, RestoreOptions,
            SessionObserver,
        };
        use plist::Value;
        use std::io::Cursor;
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc;

        const IMAGE_PORT: u16 = 9510;
        const KEY_PORT: u16 = 9511;
        const KEY_BYTES: &[u8] = b"guest-decryption-key";
        const WRAPPED_KEY: &[u8] = b"wrapped guest key";

        struct Control {
            incoming: Cursor<Vec<u8>>,
            written: Vec<u8>,
            terminal_at: u64,
            completed: Option<mpsc::Receiver<u16>>,
        }
        impl Read for Control {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                if self.incoming.position() == self.terminal_at
                    && let Some(completed) = self.completed.take()
                {
                    let mut ports = vec![
                        completed.recv_timeout(Duration::from_secs(5)).unwrap(),
                        completed.recv_timeout(Duration::from_secs(5)).unwrap(),
                    ];
                    ports.sort();
                    assert_eq!(ports, vec![IMAGE_PORT, KEY_PORT]);
                }
                self.incoming.read(bytes)
            }
        }
        impl Write for Control {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.written.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        struct GuestStream {
            incoming: Cursor<Vec<u8>>,
            key_gate: Option<mpsc::Receiver<Vec<u8>>>,
            key_sink: Option<mpsc::Sender<Vec<u8>>>,
            image_waiting: mpsc::Sender<()>,
            key_received: Arc<AtomicBool>,
            port: u16,
            written: Vec<u8>,
            captured: Arc<Mutex<BTreeMap<u16, Vec<u8>>>>,
            completed: mpsc::Sender<u16>,
        }
        impl Drop for GuestStream {
            fn drop(&mut self) {
                let _ = self.completed.send(self.port);
            }
        }
        impl Read for GuestStream {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                if let Some(gate) = self.key_gate.take() {
                    self.image_waiting.send(()).unwrap();
                    let reply = gate.recv_timeout(Duration::from_secs(5)).map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("guest image waiting for its key: {error}"),
                        )
                    })?;
                    let decoded = control_codec::read_message(&mut Cursor::new(reply))
                        .map_err(|error| {
                            io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                        })?
                        .unwrap();
                    let body = decoded.as_dictionary().unwrap();
                    assert_eq!(
                        body.get("ResponseBody").and_then(Value::as_data),
                        Some(KEY_BYTES)
                    );
                    assert_eq!(
                        body.get("ResponseBodyDone").and_then(Value::as_boolean),
                        Some(true)
                    );
                    assert_eq!(
                        body.get("ResponseStatus")
                            .and_then(Value::as_signed_integer),
                        Some(200)
                    );
                    self.key_received.store(true, Ordering::Release);
                }
                self.incoming.read(bytes)
            }
        }
        impl Write for GuestStream {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.written.extend_from_slice(bytes);
                self.captured
                    .lock()
                    .unwrap()
                    .entry(self.port)
                    .or_default()
                    .extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                if let Some(sink) = self.key_sink.take() {
                    sink.send(std::mem::take(&mut self.written))
                        .map_err(|error| {
                            io::Error::new(io::ErrorKind::BrokenPipe, error.to_string())
                        })?;
                }
                Ok(())
            }
        }
        #[derive(Clone)]
        struct Dialer {
            key_gate: Arc<Mutex<Option<mpsc::Receiver<Vec<u8>>>>>,
            key_sink: mpsc::Sender<Vec<u8>>,
            image_waiting: mpsc::Sender<()>,
            key_received: Arc<AtomicBool>,
            captured: Arc<Mutex<BTreeMap<u16, Vec<u8>>>>,
            completed: mpsc::Sender<u16>,
        }
        impl GuestDialer for Dialer {
            type Stream = GuestStream;
            fn dial(&mut self, port: u16, _timeout: Duration) -> io::Result<Self::Stream> {
                let (incoming, key_gate, key_sink) = match port {
                    IMAGE_PORT => {
                        let mut incoming =
                            encode_plist(&Request::new(Command::Initiate).to_value()).unwrap();
                        incoming.extend_from_slice(
                            &encode_plist(&Request::new(Command::Payload).to_value()).unwrap(),
                        );
                        (incoming, self.key_gate.lock().unwrap().take(), None)
                    }
                    KEY_PORT => (Vec::new(), None, Some(self.key_sink.clone())),
                    other => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            format!("guest did not name port {other}"),
                        ));
                    }
                };
                Ok(GuestStream {
                    incoming: Cursor::new(incoming),
                    key_gate,
                    key_sink,
                    image_waiting: self.image_waiting.clone(),
                    key_received: Arc::clone(&self.key_received),
                    port,
                    written: Vec::new(),
                    captured: Arc::clone(&self.captured),
                    completed: self.completed.clone(),
                })
            }
        }
        struct Observer {
            control_answered: mpsc::Sender<()>,
            completions: Vec<(u16, String)>,
        }
        impl SessionObserver for Observer {
            fn on_data_answered(&mut self, _request: &DataRequest, _keys: &[&str], _bytes: usize) {
                self.control_answered.send(()).unwrap();
            }
            fn on_bulk_served(&mut self, request: &DataRequest, port: u16, _outcome: &BulkOutcome) {
                self.completions
                    .push((port, request.data_type.wire_name().to_string()));
            }
        }
        fn request(
            data_type: &str,
            port: Option<u16>,
            asynchronous: bool,
            arguments: Dictionary,
        ) -> Value {
            let mut body = Dictionary::new();
            body.insert(
                "MsgType".into(),
                Value::String(
                    if asynchronous {
                        "AsyncDataRequestMsg"
                    } else {
                        "DataRequestMsg"
                    }
                    .into(),
                ),
            );
            body.insert("DataType".into(), Value::String(data_type.into()));
            if let Some(port) = port {
                body.insert("DataPort".into(), Value::Integer(u64::from(port).into()));
            }
            body.insert("Arguments".into(), Value::Dictionary(arguments));
            Value::Dictionary(body)
        }

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/key", listener.local_addr().unwrap());
        let (image_waiting_tx, image_waiting_rx) = mpsc::channel();
        let (control_answered_tx, control_answered_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let began = Instant::now();
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && began.elapsed() < Duration::from_secs(5) =>
                    {
                        std::thread::sleep(Duration::from_millis(1))
                    }
                    Err(error) => panic!("key HTTP request did not arrive: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut incoming = Vec::new();
            let end = loop {
                if let Some(at) = incoming.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    break at + 4;
                }
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).unwrap();
                incoming.push(byte[0]);
            };
            let headers = std::str::from_utf8(&incoming[..end]).unwrap();
            assert!(headers.starts_with("POST /key HTTP/1.1\r\n"));
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            let mut body = vec![0u8; length];
            stream.read_exact(&mut body).unwrap();
            assert_eq!(body, WRAPPED_KEY);
            image_waiting_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            control_answered_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Key-Origin: guest-request\r\nConnection: close\r\n\r\n", KEY_BYTES.len()).unwrap();
            stream.write_all(KEY_BYTES).unwrap();
            stream.flush().unwrap();
            body.len()
        });
        let (key_sink, key_gate) = mpsc::channel();
        let (completed_tx, completed_rx) = mpsc::channel();
        let captured = Arc::new(Mutex::new(BTreeMap::new()));
        let key_received = Arc::new(AtomicBool::new(false));
        let dialer = Dialer {
            key_gate: Arc::new(Mutex::new(Some(key_gate))),
            key_sink,
            image_waiting: image_waiting_tx,
            key_received: Arc::clone(&key_received),
            captured: Arc::clone(&captured),
            completed: completed_tx,
        };
        let directory = tempfile::tempdir().unwrap();
        let image = write_image(directory.path(), 4096);
        let expected_image = std::fs::read(&image).unwrap();
        let asr = AsrBulkTransfer::new(
            dialer.clone(),
            ImageSources::with_default(&image),
            AsrServerConfig {
                checksum_chunk_size: 0,
                ..AsrServerConfig::default()
            },
            (),
        );
        let stop = Arc::new(AtomicBool::new(false));
        let cancel = Arc::new(AtomicBool::new(false));
        let http = HttpAssetTransfer::new(dialer, stop, Arc::clone(&cancel));
        let mut bulk = HttpAssetRouter::new(http, asr);
        let mut arguments = Dictionary::new();
        arguments.insert("RequestMethod".into(), Value::String("POST".into()));
        arguments.insert("RequestURL".into(), Value::String(url));
        arguments.insert("RequestBody".into(), Value::Data(WRAPPED_KEY.to_vec()));
        arguments.insert(
            "RequestAdditionalHeaders".into(),
            Value::Dictionary(Dictionary::new()),
        );
        let mut final_status = Dictionary::new();
        final_status.insert(
            "MsgType".into(),
            Value::String("ReceivedFinalStatusMsg".into()),
        );
        let mut incoming = Vec::new();
        for message in [
            request(
                "RecoveryOSASRImage",
                Some(IMAGE_PORT),
                true,
                Dictionary::new(),
            ),
            request(
                "StreamedImageDecryptionKey",
                Some(KEY_PORT),
                true,
                arguments,
            ),
            request("RecoveryOSRootTicketData", None, false, Dictionary::new()),
        ] {
            incoming.extend_from_slice(
                &control_codec::encode_message(&message, PlistFormat::Binary).unwrap(),
            );
        }
        let terminal_at = incoming.len() as u64;
        incoming.extend_from_slice(
            &control_codec::encode_message(&Value::Dictionary(final_status), PlistFormat::Binary)
                .unwrap(),
        );
        let mut client = RamrodClient::new(Control {
            incoming: Cursor::new(incoming),
            written: Vec::new(),
            terminal_at,
            completed: Some(completed_rx),
        });
        client.start_restore(RestoreOptions::new()).unwrap();
        let mut provider =
            PreparedAnswers::new().with_ticket(DataType::RecoveryOSRootTicketData, vec![9, 8, 7]);
        let mut observer = Observer {
            control_answered: control_answered_tx,
            completions: Vec::new(),
        };
        let result =
            client.run_restore_with_cancellation(&mut provider, &mut bulk, &mut observer, cancel);
        assert_eq!(server.join().unwrap(), WRAPPED_KEY.len());
        let summary = result.unwrap();
        assert_eq!(summary.async_data_requests, 2);
        assert_eq!(summary.bulk_transfers, 2);
        assert_eq!(summary.data_requests, 1);
        let control = client.into_inner();
        let mut control_replies = Cursor::new(control.written);
        control_codec::read_message(&mut control_replies)
            .unwrap()
            .unwrap();
        let reply = control_codec::read_message(&mut control_replies)
            .unwrap()
            .unwrap();
        assert_eq!(
            reply
                .as_dictionary()
                .unwrap()
                .get("RootTicketData")
                .and_then(Value::as_data),
            Some(&[9, 8, 7][..])
        );
        observer.completions.sort();
        assert_eq!(
            observer.completions,
            vec![
                (IMAGE_PORT, "RecoveryOSASRImage".into()),
                (KEY_PORT, "StreamedImageDecryptionKey".into())
            ]
        );
        assert!(key_received.load(Ordering::Acquire));
        let transfers = bulk.fallback().transfers();
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].payload.as_ref().unwrap().data_bytes, 4096);
        let captured = captured.lock().unwrap();
        assert!(
            captured[&IMAGE_PORT]
                .windows(expected_image.len())
                .any(|bytes| bytes == expected_image.as_slice())
        );
        assert!(captured[&KEY_PORT].len() > KEY_BYTES.len());
    }

    fn partial_image_stop(reason: super::super::dial::DialCancellation, port: u16) {
        use super::super::dial::DialCancellation;
        use crate::asr_server::payload::DEFAULT_BLOCK_LEN;
        use crate::restore::{PayloadProgress, RestoreEvent, RestoreReporter, SharedReporter};
        use std::sync::atomic::{AtomicBool, Ordering};

        struct ProgressReporter {
            blocks: Vec<(u64, u64, u64)>,
            events: Vec<String>,
            stop: Arc<AtomicBool>,
            cancel: Arc<AtomicBool>,
            reason: DialCancellation,
        }
        impl RestoreReporter for ProgressReporter {
            fn event(&mut self, event: RestoreEvent<'_>) {
                self.events.push(event.result.into());
            }
            fn payload_block(&mut self, sent: u64, total: u64, blocks: u64, _elapsed: Duration) {
                self.blocks.push((sent, total, blocks));
                self.cancel.store(true, Ordering::Release);
                if self.reason == DialCancellation::OperatorStopped {
                    self.stop.store(true, Ordering::Release);
                }
            }
        }
        struct CaptureStream {
            incoming: std::io::Cursor<Vec<u8>>,
            captured: Arc<Mutex<Vec<u8>>>,
        }
        impl Read for CaptureStream {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                self.incoming.read(bytes)
            }
        }
        impl Write for CaptureStream {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.captured.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        #[derive(Clone)]
        struct CaptureDialer {
            captured: Arc<Mutex<Vec<u8>>>,
        }
        impl GuestDialer for CaptureDialer {
            type Stream = CaptureStream;
            fn dial(&mut self, _port: u16, _timeout: Duration) -> io::Result<Self::Stream> {
                let mut incoming =
                    encode_plist(&Request::new(Command::Initiate).to_value()).unwrap();
                incoming.extend_from_slice(
                    &encode_plist(&Request::new(Command::Payload).to_value()).unwrap(),
                );
                Ok(CaptureStream {
                    incoming: std::io::Cursor::new(incoming),
                    captured: Arc::clone(&self.captured),
                })
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let image = write_image(directory.path(), 2 * DEFAULT_BLOCK_LEN);
        let expected = std::fs::read(&image).unwrap();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let cancel = Arc::new(AtomicBool::new(false));
        let recorded = Arc::new(Mutex::new(ProgressReporter {
            blocks: Vec::new(),
            events: Vec::new(),
            stop: Arc::clone(&stop),
            cancel: Arc::clone(&cancel),
            reason,
        }));
        let reporter: SharedReporter = recorded.clone();
        let observer = PayloadProgress::new(expected.len() as u64, stop, reporter)
            .with_transfer_cancel(cancel);
        let mut service = AsrBulkTransfer::new(
            CaptureDialer {
                captured: Arc::clone(&captured),
            },
            ImageSources::with_default(&image),
            AsrServerConfig {
                checksum_chunk_size: 0,
                ..AsrServerConfig::default()
            },
            observer,
        );
        let error = service.serve(port, &image_request(port)).unwrap_err();
        let ProviderError::Io(error) = error else {
            panic!("expected a typed partial-image stop, got {error}");
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(DialCancellation::from_io_error(&error), Some(reason));
        assert!(
            error
                .to_string()
                .contains(&format!("RecoveryOSASRImage transfer on port {port}"))
        );
        assert!(error.to_string().contains(&format!(
            "stopped after {} of {} image bytes",
            DEFAULT_BLOCK_LEN,
            2 * DEFAULT_BLOCK_LEN
        )));
        assert_eq!(
            recorded.lock().unwrap().blocks,
            vec![(DEFAULT_BLOCK_LEN as u64, (2 * DEFAULT_BLOCK_LEN) as u64, 1)]
        );
        let captured = captured.lock().unwrap();
        assert!(
            captured
                .windows(DEFAULT_BLOCK_LEN)
                .any(|bytes| bytes == &expected[..DEFAULT_BLOCK_LEN])
        );
    }

    #[test]
    fn a_partially_written_image_returns_typed_terminal_cleanup_cancellation() {
        partial_image_stop(super::super::dial::DialCancellation::TransferFailed, 9630);
    }

    #[test]
    fn a_partially_written_image_returns_typed_operator_stop() {
        partial_image_stop(super::super::dial::DialCancellation::OperatorStopped, 9631);
    }
}
