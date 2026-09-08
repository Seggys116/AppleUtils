use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::asr_server::payload::PayloadObserver;
use crate::asr_server::producer::AsrPhase;
use crate::asr_server::session::{AsrServerConfig, AsrSession, SessionSummary};
use crate::asr_server::source::FileImageSource;

use super::dial::{Clock, DialPlan, GuestDialer, SystemClock, dial_until};
use super::images::bulk_image_entry;
use super::message::{DataRequest, DataType};
use super::provider::{BulkOutcome, BulkTransferService, ProviderError};

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

pub struct AsrBulkTransfer<D, O, C = SystemClock> {
    dialer: D,
    images: ImageSources,
    config: AsrServerConfig,
    observer: O,
    clock: C,
    attempt_timeout: Duration,
    retry_interval: Duration,
    window: Duration,
    transfers: Vec<SessionSummary>,
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
            clock: SystemClock,
            attempt_timeout: DEFAULT_DATA_PORT_ATTEMPT_TIMEOUT,
            retry_interval: DEFAULT_DATA_PORT_RETRY_INTERVAL,
            window: DEFAULT_DATA_PORT_WINDOW,
            transfers: Vec::new(),
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
            clock,
            attempt_timeout: DEFAULT_DATA_PORT_ATTEMPT_TIMEOUT,
            retry_interval: DEFAULT_DATA_PORT_RETRY_INTERVAL,
            window: DEFAULT_DATA_PORT_WINDOW,
            transfers: Vec::new(),
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

    pub fn transfers(&self) -> &[SessionSummary] {
        &self.transfers
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
    D: GuestDialer,
    O: PayloadObserver,
    C: Clock,
{
    fn serve(&mut self, port: u16, request: &DataRequest) -> Result<BulkOutcome, ProviderError> {
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

        let outcome = BulkOutcome::Served {
            bytes: payload.data_bytes,
            blocks: payload.blocks,
            initiates: summary.initiates,
            metadata_requests: summary.metadata_requests,
            oob_requests: summary.oob_ranges_requests + summary.oob_single_requests,
            oob_bytes: summary.oob_bytes,
        };
        self.transfers.push(summary);
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

    struct FlakyDialer {
        refusals: u32,
        attempts: u32,
        ports: Vec<u16>,
    }

    impl GuestDialer for FlakyDialer {
        type Stream = ScriptedStream;

        fn dial(&mut self, port: u16, _timeout: Duration) -> io::Result<Self::Stream> {
            self.attempts += 1;
            self.ports.push(port);
            if self.attempts <= self.refusals {
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
    fn a_data_port_request_is_answered_by_streaming_the_image_over_that_port() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_image(dir.path(), 4096);

        let mut service = AsrBulkTransfer::with_clock(
            FlakyDialer {
                refusals: 0,
                attempts: 0,
                ports: Vec::new(),
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
                attempts: 0,
                ports: Vec::new(),
            },
            ImageSources::with_default(&path),
            AsrServerConfig::default(),
            (),
            TestClock {
                now: Instant::now(),
            },
        );

        service.serve(0x4d2, &image_request(0x4d2)).unwrap();
        assert_eq!(service.dialer.attempts, 4);
        assert!(service.dialer.ports.iter().all(|port| *port == 0x4d2));
    }

    #[test]
    fn consecutive_transfers_follow_the_guest_counter_rather_than_pinning_the_first_port() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_image(dir.path(), 2048);

        let mut service = AsrBulkTransfer::with_clock(
            FlakyDialer {
                refusals: 0,
                attempts: 0,
                ports: Vec::new(),
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

        assert_eq!(service.dialer.ports, vec![12346, 12347, 12348]);
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
                attempts: 0,
                ports: Vec::new(),
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
            service.dialer.attempts, 0,
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
                attempts: 0,
                ports: Vec::new(),
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

    #[derive(Default)]
    struct RecordingObserver {
        matches: Vec<(String, u16, PathBuf)>,
        origins: Vec<(String, String)>,
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
                .push((data_type.to_string(), port, image.to_path_buf()));
            self.origins
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
                attempts: 0,
                ports: Vec::new(),
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

        let matches = &service.observer().matches;
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
                attempts: 0,
                ports: Vec::new(),
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
        assert_eq!(service.dialer.attempts, 0);
        assert!(service.transfers().is_empty());
        assert!(service.observer().matches.is_empty());
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
}
