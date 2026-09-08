use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub const DEFAULT_PRODUCER_SAMPLE: Duration = Duration::from_secs(1);

// Must stay past every bound a phase itself has: DEFAULT_DATA_PORT_WINDOW and DEFAULT_WRITE_POLL are 30s and healthy.
pub const DEFAULT_PRODUCER_STALL_AFTER: Duration = Duration::from_secs(45);

pub const DEFAULT_PRODUCER_REPEAT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum AsrPhase {
    #[default]
    Idle = 0,
    OpeningImage = 1,
    DiallingDataPort = 2,
    AwaitingRequest = 3,
    AnsweringInitiate = 4,
    ServingMetadata = 5,
    ServingOob = 6,
    ReadingImage = 7,
    DigestingBlock = 8,
    WritingPayload = 9,
    WritingDigest = 10,
    Reporting = 11,
    FlushingPayload = 12,
}

impl AsrPhase {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::OpeningImage => "opening-image",
            Self::DiallingDataPort => "dialling-data-port",
            Self::AwaitingRequest => "awaiting-request",
            Self::AnsweringInitiate => "answering-initiate",
            Self::ServingMetadata => "serving-metadata",
            Self::ServingOob => "serving-oob",
            Self::ReadingImage => "reading-image",
            Self::DigestingBlock => "digesting-block",
            Self::WritingPayload => "writing-payload",
            Self::WritingDigest => "writing-digest",
            Self::Reporting => "reporting",
            Self::FlushingPayload => "flushing-payload",
        }
    }

    #[must_use]
    pub fn waiting_on(self) -> &'static str {
        match self {
            Self::Idle => {
                "nothing; no bulk request is being served and the producing thread is reading the guest's control connection"
            }
            Self::OpeningImage => "the host filesystem, opening the image this request resolved to",
            Self::DiallingDataPort => "the guest reaching accept on the port it named",
            Self::AwaitingRequest => {
                "the guest's asr sending its next command on the data connection"
            }
            Self::AnsweringInitiate => "the transport, writing the Initiate response",
            Self::ServingMetadata => "the transport, writing the metadata blob",
            Self::ServingOob => "the image or the transport, answering an out-of-band range",
            Self::ReadingImage => "the host filesystem, reading one block of the image",
            Self::DigestingBlock => "nothing but the host CPU; a stall here is not an IO wait",
            Self::WritingPayload => {
                "the guest's receive window on the mux session carrying the payload"
            }
            Self::WritingDigest => {
                "the guest's receive window on the mux session carrying the payload"
            }
            Self::Reporting => "the restore reporter's mutex, or stdout behind it",
            Self::FlushingPayload => {
                "the guest's receive window, pushing out what the session still holds"
            }
        }
    }

    fn from_code(code: u8) -> Self {
        match code {
            1 => Self::OpeningImage,
            2 => Self::DiallingDataPort,
            3 => Self::AwaitingRequest,
            4 => Self::AnsweringInitiate,
            5 => Self::ServingMetadata,
            6 => Self::ServingOob,
            7 => Self::ReadingImage,
            8 => Self::DigestingBlock,
            9 => Self::WritingPayload,
            10 => Self::WritingDigest,
            11 => Self::Reporting,
            12 => Self::FlushingPayload,
            _ => Self::Idle,
        }
    }
}

pub struct AsrProducerActivity {
    began: Instant,
    session_offset_nanos: AtomicU64,
    phase: AtomicU8,
    phase_since: AtomicU64,
    transitions: AtomicU64,
    offset: AtomicU64,
    total: AtomicU64,
    blocks: AtomicU64,
    port: AtomicU16,
}

impl Default for AsrProducerActivity {
    fn default() -> Self {
        Self::new()
    }
}

impl AsrProducerActivity {
    #[must_use]
    pub fn new() -> Self {
        Self {
            began: Instant::now(),
            session_offset_nanos: AtomicU64::new(0),
            phase: AtomicU8::new(AsrPhase::Idle as u8),
            phase_since: AtomicU64::new(0),
            transitions: AtomicU64::new(0),
            offset: AtomicU64::new(0),
            total: AtomicU64::new(0),
            blocks: AtomicU64::new(0),
            port: AtomicU16::new(0),
        }
    }

    pub fn set_session_offset(&self, offset: Duration) {
        self.session_offset_nanos
            .store(offset.as_nanos() as u64, Ordering::Relaxed);
    }

    pub fn set_total(&self, total: u64) {
        self.total.store(total, Ordering::Relaxed);
    }

    pub fn set_port(&self, port: u16) {
        self.port.store(port, Ordering::Relaxed);
    }

    // The count is stored last and with release ordering, so `sample` can tell one phase from two.
    pub fn enter(&self, phase: AsrPhase) {
        let stamp = self.began.elapsed().as_nanos() as u64;
        self.phase.store(phase as u8, Ordering::Relaxed);
        self.phase_since.store(stamp, Ordering::Relaxed);
        self.transitions.fetch_add(1, Ordering::Release);
    }

    pub fn served_to(&self, offset: u64, blocks: u64) {
        self.offset.store(offset, Ordering::Relaxed);
        self.blocks.store(blocks, Ordering::Relaxed);
    }

    // `transitions` is read either side of the phase fields; a count that moved means no stall.
    #[must_use]
    pub fn sample(&self) -> AsrProducerSample {
        let before = self.transitions.load(Ordering::Acquire);
        let phase = AsrPhase::from_code(self.phase.load(Ordering::Relaxed));
        let since = self.phase_since.load(Ordering::Relaxed);
        let offset = self.offset.load(Ordering::Relaxed);
        let blocks = self.blocks.load(Ordering::Relaxed);
        let total = self.total.load(Ordering::Relaxed);
        let port = self.port.load(Ordering::Relaxed);
        let after = self.transitions.load(Ordering::Acquire);
        let elapsed = self.began.elapsed();
        let in_phase = if before == after {
            elapsed.saturating_sub(Duration::from_nanos(since))
        } else {
            Duration::ZERO
        };
        AsrProducerSample {
            phase,
            in_phase,
            transitions: after,
            offset,
            blocks,
            total,
            port,
            elapsed,
            session_offset: Duration::from_nanos(self.session_offset_nanos.load(Ordering::Relaxed)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsrProducerSample {
    pub phase: AsrPhase,
    pub in_phase: Duration,
    pub transitions: u64,
    pub offset: u64,
    pub blocks: u64,
    pub total: u64,
    pub port: u16,
    pub elapsed: Duration,
    pub session_offset: Duration,
}

impl AsrProducerSample {
    #[must_use]
    pub fn at(&self) -> Duration {
        self.elapsed + self.session_offset
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsrProducerEvent {
    ProducerClock {
        session_offset: Duration,
    },
    ProducerStalled {
        sample: AsrProducerSample,
        stalled: Duration,
    },
    ProducerResumed {
        sample: AsrProducerSample,
        stalled: Duration,
    },
}

impl AsrProducerEvent {
    #[must_use]
    pub fn result(&self) -> &'static str {
        match self {
            Self::ProducerClock { .. } => "producer-clock",
            Self::ProducerStalled { .. } => "producer-stalled",
            Self::ProducerResumed { .. } => "producer-resumed",
        }
    }

    fn meaning(&self) -> String {
        match self {
            Self::ProducerClock { session_offset } => format!(
                "every elapsed= on an [asr-serve] line is measured from this producer's own zero, and that zero is {:.3}s into the session; wall = elapsed + {:.3}s. The [ N.NNNs] ticker and every [usbmux] elapsed= are on the session clock and a streaming elapsed= is not, so the two must never be subtracted from one another",
                session_offset.as_secs_f64(),
                session_offset.as_secs_f64()
            ),
            Self::ProducerStalled { sample, .. } => format!(
                "the one thread that serves the guest's bulk request has been in this phase past the bound and has written nothing since; phase names where it is, in-phase how long it has been there, offset the last byte actually served, and transitions whether it is moving at all. It is waiting on {}",
                sample.phase.waiting_on()
            ),
            Self::ProducerResumed { .. } => {
                "the producing thread changed phase again, so whatever it was in has ended"
                    .to_string()
            }
        }
    }
}

impl fmt::Display for AsrProducerEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProducerClock { session_offset } => write!(
                f,
                "result=producer-clock session_offset={:.3}s ",
                session_offset.as_secs_f64()
            )?,
            Self::ProducerStalled { sample, stalled }
            | Self::ProducerResumed { sample, stalled } => {
                write!(
                    f,
                    "result={} phase={} waiting-on-port={} offset={} of={} blocks={} in-phase={:.3}s stalled={:.3}s transitions={} elapsed={:.3}s at={:.3}s ",
                    self.result(),
                    sample.phase.label(),
                    sample.port,
                    sample.offset,
                    sample.total,
                    sample.blocks,
                    sample.in_phase.as_secs_f64(),
                    stalled.as_secs_f64(),
                    sample.transitions,
                    sample.elapsed.as_secs_f64(),
                    sample.at().as_secs_f64()
                )?;
            }
        }
        write!(f, "meaning=\"{}\"", self.meaning())
    }
}

pub trait AsrProducerSink: Send + Sync {
    fn event(&self, event: AsrProducerEvent);
}

pub struct PrintingProducerTrace {
    prefix: String,
}

impl PrintingProducerTrace {
    #[must_use]
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }
}

impl AsrProducerSink for PrintingProducerTrace {
    fn event(&self, event: AsrProducerEvent) {
        use std::io::Write as _;
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{} {event}", self.prefix);
        let _ = stdout.flush();
    }
}

#[derive(Default)]
pub struct RecordingProducerTrace {
    events: std::sync::Mutex<Vec<AsrProducerEvent>>,
}

impl RecordingProducerTrace {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn events(&self) -> Vec<AsrProducerEvent> {
        match self.events.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl AsrProducerSink for RecordingProducerTrace {
    fn event(&self, event: AsrProducerEvent) {
        match self.events.lock() {
            Ok(mut guard) => guard.push(event),
            Err(poisoned) => poisoned.into_inner().push(event),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsrProducerWatchdogPolicy {
    pub sample: Duration,
    pub stall_after: Duration,
    pub repeat_every: Duration,
}

impl Default for AsrProducerWatchdogPolicy {
    fn default() -> Self {
        Self {
            sample: DEFAULT_PRODUCER_SAMPLE,
            stall_after: DEFAULT_PRODUCER_STALL_AFTER,
            repeat_every: DEFAULT_PRODUCER_REPEAT,
        }
    }
}

pub struct AsrProducerWatchdogHandle {
    stop: Arc<AtomicBool>,
    joiner: Option<std::thread::JoinHandle<()>>,
}

impl AsrProducerWatchdogHandle {
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(joiner) = self.joiner.take() {
            let _ = joiner.join();
        }
    }
}

impl Drop for AsrProducerWatchdogHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

#[must_use]
pub fn spawn_asr_producer_watchdog(
    activity: Arc<AsrProducerActivity>,
    sink: Arc<dyn AsrProducerSink>,
    policy: AsrProducerWatchdogPolicy,
) -> AsrProducerWatchdogHandle {
    let stop = Arc::new(AtomicBool::new(false));
    sink.event(AsrProducerEvent::ProducerClock {
        session_offset: activity.sample().session_offset,
    });
    let joiner = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || run_producer_watchdog(&activity, sink.as_ref(), policy, &stop))
    };
    AsrProducerWatchdogHandle {
        stop,
        joiner: Some(joiner),
    }
}

fn run_producer_watchdog(
    activity: &AsrProducerActivity,
    sink: &dyn AsrProducerSink,
    policy: AsrProducerWatchdogPolicy,
    stop: &AtomicBool,
) {
    let sample_every = policy.sample.max(Duration::from_millis(10));
    let mut stalled_since: Option<Instant> = None;
    let mut reported_at = Instant::now();

    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(sample_every);
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let now = Instant::now();
        let look = activity.sample();
        let stalled = look.phase != AsrPhase::Idle && look.in_phase >= policy.stall_after;

        match (stalled, stalled_since) {
            (true, None) => {
                stalled_since = Some(now);
                reported_at = now;
                sink.event(AsrProducerEvent::ProducerStalled {
                    sample: look,
                    stalled: Duration::ZERO,
                });
            }
            (true, Some(began)) => {
                if now.saturating_duration_since(reported_at) >= policy.repeat_every {
                    reported_at = now;
                    sink.event(AsrProducerEvent::ProducerStalled {
                        sample: look,
                        stalled: now.saturating_duration_since(began),
                    });
                }
            }
            (false, Some(began)) => {
                stalled_since = None;
                sink.event(AsrProducerEvent::ProducerResumed {
                    sample: look,
                    stalled: now.saturating_duration_since(began),
                });
            }
            (false, None) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_untouched_record_reports_idle_and_nothing_served() {
        let activity = AsrProducerActivity::new();
        let look = activity.sample();
        assert_eq!(look.phase, AsrPhase::Idle);
        assert_eq!(look.offset, 0);
        assert_eq!(look.transitions, 0);
    }

    #[test]
    fn a_phase_is_visible_with_its_offset_while_it_lasts() {
        let activity = AsrProducerActivity::new();
        activity.set_port(12346);
        activity.set_total(13_071_548_416);
        activity.served_to(7_056_916_480, 6730);
        activity.enter(AsrPhase::WritingPayload);
        let look = activity.sample();
        assert_eq!(look.phase, AsrPhase::WritingPayload);
        assert_eq!(look.offset, 7_056_916_480);
        assert_eq!(look.total, 13_071_548_416);
        assert_eq!(look.blocks, 6730);
        assert_eq!(look.port, 12346);
        assert_eq!(look.transitions, 1);
    }

    #[test]
    fn every_phase_code_survives_the_round_trip_through_the_atomic() {
        for phase in [
            AsrPhase::Idle,
            AsrPhase::OpeningImage,
            AsrPhase::DiallingDataPort,
            AsrPhase::AwaitingRequest,
            AsrPhase::AnsweringInitiate,
            AsrPhase::ServingMetadata,
            AsrPhase::ServingOob,
            AsrPhase::ReadingImage,
            AsrPhase::DigestingBlock,
            AsrPhase::WritingPayload,
            AsrPhase::WritingDigest,
            AsrPhase::Reporting,
            AsrPhase::FlushingPayload,
        ] {
            assert_eq!(AsrPhase::from_code(phase as u8), phase);
            assert!(!phase.label().is_empty());
            assert!(!phase.waiting_on().is_empty());
        }
    }

    #[test]
    fn a_sample_carries_both_the_producer_clock_and_the_session_clock() {
        let activity = AsrProducerActivity::new();
        activity.set_session_offset(Duration::from_millis(111_902));
        let look = activity.sample();
        assert_eq!(look.session_offset, Duration::from_millis(111_902));
        assert!(look.at() >= look.elapsed + Duration::from_millis(111_902));
    }

    #[test]
    fn an_idle_producer_is_never_reported_as_stalled() {
        let activity = Arc::new(AsrProducerActivity::new());
        let sink = Arc::new(RecordingProducerTrace::new());
        let stop = Arc::new(AtomicBool::new(false));
        let policy = AsrProducerWatchdogPolicy {
            sample: Duration::from_millis(10),
            stall_after: Duration::ZERO,
            repeat_every: Duration::from_millis(10),
        };
        let watcher = {
            let activity = Arc::clone(&activity);
            let sink = Arc::clone(&sink);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                run_producer_watchdog(&activity, sink.as_ref(), policy, &stop);
            })
        };
        std::thread::sleep(Duration::from_millis(60));
        stop.store(true, Ordering::Relaxed);
        let _ = watcher.join();
        assert!(
            sink.events().is_empty(),
            "an idle producer produced {:?}",
            sink.events()
        );
    }

    #[test]
    fn a_stall_line_names_the_phase_the_offset_and_both_clocks() {
        let activity = AsrProducerActivity::new();
        activity.set_session_offset(Duration::from_millis(111_902));
        activity.set_port(12346);
        activity.set_total(13_071_548_416);
        activity.served_to(7_056_916_480, 6730);
        activity.enter(AsrPhase::WritingPayload);
        let rendered = AsrProducerEvent::ProducerStalled {
            sample: activity.sample(),
            stalled: Duration::from_secs(60),
        }
        .to_string();
        assert!(rendered.contains("result=producer-stalled"), "{rendered}");
        assert!(rendered.contains("phase=writing-payload"), "{rendered}");
        assert!(rendered.contains("offset=7056916480"), "{rendered}");
        assert!(rendered.contains("of=13071548416"), "{rendered}");
        assert!(rendered.contains("waiting-on-port=12346"), "{rendered}");
        assert!(rendered.contains("stalled=60.000s"), "{rendered}");
        assert!(rendered.contains("transitions=1"), "{rendered}");
        assert!(rendered.contains("elapsed="), "{rendered}");
        assert!(rendered.contains("at="), "{rendered}");
        assert!(rendered.contains("receive window"), "{rendered}");
    }

    #[test]
    fn the_clock_line_states_the_offset_between_the_two_clocks() {
        let rendered = AsrProducerEvent::ProducerClock {
            session_offset: Duration::from_millis(111_902),
        }
        .to_string();
        assert!(rendered.contains("result=producer-clock"), "{rendered}");
        assert!(rendered.contains("session_offset=111.902s"), "{rendered}");
        assert!(rendered.contains("wall = elapsed + 111.902s"), "{rendered}");
    }
}
