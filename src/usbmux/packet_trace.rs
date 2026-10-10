use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::frame::{DEVICE_MAGIC, HOST_MAGIC, MuxHeader, MuxVersion, Protocol, VersionPacket};
use super::link::SendState;
use super::session::{SessionError, SessionEvent};
use super::tcp::TcpHeader;
use super::trace::PACKET_HEADER_TRACE_ENV;

const CAPACITY: usize = 4096;
const STAGES: usize = 10;
const SEALED: u64 = 1 << 63;
static RECORDER: OnceLock<Option<Arc<Recorder>>> = OnceLock::new();
static SOURCES: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stage {
    Enqueue,
    Dequeue,
    ReceiveReturn,
    CreditStart,
    PumpReceipt,
    Apply,
    WriteProbeStart,
    WriteProbeReturn,
    DrainProbeStart,
    DrainProbeReturn,
}

const ALL_STAGES: [Stage; STAGES] = [
    Stage::Enqueue,
    Stage::Dequeue,
    Stage::ReceiveReturn,
    Stage::CreditStart,
    Stage::PumpReceipt,
    Stage::Apply,
    Stage::WriteProbeStart,
    Stage::WriteProbeReturn,
    Stage::DrainProbeStart,
    Stage::DrainProbeReturn,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Disposition {
    Packet,
    CreditWritten,
    CreditStarted,
    IoError(io::ErrorKind, Option<i32>),
    Session(Result<SessionEvent, SessionError>),
    Unmatched,
    TcpDecodeError(super::tcp::TcpError),
    SequenceGap { expected: u16, received: u16 },
    ProbeEntered,
    ProbeSent,
    ProbeDeferred,
    ProbeEpochMoved,
    ProbeError,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Record {
    pub stage: Stage,
    pub source: u64,
    pub ordinal: u64,
    pub monotonic_ns: u64,
    pub clock_errno: Option<i32>,
    pub generation: u64,
    pub lease: u64,
    pub local_port: Option<u16>,
    pub length: usize,
    pub prefix: [u8; 36],
    pub prefix_len: usize,
    pub version: Option<MuxVersion>,
    pub before: Option<SendState>,
    pub after: Option<SendState>,
    pub disposition: Disposition,
    pub elapsed_ns: u64,
}

#[derive(Default)]
struct Population {
    seen: AtomicU64,
    lost: AtomicU64,
    reported: AtomicU64,
    report_errors: AtomicU64,
}

pub(super) struct Recorder {
    queue: Mutex<VecDeque<Record>>,
    reporting: Mutex<Vec<Record>>,
    admissions: AtomicU64,
    population: [Population; STAGES],
}

struct Admission<'a>(&'a AtomicU64);

impl Drop for Admission<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

impl Recorder {
    fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::with_capacity(CAPACITY)),
            reporting: Mutex::new(Vec::with_capacity(CAPACITY)),
            admissions: AtomicU64::new(0),
            population: std::array::from_fn(|_| Population::default()),
        }
    }

    fn push(&self, record: Record) {
        let previous = self.admissions.fetch_add(1, Ordering::Acquire);
        let _admission = Admission(&self.admissions);
        if previous & SEALED != 0 {
            return;
        }
        let population = &self.population[record.stage as usize];
        population.seen.fetch_add(1, Ordering::Relaxed);
        // Diagnostic contention loses only the record, never a transport packet.
        if let Ok(mut queue) = self.queue.try_lock()
            && queue.len() < CAPACITY
        {
            queue.push_back(record);
            return;
        }
        population.lost.fetch_add(1, Ordering::Relaxed);
    }

    fn report(&self) {
        let mut summary_at = Instant::now();
        while self.admissions.load(Ordering::Acquire) & SEALED == 0 {
            let census = Instant::now() >= summary_at;
            self.report_stderr(census, false);
            if census {
                summary_at = Instant::now() + Duration::from_secs(1);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn report_stderr(&self, census: bool, final_batch: bool) {
        // Serialise draining as well as writing, so an exit cannot miss an active reporter batch.
        let mut batch = self
            .reporting
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if !self.prepare_batch(&mut batch, final_batch) {
            return;
        }
        let stderr = io::stderr();
        let mut output = stderr.lock();
        self.write_batch(&mut batch, &mut output, census, final_batch);
    }

    fn prepare_batch(&self, batch: &mut Vec<Record>, final_batch: bool) -> bool {
        if final_batch {
            if self.admissions.fetch_or(SEALED, Ordering::AcqRel) & SEALED != 0 {
                return false;
            }
            // Producers admitted before sealing finish their counters and enqueue before the census.
            while self.admissions.load(Ordering::Acquire) & !SEALED != 0 {
                std::thread::yield_now();
            }
        } else if self.admissions.load(Ordering::Acquire) & SEALED != 0 {
            return false;
        }
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        batch.extend(queue.drain(..));
        true
    }

    fn write_batch(
        &self,
        batch: &mut Vec<Record>,
        output: &mut impl Write,
        census: bool,
        final_batch: bool,
    ) {
        for record in batch.drain(..) {
            let population = &self.population[record.stage as usize];
            if writeln!(output, "[mux-packet] {record}").is_ok() {
                population.reported.fetch_add(1, Ordering::Relaxed);
            } else {
                population.report_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        if census {
            for stage in ALL_STAGES {
                let population = &self.population[stage as usize];
                let _ = writeln!(
                    output,
                    "[mux-packet-population] final={final_batch} stage={stage:?} seen={} lost={} reported={} report_errors={}",
                    population.seen.load(Ordering::Relaxed),
                    population.lost.load(Ordering::Relaxed),
                    population.reported.load(Ordering::Relaxed),
                    population.report_errors.load(Ordering::Relaxed)
                );
            }
        }
        let _ = output.flush();
    }

    #[cfg(test)]
    fn finish_to(&self, output: &mut impl Write) {
        let mut batch = self
            .reporting
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if self.prepare_batch(&mut batch, true) {
            self.write_batch(&mut batch, output, true, true);
        }
    }

    #[cfg(test)]
    pub(super) fn drain(&self) -> Vec<Record> {
        self.queue.lock().unwrap().drain(..).collect()
    }

    #[cfg(test)]
    pub(super) fn seen(&self, stage: Stage) -> u64 {
        self.population[stage as usize].seen.load(Ordering::Relaxed)
    }
}

extern "C" fn finish_packet_trace() {
    // The C exit handler also runs when the caller terminates with std::process::exit.
    if let Some(Some(recorder)) = RECORDER.get() {
        recorder.report_stderr(true, true);
    }
}

struct Source {
    recorder: Arc<Recorder>,
    id: u64,
    generation: u64,
    lease: u64,
    ordinals: [AtomicU64; STAGES],
}

#[derive(Clone, Default)]
pub(super) struct Context(Option<Arc<Source>>);

impl Context {
    pub(super) fn new(generation: u64, lease: u64) -> Self {
        let recorder = RECORDER.get_or_init(|| {
            if !matches!(std::env::var(PACKET_HEADER_TRACE_ENV).as_deref(), Ok("1")) {
                return None;
            }
            if unsafe { libc::atexit(finish_packet_trace) } != 0 {
                eprintln!("[mux-packet] exit drain registration refused");
                return None;
            }
            let recorder = Arc::new(Recorder::new());
            let reporter = Arc::clone(&recorder);
            match std::thread::Builder::new()
                .name("mux-packet-reporter".into())
                .spawn(move || reporter.report())
            {
                Ok(_) => Some(recorder),
                Err(error) => {
                    eprintln!("[mux-packet] reporter refused: {error}");
                    None
                }
            }
        });
        recorder.as_ref().map_or_else(Self::default, |recorder| {
            Self::with_recorder(Arc::clone(recorder), generation, lease)
        })
    }

    fn with_recorder(recorder: Arc<Recorder>, generation: u64, lease: u64) -> Self {
        Self(Some(Arc::new(Source {
            recorder,
            id: SOURCES.fetch_add(1, Ordering::Relaxed),
            generation,
            lease,
            ordinals: std::array::from_fn(|_| AtomicU64::new(0)),
        })))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn packet(
        &self,
        stage: Stage,
        packet: &[u8],
        version: Option<MuxVersion>,
        local_port: Option<u16>,
        before: Option<SendState>,
        after: Option<SendState>,
        disposition: Disposition,
        elapsed_ns: u64,
    ) {
        let Some(source) = &self.0 else {
            return;
        };
        let (monotonic_ns, clock_errno) = monotonic_time();
        let mut prefix = [0; 36];
        let prefix_len = packet.len().min(prefix.len());
        prefix[..prefix_len].copy_from_slice(&packet[..prefix_len]);
        source.recorder.push(Record {
            stage,
            source: source.id,
            ordinal: source.ordinals[stage as usize].fetch_add(1, Ordering::Relaxed) + 1,
            monotonic_ns,
            clock_errno,
            generation: source.generation,
            lease: source.lease,
            local_port,
            length: packet.len(),
            prefix,
            prefix_len,
            version,
            before,
            after,
            disposition,
            elapsed_ns,
        });
    }

    pub(super) fn enabled(&self) -> bool {
        self.0.is_some()
    }

    pub(super) fn credit_started(&self) -> Option<u64> {
        self.0.as_ref().and_then(|_| {
            let (time, error) = monotonic_time();
            error.is_none().then_some(time)
        })
    }

    pub(super) fn elapsed(&self, started: Option<u64>) -> u64 {
        started.map_or(0, |started| monotonic_time().0.saturating_sub(started))
    }

    #[cfg(test)]
    pub(super) fn recording(generation: u64, lease: u64) -> (Self, Arc<Recorder>) {
        let recorder = Arc::new(Recorder::new());
        (
            Self::with_recorder(Arc::clone(&recorder), generation, lease),
            recorder,
        )
    }
}

fn monotonic_time() -> (u64, Option<i32>) {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // CLOCK_MONOTONIC is shared across the transport, link and reporter threads.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return (
            0,
            Some(
                io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO),
            ),
        );
    }
    (
        time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64,
        None,
    )
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ns={} clock_errno={:?} stage={:?} source={} ordinal={} generation={} lease={} local_port={:?} len={} elapsed_ns={} disposition={:?} before={:?} after={:?} raw=",
            self.monotonic_ns,
            self.clock_errno,
            self.stage,
            self.source,
            self.ordinal,
            self.generation,
            self.lease,
            self.local_port,
            self.length,
            self.elapsed_ns,
            self.disposition,
            self.before,
            self.after
        )?;
        for byte in &self.prefix[..self.prefix_len] {
            write!(f, "{byte:02x}")?;
        }
        if self.prefix_len >= 4 && self.prefix[..4] == Protocol::Version.wire_value().to_be_bytes()
        {
            match VersionPacket::decode(&self.prefix[..self.prefix_len]) {
                Ok(reply) => write!(
                    f,
                    " decode_version=version:{} reserved:{}",
                    reply.version, reply.reserved
                )?,
                Err(error) => write!(f, " decode_version=error({error})")?,
            }
        } else if self.prefix_len != 0 {
            match self.version {
                Some(version) => self.decode(f, version)?,
                // Transport has not negotiated framing; report both interpretations explicitly.
                None => {
                    self.decode(f, MuxVersion::V1)?;
                    self.decode(f, MuxVersion::V2)?;
                }
            }
        }
        Ok(())
    }
}

impl Record {
    fn decode(&self, f: &mut fmt::Formatter<'_>, version: MuxVersion) -> fmt::Result {
        write!(f, " decode_{version:?}=")?;
        let prefix = &self.prefix[..self.prefix_len];
        let header = match MuxHeader::decode(version, prefix) {
            Ok(header) => header,
            Err(error) => return write!(f, "error({error})"),
        };
        write!(
            f,
            "protocol:{} declared:{} magic:{:08x} outer_seq:{} outer_ack:{}",
            header.protocol.wire_value(),
            header.length,
            header.magic,
            header.tx_seq,
            header.rx_ack
        )?;
        if header.length as usize != self.length {
            write!(f, " error(length mismatch: delivered {})", self.length)?;
        }
        if version.is_sequenced() && header.magic != HOST_MAGIC && header.magic != DEVICE_MAGIC {
            write!(f, " error(unrecognised mux magic)")?;
        }
        if header.protocol == Protocol::Tcp {
            match TcpHeader::decode(&prefix[version.header_len()..]) {
                Ok(tcp) => write!(
                    f,
                    " local_port:{} remote_port:{} seq:{} ack:{} flags:{:02x} window:{}",
                    tcp.destination_port,
                    tcp.source_port,
                    tcp.sequence,
                    tcp.acknowledgement,
                    tcp.flags,
                    tcp.window
                )?,
                Err(error) => write!(f, " error({error})")?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::link::tests::{device_packet, encode_segment};
    use super::super::tcp::flags;
    use super::*;

    #[test]
    fn packet_trace_retains_wire_identity_and_reports_tcp_decode_errors() {
        let (context, recorder) = Context::recording(91, 12);
        let packet = device_packet(
            17,
            23,
            &encode_segment(
                TcpHeader {
                    source_port: 62078,
                    destination_port: 49152,
                    sequence: 123,
                    acknowledgement: 456,
                    flags: flags::ACK,
                    window: 65536,
                },
                &[],
            ),
        );
        context.packet(
            Stage::Enqueue,
            &packet,
            None,
            None,
            None,
            None,
            Disposition::Packet,
            0,
        );
        context.packet(
            Stage::Dequeue,
            &packet,
            None,
            None,
            None,
            None,
            Disposition::Packet,
            0,
        );
        let mut malformed = packet.clone();
        malformed[28] = 6 << 4;
        context.packet(
            Stage::PumpReceipt,
            &malformed,
            Some(MuxVersion::V2),
            None,
            None,
            None,
            Disposition::Packet,
            0,
        );
        let records = recorder.drain();
        assert_eq!(&records[0].prefix[..36], &packet[..]);
        assert_eq!(records[1].prefix, records[0].prefix);
        assert_eq!((records[0].generation, records[0].lease), (91, 12));
        assert!(records[1].monotonic_ns >= records[0].monotonic_ns);
        let rendered = records[0].to_string();
        assert!(rendered.contains("local_port:49152 remote_port:62078 seq:123 ack:456 flags:10"));
        assert!(
            records[2]
                .to_string()
                .contains("error(tcp data offset is 6 words")
        );
        assert_eq!(recorder.seen(Stage::Enqueue), 1);
        let version = super::super::link::tests::device_version_reply(2);
        context.packet(
            Stage::Enqueue,
            &version,
            None,
            None,
            None,
            None,
            Disposition::Packet,
            0,
        );
        let version = recorder.drain();
        assert!(
            version[0]
                .to_string()
                .contains("decode_version=version:2 reserved:0")
        );
    }

    #[test]
    fn packet_trace_process_exit_emits_final_packet_and_population() {
        const CHILD: &str = "APPLE_UTILS_PACKET_TRACE_EXIT_TEST";
        if std::env::var_os(CHILD).is_some() {
            let context = Context::new(91, 12);
            let recorder = RECORDER.get().unwrap().as_ref().unwrap();
            let held_reporter = recorder.reporting.lock().unwrap();
            let packet = device_packet(
                17,
                23,
                &encode_segment(
                    TcpHeader {
                        source_port: 62078,
                        destination_port: 49152,
                        sequence: 123,
                        acknowledgement: 456,
                        flags: flags::RST,
                        window: 65536,
                    },
                    &[],
                ),
            );
            context.packet(
                Stage::PumpReceipt,
                &packet,
                Some(MuxVersion::V2),
                Some(49152),
                None,
                None,
                Disposition::Packet,
                0,
            );
            drop(held_reporter);
            std::process::exit(2);
        }
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("usbmux::packet_trace::tests::packet_trace_process_exit_emits_final_packet_and_population")
            .arg("--nocapture")
            .env(CHILD, "1")
            .env(PACKET_HEADER_TRACE_ENV, "1")
            .output().unwrap();
        assert_eq!(child.status.code(), Some(2));
        let output = String::from_utf8(child.stderr).unwrap();
        assert!(output.contains("local_port:49152 remote_port:62078 seq:123 ack:456 flags:04"));
        let population = output
            .lines()
            .find(|line| line.contains("final=true stage=PumpReceipt seen=1"))
            .unwrap();
        assert!(population.contains("reported=1"));
    }

    #[test]
    fn packet_trace_final_drain_emits_queued_reset_and_complete_census() {
        let (context, recorder) = Context::recording(91, 12);
        let packet = device_packet(
            17,
            23,
            &encode_segment(
                TcpHeader {
                    source_port: 62078,
                    destination_port: 49152,
                    sequence: 123,
                    acknowledgement: 456,
                    flags: flags::RST,
                    window: 65536,
                },
                &[],
            ),
        );
        context.packet(
            Stage::PumpReceipt,
            &packet,
            Some(MuxVersion::V2),
            Some(49152),
            None,
            None,
            Disposition::Packet,
            0,
        );
        let mut output = Vec::new();
        recorder.finish_to(&mut output);
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("stage=PumpReceipt source="));
        assert!(output.contains("local_port:49152 remote_port:62078 seq:123 ack:456 flags:04"));
        assert!(output.contains("final=true stage=PumpReceipt seen=1"));
        assert_eq!(
            output
                .lines()
                .filter(|line| line.starts_with("[mux-packet-population]"))
                .count(),
            STAGES
        );
        assert_eq!(
            recorder.population[Stage::PumpReceipt as usize]
                .reported
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn packet_trace_counts_records_lost_to_diagnostic_capacity_and_contention() {
        let (context, recorder) = Context::recording(91, 12);
        for _ in 0..CAPACITY + 1 {
            context.packet(
                Stage::Enqueue,
                &[6],
                None,
                None,
                None,
                None,
                Disposition::Packet,
                0,
            );
        }
        assert_eq!(recorder.seen(Stage::Enqueue), (CAPACITY + 1) as u64);
        assert_eq!(
            recorder.population[Stage::Enqueue as usize]
                .lost
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(recorder.drain().len(), CAPACITY);
        let held = recorder.queue.lock().unwrap();
        context.packet(
            Stage::Dequeue,
            &[6],
            None,
            None,
            None,
            None,
            Disposition::Packet,
            0,
        );
        drop(held);
        assert_eq!(recorder.seen(Stage::Dequeue), 1);
        assert_eq!(
            recorder.population[Stage::Dequeue as usize]
                .lost
                .load(Ordering::Relaxed),
            1
        );
    }
}
