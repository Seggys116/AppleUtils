use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

pub const ROUNDTRIP_TAG: &str = "[mux-roundtrip]";

pub const WAITS_PER_SUMMARY: u32 = 128;

pub const SUMMARY_MIN_INTERVAL: Duration = Duration::from_secs(30);

pub const PROCESS_LINE_BUDGET: u32 = 1024;

const UNACKED_RING: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineGrant {
    Granted,
    Last,
    Exhausted,
}

#[derive(Clone, Debug)]
pub struct LineBudget {
    remaining: Arc<AtomicU32>,
}

impl LineBudget {
    #[must_use]
    pub fn new(lines: u32) -> Self {
        Self {
            remaining: Arc::new(AtomicU32::new(lines)),
        }
    }

    #[must_use]
    pub fn process() -> Self {
        static BUDGET: OnceLock<Arc<AtomicU32>> = OnceLock::new();
        Self {
            remaining: Arc::clone(
                BUDGET.get_or_init(|| Arc::new(AtomicU32::new(PROCESS_LINE_BUDGET))),
            ),
        }
    }

    #[must_use]
    pub fn remaining(&self) -> u32 {
        self.remaining.load(Ordering::Relaxed)
    }

    pub fn take(&self) -> LineGrant {
        let taken = self
            .remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                if left == 0 { None } else { Some(left - 1) }
            });
        match taken {
            Err(_) => LineGrant::Exhausted,
            Ok(1) => LineGrant::Last,
            Ok(_) => LineGrant::Granted,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SummaryReason {
    Periodic,
    Closed,
}

impl SummaryReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Periodic => "periodic",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    pub count: u64,
    pub total_us: u64,
    pub max_us: u64,
}

impl Tally {
    fn record(&mut self, micros: u64) {
        self.count += 1;
        self.total_us = self.total_us.saturating_add(micros);
        if micros > self.max_us {
            self.max_us = micros;
        }
    }

    #[must_use]
    pub fn mean_us(&self) -> u64 {
        self.total_us.checked_div(self.count).unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug)]
struct SentSegment {
    seq_end: u32,
    bytes: u32,
    sent_at: Instant,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PortStats {
    pub local_port: u16,
    pub bytes_queued: u64,
    pub segments_sent: u64,
    pub bytes_sent: u64,
    pub bytes_acked: u64,
    pub send: Tally,
    pub blocked: Tally,
    pub waited_window_open: Tally,
    pub lock_wait: Tally,
    pub inbound_wait_shut: Tally,
    pub inbound_wait_open: Tally,
    pub ack: Tally,
    pub peer_window: u32,
    pub usable_at_block: u32,
    pub in_flight_at_block: u32,
    pub in_flight_total_at_block: u64,
    pub unacked_now: u32,
    pub unacked_dropped: u64,
    pub span: Duration,
}

impl PortStats {
    #[must_use]
    pub fn in_flight_mean_at_block(&self) -> u64 {
        self.in_flight_total_at_block
            .checked_div(self.blocked.count)
            .unwrap_or(0)
    }

    #[must_use]
    pub fn bytes_per_second(&self) -> u64 {
        let micros = self.span.as_micros();
        if micros == 0 {
            return 0;
        }
        u64::try_from(u128::from(self.bytes_sent) * 1_000_000 / micros).unwrap_or(u64::MAX)
    }

    #[must_use]
    fn body(&self, reason: SummaryReason) -> String {
        let mut line = String::with_capacity(512);
        let _ = write!(
            line,
            "port={} why={} queued={} sent_segs={} sent_bytes={} acked_bytes={} \
             send_n={} send_mean_us={} send_max_us={} \
             blocked_n={} blocked_mean_us={} blocked_max_us={} \
             openwait_n={} openwait_mean_us={} \
             lockwait_n={} lockwait_mean_us={} lockwait_max_us={} lockwait_total_ms={} \
             inwait_shut_n={} inwait_shut_mean_us={} inwait_shut_max_us={} \
             inwait_open_n={} inwait_open_mean_us={} \
             ack_n={} ack_mean_us={} ack_max_us={} \
             peer_win={} usable_at_block={} inflight_at_block={} inflight_mean_at_block={} \
             unacked_now={} unacked_dropped={} span_ms={} bytes_per_sec={}",
            self.local_port,
            reason.as_str(),
            self.bytes_queued,
            self.segments_sent,
            self.bytes_sent,
            self.bytes_acked,
            self.send.count,
            self.send.mean_us(),
            self.send.max_us,
            self.blocked.count,
            self.blocked.mean_us(),
            self.blocked.max_us,
            self.waited_window_open.count,
            self.waited_window_open.mean_us(),
            self.lock_wait.count,
            self.lock_wait.mean_us(),
            self.lock_wait.max_us,
            self.lock_wait.total_us / 1000,
            self.inbound_wait_shut.count,
            self.inbound_wait_shut.mean_us(),
            self.inbound_wait_shut.max_us,
            self.inbound_wait_open.count,
            self.inbound_wait_open.mean_us(),
            self.ack.count,
            self.ack.mean_us(),
            self.ack.max_us,
            self.peer_window,
            self.usable_at_block,
            self.in_flight_at_block,
            self.in_flight_mean_at_block(),
            self.unacked_now,
            self.unacked_dropped,
            self.span.as_millis(),
            self.bytes_per_second(),
        );
        line
    }
}

#[derive(Debug)]
struct PortMeter {
    stats: PortStats,
    unacked: VecDeque<SentSegment>,
    first_send: Option<Instant>,
    last_activity: Option<Instant>,
    waits_since_summary: u32,
    last_summary: Option<Instant>,
}

impl PortMeter {
    fn new(local_port: u16) -> Self {
        Self {
            stats: PortStats {
                local_port,
                ..PortStats::default()
            },
            unacked: VecDeque::with_capacity(UNACKED_RING),
            first_send: None,
            last_activity: None,
            waits_since_summary: 0,
            last_summary: None,
        }
    }

    fn touch(&mut self, at: Instant) {
        if self.first_send.is_none() {
            self.first_send = Some(at);
        }
        self.last_activity = Some(at);
        if let (Some(first), Some(last)) = (self.first_send, self.last_activity) {
            self.stats.span = last.saturating_duration_since(first);
        }
    }
}

pub type LineSink = Box<dyn FnMut(&str) + Send>;

pub struct RoundtripMeter {
    ports: BTreeMap<u16, PortMeter>,
    budget: LineBudget,
    sink: LineSink,
}

impl std::fmt::Debug for RoundtripMeter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoundtripMeter")
            .field("ports", &self.ports.len())
            .field("lines_left", &self.budget.remaining())
            .finish()
    }
}

impl Default for RoundtripMeter {
    fn default() -> Self {
        Self::new()
    }
}

impl RoundtripMeter {
    #[must_use]
    pub fn new() -> Self {
        Self::with_sink(LineBudget::process(), Box::new(|_: &str| {}))
    }

    #[must_use]
    pub fn stderr() -> Self {
        Self {
            ports: BTreeMap::new(),
            budget: LineBudget::process(),
            sink: Box::new(|line: &str| {
                use std::io::Write as _;
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(stderr, "{line}");
                let _ = stderr.flush();
            }),
        }
    }

    #[must_use]
    pub fn with_sink(budget: LineBudget, sink: LineSink) -> Self {
        Self {
            ports: BTreeMap::new(),
            budget,
            sink,
        }
    }

    #[must_use]
    pub fn stats(&self, local_port: u16) -> Option<PortStats> {
        self.ports.get(&local_port).map(|port| port.stats)
    }

    pub fn on_queue(&mut self, local_port: u16, bytes: usize) {
        let port = self.port(local_port);
        port.stats.bytes_queued += bytes as u64;
    }

    pub fn on_segment_sent(
        &mut self,
        local_port: u16,
        sequence: u32,
        bytes: usize,
        send: Duration,
        at: Instant,
    ) {
        if bytes == 0 {
            return;
        }
        let port = self.port(local_port);
        port.stats.segments_sent += 1;
        port.stats.bytes_sent += bytes as u64;
        port.stats.send.record(micros(send));
        if port.unacked.len() == UNACKED_RING {
            port.unacked.pop_front();
            port.stats.unacked_dropped += 1;
        }
        port.unacked.push_back(SentSegment {
            seq_end: sequence.wrapping_add(bytes as u32),
            bytes: bytes as u32,
            sent_at: at,
        });
        port.stats.unacked_now = port.unacked.len() as u32;
        port.touch(at);
    }

    pub fn on_ack(
        &mut self,
        local_port: u16,
        before: u32,
        after: u32,
        peer_window: u32,
        at: Instant,
    ) {
        let port = self.port(local_port);
        port.stats.peer_window = peer_window;
        if before == after {
            return;
        }
        while let Some(front) = port.unacked.front().copied() {
            if !seq_reached(after, front.seq_end) {
                break;
            }
            port.unacked.pop_front();
            port.stats.bytes_acked += u64::from(front.bytes);
            port.stats
                .ack
                .record(micros(at.saturating_duration_since(front.sent_at)));
        }
        port.stats.unacked_now = port.unacked.len() as u32;
        port.touch(at);
    }

    pub fn on_write_wait(
        &mut self,
        local_port: u16,
        waited: Duration,
        usable_window: usize,
        in_flight: u32,
        peer_window: u32,
        at: Instant,
    ) {
        let usable = u32::try_from(usable_window).unwrap_or(u32::MAX);
        let port = self.port(local_port);
        port.stats.peer_window = peer_window;
        if usable == 0 {
            port.stats.blocked.record(micros(waited));
            port.stats.usable_at_block = usable;
            port.stats.in_flight_at_block = in_flight;
            port.stats.in_flight_total_at_block += u64::from(in_flight);
        } else {
            port.stats.waited_window_open.record(micros(waited));
        }
        port.touch(at);
        if usable == 0 {
            self.tick_summary(local_port, at);
        }
    }

    pub fn on_lock_wait(&mut self, local_port: u16, waited: Duration) {
        if waited.is_zero() {
            return;
        }
        let port = self.port(local_port);
        port.stats.lock_wait.record(micros(waited));
    }

    pub fn on_inbound_wait(
        &mut self,
        local_port: u16,
        waited: Duration,
        usable_window: usize,
        in_flight: u32,
        peer_window: u32,
        at: Instant,
    ) {
        if waited.is_zero() {
            return;
        }
        let usable = u32::try_from(usable_window).unwrap_or(u32::MAX);
        let port = self.port(local_port);
        if peer_window > 0 {
            port.stats.peer_window = peer_window;
        }
        if usable == 0 {
            port.stats.inbound_wait_shut.record(micros(waited));
            port.stats.usable_at_block = usable;
            port.stats.in_flight_at_block = in_flight;
        } else {
            port.stats.inbound_wait_open.record(micros(waited));
        }
        port.touch(at);
        if usable == 0 {
            self.tick_summary(local_port, at);
        }
    }

    fn tick_summary(&mut self, local_port: u16, at: Instant) {
        let due = {
            let port = self.port(local_port);
            port.waits_since_summary = port
                .waits_since_summary
                .saturating_add(1)
                .min(WAITS_PER_SUMMARY);
            let counted = port.waits_since_summary >= WAITS_PER_SUMMARY;
            let rested = port
                .last_summary
                .is_none_or(|last| at.saturating_duration_since(last) >= SUMMARY_MIN_INTERVAL);
            counted && rested
        };
        if due {
            let port = self.port(local_port);
            port.waits_since_summary = 0;
            port.last_summary = Some(at);
            self.emit(local_port, SummaryReason::Periodic);
        }
    }

    pub fn on_close(&mut self, local_port: u16) {
        if !self.ports.contains_key(&local_port) {
            return;
        }
        self.emit(local_port, SummaryReason::Closed);
        self.ports.remove(&local_port);
    }

    fn emit(&mut self, local_port: u16, reason: SummaryReason) {
        let Some(port) = self.ports.get(&local_port) else {
            return;
        };
        let body = port.stats.body(reason);
        match self.budget.take() {
            LineGrant::Granted => (self.sink)(&format!("{ROUNDTRIP_TAG} {body}")),
            LineGrant::Last => (self.sink)(&format!(
                "{ROUNDTRIP_TAG} {body} lines_left=0 note=budget-spent-no-more-lines"
            )),
            LineGrant::Exhausted => {}
        }
    }

    fn port(&mut self, local_port: u16) -> &mut PortMeter {
        self.ports
            .entry(local_port)
            .or_insert_with(|| PortMeter::new(local_port))
    }
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

// Modular comparison, as the device does it: a wrapped sequence is not two billion behind.
fn seq_reached(acknowledgement: u32, seq_end: u32) -> bool {
    (acknowledgement.wrapping_sub(seq_end) as i32) >= 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ramrod::Clock;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::sync::{Arc, Mutex};

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

    impl TestClock {
        fn new() -> Self {
            Self {
                now: Instant::now(),
            }
        }
    }

    fn recording() -> (RoundtripMeter, Arc<Mutex<Vec<String>>>, LineBudget) {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let budget = LineBudget::new(PROCESS_LINE_BUDGET);
        let sink_lines = Arc::clone(&lines);
        let meter = RoundtripMeter::with_sink(
            budget.clone(),
            Box::new(move |line: &str| sink_lines.lock().unwrap().push(line.to_string())),
        );
        (meter, lines, budget)
    }

    fn capture_stderr(action: impl FnOnce()) -> String {
        static STDERR_CAPTURE: std::sync::OnceLock<std::sync::Mutex<()>> =
            std::sync::OnceLock::new();
        let _capture_guard = STDERR_CAPTURE
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap();

        unsafe {
            let mut pipe_fds = [0; 2];
            assert_eq!(libc::pipe(pipe_fds.as_mut_ptr()), 0);
            let saved = libc::dup(libc::STDERR_FILENO);
            assert!(saved >= 0);
            assert_eq!(
                libc::dup2(pipe_fds[1], libc::STDERR_FILENO),
                libc::STDERR_FILENO
            );
            assert_eq!(libc::close(pipe_fds[1]), 0);

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action));

            std::io::stderr().flush().unwrap();
            assert_eq!(libc::dup2(saved, libc::STDERR_FILENO), libc::STDERR_FILENO);
            assert_eq!(libc::close(saved), 0);

            let mut reader = std::fs::File::from_raw_fd(pipe_fds[0]);
            let mut output = String::new();
            reader.read_to_string(&mut output).unwrap();

            if let Err(panic) = result {
                std::panic::resume_unwind(panic);
            }
            output
        }
    }

    const PORT: u16 = 49152;
    const MSS: usize = 32728;

    #[test]
    fn a_wait_with_the_window_open_is_not_counted_as_a_window_block() {
        let (mut meter, lines, _budget) = recording();
        let mut clock = TestClock::new();

        clock.sleep(Duration::from_micros(250));
        meter.on_write_wait(
            PORT,
            Duration::from_micros(250),
            65536,
            0,
            131_072,
            clock.now(),
        );
        let stats = meter.stats(PORT).unwrap();
        assert_eq!(stats.blocked.count, 0);
        assert_eq!(stats.waited_window_open.count, 1);
        assert_eq!(stats.waited_window_open.mean_us(), 250);
        assert_eq!(stats.in_flight_at_block, 0);

        clock.sleep(Duration::from_millis(119));
        meter.on_write_wait(
            PORT,
            Duration::from_millis(119),
            0,
            130_912,
            131_072,
            clock.now(),
        );
        let stats = meter.stats(PORT).unwrap();
        assert!(
            lines.lock().unwrap().is_empty(),
            "a wait with the window open must not drive the summaries"
        );
        assert_eq!(stats.blocked.count, 1);
        assert_eq!(stats.blocked.mean_us(), 119_000);
        assert_eq!(stats.blocked.max_us, 119_000);
        assert_eq!(
            stats.waited_window_open.count, 1,
            "unchanged by a real block"
        );
        assert_eq!(stats.usable_at_block, 0);
        assert_eq!(stats.in_flight_at_block, 130_912);
        assert_eq!(stats.in_flight_mean_at_block(), 130_912);
        assert_eq!(stats.peer_window, 131_072);
    }

    #[test]
    fn an_idle_reader_cannot_spend_the_line_budget_on_saying_it_was_idle() {
        let (mut meter, lines, _budget) = recording();
        let clock = TestClock::new();
        for _ in 0..(WAITS_PER_SUMMARY * 4) {
            meter.on_inbound_wait(
                PORT,
                Duration::from_millis(25),
                131_072,
                0,
                131_072,
                clock.now(),
            );
        }
        assert!(lines.lock().unwrap().is_empty());
        let stats = meter.stats(PORT).unwrap();
        assert_eq!(
            stats.inbound_wait_open.count,
            u64::from(WAITS_PER_SUMMARY) * 4
        );
        assert_eq!(stats.inbound_wait_shut.count, 0);
        meter.on_close(PORT);
        assert_eq!(lines.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_wait_for_the_link_itself_is_recorded_apart_from_every_other_wait() {
        let (mut meter, _lines, _budget) = recording();
        let clock = TestClock::new();
        meter.on_lock_wait(PORT, Duration::from_millis(4340));
        meter.on_lock_wait(PORT, Duration::from_millis(2040));
        meter.on_inbound_wait(
            PORT,
            Duration::from_millis(1),
            0,
            4096,
            131_072,
            clock.now(),
        );
        let stats = meter.stats(PORT).unwrap();
        assert_eq!(stats.lock_wait.count, 2);
        assert_eq!(stats.lock_wait.max_us, 4_340_000);
        assert_eq!(stats.lock_wait.mean_us(), 3_190_000);
        assert_eq!(stats.inbound_wait_shut.count, 1);
        assert_eq!(stats.blocked.count, 0, "the link is not the window");
        meter.on_lock_wait(PORT, Duration::ZERO);
        assert_eq!(meter.stats(PORT).unwrap().lock_wait.count, 2);
    }

    #[test]
    fn ack_latency_is_attributed_to_the_segment_the_acknowledgement_covered() {
        let (mut meter, _lines, _budget) = recording();
        let mut clock = TestClock::new();
        let base = 1000u32;

        meter.on_queue(PORT, MSS * 2);
        meter.on_segment_sent(PORT, base, MSS, Duration::from_micros(40), clock.now());
        clock.sleep(Duration::from_millis(10));
        let second_sent = clock.now();
        meter.on_segment_sent(
            PORT,
            base + MSS as u32,
            MSS,
            Duration::from_micros(60),
            second_sent,
        );
        assert_eq!(meter.stats(PORT).unwrap().unacked_now, 2);

        clock.sleep(Duration::from_millis(90));
        let first_ack = clock.now();
        meter.on_ack(PORT, base, base + MSS as u32, 131_072, first_ack);
        let stats = meter.stats(PORT).unwrap();
        assert_eq!(stats.ack.count, 1);
        assert_eq!(stats.ack.mean_us(), 100_000);
        assert_eq!(stats.bytes_acked, MSS as u64);
        assert_eq!(stats.unacked_now, 1);

        clock.sleep(Duration::from_millis(20));
        meter.on_ack(
            PORT,
            base + MSS as u32,
            base + 2 * MSS as u32,
            131_072,
            clock.now(),
        );
        let stats = meter.stats(PORT).unwrap();
        assert_eq!(stats.ack.count, 2);
        assert_eq!(
            stats.ack.total_us - 100_000,
            110_000,
            "the second sample is measured from the second segment"
        );
        assert_eq!(stats.ack.max_us, 110_000);
        assert_eq!(stats.bytes_acked, 2 * MSS as u64);
        assert_eq!(stats.unacked_now, 0);
        assert_eq!(stats.send.count, 2);
        assert_eq!(stats.send.max_us, 60);
    }

    #[test]
    fn one_acknowledgement_covering_several_segments_samples_each_of_them() {
        let (mut meter, _lines, _budget) = recording();
        let mut clock = TestClock::new();
        let base = 0u32;
        for index in 0..4u32 {
            meter.on_segment_sent(
                PORT,
                base + index * MSS as u32,
                MSS,
                Duration::ZERO,
                clock.now(),
            );
            clock.sleep(Duration::from_millis(1));
        }
        clock.sleep(Duration::from_millis(96));
        meter.on_ack(PORT, base, base + 4 * MSS as u32, 131_072, clock.now());
        let stats = meter.stats(PORT).unwrap();
        assert_eq!(stats.ack.count, 4);
        assert_eq!(stats.unacked_now, 0);
        assert_eq!(stats.ack.max_us, 100_000);
        assert_eq!(stats.ack.total_us, 100_000 + 99_000 + 98_000 + 97_000);
    }

    #[test]
    fn an_acknowledgement_that_moved_nothing_is_a_window_update_and_no_sample() {
        let (mut meter, _lines, _budget) = recording();
        let mut clock = TestClock::new();
        meter.on_segment_sent(PORT, 0, MSS, Duration::ZERO, clock.now());
        clock.sleep(Duration::from_millis(5));
        meter.on_ack(PORT, 0, 0, 262_144, clock.now());
        let stats = meter.stats(PORT).unwrap();
        assert_eq!(stats.ack.count, 0);
        assert_eq!(stats.unacked_now, 1);
        assert_eq!(stats.peer_window, 262_144);
    }

    #[test]
    fn attribution_survives_the_sequence_wrap() {
        let (mut meter, _lines, _budget) = recording();
        let mut clock = TestClock::new();
        let base = u32::MAX - 16;
        meter.on_segment_sent(PORT, base, 32, Duration::ZERO, clock.now());
        clock.sleep(Duration::from_millis(7));
        meter.on_ack(PORT, base, base.wrapping_add(32), 131_072, clock.now());
        let stats = meter.stats(PORT).unwrap();
        assert_eq!(stats.ack.count, 1);
        assert_eq!(stats.ack.mean_us(), 7_000);
    }

    #[test]
    fn the_wait_count_alone_cannot_spend_the_budget_on_the_opening_seconds() {
        let (mut meter, lines, _budget) = recording();
        let mut clock = TestClock::new();
        for _ in 0..(WAITS_PER_SUMMARY * 100) {
            meter.on_write_wait(
                PORT,
                Duration::from_millis(1),
                0,
                1024,
                131_072,
                clock.now(),
            );
        }
        assert_eq!(
            lines.lock().unwrap().len(),
            1,
            "the first line is due, and nothing after it is until the interval has passed"
        );

        clock.sleep(SUMMARY_MIN_INTERVAL);
        meter.on_write_wait(
            PORT,
            Duration::from_millis(1),
            0,
            1024,
            131_072,
            clock.now(),
        );
        assert_eq!(
            lines.lock().unwrap().len(),
            2,
            "one wait is enough once the interval has passed, because the count was already held at the threshold"
        );
    }

    #[test]
    fn a_full_ring_drops_the_oldest_sample_and_says_how_many_it_lost() {
        let (mut meter, _lines, _budget) = recording();
        let clock = TestClock::new();
        let total = UNACKED_RING + 3;
        for index in 0..total {
            meter.on_segment_sent(PORT, index as u32 * 8, 8, Duration::ZERO, clock.now());
        }
        let stats = meter.stats(PORT).unwrap();
        assert_eq!(stats.unacked_dropped, 3);
        assert_eq!(stats.unacked_now, UNACKED_RING as u32);
        assert_eq!(stats.segments_sent, total as u64);
    }

    #[test]
    fn a_summary_is_emitted_every_configured_number_of_waits() {
        let (mut meter, lines, _budget) = recording();
        let clock = TestClock::new();
        for _ in 0..(WAITS_PER_SUMMARY - 1) {
            meter.on_write_wait(
                PORT,
                Duration::from_millis(119),
                0,
                1024,
                131_072,
                clock.now(),
            );
        }
        assert!(lines.lock().unwrap().is_empty(), "not yet at the interval");
        meter.on_write_wait(
            PORT,
            Duration::from_millis(119),
            0,
            1024,
            131_072,
            clock.now(),
        );
        let emitted = lines.lock().unwrap().clone();
        assert_eq!(emitted.len(), 1);
        assert!(emitted[0].starts_with(ROUNDTRIP_TAG));
        assert!(emitted[0].contains("why=periodic"));
        assert!(emitted[0].contains(&format!("blocked_n={WAITS_PER_SUMMARY}")));
        assert!(emitted[0].contains("blocked_mean_us=119000"));
        assert!(emitted[0].contains("port=49152"));
    }

    #[test]
    fn closing_a_session_reports_once_even_when_it_never_blocked() {
        let (mut meter, lines, _budget) = recording();
        let clock = TestClock::new();
        meter.on_queue(PORT, 1024);
        meter.on_segment_sent(PORT, 0, 1024, Duration::from_micros(12), clock.now());
        meter.on_close(PORT);
        let emitted = lines.lock().unwrap().clone();
        assert_eq!(emitted.len(), 1);
        assert!(emitted[0].contains("why=closed"));
        assert!(emitted[0].contains("blocked_n=0"));
        assert!(emitted[0].contains("sent_bytes=1024"));
        meter.on_close(PORT);
        meter.on_close(PORT + 1);
        assert_eq!(lines.lock().unwrap().len(), 1);
    }

    #[test]
    fn the_line_budget_stops_output_and_says_so_on_the_last_line() {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink_lines = Arc::clone(&lines);
        let mut meter = RoundtripMeter::with_sink(
            LineBudget::new(2),
            Box::new(move |line: &str| sink_lines.lock().unwrap().push(line.to_string())),
        );
        for port in 0..8u16 {
            meter.on_queue(port, 16);
            meter.on_close(port);
        }
        let emitted = lines.lock().unwrap().clone();
        assert_eq!(emitted.len(), 2, "the budget is two lines and only two");
        assert!(!emitted[0].contains("budget-spent"));
        assert!(emitted[1].contains("note=budget-spent-no-more-lines"));
    }

    #[test]
    fn the_budget_is_shared_so_the_bound_holds_across_meters() {
        let budget = LineBudget::new(1);
        let lines = Arc::new(Mutex::new(Vec::new()));
        let mut first = {
            let lines = Arc::clone(&lines);
            RoundtripMeter::with_sink(
                budget.clone(),
                Box::new(move |line: &str| lines.lock().unwrap().push(line.to_string())),
            )
        };
        let mut second = {
            let lines = Arc::clone(&lines);
            RoundtripMeter::with_sink(
                budget.clone(),
                Box::new(move |line: &str| lines.lock().unwrap().push(line.to_string())),
            )
        };
        first.on_queue(PORT, 1);
        first.on_close(PORT);
        second.on_queue(PORT, 1);
        second.on_close(PORT);
        assert_eq!(lines.lock().unwrap().len(), 1);
        assert_eq!(budget.remaining(), 0);
    }

    #[test]
    fn the_explicit_stderr_sink_emits_lines_when_opted_in() {
        let output = capture_stderr(|| {
            let mut meter = RoundtripMeter::stderr();
            meter.on_queue(PORT, 16);
            meter.on_close(PORT);
        });
        assert!(output.contains(ROUNDTRIP_TAG), "{output:?}");
        assert!(output.contains("why=closed"), "{output:?}");
        assert!(output.contains("sent_bytes=0"), "{output:?}");
    }

    #[test]
    fn the_effective_rate_is_bytes_sent_over_the_span_they_took() {
        let (mut meter, _lines, _budget) = recording();
        let mut clock = TestClock::new();
        meter.on_segment_sent(PORT, 0, 32_728, Duration::ZERO, clock.now());
        clock.sleep(Duration::from_millis(500));
        meter.on_segment_sent(PORT, 32_728, 32_728, Duration::ZERO, clock.now());
        let stats = meter.stats(PORT).unwrap();
        assert_eq!(stats.span, Duration::from_millis(500));
        assert_eq!(stats.bytes_per_second(), 130_912);
    }
}
