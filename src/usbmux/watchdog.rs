use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::trace::{MuxTraceEvent, MuxTraceSink};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkWatchdogStats {
    pub packets_in: u64,
    pub packets_out: u64,
    pub deferred_writes: u64,
    pub idle_reads: u64,
    pub reads_refused: u64,
    pub queued: u64,
}

pub trait WatchdogMetrics: Send + Sync {
    fn snapshot(&self) -> LinkWatchdogStats;
}

pub const DEFAULT_WATCHDOG_SAMPLE: Duration = Duration::from_secs(1);

pub const DEFAULT_HELD_STALL_AFTER: Duration = Duration::from_secs(10);

// Must stay longer than DEFAULT_READ_POLL and DEFAULT_WRITE_POLL, which a healthy session waits out.
pub const DEFAULT_QUIET_AFTER: Duration = Duration::from_secs(45);

pub const DEFAULT_WATCHDOG_REPEAT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkPhase {
    #[default]
    Idle = 0,
    Inspect = 1,
    Negotiate = 2,
    OpenSyn = 3,
    OpenPoll = 4,
    OpenEnd = 5,
    Read = 6,
    Write = 7,
    WriteProbe = 8,
    Flush = 9,
    Close = 10,
    PumpFallback = 11,
}

impl LinkPhase {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Inspect => "inspect",
            Self::Negotiate => "negotiate",
            Self::OpenSyn => "open-syn",
            Self::OpenPoll => "open-poll",
            Self::OpenEnd => "open-end",
            Self::Read => "read",
            Self::Write => "write",
            Self::WriteProbe => "write-probe",
            Self::Flush => "flush",
            Self::Close => "close",
            Self::PumpFallback => "pump-fallback",
        }
    }

    fn from_code(code: u8) -> Self {
        match code {
            1 => Self::Inspect,
            2 => Self::Negotiate,
            3 => Self::OpenSyn,
            4 => Self::OpenPoll,
            5 => Self::OpenEnd,
            6 => Self::Read,
            7 => Self::Write,
            8 => Self::WriteProbe,
            9 => Self::Flush,
            10 => Self::Close,
            11 => Self::PumpFallback,
            _ => Self::Idle,
        }
    }
}

pub struct LinkActivity {
    began: Instant,
    // Stamp plus one, so zero means "nothing holds it"; one slot, so flag and stamp cannot be mixed.
    held_since: AtomicU64,
    phase: AtomicU8,
    port: AtomicU16,
    waiters: AtomicU32,
    acquisitions: AtomicU64,
    releases: AtomicU64,
}

impl Default for LinkActivity {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkActivity {
    #[must_use]
    pub fn new() -> Self {
        Self {
            began: Instant::now(),
            held_since: AtomicU64::new(0),
            phase: AtomicU8::new(LinkPhase::Idle as u8),
            port: AtomicU16::new(0),
            waiters: AtomicU32::new(0),
            acquisitions: AtomicU64::new(0),
            releases: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn begin_wait(&self) -> LinkHold<'_> {
        self.waiters.fetch_add(1, Ordering::Relaxed);
        LinkHold {
            activity: self,
            held: false,
        }
    }

    // `acquisitions` is read either side of the holder's fields; a count that moved means no hold.
    #[must_use]
    pub fn sample(&self) -> LinkSample {
        let before = self.acquisitions.load(Ordering::Acquire);
        let held_since = self.held_since.load(Ordering::Relaxed);
        let phase = LinkPhase::from_code(self.phase.load(Ordering::Relaxed));
        let port = self.port.load(Ordering::Relaxed);
        let waiters = self.waiters.load(Ordering::Relaxed);
        let after = self.acquisitions.load(Ordering::Acquire);
        let stable = before == after;
        let held = if stable && held_since != 0 {
            self.began
                .elapsed()
                .saturating_sub(Duration::from_nanos(held_since - 1))
        } else {
            Duration::ZERO
        };
        LinkSample {
            phase: if held.is_zero() {
                LinkPhase::Idle
            } else {
                phase
            },
            port: if held.is_zero() { 0 } else { port },
            held,
            waiters,
            acquisitions: after,
            releases: self.releases.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkSample {
    pub phase: LinkPhase,
    pub port: u16,
    pub held: Duration,
    pub waiters: u32,
    pub acquisitions: u64,
    pub releases: u64,
}

pub struct LinkHold<'a> {
    activity: &'a LinkActivity,
    held: bool,
}

impl LinkHold<'_> {
    // The count is stored last and with release ordering, so `sample` can tell one hold from two.
    pub fn acquired(&mut self, phase: LinkPhase, port: u16) {
        let activity = self.activity;
        activity.waiters.fetch_sub(1, Ordering::Relaxed);
        activity.phase.store(phase as u8, Ordering::Relaxed);
        activity.port.store(port, Ordering::Relaxed);
        let stamp = activity.began.elapsed().as_nanos() as u64;
        activity
            .held_since
            .store(stamp.wrapping_add(1), Ordering::Relaxed);
        activity.acquisitions.fetch_add(1, Ordering::Release);
        self.held = true;
    }
}

impl Drop for LinkHold<'_> {
    fn drop(&mut self) {
        if self.held {
            self.activity.held_since.store(0, Ordering::Relaxed);
            self.activity
                .phase
                .store(LinkPhase::Idle as u8, Ordering::Relaxed);
            self.activity.releases.fetch_add(1, Ordering::Release);
        } else {
            self.activity.waiters.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkWatchdogPolicy {
    pub sample: Duration,
    pub held_stall_after: Duration,
    pub quiet_after: Duration,
    pub repeat_every: Duration,
}

impl Default for LinkWatchdogPolicy {
    fn default() -> Self {
        Self {
            sample: DEFAULT_WATCHDOG_SAMPLE,
            held_stall_after: DEFAULT_HELD_STALL_AFTER,
            quiet_after: DEFAULT_QUIET_AFTER,
            repeat_every: DEFAULT_WATCHDOG_REPEAT,
        }
    }
}

pub struct LinkWatchdogHandle {
    stop: Arc<AtomicBool>,
    joiner: Option<std::thread::JoinHandle<()>>,
}

impl LinkWatchdogHandle {
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(joiner) = self.joiner.take() {
            let _ = joiner.join();
        }
    }
}

impl Drop for LinkWatchdogHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

#[must_use]
pub fn spawn_link_watchdog(
    activity: Arc<LinkActivity>,
    metrics: Arc<dyn WatchdogMetrics>,
    trace: Arc<dyn MuxTraceSink>,
    policy: LinkWatchdogPolicy,
) -> LinkWatchdogHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let joiner = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            run_watchdog(&activity, metrics.as_ref(), trace.as_ref(), policy, &stop)
        })
    };
    LinkWatchdogHandle {
        stop,
        joiner: Some(joiner),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Progress {
    acquisitions: u64,
    packets_in: u64,
    packets_out: u64,
}

fn run_watchdog(
    activity: &LinkActivity,
    metrics: &dyn WatchdogMetrics,
    trace: &dyn MuxTraceSink,
    policy: LinkWatchdogPolicy,
    stop: &AtomicBool,
) {
    let sample_every = policy.sample.max(Duration::from_millis(10));
    let mut last = progress(activity, metrics);
    let mut moved_at = Instant::now();
    let mut stalled_since: Option<Instant> = None;
    let mut reported_at = Instant::now();

    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(sample_every);
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let now = Instant::now();
        let look = activity.sample();
        let current = progress(activity, metrics);
        if current != last {
            last = current;
            moved_at = now;
        }
        let since_acquisition = now.saturating_duration_since(moved_at);
        let stalled = look.held >= policy.held_stall_after
            || (look.waiters > 0 && since_acquisition >= policy.held_stall_after)
            || since_acquisition >= policy.quiet_after;

        match (stalled, stalled_since) {
            (true, None) => {
                stalled_since = Some(now);
                reported_at = now;
                trace.event(stall_event(
                    look,
                    metrics,
                    since_acquisition,
                    Duration::ZERO,
                ));
            }
            (true, Some(began)) => {
                if now.saturating_duration_since(reported_at) >= policy.repeat_every {
                    reported_at = now;
                    trace.event(stall_event(
                        look,
                        metrics,
                        since_acquisition,
                        now.saturating_duration_since(began),
                    ));
                }
            }
            (false, Some(began)) => {
                stalled_since = None;
                let stats = metrics.snapshot();
                trace.event(MuxTraceEvent::LinkResumed {
                    stalled: now.saturating_duration_since(began),
                    acquisitions: look.acquisitions,
                    packets_in: stats.packets_in,
                    packets_out: stats.packets_out,
                });
            }
            (false, None) => {}
        }
    }
}

fn progress(activity: &LinkActivity, metrics: &dyn WatchdogMetrics) -> Progress {
    let stats = metrics.snapshot();
    Progress {
        acquisitions: activity.acquisitions.load(Ordering::Acquire),
        packets_in: stats.packets_in,
        packets_out: stats.packets_out,
    }
}

fn stall_event(
    look: LinkSample,
    metrics: &dyn WatchdogMetrics,
    since_acquisition: Duration,
    stalled: Duration,
) -> MuxTraceEvent {
    let stats = metrics.snapshot();
    MuxTraceEvent::LinkStalled {
        phase: look.phase,
        port: look.port,
        held: look.held,
        waiters: look.waiters,
        acquisitions: look.acquisitions,
        since_acquisition,
        stalled,
        packets_in: stats.packets_in,
        packets_out: stats.packets_out,
        queued: stats.queued,
        deferred: stats.deferred_writes,
        idle_reads: stats.idle_reads,
        refused: stats.reads_refused,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_untaken_link_reports_no_hold_and_no_waiters() {
        let activity = LinkActivity::new();
        let look = activity.sample();
        assert_eq!(look.phase, LinkPhase::Idle);
        assert_eq!(look.held, Duration::ZERO);
        assert_eq!(look.waiters, 0);
        assert_eq!(look.acquisitions, 0);
    }

    #[test]
    fn a_thread_waiting_for_the_link_is_counted_before_it_gets_it() {
        let activity = LinkActivity::new();
        let waiting = activity.begin_wait();
        assert_eq!(activity.sample().waiters, 1);
        drop(waiting);
        assert_eq!(activity.sample().waiters, 0);
    }

    #[test]
    fn a_hold_is_visible_with_its_phase_and_port_while_it_lasts() {
        let activity = LinkActivity::new();
        {
            let mut hold = activity.begin_wait();
            hold.acquired(LinkPhase::OpenPoll, 49157);
            let look = activity.sample();
            assert_eq!(look.phase, LinkPhase::OpenPoll);
            assert_eq!(look.port, 49157);
            assert_eq!(look.waiters, 0);
            assert_eq!(look.acquisitions, 1);
        }
        let look = activity.sample();
        assert_eq!(look.phase, LinkPhase::Idle);
        assert_eq!(look.held, Duration::ZERO);
        assert_eq!(look.releases, 1);
    }

    #[test]
    fn a_panic_under_the_link_still_ends_the_hold() {
        let activity = Arc::new(LinkActivity::new());
        let inner = Arc::clone(&activity);
        let _ = std::thread::spawn(move || {
            let mut hold = inner.begin_wait();
            hold.acquired(LinkPhase::Write, 49153);
            panic!("a session panicked holding the link");
        })
        .join();
        let look = activity.sample();
        assert_eq!(look.phase, LinkPhase::Idle);
        assert_eq!(look.held, Duration::ZERO);
        assert_eq!(look.waiters, 0);
        assert_eq!(look.acquisitions, 1);
        assert_eq!(look.releases, 1);
    }

    #[test]
    fn every_phase_code_survives_the_round_trip_through_the_atomic() {
        for phase in [
            LinkPhase::Idle,
            LinkPhase::Inspect,
            LinkPhase::Negotiate,
            LinkPhase::OpenSyn,
            LinkPhase::OpenPoll,
            LinkPhase::OpenEnd,
            LinkPhase::Read,
            LinkPhase::Write,
            LinkPhase::WriteProbe,
            LinkPhase::Flush,
            LinkPhase::Close,
            LinkPhase::PumpFallback,
        ] {
            assert_eq!(LinkPhase::from_code(phase as u8), phase);
            assert!(!phase.label().is_empty());
        }
    }

    #[test]
    fn the_quiet_bound_is_past_both_polls_a_healthy_session_waits_out() {
        assert!(DEFAULT_QUIET_AFTER > super::super::stream::DEFAULT_READ_POLL);
        assert!(DEFAULT_QUIET_AFTER > super::super::stream::DEFAULT_WRITE_POLL);
    }
}
