use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::ramrod::dial::{DialCancellation, GuestDialer, ShutdownWrite};

use super::frame::{MuxVersion, VersionRequest};
use super::link::{BulkTransport, InboundSignal, MuxError, MuxLink, SendState};
use super::packet_trace::{Disposition, Stage};
use super::session::SessionState;
use super::trace::MuxTraceEvent;
use super::watchdog::{LinkActivity, LinkPhase};

pub const HOST_TEARDOWN_MARKER: &str = "host-initiated-teardown";

pub const DEVICE_GONE_MARKER: &str = "device-left-the-bus";

pub const RUN_STOPPED_MARKER: &str = "restore-run-stopped";

pub const TRANSFER_CANCELLED_MARKER: &str = "restore-transfer-cancelled";

pub const CONNECTION_CANCELLED_MARKER: &str = "mux-connection-cancelled";

#[derive(Debug)]
struct DeliveryDrainError {
    port: u16,
    outstanding: Option<SendState>,
    cause: io::Error,
}

impl std::fmt::Display for DeliveryDrainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "mux port {} delivery drain failed: {}; ",
            self.port, self.cause
        )?;
        match self.outstanding {
            Some(state) => write!(
                f,
                "{} byte(s) queued and {} byte(s) sent but unacknowledged",
                state.pending,
                state.snd_nxt.wrapping_sub(state.snd_una)
            ),
            None => f.write_str(
                "outstanding byte counts are unavailable because the mux session is unavailable",
            ),
        }
    }
}

impl std::error::Error for DeliveryDrainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
            .get_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}

fn delivery_drain_error(port: u16, outstanding: Option<SendState>, cause: io::Error) -> io::Error {
    io::Error::new(
        cause.kind(),
        DeliveryDrainError {
            port,
            outstanding,
            cause,
        },
    )
}

#[derive(Debug)]
struct CancelledMuxOperation {
    reason: DialCancellation,
    port: u16,
    operation: &'static str,
    waited: Duration,
}

impl std::fmt::Display for CancelledMuxOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.reason {
            DialCancellation::OperatorStopped => write!(
                f,
                "{RUN_STOPPED_MARKER}: the run was stopped while mux port {} was {}, {:.3}s into the wait. Nothing on the wire ended this and nothing about the guest is being reported.",
                self.port,
                self.operation,
                self.waited.as_secs_f64()
            ),
            DialCancellation::TransferFailed => write!(
                f,
                "{TRANSFER_CANCELLED_MARKER}: a restore transfer failed while mux port {} was {}, {:.3}s into the wait; this operation was cancelled and the original transfer failure remains the session error",
                self.port,
                self.operation,
                self.waited.as_secs_f64()
            ),
        }
    }
}

impl std::error::Error for CancelledMuxOperation {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.reason)
    }
}

fn cancellation_error(
    stop: Option<&Arc<AtomicBool>>,
    failure: Option<&Arc<AtomicBool>>,
    port: u16,
    operation: &'static str,
    waited: Duration,
) -> Option<io::Error> {
    let reason = if stop.is_some_and(|flag| flag.load(Ordering::Acquire)) {
        DialCancellation::OperatorStopped
    } else if failure.is_some_and(|flag| flag.load(Ordering::Acquire)) {
        DialCancellation::TransferFailed
    } else {
        return None;
    };
    Some(io::Error::new(
        io::ErrorKind::ConnectionAborted,
        CancelledMuxOperation {
            reason,
            port,
            operation,
            waited,
        },
    ))
}

#[must_use]
pub fn is_host_initiated_teardown(text: &str) -> bool {
    text.contains(HOST_TEARDOWN_MARKER)
}

#[must_use]
pub fn is_device_gone(text: &str) -> bool {
    text.contains(DEVICE_GONE_MARKER)
}

#[must_use]
pub fn is_run_stopped(text: &str) -> bool {
    text.contains(RUN_STOPPED_MARKER)
}

pub const DEFAULT_READ_POLL: Duration = Duration::from_secs(30);

pub const DEFAULT_LINK_SLICE: Duration = Duration::from_millis(25);

pub const REFERENCE_ASR_READ_TIMEOUT: Duration = Duration::from_secs(5);

pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(120);

pub const DEFAULT_WRITE_POLL: Duration = Duration::from_secs(30);

pub const DEFAULT_DELIVERY_PROBE_POLL: Duration = Duration::from_secs(2);

#[derive(Default)]
struct DeliveryProbeTimer {
    send_epoch: Option<u64>,
    due: Option<Instant>,
}

impl DeliveryProbeTimer {
    fn observe(&mut self, state: SendState, now: Instant) -> bool {
        let flight_changed = self.send_epoch != Some(state.send_epoch);
        self.send_epoch = Some(state.send_epoch);
        if state.snd_una == state.snd_nxt {
            self.due = None;
            return false;
        }
        if self.due.is_none() || flight_changed {
            self.due = Some(now + DEFAULT_DELIVERY_PROBE_POLL);
            return false;
        }
        if self.due.is_some_and(|due| now >= due) {
            self.due = Some(now + DEFAULT_DELIVERY_PROBE_POLL);
            return true;
        }
        false
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WriteExpiry {
    #[default]
    Retry,
    Fail,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MuxWritePolicy {
    pub poll: Duration,
    pub on_expiry: WriteExpiry,
}

impl Default for MuxWritePolicy {
    fn default() -> Self {
        Self {
            poll: DEFAULT_WRITE_POLL,
            on_expiry: WriteExpiry::Retry,
        }
    }
}

impl MuxWritePolicy {
    #[must_use]
    pub fn retrying(poll: Duration) -> Self {
        Self {
            poll: poll.max(Duration::from_millis(1)),
            on_expiry: WriteExpiry::Retry,
        }
    }

    #[must_use]
    pub fn failing_after(bound: Duration) -> Self {
        Self {
            poll: bound.max(Duration::from_millis(1)),
            on_expiry: WriteExpiry::Fail,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReadExpiry {
    #[default]
    Retry,
    Fail,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MuxReadPolicy {
    pub poll: Duration,
    pub slice: Duration,
    pub on_expiry: ReadExpiry,
}

impl Default for MuxReadPolicy {
    fn default() -> Self {
        Self {
            poll: DEFAULT_READ_POLL,
            slice: DEFAULT_LINK_SLICE,
            on_expiry: ReadExpiry::Retry,
        }
    }
}

impl MuxReadPolicy {
    #[must_use]
    pub fn retrying(poll: Duration) -> Self {
        Self::default().with_poll(poll)
    }

    #[must_use]
    pub fn failing_after(bound: Duration) -> Self {
        Self {
            poll: bound.max(Duration::from_millis(1)),
            slice: DEFAULT_LINK_SLICE,
            on_expiry: ReadExpiry::Fail,
        }
    }

    #[must_use]
    pub fn with_poll(mut self, poll: Duration) -> Self {
        self.poll = poll.max(Duration::from_millis(1));
        self
    }

    #[must_use]
    pub fn with_slice(mut self, slice: Duration) -> Self {
        self.slice = slice.max(Duration::from_millis(1));
        self
    }

    #[must_use]
    pub fn with_expiry(mut self, on_expiry: ReadExpiry) -> Self {
        self.on_expiry = on_expiry;
        self
    }

    fn turn(&self) -> Duration {
        self.slice.min(self.poll).max(Duration::from_millis(1))
    }
}

// No thread may wait for the transport while holding the link: one mutex covers every session.
pub struct SharedLink<T> {
    inner: Arc<Mutex<MuxLink<T>>>,
    signal: Option<Arc<dyn InboundSignal>>,
    activity: Arc<LinkActivity>,
}

impl<T> Clone for SharedLink<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            signal: self.signal.clone(),
            activity: Arc::clone(&self.activity),
        }
    }
}

impl<T: BulkTransport> SharedLink<T> {
    #[must_use]
    pub fn new(link: MuxLink<T>) -> Self {
        let signal = link.inbound_signal();
        Self {
            inner: Arc::new(Mutex::new(link)),
            signal,
            activity: Arc::new(LinkActivity::new()),
        }
    }

    #[must_use]
    pub fn activity(&self) -> Arc<LinkActivity> {
        Arc::clone(&self.activity)
    }

    #[must_use]
    pub fn can_wait_off_link(&self) -> bool {
        self.signal.is_some()
    }

    #[must_use]
    pub fn roundtrip(&self, local_port: u16) -> Option<super::roundtrip::PortStats> {
        self.with(LinkPhase::Inspect, local_port, |link| {
            link.roundtrip(local_port)
        })
    }

    pub fn negotiate(
        &self,
        request: VersionRequest,
        timeout: Duration,
    ) -> Result<MuxVersion, MuxError> {
        self.with(LinkPhase::Negotiate, 0, |link| {
            link.negotiate(request, timeout)
        })
    }

    #[must_use]
    pub fn version(&self) -> Option<MuxVersion> {
        self.with(LinkPhase::Inspect, 0, |link| link.version())
    }

    pub fn open(&self, guest_port: u16, timeout: Duration) -> Result<MuxStream<T>, MuxError> {
        self.open_cancellable(guest_port, timeout, None, None)
    }

    fn open_cancellable(
        &self,
        guest_port: u16,
        timeout: Duration,
        stop: Option<&Arc<AtomicBool>>,
        failure: Option<&Arc<AtomicBool>>,
    ) -> Result<MuxStream<T>, MuxError> {
        let began = Instant::now();
        if let Some(error) =
            cancellation_error(stop, failure, guest_port, "dialling", began.elapsed())
        {
            return Err(MuxError::Io(error));
        }
        let local_port = self.with(LinkPhase::OpenSyn, 0, |link| link.begin_open(guest_port))?;
        self.complete_open_cancellable(local_port, guest_port, timeout, began, stop, failure)
    }

    fn complete_open_cancellable(
        &self,
        local_port: u16,
        guest_port: u16,
        timeout: Duration,
        began: Instant,
        stop: Option<&Arc<AtomicBool>>,
        failure: Option<&Arc<AtomicBool>>,
    ) -> Result<MuxStream<T>, MuxError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(error) =
                cancellation_error(stop, failure, guest_port, "dialling", began.elapsed())
            {
                self.with(LinkPhase::OpenEnd, local_port, |link| {
                    let _ = link.close(local_port);
                    link.forget_session(local_port);
                });
                return Err(MuxError::Io(error));
            }
            let (drained, state, generation) = self.with(LinkPhase::OpenPoll, local_port, |link| {
                let drained = link.drain_inbound();
                let generation = link.inbound_generation();
                (drained, link.session_state(local_port), generation)
            });
            if let Err(error) = drained {
                self.with(LinkPhase::OpenEnd, local_port, |link| {
                    link.forget_session(local_port);
                });
                return Err(error);
            }
            match state {
                Some(SessionState::Established) => {
                    self.with(LinkPhase::OpenEnd, local_port, |link| {
                        if let Some(error) = cancellation_error(
                            stop,
                            failure,
                            guest_port,
                            "dialling",
                            began.elapsed(),
                        ) {
                            let _ = link.close(local_port);
                            link.forget_session(local_port);
                            return Err(MuxError::Io(error));
                        }
                        link.finish_open(local_port, guest_port)
                    })?;
                    return Ok(MuxStream {
                        link: self.clone(),
                        local_port,
                        read_policy: MuxReadPolicy::default(),
                        write_policy: MuxWritePolicy::default(),
                        cancel: None,
                        transfer_cancel: None,
                        closed: false,
                    });
                }
                Some(SessionState::Closed) | None => {
                    self.with(LinkPhase::OpenEnd, local_port, |link| {
                        link.forget_session(local_port);
                    });
                    return Err(MuxError::Closed { local_port });
                }
                Some(SessionState::SynSent) => {}
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.with(LinkPhase::OpenEnd, local_port, |link| {
                    link.abandon_open(local_port, timeout);
                });
                return Err(MuxError::HandshakeTimedOut {
                    local_port,
                    waited: timeout,
                });
            }
            self.wait_for_inbound(generation, remaining.min(DEFAULT_LINK_SLICE))?;
        }
    }

    fn with<R>(&self, phase: LinkPhase, port: u16, body: impl FnOnce(&mut MuxLink<T>) -> R) -> R {
        let mut hold = self.activity.begin_wait();
        let mut guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        hold.acquired(phase, port);
        body(&mut guard)
    }

    fn with_timed<R>(
        &self,
        phase: LinkPhase,
        port: u16,
        body: impl FnOnce(&mut MuxLink<T>, Duration) -> R,
    ) -> R {
        let began = Instant::now();
        self.with(phase, port, |link| {
            let waited = began.elapsed();
            body(link, waited)
        })
    }

    pub fn wait_for_inbound(
        &self,
        generation: u64,
        timeout: Duration,
    ) -> Result<Duration, MuxError> {
        let began = Instant::now();
        match &self.signal {
            Some(signal) => signal.wait_for_inbound(generation, timeout),
            None => {
                self.with(LinkPhase::PumpFallback, 0, |link| link.pump(timeout))?;
            }
        }
        Ok(began.elapsed())
    }
}

pub struct MuxStream<T: BulkTransport> {
    link: SharedLink<T>,
    local_port: u16,
    read_policy: MuxReadPolicy,
    write_policy: MuxWritePolicy,
    cancel: Option<Arc<AtomicBool>>,
    transfer_cancel: Option<Arc<AtomicBool>>,
    closed: bool,
}

impl<T: BulkTransport> MuxStream<T> {
    #[must_use]
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    #[must_use]
    pub fn with_read_policy(mut self, policy: MuxReadPolicy) -> Self {
        self.read_policy = policy;
        self
    }

    #[must_use]
    pub fn read_policy(&self) -> MuxReadPolicy {
        self.read_policy
    }

    #[must_use]
    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_policy = self.read_policy.with_poll(timeout);
        self
    }

    #[must_use]
    pub fn with_write_timeout(mut self, timeout: Duration) -> Self {
        self.write_policy = MuxWritePolicy::failing_after(timeout);
        self
    }

    #[must_use]
    pub fn with_write_policy(mut self, policy: MuxWritePolicy) -> Self {
        self.write_policy = policy;
        self
    }

    #[must_use]
    pub fn with_cancel(mut self, cancel: Arc<AtomicBool>) -> Self {
        self.cancel = Some(cancel);
        self
    }

    #[must_use]
    pub fn with_transfer_cancel(mut self, cancel: Arc<AtomicBool>) -> Self {
        self.transfer_cancel = Some(cancel);
        self
    }

    pub fn split(&mut self) -> (MuxReadHalf<'_, T>, MuxWriteHalf<'_, T>) {
        let stream = &*self;
        (
            MuxReadHalf {
                stream,
                connection_cancel: Vec::new(),
            },
            MuxWriteHalf {
                stream,
                connection_cancel: Vec::new(),
            },
        )
    }

    fn operation_cancellation(
        &self,
        connection_cancel: &[Arc<AtomicBool>],
        operation: &'static str,
        waited: Duration,
    ) -> Option<io::Error> {
        cancellation_error(self.cancel.as_ref(), self.transfer_cancel.as_ref(), self.local_port, operation, waited)
            .or_else(|| {
                if connection_cancel.iter().any(|cancel| cancel.load(Ordering::Acquire)) {
                    Some(io::Error::new(io::ErrorKind::ConnectionAborted, format!(
                        "{CONNECTION_CANCELLED_MARKER}: mux port {} was cancelled while {operation}, {:.3}s into the wait",
                        self.local_port, waited.as_secs_f64())))
                } else {
                    None
                }
            })
    }

    pub fn close(&mut self) -> Result<(), MuxError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let port = self.local_port;
        self.link
            .with(LinkPhase::Close, port, |link| link.close(port))
    }

    #[must_use]
    pub fn is_open(&self) -> bool {
        let port = self.local_port;
        matches!(
            self.link
                .with(LinkPhase::Inspect, port, |link| link.session_state(port)),
            Some(SessionState::Established | SessionState::SynSent)
        )
    }
}

impl<T: BulkTransport> MuxStream<T> {
    fn read_shared(
        &self,
        out: &mut [u8],
        connection_cancel: &[Arc<AtomicBool>],
    ) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("mux port {} is closed", self.local_port),
            ));
        }
        let port = self.local_port;
        let policy = self.read_policy;
        let turn = policy.turn();
        let began = Instant::now();
        let mut poll_ends = began + policy.poll;
        let mut waited_off_link = Duration::ZERO;
        loop {
            let at = Instant::now();
            let slice = turn
                .min(poll_ends.saturating_duration_since(at))
                .max(Duration::from_micros(1));
            let (taken, generation, eof) = self
                .link
                .with_timed(LinkPhase::Read, port, |link, lock_wait| {
                    link.record_wait(port, lock_wait, waited_off_link);
                    let generation = link.inbound_generation();
                    link.drain_inbound()?;
                    let taken = link.take_received(port, out)?;
                    let eof = if taken == 0 {
                        link.received_eof(port)?
                    } else {
                        false
                    };
                    Ok::<_, MuxError>((taken, generation, eof))
                })
                .map_err(io::Error::from)?;
            if taken > 0 {
                return Ok(taken);
            }
            if eof {
                return Ok(0);
            }
            if let Some(error) =
                self.operation_cancellation(connection_cancel, "waiting", began.elapsed())
            {
                return Err(error);
            }
            if self
                .link
                .with(LinkPhase::Inspect, port, |link| link.device_present())
                == Some(false)
            {
                let liveness = self.link.with(LinkPhase::Inspect, port, |link| {
                    link.trace(MuxTraceEvent::DeviceGone { local_port: port });
                    link.liveness()
                });
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    format!(
                        "{DEVICE_GONE_MARKER}: the device left the bus while mux port {port} was waiting, {:.3}s into the wait. \
                         Its controller had been configured and is not any more, which discards the address, the configuration and every armed endpoint, so no session over this link can continue. \
                         This is the removal a restore host learns from usbmux, not a guest that had nothing to say: {}.",
                        began.elapsed().as_secs_f64(),
                        liveness.describe()
                    ),
                ));
            }
            waited_off_link = self
                .link
                .wait_for_inbound(generation, slice)
                .map_err(io::Error::from)?;
            let now = Instant::now();
            if now < poll_ends {
                continue;
            }
            match policy.on_expiry {
                ReadExpiry::Retry => {
                    self.link.with(LinkPhase::Inspect, port, |link| {
                        link.trace(MuxTraceEvent::ReadPollExpired {
                            local_port: port,
                            waited: policy.poll,
                            elapsed: began.elapsed(),
                        });
                    });
                    poll_ends = now + policy.poll;
                }
                ReadExpiry::Fail => {
                    let liveness = self
                        .link
                        .with(LinkPhase::Inspect, port, |link| link.liveness());
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "{HOST_TEARDOWN_MARKER}: the host stopped waiting on mux port {port} after {:.3}s, on the bounded receive this channel is given and not on anything the guest reported. \
                             The device is still on the bus and the transport did not fail: {}. \
                             This is the ASR-channel rule: a receive that expires is a failure rather than a retry, and it is the only place the host ends a session on its own clock. \
                             Anything the guest prints after this point follows from the host end going away and is not evidence about the stage it was in.",
                            began.elapsed().as_secs_f64(),
                            liveness.describe()
                        ),
                    ));
                }
            }
        }
    }

    fn write_shared(
        &self,
        data: &[u8],
        connection_cancel: &[Arc<AtomicBool>],
    ) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("mux port {} is closed", self.local_port),
            ));
        }
        let port = self.local_port;
        let policy = self.write_policy;
        let began = Instant::now();
        let mut deadline = began + policy.poll;
        let mut waited_off_link = Duration::ZERO;
        let mut queued = false;
        let mut delivery_probe = DeliveryProbeTimer::default();
        loop {
            if let Some(error) =
                self.operation_cancellation(connection_cancel, "writing", began.elapsed())
            {
                return Err(error);
            }
            if self
                .link
                .with(LinkPhase::Inspect, port, |link| link.device_present())
                == Some(false)
            {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    format!(
                        "{DEVICE_GONE_MARKER}: the device left the bus, so mux port {port} has nothing to write to"
                    ),
                ));
            }
            let (pending, send_state, generation) = self
                .link
                .with_timed(LinkPhase::Write, port, |link, lock_wait| {
                    link.record_wait(port, lock_wait, waited_off_link);
                    let generation = link.inbound_generation();
                    link.route_available()?;
                    let pending = if queued {
                        link.pending_write(port)?
                    } else {
                        link.queue_write(port, data)?
                    };
                    let send_state = link
                        .send_state(port)
                        .ok_or(MuxError::NoSession { local_port: port })?;
                    Ok::<_, MuxError>((pending, send_state, generation))
                })
                .map_err(io::Error::from)?;
            queued = true;
            let delivery_probe_due = delivery_probe.observe(send_state, Instant::now());
            if pending == 0 {
                return Ok(data.len());
            }
            if delivery_probe_due {
                self.link
                    .with(LinkPhase::WriteProbe, port, |link| {
                        link.trace_delivery_probe(
                            Stage::WriteProbeStart,
                            port,
                            send_state,
                            Disposition::ProbeEntered,
                        );
                        let mut disposition = Disposition::ProbeError;
                        let result: Result<bool, MuxError> = (|| {
                            link.route_available()?;
                            let current = link
                                .send_state(port)
                                .ok_or(MuxError::NoSession { local_port: port })?;
                            if current.send_epoch == send_state.send_epoch {
                                let sent = link.retransmit_unacknowledged(port)?;
                                disposition = if sent {
                                    Disposition::ProbeSent
                                } else {
                                    Disposition::ProbeDeferred
                                };
                                Ok(sent)
                            } else {
                                delivery_probe.observe(current, Instant::now());
                                disposition = Disposition::ProbeEpochMoved;
                                Ok(false)
                            }
                        })();
                        link.trace_delivery_probe(
                            Stage::WriteProbeReturn,
                            port,
                            send_state,
                            disposition,
                        );
                        result
                    })
                    .map_err(io::Error::from)?;
            }
            let mut remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                match policy.on_expiry {
                    WriteExpiry::Fail => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "the device's window on mux port {port} stayed shut for {:?} with {pending} byte(s) still queued",
                                policy.poll
                            ),
                        ));
                    }
                    WriteExpiry::Retry => {
                        let elapsed = began.elapsed();
                        self.link
                            .with(LinkPhase::WriteProbe, port, |link| {
                                let probed = link.probe_window(port)?;
                                if let Some(state) = link.send_state(port) {
                                    link.trace(MuxTraceEvent::WriteWindowShut {
                                        local_port: port,
                                        snd_una: state.snd_una,
                                        snd_nxt: state.snd_nxt,
                                        snd_wnd_edge: state.snd_wnd_edge,
                                        peer_window: state.peer_window,
                                        pending: state.pending,
                                        segments_in: state.segments_in,
                                        waited: policy.poll,
                                        elapsed,
                                        probed,
                                    });
                                }
                                Ok::<_, MuxError>(())
                            })
                            .map_err(io::Error::from)?;
                        deadline = Instant::now() + policy.poll;
                        remaining = policy.poll;
                    }
                }
            }
            waited_off_link = self
                .link
                .wait_for_inbound(generation, remaining.min(DEFAULT_LINK_SLICE))
                .map_err(io::Error::from)?;
        }
    }

    fn flush_shared(&self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        let port = self.local_port;
        self.link
            .with(LinkPhase::Flush, port, |link| link.flush(port))
            .map_err(io::Error::from)
    }

    fn drain_delivery_shared(&self, connection_cancel: &[Arc<AtomicBool>]) -> io::Result<()> {
        let port = self.local_port;
        let began = Instant::now();
        let mut waited_off_link = Duration::ZERO;
        let mut probe_at = began + self.write_policy.poll;
        let mut delivery_probe = DeliveryProbeTimer::default();
        let mut outstanding = self
            .link
            .with(LinkPhase::Inspect, port, |link| link.send_state(port));
        if self.closed {
            return Err(delivery_drain_error(
                port,
                outstanding,
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "the owning mux stream is closed",
                ),
            ));
        }
        loop {
            if let Some(error) =
                self.operation_cancellation(connection_cancel, "draining delivery", began.elapsed())
            {
                outstanding = self
                    .link
                    .with(LinkPhase::Inspect, port, |link| link.send_state(port))
                    .or(outstanding);
                return Err(delivery_drain_error(port, outstanding, error));
            }
            let (routed, state, send_state, present, generation) =
                self.link
                    .with_timed(LinkPhase::Flush, port, |link, lock_wait| {
                        link.record_wait(port, lock_wait, waited_off_link);
                        let generation = link.inbound_generation();
                        let routed = if link.device_present() == Some(false) {
                            Ok(())
                        } else {
                            link.route_available().and_then(|_| link.flush(port))
                        };
                        let present = link.device_present();
                        if present == Some(false) {
                            link.trace(MuxTraceEvent::DeviceGone { local_port: port });
                        }
                        (
                            routed,
                            link.session_state(port),
                            link.send_state(port),
                            present,
                            generation,
                        )
                    });
            outstanding = send_state.or(outstanding);
            if present == Some(false) {
                return Err(delivery_drain_error(
                    port,
                    outstanding,
                    io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        format!(
                            "{DEVICE_GONE_MARKER}: the device left the bus while mux port {port} was draining delivery"
                        ),
                    ),
                ));
            }
            if state != Some(SessionState::Established) {
                return Err(delivery_drain_error(
                    port,
                    outstanding,
                    io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "the mux peer closed or reset the session while draining delivery",
                    ),
                ));
            }
            if let Err(error) = routed {
                return Err(delivery_drain_error(
                    port,
                    outstanding,
                    io::Error::from(error),
                ));
            }
            let Some(send_state) = send_state else {
                return Err(delivery_drain_error(
                    port,
                    outstanding,
                    io::Error::new(
                        io::ErrorKind::NotConnected,
                        "the mux send state is unavailable while draining delivery",
                    ),
                ));
            };
            let delivery_probe_due = delivery_probe.observe(send_state, Instant::now());
            if send_state.pending == 0 && send_state.snd_una == send_state.snd_nxt {
                return Ok(());
            }
            if delivery_probe_due {
                self.link
                    .with(LinkPhase::WriteProbe, port, |link| {
                        link.trace_delivery_probe(
                            Stage::DrainProbeStart,
                            port,
                            send_state,
                            Disposition::ProbeEntered,
                        );
                        let mut disposition = Disposition::ProbeError;
                        let result: Result<bool, MuxError> = (|| {
                            link.route_available()?;
                            let current = link
                                .send_state(port)
                                .ok_or(MuxError::NoSession { local_port: port })?;
                            if current.send_epoch == send_state.send_epoch {
                                let sent = link.retransmit_unacknowledged(port)?;
                                disposition = if sent {
                                    Disposition::ProbeSent
                                } else {
                                    Disposition::ProbeDeferred
                                };
                                Ok(sent)
                            } else {
                                delivery_probe.observe(current, Instant::now());
                                disposition = Disposition::ProbeEpochMoved;
                                Ok(false)
                            }
                        })();
                        link.trace_delivery_probe(
                            Stage::DrainProbeReturn,
                            port,
                            send_state,
                            disposition,
                        );
                        result
                    })
                    .map_err(|error| {
                        delivery_drain_error(port, outstanding, io::Error::from(error))
                    })?;
            }
            if send_state.pending > 0 && Instant::now() >= probe_at {
                let probed = self
                    .link
                    .with(LinkPhase::WriteProbe, port, |link| link.probe_window(port));
                if let Err(error) = probed {
                    outstanding = self
                        .link
                        .with(LinkPhase::Inspect, port, |link| link.send_state(port))
                        .or(outstanding);
                    return Err(delivery_drain_error(
                        port,
                        outstanding,
                        io::Error::from(error),
                    ));
                }
                probe_at = Instant::now() + self.write_policy.poll;
            }
            waited_off_link = self
                .link
                .wait_for_inbound(generation, DEFAULT_LINK_SLICE)
                .map_err(|error| delivery_drain_error(port, outstanding, io::Error::from(error)))?;
        }
    }
}

impl<T: BulkTransport> ShutdownWrite for MuxStream<T> {
    fn shutdown_write(&mut self) -> io::Result<()> {
        self.drain_delivery_shared(&[])?;
        let port = self.local_port;
        self.link
            .with(LinkPhase::Flush, port, |link| link.shutdown_write(port))
            .map_err(io::Error::from)?;
        self.drain_delivery_shared(&[])
    }
}

impl<T: BulkTransport> Read for MuxStream<T> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.read_shared(out, &[])
    }
}

impl<T: BulkTransport> Write for MuxStream<T> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.write_shared(data, &[])
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_shared()
    }
}

pub struct MuxReadHalf<'a, T: BulkTransport> {
    stream: &'a MuxStream<T>,
    connection_cancel: Vec<Arc<AtomicBool>>,
}

impl<T: BulkTransport> MuxReadHalf<'_, T> {
    #[must_use]
    pub fn with_connection_cancel(mut self, cancel: Arc<AtomicBool>) -> Self {
        self.connection_cancel.push(cancel);
        self
    }
}

impl<T: BulkTransport> Read for MuxReadHalf<'_, T> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.stream.read_shared(out, &self.connection_cancel)
    }
}

pub struct MuxWriteHalf<'a, T: BulkTransport> {
    stream: &'a MuxStream<T>,
    connection_cancel: Vec<Arc<AtomicBool>>,
}

impl<T: BulkTransport> MuxWriteHalf<'_, T> {
    #[must_use]
    pub fn with_connection_cancel(mut self, cancel: Arc<AtomicBool>) -> Self {
        self.connection_cancel.push(cancel);
        self
    }

    #[must_use]
    pub fn delivery_state(&self) -> Option<SendState> {
        let port = self.stream.local_port;
        self.stream
            .link
            .with(LinkPhase::Inspect, port, |link| link.send_state(port))
    }

    pub fn drain_delivery(&mut self) -> io::Result<()> {
        self.stream.drain_delivery_shared(&self.connection_cancel)
    }
}

impl<T: BulkTransport> Write for MuxWriteHalf<'_, T> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.stream.write_shared(data, &self.connection_cancel)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush_shared()
    }
}

impl<T: BulkTransport> Drop for MuxStream<T> {
    fn drop(&mut self) {
        // Completed FIN exchanges are released; unfinished sessions retain abortive cleanup.
        let _ = self.close();
    }
}

// The version exchange must precede the first dial: negotiating on demand would reset both
// sequence counters under the sessions already open.
pub struct MuxDialer<T> {
    link: SharedLink<T>,
    control_port: u16,
    control_policy: MuxReadPolicy,
    data_policy: MuxReadPolicy,
    write_policy: MuxWritePolicy,
    cancel: Option<Arc<AtomicBool>>,
    transfer_cancel: Option<Arc<AtomicBool>>,
}

impl<T: BulkTransport> MuxDialer<T> {
    #[must_use]
    pub fn new(link: SharedLink<T>) -> Self {
        Self {
            link,
            control_port: super::RESTORED_PORT,
            control_policy: MuxReadPolicy::default(),
            data_policy: MuxReadPolicy::default(),
            write_policy: MuxWritePolicy::default(),
            cancel: None,
            transfer_cancel: None,
        }
    }

    #[must_use]
    pub fn on_control_port(mut self, port: u16) -> Self {
        self.control_port = port;
        self
    }

    #[must_use]
    pub fn with_read_policy(mut self, policy: MuxReadPolicy) -> Self {
        self.control_policy = policy;
        self
    }

    #[must_use]
    pub fn with_data_read_policy(mut self, policy: MuxReadPolicy) -> Self {
        self.data_policy = policy;
        self
    }

    #[must_use]
    pub fn read_policy(&self) -> MuxReadPolicy {
        self.control_policy
    }

    #[must_use]
    pub fn data_read_policy(&self) -> MuxReadPolicy {
        self.data_policy
    }

    #[must_use]
    pub fn policy_for(&self, port: u16) -> MuxReadPolicy {
        if port == self.control_port {
            self.control_policy
        } else {
            self.data_policy
        }
    }

    #[must_use]
    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.control_policy = self.control_policy.with_poll(timeout);
        self
    }

    #[must_use]
    pub fn with_write_timeout(mut self, timeout: Duration) -> Self {
        self.write_policy = MuxWritePolicy::failing_after(timeout);
        self
    }

    #[must_use]
    pub fn with_write_policy(mut self, policy: MuxWritePolicy) -> Self {
        self.write_policy = policy;
        self
    }

    #[must_use]
    pub fn with_cancel(mut self, cancel: Arc<AtomicBool>) -> Self {
        self.cancel = Some(cancel);
        self
    }

    #[must_use]
    pub fn with_transfer_cancel(mut self, cancel: Arc<AtomicBool>) -> Self {
        self.transfer_cancel = Some(cancel);
        self
    }

    #[must_use]
    pub fn link(&self) -> SharedLink<T> {
        self.link.clone()
    }
}

impl<T: BulkTransport> Clone for MuxDialer<T> {
    fn clone(&self) -> Self {
        Self {
            link: self.link.clone(),
            control_port: self.control_port,
            control_policy: self.control_policy,
            data_policy: self.data_policy,
            write_policy: self.write_policy,
            cancel: self.cancel.clone(),
            transfer_cancel: self.transfer_cancel.clone(),
        }
    }
}

impl<T: BulkTransport> GuestDialer for MuxDialer<T> {
    type Stream = MuxStream<T>;

    fn dial(&mut self, port: u16, timeout: Duration) -> io::Result<Self::Stream> {
        let mut stream = self
            .link
            .open_cancellable(
                port,
                timeout,
                self.cancel.as_ref(),
                self.transfer_cancel.as_ref(),
            )
            .map_err(io::Error::from)?
            .with_read_policy(self.policy_for(port))
            .with_write_policy(self.write_policy);
        if let Some(cancel) = &self.cancel {
            stream = stream.with_cancel(Arc::clone(cancel));
        }
        if let Some(cancel) = &self.transfer_cancel {
            stream = stream.with_transfer_cancel(Arc::clone(cancel));
        }
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ramrod::dial::{DialError, DialPlan, SystemClock, dial_until};
    use crate::usbmux::frame::HEADER_LEN_V2;
    use crate::usbmux::link::tests::{Device, device_packet, device_version_reply, encode_segment};
    use crate::usbmux::tcp::{TCP_HEADER_LEN, TcpHeader, flags};

    use std::cell::Cell;
    use std::rc::Rc;

    #[test]
    fn delivery_probe_deadline_starts_with_fresh_flight_after_an_idle_window() {
        let state = |snd_una, snd_nxt, send_epoch| SendState {
            snd_una,
            snd_nxt,
            snd_wnd_edge: snd_nxt,
            send_epoch,
            peer_window: 0,
            usable: 0,
            pending: 0,
            segments_in: 0,
        };
        let start = Instant::now();
        let mut timer = DeliveryProbeTimer::default();
        timer.observe(state(100, 100, 4), start);
        timer.observe(state(100, 100, 4), start + Duration::from_secs(3));

        timer.observe(state(100, 104, 5), start + Duration::from_secs(3));
        assert_eq!(timer.due, Some(start + Duration::from_secs(5)));
        assert!(timer.observe(state(100, 104, 5), start + Duration::from_secs(5)));

        timer.observe(state(104, 108, 7), start + Duration::from_secs(6));
        assert_eq!(timer.due, Some(start + Duration::from_secs(8)));
        assert!(timer.observe(state(104, 108, 7), start + Duration::from_secs(8)));
    }

    #[derive(Clone)]
    struct Switchable {
        device: Device,
        failing: Rc<Cell<bool>>,
        present: Rc<Cell<Option<bool>>>,
    }

    impl Switchable {
        fn new() -> (Device, Self) {
            let device = Device::new();
            let wrapper = Self {
                device: device.clone(),
                failing: Rc::new(Cell::new(false)),
                present: Rc::new(Cell::new(Some(true))),
            };
            (device, wrapper)
        }

        fn fail(&self) {
            self.failing.set(true);
        }

        fn remove(&self) {
            self.present.set(Some(false));
        }
    }

    impl BulkTransport for Switchable {
        fn send(&mut self, packet: &[u8]) -> io::Result<()> {
            if self.failing.get() {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "the pipe is gone",
                ));
            }
            self.device.send(packet)
        }

        fn recv(&mut self, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
            if self.failing.get() {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "the pipe is gone",
                ));
            }
            self.device.recv(timeout)
        }

        fn out_max_packet_size(&self) -> u16 {
            self.device.out_max_packet_size()
        }

        fn device_accepted_packets(&self) -> Option<u64> {
            self.device.device_accepted_packets()
        }

        fn device_present(&self) -> Option<bool> {
            self.present.get()
        }
    }

    #[derive(Clone)]
    struct QuietUntil {
        device: Device,
        quiet_for: Duration,
        speak_at: Rc<Cell<Option<Instant>>>,
        port: Rc<Cell<u16>>,
        spoken: Rc<Cell<bool>>,
        host_packets_when_spoken: Rc<Cell<usize>>,
    }

    impl QuietUntil {
        fn new(quiet_for: Duration) -> (Device, Self) {
            let device = Device::new();
            let wrapper = Self {
                device: device.clone(),
                quiet_for,
                speak_at: Rc::new(Cell::new(None)),
                port: Rc::new(Cell::new(0)),
                spoken: Rc::new(Cell::new(false)),
                host_packets_when_spoken: Rc::new(Cell::new(0)),
            };
            (device, wrapper)
        }
    }

    impl BulkTransport for QuietUntil {
        fn send(&mut self, packet: &[u8]) -> io::Result<()> {
            self.device.send(packet)
        }

        fn recv(&mut self, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
            if !self.spoken.get() && self.port.get() != 0 {
                let speak_at = match self.speak_at.get() {
                    Some(at) => at,
                    None => {
                        let at = Instant::now() + self.quiet_for;
                        self.speak_at.set(Some(at));
                        at
                    }
                };
                if Instant::now() >= speak_at {
                    self.spoken.set(true);
                    self.host_packets_when_spoken
                        .set(self.device.received_packets().len());
                    self.device.push(self.port.get(), b"Progress");
                }
            }
            self.device.recv(timeout)
        }

        fn out_max_packet_size(&self) -> u16 {
            self.device.out_max_packet_size()
        }

        fn device_accepted_packets(&self) -> Option<u64> {
            self.device.device_accepted_packets()
        }

        fn device_present(&self) -> Option<bool> {
            Some(true)
        }
    }

    #[derive(Default)]
    struct TestSignal {
        generation: Mutex<u64>,
        ready: std::sync::Condvar,
        waits: std::sync::atomic::AtomicUsize,
        wait_observer: Option<std::sync::mpsc::Sender<()>>,
    }

    impl InboundSignal for TestSignal {
        fn inbound_generation(&self) -> u64 {
            *self.generation.lock().unwrap()
        }

        fn wait_for_inbound(&self, seen: u64, timeout: Duration) {
            self.waits
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Some(observer) = &self.wait_observer {
                let _ = observer.send(());
            }
            let guard = self.generation.lock().unwrap();
            if *guard != seen {
                return;
            }
            let _ = self.ready.wait_timeout(guard, timeout);
        }
    }

    #[derive(Default)]
    struct ThreadWireState {
        sent: Vec<Vec<u8>>,
        inbound: std::collections::VecDeque<Vec<u8>>,
        sequence: u16,
    }

    #[derive(Clone)]
    struct ThreadWire {
        state: Arc<Mutex<ThreadWireState>>,
        signal: Arc<TestSignal>,
        present: Arc<AtomicBool>,
    }

    impl ThreadWire {
        fn new() -> (Self, std::sync::mpsc::Receiver<()>) {
            let (observer, waits) = std::sync::mpsc::channel();
            (
                Self {
                    state: Arc::new(Mutex::new(ThreadWireState::default())),
                    signal: Arc::new(TestSignal {
                        wait_observer: Some(observer),
                        ..TestSignal::default()
                    }),
                    present: Arc::new(AtomicBool::new(true)),
                },
                waits,
            )
        }

        fn queue(&self, packet: Vec<u8>) {
            self.state.lock().unwrap().inbound.push_back(packet);
            self.notify();
        }

        fn notify(&self) {
            let mut generation = self.signal.generation.lock().unwrap();
            *generation += 1;
            self.signal.ready.notify_all();
        }

        fn reply(&self, header: TcpHeader, payload: &[u8]) {
            let mut state = self.state.lock().unwrap();
            let packet = device_packet(state.sequence, 0, &encode_segment(header, payload));
            state.sequence = state.sequence.wrapping_add(1);
            state.inbound.push_back(packet);
            drop(state);
            self.notify();
        }

        fn take_sent(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut self.state.lock().unwrap().sent)
        }
    }

    impl BulkTransport for ThreadWire {
        fn send(&mut self, packet: &[u8]) -> io::Result<()> {
            self.state.lock().unwrap().sent.push(packet.to_vec());
            Ok(())
        }

        fn recv(&mut self, _timeout: Duration) -> io::Result<Option<Vec<u8>>> {
            Ok(self.state.lock().unwrap().inbound.pop_front())
        }

        fn out_max_packet_size(&self) -> u16 {
            512
        }

        fn inbound_signal(&self) -> Option<Arc<dyn InboundSignal>> {
            Some(Arc::clone(&self.signal) as Arc<dyn InboundSignal>)
        }

        fn device_present(&self) -> Option<bool> {
            Some(self.present.load(Ordering::Acquire))
        }
    }

    fn opened_thread_wire() -> (
        MuxStream<ThreadWire>,
        ThreadWire,
        std::sync::mpsc::Receiver<()>,
    ) {
        let (wire, waits) = ThreadWire::new();
        wire.queue(device_version_reply(2));
        let link = SharedLink::new(MuxLink::new(wire.clone()));
        assert_eq!(
            link.negotiate(VersionRequest::resync(), Duration::from_secs(1))
                .unwrap(),
            MuxVersion::V2
        );
        wire.take_sent();
        let guest_port = 62078;
        let port = link
            .with(LinkPhase::OpenSyn, 0, |link| link.begin_open(guest_port))
            .unwrap();
        let sent = wire.take_sent();
        assert_eq!(sent.len(), 1);
        let syn = TcpHeader::decode(&sent[0][HEADER_LEN_V2..]).unwrap();
        assert_eq!(syn.flags, flags::SYN);
        wire.reply(
            TcpHeader {
                source_port: guest_port,
                destination_port: port,
                sequence: 0,
                acknowledgement: syn.sequence.wrapping_add(1),
                flags: flags::SYN_ACK,
                window: 65536,
            },
            &[],
        );
        let stream = link
            .complete_open_cancellable(
                port,
                guest_port,
                Duration::from_secs(1),
                Instant::now(),
                None,
                None,
            )
            .unwrap();
        wire.take_sent();
        (stream, wire, waits)
    }

    fn peer_ack(port: u16, acknowledged: u32) -> TcpHeader {
        TcpHeader {
            source_port: 62078,
            destination_port: port,
            sequence: 1,
            acknowledgement: acknowledged,
            flags: flags::ACK,
            window: 65536,
        }
    }

    #[derive(Clone)]
    struct Signalling {
        device: Device,
        signal: Arc<TestSignal>,
        longest_recv_wait: Rc<Cell<Duration>>,
        present: Rc<Cell<bool>>,
        deaf: Rc<Cell<bool>>,
    }

    impl Signalling {
        fn new(window: Option<u32>) -> (Device, Self) {
            let device = match window {
                Some(window) => Device::new().with_window(window),
                None => Device::new(),
            };
            let wrapper = Self {
                device: device.clone(),
                signal: Arc::new(TestSignal::default()),
                longest_recv_wait: Rc::new(Cell::new(Duration::ZERO)),
                present: Rc::new(Cell::new(true)),
                deaf: Rc::new(Cell::new(false)),
            };
            (device, wrapper)
        }

        fn remove(&self) {
            self.present.set(false);
        }

        fn go_deaf(&self) {
            self.deaf.set(true);
        }

        fn forget_recv_waits(&self) {
            self.longest_recv_wait.set(Duration::ZERO);
        }

        fn longest_recv_wait(&self) -> Duration {
            self.longest_recv_wait.get()
        }

        fn signal_waits(&self) -> usize {
            self.signal.waits.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl BulkTransport for Signalling {
        fn send(&mut self, packet: &[u8]) -> io::Result<()> {
            if self.deaf.get() {
                return Ok(());
            }
            self.device.send(packet)
        }

        fn recv(&mut self, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
            if timeout > self.longest_recv_wait.get() {
                self.longest_recv_wait.set(timeout);
            }
            self.device.recv(timeout)
        }

        fn out_max_packet_size(&self) -> u16 {
            self.device.out_max_packet_size()
        }

        fn device_accepted_packets(&self) -> Option<u64> {
            self.device.device_accepted_packets()
        }

        fn device_present(&self) -> Option<bool> {
            Some(self.present.get())
        }

        fn inbound_signal(&self) -> Option<Arc<dyn InboundSignal>> {
            Some(Arc::clone(&self.signal) as Arc<dyn InboundSignal>)
        }
    }

    fn negotiated() -> (SharedLink<Device>, Device) {
        let device = Device::new();
        let link = SharedLink::new(MuxLink::new(device.clone()));
        assert_eq!(
            link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
                .unwrap(),
            MuxVersion::V2
        );
        device.take_received_packets();
        (link, device)
    }

    #[test]
    fn a_stream_carries_bytes_in_both_directions() {
        let (link, device) = negotiated();
        let mut stream = link.open(62078, Duration::from_secs(1)).unwrap();
        let port = stream.local_port();
        assert!(stream.is_open());
        assert_eq!(device.only_session_ports(), (port, 62078));

        stream.write_all(b"hello").unwrap();
        stream.flush().unwrap();
        assert_eq!(device.session_bytes(port), b"hello".to_vec());

        device.push(port, b"world");
        let mut buffer = [0u8; 8];
        let read = stream.read(&mut buffer).unwrap();
        assert_eq!(&buffer[..read], b"world");
    }

    #[test]
    fn a_stream_carries_more_than_one_segment_of_payload() {
        let (link, device) = negotiated();
        let mut stream = link.open(62078, Duration::from_secs(1)).unwrap();
        let port = stream.local_port();
        let payload: Vec<u8> = (0..8192u32).map(|byte| (byte % 251) as u8).collect();
        stream.write_all(&payload).unwrap();
        assert_eq!(device.session_bytes(port), payload);
    }

    #[test]
    fn a_stalled_delivery_retransmits_unacknowledged_payload() {
        let (link, device) = negotiated();
        let mut stream = link
            .open(62078, Duration::from_secs(1))
            .unwrap()
            .with_write_policy(MuxWritePolicy {
                poll: Duration::from_secs(4),
                on_expiry: WriteExpiry::Fail,
            });
        let port = stream.local_port();
        let payload = b"restore image data";
        device.drop_next_payload();

        stream.write_all(payload).unwrap();
        stream.drain_delivery_shared(&[]).unwrap();
        assert_eq!(device.session_bytes(port), payload);
    }

    #[test]
    fn a_full_nonzero_window_recovers_when_its_first_payload_is_lost() {
        let (link, device) = negotiated();
        device.clone().with_window(16_128);
        let mut stream = link
            .open(62078, Duration::from_secs(1))
            .unwrap()
            .with_write_policy(MuxWritePolicy {
                poll: Duration::from_secs(4),
                on_expiry: WriteExpiry::Fail,
            });
        let port = stream.local_port();
        let payload = vec![0x5A; 16_128 + 1_024];
        device.drop_next_payload();

        stream.write_all(&payload).unwrap();
        stream.drain_delivery_shared(&[]).unwrap();
        assert_eq!(device.session_bytes(port), payload);
    }

    #[test]
    fn dropping_a_stream_resets_the_session_inside_the_guest() {
        let (link, device) = negotiated();
        let stream = link.open(62078, Duration::from_secs(1)).unwrap();
        let port = stream.local_port();
        assert!(device.session_open(port));
        device.take_received_packets();
        drop(stream);
        let sent = device.take_received_packets();
        assert_eq!(sent.len(), 1);
        let tcp = TcpHeader::decode(&sent[0][HEADER_LEN_V2..]).unwrap();
        assert_eq!(tcp.flags, flags::RST);
        assert_eq!(tcp.source_port, port);
        assert!(!device.session_open(port));
    }

    #[test]
    fn the_dialler_satisfies_the_trait_ramrod_and_asr_already_take() {
        let (link, _device) = negotiated();
        let mut dialer = MuxDialer::new(link);
        let stream = dialer.dial(62078, Duration::from_secs(1)).unwrap();
        assert!(stream.is_open());
        fn assert_read_write<S: Read + Write>(_: &S) {}
        assert_read_write(&stream);
    }

    #[test]
    fn the_dialler_works_through_the_retry_loop_ramrod_uses() {
        let (link, device) = negotiated();
        let mut dialer = MuxDialer::new(link);
        let plan = DialPlan::default().with_window(Duration::from_secs(2));
        let outcome = dial_until(&mut dialer, plan, &mut SystemClock).unwrap();
        assert_eq!(outcome.attempts, 1);
        assert!(outcome.stream.is_open());
        assert_eq!(plan.port, crate::usbmux::RESTORED_PORT);
        assert_eq!(device.only_session_ports().1, 62078);
    }

    #[test]
    fn two_streams_share_one_link_which_is_what_a_restore_needs() {
        let (link, device) = negotiated();
        let mut dialer = MuxDialer::new(link);
        let mut control = dialer.dial(62078, Duration::from_secs(1)).unwrap();
        let mut data = dialer.dial(50000, Duration::from_secs(1)).unwrap();
        assert_ne!(control.local_port(), data.local_port());

        control.write_all(b"StartRestore").unwrap();
        data.write_all(b"blocks").unwrap();
        assert_eq!(
            device.session_bytes(control.local_port()),
            b"StartRestore".to_vec()
        );
        assert_eq!(device.session_bytes(data.local_port()), b"blocks".to_vec());

        device.push(data.local_port(), b"payload");
        let mut buffer = [0u8; 16];
        let read = data.read(&mut buffer).unwrap();
        assert_eq!(&buffer[..read], b"payload");
    }

    #[test]
    fn a_session_opens_on_whatever_port_the_guest_names_and_not_a_known_set() {
        let (link, device) = negotiated();
        let mut dialer = MuxDialer::new(link);
        for guest_port in [1u16, 12345, 12346, 12347, 12348, 50000, 65535] {
            let stream = dialer.dial(guest_port, Duration::from_secs(1)).unwrap();
            assert!(stream.is_open(), "port {guest_port} was refused");
            assert_eq!(
                device.session_ports(stream.local_port()),
                Some(guest_port),
                "the SYN for port {guest_port} named a different destination"
            );
        }
    }

    #[test]
    fn concurrent_sessions_on_consecutive_asynchronous_ports_do_not_cross() {
        let (link, device) = negotiated();
        let mut dialer = MuxDialer::new(link);
        let mut streams: Vec<_> = [12346u16, 12347, 12348]
            .into_iter()
            .map(|port| dialer.dial(port, Duration::from_secs(1)).unwrap())
            .collect();

        for (index, stream) in streams.iter_mut().enumerate() {
            stream.write_all(&[index as u8; 4]).unwrap();
        }
        for (index, stream) in streams.iter().enumerate() {
            assert_eq!(
                device.session_bytes(stream.local_port()),
                vec![index as u8; 4]
            );
        }

        let local_ports: Vec<u16> = streams.iter().map(MuxStream::local_port).collect();
        let mut unique = local_ports.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), local_ports.len(), "host ports collided");
    }

    #[test]
    fn a_dial_that_the_device_never_answers_fails_rather_than_hanging() {
        let (link, device) = negotiated();
        let mut dialer = MuxDialer::new(link);
        let stream = dialer.dial(62078, Duration::from_secs(1)).unwrap();
        device.reset(stream.local_port());
        drop(stream);

        let mut plan = DialPlan::default().on_port(62078);
        plan.window = Duration::from_millis(150);
        plan.attempt_timeout = Duration::from_millis(20);
        plan.retry_interval = Duration::from_millis(1);
        let outcome = dial_until(&mut dialer, plan, &mut SystemClock).unwrap();
        assert!(outcome.stream.is_open());
    }

    #[test]
    fn a_dial_against_a_silent_pipe_reports_the_window_closing() {
        use crate::usbmux::link::tests::Wire;
        let wire = Wire::new();
        let mut link = MuxLink::new(wire.clone());
        wire.queue(crate::usbmux::link::tests::device_version_reply(2));
        link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
            .unwrap();
        let shared = SharedLink::new(link);
        let mut dialer = MuxDialer::new(shared);
        let mut plan = DialPlan::default().on_port(62078);
        plan.window = Duration::from_millis(120);
        plan.attempt_timeout = Duration::from_millis(20);
        plan.retry_interval = Duration::from_millis(1);
        match dial_until(&mut dialer, plan, &mut SystemClock) {
            Err(DialError::WindowClosed { port, attempts, .. }) => {
                assert_eq!(port, 62078);
                assert!(attempts > 0);
            }
            Err(error @ DialError::Cancelled { .. }) => {
                panic!("expected the configured dial window to close, got {error}");
            }
            Ok(_) => panic!("the pipe answered nothing, so no session can have opened"),
        }
    }

    #[test]
    fn payload_fin_reads_all_buffered_bytes_before_orderly_eof() {
        let (link, device) = negotiated();
        let mut stream = link.open(62078, Duration::from_secs(1)).unwrap();
        device.push_with_flags(stream.local_port(), b"guest log", flags::ACK | flags::FIN);
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"guest log");
        assert_eq!(stream.read(&mut [0u8; 1]).unwrap(), 0);
    }

    #[test]
    fn host_half_close_completes_the_fin_exchange_and_releases_the_session() {
        let lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = Arc::clone(&lines);
        let meter = super::super::roundtrip::RoundtripMeter::with_sink(
            super::super::roundtrip::LineBudget::new(16),
            Box::new(move |line: &str| sink.lock().unwrap().push(line.to_string())),
        );
        let device = Device::new();
        let link = SharedLink::new(MuxLink::new(device.clone()).with_roundtrip_meter(meter));
        link.negotiate(VersionRequest::resync(), Duration::from_secs(1))
            .unwrap();
        let mut stream = link.open(62078, Duration::from_secs(1)).unwrap();
        let port = stream.local_port();
        device.take_received_packets();
        stream.write_all(b"host").unwrap();
        device.push_with_flags(port, b"done", flags::ACK | flags::FIN);
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"done");
        stream.shutdown_write().unwrap();
        let state = link
            .with(LinkPhase::Inspect, port, |link| link.send_state(port))
            .unwrap();
        assert_eq!(state.snd_una, state.snd_nxt);
        assert_eq!(
            stream.write(b"late").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        drop(stream);
        let headers: Vec<_> = device
            .take_received_packets()
            .iter()
            .map(|packet| TcpHeader::decode(&packet[HEADER_LEN_V2..]).unwrap())
            .collect();
        let flags: Vec<_> = headers.iter().map(|header| header.flags).collect();
        assert_eq!(
            flags,
            vec![flags::ACK, flags::ACK, flags::ACK, flags::ACK | flags::FIN]
        );
        assert_eq!(headers.last().unwrap().acknowledgement, 6);
        let closed = lines.lock().unwrap();
        assert_eq!(closed.len(), 1);
        assert!(closed[0].contains(&format!("port={port}")));
        assert!(closed[0].contains("why=closed"));
        assert!(closed[0].contains("sent_bytes=4"));
        assert!(closed[0].contains("acked_bytes=4"));
    }

    #[test]
    fn a_peer_reset_is_reported_as_a_connection_reset() {
        let (link, device) = negotiated();
        let mut stream = link.open(62078, Duration::from_secs(1)).unwrap();
        device.reset(stream.local_port());
        let mut buffer = [0u8; 8];
        assert_eq!(
            stream.read(&mut buffer).unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
    }

    #[test]
    fn a_control_read_survives_far_more_quiet_than_any_bound_and_sends_nothing_while_it_waits() {
        let quiet = Duration::from_millis(300);
        let poll = Duration::from_millis(5);
        let (device, guest) = QuietUntil::new(quiet);
        let link = SharedLink::new(MuxLink::new(guest.clone()));
        link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
            .unwrap();
        let mut stream = link
            .open(62078, Duration::from_secs(1))
            .unwrap()
            .with_read_policy(MuxReadPolicy::retrying(poll).with_slice(Duration::from_millis(1)));
        let port = stream.local_port();
        guest.port.set(port);
        device.take_received_packets();

        let began = Instant::now();
        let mut buffer = [0u8; 16];
        let read = stream.read(&mut buffer).unwrap();
        let waited = began.elapsed();

        assert_eq!(&buffer[..read], b"Progress");
        assert!(waited >= quiet, "{waited:?}");
        assert!(guest.spoken.get(), "the guest never got to speak");
        assert_eq!(
            guest.host_packets_when_spoken.get(),
            0,
            "the host put a packet on the wire during a quiet wait, which a real restore host never does"
        );
        assert!(
            stream.is_open(),
            "the session was torn down by a quiet period"
        );
        assert!(device.session_open(port), "the guest's socket was reset");
        assert!(device.session_bytes(port).is_empty());
    }

    #[test]
    fn a_genuine_transport_error_ends_the_read_promptly() {
        let (_device, switch) = Switchable::new();
        let link = SharedLink::new(MuxLink::new(switch.clone()));
        link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
            .unwrap();
        let mut stream = link
            .open(62078, Duration::from_secs(1))
            .unwrap()
            .with_read_policy(MuxReadPolicy::retrying(Duration::from_secs(3600)));
        switch.fail();

        let began = Instant::now();
        let mut buffer = [0u8; 8];
        let error = stream.read(&mut buffer).unwrap_err();
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "the error was not prompt"
        );
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        let text = error.to_string();
        assert!(!is_host_initiated_teardown(&text), "{text}");
        assert!(!is_device_gone(&text), "{text}");
    }

    #[test]
    fn a_device_that_left_the_bus_ends_the_read_promptly_and_is_not_called_a_host_teardown() {
        let (device, switch) = Switchable::new();
        let link = SharedLink::new(MuxLink::new(switch.clone()));
        link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
            .unwrap();
        let mut stream = link
            .open(62078, Duration::from_secs(1))
            .unwrap()
            .with_read_policy(
                MuxReadPolicy::retrying(Duration::from_secs(3600))
                    .with_slice(Duration::from_millis(1)),
            );
        device.take_received_packets();
        switch.remove();

        let began = Instant::now();
        let mut buffer = [0u8; 8];
        let error = stream.read(&mut buffer).unwrap_err();
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "the removal was not prompt"
        );
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        let text = error.to_string();
        assert!(is_device_gone(&text), "{text}");
        assert!(!is_host_initiated_teardown(&text), "{text}");
        assert!(text.contains("left the bus"), "{text}");
        assert!(device.take_received_packets().is_empty());
        let write_error = stream.write(b"x").unwrap_err();
        assert_eq!(write_error.kind(), io::ErrorKind::ConnectionReset);
        assert!(is_device_gone(&write_error.to_string()));
    }

    #[test]
    fn stopping_the_run_ends_a_waiting_read_and_is_not_reported_as_the_guest() {
        let (_device, switch) = Switchable::new();
        let link = SharedLink::new(MuxLink::new(switch));
        link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
            .unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut stream = link
            .open(62078, Duration::from_secs(1))
            .unwrap()
            .with_read_policy(
                MuxReadPolicy::retrying(Duration::from_secs(3600))
                    .with_slice(Duration::from_millis(1)),
            )
            .with_cancel(Arc::clone(&cancel));
        cancel.store(true, Ordering::Relaxed);

        let began = Instant::now();
        let mut buffer = [0u8; 8];
        let error = stream.read(&mut buffer).unwrap_err();
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "the stop was not prompt"
        );
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        let text = error.to_string();
        assert!(is_run_stopped(&text), "{text}");
        assert!(!is_host_initiated_teardown(&text), "{text}");
        assert!(!is_device_gone(&text), "{text}");
    }

    #[test]
    fn the_dialler_hands_the_stop_flag_to_every_session_it_opens() {
        let (link, _device) = negotiated();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut dialer = MuxDialer::new(link).with_cancel(Arc::clone(&cancel));
        let mut buffer = [0u8; 8];
        for port in [62078u16, 12345] {
            cancel.store(false, Ordering::Relaxed);
            let mut stream = dialer
                .dial(port, Duration::from_secs(1))
                .unwrap()
                .with_read_policy(
                    MuxReadPolicy::retrying(Duration::from_secs(3600))
                        .with_slice(Duration::from_millis(1)),
                );
            cancel.store(true, Ordering::Relaxed);
            let error = stream.read(&mut buffer).unwrap_err();
            assert!(is_run_stopped(&error.to_string()), "port {port}");
        }
    }

    #[test]
    fn the_asr_rule_ends_on_its_bound_and_says_plainly_that_the_host_did_it() {
        let (_link_device, switch) = Switchable::new();
        let link = SharedLink::new(MuxLink::new(switch));
        link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
            .unwrap();
        let mut stream = link
            .open(12345, Duration::from_secs(1))
            .unwrap()
            .with_read_policy(MuxReadPolicy::failing_after(Duration::from_millis(40)));
        let mut buffer = [0u8; 8];
        let began = Instant::now();
        let error = stream.read(&mut buffer).unwrap_err();
        assert!(began.elapsed() >= Duration::from_millis(40));
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let text = error.to_string();
        assert!(is_host_initiated_teardown(&text), "{text}");
        assert!(text.contains("mux port"), "{text}");
        assert!(text.contains("the host stopped waiting"), "{text}");
        assert!(
            text.contains("not on anything the guest reported"),
            "{text}"
        );
        assert!(
            text.contains("follows from the host end going away"),
            "{text}"
        );
        assert!(!is_host_initiated_teardown(
            "the guest closed the connection without replying to QueryType"
        ));
    }

    #[test]
    fn the_control_session_and_the_asr_sessions_do_not_share_one_rule() {
        let (link, _device) = negotiated();
        let control = MuxReadPolicy::retrying(Duration::from_millis(11));
        let data = MuxReadPolicy::failing_after(Duration::from_millis(22));
        let mut dialer = MuxDialer::new(link)
            .on_control_port(62078)
            .with_read_policy(control)
            .with_data_read_policy(data);
        assert_eq!(dialer.read_policy(), control);
        assert_eq!(dialer.data_read_policy(), data);
        let opened_control = dialer.dial(62078, Duration::from_secs(1)).unwrap();
        let opened_data = dialer.dial(50000, Duration::from_secs(1)).unwrap();
        assert_eq!(opened_control.read_policy(), control);
        assert_eq!(opened_control.read_policy().on_expiry, ReadExpiry::Retry);
        assert_eq!(opened_data.read_policy(), data);
        assert_eq!(opened_data.read_policy().on_expiry, ReadExpiry::Fail);
    }

    #[test]
    fn nothing_is_bounded_by_default_because_a_host_bound_ended_run_85() {
        let (link, _device) = negotiated();
        let dialer = MuxDialer::new(link);
        assert_eq!(dialer.read_policy().on_expiry, ReadExpiry::Retry);
        assert_eq!(dialer.data_read_policy().on_expiry, ReadExpiry::Retry);
        assert_eq!(dialer.read_policy().poll, DEFAULT_READ_POLL);
        assert_eq!(DEFAULT_READ_POLL, Duration::from_secs(30));
    }

    #[test]
    fn writing_to_a_closed_stream_is_refused_rather_than_silently_dropped() {
        let (link, _device) = negotiated();
        let mut stream = link.open(62078, Duration::from_secs(1)).unwrap();
        stream.close().unwrap();
        let error = stream.write(b"x").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        stream.close().unwrap();
    }

    #[test]
    fn an_idle_read_never_asks_the_transport_to_wait_while_it_holds_the_link() {
        let (_device, transport) = Signalling::new(None);
        let link = SharedLink::new(MuxLink::new(transport.clone()));
        link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
            .unwrap();
        assert!(link.can_wait_off_link());
        let mut stream = link
            .open(62078, Duration::from_secs(1))
            .unwrap()
            .with_read_policy(MuxReadPolicy::failing_after(Duration::from_millis(60)));
        transport.forget_recv_waits();

        let mut out = [0u8; 8];
        let error = stream.read(&mut out).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            transport.longest_recv_wait(),
            Duration::ZERO,
            "the read asked the transport to wait, which means it slept holding the link"
        );
        assert!(
            transport.signal_waits() > 0,
            "the wait has to have happened somewhere, and off the link is the only place left"
        );
        let port = stream.local_port();
        let stats = link
            .with(LinkPhase::Inspect, port, |link| link.roundtrip(port))
            .expect("the port was recorded");
        assert!(
            stats.inbound_wait_open.count > 0,
            "an idle reader's wait is a wait with the window open, not a window block"
        );
        assert_eq!(stats.blocked.count, 0);
    }

    #[test]
    fn a_dial_the_guest_never_answers_never_holds_the_link_while_it_waits() {
        let (_device, transport) = Signalling::new(None);
        let link = SharedLink::new(MuxLink::new(transport.clone()));
        link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
            .unwrap();
        transport.go_deaf();
        transport.forget_recv_waits();

        let local_port = match link.open(62078, Duration::from_millis(60)) {
            Err(MuxError::HandshakeTimedOut { local_port, .. }) => local_port,
            Err(other) => {
                panic!("a device that never answers times the handshake out, got {other}")
            }
            Ok(stream) => panic!(
                "a device that never answers cannot establish, got local port {}",
                stream.local_port()
            ),
        };
        assert_eq!(
            transport.longest_recv_wait(),
            Duration::ZERO,
            "the dial asked the transport to wait, which means it slept holding the link"
        );
        assert!(
            transport.signal_waits() > 0,
            "the wait has to have happened somewhere, and off the link is the only place left"
        );
        assert!(
            link.with(LinkPhase::Inspect, local_port, |link| link
                .session_state(local_port))
                .is_none()
        );
    }

    #[test]
    fn a_dial_answered_by_the_guest_still_establishes_and_carries_bytes() {
        let (device, transport) = Signalling::new(None);
        let link = SharedLink::new(MuxLink::new(transport.clone()));
        link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
            .unwrap();
        transport.forget_recv_waits();
        let mut stream = link.open(62078, Duration::from_secs(1)).unwrap();
        assert!(stream.is_open());
        assert_eq!(
            transport.longest_recv_wait(),
            Duration::ZERO,
            "even a handshake the device answers at once must not wait under the link"
        );
        stream.write_all(b"BeginCtrl\0").unwrap();
        stream.flush().unwrap();
        assert_eq!(
            device.session_bytes(stream.local_port()),
            b"BeginCtrl\0".to_vec()
        );
    }

    #[test]
    fn a_write_held_by_a_shut_window_waits_off_the_link_too() {
        let (_device, transport) = Signalling::new(Some(0));
        let link = SharedLink::new(MuxLink::new(transport.clone()));
        link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
            .unwrap();
        let mut stream = link
            .open(62078, Duration::from_secs(1))
            .unwrap()
            .with_write_timeout(Duration::from_millis(60));
        transport.forget_recv_waits();

        let error = stream.write(b"payload").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            transport.longest_recv_wait(),
            Duration::ZERO,
            "the write asked the transport to wait, which means it slept holding the link"
        );
        assert!(transport.signal_waits() > 0);
        let port = stream.local_port();
        let stats = link
            .with(LinkPhase::Inspect, port, |link| link.roundtrip(port))
            .expect("the port was recorded");
        assert!(
            stats.inbound_wait_shut.count > 0,
            "a writer's wait on a shut window is not the same fact as an idle reader's"
        );
        assert_eq!(stats.bytes_queued, 7);
        assert_eq!(stats.segments_sent, 0, "a shut window sends nothing");
    }

    #[test]
    fn a_second_expired_bounded_write_reports_the_window_rather_than_a_wrapped_count() {
        let (_device, transport) = Signalling::new(Some(0));
        let link = SharedLink::new(MuxLink::new(transport.clone()));
        link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
            .unwrap();
        let mut stream = link
            .open(62078, Duration::from_secs(1))
            .unwrap()
            .with_write_timeout(Duration::from_millis(20));

        let payload = vec![0xA5_u8; 884_776];
        let first = stream.write(&payload).unwrap_err();
        assert_eq!(first.kind(), io::ErrorKind::TimedOut);
        let second = stream.write(&payload).unwrap_err();
        assert_eq!(
            second.kind(),
            io::ErrorKind::TimedOut,
            "a queue at twice the payload has to be reported, not subtracted"
        );
        assert!(
            second.to_string().contains("still queued"),
            "the error has to name what is still owed rather than imply it was written: {second}"
        );
        let port = stream.local_port();
        let stats = link
            .with(LinkPhase::Inspect, port, |link| link.roundtrip(port))
            .expect("the port was recorded");
        assert_eq!(stats.segments_sent, 0, "a shut window sends nothing");
    }

    #[test]
    fn a_retrying_write_outlives_its_poll_and_ends_only_when_the_run_is_stopped() {
        let (_device, transport) = Signalling::new(Some(0));
        let link = SharedLink::new(MuxLink::new(transport.clone()));
        link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
            .unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let poll = Duration::from_millis(20);
        let mut stream = link
            .open(62078, Duration::from_secs(1))
            .unwrap()
            .with_write_policy(MuxWritePolicy::retrying(poll))
            .with_cancel(Arc::clone(&cancel));

        let stopper = {
            let cancel = Arc::clone(&cancel);
            std::thread::spawn(move || {
                std::thread::sleep(poll * 4);
                cancel.store(true, Ordering::Relaxed);
            })
        };
        let began = Instant::now();
        let error = stream.write(b"payload").unwrap_err();
        let waited = began.elapsed();
        stopper.join().unwrap();

        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert!(
            is_run_stopped(&error.to_string()),
            "a write that outlived its poll ended for the only reason it may: {error}"
        );
        assert!(
            waited >= poll * 2,
            "the write has to have gone round at least twice, not failed on the first expiry: {waited:?}"
        );
    }

    #[test]
    fn a_write_ends_when_the_device_leaves_the_bus_while_it_is_already_parked() {
        let (_device, transport) = Signalling::new(Some(0));
        let link = SharedLink::new(MuxLink::new(transport.clone()));
        link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
            .unwrap();
        let poll = Duration::from_millis(20);
        let mut stream = link
            .open(62078, Duration::from_secs(1))
            .unwrap()
            .with_write_policy(MuxWritePolicy::retrying(poll));

        transport.remove();
        let error = stream.write(b"payload").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert!(
            is_device_gone(&error.to_string()),
            "the removal event is what ended it, not a clock: {error}"
        );
    }

    #[test]
    fn a_large_write_with_room_in_the_window_drains_in_one_pass() {
        let (device, transport) = Signalling::new(Some(16 * 1024 * 1024));
        let link = SharedLink::new(MuxLink::new(transport.clone()));
        link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
            .unwrap();
        let mss = link.with(LinkPhase::Inspect, 0, |link| link.segment_size().unwrap());
        let bursts = 6usize;
        let payload = vec![0xAB_u8; mss * bursts];
        let mut stream = link.open(62078, Duration::from_secs(5)).unwrap();
        let began = Instant::now();
        stream.write_all(&payload).unwrap();
        let elapsed = began.elapsed();
        let port = stream.local_port();
        assert_eq!(device.session_bytes(port).len(), payload.len());
        assert!(
            elapsed < Duration::from_millis(50),
            "the window has room for all of it, so the whole payload should drain without waiting for an ACK: {elapsed:?}"
        );
    }

    #[test]
    fn a_read_and_a_write_still_carry_bytes_when_the_transport_can_signal() {
        let (device, transport) = Signalling::new(None);
        let link = SharedLink::new(MuxLink::new(transport.clone()));
        link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
            .unwrap();
        let mut stream = link.open(62078, Duration::from_secs(1)).unwrap();
        let port = stream.local_port();
        stream.write_all(b"QueryType").unwrap();
        assert_eq!(device.session_bytes(port), b"QueryType".to_vec());

        device.push(port, b"answer");
        let mut out = [0u8; 16];
        assert_eq!(stream.read(&mut out).unwrap(), 6);
        assert_eq!(&out[..6], b"answer");
    }

    #[test]
    fn every_packet_a_stream_sends_declares_its_own_length() {
        let (link, device) = negotiated();
        let mut stream = link.open(62078, Duration::from_secs(1)).unwrap();
        stream.write_all(&vec![0x5A; 1000]).unwrap();
        let packets = device.received_packets();
        assert!(packets.len() >= 3);
        for packet in packets {
            let header = crate::usbmux::MuxHeader::decode(MuxVersion::V2, &packet).unwrap();
            assert_eq!(header.length as usize, packet.len());
            assert!(packet.len() >= HEADER_LEN_V2 + TCP_HEADER_LEN);
        }
    }
    #[test]
    fn transfer_failure_cancellation_reaches_every_cloned_mux_session() {
        let (link, _device) = negotiated();
        let failure = Arc::new(AtomicBool::new(false));
        let mut dialer = MuxDialer::new(link).with_transfer_cancel(Arc::clone(&failure));
        let mut cloned = dialer.clone();
        let mut control = dialer.dial(62078, Duration::from_secs(1)).unwrap();
        let mut transfer = cloned.dial(9510, Duration::from_secs(1)).unwrap();
        failure.store(true, Ordering::Release);
        for stream in [&mut control, &mut transfer] {
            let error = stream.read_exact(&mut [0u8; 1]).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
            assert_eq!(
                DialCancellation::from_io_error(&error),
                Some(DialCancellation::TransferFailed)
            );
        }
        let write_error = transfer.write_all(b"guest payload").unwrap_err();
        assert_eq!(
            DialCancellation::from_io_error(&write_error),
            Some(DialCancellation::TransferFailed)
        );
        let dial_error = cloned.dial(9511, Duration::from_secs(1)).err().unwrap();
        assert_eq!(
            DialCancellation::from_io_error(&dial_error),
            Some(DialCancellation::TransferFailed)
        );
    }

    #[test]
    fn a_cancelled_dial_resets_a_handshake_completed_by_another_link_reader() {
        let (link, device) = negotiated();
        let guest_port = 9520;
        let local_port = link
            .with(LinkPhase::OpenSyn, 0, |link| link.begin_open(guest_port))
            .unwrap();
        let reader = link.clone();
        reader.with(LinkPhase::Read, local_port, |link| {
            link.drain_inbound().unwrap();
            assert_eq!(
                link.session_state(local_port),
                Some(SessionState::Established)
            );
            link.flush(local_port).unwrap();
        });
        assert!(device.session_open(local_port));
        let failure = Arc::new(AtomicBool::new(true));
        let error = link
            .complete_open_cancellable(
                local_port,
                guest_port,
                Duration::from_secs(1),
                Instant::now(),
                None,
                Some(&failure),
            )
            .err()
            .unwrap();
        let error = io::Error::from(error);
        assert_eq!(
            DialCancellation::from_io_error(&error),
            Some(DialCancellation::TransferFailed)
        );
        let resets: Vec<_> = device
            .received_packets()
            .iter()
            .filter_map(|packet| TcpHeader::decode(&packet[HEADER_LEN_V2..]).ok())
            .filter(|tcp| tcp.flags == flags::RST)
            .collect();
        assert_eq!(resets.len(), 1);
        assert_eq!(
            (resets[0].source_port, resets[0].destination_port),
            (local_port, guest_port)
        );
        let replacement = link.open(9521, Duration::from_secs(1)).unwrap();
        assert!(replacement.is_open());
        assert_eq!(device.session_ports(replacement.local_port()), Some(9521));
    }

    #[test]
    fn cancelled_handshake_cleanup_preserves_the_cancellation_when_reset_send_fails() {
        let (_device, transport) = Switchable::new();
        let link = SharedLink::new(MuxLink::new(transport.clone()));
        link.negotiate(VersionRequest::resync(), Duration::from_secs(1))
            .unwrap();
        let local_port = link
            .with(LinkPhase::OpenSyn, 0, |link| link.begin_open(9522))
            .unwrap();
        link.with(LinkPhase::Read, local_port, |link| {
            link.drain_inbound().unwrap();
            assert_eq!(
                link.session_state(local_port),
                Some(SessionState::Established)
            );
        });
        transport.fail();
        let failure = Arc::new(AtomicBool::new(true));
        let error = link
            .complete_open_cancellable(
                local_port,
                9522,
                Duration::from_secs(1),
                Instant::now(),
                None,
                Some(&failure),
            )
            .err()
            .unwrap();
        let error = io::Error::from(error);
        assert_eq!(
            DialCancellation::from_io_error(&error),
            Some(DialCancellation::TransferFailed)
        );
        assert!(error.to_string().contains("mux port 9522"));
    }

    #[test]
    fn operator_stop_keeps_its_reason_when_terminal_cleanup_is_also_requested() {
        let stop = Arc::new(AtomicBool::new(true));
        let cleanup = Arc::new(AtomicBool::new(true));
        let error = cancellation_error(
            Some(&stop),
            Some(&cleanup),
            9523,
            "dialling",
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(
            DialCancellation::from_io_error(&error),
            Some(DialCancellation::OperatorStopped)
        );
        assert!(error.to_string().contains("mux port 9523"));
    }

    #[test]
    fn borrowed_mux_halves_carry_both_directions_while_receive_waits() {
        let (mut stream, wire, waits) = opened_thread_wire();
        let port = stream.local_port();
        let (mut reader, mut writer) = stream.split();
        std::thread::scope(|scope| {
            let receiving = scope.spawn(move || {
                let mut response = [0u8; 6];
                reader.read_exact(&mut response).unwrap();
                response
            });
            waits
                .recv_timeout(Duration::from_secs(1))
                .expect("the receive reached its off-link wait");
            writer.write_all(b"question").unwrap();
            let sent = wire.take_sent();
            assert_eq!(sent.len(), 1);
            assert_eq!(&sent[0][HEADER_LEN_V2 + TCP_HEADER_LEN..], b"question");
            let tcp = TcpHeader::decode(&sent[0][HEADER_LEN_V2..]).unwrap();
            wire.reply(peer_ack(port, tcp.sequence.wrapping_add(8)), b"answer");
            assert_eq!(receiving.join().unwrap(), *b"answer");
            writer.drain_delivery().unwrap();
        });
        drop(writer);
        assert!(stream.is_open());
        wire.take_sent();
        stream.write_all(b"owner continues").unwrap();
        let sent = wire.take_sent();
        assert_eq!(
            &sent[0][HEADER_LEN_V2 + TCP_HEADER_LEN..],
            b"owner continues"
        );
        drop(stream);
        let sent = wire.take_sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            TcpHeader::decode(&sent[0][HEADER_LEN_V2..]).unwrap().flags,
            flags::RST
        );
    }

    #[test]
    fn packet_trace_identifies_write_delivery_probe_and_ack_advance() {
        let (mut stream, wire, waits) = opened_thread_wire();
        let port = stream.local_port();
        let link = stream.link.clone();
        let (context, recorder) = super::super::packet_trace::Context::recording(91, 12);
        link.with(LinkPhase::Inspect, port, |link| {
            link.set_packet_trace(context)
        });
        let initial = link.with(LinkPhase::Inspect, port, |link| {
            link.send_state(port).unwrap().snd_una
        });
        let mut small_window = peer_ack(port, initial);
        small_window.window = 256;
        wire.reply(small_window, &[]);
        link.with(LinkPhase::Read, port, |link| link.route_available())
            .unwrap();
        recorder.drain();
        let payload = [0x5a; 512];
        std::thread::scope(|scope| {
            let writing = scope.spawn(|| stream.write_all(&payload));
            waits
                .recv_timeout(Duration::from_secs(1))
                .expect("the write parked with an outstanding flight");
            let deadline = Instant::now() + Duration::from_secs(5);
            while recorder.seen(Stage::WriteProbeReturn) == 0 {
                assert!(
                    Instant::now() < deadline,
                    "the write delivery probe executed"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            wire.reply(peer_ack(port, initial.wrapping_add(256)), &[]);
            writing.join().unwrap().unwrap();
        });
        let records = recorder.drain();
        let entered = records
            .iter()
            .find(|record| record.stage == Stage::WriteProbeStart)
            .unwrap();
        let returned = records
            .iter()
            .find(|record| record.stage == Stage::WriteProbeReturn)
            .unwrap();
        assert_eq!(entered.local_port, Some(port));
        assert_eq!(entered.before.unwrap().snd_una, initial);
        assert_eq!(entered.before.unwrap().snd_nxt, initial.wrapping_add(256));
        assert_eq!(returned.disposition, Disposition::ProbeSent);
        assert!(returned.monotonic_ns >= entered.monotonic_ns);
        let acknowledged = records
            .iter()
            .find(|record| {
                record.stage == Stage::Apply
                    && record
                        .after
                        .is_some_and(|state| state.snd_una == initial.wrapping_add(256))
            })
            .unwrap();
        assert_eq!(acknowledged.before.unwrap().snd_una, initial);
        let packets = wire.take_sent();
        let repeated: Vec<_> = packets
            .iter()
            .filter(|packet| {
                let tcp = TcpHeader::decode(&packet[HEADER_LEN_V2..]).unwrap();
                tcp.sequence == initial && packet.len() > HEADER_LEN_V2 + TCP_HEADER_LEN
            })
            .collect();
        assert!(repeated.len() >= 2);
        for packet in repeated {
            assert_eq!(&packet[HEADER_LEN_V2 + TCP_HEADER_LEN..], &payload[..256]);
        }
        wire.reply(
            peer_ack(port, initial.wrapping_add(payload.len() as u32)),
            &[],
        );
        link.with(LinkPhase::Read, port, |link| link.route_available())
            .unwrap();
        let delivered = link.with(LinkPhase::Inspect, port, |link| {
            link.send_state(port).unwrap()
        });
        assert_eq!(
            delivered.snd_una,
            initial.wrapping_add(payload.len() as u32)
        );
    }

    #[test]
    fn a_reopened_window_delivers_a_fresh_flight_in_sequence() {
        let (mut stream, wire, waits) = opened_thread_wire();
        let port = stream.local_port();
        let link = stream.link.clone();
        stream.write_all(b"first flight").unwrap();
        let first = wire.take_sent();
        let first_tcp = TcpHeader::decode(&first[0][HEADER_LEN_V2..]).unwrap();
        let first_end = first_tcp
            .sequence
            .wrapping_add(b"first flight".len() as u32);
        let mut shut = peer_ack(port, first_end);
        shut.window = 0;
        wire.reply(shut, &[]);
        link.with(LinkPhase::Read, port, |link| link.drain_inbound())
            .unwrap();

        let payload: Vec<u8> = (0..131072u32).map(|byte| byte as u8).collect();
        std::thread::scope(|scope| {
            let writing = scope.spawn(|| stream.write_all(&payload));
            waits
                .recv_timeout(Duration::from_secs(1))
                .expect("the closed window parks the writer");
            std::thread::sleep(DEFAULT_DELIVERY_PROBE_POLL + Duration::from_millis(100));
            wire.take_sent();
            let mut reopened = peer_ack(port, first_end);
            reopened.window = 131072;
            link.with(LinkPhase::Read, port, |link| {
                wire.reply(reopened, &[]);
                link.route_available().unwrap();
            });
            writing.join().unwrap().unwrap();
        });

        let mut delivered = Vec::new();
        let mut next_sequence = first_end;
        for packet in wire.take_sent() {
            let tcp = TcpHeader::decode(&packet[HEADER_LEN_V2..]).unwrap();
            let bytes = &packet[HEADER_LEN_V2 + TCP_HEADER_LEN..];
            if bytes.is_empty() {
                continue;
            }
            assert_eq!(tcp.sequence, next_sequence);
            next_sequence = next_sequence.wrapping_add(bytes.len() as u32);
            delivered.extend_from_slice(bytes);
        }
        assert_eq!(delivered, payload);
        wire.reply(peer_ack(port, next_sequence), &[]);
        link.with(LinkPhase::Read, port, |link| link.drain_inbound())
            .unwrap();
        let state = link.with(LinkPhase::Inspect, port, |link| {
            link.send_state(port).unwrap()
        });
        assert_eq!(state.snd_una, state.snd_nxt);
    }

    #[test]
    fn delivery_drain_waits_for_delayed_partial_acknowledgements() {
        let (stream, wire, waits) = opened_thread_wire();
        let mut stream = stream.with_write_timeout(Duration::from_millis(1));
        let port = stream.local_port();
        let link = stream.link.clone();
        let (_reader, mut writer) = stream.split();
        writer.write_all(b"payload").unwrap();
        let sent = wire.take_sent();
        let tcp = TcpHeader::decode(&sent[0][HEADER_LEN_V2..]).unwrap();
        let queued = writer.delivery_state().unwrap();
        assert_eq!(queued.snd_nxt.wrapping_sub(queued.snd_una), 7);
        std::thread::scope(|scope| {
            let draining = scope.spawn(move || writer.drain_delivery());
            waits
                .recv_timeout(Duration::from_secs(1))
                .expect("delivery drain reached its acknowledgement wait");
            waits.recv_timeout(Duration::from_secs(1)).expect(
                "delivery drain outlived the write policy expiry while awaiting the peer ACK",
            );
            wire.reply(peer_ack(port, tcp.sequence.wrapping_add(3)), &[]);
            link.with(LinkPhase::Read, port, |link| link.drain_inbound())
                .unwrap();
            let partial = link.with(LinkPhase::Inspect, port, |link| {
                link.send_state(port).unwrap()
            });
            assert_eq!(partial.snd_una, tcp.sequence.wrapping_add(3));
            assert_eq!(partial.snd_nxt.wrapping_sub(partial.snd_una), 4);
            waits
                .recv_timeout(Duration::from_secs(1))
                .expect("the drain continues waiting for the remaining bytes");
            wire.reply(peer_ack(port, tcp.sequence.wrapping_add(7)), &[]);
            draining.join().unwrap().unwrap();
        });
        let delivered = link.with(LinkPhase::Inspect, port, |link| {
            link.send_state(port).unwrap()
        });
        assert_eq!(delivered.snd_una, tcp.sequence.wrapping_add(7));
        assert_eq!(delivered.snd_una, delivered.snd_nxt);
    }

    #[test]
    fn delayed_ack_retransmits_the_same_payload_and_sequence() {
        let (stream, wire, waits) = opened_thread_wire();
        let port = stream.local_port();
        let (context, recorder) = super::super::packet_trace::Context::recording(91, 12);
        stream.link.with(LinkPhase::Inspect, port, |link| {
            link.set_packet_trace(context)
        });
        let mut stream = stream.with_write_timeout(Duration::from_millis(1));
        let (_reader, mut writer) = stream.split();
        let payload = b"restore image payload";
        writer.write_all(payload).unwrap();
        let mut packets = wire.take_sent();
        let first = TcpHeader::decode(&packets[0][HEADER_LEN_V2..]).unwrap();
        std::thread::scope(|scope| {
            let draining = scope.spawn(move || writer.drain_delivery());
            waits
                .recv_timeout(Duration::from_secs(1))
                .expect("delivery drain reached its acknowledgement wait");
            let deadline = Instant::now() + Duration::from_secs(5);
            while recorder.seen(Stage::DrainProbeReturn) == 0 {
                assert!(
                    Instant::now() < deadline,
                    "the drain delivery probe executed"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            packets.extend(wire.take_sent());
            wire.reply(
                peer_ack(port, first.sequence.wrapping_add(payload.len() as u32)),
                &[],
            );
            draining.join().unwrap().unwrap();
        });
        packets.extend(wire.take_sent());
        let records = recorder.drain();
        let entered = records
            .iter()
            .find(|record| record.stage == Stage::DrainProbeStart)
            .unwrap();
        let returned = records
            .iter()
            .find(|record| record.stage == Stage::DrainProbeReturn)
            .unwrap();
        assert_eq!(entered.local_port, Some(port));
        assert_eq!(entered.before.unwrap().snd_una, first.sequence);
        assert_eq!(returned.disposition, Disposition::ProbeSent);
        assert!(returned.monotonic_ns >= entered.monotonic_ns);
        let acknowledged = records
            .iter()
            .find(|record| {
                record.stage == Stage::Apply
                    && record.after.is_some_and(|state| {
                        state.snd_una == first.sequence.wrapping_add(payload.len() as u32)
                    })
            })
            .unwrap();
        assert_eq!(acknowledged.before.unwrap().snd_una, first.sequence);
        let sent_payloads: Vec<_> = packets
            .iter()
            .filter(|packet| packet.len() > HEADER_LEN_V2 + TCP_HEADER_LEN)
            .collect();
        assert!(
            sent_payloads.len() >= 2,
            "the unacknowledged payload is retried"
        );
        for packet in sent_payloads {
            let header = TcpHeader::decode(&packet[HEADER_LEN_V2..]).unwrap();
            assert_eq!(header.sequence, first.sequence);
            assert_eq!(&packet[HEADER_LEN_V2 + TCP_HEADER_LEN..], payload);
        }
    }

    #[test]
    fn delivery_drain_names_peer_reset_and_unacknowledged_bytes() {
        let (mut stream, wire, _waits) = opened_thread_wire();
        let port = stream.local_port();
        let (_reader, mut writer) = stream.split();
        writer.write_all(b"payload").unwrap();
        let sent = wire.take_sent();
        let tcp = TcpHeader::decode(&sent[0][HEADER_LEN_V2..]).unwrap();
        let mut reset = peer_ack(port, tcp.sequence);
        reset.flags = flags::RST;
        wire.reply(reset, &[]);
        let error = writer.drain_delivery().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        let text = error.to_string();
        assert!(text.contains(&format!("mux port {port}")), "{text}");
        assert!(text.contains("peer closed or reset"), "{text}");
        assert!(text.contains("7 byte(s) sent but unacknowledged"), "{text}");
    }

    #[test]
    fn delivery_drain_names_device_removal_and_unacknowledged_bytes() {
        let (mut stream, wire, _waits) = opened_thread_wire();
        let (_reader, mut writer) = stream.split();
        writer.write_all(b"payload").unwrap();
        wire.present.store(false, Ordering::Release);
        let error = writer.drain_delivery().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        let text = error.to_string();
        assert!(is_device_gone(&text), "{text}");
        assert!(text.contains("7 byte(s) sent but unacknowledged"), "{text}");
    }

    #[test]
    fn connection_cancellation_releases_a_delivery_wait_with_its_byte_counts() {
        let (mut stream, wire, waits) = opened_thread_wire();
        let cancel = Arc::new(AtomicBool::new(false));
        let (_reader, writer) = stream.split();
        let mut writer = writer.with_connection_cancel(Arc::clone(&cancel));
        writer.write_all(b"payload").unwrap();
        std::thread::scope(|scope| {
            let draining = scope.spawn(move || writer.drain_delivery());
            waits
                .recv_timeout(Duration::from_secs(1))
                .expect("delivery wait is live before cancellation");
            cancel.store(true, Ordering::Release);
            wire.notify();
            let error = draining.join().unwrap().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
            let text = error.to_string();
            assert!(text.contains(CONNECTION_CANCELLED_MARKER), "{text}");
            assert!(text.contains("7 byte(s) sent but unacknowledged"), "{text}");
        });
    }

    #[test]
    fn borrowed_halves_preserve_run_and_transfer_cancellation_attribution() {
        let (link, _device) = negotiated();
        let stop = Arc::new(AtomicBool::new(false));
        let transfer = Arc::new(AtomicBool::new(false));
        let connection = Arc::new(AtomicBool::new(true));
        let mut stream = link
            .open(62078, Duration::from_secs(1))
            .unwrap()
            .with_cancel(Arc::clone(&stop))
            .with_transfer_cancel(Arc::clone(&transfer));
        let (reader, writer) = stream.split();
        let mut reader = reader.with_connection_cancel(Arc::clone(&connection));
        let mut writer = writer.with_connection_cancel(connection);
        let local_read = reader.read(&mut [0u8; 1]).unwrap_err();
        let local_write = writer.write(b"payload").unwrap_err();
        assert!(local_read.to_string().contains(CONNECTION_CANCELLED_MARKER));
        assert!(
            local_write
                .to_string()
                .contains(CONNECTION_CANCELLED_MARKER)
        );
        transfer.store(true, Ordering::Release);
        assert_eq!(
            DialCancellation::from_io_error(&reader.read(&mut [0u8; 1]).unwrap_err()),
            Some(DialCancellation::TransferFailed)
        );
        assert_eq!(
            DialCancellation::from_io_error(&writer.drain_delivery().unwrap_err()),
            Some(DialCancellation::TransferFailed)
        );
        stop.store(true, Ordering::Release);
        assert_eq!(
            DialCancellation::from_io_error(&writer.write(b"payload").unwrap_err()),
            Some(DialCancellation::OperatorStopped)
        );
        assert_eq!(
            DialCancellation::from_io_error(&writer.drain_delivery().unwrap_err()),
            Some(DialCancellation::OperatorStopped)
        );
    }

    #[test]
    fn connection_cancellation_releases_a_blocked_receive() {
        let (mut stream, wire, waits) = opened_thread_wire();
        let cancel = Arc::new(AtomicBool::new(false));
        let (reader, _writer) = stream.split();
        let mut reader = reader.with_connection_cancel(Arc::clone(&cancel));
        std::thread::scope(|scope| {
            let receiving = scope.spawn(move || reader.read(&mut [0u8; 1]));
            waits
                .recv_timeout(Duration::from_secs(1))
                .expect("receive is live before cancellation");
            cancel.store(true, Ordering::Release);
            wire.notify();
            let error = receiving.join().unwrap().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
            assert!(error.to_string().contains(CONNECTION_CANCELLED_MARKER));
        });
    }

    #[test]
    fn connection_cancellation_releases_a_blocked_write_and_attributes_queued_bytes() {
        let (mut stream, wire, waits) = opened_thread_wire();
        let port = stream.local_port();
        let link = stream.link.clone();
        let state = link.with(LinkPhase::Inspect, port, |link| {
            link.send_state(port).unwrap()
        });
        let mut closed_window = peer_ack(port, state.snd_una);
        closed_window.window = 0;
        wire.reply(closed_window, &[]);
        let cancel = Arc::new(AtomicBool::new(false));
        let (_reader, writer) = stream.split();
        let mut writer = writer.with_connection_cancel(Arc::clone(&cancel));
        std::thread::scope(|scope| {
            let writing = scope.spawn(move || {
                let write_error = writer.write(b"payload").unwrap_err();
                let drain_error = writer.drain_delivery().unwrap_err();
                (write_error, drain_error)
            });
            waits
                .recv_timeout(Duration::from_secs(1))
                .expect("write is live before cancellation");
            let queued = link.with(LinkPhase::Inspect, port, |link| {
                link.send_state(port).unwrap()
            });
            assert_eq!(queued.pending, 7);
            cancel.store(true, Ordering::Release);
            wire.notify();
            let (write_error, drain_error) = writing.join().unwrap();
            assert_eq!(write_error.kind(), io::ErrorKind::ConnectionAborted);
            assert!(
                write_error
                    .to_string()
                    .contains(CONNECTION_CANCELLED_MARKER)
            );
            assert!(drain_error.to_string().contains("7 byte(s) queued"));
        });
    }

    #[test]
    fn additive_connection_cancellation_releases_a_parked_receive() {
        for active in 0..2 {
            let (mut stream, wire, waits) = opened_thread_wire();
            let flags = [
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
            ];
            let (reader, _writer) = stream.split();
            let mut reader = reader
                .with_connection_cancel(Arc::clone(&flags[0]))
                .with_connection_cancel(Arc::clone(&flags[1]));
            std::thread::scope(|scope| {
                let receiving = scope.spawn(move || reader.read(&mut [0u8; 1]));
                waits
                    .recv_timeout(Duration::from_secs(1))
                    .expect("receive is live before either registered flag is set");
                flags[active].store(true, Ordering::Release);
                wire.notify();
                let error = receiving.join().unwrap().unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
                assert!(
                    error.to_string().contains(CONNECTION_CANCELLED_MARKER),
                    "flag {active}: {error}"
                );
            });
        }
    }

    #[test]
    fn additive_connection_cancellation_releases_a_parked_delivery_wait() {
        for active in 0..2 {
            let (mut stream, wire, waits) = opened_thread_wire();
            let flags = [
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
            ];
            let (_reader, writer) = stream.split();
            let mut writer = writer
                .with_connection_cancel(Arc::clone(&flags[0]))
                .with_connection_cancel(Arc::clone(&flags[1]));
            writer.write_all(b"payload").unwrap();
            std::thread::scope(|scope| {
                let draining = scope.spawn(move || writer.drain_delivery());
                waits
                    .recv_timeout(Duration::from_secs(1))
                    .expect("delivery wait is live before either registered flag is set");
                flags[active].store(true, Ordering::Release);
                wire.notify();
                let error = draining.join().unwrap().unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
                let text = error.to_string();
                assert!(
                    text.contains(CONNECTION_CANCELLED_MARKER),
                    "flag {active}: {text}"
                );
                assert!(text.contains("7 byte(s) sent but unacknowledged"), "{text}");
            });
        }
    }
}
