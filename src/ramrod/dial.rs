use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use super::client::RAMROD_PORT;

pub const DEFAULT_HOST_CONNECT_WINDOW: Duration = Duration::from_secs(120);

pub const HOST_TIMEOUT_NVRAM_VARIABLE: &str = "restored-host-timeout";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialCancellation {
    OperatorStopped,
    TransferFailed,
}

impl DialCancellation {
    pub fn from_io_error(error: &io::Error) -> Option<Self> {
        let mut source = error.get_ref()? as &(dyn std::error::Error + 'static);
        loop {
            if let Some(reason) = source.downcast_ref::<Self>() {
                return Some(*reason);
            }
            source = source.source()?;
        }
    }
}

impl fmt::Display for DialCancellation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OperatorStopped => f.write_str("restore-run-stopped: the operator stopped the restore run"),
            Self::TransferFailed => f.write_str("restore-transfer-cancelled: a restore transfer failed; this mux operation was cancelled"),
        }
    }
}

impl std::error::Error for DialCancellation {}

pub trait ShutdownWrite {
    fn shutdown_write(&mut self) -> io::Result<()>;
}

impl ShutdownWrite for TcpStream {
    fn shutdown_write(&mut self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

pub trait GuestDialer {
    type Stream: Read + Write;

    fn dial(&mut self, port: u16, timeout: Duration) -> io::Result<Self::Stream>;
}

pub trait GuestConnector {
    fn connect_to_guest(&self, port: u16, timeout: Duration) -> io::Result<TcpStream>;
}

impl<T> GuestConnector for std::sync::Arc<T>
where
    T: GuestConnector + ?Sized,
{
    fn connect_to_guest(&self, port: u16, timeout: Duration) -> io::Result<TcpStream> {
        self.as_ref().connect_to_guest(port, timeout)
    }
}

#[derive(Clone, Debug)]
pub struct ConnectorDialer<C> {
    connector: C,
}

impl<C> ConnectorDialer<C> {
    pub fn new(connector: C) -> Self {
        Self { connector }
    }

    pub fn into_inner(self) -> C {
        self.connector
    }
}

impl<C> GuestDialer for ConnectorDialer<C>
where
    C: GuestConnector,
{
    type Stream = TcpStream;

    fn dial(&mut self, port: u16, timeout: Duration) -> io::Result<Self::Stream> {
        let stream = self.connector.connect_to_guest(port, timeout)?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }
}

pub trait Clock {
    fn now(&self) -> Instant;
    fn sleep(&mut self, duration: Duration);
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DialPlan {
    pub port: u16,
    pub attempt_timeout: Duration,
    pub retry_interval: Duration,
    pub window: Duration,
}

impl DialPlan {
    pub const fn default_for_ramrod() -> Self {
        Self {
            port: RAMROD_PORT,
            attempt_timeout: Duration::from_secs(2),
            retry_interval: Duration::from_millis(250),
            window: DEFAULT_HOST_CONNECT_WINDOW,
        }
    }

    pub const fn on_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub const fn with_window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }
}

impl Default for DialPlan {
    fn default() -> Self {
        Self::default_for_ramrod()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DialOutcome<S> {
    pub stream: S,
    pub attempts: u32,
    pub elapsed: Duration,
}

pub fn dial_until<D, C>(
    dialer: &mut D,
    plan: DialPlan,
    clock: &mut C,
) -> Result<DialOutcome<D::Stream>, DialError>
where
    D: GuestDialer,
    C: Clock,
{
    let began = clock.now();
    let mut attempts = 0u32;
    let mut last_error: Option<io::Error> = None;

    loop {
        let elapsed = clock.now().saturating_duration_since(began);
        if elapsed >= plan.window {
            return Err(DialError::WindowClosed {
                port: plan.port,
                attempts,
                window: plan.window,
                last_error,
            });
        }

        let remaining = plan.window - elapsed;
        let attempt_timeout = plan.attempt_timeout.min(remaining);
        attempts += 1;
        match dialer.dial(plan.port, attempt_timeout) {
            Ok(stream) => {
                return Ok(DialOutcome {
                    stream,
                    attempts,
                    elapsed: clock.now().saturating_duration_since(began),
                });
            }
            Err(error) if DialCancellation::from_io_error(&error).is_some() => {
                return Err(DialError::Cancelled {
                    port: plan.port,
                    attempts,
                    source: error,
                });
            }
            Err(error) => last_error = Some(error),
        }

        let elapsed = clock.now().saturating_duration_since(began);
        if elapsed >= plan.window {
            return Err(DialError::WindowClosed {
                port: plan.port,
                attempts,
                window: plan.window,
                last_error,
            });
        }
        let remaining = plan.window - elapsed;
        clock.sleep(plan.retry_interval.min(remaining));
    }
}

#[derive(Debug)]
pub enum DialError {
    Cancelled {
        port: u16,
        attempts: u32,
        source: io::Error,
    },
    WindowClosed {
        port: u16,
        attempts: u32,
        window: Duration,
        last_error: Option<io::Error>,
    },
}

impl fmt::Display for DialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled {
                port,
                attempts,
                source,
            } => write!(
                f,
                "guest port {port} dial cancelled after {attempts} attempt(s): {source}"
            ),
            Self::WindowClosed {
                port,
                attempts,
                window,
                last_error,
            } => {
                write!(
                    f,
                    "guest port {port} did not answer in {attempts} attempts over {window:?}"
                )?;
                match last_error {
                    Some(error) => write!(f, "; last failure: {error}"),
                    None => Ok(()),
                }
            }
        }
    }
}

impl std::error::Error for DialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cancelled { source, .. } => source
                .get_ref()
                .map(|error| error as &(dyn std::error::Error + 'static))
                .or(Some(source)),
            Self::WindowClosed { last_error, .. } => last_error
                .as_ref()
                .map(|error| error as &(dyn std::error::Error + 'static)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    #[test]
    fn tcp_write_shutdown_delivers_peer_eof_and_preserves_the_read_half() {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            socket.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"request");
            socket.write_all(b"reply").unwrap();
        });
        let mut socket = TcpStream::connect(address).unwrap();
        socket.write_all(b"request").unwrap();
        socket.shutdown_write().unwrap();
        let mut reply = Vec::new();
        socket.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"reply");
        peer.join().unwrap();
    }

    #[derive(Clone)]
    struct Virtual {
        base: Instant,
        elapsed: Rc<Cell<Duration>>,
        slept: Rc<RefCell<Vec<Duration>>>,
    }

    impl Virtual {
        fn new() -> Self {
            Self {
                base: Instant::now(),
                elapsed: Rc::new(Cell::new(Duration::ZERO)),
                slept: Rc::new(RefCell::new(Vec::new())),
            }
        }

        fn advance(&self, by: Duration) {
            self.elapsed.set(self.elapsed.get() + by);
        }

        fn sleeps(&self) -> Vec<Duration> {
            self.slept.borrow().clone()
        }
    }

    impl Clock for Virtual {
        fn now(&self) -> Instant {
            self.base + self.elapsed.get()
        }
        fn sleep(&mut self, duration: Duration) {
            self.slept.borrow_mut().push(duration);
            self.advance(duration);
        }
    }

    struct FlakyDialer {
        refusals_remaining: u32,
        attempt_cost: Duration,
        time: Virtual,
        ports: Vec<u16>,
        timeouts: Vec<Duration>,
    }

    impl FlakyDialer {
        fn new(time: &Virtual, refusals: u32, attempt_cost: Duration) -> Self {
            Self {
                refusals_remaining: refusals,
                attempt_cost,
                time: time.clone(),
                ports: Vec::new(),
                timeouts: Vec::new(),
            }
        }
    }

    impl GuestDialer for FlakyDialer {
        type Stream = io::Cursor<Vec<u8>>;

        fn dial(&mut self, port: u16, timeout: Duration) -> io::Result<Self::Stream> {
            self.ports.push(port);
            self.timeouts.push(timeout);
            self.time.advance(self.attempt_cost);
            if self.refusals_remaining > 0 {
                self.refusals_remaining -= 1;
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "connection to guest port 62078 failed: refused",
                ));
            }
            Ok(io::Cursor::new(Vec::new()))
        }
    }

    #[test]
    fn the_default_plan_targets_the_port_and_window_the_guest_actually_uses() {
        let plan = DialPlan::default();
        assert_eq!(plan.port, RAMROD_PORT);
        assert_eq!(plan.port, 62078);
        assert_eq!(plan.window, DEFAULT_HOST_CONNECT_WINDOW);
        assert_eq!(plan.window, Duration::from_secs(120));
        assert!(
            plan.attempt_timeout < plan.window,
            "one stalled attempt must not be able to consume the window"
        );
        assert!(plan.retry_interval < plan.attempt_timeout);
    }

    #[test]
    fn a_plan_can_be_retargeted_without_losing_its_shape() {
        let plan = DialPlan::default()
            .on_port(12345)
            .with_window(Duration::from_secs(5));
        assert_eq!(plan.port, 12345);
        assert_eq!(plan.window, Duration::from_secs(5));
        assert_eq!(plan.attempt_timeout, DialPlan::default().attempt_timeout);
        assert_eq!(plan.retry_interval, DialPlan::default().retry_interval);
    }

    #[test]
    fn a_first_attempt_that_succeeds_costs_one_attempt_and_no_sleep() {
        let time = Virtual::new();
        let mut clock = time.clone();
        let mut dialer = FlakyDialer::new(&time, 0, Duration::ZERO);
        let outcome = dial_until(&mut dialer, DialPlan::default(), &mut clock).unwrap();
        assert_eq!(outcome.attempts, 1);
        assert!(time.sleeps().is_empty(), "no retry, so no sleep");
        assert_eq!(dialer.ports, vec![RAMROD_PORT]);
    }

    #[test]
    fn refusals_are_retried_because_a_listener_that_is_not_up_yet_refuses() {
        let time = Virtual::new();
        let mut clock = time.clone();
        let mut dialer = FlakyDialer::new(&time, 4, Duration::ZERO);
        let outcome = dial_until(&mut dialer, DialPlan::default(), &mut clock).unwrap();
        assert_eq!(outcome.attempts, 5);
        assert_eq!(time.sleeps().len(), 4);
        assert!(
            time.sleeps()
                .iter()
                .all(|slept| *slept == Duration::from_millis(250))
        );
    }

    #[test]
    fn a_dial_that_takes_time_still_reports_how_long_the_loop_ran() {
        let time = Virtual::new();
        let mut clock = time.clone();
        let mut dialer = FlakyDialer::new(&time, 2, Duration::from_millis(500));
        let outcome = dial_until(&mut dialer, DialPlan::default(), &mut clock).unwrap();
        assert_eq!(outcome.attempts, 3);
        assert_eq!(outcome.elapsed, Duration::from_millis(2000));
    }

    #[test]
    fn the_loop_stops_at_the_window_and_reports_the_last_failure() {
        let time = Virtual::new();
        let mut clock = time.clone();
        let mut dialer = FlakyDialer::new(&time, u32::MAX, Duration::from_millis(750));
        let plan = DialPlan::default().with_window(Duration::from_secs(10));
        match dial_until(&mut dialer, plan, &mut clock) {
            Err(DialError::WindowClosed {
                port,
                attempts,
                window,
                last_error,
            }) => {
                assert_eq!(port, RAMROD_PORT);
                assert_eq!(window, Duration::from_secs(10));
                assert!(attempts > 1, "the loop must have retried");
                let error = last_error.expect("the last failure is carried out");
                assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
            }
            other => panic!("expected the window to close, got {other:?}"),
        }
        assert!(!time.sleeps().is_empty(), "a retrying loop sleeps");
    }

    #[test]
    fn the_loop_never_runs_past_the_window() {
        let time = Virtual::new();
        let mut clock = time.clone();
        let mut dialer = FlakyDialer::new(&time, u32::MAX, Duration::from_millis(750));
        let window = Duration::from_secs(10);
        let began = clock.now();
        let _ = dial_until(
            &mut dialer,
            DialPlan::default().with_window(window),
            &mut clock,
        );
        let ran_for = clock.now().saturating_duration_since(began);
        assert!(
            ran_for <= window,
            "the loop ran {ran_for:?}, past the {window:?} window the guest allows"
        );
    }

    #[test]
    fn no_attempt_is_given_a_timeout_that_outlives_the_window() {
        let time = Virtual::new();
        let mut clock = time.clone();
        let mut dialer = FlakyDialer::new(&time, u32::MAX, Duration::from_millis(400));
        let window = Duration::from_secs(3);
        let _ = dial_until(
            &mut dialer,
            DialPlan::default().with_window(window),
            &mut clock,
        );

        assert!(!dialer.timeouts.is_empty());
        for timeout in &dialer.timeouts {
            assert!(
                *timeout <= DialPlan::default().attempt_timeout,
                "an attempt exceeded the configured attempt timeout"
            );
        }
        let last = dialer.timeouts.last().copied().unwrap();
        assert!(
            last <= window,
            "the final attempt was allowed to outlive the window"
        );
    }

    #[test]
    fn a_zero_window_makes_no_attempt_at_all() {
        let time = Virtual::new();
        let mut clock = time.clone();
        let mut dialer = FlakyDialer::new(&time, 0, Duration::ZERO);
        let plan = DialPlan::default().with_window(Duration::ZERO);
        match dial_until(&mut dialer, plan, &mut clock) {
            Err(DialError::WindowClosed { attempts, .. }) => assert_eq!(attempts, 0),
            other => panic!("expected the window to be closed already, got {other:?}"),
        }
        assert!(dialer.ports.is_empty(), "nothing may have been dialled");
    }

    #[test]
    fn a_non_default_port_is_the_one_dialled() {
        let time = Virtual::new();
        let mut clock = time.clone();
        let mut dialer = FlakyDialer::new(&time, 0, Duration::ZERO);
        let plan = DialPlan::default().on_port(12345);
        dial_until(&mut dialer, plan, &mut clock).unwrap();
        assert_eq!(dialer.ports, vec![12345]);
    }

    #[test]
    fn the_window_closed_message_names_the_port_the_attempts_and_the_cause() {
        let error = DialError::WindowClosed {
            port: RAMROD_PORT,
            attempts: 37,
            window: Duration::from_secs(120),
            last_error: Some(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "guest refused",
            )),
        };
        let rendered = error.to_string();
        assert!(rendered.contains("62078"), "{rendered}");
        assert!(rendered.contains("37 attempts"), "{rendered}");
        assert!(rendered.contains("guest refused"), "{rendered}");
    }
    #[test]
    fn explicit_transfer_cancellation_names_the_port_and_ends_the_dial() {
        struct CancelledDialer {
            calls: u32,
        }
        impl GuestDialer for CancelledDialer {
            type Stream = std::io::Cursor<Vec<u8>>;
            fn dial(&mut self, _port: u16, _timeout: Duration) -> io::Result<Self::Stream> {
                self.calls += 1;
                Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    DialCancellation::TransferFailed,
                ))
            }
        }
        let mut dialer = CancelledDialer { calls: 0 };
        let mut clock = Virtual::new();
        let error =
            dial_until(&mut dialer, DialPlan::default().on_port(9511), &mut clock).unwrap_err();
        match error {
            DialError::Cancelled {
                port,
                attempts,
                source,
            } => {
                assert_eq!(port, 9511);
                assert_eq!(attempts, 1);
                assert_eq!(
                    source.get_ref().unwrap().downcast_ref::<DialCancellation>(),
                    Some(&DialCancellation::TransferFailed)
                );
            }
            other => panic!("expected an attributed cancellation, got {other}"),
        }
        assert_eq!(dialer.calls, 1);
    }

    #[test]
    fn cancelled_dial_preserves_its_reason_through_the_error_source_chain() {
        for reason in [
            DialCancellation::OperatorStopped,
            DialCancellation::TransferFailed,
        ] {
            let dial = DialError::Cancelled {
                port: 9511,
                attempts: 1,
                source: io::Error::new(io::ErrorKind::ConnectionAborted, reason),
            };
            let source = std::error::Error::source(&dial).unwrap();
            assert_eq!(source.downcast_ref::<DialCancellation>(), Some(&reason));
            let wrapped = io::Error::new(io::ErrorKind::ConnectionAborted, dial);
            assert_eq!(DialCancellation::from_io_error(&wrapped), Some(reason));
        }
    }

    #[test]
    fn an_ordinary_interrupted_dial_is_retried_until_the_guest_accepts() {
        struct InterruptedDialer {
            calls: u32,
        }
        impl GuestDialer for InterruptedDialer {
            type Stream = std::io::Cursor<Vec<u8>>;
            fn dial(&mut self, _port: u16, _timeout: Duration) -> io::Result<Self::Stream> {
                self.calls += 1;
                if self.calls == 1 {
                    Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "transient transport interruption",
                    ))
                } else {
                    Ok(std::io::Cursor::new(vec![7]))
                }
            }
        }
        let mut dialer = InterruptedDialer { calls: 0 };
        let mut clock = Virtual::new();
        let accepted =
            dial_until(&mut dialer, DialPlan::default().on_port(9512), &mut clock).unwrap();
        assert_eq!(accepted.attempts, 2);
        assert_eq!(accepted.stream.into_inner(), vec![7]);
        assert_eq!(dialer.calls, 2);
    }
}
