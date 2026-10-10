use std::collections::HashMap;
use std::future::Future;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::usbmux::{BulkTransport, MuxWriteHalf};

use super::SocksRequest;

pub(super) const IO_POLL: Duration = Duration::from_millis(100);

#[derive(Clone)]
pub(super) struct Cancellation {
    pub local: Arc<AtomicBool>,
    run: Arc<AtomicBool>,
    proxy: Arc<AtomicBool>,
}

impl Cancellation {
    pub fn new(run: Arc<AtomicBool>, proxy: Arc<AtomicBool>) -> Self {
        Self {
            local: Arc::new(AtomicBool::new(false)),
            run,
            proxy,
        }
    }

    fn check(&self) -> io::Result<()> {
        let reason = if self.run.load(Ordering::Relaxed) {
            Some("fdr-forward-run-stopped")
        } else if self.proxy.load(Ordering::Relaxed) {
            Some("fdr-forward-proxy-stopped")
        } else if self.local.load(Ordering::Relaxed) {
            Some("fdr-forward-connection-cancelled")
        } else {
            None
        };
        match reason {
            Some(reason) => Err(io::Error::new(io::ErrorKind::Interrupted, reason)),
            None => Ok(()),
        }
    }

    fn abort(&self) {
        self.local.store(true, Ordering::Relaxed);
    }
}

pub(super) fn authorize(request: &SocksRequest) -> io::Result<String> {
    if request.port != 443 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "fdr-vendor-port-refused: HTTPS port 443 required",
        ));
    }
    let host = &request.host;
    if host.parse::<IpAddr>().is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "fdr-vendor-ip-literal-refused: DNS destination required",
        ));
    }
    let name = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if name.len() > 253
        || name.is_empty()
        || !name.is_ascii()
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "fdr-vendor-dns-name-refused: malformed DNS destination",
        ));
    }
    if name != "apple.com" && !name.ends_with(".apple.com") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "fdr-vendor-domain-refused: destination must be at the apple.com label boundary",
        ));
    }
    Ok(name)
}

fn public_ipv4(v4: Ipv4Addr) -> bool {
    let [a, b, c, d] = v4.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192
            && (b == 168
                || (b == 0 && (c == 2 || (c == 0 && d != 9 && d != 10)))
                || (b == 88 && c == 99)))
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113))
}

fn public_ipv6(v6: Ipv6Addr) -> bool {
    let segments = v6.segments();
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        // The well-known NAT64 prefix can reach only an approved embedded IPv4 address.
        let octets = v6.octets();
        return public_ipv4(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    if (segments[0] & 0xe000) != 0x2000
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || segments[0] == 0x2002
        || (segments[0] == 0x3fff && (segments[1] & 0xf000) == 0)
    {
        return false;
    }
    if segments[0] == 0x2001 && segments[1] < 0x0200 {
        return segments[1] == 3
            || (segments[1] == 4 && segments[2] == 0x112)
            || (segments[1] == 1
                && segments[2..7] == [0, 0, 0, 0, 0]
                && matches!(segments[7], 1..=3))
            || matches!(segments[1] & 0xfff0, 0x20..=0x30);
    }
    true
}

fn public_address(address: SocketAddr) -> io::Result<SocketAddr> {
    if matches!(address, SocketAddr::V6(v6) if v6.scope_id() != 0) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "fdr-vendor-address-refused: DNS candidate {address} carries an interface scope"
            ),
        ));
    }
    let address = match address {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => SocketAddr::V6(v6),
        },
        v4 => v4,
    };
    let public = match address.ip() {
        IpAddr::V4(v4) => public_ipv4(v4),
        IpAddr::V6(v6) => public_ipv6(v6),
    };
    if public && address.port() == 443 {
        Ok(address)
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "fdr-vendor-address-refused: DNS candidate {address} is not public unicast on port 443"
            ),
        ))
    }
}

async fn cancellable<F: Future<Output = io::Result<O>>, O>(
    operation: F,
    cancel: &Cancellation,
) -> io::Result<O> {
    tokio::pin!(operation);
    loop {
        cancel.check()?;
        tokio::select! {
            result = &mut operation => {
                cancel.check()?;
                return result;
            }
            _ = tokio::time::sleep(IO_POLL) => {}
        }
    }
}

async fn connect_candidates_with<F, C>(
    candidates: Vec<SocketAddr>,
    cancel: &Cancellation,
    connector: C,
) -> io::Result<tokio::net::TcpStream>
where
    F: Future<Output = io::Result<tokio::net::TcpStream>> + Send + 'static,
    C: Fn(SocketAddr) -> F,
{
    cancel.check()?;
    let mut attempts = tokio::task::JoinSet::new();
    let mut addresses = HashMap::new();
    for address in candidates {
        let handle = attempts.spawn(connector(address));
        addresses.insert(handle.id(), address);
    }
    let mut failures = Vec::new();
    let result = loop {
        let completed =
            match cancellable(async { Ok(attempts.join_next_with_id().await) }, cancel).await {
                Ok(completed) => completed,
                Err(error) => break Err(error),
            };
        match completed {
            Some(Ok((_, Ok(stream)))) => break Ok(stream),
            Some(Ok((id, Err(error)))) => {
                let address = addresses
                    .get(&id)
                    .map(ToString::to_string)
                    .unwrap_or_else(|| format!("candidate-attribution-unavailable task={id}"));
                failures.push(format!("{address}: {error}"));
            }
            Some(Err(error)) => {
                let address = addresses
                    .get(&error.id())
                    .map(ToString::to_string)
                    .unwrap_or_else(|| {
                        format!("candidate-attribution-unavailable task={}", error.id())
                    });
                failures.push(format!("{address}: {error}"));
            }
            None => {
                break Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("fdr-vendor-connect-failed: {}", failures.join("; ")),
                ));
            }
        }
    };
    // Join every cancelled loser before handing the winning socket to the forwarding owner.
    attempts.shutdown().await;
    result
}

fn resolve_and_connect(name: &str, cancel: &Cancellation) -> io::Result<TcpStream> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        // An absolute DNS name prevents resolver search suffixes from changing the destination.
        let absolute = format!("{name}.");
        let resolved = cancellable(tokio::net::lookup_host((absolute.as_str(), 443)), cancel)
            .await
            .map_err(|error| {
                io::Error::new(error.kind(), format!("fdr-vendor-dns-failed: {error}"))
            })?;
        let mut candidates = Vec::new();
        for address in resolved {
            let address = public_address(address)?;
            if !candidates.contains(&address) {
                candidates.push(address);
            }
        }
        if candidates.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "fdr-vendor-dns-empty: resolver returned no public candidates",
            ));
        }
        connect_candidates_with(candidates, cancel, |address| {
            tokio::net::TcpStream::connect(address)
        })
        .await?
        .into_std()
    });
    // Cancellation drops the request future; an OS DNS call already running can finish in the background.
    runtime.shutdown_background();
    result
}

fn connect_with<F>(
    request: &SocksRequest,
    cancel: &Cancellation,
    connector: F,
) -> io::Result<(String, TcpStream)>
where
    F: FnOnce(&str, &Cancellation) -> io::Result<TcpStream>,
{
    let name = authorize(request)?;
    cancel.check()?;
    let stream = connector(&name, cancel)?;
    cancel.check()?;
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(IO_POLL))?;
    stream.set_write_timeout(Some(IO_POLL))?;
    Ok((name, stream))
}

pub(super) fn connect(
    request: &SocksRequest,
    cancel: &Cancellation,
) -> io::Result<(String, TcpStream)> {
    connect_with(request, cancel, resolve_and_connect)
}

pub(super) trait DeliveryWriter: Write {
    fn drain_delivery(&mut self) -> io::Result<()>;
    fn delivery_state(&self) -> Option<(usize, u32)>;
}

impl<T: BulkTransport> DeliveryWriter for MuxWriteHalf<'_, T> {
    fn drain_delivery(&mut self) -> io::Result<()> {
        MuxWriteHalf::drain_delivery(self)
    }

    fn delivery_state(&self) -> Option<(usize, u32)> {
        MuxWriteHalf::delivery_state(self)
            .map(|state| (state.pending, state.snd_nxt.wrapping_sub(state.snd_una)))
    }
}

#[derive(Debug)]
pub(super) struct PumpOutcome {
    pub direction: &'static str,
    pub read_bytes: u64,
    pub written_bytes: u64,
    pub error: Option<io::Error>,
    pub delivery_state: Option<(usize, u32)>,
    pub drained: bool,
    pub completed: bool,
    pub read_progress: ProgressKnowledge,
    pub write_progress: ProgressKnowledge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProgressKnowledge {
    Known,
    Unknown,
}

impl ProgressKnowledge {
    pub fn label(self) -> &'static str {
        match self {
            Self::Known => "known",
            Self::Unknown => "unknown",
        }
    }
}

impl PumpOutcome {
    fn new(direction: &'static str) -> Self {
        Self {
            direction,
            read_bytes: 0,
            written_bytes: 0,
            error: None,
            delivery_state: None,
            drained: false,
            completed: false,
            read_progress: ProgressKnowledge::Known,
            write_progress: ProgressKnowledge::Known,
        }
    }

    fn fail(mut self, error: io::Error, cancel: &Cancellation) -> Self {
        self.error = Some(error);
        self.completed = false;
        cancel.abort();
        self
    }
}

fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IoOrigin {
    Tcp,
    Mux,
}

#[derive(Clone, Copy)]
struct CopyOrigins {
    read: IoOrigin,
    write: IoOrigin,
}

#[derive(Debug)]
struct MuxProgressError {
    operation: &'static str,
    cause: io::Error,
}

impl std::fmt::Display for MuxProgressError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "fdr-forward-mux-{}-failed: progress=unknown; {}",
            self.operation, self.cause
        )
    }
}

impl std::error::Error for MuxProgressError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

fn mux_progress_error(operation: &'static str, cause: io::Error) -> io::Error {
    io::Error::new(cause.kind(), MuxProgressError { operation, cause })
}

fn copy_bytes<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    cancel: &Cancellation,
    outcome: &mut PumpOutcome,
    origins: CopyOrigins,
) -> io::Result<()> {
    let mut buffer = [0u8; 32 * 1024];
    loop {
        cancel.check()?;
        let count = match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(count) => count,
            Err(error) if origins.read == IoOrigin::Tcp && retryable(&error) => continue,
            Err(error) if origins.read == IoOrigin::Mux => {
                outcome.read_progress = ProgressKnowledge::Unknown;
                return Err(mux_progress_error("read", error));
            }
            Err(error) => return Err(error),
        };
        outcome.read_bytes += count as u64;
        let mut written = 0;
        while written < count {
            cancel.check()?;
            match writer.write(&buffer[written..count]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "fdr-forward-write-zero",
                    ));
                }
                Ok(count) => {
                    written += count;
                    outcome.written_bytes += count as u64;
                }
                Err(error) if origins.write == IoOrigin::Tcp && retryable(&error) => continue,
                Err(error) if origins.write == IoOrigin::Mux => {
                    outcome.write_progress = ProgressKnowledge::Unknown;
                    return Err(mux_progress_error("write", error));
                }
                Err(error) => return Err(error),
            }
        }
    }
}

fn pump_result(
    result: std::thread::Result<io::Result<()>>,
    mut outcome: PumpOutcome,
    cancel: &Cancellation,
) -> PumpOutcome {
    match result {
        Ok(Ok(())) => {
            outcome.completed = true;
            outcome
        }
        Ok(Err(error)) => outcome.fail(error, cancel),
        Err(_) => {
            outcome.read_progress = ProgressKnowledge::Unknown;
            outcome.write_progress = ProgressKnowledge::Unknown;
            outcome.fail(io::Error::other("fdr-forward-pump-panicked"), cancel)
        }
    }
}

fn report_completion<F: Fn(&PumpOutcome)>(
    mut outcome: PumpOutcome,
    cancel: &Cancellation,
    completed: &F,
) -> PumpOutcome {
    if catch_unwind(AssertUnwindSafe(|| completed(&outcome))).is_err() {
        cancel.abort();
        outcome.completed = false;
        if outcome.error.is_none() {
            outcome.error = Some(io::Error::other("fdr-forward-report-panicked"));
        }
    }
    outcome
}

pub(super) fn forward<R, W, F>(
    mut guest_reader: R,
    mut guest_writer: W,
    socket: TcpStream,
    cancel: Cancellation,
    completed: F,
) -> io::Result<(PumpOutcome, PumpOutcome)>
where
    R: Read + Send,
    W: DeliveryWriter + Send,
    F: Fn(&PumpOutcome) + Sync,
{
    let mut upstream = socket.try_clone()?;
    let mut downstream = socket;
    Ok(thread::scope(|scope| {
        let upload = scope.spawn(|| {
            let mut outcome = PumpOutcome::new("guest-to-vendor");
            let result = catch_unwind(AssertUnwindSafe(|| {
                copy_bytes(
                    &mut guest_reader,
                    &mut upstream,
                    &cancel,
                    &mut outcome,
                    CopyOrigins {
                        read: IoOrigin::Mux,
                        write: IoOrigin::Tcp,
                    },
                )?;
                upstream.shutdown(Shutdown::Write)
            }));
            let outcome = pump_result(result, outcome, &cancel);
            report_completion(outcome, &cancel, &completed)
        });
        let download = scope.spawn(|| {
            let mut outcome = PumpOutcome::new("vendor-to-guest");
            let result = catch_unwind(AssertUnwindSafe(|| {
                copy_bytes(
                    &mut downstream,
                    &mut guest_writer,
                    &cancel,
                    &mut outcome,
                    CopyOrigins {
                        read: IoOrigin::Tcp,
                        write: IoOrigin::Mux,
                    },
                )?;
                guest_writer.drain_delivery()?;
                outcome.drained = true;
                Ok(())
            }));
            let mut outcome = pump_result(result, outcome, &cancel);
            outcome.delivery_state = guest_writer.delivery_state();
            report_completion(outcome, &cancel, &completed)
        });
        let uploaded = upload.join().unwrap_or_else(|_| {
            PumpOutcome::new("guest-to-vendor").fail(
                io::Error::other("fdr-forward-upload-report-panicked: byte accounting unavailable"),
                &cancel,
            )
        });
        let downloaded = download.join().unwrap_or_else(|_| {
            PumpOutcome::new("vendor-to-guest").fail(
                io::Error::other(
                    "fdr-forward-download-report-panicked: byte accounting unavailable",
                ),
                &cancel,
            )
        });
        (uploaded, downloaded)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::{Barrier, Mutex, mpsc};

    const TEST_GUARD: Duration = Duration::from_secs(10);

    fn request(host: &str, port: u16) -> SocksRequest {
        SocksRequest {
            version: 5,
            host: host.to_string(),
            port,
        }
    }

    fn cancellation() -> Cancellation {
        Cancellation::new(
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
    }

    fn test_socket(stream: &TcpStream) {
        stream
            .set_read_timeout(Some(TEST_GUARD))
            .expect("test read failure guard");
        stream
            .set_write_timeout(Some(TEST_GUARD))
            .expect("test write failure guard");
    }

    fn pair() -> (TcpStream, TcpStream) {
        let listener =
            TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("loopback listener");
        let client = TcpStream::connect(listener.local_addr().expect("listener address"))
            .expect("loopback client");
        let (server, _) = listener.accept().expect("loopback server");
        test_socket(&client);
        test_socket(&server);
        (client, server)
    }

    fn authorized_pair(cancel: &Cancellation) -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("test-only loopback listener");
        let address = listener.local_addr().expect("listener address");
        let (name, client) = connect_with(&request("GG.Apple.COM.", 443), cancel, |name, _| {
            assert_eq!(name, "gg.apple.com");
            TcpStream::connect(address)
        })
        .expect("authorized request through injected loopback connector");
        assert_eq!(name, "gg.apple.com");
        let (server, _) = listener.accept().expect("loopback vendor peer");
        test_socket(&server);
        (client, server)
    }

    struct ShortReader {
        stream: TcpStream,
        entered: Option<mpsc::Sender<()>>,
        cancel: Option<Cancellation>,
    }

    impl Read for ShortReader {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if let Some(entered) = self.entered.take() {
                let _ = entered.send(());
            }
            let take = out.len().min(41);
            loop {
                if let Some(cancel) = &self.cancel {
                    cancel.check()?;
                }
                match self.stream.read(&mut out[..take]) {
                    Err(error) if self.cancel.is_some() && retryable(&error) => continue,
                    result => return result,
                }
            }
        }
    }

    struct ShortWriter {
        stream: TcpStream,
        calls: usize,
        accepted: u64,
        delivered: Option<mpsc::Receiver<()>>,
        entered: Option<mpsc::Sender<()>>,
    }

    impl ShortWriter {
        fn new(stream: TcpStream, delivered: Option<mpsc::Receiver<()>>) -> Self {
            Self {
                stream,
                calls: 0,
                accepted: 0,
                delivered,
                entered: None,
            }
        }
    }

    impl Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls.is_multiple_of(17) {
                thread::sleep(Duration::from_millis(1));
            }
            let written = self.stream.write(&bytes[..bytes.len().min(37)])?;
            self.accepted += written as u64;
            if let Some(entered) = self.entered.take() {
                let _ = entered.send(());
            }
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.stream.flush()
        }
    }

    impl DeliveryWriter for ShortWriter {
        fn drain_delivery(&mut self) -> io::Result<()> {
            self.flush()?;
            if let Some(delivered) = self.delivered.take() {
                delivered.recv_timeout(TEST_GUARD).map_err(|error| {
                    io::Error::other(format!("test peer delivery acknowledgement: {error}"))
                })?;
            }
            Ok(())
        }

        fn delivery_state(&self) -> Option<(usize, u32)> {
            None
        }
    }

    fn payload(length: usize, seed: u8) -> Vec<u8> {
        (0..length)
            .map(|index| (index as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    #[test]
    fn stock_fdr_dns_destinations_are_authorized_and_canonicalized() {
        for host in [
            "skl.apple.com",
            "gg.apple.com",
            "ig.apple.com",
            "service.gg.apple.com",
            "apple.com",
        ] {
            assert_eq!(
                authorize(&request(host, 443)).expect("vendor HTTPS authorization"),
                host
            );
        }
        assert_eq!(
            authorize(&request("GG.Apple.COM.", 443)).expect("absolute case-insensitive DNS name"),
            "gg.apple.com"
        );
    }

    #[test]
    fn unsupported_destinations_produce_named_refusals() {
        for (host, port, reason) in [
            ("gg.apple.com", 80, "fdr-vendor-port-refused"),
            ("17.253.144.10", 443, "fdr-vendor-ip-literal-refused"),
            ("::ffff:17.253.144.10", 443, "fdr-vendor-ip-literal-refused"),
            ("gg.apple.com.example", 443, "fdr-vendor-domain-refused"),
            ("notapple.com", 443, "fdr-vendor-domain-refused"),
            ("gg..apple.com", 443, "fdr-vendor-dns-name-refused"),
            ("-gg.apple.com", 443, "fdr-vendor-dns-name-refused"),
            ("gg.apple.com..", 443, "fdr-vendor-dns-name-refused"),
            ("gg\0.apple.com", 443, "fdr-vendor-dns-name-refused"),
            ("gg\u{fffd}.apple.com", 443, "fdr-vendor-dns-name-refused"),
        ] {
            let target = request(host, port);
            let error = authorize(&target).expect_err("named destination refusal");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(error.to_string().starts_with(reason), "{error}");
            let mut reply = Vec::new();
            super::super::refuse_socks(&mut reply, &target).expect("SOCKS refusal reply");
            assert_eq!(reply, [5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);
        }
    }

    #[test]
    fn public_dns_candidates_preserve_numeric_addresses_and_normalize_mapped_ipv4() {
        for address in [
            "17.253.144.10:443",
            "192.0.0.9:443",
            "192.0.0.10:443",
            "[2620:149:a44:f001::10]:443",
            "[64:ff9b::11fd:900a]:443",
            "[2001:1::1]:443",
            "[2001:3::1]:443",
            "[2001:4:112::1]:443",
            "[2001:20::1]:443",
            "[2001:30::1]:443",
        ] {
            let numeric: SocketAddr = address.parse().expect("numeric address");
            assert_eq!(
                public_address(numeric).expect("public vendor candidate"),
                numeric
            );
        }
        assert_eq!(
            public_address(
                "[::ffff:17.253.144.10]:443"
                    .parse()
                    .expect("mapped address")
            )
            .expect("mapped public candidate"),
            "17.253.144.10:443".parse().expect("normalized address")
        );
    }

    #[test]
    fn nonpublic_dns_candidates_produce_address_refusals() {
        for address in [
            "127.0.0.1:443",
            "10.1.2.3:443",
            "100.64.0.1:443",
            "169.254.1.1:443",
            "172.31.1.1:443",
            "192.168.1.1:443",
            "192.0.2.1:443",
            "198.18.0.1:443",
            "198.51.100.1:443",
            "203.0.113.1:443",
            "224.0.0.1:443",
            "255.255.255.255:443",
            "[::ffff:127.0.0.1]:443",
            "[::1]:443",
            "[fc00::1]:443",
            "[fe80::1]:443",
            "[2001:db8::1]:443",
            "[2002:7f00:1::1]:443",
            "[3fff::1]:443",
            "[64:ff9b::7f00:1]:443",
            "[2001:2::1]:443",
            "[2001:1::4]:443",
            "[2001:10::1]:443",
        ] {
            let error = public_address(address.parse().expect("numeric refusal candidate"))
                .expect_err("named public-address refusal");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(
                error.to_string().contains("fdr-vendor-address-refused"),
                "{error}"
            );
            assert!(error.to_string().contains("DNS candidate"), "{error}");
        }
    }

    #[test]
    fn injected_connect_failure_keeps_its_named_reason() {
        let error = connect_with(
            &request("skl.apple.com", 443),
            &cancellation(),
            |name, _| {
                assert_eq!(name, "skl.apple.com");
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "test connector: vendor service refused connection",
                ))
            },
        )
        .expect_err("attributed connector failure");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(
            error.to_string(),
            "test connector: vendor service refused connection"
        );
    }

    struct ParkedAttempt {
        cleaned: mpsc::Sender<()>,
    }

    impl Drop for ParkedAttempt {
        fn drop(&mut self) {
            let _ = self.cleaned.send(());
        }
    }

    #[test]
    fn a_real_candidate_wins_while_another_live_attempt_is_parked_and_joined() {
        let parked_listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("parked loopback listener");
        let winner_listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("available loopback listener");
        let parked_address = parked_listener.local_addr().expect("parked address");
        let winner_address = winner_listener.local_addr().expect("available address");
        let populated = Arc::new(AtomicBool::new(false));
        let (cleaned, cleanup) = mpsc::channel();
        let cancel = cancellation();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let winner = runtime.block_on(async {
            let connected =
                connect_candidates_with(vec![parked_address, winner_address], &cancel, |address| {
                    let populated = Arc::clone(&populated);
                    let cleaned = cleaned.clone();
                    async move {
                        if address == parked_address {
                            let stream = tokio::net::TcpStream::connect(address).await?;
                            let guard = ParkedAttempt { cleaned };
                            let result = std::future::poll_fn(|_| {
                                populated.store(true, Ordering::Release);
                                std::task::Poll::<io::Result<tokio::net::TcpStream>>::Pending
                            })
                            .await;
                            drop(stream);
                            drop(guard);
                            result
                        } else {
                            while !populated.load(Ordering::Acquire) {
                                tokio::task::yield_now().await;
                            }
                            tokio::net::TcpStream::connect(address).await
                        }
                    }
                });
            tokio::time::timeout(TEST_GUARD, connected)
                .await
                .expect("test selection failure guard")
                .expect("available numeric candidate selected")
                .into_std()
                .expect("winning socket ownership")
        });
        runtime.shutdown_background();
        assert!(
            populated.load(Ordering::Acquire),
            "the first candidate reached a live parked state"
        );
        cleanup
            .recv_timeout(TEST_GUARD)
            .expect("losing attempt dropped before selection returns");
        let (mut parked_peer, _) = parked_listener
            .accept()
            .expect("first attempt really connected over loopback");
        test_socket(&parked_peer);
        let mut parked_bytes = Vec::new();
        parked_peer
            .read_to_end(&mut parked_bytes)
            .expect("cancelled losing socket closed at the real peer");
        let (mut server, _) = winner_listener.accept().expect("winning loopback peer");
        let mut winner = winner;
        winner.set_nonblocking(false).expect("blocking test peer");
        test_socket(&winner);
        test_socket(&server);
        let request = b"winning candidate upload";
        let reply = b"winning candidate response";
        thread::scope(|scope| {
            let peer = scope.spawn(|| {
                let mut received = vec![0; request.len()];
                server
                    .read_exact(&mut received)
                    .expect("winning peer received request");
                assert_eq!(received.as_slice(), request.as_slice());
                server.write_all(reply).expect("winning peer reply");
            });
            winner
                .write_all(request)
                .expect("real bytes through selected candidate");
            let mut received = vec![0; reply.len()];
            winner
                .read_exact(&mut received)
                .expect("selected candidate response");
            assert_eq!(received.as_slice(), reply.as_slice());
            peer.join().expect("winning peer joined");
        });
    }

    #[test]
    fn failed_candidates_report_each_numeric_address_and_its_error() {
        let (one, _one_peer) = pair();
        let (two, _two_peer) = pair();
        let one_address = one.local_addr().expect("first loopback address");
        let two_address = two.local_addr().expect("second loopback address");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let error = runtime
            .block_on(connect_candidates_with(
                vec![one_address, two_address],
                &cancellation(),
                |address| async move {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("injected candidate refusal {address}"),
                    ))
                },
            ))
            .expect_err("all candidates attributed");
        runtime.shutdown_background();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        let detail = error.to_string();
        assert!(detail.starts_with("fdr-vendor-connect-failed"));
        assert!(
            detail.contains(&format!(
                "{one_address}: injected candidate refusal {one_address}"
            )),
            "{detail}"
        );
        assert!(
            detail.contains(&format!(
                "{two_address}: injected candidate refusal {two_address}"
            )),
            "{detail}"
        );
    }

    struct CommittingMuxReader {
        stream: TcpStream,
        fault: io::ErrorKind,
        take: usize,
        committed: bool,
        observed: Arc<Mutex<Vec<u8>>>,
    }

    impl Read for CommittingMuxReader {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.committed {
                return self.stream.read(out);
            }
            self.stream.read_exact(&mut out[..self.take])?;
            self.observed
                .lock()
                .expect("committed receive observation")
                .extend_from_slice(&out[..self.take]);
            self.committed = true;
            Err(io::Error::new(
                self.fault,
                format!(
                    "test mux ACK failure after consuming guest bytes: {:?}",
                    self.fault
                ),
            ))
        }
    }

    struct CommittingMuxWriter {
        stream: TcpStream,
        fault: io::ErrorKind,
        committed: bool,
        observed: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CommittingMuxWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.committed {
                return self.stream.write(bytes);
            }
            self.stream.write_all(bytes)?;
            self.observed
                .lock()
                .expect("committed transmit observation")
                .extend_from_slice(bytes);
            self.committed = true;
            Err(io::Error::new(
                self.fault,
                format!(
                    "test mux probe failure after committing reply bytes: {:?}",
                    self.fault
                ),
            ))
        }

        fn flush(&mut self) -> io::Result<()> {
            self.stream.flush()
        }
    }

    impl DeliveryWriter for CommittingMuxWriter {
        fn drain_delivery(&mut self) -> io::Result<()> {
            self.flush()
        }
        fn delivery_state(&self) -> Option<(usize, u32)> {
            None
        }
    }

    #[test]
    fn committing_mux_read_errors_preserve_each_root_cause_and_unknown_progress() {
        for kind in [
            io::ErrorKind::Interrupted,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::TimedOut,
        ] {
            let cancel = cancellation();
            let (socket, vendor) = authorized_pair(&cancel);
            vendor
                .shutdown(Shutdown::Write)
                .expect("vendor read EOF control");
            let (guest_socket, mut guest) = pair();
            let bytes = b"committed guest upload";
            guest
                .write_all(bytes)
                .expect("populate committing mux read");
            guest.shutdown(Shutdown::Write).expect("guest upload EOF");
            let observed = Arc::new(Mutex::new(Vec::new()));
            let reader = CommittingMuxReader {
                stream: guest_socket.try_clone().expect("guest read socket"),
                fault: kind,
                take: bytes.len(),
                committed: false,
                observed: Arc::clone(&observed),
            };
            let writer = ShortWriter::new(guest_socket, None);
            let (up, _) = forward(reader, writer, socket, cancel, |_| {}).expect("forward setup");
            assert_eq!(up.direction, "guest-to-vendor");
            assert_eq!(up.read_progress, ProgressKnowledge::Unknown);
            let error = up
                .error
                .expect("committing mux read must be attributed as fatal");
            assert_eq!(error.kind(), kind);
            assert!(
                error
                    .to_string()
                    .contains("fdr-forward-mux-read-failed: progress=unknown"),
                "{error}"
            );
            assert_eq!(
                error
                    .get_ref()
                    .expect("structured mux read error")
                    .source()
                    .expect("original mux read cause")
                    .to_string(),
                format!("test mux ACK failure after consuming guest bytes: {kind:?}")
            );
            assert_eq!(
                observed
                    .lock()
                    .expect("read population observation")
                    .as_slice(),
                bytes.as_slice()
            );
        }
    }

    #[test]
    fn committing_mux_write_errors_preserve_each_root_cause_and_unknown_progress() {
        for kind in [
            io::ErrorKind::Interrupted,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::TimedOut,
        ] {
            let cancel = cancellation();
            let (socket, mut vendor) = authorized_pair(&cancel);
            let (guest_socket, mut guest) = pair();
            guest
                .shutdown(Shutdown::Write)
                .expect("guest upload EOF control");
            let bytes = b"committed vendor reply";
            vendor
                .write_all(bytes)
                .expect("populate committing mux write");
            vendor.shutdown(Shutdown::Write).expect("vendor reply EOF");
            let observed = Arc::new(Mutex::new(Vec::new()));
            let reader = ShortReader {
                stream: guest_socket.try_clone().expect("guest read socket"),
                entered: None,
                cancel: None,
            };
            let writer = CommittingMuxWriter {
                stream: guest_socket,
                fault: kind,
                committed: false,
                observed: Arc::clone(&observed),
            };
            let (_, down) = forward(reader, writer, socket, cancel, |_| {}).expect("forward setup");
            assert_eq!(down.direction, "vendor-to-guest");
            assert_eq!(down.write_progress, ProgressKnowledge::Unknown);
            let error = down
                .error
                .expect("committing mux write must be attributed as fatal");
            assert_eq!(error.kind(), kind);
            assert!(
                error
                    .to_string()
                    .contains("fdr-forward-mux-write-failed: progress=unknown"),
                "{error}"
            );
            assert_eq!(
                error
                    .get_ref()
                    .expect("structured mux write error")
                    .source()
                    .expect("original mux write cause")
                    .to_string(),
                format!("test mux probe failure after committing reply bytes: {kind:?}")
            );
            let mut delivered =
                vec![0; observed.lock().expect("write population observation").len()];
            guest
                .read_exact(&mut delivered)
                .expect("actual bytes committed before mux write error");
            assert_eq!(
                delivered.as_slice(),
                observed
                    .lock()
                    .expect("write population observation")
                    .as_slice()
            );
            assert_eq!(delivered.as_slice(), &bytes[..delivered.len()]);
            assert!(
                !delivered.is_empty(),
                "committing error seam was populated by real reply bytes"
            );
        }
    }

    struct ZeroProgressTcpReader {
        stream: TcpStream,
        faults: std::collections::VecDeque<io::ErrorKind>,
        observed: Vec<io::ErrorKind>,
    }

    impl Read for ZeroProgressTcpReader {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if let Some(kind) = self.faults.pop_front() {
                self.observed.push(kind);
                return Err(io::Error::new(kind, "test zero-progress TCP read poll"));
            }
            let take = out.len().min(41);
            self.stream.read(&mut out[..take])
        }
    }

    struct ZeroProgressTcpWriter {
        stream: TcpStream,
        faults: std::collections::VecDeque<io::ErrorKind>,
        observed: Vec<io::ErrorKind>,
    }

    impl Write for ZeroProgressTcpWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(kind) = self.faults.pop_front() {
                self.observed.push(kind);
                return Err(io::Error::new(
                    kind,
                    "test zero-progress TCP write backpressure",
                ));
            }
            self.stream.write(&bytes[..bytes.len().min(37)])
        }

        fn flush(&mut self) -> io::Result<()> {
            self.stream.flush()
        }
    }

    #[test]
    fn tcp_zero_progress_retry_families_preserve_real_bytes_through_short_io() {
        let (input, mut source) = pair();
        let (output, mut sink) = pair();
        let bytes = payload(4096, 73);
        source
            .write_all(&bytes)
            .expect("populate real TCP read source");
        source.shutdown(Shutdown::Write).expect("source EOF");
        let faults = [
            io::ErrorKind::Interrupted,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::TimedOut,
        ];
        let mut reader = ZeroProgressTcpReader {
            stream: input,
            faults: faults.into(),
            observed: Vec::new(),
        };
        let mut writer = ZeroProgressTcpWriter {
            stream: output,
            faults: faults.into(),
            observed: Vec::new(),
        };
        let mut outcome = PumpOutcome::new("test TCP zero-progress retries");
        copy_bytes(
            &mut reader,
            &mut writer,
            &cancellation(),
            &mut outcome,
            CopyOrigins {
                read: IoOrigin::Tcp,
                write: IoOrigin::Tcp,
            },
        )
        .expect("TCP retries complete");
        writer
            .stream
            .shutdown(Shutdown::Write)
            .expect("transmitted TCP EOF");
        let mut delivered = Vec::new();
        sink.read_to_end(&mut delivered)
            .expect("real TCP sink received bytes and EOF");
        assert_eq!(delivered, bytes);
        assert_eq!(reader.observed.as_slice(), faults.as_slice());
        assert_eq!(writer.observed.as_slice(), faults.as_slice());
        assert_eq!(outcome.read_bytes, bytes.len() as u64);
        assert_eq!(outcome.written_bytes, bytes.len() as u64);
        assert_eq!(outcome.read_progress, ProgressKnowledge::Known);
        assert_eq!(outcome.write_progress, ProgressKnowledge::Known);
    }

    #[test]
    fn both_real_byte_streams_survive_simultaneous_short_io_and_backpressure() {
        let cancel = cancellation();
        let (socket, mut vendor) = authorized_pair(&cancel);
        let (guest_socket, mut guest) = pair();
        let reader = ShortReader {
            stream: guest_socket.try_clone().expect("guest read half"),
            entered: None,
            cancel: None,
        };
        let (delivered, delivery) = mpsc::channel();
        let writer = ShortWriter::new(guest_socket, Some(delivery));
        let upload = payload(128 * 1024, 7);
        let download = payload(96 * 1024, 113);
        let barrier = Barrier::new(2);
        thread::scope(|scope| {
            let mut guest_upload = guest.try_clone().expect("guest duplex writer");
            let mut vendor_download = vendor.try_clone().expect("vendor duplex writer");
            let upload_payload = &upload;
            let upload_barrier = &barrier;
            let download_payload = &download;
            let download_barrier = &barrier;
            let upload_sender = scope.spawn(move || {
                upload_barrier.wait();
                guest_upload
                    .write_all(upload_payload)
                    .expect("guest upload");
                guest_upload
                    .shutdown(Shutdown::Write)
                    .expect("guest upload EOF");
            });
            let download_sender = scope.spawn(move || {
                download_barrier.wait();
                vendor_download
                    .write_all(download_payload)
                    .expect("vendor download");
                vendor_download
                    .shutdown(Shutdown::Write)
                    .expect("vendor download EOF");
            });
            let upload_receiver = scope.spawn(|| {
                let mut received = Vec::new();
                vendor
                    .read_to_end(&mut received)
                    .expect("vendor received TCP upload and EOF");
                assert_eq!(received, upload);
            });
            let download_receiver = scope.spawn(|| {
                let mut received = vec![0; download.len()];
                guest
                    .read_exact(&mut received)
                    .expect("guest received download");
                assert_eq!(received, download);
                delivered.send(()).expect("guest confirms delivery");
            });
            let (up, down) =
                forward(reader, writer, socket, cancel, |_| {}).expect("forwarding setup");
            assert_eq!(up.written_bytes, upload.len() as u64);
            assert_eq!(down.written_bytes, download.len() as u64);
            assert!(down.drained);
            assert!(
                up.completed,
                "upload finished after its TCP write half-close"
            );
            assert!(
                down.completed,
                "download finished after delivery acknowledgement"
            );
            upload_sender.join().expect("upload sender joined");
            download_sender.join().expect("download sender joined");
            upload_receiver.join().expect("upload receiver joined");
            download_receiver.join().expect("download receiver joined");
        });
    }

    #[test]
    fn vendor_read_eof_drains_delivery_before_upload_finishes() {
        let cancel = cancellation();
        let (socket, mut vendor) = authorized_pair(&cancel);
        let (guest_socket, mut guest) = pair();
        let reader = ShortReader {
            stream: guest_socket.try_clone().expect("guest read half"),
            entered: None,
            cancel: None,
        };
        let (delivered, delivery) = mpsc::channel();
        let writer = ShortWriter::new(guest_socket, Some(delivery));
        let (download_complete, upload_release) = mpsc::channel();
        let complete = Mutex::new(Some(download_complete));
        let upload = payload(4096, 29);
        let download = payload(8192, 157);
        thread::scope(|scope| {
            let vendor_peer = scope.spawn(|| {
                vendor.write_all(&download).expect("vendor response");
                vendor
                    .shutdown(Shutdown::Write)
                    .expect("vendor response EOF");
                let mut received = Vec::new();
                vendor
                    .read_to_end(&mut received)
                    .expect("upload after vendor read EOF");
                assert_eq!(received, upload);
            });
            let upload_payload = &upload;
            let download_payload = &download;
            let guest_peer = scope.spawn(move || {
                let mut received = vec![0; download_payload.len()];
                guest.read_exact(&mut received).expect("guest response");
                assert_eq!(received, *download_payload);
                delivered.send(()).expect("guest delivery acknowledgement");
                upload_release
                    .recv_timeout(TEST_GUARD)
                    .expect("download drained while upload remains live");
                guest
                    .write_all(upload_payload)
                    .expect("upload after downstream completion");
                guest.shutdown(Shutdown::Write).expect("guest upload EOF");
            });
            let (up, down) = forward(reader, writer, socket, cancel, |outcome| {
                if outcome.direction == "vendor-to-guest" {
                    assert!(outcome.drained);
                    complete
                        .lock()
                        .expect("completion lock")
                        .take()
                        .expect("download completes once")
                        .send(())
                        .expect("release upload");
                }
            })
            .expect("forwarding setup");
            assert_eq!(up.written_bytes, upload.len() as u64);
            assert_eq!(down.written_bytes, download.len() as u64);
            assert!(down.drained);
            assert!(up.completed, "upload completed after vendor read EOF");
            assert!(down.completed, "vendor response delivery completed");
            vendor_peer.join().expect("vendor peer joined");
            guest_peer.join().expect("guest peer joined");
        });
    }

    #[test]
    fn a_live_connection_cancels_both_directions_with_named_reasons() {
        let cancel = cancellation();
        let (socket, mut vendor) = authorized_pair(&cancel);
        let (guest_socket, _guest) = pair();
        guest_socket
            .set_read_timeout(Some(IO_POLL))
            .expect("cancellable guest test socket");
        let (read_entered, read_ready) = mpsc::channel();
        let (write_entered, write_ready) = mpsc::channel();
        let reader = ShortReader {
            stream: guest_socket.try_clone().expect("guest read half"),
            entered: Some(read_entered),
            cancel: Some(cancel.clone()),
        };
        let mut writer = ShortWriter::new(guest_socket, None);
        writer.entered = Some(write_entered);
        vendor
            .write_all(b"vendor activity positive control")
            .expect("populate download pump");
        thread::scope(|scope| {
            let canceller_cancel = cancel.clone();
            let canceller = scope.spawn(move || {
                read_ready
                    .recv_timeout(TEST_GUARD)
                    .expect("upload pump entered read");
                write_ready
                    .recv_timeout(TEST_GUARD)
                    .expect("download pump wrote real peer bytes");
                canceller_cancel.abort();
            });
            let (up, down) =
                forward(reader, writer, socket, cancel.clone(), |_| {}).expect("forwarding setup");
            assert!(
                up.error
                    .expect("upload cancellation")
                    .to_string()
                    .contains("fdr-forward-connection-cancelled")
            );
            assert!(
                down.error
                    .expect("download cancellation")
                    .to_string()
                    .contains("fdr-forward-connection-cancelled")
            );
            assert!(
                down.written_bytes > 0,
                "download pump was populated before cancellation"
            );
            canceller.join().expect("cancellation worker joined");
        });
    }

    struct FailingWriter {
        stream: TcpStream,
        accepted: usize,
        limit: usize,
    }

    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.accepted == self.limit {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "test guest sink failed after partial delivery",
                ));
            }
            let written = self
                .stream
                .write(&bytes[..bytes.len().min(self.limit - self.accepted)])?;
            self.accepted += written;
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.stream.flush()
        }
    }

    impl DeliveryWriter for FailingWriter {
        fn drain_delivery(&mut self) -> io::Result<()> {
            self.flush()
        }
        fn delivery_state(&self) -> Option<(usize, u32)> {
            None
        }
    }

    #[test]
    fn fatal_download_error_keeps_direction_and_partial_bytes_and_cancels_upload() {
        let cancel = cancellation();
        let (socket, mut vendor) = authorized_pair(&cancel);
        let (guest_socket, mut guest) = pair();
        guest_socket
            .set_read_timeout(Some(IO_POLL))
            .expect("cancellable guest socket");
        let reader = ShortReader {
            stream: guest_socket.try_clone().expect("guest read half"),
            entered: None,
            cancel: Some(cancel.clone()),
        };
        let writer = FailingWriter {
            stream: guest_socket,
            accepted: 0,
            limit: 5,
        };
        vendor
            .write_all(b"distinct vendor reply")
            .expect("populate download direction");
        let (up, down) = forward(reader, writer, socket, cancel, |_| {}).expect("forwarding setup");
        assert_eq!(down.direction, "vendor-to-guest");
        assert_eq!(down.written_bytes, 5);
        assert!(
            down.read_bytes > down.written_bytes,
            "outstanding bytes remain attributed to the failed direction"
        );
        let failure = down.error.expect("named download failure");
        assert_eq!(failure.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(
            failure.to_string(),
            "fdr-forward-mux-write-failed: progress=unknown; test guest sink failed after partial delivery"
        );
        assert_eq!(down.write_progress, ProgressKnowledge::Unknown);
        assert!(
            up.error
                .expect("sibling cancelled")
                .to_string()
                .contains("fdr-forward-connection-cancelled")
        );
        let mut actual = [0; 5];
        guest
            .read_exact(&mut actual)
            .expect("real partially delivered bytes");
        assert_eq!(&actual, b"disti");
    }

    struct PanickingWriter;

    impl Write for PanickingWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            panic!("injected pump failure")
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl DeliveryWriter for PanickingWriter {
        fn drain_delivery(&mut self) -> io::Result<()> {
            self.flush()
        }
        fn delivery_state(&self) -> Option<(usize, u32)> {
            None
        }
    }

    #[test]
    fn download_panic_cancels_sibling_before_upload_join() {
        let cancel = cancellation();
        let (socket, mut vendor) = authorized_pair(&cancel);
        let (guest_socket, _guest) = pair();
        guest_socket
            .set_read_timeout(Some(IO_POLL))
            .expect("cancellable guest socket");
        let reader = ShortReader {
            stream: guest_socket,
            entered: None,
            cancel: Some(cancel.clone()),
        };
        vendor
            .write_all(b"populated panic path")
            .expect("populate download direction");
        let (up, down) =
            forward(reader, PanickingWriter, socket, cancel, |_| {}).expect("forwarding setup");
        assert_eq!(down.direction, "vendor-to-guest");
        assert!(down.read_bytes > 0, "panic path was populated");
        assert_eq!(
            down.error
                .expect("panic attributed to download")
                .to_string(),
            "fdr-forward-pump-panicked"
        );
        assert!(
            up.error
                .expect("upload cancelled before join")
                .to_string()
                .contains("fdr-forward-connection-cancelled")
        );
    }

    #[test]
    fn cancellable_async_operation_reports_cancellation_after_being_polled() {
        let cancel = cancellation();
        let (polled, ready) = mpsc::channel();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        thread::scope(|scope| {
            let canceller_cancel = cancel.clone();
            let canceller = scope.spawn(move || {
                ready
                    .recv_timeout(TEST_GUARD)
                    .expect("operation population control");
                canceller_cancel.abort();
            });
            let mut observed = Some(polled);
            let operation = std::future::poll_fn(|_| {
                if let Some(polled) = observed.take() {
                    polled.send(()).expect("polled operation");
                }
                std::task::Poll::<io::Result<()>>::Pending
            });
            let error = runtime
                .block_on(cancellable(operation, &cancel))
                .expect_err("async cancellation");
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert_eq!(error.to_string(), "fdr-forward-connection-cancelled");
            canceller.join().expect("canceller joined");
        });
        runtime.shutdown_background();
    }
}
