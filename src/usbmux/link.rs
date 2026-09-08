use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::trace::{MuxTraceEvent, MuxTraceSink};

use super::frame::{
    FrameError, HEADER_LEN_V2, HOST_MAGIC, MAX_PACKET, MAX_TRANSFER, MuxHeader, MuxVersion,
    Protocol, VersionPacket, VersionRequest,
};
use super::roundtrip::{PortStats, RoundtripMeter};
use super::session::{MuxSession, SessionConfig, SessionError, SessionEvent, SessionState};
use super::tcp::{TCP_HEADER_LEN, TcpError, TcpHeader};

pub const FIRST_LOCAL_PORT: u16 = 49152;

pub const DEFAULT_RECEIVE_WINDOW: u32 = 256 * 1024;

// One mux packet is exactly one bulk transfer both ways, with a zero length packet when a transfer
// is a multiple of wMaxPacketSize, and in order: the device has no reassembly and never retries.
pub trait BulkTransport {
    fn send(&mut self, packet: &[u8]) -> io::Result<()>;

    fn recv(&mut self, timeout: Duration) -> io::Result<Option<Vec<u8>>>;

    fn out_max_packet_size(&self) -> u16;

    fn max_packet(&self) -> usize {
        MAX_PACKET
    }

    fn device_accepted_packets(&self) -> Option<u64> {
        None
    }

    fn inbound_signal(&self) -> Option<Arc<dyn InboundSignal>> {
        None
    }

    fn device_present(&self) -> Option<bool> {
        None
    }

    fn send_capacity(&self) -> Option<bool> {
        None
    }
}

pub trait InboundSignal: Send + Sync {
    fn inbound_generation(&self) -> u64;

    fn wait_for_inbound(&self, seen: u64, timeout: Duration);
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkLiveness {
    pub packets_received: u64,
    pub packets_rejected: u64,
    pub packets_accepted: Option<u64>,
}

impl LinkLiveness {
    #[must_use]
    pub fn describe(&self) -> String {
        match self.packets_accepted {
            Some(accepted) => format!(
                "{} packets have arrived from the device on this link, {} of them did not frame as mux packets and were dropped, and its bulk OUT ring has accepted {accepted}",
                self.packets_received, self.packets_rejected
            ),
            None => format!(
                "{} packets have arrived from the device on this link and {} of them did not frame as mux packets and were dropped; what its bulk OUT ring accepted is not visible to this transport",
                self.packets_received, self.packets_rejected
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkEvent {
    Idle,
    Session {
        local_port: u16,
        event: SessionEvent,
    },
    Unmatched {
        local_port: u16,
    },
    Other {
        protocol: Protocol,
    },
    Rejected {
        declared: u32,
        delivered: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendState {
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub snd_wnd_edge: u32,
    pub peer_window: u32,
    pub usable: usize,
    pub pending: usize,
    pub segments_in: u64,
}

#[derive(Debug)]
pub enum MuxError {
    Io(io::Error),
    Frame(FrameError),
    Tcp(TcpError),
    Session {
        local_port: u16,
        error: SessionError,
    },
    NotNegotiated,
    VersionTimedOut {
        waited: Duration,
    },
    SequenceGap {
        expected: u16,
        received: u16,
    },
    TooLarge {
        bytes: usize,
        limit: usize,
    },
    NoSession {
        local_port: u16,
    },
    HandshakeTimedOut {
        local_port: u16,
        waited: Duration,
    },
    Closed {
        local_port: u16,
    },
    NoPorts,
}

impl fmt::Display for MuxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "mux transport: {error}"),
            Self::Frame(error) => write!(f, "mux frame: {error}"),
            Self::Tcp(error) => write!(f, "mux tcp: {error}"),
            Self::Session { local_port, error } => {
                write!(f, "mux session on port {local_port}: {error}")
            }
            Self::NotNegotiated => {
                f.write_str("the mux version has not been exchanged, so no header size is known")
            }
            Self::VersionTimedOut { waited } => {
                write!(
                    f,
                    "the device did not answer the version packet in {waited:?}"
                )
            }
            Self::SequenceGap { expected, received } => write!(
                f,
                "mux sequence {received} arrived where {expected} was expected; the device has no reassembly queue and the link cannot recover"
            ),
            Self::TooLarge { bytes, limit } => {
                write!(
                    f,
                    "a {bytes} byte mux packet exceeds the {limit} byte limit"
                )
            }
            Self::NoSession { local_port } => {
                write!(f, "no mux session on port {local_port}")
            }
            Self::HandshakeTimedOut { local_port, waited } => write!(
                f,
                "the mux session on port {local_port} did not open in {waited:?}"
            ),
            Self::Closed { local_port } => {
                write!(f, "the mux session on port {local_port} is closed")
            }
            Self::NoPorts => f.write_str("every mux local port is in use"),
        }
    }
}

impl std::error::Error for MuxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Frame(error) => Some(error),
            Self::Tcp(error) => Some(error),
            Self::Session { error, .. } => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for MuxError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<FrameError> for MuxError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

impl From<TcpError> for MuxError {
    fn from(error: TcpError) -> Self {
        Self::Tcp(error)
    }
}

impl From<MuxError> for io::Error {
    fn from(error: MuxError) -> Self {
        match error {
            MuxError::Io(inner) => inner,
            other => io::Error::other(other.to_string()),
        }
    }
}

pub struct MuxLink<T> {
    transport: T,
    version: Option<MuxVersion>,
    tx_seq: u16,
    rx_expected: u16,
    sessions: BTreeMap<u16, MuxSession>,
    next_local_port: u16,
    receive_window: u32,
    sequence_seed: u32,
    packets_received: u64,
    packets_rejected: u64,
    in_flush: bool,
    trace: Option<Arc<dyn MuxTraceSink>>,
    roundtrip: RoundtripMeter,
}

impl<T: BulkTransport> MuxLink<T> {
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            version: None,
            tx_seq: 0,
            rx_expected: 0,
            sessions: BTreeMap::new(),
            next_local_port: FIRST_LOCAL_PORT,
            receive_window: DEFAULT_RECEIVE_WINDOW,
            sequence_seed: initial_sequence_seed(),
            packets_received: 0,
            packets_rejected: 0,
            in_flush: false,
            trace: None,
            roundtrip: RoundtripMeter::new(),
        }
    }

    #[must_use]
    pub fn roundtrip(&self, local_port: u16) -> Option<PortStats> {
        self.roundtrip.stats(local_port)
    }

    #[must_use]
    pub fn with_roundtrip_meter(mut self, meter: RoundtripMeter) -> Self {
        self.roundtrip = meter;
        self
    }

    #[must_use]
    pub fn with_trace(mut self, sink: Arc<dyn MuxTraceSink>) -> Self {
        self.trace = Some(sink);
        self
    }

    pub(super) fn trace(&self, event: MuxTraceEvent) {
        if let Some(sink) = &self.trace {
            sink.event(event);
        }
    }

    #[must_use]
    pub fn with_receive_window(mut self, window: u32) -> Self {
        self.receive_window = window;
        self
    }

    #[must_use]
    pub fn with_sequence_seed(mut self, seed: u32) -> Self {
        self.sequence_seed = seed;
        self
    }

    #[must_use]
    pub fn version(&self) -> Option<MuxVersion> {
        self.version
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn segment_size(&self) -> Result<usize, MuxError> {
        let version = self.version.ok_or(MuxError::NotNegotiated)?;
        let ceiling = self.transport.max_packet().min(MAX_TRANSFER);
        Ok(ceiling - version.header_len() - TCP_HEADER_LEN)
    }

    // Both sequence counters reset here because the device resets its own pair on the exchange;
    // a host counting from anywhere else has every packet dropped as a duplicate.
    pub fn negotiate(
        &mut self,
        request: VersionRequest,
        timeout: Duration,
    ) -> Result<MuxVersion, MuxError> {
        let packet = request.packet().encode();
        self.transport.send(&packet)?;
        self.trace(MuxTraceEvent::VersionSent {
            version: request.wire_value(),
            bytes: packet.len(),
        });

        // The version exchange is unsequenced: the reply consumes no sequence number either side.
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.trace(MuxTraceEvent::VersionTimedOut { waited: timeout });
                return Err(MuxError::VersionTimedOut { waited: timeout });
            }
            let Some(bytes) = self.transport.recv(remaining)? else {
                continue;
            };
            let reply = VersionPacket::decode(&bytes)?;
            let version = reply.negotiated();
            self.version = Some(version);
            self.tx_seq = 0;
            self.rx_expected = 0;
            self.trace(MuxTraceEvent::VersionNegotiated {
                version,
                header_len: version.header_len(),
                segment_size: self.segment_size().unwrap_or(0),
            });
            return Ok(version);
        }
    }

    pub fn begin_open(&mut self, remote_port: u16) -> Result<u16, MuxError> {
        let local_port = self.allocate_port()?;
        let mss = self.segment_size()?;
        let config = SessionConfig {
            local_port,
            remote_port,
            initial_sequence: self.next_initial_sequence(local_port),
            mss,
            receive_window: self.receive_window,
        };
        let (session, syn) = MuxSession::open(config);
        self.sessions.insert(local_port, session);
        self.send_segment(&syn.to_bytes())?;
        self.trace(MuxTraceEvent::SynSent {
            local_port,
            remote_port,
            sequence: config.initial_sequence,
        });
        Ok(local_port)
    }

    pub fn finish_open(&mut self, local_port: u16, remote_port: u16) -> Result<(), MuxError> {
        // The device learns this side's receive window only from this third leg.
        self.flush(local_port)?;
        self.trace(MuxTraceEvent::SessionEstablished {
            local_port,
            remote_port,
        });
        Ok(())
    }

    pub fn abandon_open(&mut self, local_port: u16, waited: Duration) {
        self.sessions.remove(&local_port);
        self.trace(MuxTraceEvent::HandshakeTimedOut { local_port, waited });
    }

    pub fn forget_session(&mut self, local_port: u16) {
        self.sessions.remove(&local_port);
    }

    pub fn open(&mut self, remote_port: u16, timeout: Duration) -> Result<u16, MuxError> {
        let local_port = self.begin_open(remote_port)?;
        let deadline = Instant::now() + timeout;
        loop {
            match self.session_state(local_port) {
                Some(SessionState::Established) => {
                    self.finish_open(local_port, remote_port)?;
                    return Ok(local_port);
                }
                Some(SessionState::Closed) | None => {
                    self.forget_session(local_port);
                    return Err(MuxError::Closed { local_port });
                }
                Some(SessionState::SynSent) => {}
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.abandon_open(local_port, timeout);
                return Err(MuxError::HandshakeTimedOut {
                    local_port,
                    waited: timeout,
                });
            }
            self.pump(remaining)?;
        }
    }

    #[must_use]
    pub fn session_state(&self, local_port: u16) -> Option<SessionState> {
        self.sessions.get(&local_port).map(MuxSession::state)
    }

    #[must_use]
    pub fn received_len(&self, local_port: u16) -> usize {
        self.sessions
            .get(&local_port)
            .map_or(0, MuxSession::received_len)
    }

    pub fn write(
        &mut self,
        local_port: u16,
        data: &[u8],
        timeout: Duration,
    ) -> Result<usize, MuxError> {
        let session = self
            .sessions
            .get_mut(&local_port)
            .ok_or(MuxError::NoSession { local_port })?;
        if session.state() != SessionState::Established {
            return Err(MuxError::Closed { local_port });
        }
        session.queue(data);
        self.roundtrip.on_queue(local_port, data.len());
        let deadline = Instant::now() + timeout;
        let wanted = data.len();
        loop {
            let before = self
                .sessions
                .get(&local_port)
                .ok_or(MuxError::NoSession { local_port })?
                .pending_len();
            self.flush(local_port)?;
            let session = self
                .sessions
                .get(&local_port)
                .ok_or(MuxError::NoSession { local_port })?;
            if session.state() != SessionState::Established {
                return Err(MuxError::Closed { local_port });
            }
            let outstanding = session.pending_len();
            if outstanding == 0 {
                return Ok(wanted);
            }
            let usable = session.usable_window();
            let in_flight = session.in_flight();
            let peer_window = session.peer_window();
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(wanted - outstanding.min(wanted));
            }
            if outstanding < before && usable > 0 {
                self.drain_inbound()?;
                continue;
            }
            let started = Instant::now();
            let pumped = self.pump(remaining);
            let waited = started.elapsed();
            self.roundtrip.on_write_wait(
                local_port,
                waited,
                usable,
                in_flight,
                peer_window,
                Instant::now(),
            );
            pumped?;
        }
    }

    #[must_use]
    pub fn inbound_signal(&self) -> Option<Arc<dyn InboundSignal>> {
        self.transport.inbound_signal()
    }

    // Sample under the link lock and before draining, or a packet arriving between the drain and
    // the wait is missed and the waiter sleeps out its whole timeout.
    #[must_use]
    pub fn inbound_generation(&self) -> u64 {
        self.transport
            .inbound_signal()
            .map_or(0, |signal| signal.inbound_generation())
    }

    pub fn drain_inbound(&mut self) -> Result<usize, MuxError> {
        let mut routed = 0;
        loop {
            if matches!(self.pump(Duration::ZERO)?, LinkEvent::Idle) {
                return Ok(routed);
            }
            routed += 1;
        }
    }

    pub fn route_available(&mut self) -> Result<usize, MuxError> {
        let was = self.in_flush;
        self.in_flush = true;
        let result = self.drain_inbound();
        self.in_flush = was;
        result
    }

    // Taking bytes grows the advertised window and the device sizes its next send off the last
    // window it was told, so this owes an acknowledgement.
    pub fn take_received(&mut self, local_port: u16, out: &mut [u8]) -> Result<usize, MuxError> {
        if out.is_empty() {
            return Ok(0);
        }
        let session = self
            .sessions
            .get_mut(&local_port)
            .ok_or(MuxError::NoSession { local_port })?;
        let taken = session.take_received(out);
        if taken > 0 {
            session.request_ack();
            self.flush(local_port)?;
        }
        Ok(taken)
    }

    pub fn queue_write(&mut self, local_port: u16, data: &[u8]) -> Result<usize, MuxError> {
        let session = self
            .sessions
            .get_mut(&local_port)
            .ok_or(MuxError::NoSession { local_port })?;
        if session.state() != SessionState::Established {
            return Err(MuxError::Closed { local_port });
        }
        session.queue(data);
        self.roundtrip.on_queue(local_port, data.len());
        self.pending_write(local_port)
    }

    pub fn pending_write(&mut self, local_port: u16) -> Result<usize, MuxError> {
        self.flush(local_port)?;
        let session = self
            .sessions
            .get(&local_port)
            .ok_or(MuxError::NoSession { local_port })?;
        if session.state() != SessionState::Established {
            return Err(MuxError::Closed { local_port });
        }
        Ok(session.pending_len())
    }

    #[must_use]
    pub fn send_state(&self, local_port: u16) -> Option<SendState> {
        self.sessions.get(&local_port).map(|session| SendState {
            snd_una: session.snd_una(),
            snd_nxt: session.snd_nxt(),
            snd_wnd_edge: session.snd_wnd_edge(),
            peer_window: session.peer_window(),
            usable: session.usable_window(),
            pending: session.pending_len(),
            segments_in: session.segments_in(),
        })
    }

    pub fn probe_window(&mut self, local_port: u16) -> Result<bool, MuxError> {
        let session = self
            .sessions
            .get_mut(&local_port)
            .ok_or(MuxError::NoSession { local_port })?;
        if !session.probe_window() {
            return Ok(false);
        }
        self.flush(local_port)?;
        Ok(true)
    }

    pub fn record_wait(&mut self, local_port: u16, for_link: Duration, for_inbound: Duration) {
        let (usable, in_flight, peer_window) =
            self.sessions.get(&local_port).map_or((0, 0, 0), |session| {
                (
                    session.usable_window(),
                    session.in_flight(),
                    session.peer_window(),
                )
            });
        self.roundtrip.on_lock_wait(local_port, for_link);
        self.roundtrip.on_inbound_wait(
            local_port,
            for_inbound,
            usable,
            in_flight,
            peer_window,
            Instant::now(),
        );
    }

    pub fn read(
        &mut self,
        local_port: u16,
        out: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, MuxError> {
        if out.is_empty() {
            return Ok(0);
        }
        let deadline = Instant::now() + timeout;
        loop {
            let taken = self.take_received(local_port, out)?;
            if taken > 0 {
                return Ok(taken);
            }
            if self.session_state(local_port) == Some(SessionState::Closed) {
                return Ok(0);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(0);
            }
            self.pump(remaining)?;
        }
    }

    pub fn flush(&mut self, local_port: u16) -> Result<(), MuxError> {
        loop {
            // Checked before a segment is pulled: next_segment already commits its sequence number
            // and removes its bytes from the session's queue, so nothing here may back out of one.
            if self.transport.send_capacity() == Some(false) {
                return Ok(());
            }
            let Some(session) = self.sessions.get_mut(&local_port) else {
                return Ok(());
            };
            let Some(segment) = session.next_segment() else {
                return Ok(());
            };
            let sequence = segment.header.sequence;
            let payload_len = segment.payload.len();
            let started = Instant::now();
            self.send_segment(&segment.to_bytes())?;
            if payload_len > 0 {
                let at = Instant::now();
                self.roundtrip.on_segment_sent(
                    local_port,
                    sequence,
                    payload_len,
                    at.saturating_duration_since(started),
                    at,
                );
            }
        }
    }

    #[must_use]
    pub fn liveness(&self) -> LinkLiveness {
        LinkLiveness {
            packets_received: self.packets_received,
            packets_rejected: self.packets_rejected,
            packets_accepted: self.transport.device_accepted_packets(),
        }
    }

    #[must_use]
    pub fn device_present(&self) -> Option<bool> {
        self.transport.device_present()
    }

    pub fn close(&mut self, local_port: u16) -> Result<(), MuxError> {
        let Some(session) = self.sessions.get_mut(&local_port) else {
            return Ok(());
        };
        let segment = session.close();
        self.sessions.remove(&local_port);
        self.roundtrip.on_close(local_port);
        self.send_segment(&segment.to_bytes())
    }

    pub fn pump(&mut self, timeout: Duration) -> Result<LinkEvent, MuxError> {
        let version = self.version.ok_or(MuxError::NotNegotiated)?;
        let Some(packet) = self.transport.recv(timeout)? else {
            return Ok(LinkEvent::Idle);
        };
        self.packets_received = self.packets_received.wrapping_add(1);
        let header = match MuxHeader::decode(version, &packet) {
            Ok(header) => header,
            Err(error) => return Ok(self.reject_packet(error, &packet)),
        };
        let payload = match header.payload(version, &packet) {
            Ok(payload) => payload,
            Err(error) => return Ok(self.reject_packet(error, &packet)),
        };

        if header.protocol == Protocol::Version {
            // A late version packet means the device restarted its framing: both counters go back
            // to zero, as they do in the guest.
            let reply = VersionPacket::decode(&packet)?;
            self.version = Some(reply.negotiated());
            self.tx_seq = 0;
            self.rx_expected = 0;
            return Ok(LinkEvent::Other {
                protocol: Protocol::Version,
            });
        }

        if version.is_sequenced() {
            if header.tx_seq != self.rx_expected {
                self.trace(MuxTraceEvent::SequenceGap {
                    expected: self.rx_expected,
                    received: header.tx_seq,
                });
                return Err(MuxError::SequenceGap {
                    expected: self.rx_expected,
                    received: header.tx_seq,
                });
            }
            self.rx_expected = self.rx_expected.wrapping_add(1);
        }

        if header.protocol != Protocol::Tcp {
            self.trace(MuxTraceEvent::OtherProtocol {
                protocol: header.protocol.wire_value(),
            });
            return Ok(LinkEvent::Other {
                protocol: header.protocol,
            });
        }

        let tcp = TcpHeader::decode(payload)?;
        let body = &payload[TCP_HEADER_LEN..];
        let local_port = tcp.destination_port;
        let Some(session) = self.sessions.get_mut(&local_port) else {
            self.trace(MuxTraceEvent::Unmatched { local_port });
            return Ok(LinkEvent::Unmatched { local_port });
        };
        if session.state() == SessionState::SynSent && tcp.is_syn_ack() {
            let event = MuxTraceEvent::SynAckReceived {
                local_port,
                device_sequence: tcp.sequence,
                window: tcp.window,
            };
            self.trace(event);
        }
        let session = self
            .sessions
            .get_mut(&local_port)
            .ok_or(MuxError::NoSession { local_port })?;
        let una_before = session.snd_una();
        let event = session
            .on_segment(&tcp, body)
            .map_err(|error| MuxError::Session { local_port, error })?;
        let una_after = self.sessions.get(&local_port).map(MuxSession::snd_una);
        if let Some(una_after) = una_after {
            self.roundtrip.on_ack(
                local_port,
                una_before,
                una_after,
                tcp.window,
                Instant::now(),
            );
        }
        match event {
            SessionEvent::Data { bytes } => {
                self.trace(MuxTraceEvent::Received { local_port, bytes });
            }
            SessionEvent::Reset => self.trace(MuxTraceEvent::Reset { local_port }),
            SessionEvent::OutOfOrder { expected, received } => {
                self.trace(MuxTraceEvent::OutOfOrder {
                    local_port,
                    expected,
                    received,
                });
            }
            SessionEvent::ClosedByFlags { flags } => {
                self.trace(MuxTraceEvent::SessionClosedByFlags { local_port, flags });
            }
            SessionEvent::Established | SessionEvent::Acknowledged => {}
        }
        if matches!(
            event,
            SessionEvent::Reset | SessionEvent::ClosedByFlags { .. }
        ) {
            return Ok(LinkEvent::Session { local_port, event });
        }
        if !self.in_flush {
            self.flush(local_port)?;
        }
        Ok(LinkEvent::Session { local_port, event })
    }

    fn reject_packet(&mut self, error: FrameError, packet: &[u8]) -> LinkEvent {
        let word = |offset: usize| {
            packet.get(offset..offset + 4).map_or(0, |bytes| {
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            })
        };
        let mut head = [0u8; HEADER_LEN_V2];
        let taken = packet.len().min(HEADER_LEN_V2);
        head[..taken].copy_from_slice(&packet[..taken]);
        let declared = match error {
            FrameError::LengthMismatch { declared, .. } => declared,
            FrameError::Short { .. } | FrameError::NotVersion { .. } => word(4),
        };
        self.packets_rejected = self.packets_rejected.wrapping_add(1);
        self.trace(MuxTraceEvent::PacketRejected {
            protocol: word(0),
            declared,
            delivered: packet.len(),
            magic: word(8),
            head,
            rejected: self.packets_rejected,
        });
        LinkEvent::Rejected {
            declared,
            delivered: packet.len(),
        }
    }

    fn send_segment(&mut self, segment: &[u8]) -> Result<(), MuxError> {
        self.send_packet(Protocol::Tcp, segment)
    }

    fn send_packet(&mut self, protocol: Protocol, payload: &[u8]) -> Result<(), MuxError> {
        let version = self.version.ok_or(MuxError::NotNegotiated)?;
        let header_len = version.header_len();
        let total = header_len + payload.len();
        let limit = self.transport.max_packet().min(MAX_PACKET);
        if total > limit {
            return Err(MuxError::TooLarge {
                bytes: total,
                limit,
            });
        }
        let mut packet = vec![0u8; total];
        let header = MuxHeader {
            protocol,
            length: total as u32,
            magic: HOST_MAGIC,
            tx_seq: self.tx_seq,
            rx_ack: self.rx_expected.wrapping_sub(1),
        };
        header.encode(version, &mut packet)?;
        packet[header_len..].copy_from_slice(payload);
        self.transport.send(&packet)?;
        if version.is_sequenced() {
            self.tx_seq = self.tx_seq.wrapping_add(1);
        }
        Ok(())
    }

    fn allocate_port(&mut self) -> Result<u16, MuxError> {
        for _ in 0..=(u16::MAX - FIRST_LOCAL_PORT) {
            let port = self.next_local_port;
            self.next_local_port = if port == u16::MAX {
                FIRST_LOCAL_PORT
            } else {
                port + 1
            };
            if !self.sessions.contains_key(&port) {
                return Ok(port);
            }
        }
        Err(MuxError::NoPorts)
    }

    fn next_initial_sequence(&mut self, local_port: u16) -> u32 {
        self.sequence_seed = self
            .sequence_seed
            .wrapping_mul(1_664_525)
            .wrapping_add(1_013_904_223);
        self.sequence_seed ^ (u32::from(local_port) << 16)
    }
}

fn initial_sequence_seed() -> u32 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.subsec_nanos() as u64 + since.as_secs());
    (nanos as u32) ^ ((nanos >> 32) as u32)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::usbmux::frame::{DEVICE_MAGIC, HEADER_LEN_V2, VERSION_PACKET_LEN};
    use crate::usbmux::tcp::flags;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::rc::Rc;

    #[derive(Debug, Default)]
    struct DeviceState {
        version: Option<MuxVersion>,
        tx_seq: u16,
        rx_expected: u16,
        outbound: VecDeque<Vec<u8>>,
        received: Vec<Vec<u8>>,
        sessions: Vec<DeviceSession>,
        sequence_faults: u32,
        window: u32,
    }

    #[derive(Debug)]
    struct DeviceSession {
        local_port: u16,
        remote_port: u16,
        snd_nxt: u32,
        rcv_nxt: u32,
        received: Vec<u8>,
        open: bool,
    }

    #[derive(Clone)]
    pub(crate) struct Device {
        state: Rc<RefCell<DeviceState>>,
    }

    impl Default for Device {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Device {
        pub(crate) fn new() -> Self {
            Self {
                state: Rc::new(RefCell::new(DeviceState {
                    window: 65536,
                    ..DeviceState::default()
                })),
            }
        }

        pub(crate) fn with_window(self, window: u32) -> Self {
            self.state.borrow_mut().window = window;
            self
        }

        pub(crate) fn received_packets(&self) -> Vec<Vec<u8>> {
            self.state.borrow().received.clone()
        }

        pub(crate) fn take_received_packets(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut self.state.borrow_mut().received)
        }

        pub(crate) fn session_bytes(&self, local_port: u16) -> Vec<u8> {
            self.state
                .borrow()
                .sessions
                .iter()
                .find(|session| session.local_port == local_port)
                .map(|session| session.received.clone())
                .unwrap_or_default()
        }

        pub(crate) fn session_open(&self, local_port: u16) -> bool {
            self.state
                .borrow()
                .sessions
                .iter()
                .any(|session| session.local_port == local_port && session.open)
        }

        pub(crate) fn sequence_faults(&self) -> u32 {
            self.state.borrow().sequence_faults
        }

        pub(crate) fn session_ports(&self, local_port: u16) -> Option<u16> {
            self.state
                .borrow()
                .sessions
                .iter()
                .find(|session| session.local_port == local_port)
                .map(|session| session.remote_port)
        }

        pub(crate) fn only_session_ports(&self) -> (u16, u16) {
            let state = self.state.borrow();
            let session = state
                .sessions
                .iter()
                .find(|session| session.open)
                .expect("a session is open");
            (session.local_port, session.remote_port)
        }

        pub(crate) fn push(&self, local_port: u16, data: &[u8]) {
            self.push_with_flags(local_port, data, flags::ACK);
        }

        pub(crate) fn push_with_flags(&self, local_port: u16, data: &[u8], flag_byte: u8) {
            let mut state = self.state.borrow_mut();
            let Some(index) = state
                .sessions
                .iter()
                .position(|session| session.local_port == local_port)
            else {
                return;
            };
            let (header, sequence) = {
                let session = &state.sessions[index];
                (
                    TcpHeader {
                        source_port: session.remote_port,
                        destination_port: session.local_port,
                        sequence: session.snd_nxt,
                        acknowledgement: session.rcv_nxt,
                        flags: flag_byte,
                        window: state.window,
                    },
                    session.snd_nxt,
                )
            };
            let _ = sequence;
            state.sessions[index].snd_nxt = state.sessions[index]
                .snd_nxt
                .wrapping_add(data.len() as u32);
            let payload = encode_segment(header, data);
            state.queue_tcp(&payload);
        }

        pub(crate) fn reset(&self, local_port: u16) {
            let mut state = self.state.borrow_mut();
            let Some(index) = state
                .sessions
                .iter()
                .position(|session| session.local_port == local_port)
            else {
                return;
            };
            let header = {
                let session = &state.sessions[index];
                TcpHeader {
                    source_port: session.remote_port,
                    destination_port: session.local_port,
                    sequence: session.snd_nxt,
                    acknowledgement: session.rcv_nxt,
                    flags: flags::RST,
                    window: 0,
                }
            };
            state.sessions[index].open = false;
            let payload = encode_segment(header, &[]);
            state.queue_tcp(&payload);
        }
    }

    impl DeviceState {
        fn queue_tcp(&mut self, segment: &[u8]) {
            let total = HEADER_LEN_V2 + segment.len();
            let mut packet = vec![0u8; total];
            packet[0..4].copy_from_slice(&Protocol::Tcp.wire_value().to_be_bytes());
            packet[4..8].copy_from_slice(&(total as u32).to_be_bytes());
            packet[8..12].copy_from_slice(&DEVICE_MAGIC.to_be_bytes());
            packet[12..14].copy_from_slice(&self.tx_seq.to_be_bytes());
            packet[14..16].copy_from_slice(&self.rx_expected.wrapping_sub(1).to_be_bytes());
            packet[HEADER_LEN_V2..].copy_from_slice(segment);
            self.tx_seq = self.tx_seq.wrapping_add(1);
            self.outbound.push_back(packet);
        }

        fn handle(&mut self, packet: &[u8]) {
            self.received.push(packet.to_vec());
            let Some(version) = self.version else {
                self.handle_version(packet);
                return;
            };
            let Ok(header) = MuxHeader::decode(version, packet) else {
                return;
            };
            if header.protocol == Protocol::Version {
                self.handle_version(packet);
                return;
            }
            if version.is_sequenced() {
                if header.tx_seq != self.rx_expected {
                    self.sequence_faults += 1;
                    return;
                }
                self.rx_expected = self.rx_expected.wrapping_add(1);
            }
            if header.protocol != Protocol::Tcp {
                return;
            }
            let Ok(payload) = header.payload(version, packet) else {
                return;
            };
            self.handle_tcp(payload);
        }

        fn handle_version(&mut self, packet: &[u8]) {
            let Ok(request) = VersionPacket::decode(packet) else {
                return;
            };
            let version = request.negotiated();
            self.version = Some(version);
            self.tx_seq = 0;
            self.rx_expected = 0;
            let mut reply = vec![0u8; VERSION_PACKET_LEN];
            reply[4..8].copy_from_slice(&(VERSION_PACKET_LEN as u32).to_be_bytes());
            reply[8..12].copy_from_slice(&version.wire_value().to_be_bytes());
            self.outbound.push_back(reply);
        }

        fn handle_tcp(&mut self, payload: &[u8]) {
            let Ok(tcp) = TcpHeader::decode(payload) else {
                return;
            };
            let body = &payload[TCP_HEADER_LEN..];
            if tcp.is_reset() {
                for session in &mut self.sessions {
                    if session.local_port == tcp.source_port {
                        session.open = false;
                    }
                }
                return;
            }
            if tcp.is_bare_syn() {
                if !body.is_empty() {
                    return;
                }
                self.sessions.push(DeviceSession {
                    local_port: tcp.source_port,
                    remote_port: tcp.destination_port,
                    snd_nxt: 0,
                    rcv_nxt: tcp.sequence.wrapping_add(1),
                    received: Vec::new(),
                    open: true,
                });
                let session = self.sessions.last().expect("just pushed");
                let reply = TcpHeader {
                    source_port: session.remote_port,
                    destination_port: session.local_port,
                    sequence: session.snd_nxt,
                    acknowledgement: session.rcv_nxt,
                    flags: flags::SYN_ACK,
                    window: self.window,
                };
                let sequence_after = session.snd_nxt.wrapping_add(1);
                let index = self.sessions.len() - 1;
                self.sessions[index].snd_nxt = sequence_after;
                let segment = encode_segment(reply, &[]);
                self.queue_tcp(&segment);
                return;
            }
            if !tcp.is_bare_ack() {
                return;
            }
            let Some(index) = self
                .sessions
                .iter()
                .position(|session| session.local_port == tcp.source_port && session.open)
            else {
                return;
            };
            if tcp.sequence != self.sessions[index].rcv_nxt {
                return;
            }
            if !body.is_empty() {
                self.sessions[index].received.extend_from_slice(body);
                self.sessions[index].rcv_nxt =
                    self.sessions[index].rcv_nxt.wrapping_add(body.len() as u32);
            }
            let reply = {
                let session = &self.sessions[index];
                TcpHeader {
                    source_port: session.remote_port,
                    destination_port: session.local_port,
                    sequence: session.snd_nxt,
                    acknowledgement: session.rcv_nxt,
                    flags: flags::ACK,
                    window: self.window,
                }
            };
            let segment = encode_segment(reply, &[]);
            self.queue_tcp(&segment);
        }
    }

    impl BulkTransport for Device {
        fn send(&mut self, packet: &[u8]) -> io::Result<()> {
            self.state.borrow_mut().handle(packet);
            Ok(())
        }

        fn recv(&mut self, _timeout: Duration) -> io::Result<Option<Vec<u8>>> {
            Ok(self.state.borrow_mut().outbound.pop_front())
        }

        fn out_max_packet_size(&self) -> u16 {
            512
        }

        fn device_accepted_packets(&self) -> Option<u64> {
            Some(self.state.borrow().received.len() as u64)
        }
    }

    #[derive(Clone, Default)]
    pub(crate) struct Wire {
        sent: Rc<RefCell<Vec<Vec<u8>>>>,
        inbound: Rc<RefCell<VecDeque<Vec<u8>>>>,
    }

    impl Wire {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        pub(crate) fn queue(&self, packet: Vec<u8>) {
            self.inbound.borrow_mut().push_back(packet);
        }

        pub(crate) fn take_sent(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut self.sent.borrow_mut())
        }
    }

    impl BulkTransport for Wire {
        fn send(&mut self, packet: &[u8]) -> io::Result<()> {
            self.sent.borrow_mut().push(packet.to_vec());
            Ok(())
        }

        fn recv(&mut self, _timeout: Duration) -> io::Result<Option<Vec<u8>>> {
            Ok(self.inbound.borrow_mut().pop_front())
        }

        fn out_max_packet_size(&self) -> u16 {
            512
        }
    }

    pub(crate) fn encode_segment(header: TcpHeader, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; TCP_HEADER_LEN + payload.len()];
        header.encode(&mut out).expect("segment buffer is sized");
        out[TCP_HEADER_LEN..].copy_from_slice(payload);
        out
    }

    pub(crate) fn device_version_reply(version: u32) -> Vec<u8> {
        let mut packet = vec![0u8; VERSION_PACKET_LEN];
        packet[4..8].copy_from_slice(&(VERSION_PACKET_LEN as u32).to_be_bytes());
        packet[8..12].copy_from_slice(&version.to_be_bytes());
        packet
    }

    pub(crate) fn device_packet(seq: u16, rx_ack: u16, payload: &[u8]) -> Vec<u8> {
        let total = HEADER_LEN_V2 + payload.len();
        let mut packet = vec![0u8; total];
        packet[0..4].copy_from_slice(&Protocol::Tcp.wire_value().to_be_bytes());
        packet[4..8].copy_from_slice(&(total as u32).to_be_bytes());
        packet[8..12].copy_from_slice(&DEVICE_MAGIC.to_be_bytes());
        packet[12..14].copy_from_slice(&seq.to_be_bytes());
        packet[14..16].copy_from_slice(&rx_ack.to_be_bytes());
        packet[HEADER_LEN_V2..].copy_from_slice(payload);
        packet
    }

    pub(crate) fn negotiated_device() -> (MuxLink<Device>, Device) {
        let device = Device::new();
        let mut link = MuxLink::new(device.clone());
        assert_eq!(
            link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
                .unwrap(),
            MuxVersion::V2
        );
        (link, device)
    }

    fn negotiated_wire() -> (MuxLink<Wire>, Wire) {
        let wire = Wire::new();
        let mut link = MuxLink::new(wire.clone());
        wire.queue(device_version_reply(2));
        assert_eq!(
            link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
                .unwrap(),
            MuxVersion::V2
        );
        wire.take_sent();
        (link, wire)
    }

    fn drain_handshake_ack<T: BulkTransport>(link: &mut MuxLink<T>) {
        assert_eq!(
            link.drain_inbound().unwrap(),
            1,
            "the device answered the third leg of the handshake"
        );
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

    #[test]
    fn the_host_speaks_first_and_the_version_packet_is_unwrapped() {
        let device = Device::new();
        let mut link = MuxLink::new(device.clone());
        assert!(link.version().is_none());
        assert_eq!(
            link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
                .unwrap(),
            MuxVersion::V2
        );
        let sent = device.received_packets();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].len(), VERSION_PACKET_LEN);
        assert_eq!(&sent[0][0..4], &[0, 0, 0, 0]);
        assert_eq!(&sent[0][4..8], &[0, 0, 0, 0x14]);
        assert_eq!(&sent[0][8..12], &[0xFE, 0xED, 0xFA, 0xCE]);
    }

    #[test]
    fn negotiating_version_one_selects_the_eight_byte_header() {
        let (mut link, wire) = {
            let wire = Wire::new();
            let link = MuxLink::new(wire.clone());
            (link, wire)
        };
        wire.queue(device_version_reply(1));
        let version = link
            .negotiate(
                VersionRequest::exact(MuxVersion::V1),
                Duration::from_millis(50),
            )
            .unwrap();
        assert_eq!(version, MuxVersion::V1);
        assert_eq!(version.header_len(), 8);
        assert_eq!(link.segment_size().unwrap(), MAX_TRANSFER - 8 - 20);
    }

    #[test]
    fn the_segment_size_is_the_arithmetic_the_guest_does() {
        let (link, _device) = negotiated_device();
        assert_eq!(link.segment_size().unwrap(), 0x7FFC - 16 - 20);
        assert_eq!(link.segment_size().unwrap(), 32728);
    }

    #[test]
    fn nothing_can_be_sent_before_the_version_exchange() {
        let mut link = MuxLink::new(Wire::new());
        assert!(matches!(link.segment_size(), Err(MuxError::NotNegotiated)));
        assert!(matches!(
            link.open(62078, Duration::from_millis(1)),
            Err(MuxError::NotNegotiated)
        ));
        assert!(matches!(
            link.pump(Duration::from_millis(1)),
            Err(MuxError::NotNegotiated)
        ));
    }

    #[test]
    fn the_version_exchange_times_out_rather_than_blocking_forever() {
        let mut link = MuxLink::new(Wire::new());
        assert!(matches!(
            link.negotiate(VersionRequest::resync(), Duration::from_millis(5)),
            Err(MuxError::VersionTimedOut { .. })
        ));
    }

    #[test]
    fn the_first_sequenced_packet_after_the_handshake_carries_sequence_zero() {
        let (mut link, device) = negotiated_device();
        device.take_received_packets();
        link.open(62078, Duration::from_millis(200)).unwrap();
        let sent = device.received_packets();
        assert!(!sent.is_empty());
        let header = MuxHeader::decode(MuxVersion::V2, &sent[0]).unwrap();
        assert_eq!(header.tx_seq, 0);
        assert_eq!(header.protocol, Protocol::Tcp);
        assert_eq!(header.magic, HOST_MAGIC);
        assert_eq!(header.rx_ack, 0xFFFF);
    }

    #[test]
    fn the_sequence_increments_by_one_per_packet_and_the_device_never_faults() {
        let (mut link, device) = negotiated_device();
        device.take_received_packets();
        let port = link.open(62078, Duration::from_millis(200)).unwrap();
        link.write(port, b"one", Duration::from_millis(200))
            .unwrap();
        link.write(port, b"two", Duration::from_millis(200))
            .unwrap();
        link.close(port).unwrap();
        let sent = device.received_packets();
        assert!(sent.len() >= 4);
        for (index, packet) in sent.iter().enumerate() {
            let header = MuxHeader::decode(MuxVersion::V2, packet).unwrap();
            assert_eq!(header.tx_seq, index as u16, "packet {index}");
        }
        assert_eq!(device.sequence_faults(), 0);
    }

    #[test]
    fn the_declared_length_always_equals_the_transfer_length() {
        let (mut link, device) = negotiated_device();
        device.take_received_packets();
        let port = link.open(62078, Duration::from_millis(200)).unwrap();
        link.write(port, &vec![0xAB; 300], Duration::from_millis(200))
            .unwrap();
        let sent = device.received_packets();
        assert!(sent.len() >= 2);
        for packet in &sent {
            let header = MuxHeader::decode(MuxVersion::V2, packet).unwrap();
            assert_eq!(header.length as usize, packet.len());
        }
        assert_eq!(sent[0].len(), HEADER_LEN_V2 + TCP_HEADER_LEN);
    }

    #[test]
    fn a_full_handshake_opens_the_session_on_both_sides() {
        let (mut link, device) = negotiated_device();
        device.take_received_packets();
        let port = link.open(62078, Duration::from_millis(200)).unwrap();
        assert_eq!(link.session_state(port), Some(SessionState::Established));
        assert!(device.session_open(port));
        assert_eq!(device.only_session_ports(), (port, 62078));

        let sent = device.received_packets();
        assert!(sent.len() >= 2);
        let syn = TcpHeader::decode(&sent[0][HEADER_LEN_V2..]).unwrap();
        assert!(syn.is_bare_syn());
        assert_eq!(syn.destination_port, 62078);
        assert_eq!(sent[0].len(), HEADER_LEN_V2 + TCP_HEADER_LEN);
        let ack = TcpHeader::decode(&sent[1][HEADER_LEN_V2..]).unwrap();
        assert_eq!(ack.flags, flags::ACK);
        assert_eq!(ack.sequence, syn.sequence.wrapping_add(1));
        assert_eq!(ack.acknowledgement, 1);
    }

    #[test]
    fn a_handshake_the_device_never_answers_times_out_and_forgets_the_session() {
        let (mut link, _wire) = negotiated_wire();
        match link.open(62078, Duration::from_millis(20)) {
            Err(MuxError::HandshakeTimedOut { local_port, .. }) => {
                assert_eq!(local_port, FIRST_LOCAL_PORT);
                assert!(link.session_state(local_port).is_none());
            }
            other => panic!("expected the handshake to time out, got {other:?}"),
        }
    }

    #[test]
    fn a_gap_in_the_device_sequence_is_reported_and_not_papered_over() {
        let (mut link, wire) = negotiated_wire();
        wire.queue(device_packet(3, 0, &[0u8; TCP_HEADER_LEN]));
        assert!(matches!(
            link.pump(Duration::from_millis(10)),
            Err(MuxError::SequenceGap {
                expected: 0,
                received: 3
            })
        ));
    }

    #[test]
    fn a_segment_for_a_port_with_no_session_is_reported_rather_than_dropped_silently() {
        let (mut link, wire) = negotiated_wire();
        let header = TcpHeader {
            source_port: 62078,
            destination_port: 5555,
            sequence: 1,
            acknowledgement: 1,
            flags: flags::ACK,
            window: 65536,
        };
        wire.queue(device_packet(0, 0xFFFF, &encode_segment(header, &[])));
        assert_eq!(
            link.pump(Duration::from_millis(10)).unwrap(),
            LinkEvent::Unmatched { local_port: 5555 }
        );
    }

    #[test]
    fn a_transfer_that_does_not_frame_is_dropped_and_the_link_keeps_running() {
        let (mut link, wire) = negotiated_wire();
        wire.queue(vec![0u8; MAX_PACKET]);
        assert_eq!(
            link.pump(Duration::from_millis(10)).unwrap(),
            LinkEvent::Rejected {
                declared: 0,
                delivered: MAX_PACKET
            }
        );
        let header = TcpHeader {
            source_port: 62078,
            destination_port: 5555,
            sequence: 1,
            acknowledgement: 1,
            flags: flags::ACK,
            window: 65536,
        };
        wire.queue(device_packet(0, 0xFFFF, &encode_segment(header, &[])));
        assert_eq!(
            link.pump(Duration::from_millis(10)).unwrap(),
            LinkEvent::Unmatched { local_port: 5555 }
        );
    }

    #[test]
    fn an_idle_pipe_is_an_ordinary_state_and_not_an_error() {
        let (mut link, _wire) = negotiated_wire();
        assert_eq!(
            link.pump(Duration::from_millis(1)).unwrap(),
            LinkEvent::Idle
        );
    }

    #[test]
    fn a_packet_past_the_transfer_ceiling_is_refused_before_it_reaches_the_device() {
        let (mut link, _wire) = negotiated_wire();
        let oversized = vec![0u8; MAX_PACKET];
        assert!(matches!(
            link.send_packet(Protocol::Tcp, &oversized),
            Err(MuxError::TooLarge { .. })
        ));
    }

    #[test]
    fn data_flows_both_ways_and_arrives_in_order() {
        let (mut link, device) = negotiated_device();
        let port = link.open(62078, Duration::from_millis(200)).unwrap();

        assert_eq!(
            link.write(port, b"QueryType", Duration::from_millis(200))
                .unwrap(),
            9
        );
        assert_eq!(device.session_bytes(port), b"QueryType".to_vec());

        device.push(port, b"answer");
        let mut out = [0u8; 16];
        assert_eq!(
            link.read(port, &mut out, Duration::from_millis(200))
                .unwrap(),
            6
        );
        assert_eq!(&out[..6], b"answer");
    }

    #[test]
    fn a_write_larger_than_one_segment_is_split_and_reassembles_at_the_device() {
        let (mut link, device) = negotiated_device();
        let port = link.open(62078, Duration::from_millis(200)).unwrap();
        let payload: Vec<u8> = (0..4096u32).map(|byte| byte as u8).collect();
        assert_eq!(
            link.write(port, &payload, Duration::from_secs(1)).unwrap(),
            payload.len()
        );
        assert_eq!(device.session_bytes(port), payload);
    }

    #[test]
    fn a_send_window_that_is_shut_can_be_probed_and_says_what_it_is_parked_on() {
        let device = Device::new().with_window(0);
        let mut link = MuxLink::new(device.clone());
        assert_eq!(
            link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
                .unwrap(),
            MuxVersion::V2
        );
        let port = link.open(62078, Duration::from_millis(200)).unwrap();

        assert_eq!(link.queue_write(port, b"payload").unwrap(), 7);
        let parked = link.send_state(port).expect("the session is open");
        assert_eq!(parked.usable, 0, "the device advertised no room");
        assert_eq!(parked.pending, 7, "the whole write is stuck");
        assert_eq!(parked.peer_window, 0);
        assert_eq!(
            parked.snd_nxt, parked.snd_una,
            "nothing is in flight, so no acknowledgement is owed to this side"
        );
        assert_eq!(
            parked.snd_wnd_edge, parked.snd_nxt,
            "the edge is where the send pointer is, which is what a shut window is"
        );

        assert!(link.probe_window(port).unwrap());
        assert_eq!(
            link.send_state(port).unwrap().pending,
            7,
            "a probe is not a flush and must not consume the queue"
        );
        assert!(
            device.session_bytes(port).is_empty(),
            "a probe that carried payload would be sent past the device's window edge"
        );

        assert!(matches!(
            link.pump(Duration::from_millis(50)).unwrap(),
            LinkEvent::Session {
                event: SessionEvent::Acknowledged,
                ..
            }
        ));
        assert_eq!(link.send_state(port).unwrap().usable, 0);
        assert_eq!(link.send_state(port).unwrap().pending, 7);
    }

    #[test]
    fn a_segment_that_is_not_a_bare_ack_ends_the_session_by_name() {
        let (mut link, device) = negotiated_device();
        let port = link.open(62078, Duration::from_millis(200)).unwrap();
        drain_handshake_ack(&mut link);
        device.push_with_flags(port, b"x", flags::ACK | flags::PSH);
        assert!(matches!(
            link.pump(Duration::from_millis(50)).unwrap(),
            LinkEvent::Session {
                event: SessionEvent::ClosedByFlags { flags: 0x18 },
                ..
            }
        ));
        assert_eq!(link.session_state(port), Some(SessionState::Closed));
    }

    #[test]
    fn a_shut_window_holds_the_rest_back_rather_than_oversending() {
        let device = Device::new().with_window(1024);
        let mut link = MuxLink::new(device.clone());
        link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
            .unwrap();
        let port = link.open(62078, Duration::from_millis(200)).unwrap();
        let payload = vec![0xCD; 4096];
        let written = link.write(port, &payload, Duration::from_secs(1)).unwrap();
        assert_eq!(written, payload.len());
        assert_eq!(device.session_bytes(port), payload);
        for packet in device.received_packets() {
            if packet.len() > HEADER_LEN_V2 + TCP_HEADER_LEN {
                let body = packet.len() - HEADER_LEN_V2 - TCP_HEADER_LEN;
                assert!(body <= 1024, "a {body} byte segment exceeded the window");
            }
        }
    }

    #[test]
    fn closing_sends_a_reset_and_forgets_the_session() {
        let (mut link, device) = negotiated_device();
        let port = link.open(62078, Duration::from_millis(200)).unwrap();
        device.take_received_packets();
        link.close(port).unwrap();
        let sent = device.take_received_packets();
        assert_eq!(sent.len(), 1);
        let tcp = TcpHeader::decode(&sent[0][HEADER_LEN_V2..]).unwrap();
        assert_eq!(tcp.flags, flags::RST);
        assert!(link.session_state(port).is_none());
        assert!(!device.session_open(port));
        link.close(port).unwrap();
        assert!(device.take_received_packets().is_empty());
    }

    #[test]
    fn a_reset_from_the_device_closes_the_session_here() {
        let (mut link, device) = negotiated_device();
        let port = link.open(62078, Duration::from_millis(200)).unwrap();
        drain_handshake_ack(&mut link);
        device.reset(port);
        assert_eq!(
            link.pump(Duration::from_millis(50)).unwrap(),
            LinkEvent::Session {
                local_port: port,
                event: SessionEvent::Reset
            }
        );
        assert_eq!(link.session_state(port), Some(SessionState::Closed));
    }

    #[test]
    fn two_sessions_share_one_link_without_crossing() {
        let (mut link, device) = negotiated_device();
        let control = link.open(62078, Duration::from_millis(200)).unwrap();
        let data = link.open(50000, Duration::from_millis(200)).unwrap();
        assert_ne!(control, data);

        link.write(control, b"control", Duration::from_millis(200))
            .unwrap();
        link.write(data, b"payload", Duration::from_millis(200))
            .unwrap();
        assert_eq!(device.session_bytes(control), b"control".to_vec());
        assert_eq!(device.session_bytes(data), b"payload".to_vec());

        device.push(data, b"blocks");
        let mut out = [0u8; 8];
        assert_eq!(
            link.read(data, &mut out, Duration::from_millis(200))
                .unwrap(),
            6
        );
        assert_eq!(&out[..6], b"blocks");
        assert_eq!(link.received_len(control), 0);
    }

    #[test]
    fn liveness_counts_every_packet_the_device_sent_whatever_it_was_for() {
        let (mut link, wire) = negotiated_wire();
        assert_eq!(link.liveness().packets_received, 0);
        let header = TcpHeader {
            source_port: 62078,
            destination_port: 5555,
            sequence: 1,
            acknowledgement: 1,
            flags: flags::ACK,
            window: 65536,
        };
        wire.queue(device_packet(0, 0xFFFF, &encode_segment(header, &[])));
        link.pump(Duration::from_millis(10)).unwrap();
        assert_eq!(link.liveness().packets_received, 1);
    }

    #[test]
    fn a_packet_the_device_sent_that_this_side_cannot_use_still_counts_as_life() {
        let (mut link, wire) = negotiated_wire();
        wire.queue(device_packet(3, 0, &[0u8; TCP_HEADER_LEN]));
        assert!(link.pump(Duration::from_millis(10)).is_err());
        assert_eq!(link.liveness().packets_received, 1);
    }

    #[test]
    fn an_unknown_accepted_count_is_named_rather_than_rendered_as_a_zero() {
        let blind = LinkLiveness {
            packets_received: 7,
            packets_rejected: 0,
            packets_accepted: None,
        };
        assert!(blind.describe().contains("not visible to this transport"));
        let seen = LinkLiveness {
            packets_received: 7,
            packets_rejected: 0,
            packets_accepted: Some(2),
        };
        assert!(
            seen.describe().contains("accepted 2"),
            "{}",
            seen.describe()
        );
    }

    #[test]
    fn a_transport_that_cannot_see_the_device_end_reports_neither_present_nor_gone() {
        let (link, _wire) = negotiated_wire();
        assert_eq!(link.device_present(), None);
    }

    fn recording_meter() -> (
        RoundtripMeter,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&lines);
        let meter = RoundtripMeter::with_sink(
            crate::usbmux::roundtrip::LineBudget::new(16),
            Box::new(move |line: &str| sink.lock().unwrap().push(line.to_string())),
        );
        (meter, lines)
    }

    #[test]
    fn the_round_trip_meter_counts_every_segment_and_every_acknowledgement() {
        let device = Device::new().with_window(1024);
        let (meter, _lines) = recording_meter();
        let mut link = MuxLink::new(device.clone()).with_roundtrip_meter(meter);
        link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
            .unwrap();
        let port = link.open(62078, Duration::from_millis(200)).unwrap();
        drain_handshake_ack(&mut link);
        let payload = vec![0xCD; 4096];
        assert_eq!(
            link.write(port, &payload, Duration::from_secs(1)).unwrap(),
            payload.len()
        );

        let stats = link.roundtrip(port).expect("the port was recorded");
        assert_eq!(stats.bytes_queued, 4096);
        assert_eq!(stats.segments_sent, 4, "1024 bytes of window at a time");
        assert_eq!(stats.bytes_sent, 4096);
        assert_eq!(stats.blocked.count, 3);
        assert_eq!(stats.waited_window_open.count, 0);
        assert_eq!(stats.usable_at_block, 0);
        assert_eq!(stats.ack.count, 3);
        assert_eq!(stats.bytes_acked, 3072);
        assert_eq!(stats.unacked_now, 1);
        assert_eq!(stats.unacked_dropped, 0);
        assert_eq!(stats.peer_window, 1024);
        assert_eq!(stats.send.count, 4);
    }

    #[test]
    fn closing_a_session_reports_its_accounting_once() {
        let (meter, lines) = recording_meter();
        let device = Device::new();
        let mut link = MuxLink::new(device).with_roundtrip_meter(meter);
        link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
            .unwrap();
        let port = link.open(62078, Duration::from_millis(200)).unwrap();
        link.write(port, b"QueryType", Duration::from_millis(200))
            .unwrap();
        assert!(lines.lock().unwrap().is_empty(), "nothing said mid session");
        link.close(port).unwrap();
        let emitted = lines.lock().unwrap().clone();
        assert_eq!(emitted.len(), 1);
        assert!(emitted[0].starts_with(crate::usbmux::roundtrip::ROUNDTRIP_TAG));
        assert!(emitted[0].contains(&format!("port={port}")));
        assert!(emitted[0].contains("sent_bytes=9"));
        assert!(emitted[0].contains("blocked_n=0"));
        assert!(link.roundtrip(port).is_none(), "the port is finished with");
    }

    #[test]
    fn the_default_link_meter_is_silent_on_terminal_output() {
        let output = capture_stderr(|| {
            let device = Device::new();
            let mut link = MuxLink::new(device);
            link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
                .unwrap();
            let port = link.open(62078, Duration::from_millis(200)).unwrap();
            link.write(port, b"QueryType", Duration::from_millis(200))
                .unwrap();
            link.close(port).unwrap();
        });
        assert_eq!(output, "");
    }

    #[test]
    fn the_bounded_half_of_a_read_takes_what_arrived_without_waiting_for_more() {
        let (mut link, device) = negotiated_device();
        let port = link.open(62078, Duration::from_millis(200)).unwrap();
        let mut out = [0u8; 16];
        drain_handshake_ack(&mut link);
        assert_eq!(link.drain_inbound().unwrap(), 0, "nothing is waiting");
        assert_eq!(link.take_received(port, &mut out).unwrap(), 0);

        device.push(port, b"answer");
        assert_eq!(link.drain_inbound().unwrap(), 2);
        assert_eq!(link.take_received(port, &mut out).unwrap(), 6);
        assert_eq!(&out[..6], b"answer");
    }

    #[test]
    fn queueing_a_write_reports_what_the_window_would_not_take() {
        let device = Device::new().with_window(1024);
        let mut link = MuxLink::new(device.clone());
        link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
            .unwrap();
        let port = link.open(62078, Duration::from_millis(200)).unwrap();
        drain_handshake_ack(&mut link);
        let payload = vec![0xAB; 4096];
        assert_eq!(link.queue_write(port, &payload).unwrap(), 3072);
        assert_eq!(device.session_bytes(port).len(), 1024);
        assert_eq!(link.drain_inbound().unwrap(), 4);
        assert_eq!(link.pending_write(port).unwrap(), 0);
        assert_eq!(device.session_bytes(port).len(), 4096);
    }

    #[test]
    fn a_flush_drains_every_segment_the_window_allows_in_one_call() {
        let device = Device::new().with_window(16 * 1024 * 1024);
        let mut link = MuxLink::new(device.clone());
        link.negotiate(VersionRequest::resync(), Duration::from_millis(50))
            .unwrap();
        let port = link.open(62078, Duration::from_millis(200)).unwrap();
        drain_handshake_ack(&mut link);
        let mss = link.segment_size().unwrap();
        let payload = vec![0xAB; mss * 10];
        let leftover = link.queue_write(port, &payload).unwrap();
        assert_eq!(
            leftover, 0,
            "the window has room for all of it, so one flush call drains the whole queue"
        );
        assert_eq!(device.session_bytes(port).len(), mss * 10);
        let state = link.send_state(port).expect("the session is open");
        assert_eq!(state.pending, 0);
    }

    #[test]
    fn a_transport_that_cannot_signal_says_so_rather_than_pretending() {
        let (link, _wire) = negotiated_wire();
        assert!(link.inbound_signal().is_none());
        assert_eq!(link.inbound_generation(), 0);
    }

    #[test]
    fn ports_are_handed_out_without_collision() {
        let (mut link, _device) = negotiated_device();
        let first = link.open(62078, Duration::from_millis(200)).unwrap();
        assert_eq!(first, FIRST_LOCAL_PORT);
        let second = link.open(62078, Duration::from_millis(200)).unwrap();
        assert_ne!(second, first);
        link.next_local_port = first;
        let third = link.open(62078, Duration::from_millis(200)).unwrap();
        assert_ne!(third, first);
        assert_ne!(third, second);
    }
}
