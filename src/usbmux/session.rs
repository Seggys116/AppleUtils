use std::collections::VecDeque;
use std::fmt;

use super::tcp::{DEVICE_INITIAL_SEQUENCE, TcpHeader, flags};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    SynSent,
    Established,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    Established,
    Data { bytes: usize },
    Acknowledged,
    Reset,
    // Dropped exactly as the device drops it: no reassembly and no retransmission either side,
    // so a gap is terminal.
    OutOfOrder { expected: u32, received: u32 },
    ClosedByFlags { flags: u8 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionError {
    Closed,
    BadHandshake { flags: u8 },
    BadAcknowledgement { sent: u32, acknowledged: u32 },
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("the mux session is closed"),
            Self::BadHandshake { flags } => write!(
                f,
                "expected SYN and ACK from the device, flags were 0x{flags:02x}"
            ),
            Self::BadAcknowledgement { sent, acknowledged } => write!(
                f,
                "the device acknowledged {acknowledged} but only {sent} was ever sent"
            ),
        }
    }
}

impl std::error::Error for SessionError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub header: TcpHeader,
    pub payload: Vec<u8>,
}

impl Segment {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; super::tcp::TCP_HEADER_LEN + self.payload.len()];
        let written = self
            .header
            .encode(&mut out)
            .expect("a segment buffer is always sized for its own header");
        out[written..].copy_from_slice(&self.payload);
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionConfig {
    pub local_port: u16,
    pub remote_port: u16,
    pub initial_sequence: u32,
    pub mss: usize,
    pub receive_window: u32,
}

#[derive(Debug)]
pub struct MuxSession {
    config: SessionConfig,
    state: SessionState,
    snd_nxt: u32,
    snd_una: u32,
    snd_wnd_edge: u32,
    rcv_nxt: u32,
    outbound: VecDeque<u8>,
    inbound: VecDeque<u8>,
    owe_ack: bool,
    peer_window: u32,
    max_peer_window: u32,
    segments_in: u64,
}

impl MuxSession {
    // The SYN must carry no payload: the device answers one that does with a reset.
    #[must_use]
    pub fn open(config: SessionConfig) -> (Self, Segment) {
        let session = Self {
            config,
            state: SessionState::SynSent,
            snd_nxt: config.initial_sequence,
            snd_una: config.initial_sequence,
            snd_wnd_edge: config.initial_sequence,
            rcv_nxt: 0,
            outbound: VecDeque::new(),
            inbound: VecDeque::new(),
            owe_ack: false,
            peer_window: 0,
            max_peer_window: 0,
            segments_in: 0,
        };
        let header = TcpHeader {
            source_port: config.local_port,
            destination_port: config.remote_port,
            sequence: config.initial_sequence,
            acknowledgement: 0,
            flags: flags::SYN,
            window: config.receive_window,
        };
        (
            session,
            Segment {
                header,
                payload: Vec::new(),
            },
        )
    }

    #[must_use]
    pub fn state(&self) -> SessionState {
        self.state
    }

    #[must_use]
    pub fn ports(&self) -> (u16, u16) {
        (self.config.local_port, self.config.remote_port)
    }

    #[must_use]
    pub fn is_open(&self) -> bool {
        !matches!(self.state, SessionState::Closed)
    }

    #[must_use]
    pub fn received_len(&self) -> usize {
        self.inbound.len()
    }

    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.outbound.len()
    }

    pub fn queue(&mut self, data: &[u8]) {
        self.outbound.reserve(data.len());
        self.outbound.extend(data);
    }

    fn take_outbound(&mut self, take: usize) -> Vec<u8> {
        let mut payload = Vec::with_capacity(take);
        let (front, back) = self.outbound.as_slices();
        let from_front = front.len().min(take);
        payload.extend_from_slice(&front[..from_front]);
        if from_front < take {
            payload.extend_from_slice(&back[..take - from_front]);
        }
        self.outbound.drain(..take);
        payload
    }

    pub fn take_received(&mut self, out: &mut [u8]) -> usize {
        let taken = out.len().min(self.inbound.len());
        let (front, back) = self.inbound.as_slices();
        let from_front = front.len().min(taken);
        out[..from_front].copy_from_slice(&front[..from_front]);
        if from_front < taken {
            out[from_front..taken].copy_from_slice(&back[..taken - from_front]);
        }
        self.inbound.drain(..taken);
        taken
    }

    pub fn on_segment(
        &mut self,
        header: &TcpHeader,
        payload: &[u8],
    ) -> Result<SessionEvent, SessionError> {
        self.segments_in = self.segments_in.saturating_add(1);
        if header.is_reset() {
            self.state = SessionState::Closed;
            return Ok(SessionEvent::Reset);
        }
        match self.state {
            SessionState::Closed => Err(SessionError::Closed),
            SessionState::SynSent => self.on_syn_ack(header),
            SessionState::Established => self.on_established(header, payload),
        }
    }

    fn on_syn_ack(&mut self, header: &TcpHeader) -> Result<SessionEvent, SessionError> {
        if !header.is_syn_ack() {
            return Err(SessionError::BadHandshake {
                flags: header.flags,
            });
        }
        let expected = self.config.initial_sequence.wrapping_add(1);
        if header.acknowledgement != expected {
            return Err(SessionError::BadAcknowledgement {
                sent: expected,
                acknowledged: header.acknowledgement,
            });
        }
        self.snd_nxt = expected;
        self.snd_una = expected;
        self.snd_wnd_edge = header.window_edge();
        self.peer_window = header.window;
        self.max_peer_window = self.max_peer_window.max(header.window);
        self.rcv_nxt = header.sequence.wrapping_add(1);
        self.state = SessionState::Established;
        self.owe_ack = true;
        Ok(SessionEvent::Established)
    }

    fn on_established(
        &mut self,
        header: &TcpHeader,
        payload: &[u8],
    ) -> Result<SessionEvent, SessionError> {
        if !header.is_bare_ack() {
            self.state = SessionState::Closed;
            return Ok(SessionEvent::ClosedByFlags {
                flags: header.flags,
            });
        }
        if seq_gt(header.acknowledgement, self.snd_una) {
            if seq_gt(header.acknowledgement, self.snd_nxt) {
                return Err(SessionError::BadAcknowledgement {
                    sent: self.snd_nxt,
                    acknowledged: header.acknowledgement,
                });
            }
            self.snd_una = header.acknowledgement;
        }
        // The last segment's edge, never the widest seen: the device advertises free space rounded
        // down to 256, so its edge retracts by up to 255 and an older edge over-sends with no retransmit.
        self.snd_wnd_edge = header.window_edge();
        self.peer_window = header.window;
        self.max_peer_window = self.max_peer_window.max(header.window);
        if payload.is_empty() {
            return Ok(SessionEvent::Acknowledged);
        }
        if header.sequence != self.rcv_nxt {
            return Ok(SessionEvent::OutOfOrder {
                expected: self.rcv_nxt,
                received: header.sequence,
            });
        }
        self.inbound.reserve(payload.len());
        self.inbound.extend(payload);
        self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
        self.owe_ack = true;
        Ok(SessionEvent::Data {
            bytes: payload.len(),
        })
    }

    fn may_send_now(&self, take: usize) -> bool {
        take >= self.config.mss
            || take >= (self.max_peer_window / 2) as usize
            || take >= self.peer_window as usize
            || take == self.outbound.len()
            || self.in_flight() == 0
    }

    // Data held back by `may_send_now` must still fall through to an owed acknowledgement:
    // withholding one shuts the device's send window for good.
    pub fn next_segment(&mut self) -> Option<Segment> {
        if self.state != SessionState::Established {
            return None;
        }
        let usable = self.usable_window();
        if usable > 0 && !self.outbound.is_empty() {
            let take = self.outbound.len().min(self.config.mss).min(usable);
            if self.may_send_now(take) {
                let payload = self.take_outbound(take);
                let header = self.ack_header(self.snd_nxt);
                self.snd_nxt = self.snd_nxt.wrapping_add(take as u32);
                self.owe_ack = false;
                return Some(Segment { header, payload });
            }
        }
        if self.owe_ack {
            self.owe_ack = false;
            return Some(Segment {
                header: self.ack_header(self.snd_nxt),
                payload: Vec::new(),
            });
        }
        None
    }

    pub fn request_ack(&mut self) {
        if self.state == SessionState::Established {
            self.owe_ack = true;
        }
    }

    // Neither end probes on its own, so this is the only way a shut send window reopens. It goes out
    // as a bare acknowledgement at `snd_nxt`, taking no sequence number, or it could never be acked.
    pub fn probe_window(&mut self) -> bool {
        if self.state != SessionState::Established || self.owe_ack {
            return false;
        }
        if self.usable_window() > 0 && !self.outbound.is_empty() {
            return false;
        }
        self.owe_ack = true;
        true
    }

    // A reset is the only teardown the device cleans up without answering; a FIN draws a reset back.
    pub fn close(&mut self) -> Segment {
        self.state = SessionState::Closed;
        let header = TcpHeader {
            source_port: self.config.local_port,
            destination_port: self.config.remote_port,
            sequence: self.snd_nxt,
            acknowledgement: self.rcv_nxt,
            flags: flags::RST,
            window: 0,
        };
        Segment {
            header,
            payload: Vec::new(),
        }
    }

    #[must_use]
    pub fn usable_window(&self) -> usize {
        let room = self.snd_wnd_edge.wrapping_sub(self.snd_nxt);
        if (room as i32) <= 0 { 0 } else { room as usize }
    }

    #[must_use]
    pub fn snd_una(&self) -> u32 {
        self.snd_una
    }

    #[must_use]
    pub fn snd_nxt(&self) -> u32 {
        self.snd_nxt
    }

    #[must_use]
    pub fn in_flight(&self) -> u32 {
        self.snd_nxt.wrapping_sub(self.snd_una)
    }

    #[must_use]
    pub fn snd_wnd_edge(&self) -> u32 {
        self.snd_wnd_edge
    }

    #[must_use]
    pub fn segments_in(&self) -> u64 {
        self.segments_in
    }

    #[must_use]
    pub fn peer_window(&self) -> u32 {
        self.peer_window
    }

    #[must_use]
    pub fn advertised_window(&self) -> u32 {
        let used = u32::try_from(self.inbound.len()).unwrap_or(u32::MAX);
        self.config.receive_window.saturating_sub(used)
    }

    fn ack_header(&self, sequence: u32) -> TcpHeader {
        TcpHeader {
            source_port: self.config.local_port,
            destination_port: self.config.remote_port,
            sequence,
            acknowledgement: self.rcv_nxt,
            flags: flags::ACK,
            window: self.advertised_window(),
        }
    }
}

fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

pub const DEVICE_ISN: u32 = DEVICE_INITIAL_SEQUENCE;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usbmux::tcp::{TCP_HEADER_LEN, WINDOW_SCALE_SHIFT};

    const HOST_ISN: u32 = 0x1122_3344;
    const HOST_PORT: u16 = 49152;
    const RESTORED_PORT: u16 = 62078;

    const DEVICE_SYN_ACK: [u8; 20] = [
        0xF2, 0x7E, 0xC0, 0x00, //
        0x00, 0x00, 0x00, 0x00, // the device's sequence is zero
        0x11, 0x22, 0x33, 0x45, // the host sequence plus one
        0x50, 0x12, //
        0x01, 0x00, // window 0x0100, so 65536 bytes
        0x00, 0x00, 0x00, 0x00,
    ];

    fn config() -> SessionConfig {
        SessionConfig {
            local_port: HOST_PORT,
            remote_port: RESTORED_PORT,
            initial_sequence: HOST_ISN,
            mss: 1024,
            receive_window: 65536,
        }
    }

    fn established() -> MuxSession {
        let (mut session, _syn) = MuxSession::open(config());
        let header = TcpHeader::decode(&DEVICE_SYN_ACK).unwrap();
        assert_eq!(
            session.on_segment(&header, &[]).unwrap(),
            SessionEvent::Established
        );
        session
    }

    #[test]
    fn a_wide_window_emits_until_the_window_is_full() {
        let mut session = established();
        session.queue(&vec![0xAB; 128_000]);
        let mut sent = 0usize;
        let mut segments = 0usize;
        while let Some(segment) = session.next_segment() {
            if segment.payload.is_empty() {
                break;
            }
            segments += 1;
            sent += segment.payload.len();
        }
        assert_eq!(segments, 64);
        assert_eq!(sent, 65_536);
        assert!(session.pending_len() > 0);
        assert_eq!(session.usable_window(), 0);
        assert_eq!(session.in_flight() as usize, sent);
    }

    #[test]
    fn opening_produces_a_bare_syn_with_no_payload() {
        let (session, syn) = MuxSession::open(config());
        assert_eq!(session.state(), SessionState::SynSent);
        assert!(syn.header.is_bare_syn());
        assert!(syn.payload.is_empty());
        assert_eq!(syn.to_bytes().len(), TCP_HEADER_LEN);
        assert_eq!(syn.header.destination_port, RESTORED_PORT);
        assert_eq!(syn.header.sequence, HOST_ISN);
    }

    #[test]
    fn the_handshake_completes_on_the_device_syn_ack_and_takes_its_window() {
        let session = established();
        assert_eq!(session.state(), SessionState::Established);
        assert_eq!(session.rcv_nxt, DEVICE_ISN.wrapping_add(1));
        assert_eq!(session.snd_nxt, HOST_ISN.wrapping_add(1));
        assert_eq!(session.usable_window(), 65536);
    }

    #[test]
    fn an_answer_that_is_not_syn_and_ack_is_refused() {
        let (mut session, _syn) = MuxSession::open(config());
        let mut bytes = DEVICE_SYN_ACK;
        bytes[13] = flags::ACK;
        let header = TcpHeader::decode(&bytes).unwrap();
        assert!(matches!(
            session.on_segment(&header, &[]),
            Err(SessionError::BadHandshake { flags: 0x10 })
        ));
    }

    #[test]
    fn an_answer_acknowledging_a_sequence_never_sent_is_refused() {
        let (mut session, _syn) = MuxSession::open(config());
        let mut bytes = DEVICE_SYN_ACK;
        bytes[11] = 0x99;
        let header = TcpHeader::decode(&bytes).unwrap();
        assert!(matches!(
            session.on_segment(&header, &[]),
            Err(SessionError::BadAcknowledgement { .. })
        ));
    }

    #[test]
    fn the_handshake_leaves_an_acknowledgement_owed_so_the_device_learns_our_window() {
        let mut session = established();
        let segment = session
            .next_segment()
            .expect("the third leg of the handshake");
        assert!(segment.header.is_bare_ack());
        assert!(segment.payload.is_empty());
        assert_eq!(segment.header.sequence, HOST_ISN.wrapping_add(1));
        assert_eq!(segment.header.acknowledgement, DEVICE_ISN.wrapping_add(1));
        assert_eq!(segment.header.window, 65536);
        assert!(session.next_segment().is_none());
    }

    #[test]
    fn queued_data_leaves_as_bare_acks_because_that_is_the_only_form_accepted() {
        let mut session = established();
        let _third_leg = session.next_segment();
        session.queue(b"hello");
        let segment = session.next_segment().unwrap();
        assert_eq!(segment.header.flags, flags::ACK);
        assert_eq!(segment.payload, b"hello");
        assert_eq!(segment.header.sequence, HOST_ISN.wrapping_add(1));
        assert!(session.next_segment().is_none());
    }

    #[test]
    fn sending_is_split_at_the_segment_size() {
        let mut session = established();
        let _third_leg = session.next_segment();
        session.queue(&vec![0xAA; 2500]);
        let first = session.next_segment().unwrap();
        assert_eq!(first.payload.len(), 1024);
        let second = session.next_segment().unwrap();
        assert_eq!(second.payload.len(), 1024);
        assert_eq!(
            second.header.sequence,
            first.header.sequence.wrapping_add(1024)
        );
        let third = session.next_segment().unwrap();
        assert_eq!(third.payload.len(), 452);
        assert!(session.next_segment().is_none());
    }

    #[test]
    fn sending_stops_at_the_window_the_device_advertised() {
        let mut config = config();
        config.mss = 4096;
        let (mut session, _syn) = MuxSession::open(config);
        let mut bytes = DEVICE_SYN_ACK;
        bytes[14] = 0x00;
        bytes[15] = 0x04;
        let header = TcpHeader::decode(&bytes).unwrap();
        session.on_segment(&header, &[]).unwrap();
        let _third_leg = session.next_segment();
        session.queue(&vec![0xBB; 4096]);
        let segment = session.next_segment().unwrap();
        assert_eq!(segment.payload.len(), 1024);
        assert_eq!(session.usable_window(), 0);
        assert!(session.next_segment().is_none(), "the window is shut");
        assert_eq!(session.pending_len(), 3072);
    }

    fn retracting_device() -> (MuxSession, u32) {
        let mut config = config();
        config.mss = 32728;
        let (mut session, _syn) = MuxSession::open(config);
        let mut bytes = DEVICE_SYN_ACK;
        bytes[14] = 0x00;
        bytes[15] = 0x41;
        session
            .on_segment(&TcpHeader::decode(&bytes).unwrap(), &[])
            .unwrap();
        let _third_leg = session.next_segment();
        let base = HOST_ISN.wrapping_add(1);
        assert_eq!(session.snd_una(), base);
        assert_eq!(session.snd_wnd_edge(), base.wrapping_add(16640));
        (session, base)
    }

    fn device_ack(session: &MuxSession, acknowledgement: u32, window: u32) -> TcpHeader {
        TcpHeader {
            source_port: RESTORED_PORT,
            destination_port: HOST_PORT,
            sequence: session.rcv_nxt,
            acknowledgement,
            flags: flags::ACK,
            window,
        }
    }

    #[test]
    fn the_send_window_edge_follows_the_device_back_when_it_retracts() {
        let (mut session, base) = retracting_device();
        session.queue(&vec![0xCC; 248]);
        assert_eq!(session.next_segment().unwrap().payload.len(), 248);
        session.queue(&vec![0xCC; 1 << 20]);

        let retracted = device_ack(&session, base.wrapping_add(248), 16384);
        assert_eq!(
            session.on_segment(&retracted, &[]).unwrap(),
            SessionEvent::Acknowledged
        );
        assert_eq!(
            session.snd_wnd_edge(),
            base.wrapping_add(248 + 16384),
            "the edge is the last segment's, not the widest one ever seen"
        );
        assert_eq!(session.peer_window(), 16384);
        assert_eq!(
            session.usable_window(),
            16384,
            "16392 is what the withdrawn edge said"
        );

        let segment = session.next_segment().expect("the window is open");
        assert_eq!(
            segment.payload.len(),
            16384,
            "16392 bytes here is 8 past the edge the device is holding"
        );
        assert_eq!(session.snd_nxt(), base.wrapping_add(248 + 16384));
        assert_eq!(session.in_flight(), 16384);
        assert!(
            session.in_flight() <= session.peer_window(),
            "in flight {} is past the window {}",
            session.in_flight(),
            session.peer_window()
        );
        assert_eq!(session.usable_window(), 0);
        assert!(session.next_segment().is_none(), "the window is shut");
    }

    #[test]
    fn a_retraction_under_bytes_already_sent_stops_the_sender_rather_than_wrapping() {
        let (mut session, base) = retracting_device();
        session.queue(&vec![0xCC; 1 << 20]);
        let segment = session.next_segment().expect("the window is open");
        assert_eq!(segment.payload.len(), 16640);
        assert_eq!(session.snd_nxt(), base.wrapping_add(16640));

        let retracted = device_ack(&session, base.wrapping_add(248), 16384);
        session.on_segment(&retracted, &[]).unwrap();
        assert_eq!(session.snd_wnd_edge(), base.wrapping_add(248 + 16384));
        assert_eq!(
            session.in_flight(),
            16392,
            "the residue of a send that was inside the window when it went out"
        );
        assert_eq!(
            session.usable_window(),
            0,
            "an edge behind the send pointer is a shut window"
        );
        assert!(session.next_segment().is_none());
        assert_eq!(session.pending_len(), (1 << 20) - 16640);

        let onward = device_ack(&session, base.wrapping_add(16640), 16384);
        session.on_segment(&onward, &[]).unwrap();
        assert_eq!(session.usable_window(), 16384);
    }

    #[test]
    fn a_window_probe_consumes_no_sequence_space() {
        let (mut session, base) = retracting_device();
        session.queue(&vec![0xCC; 1 << 20]);
        let _filled = session.next_segment().expect("the window is open");
        let nxt = session.snd_nxt();
        let una = session.snd_una();
        assert_eq!(session.usable_window(), 0);

        for _ in 0..8 {
            assert!(session.probe_window());
            let probe = session.next_segment().expect("the probe arms a segment");
            assert!(probe.payload.is_empty());
            assert_eq!(probe.header.sequence, nxt);
            assert_eq!(session.snd_nxt(), nxt, "a probe must not move snd_nxt");
            assert_eq!(session.snd_una(), una);
            assert_eq!(session.in_flight(), 16640);
        }
        assert_eq!(base.wrapping_add(16640), nxt);
    }

    #[test]
    fn every_inbound_segment_is_counted_so_silence_can_be_told_from_an_answer() {
        let (mut session, base) = retracting_device();
        assert_eq!(session.segments_in(), 1, "the SYN-ACK is one");
        session.queue(&vec![0xCC; 1 << 20]);
        let _filled = session.next_segment().expect("the window is open");

        let marks = |session: &MuxSession| {
            (
                session.snd_una(),
                session.snd_nxt(),
                session.snd_wnd_edge(),
                session.peer_window(),
                session.usable_window(),
            )
        };
        let before = marks(&session);
        for answer in 1..=5u64 {
            let repeat = device_ack(&session, base, 16640);
            assert_eq!(
                session.on_segment(&repeat, &[]).unwrap(),
                SessionEvent::Acknowledged
            );
            assert_eq!(session.segments_in(), 1 + answer);
            assert_eq!(
                marks(&session),
                before,
                "nothing else on the line moves for a repeated window"
            );
        }
    }

    #[test]
    fn an_acknowledgement_reopens_the_window() {
        let mut config = config();
        config.mss = 4096;
        let (mut session, _syn) = MuxSession::open(config);
        let mut bytes = DEVICE_SYN_ACK;
        bytes[14] = 0x00;
        bytes[15] = 0x04;
        session
            .on_segment(&TcpHeader::decode(&bytes).unwrap(), &[])
            .unwrap();
        let _third_leg = session.next_segment();
        session.queue(&vec![0xBB; 4096]);
        let first = session.next_segment().unwrap();
        assert_eq!(first.payload.len(), 1024);

        let ack = TcpHeader {
            source_port: RESTORED_PORT,
            destination_port: HOST_PORT,
            sequence: DEVICE_ISN.wrapping_add(1),
            acknowledgement: session.snd_nxt,
            flags: flags::ACK,
            window: 2048,
        };
        assert_eq!(
            session.on_segment(&ack, &[]).unwrap(),
            SessionEvent::Acknowledged
        );
        assert_eq!(session.usable_window(), 2048);
        let second = session.next_segment().unwrap();
        assert_eq!(second.payload.len(), 2048);
    }

    #[test]
    fn inbound_payload_is_accepted_in_order_and_advances_the_expectation() {
        let mut session = established();
        let _third_leg = session.next_segment();
        let header = TcpHeader {
            source_port: RESTORED_PORT,
            destination_port: HOST_PORT,
            sequence: DEVICE_ISN.wrapping_add(1),
            acknowledgement: session.snd_nxt,
            flags: flags::ACK,
            window: 65536,
        };
        assert_eq!(
            session.on_segment(&header, b"abcd").unwrap(),
            SessionEvent::Data { bytes: 4 }
        );
        assert_eq!(session.received_len(), 4);
        let mut out = [0u8; 8];
        assert_eq!(session.take_received(&mut out), 4);
        assert_eq!(&out[..4], b"abcd");

        let ack = session.next_segment().unwrap();
        assert_eq!(ack.header.acknowledgement, DEVICE_ISN.wrapping_add(5));
        assert!(ack.payload.is_empty());
    }

    #[test]
    fn a_segment_that_is_not_the_next_one_is_dropped_exactly_as_the_device_drops_it() {
        let mut session = established();
        let _third_leg = session.next_segment();
        let header = TcpHeader {
            source_port: RESTORED_PORT,
            destination_port: HOST_PORT,
            sequence: DEVICE_ISN.wrapping_add(9),
            acknowledgement: session.snd_nxt,
            flags: flags::ACK,
            window: 65536,
        };
        assert_eq!(
            session.on_segment(&header, b"abcd").unwrap(),
            SessionEvent::OutOfOrder {
                expected: 1,
                received: 9
            }
        );
        assert_eq!(session.received_len(), 0);
    }

    #[test]
    fn the_advertised_window_shrinks_as_data_goes_unread() {
        let mut session = established();
        let _third_leg = session.next_segment();
        let header = TcpHeader {
            source_port: RESTORED_PORT,
            destination_port: HOST_PORT,
            sequence: DEVICE_ISN.wrapping_add(1),
            acknowledgement: session.snd_nxt,
            flags: flags::ACK,
            window: 65536,
        };
        session.on_segment(&header, &vec![0u8; 4096]).unwrap();
        assert_eq!(session.advertised_window(), 65536 - 4096);
        let mut sink = vec![0u8; 4096];
        session.take_received(&mut sink);
        assert_eq!(session.advertised_window(), 65536);
        session.request_ack();
        let ack = session.next_segment().unwrap();
        assert_eq!(ack.header.window, 65536);
    }

    #[test]
    fn a_reset_from_the_device_closes_the_session() {
        let mut session = established();
        let header = TcpHeader {
            source_port: RESTORED_PORT,
            destination_port: HOST_PORT,
            sequence: DEVICE_ISN.wrapping_add(1),
            acknowledgement: session.snd_nxt,
            flags: flags::RST,
            window: 0,
        };
        assert_eq!(
            session.on_segment(&header, &[]).unwrap(),
            SessionEvent::Reset
        );
        assert_eq!(session.state(), SessionState::Closed);
        assert!(!session.is_open());
        assert!(session.next_segment().is_none());
        assert!(matches!(
            session.on_segment(&header, &[]),
            Ok(SessionEvent::Reset)
        ));
    }

    #[test]
    fn closing_sends_a_reset_rather_than_a_final_segment() {
        let mut session = established();
        let segment = session.close();
        assert_eq!(segment.header.flags, flags::RST);
        assert!(segment.payload.is_empty());
        assert_eq!(session.state(), SessionState::Closed);
    }

    #[test]
    fn anything_but_a_bare_ack_on_an_established_session_ends_it() {
        let mut session = established();
        let header = TcpHeader {
            source_port: RESTORED_PORT,
            destination_port: HOST_PORT,
            sequence: DEVICE_ISN.wrapping_add(1),
            acknowledgement: session.snd_nxt,
            flags: flags::ACK | flags::PSH,
            window: 65536,
        };
        assert_eq!(
            session.on_segment(&header, b"x").unwrap(),
            SessionEvent::ClosedByFlags {
                flags: flags::ACK | flags::PSH
            }
        );
        assert_eq!(session.state(), SessionState::Closed);
    }

    fn streaming_session(window: u32) -> MuxSession {
        let mut config = config();
        config.mss = 32728;
        let (mut session, _syn) = MuxSession::open(config);
        let mut bytes = DEVICE_SYN_ACK;
        let field = (window >> WINDOW_SCALE_SHIFT) as u16;
        bytes[14] = (field >> 8) as u8;
        bytes[15] = field as u8;
        session
            .on_segment(&TcpHeader::decode(&bytes).unwrap(), &[])
            .unwrap();
        let _third_leg = session.next_segment();
        session
    }

    #[test]
    fn a_window_remainder_too_small_for_a_segment_is_held_rather_than_sent() {
        let mut session = streaming_session(65_792);
        session.queue(&vec![0xDD; 1 << 20]);

        assert_eq!(session.next_segment().unwrap().payload.len(), 32_728);
        assert_eq!(session.next_segment().unwrap().payload.len(), 32_728);
        assert_eq!(session.usable_window(), 336, "the remainder is real room");
        assert!(
            session.next_segment().is_none(),
            "336 bytes is not worth a transfer while 65,456 are in flight"
        );
    }

    #[test]
    fn the_held_remainder_leaves_in_the_next_full_segment() {
        let mut session = streaming_session(65_792);
        let base = session.snd_nxt();
        session.queue(&vec![0xDD; 1 << 20]);
        assert_eq!(session.next_segment().unwrap().payload.len(), 32_728);
        assert_eq!(session.next_segment().unwrap().payload.len(), 32_728);
        assert!(session.next_segment().is_none());

        let ack = device_ack(&session, base.wrapping_add(32_728), 65_792);
        session.on_segment(&ack, &[]).unwrap();
        assert_eq!(
            session.next_segment().unwrap().payload.len(),
            32_728,
            "the remainder went out inside a full segment, not beside one"
        );
    }

    #[test]
    fn nothing_in_flight_sends_whatever_is_queued_however_small() {
        let mut session = streaming_session(65_792);
        session.queue(b"four");
        let segment = session
            .next_segment()
            .expect("nothing is in flight, so nothing is waited for");
        assert_eq!(segment.payload, b"four");
    }

    #[test]
    fn the_tail_of_a_write_is_never_held_behind_a_size_test() {
        let mut session = streaming_session(131_072);
        let base = session.snd_nxt();
        session.queue(&vec![0xEE; 32_728 + 400]);
        assert_eq!(session.next_segment().unwrap().payload.len(), 32_728);
        let tail = session
            .next_segment()
            .expect("the last 400 bytes empty the queue, so they are not held");
        assert_eq!(tail.payload.len(), 400);
        assert_eq!(tail.header.sequence, base.wrapping_add(32_728));
        assert_eq!(session.pending_len(), 0);
    }

    #[test]
    fn a_window_narrower_than_a_segment_still_fills_it_every_time() {
        let mut session = streaming_session(16_640);
        let base = session.snd_nxt();
        session.queue(&vec![0xCC; 1 << 20]);
        assert_eq!(session.next_segment().unwrap().payload.len(), 16_640);

        let ack = device_ack(&session, base.wrapping_add(16_640), 16_640);
        session.on_segment(&ack, &[]).unwrap();
        assert_eq!(
            session.next_segment().unwrap().payload.len(),
            16_640,
            "the window is the ceiling here, so every send fills it"
        );
    }

    #[test]
    fn held_data_does_not_hold_the_acknowledgement_the_device_is_owed() {
        let mut session = streaming_session(65_792);
        session.queue(&vec![0xDD; 1 << 20]);
        let _first = session.next_segment().unwrap();
        let _second = session.next_segment().unwrap();
        assert!(session.next_segment().is_none());

        let header = TcpHeader {
            source_port: RESTORED_PORT,
            destination_port: HOST_PORT,
            sequence: session.rcv_nxt,
            acknowledgement: session.snd_una(),
            flags: flags::ACK,
            window: 65_792,
        };
        session.on_segment(&header, b"status").unwrap();
        let owed = session
            .next_segment()
            .expect("the acknowledgement is owed whether or not data is held");
        assert!(owed.payload.is_empty());
        assert_eq!(owed.header.acknowledgement, session.rcv_nxt);
    }

    #[test]
    fn a_probe_arms_the_same_bare_acknowledgement_the_session_already_sends() {
        let mut config = config();
        config.mss = 4096;
        let (mut session, _syn) = MuxSession::open(config);
        let mut bytes = DEVICE_SYN_ACK;
        bytes[14] = 0x00;
        bytes[15] = 0x04;
        session
            .on_segment(&TcpHeader::decode(&bytes).unwrap(), &[])
            .unwrap();
        let _ = session.next_segment();
        session.queue(&vec![0u8; 4096]);
        assert_eq!(session.next_segment().unwrap().payload.len(), 1024);
        assert_eq!(session.usable_window(), 0);
        assert!(session.pending_len() > 0);
        assert!(session.next_segment().is_none(), "the window is shut");

        assert!(session.probe_window());
        let probe = session.next_segment().expect("the probe arms a segment");
        assert_eq!(probe.header.flags, flags::ACK);
        assert!(
            probe.payload.is_empty(),
            "a probe carrying payload would be read past the device's window edge"
        );
        assert_eq!(
            probe.header.sequence,
            session.snd_nxt(),
            "the device delivers only on an exact sequence match"
        );
        assert_eq!(probe.header.acknowledgement, session.rcv_nxt);
        assert_eq!(probe.header.window, session.advertised_window());

        session.request_ack();
        assert!(!session.probe_window());
    }

    #[test]
    fn a_probe_does_nothing_on_a_session_that_is_not_established() {
        let (mut session, _syn) = MuxSession::open(config());
        assert!(
            !session.probe_window(),
            "nothing to probe before the handshake"
        );
        let mut session = established();
        let _reset = session.close();
        assert!(!session.probe_window(), "a closed session is not probed");
    }

    #[test]
    fn a_probe_is_not_armed_while_the_window_is_open() {
        let mut session = established();
        assert!(session.next_segment().is_some());
        session.queue(b"payload");
        assert!(session.usable_window() > 0);
        assert!(!session.probe_window());
    }

    #[test]
    fn sequence_comparison_is_modular_so_a_session_survives_the_wrap() {
        assert!(seq_gt(1, 0));
        assert!(!seq_gt(0, 1));
        assert!(seq_gt(5, 0xFFFF_FFF0));
        assert!(!seq_gt(0xFFFF_FFF0, 5));
        assert!(!seq_gt(7, 7));

        let mut config = config();
        config.initial_sequence = 0xFFFF_FFFE;
        let (mut session, syn) = MuxSession::open(config);
        assert_eq!(syn.header.sequence, 0xFFFF_FFFE);
        let header = TcpHeader {
            source_port: RESTORED_PORT,
            destination_port: HOST_PORT,
            sequence: DEVICE_ISN,
            acknowledgement: 0xFFFF_FFFF,
            flags: flags::SYN_ACK,
            window: 65536,
        };
        session.on_segment(&header, &[]).unwrap();
        assert_eq!(session.snd_nxt, 0xFFFF_FFFF);
        let _third_leg = session.next_segment();
        session.queue(b"ab");
        let segment = session.next_segment().unwrap();
        assert_eq!(segment.header.sequence, 0xFFFF_FFFF);
        assert_eq!(session.snd_nxt, 1);
    }

    #[test]
    fn a_segment_serialises_to_its_header_followed_by_its_payload() {
        let mut session = established();
        let _third_leg = session.next_segment();
        session.queue(b"xyz");
        let segment = session.next_segment().unwrap();
        let bytes = segment.to_bytes();
        assert_eq!(bytes.len(), TCP_HEADER_LEN + 3);
        assert_eq!(&bytes[TCP_HEADER_LEN..], b"xyz");
        assert_eq!(TcpHeader::decode(&bytes).unwrap(), segment.header);
    }
}
