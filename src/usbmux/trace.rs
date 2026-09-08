use std::fmt;
use std::time::Duration;

use super::frame::MuxVersion;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MuxTraceEvent {
    VersionSent {
        version: u32,
        bytes: usize,
    },
    VersionTimedOut {
        waited: Duration,
    },
    VersionNegotiated {
        version: MuxVersion,
        header_len: usize,
        segment_size: usize,
    },
    SynSent {
        local_port: u16,
        remote_port: u16,
        sequence: u32,
    },
    SynAckReceived {
        local_port: u16,
        device_sequence: u32,
        window: u32,
    },
    SessionEstablished {
        local_port: u16,
        remote_port: u16,
    },
    HandshakeTimedOut {
        local_port: u16,
        waited: Duration,
    },
    Sent {
        local_port: u16,
        bytes: usize,
    },
    Received {
        local_port: u16,
        bytes: usize,
    },
    SequenceGap {
        expected: u16,
        received: u16,
    },
    OutOfOrder {
        local_port: u16,
        expected: u32,
        received: u32,
    },
    Reset {
        local_port: u16,
    },
    Unmatched {
        local_port: u16,
    },
    OtherProtocol {
        protocol: u32,
    },
    PacketRejected {
        protocol: u32,
        declared: u32,
        delivered: usize,
        magic: u32,
        head: [u8; 16],
        rejected: u64,
    },
    ReadPollExpired {
        local_port: u16,
        waited: Duration,
        elapsed: Duration,
    },
    WriteWindowShut {
        local_port: u16,
        snd_una: u32,
        snd_nxt: u32,
        snd_wnd_edge: u32,
        peer_window: u32,
        pending: usize,
        segments_in: u64,
        waited: Duration,
        elapsed: Duration,
        probed: bool,
    },
    SessionClosedByFlags {
        local_port: u16,
        flags: u8,
    },
    DeviceGone {
        local_port: u16,
    },
    LinkStalled {
        phase: super::watchdog::LinkPhase,
        port: u16,
        held: Duration,
        waiters: u32,
        acquisitions: u64,
        since_acquisition: Duration,
        stalled: Duration,
        packets_in: u64,
        packets_out: u64,
        queued: u64,
        deferred: u64,
        idle_reads: u64,
        refused: u64,
    },
    LinkResumed {
        stalled: Duration,
        acquisitions: u64,
        packets_in: u64,
        packets_out: u64,
    },
}

impl MuxTraceEvent {
    #[must_use]
    pub fn result(&self) -> &'static str {
        match self {
            Self::VersionSent { .. } => "version-sent",
            Self::VersionTimedOut { .. } => "version-no-reply",
            Self::VersionNegotiated { .. } => "version-negotiated",
            Self::SynSent { .. } => "syn-sent",
            Self::SynAckReceived { .. } => "syn-ack-received",
            Self::SessionEstablished { .. } => "session-established",
            Self::HandshakeTimedOut { .. } => "handshake-no-reply",
            Self::Sent { .. } => "sent",
            Self::Received { .. } => "received",
            Self::SequenceGap { .. } => "sequence-gap",
            Self::OutOfOrder { .. } => "out-of-order",
            Self::Reset { .. } => "reset",
            Self::Unmatched { .. } => "unmatched",
            Self::OtherProtocol { .. } => "other-protocol",
            Self::PacketRejected { .. } => "packet-rejected",
            Self::ReadPollExpired { .. } => "read-poll-expired",
            Self::WriteWindowShut { .. } => "write-window-shut",
            Self::SessionClosedByFlags { .. } => "session-closed-by-flags",
            Self::DeviceGone { .. } => "device-gone",
            Self::LinkStalled { .. } => "link-stalled",
            Self::LinkResumed { .. } => "link-resumed",
        }
    }

    #[must_use]
    pub fn meaning(&self) -> &'static str {
        match self {
            Self::VersionSent { .. } => {
                "the host opened the conversation; the device cannot speak first, so silence after this line means the packet did not reach the mux function"
            }
            Self::VersionTimedOut { .. } => {
                "the version packet was written and nothing came back; check the bulk pair selection, that the packet went as one transfer, and that the interface was activated"
            }
            Self::VersionNegotiated { .. } => {
                "the device answered and the framing is agreed; sessions can now be opened"
            }
            Self::SynSent { .. } => "a session was requested on a guest port",
            Self::SynAckReceived { .. } => {
                "the device connected to 127.0.0.1 on that port inside itself and answered"
            }
            Self::SessionEstablished { .. } => "the session can carry bytes in both directions",
            Self::HandshakeTimedOut { .. } => {
                "the mux answered the version packet but not the SYN; nothing is listening on that guest port yet, or the connect inside the guest failed"
            }
            Self::Sent { .. } => "payload left the host",
            Self::Received { .. } => "payload arrived from the guest",
            Self::SequenceGap { .. } => {
                "the device's packet counter skipped; neither side has a reassembly queue, so this link cannot recover and the run should stop"
            }
            Self::OutOfOrder { .. } => {
                "a segment was not the next one and was dropped, exactly as the device drops it; the session is unrecoverable"
            }
            Self::Reset { .. } => "the device ended the session",
            Self::Unmatched { .. } => {
                "a segment arrived for a port with no session, which is a stale segment from a session that was already closed"
            }
            Self::OtherProtocol { .. } => {
                "the device sent a protocol other than TCP, which is informational"
            }
            Self::PacketRejected { .. } => {
                "a transfer came off the bulk IN endpoint that does not frame as a mux packet, so it was dropped and the link kept running, exactly as handleMuxInput drops what it cannot frame rather than tearing the link down; the sequence counter is not advanced, because a packet with no readable header carries no sequence to advance past, so a device that really did send this one answers with a sequence-gap on its next packet and nothing is masked; delivered above 0x7ffc means the device cannot have sent it at all, since sendMuxSegment sizes every packet it sends off that bound, and an all-zero head is one of the eight 0x8000 host-to-device read buffers allocateUSBReadBuffers hands out, taken as though it were a transfer the device was offering"
            }
            Self::ReadPollExpired { .. } => {
                "no data to read, so the read went round again; a quiet session is not a dead one and nothing here counts towards ending it"
            }
            Self::WriteWindowShut { .. } => {
                "the device's window has been shut for the whole poll, so nothing queued can leave; edge minus nxt is the room the device's last segment left and only an inbound segment moves it, and answers is the count of segments the device has sent on this session, which is the only field that separates a device answering every probe with the window it already gave from a device that has stopped answering, because none of the sequence numbers move in either case; past-edge must be 0, and anything above it is the host holding a right edge the device has withdrawn and sending past what the device can take, which is a host sending past what the device can take"
            }
            Self::SessionClosedByFlags { .. } => {
                "a segment whose flag byte was not a bare acknowledgement arrived on an established session, and the device answers that with a reset, so this session is finished; this is a framing failure on the link, not a quiet guest"
            }
            Self::DeviceGone { .. } => {
                "the device left the bus, so every session over this link is finished; this is a removal and not a quiet guest"
            }
            Self::LinkStalled { .. } => {
                "the shared link has stopped moving and this line was written by a thread that is not on it, which is why there is a line at all; read held first, because it separates the two opposite failures that produce the same silence. held above zero means one thread is inside the link and has not come out, phase and port name the work it went in to do, and waiters is how many sessions are blocked on the mutex behind it and cannot say so themselves. held zero with waiters zero means nothing holds the link and nothing wants it, so the mutex is not what froze and every mux thread is parked somewhere outside this module. acquisitions is the heartbeat: a session parked in a read re-takes the link every 25ms, so a stationary count is never a quiet guest. idle-reads climbing with packets-out stationary is the service thread alive and the host side producing nothing; refused above zero is a transfer longer than the 0x7ffc sendMuxSegment sizes every device-to-host packet off, which the device cannot have sent, so it was left with the guest whole rather than retired and its buffer destroyed"
            }
            Self::LinkResumed { .. } => {
                "the shared link is turning again; stalled is how long it was not, and it is the interval in which no other mux line could be written whatever was happening on the wire"
            }
        }
    }
}

impl fmt::Display for MuxTraceEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "result={} ", self.result())?;
        match self {
            Self::VersionSent { version, bytes } => {
                write!(f, "version={version:#010x} bytes={bytes} ")
            }
            Self::VersionTimedOut { waited } => {
                write!(f, "waited={:.3}s ", waited.as_secs_f64())
            }
            Self::VersionNegotiated {
                version,
                header_len,
                segment_size,
            } => write!(
                f,
                "version={} header={header_len} segment={segment_size} ",
                version.wire_value()
            ),
            Self::SynSent {
                local_port,
                remote_port,
                sequence,
            } => write!(f, "local={local_port} guest={remote_port} seq={sequence} "),
            Self::SynAckReceived {
                local_port,
                device_sequence,
                window,
            } => write!(
                f,
                "local={local_port} device-seq={device_sequence} window={window} "
            ),
            Self::SessionEstablished {
                local_port,
                remote_port,
            } => write!(f, "local={local_port} guest={remote_port} "),
            Self::HandshakeTimedOut { local_port, waited } => {
                write!(f, "local={local_port} waited={:.3}s ", waited.as_secs_f64())
            }
            Self::Sent { local_port, bytes } | Self::Received { local_port, bytes } => {
                write!(f, "local={local_port} bytes={bytes} ")
            }
            Self::SequenceGap { expected, received } => {
                write!(f, "expected={expected} received={received} ")
            }
            Self::OutOfOrder {
                local_port,
                expected,
                received,
            } => write!(
                f,
                "local={local_port} expected={expected} received={received} "
            ),
            Self::Reset { local_port }
            | Self::Unmatched { local_port }
            | Self::DeviceGone { local_port } => write!(f, "local={local_port} "),
            Self::OtherProtocol { protocol } => write!(f, "protocol={protocol} "),
            Self::PacketRejected {
                protocol,
                declared,
                delivered,
                magic,
                head,
                rejected,
            } => {
                write!(
                    f,
                    "protocol={protocol} declared={declared} delivered={delivered} magic={magic:#010x} \
                     max-device-send={max_send} rejected={rejected} head=",
                    max_send = super::frame::MAX_TRANSFER
                )?;
                for byte in head {
                    write!(f, "{byte:02x}")?;
                }
                write!(f, " ")
            }
            Self::ReadPollExpired {
                local_port,
                waited,
                elapsed,
            } => write!(
                f,
                "local={local_port} poll={:.3}s waiting={:.3}s ",
                waited.as_secs_f64(),
                elapsed.as_secs_f64()
            ),
            Self::WriteWindowShut {
                local_port,
                snd_una,
                snd_nxt,
                snd_wnd_edge,
                peer_window,
                pending,
                segments_in,
                waited,
                elapsed,
                probed,
            } => write!(
                f,
                "local={local_port} una={snd_una} nxt={snd_nxt} edge={snd_wnd_edge} peer-window={peer_window} \
                 usable={usable} in-flight={in_flight} past-edge={past_edge} pending={pending} answers={segments_in} \
                 poll={poll:.3}s parked={parked:.3}s probed={probed} ",
                usable = (snd_wnd_edge.wrapping_sub(*snd_nxt) as i32).max(0),
                in_flight = snd_nxt.wrapping_sub(*snd_una),
                past_edge = snd_wnd_edge.wrapping_sub(snd_una.wrapping_add(*peer_window)) as i32,
                poll = waited.as_secs_f64(),
                parked = elapsed.as_secs_f64()
            ),
            Self::SessionClosedByFlags { local_port, flags } => {
                write!(f, "local={local_port} flags={flags:#04x} ")
            }
            Self::LinkStalled {
                phase,
                port,
                held,
                waiters,
                acquisitions,
                since_acquisition,
                stalled,
                packets_in,
                packets_out,
                queued,
                deferred,
                idle_reads,
                refused,
            } => write!(
                f,
                "phase={} local={port} held={held:.3}s waiters={waiters} acquisitions={acquisitions} \
                 since-acquisition={since:.3}s stalled={stalled:.3}s packets-in={packets_in} \
                 packets-out={packets_out} queued={queued} undrained={undrained} deferred={deferred} \
                 idle-reads={idle_reads} refused={refused} ",
                phase.label(),
                held = held.as_secs_f64(),
                since = since_acquisition.as_secs_f64(),
                stalled = stalled.as_secs_f64(),
                undrained = queued.saturating_sub(*packets_out)
            ),
            Self::LinkResumed {
                stalled,
                acquisitions,
                packets_in,
                packets_out,
            } => write!(
                f,
                "stalled={:.3}s acquisitions={acquisitions} packets-in={packets_in} packets-out={packets_out} ",
                stalled.as_secs_f64()
            ),
        }?;
        write!(f, "meaning=\"{}\"", self.meaning())
    }
}

pub trait MuxTraceSink: Send + Sync {
    fn event(&self, event: MuxTraceEvent);
}

pub struct PrintingTrace {
    prefix: String,
}

impl PrintingTrace {
    #[must_use]
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }
}

impl MuxTraceSink for PrintingTrace {
    fn event(&self, event: MuxTraceEvent) {
        use std::io::Write as _;
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{} {event}", self.prefix);
        let _ = stdout.flush();
    }
}

#[derive(Default)]
pub struct RecordingTrace {
    events: std::sync::Mutex<Vec<MuxTraceEvent>>,
}

impl RecordingTrace {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn events(&self) -> Vec<MuxTraceEvent> {
        self.events.lock().map_or_else(
            |poisoned| poisoned.into_inner().clone(),
            |guard| guard.clone(),
        )
    }

    #[must_use]
    pub fn results(&self) -> Vec<&'static str> {
        self.events().iter().map(MuxTraceEvent::result).collect()
    }
}

impl MuxTraceSink for RecordingTrace {
    fn event(&self, event: MuxTraceEvent) {
        match self.events.lock() {
            Ok(mut guard) => guard.push(event),
            Err(poisoned) => poisoned.into_inner().push(event),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_transition_the_coordinator_asked_to_tell_apart_has_its_own_token() {
        let tokens = [
            MuxTraceEvent::VersionSent {
                version: 0xFEED_FACE,
                bytes: 20,
            }
            .result(),
            MuxTraceEvent::VersionTimedOut {
                waited: Duration::from_secs(5),
            }
            .result(),
            MuxTraceEvent::VersionNegotiated {
                version: MuxVersion::V2,
                header_len: 16,
                segment_size: 32728,
            }
            .result(),
            MuxTraceEvent::SynSent {
                local_port: 49152,
                remote_port: 62078,
                sequence: 1,
            }
            .result(),
            MuxTraceEvent::SynAckReceived {
                local_port: 49152,
                device_sequence: 0,
                window: 65536,
            }
            .result(),
            MuxTraceEvent::SessionEstablished {
                local_port: 49152,
                remote_port: 62078,
            }
            .result(),
            MuxTraceEvent::Sent {
                local_port: 49152,
                bytes: 9,
            }
            .result(),
            MuxTraceEvent::Received {
                local_port: 49152,
                bytes: 9,
            }
            .result(),
        ];
        let unique: std::collections::BTreeSet<_> = tokens.iter().collect();
        assert_eq!(unique.len(), tokens.len(), "two transitions share a token");
    }

    #[test]
    fn the_version_sent_line_names_the_bytes_and_says_silence_is_the_likely_failure() {
        let rendered = MuxTraceEvent::VersionSent {
            version: 0xFEED_FACE,
            bytes: 20,
        }
        .to_string();
        assert!(rendered.contains("result=version-sent"), "{rendered}");
        assert!(rendered.contains("0xfeedface"), "{rendered}");
        assert!(rendered.contains("bytes=20"), "{rendered}");
        assert!(rendered.contains("cannot speak first"), "{rendered}");
    }

    #[test]
    fn the_no_reply_line_tells_a_reader_what_to_check() {
        let rendered = MuxTraceEvent::VersionTimedOut {
            waited: Duration::from_millis(2500),
        }
        .to_string();
        assert!(rendered.contains("waited=2.500s"), "{rendered}");
        assert!(rendered.contains("bulk pair"), "{rendered}");
        assert!(rendered.contains("one transfer"), "{rendered}");
    }

    #[test]
    fn the_negotiated_line_carries_the_header_size_the_rest_of_the_run_depends_on() {
        let rendered = MuxTraceEvent::VersionNegotiated {
            version: MuxVersion::V2,
            header_len: 16,
            segment_size: 32728,
        }
        .to_string();
        assert!(rendered.contains("version=2"), "{rendered}");
        assert!(rendered.contains("header=16"), "{rendered}");
        assert!(rendered.contains("segment=32728"), "{rendered}");
    }

    #[test]
    fn a_sequence_gap_says_the_run_should_stop_rather_than_only_that_it_happened() {
        let rendered = MuxTraceEvent::SequenceGap {
            expected: 4,
            received: 7,
        }
        .to_string();
        assert!(rendered.contains("expected=4 received=7"), "{rendered}");
        assert!(rendered.contains("cannot recover"), "{rendered}");
    }

    #[test]
    fn an_expired_poll_reads_as_a_retry_and_a_removal_reads_as_the_end() {
        let retried = MuxTraceEvent::ReadPollExpired {
            local_port: 49152,
            waited: Duration::from_secs(30),
            elapsed: Duration::from_secs(454),
        }
        .to_string();
        assert!(retried.contains("result=read-poll-expired"), "{retried}");
        assert!(retried.contains("poll=30.000s"), "{retried}");
        assert!(retried.contains("waiting=454.000s"), "{retried}");
        assert!(retried.contains("went round again"), "{retried}");
        assert!(
            retried.contains("nothing here counts towards ending it"),
            "{retried}"
        );

        let gone = MuxTraceEvent::DeviceGone { local_port: 49152 }.to_string();
        assert!(gone.contains("result=device-gone"), "{gone}");
        assert!(gone.contains("left the bus"), "{gone}");
        assert!(gone.contains("not a quiet guest"), "{gone}");
        assert_ne!(
            MuxTraceEvent::ReadPollExpired {
                local_port: 1,
                waited: Duration::ZERO,
                elapsed: Duration::ZERO,
            }
            .result(),
            MuxTraceEvent::DeviceGone { local_port: 1 }.result()
        );
    }

    #[test]
    fn a_parked_write_says_what_it_is_parked_on_rather_than_saying_nothing() {
        let rendered = MuxTraceEvent::WriteWindowShut {
            local_port: 49154,
            snd_una: 1_000_000,
            snd_nxt: 1_098_304,
            snd_wnd_edge: 1_098_304,
            peer_window: 98_304,
            pending: 884_776,
            segments_in: 119_614,
            waited: Duration::from_secs(30),
            elapsed: Duration::from_secs(238),
            probed: true,
        }
        .to_string();
        assert!(rendered.contains("result=write-window-shut"), "{rendered}");
        assert!(rendered.contains("local=49154"), "{rendered}");
        assert!(rendered.contains("una=1000000"), "{rendered}");
        assert!(rendered.contains("nxt=1098304"), "{rendered}");
        assert!(rendered.contains("edge=1098304"), "{rendered}");
        assert!(rendered.contains("peer-window=98304"), "{rendered}");
        assert!(rendered.contains("pending=884776"), "{rendered}");
        assert!(rendered.contains("probed=true"), "{rendered}");
        assert!(rendered.contains("answers=119614"), "{rendered}");
        assert!(rendered.contains("usable=0"), "{rendered}");
        assert!(rendered.contains("in-flight=98304"), "{rendered}");
        assert!(rendered.contains("past-edge=0"), "{rendered}");
        assert!(rendered.contains("poll=30.000s"), "{rendered}");
        assert!(rendered.contains("parked=238.000s"), "{rendered}");

        let past = MuxTraceEvent::WriteWindowShut {
            local_port: 49154,
            snd_una: 382_088_912,
            snd_nxt: 382_105_304,
            snd_wnd_edge: 382_105_304,
            peer_window: 16_384,
            pending: 869_968,
            segments_in: 135_416,
            waited: Duration::from_secs(30),
            elapsed: Duration::from_secs_f64(690.066),
            probed: true,
        }
        .to_string();
        assert!(past.contains("past-edge=8"), "{past}");
        assert!(past.contains("in-flight=16392"), "{past}");

        let open = MuxTraceEvent::WriteWindowShut {
            local_port: 49154,
            snd_una: 1_000_000,
            snd_nxt: 1_098_304,
            snd_wnd_edge: 1_130_304,
            peer_window: 130_304,
            pending: 884_776,
            segments_in: 119_615,
            waited: Duration::from_secs(30),
            elapsed: Duration::from_secs(30),
            probed: false,
        }
        .to_string();
        assert!(open.contains("usable=32000"), "{open}");

        let wrapped = MuxTraceEvent::WriteWindowShut {
            local_port: 49154,
            snd_una: 0xFFFF_0000,
            snd_nxt: 0x0000_0100,
            snd_wnd_edge: 0xFFFF_FF00,
            peer_window: 0xFF00,
            pending: 1,
            segments_in: 7,
            waited: Duration::from_secs(30),
            elapsed: Duration::from_secs(30),
            probed: true,
        }
        .to_string();
        assert!(wrapped.contains("usable=0"), "{wrapped}");
        assert!(wrapped.contains("in-flight=65792"), "{wrapped}");
        assert!(wrapped.contains("past-edge=0"), "{wrapped}");
    }

    #[test]
    fn a_flag_byte_that_ends_a_session_reads_as_the_end_and_names_the_byte() {
        let rendered = MuxTraceEvent::SessionClosedByFlags {
            local_port: 49154,
            flags: 0x18,
        }
        .to_string();
        assert!(
            rendered.contains("result=session-closed-by-flags"),
            "{rendered}"
        );
        assert!(rendered.contains("flags=0x18"), "{rendered}");
        assert!(rendered.contains("this session is finished"), "{rendered}");
        assert_ne!(
            MuxTraceEvent::SessionClosedByFlags {
                local_port: 1,
                flags: 0x18,
            }
            .result(),
            MuxTraceEvent::Reset { local_port: 1 }.result()
        );
    }

    #[test]
    fn a_recorder_keeps_the_order_a_boot_would_have_printed() {
        let trace = RecordingTrace::new();
        trace.event(MuxTraceEvent::VersionSent {
            version: 0xFEED_FACE,
            bytes: 20,
        });
        trace.event(MuxTraceEvent::VersionNegotiated {
            version: MuxVersion::V2,
            header_len: 16,
            segment_size: 32728,
        });
        assert_eq!(trace.results(), vec!["version-sent", "version-negotiated"]);
    }
}
