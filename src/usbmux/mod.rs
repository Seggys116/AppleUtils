pub mod frame;
pub mod session;
pub mod tcp;

pub mod link;

pub mod stream;

pub use crate::bridge_protocol;

#[path = "../bridge_transport.rs"]
pub mod bridge_transport;

pub mod trace;
pub mod watchdog;

pub mod roundtrip;

pub use bridge_protocol::{
    BOOT_CONTEXT_ENCODING_VERSION, BootContext, ClaimRequest, Claimed, CreditRecord, Detach,
    DetachOutcome, Detached, DetachedDeviceState, DeviceEvent, DeviceRecord, DeviceState,
    ErrorRecord, FdrManifestSignature, FrameAssembler, Gone, GoneReason, HEADER_LEN, Hello,
    ListEnd, MAGIC, MAX_BOOT_CONTEXT_BYTES, MAX_JSON_BYTES, MAX_PACKET_BYTES,
    MAX_SIGNED_BODY_BYTES, MAX_TRANSFER_BYTES, RawRecord, RecordHeader, RecordKind,
    SERVER_CAPABILITIES, SIGNATURE_FORMAT_RS, SIGNING_DIGEST_ALGORITHM, SIGNING_ENCODING_VERSION,
    ServerHello, SignFdrManifestRequest, StatsRecord, TransportKind, VERSION, WatchRequest,
};
pub use bridge_transport::{
    BridgeClaim, BridgeClient, BridgeDiscoveredDevice, BridgeInventory, BridgeWatch,
    BridgeWatchEvent, ClaimedSessionControl, SocketBulkTransport, default_discovery_socket_path,
};
pub use frame::{
    DEVICE_MAGIC, FrameError, HEADER_LEN_V1, HEADER_LEN_V2, HOST_MAGIC, MAX_PACKET, MAX_TRANSFER,
    MuxHeader, MuxVersion, Protocol, VERSION_PACKET_LEN, VersionPacket, VersionRequest,
};
pub use link::{
    BulkTransport, DEFAULT_RECEIVE_WINDOW, FIRST_LOCAL_PORT, InboundSignal, LinkEvent,
    LinkLiveness, MuxError, MuxLink,
};
pub use roundtrip::{
    LineBudget, LineGrant, LineSink, PROCESS_LINE_BUDGET, PortStats, ROUNDTRIP_TAG, RoundtripMeter,
    SummaryReason, Tally, WAITS_PER_SUMMARY,
};
pub use session::{
    DEVICE_ISN, MuxSession, Segment, SessionConfig, SessionError, SessionEvent, SessionState,
};
pub use stream::{
    DEFAULT_LINK_SLICE, DEFAULT_READ_POLL, DEFAULT_WRITE_POLL, DEFAULT_WRITE_TIMEOUT,
    DEVICE_GONE_MARKER, HOST_TEARDOWN_MARKER, MuxDialer, MuxReadPolicy, MuxStream, MuxWritePolicy,
    REFERENCE_ASR_READ_TIMEOUT, RUN_STOPPED_MARKER, ReadExpiry, SharedLink, WriteExpiry,
    is_device_gone, is_host_initiated_teardown, is_run_stopped,
};
pub use tcp::{DATA_OFFSET_WORDS, TCP_HEADER_LEN, TcpError, TcpHeader, WINDOW_SCALE_SHIFT, flags};
pub use watchdog::{
    DEFAULT_HELD_STALL_AFTER, DEFAULT_QUIET_AFTER, DEFAULT_WATCHDOG_REPEAT,
    DEFAULT_WATCHDOG_SAMPLE, LinkActivity, LinkPhase, LinkSample, LinkWatchdogHandle,
    LinkWatchdogPolicy, LinkWatchdogStats, WatchdogMetrics, spawn_link_watchdog,
};

pub use trace::{MuxTraceEvent, MuxTraceSink, PrintingTrace, RecordingTrace};

pub const RESTORED_PORT: u16 = crate::ramrod::RAMROD_PORT;
