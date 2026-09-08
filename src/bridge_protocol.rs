use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use serde::{Deserialize, Serialize};

use crate::crypto::sha256;

pub const MAGIC: [u8; 4] = *b"RBRG";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 40;
pub const MAX_JSON_BYTES: usize = 64 * 1024;
pub const MAX_PACKET_BYTES: usize = 0x8000;
pub const MAX_TRANSFER_BYTES: usize = 0x7ffc;
pub const MAX_BOOT_CONTEXT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SIGNED_BODY_BYTES: usize = 4 * 1024 * 1024;
pub const BOOT_CONTEXT_ENCODING_VERSION: u16 = 1;
pub const SIGNING_ENCODING_VERSION: u16 = 1;
pub const SIGNING_DIGEST_ALGORITHM: u16 = 1;
pub const SIGNATURE_FORMAT_RS: u16 = 1;
pub const MANB_IDENTIFIER_BYTES: [u8; 6] = [0xff, 0x84, 0xea, 0x85, 0x9c, 0x42];
pub const SERVER_CAPABILITIES: [&str; 6] = [
    "list",
    "watch",
    "packetCredit",
    "bootContext",
    "signFdrManifest",
    "detach",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordKind {
    Hello = 1,
    ServerHello = 2,
    List = 3,
    Device = 4,
    ListEnd = 5,
    Watch = 6,
    Claim = 7,
    Claimed = 8,
    PacketToDevice = 9,
    PacketFromDevice = 10,
    Credit = 11,
    Stats = 12,
    Gone = 13,
    Detach = 14,
    Detached = 15,
    Ping = 16,
    Pong = 17,
    Error = 18,
    GetBootContext = 19,
    BootContext = 20,
    SignFdrManifest = 21,
    FdrManifestSignature = 22,
}

impl RecordKind {
    pub fn from_wire(value: u16) -> io::Result<Self> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::ServerHello),
            3 => Ok(Self::List),
            4 => Ok(Self::Device),
            5 => Ok(Self::ListEnd),
            6 => Ok(Self::Watch),
            7 => Ok(Self::Claim),
            8 => Ok(Self::Claimed),
            9 => Ok(Self::PacketToDevice),
            10 => Ok(Self::PacketFromDevice),
            11 => Ok(Self::Credit),
            12 => Ok(Self::Stats),
            13 => Ok(Self::Gone),
            14 => Ok(Self::Detach),
            15 => Ok(Self::Detached),
            16 => Ok(Self::Ping),
            17 => Ok(Self::Pong),
            18 => Ok(Self::Error),
            19 => Ok(Self::GetBootContext),
            20 => Ok(Self::BootContext),
            21 => Ok(Self::SignFdrManifest),
            22 => Ok(Self::FdrManifestSignature),
            other => Err(invalid_data(format!(
                "unknown Restore Bridge v1 record kind {other}"
            ))),
        }
    }

    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    pub const fn payload_limit(self) -> usize {
        match self {
            Self::Hello
            | Self::ServerHello
            | Self::Device
            | Self::ListEnd
            | Self::Watch
            | Self::Claim
            | Self::Claimed
            | Self::Gone
            | Self::Detach
            | Self::Detached
            | Self::Error => MAX_JSON_BYTES,
            Self::List | Self::GetBootContext => 0,
            Self::PacketToDevice => MAX_PACKET_BYTES,
            Self::PacketFromDevice => MAX_TRANSFER_BYTES,
            Self::Credit => 8,
            Self::Stats => 64,
            Self::Ping | Self::Pong => 8,
            Self::BootContext => MAX_BOOT_CONTEXT_BYTES,
            Self::SignFdrManifest => MAX_SIGNED_BODY_BYTES + 8,
            Self::FdrManifestSignature => 185,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordHeader {
    pub version: u16,
    pub kind: RecordKind,
    pub flags: u32,
    pub payload_len: u32,
    pub request_id: u64,
    pub generation: u64,
    pub lease_id: u64,
}

impl RecordHeader {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.kind.wire_value().to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.payload_len.to_be_bytes());
        out.extend_from_slice(&self.request_id.to_be_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.lease_id.to_be_bytes());
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != HEADER_LEN {
            return Err(invalid_data(format!(
                "Restore Bridge v1 header needs {HEADER_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        if bytes[..4] != MAGIC {
            return Err(invalid_data("Restore Bridge v1 magic mismatch"));
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != VERSION {
            return Err(invalid_data(format!(
                "unsupported Restore Bridge version {version}, expected {VERSION}"
            )));
        }
        let kind = RecordKind::from_wire(u16::from_be_bytes([bytes[6], bytes[7]]))?;
        let flags = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if flags != 0 {
            return Err(invalid_data(format!(
                "Restore Bridge v1 flags must be zero, got {flags}"
            )));
        }
        Ok(Self {
            version,
            kind,
            flags,
            payload_len: u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            request_id: u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
            generation: u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
            lease_id: u64::from_be_bytes(bytes[32..40].try_into().unwrap()),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawRecord {
    pub header: RecordHeader,
    pub payload: Vec<u8>,
}

pub fn encode_record(header: RecordHeader, payload: &[u8]) -> io::Result<Vec<u8>> {
    validate_record_header(&header)?;
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| invalid_input(format!("payload too large: {}", payload.len())))?;
    if usize::try_from(payload_len).unwrap() > header.kind.payload_limit() {
        return Err(invalid_input(format!(
            "payload {} exceeds limit {} for {:?}",
            payload.len(),
            header.kind.payload_limit(),
            header.kind
        )));
    }
    validate_record_payload(header.kind, payload)?;
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    RecordHeader {
        payload_len,
        ..header
    }
    .encode(&mut out);
    out.extend_from_slice(payload);
    Ok(out)
}

#[derive(Default)]
pub struct FrameAssembler {
    buffer: Vec<u8>,
    consumed: usize,
}

impl FrameAssembler {
    pub fn push(&mut self, bytes: &[u8]) -> io::Result<Vec<RawRecord>> {
        self.buffer.extend_from_slice(bytes);
        let mut frames = Vec::new();
        while let Some(frame) = self.try_take()? {
            frames.push(frame);
        }
        Ok(frames)
    }

    pub fn try_take(&mut self) -> io::Result<Option<RawRecord>> {
        let available = &self.buffer[self.consumed..];
        if available.len() < HEADER_LEN {
            return Ok(None);
        }
        let header = RecordHeader::decode(&available[..HEADER_LEN])?;
        let payload_len = usize::try_from(header.payload_len)
            .map_err(|_| invalid_data("payload length does not fit in memory"))?;
        if payload_len > header.kind.payload_limit() {
            return Err(invalid_data(format!(
                "payload {} exceeds limit {} for {:?}",
                payload_len,
                header.kind.payload_limit(),
                header.kind
            )));
        }
        let total = HEADER_LEN + payload_len;
        if available.len() < total {
            return Ok(None);
        }
        let payload = available[HEADER_LEN..total].to_vec();
        self.consumed += total;
        self.compact();
        Ok(Some(RawRecord { header, payload }))
    }

    fn compact(&mut self) {
        if self.consumed == 0 {
            return;
        }
        if self.consumed == self.buffer.len() {
            self.buffer.clear();
            self.consumed = 0;
            return;
        }
        if self.consumed >= 4096 || self.consumed * 2 >= self.buffer.len() {
            self.buffer.drain(..self.consumed);
            self.consumed = 0;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Hello {
    pub minimum_version: u16,
    pub maximum_version: u16,
    pub client_name: String,
    pub client_instance_id: String,
    pub client_pid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServerHello {
    pub selected_version: u16,
    pub server_name: String,
    pub broker_id: String,
    pub server_pid: u32,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DeviceEvent {
    Snapshot,
    Added,
    Changed,
    Removed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportKind {
    #[serde(rename = "dwc3")]
    Dwc3,
    #[serde(rename = "virtio-gadget")]
    VirtioGadget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DeviceState {
    Available,
    Claimed,
    Unavailable,
    Removed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DeviceRecord {
    pub revision: u64,
    pub event: DeviceEvent,
    pub broker_id: String,
    pub device_id: String,
    pub vm_id: String,
    pub vm_name: String,
    pub controller_index: u32,
    pub transport_kind: TransportKind,
    pub state: DeviceState,
    pub detail: Option<String>,
    #[serde(rename = "outMaxPacketSize")]
    pub out_max_packet_size: u16,
    #[serde(rename = "maxPacketSize")]
    pub max_packet_size: u32,
    #[serde(rename = "maxTransferSize")]
    pub max_transfer_size: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ListEnd {
    pub revision: u64,
    pub device_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WatchRequest {
    pub after_revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClaimRequest {
    pub device_id: String,
    pub receive_depth_packets: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Claimed {
    pub device_id: String,
    pub transport_kind: TransportKind,
    #[serde(rename = "outMaxPacketSize")]
    pub out_max_packet_size: u16,
    #[serde(rename = "maxPacketSize")]
    pub max_packet_size: u32,
    #[serde(rename = "maxTransferSize")]
    pub max_transfer_size: u32,
    pub host_to_device_credits: u32,
    pub device_to_host_credits: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GoneReason {
    VmStopped,
    VmReset,
    GuestDisconnected,
    PumpFailed,
    BrokerStopping,
    ClaimAborted,
    TransportClosed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Gone {
    pub reason: GoneReason,
    pub detail: Option<String>,
    pub replacement_generation: Option<u64>,
    pub retryable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DetachOutcome {
    Complete,
    Cancelled,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Detach {
    pub outcome: DetachOutcome,
    pub detail: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DetachedDeviceState {
    Detached,
    AlreadyGone,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Detached {
    pub outcome: DetachOutcome,
    pub device_state: DetachedDeviceState,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ErrorRecord {
    pub code: String,
    pub detail: String,
    pub fatal: bool,
    pub retryable: bool,
    pub current_revision: Option<u64>,
    pub current_generation: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreditRecord {
    pub direction: u8,
    pub delta: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatsRecord {
    pub packets_to_device_received: u64,
    pub packets_accepted_by_device: u64,
    pub bytes_accepted_by_device: u64,
    pub packets_from_device_sent: u64,
    pub bytes_from_device_sent: u64,
    pub queued_to_device: u32,
    pub queued_from_device: u32,
    pub host_to_device_credits_outstanding: u32,
    pub device_to_host_credits_outstanding: u32,
    pub presence: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootContext {
    pub staged_boot_manifest_sha384: [u8; 48],
    pub ap_nonce: Option<[u8; 32]>,
    pub fdr_element_index: u32,
    pub fdr_element_count: u32,
    pub fdr_trust_digest_sha256: Option<[u8; 32]>,
    pub fdr_trust_object: Option<Vec<u8>>,
    pub fdr_instance: Option<String>,
    pub fdr_material_path: Option<OsString>,
    pub sep_public_key_uncompressed: Option<[u8; 65]>,
    pub remote_signer_available: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignFdrManifestRequest {
    pub signed_body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FdrManifestSignature {
    pub signed_body_length: u32,
    pub digest_sha384: [u8; 48],
    pub signature_rs: [u8; 64],
    pub signer_public_key_uncompressed: [u8; 65],
}

pub fn encode_json<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| invalid_input(format!("JSON encode failed: {error}")))?;
    if bytes.len() > MAX_JSON_BYTES {
        return Err(invalid_input(format!(
            "JSON payload {} exceeds {}",
            bytes.len(),
            MAX_JSON_BYTES
        )));
    }
    Ok(bytes)
}

pub fn decode_json<T: for<'de> Deserialize<'de>>(payload: &[u8]) -> io::Result<T> {
    if payload.len() > MAX_JSON_BYTES {
        return Err(invalid_data(format!(
            "JSON payload {} exceeds {}",
            payload.len(),
            MAX_JSON_BYTES
        )));
    }
    serde_json::from_slice(payload)
        .map_err(|error| invalid_data(format!("JSON decode failed: {error}")))
}

pub fn validate_hello(hello: &Hello) -> io::Result<()> {
    if hello.minimum_version > VERSION || hello.maximum_version < VERSION {
        return Err(invalid_data(format!(
            "hello version range {}..{} does not bracket {}",
            hello.minimum_version, hello.maximum_version, VERSION
        )));
    }
    if hello.client_name != "apple-utils" {
        return Err(invalid_data(format!(
            "unexpected client name '{}'",
            hello.client_name
        )));
    }
    validate_hex_id(&hello.client_instance_id, "clientInstanceId")?;
    Ok(())
}

pub fn validate_server_hello(hello: &ServerHello) -> io::Result<()> {
    if hello.selected_version != VERSION {
        return Err(invalid_data(format!(
            "server selected version {}, expected {}",
            hello.selected_version, VERSION
        )));
    }
    validate_hex_id(&hello.broker_id, "brokerId")?;
    if hello.capabilities.len() != SERVER_CAPABILITIES.len()
        || hello
            .capabilities
            .iter()
            .map(String::as_str)
            .ne(SERVER_CAPABILITIES)
    {
        return Err(invalid_data(format!(
            "unexpected capabilities {:?}",
            hello.capabilities
        )));
    }
    Ok(())
}

pub fn validate_device_record(record: &DeviceRecord) -> io::Result<()> {
    validate_hex_id(&record.broker_id, "brokerId")?;
    validate_ascii_identifier(&record.device_id, "deviceId", 128)?;
    validate_utf8_nonempty(&record.vm_id, "vmId", 256)?;
    validate_utf8_nonempty(&record.vm_name, "vmName", 256)?;
    if record.out_max_packet_size == 0 {
        return Err(invalid_data("outMaxPacketSize must be nonzero"));
    }
    if record.max_packet_size == 0
        || usize::try_from(record.max_packet_size).unwrap() > MAX_PACKET_BYTES
    {
        return Err(invalid_data(format!(
            "maxPacketSize {} exceeds {}",
            record.max_packet_size, MAX_PACKET_BYTES
        )));
    }
    if record.max_transfer_size == 0
        || usize::try_from(record.max_transfer_size).unwrap() > MAX_TRANSFER_BYTES
    {
        return Err(invalid_data(format!(
            "maxTransferSize {} exceeds {}",
            record.max_transfer_size, MAX_TRANSFER_BYTES
        )));
    }
    Ok(())
}

pub fn validate_claim_request(request: &ClaimRequest) -> io::Result<()> {
    validate_ascii_identifier(&request.device_id, "deviceId", 128)?;
    if !(1..=256).contains(&request.receive_depth_packets) {
        return Err(invalid_input(format!(
            "receiveDepthPackets {} is outside 1..=256",
            request.receive_depth_packets
        )));
    }
    Ok(())
}

pub fn validate_claimed(claimed: &Claimed) -> io::Result<()> {
    validate_ascii_identifier(&claimed.device_id, "deviceId", 128)?;
    if !(1..=256).contains(&claimed.host_to_device_credits) {
        return Err(invalid_data(format!(
            "hostToDeviceCredits {} is outside 1..=256",
            claimed.host_to_device_credits
        )));
    }
    if !(1..=256).contains(&claimed.device_to_host_credits) {
        return Err(invalid_data(format!(
            "deviceToHostCredits {} is outside 1..=256",
            claimed.device_to_host_credits
        )));
    }
    if usize::try_from(claimed.max_packet_size).unwrap() > MAX_PACKET_BYTES {
        return Err(invalid_data(format!(
            "maxPacketSize {} exceeds {}",
            claimed.max_packet_size, MAX_PACKET_BYTES
        )));
    }
    if usize::try_from(claimed.max_transfer_size).unwrap() > MAX_TRANSFER_BYTES {
        return Err(invalid_data(format!(
            "maxTransferSize {} exceeds {}",
            claimed.max_transfer_size, MAX_TRANSFER_BYTES
        )));
    }
    Ok(())
}

pub fn encode_credit(credit: CreditRecord) -> io::Result<Vec<u8>> {
    if credit.direction != 1 && credit.direction != 2 {
        return Err(invalid_input(format!(
            "credit direction {} is invalid",
            credit.direction
        )));
    }
    if credit.delta == 0 {
        return Err(invalid_input("credit delta must be nonzero"));
    }
    let mut out = Vec::with_capacity(8);
    out.push(credit.direction);
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(&credit.delta.to_be_bytes());
    Ok(out)
}

pub fn decode_credit(payload: &[u8]) -> io::Result<CreditRecord> {
    if payload.len() != 8 {
        return Err(invalid_data(format!(
            "credit payload must be 8 bytes, got {}",
            payload.len()
        )));
    }
    if payload[1..4] != [0, 0, 0] {
        return Err(invalid_data("credit reserved bytes must be zero"));
    }
    let direction = payload[0];
    let delta = u32::from_be_bytes(payload[4..8].try_into().unwrap());
    if (direction != 1 && direction != 2) || delta == 0 {
        return Err(invalid_data(format!(
            "invalid credit direction {direction} delta {delta}"
        )));
    }
    Ok(CreditRecord { direction, delta })
}

pub fn encode_stats(stats: &StatsRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&stats.packets_to_device_received.to_be_bytes());
    out.extend_from_slice(&stats.packets_accepted_by_device.to_be_bytes());
    out.extend_from_slice(&stats.bytes_accepted_by_device.to_be_bytes());
    out.extend_from_slice(&stats.packets_from_device_sent.to_be_bytes());
    out.extend_from_slice(&stats.bytes_from_device_sent.to_be_bytes());
    out.extend_from_slice(&stats.queued_to_device.to_be_bytes());
    out.extend_from_slice(&stats.queued_from_device.to_be_bytes());
    out.extend_from_slice(&stats.host_to_device_credits_outstanding.to_be_bytes());
    out.extend_from_slice(&stats.device_to_host_credits_outstanding.to_be_bytes());
    out.push(stats.presence);
    out.extend_from_slice(&[0; 7]);
    out
}

pub fn decode_stats(payload: &[u8]) -> io::Result<StatsRecord> {
    if payload.len() != 64 {
        return Err(invalid_data(format!(
            "stats payload must be 64 bytes, got {}",
            payload.len()
        )));
    }
    if payload[57..64] != [0; 7] {
        return Err(invalid_data("stats trailing reserved bytes must be zero"));
    }
    Ok(StatsRecord {
        packets_to_device_received: u64::from_be_bytes(payload[0..8].try_into().unwrap()),
        packets_accepted_by_device: u64::from_be_bytes(payload[8..16].try_into().unwrap()),
        bytes_accepted_by_device: u64::from_be_bytes(payload[16..24].try_into().unwrap()),
        packets_from_device_sent: u64::from_be_bytes(payload[24..32].try_into().unwrap()),
        bytes_from_device_sent: u64::from_be_bytes(payload[32..40].try_into().unwrap()),
        queued_to_device: u32::from_be_bytes(payload[40..44].try_into().unwrap()),
        queued_from_device: u32::from_be_bytes(payload[44..48].try_into().unwrap()),
        host_to_device_credits_outstanding: u32::from_be_bytes(payload[48..52].try_into().unwrap()),
        device_to_host_credits_outstanding: u32::from_be_bytes(payload[52..56].try_into().unwrap()),
        presence: payload[56],
    })
}

pub fn encode_ping_nonce(nonce: u64) -> Vec<u8> {
    nonce.to_be_bytes().to_vec()
}

pub fn decode_ping_nonce(payload: &[u8]) -> io::Result<u64> {
    if payload.len() != 8 {
        return Err(invalid_data(format!(
            "ping payload must be 8 bytes, got {}",
            payload.len()
        )));
    }
    Ok(u64::from_be_bytes(payload.try_into().unwrap()))
}

impl BootContext {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut flags = 0u32;
        let ap_nonce = self.ap_nonce.as_ref();
        if ap_nonce.is_some() {
            flags |= 1 << 0;
        }
        let trust_object = self.fdr_trust_object.as_ref();
        let trust_digest = self.fdr_trust_digest_sha256.as_ref();
        if trust_object.is_some() || trust_digest.is_some() {
            if trust_object.is_none() || trust_digest.is_none() {
                return Err(invalid_input(
                    "trust object and digest must appear together",
                ));
            }
            if trust_object.unwrap().is_empty() {
                return Err(invalid_input("trust object must not be empty"));
            }
            if self.fdr_element_count == 0 || self.fdr_element_index >= self.fdr_element_count {
                return Err(invalid_input("FDR element metadata is invalid"));
            }
            if sha256(trust_object.unwrap()) != *trust_digest.unwrap() {
                return Err(invalid_input("trust digest does not match trust object"));
            }
            flags |= 1 << 1;
        } else if self.fdr_element_index != 0 || self.fdr_element_count != 0 {
            return Err(invalid_input(
                "FDR element metadata must be zero without trust data",
            ));
        }
        let instance = self.fdr_instance.as_ref();
        if let Some(instance) = instance {
            if trust_object.is_none() {
                return Err(invalid_input("FDR instance requires trust data"));
            }
            if instance.is_empty() {
                return Err(invalid_input("FDR instance must not be empty"));
            }
            flags |= 1 << 2;
        }
        let material_path = self.fdr_material_path.as_ref();
        if let Some(material_path) = material_path {
            if trust_object.is_none() {
                return Err(invalid_input("FDR material path requires trust data"));
            }
            let bytes = material_path.as_os_str().as_bytes();
            if bytes.is_empty() || bytes[0] != b'/' || bytes.contains(&0) {
                return Err(invalid_input(
                    "FDR material path must be nonempty absolute raw Unix bytes with no NUL",
                ));
            }
            flags |= 1 << 3;
        }
        let sep = self.sep_public_key_uncompressed.as_ref();
        if let Some(sep) = sep {
            if sep[0] != 0x04 {
                return Err(invalid_input("SEP public key must be uncompressed SEC1"));
            }
            flags |= 1 << 4;
        }
        if self.remote_signer_available {
            if sep.is_none() {
                return Err(invalid_input("remote signer requires SEP public key"));
            }
            flags |= 1 << 5;
        }
        let trust_object_len = trust_object.map_or(0, Vec::len);
        let instance_bytes = instance.map_or(&[][..], String::as_bytes);
        let material_bytes = material_path
            .map(|path| path.as_os_str().as_bytes())
            .unwrap_or(&[]);
        let mut out = Vec::with_capacity(
            32 + 48
                + ap_nonce.map_or(0, |_| 32)
                + trust_digest.map_or(0, |_| 32)
                + trust_object_len
                + instance_bytes.len()
                + material_bytes.len()
                + sep.map_or(0, |_| 65),
        );
        out.extend_from_slice(&BOOT_CONTEXT_ENCODING_VERSION.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&self.fdr_element_index.to_be_bytes());
        out.extend_from_slice(&self.fdr_element_count.to_be_bytes());
        out.extend_from_slice(
            &(u32::try_from(trust_object_len).map_err(|_| {
                invalid_input(format!("trust object too large: {trust_object_len}"))
            })?)
            .to_be_bytes(),
        );
        out.extend_from_slice(
            &(u32::try_from(instance_bytes.len()).map_err(|_| {
                invalid_input(format!("instance too large: {}", instance_bytes.len()))
            })?)
            .to_be_bytes(),
        );
        out.extend_from_slice(
            &(u32::try_from(material_bytes.len()).map_err(|_| {
                invalid_input(format!("material path too large: {}", material_bytes.len()))
            })?)
            .to_be_bytes(),
        );
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&self.staged_boot_manifest_sha384);
        if let Some(ap_nonce) = ap_nonce {
            out.extend_from_slice(ap_nonce);
        }
        if let Some(digest) = trust_digest {
            out.extend_from_slice(digest);
        }
        if let Some(object) = trust_object {
            out.extend_from_slice(object);
        }
        if !instance_bytes.is_empty() {
            out.extend_from_slice(instance_bytes);
        }
        if !material_bytes.is_empty() {
            out.extend_from_slice(material_bytes);
        }
        if let Some(sep) = sep {
            out.extend_from_slice(sep);
        }
        if out.len() > MAX_BOOT_CONTEXT_BYTES {
            return Err(invalid_input(format!(
                "boot context {} exceeds {}",
                out.len(),
                MAX_BOOT_CONTEXT_BYTES
            )));
        }
        Ok(out)
    }

    pub fn decode(payload: &[u8]) -> io::Result<Self> {
        if payload.len() < 80 {
            return Err(invalid_data(format!(
                "boot context payload too short: {}",
                payload.len()
            )));
        }
        if payload.len() > MAX_BOOT_CONTEXT_BYTES {
            return Err(invalid_data(format!(
                "boot context payload {} exceeds {}",
                payload.len(),
                MAX_BOOT_CONTEXT_BYTES
            )));
        }
        let encoding_version = u16::from_be_bytes(payload[0..2].try_into().unwrap());
        let reserved0 = u16::from_be_bytes(payload[2..4].try_into().unwrap());
        let flags = u32::from_be_bytes(payload[4..8].try_into().unwrap());
        let fdr_element_index = u32::from_be_bytes(payload[8..12].try_into().unwrap());
        let fdr_element_count = u32::from_be_bytes(payload[12..16].try_into().unwrap());
        let trust_object_len =
            usize::try_from(u32::from_be_bytes(payload[16..20].try_into().unwrap())).unwrap();
        let instance_len =
            usize::try_from(u32::from_be_bytes(payload[20..24].try_into().unwrap())).unwrap();
        let material_len =
            usize::try_from(u32::from_be_bytes(payload[24..28].try_into().unwrap())).unwrap();
        let reserved1 = u32::from_be_bytes(payload[28..32].try_into().unwrap());
        if encoding_version != BOOT_CONTEXT_ENCODING_VERSION || reserved0 != 0 || reserved1 != 0 {
            return Err(invalid_data("boot context prefix is invalid"));
        }
        if flags & !0x3f != 0 {
            return Err(invalid_data(format!(
                "unknown boot context flags 0x{flags:08x}"
            )));
        }
        let mut cursor = 32usize;
        let staged_boot_manifest_sha384 =
            take_fixed::<48>(payload, &mut cursor, "staged boot manifest digest")?;
        let ap_nonce = if flags & (1 << 0) != 0 {
            Some(take_fixed::<32>(payload, &mut cursor, "AP nonce")?)
        } else {
            None
        };
        let (fdr_trust_digest_sha256, fdr_trust_object) = if flags & (1 << 1) != 0 {
            let digest = take_fixed::<32>(payload, &mut cursor, "FDR trust digest")?;
            let object = slice_at(payload, &mut cursor, trust_object_len)?.to_vec();
            (Some(digest), Some(object))
        } else {
            if trust_object_len != 0
                || fdr_element_index != 0
                || fdr_element_count != 0
                || instance_len != 0
                || material_len != 0
            {
                return Err(invalid_data(
                    "boot context has FDR lengths without FDR presence bit",
                ));
            }
            (None, None)
        };
        let fdr_instance =
            if flags & (1 << 2) != 0 {
                if flags & (1 << 1) == 0 {
                    return Err(invalid_data(
                        "boot context instance requires FDR trust data",
                    ));
                }
                let bytes = slice_at(payload, &mut cursor, instance_len)?;
                Some(String::from_utf8(bytes.to_vec()).map_err(|error| {
                    invalid_data(format!("invalid FDR instance UTF-8: {error}"))
                })?)
            } else {
                if instance_len != 0 {
                    return Err(invalid_data(
                        "boot context instance length without presence bit",
                    ));
                }
                None
            };
        let fdr_material_path = if flags & (1 << 3) != 0 {
            if flags & (1 << 1) == 0 {
                return Err(invalid_data(
                    "boot context material path requires FDR trust data",
                ));
            }
            let bytes = slice_at(payload, &mut cursor, material_len)?.to_vec();
            if bytes.is_empty() || bytes[0] != b'/' || bytes.contains(&0) {
                return Err(invalid_data(
                    "boot context material path must be nonempty absolute raw Unix bytes with no NUL",
                ));
            }
            Some(OsString::from_vec(bytes))
        } else {
            if material_len != 0 {
                return Err(invalid_data(
                    "boot context material path length without presence bit",
                ));
            }
            None
        };
        let sep_public_key_uncompressed = if flags & (1 << 4) != 0 {
            let key = take_fixed::<65>(payload, &mut cursor, "SEP public key")?;
            if key[0] != 0x04 {
                return Err(invalid_data(
                    "boot context SEP public key must be uncompressed SEC1",
                ));
            }
            Some(key)
        } else {
            None
        };
        let remote_signer_available = flags & (1 << 5) != 0;
        if remote_signer_available && sep_public_key_uncompressed.is_none() {
            return Err(invalid_data(
                "boot context remote signer requires SEP public key",
            ));
        }
        if cursor != payload.len() {
            return Err(invalid_data(format!(
                "boot context has {} trailing bytes",
                payload.len() - cursor
            )));
        }
        if let Some(digest) = fdr_trust_digest_sha256 {
            if trust_object_len == 0
                || fdr_element_count == 0
                || fdr_element_index >= fdr_element_count
            {
                return Err(invalid_data("boot context FDR element metadata is invalid"));
            }
            if sha256(fdr_trust_object.as_ref().unwrap()) != digest {
                return Err(invalid_data(
                    "boot context trust digest does not match trust object",
                ));
            }
        }
        Ok(Self {
            staged_boot_manifest_sha384,
            ap_nonce,
            fdr_element_index,
            fdr_element_count,
            fdr_trust_digest_sha256,
            fdr_trust_object,
            fdr_instance,
            fdr_material_path,
            sep_public_key_uncompressed,
            remote_signer_available,
        })
    }
}

impl SignFdrManifestRequest {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        validate_signed_manb_body(&self.signed_body)?;
        let body_len = u32::try_from(self.signed_body.len()).map_err(|_| {
            invalid_input(format!("signed body too large: {}", self.signed_body.len()))
        })?;
        let mut out = Vec::with_capacity(8 + self.signed_body.len());
        out.extend_from_slice(&SIGNING_ENCODING_VERSION.to_be_bytes());
        out.extend_from_slice(&SIGNING_DIGEST_ALGORITHM.to_be_bytes());
        out.extend_from_slice(&body_len.to_be_bytes());
        out.extend_from_slice(&self.signed_body);
        Ok(out)
    }

    pub fn decode(payload: &[u8]) -> io::Result<Self> {
        if payload.len() < 8 {
            return Err(invalid_data(format!(
                "sign request payload too short: {}",
                payload.len()
            )));
        }
        let encoding = u16::from_be_bytes(payload[0..2].try_into().unwrap());
        let algorithm = u16::from_be_bytes(payload[2..4].try_into().unwrap());
        let signed_body_len =
            usize::try_from(u32::from_be_bytes(payload[4..8].try_into().unwrap())).unwrap();
        if encoding != SIGNING_ENCODING_VERSION || algorithm != SIGNING_DIGEST_ALGORITHM {
            return Err(invalid_data("sign request header is invalid"));
        }
        if signed_body_len > MAX_SIGNED_BODY_BYTES {
            return Err(invalid_data(format!(
                "signed body {} exceeds {}",
                signed_body_len, MAX_SIGNED_BODY_BYTES
            )));
        }
        if payload.len() != 8 + signed_body_len {
            return Err(invalid_data(format!(
                "sign request length {} does not match header {}",
                payload.len(),
                signed_body_len
            )));
        }
        let signed_body = payload[8..].to_vec();
        validate_signed_manb_body(&signed_body)?;
        Ok(Self { signed_body })
    }
}

impl FdrManifestSignature {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(185);
        out.extend_from_slice(&SIGNING_ENCODING_VERSION.to_be_bytes());
        out.extend_from_slice(&SIGNATURE_FORMAT_RS.to_be_bytes());
        out.extend_from_slice(&self.signed_body_length.to_be_bytes());
        out.extend_from_slice(&self.digest_sha384);
        out.extend_from_slice(&self.signature_rs);
        out.extend_from_slice(&self.signer_public_key_uncompressed);
        out
    }

    pub fn decode(payload: &[u8]) -> io::Result<Self> {
        if payload.len() != 185 {
            return Err(invalid_data(format!(
                "signature payload must be 185 bytes, got {}",
                payload.len()
            )));
        }
        let encoding = u16::from_be_bytes(payload[0..2].try_into().unwrap());
        let format = u16::from_be_bytes(payload[2..4].try_into().unwrap());
        if encoding != SIGNING_ENCODING_VERSION || format != SIGNATURE_FORMAT_RS {
            return Err(invalid_data("signature header is invalid"));
        }
        let mut digest_sha384 = [0u8; 48];
        digest_sha384.copy_from_slice(&payload[8..56]);
        let mut signature_rs = [0u8; 64];
        signature_rs.copy_from_slice(&payload[56..120]);
        let mut signer_public_key_uncompressed = [0u8; 65];
        signer_public_key_uncompressed.copy_from_slice(&payload[120..185]);
        if signer_public_key_uncompressed[0] != 0x04 {
            return Err(invalid_data("signer public key must be uncompressed SEC1"));
        }
        Ok(Self {
            signed_body_length: u32::from_be_bytes(payload[4..8].try_into().unwrap()),
            digest_sha384,
            signature_rs,
            signer_public_key_uncompressed,
        })
    }
}

pub fn validate_packet_to_device(payload: &[u8]) -> io::Result<()> {
    if !(8..=MAX_PACKET_BYTES).contains(&payload.len()) {
        return Err(invalid_data(format!(
            "packet-to-device length {} is outside 8..={MAX_PACKET_BYTES}",
            payload.len()
        )));
    }
    let declared = u32::from_be_bytes(payload[4..8].try_into().unwrap());
    if usize::try_from(declared).unwrap() != payload.len() {
        return Err(invalid_data(format!(
            "packet-to-device inner length {} does not match {}",
            declared,
            payload.len()
        )));
    }
    Ok(())
}

pub fn validate_packet_from_device(payload: &[u8], max_transfer_size: usize) -> io::Result<()> {
    if payload.is_empty() || payload.len() > max_transfer_size || payload.len() > MAX_TRANSFER_BYTES
    {
        return Err(invalid_data(format!(
            "packet-from-device length {} exceeds {}",
            payload.len(),
            max_transfer_size.min(MAX_TRANSFER_BYTES)
        )));
    }
    Ok(())
}

pub fn validate_signed_manb_body(body: &[u8]) -> io::Result<()> {
    if body.is_empty() || body.len() > MAX_SIGNED_BODY_BYTES {
        return Err(invalid_data(format!(
            "signed MANB body {} exceeds {}",
            body.len(),
            MAX_SIGNED_BODY_BYTES
        )));
    }
    let mut cursor = 0usize;
    let set_body = take_der_element(body, &mut cursor, 0x31, "outer SET")?;
    if cursor != body.len() {
        return Err(invalid_data("signed MANB body has trailing bytes"));
    }
    let mut set_cursor = 0usize;
    let private_body = take_private_manb_element(set_body, &mut set_cursor)?;
    if set_cursor != set_body.len() {
        return Err(invalid_data("outer SET must contain exactly one element"));
    }
    let mut private_cursor = 0usize;
    let sequence_body = take_der_element(private_body, &mut private_cursor, 0x30, "MANB sequence")?;
    if private_cursor != private_body.len() {
        return Err(invalid_data(
            "MANB private element must contain exactly one sequence",
        ));
    }
    let mut sequence_cursor = 0usize;
    let ia5 = take_der_element(sequence_body, &mut sequence_cursor, 0x16, "MANB IA5String")?;
    if ia5 != b"MANB" {
        return Err(invalid_data("MANB IA5String payload must be 'MANB'"));
    }
    let inner_set = take_der_element(sequence_body, &mut sequence_cursor, 0x31, "MANB inner SET")?;
    if inner_set.is_empty() {
        return Err(invalid_data("MANB inner SET must not be empty"));
    }
    if sequence_cursor != sequence_body.len() {
        return Err(invalid_data("MANB sequence has trailing elements"));
    }
    Ok(())
}

fn validate_record_header(header: &RecordHeader) -> io::Result<()> {
    if header.version != VERSION {
        return Err(invalid_input(format!(
            "Restore Bridge version must be {VERSION}, got {}",
            header.version
        )));
    }
    if header.flags != 0 {
        return Err(invalid_input(format!(
            "Restore Bridge v1 flags must be zero, got {}",
            header.flags
        )));
    }
    match header.kind {
        RecordKind::Hello
        | RecordKind::ServerHello
        | RecordKind::List
        | RecordKind::ListEnd
        | RecordKind::Watch => {
            if header.request_id == 0 {
                return Err(invalid_input(format!(
                    "{:?} requestId must be nonzero",
                    header.kind
                )));
            }
            if header.generation != 0 || header.lease_id != 0 {
                return Err(invalid_input(format!(
                    "{:?} generation and lease must be zero",
                    header.kind
                )));
            }
        }
        RecordKind::Device => {
            if header.request_id == 0 {
                return Err(invalid_input("DEVICE requestId must be nonzero"));
            }
            if header.generation == 0 || header.lease_id != 0 {
                return Err(invalid_input(
                    "DEVICE generation must be nonzero and lease must be zero",
                ));
            }
        }
        RecordKind::Claim => {
            if header.request_id == 0 {
                return Err(invalid_input("CLAIM requestId must be nonzero"));
            }
            if header.generation == 0 || header.lease_id != 0 {
                return Err(invalid_input(
                    "CLAIM generation must be nonzero and lease must be zero",
                ));
            }
        }
        RecordKind::Claimed => {
            if header.request_id == 0 {
                return Err(invalid_input("CLAIMED requestId must be nonzero"));
            }
            if header.generation == 0 || header.lease_id == 0 {
                return Err(invalid_input(
                    "CLAIMED generation and lease must be nonzero",
                ));
            }
        }
        RecordKind::PacketToDevice
        | RecordKind::PacketFromDevice
        | RecordKind::Credit
        | RecordKind::Stats
        | RecordKind::Gone => {
            if header.request_id != 0 {
                return Err(invalid_input(format!(
                    "{:?} requestId must be zero",
                    header.kind
                )));
            }
            if header.generation == 0 || header.lease_id == 0 {
                return Err(invalid_input(format!(
                    "{:?} generation and lease must be nonzero",
                    header.kind
                )));
            }
        }
        RecordKind::Detach
        | RecordKind::Detached
        | RecordKind::GetBootContext
        | RecordKind::BootContext
        | RecordKind::SignFdrManifest
        | RecordKind::FdrManifestSignature => {
            if header.request_id == 0 {
                return Err(invalid_input(format!(
                    "{:?} requestId must be nonzero",
                    header.kind
                )));
            }
            if header.generation == 0 || header.lease_id == 0 {
                return Err(invalid_input(format!(
                    "{:?} generation and lease must be nonzero",
                    header.kind
                )));
            }
        }
        RecordKind::Ping | RecordKind::Pong => {
            if header.request_id == 0 {
                return Err(invalid_input(format!(
                    "{:?} requestId must be nonzero",
                    header.kind
                )));
            }
        }
        RecordKind::Error => {}
    }
    Ok(())
}

fn validate_record_payload(kind: RecordKind, payload: &[u8]) -> io::Result<()> {
    match kind {
        RecordKind::List | RecordKind::GetBootContext => {
            if !payload.is_empty() {
                return Err(invalid_input(format!("{:?} payload must be empty", kind)));
            }
        }
        RecordKind::PacketToDevice => validate_packet_to_device(payload)?,
        RecordKind::PacketFromDevice => validate_packet_from_device(payload, MAX_TRANSFER_BYTES)?,
        RecordKind::Credit => {
            decode_credit(payload)?;
        }
        RecordKind::Stats => {
            decode_stats(payload)?;
        }
        RecordKind::Ping | RecordKind::Pong => {
            decode_ping_nonce(payload)?;
        }
        RecordKind::BootContext => {
            BootContext::decode(payload)?;
        }
        RecordKind::SignFdrManifest => {
            SignFdrManifestRequest::decode(payload)?;
        }
        RecordKind::FdrManifestSignature => {
            FdrManifestSignature::decode(payload)?;
        }
        _ => {}
    }
    Ok(())
}

fn take_private_manb_element<'a>(bytes: &'a [u8], cursor: &mut usize) -> io::Result<&'a [u8]> {
    let start = *cursor;
    if bytes.get(start..start + MANB_IDENTIFIER_BYTES.len()) != Some(&MANB_IDENTIFIER_BYTES) {
        return Err(invalid_data("MANB private identifier bytes are missing"));
    }
    *cursor += MANB_IDENTIFIER_BYTES.len();
    let length = decode_der_length(bytes, cursor)?;
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| invalid_data("MANB private element length overflow"))?;
    let body = bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_data("MANB private element overruns payload"))?;
    *cursor = end;
    Ok(body)
}

fn take_der_element<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    expected_tag: u8,
    label: &str,
) -> io::Result<&'a [u8]> {
    let tag = *bytes
        .get(*cursor)
        .ok_or_else(|| invalid_data(format!("{label} is truncated before tag")))?;
    if tag != expected_tag {
        return Err(invalid_data(format!(
            "{label} tag 0x{tag:02x} does not match 0x{expected_tag:02x}"
        )));
    }
    *cursor += 1;
    let length = decode_der_length(bytes, cursor)?;
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| invalid_data(format!("{label} length overflow")))?;
    let body = bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_data(format!("{label} overruns payload")))?;
    *cursor = end;
    Ok(body)
}

fn decode_der_length(bytes: &[u8], cursor: &mut usize) -> io::Result<usize> {
    let first = *bytes
        .get(*cursor)
        .ok_or_else(|| invalid_data("DER length is truncated"))?;
    *cursor += 1;
    if first == 0x80 {
        return Err(invalid_data("indefinite DER length is not allowed"));
    }
    if first & 0x80 == 0 {
        return Ok(usize::from(first));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 4 {
        return Err(invalid_data(format!(
            "DER length uses invalid byte count {count}"
        )));
    }
    let length_bytes = bytes
        .get(*cursor..*cursor + count)
        .ok_or_else(|| invalid_data("DER long length is truncated"))?;
    if length_bytes[0] == 0 {
        return Err(invalid_data("DER length is not minimally encoded"));
    }
    if count == 1 && length_bytes[0] < 0x80 {
        return Err(invalid_data("DER long length should have used short form"));
    }
    let mut length = 0usize;
    for byte in length_bytes {
        length = (length << 8) | usize::from(*byte);
    }
    *cursor += count;
    Ok(length)
}

fn take_fixed<const N: usize>(
    payload: &[u8],
    cursor: &mut usize,
    label: &str,
) -> io::Result<[u8; N]> {
    let mut out = [0u8; N];
    out.copy_from_slice(
        slice_at(payload, cursor, N)
            .map_err(|_| invalid_data(format!("{label} overruns payload")))?,
    );
    Ok(out)
}

fn slice_at<'a>(payload: &'a [u8], cursor: &mut usize, len: usize) -> io::Result<&'a [u8]> {
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| invalid_data("payload length overflow"))?;
    let slice = payload
        .get(*cursor..end)
        .ok_or_else(|| invalid_data("payload truncated"))?;
    *cursor = end;
    Ok(slice)
}

fn validate_hex_id(value: &str, field: &str) -> io::Result<()> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid_data(format!(
            "{field} must be 32 lower-case hex digits, got '{value}'"
        )));
    }
    Ok(())
}

fn validate_ascii_identifier(value: &str, field: &str, max_len: usize) -> io::Result<()> {
    if value.is_empty()
        || value.len() > max_len
        || value.bytes().any(|byte| !byte.is_ascii() || byte == 0)
    {
        return Err(invalid_data(format!(
            "{field} must be nonempty ASCII up to {max_len} bytes"
        )));
    }
    Ok(())
}

fn validate_utf8_nonempty(value: &str, field: &str, max_len: usize) -> io::Result<()> {
    if value.is_empty() || value.len() > max_len {
        return Err(invalid_data(format!(
            "{field} must be nonempty UTF-8 up to {max_len} bytes"
        )));
    }
    Ok(())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{P256PrivateKey, sha384};

    const HELLO_GOLDEN: &[u8] = &[
        0x52, 0x42, 0x52, 0x47, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b, 0x22, 0x6d, 0x69, 0x6e,
        0x69, 0x6d, 0x75, 0x6d, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x3a, 0x31, 0x2c,
        0x22, 0x6d, 0x61, 0x78, 0x69, 0x6d, 0x75, 0x6d, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
        0x22, 0x3a, 0x31, 0x2c, 0x22, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x4e, 0x61, 0x6d, 0x65,
        0x22, 0x3a, 0x22, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2d, 0x75, 0x74, 0x69, 0x6c, 0x73, 0x22,
        0x2c, 0x22, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63,
        0x65, 0x49, 0x64, 0x22, 0x3a, 0x22, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x22, 0x2c, 0x22, 0x63, 0x6c, 0x69, 0x65,
        0x6e, 0x74, 0x50, 0x69, 0x64, 0x22, 0x3a, 0x31, 0x32, 0x33, 0x7d,
    ];

    const CREDIT_GOLDEN: &[u8] = &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];

    fn sample_boot_context() -> BootContext {
        let trust_object = vec![0xaa, 0xbb, 0xcc];
        let signing_key = P256PrivateKey::derive(b"restore-bridge-protocol", b"boot-context");
        let staged_boot_manifest_sha384 = [0x11; 48];
        let ap_nonce = Some([0x22; 32]);
        BootContext {
            staged_boot_manifest_sha384,
            ap_nonce,
            fdr_element_index: 1,
            fdr_element_count: 2,
            fdr_trust_digest_sha256: Some(sha256(&trust_object)),
            fdr_trust_object: Some(trust_object),
            fdr_instance: Some("instance-1".to_string()),
            fdr_material_path: Some(OsString::from_vec(b"/tmp/material".to_vec())),
            sep_public_key_uncompressed: Some(signing_key.public_uncompressed()),
            remote_signer_available: true,
        }
    }

    #[test]
    fn hello_golden_vector_matches() {
        let payload = encode_json(&Hello {
            minimum_version: 1,
            maximum_version: 1,
            client_name: "apple-utils".to_string(),
            client_instance_id: "0123456789abcdef0123456789abcdef".to_string(),
            client_pid: 123,
        })
        .unwrap();
        let bytes = encode_record(
            RecordHeader {
                version: VERSION,
                kind: RecordKind::Hello,
                flags: 0,
                payload_len: 0,
                request_id: 0x1122_3344_5566_7788,
                generation: 0,
                lease_id: 0,
            },
            &payload,
        )
        .unwrap();
        assert_eq!(bytes, HELLO_GOLDEN);
    }

    #[test]
    fn credit_golden_vector_matches() {
        assert_eq!(
            encode_credit(CreditRecord {
                direction: 2,
                delta: 3
            })
            .unwrap(),
            CREDIT_GOLDEN
        );
    }

    #[test]
    fn record_header_decode_requires_exact_length() {
        let bytes = [0u8; HEADER_LEN + 1];
        let error = RecordHeader::decode(&bytes).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn transport_kind_uses_exact_json_spelling() {
        let encoded = serde_json::to_string(&TransportKind::VirtioGadget).unwrap();
        assert_eq!(encoded, "\"virtio-gadget\"");
        let decoded: TransportKind = serde_json::from_str("\"virtio-gadget\"").unwrap();
        assert_eq!(decoded, TransportKind::VirtioGadget);
        assert!(serde_json::from_str::<TransportKind>("\"virtioGadget\"").is_err());
    }

    #[test]
    fn encode_record_rejects_noncanonical_header_values() {
        let error = encode_record(
            RecordHeader {
                version: VERSION + 1,
                kind: RecordKind::List,
                flags: 0,
                payload_len: 0,
                request_id: 7,
                generation: 0,
                lease_id: 0,
            },
            &[],
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let error = encode_record(
            RecordHeader {
                version: VERSION,
                kind: RecordKind::Ping,
                flags: 1,
                payload_len: 0,
                request_id: 7,
                generation: 0,
                lease_id: 0,
            },
            &encode_ping_nonce(9),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn encode_record_rejects_invalid_packet_payload() {
        let error = encode_record(
            RecordHeader {
                version: VERSION,
                kind: RecordKind::PacketToDevice,
                flags: 0,
                payload_len: 0,
                request_id: 0,
                generation: 4,
                lease_id: 5,
            },
            &[0, 0, 0, 0, 0, 0, 0, 7],
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn frame_assembler_handles_fragmentation_and_coalescing() {
        let first = encode_record(
            RecordHeader {
                version: VERSION,
                kind: RecordKind::Ping,
                flags: 0,
                payload_len: 0,
                request_id: 7,
                generation: 0,
                lease_id: 0,
            },
            &encode_ping_nonce(9),
        )
        .unwrap();
        let second = encode_record(
            RecordHeader {
                version: VERSION,
                kind: RecordKind::Credit,
                flags: 0,
                payload_len: 0,
                request_id: 0,
                generation: 4,
                lease_id: 5,
            },
            &encode_credit(CreditRecord {
                direction: 1,
                delta: 2,
            })
            .unwrap(),
        )
        .unwrap();
        let mut parser = FrameAssembler::default();
        assert!(parser.push(&first[..13]).unwrap().is_empty());
        let mut rest = first[13..].to_vec();
        rest.extend_from_slice(&second);
        let frames = parser.push(&rest).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(decode_ping_nonce(&frames[0].payload).unwrap(), 9);
        assert_eq!(
            decode_credit(&frames[1].payload).unwrap(),
            CreditRecord {
                direction: 1,
                delta: 2
            }
        );
    }

    #[test]
    fn boot_context_round_trip() {
        let encoded = sample_boot_context().encode().unwrap();
        let decoded = BootContext::decode(&encoded).unwrap();
        assert_eq!(decoded, sample_boot_context());
    }

    #[test]
    fn boot_context_encode_rejects_remote_signer_without_sep_key() {
        let mut context = sample_boot_context();
        context.sep_public_key_uncompressed = None;
        let error = context.encode().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn boot_context_encode_rejects_nonzero_element_metadata_without_trust() {
        let mut context = sample_boot_context();
        context.fdr_trust_digest_sha256 = None;
        context.fdr_trust_object = None;
        let error = context.encode().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn boot_context_encode_rejects_empty_instance() {
        let mut context = sample_boot_context();
        context.fdr_instance = Some(String::new());
        let error = context.encode().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn boot_context_encode_rejects_invalid_material_path() {
        let mut context = sample_boot_context();
        context.fdr_material_path = Some(OsString::from_vec(b"relative/path".to_vec()));
        let error = context.encode().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let mut nul_path = sample_boot_context();
        nul_path.fdr_material_path = Some(OsString::from_vec(b"/tmp/\0bad".to_vec()));
        let error = nul_path.encode().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn boot_context_encode_rejects_invalid_sep_prefix() {
        let mut context = sample_boot_context();
        let mut sep = context.sep_public_key_uncompressed.unwrap();
        sep[0] = 0x02;
        context.sep_public_key_uncompressed = Some(sep);
        let error = context.encode().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn boot_context_decode_rejects_mismatched_trust_digest() {
        let mut bytes = sample_boot_context().encode().unwrap();
        let trust_digest_offset = 32 + 48 + 32;
        bytes[trust_digest_offset] ^= 1;
        let error = BootContext::decode(&bytes).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn sign_request_rejects_noncanonical_der() {
        let error = SignFdrManifestRequest::decode(&[
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x31, 0x80,
        ])
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn sign_request_round_trip() {
        let signed_body = vec![
            0x31, 0x12, 0xff, 0x84, 0xea, 0x85, 0x9c, 0x42, 0x0b, 0x30, 0x09, 0x16, 0x04, b'M',
            b'A', b'N', b'B', 0x31, 0x01, 0x00,
        ];
        let encoded = SignFdrManifestRequest {
            signed_body: signed_body.clone(),
        }
        .encode()
        .unwrap();
        let decoded = SignFdrManifestRequest::decode(&encoded).unwrap();
        assert_eq!(decoded.signed_body, signed_body);
    }

    #[test]
    fn fdr_signature_round_trip() {
        let mut signer_public_key_uncompressed = [0u8; 65];
        signer_public_key_uncompressed[0] = 0x04;
        signer_public_key_uncompressed[1..].fill(0x77);
        let signature = FdrManifestSignature {
            signed_body_length: 99,
            digest_sha384: [0x55; 48],
            signature_rs: [0x66; 64],
            signer_public_key_uncompressed,
        };
        let encoded = signature.encode();
        assert_eq!(FdrManifestSignature::decode(&encoded).unwrap(), signature);
    }

    #[test]
    fn stats_round_trip() {
        let stats = StatsRecord {
            packets_to_device_received: 1,
            packets_accepted_by_device: 2,
            bytes_accepted_by_device: 3,
            packets_from_device_sent: 4,
            bytes_from_device_sent: 5,
            queued_to_device: 6,
            queued_from_device: 7,
            host_to_device_credits_outstanding: 8,
            device_to_host_credits_outstanding: 9,
            presence: 1,
        };
        assert_eq!(decode_stats(&encode_stats(&stats)).unwrap(), stats);
    }

    #[derive(serde::Deserialize)]
    struct RestoreBridgeV1GoldenFrames {
        hello: String,
        server_hello: String,
        credit_host_to_device: String,
        credit_device_to_host: String,
        device_dwc3: String,
        device_virtio_gadget: String,
        claimed_dwc3: String,
        claimed_virtio_gadget: String,
        boot_context_min: String,
        boot_context_all_fields: String,
        sign_request: String,
        fdr_manifest_signature: String,
        detach: String,
        detached: String,
        gone: String,
    }

    fn load_fixtures() -> RestoreBridgeV1GoldenFrames {
        serde_json::from_str(include_str!(
            "../fixtures/restore_bridge_v1_golden_frames.json"
        ))
        .expect("Restore Bridge v1 golden fixtures must be valid JSON")
    }

    fn decode_hex(bytes: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len() / 2);
        let mut offset = 0;
        while offset < bytes.len() {
            let value = u8::from_str_radix(&bytes[offset..offset + 2], 16)
                .expect("fixture bytes must be valid hex");
            out.push(value);
            offset += 2;
        }
        out
    }

    fn to_lower_hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
            out.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
        }
        out
    }

    fn assert_frozen_header_offset_bytes(bytes: &[u8], kind: RecordKind) {
        assert!(bytes.len() >= HEADER_LEN);
        assert_eq!(&bytes[0..4], &MAGIC);
        assert_eq!(u16::from_be_bytes(bytes[4..6].try_into().unwrap()), VERSION);
        assert_eq!(
            u16::from_be_bytes(bytes[6..8].try_into().unwrap()),
            kind.wire_value()
        );
        assert_eq!(u32::from_be_bytes(bytes[8..12].try_into().unwrap()), 0);
    }

    fn assert_record_decodes_and_reencodes_exactly(
        bytes: &[u8],
        expected_kind: RecordKind,
    ) -> RawRecord {
        assert_frozen_header_offset_bytes(bytes, expected_kind);
        let mut assembler = FrameAssembler::default();
        let mut records = assembler.push(bytes).unwrap();
        assert_eq!(records.len(), 1);
        let record = records.pop().unwrap();
        assert_eq!(record.header.kind, expected_kind);
        assert_eq!(record.header.payload_len as usize, record.payload.len());
        assert_eq!(
            encode_record(record.header, &record.payload).unwrap(),
            bytes
        );
        record
    }

    fn assert_request_generation_lease(
        frame: &RecordHeader,
        request_id: u64,
        generation: u64,
        lease_id: u64,
    ) {
        assert_eq!(frame.request_id, request_id);
        assert_eq!(frame.generation, generation);
        assert_eq!(frame.lease_id, lease_id);
    }

    fn assert_boot_context_all_fields(context: &BootContext) {
        assert_eq!(context.staged_boot_manifest_sha384, [0x11; 48]);
        assert_eq!(context.ap_nonce, Some([0x22; 32]));
        assert_eq!(context.fdr_element_index, 1);
        assert_eq!(context.fdr_element_count, 2);
        let expected_digest = sha256(
            context
                .fdr_trust_object
                .as_ref()
                .expect("trust object needed"),
        );
        assert_eq!(context.fdr_trust_digest_sha256, Some(expected_digest));
        assert_eq!(context.fdr_instance, Some("instance-1".to_string()));
        assert_eq!(
            context.fdr_material_path,
            Some(OsString::from_vec(b"/tmp/material".to_vec()))
        );
        let key = context
            .sep_public_key_uncompressed
            .expect("SEP key must be present for full context");
        assert_eq!(key[0], 0x04);
        assert!(context.remote_signer_available);
    }

    #[test]
    fn restore_bridge_v1_golden_fixtures_file_matches_expected_digest() {
        let expected = "650326c7be23bd884f9734e1a4bb7e7f5d74161c99206ebb24172d3bcc32a954";
        let text = include_str!("../fixtures/restore_bridge_v1_golden_frames.json");
        assert_eq!(text.len(), 5563);
        assert_eq!(to_lower_hex(&sha256(text.as_bytes())), expected);
    }

    #[test]
    fn restore_bridge_v1_hello_and_server_hello_frames_match_fixed_golden() {
        let fixture = load_fixtures();

        let hello = decode_hex(&fixture.hello);
        assert_record_decodes_and_reencodes_exactly(&hello, RecordKind::Hello);
        assert_frozen_header_offset_bytes(&hello, RecordKind::Hello);
        let frame = RecordHeader::decode(&hello[..HEADER_LEN]).unwrap();
        assert_request_generation_lease(&frame, 0x0102030405060708, 0, 0);
        let hello_payload: Hello = decode_json(&hello[HEADER_LEN..]).unwrap();
        validate_hello(&hello_payload).unwrap();
        assert_eq!(hello_payload.client_name, "apple-utils");
        let hello_payload_bytes = encode_json(&hello_payload).unwrap();
        let expected_hello = encode_record(frame, &hello_payload_bytes).unwrap();
        assert_eq!(hello, expected_hello);

        let server_hello = decode_hex(&fixture.server_hello);
        assert_record_decodes_and_reencodes_exactly(&server_hello, RecordKind::ServerHello);
        assert_frozen_header_offset_bytes(&server_hello, RecordKind::ServerHello);
        let server_frame_header = RecordHeader::decode(&server_hello[..HEADER_LEN]).unwrap();
        assert_request_generation_lease(&server_frame_header, 0x0102030405060708, 0, 0);
        let server_payload: ServerHello = decode_json(&server_hello[HEADER_LEN..]).unwrap();
        validate_server_hello(&server_payload).unwrap();
        assert_eq!(server_payload.server_name, "restore-host");
        let server_payload_bytes = encode_json(&server_payload).unwrap();
        let expected_server = encode_record(server_frame_header, &server_payload_bytes).unwrap();
        assert_eq!(server_hello, expected_server);
    }

    #[test]
    fn restore_bridge_v1_credit_frames_match_fixed_golden() {
        let fixture = load_fixtures();

        let host_to_device = decode_hex(&fixture.credit_host_to_device);
        assert_record_decodes_and_reencodes_exactly(&host_to_device, RecordKind::Credit);
        let header = RecordHeader::decode(&host_to_device[..HEADER_LEN]).unwrap();
        assert_frozen_header_offset_bytes(&host_to_device, RecordKind::Credit);
        assert_request_generation_lease(&header, 0, 11, 22);
        assert_eq!(
            decode_credit(&host_to_device[HEADER_LEN..]).unwrap(),
            CreditRecord {
                direction: 1,
                delta: 3,
            }
        );
        let expected = encode_record(
            header,
            &encode_credit(CreditRecord {
                direction: 1,
                delta: 3,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(expected, host_to_device);

        let device_to_host = decode_hex(&fixture.credit_device_to_host);
        assert_record_decodes_and_reencodes_exactly(&device_to_host, RecordKind::Credit);
        let header = RecordHeader::decode(&device_to_host[..HEADER_LEN]).unwrap();
        assert_frozen_header_offset_bytes(&device_to_host, RecordKind::Credit);
        assert_request_generation_lease(&header, 0, 11, 22);
        assert_eq!(
            decode_credit(&device_to_host[HEADER_LEN..]).unwrap(),
            CreditRecord {
                direction: 2,
                delta: 4,
            }
        );
        let expected = encode_record(
            header,
            &encode_credit(CreditRecord {
                direction: 2,
                delta: 4,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(expected, device_to_host);
    }

    #[test]
    fn restore_bridge_v1_device_and_claimed_frames_cover_transport_variants() {
        let fixture = load_fixtures();

        let dwc3 = decode_hex(&fixture.device_dwc3);
        assert_record_decodes_and_reencodes_exactly(&dwc3, RecordKind::Device);
        let header = RecordHeader::decode(&dwc3[..HEADER_LEN]).unwrap();
        assert_frozen_header_offset_bytes(&dwc3, RecordKind::Device);
        assert_request_generation_lease(&header, 0x1111111111111111, 22, 0);
        let payload: DeviceRecord = decode_json(&dwc3[HEADER_LEN..]).unwrap();
        validate_device_record(&payload).unwrap();
        assert_eq!(payload.transport_kind, TransportKind::Dwc3);
        assert_eq!(payload.state, DeviceState::Available);
        let expected = encode_record(header, &encode_json(&payload).unwrap()).unwrap();
        assert_eq!(expected, dwc3);

        let virtio = decode_hex(&fixture.device_virtio_gadget);
        assert_record_decodes_and_reencodes_exactly(&virtio, RecordKind::Device);
        let header = RecordHeader::decode(&virtio[..HEADER_LEN]).unwrap();
        assert_frozen_header_offset_bytes(&virtio, RecordKind::Device);
        assert_request_generation_lease(&header, 0x2222222222222222, 22, 0);
        let payload: DeviceRecord = decode_json(&virtio[HEADER_LEN..]).unwrap();
        validate_device_record(&payload).unwrap();
        assert_eq!(payload.transport_kind, TransportKind::VirtioGadget);
        let expected = encode_record(header, &encode_json(&payload).unwrap()).unwrap();
        assert_eq!(expected, virtio);

        let claimed_dwc3 = decode_hex(&fixture.claimed_dwc3);
        assert_record_decodes_and_reencodes_exactly(&claimed_dwc3, RecordKind::Claimed);
        let header = RecordHeader::decode(&claimed_dwc3[..HEADER_LEN]).unwrap();
        assert_request_generation_lease(&header, 0x3333333333333333, 22, 44);
        let claimed_payload: Claimed = decode_json(&claimed_dwc3[HEADER_LEN..]).unwrap();
        validate_claimed(&claimed_payload).unwrap();
        assert_eq!(claimed_payload.transport_kind, TransportKind::Dwc3);
        assert_eq!(claimed_payload.host_to_device_credits, 4);
        assert_eq!(claimed_payload.device_to_host_credits, 6);
        let expected = encode_record(header, &encode_json(&claimed_payload).unwrap()).unwrap();
        assert_eq!(expected, claimed_dwc3);

        let claimed_vg = decode_hex(&fixture.claimed_virtio_gadget);
        assert_record_decodes_and_reencodes_exactly(&claimed_vg, RecordKind::Claimed);
        let header = RecordHeader::decode(&claimed_vg[..HEADER_LEN]).unwrap();
        assert_request_generation_lease(&header, 0x4444444444444444, 22, 44);
        let claimed_payload: Claimed = decode_json(&claimed_vg[HEADER_LEN..]).unwrap();
        validate_claimed(&claimed_payload).unwrap();
        assert_eq!(claimed_payload.transport_kind, TransportKind::VirtioGadget);
        let expected = encode_record(header, &encode_json(&claimed_payload).unwrap()).unwrap();
        assert_eq!(expected, claimed_vg);
    }

    #[test]
    fn restore_bridge_v1_boot_context_frames_validate_minimal_and_all_fields_payloads() {
        let fixture = load_fixtures();

        let minimal = decode_hex(&fixture.boot_context_min);
        assert_record_decodes_and_reencodes_exactly(&minimal, RecordKind::BootContext);
        let header = RecordHeader::decode(&minimal[..HEADER_LEN]).unwrap();
        assert_request_generation_lease(&header, 0x5555555555555555, 22, 44);
        let context = BootContext::decode(&minimal[HEADER_LEN..]).unwrap();
        assert_eq!(context.staged_boot_manifest_sha384, [0x11; 48]);
        assert!(context.fdr_trust_digest_sha256.is_none());
        assert_eq!(context.encode().unwrap(), minimal[HEADER_LEN..]);

        let all_fields = decode_hex(&fixture.boot_context_all_fields);
        assert_record_decodes_and_reencodes_exactly(&all_fields, RecordKind::BootContext);
        let header = RecordHeader::decode(&all_fields[..HEADER_LEN]).unwrap();
        assert_request_generation_lease(&header, 0x6666666666666666, 22, 44);
        let context = BootContext::decode(&all_fields[HEADER_LEN..]).unwrap();
        assert_boot_context_all_fields(&context);
        assert_eq!(context.encode().unwrap(), all_fields[HEADER_LEN..]);
    }

    #[test]
    fn restore_bridge_v1_sign_and_signature_frames_match_fixed_golden() {
        let fixture = load_fixtures();

        let sign = decode_hex(&fixture.sign_request);
        assert_record_decodes_and_reencodes_exactly(&sign, RecordKind::SignFdrManifest);
        let header = RecordHeader::decode(&sign[..HEADER_LEN]).unwrap();
        assert_frozen_header_offset_bytes(&sign, RecordKind::SignFdrManifest);
        assert_request_generation_lease(&header, 0x7777777777777777, 22, 44);
        let payload = &sign[HEADER_LEN..];
        assert_eq!(payload.len(), 28);
        assert_eq!(&payload[0..2], &[0x00, 0x01]);
        assert_eq!(&payload[2..4], &[0x00, 0x01]);
        let body_len = u32::from_be_bytes(payload[4..8].try_into().unwrap()) as usize;
        assert_eq!(payload.len(), 8 + body_len);
        assert_eq!(body_len, 20);
        let request = SignFdrManifestRequest::decode(payload).unwrap();
        assert_eq!(request.encode().unwrap(), payload);

        let signature = decode_hex(&fixture.fdr_manifest_signature);
        assert_record_decodes_and_reencodes_exactly(&signature, RecordKind::FdrManifestSignature);
        let header = RecordHeader::decode(&signature[..HEADER_LEN]).unwrap();
        assert_frozen_header_offset_bytes(&signature, RecordKind::FdrManifestSignature);
        assert_request_generation_lease(&header, 0x8888888888888888, 22, 44);
        assert_eq!(signature.len(), HEADER_LEN + 185);
        let sig_payload = &signature[HEADER_LEN..];
        let decoded_sig = FdrManifestSignature::decode(sig_payload).unwrap();
        assert_eq!(u16::from_be_bytes(sig_payload[0..2].try_into().unwrap()), 1);
        assert_eq!(u16::from_be_bytes(sig_payload[2..4].try_into().unwrap()), 1);
        assert_eq!(
            u32::from_be_bytes(sig_payload[4..8].try_into().unwrap()),
            20
        );
        assert_eq!(sig_payload[8..56], sha384(&request.signed_body));
        let expected = encode_record(header, &decoded_sig.encode()).unwrap();
        assert_eq!(expected, signature);
    }

    #[test]
    fn restore_bridge_v1_detach_detached_and_gone_frames_match_fixed_golden() {
        let fixture = load_fixtures();

        let detach = decode_hex(&fixture.detach);
        assert_record_decodes_and_reencodes_exactly(&detach, RecordKind::Detach);
        let header = RecordHeader::decode(&detach[..HEADER_LEN]).unwrap();
        assert_frozen_header_offset_bytes(&detach, RecordKind::Detach);
        assert_request_generation_lease(&header, 0x9999999999999999, 22, 44);
        let payload: Detach = decode_json(&detach[HEADER_LEN..]).unwrap();
        assert_eq!(payload.outcome, DetachOutcome::Complete);
        assert_eq!(encode_json(&payload).unwrap(), detach[HEADER_LEN..]);

        let detached = decode_hex(&fixture.detached);
        assert_record_decodes_and_reencodes_exactly(&detached, RecordKind::Detached);
        let header = RecordHeader::decode(&detached[..HEADER_LEN]).unwrap();
        assert_frozen_header_offset_bytes(&detached, RecordKind::Detached);
        assert_request_generation_lease(&header, 0xaaaaaaaaaaaaaaaa, 22, 44);
        let payload: Detached = decode_json(&detached[HEADER_LEN..]).unwrap();
        assert_eq!(payload.device_state, DetachedDeviceState::Detached);
        assert_eq!(encode_json(&payload).unwrap(), detached[HEADER_LEN..]);

        let gone = decode_hex(&fixture.gone);
        assert_record_decodes_and_reencodes_exactly(&gone, RecordKind::Gone);
        let header = RecordHeader::decode(&gone[..HEADER_LEN]).unwrap();
        assert_frozen_header_offset_bytes(&gone, RecordKind::Gone);
        assert_request_generation_lease(&header, 0, 22, 44);
        let payload: Gone = decode_json(&gone[HEADER_LEN..]).unwrap();
        assert_eq!(payload.reason, GoneReason::BrokerStopping);
        assert_eq!(payload.replacement_generation, Some(9));
        assert!(!payload.retryable);
        assert_eq!(encode_json(&payload).unwrap(), gone[HEADER_LEN..]);
    }
}
