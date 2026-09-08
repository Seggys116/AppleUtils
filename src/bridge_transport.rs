use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::crypto::{import_public, sha256, sha384, signature_to_der, verify_uncompressed};

use super::bridge_protocol::{
    self, BootContext, ClaimRequest, Claimed, CreditRecord, Detach, DetachOutcome, Detached,
    DeviceEvent, DeviceRecord, ErrorRecord, FdrManifestSignature, FrameAssembler, Gone, Hello,
    ListEnd, RawRecord, RecordHeader, RecordKind, ServerHello, SignFdrManifestRequest, StatsRecord,
    WatchRequest,
};
use super::link::{BulkTransport, InboundSignal};
use super::watchdog::{LinkWatchdogStats, WatchdogMetrics};
use super::{MAX_PACKET, MAX_TRANSFER};

const DEFAULT_RECEIVE_DEPTH_PACKETS: u32 = 256;

const USB2_HS_BULK_MAX_PACKET: u16 = 512;
const _: () = assert!(USB2_HS_BULK_MAX_PACKET == 512);

// allocateUSBReadBuffers hands the guest exactly eight 0x8000 read buffers (usbmux/trace.rs's
// PacketRejected meaning); the broker's own credit is its software queue depth, not this, so the
// in-flight bound is whichever of the two is smaller.
const GUEST_USB_READ_BUFFERS: u32 = 8;
const READ_CHUNK: usize = 4096;
const SOCKET_DIR_NAME: &str = "restore-bridge-v1";
const SOCKET_OVERRIDE_ENV: &str = "APPLE_UTILS_RESTORE_BRIDGE_DIR";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(250);
// Only read by the `#[cfg(not(test))]` arm of `control_request_timeout()`.
#[cfg_attr(test, allow(dead_code))]
const CONTROL_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeDiscoveredDevice {
    pub generation: u64,
    pub record: DeviceRecord,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeInventory {
    pub revision: u64,
    pub devices: Vec<BridgeDiscoveredDevice>,
}

#[derive(Debug)]
pub struct BridgeClaim {
    pub device_id: String,
    pub generation: u64,
    pub lease_id: u64,
    pub transport_kind: bridge_protocol::TransportKind,
    pub out_max_packet_size: u16,
    pub max_packet_size: usize,
    pub max_transfer_size: usize,
    pub host_to_device_credits: u32,
    pub device_to_host_credits: u32,
    packet_stream: UnixStream,
    packet_reader: RecordReader,
}

impl BridgeClaim {
    pub fn into_transport(self) -> io::Result<SocketBulkTransport> {
        SocketBulkTransport::connect(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeWatchEvent {
    Device {
        generation: u64,
        record: DeviceRecord,
    },
    Barrier(ListEnd),
}

pub struct BridgeWatch {
    stream: UnixStream,
    reader: RecordReader,
    request_id: u64,
}

impl BridgeWatch {
    pub fn next_event(&mut self) -> io::Result<Option<BridgeWatchEvent>> {
        loop {
            let record = match self.reader.read(&mut self.stream)? {
                Some(record) => record,
                None => return Ok(None),
            };
            if record.header.request_id != self.request_id {
                if handle_ping_record(&mut self.stream, &record)? {
                    continue;
                }
                return Err(invalid_data(format!(
                    "unexpected watch request id {}",
                    record.header.request_id
                )));
            }
            match record.header.kind {
                RecordKind::Device => {
                    let device: DeviceRecord = bridge_protocol::decode_json(&record.payload)?;
                    bridge_protocol::validate_device_record(&device)?;
                    return Ok(Some(BridgeWatchEvent::Device {
                        generation: record.header.generation,
                        record: device,
                    }));
                }
                RecordKind::ListEnd => {
                    let barrier: ListEnd = bridge_protocol::decode_json(&record.payload)?;
                    return Ok(Some(BridgeWatchEvent::Barrier(barrier)));
                }
                RecordKind::Error => {
                    let error: ErrorRecord = bridge_protocol::decode_json(&record.payload)?;
                    return Err(error_to_io(error));
                }
                RecordKind::Pong => continue,
                other => {
                    return Err(invalid_data(format!("unexpected watch record {:?}", other)));
                }
            }
        }
    }
}

pub struct BridgeClient {
    stream: UnixStream,
    reader: RecordReader,
    socket_path: PathBuf,
}

impl std::fmt::Debug for BridgeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeClient")
            .field("socket_path", &self.socket_path)
            .finish_non_exhaustive()
    }
}

impl BridgeClient {
    pub fn connect_default() -> io::Result<Self> {
        Self::connect_all_default()?
            .into_iter()
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "no restore bridge brokers were reachable",
                )
            })
    }

    pub fn connect_path(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::connect_all_path(path)?
            .into_iter()
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "no restore bridge brokers were reachable",
                )
            })
    }

    pub fn connect_all_default() -> io::Result<Vec<Self>> {
        Self::connect_all_path(default_discovery_socket_path())
    }

    pub fn connect_all_path(path: impl AsRef<Path>) -> io::Result<Vec<Self>> {
        let path = path.as_ref();
        let mut first_error: Option<io::Error> = None;
        let mut clients = Vec::new();
        let socket_paths = broker_socket_candidates(path)?;
        if socket_paths.is_empty() {
            return Ok(Vec::new());
        }
        for socket_path in socket_paths {
            match connect_and_handshake(&socket_path) {
                Ok((stream, _hello, reader)) => {
                    clients.push(Self {
                        stream,
                        reader,
                        socket_path,
                    });
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        if !clients.is_empty() {
            return Ok(clients);
        }
        Err(first_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "no restore bridge brokers were reachable under {}",
                    path.display()
                ),
            )
        }))
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn list_devices(&mut self) -> io::Result<BridgeInventory> {
        let request_id = next_request_id();
        write_frame(
            &mut self.stream,
            RecordHeader {
                version: bridge_protocol::VERSION,
                kind: RecordKind::List,
                flags: 0,
                payload_len: 0,
                request_id,
                generation: 0,
                lease_id: 0,
            },
            &[],
        )?;
        let mut devices = Vec::new();
        loop {
            let Some(record) = self.reader.read(&mut self.stream)? else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "broker closed discovery stream during LIST",
                ));
            };
            if record.header.request_id != request_id {
                if handle_ping_record(&mut self.stream, &record)? {
                    continue;
                }
                return Err(invalid_data(format!(
                    "unexpected LIST request id {}",
                    record.header.request_id
                )));
            }
            match record.header.kind {
                RecordKind::Device => {
                    if record.header.generation == 0 {
                        return Err(invalid_data("device generation must be nonzero"));
                    }
                    let device: DeviceRecord = bridge_protocol::decode_json(&record.payload)?;
                    bridge_protocol::validate_device_record(&device)?;
                    if device.event != DeviceEvent::Snapshot {
                        return Err(invalid_data(format!(
                            "LIST device event must be snapshot, got {:?}",
                            device.event
                        )));
                    }
                    devices.push(BridgeDiscoveredDevice {
                        generation: record.header.generation,
                        record: device,
                    });
                }
                RecordKind::ListEnd => {
                    let barrier: ListEnd = bridge_protocol::decode_json(&record.payload)?;
                    if barrier.device_count as usize != devices.len() {
                        return Err(invalid_data(format!(
                            "LIST_END count {} does not match {} devices",
                            barrier.device_count,
                            devices.len()
                        )));
                    }
                    return Ok(BridgeInventory {
                        revision: barrier.revision,
                        devices,
                    });
                }
                RecordKind::Error => {
                    let error: ErrorRecord = bridge_protocol::decode_json(&record.payload)?;
                    return Err(error_to_io(error));
                }
                RecordKind::Pong => {}
                other => {
                    return Err(invalid_data(format!("unexpected LIST record {:?}", other)));
                }
            }
        }
    }

    pub fn into_watch(mut self, after_revision: u64) -> io::Result<BridgeWatch> {
        let request = WatchRequest { after_revision };
        let request_id = next_request_id();
        let payload = bridge_protocol::encode_json(&request)?;
        write_frame(
            &mut self.stream,
            RecordHeader {
                version: bridge_protocol::VERSION,
                kind: RecordKind::Watch,
                flags: 0,
                payload_len: 0,
                request_id,
                generation: 0,
                lease_id: 0,
            },
            &payload,
        )?;
        Ok(BridgeWatch {
            stream: self.stream,
            reader: self.reader,
            request_id,
        })
    }

    pub fn claim_device(
        &self,
        device_id: impl Into<String>,
        generation: u64,
    ) -> io::Result<BridgeClaim> {
        if generation == 0 {
            return Err(invalid_input("claim generation must be nonzero"));
        }
        let device_id = device_id.into();
        let request = ClaimRequest {
            device_id: device_id.clone(),
            receive_depth_packets: DEFAULT_RECEIVE_DEPTH_PACKETS,
        };
        bridge_protocol::validate_claim_request(&request)?;
        let (mut stream, _, mut reader) = connect_and_handshake(&self.socket_path)?;
        let request_id = next_request_id();
        let payload = bridge_protocol::encode_json(&request)?;
        write_frame(
            &mut stream,
            RecordHeader {
                version: bridge_protocol::VERSION,
                kind: RecordKind::Claim,
                flags: 0,
                payload_len: 0,
                request_id,
                generation,
                lease_id: 0,
            },
            &payload,
        )?;
        loop {
            let Some(record) = reader.read(&mut stream)? else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "broker closed claim stream during CLAIM",
                ));
            };
            if record.header.request_id != request_id {
                if handle_ping_record(&mut stream, &record)? {
                    continue;
                }
                return Err(invalid_data(format!(
                    "unexpected CLAIM request id {}",
                    record.header.request_id
                )));
            }
            match record.header.kind {
                RecordKind::Claimed => {
                    if record.header.generation != generation || record.header.lease_id == 0 {
                        return Err(invalid_data("CLAIMED generation or lease is invalid"));
                    }
                    let claimed: Claimed = bridge_protocol::decode_json(&record.payload)?;
                    bridge_protocol::validate_claimed(&claimed)?;
                    if claimed.device_id != device_id {
                        return Err(invalid_data(format!(
                            "CLAIMED device '{}' does not match '{}'",
                            claimed.device_id, device_id
                        )));
                    }
                    return Ok(BridgeClaim {
                        device_id,
                        generation,
                        lease_id: record.header.lease_id,
                        transport_kind: claimed.transport_kind,
                        out_max_packet_size: claimed.out_max_packet_size,
                        max_packet_size: usize::try_from(claimed.max_packet_size).unwrap(),
                        max_transfer_size: usize::try_from(claimed.max_transfer_size).unwrap(),
                        host_to_device_credits: claimed.host_to_device_credits,
                        device_to_host_credits: claimed.device_to_host_credits,
                        packet_stream: stream,
                        packet_reader: reader,
                    });
                }
                RecordKind::Error => {
                    let error: ErrorRecord = bridge_protocol::decode_json(&record.payload)?;
                    return Err(error_to_io(error));
                }
                RecordKind::Pong => {}
                other => {
                    return Err(invalid_data(format!("unexpected CLAIM record {:?}", other)));
                }
            }
        }
    }
}

pub fn default_discovery_socket_path() -> PathBuf {
    discovery_socket_path(
        std::env::var_os(SOCKET_OVERRIDE_ENV).map(PathBuf::from),
        current_euid(),
    )
}

fn discovery_socket_path(override_path: Option<PathBuf>, effective_uid: u32) -> PathBuf {
    override_path
        .unwrap_or_else(|| Path::new("/tmp").join(format!("{SOCKET_DIR_NAME}-{effective_uid}")))
}

pub struct SocketBulkTransport {
    writer: Arc<Mutex<UnixStream>>,
    state: Arc<TransportState>,
    reader: Option<JoinHandle<()>>,
    out_max_packet_size: u16,
    max_packet_size: usize,
    generation: u64,
    lease_id: u64,
}

#[derive(Clone)]
pub struct ClaimedSessionControl {
    writer: Arc<Mutex<UnixStream>>,
    state: Arc<TransportState>,
    generation: u64,
    lease_id: u64,
}

impl SocketBulkTransport {
    pub fn connect(claim: BridgeClaim) -> io::Result<Self> {
        if claim.max_packet_size > MAX_PACKET
            || claim.max_packet_size > bridge_protocol::MAX_PACKET_BYTES
        {
            return Err(invalid_data(format!(
                "claim maxPacketSize {} exceeds {}",
                claim.max_packet_size,
                MAX_PACKET.min(bridge_protocol::MAX_PACKET_BYTES)
            )));
        }
        if claim.max_transfer_size > MAX_TRANSFER
            || claim.max_transfer_size > bridge_protocol::MAX_TRANSFER_BYTES
        {
            return Err(invalid_data(format!(
                "claim maxTransferSize {} exceeds {}",
                claim.max_transfer_size,
                MAX_TRANSFER.min(bridge_protocol::MAX_TRANSFER_BYTES)
            )));
        }
        let reader_stream = claim.packet_stream.try_clone()?;
        let writer = Arc::new(Mutex::new(claim.packet_stream));
        let state = Arc::new(TransportState::new(
            claim.host_to_device_credits,
            claim.device_to_host_credits,
            claim.max_transfer_size,
        ));
        let reader_state = Arc::clone(&state);
        let reader_writer = Arc::clone(&writer);
        let generation = claim.generation;
        let lease_id = claim.lease_id;
        let max_transfer_size = claim.max_transfer_size;
        let packet_reader = claim.packet_reader;
        let reader = thread::Builder::new()
            .name(format!("restore-bridge-packet-{}-{}", generation, lease_id))
            .spawn(move || {
                read_loop(
                    reader_stream,
                    packet_reader,
                    reader_writer,
                    reader_state,
                    generation,
                    lease_id,
                    max_transfer_size,
                );
            })?;
        Ok(Self {
            writer,
            state,
            reader: Some(reader),
            out_max_packet_size: claim.out_max_packet_size,
            max_packet_size: claim.max_packet_size,
            generation,
            lease_id,
        })
    }

    pub fn control_handle(&self) -> ClaimedSessionControl {
        ClaimedSessionControl {
            writer: Arc::clone(&self.writer),
            state: Arc::clone(&self.state),
            generation: self.generation,
            lease_id: self.lease_id,
        }
    }

    pub fn get_boot_context(&self) -> io::Result<BootContext> {
        self.control_handle().get_boot_context()
    }

    pub fn sign_fdr_manifest(
        &self,
        signed_body: &[u8],
        boot_context: &BootContext,
    ) -> io::Result<FdrManifestSignature> {
        self.control_handle()
            .sign_fdr_manifest(signed_body, boot_context)
    }

    pub fn sign_fdr_manifest_der(
        &self,
        signed_body: &[u8],
        boot_context: &BootContext,
    ) -> io::Result<Vec<u8>> {
        self.control_handle()
            .sign_fdr_manifest_der(signed_body, boot_context)
    }

    pub fn detach(&self, outcome: DetachOutcome, detail: Option<String>) -> io::Result<Detached> {
        self.control_handle().detach(outcome, detail)
    }

    // Held directly rather than reached through the link, so a watchdog sampling it never has to
    // take the mutex it exists to watch.
    #[must_use]
    pub fn watchdog_metrics(&self) -> Arc<dyn WatchdogMetrics> {
        Arc::clone(&self.state) as Arc<dyn WatchdogMetrics>
    }
}

impl ClaimedSessionControl {
    pub fn abort(&self) -> io::Result<()> {
        self.close_with_reason("claimed session aborted")
    }

    pub fn close(&self) -> io::Result<()> {
        self.close_with_reason("claimed session closed")
    }

    pub fn get_boot_context(&self) -> io::Result<BootContext> {
        let record = self.send_request(RecordKind::GetBootContext, &[])?;
        match record.header.kind {
            RecordKind::BootContext => {
                let context = BootContext::decode(&record.payload)?;
                validate_boot_context(&context)?;
                Ok(context)
            }
            RecordKind::Error => {
                let error: ErrorRecord = bridge_protocol::decode_json(&record.payload)?;
                Err(error_to_io(error))
            }
            other => Err(invalid_data(format!(
                "unexpected GetBootContext response {:?}",
                other
            ))),
        }
    }

    pub fn sign_fdr_manifest(
        &self,
        signed_body: &[u8],
        boot_context: &BootContext,
    ) -> io::Result<FdrManifestSignature> {
        let request = SignFdrManifestRequest {
            signed_body: signed_body.to_vec(),
        };
        let record = self.send_request(RecordKind::SignFdrManifest, &request.encode()?)?;
        match record.header.kind {
            RecordKind::FdrManifestSignature => {
                let signature = FdrManifestSignature::decode(&record.payload)?;
                validate_manifest_signature(signed_body, boot_context, &signature)?;
                Ok(signature)
            }
            RecordKind::Error => {
                let error: ErrorRecord = bridge_protocol::decode_json(&record.payload)?;
                Err(error_to_io(error))
            }
            other => Err(invalid_data(format!(
                "unexpected SignFdrManifest response {:?}",
                other
            ))),
        }
    }

    pub fn sign_fdr_manifest_der(
        &self,
        signed_body: &[u8],
        boot_context: &BootContext,
    ) -> io::Result<Vec<u8>> {
        Ok(signature_to_der(
            &self
                .sign_fdr_manifest(signed_body, boot_context)?
                .signature_rs,
        ))
    }

    pub fn detach(&self, outcome: DetachOutcome, detail: Option<String>) -> io::Result<Detached> {
        let payload = bridge_protocol::encode_json(&Detach { outcome, detail })?;
        let record = self.send_request(RecordKind::Detach, &payload)?;
        match record.header.kind {
            RecordKind::Detached => Ok(bridge_protocol::decode_json(&record.payload)?),
            RecordKind::Error => {
                let error: ErrorRecord = bridge_protocol::decode_json(&record.payload)?;
                Err(error_to_io(error))
            }
            other => Err(invalid_data(format!(
                "unexpected DETACH response {:?}",
                other
            ))),
        }
    }

    fn send_request(&self, kind: RecordKind, payload: &[u8]) -> io::Result<RawRecord> {
        if self.state.is_closed() {
            return Err(broken_pipe("claimed session is closed"));
        }
        let request_id = next_request_id();
        let (tx, rx) = mpsc::sync_channel(1);
        self.state.register_waiter(request_id, tx)?;
        let write_result = write_frame(
            &mut self.writer.lock().unwrap(),
            RecordHeader {
                version: bridge_protocol::VERSION,
                kind,
                flags: 0,
                payload_len: 0,
                request_id,
                generation: self.generation,
                lease_id: self.lease_id,
            },
            payload,
        );
        if let Err(error) = write_result {
            self.state.remove_waiter(request_id);
            self.state.mark_terminal(Some(error.to_string()), false);
            return Err(error);
        }
        match rx.recv_timeout(control_request_timeout()) {
            Ok(record) => Ok(record),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.state.remove_waiter(request_id);
                let message = format!("{kind:?} request timed out");
                let _ = self.close_with_reason(&message);
                Err(io::Error::new(io::ErrorKind::TimedOut, message))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "packet stream closed before reply arrived",
            )),
        }
    }

    fn close_with_reason(&self, reason: &str) -> io::Result<()> {
        self.state.mark_terminal(Some(reason.to_string()), false);
        match self.writer.lock().unwrap().shutdown(Shutdown::Both) {
            Ok(()) => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe | io::ErrorKind::NotConnected
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

fn validate_boot_context(context: &BootContext) -> io::Result<()> {
    if let Some(ref object) = context.fdr_trust_object {
        let digest = context
            .fdr_trust_digest_sha256
            .ok_or_else(|| invalid_data("boot context trust object is missing digest"))?;
        if sha256(object) != digest {
            return Err(invalid_data(
                "boot context trust digest does not match trust object",
            ));
        }
    } else if context.fdr_trust_digest_sha256.is_some() {
        return Err(invalid_data(
            "boot context trust digest is present without trust object",
        ));
    }
    if context.fdr_trust_object.is_none()
        && (context.fdr_element_index != 0 || context.fdr_element_count != 0)
    {
        return Err(invalid_data(
            "boot context FDR element metadata must be zero without trust data",
        ));
    }
    if let Some(ref instance) = context.fdr_instance
        && (instance.is_empty() || context.fdr_trust_object.is_none())
    {
        return Err(invalid_data(
            "boot context FDR instance requires trust data",
        ));
    }
    if let Some(ref path) = context.fdr_material_path
        && (path.as_bytes().is_empty() || context.fdr_trust_object.is_none())
    {
        return Err(invalid_data(
            "boot context FDR material path requires trust data",
        ));
    }
    if context.remote_signer_available && context.sep_public_key_uncompressed.is_none() {
        return Err(invalid_data(
            "boot context remote signer requires SEP public key",
        ));
    }
    if let Some(public_key) = context.sep_public_key_uncompressed
        && import_public(&public_key).is_none()
    {
        return Err(invalid_data(
            "boot context SEP public key is not a valid P-256 point",
        ));
    }
    Ok(())
}

fn validate_manifest_signature(
    signed_body: &[u8],
    boot_context: &BootContext,
    signature: &FdrManifestSignature,
) -> io::Result<()> {
    let expected_public_key = boot_context.sep_public_key_uncompressed.ok_or_else(|| {
        invalid_data("boot context has no SEP public key for signature verification")
    })?;
    let expected_digest = sha384(signed_body);
    if signature.signed_body_length
        != u32::try_from(signed_body.len()).map_err(|_| invalid_input("signed body too large"))?
    {
        return Err(invalid_data(
            "signature signedBodyLength does not match request",
        ));
    }
    if signature.digest_sha384 != expected_digest {
        return Err(invalid_data(
            "signature SHA-384 digest does not match local digest",
        ));
    }
    if signature.signer_public_key_uncompressed != expected_public_key {
        return Err(invalid_data(
            "signature public key does not match BootContext SEP key",
        ));
    }
    let mut reduced = [0u8; 32];
    reduced.copy_from_slice(&expected_digest[..32]);
    if !verify_uncompressed(
        &signature.signer_public_key_uncompressed,
        &reduced,
        &signature.signature_rs,
    ) {
        return Err(invalid_data(
            "signature r||s does not verify against BootContext SEP key",
        ));
    }
    Ok(())
}

impl Drop for SocketBulkTransport {
    fn drop(&mut self) {
        self.state.mark_terminal(None, false);
        let _ = self.writer.lock().unwrap().shutdown(Shutdown::Both);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl BulkTransport for SocketBulkTransport {
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        bridge_protocol::validate_packet_to_device(packet)?;
        if packet.len() > self.max_packet_size {
            return Err(invalid_input(format!(
                "packet {} exceeds max packet size {}",
                packet.len(),
                self.max_packet_size
            )));
        }
        if !self.state.try_take_host_credit()? {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no host-to-device credit is available for this mux port write yet",
            ));
        }
        write_frame(
            &mut self.writer.lock().unwrap(),
            RecordHeader {
                version: bridge_protocol::VERSION,
                kind: RecordKind::PacketToDevice,
                flags: 0,
                payload_len: 0,
                request_id: 0,
                generation: self.generation,
                lease_id: self.lease_id,
            },
            packet,
        )
        .inspect_err(|error| {
            self.state.mark_terminal(Some(error.to_string()), false);
        })?;
        self.state
            .packets_sent_to_broker
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn recv(&mut self, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
        let packet = self.state.recv_packet(timeout)?;
        if let Some(ref packet) = packet {
            let credit = bridge_protocol::encode_credit(CreditRecord {
                direction: 2,
                delta: 1,
            })?;
            write_frame(
                &mut self.writer.lock().unwrap(),
                RecordHeader {
                    version: bridge_protocol::VERSION,
                    kind: RecordKind::Credit,
                    flags: 0,
                    payload_len: 0,
                    request_id: 0,
                    generation: self.generation,
                    lease_id: self.lease_id,
                },
                &credit,
            )
            .inspect_err(|error| {
                self.state.mark_terminal(Some(error.to_string()), false);
            })?;
            self.state.packets_in.fetch_add(1, Ordering::Relaxed);
            self.state
                .queued_from_device
                .store(self.state.queue_len() as u32, Ordering::Relaxed);
            let _ = packet;
        } else {
            self.state.idle_reads.fetch_add(1, Ordering::Relaxed);
        }
        Ok(packet)
    }

    fn out_max_packet_size(&self) -> u16 {
        self.out_max_packet_size
    }

    fn max_packet(&self) -> usize {
        self.max_packet_size
    }

    fn device_accepted_packets(&self) -> Option<u64> {
        Some(
            self.state
                .packets_accepted_by_device
                .load(Ordering::Relaxed),
        )
    }

    fn inbound_signal(&self) -> Option<Arc<dyn InboundSignal>> {
        Some(self.state.clone())
    }

    fn device_present(&self) -> Option<bool> {
        Some(self.state.device_present.load(Ordering::Relaxed))
    }

    fn send_capacity(&self) -> Option<bool> {
        Some(self.state.has_host_credit())
    }
}

impl WatchdogMetrics for SocketBulkTransport {
    fn snapshot(&self) -> LinkWatchdogStats {
        self.state.watchdog_snapshot()
    }
}

struct QueueState {
    packets: VecDeque<Vec<u8>>,
    closed: bool,
    error: Option<String>,
    host_credits: u32,
    host_credit_limit: u32,
    inbound_generation: u64,
}

struct TransportState {
    queue: Mutex<QueueState>,
    queue_cv: Condvar,
    waiters: Mutex<HashMap<u64, SyncSender<RawRecord>>>,
    device_present: AtomicBool,
    max_transfer_size: usize,
    queue_limit: usize,
    max_in_flight: u32,
    packets_in: AtomicU64,
    packets_sent_to_broker: AtomicU64,
    deferred_writes: AtomicU64,
    idle_reads: AtomicU64,
    reads_refused: AtomicU64,
    queued_from_device: AtomicU32,
    packets_to_device_received: AtomicU64,
    packets_accepted_by_device: AtomicU64,
}

impl TransportState {
    fn new(host_credits: u32, device_to_host_credits: u32, max_transfer_size: usize) -> Self {
        Self {
            queue: Mutex::new(QueueState {
                packets: VecDeque::new(),
                closed: false,
                error: None,
                host_credits,
                host_credit_limit: host_credits,
                inbound_generation: 0,
            }),
            queue_cv: Condvar::new(),
            waiters: Mutex::new(HashMap::new()),
            device_present: AtomicBool::new(true),
            max_transfer_size,
            queue_limit: usize::try_from(device_to_host_credits).unwrap(),
            max_in_flight: GUEST_USB_READ_BUFFERS.min(host_credits),
            packets_in: AtomicU64::new(0),
            packets_sent_to_broker: AtomicU64::new(0),
            deferred_writes: AtomicU64::new(0),
            idle_reads: AtomicU64::new(0),
            reads_refused: AtomicU64::new(0),
            queued_from_device: AtomicU32::new(0),
            packets_to_device_received: AtomicU64::new(0),
            packets_accepted_by_device: AtomicU64::new(0),
        }
    }

    fn apply_broker_stats(&self, stats: &StatsRecord) {
        self.packets_to_device_received
            .store(stats.packets_to_device_received, Ordering::Relaxed);
        self.packets_accepted_by_device
            .store(stats.packets_accepted_by_device, Ordering::Relaxed);
        if stats.presence == 0 {
            self.mark_terminal(
                Some("broker heartbeat reports the device is not present".to_string()),
                false,
            );
        }
    }

    fn watchdog_snapshot(&self) -> LinkWatchdogStats {
        LinkWatchdogStats {
            packets_in: self.packets_in.load(Ordering::Relaxed),
            packets_out: self.packets_accepted_by_device.load(Ordering::Relaxed),
            deferred_writes: self.deferred_writes.load(Ordering::Relaxed),
            idle_reads: self.idle_reads.load(Ordering::Relaxed),
            reads_refused: self.reads_refused.load(Ordering::Relaxed),
            queued: self.packets_to_device_received.load(Ordering::Relaxed),
        }
    }

    fn register_waiter(&self, request_id: u64, tx: SyncSender<RawRecord>) -> io::Result<()> {
        let mut waiters = self.waiters.lock().unwrap();
        if waiters.insert(request_id, tx).is_some() {
            return Err(invalid_data(format!(
                "duplicate in-flight request {request_id}"
            )));
        }
        Ok(())
    }

    fn remove_waiter(&self, request_id: u64) {
        self.waiters.lock().unwrap().remove(&request_id);
    }

    fn deliver_waiter(&self, record: RawRecord) -> bool {
        let Some(waiter) = self
            .waiters
            .lock()
            .unwrap()
            .remove(&record.header.request_id)
        else {
            return false;
        };
        let _ = waiter.send(record);
        true
    }

    fn add_host_credit(&self, delta: u32) -> io::Result<()> {
        let mut guard = self.queue.lock().unwrap();
        let Some(next) = guard.host_credits.checked_add(delta) else {
            return Err(invalid_data("host credits overflowed"));
        };
        if next > guard.host_credit_limit {
            return Err(invalid_data(format!(
                "host credits {next} exceed limit {}",
                guard.host_credit_limit
            )));
        }
        guard.host_credits = next;
        guard.inbound_generation = guard.inbound_generation.wrapping_add(1);
        self.queue_cv.notify_all();
        Ok(())
    }

    // Never blocks: a writer holding the shared link mutex must not wait for the transport under
    // it, so the wait for a refused credit happens off-link, through InboundSignal, one layer up.
    fn try_take_host_credit(&self) -> io::Result<bool> {
        let mut guard = self.queue.lock().unwrap();
        if guard.closed || !self.device_present.load(Ordering::Relaxed) {
            self.reads_refused.fetch_add(1, Ordering::Relaxed);
            return Err(broken_pipe(
                guard.error.as_deref().unwrap_or("device is gone"),
            ));
        }
        let outstanding = guard.host_credit_limit.saturating_sub(guard.host_credits);
        if guard.host_credits != 0 && outstanding < self.max_in_flight {
            guard.host_credits -= 1;
            return Ok(true);
        }
        self.deferred_writes.fetch_add(1, Ordering::Relaxed);
        Ok(false)
    }

    fn has_host_credit(&self) -> bool {
        let guard = self.queue.lock().unwrap();
        if guard.closed || !self.device_present.load(Ordering::Relaxed) {
            return true;
        }
        let outstanding = guard.host_credit_limit.saturating_sub(guard.host_credits);
        guard.host_credits != 0 && outstanding < self.max_in_flight
    }

    fn push_packet(&self, packet: Vec<u8>) -> io::Result<()> {
        bridge_protocol::validate_packet_from_device(&packet, self.max_transfer_size)?;
        let mut guard = self.queue.lock().unwrap();
        if guard.packets.len() >= self.queue_limit {
            return Err(invalid_data(
                "device sent more packets than the restore client credited",
            ));
        }
        guard.inbound_generation = guard.inbound_generation.wrapping_add(1);
        guard.packets.push_back(packet);
        self.queued_from_device
            .store(guard.packets.len() as u32, Ordering::Relaxed);
        self.queue_cv.notify_all();
        Ok(())
    }

    fn recv_packet(&self, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
        let mut guard = self.queue.lock().unwrap();
        if guard.packets.is_empty() && !guard.closed {
            let (next_guard, result) = self.queue_cv.wait_timeout(guard, timeout).unwrap();
            guard = next_guard;
            if result.timed_out() && guard.packets.is_empty() {
                return Ok(None);
            }
        }
        if let Some(packet) = guard.packets.pop_front() {
            self.queued_from_device
                .store(guard.packets.len() as u32, Ordering::Relaxed);
            return Ok(Some(packet));
        }
        if guard.closed || !self.device_present.load(Ordering::Relaxed) {
            return Err(broken_pipe(
                guard.error.as_deref().unwrap_or("device is gone"),
            ));
        }
        Ok(None)
    }

    fn mark_terminal(&self, error: Option<String>, device_present: bool) {
        self.device_present.store(device_present, Ordering::Relaxed);
        let mut guard = self.queue.lock().unwrap();
        guard.closed = true;
        if let Some(error) = error {
            guard.error = Some(error);
        }
        self.queue_cv.notify_all();
        drop(guard);
        self.waiters.lock().unwrap().clear();
    }

    fn queue_len(&self) -> usize {
        self.queue.lock().unwrap().packets.len()
    }

    fn is_closed(&self) -> bool {
        self.queue.lock().unwrap().closed
    }
}

impl InboundSignal for TransportState {
    fn inbound_generation(&self) -> u64 {
        self.queue.lock().unwrap().inbound_generation
    }

    fn wait_for_inbound(&self, seen: u64, timeout: Duration) {
        let guard = self.queue.lock().unwrap();
        if guard.inbound_generation != seen || guard.closed {
            return;
        }
        let _ = self.queue_cv.wait_timeout(guard, timeout);
    }
}

impl WatchdogMetrics for TransportState {
    fn snapshot(&self) -> LinkWatchdogStats {
        self.watchdog_snapshot()
    }
}

fn read_loop(
    mut stream: UnixStream,
    mut reader: RecordReader,
    writer: Arc<Mutex<UnixStream>>,
    state: Arc<TransportState>,
    generation: u64,
    lease_id: u64,
    max_transfer_size: usize,
) {
    loop {
        let frame = match reader.read(&mut stream) {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                state.mark_terminal(None, false);
                return;
            }
            Err(error) => {
                state.mark_terminal(Some(error.to_string()), false);
                return;
            }
        };
        if frame.header.generation != generation || frame.header.lease_id != lease_id {
            state.mark_terminal(
                Some(format!(
                    "packet stream generation/lease mismatch {}:{} expected {}:{}",
                    frame.header.generation, frame.header.lease_id, generation, lease_id
                )),
                false,
            );
            return;
        }
        if let Err(error) = handle_packet_frame(&writer, &state, frame, max_transfer_size) {
            state.mark_terminal(Some(error.to_string()), false);
            return;
        }
        if state.is_closed() {
            return;
        }
    }
}

fn handle_packet_frame(
    writer: &Arc<Mutex<UnixStream>>,
    state: &Arc<TransportState>,
    frame: RawRecord,
    _max_transfer_size: usize,
) -> io::Result<()> {
    match frame.header.kind {
        RecordKind::PacketFromDevice => {
            if frame.header.request_id != 0 {
                return Err(invalid_data("PACKET_FROM_DEVICE requestId must be zero"));
            }
            state.push_packet(frame.payload)
        }
        RecordKind::Credit => {
            if frame.header.request_id != 0 {
                return Err(invalid_data("CREDIT requestId must be zero"));
            }
            let credit = bridge_protocol::decode_credit(&frame.payload)?;
            if credit.direction != 1 {
                return Err(invalid_data(format!(
                    "broker sent invalid credit direction {}",
                    credit.direction
                )));
            }
            state.add_host_credit(credit.delta)
        }
        RecordKind::Stats => {
            if frame.header.request_id != 0 {
                return Err(invalid_data("STATS requestId must be zero"));
            }
            let stats = bridge_protocol::decode_stats(&frame.payload)?;
            state.apply_broker_stats(&stats);
            Ok(())
        }
        RecordKind::Gone => {
            if frame.header.request_id != 0 {
                return Err(invalid_data("GONE requestId must be zero"));
            }
            let gone: Gone = bridge_protocol::decode_json(&frame.payload)?;
            let detail = gone
                .detail
                .unwrap_or_else(|| format!("device went away because {:?}", gone.reason));
            state.mark_terminal(Some(detail), false);
            Ok(())
        }
        RecordKind::Ping => {
            if frame.header.request_id == 0 {
                return Err(invalid_data("PING requestId must be nonzero"));
            }
            let nonce = bridge_protocol::decode_ping_nonce(&frame.payload)?;
            write_frame(
                &mut writer.lock().unwrap(),
                RecordHeader {
                    version: bridge_protocol::VERSION,
                    kind: RecordKind::Pong,
                    flags: 0,
                    payload_len: 0,
                    request_id: frame.header.request_id,
                    generation: frame.header.generation,
                    lease_id: frame.header.lease_id,
                },
                &bridge_protocol::encode_ping_nonce(nonce),
            )
        }
        RecordKind::Pong | RecordKind::BootContext | RecordKind::FdrManifestSignature => {
            if frame.header.request_id == 0 {
                return Err(invalid_data("control reply requestId must be nonzero"));
            }
            if !state.deliver_waiter(frame) {
                return Err(invalid_data(
                    "unexpected unsolicited control reply on packet stream",
                ));
            }
            Ok(())
        }
        RecordKind::Detached => {
            if frame.header.request_id == 0 {
                return Err(invalid_data("DETACHED requestId must be nonzero"));
            }
            if !state.deliver_waiter(frame) {
                return Err(invalid_data(
                    "unexpected unsolicited DETACHED on packet stream",
                ));
            }
            state.mark_terminal(None, false);
            Ok(())
        }
        RecordKind::Error => {
            if frame.header.request_id == 0 {
                let error: ErrorRecord = bridge_protocol::decode_json(&frame.payload)?;
                state.mark_terminal(Some(format!("{}: {}", error.code, error.detail)), false);
                return Ok(());
            }
            if !state.deliver_waiter(frame) {
                return Err(invalid_data(
                    "unexpected unsolicited control error on packet stream",
                ));
            }
            Ok(())
        }
        other => Err(invalid_data(format!(
            "unexpected packet-mode frame {:?}",
            other
        ))),
    }
}

fn connect_and_handshake(
    socket_path: &Path,
) -> io::Result<(UnixStream, ServerHello, RecordReader)> {
    verify_same_user_socket(socket_path)?;
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    validate_peer_uid(&stream, current_euid())?;
    let hello = Hello {
        minimum_version: bridge_protocol::VERSION,
        maximum_version: bridge_protocol::VERSION,
        client_name: "apple-utils".to_string(),
        client_instance_id: client_instance_id(),
        client_pid: std::process::id(),
    };
    bridge_protocol::validate_hello(&hello)?;
    let request_id = next_request_id();
    let payload = bridge_protocol::encode_json(&hello)?;
    write_frame(
        &mut stream,
        RecordHeader {
            version: bridge_protocol::VERSION,
            kind: RecordKind::Hello,
            flags: 0,
            payload_len: 0,
            request_id,
            generation: 0,
            lease_id: 0,
        },
        &payload,
    )?;
    let mut reader = RecordReader::default();
    let record = reader.read(&mut stream)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "broker closed before SERVER_HELLO",
        )
    })?;
    if record.header.request_id != request_id
        || record.header.generation != 0
        || record.header.lease_id != 0
    {
        return Err(invalid_data("SERVER_HELLO header values are invalid"));
    }
    match record.header.kind {
        RecordKind::ServerHello => {
            let hello: ServerHello = bridge_protocol::decode_json(&record.payload)?;
            bridge_protocol::validate_server_hello(&hello)?;
            stream.set_read_timeout(None)?;
            stream.set_write_timeout(None)?;
            Ok((stream, hello, reader))
        }
        RecordKind::Error => {
            let error: ErrorRecord = bridge_protocol::decode_json(&record.payload)?;
            Err(error_to_io(error))
        }
        other => Err(invalid_data(format!(
            "expected SERVER_HELLO, got {:?}",
            other
        ))),
    }
}

fn write_frame(stream: &mut UnixStream, header: RecordHeader, payload: &[u8]) -> io::Result<()> {
    let bytes = bridge_protocol::encode_record(header, payload)?;
    stream.write_all(&bytes)
}

#[derive(Default)]
struct RecordReader {
    assembler: FrameAssembler,
    pending: VecDeque<RawRecord>,
}

impl std::fmt::Debug for RecordReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordReader")
            .field("pending", &self.pending.len())
            .finish_non_exhaustive()
    }
}

impl RecordReader {
    fn read(&mut self, stream: &mut UnixStream) -> io::Result<Option<RawRecord>> {
        let mut scratch = [0u8; READ_CHUNK];
        loop {
            if let Some(record) = self.pending.pop_front() {
                return Ok(Some(record));
            }
            let read = match stream.read(&mut scratch) {
                Ok(0) => return Ok(None),
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            self.pending.extend(self.assembler.push(&scratch[..read])?);
        }
    }
}

fn handle_ping_record(stream: &mut UnixStream, record: &RawRecord) -> io::Result<bool> {
    if record.header.kind != RecordKind::Ping {
        return Ok(false);
    }
    if record.header.request_id == 0 {
        return Err(invalid_data("PING requestId must be nonzero"));
    }
    let nonce = bridge_protocol::decode_ping_nonce(&record.payload)?;
    write_frame(
        stream,
        RecordHeader {
            version: bridge_protocol::VERSION,
            kind: RecordKind::Pong,
            flags: 0,
            payload_len: 0,
            request_id: record.header.request_id,
            generation: record.header.generation,
            lease_id: record.header.lease_id,
        },
        &bridge_protocol::encode_ping_nonce(nonce),
    )?;
    Ok(true)
}

fn broker_socket_candidates(path: &Path) -> io::Result<Vec<PathBuf>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() {
        return Err(invalid_input(format!(
            "{} must not be a symlink",
            path.display()
        )));
    }
    if metadata.file_type().is_socket() {
        verify_same_user_socket(path)?;
        return Ok(vec![path.to_path_buf()]);
    }
    if !metadata.is_dir() {
        return Err(invalid_input(format!(
            "{} is not a discovery directory",
            path.display()
        )));
    }
    if metadata.uid() != current_euid() {
        return Err(invalid_input(format!(
            "discovery directory {} is not owned by the current user",
            path.display()
        )));
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(invalid_input(format!(
            "discovery directory {} must have mode 0700",
            path.display()
        )));
    }
    let mut sockets = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("b-") || !name.ends_with(".sock") {
            continue;
        }
        sockets.push(entry.path());
    }
    sockets.sort();
    Ok(sockets)
}

fn verify_same_user_socket(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(invalid_input(format!(
            "socket {} must not be a symlink",
            path.display()
        )));
    }
    if !metadata.file_type().is_socket() {
        return Err(invalid_input(format!(
            "{} is not a Unix socket",
            path.display()
        )));
    }
    if metadata.uid() != current_euid() {
        return Err(invalid_input(format!(
            "socket {} is not owned by the current user",
            path.display()
        )));
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(invalid_input(format!(
            "socket {} must have mode 0600",
            path.display()
        )));
    }
    Ok(())
}

fn validate_peer_uid(stream: &UnixStream, expected_uid: u32) -> io::Result<()> {
    let uid = peer_uid(stream)?;
    if uid != expected_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("broker peer uid {uid} does not match current uid {expected_uid}"),
        ));
    }
    Ok(())
}

fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid as u32)
    }
    #[cfg(target_os = "linux")]
    {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(cred.uid)
    }
}

fn current_euid() -> u32 {
    unsafe { libc::geteuid() }
}

fn next_request_id() -> u64 {
    REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed).max(1)
}

#[cfg(test)]
fn control_request_timeout() -> Duration {
    Duration::from_millis(200)
}

#[cfg(not(test))]
fn control_request_timeout() -> Duration {
    CONTROL_REQUEST_TIMEOUT
}

fn client_instance_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos();
    let pid = u128::from(std::process::id());
    format!("{:032x}", now ^ (pid << 64) ^ u128::from(next_request_id()))
}

fn error_to_io(error: ErrorRecord) -> io::Error {
    let kind = match error.code.as_str() {
        "unsupportedVersion" => io::ErrorKind::Unsupported,
        "wrongConnectionMode" | "invalidFrame" | "invalidJson" | "invalidRequest" => {
            io::ErrorKind::InvalidData
        }
        "resyncRequired" => io::ErrorKind::InvalidData,
        "deviceNotFound" => io::ErrorKind::NotFound,
        "staleGeneration" | "deviceUnavailable" | "deviceBusy" | "deviceGone" => {
            io::ErrorKind::WouldBlock
        }
        "bootContextUnavailable" | "signerUnavailable" => io::ErrorKind::NotFound,
        "invalidFdrManifest" | "creditViolation" | "internal" => io::ErrorKind::InvalidData,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("{}: {}", error.code, error.detail))
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn broken_pipe(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::crypto::P256PrivateKey;
    use std::os::unix::net::UnixListener;
    use std::sync::Barrier;
    use std::time::Instant;

    use tempfile::TempDir;

    fn temp_socket_dir() -> TempDir {
        let root = tempfile::Builder::new()
            .prefix("restore-bridge-")
            .tempdir_in("/tmp")
            .unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(root.path()).unwrap();
        assert_eq!(metadata.uid(), current_euid());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        let path = root.path().join("restore-bridge-v1");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    fn broker_path(root: &TempDir) -> PathBuf {
        let path = root
            .path()
            .join("restore-bridge-v1")
            .join("b-4242-0123456789abcdef0123456789abcdef.sock");
        assert!(path.as_os_str().as_bytes().len() < 100);
        path
    }

    fn broker_path_named(root: &TempDir, name: &str) -> PathBuf {
        let path = root.path().join("restore-bridge-v1").join(name);
        assert!(path.as_os_str().as_bytes().len() < 100);
        path
    }

    #[test]
    fn discovery_path_override_takes_precedence_over_uid_default() {
        let override_path = PathBuf::from("/private/tmp/custom-restore-bridge");

        assert_eq!(
            discovery_socket_path(Some(override_path.clone()), 501),
            override_path
        );
    }

    #[test]
    fn discovery_default_is_isolated_by_effective_uid() {
        assert_eq!(
            discovery_socket_path(None, 501),
            PathBuf::from("/tmp/restore-bridge-v1-501")
        );
        assert_eq!(
            discovery_socket_path(None, 502),
            PathBuf::from("/tmp/restore-bridge-v1-502")
        );
        assert_ne!(
            discovery_socket_path(None, 501),
            discovery_socket_path(None, 502)
        );
    }

    #[test]
    fn discovery_default_is_short_and_deterministic() {
        let first = discovery_socket_path(None, u32::MAX);
        let second = discovery_socket_path(None, u32::MAX);

        assert_eq!(first, PathBuf::from("/tmp/restore-bridge-v1-4294967295"));
        assert_eq!(first, second);
        assert!(first.as_os_str().as_bytes().len() < 100);
    }

    fn bind_listener(path: &Path) -> UnixListener {
        let listener = UnixListener::bind(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        listener
    }

    fn server_hello() -> ServerHello {
        server_hello_for("0123456789abcdef0123456789abcdef", 4242)
    }

    fn server_hello_for(broker_id: &str, server_pid: u32) -> ServerHello {
        ServerHello {
            selected_version: 1,
            server_name: "restore-host".to_string(),
            broker_id: broker_id.to_string(),
            server_pid,
            capabilities: bridge_protocol::SERVER_CAPABILITIES
                .into_iter()
                .map(str::to_string)
                .collect(),
        }
    }

    fn complete_server_handshake(
        stream: &mut UnixStream,
        server_hello: &ServerHello,
    ) -> RecordReader {
        let mut parser = RecordReader::default();
        let hello = read_one(stream, &mut parser);
        assert_eq!(hello.header.kind, RecordKind::Hello);
        let hello_request_id = hello.header.request_id;
        let hello: Hello = bridge_protocol::decode_json(&hello.payload).unwrap();
        bridge_protocol::validate_hello(&hello).unwrap();
        write_json_frame(
            stream,
            RecordKind::ServerHello,
            hello_request_id,
            0,
            0,
            server_hello,
        );
        parser
    }

    fn accept_server_connection(
        listener: &UnixListener,
        server_hello: &ServerHello,
    ) -> (UnixStream, RecordReader) {
        let (mut stream, _) = listener.accept().unwrap();
        let reader = complete_server_handshake(&mut stream, server_hello);
        (stream, reader)
    }

    fn available_device(
        revision: u64,
        broker_id: &str,
        device_id: &str,
        vm_id: &str,
    ) -> DeviceRecord {
        DeviceRecord {
            revision,
            event: DeviceEvent::Snapshot,
            broker_id: broker_id.to_string(),
            device_id: device_id.to_string(),
            vm_id: vm_id.to_string(),
            vm_name: format!("Mac {vm_id}"),
            controller_index: 0,
            transport_kind: bridge_protocol::TransportKind::Dwc3,
            state: bridge_protocol::DeviceState::Available,
            detail: None,
            out_max_packet_size: 512,
            max_packet_size: MAX_PACKET as u32,
            max_transfer_size: MAX_TRANSFER as u32,
        }
    }

    fn valid_boot_context(signing_key: &P256PrivateKey) -> BootContext {
        BootContext {
            staged_boot_manifest_sha384: [0x10; 48],
            ap_nonce: Some([0x20; 32]),
            fdr_element_index: 0,
            fdr_element_count: 1,
            fdr_trust_digest_sha256: Some(sha256(&[0xaa, 0xbb, 0xcc])),
            fdr_trust_object: Some(vec![0xaa, 0xbb, 0xcc]),
            fdr_instance: Some("instance-1".to_string()),
            fdr_material_path: Some(PathBuf::from("/tmp/fdr-material").into_os_string()),
            sep_public_key_uncompressed: Some(signing_key.public_uncompressed()),
            remote_signer_available: true,
        }
    }

    fn valid_manb_body() -> Vec<u8> {
        let inner_set = vec![0x31, 0x03, 0x02, 0x01, 0x01];
        let mut sequence = vec![0x30, 0x0b, 0x16, 0x04, b'M', b'A', b'N', b'B'];
        sequence.extend_from_slice(&inner_set);
        let mut outer = vec![0x31, 0x14];
        outer.extend_from_slice(&bridge_protocol::MANB_IDENTIFIER_BYTES);
        outer.push(0x0d);
        outer.extend_from_slice(&sequence);
        outer
    }

    #[test]
    fn host_to_device_outstanding_is_capped_to_the_guest_usb_read_buffers() {
        assert_eq!(USB2_HS_BULK_MAX_PACKET, 512);
        assert_eq!(GUEST_USB_READ_BUFFERS, 8);
        // The broker grants 256, far more than the guest's eight read buffers, so the derived cap
        // is the guest's own hardware limit rather than the broker's software queue depth.
        let state = TransportState::new(256, 8, MAX_TRANSFER);
        for _ in 0..GUEST_USB_READ_BUFFERS {
            assert!(state.try_take_host_credit().unwrap());
        }
        assert!(
            !state.try_take_host_credit().unwrap(),
            "a ninth 32 KiB mux packet must not go out until the guest accepts one of the eight USB 2 read buffers"
        );
        assert!(!state.has_host_credit());
        state.add_host_credit(1).unwrap();
        assert!(state.has_host_credit());
        assert!(
            state.try_take_host_credit().unwrap(),
            "a USB accept returns a host-to-device credit"
        );
    }

    #[test]
    fn the_in_flight_cap_never_exceeds_what_the_broker_actually_granted() {
        // The broker granted only three, fewer than the guest's eight read buffers, so the derived
        // cap follows the broker's grant rather than the guest's hardware limit.
        let state = TransportState::new(3, 8, MAX_TRANSFER);
        for _ in 0..3 {
            assert!(state.try_take_host_credit().unwrap());
        }
        assert!(
            !state.try_take_host_credit().unwrap(),
            "the broker granted only three host-to-device credits, so a fourth must wait"
        );
    }

    #[test]
    fn watchdog_queue_and_undrained_use_cumulative_host_to_device_counts() {
        let state = TransportState::new(4, 8, MAX_TRANSFER);
        state.packets_sent_to_broker.store(13, Ordering::Relaxed);
        state.queued_from_device.store(3, Ordering::Relaxed);
        state.apply_broker_stats(&StatsRecord {
            packets_to_device_received: 11,
            packets_accepted_by_device: 7,
            bytes_accepted_by_device: 1_024,
            packets_from_device_sent: 5,
            bytes_from_device_sent: 512,
            queued_to_device: 4,
            queued_from_device: 9,
            host_to_device_credits_outstanding: 2,
            device_to_host_credits_outstanding: 6,
            presence: 1,
        });

        let snapshot = state.watchdog_snapshot();
        assert_eq!(snapshot.queued, 11);
        assert_eq!(snapshot.packets_out, 7);
        assert_eq!(snapshot.queued.saturating_sub(snapshot.packets_out), 4);
        assert_eq!(state.packets_sent_to_broker.load(Ordering::Relaxed), 13);
        assert_eq!(state.queued_from_device.load(Ordering::Relaxed), 3);
    }

    fn stats_with_presence(presence: u8) -> StatsRecord {
        StatsRecord {
            packets_to_device_received: 0,
            packets_accepted_by_device: 0,
            bytes_accepted_by_device: 0,
            packets_from_device_sent: 0,
            bytes_from_device_sent: 0,
            queued_to_device: 0,
            queued_from_device: 0,
            host_to_device_credits_outstanding: 0,
            device_to_host_credits_outstanding: 0,
            presence,
        }
    }

    #[test]
    fn a_present_heartbeat_leaves_the_transport_open() {
        let state = TransportState::new(4, 8, MAX_TRANSFER);
        state.apply_broker_stats(&stats_with_presence(1));
        assert!(!state.is_closed());
        assert!(state.device_present.load(Ordering::Relaxed));
    }

    #[test]
    fn an_absent_heartbeat_closes_the_transport_and_releases_a_credit_waiter() {
        let state = TransportState::new(0, 8, MAX_TRANSFER);
        assert!(
            !state.try_take_host_credit().unwrap(),
            "no credit has been granted yet"
        );
        let before = state.inbound_generation();
        state.apply_broker_stats(&stats_with_presence(0));
        assert!(!state.device_present.load(Ordering::Relaxed));
        assert!(state.is_closed());
        assert!(
            state.try_take_host_credit().is_err(),
            "a stalled-but-present connection must not stay open once presence says otherwise"
        );
        // wait_for_inbound must return immediately once closed, not park on the condvar.
        let began = Instant::now();
        state.wait_for_inbound(before, Duration::from_secs(30));
        assert!(began.elapsed() < Duration::from_secs(1));
    }

    fn read_one(stream: &mut UnixStream, reader: &mut RecordReader) -> RawRecord {
        reader.read(stream).unwrap().unwrap()
    }

    fn write_json_frame<T: serde::Serialize>(
        stream: &mut UnixStream,
        kind: RecordKind,
        request_id: u64,
        generation: u64,
        lease_id: u64,
        value: &T,
    ) {
        let payload = bridge_protocol::encode_json(value).unwrap();
        write_frame(
            stream,
            RecordHeader {
                version: bridge_protocol::VERSION,
                kind,
                flags: 0,
                payload_len: 0,
                request_id,
                generation,
                lease_id,
            },
            &payload,
        )
        .unwrap();
    }

    #[test]
    fn list_claim_boot_context_sign_and_packet_flow_work_end_to_end() {
        let root = temp_socket_dir();
        let socket_path = broker_path(&root);
        let listener = bind_listener(&socket_path);
        let signing_key =
            P256PrivateKey::derive(b"restore-bridge-test-seed", b"restore-bridge-test-domain");
        let boot_context = valid_boot_context(&signing_key);
        let expected_boot_context = boot_context.clone();
        let barrier = Arc::new(Barrier::new(2));
        let server_barrier = barrier.clone();
        let server = thread::spawn(move || {
            let (mut discovery, _) = listener.accept().unwrap();
            let mut parser = RecordReader::default();
            let hello = read_one(&mut discovery, &mut parser);
            let hello_request_id = hello.header.request_id;
            let hello: Hello = bridge_protocol::decode_json(&hello.payload).unwrap();
            bridge_protocol::validate_hello(&hello).unwrap();
            write_json_frame(
                &mut discovery,
                RecordKind::ServerHello,
                hello_request_id,
                0,
                0,
                &server_hello(),
            );
            let list = read_one(&mut discovery, &mut parser);
            assert_eq!(list.header.kind, RecordKind::List);
            let request_id = list.header.request_id;
            let device = DeviceRecord {
                revision: 7,
                event: DeviceEvent::Snapshot,
                broker_id: "0123456789abcdef0123456789abcdef".to_string(),
                device_id: "opaque-1".to_string(),
                vm_id: "vm-1".to_string(),
                vm_name: "Mac".to_string(),
                controller_index: 0,
                transport_kind: bridge_protocol::TransportKind::Dwc3,
                state: bridge_protocol::DeviceState::Available,
                detail: None,
                out_max_packet_size: 512,
                max_packet_size: MAX_PACKET as u32,
                max_transfer_size: MAX_TRANSFER as u32,
            };
            write_json_frame(
                &mut discovery,
                RecordKind::Device,
                request_id,
                91,
                0,
                &device,
            );
            write_json_frame(
                &mut discovery,
                RecordKind::ListEnd,
                request_id,
                0,
                0,
                &ListEnd {
                    revision: 7,
                    device_count: 1,
                },
            );

            let (mut claim_stream, _) = listener.accept().unwrap();
            let mut claim_parser = RecordReader::default();
            let hello = read_one(&mut claim_stream, &mut claim_parser);
            let hello_request_id = hello.header.request_id;
            let hello: Hello = bridge_protocol::decode_json(&hello.payload).unwrap();
            bridge_protocol::validate_hello(&hello).unwrap();
            write_json_frame(
                &mut claim_stream,
                RecordKind::ServerHello,
                hello_request_id,
                0,
                0,
                &server_hello(),
            );
            let claim = read_one(&mut claim_stream, &mut claim_parser);
            assert_eq!(claim.header.kind, RecordKind::Claim);
            let request_id = claim.header.request_id;
            let claim_request: ClaimRequest = bridge_protocol::decode_json(&claim.payload).unwrap();
            bridge_protocol::validate_claim_request(&claim_request).unwrap();
            write_json_frame(
                &mut claim_stream,
                RecordKind::Claimed,
                request_id,
                claim.header.generation,
                1234,
                &Claimed {
                    device_id: claim_request.device_id.clone(),
                    transport_kind: bridge_protocol::TransportKind::Dwc3,
                    out_max_packet_size: 512,
                    max_packet_size: MAX_PACKET as u32,
                    max_transfer_size: MAX_TRANSFER as u32,
                    host_to_device_credits: 2,
                    device_to_host_credits: 2,
                },
            );

            let boot_request = read_one(&mut claim_stream, &mut claim_parser);
            assert_eq!(boot_request.header.kind, RecordKind::GetBootContext);
            write_frame(
                &mut claim_stream,
                RecordHeader {
                    version: bridge_protocol::VERSION,
                    kind: RecordKind::BootContext,
                    flags: 0,
                    payload_len: 0,
                    request_id: boot_request.header.request_id,
                    generation: boot_request.header.generation,
                    lease_id: boot_request.header.lease_id,
                },
                &boot_context.encode().unwrap(),
            )
            .unwrap();

            let sign_record = read_one(&mut claim_stream, &mut claim_parser);
            assert_eq!(sign_record.header.kind, RecordKind::SignFdrManifest);
            let request_id = sign_record.header.request_id;
            let sign_request = SignFdrManifestRequest::decode(&sign_record.payload).unwrap();
            let digest = sha384(&sign_request.signed_body);
            let mut reduced = [0u8; 32];
            reduced.copy_from_slice(&digest[..32]);
            let signature = FdrManifestSignature {
                signed_body_length: sign_request.signed_body.len() as u32,
                digest_sha384: digest,
                signature_rs: signing_key.sign_digest(&reduced),
                signer_public_key_uncompressed: signing_key.public_uncompressed(),
            };
            write_frame(
                &mut claim_stream,
                RecordHeader {
                    version: bridge_protocol::VERSION,
                    kind: RecordKind::FdrManifestSignature,
                    flags: 0,
                    payload_len: 0,
                    request_id,
                    generation: 91,
                    lease_id: 1234,
                },
                &signature.encode(),
            )
            .unwrap();

            write_frame(
                &mut claim_stream,
                RecordHeader {
                    version: bridge_protocol::VERSION,
                    kind: RecordKind::PacketFromDevice,
                    flags: 0,
                    payload_len: 0,
                    request_id: 0,
                    generation: 91,
                    lease_id: 1234,
                },
                &[0xaa, 0xbb, 0xcc],
            )
            .unwrap();

            let credit = read_one(&mut claim_stream, &mut claim_parser);
            assert_eq!(credit.header.kind, RecordKind::Credit);
            assert_eq!(
                bridge_protocol::decode_credit(&credit.payload).unwrap(),
                CreditRecord {
                    direction: 2,
                    delta: 1
                }
            );

            server_barrier.wait();
            let packet = read_one(&mut claim_stream, &mut claim_parser);
            assert_eq!(packet.header.kind, RecordKind::PacketToDevice);
            assert_eq!(packet.payload, vec![0, 0, 0, 0, 0, 0, 0, 8]);
            let credit = bridge_protocol::encode_credit(CreditRecord {
                direction: 1,
                delta: 1,
            })
            .unwrap();
            write_frame(
                &mut claim_stream,
                RecordHeader {
                    version: bridge_protocol::VERSION,
                    kind: RecordKind::Credit,
                    flags: 0,
                    payload_len: 0,
                    request_id: 0,
                    generation: 91,
                    lease_id: 1234,
                },
                &credit,
            )
            .unwrap();
            write_json_frame(
                &mut claim_stream,
                RecordKind::Gone,
                0,
                91,
                1234,
                &Gone {
                    reason: bridge_protocol::GoneReason::VmReset,
                    detail: Some("the VM reset".to_string()),
                    replacement_generation: None,
                    retryable: true,
                },
            );
        });

        let mut client = BridgeClient::connect_path(root.path().join("restore-bridge-v1")).unwrap();
        let inventory = client.list_devices().unwrap();
        assert_eq!(inventory.revision, 7);
        assert_eq!(inventory.devices.len(), 1);
        let claim = client
            .claim_device(
                &inventory.devices[0].record.device_id,
                inventory.devices[0].generation,
            )
            .unwrap();
        let mut transport = SocketBulkTransport::connect(claim).unwrap();
        let control = transport.control_handle();
        let context = control.get_boot_context().unwrap();
        assert_eq!(context, expected_boot_context);
        let body = valid_manb_body();
        let signature = control.sign_fdr_manifest(&body, &context).unwrap();
        assert_eq!(signature.digest_sha384, sha384(&body));
        assert_eq!(
            transport.recv(Duration::from_secs(1)).unwrap().unwrap(),
            vec![0xaa, 0xbb, 0xcc]
        );
        barrier.wait();
        transport.send(&[0, 0, 0, 0, 0, 0, 0, 8]).unwrap();
        thread::sleep(Duration::from_millis(50));
        assert_eq!(transport.device_present(), Some(false));
        server.join().unwrap();
    }

    #[test]
    fn watch_stream_replays_barrier_and_live_event() {
        let root = temp_socket_dir();
        let socket_path = broker_path(&root);
        let listener = bind_listener(&socket_path);
        let server = thread::spawn(move || {
            let (mut watch_stream, _) = listener.accept().unwrap();
            let mut parser = RecordReader::default();
            let hello = read_one(&mut watch_stream, &mut parser);
            let hello_request_id = hello.header.request_id;
            let hello: Hello = bridge_protocol::decode_json(&hello.payload).unwrap();
            bridge_protocol::validate_hello(&hello).unwrap();
            write_json_frame(
                &mut watch_stream,
                RecordKind::ServerHello,
                hello_request_id,
                0,
                0,
                &server_hello(),
            );
            let watch = read_one(&mut watch_stream, &mut parser);
            assert_eq!(watch.header.kind, RecordKind::Watch);
            let request_id = watch.header.request_id;
            let device = DeviceRecord {
                revision: 8,
                event: DeviceEvent::Changed,
                broker_id: "0123456789abcdef0123456789abcdef".to_string(),
                device_id: "opaque-1".to_string(),
                vm_id: "vm-1".to_string(),
                vm_name: "Mac".to_string(),
                controller_index: 0,
                transport_kind: bridge_protocol::TransportKind::Dwc3,
                state: bridge_protocol::DeviceState::Claimed,
                detail: Some("claimed".to_string()),
                out_max_packet_size: 512,
                max_packet_size: MAX_PACKET as u32,
                max_transfer_size: MAX_TRANSFER as u32,
            };
            write_json_frame(
                &mut watch_stream,
                RecordKind::Device,
                request_id,
                92,
                0,
                &device,
            );
            write_json_frame(
                &mut watch_stream,
                RecordKind::ListEnd,
                request_id,
                0,
                0,
                &ListEnd {
                    revision: 8,
                    device_count: 1,
                },
            );
        });

        let client = BridgeClient::connect_path(root.path().join("restore-bridge-v1")).unwrap();
        let mut watch = client.into_watch(7).unwrap();
        match watch.next_event().unwrap().unwrap() {
            BridgeWatchEvent::Device { generation, record } => {
                assert_eq!(generation, 92);
                assert_eq!(record.event, DeviceEvent::Changed);
                assert_eq!(record.detail.as_deref(), Some("claimed"));
            }
            other => panic!("unexpected first watch event {other:?}"),
        }
        match watch.next_event().unwrap().unwrap() {
            BridgeWatchEvent::Barrier(barrier) => assert_eq!(barrier.revision, 8),
            other => panic!("unexpected second watch event {other:?}"),
        }
        server.join().unwrap();
    }

    #[test]
    fn insecure_socket_permissions_are_rejected() {
        let root = temp_socket_dir();
        let socket_path = broker_path(&root);
        let _listener = bind_listener(&socket_path);
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o400)).unwrap();
        let error = BridgeClient::connect_path(root.path().join("restore-bridge-v1")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn second_claim_reports_device_busy() {
        let root = temp_socket_dir();
        let socket_path = broker_path(&root);
        let listener = bind_listener(&socket_path);
        let server = thread::spawn(move || {
            for index in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut parser = RecordReader::default();
                let hello = read_one(&mut stream, &mut parser);
                let hello_request_id = hello.header.request_id;
                let hello: Hello = bridge_protocol::decode_json(&hello.payload).unwrap();
                bridge_protocol::validate_hello(&hello).unwrap();
                write_json_frame(
                    &mut stream,
                    RecordKind::ServerHello,
                    hello_request_id,
                    0,
                    0,
                    &server_hello(),
                );
                if index == 0 {
                    let list = read_one(&mut stream, &mut parser);
                    let request_id = list.header.request_id;
                    write_json_frame(
                        &mut stream,
                        RecordKind::Device,
                        request_id,
                        91,
                        0,
                        &DeviceRecord {
                            revision: 1,
                            event: DeviceEvent::Snapshot,
                            broker_id: "0123456789abcdef0123456789abcdef".to_string(),
                            device_id: "opaque-1".to_string(),
                            vm_id: "vm-1".to_string(),
                            vm_name: "Mac".to_string(),
                            controller_index: 0,
                            transport_kind: bridge_protocol::TransportKind::Dwc3,
                            state: bridge_protocol::DeviceState::Available,
                            detail: None,
                            out_max_packet_size: 512,
                            max_packet_size: MAX_PACKET as u32,
                            max_transfer_size: MAX_TRANSFER as u32,
                        },
                    );
                    write_json_frame(
                        &mut stream,
                        RecordKind::ListEnd,
                        request_id,
                        0,
                        0,
                        &ListEnd {
                            revision: 1,
                            device_count: 1,
                        },
                    );
                } else {
                    let claim = read_one(&mut stream, &mut parser);
                    let request_id = claim.header.request_id;
                    if index == 1 {
                        let request: ClaimRequest =
                            bridge_protocol::decode_json(&claim.payload).unwrap();
                        write_json_frame(
                            &mut stream,
                            RecordKind::Claimed,
                            request_id,
                            91,
                            1234,
                            &Claimed {
                                device_id: request.device_id,
                                transport_kind: bridge_protocol::TransportKind::Dwc3,
                                out_max_packet_size: 512,
                                max_packet_size: MAX_PACKET as u32,
                                max_transfer_size: MAX_TRANSFER as u32,
                                host_to_device_credits: 1,
                                device_to_host_credits: 1,
                            },
                        );
                    } else {
                        write_json_frame(
                            &mut stream,
                            RecordKind::Error,
                            request_id,
                            91,
                            0,
                            &ErrorRecord {
                                code: "deviceBusy".to_string(),
                                detail: "already claimed".to_string(),
                                fatal: false,
                                retryable: true,
                                current_revision: None,
                                current_generation: Some(91),
                            },
                        );
                    }
                }
            }
        });

        let mut client = BridgeClient::connect_path(root.path().join("restore-bridge-v1")).unwrap();
        let _inventory = client.list_devices().unwrap();
        let _first = client.claim_device("opaque-1", 91).unwrap();
        let second = client.claim_device("opaque-1", 91).unwrap_err();
        assert_eq!(second.kind(), io::ErrorKind::WouldBlock);
        server.join().unwrap();
    }

    #[test]
    fn explicit_socket_path_is_supported() {
        let root = temp_socket_dir();
        let socket_path = broker_path(&root);
        let listener = bind_listener(&socket_path);
        let barrier = Arc::new(Barrier::new(2));
        let server_barrier = barrier.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut parser = RecordReader::default();
            let hello = read_one(&mut stream, &mut parser);
            write_json_frame(
                &mut stream,
                RecordKind::ServerHello,
                hello.header.request_id,
                0,
                0,
                &server_hello(),
            );
            server_barrier.wait();
        });
        let client = BridgeClient::connect_path(&socket_path).unwrap();
        assert_eq!(client.socket_path(), socket_path.as_path());
        barrier.wait();
        server.join().unwrap();
    }

    #[test]
    fn exact_directory_mode_is_enforced() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("restore-bridge-v1");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
        let error = BridgeClient::connect_all_path(&path).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn missing_or_empty_discovery_directory_returns_empty_clients() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing-restore-bridge-v1");
        assert!(BridgeClient::connect_all_path(&missing).unwrap().is_empty());

        let empty = root.path().join("restore-bridge-v1");
        fs::create_dir(&empty).unwrap();
        fs::set_permissions(&empty, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(BridgeClient::connect_all_path(&empty).unwrap().is_empty());
    }

    #[test]
    fn connect_all_returns_every_responsive_broker() {
        let root = temp_socket_dir();
        let first_path = broker_path_named(&root, "b-1000-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.sock");
        let second_path = broker_path_named(&root, "b-2000-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.sock");
        let first_listener = bind_listener(&first_path);
        let second_listener = bind_listener(&second_path);
        let barrier = Arc::new(Barrier::new(3));
        let first_barrier = barrier.clone();
        let first = thread::spawn(move || {
            let (mut stream, _) = first_listener.accept().unwrap();
            let mut parser = RecordReader::default();
            let hello = read_one(&mut stream, &mut parser);
            write_json_frame(
                &mut stream,
                RecordKind::ServerHello,
                hello.header.request_id,
                0,
                0,
                &ServerHello {
                    broker_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                    ..server_hello()
                },
            );
            first_barrier.wait();
        });
        let second_barrier = barrier.clone();
        let second = thread::spawn(move || {
            let (mut stream, _) = second_listener.accept().unwrap();
            let mut parser = RecordReader::default();
            let hello = read_one(&mut stream, &mut parser);
            write_json_frame(
                &mut stream,
                RecordKind::ServerHello,
                hello.header.request_id,
                0,
                0,
                &ServerHello {
                    broker_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                    ..server_hello()
                },
            );
            second_barrier.wait();
        });
        let clients =
            BridgeClient::connect_all_path(root.path().join("restore-bridge-v1")).unwrap();
        assert_eq!(clients.len(), 2);
        let mut paths = clients
            .iter()
            .map(|client| {
                client
                    .socket_path()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .collect::<Vec<_>>();
        paths.sort();
        assert_eq!(
            paths,
            vec![
                "b-1000-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.sock".to_string(),
                "b-2000-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.sock".to_string()
            ]
        );
        barrier.wait();
        first.join().unwrap();
        second.join().unwrap();
    }

    #[test]
    fn overlapping_device_ids_claim_through_the_selected_broker() {
        let root = temp_socket_dir();
        let first_path = broker_path_named(&root, "b-1000-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.sock");
        let second_path = broker_path_named(&root, "b-2000-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.sock");
        let first_listener = bind_listener(&first_path);
        let second_listener = bind_listener(&second_path);
        let first = thread::spawn(move || {
            let hello = server_hello_for("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1000);
            let (mut discovery, _) = first_listener.accept().unwrap();
            let mut parser = complete_server_handshake(&mut discovery, &hello);
            let list = read_one(&mut discovery, &mut parser);
            assert_eq!(list.header.kind, RecordKind::List);
            write_json_frame(
                &mut discovery,
                RecordKind::Device,
                list.header.request_id,
                101,
                0,
                &available_device(
                    1,
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "shared-device",
                    "vm-a",
                ),
            );
            write_json_frame(
                &mut discovery,
                RecordKind::ListEnd,
                list.header.request_id,
                0,
                0,
                &ListEnd {
                    revision: 1,
                    device_count: 1,
                },
            );
        });
        let second = thread::spawn(move || {
            let hello = server_hello_for("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 2000);
            let (mut discovery, _) = second_listener.accept().unwrap();
            let mut parser = complete_server_handshake(&mut discovery, &hello);
            let list = read_one(&mut discovery, &mut parser);
            assert_eq!(list.header.kind, RecordKind::List);
            write_json_frame(
                &mut discovery,
                RecordKind::Device,
                list.header.request_id,
                202,
                0,
                &available_device(
                    2,
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "shared-device",
                    "vm-b",
                ),
            );
            write_json_frame(
                &mut discovery,
                RecordKind::ListEnd,
                list.header.request_id,
                0,
                0,
                &ListEnd {
                    revision: 2,
                    device_count: 1,
                },
            );

            let (mut claim_stream, _) = second_listener.accept().unwrap();
            let mut claim_parser = complete_server_handshake(&mut claim_stream, &hello);
            let claim = read_one(&mut claim_stream, &mut claim_parser);
            assert_eq!(claim.header.kind, RecordKind::Claim);
            assert_eq!(claim.header.generation, 202);
            let request: ClaimRequest = bridge_protocol::decode_json(&claim.payload).unwrap();
            assert_eq!(request.device_id, "shared-device");
            write_json_frame(
                &mut claim_stream,
                RecordKind::Claimed,
                claim.header.request_id,
                202,
                2202,
                &Claimed {
                    device_id: request.device_id,
                    transport_kind: bridge_protocol::TransportKind::Dwc3,
                    out_max_packet_size: 512,
                    max_packet_size: MAX_PACKET as u32,
                    max_transfer_size: MAX_TRANSFER as u32,
                    host_to_device_credits: 1,
                    device_to_host_credits: 1,
                },
            );
        });

        let clients =
            BridgeClient::connect_all_path(root.path().join("restore-bridge-v1")).unwrap();
        assert_eq!(clients.len(), 2);
        let mut observed = Vec::new();
        let mut selected = None;
        for mut client in clients {
            let is_selected = client.socket_path() == second_path;
            let inventory = client.list_devices().unwrap();
            assert_eq!(inventory.devices.len(), 1);
            let device = &inventory.devices[0];
            observed.push((
                device.record.broker_id.clone(),
                device.record.device_id.clone(),
                device.generation,
            ));
            if is_selected {
                selected = Some((client, device.generation));
            }
        }
        observed.sort();
        assert_eq!(
            observed,
            vec![
                (
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                    "shared-device".to_string(),
                    101,
                ),
                (
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                    "shared-device".to_string(),
                    202,
                ),
            ]
        );
        let (selected, generation) = selected.unwrap();
        let claim = selected.claim_device("shared-device", generation).unwrap();
        assert_eq!(claim.generation, 202);
        assert_eq!(claim.lease_id, 2202);
        assert_eq!(claim.device_id, "shared-device");
        drop(claim);
        first.join().unwrap();
        second.join().unwrap();
    }

    #[test]
    fn stale_claim_and_gone_require_the_replacement_generation() {
        let root = temp_socket_dir();
        let socket_path = broker_path(&root);
        let listener = bind_listener(&socket_path);
        let gone_barrier = Arc::new(Barrier::new(2));
        let server_gone_barrier = Arc::clone(&gone_barrier);
        let server = thread::spawn(move || {
            let hello = server_hello();
            {
                let (mut discovery, _) = listener.accept().unwrap();
                let mut parser = complete_server_handshake(&mut discovery, &hello);
                let list = read_one(&mut discovery, &mut parser);
                write_json_frame(
                    &mut discovery,
                    RecordKind::Device,
                    list.header.request_id,
                    91,
                    0,
                    &available_device(1, "0123456789abcdef0123456789abcdef", "opaque-1", "vm-1"),
                );
                write_json_frame(
                    &mut discovery,
                    RecordKind::ListEnd,
                    list.header.request_id,
                    0,
                    0,
                    &ListEnd {
                        revision: 1,
                        device_count: 1,
                    },
                );
            }
            {
                let (mut stale_stream, _) = listener.accept().unwrap();
                let mut parser = complete_server_handshake(&mut stale_stream, &hello);
                let claim = read_one(&mut stale_stream, &mut parser);
                assert_eq!(claim.header.kind, RecordKind::Claim);
                assert_eq!(claim.header.generation, 90);
                write_json_frame(
                    &mut stale_stream,
                    RecordKind::Error,
                    claim.header.request_id,
                    90,
                    0,
                    &ErrorRecord {
                        code: "staleGeneration".to_string(),
                        detail: "generation 90 was replaced by generation 91".to_string(),
                        fatal: true,
                        retryable: true,
                        current_revision: Some(1),
                        current_generation: Some(91),
                    },
                );
            }
            {
                let (mut claim_stream, _) = listener.accept().unwrap();
                let mut parser = complete_server_handshake(&mut claim_stream, &hello);
                let claim = read_one(&mut claim_stream, &mut parser);
                assert_eq!(claim.header.kind, RecordKind::Claim);
                assert_eq!(claim.header.generation, 91);
                let request: ClaimRequest = bridge_protocol::decode_json(&claim.payload).unwrap();
                write_json_frame(
                    &mut claim_stream,
                    RecordKind::Claimed,
                    claim.header.request_id,
                    91,
                    9191,
                    &Claimed {
                        device_id: request.device_id,
                        transport_kind: bridge_protocol::TransportKind::Dwc3,
                        out_max_packet_size: 512,
                        max_packet_size: MAX_PACKET as u32,
                        max_transfer_size: MAX_TRANSFER as u32,
                        host_to_device_credits: 1,
                        device_to_host_credits: 1,
                    },
                );
                server_gone_barrier.wait();
                write_json_frame(
                    &mut claim_stream,
                    RecordKind::Gone,
                    0,
                    91,
                    9191,
                    &Gone {
                        reason: bridge_protocol::GoneReason::VmReset,
                        detail: Some("generation 92 is ready".to_string()),
                        replacement_generation: Some(92),
                        retryable: true,
                    },
                );
            }
            {
                let (mut discovery, _) = listener.accept().unwrap();
                let mut parser = complete_server_handshake(&mut discovery, &hello);
                let list = read_one(&mut discovery, &mut parser);
                write_json_frame(
                    &mut discovery,
                    RecordKind::Device,
                    list.header.request_id,
                    92,
                    0,
                    &available_device(2, "0123456789abcdef0123456789abcdef", "opaque-1", "vm-1"),
                );
                write_json_frame(
                    &mut discovery,
                    RecordKind::ListEnd,
                    list.header.request_id,
                    0,
                    0,
                    &ListEnd {
                        revision: 2,
                        device_count: 1,
                    },
                );
            }
            {
                let (mut claim_stream, _) = listener.accept().unwrap();
                let mut parser = complete_server_handshake(&mut claim_stream, &hello);
                let claim = read_one(&mut claim_stream, &mut parser);
                assert_eq!(claim.header.kind, RecordKind::Claim);
                assert_eq!(claim.header.generation, 92);
                let request: ClaimRequest = bridge_protocol::decode_json(&claim.payload).unwrap();
                write_json_frame(
                    &mut claim_stream,
                    RecordKind::Claimed,
                    claim.header.request_id,
                    92,
                    9292,
                    &Claimed {
                        device_id: request.device_id,
                        transport_kind: bridge_protocol::TransportKind::Dwc3,
                        out_max_packet_size: 512,
                        max_packet_size: MAX_PACKET as u32,
                        max_transfer_size: MAX_TRANSFER as u32,
                        host_to_device_credits: 1,
                        device_to_host_credits: 1,
                    },
                );
            }
        });

        let mut client = BridgeClient::connect_path(root.path().join("restore-bridge-v1")).unwrap();
        let inventory = client.list_devices().unwrap();
        assert_eq!(inventory.devices[0].generation, 91);
        let stale = client.claim_device("opaque-1", 90).unwrap_err();
        assert_eq!(stale.kind(), io::ErrorKind::WouldBlock);
        assert!(stale.to_string().contains("generation 91"));

        let claim = client.claim_device("opaque-1", 91).unwrap();
        let mut transport = claim.into_transport().unwrap();
        gone_barrier.wait();
        let gone = transport.recv(Duration::from_secs(1)).unwrap_err();
        assert_eq!(gone.kind(), io::ErrorKind::BrokenPipe);
        assert!(gone.to_string().contains("generation 92 is ready"));
        assert_eq!(transport.device_present(), Some(false));
        drop(transport);

        let mut replacement =
            BridgeClient::connect_path(root.path().join("restore-bridge-v1")).unwrap();
        let inventory = replacement.list_devices().unwrap();
        assert_eq!(inventory.revision, 2);
        assert_eq!(inventory.devices[0].record.device_id, "opaque-1");
        assert_eq!(inventory.devices[0].generation, 92);
        let claim = replacement.claim_device("opaque-1", 92).unwrap();
        assert_eq!(claim.generation, 92);
        assert_eq!(claim.lease_id, 9292);
        drop(claim);
        server.join().unwrap();
    }

    #[test]
    fn nonresponsive_first_candidate_is_skipped() {
        let root = temp_socket_dir();
        let first_path = broker_path_named(&root, "b-1000-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.sock");
        let second_path = broker_path_named(&root, "b-2000-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.sock");
        let first_listener = bind_listener(&first_path);
        let second_listener = bind_listener(&second_path);
        let first = thread::spawn(move || {
            let (_stream, _) = first_listener.accept().unwrap();
            thread::sleep(HANDSHAKE_TIMEOUT + Duration::from_millis(100));
        });
        let barrier = Arc::new(Barrier::new(2));
        let server_barrier = barrier.clone();
        let second = thread::spawn(move || {
            let (mut stream, _) = second_listener.accept().unwrap();
            let mut parser = RecordReader::default();
            let hello = read_one(&mut stream, &mut parser);
            write_json_frame(
                &mut stream,
                RecordKind::ServerHello,
                hello.header.request_id,
                0,
                0,
                &server_hello(),
            );
            server_barrier.wait();
        });
        let client = BridgeClient::connect_path(root.path().join("restore-bridge-v1")).unwrap();
        assert_eq!(client.socket_path(), second_path.as_path());
        barrier.wait();
        first.join().unwrap();
        second.join().unwrap();
    }

    #[test]
    fn packet_scope_violation_is_terminal() {
        let root = temp_socket_dir();
        let socket_path = broker_path(&root);
        let listener = bind_listener(&socket_path);
        let server = thread::spawn(move || {
            let hello = server_hello();
            let (_discovery, _) = accept_server_connection(&listener, &hello);
            let (mut stream, mut parser) = accept_server_connection(&listener, &hello);
            let claim = read_one(&mut stream, &mut parser);
            write_json_frame(
                &mut stream,
                RecordKind::Claimed,
                claim.header.request_id,
                91,
                1234,
                &Claimed {
                    device_id: "opaque-1".to_string(),
                    transport_kind: bridge_protocol::TransportKind::Dwc3,
                    out_max_packet_size: 512,
                    max_packet_size: MAX_PACKET as u32,
                    max_transfer_size: MAX_TRANSFER as u32,
                    host_to_device_credits: 1,
                    device_to_host_credits: 1,
                },
            );
            let mut invalid_packet = Vec::new();
            RecordHeader {
                version: bridge_protocol::VERSION,
                kind: RecordKind::PacketFromDevice,
                flags: 0,
                payload_len: 1,
                request_id: 9,
                generation: 91,
                lease_id: 1234,
            }
            .encode(&mut invalid_packet);
            invalid_packet.push(0xaa);
            stream.write_all(&invalid_packet).unwrap();
        });
        let client = BridgeClient::connect_path(&socket_path).unwrap();
        let claim = client.claim_device("opaque-1", 91).unwrap();
        let mut transport = SocketBulkTransport::connect(claim).unwrap();
        let error = transport.recv(Duration::from_secs(1)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        server.join().unwrap();
    }

    #[test]
    fn overcredit_is_terminal() {
        let root = temp_socket_dir();
        let socket_path = broker_path(&root);
        let listener = bind_listener(&socket_path);
        let server = thread::spawn(move || {
            let hello = server_hello();
            let (_discovery, _) = accept_server_connection(&listener, &hello);
            let (mut stream, mut parser) = accept_server_connection(&listener, &hello);
            let claim = read_one(&mut stream, &mut parser);
            write_json_frame(
                &mut stream,
                RecordKind::Claimed,
                claim.header.request_id,
                91,
                1234,
                &Claimed {
                    device_id: "opaque-1".to_string(),
                    transport_kind: bridge_protocol::TransportKind::Dwc3,
                    out_max_packet_size: 512,
                    max_packet_size: MAX_PACKET as u32,
                    max_transfer_size: MAX_TRANSFER as u32,
                    host_to_device_credits: 1,
                    device_to_host_credits: 1,
                },
            );
            let credit = bridge_protocol::encode_credit(CreditRecord {
                direction: 1,
                delta: 1,
            })
            .unwrap();
            write_frame(
                &mut stream,
                RecordHeader {
                    version: bridge_protocol::VERSION,
                    kind: RecordKind::Credit,
                    flags: 0,
                    payload_len: 0,
                    request_id: 0,
                    generation: 91,
                    lease_id: 1234,
                },
                &credit,
            )
            .unwrap();
        });
        let client = BridgeClient::connect_path(&socket_path).unwrap();
        let claim = client.claim_device("opaque-1", 91).unwrap();
        let mut transport = SocketBulkTransport::connect(claim).unwrap();
        let error = transport.recv(Duration::from_secs(1)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        server.join().unwrap();
    }

    #[test]
    fn detached_reply_is_terminal() {
        let root = temp_socket_dir();
        let socket_path = broker_path(&root);
        let listener = bind_listener(&socket_path);
        let server = thread::spawn(move || {
            let hello = server_hello();
            let (_discovery, _) = accept_server_connection(&listener, &hello);
            let (mut stream, mut parser) = accept_server_connection(&listener, &hello);
            let claim = read_one(&mut stream, &mut parser);
            write_json_frame(
                &mut stream,
                RecordKind::Claimed,
                claim.header.request_id,
                91,
                1234,
                &Claimed {
                    device_id: "opaque-1".to_string(),
                    transport_kind: bridge_protocol::TransportKind::Dwc3,
                    out_max_packet_size: 512,
                    max_packet_size: MAX_PACKET as u32,
                    max_transfer_size: MAX_TRANSFER as u32,
                    host_to_device_credits: 1,
                    device_to_host_credits: 1,
                },
            );
            let detach = read_one(&mut stream, &mut parser);
            write_json_frame(
                &mut stream,
                RecordKind::Detached,
                detach.header.request_id,
                91,
                1234,
                &Detached {
                    outcome: DetachOutcome::Complete,
                    device_state: bridge_protocol::DetachedDeviceState::Detached,
                    detail: None,
                },
            );
            write_frame(
                &mut stream,
                RecordHeader {
                    version: bridge_protocol::VERSION,
                    kind: RecordKind::PacketFromDevice,
                    flags: 0,
                    payload_len: 0,
                    request_id: 0,
                    generation: 91,
                    lease_id: 1234,
                },
                &[0xaa],
            )
            .unwrap();
        });
        let client = BridgeClient::connect_path(&socket_path).unwrap();
        let claim = client.claim_device("opaque-1", 91).unwrap();
        let mut transport = SocketBulkTransport::connect(claim).unwrap();
        let detached = transport.detach(DetachOutcome::Complete, None).unwrap();
        assert_eq!(
            detached.device_state,
            bridge_protocol::DetachedDeviceState::Detached
        );
        let error = transport.recv(Duration::from_millis(50)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        server.join().unwrap();
    }

    #[test]
    fn gone_reply_is_terminal() {
        let root = temp_socket_dir();
        let socket_path = broker_path(&root);
        let listener = bind_listener(&socket_path);
        let server = thread::spawn(move || {
            let hello = server_hello();
            let (_discovery, _) = accept_server_connection(&listener, &hello);
            let (mut stream, mut parser) = accept_server_connection(&listener, &hello);
            let claim = read_one(&mut stream, &mut parser);
            write_json_frame(
                &mut stream,
                RecordKind::Claimed,
                claim.header.request_id,
                91,
                1234,
                &Claimed {
                    device_id: "opaque-1".to_string(),
                    transport_kind: bridge_protocol::TransportKind::Dwc3,
                    out_max_packet_size: 512,
                    max_packet_size: MAX_PACKET as u32,
                    max_transfer_size: MAX_TRANSFER as u32,
                    host_to_device_credits: 1,
                    device_to_host_credits: 1,
                },
            );
            write_json_frame(
                &mut stream,
                RecordKind::Gone,
                0,
                91,
                1234,
                &Gone {
                    reason: bridge_protocol::GoneReason::VmReset,
                    detail: Some("reset".to_string()),
                    replacement_generation: None,
                    retryable: true,
                },
            );
            write_frame(
                &mut stream,
                RecordHeader {
                    version: bridge_protocol::VERSION,
                    kind: RecordKind::PacketFromDevice,
                    flags: 0,
                    payload_len: 0,
                    request_id: 0,
                    generation: 91,
                    lease_id: 1234,
                },
                &[0xaa],
            )
            .unwrap();
        });
        let client = BridgeClient::connect_path(&socket_path).unwrap();
        let claim = client.claim_device("opaque-1", 91).unwrap();
        let mut transport = SocketBulkTransport::connect(claim).unwrap();
        let error = transport.recv(Duration::from_secs(1)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(transport.device_present(), Some(false));
        server.join().unwrap();
    }

    #[test]
    fn control_request_timeout_is_terminal() {
        let root = temp_socket_dir();
        let socket_path = broker_path(&root);
        let listener = bind_listener(&socket_path);
        let server = thread::spawn(move || {
            let hello = server_hello();
            let (_discovery, _) = accept_server_connection(&listener, &hello);
            let (mut stream, mut parser) = accept_server_connection(&listener, &hello);
            let claim = read_one(&mut stream, &mut parser);
            write_json_frame(
                &mut stream,
                RecordKind::Claimed,
                claim.header.request_id,
                91,
                1234,
                &Claimed {
                    device_id: "opaque-1".to_string(),
                    transport_kind: bridge_protocol::TransportKind::Dwc3,
                    out_max_packet_size: 512,
                    max_packet_size: MAX_PACKET as u32,
                    max_transfer_size: MAX_TRANSFER as u32,
                    host_to_device_credits: 1,
                    device_to_host_credits: 1,
                },
            );
            let _boot_request = read_one(&mut stream, &mut parser);
            thread::sleep(control_request_timeout() + Duration::from_millis(50));
        });
        let client = BridgeClient::connect_path(&socket_path).unwrap();
        let claim = client.claim_device("opaque-1", 91).unwrap();
        let mut transport = SocketBulkTransport::connect(claim).unwrap();
        let control = transport.control_handle();
        let error = control.get_boot_context().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let error = transport.recv(Duration::from_millis(50)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        server.join().unwrap();
    }

    #[test]
    fn control_abort_closes_transport() {
        let root = temp_socket_dir();
        let socket_path = broker_path(&root);
        let listener = bind_listener(&socket_path);
        let server = thread::spawn(move || {
            let hello = server_hello();
            let (_discovery, _) = accept_server_connection(&listener, &hello);
            let (mut stream, mut parser) = accept_server_connection(&listener, &hello);
            let claim = read_one(&mut stream, &mut parser);
            write_json_frame(
                &mut stream,
                RecordKind::Claimed,
                claim.header.request_id,
                91,
                1234,
                &Claimed {
                    device_id: "opaque-1".to_string(),
                    transport_kind: bridge_protocol::TransportKind::Dwc3,
                    out_max_packet_size: 512,
                    max_packet_size: MAX_PACKET as u32,
                    max_transfer_size: MAX_TRANSFER as u32,
                    host_to_device_credits: 1,
                    device_to_host_credits: 1,
                },
            );
            let mut scratch = [0u8; 1];
            let read = stream.read(&mut scratch).unwrap();
            assert_eq!(read, 0);
        });
        let client = BridgeClient::connect_path(&socket_path).unwrap();
        let claim = client.claim_device("opaque-1", 91).unwrap();
        let mut transport = SocketBulkTransport::connect(claim).unwrap();
        let control = transport.control_handle();
        control.abort().unwrap();
        let error = transport.recv(Duration::from_millis(50)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        server.join().unwrap();
    }
}
