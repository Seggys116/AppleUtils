use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::symlink;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(test)]
use plist::Dictionary;
use plist::Value;
use tempfile::{Builder as TempDirBuilder, TempDir};

use crate::asr_server::AsrServerConfig;
use crate::bridge_protocol::{
    BootContext as BridgeBootContext, DetachOutcome, DetachedDeviceState, DeviceRecord,
    DeviceState as BridgeDeviceState, SignFdrManifestRequest,
};
use crate::clip::{FileKind, inspect};
use crate::crypto::{Sha256, Sha512};
#[cfg(test)]
use crate::ramrod::BOOT_NONCE_HASH_BYTES;
use crate::ramrod::{
    BUILD_MANIFEST_FILE_NAME, BuildIdentity, DeviceType, FinalStatus, RESTORE_PLIST_FILE_NAME,
    RestoreBehavior, image_candidates, install_behaviors_for_board, load_build_manifest,
    load_restore_catalog, select_install_identity, select_macos_identity,
};
use crate::recovery_model::RestoreMode;
use crate::recovery_model::{
    FileRequestSpec, HashExpectation, LogLevel, RecoveryDevice, RecoveryEvent, RestoreProgress,
    SessionPhase, declares_another_restore_set, expand_accepted_names, resolve_handoff,
    resolve_handoff_candidates, restore_set_manifest,
};
use crate::recovery_runtime::{RecoveryCommand, RecoveryService, RecoveryServiceError};
use crate::restore::{
    BRIDGE_SIGN_MANB_REQUEST, BRIDGE_SIGN_MANB_RESPONSE, ClaimedMuxTransport,
    ClaimedMuxTransportMetadata, FdrTrustDigest, HostDetachDisposition, HostDetachOutcome,
    HostDetacher, MUX_PREFIX, RemoteManifestSigner, RestoreBootContext, RestoreOutcome,
    RestorePlan, SessionBroker, SessionReply, derive_restore_options, hex_digest,
    prepare_restore_session_with_branching, run_ramrod_restore_over_mux,
};
use crate::usbmux::{
    BridgeClaim, BridgeClient, ClaimedSessionControl, LinkWatchdogPolicy, MuxDialer, MuxLink,
    MuxTraceEvent, MuxTraceSink, SharedLink, SocketBulkTransport, VersionRequest,
    spawn_link_watchdog,
};

const DISCOVERY_INTERVAL: Duration = Duration::from_millis(500);
const DISCOVERY_BACKOFF_MAX: Duration = Duration::from_secs(5);
const COMMAND_QUEUE_BOUND: usize = 64;
const EVENT_QUEUE_BOUND: usize = 512;
const MANIFEST_REQUEST_ID: &str = "build-manifest";
const SYSTEM_IMAGE_REQUEST_ID: &str = "system-image";

pub struct AppleRecoveryService {
    command_tx: SyncSender<ServiceCommand>,
    event_rx: Receiver<RecoveryEvent>,
    worker: Option<JoinHandle<()>>,
}

impl AppleRecoveryService {
    pub fn production() -> Self {
        Self::with_backend(Arc::new(RealBackend::default()))
    }

    fn with_backend(backend: Arc<dyn RestoreBackend>) -> Self {
        let (command_tx, command_rx) = mpsc::sync_channel(COMMAND_QUEUE_BOUND);
        let (event_tx, event_rx) = mpsc::sync_channel(EVENT_QUEUE_BOUND);
        let worker = thread::spawn(move || {
            ServiceWorker::new(backend, command_rx, event_tx).run();
        });
        Self {
            command_tx,
            event_rx,
            worker: Some(worker),
        }
    }
}

impl Drop for AppleRecoveryService {
    fn drop(&mut self) {
        let _ = self.command_tx.send(ServiceCommand::Shutdown);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl RecoveryService for AppleRecoveryService {
    fn send(&mut self, command: RecoveryCommand) -> Result<(), RecoveryServiceError> {
        match self.command_tx.try_send(ServiceCommand::User(command)) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(RecoveryServiceError::new(
                "Recovery service is busy processing another request",
            )),
            Err(TrySendError::Disconnected(_)) => Err(RecoveryServiceError::new(
                "Recovery service worker is no longer running",
            )),
        }
    }

    fn poll(&mut self) -> Vec<RecoveryEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.event_rx.try_recv() {
            events.push(event);
        }
        events
    }
}

enum ServiceCommand {
    User(RecoveryCommand),
    Shutdown,
}

trait RestoreBackend: Send + Sync {
    fn discover(&self) -> Result<BackendDiscovery, String>;
    fn claim(
        &self,
        device_id: &str,
        reporter: crate::restore::SharedReporter,
    ) -> Result<Arc<dyn ClaimedRestore>, String>;
}

trait ClaimedRestore: Send + Sync {
    fn device_id(&self) -> &str;
    fn detail(&self) -> Option<&str>;
    fn context(&self) -> ClaimedBootContext;
    fn identify(&self) -> Result<DeviceType, String>;
    fn abort(&self);
    fn detach_host(&self, disposition: HostDetachDisposition) -> HostDetachOutcome;
    fn run_restore(
        &self,
        boot: RestoreBootContext,
        plan: RestorePlan,
        image_size: u64,
        stop: Arc<AtomicBool>,
        reporter: crate::restore::SharedReporter,
    ) -> RestoreOutcome;
}

#[derive(Clone)]
struct BackendDiscovery {
    devices: Vec<DiscoveredDevice>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DiscoveredDevice {
    id: String,
    title: String,
    detail: String,
    connection: String,
    state: crate::recovery_model::DeviceState,
    connected: bool,
}

#[derive(Clone, Debug)]
struct BackendClaimTarget {
    device_id: String,
    socket_path: PathBuf,
    generation: u64,
    detail: Option<String>,
}

#[derive(Default)]
struct RealBackend {
    routes: Mutex<HashMap<String, BackendClaimTarget>>,
}

#[derive(Clone)]
struct ClaimedBootContext {
    bridge: BridgeBootContext,
    restore: RestoreBootContext,
}

impl RestoreBackend for RealBackend {
    fn discover(&self) -> Result<BackendDiscovery, String> {
        let clients = BridgeClient::connect_all_default().map_err(|error| error.to_string())?;
        let mut devices = Vec::new();
        let mut routes = HashMap::new();
        let mut failures = Vec::new();
        for mut client in clients {
            let socket_path = client.socket_path().to_path_buf();
            match client.list_devices() {
                Ok(inventory) => {
                    devices.extend(inventory.devices.into_iter().map(|discovered| {
                        let record = discovered.record;
                        let device_id = stable_device_id(&record.broker_id, &record.device_id);
                        routes.insert(
                            device_id.clone(),
                            BackendClaimTarget {
                                device_id: record.device_id.clone(),
                                socket_path: socket_path.clone(),
                                generation: discovered.generation,
                                detail: record.detail.clone(),
                            },
                        );
                        DiscoveredDevice {
                            id: device_id,
                            title: discovered_title(&record),
                            detail: discovered_detail(&record),
                            connection: discovered_connection(&record),
                            state: discovered_state(record.state),
                            connected: record.state != BridgeDeviceState::Removed,
                        }
                    }));
                }
                Err(error) => failures.push(format!("{}: {error}", socket_path.display())),
            }
        }
        if devices.is_empty() && !failures.is_empty() {
            return Err(format!(
                "no recovery inventory could be read: {}",
                failures.join("; ")
            ));
        }
        devices.sort_by(|left, right| left.id.cmp(&right.id));
        *self.routes.lock().unwrap() = routes;
        Ok(BackendDiscovery { devices })
    }

    fn claim(
        &self,
        device_id: &str,
        reporter: crate::restore::SharedReporter,
    ) -> Result<Arc<dyn ClaimedRestore>, String> {
        let route = self
            .routes
            .lock()
            .unwrap()
            .get(device_id)
            .cloned()
            .ok_or_else(|| format!("The selected device is no longer available: {device_id}"))?;
        let client =
            BridgeClient::connect_path(&route.socket_path).map_err(|error| error.to_string())?;
        let claim = client
            .claim_device(route.device_id.clone(), route.generation)
            .map_err(|error| error.to_string())?;
        let (claimed, control, bridge_context) = build_claimed_transport(claim, &reporter)?;
        let context = claimed_boot_context(control.clone(), bridge_context)?;
        Ok(Arc::new(RealClaimedRestore {
            device_id: device_id.to_string(),
            detail: route.detail,
            claimed,
            control,
            context,
        }))
    }
}

struct RealClaimedRestore {
    device_id: String,
    detail: Option<String>,
    claimed: ClaimedMuxTransport<SocketBulkTransport>,
    control: ClaimedSessionControl,
    context: ClaimedBootContext,
}

impl ClaimedRestore for RealClaimedRestore {
    fn device_id(&self) -> &str {
        &self.device_id
    }

    fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    fn context(&self) -> ClaimedBootContext {
        self.context.clone()
    }

    fn identify(&self) -> Result<DeviceType, String> {
        let mut dialer = self.claimed.dialer().clone();
        let identified = crate::restore::identify_restore_session(
            &mut dialer,
            crate::ramrod::DialPlan::default().on_port(62078),
            &mut crate::ramrod::SystemClock,
        )
        .map_err(|error| error.to_string())?;
        Ok(identified.device)
    }

    fn abort(&self) {
        let _ = self.control.abort();
    }

    fn detach_host(&self, disposition: HostDetachDisposition) -> HostDetachOutcome {
        self.claimed.detach_host(disposition)
    }

    fn run_restore(
        &self,
        boot: RestoreBootContext,
        plan: RestorePlan,
        image_size: u64,
        stop: Arc<AtomicBool>,
        reporter: crate::restore::SharedReporter,
    ) -> RestoreOutcome {
        run_ramrod_restore_over_mux(
            self.claimed.clone(),
            boot,
            &plan,
            AsrServerConfig::default(),
            image_size,
            0.0,
            stop,
            reporter,
        )
    }
}

struct MuxReportTrace {
    reporter: crate::restore::SharedReporter,
}

impl MuxReportTrace {
    fn new(reporter: crate::restore::SharedReporter) -> Self {
        Self { reporter }
    }
}

impl MuxTraceSink for MuxReportTrace {
    fn event(&self, event: MuxTraceEvent) {
        crate::restore::report::report(
            &self.reporter,
            event.result(),
            &format!("{MUX_PREFIX} {event}"),
        );
    }
}

fn build_claimed_transport(
    claim: BridgeClaim,
    reporter: &crate::restore::SharedReporter,
) -> Result<
    (
        ClaimedMuxTransport<SocketBulkTransport>,
        ClaimedSessionControl,
        BridgeBootContext,
    ),
    String,
> {
    let out_max_packet_size = claim.out_max_packet_size;
    let transport = claim.into_transport().map_err(|error| error.to_string())?;
    let control = transport.control_handle();
    let bridge_context = control
        .get_boot_context()
        .map_err(|error| error.to_string())?;
    // Held directly off the transport, before it moves into the link, so the watchdog never has
    // to take the link mutex it exists to watch in order to sample it.
    let watchdog_metrics = transport.watchdog_metrics();
    let link = SharedLink::new(MuxLink::new(transport));
    // Started before the version exchange, not after it, so the one exchange that is allowed to
    // wait under the link is watched too. Traces only, never aborts: this is a diagnosis fix.
    let watchdog = Arc::new(spawn_link_watchdog(
        link.activity(),
        watchdog_metrics,
        Arc::new(MuxReportTrace::new(reporter.clone())),
        LinkWatchdogPolicy::default(),
    ));
    let version = link
        .negotiate(VersionRequest::resync(), Duration::from_secs(1))
        .map_err(|error| error.to_string())?;
    let dialer = MuxDialer::new(link);
    let detacher = Arc::new(BridgeHostDetacher::new(control.clone()));
    let claimed = ClaimedMuxTransport::new(
        dialer,
        ClaimedMuxTransportMetadata {
            transport_kind: "local-bridge",
            interface: 0,
            device_to_host_endpoint: 0x81,
            host_to_device_endpoint: 0x01,
            host_to_device_max_packet_size: out_max_packet_size,
            version,
        },
    )
    .with_detacher(detacher)
    .with_watchdog(watchdog);
    Ok((claimed, control, bridge_context))
}

fn stable_device_id(broker_id: &str, device_id: &str) -> String {
    format!("{broker_id}:{device_id}")
}

fn discovered_title(record: &DeviceRecord) -> String {
    if record.vm_name.trim().is_empty() {
        "Recovery device".to_string()
    } else {
        record.vm_name.clone()
    }
}

fn discovered_detail(record: &DeviceRecord) -> String {
    record.detail.clone().unwrap_or_else(|| {
        format!(
            "{} controller {} source {}",
            transport_label(record.transport_kind),
            record.controller_index,
            record.vm_id
        )
    })
}

fn discovered_connection(record: &DeviceRecord) -> String {
    format!("local socket ({})", transport_label(record.transport_kind))
}

fn transport_label(kind: crate::bridge_protocol::TransportKind) -> &'static str {
    match kind {
        crate::bridge_protocol::TransportKind::Dwc3 => "DWC3",
        crate::bridge_protocol::TransportKind::VirtioGadget => "virtio gadget",
    }
}

fn discovered_state(state: BridgeDeviceState) -> crate::recovery_model::DeviceState {
    match state {
        BridgeDeviceState::Available => crate::recovery_model::DeviceState::Available,
        BridgeDeviceState::Claimed | BridgeDeviceState::Unavailable => {
            crate::recovery_model::DeviceState::Busy
        }
        BridgeDeviceState::Removed => crate::recovery_model::DeviceState::Disconnected,
    }
}

struct ControlManifestBroker {
    control: ClaimedSessionControl,
    boot_context: BridgeBootContext,
}

impl SessionBroker for ControlManifestBroker {
    fn request(&self, request_code: u16, body: &[u8]) -> Result<SessionReply, String> {
        if request_code != BRIDGE_SIGN_MANB_REQUEST {
            return Err(format!(
                "unsupported recovery bridge control request code {request_code}"
            ));
        }
        let request = SignFdrManifestRequest::decode(body).map_err(|error| error.to_string())?;
        let signature = self
            .control
            .sign_fdr_manifest(&request.signed_body, &self.boot_context)
            .map_err(|error| error.to_string())?;
        Ok(SessionReply {
            response_code: BRIDGE_SIGN_MANB_RESPONSE,
            body: signature.encode(),
        })
    }
}

fn claimed_boot_context(
    control: ClaimedSessionControl,
    bridge: BridgeBootContext,
) -> Result<ClaimedBootContext, String> {
    let mut restore = RestoreBootContext {
        ap_nonce: bridge.ap_nonce,
        sep_public_key: bridge.sep_public_key_uncompressed,
        remote_digest_signing: bridge.remote_signer_available,
        manifest_signer: None,
        local_test_signing_key: None,
    };
    if bridge.remote_signer_available {
        let public_key = bridge.sep_public_key_uncompressed.ok_or_else(|| {
            "bridge boot context requires remote signing but carries no SEP public key".to_string()
        })?;
        let broker: Arc<dyn SessionBroker> = Arc::new(ControlManifestBroker {
            control,
            boot_context: bridge.clone(),
        });
        restore.manifest_signer = Some(Arc::new(RemoteManifestSigner::new(broker, public_key)));
    }
    Ok(ClaimedBootContext { bridge, restore })
}

struct BridgeHostDetacher {
    control: ClaimedSessionControl,
    detached: AtomicBool,
}

impl BridgeHostDetacher {
    fn new(control: ClaimedSessionControl) -> Self {
        Self {
            control,
            detached: AtomicBool::new(false),
        }
    }
}

impl HostDetacher for BridgeHostDetacher {
    fn detach_host(&self, disposition: HostDetachDisposition) -> HostDetachOutcome {
        if self.detached.swap(true, Ordering::AcqRel) {
            return HostDetachOutcome::default();
        }
        let outcome = match disposition {
            HostDetachDisposition::Complete => DetachOutcome::Complete,
            HostDetachDisposition::Cancelled => DetachOutcome::Cancelled,
            HostDetachDisposition::Failed => DetachOutcome::Failed,
        };
        match self.control.detach(outcome, None) {
            Ok(detached) => {
                let delivered = detached.device_state == DetachedDeviceState::Detached;
                HostDetachOutcome {
                    was_connected: delivered,
                    was_configured: delivered,
                    disconnect_delivered: delivered,
                    reset_delivered: false,
                }
            }
            Err(_) => HostDetachOutcome::default(),
        }
    }
}

struct PreparedRestore {
    pending: BTreeMap<String, PendingRequest>,
    accepted: HashMap<String, AcceptedFile>,
    manifest_root: Option<PathBuf>,
    selected_class: Option<String>,
    selected_behavior: Option<RestoreBehavior>,
}

struct ServiceWorker {
    backend: Arc<dyn RestoreBackend>,
    command_rx: Receiver<ServiceCommand>,
    event_tx: SyncSender<RecoveryEvent>,
    last_discovery: Option<BackendDiscovery>,
    last_devices: HashMap<String, RecoveryDevice>,
    last_discovery_error: Option<String>,
    discovery_failures: u32,
    session: Option<ClaimedSession>,
    prepared: Option<PreparedRestore>,
}

impl ServiceWorker {
    fn new(
        backend: Arc<dyn RestoreBackend>,
        command_rx: Receiver<ServiceCommand>,
        event_tx: SyncSender<RecoveryEvent>,
    ) -> Self {
        Self {
            backend,
            command_rx,
            event_tx,
            last_discovery: None,
            last_devices: HashMap::new(),
            last_discovery_error: None,
            discovery_failures: 0,
            session: None,
            prepared: None,
        }
    }

    fn run(&mut self) {
        self.open_manifest_request();
        let mut next_discovery = Instant::now();
        loop {
            self.poll_restore_outcome();
            let wait = next_discovery.saturating_duration_since(Instant::now());
            match self.command_rx.recv_timeout(wait) {
                Ok(ServiceCommand::User(command)) => self.handle_command(command),
                Ok(ServiceCommand::Shutdown) => {
                    self.shutdown();
                    break;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    self.shutdown();
                    break;
                }
            }
            if Instant::now() >= next_discovery {
                self.refresh_discovery();
                next_discovery = Instant::now() + discovery_interval(self.discovery_failures);
            }
        }
    }

    fn shutdown(&mut self) {
        self.cleanup_session(HostDetachDisposition::Cancelled);
    }

    fn handle_command(&mut self, command: RecoveryCommand) {
        match command {
            RecoveryCommand::ClaimDevice { device_id } => self.claim_device(&device_id),
            RecoveryCommand::ReleaseDevice { device_id } => self.release_device(&device_id),
            RecoveryCommand::ProvideFile {
                device_id,
                request_id,
                path,
            } => self.provide_file(&device_id, &request_id, &path),
            RecoveryCommand::StartRestore { device_id } => self.start_restore(&device_id),
            RecoveryCommand::CancelRestore { device_id } => self.cancel_restore(&device_id),
            RecoveryCommand::RetryRestore { device_id } => self.retry_restore(&device_id),
            RecoveryCommand::SelectSystem { device_class } => self.select_system(&device_class),
            RecoveryCommand::SelectRestoreMode { mode } => self.select_restore_mode(mode),
            RecoveryCommand::Autosearch { device_id, path } => self.autosearch(&device_id, &path),
        }
    }

    fn refresh_discovery(&mut self) {
        let discovery = match self.backend.discover() {
            Ok(discovery) => discovery,
            Err(error) => {
                self.note_discovery_failure(&error);
                return;
            }
        };
        if self.last_discovery_error.take().is_some() {
            self.try_emit(RecoveryEvent::Log {
                level: LogLevel::Info,
                message: "Recovery device discovery resumed".into(),
            });
        }
        self.discovery_failures = 0;
        self.last_discovery = Some(discovery.clone());
        let claimed = self
            .session
            .as_ref()
            .map(|session| session.claim.device_id());
        let mapped = map_devices(&discovery.devices, claimed);

        for device in mapped.values() {
            let changed = self.last_devices.get(&device.id) != Some(device);
            if changed {
                self.emit(RecoveryEvent::DeviceDiscovered(device.clone()));
            }
        }

        for missing_id in self
            .last_devices
            .keys()
            .filter(|device_id| !mapped.contains_key(*device_id))
            .cloned()
            .collect::<Vec<_>>()
        {
            self.emit(RecoveryEvent::DeviceDisconnected {
                device_id: missing_id.clone(),
                note: Some("Device left the recovery inventory".to_string()),
            });
            if self
                .session
                .as_ref()
                .is_some_and(|session| session.claim.device_id() == missing_id)
                && let Some(session) = &mut self.session
                && let Some(run) = &mut session.restore_run
            {
                run.stop.store(true, Ordering::Relaxed);
                run.release_after = true;
            }
        }

        self.last_devices = mapped;
    }

    fn note_discovery_failure(&mut self, error: &str) {
        self.discovery_failures = self.discovery_failures.saturating_add(1);
        let message = if is_transient_discovery_error(error) {
            format!("Recovery broker is busy ({error})")
        } else {
            format!("Recovery device discovery failed: {error}")
        };
        if self.last_discovery_error.as_deref() == Some(message.as_str()) {
            return;
        }
        self.last_discovery_error = Some(message.clone());
        self.try_emit(RecoveryEvent::Log {
            level: LogLevel::Warn,
            message,
        });
    }

    fn claim_device(&mut self, device_id: &str) {
        let Some(discovery) = self.last_discovery.clone() else {
            self.emit(RecoveryEvent::ClaimRejected {
                device_id: device_id.to_string(),
                reason: "No recovery inventory is available yet".to_string(),
            });
            return;
        };
        let Some(entry) = discovery.devices.iter().find(|entry| entry.id == device_id) else {
            self.emit(RecoveryEvent::ClaimRejected {
                device_id: device_id.to_string(),
                reason: "The selected device is no longer in the recovery inventory".to_string(),
            });
            return;
        };
        if entry.state != crate::recovery_model::DeviceState::Available {
            self.emit(RecoveryEvent::ClaimRejected {
                device_id: device_id.to_string(),
                reason: "The selected device is not claimable right now".to_string(),
            });
            return;
        }

        self.cleanup_session(HostDetachDisposition::Cancelled);
        let reporter: crate::restore::SharedReporter =
            Arc::new(Mutex::new(UiReporter::new(self.event_tx.clone())));
        let claim = match self.backend.claim(&entry.id, reporter) {
            Ok(claim) => claim,
            Err(error) => {
                self.emit(RecoveryEvent::ClaimRejected {
                    device_id: device_id.to_string(),
                    reason: error,
                });
                return;
            }
        };
        let identified = match claim.identify() {
            Ok(device) => device,
            Err(error) => {
                let detach = claim.detach_host(HostDetachDisposition::Failed);
                self.try_emit(host_detach_log_event(HostDetachDisposition::Failed, detach));
                if should_abort_after_detach(detach) {
                    claim.abort();
                }
                self.emit(RecoveryEvent::ClaimRejected {
                    device_id: device_id.to_string(),
                    reason: error,
                });
                return;
            }
        };
        if let Some(class) = self
            .prepared
            .as_ref()
            .and_then(|prepared| prepared.selected_class.as_deref())
        {
            let model = identified.string("HardwareModel").unwrap_or("");
            if !model.eq_ignore_ascii_case(class) {
                let detach = claim.detach_host(HostDetachDisposition::Failed);
                self.try_emit(host_detach_log_event(HostDetachDisposition::Failed, detach));
                if should_abort_after_detach(detach) {
                    claim.abort();
                }
                self.emit(RecoveryEvent::ClaimRejected {
                    device_id: device_id.to_string(),
                    reason: format!("this Mac is {model}, the restore set is for {class}"),
                });
                return;
            }
        }
        let context = claim.context();
        self.session = Some(ClaimedSession::new(claim, context, identified));
        self.emit(RecoveryEvent::ClaimAccepted {
            device_id: device_id.to_string(),
            note: Some(
                self.session
                    .as_ref()
                    .and_then(|session| session.claim.detail().map(str::to_string))
                    .unwrap_or_else(|| "Exclusive claim accepted".to_string()),
            ),
        });
        if self.apply_prepared_to_session().is_err() {
            self.emit_manifest_request();
        }
        self.last_devices.clear();
        self.refresh_discovery();
    }

    fn apply_prepared_to_session(&mut self) -> Result<(), String> {
        let prepared = self
            .prepared
            .as_ref()
            .ok_or_else(|| "no prepared kit".to_string())?;
        if !prepared.accepted.contains_key(MANIFEST_REQUEST_ID) {
            return Err("manifest not prepared".into());
        }
        let root = prepared
            .manifest_root
            .clone()
            .ok_or_else(|| "prepared kit has no extract root".to_string())?;
        let prepared = self.prepared.take().expect("prepared");
        let device = self
            .session
            .as_ref()
            .map(|session| session.device.clone())
            .ok_or_else(|| "No claimed session is active".to_string())?;
        let manifest_path = root.join(BUILD_MANIFEST_FILE_NAME);
        let manifest_dict =
            load_build_manifest(&manifest_path).map_err(|error| error.to_string())?;
        let request_global_manifest = locate_global_manifest_source(&root)?.is_some();
        let derived = match derive_restore_options(
            &manifest_dict,
            &device,
            request_global_manifest,
            prepared.selected_behavior,
        ) {
            Ok(derived) => derived,
            Err(error) => {
                self.prepared = Some(prepared);
                return Err(error.detail());
            }
        };
        let session = self.session.as_mut().expect("session");
        session.accepted_files = prepared.accepted;
        session.pending_requests.clear();
        session.manifest_root = Some(root.clone());
        session.request_global_manifest = request_global_manifest;
        session.derived = Some(derived);
        session.selected_behavior = prepared.selected_behavior;

        self.collect_identity_payloads(&root)?;
        let _ = self.emit_pending_file_requests();
        Ok(())
    }

    fn provide_prepared_file(&mut self, request_id: &str, path: &str) {
        let path_buf = PathBuf::from(path);
        if path_buf.is_dir() {
            self.provide_prepared_directory(request_id, &path_buf);
            return;
        }
        let already = self
            .prepared
            .as_ref()
            .is_some_and(|prepared| prepared.accepted.contains_key(request_id));
        if already {
            self.emit(RecoveryEvent::FileAccepted {
                request_id: request_id.to_string(),
                note: Some("Already accepted".to_string()),
            });
            return;
        }
        let Some(pending) = self
            .prepared
            .as_ref()
            .and_then(|prepared| prepared.pending.get(request_id).cloned())
        else {
            self.emit(RecoveryEvent::FileRejected {
                request_id: request_id.to_string(),
                reason: "That file request is no longer active".to_string(),
                keep_claim: true,
            });
            return;
        };
        let path = PathBuf::from(path);
        let event_tx = self.event_tx.clone();
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file")
            .to_string();
        match validate_pending_request_reported(&pending, &path, |done, total| {
            let fraction = if total == 0 {
                None
            } else {
                Some(done as f64 / total as f64)
            };
            let _ = event_tx.try_send(RecoveryEvent::Progress(RestoreProgress {
                stage: "checking".into(),
                detail: file_name.clone(),
                fraction,
            }));
        }) {
            Ok(validated) => {
                if let Some(prepared) = self.prepared.as_mut() {
                    prepared.pending.remove(request_id);
                    prepared.accepted.insert(
                        request_id.to_string(),
                        AcceptedFile {
                            source: validated.source.clone(),
                            overlay_relative: pending.overlay_relative,
                            expected_hash: validated.content_hash,
                            source_root: pending.source_root,
                        },
                    );
                }
                self.emit(RecoveryEvent::FileAccepted {
                    request_id: request_id.to_string(),
                    note: Some(format!(
                        "{} accepted ({} bytes)",
                        path.file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("file"),
                        validated.metadata.len()
                    )),
                });
                if request_id == MANIFEST_REQUEST_ID {
                    if let Err(error) = self.prepare_from_manifest(&path) {
                        self.emit(RecoveryEvent::FileRejected {
                            request_id: MANIFEST_REQUEST_ID.to_string(),
                            reason: error,
                            keep_claim: true,
                        });
                        self.prepared = None;
                        self.open_manifest_request();
                    }
                } else if let Some(parent) = path.parent() {
                    self.scan_prepared_pending_from(parent);
                    self.scan_prepared_extract_roots();
                }
            }
            Err(error) => {
                self.reject_and_reask(request_id, pending.spec, error);
            }
        }
    }

    fn provide_prepared_directory(&mut self, request_id: &str, dir: &Path) {
        let dir = match fs::canonicalize(dir) {
            Ok(dir) if dir.is_dir() => dir,
            Ok(dir) => {
                self.emit(RecoveryEvent::FileRejected {
                    request_id: request_id.to_string(),
                    reason: format!("{} is not a folder", dir.display()),
                    keep_claim: true,
                });
                return;
            }
            Err(error) => {
                self.emit(RecoveryEvent::FileRejected {
                    request_id: request_id.to_string(),
                    reason: format!("Could not read folder: {error}"),
                    keep_claim: true,
                });
                return;
            }
        };
        self.emit(RecoveryEvent::Progress(RestoreProgress {
            stage: "scanning".into(),
            detail: dir
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("folder")
                .to_string(),
            fraction: None,
        }));
        let catalog_pending = self
            .prepared
            .as_ref()
            .is_some_and(|prepared| prepared.pending.contains_key(MANIFEST_REQUEST_ID));
        if catalog_pending {
            if let Some(spec) = self.prepared.as_ref().and_then(|prepared| {
                prepared
                    .pending
                    .get(MANIFEST_REQUEST_ID)
                    .map(|pending| pending.spec.clone())
            }) && let Some(dir_info) = inspect(&dir.to_string_lossy())
                && let Ok(resolved) = resolve_handoff(&dir_info, &spec)
            {
                self.provide_prepared_file(MANIFEST_REQUEST_ID, &resolved.path.to_string_lossy());
                return;
            }
            if request_id == MANIFEST_REQUEST_ID {
                if let Some(spec) = self.prepared.as_ref().and_then(|prepared| {
                    prepared
                        .pending
                        .get(MANIFEST_REQUEST_ID)
                        .map(|pending| pending.spec.clone())
                }) {
                    self.reject_and_reask(
                        MANIFEST_REQUEST_ID,
                        spec,
                        format!(
                            "Folder {} does not contain BuildManifest.plist or Restore.plist",
                            dir.display()
                        ),
                    );
                }
                return;
            }
        }
        let found = self.scan_prepared_pending_from(&dir);
        if found == 0 {
            let remaining = self.prepared_remaining_titles();
            if let Some(spec) = self.prepared.as_ref().and_then(|prepared| {
                prepared
                    .pending
                    .get(request_id)
                    .map(|pending| pending.spec.clone())
            }) {
                let hint = if remaining.is_empty() {
                    spec.expectation_label()
                } else {
                    remaining
                };
                self.reject_and_reask(
                    request_id,
                    spec,
                    format!("Folder {} does not contain {hint}", dir.display()),
                );
            }
        }
    }

    fn prepared_remaining_titles(&self) -> String {
        self.prepared
            .as_ref()
            .map(|prepared| {
                prepared
                    .pending
                    .values()
                    .map(|pending| pending.spec.title().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default()
    }

    fn scan_prepared_pending_from(&mut self, dir: &Path) -> usize {
        let Some(dir_info) = inspect(&dir.to_string_lossy()) else {
            return 0;
        };
        if dir_info.kind != FileKind::Directory {
            return 0;
        }
        let Some(prepared) = self.prepared.as_ref() else {
            return 0;
        };
        let pending_ids = prepared.pending.keys().cloned().collect::<Vec<_>>();
        let event_tx = self.event_tx.clone();
        let total = pending_ids.len().max(1);
        let mut found = 0;
        for (index, request_id) in pending_ids.into_iter().enumerate() {
            let Some(pending) = self
                .prepared
                .as_ref()
                .and_then(|prepared| prepared.pending.get(&request_id).cloned())
            else {
                continue;
            };
            let Ok(candidates) = resolve_handoff_candidates(&dir_info, &pending.spec) else {
                continue;
            };
            for resolved in candidates {
                if let Some(existing) = self.prepared.as_ref().and_then(|prepared| {
                    prepared
                        .accepted
                        .values()
                        .find(|file| file.source == resolved.path)
                        .cloned()
                }) {
                    if let Some(prepared) = self.prepared.as_mut() {
                        prepared.pending.remove(&request_id);
                        prepared.accepted.insert(
                            request_id.clone(),
                            AcceptedFile {
                                source: existing.source,
                                overlay_relative: pending.overlay_relative.clone(),
                                expected_hash: existing.expected_hash,
                                source_root: existing
                                    .source_root
                                    .or_else(|| Some(dir.to_path_buf())),
                            },
                        );
                    }
                    found += 1;
                    self.emit(RecoveryEvent::FileAccepted {
                        request_id: request_id.clone(),
                        note: Some(format!("{} accepted from {}", resolved.name, dir_info.name)),
                    });
                    break;
                }
                let file_name = resolved.name.clone();
                match validate_pending_request_reported(
                    &pending,
                    &resolved.path,
                    |done, total_bytes| {
                        let fraction = if total_bytes == 0 {
                            Some((index as f64 + 1.0) / total as f64)
                        } else {
                            Some((index as f64 + done as f64 / total_bytes as f64) / total as f64)
                        };
                        let _ = event_tx.try_send(RecoveryEvent::Progress(RestoreProgress {
                            stage: "scanning".into(),
                            detail: file_name.clone(),
                            fraction,
                        }));
                    },
                ) {
                    Ok(validated) => {
                        if let Some(prepared) = self.prepared.as_mut() {
                            prepared.pending.remove(&request_id);
                            prepared.accepted.insert(
                                request_id.clone(),
                                AcceptedFile {
                                    source: validated.source.clone(),
                                    overlay_relative: pending.overlay_relative.clone(),
                                    expected_hash: validated.content_hash,
                                    source_root: pending
                                        .source_root
                                        .clone()
                                        .or_else(|| Some(dir.to_path_buf())),
                                },
                            );
                        }
                        found += 1;
                        self.emit(RecoveryEvent::FileAccepted {
                            request_id: request_id.clone(),
                            note: Some(format!(
                                "{} accepted from {} ({} bytes)",
                                resolved.name,
                                dir_info.name,
                                validated.metadata.len()
                            )),
                        });
                        if request_id == MANIFEST_REQUEST_ID {
                            if let Err(error) = self.prepare_from_manifest(&resolved.path) {
                                self.emit(RecoveryEvent::FileRejected {
                                    request_id: MANIFEST_REQUEST_ID.to_string(),
                                    reason: error,
                                    keep_claim: true,
                                });
                                self.prepared = None;
                                self.open_manifest_request();
                            }
                            return found;
                        }
                        break;
                    }
                    Err(error) => {
                        self.emit(RecoveryEvent::Log {
                            level: LogLevel::Warn,
                            message: format!("Skipping {}: {error}", resolved.name),
                        });
                    }
                }
            }
        }
        found
    }

    fn scan_prepared_extract_roots(&mut self) -> usize {
        let Some(root) = self
            .prepared
            .as_ref()
            .and_then(|prepared| prepared.manifest_root.clone())
        else {
            return 0;
        };
        let mut found = self.scan_prepared_pending_from(&root);
        if let Ok(Some(firmware)) = locate_firmware_source(&root) {
            found += self.scan_prepared_pending_from(&firmware);
        }
        found
    }

    fn autosearch(&mut self, device_id: &str, path: &str) {
        if self.session.is_some() {
            if !device_id.is_empty()
                && self
                    .session
                    .as_ref()
                    .is_some_and(|session| session.claim.device_id() != device_id)
            {
                return;
            }
            self.autosearch_session(path);
            return;
        }
        self.autosearch_prepared(path);
    }

    fn autosearch_prepared(&mut self, path: &str) {
        let dir = match fs::canonicalize(path) {
            Ok(dir) if dir.is_dir() => dir,
            Ok(dir) => {
                self.autosearch_reject(&format!("{} is not a folder", dir.display()));
                return;
            }
            Err(error) => {
                self.autosearch_reject(&format!("Could not read folder: {error}"));
                return;
            }
        };
        if self
            .prepared
            .as_ref()
            .is_some_and(|prepared| prepared.pending.is_empty())
        {
            return;
        }
        self.emit(RecoveryEvent::Progress(RestoreProgress {
            stage: "scanning".into(),
            detail: dir
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("folder")
                .to_string(),
            fraction: Some(0.0),
        }));
        let roots = autosearch_from(&dir);
        let total = roots.len().max(1);
        let mut found = 0;
        for (index, root) in roots.iter().enumerate() {
            self.emit(RecoveryEvent::Progress(RestoreProgress {
                stage: "scanning".into(),
                detail: root
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("folder")
                    .to_string(),
                fraction: Some((index as f64 + 1.0) / total as f64),
            }));
            found += self.scan_prepared_pending_from(root);
            if self
                .prepared
                .as_ref()
                .is_some_and(|prepared| prepared.pending.is_empty())
            {
                break;
            }
        }
        let remaining = self.prepared_remaining_titles();
        if remaining.is_empty() {
            self.emit(RecoveryEvent::Log {
                level: LogLevel::Info,
                message: format!("Autosearch found {found} file(s) under {}", dir.display()),
            });
            return;
        }
        self.autosearch_reject(&autosearch_remaining_reason(&dir, found, &remaining));
    }

    fn autosearch_session(&mut self, path: &str) {
        let dir = match fs::canonicalize(path) {
            Ok(dir) if dir.is_dir() => dir,
            Ok(dir) => {
                self.autosearch_reject(&format!("{} is not a folder", dir.display()));
                return;
            }
            Err(error) => {
                self.autosearch_reject(&format!("Could not read folder: {error}"));
                return;
            }
        };
        if self
            .session
            .as_ref()
            .is_some_and(|session| session.pending_requests.is_empty())
        {
            return;
        }
        self.emit(RecoveryEvent::Progress(RestoreProgress {
            stage: "scanning".into(),
            detail: dir
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("folder")
                .to_string(),
            fraction: Some(0.0),
        }));
        let roots = autosearch_from(&dir);
        let total = roots.len().max(1);
        let mut found = 0;
        for (index, root) in roots.iter().enumerate() {
            self.emit(RecoveryEvent::Progress(RestoreProgress {
                stage: "scanning".into(),
                detail: root
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("folder")
                    .to_string(),
                fraction: Some((index as f64 + 1.0) / total as f64),
            }));
            found += self.scan_session_pending_from(root);
            if self
                .session
                .as_ref()
                .is_some_and(|session| session.pending_requests.is_empty())
            {
                break;
            }
        }
        self.try_fill_pending_from(&roots);
        let remaining = self
            .session
            .as_ref()
            .map(|session| {
                session
                    .pending_requests
                    .values()
                    .map(|pending| pending.spec.title().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        if remaining.is_empty() {
            self.emit(RecoveryEvent::Log {
                level: LogLevel::Info,
                message: format!("Autosearch found {found} file(s) under {}", dir.display()),
            });
            return;
        }
        self.autosearch_reject(&autosearch_remaining_reason(&dir, found, &remaining));
    }

    fn autosearch_reject(&mut self, reason: &str) {
        let spec = self
            .prepared
            .as_ref()
            .and_then(|prepared| {
                prepared
                    .pending
                    .values()
                    .next()
                    .map(|pending| pending.spec.clone())
            })
            .or_else(|| {
                self.session.as_ref().and_then(|session| {
                    session
                        .pending_requests
                        .values()
                        .next()
                        .map(|pending| pending.spec.clone())
                })
            });
        let Some(spec) = spec else {
            self.emit(RecoveryEvent::Log {
                level: LogLevel::Warn,
                message: reason.to_string(),
            });
            return;
        };
        let request_id = spec.request_id.clone();
        self.reject_and_reask(&request_id, spec, reason.to_string());
    }

    fn reject_and_reask(&mut self, request_id: &str, spec: FileRequestSpec, reason: String) {
        self.emit(RecoveryEvent::FileRejected {
            request_id: request_id.to_string(),
            reason,
            keep_claim: true,
        });
        self.emit(RecoveryEvent::FileRequested(spec));
    }

    fn prepare_from_manifest(&mut self, selected_path: &Path) -> Result<(), String> {
        let root = selected_path
            .parent()
            .ok_or_else(|| "The restore catalog has no parent directory".to_string())?;
        let root = fs::canonicalize(root)
            .map_err(|error| format!("Could not resolve the extracted restore root: {error}"))?;
        let build_manifest = root.join(BUILD_MANIFEST_FILE_NAME);
        if !build_manifest.is_file() {
            return Err(format!(
                "{RESTORE_PLIST_FILE_NAME} needs {BUILD_MANIFEST_FILE_NAME} in the same folder"
            ));
        }
        let selected_is_restore = selected_path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case(RESTORE_PLIST_FILE_NAME));
        if let Some(prepared) = self.prepared.as_mut()
            && let Some(accepted) = prepared.accepted.get_mut(MANIFEST_REQUEST_ID)
        {
            accepted.source = build_manifest.clone();
            accepted.overlay_relative = PathBuf::from(BUILD_MANIFEST_FILE_NAME);
            accepted.source_root = Some(root.clone());
            if selected_is_restore {
                accepted.expected_hash = None;
            }
        }
        self.emit(RecoveryEvent::Progress(RestoreProgress {
            stage: "reading".into(),
            detail: BUILD_MANIFEST_FILE_NAME.to_string(),
            fraction: None,
        }));
        let dict = load_build_manifest(&build_manifest).map_err(|error| error.to_string())?;
        let classes = crate::ramrod::installable_device_classes(&dict);
        if classes.is_empty() {
            return Err("BuildManifest.plist carries no build identities".into());
        }
        let catalog = load_restore_catalog(&root);
        let systems = compatible_systems_from(classes, catalog.as_ref());
        if systems.is_empty() {
            return Err("this restore set names no devices".into());
        }
        let (product_version, product_build) = catalog
            .as_ref()
            .map(|catalog| {
                (
                    catalog.product_version.clone(),
                    catalog.product_build.clone(),
                )
            })
            .unwrap_or_else(|| product_version_from_manifest(&dict));
        let mut accepted = HashMap::new();
        if let Some(prepared) = self.prepared.as_ref() {
            accepted.extend(
                prepared
                    .accepted
                    .iter()
                    .filter(|(request_id, _)| request_id.as_str() == MANIFEST_REQUEST_ID)
                    .map(|(request_id, file)| (request_id.clone(), file.clone())),
            );
        }
        self.prepared = Some(PreparedRestore {
            pending: BTreeMap::new(),
            accepted,
            manifest_root: Some(root),
            selected_class: None,
            selected_behavior: None,
        });
        self.emit(RecoveryEvent::CompatibleBoards {
            systems,
            product_version,
            product_build,
        });
        Ok(())
    }

    fn select_system(&mut self, device_class: &str) {
        if let Err(error) = self.offer_or_collect_for_class(device_class) {
            self.emit(RecoveryEvent::FileRejected {
                request_id: MANIFEST_REQUEST_ID.to_string(),
                reason: error,
                keep_claim: true,
            });
        }
    }

    fn select_restore_mode(&mut self, mode: RestoreMode) {
        let Some(class) = self
            .prepared
            .as_ref()
            .and_then(|prepared| prepared.selected_class.clone())
        else {
            self.emit(RecoveryEvent::FileRejected {
                request_id: MANIFEST_REQUEST_ID.to_string(),
                reason: "Choose a Mac before choosing erase or upgrade".to_string(),
                keep_claim: true,
            });
            return;
        };
        if let Err(error) = self.collect_prepared_for_class(&class, behavior_from_mode(mode)) {
            self.emit(RecoveryEvent::FileRejected {
                request_id: MANIFEST_REQUEST_ID.to_string(),
                reason: error,
                keep_claim: true,
            });
        }
    }

    fn offer_or_collect_for_class(&mut self, device_class: &str) -> Result<(), String> {
        let prepared = self
            .prepared
            .as_ref()
            .ok_or_else(|| "BuildManifest.plist has not been accepted yet".to_string())?;
        let root = prepared
            .manifest_root
            .clone()
            .ok_or_else(|| "The extracted restore root is not known yet".to_string())?;
        let dict = load_build_manifest(&root.join(BUILD_MANIFEST_FILE_NAME))
            .map_err(|error| error.to_string())?;
        let behaviors = install_behaviors_for_board(&dict, device_class);
        if behaviors.is_empty() {
            return Err(format!(
                "BuildManifest.plist has no install identity for {device_class}"
            ));
        }
        if behaviors.len() > 1 {
            if let Some(prepared) = self.prepared.as_mut() {
                prepared.selected_class = Some(device_class.to_string());
                prepared.selected_behavior = None;
                prepared.pending.clear();
            }
            self.emit(RecoveryEvent::SystemSelected {
                class: device_class.to_string(),
            });
            self.emit(RecoveryEvent::CompatibleModes {
                modes: behaviors.into_iter().map(mode_from_behavior).collect(),
            });
            return Ok(());
        }
        self.collect_prepared_for_class(device_class, behaviors[0])
    }

    fn collect_prepared_for_class(
        &mut self,
        device_class: &str,
        behavior: RestoreBehavior,
    ) -> Result<(), String> {
        let prepared = self
            .prepared
            .as_ref()
            .ok_or_else(|| "BuildManifest.plist has not been accepted yet".to_string())?;
        let root = prepared
            .manifest_root
            .clone()
            .ok_or_else(|| "The extracted restore root is not known yet".to_string())?;
        let dict = load_build_manifest(&root.join(BUILD_MANIFEST_FILE_NAME))
            .map_err(|error| error.to_string())?;
        let identities = identities_for_board(&dict, device_class, behavior)?;
        let mut accepted = HashMap::new();
        if let Some(manifest) = prepared.accepted.get(MANIFEST_REQUEST_ID) {
            accepted.insert(MANIFEST_REQUEST_ID.to_string(), manifest.clone());
        }
        let mut pending = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for identity in &identities {
            for name in identity_component_names(identity) {
                let request_id = component_request_id(&name);
                if !seen.insert(request_id.clone()) {
                    continue;
                }
                if accepted.contains_key(&request_id) {
                    continue;
                }
                match resolve_identity_component(&root, identity, &name) {
                    Ok(ComponentResolution::Present {
                        source,
                        relative,
                        expected_hash,
                    }) => {
                        accepted.insert(
                            request_id,
                            AcceptedFile {
                                source,
                                overlay_relative: relative,
                                expected_hash,
                                source_root: Some(root.clone()),
                            },
                        );
                    }
                    Ok(ComponentResolution::Missing {
                        spec,
                        relative,
                        expected_hash,
                        manifest_file_name,
                    }) => {
                        pending.insert(
                            request_id,
                            PendingRequest {
                                spec,
                                overlay_relative: relative,
                                expected_hash,
                                source_root: None,
                                component: name,
                                manifest_file_name,
                            },
                        );
                    }
                    Err(error) => {
                        self.emit(RecoveryEvent::Log {
                            level: LogLevel::Warn,
                            message: format!(
                                "{name} was not in the extract tree ({error}); it will be asked for"
                            ),
                        });
                        pending.insert(
                            request_id,
                            pending_request_for_unresolved_component(&name, &error),
                        );
                    }
                }
            }
        }
        let pending_specs = pending
            .values()
            .map(|pending| pending.spec.clone())
            .collect::<Vec<_>>();
        self.prepared = Some(PreparedRestore {
            pending,
            accepted,
            manifest_root: Some(root),
            selected_class: Some(device_class.to_string()),
            selected_behavior: Some(behavior),
        });
        if let Some(session) = self.session.as_mut() {
            session.selected_behavior = Some(behavior);
        }
        self.emit(RecoveryEvent::SystemSelected {
            class: device_class.to_string(),
        });
        self.emit(RecoveryEvent::ModeSelected {
            mode: mode_from_behavior(behavior),
        });
        for spec in pending_specs {
            self.emit(RecoveryEvent::FileRequested(spec));
        }
        Ok(())
    }

    fn emit_manifest_request(&mut self) {
        let Some(session) = &mut self.session else {
            return;
        };
        session.reset_for_manifest_request();
        self.emit(RecoveryEvent::FileRequested(manifest_request_spec()));
    }

    fn open_manifest_request(&mut self) {
        if self.prepared.is_some() || self.session.is_some() {
            return;
        }
        let spec = manifest_request_spec();
        let mut pending = BTreeMap::new();
        pending.insert(
            MANIFEST_REQUEST_ID.to_string(),
            PendingRequest {
                spec: spec.clone(),
                overlay_relative: PathBuf::from(BUILD_MANIFEST_FILE_NAME),
                expected_hash: None,
                source_root: None,
                component: BUILD_MANIFEST_FILE_NAME.to_string(),
                manifest_file_name: BUILD_MANIFEST_FILE_NAME.to_string(),
            },
        );
        self.prepared = Some(PreparedRestore {
            pending,
            accepted: HashMap::new(),
            manifest_root: None,
            selected_class: None,
            selected_behavior: None,
        });
        self.emit(RecoveryEvent::FileRequested(spec));
    }

    fn release_device(&mut self, device_id: &str) {
        let event_tx = self.event_tx.clone();
        let Some(session) = &mut self.session else {
            return;
        };
        if session.claim.device_id() != device_id {
            return;
        }
        if let Some(run) = &mut session.restore_run {
            run.stop.store(true, Ordering::Relaxed);
            run.release_after = true;
            run.cancel_requested = true;
            detach_session(&event_tx, session, HostDetachDisposition::Cancelled);
            self.emit(RecoveryEvent::PhaseChanged {
                phase: SessionPhase::Cancelling,
                note: Some("Release requested, stopping restore".to_string()),
            });
            return;
        }
        self.cleanup_session(HostDetachDisposition::Cancelled);
        self.emit(RecoveryEvent::Released {
            device_id: device_id.to_string(),
            note: Some("Claim released".to_string()),
        });
    }

    fn provide_file(&mut self, device_id: &str, request_id: &str, path: &str) {
        if self.session.is_none() {
            self.provide_prepared_file(request_id, path);
            return;
        }
        let path_buf = PathBuf::from(path);
        if path_buf.is_dir() {
            self.provide_session_directory(request_id, &path_buf);
            return;
        }
        let Some(session) = &mut self.session else {
            return;
        };
        if !device_id.is_empty() && session.claim.device_id() != device_id {
            return;
        }
        if session.accepted_files.contains_key(request_id) {
            self.emit(RecoveryEvent::FileAccepted {
                request_id: request_id.to_string(),
                note: Some("Already accepted".to_string()),
            });
            return;
        }
        let Some(pending) = session.pending_requests.get(request_id).cloned() else {
            self.emit(RecoveryEvent::FileRejected {
                request_id: request_id.to_string(),
                reason: "That file request is no longer active".to_string(),
                keep_claim: true,
            });
            return;
        };
        let path = PathBuf::from(path);
        let event_tx = self.event_tx.clone();
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file")
            .to_string();
        match validate_pending_request_reported(&pending, &path, |done, total| {
            let fraction = if total == 0 {
                None
            } else {
                Some(done as f64 / total as f64)
            };
            let _ = event_tx.try_send(RecoveryEvent::Progress(RestoreProgress {
                stage: "checking".into(),
                detail: file_name.clone(),
                fraction,
            }));
        }) {
            Ok(validated) => {
                session.pending_requests.remove(request_id);
                session.accepted_files.insert(
                    request_id.to_string(),
                    AcceptedFile {
                        source: validated.source,
                        overlay_relative: pending.overlay_relative,
                        expected_hash: validated.content_hash,
                        source_root: pending.source_root,
                    },
                );
                self.emit(RecoveryEvent::FileAccepted {
                    request_id: request_id.to_string(),
                    note: Some(format!(
                        "{} accepted ({} bytes)",
                        path.file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("file"),
                        validated.metadata.len()
                    )),
                });
                if request_id == MANIFEST_REQUEST_ID {
                    if let Err(error) = self.derive_manifest_assets() {
                        if let Some(session) = &mut self.session {
                            session.accepted_files.remove(MANIFEST_REQUEST_ID);
                        }
                        self.emit(RecoveryEvent::FileRejected {
                            request_id: MANIFEST_REQUEST_ID.to_string(),
                            reason: error,
                            keep_claim: true,
                        });
                        self.emit_manifest_request();
                    }
                } else {
                    let mut roots = Vec::new();
                    if let Some(parent) = path.parent() {
                        self.scan_session_pending_from(parent);
                        self.scan_session_extract_roots();
                        roots.push(parent.to_path_buf());
                    }
                    if let Some(root) = self
                        .session
                        .as_ref()
                        .and_then(|session| session.manifest_root.clone())
                    {
                        roots.push(root);
                    }
                    self.try_fill_pending_from(&roots);
                }
            }
            Err(error) => {
                self.reject_and_reask(request_id, pending.spec, error);
            }
        }
    }

    fn provide_session_directory(&mut self, request_id: &str, dir: &Path) {
        let dir = match fs::canonicalize(dir) {
            Ok(dir) if dir.is_dir() => dir,
            Ok(dir) => {
                self.emit(RecoveryEvent::FileRejected {
                    request_id: request_id.to_string(),
                    reason: format!("{} is not a folder", dir.display()),
                    keep_claim: true,
                });
                return;
            }
            Err(error) => {
                self.emit(RecoveryEvent::FileRejected {
                    request_id: request_id.to_string(),
                    reason: format!("Could not read folder: {error}"),
                    keep_claim: true,
                });
                return;
            }
        };
        self.emit(RecoveryEvent::Progress(RestoreProgress {
            stage: "scanning".into(),
            detail: dir
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("folder")
                .to_string(),
            fraction: None,
        }));
        let found = self.scan_session_pending_from(&dir);
        self.try_fill_pending_from(std::slice::from_ref(&dir));
        let still_pending = self
            .session
            .as_ref()
            .is_some_and(|session| session.pending_requests.contains_key(request_id));
        if found == 0
            && still_pending
            && let Some(spec) = self.session.as_ref().and_then(|session| {
                session
                    .pending_requests
                    .get(request_id)
                    .map(|pending| pending.spec.clone())
            })
        {
            let remaining = self
                .session
                .as_ref()
                .map(|session| {
                    session
                        .pending_requests
                        .values()
                        .map(|pending| pending.spec.title().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|| spec.expectation_label());
            self.reject_and_reask(
                request_id,
                spec,
                format!("Folder {} does not contain {remaining}", dir.display()),
            );
        }
    }

    fn scan_session_pending_from(&mut self, dir: &Path) -> usize {
        let Some(dir_info) = inspect(&dir.to_string_lossy()) else {
            return 0;
        };
        if dir_info.kind != FileKind::Directory {
            return 0;
        }
        let Some(session) = self.session.as_ref() else {
            return 0;
        };
        let pending_ids = session.pending_requests.keys().cloned().collect::<Vec<_>>();
        let event_tx = self.event_tx.clone();
        let total = pending_ids.len().max(1);
        let mut found = 0;
        for (index, request_id) in pending_ids.into_iter().enumerate() {
            let Some(pending) = self
                .session
                .as_ref()
                .and_then(|session| session.pending_requests.get(&request_id).cloned())
            else {
                continue;
            };
            let Ok(candidates) = resolve_handoff_candidates(&dir_info, &pending.spec) else {
                continue;
            };
            for resolved in candidates {
                if let Some(existing) = self.session.as_ref().and_then(|session| {
                    session
                        .accepted_files
                        .values()
                        .find(|file| file.source == resolved.path)
                        .cloned()
                }) {
                    if let Some(session) = self.session.as_mut() {
                        session.pending_requests.remove(&request_id);
                        session.accepted_files.insert(
                            request_id.clone(),
                            AcceptedFile {
                                source: existing.source,
                                overlay_relative: pending.overlay_relative.clone(),
                                expected_hash: existing.expected_hash,
                                source_root: existing
                                    .source_root
                                    .or_else(|| Some(dir.to_path_buf())),
                            },
                        );
                    }
                    found += 1;
                    self.emit(RecoveryEvent::FileAccepted {
                        request_id: request_id.clone(),
                        note: Some(format!("{} accepted from {}", resolved.name, dir_info.name)),
                    });
                    break;
                }
                let file_name = resolved.name.clone();
                match validate_pending_request_reported(
                    &pending,
                    &resolved.path,
                    |done, total_bytes| {
                        let fraction = if total_bytes == 0 {
                            Some((index as f64 + 1.0) / total as f64)
                        } else {
                            Some((index as f64 + done as f64 / total_bytes as f64) / total as f64)
                        };
                        let _ = event_tx.try_send(RecoveryEvent::Progress(RestoreProgress {
                            stage: "scanning".into(),
                            detail: file_name.clone(),
                            fraction,
                        }));
                    },
                ) {
                    Ok(validated) => {
                        if let Some(session) = self.session.as_mut() {
                            session.pending_requests.remove(&request_id);
                            session.accepted_files.insert(
                                request_id.clone(),
                                AcceptedFile {
                                    source: validated.source.clone(),
                                    overlay_relative: pending.overlay_relative.clone(),
                                    expected_hash: validated.content_hash,
                                    source_root: pending
                                        .source_root
                                        .clone()
                                        .or_else(|| Some(dir.to_path_buf())),
                                },
                            );
                        }
                        found += 1;
                        self.emit(RecoveryEvent::FileAccepted {
                            request_id: request_id.clone(),
                            note: Some(format!(
                                "{} accepted from {} ({} bytes)",
                                resolved.name,
                                dir_info.name,
                                validated.metadata.len()
                            )),
                        });
                        break;
                    }
                    Err(error) => {
                        self.emit(RecoveryEvent::Log {
                            level: LogLevel::Warn,
                            message: format!("Skipping {}: {error}", resolved.name),
                        });
                    }
                }
            }
        }
        found
    }

    fn scan_session_extract_roots(&mut self) -> usize {
        let Some(root) = self
            .session
            .as_ref()
            .and_then(|session| session.manifest_root.clone())
        else {
            return 0;
        };
        let mut found = self.scan_session_pending_from(&root);
        let firmware = root.join("Firmware");
        if firmware.is_dir() {
            found += self.scan_session_pending_from(&firmware);
        }
        found
    }

    fn recollect_missing_identity_payloads(&mut self) {
        let Some(session) = self.session.as_ref() else {
            return;
        };
        let Some(root) = session.manifest_root.clone() else {
            return;
        };
        let Some(derived) = session.derived.clone() else {
            return;
        };
        let identities = identity_payload_sources(&derived)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let mut seen = session
            .accepted_files
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        seen.extend(session.pending_requests.keys().cloned());
        let mut missing = Vec::new();
        for identity in &identities {
            for name in identity_component_names(identity) {
                let request_id = component_request_id(&name);
                if !seen.insert(request_id.clone()) {
                    continue;
                }
                match resolve_identity_component(&root, identity, &name) {
                    Ok(ComponentResolution::Present {
                        source,
                        relative,
                        expected_hash,
                    }) => {
                        if let Some(session) = self.session.as_mut() {
                            session.accepted_files.insert(
                                request_id,
                                AcceptedFile {
                                    source,
                                    overlay_relative: relative,
                                    expected_hash,
                                    source_root: Some(root.clone()),
                                },
                            );
                        }
                    }
                    Ok(ComponentResolution::Missing {
                        spec,
                        relative,
                        expected_hash,
                        manifest_file_name,
                    }) => {
                        missing.push((
                            request_id,
                            PendingRequest {
                                spec,
                                overlay_relative: relative,
                                expected_hash,
                                source_root: None,
                                component: name,
                                manifest_file_name,
                            },
                        ));
                    }
                    Err(error) => {
                        missing.push((
                            request_id,
                            pending_request_for_unresolved_component(&name, &error),
                        ));
                    }
                }
            }
        }
        if let Some(session) = self.session.as_mut() {
            for (request_id, pending) in missing {
                session.pending_requests.insert(request_id, pending);
            }
        }
    }

    fn derive_manifest_assets(&mut self) -> Result<(), String> {
        let event_tx = self.event_tx.clone();
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| "No claimed session is active".to_string())?;
        let manifest = session
            .accepted_files
            .get(MANIFEST_REQUEST_ID)
            .cloned()
            .ok_or_else(|| "BuildManifest.plist has not been accepted yet".to_string())?;
        let manifest_parent = manifest
            .source
            .parent()
            .ok_or_else(|| "BuildManifest.plist has no parent directory".to_string())?;
        let manifest_root = fs::canonicalize(manifest_parent)
            .map_err(|error| format!("Could not resolve the extracted IPSW root: {error}"))?;
        let manifest_path = manifest_root.join(BUILD_MANIFEST_FILE_NAME);
        validate_regular_source(&manifest_path, Some(&manifest_root))?;
        let manifest_dict =
            load_build_manifest(&manifest_path).map_err(|error| error.to_string())?;
        let request_global_manifest = locate_global_manifest_source(&manifest_root)?.is_some();
        let behavior = self
            .prepared
            .as_ref()
            .and_then(|prepared| prepared.selected_behavior);
        let derived = derive_restore_options(
            &manifest_dict,
            &session.device,
            request_global_manifest,
            behavior,
        )
        .map_err(|error| error.detail())?;

        for request_id in session
            .pending_requests
            .keys()
            .filter(|request_id| request_id.as_str() != MANIFEST_REQUEST_ID)
            .cloned()
            .collect::<Vec<_>>()
        {
            let _ = event_tx.send(RecoveryEvent::FileRequestCleared {
                request_id: request_id.clone(),
                note: Some("Manifest changed, reopening derived request".to_string()),
            });
            session.pending_requests.remove(&request_id);
        }
        session
            .accepted_files
            .retain(|request_id, _| request_id == MANIFEST_REQUEST_ID);
        session.manifest_root = Some(manifest_root.clone());
        session.request_global_manifest = request_global_manifest;
        session.derived = Some(derived);
        session.selected_behavior = behavior;
        if let Some(accepted_manifest) = session.accepted_files.get_mut(MANIFEST_REQUEST_ID) {
            accepted_manifest.source_root = Some(manifest_root.clone());
        }

        self.collect_identity_payloads(&manifest_root)?;
        Ok(())
    }

    fn collect_identity_payloads(&mut self, manifest_root: &Path) -> Result<(), String> {
        let event_tx = self.event_tx.clone();
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| "No claimed session is active".to_string())?;
        let derived = session
            .derived
            .clone()
            .ok_or_else(|| "Restore identities have not been derived yet".to_string())?;
        let identities = identity_payload_sources(&derived);
        let mut seen = std::collections::BTreeSet::new();
        let mut missing = Vec::new();
        for identity in identities {
            let names = identity_component_names(identity);
            for name in names {
                let request_id = component_request_id(&name);
                if !seen.insert(request_id.clone()) {
                    continue;
                }
                if session.accepted_files.contains_key(&request_id) {
                    continue;
                }
                match resolve_identity_component(manifest_root, identity, &name) {
                    Ok(ComponentResolution::Present {
                        source,
                        relative,
                        expected_hash,
                    }) => {
                        session.accepted_files.insert(
                            request_id,
                            AcceptedFile {
                                source,
                                overlay_relative: relative,
                                expected_hash,
                                source_root: Some(manifest_root.to_path_buf()),
                            },
                        );
                    }
                    Ok(ComponentResolution::Missing {
                        spec,
                        relative,
                        expected_hash,
                        manifest_file_name,
                    }) => {
                        missing.push((
                            request_id,
                            PendingRequest {
                                spec,
                                overlay_relative: relative,
                                expected_hash,
                                source_root: None,
                                component: name,
                                manifest_file_name,
                            },
                        ));
                    }
                    Err(error) => {
                        missing.push((
                            request_id,
                            pending_request_for_unresolved_component(&name, &error),
                        ));
                    }
                }
            }
        }
        for (request_id, pending) in missing {
            let spec = pending.spec.clone();
            session.pending_requests.insert(request_id, pending);
            let _ = event_tx.send(RecoveryEvent::FileRequested(spec));
        }
        Ok(())
    }

    fn try_fill_pending_from(&mut self, roots: &[PathBuf]) {
        let event_tx = self.event_tx.clone();
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let Some(derived) = session.derived.clone() else {
            return;
        };
        let pending_ids = session.pending_requests.keys().cloned().collect::<Vec<_>>();
        for request_id in pending_ids {
            let Some(pending) = session.pending_requests.get(&request_id).cloned() else {
                continue;
            };
            let identity = identity_payload_sources(&derived)
                .into_iter()
                .find(|identity| {
                    identity_component_names(identity)
                        .iter()
                        .any(|name| name == &pending.component)
                });
            let Some(identity) = identity else {
                continue;
            };
            for root in roots {
                if !root.is_dir() {
                    continue;
                }
                let Ok(resolved) = resolve_identity_component(root, identity, &pending.component)
                else {
                    continue;
                };
                if let ComponentResolution::Present {
                    source,
                    relative,
                    expected_hash,
                } = resolved
                {
                    session.pending_requests.remove(&request_id);
                    session.accepted_files.insert(
                        request_id.clone(),
                        AcceptedFile {
                            source,
                            overlay_relative: relative,
                            expected_hash,
                            source_root: Some(root.clone()),
                        },
                    );
                    let _ = event_tx.send(RecoveryEvent::FileAccepted {
                        request_id: request_id.clone(),
                        note: Some(format!(
                            "{} found under {}",
                            pending.spec.title(),
                            root.display()
                        )),
                    });
                    break;
                }
            }
        }
    }

    fn start_restore(&mut self, device_id: &str) {
        let allowed = self.session.as_ref().is_some_and(|session| {
            session.claim.device_id() == device_id && session.restore_run.is_none()
        });
        if !allowed {
            return;
        }
        self.recollect_missing_identity_payloads();
        if self.emit_pending_file_requests() {
            return;
        }
        let plan = match self
            .session
            .as_mut()
            .expect("claimed session")
            .build_restore_plan()
        {
            Ok(plan) => plan,
            Err(error) => {
                if self.emit_pending_file_requests() {
                    return;
                }
                self.emit(RecoveryEvent::Failed { note: error });
                return;
            }
        };
        let image_size = match fs::metadata(&plan.image) {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                if let Some(session) = &mut self.session {
                    session.cleanup_overlay();
                }
                self.emit(RecoveryEvent::Failed {
                    note: format!("Could not read restore image size: {error}"),
                });
                return;
            }
        };
        let Some(session) = &mut self.session else {
            return;
        };
        let stop = Arc::new(AtomicBool::new(false));
        let reporter: crate::restore::SharedReporter =
            Arc::new(Mutex::new(UiReporter::new(self.event_tx.clone())));
        let (outcome_tx, outcome_rx) = mpsc::channel();
        let claim = Arc::clone(&session.claim);
        let boot = session.boot.clone();
        let plan_for_thread = plan;
        let stop_for_thread = Arc::clone(&stop);
        let join = thread::spawn(move || {
            let outcome =
                claim.run_restore(boot, plan_for_thread, image_size, stop_for_thread, reporter);
            let _ = outcome_tx.send(outcome);
        });
        session.restore_run = Some(ActiveRestore {
            stop,
            outcome_rx,
            join,
            cancel_requested: false,
            release_after: false,
            device_id: device_id.to_string(),
        });
        self.emit(RecoveryEvent::PhaseChanged {
            phase: SessionPhase::Starting,
            note: Some("Starting restore".to_string()),
        });
    }

    fn emit_pending_file_requests(&mut self) -> bool {
        let Some(session) = &self.session else {
            return false;
        };
        if session.pending_requests.is_empty() {
            return false;
        }
        let specs = session
            .pending_requests
            .values()
            .map(|pending| pending.spec.clone())
            .collect::<Vec<_>>();
        for spec in specs {
            self.emit(RecoveryEvent::FileRequested(spec));
        }
        self.emit(RecoveryEvent::PhaseChanged {
            phase: SessionPhase::Collecting,
            note: Some("Select the next restore file".to_string()),
        });
        true
    }

    fn cancel_restore(&mut self, device_id: &str) {
        let event_tx = self.event_tx.clone();
        let Some(session) = &mut self.session else {
            return;
        };
        if session.claim.device_id() != device_id {
            return;
        }
        if let Some(run) = &mut session.restore_run {
            run.cancel_requested = true;
            run.stop.store(true, Ordering::Relaxed);
            detach_session(&event_tx, session, HostDetachDisposition::Cancelled);
            self.emit(RecoveryEvent::PhaseChanged {
                phase: SessionPhase::Cancelling,
                note: Some("Stopping restore".to_string()),
            });
            return;
        }
        self.emit(RecoveryEvent::Cancelled {
            note: Some("Restore start cancelled".to_string()),
        });
    }

    fn retry_restore(&mut self, device_id: &str) {
        let Some(session) = &self.session else {
            return;
        };
        if session.claim.device_id() != device_id {
            return;
        }
        self.start_restore(device_id);
    }

    fn poll_restore_outcome(&mut self) {
        let event_tx = self.event_tx.clone();
        let Some(session) = &mut self.session else {
            return;
        };
        let Some(run) = &mut session.restore_run else {
            return;
        };
        let outcome = match run.outcome_rx.try_recv() {
            Ok(outcome) => outcome,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => RestoreOutcome::Failed {
                stage: "restore-thread".to_string(),
                reason: "The restore worker ended without reporting an outcome".to_string(),
            },
        };
        let dummy = thread::spawn(|| {});
        let join = std::mem::replace(&mut run.join, dummy);
        let cancel_requested = run.cancel_requested;
        let release_after = run.release_after;
        let device_id = run.device_id.clone();
        let _ = join.join();
        let disposition = classify_detach_disposition(&outcome, cancel_requested);
        session.restore_run = None;
        session.cleanup_overlay();
        detach_session(&event_tx, session, disposition);

        match outcome {
            RestoreOutcome::Ended { summary, .. } => {
                if summary
                    .final_status
                    .as_ref()
                    .is_some_and(FinalStatus::succeeded)
                {
                    self.emit(RecoveryEvent::Succeeded {
                        note: Some("Restore completed".to_string()),
                    });
                } else if cancel_requested {
                    self.emit(RecoveryEvent::Cancelled {
                        note: Some("Restore cancelled".to_string()),
                    });
                } else {
                    self.emit(RecoveryEvent::Failed {
                        note: guest_failure_note(&summary),
                    });
                }
            }
            RestoreOutcome::Failed { stage, reason } => {
                if cancel_requested {
                    self.emit(RecoveryEvent::Cancelled {
                        note: Some("Restore cancelled".to_string()),
                    });
                } else {
                    self.emit(RecoveryEvent::Failed {
                        note: format!("{stage}: {reason}"),
                    });
                }
            }
        }

        if release_after {
            self.cleanup_session(HostDetachDisposition::Cancelled);
            self.emit(RecoveryEvent::Released {
                device_id,
                note: Some("Claim released".to_string()),
            });
        }
    }
}

fn guest_failure_note(summary: &crate::ramrod::RestoreSummary) -> String {
    if let Some(log) = summary.guest_log.as_deref()
        && let Some(line) = notable_guest_error(log)
    {
        return line;
    }
    if let Some(error) = summary.checkpoint_error.as_deref() {
        if let Some(line) = notable_guest_error(error) {
            return line;
        }
        let trimmed = error.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Some(checkpoint) = summary.open_checkpoint.as_deref() {
        return format!("{checkpoint} failed");
    }
    summary
        .final_status
        .as_ref()
        .map(|status| format!("Restore ended with {}", status.outcome()))
        .unwrap_or_else(|| "Restore ended without a final status".to_string())
}

fn notable_guest_error(log: &str) -> Option<String> {
    let needles = [
        "Erase restore may be required",
        "invalid GPT",
        "AMRestoreErrorDomain",
    ];
    let descriptions = cf_error_descriptions(log);
    let lines: Vec<&str> = if descriptions.is_empty() {
        log.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect()
    } else {
        descriptions.iter().map(String::as_str).collect()
    };
    lines
        .into_iter()
        .rev()
        .find(|line| needles.iter().any(|needle| line.contains(needle)))
        .map(|line| line.rsplit(": ").next().unwrap_or(line).trim().to_string())
}

fn cf_error_descriptions(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("]D(") {
        let body = &rest[start + 3..];
        let Some(end) = body.find(')') else {
            break;
        };
        let inner = body[..end].trim();
        if !inner.is_empty() {
            out.push(inner.to_string());
        }
        rest = &body[end + 1..];
    }
    out
}

impl ServiceWorker {
    fn cleanup_session(&mut self, disposition: HostDetachDisposition) {
        let event_tx = self.event_tx.clone();
        if let Some(mut session) = self.session.take() {
            detach_session(&event_tx, &mut session, disposition);
            if let Some(mut run) = session.restore_run.take() {
                run.cancel_requested = true;
                run.stop.store(true, Ordering::Relaxed);
                let _ = run.join.join();
            }
            session.cleanup_overlay();
        }
    }

    fn emit(&self, event: RecoveryEvent) {
        let _ = self.event_tx.send(event);
    }

    fn try_emit(&self, event: RecoveryEvent) {
        let _ = self.event_tx.try_send(event);
    }
}

fn host_detach_log_event(
    disposition: HostDetachDisposition,
    detach: HostDetachOutcome,
) -> RecoveryEvent {
    let result = match disposition {
        HostDetachDisposition::Complete => "host-detached-complete",
        HostDetachDisposition::Cancelled => "host-detached-cancelled",
        HostDetachDisposition::Failed => "host-detached-failed",
    };
    let outcome = match disposition {
        HostDetachDisposition::Complete => "complete",
        HostDetachDisposition::Cancelled => "cancelled",
        HostDetachDisposition::Failed => "failed",
    };
    RecoveryEvent::Log {
        level: if matches!(disposition, HostDetachDisposition::Failed) {
            LogLevel::Warn
        } else {
            LogLevel::Info
        },
        message: format!(
            "{MUX_PREFIX} result={result} port=62078 connected={} configured={} disconnect_event={} reset_event={} outcome={} meaning=\"the host end of the claimed restore cable is out, so the guest can leave any disconnect wait and the recovery bridge can retire the claim cleanly\" detail=\"disconnect_event is the DWC3 disconnect event as seen by the bridge, reset_event reports whether a reset reached the guest after detaching the host\"",
            detach.was_connected,
            detach.was_configured,
            detach.disconnect_delivered,
            detach.reset_delivered,
            outcome
        ),
    }
}

fn classify_detach_disposition(
    outcome: &RestoreOutcome,
    cancel_requested: bool,
) -> HostDetachDisposition {
    if cancel_requested {
        return HostDetachDisposition::Cancelled;
    }
    match outcome {
        RestoreOutcome::Ended { summary, .. }
            if summary
                .final_status
                .as_ref()
                .is_some_and(FinalStatus::succeeded) =>
        {
            HostDetachDisposition::Complete
        }
        RestoreOutcome::Ended { .. } | RestoreOutcome::Failed { .. } => {
            HostDetachDisposition::Failed
        }
    }
}

fn should_abort_after_detach(detach: HostDetachOutcome) -> bool {
    !detach.was_connected
        && !detach.was_configured
        && !detach.disconnect_delivered
        && !detach.reset_delivered
}

fn detach_session(
    event_tx: &SyncSender<RecoveryEvent>,
    session: &mut ClaimedSession,
    disposition: HostDetachDisposition,
) {
    let Some(detach) = session.detach_host_once(disposition) else {
        return;
    };
    let _ = event_tx.try_send(host_detach_log_event(disposition, detach));
    if should_abort_after_detach(detach) {
        session.claim.abort();
    }
}

#[derive(Clone)]
struct PendingRequest {
    spec: FileRequestSpec,
    overlay_relative: PathBuf,
    expected_hash: Option<HashExpectation>,
    source_root: Option<PathBuf>,
    component: String,
    manifest_file_name: String,
}

#[derive(Clone)]
struct AcceptedFile {
    source: PathBuf,
    overlay_relative: PathBuf,
    expected_hash: Option<HashExpectation>,
    source_root: Option<PathBuf>,
}

#[derive(Debug)]
struct ValidatedSelection {
    source: PathBuf,
    metadata: fs::Metadata,
    content_hash: Option<HashExpectation>,
}

struct ClaimedSession {
    claim: Arc<dyn ClaimedRestore>,
    boot: RestoreBootContext,
    bridge_context: BridgeBootContext,
    device: DeviceType,
    host_detached: bool,
    request_global_manifest: bool,
    manifest_root: Option<PathBuf>,
    derived: Option<crate::restore::DerivedRestoreOptions>,
    selected_behavior: Option<RestoreBehavior>,
    accepted_files: HashMap<String, AcceptedFile>,
    pending_requests: BTreeMap<String, PendingRequest>,
    overlay_root: Option<TempDir>,
    restore_run: Option<ActiveRestore>,
}

impl ClaimedSession {
    fn new(
        claim: Arc<dyn ClaimedRestore>,
        context: ClaimedBootContext,
        device: DeviceType,
    ) -> Self {
        Self {
            claim,
            boot: context.restore,
            bridge_context: context.bridge,
            device,
            host_detached: false,
            request_global_manifest: false,
            manifest_root: None,
            derived: None,
            selected_behavior: None,
            accepted_files: HashMap::new(),
            pending_requests: BTreeMap::new(),
            overlay_root: None,
            restore_run: None,
        }
    }

    fn reset_for_manifest_request(&mut self) {
        self.request_global_manifest = false;
        self.manifest_root = None;
        self.derived = None;
        self.selected_behavior = None;
        self.accepted_files.clear();
        self.pending_requests.clear();
        self.cleanup_overlay();
        self.pending_requests.insert(
            MANIFEST_REQUEST_ID.to_string(),
            PendingRequest {
                spec: manifest_request_spec(),
                overlay_relative: PathBuf::from(BUILD_MANIFEST_FILE_NAME),
                expected_hash: None,
                source_root: None,
                component: BUILD_MANIFEST_FILE_NAME.to_string(),
                manifest_file_name: BUILD_MANIFEST_FILE_NAME.to_string(),
            },
        );
    }

    fn build_restore_plan(&mut self) -> Result<RestorePlan, String> {
        if !self.pending_requests.is_empty() {
            return Err("More files are still required before restore can start".to_string());
        }
        let manifest = self
            .accepted_files
            .get(MANIFEST_REQUEST_ID)
            .cloned()
            .ok_or_else(|| "BuildManifest.plist has not been accepted yet".to_string())?;
        let system_image = self
            .accepted_files
            .get(SYSTEM_IMAGE_REQUEST_ID)
            .cloned()
            .ok_or_else(|| "The restore image has not been accepted yet".to_string())?;
        let manifest_root = self
            .manifest_root
            .clone()
            .ok_or_else(|| "The BuildManifest root has not been resolved".to_string())?;
        self.cleanup_overlay();
        let overlay_root = create_overlay_root()?;
        let overlay_path = overlay_root.path().to_path_buf();
        let result = (|| {
            let global_source = locate_global_manifest_source(&manifest_root)?;
            if global_source.is_some() != self.request_global_manifest {
                return Err(
                    "The Firmware/Manifests/restore tree changed after BuildManifest validation"
                        .to_string(),
                );
            }
            let firmware_source = locate_firmware_source(&manifest_root)?;
            if let Some(source) = firmware_source {
                mirror_located_directory(
                    &manifest_root,
                    &source,
                    Path::new("Firmware"),
                    &overlay_path,
                )?;
            }
            let bootability_bundle = mirror_optional_directory(
                &manifest_root,
                Path::new("BootabilityBundle"),
                &overlay_path,
            )?;
            let manifest_path = materialize_accepted_file(
                &manifest,
                &overlay_path,
                Path::new(BUILD_MANIFEST_FILE_NAME),
            )?;
            let image_path = materialize_accepted_file(
                &system_image,
                &overlay_path,
                &system_image.overlay_relative,
            )?;
            for (request_id, accepted) in &self.accepted_files {
                if request_id == MANIFEST_REQUEST_ID || request_id == SYSTEM_IMAGE_REQUEST_ID {
                    continue;
                }
                materialize_accepted_file(accepted, &overlay_path, &accepted.overlay_relative)?;
            }

            let global_manifests = if global_source.is_some() {
                let staged = overlay_path.join("Firmware/Manifests/restore");
                if staged.is_dir() {
                    Some(staged)
                } else if let Some(source) = global_source {
                    Some(mirror_located_directory(
                        &manifest_root,
                        &source,
                        Path::new("Firmware/Manifests/restore"),
                        &overlay_path,
                    )?)
                } else {
                    None
                }
            } else {
                None
            };
            let firmware_root = Some(overlay_path.clone());

            let plan = RestorePlan {
                image: image_path.clone(),
                system_image: Some(image_path.clone()),
                recovery_image: Some(image_path),
                image_root: Some(overlay_path.clone()),
                manifest: Some(manifest_path),
                behavior: self
                    .selected_behavior
                    .or_else(|| self.derived.as_ref().map(|derived| derived.behavior)),
                port: 62078,
                timeout: Duration::from_secs(35),
                window: Duration::from_secs(600),
                retry: Duration::from_secs(5),
                read_poll: Duration::from_secs(30),
                asr_read_timeout: None,
                metadata: true,
                global_manifests,
                firmware_root,
                bootability_bundle,
                corrupt_manifest: false,
                staged_boot_manifest_sha384: Some(self.bridge_context.staged_boot_manifest_sha384),
                fdr_trust_digest: fdr_trust_digest_from_context(&self.bridge_context),
                fdr_material_dir: self
                    .bridge_context
                    .fdr_material_path
                    .clone()
                    .map(PathBuf::from)
                    .filter(|path| path.is_dir()),
            };
            let prepared = prepare_restore_session_with_branching(
                &plan,
                &self.device,
                self.request_global_manifest,
            )
            .map_err(|error| error.to_string())?;
            prepared
                .validate_required_assets()
                .map_err(|error| error.to_string())?;
            Ok(plan)
        })();

        let plan = result?;
        self.overlay_root = Some(overlay_root);
        Ok(plan)
    }

    fn cleanup_overlay(&mut self) {
        drop(self.overlay_root.take());
    }

    fn detach_host_once(
        &mut self,
        disposition: HostDetachDisposition,
    ) -> Option<HostDetachOutcome> {
        if self.host_detached {
            return None;
        }
        self.host_detached = true;
        Some(self.claim.detach_host(disposition))
    }
}

struct ActiveRestore {
    stop: Arc<AtomicBool>,
    outcome_rx: Receiver<RestoreOutcome>,
    join: JoinHandle<()>,
    cancel_requested: bool,
    release_after: bool,
    device_id: String,
}

// `Missing.spec` is moved out as an owned value at several call sites.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum ComponentResolution {
    Present {
        source: PathBuf,
        relative: PathBuf,
        expected_hash: Option<HashExpectation>,
    },
    Missing {
        spec: FileRequestSpec,
        relative: PathBuf,
        expected_hash: Option<HashExpectation>,
        manifest_file_name: String,
    },
}

fn discovery_interval(failures: u32) -> Duration {
    if failures == 0 {
        return DISCOVERY_INTERVAL;
    }
    let shift = failures.min(4);
    let millis = DISCOVERY_INTERVAL
        .as_millis()
        .saturating_mul(2u128.saturating_pow(shift)) as u64;
    Duration::from_millis(millis).min(DISCOVERY_BACKOFF_MAX)
}

fn is_transient_discovery_error(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("os error 35")
        || lower.contains("os error 11")
        || lower.contains("resource temporarily unavailable")
        || lower.contains("would block")
        || lower.contains("interrupted")
        || lower.contains("connection refused")
}

fn manifest_request_spec() -> FileRequestSpec {
    FileRequestSpec {
        request_id: MANIFEST_REQUEST_ID.to_string(),
        role: "BuildManifest".to_string(),
        preferred_name: Some(BUILD_MANIFEST_FILE_NAME.to_string()),
        accepted_names: vec![
            BUILD_MANIFEST_FILE_NAME.to_string(),
            RESTORE_PLIST_FILE_NAME.to_string(),
        ],
        allowed_extensions: vec!["plist".to_string()],
        accept_directory: false,
        expected_size: None,
        expected_hash: None,
        detail: Some(
            "Select BuildManifest.plist, Restore.plist, or the extracted restore folder."
                .to_string(),
        ),
        required: true,
    }
}

fn map_devices(
    entries: &[DiscoveredDevice],
    claimed_device: Option<&str>,
) -> HashMap<String, RecoveryDevice> {
    entries
        .iter()
        .map(|entry| {
            let state = if claimed_device == Some(entry.id.as_str()) {
                crate::recovery_model::DeviceState::Claimed
            } else if claimed_device.is_some()
                && entry.state != crate::recovery_model::DeviceState::Disconnected
            {
                crate::recovery_model::DeviceState::Busy
            } else {
                entry.state
            };
            (
                entry.id.clone(),
                RecoveryDevice {
                    id: entry.id.clone(),
                    title: entry.title.clone(),
                    detail: entry.detail.clone(),
                    connection: entry.connection.clone(),
                    state,
                    connected: entry.connected,
                },
            )
        })
        .collect()
}

#[cfg(test)]
fn validate_pending_request(
    pending: &PendingRequest,
    path: &Path,
) -> Result<ValidatedSelection, String> {
    validate_pending_request_reported(pending, path, |_, _| {})
}

fn validate_pending_request_reported(
    pending: &PendingRequest,
    path: &Path,
    report: impl FnMut(u64, u64),
) -> Result<ValidatedSelection, String> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "The selected file name is not valid UTF-8".to_string())?;
    let (source, metadata) = validate_regular_source(path, pending.source_root.as_deref())?;
    if let Some(expected_size) = pending.spec.expected_size
        && !expected_size.contains(metadata.len())
    {
        return Err(format!(
            "size mismatch: expected {}, got {} bytes",
            expected_size.label(),
            metadata.len()
        ));
    }
    let expected_kind = payload_kind_from_name(&pending.manifest_file_name);
    let actual_kind = sniff_payload_kind(&source)?;
    if !kinds_compatible(expected_kind, actual_kind) {
        return Err(format!(
            "{file_name} is not a {} payload (expected {}, got {})",
            pending.spec.role,
            expected_kind.label(),
            actual_kind.label()
        ));
    }
    let mut report = report;
    let content_hash = if pending.spec.request_id == MANIFEST_REQUEST_ID {
        Some(HashExpectation {
            algorithm: "sha2-256".to_string(),
            value: digest_file_with_progress(&source, "sha2-256", &mut report)?,
        })
    } else if let Some(hash) = &pending.expected_hash {
        if digest_covers(expected_kind, actual_kind) {
            let actual = digest_file_with_progress(&source, &hash.algorithm, &mut report)?;
            if !actual.eq_ignore_ascii_case(&hash.value) {
                return Err(hash_mismatch_reason(
                    &pending.spec,
                    file_name,
                    hash,
                    &actual,
                ));
            }
            Some(hash.clone())
        } else {
            Some(HashExpectation {
                algorithm: hash.algorithm.clone(),
                value: digest_file_with_progress(&source, &hash.algorithm, &mut report)?,
            })
        }
    } else {
        None
    };
    Ok(ValidatedSelection {
        source,
        metadata,
        content_hash,
    })
}

fn wanted_payload_name(spec: &FileRequestSpec) -> String {
    spec.preferred_name
        .as_deref()
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .or_else(|| spec.accepted_names.first().cloned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| spec.role.clone())
}

fn short_digest(value: &str) -> String {
    let take = 12;
    let chars: String = value.chars().take(take).collect();
    if value.chars().count() > take {
        format!("{chars}…")
    } else {
        chars
    }
}

fn hash_mismatch_reason(
    spec: &FileRequestSpec,
    file_name: &str,
    expected: &HashExpectation,
    actual: &str,
) -> String {
    let want = wanted_payload_name(spec);
    format!(
        "{file_name} does not match {want}. Select the correct file ({} {} vs {})",
        expected.algorithm,
        short_digest(&expected.value),
        short_digest(actual)
    )
}

fn autosearch_remaining_reason(dir: &Path, found: usize, remaining: &str) -> String {
    if found == 0 {
        format!(
            "Paste the Firmware folder and press Enter. {} has no remaining files. Still need {remaining}",
            dir.display()
        )
    } else {
        format!(
            "Autosearch found {found} file(s) under {}; still need {remaining}",
            dir.display()
        )
    }
}

fn autosearch_from(dir: &Path) -> Vec<PathBuf> {
    vec![dir.to_path_buf()]
}

fn component_request_id(component: &str) -> String {
    if component == "OS" {
        SYSTEM_IMAGE_REQUEST_ID.to_string()
    } else {
        format!("component:{component}")
    }
}

fn pending_request_for_unresolved_component(name: &str, reason: &str) -> PendingRequest {
    let file_name = Path::new(name)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(name)
        .to_string();
    let mut allowed_extensions = Vec::new();
    if let Some(ext) = Path::new(&file_name)
        .extension()
        .and_then(|ext| ext.to_str())
    {
        allowed_extensions.push(ext.to_ascii_lowercase());
    }
    extend_payload_extensions(&mut allowed_extensions, payload_kind_from_name(&file_name));
    PendingRequest {
        spec: FileRequestSpec {
            request_id: component_request_id(name),
            role: name.to_string(),
            preferred_name: Some(file_name.clone()),
            accepted_names: vec![file_name.clone()],
            allowed_extensions,
            accept_directory: false,
            expected_size: None,
            expected_hash: None,
            detail: Some(format!(
                "Type the path to {name}, or a folder that holds the remaining restore files. ({reason})"
            )),
            required: true,
        },
        overlay_relative: PathBuf::from(&file_name),
        expected_hash: None,
        source_root: None,
        component: name.to_string(),
        manifest_file_name: file_name,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PayloadKind {
    Aea,
    DiskImage,
    Im4p,
    Plist,
    Other,
}

impl PayloadKind {
    fn label(self) -> &'static str {
        match self {
            Self::Aea => "aea",
            Self::DiskImage => "dmg",
            Self::Im4p => "im4p",
            Self::Plist => "plist",
            Self::Other => "payload",
        }
    }
}

fn payload_kind_from_name(name: &str) -> PayloadKind {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".trustcache") {
        PayloadKind::Im4p
    } else if lower.ends_with(".dmg.aea") || lower.ends_with(".aea") {
        PayloadKind::Aea
    } else if lower.ends_with(".dmg") {
        PayloadKind::DiskImage
    } else if lower.ends_with(".im4p")
        || lower.ends_with(".img4")
        || lower.ends_with(".root_hash")
        || lower.ends_with(".mtree")
    {
        PayloadKind::Im4p
    } else if lower.ends_with(".sefw") {
        PayloadKind::Other
    } else if lower.ends_with(".plist") {
        PayloadKind::Plist
    } else {
        PayloadKind::Other
    }
}

fn sniff_payload_kind(path: &Path) -> Result<PayloadKind, String> {
    let mut file = fs::File::open(path).map_err(|error| error.to_string())?;
    let mut head = [0u8; 16];
    let read = file.read(&mut head).map_err(|error| error.to_string())?;
    let head = &head[..read];
    if head.starts_with(b"AEA1") {
        return Ok(PayloadKind::Aea);
    }
    if head.starts_with(b"IM4P") || head.starts_with(b"IMG4") {
        return Ok(PayloadKind::Im4p);
    }
    if head.starts_with(b"<?xml") || head.starts_with(b"bplist") {
        return Ok(PayloadKind::Plist);
    }
    if let Ok(metadata) = file.metadata()
        && metadata.len() >= 512
        && file.seek(SeekFrom::End(-512)).is_ok()
    {
        let mut magic = [0u8; 4];
        if file.read_exact(&mut magic).is_ok() && &magic == b"koly" {
            return Ok(PayloadKind::DiskImage);
        }
    }
    Ok(payload_kind_from_name(
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default(),
    ))
}

fn kinds_compatible(expected: PayloadKind, actual: PayloadKind) -> bool {
    expected == actual
        || matches!(
            (expected, actual),
            (PayloadKind::Aea, PayloadKind::DiskImage)
                | (PayloadKind::DiskImage, PayloadKind::Aea)
                | (PayloadKind::Im4p, PayloadKind::Other)
                | (PayloadKind::Other, PayloadKind::Im4p)
        )
}

fn digest_covers(expected: PayloadKind, actual: PayloadKind) -> bool {
    matches!(
        (expected, actual),
        (PayloadKind::Aea, PayloadKind::Aea)
            | (PayloadKind::DiskImage, PayloadKind::DiskImage)
            | (PayloadKind::Plist, PayloadKind::Plist)
    )
}

fn extend_payload_extensions(extensions: &mut Vec<String>, kind: PayloadKind) {
    let extra: &[&str] = match kind {
        PayloadKind::Aea => &["aea", "dmg"],
        PayloadKind::DiskImage => &["dmg", "aea"],
        PayloadKind::Im4p => &["im4p", "img4", "trustcache", "root_hash", "mtree"],
        PayloadKind::Plist => &["plist"],
        PayloadKind::Other => &["sefw"],
    };
    for ext in extra {
        if !extensions.iter().any(|existing| existing == *ext) {
            extensions.push((*ext).to_string());
        }
    }
}

fn component_digest(
    component: &plist::Dictionary,
    info: &plist::Dictionary,
) -> Result<Option<HashExpectation>, String> {
    let Some(digest) = component.get("Digest").and_then(Value::as_data) else {
        return Ok(None);
    };
    let algorithm = info
        .get("HashMethod")
        .and_then(Value::as_string)
        .map(str::trim)
        .filter(|method| !method.is_empty())
        .map(str::to_string)
        .or_else(|| match digest.len() {
            48 => Some("sha2-384".to_string()),
            32 => Some("sha2-256".to_string()),
            _ => None,
        });
    let Some(algorithm) = algorithm else {
        return Ok(None);
    };
    validate_hash_algorithm(&algorithm)?;
    Ok(Some(HashExpectation {
        algorithm,
        value: hex_digest(digest),
    }))
}

#[cfg(test)]
fn component_path_and_digest(identity: &BuildIdentity, name: &str) -> Option<(String, Vec<u8>)> {
    let component = identity.components.as_ref()?.get(name)?.as_dictionary()?;
    let info = component.get("Info")?.as_dictionary()?;
    let path = info.get("Path")?.as_string()?.to_string();
    let digest = component
        .get("Digest")
        .and_then(Value::as_data)
        .unwrap_or(&[])
        .to_vec();
    Some((path, digest))
}

fn identities_for_board(
    dict: &plist::Dictionary,
    device_class: &str,
    behavior: RestoreBehavior,
) -> Result<Vec<BuildIdentity>, String> {
    let install =
        select_install_identity(dict, device_class, behavior).map_err(|error| error.to_string())?;
    let mut identities = vec![install];
    if let Some(macos) = select_macos_identity(dict, device_class)
        && identities[0].index != macos.index
    {
        identities.push(macos);
    }
    Ok(identities)
}

fn mode_from_behavior(behavior: RestoreBehavior) -> RestoreMode {
    match behavior {
        RestoreBehavior::Update => RestoreMode::Update,
        RestoreBehavior::Erase => RestoreMode::Erase,
    }
}

fn behavior_from_mode(mode: RestoreMode) -> RestoreBehavior {
    match mode {
        RestoreMode::Update => RestoreBehavior::Update,
        RestoreMode::Erase => RestoreBehavior::Erase,
    }
}

fn product_version_from_manifest(dict: &plist::Dictionary) -> (Option<String>, Option<String>) {
    let version = dict
        .get("ProductVersion")
        .and_then(Value::as_string)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let build = dict
        .get("ProductBuildVersion")
        .and_then(Value::as_string)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    (version, build)
}

fn compatible_systems_from(
    classes: Vec<String>,
    catalog: Option<&crate::ramrod::RestoreCatalog>,
) -> Vec<crate::recovery_model::CompatibleSystem> {
    let classes = classes
        .into_iter()
        .filter(|class| !class.trim().is_empty())
        .collect::<BTreeSet<_>>();
    let mapped = catalog
        .filter(|catalog| !catalog.boards.is_empty())
        .map(|catalog| {
            catalog
                .boards
                .iter()
                .map(|board| board.to_ascii_lowercase())
                .collect::<BTreeSet<_>>()
        });
    let mut classes: Vec<String> = match mapped {
        Some(map) => {
            let fallback = classes.clone();
            let intersect: Vec<String> = classes
                .into_iter()
                .filter(|class| map.contains(&class.to_ascii_lowercase()))
                .collect();
            if intersect.is_empty() {
                fallback.into_iter().collect()
            } else {
                intersect
            }
        }
        None => classes.into_iter().collect(),
    };
    classes.sort_by(|left, right| {
        let platform = |class: &str| {
            catalog.and_then(|catalog| {
                catalog
                    .platforms
                    .get(&class.to_ascii_lowercase())
                    .map(String::as_str)
            })
        };
        let left_label = crate::ramrod::describe_board(left, platform(left));
        let right_label = crate::ramrod::describe_board(right, platform(right));
        left_label
            .title
            .to_ascii_lowercase()
            .cmp(&right_label.title.to_ascii_lowercase())
            .then_with(|| left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase()))
    });
    classes
        .into_iter()
        .map(|class| {
            let platform = catalog.and_then(|catalog| {
                catalog
                    .platforms
                    .get(&class.to_ascii_lowercase())
                    .map(String::as_str)
            });
            let label = crate::ramrod::describe_board(&class, platform);
            crate::recovery_model::CompatibleSystem {
                class: label.class,
                title: label.title,
                detail: label.detail,
            }
        })
        .collect()
}

#[cfg(test)]
fn shared_component_identity<'a>(
    identities: &'a [BuildIdentity],
    name: &str,
) -> Option<&'a BuildIdentity> {
    let mut owner = None;
    let mut signature = None;
    for identity in identities {
        let Some(found) = component_path_and_digest(identity, name) else {
            continue;
        };
        match &signature {
            None => {
                signature = Some(found);
                owner = Some(identity);
            }
            Some(existing) if *existing == found => {}
            Some(_) => return None,
        }
    }
    owner
}

fn identity_payload_sources(
    derived: &crate::restore::DerivedRestoreOptions,
) -> Vec<&BuildIdentity> {
    let mut identities = vec![&derived.install_identity];
    if derived.macos_identity.index != derived.install_identity.index {
        identities.push(&derived.macos_identity);
    }
    identities
}

fn identity_component_names(identity: &BuildIdentity) -> Vec<String> {
    let Some(components) = identity.components.as_ref() else {
        return Vec::new();
    };
    let mut names = components
        .iter()
        .filter(|(name, value)| {
            value
                .as_dictionary()
                .and_then(|component| component.get("Info"))
                .and_then(Value::as_dictionary)
                .and_then(|info| info.get("Path"))
                .and_then(Value::as_string)
                .map(str::trim)
                .is_some_and(|path| !path.is_empty())
                && *name != BUILD_MANIFEST_FILE_NAME
        })
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    names.sort();
    if let Some(os) = names.iter().position(|name| name == "OS") {
        names.swap(0, os);
    }
    names
}

#[cfg(test)]
fn resolve_system_image(
    root: &Path,
    identity: &BuildIdentity,
) -> Result<ComponentResolution, String> {
    resolve_identity_component(root, identity, "OS")
}

fn resolve_identity_component(
    root: &Path,
    identity: &BuildIdentity,
    component_name: &str,
) -> Result<ComponentResolution, String> {
    let root = fs::canonicalize(root)
        .map_err(|error| format!("Could not resolve the extracted IPSW root: {error}"))?;
    let components = identity
        .components
        .as_ref()
        .ok_or_else(|| "The selected identity carries no Manifest dictionary".to_string())?;
    let component = components
        .get(component_name)
        .and_then(Value::as_dictionary)
        .ok_or_else(|| format!("The selected identity ships no {component_name} component"))?;
    let info = component
        .get("Info")
        .and_then(Value::as_dictionary)
        .ok_or_else(|| {
            format!("The selected {component_name} component carries no Info dictionary")
        })?;
    let manifest_path = info
        .get("Path")
        .and_then(Value::as_string)
        .ok_or_else(|| format!("The selected {component_name} component carries no path"))?;
    let manifest_relative =
        validate_manifest_relative_path(manifest_path, &format!("{component_name} Info/Path"))?;
    let manifest_path = manifest_relative.to_str().ok_or_else(|| {
        format!("The selected {component_name} component path is not valid UTF-8")
    })?;
    let expected_hash = component_digest(component, info)?;
    let expected_kind = payload_kind_from_name(manifest_path);
    let manifest_file_name = Path::new(manifest_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(manifest_path)
        .to_string();
    let content_encoding = identity.info_string("ContentEncoding");
    let candidates = image_candidates(&root, component_name, manifest_path, content_encoding);
    if candidates.is_empty() {
        return Err(format!(
            "The selected {component_name} component produced no file candidates"
        ));
    }
    let decoded_name = content_encoding
        .and_then(|encoding| {
            manifest_file_name
                .strip_suffix(&format!(".{encoding}"))
                .map(str::to_string)
        })
        .unwrap_or_else(|| manifest_file_name.clone());

    let exact = root.join(&manifest_relative);
    if let Ok((source, _)) = validate_regular_source(&exact, Some(&root))
        && let Ok(actual_kind) = sniff_payload_kind(&source)
        && kinds_compatible(expected_kind, actual_kind)
    {
        return Ok(ComponentResolution::Present {
            source,
            relative: manifest_relative.clone(),
            expected_hash: None,
        });
    }

    for (_, candidate) in &candidates {
        match fs::symlink_metadata(candidate) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                    continue;
                }
            }
            Err(_) => continue,
        }
        let Ok((source, _)) = validate_regular_source(candidate, Some(&root)) else {
            continue;
        };
        let Ok(actual_kind) = sniff_payload_kind(&source) else {
            continue;
        };
        if !kinds_compatible(expected_kind, actual_kind) {
            continue;
        }
        return Ok(ComponentResolution::Present {
            source,
            relative: relative_under(&root, candidate).ok_or_else(|| {
                format!("Resolved {component_name} candidate escapes the IPSW root")
            })?,
            expected_hash: None,
        });
    }

    let mut accepted_names = candidates
        .iter()
        .filter_map(|(_, path)| path.file_name().and_then(|name| name.to_str()))
        .map(str::to_string)
        .collect::<Vec<_>>();
    accepted_names.dedup();
    accepted_names = expand_accepted_names(&accepted_names);
    let mut allowed_extensions = accepted_names
        .iter()
        .filter_map(|name| {
            Path::new(name)
                .extension()
                .and_then(|ext| ext.to_str())
                .map(str::to_ascii_lowercase)
        })
        .collect::<Vec<_>>();
    allowed_extensions.sort();
    allowed_extensions.dedup();
    extend_payload_extensions(&mut allowed_extensions, expected_kind);
    let role = if component_name == "OS" {
        "Restore image".to_string()
    } else {
        component_name.to_string()
    };
    let spec = FileRequestSpec {
        request_id: component_request_id(component_name),
        role: role.clone(),
        preferred_name: Some(decoded_name.clone()),
        accepted_names: accepted_names.clone(),
        allowed_extensions: allowed_extensions.clone(),
        accept_directory: false,
        expected_size: None,
        expected_hash: expected_hash.clone(),
        detail: Some(format!(
            "Type the path to {component_name} ({manifest_path}), or a folder that holds the remaining restore files."
        )),
        required: true,
    };
    Ok(ComponentResolution::Missing {
        relative: manifest_relative,
        expected_hash,
        manifest_file_name,
        spec,
    })
}

fn fdr_trust_digest_from_context(context: &BridgeBootContext) -> Option<FdrTrustDigest> {
    let digest = context.fdr_trust_digest_sha256?;
    let trust_object = context.fdr_trust_object.clone()?;
    Some(FdrTrustDigest {
        digest,
        element_index: usize::try_from(context.fdr_element_index).ok()?,
        element_count: usize::try_from(context.fdr_element_count).ok()?,
        trust_object,
        instance: context.fdr_instance.clone(),
    })
}

fn digest_file(path: &Path, algorithm: &str) -> Result<String, String> {
    digest_file_with_progress(path, algorithm, |_, _| {})
}

fn digest_file_with_progress(
    path: &Path,
    algorithm: &str,
    mut report: impl FnMut(u64, u64),
) -> Result<String, String> {
    let total = fs::metadata(path).ok().map(|meta| meta.len()).unwrap_or(0);
    let mut file = fs::File::open(path).map_err(|error| error.to_string())?;
    let mut buffer = [0u8; 1 << 20];
    let mut done = 0u64;
    let mut last_fraction = -1.0f64;
    let mut emit = |done: u64| {
        let fraction = if total == 0 {
            1.0
        } else {
            done as f64 / total as f64
        };
        if last_fraction < 0.0 || done >= total || fraction - last_fraction >= 0.01 {
            last_fraction = fraction;
            report(done, total);
        }
    };
    emit(0);
    match algorithm {
        "sha2-256" => {
            let mut hasher = Sha256::new();
            loop {
                let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
                done = done.saturating_add(read as u64);
                emit(done);
            }
            emit(done);
            Ok(hex_digest(&hasher.finish()))
        }
        "sha2-384" => {
            let mut hasher = Sha512::sha384();
            loop {
                let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
                done = done.saturating_add(read as u64);
                emit(done);
            }
            emit(done);
            Ok(hex_digest(&hasher.finish()[..48]))
        }
        other => Err(format!("Unsupported digest algorithm {other}")),
    }
}

fn validate_hash_algorithm(algorithm: &str) -> Result<(), String> {
    match algorithm {
        "sha2-256" | "sha2-384" => Ok(()),
        other => Err(format!("Unsupported digest algorithm {other}")),
    }
}

fn validate_manifest_relative_path(path: &str, role: &str) -> Result<PathBuf, String> {
    let normalised = path.replace('\\', "/");
    if normalised
        .split('/')
        .any(|component| component == "." || component == "..")
    {
        return Err(format!("{role} contains a traversal component: {path}"));
    }
    let bytes = normalised.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(format!("{role} contains a path prefix: {path}"));
    }
    let relative = PathBuf::from(normalised);
    validate_relative_path(&relative, role)?;
    if relative.file_name().is_none() {
        return Err(format!("{role} names no file: {path}"));
    }
    Ok(relative)
}

fn validate_relative_path(path: &Path, role: &str) -> Result<(), String> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(format!("{role} must be a non-empty relative path"));
    }
    let mut components = 0usize;
    for component in path.components() {
        match component {
            Component::Normal(_) => components += 1,
            Component::Prefix(_)
            | Component::RootDir
            | Component::ParentDir
            | Component::CurDir => {
                return Err(format!(
                    "{role} contains an invalid relative component: {}",
                    path.display()
                ));
            }
        }
    }
    if components == 0 {
        return Err(format!("{role} must contain a normal path component"));
    }
    Ok(())
}

fn validate_regular_source(
    path: &Path,
    root: Option<&Path>,
) -> Result<(PathBuf, fs::Metadata), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "Could not inspect selected file {}: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "The selected file is a symlink: {}",
            path.display()
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "The selected path is not a regular file: {}",
            path.display()
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        format!(
            "Could not resolve selected file {}: {error}",
            path.display()
        )
    })?;
    if let Some(root) = root
        && !canonical.starts_with(root)
    {
        return Err(format!(
            "The selected file escapes the extracted IPSW root: {}",
            path.display()
        ));
    }
    let canonical_metadata = fs::symlink_metadata(&canonical).map_err(|error| {
        format!(
            "Could not recheck selected file {}: {error}",
            canonical.display()
        )
    })?;
    if canonical_metadata.file_type().is_symlink() || !canonical_metadata.file_type().is_file() {
        return Err(format!(
            "The resolved selection is not a regular file: {}",
            canonical.display()
        ));
    }
    Ok((canonical, canonical_metadata))
}

fn optional_source_directory(root: &Path, relative: &Path) -> Result<Option<PathBuf>, String> {
    validate_relative_path(relative, "provider directory")?;
    let canonical_root = fs::canonicalize(root)
        .map_err(|error| format!("Could not resolve extracted IPSW root: {error}"))?;
    let mut current = canonical_root.clone();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(format!(
                "provider directory contains an invalid component: {}",
                relative.display()
            ));
        };
        current.push(name);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(format!(
                    "Could not inspect provider directory {}: {error}",
                    current.display()
                ));
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "Provider directory path contains a symlink: {}",
                current.display()
            ));
        }
        if !metadata.file_type().is_dir() {
            return Err(format!(
                "Provider directory path is not a directory: {}",
                current.display()
            ));
        }
    }
    let canonical = fs::canonicalize(&current).map_err(|error| {
        format!(
            "Could not resolve provider directory {}: {error}",
            current.display()
        )
    })?;
    if !canonical.starts_with(&canonical_root) {
        return Err(format!(
            "Provider directory escapes the extracted IPSW root: {}",
            current.display()
        ));
    }
    Ok(Some(canonical))
}

fn locate_global_manifest_source(root: &Path) -> Result<Option<PathBuf>, String> {
    if let Some(found) = optional_source_directory(root, Path::new("Firmware/Manifests/restore"))? {
        return Ok(Some(found));
    }
    find_directory_with_suffix(root, &["Firmware", "Manifests", "restore"])
}

fn locate_firmware_source(root: &Path) -> Result<Option<PathBuf>, String> {
    let exact = optional_source_directory(root, Path::new("Firmware"))?;
    if exact
        .as_ref()
        .is_some_and(|firmware| firmware.join("Manifests").join("restore").is_dir())
    {
        return Ok(exact);
    }
    if let Some(manifests) = locate_global_manifest_source(root)?
        && let Some(firmware) = manifests.parent().and_then(Path::parent)
    {
        return Ok(Some(firmware.to_path_buf()));
    }
    Ok(exact)
}

fn find_directory_with_suffix(root: &Path, suffix: &[&str]) -> Result<Option<PathBuf>, String> {
    if suffix.is_empty() {
        return Ok(None);
    }
    let canonical_root = fs::canonicalize(root)
        .map_err(|error| format!("Could not resolve extracted IPSW root: {error}"))?;
    let root_manifest = restore_set_manifest(&canonical_root);
    let mut stack = vec![canonical_root.clone()];
    let mut seen = HashSet::new();
    let mut visited = 0usize;
    while let Some(dir) = stack.pop() {
        if visited >= 100_000 {
            break;
        }
        if !seen.insert(dir.clone()) {
            continue;
        }
        if directory_ends_with(&dir, suffix) && dir != canonical_root {
            return Ok(Some(dir));
        }
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            visited += 1;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.starts_with('.') || name == "__MACOSX" {
                continue;
            }
            let child = entry.path();
            let Ok(metadata) = fs::symlink_metadata(&child) else {
                continue;
            };
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                continue;
            }
            if root_manifest
                .as_ref()
                .is_some_and(|manifest| declares_another_restore_set(&child, manifest))
            {
                continue;
            }
            stack.push(child);
        }
    }
    Ok(None)
}

fn directory_ends_with(path: &Path, suffix: &[&str]) -> bool {
    let names: Vec<&str> = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect();
    if names.len() < suffix.len() {
        return false;
    }
    names[names.len() - suffix.len()..]
        .iter()
        .zip(suffix.iter())
        .all(|(name, want)| name.eq_ignore_ascii_case(want))
}

fn mirror_located_directory(
    extract_root: &Path,
    source: &Path,
    relative: &Path,
    overlay: &Path,
) -> Result<PathBuf, String> {
    validate_relative_path(relative, "mirrored provider directory")?;
    let canonical_root = fs::canonicalize(extract_root)
        .map_err(|error| format!("Could not resolve extracted IPSW root: {error}"))?;
    let canonical_source = fs::canonicalize(source).map_err(|error| {
        format!(
            "Could not resolve provider directory {}: {error}",
            source.display()
        )
    })?;
    if !canonical_source.starts_with(&canonical_root) {
        return Err(format!(
            "Provider directory escapes the extracted IPSW root: {}",
            source.display()
        ));
    }
    let destination = overlay.join(relative);
    ensure_destination_parent(overlay, relative)?;
    fs::create_dir(&destination).map_err(|error| {
        format!(
            "Could not create mirrored provider directory {}: {error}",
            destination.display()
        )
    })?;
    mirror_directory_contents(&canonical_root, &canonical_source, &destination)?;
    Ok(destination)
}

fn mirror_optional_directory(
    root: &Path,
    relative: &Path,
    overlay: &Path,
) -> Result<Option<PathBuf>, String> {
    let Some(source) = optional_source_directory(root, relative)? else {
        return Ok(None);
    };
    validate_relative_path(relative, "mirrored provider directory")?;
    let destination = overlay.join(relative);
    ensure_destination_parent(overlay, relative)?;
    fs::create_dir(&destination).map_err(|error| {
        format!(
            "Could not create mirrored provider directory {}: {error}",
            destination.display()
        )
    })?;
    let canonical_root = fs::canonicalize(root)
        .map_err(|error| format!("Could not resolve extracted IPSW root: {error}"))?;
    mirror_directory_contents(&canonical_root, &source, &destination)?;
    Ok(Some(destination))
}

fn mirror_directory_contents(root: &Path, source: &Path, destination: &Path) -> Result<(), String> {
    let source_metadata = fs::symlink_metadata(source).map_err(|error| {
        format!(
            "Could not inspect provider directory {}: {error}",
            source.display()
        )
    })?;
    if source_metadata.file_type().is_symlink() || !source_metadata.file_type().is_dir() {
        return Err(format!(
            "Mirrored provider source is not a real directory: {}",
            source.display()
        ));
    }
    let canonical_source = fs::canonicalize(source).map_err(|error| {
        format!(
            "Could not resolve provider directory {}: {error}",
            source.display()
        )
    })?;
    if !canonical_source.starts_with(root) {
        return Err(format!(
            "Provider directory escapes the extracted IPSW root: {}",
            source.display()
        ));
    }
    let mut entries = fs::read_dir(&canonical_source)
        .map_err(|error| {
            format!(
                "Could not read provider directory {}: {error}",
                canonical_source.display()
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("Could not enumerate provider directory: {error}"))?;
    entries.sort_by_key(fs::DirEntry::file_name);

    for entry in entries {
        let source_path = entry.path();
        let relative = source_path.strip_prefix(root).map_err(|_| {
            format!(
                "Provider entry escapes the extracted IPSW root: {}",
                source_path.display()
            )
        })?;
        validate_relative_path(relative, "provider entry")?;
        let canonical = fs::canonicalize(&source_path).map_err(|error| {
            format!(
                "Could not resolve provider entry {}: {error}",
                source_path.display()
            )
        })?;
        if !canonical.starts_with(root) {
            return Err(format!(
                "Provider entry escapes the extracted IPSW root: {}",
                source_path.display()
            ));
        }
        let destination_path = destination.join(entry.file_name());
        let kind = fs::symlink_metadata(&canonical)
            .map_err(|error| {
                format!(
                    "Could not inspect resolved provider entry {}: {error}",
                    canonical.display()
                )
            })?
            .file_type();
        if kind.is_dir() {
            fs::create_dir(&destination_path).map_err(|error| {
                format!(
                    "Could not create mirrored directory {}: {error}",
                    destination_path.display()
                )
            })?;
            mirror_directory_contents(root, &canonical, &destination_path)?;
        } else if kind.is_file() {
            link_exact_file(&canonical, &destination_path)?;
        } else {
            return Err(format!(
                "Provider tree contains a special file: {}",
                source_path.display()
            ));
        }
    }
    Ok(())
}

fn ensure_destination_parent(overlay: &Path, relative: &Path) -> Result<(), String> {
    let Some(parent) = relative.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    validate_relative_path(parent, "staged file parent")?;
    let mut current = overlay.to_path_buf();
    for component in parent.components() {
        let Component::Normal(name) = component else {
            return Err(format!(
                "staged file parent contains an invalid component: {}",
                parent.display()
            ));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            }
            Ok(_) => {
                return Err(format!(
                    "Staged file parent is not a real directory: {}",
                    current.display()
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|error| {
                    format!(
                        "Could not create staged file parent {}: {error}",
                        current.display()
                    )
                })?;
            }
            Err(error) => {
                return Err(format!(
                    "Could not inspect staged file parent {}: {error}",
                    current.display()
                ));
            }
        }
    }
    Ok(())
}

fn materialize_accepted_file(
    accepted: &AcceptedFile,
    overlay: &Path,
    relative: &Path,
) -> Result<PathBuf, String> {
    if accepted.overlay_relative != relative {
        return Err(format!(
            "Accepted file staging path changed from {} to {}",
            accepted.overlay_relative.display(),
            relative.display()
        ));
    }
    validate_relative_path(relative, "staged file path")?;
    let (source, _) = validate_regular_source(&accepted.source, accepted.source_root.as_deref())?;
    if let Some(expected_hash) = &accepted.expected_hash {
        let actual = digest_file(&source, &expected_hash.algorithm)?;
        if actual != expected_hash.value {
            return Err(format!(
                "hash mismatch while staging {}: expected {} {}, got {}",
                source.display(),
                expected_hash.algorithm,
                expected_hash.value,
                actual
            ));
        }
    }
    ensure_destination_parent(overlay, relative)?;
    let destination = overlay.join(relative);
    link_exact_file(&source, &destination)?;
    Ok(destination)
}

fn link_exact_file(source: &Path, destination: &Path) -> Result<(), String> {
    link_exact_file_with(source, destination, |source, destination| {
        fs::hard_link(source, destination)
    })
}

fn link_exact_file_with<F>(source: &Path, destination: &Path, hard_link: F) -> Result<(), String>
where
    F: FnOnce(&Path, &Path) -> io::Result<()>,
{
    match fs::symlink_metadata(destination) {
        Ok(_) => {
            if validate_existing_materialization(source, destination).is_ok() {
                return Ok(());
            }
            fs::remove_file(destination).map_err(|error| {
                format!(
                    "Could not replace staged destination {}: {error}",
                    destination.display()
                )
            })?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "Could not inspect staged destination {}: {error}",
                destination.display()
            ));
        }
    }
    match hard_link(source, destination) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::EXDEV) => symlink(source, destination)
            .map_err(|error| {
                format!(
                    "Could not link staged file {} to {}: {error}",
                    source.display(),
                    destination.display()
                )
            }),
        Err(error) => Err(format!(
            "Could not hard link staged file {} to {}: {error}",
            source.display(),
            destination.display()
        )),
    }
}

fn validate_existing_materialization(source: &Path, destination: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let destination_metadata = fs::symlink_metadata(destination).map_err(|error| {
        format!(
            "Could not inspect staged destination {}: {error}",
            destination.display()
        )
    })?;
    if destination_metadata.file_type().is_symlink() {
        let target = fs::read_link(destination).map_err(|error| {
            format!(
                "Could not inspect staged file link {}: {error}",
                destination.display()
            )
        })?;
        if target == source {
            return Ok(());
        }
    } else if destination_metadata.file_type().is_file() {
        let source_metadata = fs::metadata(source).map_err(|error| error.to_string())?;
        if source_metadata.dev() == destination_metadata.dev()
            && source_metadata.ino() == destination_metadata.ino()
        {
            return Ok(());
        }
        if source_metadata.len() == destination_metadata.len()
            && files_have_identical_contents(source, destination)?
        {
            return Ok(());
        }
    }
    Err(format!(
        "Staged destination already holds a different object: {}",
        destination.display()
    ))
}

fn files_have_identical_contents(left: &Path, right: &Path) -> Result<bool, String> {
    let mut left_file = fs::File::open(left).map_err(|error| error.to_string())?;
    let mut right_file = fs::File::open(right).map_err(|error| error.to_string())?;
    let mut left_buf = [0u8; 64 * 1024];
    let mut right_buf = [0u8; 64 * 1024];
    loop {
        let left_read = left_file
            .read(&mut left_buf)
            .map_err(|error| error.to_string())?;
        let right_read = right_file
            .read(&mut right_buf)
            .map_err(|error| error.to_string())?;
        if left_read != right_read || left_buf[..left_read] != right_buf[..right_read] {
            return Ok(false);
        }
        if left_read == 0 {
            return Ok(true);
        }
    }
}

fn relative_under(root: &Path, path: &Path) -> Option<PathBuf> {
    path.strip_prefix(root).ok().map(Path::to_path_buf)
}

fn create_overlay_root() -> Result<TempDir, String> {
    TempDirBuilder::new()
        .prefix("apple-utils-restore-overlay-")
        .tempdir()
        .map_err(|error| format!("Could not create restore staging directory: {error}"))
}

struct UiReporter {
    event_tx: SyncSender<RecoveryEvent>,
    last_payload_fraction: Option<f64>,
    last_stage: Option<String>,
    last_fraction: Option<f64>,
}

impl UiReporter {
    fn new(event_tx: SyncSender<RecoveryEvent>) -> Self {
        Self {
            event_tx,
            last_payload_fraction: None,
            last_stage: None,
            last_fraction: None,
        }
    }

    fn try_send(&self, event: RecoveryEvent) {
        let _ = self.event_tx.try_send(event);
    }

    fn emit_stage(&mut self, stage: String, fraction: Option<f64>) {
        self.last_stage = Some(stage.clone());
        if let Some(fraction) = fraction {
            self.last_fraction = Some(fraction);
        }
        self.try_send(RecoveryEvent::Progress(RestoreProgress {
            stage,
            detail: String::new(),
            fraction: self.last_fraction,
        }));
    }
}

impl crate::restore::RestoreReporter for UiReporter {
    fn event(&mut self, event: crate::restore::RestoreEvent<'_>) {
        let level = if event.result.contains("failed") || event.result.contains("error") {
            LogLevel::Error
        } else if event.result.contains("warn") || event.result.contains("missing") {
            LogLevel::Warn
        } else {
            LogLevel::Info
        };
        self.try_send(RecoveryEvent::Log {
            level,
            message: event.line.to_string(),
        });
    }

    fn payload_block(
        &mut self,
        sent_bytes: u64,
        total_bytes: u64,
        _blocks: u64,
        _elapsed: Duration,
    ) {
        let fraction = (total_bytes > 0).then_some(sent_bytes as f64 / total_bytes as f64);
        if self.last_payload_fraction == fraction {
            return;
        }
        self.last_payload_fraction = fraction;
        self.try_send(RecoveryEvent::Progress(RestoreProgress {
            stage: self
                .last_stage
                .clone()
                .unwrap_or_else(|| "Streaming restore image".to_string()),
            detail: String::new(),
            fraction,
        }));
    }

    fn guest_progress(&mut self, _operation: Option<i64>, fraction: Option<f64>) {
        self.emit_stage(
            self.last_stage
                .clone()
                .unwrap_or_else(|| "restore".to_string()),
            fraction,
        );
    }

    fn guest_checkpoint(&mut self, name: &str, beginning: bool) {
        self.emit_stage(
            name.to_string(),
            if beginning {
                Some(self.last_fraction.unwrap_or(0.0))
            } else {
                self.last_fraction
            },
        );
    }

    fn guest_status(&mut self, status: i64) {
        self.try_send(RecoveryEvent::Log {
            level: LogLevel::Info,
            message: format!("Guest restore status {status}"),
        });
    }

    fn data_request(&mut self, data_type: &str, answered: bool) {
        self.try_send(RecoveryEvent::Log {
            level: if answered {
                LogLevel::Info
            } else {
                LogLevel::Warn
            },
            message: format!(
                "Guest requested {data_type}, host {}",
                if answered { "answered" } else { "declined" }
            ),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge_protocol::{
        self, BootContext, ClaimRequest, Claimed, Detached, DetachedDeviceState, DeviceEvent,
        ErrorRecord, ListEnd, RawRecord, RecordHeader, RecordKind, ServerHello, TransportKind,
    };
    use crate::ramrod::codec::{PlistFormat, encode_message};
    use crate::ramrod::message::{KEY_RESTORE_PROTOCOL_VERSION, KEY_TYPE, SERVICE_TYPE};
    use crate::usbmux::frame::{
        DEVICE_MAGIC, HEADER_LEN_V2, MuxHeader, MuxVersion, Protocol, VERSION_PACKET_LEN,
        VersionPacket,
    };
    use crate::usbmux::tcp::{TCP_HEADER_LEN, TcpHeader, flags};
    use plist::Value;
    use std::collections::VecDeque;
    use std::io::Cursor;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::AtomicU64;
    use std::sync::{Arc, Mutex, OnceLock};
    use tempfile::TempDir;
    use tempfile::tempdir;

    #[derive(Default)]
    struct RecordingReporter {
        lines: Vec<String>,
    }

    impl crate::restore::RestoreReporter for RecordingReporter {
        fn event(&mut self, event: crate::restore::RestoreEvent<'_>) {
            self.lines.push(format!("{}: {}", event.result, event.line));
        }
    }

    #[test]
    fn mux_report_trace_forwards_a_link_stall_into_the_restore_reporter_under_the_mux_prefix() {
        let recorder = Arc::new(Mutex::new(RecordingReporter::default()));
        let reporter: crate::restore::SharedReporter = recorder.clone();
        let trace = MuxReportTrace::new(reporter);
        trace.event(MuxTraceEvent::LinkStalled {
            phase: crate::usbmux::LinkPhase::Write,
            port: 49153,
            held: Duration::from_secs(12),
            waiters: 1,
            acquisitions: 4,
            since_acquisition: Duration::from_secs(12),
            stalled: Duration::from_secs(2),
            packets_in: 10,
            packets_out: 3,
            queued: 2,
            deferred: 1,
            idle_reads: 0,
            refused: 0,
        });
        let lines = recorder.lock().unwrap().lines.clone();
        assert_eq!(
            lines.len(),
            1,
            "the watchdog stall must reach the reporter exactly once"
        );
        assert!(lines[0].starts_with("link-stalled: "));
        assert!(lines[0].contains(MUX_PREFIX));
        assert!(lines[0].contains("result=link-stalled"));
    }

    struct FakeBackend {
        discovery: Mutex<BackendDiscovery>,
        claims: Mutex<Vec<(String, Arc<FakeClaimedRestore>)>>,
    }

    #[derive(Debug, Default, Clone)]
    struct RealBackendTranscript {
        list_requests: u32,
        claim_generations: Vec<u64>,
        claim_device_ids: Vec<String>,
        boot_context_requests: u32,
        query_type_requests: u32,
        detach_outcomes: Vec<bridge_protocol::DetachOutcome>,
        handshake_only_closes: u32,
        handshake_only_timeouts: u32,
        claim_read_timeouts: u32,
        credit_from_host_frames: u32,
        credit_to_host_frames: u32,
        accept_loop_timed_out: bool,
        handler_errors: Vec<String>,
        host_mux_sequences: Vec<u16>,
        saw_claim_stream_eof: bool,
    }

    #[derive(Debug)]
    struct FakeTcpSession {
        local_port: u16,
        remote_port: u16,
        snd_nxt: u32,
        rcv_nxt: u32,
        received: Vec<u8>,
        replied_to_query: bool,
    }

    #[derive(Debug, Default)]
    struct FakeMuxDevice {
        version: Option<MuxVersion>,
        tx_seq: u16,
        rx_expected: u16,
        session: Option<FakeTcpSession>,
    }

    impl FakeMuxDevice {
        fn handle_packet(
            &mut self,
            packet: &[u8],
            transcript: &Arc<Mutex<RealBackendTranscript>>,
        ) -> Result<Vec<Vec<u8>>, String> {
            let Some(version) = self.version else {
                let request = VersionPacket::decode(packet).map_err(|error| error.to_string())?;
                let negotiated = request.negotiated();
                self.version = Some(negotiated);
                self.tx_seq = 0;
                self.rx_expected = 0;
                let mut reply = vec![0u8; VERSION_PACKET_LEN];
                reply[4..8].copy_from_slice(&(VERSION_PACKET_LEN as u32).to_be_bytes());
                reply[8..12].copy_from_slice(&negotiated.wire_value().to_be_bytes());
                return Ok(vec![reply]);
            };

            let header = MuxHeader::decode(version, packet).map_err(|error| error.to_string())?;
            if header.protocol == Protocol::Version {
                return Err("unexpected version packet after negotiation".to_string());
            }
            transcript
                .lock()
                .unwrap()
                .host_mux_sequences
                .push(header.tx_seq);
            if version.is_sequenced() {
                if header.tx_seq != self.rx_expected {
                    return Err(format!(
                        "unexpected mux sequence {}, expected {}",
                        header.tx_seq, self.rx_expected
                    ));
                }
                self.rx_expected = self.rx_expected.wrapping_add(1);
            }
            if header.protocol != Protocol::Tcp {
                return Err(format!("unexpected mux protocol {:?}", header.protocol));
            }

            let payload = header
                .payload(version, packet)
                .map_err(|error| error.to_string())?;
            let tcp = TcpHeader::decode(payload).map_err(|error| error.to_string())?;
            let body = &payload[TCP_HEADER_LEN..];

            if tcp.is_reset() {
                self.session = None;
                return Ok(Vec::new());
            }

            if tcp.is_bare_syn() {
                if !body.is_empty() {
                    return Err("SYN carried payload".to_string());
                }
                self.session = Some(FakeTcpSession {
                    local_port: tcp.source_port,
                    remote_port: tcp.destination_port,
                    snd_nxt: 1,
                    rcv_nxt: tcp.sequence.wrapping_add(1),
                    received: Vec::new(),
                    replied_to_query: false,
                });
                let reply = TcpHeader {
                    source_port: tcp.destination_port,
                    destination_port: tcp.source_port,
                    sequence: 0,
                    acknowledgement: tcp.sequence.wrapping_add(1),
                    flags: flags::SYN_ACK,
                    window: 0x20_000,
                };
                return Ok(vec![self.queue_tcp(&encode_segment(reply, &[]))]);
            }

            if !tcp.is_bare_ack() {
                return Err(format!("unexpected TCP flags 0x{:02x}", tcp.flags));
            }

            let session = self
                .session
                .as_mut()
                .ok_or_else(|| "ACK arrived before SYN".to_string())?;
            if tcp.source_port != session.local_port || tcp.destination_port != session.remote_port
            {
                return Err(format!(
                    "unexpected TCP port pair {} -> {}",
                    tcp.source_port, tcp.destination_port
                ));
            }
            if tcp.sequence != session.rcv_nxt {
                return Err(format!(
                    "unexpected TCP sequence {}, expected {}",
                    tcp.sequence, session.rcv_nxt
                ));
            }

            let mut outbound_segments = Vec::new();
            if !body.is_empty() {
                session.received.extend_from_slice(body);
                session.rcv_nxt = session.rcv_nxt.wrapping_add(body.len() as u32);
            }

            let ack = TcpHeader {
                source_port: session.remote_port,
                destination_port: session.local_port,
                sequence: session.snd_nxt,
                acknowledgement: session.rcv_nxt,
                flags: flags::ACK,
                window: 0x20_000,
            };
            outbound_segments.push(encode_segment(ack, &[]));

            if !session.replied_to_query
                && let Some(request) = take_ramrod_message(&mut session.received)?
            {
                let request_name = request
                    .as_dictionary()
                    .and_then(|dict| dict.get("Request"))
                    .and_then(Value::as_string)
                    .ok_or_else(|| "identify request carried no Request key".to_string())?;
                if request_name != "QueryType" {
                    return Err(format!("unexpected identify request {request_name}"));
                }
                transcript.lock().unwrap().query_type_requests += 1;
                let reply = Value::Dictionary(plist::Dictionary::from_iter([
                    (
                        KEY_TYPE.to_string(),
                        Value::String(SERVICE_TYPE.to_string()),
                    ),
                    (
                        KEY_RESTORE_PROTOCOL_VERSION.to_string(),
                        Value::Integer(14.into()),
                    ),
                    (
                        "HardwareModel".to_string(),
                        Value::String("J274AP".to_string()),
                    ),
                ]));
                let payload = encode_message(&reply, PlistFormat::Binary)
                    .map_err(|error| error.to_string())?;
                let reply_header = TcpHeader {
                    source_port: session.remote_port,
                    destination_port: session.local_port,
                    sequence: session.snd_nxt,
                    acknowledgement: session.rcv_nxt,
                    flags: flags::ACK,
                    window: 0x20_000,
                };
                session.snd_nxt = session.snd_nxt.wrapping_add(payload.len() as u32);
                outbound_segments.push(encode_segment(reply_header, &payload));
                session.replied_to_query = true;
            }
            Ok(outbound_segments
                .into_iter()
                .map(|segment| self.queue_tcp(&segment))
                .collect())
        }

        fn queue_tcp(&mut self, segment: &[u8]) -> Vec<u8> {
            let total = HEADER_LEN_V2 + segment.len();
            let mut packet = vec![0u8; total];
            packet[0..4].copy_from_slice(&Protocol::Tcp.wire_value().to_be_bytes());
            packet[4..8].copy_from_slice(&(total as u32).to_be_bytes());
            packet[8..12].copy_from_slice(&DEVICE_MAGIC.to_be_bytes());
            packet[12..14].copy_from_slice(&self.tx_seq.to_be_bytes());
            packet[14..16].copy_from_slice(&self.rx_expected.wrapping_sub(1).to_be_bytes());
            packet[HEADER_LEN_V2..].copy_from_slice(segment);
            self.tx_seq = self.tx_seq.wrapping_add(1);
            packet
        }
    }

    impl FakeBackend {
        fn new(discovery: BackendDiscovery, claim: Arc<FakeClaimedRestore>) -> Self {
            Self::with_claims(discovery, vec![claim])
        }

        fn with_claims(discovery: BackendDiscovery, claims: Vec<Arc<FakeClaimedRestore>>) -> Self {
            Self {
                discovery: Mutex::new(discovery),
                claims: Mutex::new(
                    claims
                        .into_iter()
                        .map(|claim| (claim.device_id.clone(), claim))
                        .collect(),
                ),
            }
        }

        fn set_devices(&self, devices: Vec<DiscoveredDevice>) {
            self.discovery.lock().unwrap().devices = devices;
        }
    }

    struct FailingBackend {
        error: String,
    }

    impl RestoreBackend for FailingBackend {
        fn discover(&self) -> Result<BackendDiscovery, String> {
            Err(self.error.clone())
        }

        fn claim(
            &self,
            device_id: &str,
            _reporter: crate::restore::SharedReporter,
        ) -> Result<Arc<dyn ClaimedRestore>, String> {
            Err(format!("no claim while discovery is down: {device_id}"))
        }
    }

    impl RestoreBackend for FakeBackend {
        fn discover(&self) -> Result<BackendDiscovery, String> {
            Ok(self.discovery.lock().unwrap().clone())
        }

        fn claim(
            &self,
            device_id: &str,
            _reporter: crate::restore::SharedReporter,
        ) -> Result<Arc<dyn ClaimedRestore>, String> {
            if !self
                .discovery
                .lock()
                .unwrap()
                .devices
                .iter()
                .any(|device| device.id == device_id)
            {
                return Err(format!(
                    "The selected device is no longer available: {device_id}"
                ));
            }
            let mut claims = self.claims.lock().unwrap();
            let position = claims
                .iter()
                .position(|(claim_id, _)| claim_id == device_id)
                .ok_or_else(|| format!("No claim target is registered for {device_id}"))?;
            Ok(claims.remove(position).1)
        }
    }

    #[derive(Clone)]
    struct FakeClaimedRestore {
        device_id: String,
        detail: Option<String>,
        context: ClaimedBootContext,
        device: DeviceType,
        identify_error: Option<String>,
        outcome: FakeOutcome,
        detach_requests: Arc<Mutex<Vec<HostDetachDisposition>>>,
        aborts: Arc<AtomicU64>,
        captured_plans: Arc<Mutex<Vec<RestorePlan>>>,
    }

    #[derive(Clone)]
    enum FakeOutcome {
        Success,
        Failure,
        CancelAware,
    }

    impl FakeClaimedRestore {
        fn new(
            device_id: &str,
            detail: Option<&str>,
            outcome: FakeOutcome,
        ) -> Arc<FakeClaimedRestore> {
            Self::new_with_identify(device_id, detail, outcome, None)
        }

        fn new_with_identify_failure(
            device_id: &str,
            detail: Option<&str>,
            error: &str,
        ) -> Arc<FakeClaimedRestore> {
            Self::new_with_identify(
                device_id,
                detail,
                FakeOutcome::Success,
                Some(error.to_string()),
            )
        }

        fn new_with_identify(
            device_id: &str,
            detail: Option<&str>,
            outcome: FakeOutcome,
            identify_error: Option<String>,
        ) -> Arc<FakeClaimedRestore> {
            Arc::new(FakeClaimedRestore {
                device_id: device_id.to_string(),
                detail: detail.map(str::to_string),
                context: sample_context(),
                device: device_reporting("J274AP"),
                identify_error,
                outcome,
                detach_requests: Arc::new(Mutex::new(Vec::new())),
                aborts: Arc::new(AtomicU64::new(0)),
                captured_plans: Arc::new(Mutex::new(Vec::new())),
            })
        }

        fn last_plan(&self) -> Option<RestorePlan> {
            self.captured_plans.lock().unwrap().last().cloned()
        }

        fn detach_requests(&self) -> Vec<HostDetachDisposition> {
            self.detach_requests.lock().unwrap().clone()
        }

        fn abort_count(&self) -> u64 {
            self.aborts.load(Ordering::Relaxed)
        }
    }

    impl ClaimedRestore for FakeClaimedRestore {
        fn device_id(&self) -> &str {
            &self.device_id
        }

        fn detail(&self) -> Option<&str> {
            self.detail.as_deref()
        }

        fn context(&self) -> ClaimedBootContext {
            self.context.clone()
        }

        fn identify(&self) -> Result<DeviceType, String> {
            if let Some(error) = &self.identify_error {
                return Err(error.clone());
            }
            Ok(self.device.clone())
        }

        fn abort(&self) {
            self.aborts.fetch_add(1, Ordering::Relaxed);
        }

        fn detach_host(&self, disposition: HostDetachDisposition) -> HostDetachOutcome {
            self.detach_requests.lock().unwrap().push(disposition);
            HostDetachOutcome {
                was_connected: true,
                was_configured: true,
                disconnect_delivered: true,
                reset_delivered: false,
            }
        }

        fn run_restore(
            &self,
            _boot: RestoreBootContext,
            plan: RestorePlan,
            _image_size: u64,
            stop: Arc<AtomicBool>,
            _reporter: crate::restore::SharedReporter,
        ) -> RestoreOutcome {
            self.captured_plans.lock().unwrap().push(plan);
            match self.outcome {
                FakeOutcome::Success => RestoreOutcome::Ended {
                    summary: Box::new(fake_summary(true)),
                    bulk_transfers: 1,
                },
                FakeOutcome::Failure => RestoreOutcome::Ended {
                    summary: Box::new(fake_summary(false)),
                    bulk_transfers: 1,
                },
                FakeOutcome::CancelAware => {
                    while !stop.load(Ordering::Relaxed) {
                        thread::sleep(Duration::from_millis(10));
                    }
                    RestoreOutcome::Failed {
                        stage: "run-stopped-teardown".to_string(),
                        reason: "cancelled".to_string(),
                    }
                }
            }
        }
    }

    fn fake_summary(successful: bool) -> crate::ramrod::RestoreSummary {
        crate::ramrod::RestoreSummary {
            data_requests: 0,
            bulk_transfers: 1,
            async_data_requests: 0,
            async_waits: 0,
            bulk_declined: 0,
            bulk_empty: 0,
            progress_messages: 1,
            status_messages: 1,
            final_status_acks_sent: 1,
            checkpoints: 0,
            checkpoints_begun: 0,
            checkpoints_ended: 0,
            open_checkpoint: None,
            untyped_messages: 0,
            last_status: Some(if successful { 0 } else { 6 }),
            final_status: Some(FinalStatus {
                status: Some(if successful { 0 } else { 6 }),
                amr_error: Some(if successful { 0 } else { 6 }),
                successful: Some(successful),
                will_send_eof: Some(true),
                has_checkpoint_stats: false,
                has_log: !successful,
            }),
            guest_echoed_final_status: false,
            crash_logs: 0,
            crash_logs_written: 0,
            guest_log: None,
            checkpoint_error: None,
        }
    }

    #[test]
    fn a_checkpoint_error_is_the_plate_when_status_never_brought_the_log() {
        let mut summary = fake_summary(false);
        summary.status_messages = 0;
        summary.guest_log = None;
        summary.open_checkpoint = Some("verify_storage_for_update".into());
        summary.checkpoint_error = Some(
            "[0]D(Storage with invalid GPT header 0000000000000000 0000000000000000)[1]D(Possible blank device. Erase restore may be required.)"
                .into(),
        );
        assert_eq!(
            guest_failure_note(&summary),
            "Possible blank device. Erase restore may be required."
        );
    }

    #[test]
    fn a_checkpoint_error_without_the_known_needles_is_still_preferred_to_the_step_name() {
        let mut summary = fake_summary(false);
        summary.guest_log = None;
        summary.open_checkpoint = Some("verify_storage_for_update".into());
        summary.checkpoint_error = Some("AMRestoreErrorDomain/78".into());
        assert_eq!(guest_failure_note(&summary), "AMRestoreErrorDomain/78");
    }

    fn sample_context() -> ClaimedBootContext {
        let bridge = BridgeBootContext {
            staged_boot_manifest_sha384: [2; 48],
            ap_nonce: Some([1; BOOT_NONCE_HASH_BYTES]),
            fdr_element_index: 0,
            fdr_element_count: 0,
            fdr_trust_digest_sha256: None,
            fdr_trust_object: None,
            fdr_instance: None,
            fdr_material_path: None,
            sep_public_key_uncompressed: None,
            remote_signer_available: false,
        };
        ClaimedBootContext {
            restore: RestoreBootContext {
                ap_nonce: bridge.ap_nonce,
                ..RestoreBootContext::default()
            },
            bridge,
        }
    }

    fn device_reporting(model: &str) -> DeviceType {
        let mut body = Dictionary::new();
        body.insert(
            "HardwareModel".to_string(),
            Value::String(model.to_string()),
        );
        DeviceType {
            service_type: "com.apple.mobile.restored".to_string(),
            protocol_version: Some(14),
            body,
        }
    }

    fn build_identity(
        model: &str,
        variant: &str,
        restore_behavior: &str,
        installed_variant: &str,
        digest: &[u8],
    ) -> Value {
        Value::Dictionary(Dictionary::from_iter([
            ("ApBoardID".to_string(), Value::String("0x00".to_string())),
            ("ApChipID".to_string(), Value::String("0x00".to_string())),
            (
                "Info".to_string(),
                Value::Dictionary(Dictionary::from_iter([
                    ("DeviceClass".to_string(), Value::String(model.to_string())),
                    ("Variant".to_string(), Value::String(variant.to_string())),
                    (
                        "ContentEncoding".to_string(),
                        Value::String("aea".to_string()),
                    ),
                    (
                        "RestoreBehavior".to_string(),
                        Value::String(restore_behavior.to_string()),
                    ),
                ])),
            ),
            (
                "Manifest".to_string(),
                Value::Dictionary(Dictionary::from_iter([(
                    "OS".to_string(),
                    Value::Dictionary(Dictionary::from_iter([
                        ("Digest".to_string(), Value::Data(digest.to_vec())),
                        (
                            "Info".to_string(),
                            Value::Dictionary(Dictionary::from_iter([
                                (
                                    "Path".to_string(),
                                    Value::String("058-12345-001.dmg.aea".to_string()),
                                ),
                                (
                                    "HashMethod".to_string(),
                                    Value::String("sha2-384".to_string()),
                                ),
                            ])),
                        ),
                    ])),
                )])),
            ),
            (
                "VariantContents".to_string(),
                Value::Dictionary(Dictionary::from_iter([(
                    "InstalledOSVariant".to_string(),
                    Value::String(installed_variant.to_string()),
                )])),
            ),
        ]))
    }

    fn manifest(model: &str, digest: &[u8]) -> Value {
        Value::Dictionary(Dictionary::from_iter([(
            "BuildIdentities".to_string(),
            Value::Array(vec![
                build_identity(
                    model,
                    "macOS Customer",
                    "Erase",
                    "Customer Erase Install (IPSW)",
                    digest,
                ),
                build_identity(
                    model,
                    "Customer Erase Install (IPSW)",
                    "Erase",
                    "Customer Erase Install (IPSW)",
                    digest,
                ),
            ]),
        )]))
    }

    fn write_manifest(path: &Path, value: &Value) {
        let mut file = fs::File::create(path).unwrap();
        value.to_writer_xml(&mut file).unwrap();
    }

    fn write_restore_plist(path: &Path, boards: &[(&str, &str)], version: &str, build: &str) {
        let map = boards
            .iter()
            .map(|(board, platform)| {
                Value::Dictionary(Dictionary::from_iter([
                    ("BoardConfig".to_string(), Value::String((*board).into())),
                    ("Platform".to_string(), Value::String((*platform).into())),
                ]))
            })
            .collect();
        let value = Value::Dictionary(Dictionary::from_iter([
            (
                "ProductVersion".to_string(),
                Value::String(version.to_string()),
            ),
            (
                "ProductBuildVersion".to_string(),
                Value::String(build.to_string()),
            ),
            ("DeviceMap".to_string(), Value::Array(map)),
        ]));
        let mut file = fs::File::create(path).unwrap();
        value.to_writer_xml(&mut file).unwrap();
    }

    fn add_identity_component(manifest: &mut Value, name: &str, path: &str, digest: &[u8]) {
        let identities = manifest
            .as_dictionary_mut()
            .unwrap()
            .get_mut("BuildIdentities")
            .unwrap()
            .as_array_mut()
            .unwrap();
        for identity in identities {
            let components = identity
                .as_dictionary_mut()
                .unwrap()
                .get_mut("Manifest")
                .unwrap()
                .as_dictionary_mut()
                .unwrap();
            components.insert(
                name.to_string(),
                Value::Dictionary(Dictionary::from_iter([
                    ("Digest".to_string(), Value::Data(digest.to_vec())),
                    (
                        "Info".to_string(),
                        Value::Dictionary(Dictionary::from_iter([
                            ("Path".to_string(), Value::String(path.to_string())),
                            (
                                "HashMethod".to_string(),
                                Value::String("sha2-384".to_string()),
                            ),
                        ])),
                    ),
                ])),
            );
        }
    }

    fn os_identity(path: &str, digest: &[u8]) -> BuildIdentity {
        let identity_info = Dictionary::from_iter([(
            "ContentEncoding".to_string(),
            Value::String("aea".to_string()),
        )]);
        let component_info = Dictionary::from_iter([
            ("Path".to_string(), Value::String(path.to_string())),
            (
                "HashMethod".to_string(),
                Value::String("sha2-384".to_string()),
            ),
        ]);
        let component = Dictionary::from_iter([
            ("Digest".to_string(), Value::Data(digest.to_vec())),
            ("Info".to_string(), Value::Dictionary(component_info)),
        ]);
        BuildIdentity {
            index: 0,
            device_class: "j274ap".to_string(),
            variant: "macOS Customer".to_string(),
            info: identity_info,
            components: Some(Dictionary::from_iter([(
                "OS".to_string(),
                Value::Dictionary(component),
            )])),
        }
    }

    fn firmware_identity(component: &str, path: &str, digest: &[u8]) -> BuildIdentity {
        let component_info = Dictionary::from_iter([
            ("Path".to_string(), Value::String(path.to_string())),
            (
                "HashMethod".to_string(),
                Value::String("sha2-384".to_string()),
            ),
        ]);
        let body = Dictionary::from_iter([
            ("Digest".to_string(), Value::Data(digest.to_vec())),
            ("Info".to_string(), Value::Dictionary(component_info)),
        ]);
        BuildIdentity {
            index: 0,
            device_class: "j274ap".to_string(),
            variant: "Customer Erase Install (IPSW)".to_string(),
            info: Dictionary::from_iter([] as [(String, Value); 0]),
            components: Some(Dictionary::from_iter([(
                component.to_string(),
                Value::Dictionary(body),
            )])),
        }
    }

    fn device_record(id: &str) -> DeviceRecord {
        DeviceRecord {
            revision: 1,
            event: crate::bridge_protocol::DeviceEvent::Snapshot,
            broker_id: "0123456789abcdef0123456789abcdef".to_string(),
            device_id: id.to_string(),
            vm_id: id.to_string(),
            vm_name: "Recovery Device".to_string(),
            controller_index: 0,
            transport_kind: crate::bridge_protocol::TransportKind::Dwc3,
            state: BridgeDeviceState::Available,
            detail: Some("DFU".to_string()),
            out_max_packet_size: 512,
            max_packet_size: 0x8000,
            max_transfer_size: 0x7ffc,
        }
    }

    fn discovered_device_from_record(id: &str, record: DeviceRecord) -> DiscoveredDevice {
        DiscoveredDevice {
            id: id.to_string(),
            title: discovered_title(&record),
            detail: discovered_detail(&record),
            connection: discovered_connection(&record),
            state: discovered_state(record.state),
            connected: record.state != BridgeDeviceState::Removed,
        }
    }

    fn broker_device(id: &str) -> DiscoveredDevice {
        discovered_device_from_record(id, device_record(id))
    }

    fn wait_for<F>(service: &mut AppleRecoveryService, predicate: F) -> Vec<RecoveryEvent>
    where
        F: FnMut(&[RecoveryEvent]) -> bool,
    {
        wait_for_with_timeout(service, Duration::from_secs(3), predicate)
    }

    fn select_prepared_board(service: &mut AppleRecoveryService, class: &str) {
        let boards = wait_for(service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::CompatibleBoards { .. }))
        });
        assert!(
            !boards.iter().any(|event| {
                matches!(
                    event,
                    RecoveryEvent::FileRequested(spec) if spec.request_id == SYSTEM_IMAGE_REQUEST_ID
                )
            }),
            "the OS image must not be requested before a system is chosen: {boards:?}"
        );
        service
            .send(RecoveryCommand::SelectSystem {
                device_class: class.to_string(),
            })
            .unwrap();
    }

    fn wait_for_with_timeout<F>(
        service: &mut AppleRecoveryService,
        timeout: Duration,
        mut predicate: F,
    ) -> Vec<RecoveryEvent>
    where
        F: FnMut(&[RecoveryEvent]) -> bool,
    {
        let deadline = Instant::now() + timeout;
        let mut all = Vec::new();
        while Instant::now() < deadline {
            let events = service.poll();
            if !events.is_empty() {
                all.extend(events);
                if predicate(&all) {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(20));
        }
        all
    }

    fn test_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn temp_socket_dir() -> TempDir {
        let root = tempfile::Builder::new()
            .prefix("restore-service-bridge-")
            .tempdir_in("/tmp")
            .unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("restore-bridge-v1");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
        if let Some(message) = payload.downcast_ref::<&'static str>() {
            (*message).to_string()
        } else if let Some(message) = payload.downcast_ref::<String>() {
            message.clone()
        } else {
            "non-string panic payload".to_string()
        }
    }

    fn broker_socket_path(root: &TempDir) -> PathBuf {
        root.path()
            .join("restore-bridge-v1")
            .join("b-4242-0123456789abcdef0123456789abcdef.sock")
    }

    fn bind_listener(path: &Path) -> UnixListener {
        let listener = UnixListener::bind(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        listener
    }

    fn server_hello() -> ServerHello {
        ServerHello {
            selected_version: bridge_protocol::VERSION,
            server_name: "restore-host".to_string(),
            broker_id: "0123456789abcdef0123456789abcdef".to_string(),
            server_pid: 4242,
            capabilities: bridge_protocol::SERVER_CAPABILITIES
                .into_iter()
                .map(str::to_string)
                .collect(),
        }
    }

    #[derive(Default)]
    struct TestFrameReader {
        assembler: bridge_protocol::FrameAssembler,
        queued: VecDeque<RawRecord>,
    }

    impl TestFrameReader {
        fn try_take(&mut self) -> io::Result<Option<RawRecord>> {
            if let Some(frame) = self.queued.pop_front() {
                return Ok(Some(frame));
            }
            self.assembler.try_take()
        }

        fn push(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.queued.extend(self.assembler.push(bytes)?);
            Ok(())
        }
    }

    fn read_first_frame_or_eof(
        stream: &mut UnixStream,
        reader: &mut TestFrameReader,
    ) -> io::Result<Option<RawRecord>> {
        loop {
            if let Some(frame) = reader.try_take()? {
                return Ok(Some(frame));
            }
            let mut chunk = [0u8; 4096];
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                return Ok(None);
            }
            reader.push(&chunk[..read])?;
        }
    }

    fn read_first_frame_or_idle_timeout(
        stream: &mut UnixStream,
        reader: &mut TestFrameReader,
        timeout: Duration,
    ) -> io::Result<Option<RawRecord>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(frame) = reader.try_take()? {
                return Ok(Some(frame));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            stream.set_read_timeout(Some(remaining))?;
            let mut chunk = [0u8; 4096];
            match stream.read(&mut chunk) {
                Ok(0) => return Ok(None),
                Ok(read) => {
                    reader.push(&chunk[..read])?;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn write_frame(stream: &mut UnixStream, header: RecordHeader, payload: &[u8]) {
        let bytes = bridge_protocol::encode_record(header, payload).unwrap();
        stream.write_all(&bytes).unwrap_or_else(|error| {
            panic!(
                "failed to write {:?} request={} generation={} lease={}: {error}",
                header.kind, header.request_id, header.generation, header.lease_id
            )
        });
        stream.flush().unwrap_or_else(|error| {
            panic!(
                "failed to flush {:?} request={} generation={} lease={}: {error}",
                header.kind, header.request_id, header.generation, header.lease_id
            )
        });
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
        );
    }

    fn try_complete_server_handshake(
        stream: &mut UnixStream,
        hello: &ServerHello,
    ) -> io::Result<Option<TestFrameReader>> {
        let mut reader = TestFrameReader::default();
        let Some(client_hello) = read_first_frame_or_eof(stream, &mut reader)? else {
            return Ok(None);
        };
        let request_id = client_hello.header.request_id;
        let decoded: bridge_protocol::Hello =
            bridge_protocol::decode_json(&client_hello.payload).unwrap();
        bridge_protocol::validate_hello(&decoded).unwrap();
        let payload = bridge_protocol::encode_json(hello).unwrap();
        let header = RecordHeader {
            version: bridge_protocol::VERSION,
            kind: RecordKind::ServerHello,
            flags: 0,
            payload_len: 0,
            request_id,
            generation: 0,
            lease_id: 0,
        };
        let bytes = bridge_protocol::encode_record(header, &payload).unwrap();
        match stream.write_all(&bytes) {
            Ok(()) => {
                stream.flush().unwrap();
                Ok(Some(reader))
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::NotConnected
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn available_device_record() -> DeviceRecord {
        DeviceRecord {
            revision: 7,
            event: DeviceEvent::Snapshot,
            broker_id: "0123456789abcdef0123456789abcdef".to_string(),
            device_id: "opaque-1".to_string(),
            vm_id: "vm-1".to_string(),
            vm_name: "Recovery Device".to_string(),
            controller_index: 0,
            transport_kind: TransportKind::Dwc3,
            state: BridgeDeviceState::Available,
            detail: Some("DFU".to_string()),
            out_max_packet_size: 512,
            max_packet_size: 0x8000,
            max_transfer_size: 0x7ffc,
        }
    }

    fn sample_bridge_boot_context() -> BootContext {
        BootContext {
            staged_boot_manifest_sha384: [2; 48],
            ap_nonce: Some([1; BOOT_NONCE_HASH_BYTES]),
            fdr_element_index: 0,
            fdr_element_count: 0,
            fdr_trust_digest_sha256: None,
            fdr_trust_object: None,
            fdr_instance: None,
            fdr_material_path: None,
            sep_public_key_uncompressed: None,
            remote_signer_available: false,
        }
    }

    fn encode_segment(header: TcpHeader, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; TCP_HEADER_LEN + payload.len()];
        header.encode(&mut out).unwrap();
        out[TCP_HEADER_LEN..].copy_from_slice(payload);
        out
    }

    fn take_ramrod_message(buffer: &mut Vec<u8>) -> Result<Option<Value>, String> {
        if buffer.len() < 4 {
            return Ok(None);
        }
        let announced = u32::from_be_bytes(buffer[..4].try_into().unwrap()) as usize;
        let total = 4 + announced;
        if buffer.len() < total {
            return Ok(None);
        }
        let body = buffer[4..total].to_vec();
        buffer.drain(..total);
        Value::from_reader(Cursor::new(body))
            .map(Some)
            .map_err(|error| error.to_string())
    }

    fn serve_discovery_request(
        stream: &mut UnixStream,
        list: RawRecord,
        transcript: &Arc<Mutex<RealBackendTranscript>>,
    ) {
        assert_eq!(list.header.kind, RecordKind::List);
        transcript.lock().unwrap().list_requests += 1;
        write_json_frame(
            stream,
            RecordKind::Device,
            list.header.request_id,
            91,
            0,
            &available_device_record(),
        );
        write_json_frame(
            stream,
            RecordKind::ListEnd,
            list.header.request_id,
            0,
            0,
            &ListEnd {
                revision: 7,
                device_count: 1,
            },
        );
    }

    fn serve_claim_connection_after_claim(
        mut stream: UnixStream,
        mut reader: TestFrameReader,
        claim: RawRecord,
        transcript: Arc<Mutex<RealBackendTranscript>>,
    ) {
        assert_eq!(claim.header.kind, RecordKind::Claim);
        assert_eq!(claim.header.generation, 91);
        let claim_request: ClaimRequest = bridge_protocol::decode_json(&claim.payload).unwrap();
        {
            let mut transcript = transcript.lock().unwrap();
            transcript.claim_generations.push(claim.header.generation);
            transcript
                .claim_device_ids
                .push(claim_request.device_id.clone());
        }
        write_json_frame(
            &mut stream,
            RecordKind::Claimed,
            claim.header.request_id,
            91,
            9191,
            &Claimed {
                device_id: claim_request.device_id,
                transport_kind: TransportKind::Dwc3,
                out_max_packet_size: 512,
                max_packet_size: 0x8000,
                max_transfer_size: 0x7ffc,
                host_to_device_credits: 8,
                device_to_host_credits: 8,
            },
        );

        stream
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        let mut mux = FakeMuxDevice::default();
        let mut idle_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let frame = match reader.try_take().unwrap() {
                Some(frame) => frame,
                None => {
                    let mut chunk = [0u8; 4096];
                    let read = match stream.read(&mut chunk) {
                        Ok(read) => read,
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) =>
                        {
                            if Instant::now() >= idle_deadline {
                                transcript.lock().unwrap().claim_read_timeouts += 1;
                                break;
                            }
                            continue;
                        }
                        Err(error) => panic!("claim stream read failed: {error}"),
                    };
                    if read == 0 {
                        transcript.lock().unwrap().saw_claim_stream_eof = true;
                        break;
                    }
                    reader.push(&chunk[..read]).unwrap();
                    let Some(frame) = reader.try_take().unwrap() else {
                        continue;
                    };
                    idle_deadline = Instant::now() + Duration::from_secs(10);
                    frame
                }
            };
            match frame.header.kind {
                RecordKind::GetBootContext => {
                    transcript.lock().unwrap().boot_context_requests += 1;
                    write_frame(
                        &mut stream,
                        RecordHeader {
                            version: bridge_protocol::VERSION,
                            kind: RecordKind::BootContext,
                            flags: 0,
                            payload_len: 0,
                            request_id: frame.header.request_id,
                            generation: 91,
                            lease_id: 9191,
                        },
                        &sample_bridge_boot_context().encode().unwrap(),
                    );
                }
                RecordKind::PacketToDevice => {
                    assert_eq!(frame.header.request_id, 0);
                    let outbound = match mux.handle_packet(&frame.payload, &transcript) {
                        Ok(outbound) => outbound,
                        Err(error) => {
                            transcript.lock().unwrap().handler_errors.push(error);
                            break;
                        }
                    };
                    for packet in outbound {
                        write_frame(
                            &mut stream,
                            RecordHeader {
                                version: bridge_protocol::VERSION,
                                kind: RecordKind::PacketFromDevice,
                                flags: 0,
                                payload_len: 0,
                                request_id: 0,
                                generation: 91,
                                lease_id: 9191,
                            },
                            &packet,
                        );
                    }
                    let credit = bridge_protocol::encode_credit(bridge_protocol::CreditRecord {
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
                            lease_id: 9191,
                        },
                        &credit,
                    );
                    transcript.lock().unwrap().credit_to_host_frames += 1;
                }
                RecordKind::Credit => {
                    assert_eq!(frame.header.request_id, 0);
                    let credit = bridge_protocol::decode_credit(&frame.payload).unwrap();
                    assert_eq!(credit.direction, 2);
                    transcript.lock().unwrap().credit_from_host_frames += 1;
                }
                RecordKind::Detach => {
                    let detach: bridge_protocol::Detach =
                        bridge_protocol::decode_json(&frame.payload).unwrap();
                    transcript
                        .lock()
                        .unwrap()
                        .detach_outcomes
                        .push(detach.outcome);
                    write_json_frame(
                        &mut stream,
                        RecordKind::Detached,
                        frame.header.request_id,
                        91,
                        9191,
                        &Detached {
                            outcome: detach.outcome,
                            device_state: DetachedDeviceState::Detached,
                            detail: None,
                        },
                    );
                }
                RecordKind::Ping => {
                    let nonce = bridge_protocol::decode_ping_nonce(&frame.payload).unwrap();
                    write_frame(
                        &mut stream,
                        RecordHeader {
                            version: bridge_protocol::VERSION,
                            kind: RecordKind::Pong,
                            flags: 0,
                            payload_len: 0,
                            request_id: frame.header.request_id,
                            generation: 91,
                            lease_id: 9191,
                        },
                        &bridge_protocol::encode_ping_nonce(nonce),
                    );
                }
                RecordKind::Pong => {}
                other => {
                    write_json_frame(
                        &mut stream,
                        RecordKind::Error,
                        frame.header.request_id,
                        91,
                        9191,
                        &ErrorRecord {
                            code: "invalidRequest".to_string(),
                            detail: format!("unexpected frame {other:?}"),
                            fatal: true,
                            retryable: false,
                            current_revision: None,
                            current_generation: Some(91),
                        },
                    );
                }
            }
        }
    }

    fn serve_accepted_connection(
        mut stream: UnixStream,
        transcript: Arc<Mutex<RealBackendTranscript>>,
    ) {
        stream.set_nonblocking(false).unwrap();
        let hello = server_hello();
        let Some(mut reader) = try_complete_server_handshake(&mut stream, &hello).unwrap() else {
            transcript.lock().unwrap().handshake_only_closes += 1;
            return;
        };
        let Some(first) =
            read_first_frame_or_idle_timeout(&mut stream, &mut reader, Duration::from_millis(150))
                .unwrap()
        else {
            transcript.lock().unwrap().handshake_only_timeouts += 1;
            return;
        };
        match first.header.kind {
            RecordKind::List => {
                serve_discovery_request(&mut stream, first, &transcript);
            }
            RecordKind::Claim => {
                serve_claim_connection_after_claim(stream, reader, first, transcript);
            }
            other => panic!("unexpected initial broker frame {other:?}"),
        }
    }

    #[test]
    fn neutral_discovery_mapping_uses_device_facing_labels() {
        let mut record = device_record("unit-1");
        record.vm_name.clear();
        record.detail = None;
        record.vm_id = "source-a".to_string();

        let discovered = discovered_device_from_record("unit-1", record);
        assert_eq!(discovered.title, "Recovery device");
        assert_eq!(discovered.detail, "DWC3 controller 0 source source-a");
        assert_eq!(discovered.connection, "local socket (DWC3)");
        assert_eq!(
            discovered.state,
            crate::recovery_model::DeviceState::Available
        );
        assert!(discovered.connected);
    }

    #[test]
    fn stale_claim_id_is_rejected_against_live_backend_cache() {
        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            FakeClaimedRestore::new("vm-1", Some("claimed"), FakeOutcome::Success),
        ));
        let mut service = AppleRecoveryService::with_backend(backend.clone());

        let _ = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::DeviceDiscovered(_)))
        });

        backend.set_devices(Vec::new());
        service
            .send(RecoveryCommand::ClaimDevice {
                device_id: "vm-1".to_string(),
            })
            .unwrap();

        let rejected = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::ClaimRejected { device_id, .. } if device_id == "vm-1")
            })
        });
        assert!(rejected.iter().any(|event| matches!(
            event,
            RecoveryEvent::ClaimRejected { device_id, reason }
                if device_id == "vm-1" && reason.contains("no longer available")
        )));
    }

    #[test]
    fn mixed_transport_labels_keep_claim_projection_intact() {
        let mut first = device_record("dwc3");
        first.detail = None;
        let mut second = device_record("virtio");
        second.detail = None;
        second.transport_kind = crate::bridge_protocol::TransportKind::VirtioGadget;

        let mapped = map_devices(
            &[
                discovered_device_from_record("dwc3", first),
                discovered_device_from_record("virtio", second),
            ],
            Some("dwc3"),
        );
        assert_eq!(
            mapped.get("dwc3").unwrap().connection,
            "local socket (DWC3)"
        );
        assert_eq!(
            mapped.get("virtio").unwrap().connection,
            "local socket (virtio gadget)"
        );
        assert_eq!(
            mapped.get("dwc3").unwrap().state,
            crate::recovery_model::DeviceState::Claimed
        );
        assert_eq!(
            mapped.get("virtio").unwrap().state,
            crate::recovery_model::DeviceState::Busy
        );
    }

    #[test]
    fn nested_restore_assets_manifests_are_found_under_the_extract_root() {
        let directory = tempdir().unwrap();
        let nested = directory
            .path()
            .join("restore-assets")
            .join("Firmware")
            .join("Manifests")
            .join("restore");
        fs::create_dir_all(&nested).unwrap();
        let found = locate_global_manifest_source(directory.path())
            .unwrap()
            .expect("nested Firmware/Manifests/restore");
        assert_eq!(found, nested.canonicalize().unwrap());
        let firmware = locate_firmware_source(directory.path())
            .unwrap()
            .expect("Firmware parent of the nested manifests");
        assert_eq!(
            firmware,
            directory
                .path()
                .join("restore-assets")
                .join("Firmware")
                .canonicalize()
                .unwrap()
        );
    }

    #[test]
    fn overlay_tempdir_is_removed_when_dropped() {
        let overlay_path = {
            let overlay = create_overlay_root().unwrap();
            let path = overlay.path().to_path_buf();
            fs::write(path.join("sentinel"), b"staged").unwrap();
            assert!(path.exists());
            path
        };
        assert!(!overlay_path.exists());
    }

    #[test]
    fn traversal_manifest_path_is_rejected() {
        let directory = tempdir().unwrap();
        let digest = crate::crypto::sha384(b"image");
        for path in [
            "../outside.dmg.aea",
            "Firmware/../outside.dmg.aea",
            "./outside.dmg.aea",
            "/outside.dmg.aea",
            "C:\\outside.dmg.aea",
        ] {
            let error = match resolve_system_image(directory.path(), &os_identity(path, &digest)) {
                Err(error) => error,
                Ok(_) => panic!("unsafe OS path was accepted: {path}"),
            };
            assert!(
                error.contains("component")
                    || error.contains("relative path")
                    || error.contains("prefix"),
                "{path}: {error}"
            );
        }
    }

    #[test]
    fn symlink_selected_file_is_rejected() {
        let directory = tempdir().unwrap();
        let target = directory.path().join("manifest-target.plist");
        fs::write(&target, b"manifest").unwrap();
        let selected = directory.path().join(BUILD_MANIFEST_FILE_NAME);
        symlink(&target, &selected).unwrap();
        let pending = PendingRequest {
            spec: manifest_request_spec(),
            overlay_relative: PathBuf::from(BUILD_MANIFEST_FILE_NAME),
            expected_hash: None,
            source_root: None,
            component: BUILD_MANIFEST_FILE_NAME.to_string(),
            manifest_file_name: BUILD_MANIFEST_FILE_NAME.to_string(),
        };

        let error = match validate_pending_request(&pending, &selected) {
            Err(error) => error,
            Ok(_) => panic!("selected symlink was accepted"),
        };
        assert!(error.contains("symlink"), "{error}");
    }

    #[test]
    fn digest_file_reports_increasing_progress() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("payload.bin");
        let body = vec![0x5a; (1 << 20) * 2 + 4096];
        fs::write(&path, &body).unwrap();

        let mut fractions = Vec::new();
        let digest = digest_file_with_progress(&path, "sha2-256", |done, total| {
            let fraction = if total == 0 {
                1.0
            } else {
                done as f64 / total as f64
            };
            fractions.push(fraction);
        })
        .unwrap();

        assert_eq!(digest, hex_digest(&crate::crypto::sha256(&body)));
        assert!(
            fractions.len() >= 2,
            "expected multiple progress samples, got {fractions:?}"
        );
        assert!(
            fractions.windows(2).all(|pair| pair[1] >= pair[0]),
            "progress must not go backwards: {fractions:?}"
        );
        assert_eq!(*fractions.last().unwrap(), 1.0);
        assert!(
            fractions.iter().any(|value| *value > 0.0 && *value < 1.0),
            "expected a mid-file fraction, got {fractions:?}"
        );
    }

    #[test]
    fn symlink_inside_mirrored_tree_is_materialized() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("Firmware");
        fs::create_dir_all(&firmware).unwrap();
        let target = firmware.join("target.im4p");
        fs::write(&target, b"firmware").unwrap();
        symlink(&target, firmware.join("alias.im4p")).unwrap();
        let overlay = create_overlay_root().unwrap();

        let mirrored =
            mirror_optional_directory(directory.path(), Path::new("Firmware"), overlay.path())
                .unwrap()
                .unwrap();
        let alias = mirrored.join("alias.im4p");
        assert!(alias.is_file());
        assert!(
            !fs::symlink_metadata(&alias)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&alias).unwrap(), b"firmware");
    }

    #[test]
    fn symlink_escaping_the_ipsw_root_is_rejected() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("Firmware");
        fs::create_dir_all(&firmware).unwrap();
        let outside = tempdir().unwrap();
        let target = outside.path().join("secret.im4p");
        fs::write(&target, b"secret").unwrap();
        symlink(&target, firmware.join("alias.im4p")).unwrap();
        let overlay = create_overlay_root().unwrap();

        let error =
            mirror_optional_directory(directory.path(), Path::new("Firmware"), overlay.path())
                .expect_err("an escaping symlink must stop staging");
        assert!(
            error.contains("escapes") || error.contains("symlink"),
            "{error}"
        );
    }

    #[test]
    fn mirrored_tree_contains_real_directories_and_exact_files() {
        use std::os::unix::fs::MetadataExt as _;

        let directory = tempdir().unwrap();
        let source = directory.path().join("Firmware/nested/payload.im4p");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(&source, b"firmware payload").unwrap();
        let overlay = create_overlay_root().unwrap();

        let mirrored =
            mirror_optional_directory(directory.path(), Path::new("Firmware"), overlay.path())
                .unwrap()
                .unwrap();
        let nested = mirrored.join("nested");
        let destination = nested.join("payload.im4p");
        assert!(
            !fs::symlink_metadata(&mirrored)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            !fs::symlink_metadata(&nested)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            !fs::symlink_metadata(&destination)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let source_metadata = fs::metadata(&source).unwrap();
        let destination_metadata = fs::metadata(&destination).unwrap();
        assert_eq!(source_metadata.dev(), destination_metadata.dev());
        assert_eq!(source_metadata.ino(), destination_metadata.ino());
    }

    #[test]
    fn staging_an_accepted_copy_over_a_mirrored_firmware_file_is_allowed() {
        let extract = tempdir().unwrap();
        let firmware = extract.path().join("Firmware/SE");
        fs::create_dir_all(&firmware).unwrap();
        let mirrored_source = firmware.join("Stockholm7.RELEASE.sefw");
        fs::write(&mirrored_source, b"sefw-payload").unwrap();
        let overlay = create_overlay_root().unwrap();
        mirror_optional_directory(extract.path(), Path::new("Firmware"), overlay.path())
            .unwrap()
            .unwrap();

        let handed = tempdir().unwrap();
        let accepted_source = handed.path().join("Stockholm7.RELEASE.sefw");
        fs::write(&accepted_source, b"sefw-payload").unwrap();
        let relative = PathBuf::from("Firmware/SE/Stockholm7.RELEASE.sefw");
        let accepted = AcceptedFile {
            source: fs::canonicalize(&accepted_source).unwrap(),
            overlay_relative: relative.clone(),
            expected_hash: None,
            source_root: None,
        };
        materialize_accepted_file(&accepted, overlay.path(), &relative)
            .expect("a second copy of the same payload must stage over the mirrored Firmware file");
        assert_eq!(
            fs::read(overlay.path().join(&relative)).unwrap(),
            b"sefw-payload"
        );
    }

    #[test]
    fn staging_a_different_accepted_file_replaces_the_mirrored_copy() {
        let extract = tempdir().unwrap();
        let firmware = extract.path().join("Firmware/SE");
        fs::create_dir_all(&firmware).unwrap();
        fs::write(firmware.join("Stockholm7.RELEASE.sefw"), b"from-extract").unwrap();
        let overlay = create_overlay_root().unwrap();
        mirror_optional_directory(extract.path(), Path::new("Firmware"), overlay.path())
            .unwrap()
            .unwrap();

        let handed = tempdir().unwrap();
        let accepted_source = handed.path().join("Stockholm7.RELEASE.sefw");
        fs::write(&accepted_source, b"from-handoff").unwrap();
        let relative = PathBuf::from("Firmware/SE/Stockholm7.RELEASE.sefw");
        let accepted = AcceptedFile {
            source: fs::canonicalize(&accepted_source).unwrap(),
            overlay_relative: relative.clone(),
            expected_hash: None,
            source_root: None,
        };
        materialize_accepted_file(&accepted, overlay.path(), &relative).unwrap();
        assert_eq!(
            fs::read(overlay.path().join(&relative)).unwrap(),
            b"from-handoff"
        );
    }

    #[test]
    fn cross_filesystem_fallback_links_only_the_exact_file() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("payload.im4p");
        let destination = directory.path().join("staged.im4p");
        fs::write(&source, b"firmware payload").unwrap();
        let source = fs::canonicalize(source).unwrap();

        link_exact_file_with(&source, &destination, |_, _| {
            Err(io::Error::from_raw_os_error(libc::EXDEV))
        })
        .unwrap();

        assert!(
            fs::symlink_metadata(&destination)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(destination).unwrap(), source);
    }

    #[test]
    fn existing_hash_valid_os_candidate_is_accepted() {
        let directory = tempdir().unwrap();
        let body = b"resolved image";
        let digest = crate::crypto::sha384(body);
        let image = directory.path().join("OS__058-12345-001.dmg");
        fs::write(&image, body).unwrap();

        match resolve_system_image(
            directory.path(),
            &os_identity("058-12345-001.dmg.aea", &digest),
        )
        .unwrap()
        {
            ComponentResolution::Present {
                source, relative, ..
            } => {
                assert_eq!(source, fs::canonicalize(image).unwrap());
                assert_eq!(relative, PathBuf::from("OS__058-12345-001.dmg"));
            }
            ComponentResolution::Missing { .. } => panic!("valid OS image was not accepted"),
        }
    }

    #[test]
    fn missing_os_candidate_produces_one_hashed_file_request() {
        let directory = tempdir().unwrap();
        let digest = crate::crypto::sha384(b"expected image");

        match resolve_system_image(
            directory.path(),
            &os_identity("058-12345-001.dmg.aea", &digest),
        )
        .unwrap()
        {
            ComponentResolution::Missing { spec, relative, .. } => {
                assert_eq!(spec.request_id, SYSTEM_IMAGE_REQUEST_ID);
                assert!(spec.required);
                assert!(!spec.accept_directory);
                assert_eq!(spec.preferred_name.as_deref(), Some("058-12345-001.dmg"));
                assert!(
                    spec.accepted_names
                        .iter()
                        .any(|name| name == "OS__058-12345-001.dmg" || name == "058-12345-001.dmg")
                );
                assert!(
                    spec.accepted_names
                        .iter()
                        .all(|name| !name.contains('*') && !name.contains('/'))
                );
                assert_eq!(relative, PathBuf::from("058-12345-001.dmg.aea"));
                assert_eq!(
                    spec.expected_hash,
                    Some(HashExpectation {
                        algorithm: "sha2-384".to_string(),
                        value: hex_digest(&digest),
                    })
                );
            }
            ComponentResolution::Present { .. } => panic!("missing OS image was accepted"),
        }
    }

    #[test]
    fn valid_manually_supplied_os_outside_root_is_staged() {
        let extracted = tempdir().unwrap();
        let selected_directory = tempdir().unwrap();
        let body = b"expected image";
        let digest = crate::crypto::sha384(body);
        let ComponentResolution::Missing { spec, relative, .. } = resolve_system_image(
            extracted.path(),
            &os_identity("058-12345-001.dmg.aea", &digest),
        )
        .unwrap() else {
            panic!("missing OS image was accepted");
        };
        let selected = selected_directory.path().join("OS__058-12345-001.dmg");
        fs::write(&selected, body).unwrap();
        let pending = PendingRequest {
            expected_hash: spec.expected_hash.clone(),
            spec,
            overlay_relative: relative.clone(),
            source_root: None,
            component: "OS".to_string(),
            manifest_file_name: "058-12345-001.dmg.aea".to_string(),
        };
        let validated = validate_pending_request(&pending, &selected).unwrap();
        let accepted = AcceptedFile {
            source: validated.source,
            overlay_relative: relative.clone(),
            expected_hash: validated.content_hash,
            source_root: None,
        };
        let overlay = create_overlay_root().unwrap();

        let staged = materialize_accepted_file(&accepted, overlay.path(), &relative).unwrap();
        assert_eq!(staged, overlay.path().join(relative));
        assert!(fs::symlink_metadata(staged).unwrap().file_type().is_file());
    }

    #[test]
    fn hash_mismatched_os_candidate_remains_pending_and_is_rejected() {
        let directory = tempdir().unwrap();
        let digest = crate::crypto::sha384(b"AEA1expected image");
        let outside = tempdir().unwrap();
        let image = outside.path().join("058-12345-001.dmg.aea");
        fs::write(&image, b"AEA1wrong image").unwrap();
        let ComponentResolution::Missing { spec, relative, .. } = resolve_system_image(
            directory.path(),
            &os_identity("058-12345-001.dmg.aea", &digest),
        )
        .unwrap() else {
            panic!("hash-mismatched OS image was accepted");
        };
        let pending = PendingRequest {
            expected_hash: spec.expected_hash.clone(),
            spec,
            overlay_relative: relative,
            source_root: None,
            component: "OS".to_string(),
            manifest_file_name: "058-12345-001.dmg.aea".to_string(),
        };

        let error = match validate_pending_request(&pending, &image) {
            Err(error) => error,
            Ok(_) => panic!("hash-mismatched selection was accepted"),
        };
        assert!(
            error.contains("does not match") && error.contains("Select the correct file"),
            "{error}"
        );
    }

    #[test]
    fn decrypted_dmg_is_accepted_without_the_aea_digest() {
        let directory = tempdir().unwrap();
        let aea_digest = crate::crypto::sha384(b"AEA1ciphertext");
        let ComponentResolution::Missing { spec, relative, .. } = resolve_system_image(
            directory.path(),
            &os_identity("058-12345-001.dmg.aea", &aea_digest),
        )
        .unwrap() else {
            panic!("missing OS image was accepted");
        };
        let selected = directory.path().join("OS__058-12345-001.dmg");
        fs::write(&selected, b"decrypted restore image").unwrap();
        let pending = PendingRequest {
            expected_hash: spec.expected_hash.clone(),
            spec,
            overlay_relative: relative,
            source_root: None,
            component: "OS".to_string(),
            manifest_file_name: "058-12345-001.dmg.aea".to_string(),
        };
        let validated = validate_pending_request(&pending, &selected)
            .expect("decrypted dmg must be accepted without the aea digest");
        assert_ne!(
            validated
                .content_hash
                .as_ref()
                .map(|hash| hash.value.clone()),
            Some(hex_digest(&aea_digest))
        );
    }

    #[test]
    fn plist_is_rejected_when_a_restore_image_is_required() {
        let directory = tempdir().unwrap();
        let digest = crate::crypto::sha384(b"AEA1ciphertext");
        let ComponentResolution::Missing { spec, relative, .. } = resolve_system_image(
            directory.path(),
            &os_identity("058-12345-001.dmg.aea", &digest),
        )
        .unwrap() else {
            panic!("missing OS image was accepted");
        };
        let selected = directory.path().join("BuildManifest.plist");
        fs::write(&selected, b"<?xml version=\"1.0\"?>\n<plist></plist>\n").unwrap();
        let pending = PendingRequest {
            expected_hash: spec.expected_hash.clone(),
            spec,
            overlay_relative: relative,
            source_root: None,
            component: "OS".to_string(),
            manifest_file_name: "058-12345-001.dmg.aea".to_string(),
        };
        let error = match validate_pending_request(&pending, &selected) {
            Err(error) => error,
            Ok(_) => panic!("plist was accepted as a restore image"),
        };
        assert!(error.contains("is not a"), "{error}");
    }

    #[test]
    fn nested_firmware_is_asked_for_until_the_user_hands_a_folder() {
        let directory = tempdir().unwrap();
        let nested = directory
            .path()
            .join("fw")
            .join("25F80__MacOS")
            .join("Firmware")
            .join("dcp");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("ipad13dcp.im4p"), b"IM4P-dcp-bytes").unwrap();
        let digest = crate::crypto::sha384(b"not the file bytes");

        match resolve_identity_component(
            directory.path(),
            &firmware_identity("Ap,DCP2", "Firmware/dcp/ipad13dcp.im4p", &digest),
            "Ap,DCP2",
        )
        .unwrap()
        {
            ComponentResolution::Present { .. } => {
                panic!("collect must not silently take nested firmware; the path picker has to ask")
            }
            ComponentResolution::Missing { spec, relative, .. } => {
                assert_eq!(relative, PathBuf::from("Firmware/dcp/ipad13dcp.im4p"));
                assert_eq!(spec.preferred_name.as_deref(), Some("ipad13dcp.im4p"));
                assert!(
                    spec.accepted_names
                        .iter()
                        .any(|name| name == "ipad13dcp.im4p")
                );
            }
        }
    }

    #[test]
    fn firmware_im4p_is_accepted_without_a_file_digest() {
        let directory = tempdir().unwrap();
        let digest = crate::crypto::sha384(b"personalized digest");
        let ComponentResolution::Missing { spec, relative, .. } = resolve_identity_component(
            directory.path(),
            &firmware_identity("Ap,DCP2", "Firmware/dcp/ipad13dcp.im4p", &digest),
            "Ap,DCP2",
        )
        .unwrap() else {
            panic!("missing DCP payload was accepted");
        };
        assert_eq!(spec.preferred_name.as_deref(), Some("ipad13dcp.im4p"));
        assert!(
            spec.accepted_names
                .iter()
                .any(|name| name == "ipad13dcp.im4p")
        );
        let selected = directory.path().join("ipad13dcp.im4p");
        fs::write(&selected, b"IM4P-not-the-digest").unwrap();
        let pending = PendingRequest {
            expected_hash: spec.expected_hash.clone(),
            spec,
            overlay_relative: relative,
            source_root: None,
            component: "Ap,DCP2".to_string(),
            manifest_file_name: "ipad13dcp.im4p".to_string(),
        };
        validate_pending_request(&pending, &selected)
            .expect("firmware im4p must be accepted by name, not file digest");
    }

    #[test]
    fn board_specific_payloads_are_not_shared_across_identities() {
        let os_digest = crate::crypto::sha384(b"os");
        let left = os_identity("058-12345-001.dmg.aea", &os_digest);
        let mut right = left.clone();
        right.device_class = "j180dap".to_string();
        right.index = 1;
        let mut left_components = left.components.clone().unwrap();
        left_components.insert(
            "KernelCache".to_string(),
            Value::Dictionary(Dictionary::from_iter([
                ("Digest".to_string(), Value::Data(vec![1; 48])),
                (
                    "Info".to_string(),
                    Value::Dictionary(Dictionary::from_iter([(
                        "Path".to_string(),
                        Value::String("kernelcache.release.mac13g".to_string()),
                    )])),
                ),
            ])),
        );
        let mut right_components = right.components.clone().unwrap();
        right_components.insert(
            "KernelCache".to_string(),
            Value::Dictionary(Dictionary::from_iter([
                ("Digest".to_string(), Value::Data(vec![2; 48])),
                (
                    "Info".to_string(),
                    Value::Dictionary(Dictionary::from_iter([(
                        "Path".to_string(),
                        Value::String("kernelcache.release.mac14g".to_string()),
                    )])),
                ),
            ])),
        );
        let mut left = left;
        left.components = Some(left_components);
        right.components = Some(right_components);
        let identities = vec![left, right];
        assert!(shared_component_identity(&identities, "OS").is_some());
        assert!(shared_component_identity(&identities, "KernelCache").is_none());
    }

    #[test]
    fn discovery_claim_manifest_request_and_successful_restore_flow() {
        let directory = tempdir().unwrap();
        fs::create_dir_all(directory.path().join("Firmware/Manifests/restore")).unwrap();
        let image = directory.path().join("OS__058-12345-001.dmg");
        let image_body = b"resolved image";
        fs::write(&image, image_body).unwrap();
        let digest = crate::crypto::sha384(image_body);
        let manifest_path = directory.path().join("BuildManifest.plist");
        write_manifest(&manifest_path, &manifest("J274AP", &digest));

        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            FakeClaimedRestore::new("vm-1", Some("claimed"), FakeOutcome::Success),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);

        let discovery = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::DeviceDiscovered(_)))
        });
        assert!(discovery.iter().any(
            |event| matches!(event, RecoveryEvent::DeviceDiscovered(device) if device.id == "vm-1")
        ));

        service
            .send(RecoveryCommand::ClaimDevice {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let claimed = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        assert!(claimed.iter().any(|event| matches!(
            event,
            RecoveryEvent::ClaimAccepted { device_id, .. } if device_id == "vm-1"
        )));

        service
            .send(RecoveryCommand::ProvideFile {
                device_id: "vm-1".to_string(),
                request_id: MANIFEST_REQUEST_ID.to_string(),
                path: manifest_path.display().to_string(),
            })
            .unwrap();
        let after_manifest = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileAccepted { request_id, .. } if request_id == MANIFEST_REQUEST_ID)
            })
        });
        assert!(after_manifest.iter().any(|event| matches!(
            event,
            RecoveryEvent::FileAccepted { request_id, .. } if request_id == MANIFEST_REQUEST_ID
        )));
        assert!(!after_manifest.iter().any(|event| matches!(
            event,
            RecoveryEvent::FileRequested(spec) if spec.request_id == SYSTEM_IMAGE_REQUEST_ID
        )));

        service
            .send(RecoveryCommand::StartRestore {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let terminal = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::Succeeded { .. }))
        });
        assert!(
            terminal
                .iter()
                .any(|event| matches!(event, RecoveryEvent::Succeeded { .. }))
        );
    }

    #[test]
    fn real_backend_socket_discovery_claim_identify_and_release_detach() {
        let _env_guard = test_env_lock().lock().unwrap();
        let root = temp_socket_dir();
        let socket_path = broker_socket_path(&root);
        let listener = bind_listener(&socket_path);
        let transcript = Arc::new(Mutex::new(RealBackendTranscript::default()));
        let server_transcript = Arc::clone(&transcript);
        let server = thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_secs(20);
            let mut handlers = Vec::new();
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let connection_transcript = Arc::clone(&server_transcript);
                        handlers.push(thread::spawn(move || {
                            std::panic::catch_unwind(|| {
                                serve_accepted_connection(stream, connection_transcript);
                            })
                            .map_err(panic_message)
                        }));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        let snapshot = server_transcript.lock().unwrap();
                        if !snapshot.detach_outcomes.is_empty()
                            && snapshot.saw_claim_stream_eof
                            && snapshot.list_requests >= 2
                        {
                            drop(snapshot);
                            break;
                        }
                        drop(snapshot);
                        if Instant::now() >= deadline {
                            server_transcript.lock().unwrap().accept_loop_timed_out = true;
                            break;
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("listener accept failed: {error}"),
                }
            }
            for handler in handlers {
                match handler.join().unwrap() {
                    Ok(()) => {}
                    Err(error) => server_transcript.lock().unwrap().handler_errors.push(error),
                }
            }
            server_transcript.lock().unwrap().clone()
        });

        let discovery_dir = root.path().join("restore-bridge-v1");
        unsafe {
            std::env::set_var("APPLE_UTILS_RESTORE_BRIDGE_DIR", &discovery_dir);
        }

        let stable_id = "0123456789abcdef0123456789abcdef:opaque-1".to_string();
        let mut service = AppleRecoveryService::production();
        let discovered = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::DeviceDiscovered(device) if device.id == stable_id)
            })
        });
        assert!(discovered.iter().any(|event| matches!(
            event,
            RecoveryEvent::DeviceDiscovered(device)
                if device.id == stable_id
                    && device.title == "Recovery Device"
                    && device.detail == "DFU"
                    && device.connection == "local socket (DWC3)"
                    && device.state == crate::recovery_model::DeviceState::Available
        )));

        service
            .send(RecoveryCommand::ClaimDevice {
                device_id: stable_id.clone(),
            })
            .unwrap();
        let claimed = wait_for_with_timeout(&mut service, Duration::from_secs(10), |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        let transcript_snapshot = format!("{:?}", *transcript.lock().unwrap());
        assert!(
            claimed.iter().any(|event| matches!(
                event,
                RecoveryEvent::ClaimAccepted { device_id, .. } if device_id == &stable_id
            )),
            "events={claimed:?} transcript={transcript_snapshot}"
        );
        assert!(
            claimed.iter().any(|event| matches!(
                event,
                RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID
            )),
            "events={claimed:?} transcript={transcript_snapshot}"
        );

        service
            .send(RecoveryCommand::ReleaseDevice {
                device_id: stable_id.clone(),
            })
            .unwrap();
        let released = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::Released { device_id, .. } if device_id == &stable_id)
            })
        });
        assert!(released.iter().any(|event| matches!(
            event,
            RecoveryEvent::Released { device_id, note }
                if device_id == &stable_id && note.as_deref() == Some("Claim released")
        )));
        drop(service);
        unsafe {
            std::env::remove_var("APPLE_UTILS_RESTORE_BRIDGE_DIR");
        }

        let transcript = server.join().unwrap();
        assert!(transcript.list_requests >= 2, "{transcript:?}");
        assert_eq!(transcript.claim_generations, vec![91]);
        assert_eq!(transcript.claim_device_ids, vec!["opaque-1".to_string()]);
        assert_eq!(transcript.boot_context_requests, 1);
        assert_eq!(transcript.query_type_requests, 1);
        assert_eq!(
            transcript.detach_outcomes,
            vec![bridge_protocol::DetachOutcome::Cancelled]
        );
        assert!(transcript.saw_claim_stream_eof);
        assert!(!transcript.accept_loop_timed_out, "{transcript:?}");
        assert_eq!(transcript.claim_read_timeouts, 0, "{transcript:?}");
        assert!(transcript.handler_errors.is_empty(), "{transcript:?}");
        assert!(transcript.credit_to_host_frames >= 4, "{transcript:?}");
    }

    #[test]
    fn missing_system_image_is_requested_progressively() {
        let directory = tempdir().unwrap();
        fs::create_dir_all(directory.path().join("Firmware/Manifests/restore")).unwrap();
        let image_body = b"expected image";
        let digest = crate::crypto::sha384(image_body);
        let manifest_path = directory.path().join("BuildManifest.plist");
        write_manifest(&manifest_path, &manifest("J274AP", &digest));

        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            FakeClaimedRestore::new("vm-1", None, FakeOutcome::Success),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::DeviceDiscovered(_)))
        });
        service
            .send(RecoveryCommand::ClaimDevice {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: "vm-1".to_string(),
                request_id: MANIFEST_REQUEST_ID.to_string(),
                path: manifest_path.display().to_string(),
            })
            .unwrap();
        let events = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == SYSTEM_IMAGE_REQUEST_ID)
            })
        });
        assert!(events.iter().any(|event| {
            matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == SYSTEM_IMAGE_REQUEST_ID)
        }));

        service
            .send(RecoveryCommand::StartRestore {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let asked = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == SYSTEM_IMAGE_REQUEST_ID)
                    || matches!(event, RecoveryEvent::PhaseChanged { phase: SessionPhase::Collecting, .. })
            })
        });
        assert!(
            !asked
                .iter()
                .any(|event| matches!(event, RecoveryEvent::Failed { .. })),
            "start with pending files must ask for them, not fail: {asked:?}"
        );
        assert!(asked.iter().any(|event| {
            matches!(
                event,
                RecoveryEvent::FileRequested(spec) if spec.request_id == SYSTEM_IMAGE_REQUEST_ID
            ) || matches!(
                event,
                RecoveryEvent::PhaseChanged {
                    phase: SessionPhase::Collecting,
                    ..
                }
            )
        }));
    }

    #[test]
    fn manifest_can_be_prepared_before_a_device_is_claimed() {
        let directory = tempdir().unwrap();
        fs::create_dir_all(directory.path().join("Firmware/Manifests/restore")).unwrap();
        let digest = crate::crypto::sha384(b"expected image");
        let extra_digest = crate::crypto::sha384(b"extra payload");
        let extra_name = "Cryptex1,SystemOS";
        let mut value = manifest("J274AP", &digest);
        add_identity_component(
            &mut value,
            extra_name,
            "Image/Cryptex1SystemOS.dmg.aea",
            &extra_digest,
        );
        let manifest_path = directory.path().join("BuildManifest.plist");
        write_manifest(&manifest_path, &value);

        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            FakeClaimedRestore::new("vm-1", None, FakeOutcome::Success),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: String::new(),
                request_id: MANIFEST_REQUEST_ID.to_string(),
                path: manifest_path.display().to_string(),
            })
            .unwrap();
        select_prepared_board(&mut service, "J274AP");
        let events = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == SYSTEM_IMAGE_REQUEST_ID)
            })
        });
        assert!(events.iter().any(|event| {
            matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == SYSTEM_IMAGE_REQUEST_ID)
        }));
        assert!(events.iter().any(|event| {
            matches!(
                event,
                RecoveryEvent::FileRequested(spec) if spec.request_id == component_request_id(extra_name)
            )
        }));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::Failed { .. })),
            "{events:?}"
        );
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: String::new(),
                request_id: MANIFEST_REQUEST_ID.to_string(),
                path: manifest_path.display().to_string(),
            })
            .unwrap();
        let again = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileAccepted { request_id, .. } if request_id == MANIFEST_REQUEST_ID)
            })
        });
        assert!(
            !again
                .iter()
                .any(|event| matches!(event, RecoveryEvent::FileRejected { .. })),
            "a second handoff of an already-accepted file must not say the request is inactive: {again:?}"
        );
    }

    #[test]
    fn restore_plist_is_a_catalog_and_offers_upgrade_then_erase() {
        let directory = tempdir().unwrap();
        let digest = crate::crypto::sha384(b"expected image");
        let mut value = manifest("J274AP", &digest);
        value
            .as_dictionary_mut()
            .unwrap()
            .get_mut("BuildIdentities")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .insert(
                0,
                build_identity(
                    "J274AP",
                    "Customer Upgrade Install (IPSW)",
                    "Update",
                    "Customer Upgrade Install (IPSW)",
                    digest.as_slice(),
                ),
            );
        value
            .as_dictionary_mut()
            .unwrap()
            .get_mut("BuildIdentities")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(build_identity(
                "J999AP",
                "Customer Erase Install (IPSW)",
                "Erase",
                "Customer Erase Install (IPSW)",
                digest.as_slice(),
            ));
        write_manifest(&directory.path().join("BuildManifest.plist"), &value);
        write_restore_plist(
            &directory.path().join("Restore.plist"),
            &[("j274ap", "t8103")],
            "26.5.1",
            "25F80",
        );

        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            FakeClaimedRestore::new("vm-1", None, FakeOutcome::Success),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: String::new(),
                request_id: MANIFEST_REQUEST_ID.to_string(),
                path: directory.path().join("Restore.plist").display().to_string(),
            })
            .unwrap();
        let boards = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::CompatibleBoards { .. }))
        });
        let RecoveryEvent::CompatibleBoards {
            systems,
            product_version,
            product_build,
        } = boards
            .iter()
            .find(|event| matches!(event, RecoveryEvent::CompatibleBoards { .. }))
            .cloned()
            .expect("catalog")
        else {
            panic!("catalog");
        };
        assert_eq!(product_version.as_deref(), Some("26.5.1"));
        assert_eq!(product_build.as_deref(), Some("25F80"));
        assert_eq!(systems.len(), 1, "{systems:?}");
        assert!(
            systems[0].class.eq_ignore_ascii_case("j274ap"),
            "{systems:?}"
        );
        assert_eq!(systems[0].title, "Mac mini (M1, 2020)");

        service
            .send(RecoveryCommand::SelectSystem {
                device_class: "j274ap".to_string(),
            })
            .unwrap();
        let offered = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::CompatibleModes { .. }))
        });
        assert!(
            !offered.iter().any(|event| {
                matches!(
                    event,
                    RecoveryEvent::FileRequested(spec) if spec.request_id == SYSTEM_IMAGE_REQUEST_ID
                )
            }),
            "files must wait until erase or upgrade is chosen: {offered:?}"
        );
        let RecoveryEvent::CompatibleModes { modes } = offered
            .iter()
            .find(|event| matches!(event, RecoveryEvent::CompatibleModes { .. }))
            .cloned()
            .expect("modes")
        else {
            panic!("modes");
        };
        assert_eq!(modes, vec![RestoreMode::Update, RestoreMode::Erase]);

        service
            .send(RecoveryCommand::SelectRestoreMode {
                mode: RestoreMode::Update,
            })
            .unwrap();
        let collected = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == SYSTEM_IMAGE_REQUEST_ID)
                    || matches!(event, RecoveryEvent::ModeSelected { .. })
            })
        });
        assert!(
            collected.iter().any(|event| {
                matches!(
                    event,
                    RecoveryEvent::ModeSelected {
                        mode: RestoreMode::Update
                    }
                )
            }),
            "{collected:?}"
        );
    }

    #[test]
    fn an_ipados_manifest_lists_boards_without_a_macos_identity() {
        let directory = tempdir().unwrap();
        let digest = crate::crypto::sha384(b"ipad image");
        let value = Value::Dictionary(Dictionary::from_iter([
            (
                "ProductVersion".to_string(),
                Value::String("27.0".to_string()),
            ),
            (
                "ProductBuildVersion".to_string(),
                Value::String("24A5390f".to_string()),
            ),
            (
                "BuildIdentities".to_string(),
                Value::Array(vec![
                    build_identity(
                        "J617AP",
                        "Developer Erase Install (IPSW)",
                        "Erase",
                        "Developer Erase Install (IPSW)",
                        digest.as_slice(),
                    ),
                    build_identity(
                        "J617AP",
                        "Developer Upgrade Install (IPSW)",
                        "Update",
                        "Developer Upgrade Install (IPSW)",
                        digest.as_slice(),
                    ),
                    build_identity(
                        "J617AP",
                        "Recovery Customer Install",
                        "Erase",
                        "Recovery Customer Install",
                        digest.as_slice(),
                    ),
                ]),
            ),
        ]));
        write_manifest(&directory.path().join("BuildManifest.plist"), &value);

        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            FakeClaimedRestore::new("vm-1", None, FakeOutcome::Success),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: String::new(),
                request_id: MANIFEST_REQUEST_ID.to_string(),
                path: directory
                    .path()
                    .join("BuildManifest.plist")
                    .display()
                    .to_string(),
            })
            .unwrap();
        let boards = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::CompatibleBoards { .. }))
        });
        let RecoveryEvent::CompatibleBoards { systems, .. } = boards
            .iter()
            .find(|event| matches!(event, RecoveryEvent::CompatibleBoards { .. }))
            .cloned()
            .expect("catalog")
        else {
            panic!("catalog");
        };
        assert_eq!(systems.len(), 1, "{systems:?}");
        assert!(
            systems[0].class.eq_ignore_ascii_case("j617ap"),
            "{systems:?}"
        );

        service
            .send(RecoveryCommand::SelectSystem {
                device_class: "J617AP".to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::CompatibleModes { .. }))
        });
        service
            .send(RecoveryCommand::SelectRestoreMode {
                mode: RestoreMode::Erase,
            })
            .unwrap();
        let collected = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == SYSTEM_IMAGE_REQUEST_ID)
            })
        });
        assert!(
            collected.iter().any(|event| {
                matches!(
                    event,
                    RecoveryEvent::FileRequested(spec) if spec.request_id == SYSTEM_IMAGE_REQUEST_ID
                )
            }),
            "{collected:?}"
        );
    }

    #[test]
    fn picking_erase_is_what_start_restore_sends() {
        let directory = tempdir().unwrap();
        fs::create_dir_all(directory.path().join("Firmware/Manifests/restore")).unwrap();
        let image_body = b"expected image";
        let digest = crate::crypto::sha384(image_body);
        let mut value = manifest("J274AP", &digest);
        value
            .as_dictionary_mut()
            .unwrap()
            .get_mut("BuildIdentities")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .insert(
                0,
                build_identity(
                    "J274AP",
                    "Customer Upgrade Install (IPSW)",
                    "Update",
                    "Customer Upgrade Install (IPSW)",
                    digest.as_slice(),
                ),
            );
        write_manifest(&directory.path().join("BuildManifest.plist"), &value);
        write_restore_plist(
            &directory.path().join("Restore.plist"),
            &[("j274ap", "t8103")],
            "26.5.1",
            "25F80",
        );
        let image = directory.path().join("OS__058-12345-001.dmg");
        fs::write(&image, image_body).unwrap();

        let claim = FakeClaimedRestore::new("vm-1", None, FakeOutcome::Success);
        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            Arc::clone(&claim),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: String::new(),
                request_id: MANIFEST_REQUEST_ID.to_string(),
                path: directory.path().join("Restore.plist").display().to_string(),
            })
            .unwrap();
        select_prepared_board(&mut service, "j274ap");
        let _ = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::CompatibleModes { .. }))
        });
        service
            .send(RecoveryCommand::SelectRestoreMode {
                mode: RestoreMode::Erase,
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == SYSTEM_IMAGE_REQUEST_ID)
                    || matches!(
                        event,
                        RecoveryEvent::FileAccepted { request_id, .. }
                            if request_id == SYSTEM_IMAGE_REQUEST_ID
                    )
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: String::new(),
                request_id: SYSTEM_IMAGE_REQUEST_ID.to_string(),
                path: image.display().to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(
                    event,
                    RecoveryEvent::FileAccepted { request_id, .. }
                        if request_id == SYSTEM_IMAGE_REQUEST_ID
                )
            })
        });
        service
            .send(RecoveryCommand::ClaimDevice {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::ClaimAccepted { device_id, .. } if device_id == "vm-1")
            })
        });
        service
            .send(RecoveryCommand::StartRestore {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::Succeeded { .. }))
        });

        let plan = claim.last_plan().expect("StartRestore armed a plan");
        assert_eq!(
            plan.behavior,
            Some(RestoreBehavior::Erase),
            "the user's erase pick must be the restore that is started, not the upgrade default"
        );
    }

    #[test]
    fn a_payload_folder_fills_every_missing_file() {
        let directory = tempdir().unwrap();
        let image_body = b"expected image";
        let digest = crate::crypto::sha384(image_body);
        let extra_body = b"extra payload";
        let extra_digest = crate::crypto::sha384(extra_body);
        let extra_name = "Cryptex1,SystemOS";
        let mut value = manifest("J274AP", &digest);
        add_identity_component(
            &mut value,
            extra_name,
            "Image/Cryptex1SystemOS.dmg.aea",
            &extra_digest,
        );
        write_manifest(&directory.path().join("BuildManifest.plist"), &value);

        let payloads = tempdir().unwrap();
        fs::write(payloads.path().join("OS__058-12345-001.dmg"), image_body).unwrap();
        fs::write(payloads.path().join("Cryptex1SystemOS.dmg"), extra_body).unwrap();

        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            FakeClaimedRestore::new("vm-1", None, FakeOutcome::Success),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: String::new(),
                request_id: MANIFEST_REQUEST_ID.to_string(),
                path: directory
                    .path()
                    .join("BuildManifest.plist")
                    .display()
                    .to_string(),
            })
            .unwrap();
        select_prepared_board(&mut service, "J274AP");
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == SYSTEM_IMAGE_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: String::new(),
                request_id: SYSTEM_IMAGE_REQUEST_ID.to_string(),
                path: payloads.path().display().to_string(),
            })
            .unwrap();
        let events = wait_for(&mut service, |events| {
            let accepted = events
                .iter()
                .filter(|event| matches!(event, RecoveryEvent::FileAccepted { .. }))
                .count();
            accepted >= 2
                || events
                    .iter()
                    .any(|event| matches!(event, RecoveryEvent::FileRejected { .. }))
        });
        assert!(
            events.iter().any(|event| {
                matches!(
                    event,
                    RecoveryEvent::FileAccepted { request_id, .. }
                        if request_id == SYSTEM_IMAGE_REQUEST_ID
                )
            }),
            "{events:?}"
        );
        assert!(
            events.iter().any(|event| {
                matches!(
                    event,
                    RecoveryEvent::FileAccepted { request_id, .. }
                        if request_id == &component_request_id(extra_name)
                )
            }),
            "{events:?}"
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::FileRejected { .. })),
            "{events:?}"
        );
    }

    #[test]
    fn a_missing_trustcache_is_requested_instead_of_skipped() {
        let directory = tempdir().unwrap();
        let digest = crate::crypto::sha384(b"expected image");
        let cache_digest = crate::crypto::sha384(b"trustcache");
        let mut value = manifest("J274AP", &digest);
        add_identity_component(
            &mut value,
            "Cryptex1,SystemTrustCache",
            "Firmware/094-56679-090.dmg.aea.trustcache",
            &cache_digest,
        );
        write_manifest(&directory.path().join("BuildManifest.plist"), &value);

        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            FakeClaimedRestore::new("vm-1", None, FakeOutcome::Success),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: String::new(),
                request_id: MANIFEST_REQUEST_ID.to_string(),
                path: directory
                    .path()
                    .join("BuildManifest.plist")
                    .display()
                    .to_string(),
            })
            .unwrap();
        select_prepared_board(&mut service, "J274AP");
        let events = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(
                    event,
                    RecoveryEvent::FileRequested(spec)
                        if spec.request_id == component_request_id("Cryptex1,SystemTrustCache")
                )
            })
        });
        assert!(
            events.iter().any(|event| {
                matches!(
                    event,
                    RecoveryEvent::FileRequested(spec)
                        if spec.request_id == component_request_id("Cryptex1,SystemTrustCache")
                )
            }),
            "the trust cache must be asked for when it is not in the extract tree: {events:?}"
        );
    }

    #[test]
    fn autosearch_uses_the_folder_it_is_handed() {
        let catalog = tempdir().unwrap();
        let payloads = tempdir().unwrap();
        let image_body = b"expected image";
        let digest = crate::crypto::sha384(image_body);
        write_manifest(
            &catalog.path().join("BuildManifest.plist"),
            &manifest("J274AP", &digest),
        );
        fs::write(payloads.path().join("OS__058-12345-001.dmg"), image_body).unwrap();

        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            FakeClaimedRestore::new("vm-1", None, FakeOutcome::Success),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: String::new(),
                request_id: MANIFEST_REQUEST_ID.to_string(),
                path: catalog
                    .path()
                    .join("BuildManifest.plist")
                    .display()
                    .to_string(),
            })
            .unwrap();
        select_prepared_board(&mut service, "J274AP");
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == SYSTEM_IMAGE_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::Autosearch {
                device_id: String::new(),
                path: payloads.path().display().to_string(),
            })
            .unwrap();
        let events = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(
                    event,
                    RecoveryEvent::FileAccepted { request_id, .. }
                        if request_id == SYSTEM_IMAGE_REQUEST_ID
                )
            })
        });
        assert!(
            events.iter().any(|event| {
                matches!(
                    event,
                    RecoveryEvent::FileAccepted { request_id, .. }
                        if request_id == SYSTEM_IMAGE_REQUEST_ID
                )
            }),
            "{events:?}"
        );
    }

    #[test]
    fn missing_identity_payloads_are_requested_from_the_manifest() {
        let directory = tempdir().unwrap();
        fs::create_dir_all(directory.path().join("Firmware/Manifests/restore")).unwrap();
        let image_body = b"expected image";
        let digest = crate::crypto::sha384(image_body);
        let extra_digest = crate::crypto::sha384(b"extra payload");
        let extra_name = "Cryptex1,SystemOS";
        let mut value = manifest("J274AP", &digest);
        add_identity_component(
            &mut value,
            extra_name,
            "Image/Cryptex1SystemOS.dmg.aea",
            &extra_digest,
        );
        let manifest_path = directory.path().join("BuildManifest.plist");
        write_manifest(&manifest_path, &value);

        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            FakeClaimedRestore::new("vm-1", None, FakeOutcome::Success),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::DeviceDiscovered(_)))
        });
        service
            .send(RecoveryCommand::ClaimDevice {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: "vm-1".to_string(),
                request_id: MANIFEST_REQUEST_ID.to_string(),
                path: manifest_path.display().to_string(),
            })
            .unwrap();
        let events = wait_for(&mut service, |events| {
            let requested = events
                .iter()
                .filter_map(|event| match event {
                    RecoveryEvent::FileRequested(spec) => Some(spec.request_id.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            requested.contains(&SYSTEM_IMAGE_REQUEST_ID)
                && requested
                    .iter()
                    .any(|id| *id == component_request_id(extra_name))
        });
        let requested = events
            .iter()
            .filter_map(|event| match event {
                RecoveryEvent::FileRequested(spec) => Some(spec.request_id.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            requested.iter().any(|id| id == SYSTEM_IMAGE_REQUEST_ID),
            "{requested:?}"
        );
        assert!(
            requested
                .iter()
                .any(|id| id == &component_request_id(extra_name)),
            "{requested:?}"
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::Failed { .. })),
            "{events:?}"
        );
    }

    #[test]
    fn hash_mismatch_is_rejected_against_manifest_digest() {
        let directory = tempdir().unwrap();
        fs::create_dir_all(directory.path().join("Firmware/Manifests/restore")).unwrap();
        let good_body = b"expected image";
        let digest = crate::crypto::sha384(good_body);
        let manifest_path = directory.path().join("BuildManifest.plist");
        write_manifest(&manifest_path, &manifest("J274AP", &digest));
        let outside = tempdir().unwrap();
        let wrong_image = outside.path().join("058-12345-001.dmg.aea");
        fs::write(&wrong_image, b"AEA1wrong image").unwrap();

        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            FakeClaimedRestore::new("vm-1", None, FakeOutcome::Success),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::DeviceDiscovered(_)))
        });
        service
            .send(RecoveryCommand::ClaimDevice {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: "vm-1".to_string(),
                request_id: MANIFEST_REQUEST_ID.to_string(),
                path: manifest_path.display().to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == SYSTEM_IMAGE_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: "vm-1".to_string(),
                request_id: SYSTEM_IMAGE_REQUEST_ID.to_string(),
                path: wrong_image.display().to_string(),
            })
            .unwrap();
        let events = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::FileRejected { .. }))
        });
        assert!(events.iter().any(|event| matches!(
            event,
            RecoveryEvent::FileRejected { request_id, reason, .. }
                if request_id == SYSTEM_IMAGE_REQUEST_ID
                    && (reason.contains("does not match") || reason.contains("hash mismatch"))
                    && reason.contains("Select the correct file")
        )));
        let rejected_at = events
            .iter()
            .position(|event| {
                matches!(
                    event,
                    RecoveryEvent::FileRejected { request_id, .. }
                        if request_id == SYSTEM_IMAGE_REQUEST_ID
                )
            })
            .expect("os image was rejected");
        assert!(
            events[rejected_at + 1..].iter().any(|event| {
                matches!(
                    event,
                    RecoveryEvent::FileRequested(spec) if spec.request_id == SYSTEM_IMAGE_REQUEST_ID
                )
            }),
            "hash mismatch must re-ask for the same payload: {events:?}"
        );
    }

    #[test]
    fn hash_mismatch_before_claim_reasks_then_accepts_the_correct_file() {
        let directory = tempdir().unwrap();
        fs::create_dir_all(directory.path().join("Firmware/Manifests/restore")).unwrap();
        let good_body = b"expected image";
        let digest = crate::crypto::sha384(good_body);
        let manifest_path = directory.path().join("BuildManifest.plist");
        write_manifest(&manifest_path, &manifest("J274AP", &digest));
        let wrong_image = directory.path().join("058-12345-001.dmg.aea");
        fs::write(&wrong_image, b"AEA1wrong image").unwrap();
        let good_dir = tempdir().unwrap();
        let good_image = good_dir.path().join("OS__058-12345-001.dmg");
        fs::write(&good_image, good_body).unwrap();

        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            FakeClaimedRestore::new("vm-1", None, FakeOutcome::Success),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: String::new(),
                request_id: MANIFEST_REQUEST_ID.to_string(),
                path: manifest_path.display().to_string(),
            })
            .unwrap();
        select_prepared_board(&mut service, "J274AP");
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == SYSTEM_IMAGE_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: String::new(),
                request_id: SYSTEM_IMAGE_REQUEST_ID.to_string(),
                path: wrong_image.display().to_string(),
            })
            .unwrap();
        let rejected = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(
                    event,
                    RecoveryEvent::FileRejected { request_id, .. }
                        if request_id == SYSTEM_IMAGE_REQUEST_ID
                ) && events.iter().any(|event| {
                    matches!(
                        event,
                        RecoveryEvent::FileRequested(spec) if spec.request_id == SYSTEM_IMAGE_REQUEST_ID
                    )
                })
            })
        });
        assert!(
            !rejected
                .iter()
                .any(|event| matches!(event, RecoveryEvent::Failed { .. })),
            "a wrong file must stay on the request, not fail the session: {rejected:?}"
        );

        service
            .send(RecoveryCommand::ProvideFile {
                device_id: String::new(),
                request_id: SYSTEM_IMAGE_REQUEST_ID.to_string(),
                path: good_image.display().to_string(),
            })
            .unwrap();
        let accepted = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(
                    event,
                    RecoveryEvent::FileAccepted { request_id, .. }
                        if request_id == SYSTEM_IMAGE_REQUEST_ID
                )
            })
        });
        assert!(accepted.iter().any(|event| matches!(
            event,
            RecoveryEvent::FileAccepted { request_id, .. }
                if request_id == SYSTEM_IMAGE_REQUEST_ID
        )));
        assert!(
            !accepted.iter().any(|event| matches!(
                event,
                RecoveryEvent::FileRejected { request_id, .. }
                    if request_id == SYSTEM_IMAGE_REQUEST_ID
            )),
            "the matching file must be accepted after the wrong one was rejected: {accepted:?}"
        );
    }

    #[test]
    fn cancellation_reports_cancelled() {
        let directory = tempdir().unwrap();
        fs::create_dir_all(directory.path().join("Firmware/Manifests/restore")).unwrap();
        let image = directory.path().join("OS__058-12345-001.dmg");
        let image_body = b"resolved image";
        fs::write(&image, image_body).unwrap();
        let digest = crate::crypto::sha384(image_body);
        let manifest_path = directory.path().join("BuildManifest.plist");
        write_manifest(&manifest_path, &manifest("J274AP", &digest));

        let claim = FakeClaimedRestore::new("vm-1", None, FakeOutcome::CancelAware);
        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            Arc::clone(&claim),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::DeviceDiscovered(_)))
        });
        service
            .send(RecoveryCommand::ClaimDevice {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: "vm-1".to_string(),
                request_id: MANIFEST_REQUEST_ID.to_string(),
                path: manifest_path.display().to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileAccepted { request_id, .. } if request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::StartRestore {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        service
            .send(RecoveryCommand::CancelRestore {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let terminal = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::Cancelled { .. }))
        });
        assert!(
            terminal
                .iter()
                .any(|event| matches!(event, RecoveryEvent::Cancelled { .. }))
        );
        assert_eq!(
            claim.detach_requests(),
            vec![HostDetachDisposition::Cancelled]
        );
        assert_eq!(claim.abort_count(), 0);
    }

    #[test]
    fn idle_release_detaches_cancelled_once() {
        let claim = FakeClaimedRestore::new("vm-1", None, FakeOutcome::Success);
        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            Arc::clone(&claim),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::DeviceDiscovered(_)))
        });
        service
            .send(RecoveryCommand::ClaimDevice {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ReleaseDevice {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let events = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::Released { device_id, .. } if device_id == "vm-1")
            })
        });
        assert!(events.iter().any(|event| {
            matches!(event, RecoveryEvent::Released { device_id, .. } if device_id == "vm-1")
        }));
        assert_eq!(
            claim.detach_requests(),
            vec![HostDetachDisposition::Cancelled]
        );
        assert_eq!(claim.abort_count(), 0);
    }

    #[test]
    fn replacement_claim_detaches_previous_session_once() {
        let first = FakeClaimedRestore::new("vm-1", None, FakeOutcome::Success);
        let second = FakeClaimedRestore::new("vm-2", None, FakeOutcome::Success);
        let backend = Arc::new(FakeBackend::with_claims(
            BackendDiscovery {
                devices: vec![broker_device("vm-1"), broker_device("vm-2")],
            },
            vec![Arc::clone(&first), Arc::clone(&second)],
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events
                .iter()
                .filter(|event| matches!(event, RecoveryEvent::DeviceDiscovered(_)))
                .count()
                >= 2
        });
        service
            .send(RecoveryCommand::ClaimDevice {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::ClaimAccepted { device_id, .. } if device_id == "vm-1")
            })
        });
        service
            .send(RecoveryCommand::ClaimDevice {
                device_id: "vm-2".to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::ClaimAccepted { device_id, .. } if device_id == "vm-2")
            })
        });
        assert_eq!(
            first.detach_requests(),
            vec![HostDetachDisposition::Cancelled]
        );
        assert_eq!(first.abort_count(), 0);
        assert!(second.detach_requests().is_empty());
    }

    #[test]
    fn identify_failure_detaches_failed_once() {
        let claim =
            FakeClaimedRestore::new_with_identify_failure("vm-1", None, "identify exchange failed");
        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            Arc::clone(&claim),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::DeviceDiscovered(_)))
        });
        service
            .send(RecoveryCommand::ClaimDevice {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let events = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::ClaimRejected { device_id, .. } if device_id == "vm-1")
            })
        });
        assert!(events.iter().any(|event| {
            matches!(event, RecoveryEvent::ClaimRejected { device_id, reason } if device_id == "vm-1" && reason.contains("identify exchange failed"))
        }));
        assert_eq!(claim.detach_requests(), vec![HostDetachDisposition::Failed]);
        assert_eq!(claim.abort_count(), 0);
    }

    #[test]
    fn command_channel_disconnect_detaches_cancelled_once() {
        let directory = tempdir().unwrap();
        fs::create_dir_all(directory.path().join("Firmware/Manifests/restore")).unwrap();
        let image = directory.path().join("OS__058-12345-001.dmg");
        let image_body = b"resolved image";
        fs::write(&image, image_body).unwrap();
        let digest = crate::crypto::sha384(image_body);
        let manifest_path = directory.path().join("BuildManifest.plist");
        write_manifest(&manifest_path, &manifest("J274AP", &digest));

        let claim = FakeClaimedRestore::new("vm-1", None, FakeOutcome::CancelAware);
        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            Arc::clone(&claim),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::DeviceDiscovered(_)))
        });
        service
            .send(RecoveryCommand::ClaimDevice {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: "vm-1".to_string(),
                request_id: MANIFEST_REQUEST_ID.to_string(),
                path: manifest_path.display().to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileAccepted { request_id, .. } if request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::StartRestore {
                device_id: "vm-1".to_string(),
            })
            .unwrap();

        let replacement_tx = std::mem::replace(
            &mut service.command_tx,
            mpsc::sync_channel(COMMAND_QUEUE_BOUND).0,
        );
        drop(replacement_tx);
        service.worker.take().unwrap().join().unwrap();

        assert_eq!(
            claim.detach_requests(),
            vec![HostDetachDisposition::Cancelled]
        );
        assert_eq!(claim.abort_count(), 0);
    }

    #[test]
    fn device_loss_is_reported() {
        let claim = FakeClaimedRestore::new("vm-1", None, FakeOutcome::CancelAware);
        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            Arc::clone(&claim),
        ));
        let mut service = AppleRecoveryService::with_backend(backend.clone());
        let _ = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::DeviceDiscovered(_)))
        });
        service
            .send(RecoveryCommand::ClaimDevice {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        backend.set_devices(Vec::new());
        let events = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::DeviceDisconnected { .. }))
        });
        assert!(events.iter().any(|event| matches!(
            event,
            RecoveryEvent::DeviceDisconnected { device_id, .. } if device_id == "vm-1"
        )));
    }

    #[test]
    fn second_device_is_marked_busy_while_one_is_claimed() {
        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1"), broker_device("vm-2")],
            },
            FakeClaimedRestore::new("vm-1", None, FakeOutcome::Success),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events
                .iter()
                .filter(|event| matches!(event, RecoveryEvent::DeviceDiscovered(_)))
                .count()
                >= 2
        });
        service
            .send(RecoveryCommand::ClaimDevice {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let events = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(
                    event,
                    RecoveryEvent::DeviceDiscovered(device)
                        if device.id == "vm-2"
                            && device.state == crate::recovery_model::DeviceState::Busy
                )
            })
        });
        assert!(events.iter().any(|event| matches!(
            event,
            RecoveryEvent::DeviceDiscovered(device)
                if device.id == "vm-2"
                    && device.state == crate::recovery_model::DeviceState::Busy
        )));
    }

    #[test]
    fn successful_restore_detaches_complete() {
        let directory = tempdir().unwrap();
        fs::create_dir_all(directory.path().join("Firmware/Manifests/restore")).unwrap();
        let image = directory.path().join("OS__058-12345-001.dmg");
        let image_body = b"resolved image";
        fs::write(&image, image_body).unwrap();
        let digest = crate::crypto::sha384(image_body);
        let manifest_path = directory.path().join("BuildManifest.plist");
        write_manifest(&manifest_path, &manifest("J274AP", &digest));

        let claim = FakeClaimedRestore::new("vm-1", None, FakeOutcome::Success);
        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            Arc::clone(&claim),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::DeviceDiscovered(_)))
        });
        service
            .send(RecoveryCommand::ClaimDevice {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: "vm-1".to_string(),
                request_id: MANIFEST_REQUEST_ID.to_string(),
                path: manifest_path.display().to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileAccepted { request_id, .. } if request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::StartRestore {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::Succeeded { .. }))
        });
        assert_eq!(
            claim.detach_requests(),
            vec![HostDetachDisposition::Complete]
        );
        assert_eq!(claim.abort_count(), 0);
    }

    #[test]
    fn failed_restore_detaches_failed() {
        let directory = tempdir().unwrap();
        fs::create_dir_all(directory.path().join("Firmware/Manifests/restore")).unwrap();
        let image = directory.path().join("OS__058-12345-001.dmg");
        let image_body = b"resolved image";
        fs::write(&image, image_body).unwrap();
        let digest = crate::crypto::sha384(image_body);
        let manifest_path = directory.path().join("BuildManifest.plist");
        write_manifest(&manifest_path, &manifest("J274AP", &digest));

        let claim = FakeClaimedRestore::new("vm-1", None, FakeOutcome::Failure);
        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            Arc::clone(&claim),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::DeviceDiscovered(_)))
        });
        service
            .send(RecoveryCommand::ClaimDevice {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: "vm-1".to_string(),
                request_id: MANIFEST_REQUEST_ID.to_string(),
                path: manifest_path.display().to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileAccepted { request_id, .. } if request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::StartRestore {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::Failed { .. }))
        });
        assert_eq!(claim.detach_requests(), vec![HostDetachDisposition::Failed]);
        assert_eq!(claim.abort_count(), 0);
    }

    #[test]
    fn release_during_restore_detaches_cancelled_then_releases() {
        let directory = tempdir().unwrap();
        fs::create_dir_all(directory.path().join("Firmware/Manifests/restore")).unwrap();
        let image = directory.path().join("OS__058-12345-001.dmg");
        let image_body = b"resolved image";
        fs::write(&image, image_body).unwrap();
        let digest = crate::crypto::sha384(image_body);
        let manifest_path = directory.path().join("BuildManifest.plist");
        write_manifest(&manifest_path, &manifest("J274AP", &digest));

        let claim = FakeClaimedRestore::new("vm-1", None, FakeOutcome::CancelAware);
        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            Arc::clone(&claim),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::DeviceDiscovered(_)))
        });
        service
            .send(RecoveryCommand::ClaimDevice {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: "vm-1".to_string(),
                request_id: MANIFEST_REQUEST_ID.to_string(),
                path: manifest_path.display().to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileAccepted { request_id, .. } if request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::StartRestore {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        service
            .send(RecoveryCommand::ReleaseDevice {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let events = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::Released { device_id, .. } if device_id == "vm-1")
            })
        });
        assert!(
            events
                .iter()
                .any(|event| { matches!(event, RecoveryEvent::Cancelled { .. }) })
        );
        assert!(events.iter().any(|event| {
            matches!(event, RecoveryEvent::Released { device_id, .. } if device_id == "vm-1")
        }));
        assert_eq!(
            claim.detach_requests(),
            vec![HostDetachDisposition::Cancelled]
        );
        assert_eq!(claim.abort_count(), 0);
    }

    #[test]
    fn repeated_discovery_failures_emit_one_log() {
        let mut service = AppleRecoveryService::with_backend(Arc::new(FailingBackend {
            error: "Resource temporarily unavailable (os error 35)".into(),
        }));
        thread::sleep(Duration::from_millis(1300));
        let events = service.poll();
        let logs = events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    RecoveryEvent::Log {
                        message,
                        ..
                    } if message.contains("os error 35") || message.contains("busy")
                )
            })
            .count();
        assert_eq!(
            logs, 1,
            "discovery EAGAIN must not spam the activity log: {events:?}"
        );
    }

    #[test]
    fn shutdown_with_active_restore_detaches_cancelled() {
        let directory = tempdir().unwrap();
        fs::create_dir_all(directory.path().join("Firmware/Manifests/restore")).unwrap();
        let image = directory.path().join("OS__058-12345-001.dmg");
        let image_body = b"resolved image";
        fs::write(&image, image_body).unwrap();
        let digest = crate::crypto::sha384(image_body);
        let manifest_path = directory.path().join("BuildManifest.plist");
        write_manifest(&manifest_path, &manifest("J274AP", &digest));

        let claim = FakeClaimedRestore::new("vm-1", None, FakeOutcome::CancelAware);
        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: vec![broker_device("vm-1")],
            },
            Arc::clone(&claim),
        ));
        let mut service = AppleRecoveryService::with_backend(backend);
        let _ = wait_for(&mut service, |events| {
            events
                .iter()
                .any(|event| matches!(event, RecoveryEvent::DeviceDiscovered(_)))
        });
        service
            .send(RecoveryCommand::ClaimDevice {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileRequested(spec) if spec.request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::ProvideFile {
                device_id: "vm-1".to_string(),
                request_id: MANIFEST_REQUEST_ID.to_string(),
                path: manifest_path.display().to_string(),
            })
            .unwrap();
        let _ = wait_for(&mut service, |events| {
            events.iter().any(|event| {
                matches!(event, RecoveryEvent::FileAccepted { request_id, .. } if request_id == MANIFEST_REQUEST_ID)
            })
        });
        service
            .send(RecoveryCommand::StartRestore {
                device_id: "vm-1".to_string(),
            })
            .unwrap();
        drop(service);
        assert_eq!(
            claim.detach_requests(),
            vec![HostDetachDisposition::Cancelled]
        );
        assert_eq!(claim.abort_count(), 0);
    }

    fn handoff_worker() -> (ServiceWorker, Receiver<RecoveryEvent>) {
        let backend = Arc::new(FakeBackend::new(
            BackendDiscovery {
                devices: Vec::new(),
            },
            FakeClaimedRestore::new("vm-1", None, FakeOutcome::Success),
        ));
        let (command_tx, command_rx) = mpsc::sync_channel(COMMAND_QUEUE_BOUND);
        drop(command_tx);
        let (event_tx, event_rx) = mpsc::sync_channel(EVENT_QUEUE_BOUND);
        (ServiceWorker::new(backend, command_rx, event_tx), event_rx)
    }

    fn two_tree_manifest() -> Value {
        let mut value = manifest("J274AP", &crate::crypto::sha384(b"expected image"));
        add_identity_component(
            &mut value,
            "Ap,DCP2",
            "Firmware/dcp/ipad13dcp.im4p",
            &crate::crypto::sha384(b"dcp"),
        );
        value
    }

    fn drained(events: &Receiver<RecoveryEvent>) -> Vec<RecoveryEvent> {
        events.try_iter().collect()
    }

    #[test]
    fn prepared_folder_ignores_prefixed_sibling() {
        let root = tempdir().unwrap();
        let manifest_path = root.path().join(BUILD_MANIFEST_FILE_NAME);
        write_manifest(&manifest_path, &two_tree_manifest());

        let handed = root.path().join("Wanted");
        fs::create_dir_all(handed.join("restore-assets")).unwrap();
        fs::write(handed.join("restore-assets").join("notes.txt"), b"empty").unwrap();

        let sibling = root.path().join("Wanted-b");
        let sibling_dcp = sibling.join("Firmware").join("dcp");
        fs::create_dir_all(&sibling_dcp).unwrap();
        fs::write(sibling_dcp.join("ipad13dcp.im4p"), b"other-payload").unwrap();

        let (mut worker, events) = handoff_worker();
        worker.open_manifest_request();
        worker.provide_prepared_file(MANIFEST_REQUEST_ID, &manifest_path.to_string_lossy());
        worker.select_system("J274AP");
        let request_id = component_request_id("Ap,DCP2");
        assert!(
            worker
                .prepared
                .as_ref()
                .is_some_and(|prepared| prepared.pending.contains_key(&request_id))
        );
        let _ = drained(&events);

        worker.provide_prepared_file(&request_id, &handed.to_string_lossy());

        let prepared = worker.prepared.as_ref().unwrap();
        let sibling_root = sibling.canonicalize().unwrap();
        for accepted in prepared.accepted.values() {
            assert!(!accepted.source.starts_with(&sibling_root));
        }
        assert!(prepared.pending.contains_key(&request_id));
        let events = drained(&events);
        assert!(events.iter().any(|event| matches!(
            event,
            RecoveryEvent::FileRejected { request_id: rejected, reason, .. }
                if rejected == &request_id && reason.contains(&handed.display().to_string())
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            RecoveryEvent::FileRequested(spec) if spec.request_id == request_id
        )));
    }

    #[test]
    fn prepared_folder_uses_nested_payload() {
        let root = tempdir().unwrap();
        let manifest_path = root.path().join(BUILD_MANIFEST_FILE_NAME);
        write_manifest(&manifest_path, &two_tree_manifest());

        let handed = root.path().join("Wanted");
        let handed_dcp = handed.join("restore-assets").join("Firmware").join("dcp");
        fs::create_dir_all(&handed_dcp).unwrap();
        let wanted_payload = handed_dcp.join("ipad13dcp.im4p");
        fs::write(&wanted_payload, b"payload").unwrap();

        let sibling = root.path().join("Wanted-b");
        let sibling_dcp = sibling.join("Firmware").join("dcp");
        fs::create_dir_all(&sibling_dcp).unwrap();
        fs::write(sibling_dcp.join("ipad13dcp.im4p"), b"other-payload").unwrap();

        let (mut worker, events) = handoff_worker();
        worker.open_manifest_request();
        worker.provide_prepared_file(MANIFEST_REQUEST_ID, &manifest_path.to_string_lossy());
        worker.select_system("J274AP");
        let request_id = component_request_id("Ap,DCP2");
        let _ = drained(&events);

        worker.provide_prepared_file(&request_id, &handed.to_string_lossy());

        let accepted = worker
            .prepared
            .as_ref()
            .unwrap()
            .accepted
            .get(&request_id)
            .unwrap();
        assert_eq!(accepted.source, wanted_payload.canonicalize().unwrap());
        assert_ne!(
            accepted.source,
            sibling_dcp.join("ipad13dcp.im4p").canonicalize().unwrap()
        );
    }

    #[test]
    fn session_folder_ignores_prefixed_sibling() {
        let root = tempdir().unwrap();
        let manifest_path = root.path().join(BUILD_MANIFEST_FILE_NAME);
        write_manifest(&manifest_path, &two_tree_manifest());

        let handed = root.path().join("Wanted");
        fs::create_dir_all(handed.join("restore-assets")).unwrap();
        fs::write(handed.join("restore-assets").join("notes.txt"), b"empty").unwrap();

        let sibling = root.path().join("Wanted-b");
        let sibling_dcp = sibling.join("Firmware").join("dcp");
        fs::create_dir_all(&sibling_dcp).unwrap();
        fs::write(sibling_dcp.join("ipad13dcp.im4p"), b"other-payload").unwrap();

        let (mut worker, events) = handoff_worker();
        let claim = FakeClaimedRestore::new("vm-1", None, FakeOutcome::Success);
        let mut session = ClaimedSession::new(claim, sample_context(), device_reporting("J274AP"));
        session.reset_for_manifest_request();
        worker.session = Some(session);
        worker.provide_file(
            "vm-1",
            MANIFEST_REQUEST_ID,
            &manifest_path.to_string_lossy(),
        );
        let request_id = component_request_id("Ap,DCP2");
        assert!(
            worker
                .session
                .as_ref()
                .is_some_and(|session| session.pending_requests.contains_key(&request_id))
        );
        let _ = drained(&events);

        worker.provide_file("vm-1", &request_id, &handed.to_string_lossy());

        let session = worker.session.as_ref().unwrap();
        let sibling_root = sibling.canonicalize().unwrap();
        for accepted in session.accepted_files.values() {
            assert!(!accepted.source.starts_with(&sibling_root));
        }
        assert!(session.pending_requests.contains_key(&request_id));
        let events = drained(&events);
        assert!(events.iter().any(|event| matches!(
            event,
            RecoveryEvent::FileRejected { request_id: rejected, reason, .. }
                if rejected == &request_id && reason.contains(&handed.display().to_string())
        )));
    }

    #[test]
    fn other_manifest_is_not_global_source() {
        let root = tempdir().unwrap();
        fs::write(root.path().join(BUILD_MANIFEST_FILE_NAME), b"root-manifest").unwrap();
        let foreign = root.path().join("other");
        fs::create_dir_all(foreign.join("Firmware").join("Manifests").join("restore")).unwrap();
        fs::write(foreign.join(BUILD_MANIFEST_FILE_NAME), b"other-manifest").unwrap();

        assert_eq!(locate_global_manifest_source(root.path()).unwrap(), None);
        assert_eq!(locate_firmware_source(root.path()).unwrap(), None);
    }

    #[test]
    fn matching_manifest_is_global_source() {
        let root = tempdir().unwrap();
        let manifest_bytes = b"root-manifest";
        fs::write(root.path().join(BUILD_MANIFEST_FILE_NAME), manifest_bytes).unwrap();

        let handed = root.path().join("Wanted");
        let handed_manifests = handed
            .join("restore-assets")
            .join("Firmware")
            .join("Manifests")
            .join("restore");
        fs::create_dir_all(&handed_manifests).unwrap();
        fs::write(handed.join(BUILD_MANIFEST_FILE_NAME), manifest_bytes).unwrap();
        fs::write(
            handed.join("restore-assets").join(BUILD_MANIFEST_FILE_NAME),
            manifest_bytes,
        )
        .unwrap();

        let sibling = root.path().join("Wanted-b");
        fs::create_dir_all(sibling.join("Firmware").join("Manifests").join("restore")).unwrap();
        fs::write(sibling.join(BUILD_MANIFEST_FILE_NAME), b"other-manifest").unwrap();

        assert_eq!(
            locate_global_manifest_source(root.path()).unwrap(),
            Some(handed_manifests.canonicalize().unwrap())
        );
        assert_eq!(
            locate_firmware_source(root.path()).unwrap(),
            Some(
                handed
                    .join("restore-assets")
                    .join("Firmware")
                    .canonicalize()
                    .unwrap()
            )
        );
    }
}
