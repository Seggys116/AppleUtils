use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::crypto::{Sha256, Sha512, sha256, sha384};
use crate::ramrod::message::{
    KEY_BUILD_IDENTITY_DICT, KEY_FILE_DATA, KEY_FILE_DATA_DONE, KEY_VARIANT, streamed_done_message,
};
use crate::ramrod::{
    BOOT_NONCE_HASH_BYTES, BuildIdentity, BulkOutcome, Checkpoint, DataRequest, DataType,
    FDR_TRUST_OBJECT_TAGS, FinalStatus, GlobalManifestKind, IMAGE_NAME_GLOBAL_MANIFEST,
    IMAGE_NAME_RESTORE_VERSION, IMAGE_NAME_SYSTEM_VERSION, KEY_DATA_CHUNK_SIZE,
    KEY_GLOBAL_MANIFEST_OPTIONAL, KEY_GLOBAL_MANIFEST_PREFIX, KEY_IMAGE_LIST, KEY_IMAGE_NAME,
    KEY_IMAGE_TYPE, KEY_IS_RECOVERY_OS, NorPayload, ProviderError, RESTORE_VERSION_FILE_NAME,
    RestoreDataProvider, SYSTEM_VERSION_FILE_NAME, SessionObserver, StreamedObject, audit_ticket,
    build_nor_payload, corrupt_manifest_bytes, image_candidates, load_global_manifest,
    normalise_board, plan_nor_payload, raw_identity_for_variant,
    resolve_global_manifest_in_variants, validate_firmware_root, wants_flash_version_1,
    wrap_image4,
};

use super::plan::{FdrTrustDigest, hex_digest};
use super::report::{MUX_PREFIX, SharedReporter, lock, report};
use super::thread_class::{ThreadClass, with_thread_class};

pub const NOR_DATA_TYPE: &str = "NORData";

pub const FDR_TRUST_DATA_TYPE: &str = "FDRTrustData";

pub const FDR_MEMORY_COMMIT_DATA_TYPE: &str = "FDRMemoryCommit";

pub const KEY_FDR_TRUST_DATA: &str = "FDRTrustData";

pub const KEY_RECOVERY_OS_VERSION_DATA: &str = "RecoveryOSVersionData";

pub const KEY_BOOTED_OS_FDR_TRUST_DATA: &str = "BootedOSFDRTrustData";

pub const KEY_FDR_MEMORY_STORE_DATA: &str = "FDRMemoryStoreData";

fn describe_bulk_outcome(outcome: &BulkOutcome) -> String {
    match outcome {
        BulkOutcome::Served {
            bytes,
            blocks,
            initiates,
            metadata_requests,
            oob_requests,
            oob_bytes,
        } => format!(
            "bytes={bytes} blocks={blocks} initiates={initiates} metadata={metadata_requests} oob_requests={oob_requests} oob_bytes={oob_bytes}"
        ),
        BulkOutcome::Declined { reason } => format!("declined=\"{reason}\""),
    }
}

pub struct RamrodTrace {
    pub port: u16,
    pub armed_at_secs: f64,
    pub reporter: SharedReporter,
    last_operation: Option<i64>,
    last_checkpoint_begun: Option<String>,
    last_checkpoint_ended: Option<String>,
    checkpoints_seen: u64,
    checkpoints_begun: u64,
    checkpoints_ended: u64,
    sequence: u64,
}

impl RamrodTrace {
    pub fn new(port: u16, armed_at_secs: f64, reporter: SharedReporter) -> Self {
        Self {
            port,
            armed_at_secs,
            reporter,
            last_operation: None,
            last_checkpoint_begun: None,
            last_checkpoint_ended: None,
            checkpoints_seen: 0,
            checkpoints_begun: 0,
            checkpoints_ended: 0,
            sequence: 0,
        }
    }

    fn next_sequence(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }

    fn checkpoint_state(&self) -> String {
        format!(
            "checkpoints_seen={} begun={} ended={} open={} last_begun={} last_ended={}",
            self.checkpoints_seen,
            self.checkpoints_begun,
            self.checkpoints_ended,
            self.checkpoints_begun
                .saturating_sub(self.checkpoints_ended),
            self.last_checkpoint_begun.as_deref().unwrap_or("none"),
            self.last_checkpoint_ended.as_deref().unwrap_or("none")
        )
    }
}

fn describe_checkpoint(checkpoint: &Checkpoint<'_>) -> String {
    format!(
        "{} {}",
        checkpoint.id_display(),
        checkpoint.name.unwrap_or("unnamed")
    )
}

impl SessionObserver for RamrodTrace {
    fn on_stream_thread_class(&mut self, request: &DataRequest, class: ThreadClass) {
        let line = format!(
            "{MUX_PREFIX} result=stream-thread-class port={} at={:.3}s type={:?} class={class} competes_with_vcpu={} meaning=\"the thread that read this payload off disk and framed it ran in this class for the whole transfer, below the class the guest's vCPU threads hold, so a multi gigabyte transfer cannot take a performance core from a running guest; the value is the readback off the thread rather than the one that was asked for, so a platform that refused the change reports what it actually got\" detail=\"a true competes_with_vcpu is a defect: host work is never allowed to decide whether a guest stays up\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            class.competes_with_vcpu()
        );
        report(&self.reporter, "stream-thread-class", &line);
    }

    fn on_progress(&mut self, operation: Option<i64>, fraction: Option<f64>) {
        if operation.is_some() {
            self.last_operation = operation;
        }
        let sequence = self.next_sequence();
        let line = format!(
            "{MUX_PREFIX} result=restore-progress port={} at={:.3}s seq={sequence} operation={} fraction={:.4} meaning=\"the guest reported restore progress\" detail=\"\"",
            self.port,
            self.armed_at_secs,
            operation.unwrap_or(-1),
            fraction.unwrap_or(0.0)
        );
        report(&self.reporter, "restore-progress", &line);
        lock(&self.reporter).guest_progress(operation, fraction);
    }

    fn on_status(&mut self, status: i64, _body: &plist::Dictionary) {
        let sequence = self.next_sequence();
        let line = format!(
            "{MUX_PREFIX} result=restore-status port={} at={:.3}s seq={sequence} status={status} {} meaning=\"the guest reported a restore status\" detail=\"\"",
            self.port,
            self.armed_at_secs,
            self.checkpoint_state()
        );
        report(&self.reporter, "restore-status", &line);
        lock(&self.reporter).guest_status(status);
    }

    fn on_final_status(&mut self, status: &FinalStatus, _body: &plist::Dictionary) {
        let sequence = self.next_sequence();
        let line = format!(
            "{MUX_PREFIX} result=restore-final-status port={} at={:.3}s seq={sequence} outcome={} successful={} status={} amr_error={} checkpoint_stats={} log={} {} meaning=\"the one StatusMsg a restore sends, read whole; Successful is the criterion and the guest derives it from its own engine's accumulated code with the csel at 0x100017f24, so no host action sets it and a non-zero code names the step that failed\" detail=\"outcome=unreadable is a message that carried no Successful key, which is neither of the two outcomes and is not folded into either; the guest attaches its whole restore log only behind the failing branch, so log=true is itself a failure reading\"",
            self.port,
            self.armed_at_secs,
            status.outcome(),
            status
                .successful
                .map_or_else(|| "none".to_string(), |value| value.to_string()),
            status
                .status
                .map_or_else(|| "none".to_string(), |value| value.to_string()),
            status
                .amr_error
                .map_or_else(|| "none".to_string(), |value| value.to_string()),
            status.has_checkpoint_stats,
            status.has_log,
            self.checkpoint_state()
        );
        report(&self.reporter, "restore-final-status", &line);
    }

    fn on_final_status_acknowledged(&mut self, status: Option<i64>, bytes: usize) {
        let sequence = self.next_sequence();
        let line = format!(
            "{MUX_PREFIX} result=final-status-acked port={} at={:.3}s seq={sequence} status={} framed_bytes={bytes} meaning=\"the guest's final status is answered; it sits in cleanup_wait_status_received until this arrives and the answer is the same on a restore that succeeded and one that failed\" detail=\"sent MsgType=ReceivedFinalStatusMsg with no WillSendEOF, so the guest closes the connection itself with -shutdownWithError: and the next line for this port is the session ending\"",
            self.port,
            self.armed_at_secs,
            status.map_or_else(|| "unreadable".to_string(), |status| status.to_string())
        );
        report(&self.reporter, "final-status-acked", &line);
    }

    fn on_checkpoint(&mut self, checkpoint: &Checkpoint<'_>, body: &plist::Dictionary) {
        self.checkpoints_seen += 1;
        let step = describe_checkpoint(checkpoint);
        let phase = if checkpoint.ends_step() {
            self.checkpoints_ended += 1;
            self.last_checkpoint_ended = Some(step.clone());
            "end"
        } else {
            self.checkpoints_begun += 1;
            self.last_checkpoint_begun = Some(step.clone());
            "begin"
        };
        let sequence = self.next_sequence();
        let line = format!(
            "{MUX_PREFIX} result=restore-checkpoint port={} at={:.3}s seq={sequence} phase={phase} step=\"{step}\" result={} error={} warning={} info={} {} meaning=\"the guest's own checkpoint engine reported one step starting or finishing, on the host's clock and in order with the host's own sends; a begin whose end never arrives names the step a silent guest is still inside, which is the one fact a serial log on a second clock cannot settle\" detail=\"{}\"",
            self.port,
            self.armed_at_secs,
            checkpoint
                .result
                .map_or_else(|| "none".to_string(), |result| result.to_string()),
            checkpoint.has_error,
            checkpoint.has_warning,
            checkpoint.has_info,
            self.checkpoint_state(),
            describe_dictionary_entries(body)
        );
        report(&self.reporter, "restore-checkpoint", &line);
        if let Some(name) = checkpoint.name {
            lock(&self.reporter).guest_checkpoint(name, !checkpoint.ends_step());
        }
    }

    fn on_crash_log(
        &mut self,
        filename: &str,
        bytes: usize,
        path: Option<&std::path::Path>,
        error: Option<&str>,
    ) {
        let sequence = self.next_sequence();
        let line = format!(
            "{MUX_PREFIX} result=restore-crash-log port={} at={:.3}s seq={sequence} filename=\"{filename}\" bytes={bytes} written={} {} meaning=\"cleanup_send_crash_logs walked the guest's own ramdisk at /mnt5 on the way out of the restore and sent one message per .diag, .ips, .crash or .spin file it found; nothing is owed in reply and the bytes are written out here because the ramdisk goes away with the restore, so this message is the only copy of the file that outlives the run\" detail=\"{}\"",
            self.port,
            self.armed_at_secs,
            path.is_some(),
            path.map_or_else(
                || "path=none".to_string(),
                |path| format!("path=\"{}\"", path.display())
            ),
            error.unwrap_or("")
        );
        report(&self.reporter, "restore-crash-log", &line);
    }

    fn on_message(&mut self, msg_type: &str, body: &plist::Dictionary) {
        let sequence = self.next_sequence();
        let line = format!(
            "{MUX_PREFIX} result=restore-message port={} at={:.3}s seq={sequence} msg={msg_type} meaning=\"the guest sent a message this host does not model\" detail=\"{}\"",
            self.port,
            self.armed_at_secs,
            describe_dictionary_entries(body)
        );
        report(&self.reporter, "restore-message", &line);
    }

    fn on_data_request(&mut self, request: &DataRequest) {
        let argument_keys: Vec<&str> = request.arguments.keys().map(String::as_str).collect();
        let sequence = self.next_sequence();
        let line = format!(
            "{MUX_PREFIX} result=data-requested port={} at={:.3}s seq={sequence} type={:?} data_port={} async={} async_uuid={} args=[{}] {} meaning=\"the guest asked the host for restore data; async true is the guest's own confirmation that it accepted this host's AsyncDataRequestMsg and AsyncWait declaration, which is what makes restore_system_image run instead of being skipped\" detail=\"\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            request
                .data_port
                .map_or_else(|| "none".to_string(), |p| p.to_string()),
            request.asynchronous,
            request.async_context_uuid.as_deref().unwrap_or("none"),
            argument_keys.join(","),
            self.checkpoint_state()
        );
        report(&self.reporter, "data-requested", &line);
        lock(&self.reporter).data_request(request.data_type.wire_name(), false);
    }

    fn on_data_answered(&mut self, request: &DataRequest, keys: &[&str], bytes: usize) {
        let sequence = self.next_sequence();
        let line = format!(
            "{MUX_PREFIX} result=data-answered port={} at={:.3}s seq={sequence} type={:?} keys=[{}] framed_bytes={bytes} meaning=\"the reply to this request is on the wire; keys names what went back and framed_bytes is what was written including the length prefix\" detail=\"\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            keys.join(",")
        );
        report(&self.reporter, "data-answered", &line);
        lock(&self.reporter).data_request(request.data_type.wire_name(), true);
    }

    fn on_data_streamed(
        &mut self,
        request: &DataRequest,
        object_bytes: usize,
        messages: usize,
        framed_bytes: usize,
    ) {
        let sequence = self.next_sequence();
        let line = format!(
            "{MUX_PREFIX} result=data-streamed port={} at={:.3}s seq={sequence} type={:?} object_bytes={object_bytes} messages={messages} framed_bytes={framed_bytes} meaning=\"the answer to this request went out as a streamed object, which is how the guest reads this type: messages carrying FileData until one sets FileDataDone, with DataSize on the first; object_bytes of zero is a well formed transfer that delivered nothing and the guest reads it as the object being absent\" detail=\"\"",
            self.port, self.armed_at_secs, request.data_type,
        );
        report(&self.reporter, "data-streamed", &line);
        lock(&self.reporter).data_request(request.data_type.wire_name(), true);
    }

    fn on_bulk_serving(&mut self, request: &DataRequest, port: u16) {
        let sequence = self.next_sequence();
        let line = format!(
            "{MUX_PREFIX} result=bulk-serving port={} at={:.3}s seq={sequence} type={:?} data_port={port} async={} async_uuid={} {} meaning=\"the host is about to dial the guest port for this transfer; nothing has been streamed yet and the matching bulk-served or bulk-served-empty line does not arrive until the whole transfer has finished\" detail=\"every line between this one and its outcome line happened while the transfer was in flight\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            request.asynchronous,
            request.async_context_uuid.as_deref().unwrap_or("none"),
            self.checkpoint_state()
        );
        report(&self.reporter, "bulk-serving", &line);
    }

    fn on_bulk_served(&mut self, request: &DataRequest, port: u16, outcome: &BulkOutcome) {
        let sequence = self.next_sequence();
        let line = format!(
            "{MUX_PREFIX} result=bulk-served port={} at={:.3}s seq={sequence} type={:?} data_port={port} async={} async_uuid={} {} meaning=\"the transfer the guest opened a port for finished and put payload bytes on the wire; nothing goes back on the control connection for one of these, so bytes here is the only record that the image was delivered\" detail=\"\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            request.asynchronous,
            request.async_context_uuid.as_deref().unwrap_or("none"),
            describe_bulk_outcome(outcome)
        );
        report(&self.reporter, "bulk-served", &line);
        lock(&self.reporter).data_request(request.data_type.wire_name(), true);
    }

    fn on_bulk_served_empty(&mut self, request: &DataRequest, port: u16, outcome: &BulkOutcome) {
        let sequence = self.next_sequence();
        let line = format!(
            "{MUX_PREFIX} result=bulk-served-empty port={} at={:.3}s seq={sequence} type={:?} data_port={port} async={} async_uuid={} {} meaning=\"the guest opened a port for this image, the ASR session ran to a normal end, and not one payload byte was streamed; this is a delivery that did not happen and is never counted as a served transfer, because a guest that carries on from here is carrying on against content it never received\" detail=\"the counts say where it stopped: initiates without a payload is a client that asked what the image was and then closed, and an oob_requests run with no payload is a validation pass that was not followed by the payload command\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            request.asynchronous,
            request.async_context_uuid.as_deref().unwrap_or("none"),
            describe_bulk_outcome(outcome)
        );
        report(&self.reporter, "bulk-served-empty", &line);
        lock(&self.reporter).data_request(request.data_type.wire_name(), false);
    }

    fn on_bulk_declined(&mut self, request: &DataRequest, port: u16, reason: &str) {
        let sequence = self.next_sequence();
        let line = format!(
            "{MUX_PREFIX} result=bulk-declined port={} at={:.3}s seq={sequence} type={:?} data_port={port} async={} async_uuid={} meaning=\"the guest opened a port for a bulk transfer this host holds no genuine file for; no bytes were streamed, no other image was put on that port, and the session continues so the guest reaches its own failure at the step that reads what never arrived\" detail=\"{reason}\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            request.asynchronous,
            request.async_context_uuid.as_deref().unwrap_or("none")
        );
        report(&self.reporter, "bulk-declined", &line);
        lock(&self.reporter).data_request(request.data_type.wire_name(), false);
    }

    fn on_async_wait(&mut self, uuid: Option<&str>, body: &plist::Dictionary) {
        let sequence = self.next_sequence();
        let line = format!(
            "{MUX_PREFIX} result=async-wait port={} at={:.3}s seq={sequence} uuid={} {} meaning=\"the guest blocked on an outstanding asynchronous operation and named it; no answer is due on the control connection, because the sender at 0x100025e7c writes through the do-not-wait path and what releases the guest is the transfer on that operation's own data port completing\" detail=\"{}\"",
            self.port,
            self.armed_at_secs,
            uuid.unwrap_or("none"),
            self.checkpoint_state(),
            describe_dictionary_entries(body)
        );
        report(&self.reporter, "async-wait", &line);
    }

    fn on_control_send_failed(&mut self, request: &DataRequest, error: &str) {
        let sequence = self.next_sequence();
        let line = format!(
            "{MUX_PREFIX} result=nor-write-failed port={} at={:.3}s seq={sequence} type={:?} meaning=\"the control connection reset while this reply was being written, so copy_restore_sep never received the payload and load_sep_os fails; this line is the send failure, not a missing RestoreSEP file\" detail=\"{error}\"",
            self.port, self.armed_at_secs, request.data_type,
        );
        report(&self.reporter, "nor-write-failed", &line);
    }

    fn on_data_unanswered(&mut self, request: &DataRequest, error: &ProviderError) {
        let sequence = self.next_sequence();
        let line = format!(
            "{MUX_PREFIX} result=data-unanswered port={} at={:.3}s seq={sequence} type={:?} data_port={} args=[{}] last_operation={} {} meaning=\"the guest asked for something this host could not supply, so nothing was written and the session ends here; this line is the only record of what the request actually carried, because the session dies immediately after it\" detail=\"{error}\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            request
                .data_port
                .map_or_else(|| "none".to_string(), |p| p.to_string()),
            describe_dictionary_entries(&request.arguments),
            self.last_operation
                .map_or_else(|| "none".to_string(), |operation| operation.to_string()),
            self.checkpoint_state()
        );
        report(&self.reporter, "data-unanswered", &line);
        lock(&self.reporter).data_request(request.data_type.wire_name(), false);
    }
}

fn describe_dictionary_entries(dict: &plist::Dictionary) -> String {
    dict.iter()
        .map(|(key, value)| format!("{key}={}", describe_plist_value(value)))
        .collect::<Vec<_>>()
        .join(",")
}

fn describe_plist_value(value: &plist::Value) -> String {
    match value {
        plist::Value::String(text) => text.clone(),
        plist::Value::Integer(integer) => integer.to_string(),
        plist::Value::Real(real) => real.to_string(),
        plist::Value::Boolean(flag) => flag.to_string(),
        plist::Value::Data(bytes) => format!("<data:{}bytes>", bytes.len()),
        plist::Value::Array(items) => format!("<array:{}items>", items.len()),
        plist::Value::Dictionary(nested) => format!("<dict:{}keys>", nested.len()),
        plist::Value::Date(date) => format!("{date:?}"),
        _ => "<unmodelled-plist-value>".to_string(),
    }
}

#[derive(Clone, Debug)]
pub struct RestoreVariants {
    pub install: String,
    pub recovery_os: String,
}

impl RestoreVariants {
    #[must_use]
    pub fn os_order(&self) -> Vec<&str> {
        vec![self.install.as_str(), self.recovery_os.as_str()]
    }

    #[must_use]
    pub fn recovery_order(&self) -> Vec<&str> {
        vec![self.recovery_os.as_str()]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TicketRole {
    Os,
    RecoveryOs,
}

impl TicketRole {
    fn label(self) -> &'static str {
        match self {
            Self::Os => "os",
            Self::RecoveryOs => "recovery-os",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TicketRequest {
    role: TicketRole,
    kind: GlobalManifestKind,
}

pub struct GlobalManifestProvider {
    root: PathBuf,
    variants: RestoreVariants,
    hardware_model: String,
    corrupt: bool,
    port: u16,
    armed_at_secs: f64,
    logged: std::collections::HashSet<String>,
    staged_boot_manifest_sha384: Option<[u8; 48]>,
    fdr_trust_digest: Option<FdrTrustDigest>,
    ap_nonce: Option<[u8; BOOT_NONCE_HASH_BYTES]>,
    reporter: SharedReporter,
}

impl GlobalManifestProvider {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        root: PathBuf,
        variants: RestoreVariants,
        hardware_model: String,
        corrupt: bool,
        port: u16,
        armed_at_secs: f64,
        staged_boot_manifest_sha384: Option<[u8; 48]>,
        fdr_trust_digest: Option<FdrTrustDigest>,
        ap_nonce: Option<[u8; BOOT_NONCE_HASH_BYTES]>,
        reporter: &SharedReporter,
    ) -> Self {
        Self {
            root,
            variants,
            hardware_model,
            corrupt,
            port,
            armed_at_secs,
            staged_boot_manifest_sha384,
            fdr_trust_digest,
            ap_nonce,
            logged: std::collections::HashSet::new(),
            reporter: Arc::clone(reporter),
        }
    }

    fn classify(request: &DataRequest) -> Option<TicketRequest> {
        let type_name = request.data_type.wire_name();
        let mentions = |text: &str, needle: &str| text.to_ascii_lowercase().contains(needle);
        let is_ticket = matches!(
            request.data_type,
            DataType::RootTicket
                | DataType::RootTicketData
                | DataType::ApTicket
                | DataType::RecoveryOSRootTicketData
        ) || (type_name.contains("Ticket") && mentions(type_name, "cryptex"));
        if !is_ticket {
            return None;
        }
        let argument_mentions = |needle: &str| {
            request
                .arguments
                .values()
                .any(|value| value.as_string().is_some_and(|text| mentions(text, needle)))
        };
        let role = if request.data_type == DataType::RecoveryOSRootTicketData {
            TicketRole::RecoveryOs
        } else {
            TicketRole::Os
        };
        let kind = if mentions(type_name, "cryptex") || argument_mentions("cryptex") {
            GlobalManifestKind::Cryptex1
        } else if mentions(type_name, "centauri") || argument_mentions("centauri") {
            GlobalManifestKind::Centauri
        } else {
            GlobalManifestKind::Os
        };
        Some(TicketRequest { role, kind })
    }

    fn cryptex1_splat_manifest(&self) -> Result<SplatManifest, String> {
        let order = self.variants.os_order();
        let resolved = resolve_global_manifest_in_variants(
            &self.root,
            &order,
            &self.hardware_model,
            GlobalManifestKind::Cryptex1,
        )
        .map_err(|error| error.to_string())?;
        let bytes = load_global_manifest(&resolved).map_err(|error| error.to_string())?;
        Ok(SplatManifest {
            bytes,
            path: resolved.path,
            variant: resolved.variant,
            nonce_staged: false,
        })
    }
}

impl GlobalManifestProvider {
    #[must_use]
    pub fn cryptex1_ticket_bytes(&self) -> Option<Vec<u8>> {
        self.cryptex1_splat_manifest()
            .ok()
            .map(|manifest| manifest.bytes)
    }

    fn recovery_os_manifest(&self) -> Result<SplatManifest, String> {
        let order = self.variants.recovery_order();
        let resolved = resolve_global_manifest_in_variants(
            &self.root,
            &order,
            &self.hardware_model,
            GlobalManifestKind::Os,
        )
        .map_err(|error| error.to_string())?;
        let bytes = load_global_manifest(&resolved).map_err(|error| error.to_string())?;
        Ok(SplatManifest {
            bytes,
            path: resolved.path,
            variant: resolved.variant,
            nonce_staged: false,
        })
    }
}

struct SplatManifest {
    bytes: Vec<u8>,
    path: PathBuf,
    variant: String,
    nonce_staged: bool,
}

impl RestoreDataProvider for GlobalManifestProvider {
    fn supply(&mut self, request: &DataRequest) -> Result<plist::Dictionary, ProviderError> {
        let Some(TicketRequest { role, kind }) = Self::classify(request) else {
            let line = format!(
                "{MUX_PREFIX} result=ticket-not-classified port={} at={:.3}s type={:?} args=[{}] meaning=\"this provider answers ticket requests only and this request is not one; no bytes were served and the session ends on it\" detail=\"\"",
                self.port,
                self.armed_at_secs,
                request.data_type,
                request
                    .arguments
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            );
            report(&self.reporter, "ticket-not-classified", &line);
            return Err(ProviderError::Unsupported {
                data_type: request.data_type.wire_name().to_string(),
            });
        };
        let order = match role {
            TicketRole::Os => self.variants.os_order(),
            TicketRole::RecoveryOs => self.variants.recovery_order(),
        };
        let resolved = match resolve_global_manifest_in_variants(
            &self.root,
            &order,
            &self.hardware_model,
            kind,
        ) {
            Ok(resolved) => resolved,
            Err(error) => {
                let line = format!(
                    "{MUX_PREFIX} result=ticket-manifest-missing port={} at={:.3}s type={:?} role={} kind={} variants_wanted=[{}] meaning=\"the guest asked for a ticket the host could not resolve to a genuine manifest under any variant this restore declared; the failure names the paths tried\" detail=\"{error}\"",
                    self.port,
                    self.armed_at_secs,
                    request.data_type,
                    role.label(),
                    kind.label(),
                    order.join(","),
                    error = error
                );
                report(&self.reporter, "ticket-manifest-missing", &line);
                return Err(ProviderError::Other(format!(
                    "{role} {kind} ticket for {model}: {error}",
                    role = role.label(),
                    kind = kind.label(),
                    model = self.hardware_model
                )));
            }
        };
        let bytes = match load_global_manifest(&resolved) {
            Ok(bytes) => bytes,
            Err(error) => {
                let line = format!(
                    "{MUX_PREFIX} result=ticket-manifest-unreadable port={} at={:.3}s type={:?} kind={} meaning=\"the genuine manifest was located but could not be read\" detail=\"{error}\"",
                    self.port,
                    self.armed_at_secs,
                    request.data_type,
                    kind.label(),
                    error = error
                );
                report(&self.reporter, "ticket-manifest-unreadable", &line);
                return Err(ProviderError::Other(format!(
                    "{kind} ticket for {model}: {error}",
                    kind = kind.label(),
                    model = self.hardware_model
                )));
            }
        };
        let bytes = if matches!((role, kind), (TicketRole::Os, GlobalManifestKind::Os)) {
            match &self.fdr_trust_digest {
                None => {
                    let line = format!(
                        "{MUX_PREFIX} result=ticket-fdr-objects-unadded port={} at={:.3}s type={:?} meaning=\"no FDR trust digest was resolved for this machine, so the OS ticket is served without rfta/ftap and fdr_create will find them absent\" detail=\"\"",
                        self.port, self.armed_at_secs, request.data_type,
                    );
                    report(&self.reporter, "ticket-fdr-objects-unadded", &line);
                    bytes
                }
                Some(trust_digest) => {
                    match crate::ramrod::ticket::add_fdr_trust_objects(&bytes, &trust_digest.digest)
                    {
                        Ok(updated) => {
                            if updated.len() != bytes.len() {
                                let digest = sha384(&updated);
                                let line = format!(
                                    "{MUX_PREFIX} result=ticket-fdr-objects-added port={} at={:.3}s type={:?} role={} kind={} before={} after={} sha384={} fdr_digest={} fdr_element_index={} fdr_element_count={} meaning=\"the recovery host signed the two FDR trust objects rfta and ftap into the OS ticket it serves and hashes, the same objects a personalised Apple ticket carries and a global one does not, so the step that reads them at fdr_create finds them; the digest is the SHA-256 of the local trust object, the same bytes FdrTrustProvider serves into the guest's memory store, so what the guest hashes back and what it reads out of this ticket are one value resolved once\" detail=\"\"",
                                    self.port,
                                    self.armed_at_secs,
                                    request.data_type,
                                    role.label(),
                                    kind.label(),
                                    bytes.len(),
                                    updated.len(),
                                    hex_digest(&digest),
                                    trust_digest.hex(),
                                    trust_digest.element_index,
                                    trust_digest.element_count,
                                );
                                report(&self.reporter, "ticket-fdr-objects-added", &line);
                            }
                            updated
                        }
                        Err(error) => {
                            let line = format!(
                                "{MUX_PREFIX} result=ticket-fdr-objects-unadded port={} at={:.3}s type={:?} meaning=\"the OS ticket could not be parsed to add the FDR trust objects, so it is served as loaded and fdr_create will still miss them\" detail=\"{error}\"",
                                self.port, self.armed_at_secs, request.data_type,
                            );
                            report(&self.reporter, "ticket-fdr-objects-unadded", &line);
                            bytes
                        }
                    }
                }
            }
        } else {
            bytes
        };
        let bytes = match (role, kind, self.ap_nonce.as_ref()) {
            (TicketRole::Os, GlobalManifestKind::Os, Some(ap_nonce)) => {
                match crate::ramrod::ticket::set_boot_nonce_hash(&bytes, ap_nonce) {
                    Ok(updated) => updated,
                    Err(error) => {
                        let line = format!(
                            "{MUX_PREFIX} result=ticket-nonce-unwritten port={} at={:.3}s type={:?} meaning=\"the ticket could not be parsed to write this boot's AP nonce into its MANP, so it is served as loaded and install_splat will still find no BNCH\" detail=\"{error}\"",
                            self.port, self.armed_at_secs, request.data_type,
                        );
                        report(&self.reporter, "ticket-nonce-unwritten", &line);
                        bytes
                    }
                }
            }
            _ => bytes,
        };
        let genuine_len = bytes.len();
        let served = if self.corrupt {
            corrupt_manifest_bytes(&bytes)
        } else {
            bytes
        };
        if self.logged.insert(format!(
            "{}:{}:{}",
            request.data_type.wire_name(),
            role.label(),
            kind.label()
        )) {
            let digest = sha384(&served);
            let boot_manifest = match (role, self.staged_boot_manifest_sha384) {
                (TicketRole::Os, Some(staged)) if staged == digest => "match",
                (TicketRole::Os, Some(_)) => "mismatch",
                (TicketRole::Os, None) => "none",
                (TicketRole::RecoveryOs, Some(staged)) if staged == digest => "not-compared-match",
                (TicketRole::RecoveryOs, Some(_)) => "not-compared-mismatch",
                (TicketRole::RecoveryOs, None) => "not-compared-none",
            };
            let line = format!(
                "{MUX_PREFIX} result=ticket-answered port={} at={:.3}s type={:?} role={} kind={} variant=\"{}\" variant_wanted=\"{}\" variant_fallback={} variants_skipped=[{}] layout={} corrupt={} bytes={} sha384={} boot_manifest={boot_manifest} staged_sha384={} meaning=\"the guest's ticket request was answered from the genuine board manifest; variant names which restore variant the manifest actually came out of and variant_wanted which one this role asked for first, so a fallback is visible here rather than inferred later; sha384 is what the guest compares against /chosen/boot-manifest-hash and boot_manifest says whether the machine published that same value, so anything but match fails the root ticket step; a not-compared prefix marks the recovery-OS role, whose sibling verifier is entered with that comparison switched off\" detail=\"path={}\"",
                self.port,
                self.armed_at_secs,
                request.data_type,
                role.label(),
                kind.label(),
                resolved.variant,
                order.first().copied().unwrap_or(""),
                !resolved.is_preferred_variant(),
                resolved.skipped.join(","),
                resolved.layout.label(),
                self.corrupt,
                genuine_len,
                hex_digest(&digest),
                self.staged_boot_manifest_sha384
                    .as_ref()
                    .map_or_else(|| "none".to_string(), |staged| hex_digest(staged)),
                resolved.path.display()
            );
            report(&self.reporter, "ticket-answered", &line);
            let mut audit_carries_boot_nonce = true;
            let audit_line = match audit_ticket(&served, &FDR_TRUST_OBJECT_TAGS) {
                Ok(audit) => {
                    audit_carries_boot_nonce = audit.carries_boot_nonce_hash();
                    format!(
                        "{MUX_PREFIX} result=ticket-audited port={} at={:.3}s type={:?} role={} kind={} variant=\"{}\" variant_wanted=\"{}\" {}",
                        self.port,
                        self.armed_at_secs,
                        request.data_type,
                        role.label(),
                        kind.label(),
                        resolved.variant,
                        order.first().copied().unwrap_or(""),
                        audit.trace_fields()
                    )
                }
                Err(error) => format!(
                    "{MUX_PREFIX} result=ticket-unreadable port={} at={:.3}s type={:?} role={} kind={} variant=\"{}\" bytes={} meaning=\"the bytes served as a ticket could not be read back as an Image4 manifest, so what they authorise is unknown and the guest will be the first to find out\" detail=\"{error}\"",
                    self.port,
                    self.armed_at_secs,
                    request.data_type,
                    role.label(),
                    kind.label(),
                    resolved.variant,
                    served.len()
                ),
            };
            report(&self.reporter, "ticket-audited", &audit_line);
            if matches!((role, kind), (TicketRole::Os, GlobalManifestKind::Os)) {
                let line = if audit_carries_boot_nonce {
                    format!(
                        "{MUX_PREFIX} result=splat-nonce-staged port={} at={:.3}s type={:?} role={} kind={} variant=\"{}\" property=BNCH bytes={BOOT_NONCE_HASH_BYTES} boot_manifest={boot_manifest} meaning=\"the AP ticket served here carries this boot's AP nonce as its BNCH manifest property, which is what install_splat at checkpoint 0x06A6 reads through ramrod_ticket_copy_data_manifest_property and puts into the personalisation request under the key Nonce; the same 32 bytes were staged into the manifest the machine published /chosen/boot-manifest-hash over, and boot_manifest above is the on-host confirmation that the guest still accepts these bytes as the root ticket\" detail=\"path={}\"",
                        self.port,
                        self.armed_at_secs,
                        request.data_type,
                        role.label(),
                        kind.label(),
                        resolved.variant,
                        resolved.path.display()
                    )
                } else {
                    format!(
                        "{MUX_PREFIX} result=splat-nonce-refused port={} at={:.3}s type={:?} role={} kind={} variant=\"{}\" property=BNCH expected_bytes={BOOT_NONCE_HASH_BYTES} meaning=\"the AP ticket served here carries no BNCH manifest property, so install_splat at checkpoint 0x06A6 will log '_personalize_splat_ticket: failed to get BNCH from SFR manifest' and fail perform_restore_installing; the host refuses to synthesise the value because BNCH is this machine's AP boot nonce, and this launch published none for the ticket to carry\" detail=\"path={}\"",
                        self.port,
                        self.armed_at_secs,
                        request.data_type,
                        role.label(),
                        kind.label(),
                        resolved.variant,
                        resolved.path.display()
                    )
                };
                report(
                    &self.reporter,
                    if audit_carries_boot_nonce {
                        "splat-nonce-staged"
                    } else {
                        "splat-nonce-refused"
                    },
                    &line,
                );
            }
        }
        let mut body = plist::Dictionary::new();
        body.insert("RootTicketData".to_string(), plist::Value::Data(served));
        Ok(body)
    }
}

pub struct BoardManifest {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
}

pub fn board_manifest_for_firmware(
    root: &Path,
    variants: &RestoreVariants,
    hardware_model: &str,
    corrupt: bool,
    port: u16,
    armed_at_secs: f64,
    reporter: &SharedReporter,
) -> Option<BoardManifest> {
    let order = variants.os_order();
    let resolved = match resolve_global_manifest_in_variants(
        root,
        &order,
        hardware_model,
        GlobalManifestKind::Os,
    ) {
        Ok(resolved) => resolved,
        Err(error) => {
            let line = format!(
                "{MUX_PREFIX} result=nor-manifest-missing port={port} at={armed_at_secs:.3}s variants_wanted=[{}] meaning=\"every firmware image is wrapped with the board's own global manifest and that manifest could not be resolved under any variant this restore declared, so no firmware payload is prepared; the failure names the paths tried\" detail=\"{error}\"",
                order.join(",")
            );
            report(reporter, "nor-manifest-missing", &line);
            return None;
        }
    };
    if !resolved.is_preferred_variant() {
        let line = format!(
            "{MUX_PREFIX} result=nor-manifest-variant-fallback port={port} at={armed_at_secs:.3}s variant=\"{}\" variant_wanted=\"{}\" variants_skipped=[{}] meaning=\"the firmware wrapping manifest came from a variant this restore did not prefer, because the preferred one ships no AP manifest for this board; the firmware is still genuine and still this board's, but it is not cut for the identity being installed\" detail=\"path={}\"",
            resolved.variant,
            order.first().copied().unwrap_or(""),
            resolved.skipped.join(","),
            resolved.path.display()
        );
        report(reporter, "nor-manifest-variant-fallback", &line);
    }
    let bytes = match load_global_manifest(&resolved) {
        Ok(bytes) => bytes,
        Err(error) => {
            let line = format!(
                "{MUX_PREFIX} result=nor-manifest-unreadable port={port} at={armed_at_secs:.3}s meaning=\"the global manifest every firmware image is wrapped with was located and could not be read\" detail=\"{error}\""
            );
            report(reporter, "nor-manifest-unreadable", &line);
            return None;
        }
    };
    let bytes = if corrupt {
        corrupt_manifest_bytes(&bytes)
    } else {
        bytes
    };
    Some(BoardManifest {
        path: resolved.path,
        bytes,
    })
}

pub struct NorFirmwareProvider {
    payload: Result<NorPayload, String>,
    firmware_root: PathBuf,
    manifest_path: PathBuf,
    port: u16,
    armed_at_secs: f64,
    reporter: SharedReporter,
}

impl NorFirmwareProvider {
    fn poisoned(
        firmware_root: PathBuf,
        manifest_path: PathBuf,
        port: u16,
        armed_at_secs: f64,
        reporter: &SharedReporter,
        reason: String,
    ) -> Self {
        Self {
            payload: Err(reason),
            firmware_root,
            manifest_path,
            port,
            armed_at_secs,
            reporter: Arc::clone(reporter),
        }
    }

    pub fn prepare(
        identity: &BuildIdentity,
        firmware_root: PathBuf,
        manifest_path: PathBuf,
        board_manifest: &[u8],
        port: u16,
        armed_at_secs: f64,
        reporter: &SharedReporter,
    ) -> Self {
        let plan = match plan_nor_payload(identity) {
            Ok(plan) => plan,
            Err(error) => {
                let line = format!(
                    "{MUX_PREFIX} result=nor-plan-unreadable port={port} at={armed_at_secs:.3}s identity=#{} meaning=\"the chosen build identity does not name a firmware payload this host can resolve, so a NORData request cannot be answered and will end the restore at load_sep_os\" detail=\"{error}\"",
                    identity.index
                );
                report(reporter, "nor-plan-unreadable", &line);
                return Self::poisoned(
                    firmware_root,
                    manifest_path,
                    port,
                    armed_at_secs,
                    reporter,
                    error.to_string(),
                );
            }
        };
        let line = format!(
            "{MUX_PREFIX} result=nor-plan-read port={port} at={armed_at_secs:.3}s identity=#{} components={} meaning=\"which components the firmware payload is made of, read off the identity's own IsFirmwarePayload and IsSecondaryFirmwarePayload flags rather than off the board; unclaimed names a component the manifest flags as a SEP payload that the guest has no reader for\" detail=\"{}; unclaimed=[{}]\"",
            identity.index,
            plan.components.len(),
            plan.components
                .iter()
                .map(|component| format!(
                    "{}={}:{}",
                    component.slot.label(),
                    component.name,
                    component.path
                ))
                .collect::<Vec<_>>()
                .join(" "),
            plan.unclaimed_secondary.join(",")
        );
        report(reporter, "nor-plan-read", &line);
        let plan = match validate_firmware_root(&plan, &firmware_root) {
            Ok(()) => plan,
            Err(error) => {
                let line = format!(
                    "{MUX_PREFIX} result=nor-firmware-root-unresolved port={port} at={armed_at_secs:.3}s identity=#{} components={} meaning=\"the firmware root does not resolve every component path the chosen build identity names, so this is an operator mistake in --asr-serve-firmware-root rather than anything the guest did; the reply is fetched once and drained key by key, so a NORData reply carrying only the components that happened to resolve would be indistinguishable from a complete one at the point the guest reads it, and the missing keys could never be asked for again. No payload is prepared and the whole request is refused by name rather than answered short of it\" detail=\"{error}\"",
                    identity.index,
                    plan.components.len()
                );
                report(reporter, "nor-firmware-root-unresolved", &line);
                return Self::poisoned(
                    firmware_root,
                    manifest_path,
                    port,
                    armed_at_secs,
                    reporter,
                    error.to_string(),
                );
            }
        };
        let payload = match build_nor_payload(&plan, &firmware_root, board_manifest) {
            Ok(payload) => payload,
            Err(error) => {
                let line = format!(
                    "{MUX_PREFIX} result=nor-payload-unbuildable port={port} at={armed_at_secs:.3}s meaning=\"a component the identity names could not be turned into an Image4 image, so no firmware payload is prepared and a NORData request will be refused by name rather than answered short of it\" detail=\"root={}: {error}\"",
                    firmware_root.display()
                );
                report(reporter, "nor-payload-unbuildable", &line);
                return Self::poisoned(
                    firmware_root,
                    manifest_path,
                    port,
                    armed_at_secs,
                    reporter,
                    error.to_string(),
                );
            }
        };
        let line = format!(
            "{MUX_PREFIX} result=nor-payload-built port={port} at={armed_at_secs:.3}s images={} bytes={} meaning=\"every image is an Image4 container holding the IPSW's own im4p payload and the board's own global manifest; im4p is what the IPSW ships and img4 is what goes on the wire, so the two differing by the manifest length is what a genuine wrap looks like. served_type names the Img4PayloadType actually written into each container, and retag=yes means the shipped file's own type did not match the identity's Img4PayloadType and the container was rewritten to it after its digest was checked against the manifest\" detail=\"root={} manifest={} {}\"",
            payload.images.len(),
            payload.total_image_bytes(),
            firmware_root.display(),
            manifest_path.display(),
            payload
                .images
                .iter()
                .map(|image| format!(
                    "{}={} im4p={} img4={} served_type={} retag={}",
                    image.slot.label(),
                    image.name,
                    image.payload_bytes,
                    image.image_bytes,
                    image.served_type.as_deref().unwrap_or("unstated"),
                    if image.retagged { "yes" } else { "no" }
                ))
                .collect::<Vec<_>>()
                .join(" ")
        );
        report(reporter, "nor-payload-built", &line);
        Self {
            payload: Ok(payload),
            firmware_root,
            manifest_path,
            port,
            armed_at_secs,
            reporter: Arc::clone(reporter),
        }
    }
}

impl RestoreDataProvider for NorFirmwareProvider {
    fn supply(&mut self, request: &DataRequest) -> Result<plist::Dictionary, ProviderError> {
        let payload = match &self.payload {
            Ok(payload) => payload,
            Err(reason) => {
                let line = format!(
                    "{MUX_PREFIX} result=nor-plan-failed port={} at={:.3}s type={:?} meaning=\"the guest asked for the firmware payload and the plan this host built for it earlier could not be turned into a servable NORData reply, so the request is refused by name rather than answered with an empty dictionary; an empty dictionary here is indistinguishable from RestoreSEPImageData genuinely absent, and because the reply is fetched once and drained key by key, the guest could never ask again\" detail=\"root={} manifest={} {reason}\"",
                    self.port,
                    self.armed_at_secs,
                    request.data_type,
                    self.firmware_root.display(),
                    self.manifest_path.display()
                );
                report(&self.reporter, "nor-plan-failed", &line);
                return Err(ProviderError::Other(reason.clone()));
            }
        };
        let named = wants_flash_version_1(&request.arguments);
        let body = payload.answer(named);
        if body.is_empty() {
            return Err(ProviderError::Other(format!(
                "the firmware payload built from {} carries no image the guest reads",
                self.firmware_root.display()
            )));
        }
        let line = format!(
            "{MUX_PREFIX} result=nor-served port={} at={:.3}s type={:?} form={} keys=[{}] images={} bytes={} meaning=\"the firmware payload is on its way back on the control connection; the guest fetches this once and removes each key as it reads it, so what is not in this reply can never be asked for again\" detail=\"root={} manifest={}\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            if named { "named" } else { "ordered" },
            body.keys()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(","),
            payload.images.len(),
            payload.total_image_bytes(),
            self.firmware_root.display(),
            self.manifest_path.display()
        );
        report(&self.reporter, "nor-served", &line);
        Ok(body)
    }
}

pub struct FdrTrustProvider {
    pub port: u16,
    pub armed_at_secs: f64,
    pub reporter: SharedReporter,
    trust_object: Vec<u8>,
    instance: Option<String>,
    committed: plist::Dictionary,
}

impl FdrTrustProvider {
    pub fn new(
        trust_digest: Option<&FdrTrustDigest>,
        port: u16,
        armed_at_secs: f64,
        reporter: &SharedReporter,
    ) -> Self {
        Self {
            port,
            armed_at_secs,
            reporter: Arc::clone(reporter),
            trust_object: trust_digest
                .map(|resolved| resolved.trust_object.clone())
                .unwrap_or_default(),
            instance: trust_digest.and_then(|resolved| resolved.instance.clone()),
            committed: plist::Dictionary::new(),
        }
    }

    fn memory_store(&self) -> plist::Dictionary {
        let mut store = self.committed.clone();
        store.insert(
            crate::ramrod::TRUST_OBJECT_KEY.to_string(),
            plist::Value::Data(self.trust_object.clone()),
        );
        store
    }

    fn commit(&mut self, request: &DataRequest) -> Result<plist::Dictionary, ProviderError> {
        let committed = request
            .arguments
            .get(KEY_FDR_MEMORY_STORE_DATA)
            .and_then(plist::Value::as_dictionary);
        let entries = match committed {
            Some(store) => {
                self.committed = store.clone();
                store
                    .iter()
                    .map(|(key, value)| format!("{key}={}", describe_plist_value(value)))
                    .collect::<Vec<_>>()
                    .join(",")
            }
            None => String::new(),
        };
        let line = format!(
            "{MUX_PREFIX} result=fdr-memory-committed port={} at={:.3}s type={:?} present={} instance={} entries={} store=[{}] meaning=\"the guest uploaded its own FDR memory store after fdr_recover, which is the guest generating its class data and handing it back rather than the host authoring any of it; every entry is retained exactly as keyed, so a later FDRTrustData request is answered with this store plus the local trust object, and each key is printed with the byte count of its data so what the guest produced is on the record\" detail=\"the acknowledgement echoes the store back under {}; restored never reads this reply, it only requires that one arrives, since func_100025f48 stores the response and the caller releases it unread at 0x100070130, and a NULL response is what produces failed to copy response to data request and a -1\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            committed.is_some(),
            self.instance.as_deref().unwrap_or("none"),
            self.committed.len(),
            entries,
            KEY_FDR_MEMORY_STORE_DATA
        );
        report(&self.reporter, "fdr-memory-committed", &line);
        let mut body = plist::Dictionary::new();
        body.insert(
            KEY_FDR_MEMORY_STORE_DATA.to_string(),
            plist::Value::Dictionary(self.committed.clone()),
        );
        Ok(body)
    }

    fn trust(&mut self, request: &DataRequest) -> Result<plist::Dictionary, ProviderError> {
        if self.trust_object.is_empty() {
            let line = format!(
                "{MUX_PREFIX} result=fdr-trust-unheld port={} at={:.3}s type={:?} args=[{}] keys=[] meaning=\"the guest asked for factory data restore trust material and the host has none to give: its local trust object could not be built, so this reply carries no trust bytes and no memory store, and nothing is fabricated to fill them\" detail=\"read this run's fdr-trust-digest-unresolved line for why the material is missing; with the memory store selected and empty, AMFDRDataMemoryCopyTrustObject finds nothing under {}, the digest comparison has nothing to make, and the ticket's {} and {} are equally absent because the same unresolved digest feeds both\"",
                self.port,
                self.armed_at_secs,
                request.data_type,
                request
                    .arguments
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                crate::ramrod::TRUST_OBJECT_KEY,
                FDR_TRUST_OBJECT_TAGS[0],
                FDR_TRUST_OBJECT_TAGS[1]
            );
            report(&self.reporter, "fdr-trust-unheld", &line);
            return Ok(plist::Dictionary::new());
        }
        let store = self.memory_store();
        let store_entries = store.len();
        let store_keys = store
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(",");
        let mut body = plist::Dictionary::new();
        body.insert(
            KEY_FDR_TRUST_DATA.to_string(),
            plist::Value::Data(self.trust_object.clone()),
        );
        body.insert(
            KEY_BOOTED_OS_FDR_TRUST_DATA.to_string(),
            plist::Value::Data(self.trust_object.clone()),
        );
        body.insert(
            KEY_FDR_MEMORY_STORE_DATA.to_string(),
            plist::Value::Dictionary(store),
        );
        let line = format!(
            "{MUX_PREFIX} result=fdr-trust-served port={} at={:.3}s type={:?} args=[{}] keys=[{}] object_bytes={} sha256={} store_entries={} store_keys=[{}] instance={} meaning=\"the recovery host served this machine's factory data restore trust object, its offline local trust root, under both {} and {} and inside a flat {} dictionary keyed {}; the restore options carry FDRMemoryStorePath so the guest built a memory backed FDR client, which is what makes this dictionary reach AMFDRSetMemoryStore at 0x10006edd8 instead of being discarded, and AMFDRDataMemoryCopyTrustObject then returns exactly these bytes for the digest comparison\" detail=\"the ticket half has to agree: {} and {} in the OS ticket carry the SHA-256 printed here, resolved once for this machine and used for both, so a ticket-fdr-objects-unadded line on this run is what puts the guest back on failed to set trust object digest and a return of 6. store_entries counts the local object plus everything the guest has already committed back under FDRMemoryCommit\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            request
                .arguments
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(","),
            body.keys()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(","),
            self.trust_object.len(),
            hex_digest(&sha256(&self.trust_object)),
            store_entries,
            store_keys,
            self.instance.as_deref().unwrap_or("none"),
            KEY_FDR_TRUST_DATA,
            KEY_BOOTED_OS_FDR_TRUST_DATA,
            KEY_FDR_MEMORY_STORE_DATA,
            crate::ramrod::TRUST_OBJECT_KEY,
            FDR_TRUST_OBJECT_TAGS[0],
            FDR_TRUST_OBJECT_TAGS[1]
        );
        report(&self.reporter, "fdr-trust-served", &line);
        Ok(body)
    }
}

impl RestoreDataProvider for FdrTrustProvider {
    fn supply(&mut self, request: &DataRequest) -> Result<plist::Dictionary, ProviderError> {
        if request.data_type.wire_name() == FDR_MEMORY_COMMIT_DATA_TYPE {
            return self.commit(request);
        }
        self.trust(request)
    }
}

pub struct BuildIdentityProvider {
    manifest: plist::Dictionary,
    hardware_model: String,
    default_variant: String,
    recovery_variant: String,
    last_variant: Option<String>,
    omitted_components: Vec<String>,
    port: u16,
    armed_at_secs: f64,
    reporter: SharedReporter,
}

impl BuildIdentityProvider {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manifest: plist::Dictionary,
        hardware_model: String,
        default_variant: String,
        recovery_variant: String,
        omitted_components: Vec<String>,
        port: u16,
        armed_at_secs: f64,
        reporter: &SharedReporter,
    ) -> Self {
        Self {
            manifest,
            hardware_model,
            default_variant,
            recovery_variant,
            last_variant: None,
            omitted_components,
            port,
            armed_at_secs,
            reporter: Arc::clone(reporter),
        }
    }

    #[must_use]
    pub fn last_variant(&self) -> Option<&str> {
        self.last_variant.as_deref()
    }

    fn recovery_os_version(&self) -> Option<(Vec<&'static str>, plist::Dictionary)> {
        let identity =
            raw_identity_for_variant(&self.manifest, &self.hardware_model, &self.recovery_variant)?;
        let info = identity.get("Info")?.as_dictionary()?;
        let mut version = plist::Dictionary::new();
        let mut copied = Vec::new();
        for key in ["BuildNumber", "Variant", "BuildTrain"] {
            if let Some(value) = info.get(key) {
                version.insert(key.to_string(), value.clone());
                copied.push(key);
            }
        }
        if let Some(value) = info.get("ProductMarketingVersion") {
            version.insert("ProductVersion".to_string(), value.clone());
            copied.push("ProductVersion");
        }
        let mut xml = Vec::new();
        plist::to_writer_xml(&mut xml, &plist::Value::Dictionary(version)).ok()?;
        let mut body = plist::Dictionary::new();
        body.insert(
            KEY_RECOVERY_OS_VERSION_DATA.to_string(),
            plist::Value::Data(xml),
        );
        Some((copied, body))
    }

    fn drop_omitted_components(&self, identity: &mut plist::Dictionary) -> Vec<String> {
        if self.omitted_components.is_empty() {
            return Vec::new();
        }
        let Some(components) = identity
            .get_mut(IDENTITY_MANIFEST_KEY)
            .and_then(plist::Value::as_dictionary_mut)
        else {
            return Vec::new();
        };
        let mut dropped = Vec::new();
        for name in &self.omitted_components {
            if components.remove(name).is_some() {
                dropped.push(name.clone());
            }
        }
        dropped
    }

    fn answer(&self, request: &DataRequest) -> Option<(String, plist::Dictionary)> {
        let wanted = request
            .argument_string(KEY_VARIANT)
            .unwrap_or(&self.default_variant)
            .to_string();
        let mut identity = raw_identity_for_variant(&self.manifest, &self.hardware_model, &wanted)?;
        let dropped = self.drop_omitted_components(&mut identity);
        if !dropped.is_empty() {
            let line = format!(
                "{MUX_PREFIX} result=build-identity-components-dropped port={} at={:.3}s variant=\"{wanted}\" dropped=[{}] meaning=\"DEVIATION FROM A REAL RESTORE: the identity handed to the guest is Apple's own with these components removed, because this host holds no genuine copy of them. install_splat gates each cryptex member on the component being present here, so a member left in and then not delivered fails the step, and a member taken out is skipped with no failure. Apple's build ships them; this tree is short of them, and the install is smaller than the build describes by exactly this list\" detail=\"\"",
                self.port,
                self.armed_at_secs,
                dropped.join(",")
            );
            report(&self.reporter, "build-identity-components-dropped", &line);
        }
        let mut body = plist::Dictionary::new();
        body.insert(
            KEY_BUILD_IDENTITY_DICT.to_string(),
            plist::Value::Dictionary(identity),
        );
        body.insert(
            KEY_VARIANT.to_string(),
            plist::Value::String(wanted.clone()),
        );
        Some((wanted, body))
    }
}

impl RestoreDataProvider for BuildIdentityProvider {
    fn supply(&mut self, request: &DataRequest) -> Result<plist::Dictionary, ProviderError> {
        if request.data_type == DataType::RecoveryOSVersionData {
            return Ok(match self.recovery_os_version() {
                Some((copied, body)) => {
                    let line = format!(
                        "{MUX_PREFIX} result=recovery-os-version-answered port={} at={:.3}s variant=\"{}\" model={} fields=[{}] bytes={} meaning=\"the guest asked what the recovery OS build is and was answered from that identity's own Info, copied verbatim into an XML property list; a field the identity does not carry is absent rather than invented\" detail=\"\"",
                        self.port,
                        self.armed_at_secs,
                        self.recovery_variant,
                        self.hardware_model,
                        copied.join(","),
                        body.get(KEY_RECOVERY_OS_VERSION_DATA)
                            .and_then(plist::Value::as_data)
                            .map_or(0, <[u8]>::len)
                    );
                    report(&self.reporter, "recovery-os-version-answered", &line);
                    body
                }
                None => {
                    let line = format!(
                        "{MUX_PREFIX} result=recovery-os-version-absent port={} at={:.3}s variant=\"{}\" model={} meaning=\"this manifest carries no recovery OS identity for this model, so the reply carries no version data rather than the install identity's; the guest reports the missing key itself and the session continues\" detail=\"\"",
                        self.port, self.armed_at_secs, self.recovery_variant, self.hardware_model
                    );
                    report(&self.reporter, "recovery-os-version-absent", &line);
                    plist::Dictionary::new()
                }
            });
        }
        match self.answer(request) {
            Some((variant, body)) => {
                self.last_variant = Some(variant.clone());
                let line = format!(
                    "{MUX_PREFIX} result=build-identity-answered port={} at={:.3}s type={:?} variant=\"{variant}\" variant_requested=\"{}\" model={} keys=[{}] meaning=\"the guest's build identity request was answered with the BuildIdentities entry the manifest itself holds for that variant, unaltered; variant_requested is what the request named and variant is what answered, and they differ only when the request named none and the install variant was used\" detail=\"\"",
                    self.port,
                    self.armed_at_secs,
                    request.data_type,
                    request.argument_string(KEY_VARIANT).unwrap_or("none"),
                    self.hardware_model,
                    body.keys()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(",")
                );
                report(&self.reporter, "build-identity-answered", &line);
                Ok(body)
            }
            None => {
                let line = format!(
                    "{MUX_PREFIX} result=build-identity-absent port={} at={:.3}s type={:?} variant_requested=\"{}\" model={} meaning=\"the guest asked for a build identity under a variant this manifest carries none of for this model, so the reply carries no identity rather than the wrong one; an identity cut for a different variant passes every check made here and fails later in the first step that reads a component it does not ship\" detail=\"the reply is well formed and empty, so the guest reports the missing key itself and the session continues\"",
                    self.port,
                    self.armed_at_secs,
                    request.data_type,
                    request.argument_string(KEY_VARIANT).unwrap_or("none"),
                    self.hardware_model
                );
                report(&self.reporter, "build-identity-absent", &line);
                Ok(plist::Dictionary::new())
            }
        }
    }
}

pub const PERSONALIZED_DATA_TYPE: &str = "PersonalizedData";

const IDENTITY_MANIFEST_KEY: &str = "Manifest";
const COMPONENT_INFO_KEY: &str = "Info";
const COMPONENT_PATH_KEY: &str = "Path";
const COMPONENT_PAYLOAD_TYPE_KEY: &str = "Img4PayloadType";

const COMPONENT_SYSTEM_VOLUME: &str = "SystemVolume";
const COMPONENT_SYSTEM_VOLUME_CANONICAL_METADATA: &str = "Ap,SystemVolumeCanonicalMetadata";

pub const EAN_DATA_TYPE: &str = "EANData";
pub const FUD_DATA_TYPE: &str = "FUDData";

pub const FIRMWARE_UPDATER_DATA_TYPE: &str = "FirmwareUpdaterData";
pub const FIRMWARE_UPDATER_DATA_V2_TYPE: &str = "FirmwareUpdaterDataV2";

const KEY_MESSAGE_ARG_UPDATER_NAME: &str = "MessageArgUpdaterName";
const UPDATER_NAME_CRYPTEX1: &str = "Cryptex1";

pub const KEY_FIRMWARE_RESPONSE_DATA: &str = "FirmwareResponseData";

pub const KEY_CRYPTEX1_TICKET: &str = "Cryptex1,Ticket";

pub const KEY_AP_LOCAL_POLICY: &str = "Ap,LocalPolicy";

const RECOVERY_OS_LOCAL_POLICY_IM4P: [u8; 22] = [
    0x30, 0x14, 0x16, 0x04, b'I', b'M', b'4', b'P', 0x16, 0x04, b'l', b'p', b'o', b'l', 0x16, 0x03,
    b'1', b'.', b'0', 0x04, 0x01, 0x00,
];

const RECOVERY_OS_LOCAL_POLICY_IM4P_SHA384: [u8; 48] = [
    0xd1, 0x01, 0x54, 0x38, 0xc4, 0xa8, 0x91, 0x72, 0xa3, 0x04, 0x8d, 0x5e, 0xae, 0xbc, 0xb2, 0xde,
    0x65, 0x77, 0x75, 0xc6, 0x6a, 0xf8, 0x68, 0x91, 0x6a, 0xa7, 0x96, 0x19, 0x02, 0x3d, 0x82, 0x86,
    0xa1, 0x46, 0x10, 0xc7, 0x25, 0xe4, 0x91, 0xce, 0x67, 0xf4, 0x0c, 0xbd, 0x58, 0xb7, 0x78, 0x72,
];

pub const KEY_EAN_IMAGE_LIST: &str = "EANImageList";
pub const KEY_FUD_IMAGE_LIST: &str = "FUDImageList";

const INFO_FLAG_EARLY_ACCESS_FIRMWARE: &str = "IsEarlyAccessFirmware";
const INFO_FLAG_FUD_FIRMWARE: &str = "IsFUDFirmware";

pub struct PersonalizedFirmwareProvider {
    manifest: plist::Dictionary,
    hardware_model: String,
    install_variant: String,
    recovery_variant: String,
    followed_variant: Option<String>,
    firmware_root: Option<PathBuf>,
    board_manifest: Option<Vec<u8>>,
    board_manifest_path: Option<PathBuf>,
    port: u16,
    armed_at_secs: f64,
    reporter: SharedReporter,
}

impl PersonalizedFirmwareProvider {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manifest: plist::Dictionary,
        hardware_model: String,
        install_variant: String,
        recovery_variant: String,
        firmware_root: Option<PathBuf>,
        board_manifest: Option<Vec<u8>>,
        board_manifest_path: Option<PathBuf>,
        port: u16,
        armed_at_secs: f64,
        reporter: &SharedReporter,
    ) -> Self {
        Self {
            manifest,
            hardware_model,
            install_variant,
            recovery_variant,
            followed_variant: None,
            firmware_root,
            board_manifest,
            board_manifest_path,
            port,
            armed_at_secs,
            reporter: Arc::clone(reporter),
        }
    }

    pub fn follow_variant(&mut self, variant: &str) {
        if self.followed_variant.as_deref() == Some(variant) {
            return;
        }
        let line = format!(
            "{MUX_PREFIX} result=personalized-variant-followed port={} at={:.3}s variant=\"{variant}\" previous=\"{}\" meaning=\"the guest fetched a build identity for this variant, so the image list and personalised object requests that follow it without naming one are answered off that identity; the firmware update names its identity once and then stops naming it, and answering those off the install variant instead would enumerate components the guest is not installing\" detail=\"\"",
            self.port,
            self.armed_at_secs,
            self.followed_variant.as_deref().unwrap_or("none")
        );
        report(&self.reporter, "personalized-variant-followed", &line);
        self.followed_variant = Some(variant.to_string());
    }

    fn variant_for(&self, request: &DataRequest) -> (String, &'static str) {
        if let Some(named) = request.argument_string(KEY_VARIANT) {
            return (named.to_string(), "request");
        }
        // Must outrank the `IsRecoveryOS` branch below: a per-image fetch sends it false while enumerating a list that came off the followed identity.
        if let Some(followed) = self.followed_variant.as_deref() {
            return (followed.to_string(), "followed-identity");
        }
        if request.argument_bool(KEY_IS_RECOVERY_OS) == Some(true) {
            return (self.recovery_variant.clone(), "is-recovery-os");
        }
        (self.install_variant.clone(), "install-default")
    }

    fn components_flagged(&self, variant: &str, flag: &str) -> Option<Vec<String>> {
        let identity = raw_identity_for_variant(&self.manifest, &self.hardware_model, variant)?;
        let components = identity.get(IDENTITY_MANIFEST_KEY)?.as_dictionary()?;
        let mut names: Vec<String> = components
            .iter()
            .filter(|(_, entry)| {
                entry
                    .as_dictionary()
                    .and_then(|entry| entry.get(COMPONENT_INFO_KEY))
                    .and_then(plist::Value::as_dictionary)
                    .and_then(|info| info.get(flag))
                    .and_then(plist::Value::as_boolean)
                    == Some(true)
            })
            .map(|(name, _)| name.clone())
            .collect();
        names.sort();
        Some(names)
    }

    pub fn early_access_list(&mut self, request: &DataRequest) -> plist::Dictionary {
        self.flagged_list(
            request,
            KEY_EAN_IMAGE_LIST,
            INFO_FLAG_EARLY_ACCESS_FIRMWARE,
            "ean",
        )
    }

    pub fn fud_list(&mut self, request: &DataRequest) -> plist::Dictionary {
        self.flagged_list(request, KEY_FUD_IMAGE_LIST, INFO_FLAG_FUD_FIRMWARE, "fud")
    }

    fn flagged_list(
        &mut self,
        request: &DataRequest,
        list_key: &str,
        flag: &str,
        label: &str,
    ) -> plist::Dictionary {
        if request.argument_bool(list_key) != Some(true) {
            let line = format!(
                "{MUX_PREFIX} result={label}-list-not-requested port={} at={:.3}s type={:?} args=[{}] meaning=\"this request is the {label} data type but does not set {list_key}, which is the only shape of it this host answers, so the reply carries no key and nothing was guessed about what else it might have wanted\" detail=\"\"",
                self.port,
                self.armed_at_secs,
                request.data_type,
                describe_dictionary_entries(&request.arguments)
            );
            report(
                &self.reporter,
                &format!("{label}-list-not-requested"),
                &line,
            );
            return plist::Dictionary::new();
        }
        let (variant, chosen_by) = self.variant_for(request);
        let Some(names) = self.components_flagged(&variant, flag) else {
            let line = format!(
                "{MUX_PREFIX} result={label}-list-identity-absent port={} at={:.3}s type={:?} variant=\"{variant}\" variant_chosen_by={chosen_by} model={} flag={flag} meaning=\"this manifest carries no identity for that variant and model, so there is no component list to read the flag off; the reply carries no key and the guest reports the missing list itself\" detail=\"\"",
                self.port, self.armed_at_secs, request.data_type, self.hardware_model
            );
            report(
                &self.reporter,
                &format!("{label}-list-identity-absent"),
                &line,
            );
            return plist::Dictionary::new();
        };
        let mut body = plist::Dictionary::new();
        body.insert(
            list_key.to_string(),
            plist::Value::Array(
                names
                    .iter()
                    .map(|name| plist::Value::String(name.clone()))
                    .collect(),
            ),
        );
        let line = format!(
            "{MUX_PREFIX} result={label}-list-answered port={} at={:.3}s type={:?} variant=\"{variant}\" variant_chosen_by={chosen_by} model={} flag={flag} key={list_key} images={} names=[{}] meaning=\"the enumeration was answered by reading that Info flag off every component of that identity's own Manifest, which is what the data type means and what a host reads it off; the key is present whatever the count, because the step fails on a missing key and completes on a count of zero, and each name that comes back is fetched afterwards as a personalised boot object\" detail=\"\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            self.hardware_model,
            names.len(),
            names.join(",")
        );
        report(&self.reporter, &format!("{label}-list-answered"), &line);
        body
    }

    fn component_path(&self, variant: &str, name: &str) -> Option<String> {
        let identity = raw_identity_for_variant(&self.manifest, &self.hardware_model, variant)?;
        Some(
            identity
                .get(IDENTITY_MANIFEST_KEY)?
                .as_dictionary()?
                .get(name)?
                .as_dictionary()?
                .get(COMPONENT_INFO_KEY)?
                .as_dictionary()?
                .get(COMPONENT_PATH_KEY)?
                .as_string()?
                .to_string(),
        )
    }

    fn system_volume_object(
        &self,
        request: &DataRequest,
        component: &str,
    ) -> Option<Result<StreamedObject, ProviderError>> {
        let (variant, chosen_by) = self.variant_for(request);
        let missing = |reason: &str| {
            let line = format!(
                "{MUX_PREFIX} result=system-volume-object-absent port={} at={:.3}s type={:?} variant=\"{variant}\" component={component} meaning=\"the seal step's input could not be resolved to genuine Apple bytes this host holds, so the request is left to the decline that answers it with a well formed empty reply; nothing is fabricated and the guest fails at the step that reads it\" detail=\"{reason}\"",
                self.port, self.armed_at_secs, request.data_type,
            );
            report(&self.reporter, "system-volume-object-absent", &line);
            None::<Result<StreamedObject, ProviderError>>
        };
        let relative = match self.component_path(&variant, component) {
            Some(relative) => relative,
            None => {
                return missing(&format!(
                    "the {variant} identity for {model} names no component {component} with a path",
                    model = self.hardware_model
                ));
            }
        };
        let root = match self.firmware_root.as_ref() {
            Some(root) => root,
            None => {
                return missing(&format!(
                    "this run was given no firmware root to read {relative} from; pass --asr-serve-firmware-root DIR"
                ));
            }
        };
        let board_manifest = match self.board_manifest.as_ref() {
            Some(manifest) => manifest,
            None => {
                return missing(
                    "no board manifest was resolved to wrap the payload with, so no Image4 can be built for it",
                );
            }
        };
        let path = root.join(&relative);
        let payload = match std::fs::read(&path) {
            Ok(payload) => payload,
            Err(error) => {
                return missing(&format!("path={} {error}", path.display()));
            }
        };
        let image = match wrap_image4(&payload, board_manifest) {
            Ok(image) => image,
            Err(error) => return Some(Err(ProviderError::Other(error))),
        };
        let chunk_size = requested_chunk_size(request);
        let line = format!(
            "{MUX_PREFIX} result=system-volume-object-served port={} at={:.3}s type={:?} variant=\"{variant}\" variant_chosen_by={chosen_by} component={component} im4p={} img4={} chunk={chunk_size} meaning=\"the seal step's input was answered from the genuine Apple payload this identity's own Info.Path names, wrapped with the board's AP global manifest, which signs isys and msys; the host computes no digest and seals nothing, the guest computes its own over the volume it wrote and apfs_sealvolume compares it against the one inside Apple's payload\" detail=\"path={} manifest={}\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            payload.len(),
            image.len(),
            path.display(),
            self.board_manifest_path
                .as_ref()
                .map_or_else(|| "none".to_string(), |path| path.display().to_string())
        );
        report(&self.reporter, "system-volume-object-served", &line);
        Some(Ok(StreamedObject::from_bytes(image, chunk_size)))
    }

    fn retagged_component_payload(
        &self,
        variant: &str,
        name: &str,
        path: &Path,
    ) -> Option<(Vec<u8>, String)> {
        let identity = raw_identity_for_variant(&self.manifest, &self.hardware_model, variant)?;
        let entry = identity
            .get(IDENTITY_MANIFEST_KEY)?
            .as_dictionary()?
            .get(name)?
            .as_dictionary()?;
        let info = entry.get(COMPONENT_INFO_KEY)?.as_dictionary()?;
        let payload_type = info.get(COMPONENT_PAYLOAD_TYPE_KEY)?.as_string()?;
        let expected = entry.get("Digest")?.as_data()?;
        let method = info
            .get("HashMethod")
            .and_then(plist::Value::as_string)
            .unwrap_or(HASH_METHOD_SHA2_384);
        let retagged = im4p_retag(path, payload_type, method, expected).ok()??;
        Some((retagged.matching?, payload_type.to_string()))
    }

    fn personalized_object(&self, request: &DataRequest) -> Result<StreamedObject, ProviderError> {
        let (variant, chosen_by) = self.variant_for(request);
        let Some(name) = request.argument_string(KEY_IMAGE_NAME) else {
            return Err(ProviderError::Other(
                "a personalised boot object request named no ImageName, so there is nothing to resolve against the build identity".to_string(),
            ));
        };
        let Some(relative) = self.component_path(&variant, name) else {
            return Err(ProviderError::Other(format!(
                "the {variant} identity for {model} names no component {name} with a path, so no payload can be read for it",
                model = self.hardware_model
            )));
        };
        let Some(root) = self.firmware_root.as_ref() else {
            return Err(ProviderError::Other(format!(
                "the guest asked for the personalised {name} and this run was given no firmware root to read {relative} from; pass --asr-serve-firmware-root DIR"
            )));
        };
        let Some(board_manifest) = self.board_manifest.as_ref() else {
            return Err(ProviderError::Other(format!(
                "the guest asked for the personalised {name} and no board manifest was resolved to wrap it with, so the object cannot be personalised"
            )));
        };
        let path = root.join(&relative);
        let (payload, payload_type) = match self.retagged_component_payload(&variant, name, &path) {
            Some((payload, payload_type)) => (payload, payload_type),
            None => (
                std::fs::read(&path).map_err(ProviderError::Io)?,
                "as-shipped".to_string(),
            ),
        };
        let image = wrap_image4(&payload, board_manifest).map_err(ProviderError::Other)?;
        let chunk_size = requested_chunk_size(request);
        let line = format!(
            "{MUX_PREFIX} result=personalized-object-served port={} at={:.3}s type={:?} variant=\"{variant}\" variant_chosen_by={chosen_by} name={name} im4p={} img4={} chunk={chunk_size} payload_type={payload_type} meaning=\"the guest asked for one personalised firmware object by name and it was built from the payload that identity's own Info.Path names, wrapped with the board's global manifest, which is the same Image4 the NOR payload carries; payload_type is the Image4 type the container went out carrying, which is the one this identity states for the component when it states one, because that is what the manifest signs the object's tag as. It goes back as a streamed object because the guest reads this type with a RestoreFileDataMessageStream and not as a reply dictionary\" detail=\"path={} manifest={}\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            payload.len(),
            image.len(),
            path.display(),
            self.board_manifest_path
                .as_ref()
                .map_or_else(|| "none".to_string(), |path| path.display().to_string())
        );
        report(&self.reporter, "personalized-object-served", &line);
        Ok(StreamedObject::from_bytes(image, chunk_size))
    }
}

impl RestoreDataProvider for PersonalizedFirmwareProvider {
    fn supply(&mut self, request: &DataRequest) -> Result<plist::Dictionary, ProviderError> {
        if request.argument_bool(KEY_IMAGE_LIST) != Some(true) {
            let line = format!(
                "{MUX_PREFIX} result=personalized-list-not-requested port={} at={:.3}s type={:?} args=[{}] meaning=\"this request is the personalised data type but does not set ImageList, which is the only shape of it this host answers, so the reply carries no key and nothing was guessed about what else it might have wanted\" detail=\"\"",
                self.port,
                self.armed_at_secs,
                request.data_type,
                describe_dictionary_entries(&request.arguments)
            );
            report(&self.reporter, "personalized-list-not-requested", &line);
            return Ok(plist::Dictionary::new());
        }
        let Some(flag) = request.argument_string(KEY_IMAGE_TYPE) else {
            let line = format!(
                "{MUX_PREFIX} result=personalized-list-untyped port={} at={:.3}s type={:?} args=[{}] meaning=\"the guest asked for an image list without naming the ImageType, and the type is the build identity Info flag the list is read off, so there is nothing to enumerate; no list is invented\" detail=\"\"",
                self.port,
                self.armed_at_secs,
                request.data_type,
                describe_dictionary_entries(&request.arguments)
            );
            report(&self.reporter, "personalized-list-untyped", &line);
            return Ok(plist::Dictionary::new());
        };
        let (variant, chosen_by) = self.variant_for(request);
        let Some(names) = self.components_flagged(&variant, flag) else {
            let line = format!(
                "{MUX_PREFIX} result=personalized-list-identity-absent port={} at={:.3}s type={:?} variant=\"{variant}\" variant_chosen_by={chosen_by} model={} image_type={flag} meaning=\"this manifest carries no identity for that variant and model, so there is no component list to read the flag off; the reply carries no key and the guest reports the missing list itself\" detail=\"\"",
                self.port, self.armed_at_secs, request.data_type, self.hardware_model
            );
            report(&self.reporter, "personalized-list-identity-absent", &line);
            return Ok(plist::Dictionary::new());
        };
        let mut body = plist::Dictionary::new();
        body.insert(
            KEY_IMAGE_LIST.to_string(),
            plist::Value::Array(
                names
                    .iter()
                    .map(|name| plist::Value::String(name.clone()))
                    .collect(),
            ),
        );
        let line = format!(
            "{MUX_PREFIX} result=personalized-list-answered port={} at={:.3}s type={:?} variant=\"{variant}\" variant_chosen_by={chosen_by} model={} image_type={flag} images={} names=[{}] meaning=\"the guest's image list request was answered by reading the Info flag it named off every component of that identity's own Manifest; an empty list is the answer for an identity that flags none, and update_iBoot skips the whole EAN write below a count of one, which is what a missing list could not tell it\" detail=\"\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            self.hardware_model,
            names.len(),
            names.join(",")
        );
        report(&self.reporter, "personalized-list-answered", &line);
        Ok(body)
    }

    fn supply_streamed(
        &mut self,
        request: &DataRequest,
    ) -> Option<Result<StreamedObject, ProviderError>> {
        match &request.data_type {
            DataType::PersonalizedBootObjectV3 => Some(self.personalized_object(request)),
            DataType::SystemImageRootHash => {
                self.system_volume_object(request, COMPONENT_SYSTEM_VOLUME)
            }
            DataType::SystemImageCanonicalMetadata => {
                self.system_volume_object(request, COMPONENT_SYSTEM_VOLUME_CANONICAL_METADATA)
            }
            _ => None,
        }
    }
}

fn requested_chunk_size(request: &DataRequest) -> usize {
    request
        .argument_integer(KEY_DATA_CHUNK_SIZE)
        .and_then(|size| usize::try_from(size).ok())
        .unwrap_or(0)
}

const HASH_METHOD_SHA2_384: &str = "sha2-384";
const HASH_METHOD_SHA2_256: &str = "sha2-256";

fn file_digest(path: &Path, method: &str) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read;

    enum Hasher {
        Sha384(Sha512),
        Sha256(Sha256),
    }
    let mut hasher = match method {
        HASH_METHOD_SHA2_384 => Hasher::Sha384(Sha512::sha384()),
        HASH_METHOD_SHA2_256 => Hasher::Sha256(Sha256::new()),
        _ => return Ok(None),
    };
    let mut file = std::fs::File::open(path)?;
    let mut buffer = vec![0u8; 1 << 22];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        match &mut hasher {
            Hasher::Sha384(inner) => inner.update(&buffer[..read]),
            Hasher::Sha256(inner) => inner.update(&buffer[..read]),
        }
    }
    Ok(Some(match hasher {
        Hasher::Sha384(inner) => inner.finish()[..48].to_vec(),
        Hasher::Sha256(inner) => inner.finish().to_vec(),
    }))
}

fn bytes_digest(bytes: &[u8], method: &str) -> Option<Vec<u8>> {
    match method {
        HASH_METHOD_SHA2_384 => {
            let mut hasher = Sha512::sha384();
            hasher.update(bytes);
            Some(hasher.finish()[..48].to_vec())
        }
        HASH_METHOD_SHA2_256 => {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            Some(hasher.finish().to_vec())
        }
        _ => None,
    }
}

fn der_header(bytes: &[u8], offset: usize) -> Option<(u8, usize, usize)> {
    let identifier = *bytes.get(offset)?;
    let first = *bytes.get(offset.checked_add(1)?)?;
    let (length, contents) = if first & 0x80 == 0 {
        (usize::from(first), offset.checked_add(2)?)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for index in 0..count {
            length = (length << 8)
                | usize::from(*bytes.get(offset.checked_add(2)?.checked_add(index)?)?);
        }
        (length, offset.checked_add(2)?.checked_add(count)?)
    };
    Some((identifier, contents, length))
}

fn im4p_type_span(bytes: &[u8]) -> Option<(usize, usize)> {
    const DER_SEQUENCE: u8 = 0x30;
    const DER_IA5_STRING: u8 = 0x16;
    let (identifier, contents, length) = der_header(bytes, 0)?;
    if identifier != DER_SEQUENCE {
        return None;
    }
    let end = contents.checked_add(length)?;
    let (identifier, magic_at, magic_len) = der_header(bytes, contents)?;
    if identifier != DER_IA5_STRING
        || bytes.get(magic_at..magic_at.checked_add(magic_len)?)? != b"IM4P"
    {
        return None;
    }
    let after_magic = magic_at.checked_add(magic_len)?;
    if after_magic >= end {
        return None;
    }
    let (identifier, type_at, type_len) = der_header(bytes, after_magic)?;
    if identifier != DER_IA5_STRING {
        return None;
    }
    bytes.get(type_at..type_at.checked_add(type_len)?)?;
    Some((type_at, type_len))
}

const IM4P_HEADER_PROBE_BYTES: usize = 64;

fn im4p_file_type(path: &Path) -> Option<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).ok()?;
    let mut prefix = [0u8; IM4P_HEADER_PROBE_BYTES];
    let mut filled = 0usize;
    while filled < prefix.len() {
        match file.read(&mut prefix[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    let (type_at, type_len) = im4p_type_span(&prefix[..filled])?;
    std::str::from_utf8(&prefix[type_at..type_at + type_len])
        .ok()
        .map(str::to_string)
}

const IM4P_RETAG_MAX_BYTES: u64 = 64 << 20;

struct Im4pRetag {
    digest: Option<Vec<u8>>,
    matching: Option<Vec<u8>>,
}

fn im4p_retag(
    path: &Path,
    payload_type: &str,
    method: &str,
    expected: &[u8],
) -> std::io::Result<Option<Im4pRetag>> {
    if std::fs::metadata(path)?.len() > IM4P_RETAG_MAX_BYTES {
        return Ok(None);
    }
    let bytes = std::fs::read(path)?;
    let Some((type_at, type_len)) = im4p_type_span(&bytes) else {
        return Ok(None);
    };
    if type_len != payload_type.len() {
        return Ok(None);
    }
    let mut retagged = bytes;
    retagged[type_at..type_at + type_len].copy_from_slice(payload_type.as_bytes());
    let digest = bytes_digest(&retagged, method);
    let matching = (digest.as_deref() == Some(expected)).then_some(retagged);
    Ok(Some(Im4pRetag { digest, matching }))
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct DigestKey {
    path: PathBuf,
    len: u64,
    modified_nanos: u128,
    method: String,
}

static DIGEST_CACHE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<DigestKey, Option<Vec<u8>>>>,
> = std::sync::OnceLock::new();

#[derive(Clone, Copy, Debug, Default)]
struct VerifyCost {
    files_hashed: u64,
    bytes_hashed: u64,
    cache_hits: u64,
    bytes_not_rehashed: u64,
}

fn cached_file_digest(
    path: &Path,
    method: &str,
    metadata: &std::fs::Metadata,
    cost: &mut VerifyCost,
) -> std::io::Result<Option<Vec<u8>>> {
    let modified_nanos = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |since| since.as_nanos());
    let key = DigestKey {
        path: path.to_path_buf(),
        len: metadata.len(),
        modified_nanos,
        method: method.to_string(),
    };
    let cache =
        DIGEST_CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    if let Some(hit) = lock_digest_cache(cache).get(&key).cloned() {
        cost.cache_hits += 1;
        cost.bytes_not_rehashed += metadata.len();
        return Ok(hit);
    }
    let digest = file_digest(path, method)?;
    cost.files_hashed += 1;
    cost.bytes_hashed += metadata.len();
    lock_digest_cache(cache).insert(key, digest.clone());
    Ok(digest)
}

fn lock_digest_cache(
    cache: &std::sync::Mutex<std::collections::HashMap<DigestKey, Option<Vec<u8>>>>,
) -> std::sync::MutexGuard<'_, std::collections::HashMap<DigestKey, Option<Vec<u8>>>> {
    match cache.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

const GLOBAL_MANIFEST_PREFIX_DEFAULT: &str = "apticket";

// The second field is the four character code the guest finds `IM4M.object[<tag>].DGST` under; the table is fixed in the guest, so it is fixed here.
pub const SPLAT_COMPONENTS: &[(&str, &str)] = &[
    ("Cryptex1,SystemOS", "csos"),
    ("Cryptex1,SystemVolume", "cssy"),
    ("Cryptex1,SystemTrustCache", "trcs"),
    ("Cryptex1,AppOS", "caos"),
    ("Cryptex1,AppVolume", "casy"),
    ("Cryptex1,AppTrustCache", "trca"),
];

pub const SPLAT_VERIFY_BUDGET_BYTES: u64 = 1 << 30;

#[derive(Clone, Debug)]
pub enum SplatComponent {
    Serve {
        path: PathBuf,
        len: u64,
        verified: bool,
    },
    Omit {
        reason: String,
    },
    Unlisted {
        reason: String,
    },
}

#[derive(Clone, Debug, Default)]
pub struct SplatPlan {
    pub components: std::collections::BTreeMap<String, SplatComponent>,
}

impl SplatPlan {
    #[must_use]
    pub fn omitted(&self) -> Vec<String> {
        self.components
            .iter()
            .filter(|(_, component)| matches!(component, SplatComponent::Omit { .. }))
            .map(|(name, _)| name.clone())
            .collect()
    }
}

#[allow(clippy::too_many_arguments)]
pub fn resolve_splat_components(
    manifest: &plist::Dictionary,
    hardware_model: &str,
    variant: &str,
    ticket: Option<&[u8]>,
    firmware_root: Option<&PathBuf>,
    image_root: Option<&PathBuf>,
    port: u16,
    armed_at_secs: f64,
    reporter: &SharedReporter,
) -> SplatPlan {
    let mut plan = SplatPlan::default();
    let identity = raw_identity_for_variant(manifest, hardware_model, variant);
    let ticket = ticket.and_then(|bytes| crate::ramrod::read_manifest(bytes).ok());
    let began = std::time::Instant::now();
    // Utility, not background: background also puts the thread in I/O throttling tier 3, and this reads whole payloads off disk.
    let ((resolved, cost), hashing_class) = with_thread_class(ThreadClass::Utility, || {
        let mut cost = VerifyCost::default();
        let resolved: Vec<SplatComponent> = SPLAT_COMPONENTS
            .iter()
            .map(|(name, tag)| {
                resolve_one_splat_component(
                    identity.as_ref(),
                    name,
                    tag,
                    ticket.as_ref(),
                    firmware_root,
                    image_root,
                    &mut cost,
                )
            })
            .collect();
        (resolved, cost)
    });
    let elapsed = began.elapsed().as_secs_f64();
    for ((name, tag), component) in SPLAT_COMPONENTS.iter().zip(resolved) {
        let line = match &component {
            SplatComponent::Serve {
                path,
                len,
                verified,
            } => format!(
                "{MUX_PREFIX} result=splat-component-held port={port} at={armed_at_secs:.3}s variant=\"{variant}\" component={name} tag={tag} bytes={len} digest={} meaning=\"this host holds a genuine copy of one of the six cryptex payloads install_splat installs, so the member stays in the build identity the guest is handed and the SourceBootObjectV4 request for it is answered from this file, byte for byte with nothing wrapped around it\" detail=\"path={}\"",
                if *verified {
                    "ticket-verified"
                } else {
                    "unverified-oversize"
                },
                path.display()
            ),
            SplatComponent::Omit { reason } => format!(
                "{MUX_PREFIX} result=splat-component-omitted port={port} at={armed_at_secs:.3}s variant=\"{variant}\" component={name} tag={tag} meaning=\"DEVIATION FROM A REAL RESTORE: this host holds no genuine copy of this cryptex payload, so the member is dropped from the build identity served to the guest and install_splat skips it with 'isn't present in build identity'. Apple's build does ship it; this tree is short of it. The alternative is not a smaller install, it is a fatal one: a member named by the identity and then not delivered fails the step with a digest mismatch or a malformed transfer, and nothing is fabricated to avoid that\" detail=\"{reason}\"",
            ),
            SplatComponent::Unlisted { reason } => format!(
                "{MUX_PREFIX} result=splat-component-unlisted port={port} at={armed_at_secs:.3}s variant=\"{variant}\" component={name} tag={tag} meaning=\"this is not a deviation and nothing was dropped: Apple's own build identity for this model and variant names no such member, so install_splat never asks for it and would skip it on a real device too. The member is left out of the omitted list because that list is subtracted from every identity this host serves, and taking a name out of an identity that does carry it, on the strength of a lookup in one that does not, is how a host comes to install less than the build describes for no reason\" detail=\"{reason}\"",
            ),
        };
        let label = match &component {
            SplatComponent::Serve { .. } => "splat-component-held",
            SplatComponent::Omit { .. } => "splat-component-omitted",
            SplatComponent::Unlisted { .. } => "splat-component-unlisted",
        };
        report(reporter, label, &line);
        plan.components.insert((*name).to_string(), component);
    }
    let rate = if elapsed > 0.0 {
        #[allow(clippy::cast_precision_loss)]
        let hashed = cost.bytes_hashed as f64;
        hashed / (1024.0 * 1024.0) / elapsed
    } else {
        0.0
    };
    let line = format!(
        "{MUX_PREFIX} result=splat-verify-cost port={port} at={armed_at_secs:.3}s variant=\"{variant}\" elapsed={elapsed:.3}s files_hashed={} bytes_hashed={} rate={rate:.1}MiB/s rehashes_avoided={} bytes_not_rehashed={} thread_class={} disk_io_policy={} competes_with_vcpu={} meaning=\"every payload at or under the verify budget was read and hashed and compared against the ticket, and this is what that cost; the class names what the host's own work was allowed to take from the machine, and no is the invariant that host work cannot take a performance core from a running guest vCPU; disk_io_policy 0 is IOPOL_IMPORTANT, which is the throttle the class would have carried being taken back off, because throttling the host's reads serves no invariant and the guest waits on them\" detail=\"budget={SPLAT_VERIFY_BUDGET_BYTES} bytes; anything larger is served with digest=unverified-oversize on its own line and the guest still hashes every byte it receives\"",
        cost.files_hashed,
        cost.bytes_hashed,
        cost.cache_hits,
        cost.bytes_not_rehashed,
        hashing_class.class,
        hashing_class
            .disk_io_policy
            .map_or_else(|| "unpublished".to_string(), |policy| policy.to_string()),
        if hashing_class.class.competes_with_vcpu() {
            "yes"
        } else {
            "no"
        }
    );
    report(reporter, "splat-verify-cost", &line);
    plan
}

fn payload_search_roots(roots: &[&PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root in roots {
        out.push((*root).clone());
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        let mut nested: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .map(|entry| entry.path())
            .collect();
        nested.sort();
        out.extend(nested);
    }
    out
}

fn version_plist_file_name(component: &str) -> Option<&'static str> {
    match component {
        IMAGE_NAME_RESTORE_VERSION => Some(RESTORE_VERSION_FILE_NAME),
        IMAGE_NAME_SYSTEM_VERSION => Some(SYSTEM_VERSION_FILE_NAME),
        _ => None,
    }
}

fn resolve_one_splat_component(
    identity: Option<&plist::Dictionary>,
    name: &str,
    tag: &str,
    ticket: Option<&crate::ramrod::Im4mManifest>,
    firmware_root: Option<&PathBuf>,
    image_root: Option<&PathBuf>,
    cost: &mut VerifyCost,
) -> SplatComponent {
    let Some(identity) = identity else {
        return SplatComponent::Omit {
            reason: "this manifest carries no identity for that model and variant".to_string(),
        };
    };
    let entry = identity
        .get(IDENTITY_MANIFEST_KEY)
        .and_then(plist::Value::as_dictionary)
        .and_then(|components| components.get(name))
        .and_then(plist::Value::as_dictionary);
    let Some(entry) = entry else {
        return SplatComponent::Unlisted {
            reason: "the build identity itself names no such component, so this is Apple's own build and not a gap in this tree".to_string(),
        };
    };
    let info = entry
        .get(COMPONENT_INFO_KEY)
        .and_then(plist::Value::as_dictionary);
    let Some(manifest_path) = info
        .and_then(|info| info.get(COMPONENT_PATH_KEY))
        .and_then(plist::Value::as_string)
    else {
        return SplatComponent::Omit {
            reason: "the component names no Info/Path, so there is no payload to resolve"
                .to_string(),
        };
    };
    let encoding = identity
        .get(COMPONENT_INFO_KEY)
        .and_then(plist::Value::as_dictionary)
        .and_then(|info| info.get("ContentEncoding"))
        .and_then(plist::Value::as_string);
    let expected = ticket
        .and_then(|ticket| ticket.object(tag))
        .and_then(crate::ramrod::Im4mObject::digest);
    let method = info
        .and_then(|info| info.get("HashMethod"))
        .and_then(plist::Value::as_string)
        .unwrap_or(HASH_METHOD_SHA2_384);
    let mut tried: Vec<String> = Vec::new();
    let mut mismatched: Vec<String> = Vec::new();
    let roots: Vec<&PathBuf> = [firmware_root, image_root].into_iter().flatten().collect();
    for root in payload_search_roots(&roots) {
        for (_, path) in image_candidates(&root, name, manifest_path, encoding) {
            let Ok(metadata) = std::fs::metadata(&path) else {
                tried.push(path.display().to_string());
                continue;
            };
            if !metadata.is_file() {
                tried.push(path.display().to_string());
                continue;
            }
            let len = metadata.len();
            let Some(expected) = expected else {
                return SplatComponent::Serve {
                    path,
                    len,
                    verified: false,
                };
            };
            if len > SPLAT_VERIFY_BUDGET_BYTES {
                return SplatComponent::Serve {
                    path,
                    len,
                    verified: false,
                };
            }
            match cached_file_digest(&path, method, &metadata, cost) {
                Ok(Some(digest)) if digest == expected => {
                    return SplatComponent::Serve {
                        path,
                        len,
                        verified: true,
                    };
                }
                Ok(Some(digest)) => mismatched.push(format!(
                    "{} wanted={} got={}",
                    path.display(),
                    hex_digest(expected),
                    hex_digest(&digest)
                )),
                Ok(None) => {
                    return SplatComponent::Serve {
                        path,
                        len,
                        verified: false,
                    };
                }
                Err(error) => tried.push(format!("{} {error}", path.display())),
            }
        }
    }
    if !mismatched.is_empty() {
        return SplatComponent::Omit {
            reason: format!(
                "the identity names {manifest_path} and every copy this host holds hashes to something other than the ticket's {tag} DGST, so none of them is this build's payload: {}",
                mismatched.join("; ")
            ),
        };
    }
    SplatComponent::Omit {
        reason: format!(
            "the identity names {manifest_path} and no spelling of it is a file under any root this run was given: tried {}",
            tried.join(", ")
        ),
    }
}

fn prefix_is_contained(prefix: &str) -> bool {
    !prefix.is_empty()
        && prefix
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

pub struct SourceBootObjectProvider {
    root: PathBuf,
    default_variant: String,
    hardware_model: String,
    manifest: plist::Dictionary,
    firmware_root: Option<PathBuf>,
    image_root: Option<PathBuf>,
    splat: SplatPlan,
    port: u16,
    armed_at_secs: f64,
    reporter: SharedReporter,
}

impl SourceBootObjectProvider {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        root: PathBuf,
        default_variant: String,
        hardware_model: String,
        manifest: plist::Dictionary,
        firmware_root: Option<PathBuf>,
        image_root: Option<PathBuf>,
        splat: SplatPlan,
        port: u16,
        armed_at_secs: f64,
        reporter: &SharedReporter,
    ) -> Self {
        Self {
            root,
            default_variant,
            hardware_model,
            manifest,
            firmware_root,
            image_root,
            splat,
            port,
            armed_at_secs,
            reporter: Arc::clone(reporter),
        }
    }

    fn source_component(request: &DataRequest) -> Option<&str> {
        if !matches!(
            request.data_type,
            DataType::SourceBootObjectV3
                | DataType::SourceBootObjectV4
                | DataType::SourceBootObjectV5
        ) {
            return None;
        }
        match request.argument_string(KEY_IMAGE_NAME) {
            Some(IMAGE_NAME_GLOBAL_MANIFEST) | None => None,
            Some(name) => Some(name),
        }
    }

    fn source_component_object(
        &self,
        request: &DataRequest,
        component: &str,
    ) -> Option<Result<StreamedObject, ProviderError>> {
        let variant = request
            .argument_string(KEY_VARIANT)
            .unwrap_or(&self.default_variant)
            .to_string();
        let chunk_size = requested_chunk_size(request);
        let refuse = |reason: &str| {
            let line = format!(
                "{MUX_PREFIX} result=source-component-refused port={} at={:.3}s type={:?} variant=\"{variant}\" component={component} chunk={chunk_size} meaning=\"the guest asked for a source build payload by name and this host holds no genuine copy of it, so the answer is a well formed transfer of zero bytes rather than an empty reply dictionary the guest reads as a malformed message; nothing was substituted. For one of the six cryptex members this is fatal at install_splat and should have been prevented by dropping the member from the served build identity, so reaching it means the identity named something this provider cannot answer\" detail=\"{reason}\"",
                self.port, self.armed_at_secs, request.data_type,
            );
            report(&self.reporter, "source-component-refused", &line);
            Some(Ok(StreamedObject::from_bytes(Vec::new(), chunk_size)))
        };
        match self.splat.components.get(component) {
            Some(SplatComponent::Serve {
                path,
                len,
                verified,
            }) => {
                let object = match StreamedObject::from_file(path.clone(), chunk_size) {
                    Ok(object) => object,
                    Err(error) => return Some(Err(ProviderError::Io(error))),
                };
                let line = format!(
                    "{MUX_PREFIX} result=source-component-served port={} at={:.3}s type={:?} variant=\"{variant}\" component={component} bytes={len} chunk={chunk_size} digest={} meaning=\"one of the six cryptex payloads install_splat installs, answered from the genuine Apple file this identity's own Info.Path names, streamed off disk a chunk at a time and never held whole; the bytes go out exactly as they are on disk because that is what the guest hashes against the ticket's DGST, and anything wrapped around them would fail that check\" detail=\"path={}\"",
                    self.port,
                    self.armed_at_secs,
                    request.data_type,
                    if *verified {
                        "ticket-verified"
                    } else {
                        "unverified-oversize"
                    },
                    path.display()
                );
                report(&self.reporter, "source-component-served", &line);
                return Some(Ok(object));
            }
            Some(SplatComponent::Omit { reason }) => return refuse(reason),
            Some(SplatComponent::Unlisted { .. }) | None => {}
        }
        if let Some(file_name) = version_plist_file_name(component) {
            let roots: Vec<&PathBuf> = [self.firmware_root.as_ref(), self.image_root.as_ref()]
                .into_iter()
                .flatten()
                .collect();
            let mut tried: Vec<String> = Vec::new();
            for root in payload_search_roots(&roots) {
                let path = root.join(file_name);
                if !path.is_file() {
                    tried.push(path.display().to_string());
                    continue;
                }
                let object = match StreamedObject::from_file(path.clone(), chunk_size) {
                    Ok(object) => object,
                    Err(error) => return Some(Err(ProviderError::Io(error))),
                };
                let line = format!(
                    "{MUX_PREFIX} result=source-version-plist-served port={} at={:.3}s type={:?} variant=\"{variant}\" component={component} file={file_name} bytes={} chunk={chunk_size} meaning=\"the guest asked for one of the two source build version property lists, which no build identity names and which the host resolves by file name at the root of the extracted tree; the bytes go out exactly as they are on disk and no manifest states a digest for them, so none is checked and none is invented\" detail=\"path={}\"",
                    self.port,
                    self.armed_at_secs,
                    request.data_type,
                    object.len(),
                    path.display()
                );
                report(&self.reporter, "source-version-plist-served", &line);
                return Some(Ok(object));
            }
            return refuse(&format!(
                "{component} names {file_name} at the root of the source build tree and no copy of it is a file under any root this run was given: tried {}",
                tried.join(", ")
            ));
        }
        let Some(identity) =
            raw_identity_for_variant(&self.manifest, &self.hardware_model, &variant)
        else {
            return refuse(&format!(
                "this manifest carries no identity for model {} and variant {variant}",
                self.hardware_model
            ));
        };
        let entry = identity
            .get(IDENTITY_MANIFEST_KEY)
            .and_then(plist::Value::as_dictionary)
            .and_then(|components| components.get(component))
            .and_then(plist::Value::as_dictionary);
        let Some(entry) = entry else {
            return refuse(&format!(
                "the {variant} identity names no component {component} at all"
            ));
        };
        let info = entry
            .get(COMPONENT_INFO_KEY)
            .and_then(plist::Value::as_dictionary);
        let Some(manifest_path) = info
            .and_then(|info| info.get(COMPONENT_PATH_KEY))
            .and_then(plist::Value::as_string)
        else {
            return refuse(&format!(
                "the {variant} identity's {component} names no Info/Path, so there is no payload to resolve"
            ));
        };
        let encoding = identity
            .get(COMPONENT_INFO_KEY)
            .and_then(plist::Value::as_dictionary)
            .and_then(|info| info.get("ContentEncoding"))
            .and_then(plist::Value::as_string);
        let expected = entry.get("Digest").and_then(plist::Value::as_data);
        let payload_type = info
            .and_then(|info| info.get(COMPONENT_PAYLOAD_TYPE_KEY))
            .and_then(plist::Value::as_string);
        let method = info
            .and_then(|info| info.get("HashMethod"))
            .and_then(plist::Value::as_string)
            .unwrap_or(HASH_METHOD_SHA2_384);
        let mut tried: Vec<String> = Vec::new();
        let mut mismatched: Vec<String> = Vec::new();
        let roots: Vec<&PathBuf> = [self.firmware_root.as_ref(), self.image_root.as_ref()]
            .into_iter()
            .flatten()
            .collect();
        for root in payload_search_roots(&roots) {
            for (rule, path) in image_candidates(&root, component, manifest_path, encoding) {
                if !path.is_file() {
                    tried.push(path.display().to_string());
                    continue;
                }
                let (digest, _) =
                    with_thread_class(ThreadClass::Utility, || file_digest(&path, method));
                let digest = match digest {
                    Ok(digest) => digest,
                    Err(error) => {
                        let line = format!(
                            "{MUX_PREFIX} result=source-component-unreadable port={} at={:.3}s type={:?} variant=\"{variant}\" component={component} meaning=\"the payload this component names was located and could not be read, so the request fails by name rather than being answered with a transfer that delivered nothing\" detail=\"path={} {error}\"",
                            self.port,
                            self.armed_at_secs,
                            request.data_type,
                            path.display()
                        );
                        report(&self.reporter, "source-component-unreadable", &line);
                        return Some(Err(ProviderError::Io(error)));
                    }
                };
                match (expected, digest.as_deref()) {
                    (Some(want), Some(got)) if want == got => {}
                    (Some(want), Some(got)) => {
                        let retagged = match payload_type {
                            Some(payload_type) => {
                                let (built, _) = with_thread_class(ThreadClass::Utility, || {
                                    im4p_retag(&path, payload_type, method, want)
                                });
                                match built {
                                    Ok(built) => built,
                                    Err(error) => {
                                        let line = format!(
                                            "{MUX_PREFIX} result=source-component-unreadable port={} at={:.3}s type={:?} variant=\"{variant}\" component={component} meaning=\"the payload this component names was located and could not be read, so the request fails by name rather than being answered with a transfer that delivered nothing\" detail=\"path={} {error}\"",
                                            self.port,
                                            self.armed_at_secs,
                                            request.data_type,
                                            path.display()
                                        );
                                        report(
                                            &self.reporter,
                                            "source-component-unreadable",
                                            &line,
                                        );
                                        return Some(Err(ProviderError::Io(error)));
                                    }
                                }
                            }
                            None => None,
                        };
                        if retagged
                            .as_ref()
                            .is_some_and(|retagged| retagged.matching.is_some())
                        {
                            let object = match StreamedObject::from_file(path.clone(), chunk_size) {
                                Ok(object) => object,
                                Err(error) => return Some(Err(ProviderError::Io(error))),
                            };
                            let payload_type = payload_type.unwrap_or_default();
                            let line = format!(
                                "{MUX_PREFIX} result=source-component-served port={} at={:.3}s type={:?} variant=\"{variant}\" component={component} rule={rule:?} bytes={} chunk={chunk_size} digest=manifest-verified-as-retagged method={method} payload_type={payload_type} file_digest={} meaning=\"this component states an Img4PayloadType the shipped file does not carry, so the digest the identity states is over the container retagged to that type rather than over the file; the retagged form hashes to it, which proves this file is the payload this component describes. The file is streamed off disk untouched, a chunk at a time and never held whole, because that is what the reference host sends for this request; the retag is applied where it is needed, when the object is personalised\" detail=\"path={} manifest_path={manifest_path}\"",
                                self.port,
                                self.armed_at_secs,
                                request.data_type,
                                object.len(),
                                hex_digest(got),
                                path.display(),
                            );
                            report(&self.reporter, "source-component-served", &line);
                            return Some(Ok(object));
                        }
                        let (retagged_digest, verdict) = match (payload_type, &retagged) {
                            (None, _) => (
                                "not-applicable-identity-states-no-type".to_string(),
                                "stale-file-only-one-form-exists",
                            ),
                            (Some(_), Some(retagged)) => (
                                retagged
                                    .digest
                                    .as_deref()
                                    .map_or_else(|| "unhashable-method".to_string(), hex_digest),
                                "stale-file-both-forms-disagree",
                            ),
                            (Some(_), None) => (
                                "underivable".to_string(),
                                "derived-form-uncomputable-not-an-im4p-or-type-length-differs-or-over-retag-bound",
                            ),
                        };
                        mismatched.push(format!(
                            "{} rule={rule:?} file_type={} stated_type={} wanted={} raw={} retagged={retagged_digest} verdict={verdict}",
                            path.display(),
                            im4p_file_type(&path).unwrap_or_else(|| "not-an-im4p".to_string()),
                            payload_type.unwrap_or("none"),
                            hex_digest(want),
                            hex_digest(got),
                        ));
                        continue;
                    }
                    _ => {}
                }
                let object = match StreamedObject::from_file(path.clone(), chunk_size) {
                    Ok(object) => object,
                    Err(error) => return Some(Err(ProviderError::Io(error))),
                };
                let line = format!(
                    "{MUX_PREFIX} result=source-component-served port={} at={:.3}s type={:?} variant=\"{variant}\" component={component} rule={rule:?} bytes={} chunk={chunk_size} digest={} method={method} meaning=\"the guest's named source build request was answered from the genuine Apple payload this identity's own Info.Path names, streamed off disk a chunk at a time and never held whole, in the chunk size the guest asked for; the bytes go out exactly as they are on disk and nothing is wrapped around them\" detail=\"path={} manifest_path={manifest_path}\"",
                    self.port,
                    self.armed_at_secs,
                    request.data_type,
                    object.len(),
                    if expected.is_some() {
                        "manifest-verified"
                    } else {
                        "unverified-manifest-states-none"
                    },
                    path.display(),
                );
                report(&self.reporter, "source-component-served", &line);
                return Some(Ok(object));
            }
        }
        if !mismatched.is_empty() {
            return refuse(&format!(
                "the {variant} identity's {component} names {manifest_path} and every copy this host holds hashes to something else, in every form the identity describes, so none of them is this build's payload. Each candidate below names the Image4 type the file carries, the type the identity states for it if any, the digest the identity wants, the digest of the file as it sits on disk, and the digest of the container retagged to the stated type; verdict=stale-file means a form was built and still disagreed, verdict=derived-form-uncomputable means the stated form could not be built at all and the file is not shown to be stale: {}",
                mismatched.join("; ")
            ));
        }
        refuse(&format!(
            "the {variant} identity's {component} names {manifest_path} and no spelling of it is a file under any root this run was given: tried {}",
            tried.join(", ")
        ))
    }

    fn global_manifest_prefix(request: &DataRequest) -> Option<&str> {
        if !matches!(
            request.data_type,
            DataType::SourceBootObjectV3
                | DataType::SourceBootObjectV4
                | DataType::SourceBootObjectV5
        ) {
            return None;
        }
        if request.argument_string(KEY_IMAGE_NAME) != Some(IMAGE_NAME_GLOBAL_MANIFEST) {
            return None;
        }
        Some(
            request
                .argument_string(KEY_GLOBAL_MANIFEST_PREFIX)
                .unwrap_or(GLOBAL_MANIFEST_PREFIX_DEFAULT),
        )
    }
}

impl RestoreDataProvider for SourceBootObjectProvider {
    fn supply(&mut self, _request: &DataRequest) -> Result<plist::Dictionary, ProviderError> {
        Ok(plist::Dictionary::new())
    }

    fn supply_streamed(
        &mut self,
        request: &DataRequest,
    ) -> Option<Result<StreamedObject, ProviderError>> {
        if let Some(component) = Self::source_component(request) {
            return self.source_component_object(request, component);
        }
        let prefix = Self::global_manifest_prefix(request)?;
        let variant = request
            .argument_string(KEY_VARIANT)
            .unwrap_or(&self.default_variant)
            .to_string();
        let optional = request.argument_bool(KEY_GLOBAL_MANIFEST_OPTIONAL) == Some(true);
        let chunk_size = requested_chunk_size(request);
        if !prefix_is_contained(prefix) {
            let line = format!(
                "{MUX_PREFIX} result=source-boot-object-prefix-refused port={} at={:.3}s type={:?} prefix=\"{prefix}\" meaning=\"the global manifest prefix has a segment that is not a plain name, so it is not joined onto the manifests root; nothing outside the tree is read and the request is left to the ordinary decline\" detail=\"\"",
                self.port, self.armed_at_secs, request.data_type
            );
            report(&self.reporter, "source-boot-object-prefix-refused", &line);
            return None;
        }
        let board = normalise_board(&self.hardware_model);
        let path = self
            .root
            .join(&variant)
            .join(format!("{prefix}.{board}.im4m"));
        if !path.is_file() {
            let line = format!(
                "{MUX_PREFIX} result=source-boot-object-absent port={} at={:.3}s type={:?} variant=\"{variant}\" prefix=\"{prefix}\" board={board} optional={optional} meaning=\"the extracted manifests tree ships no such global manifest for this board, so this host holds nothing genuine for the request and leaves it to be declined; the IPSW ships this object only for the boards that carry the part, the guest marks the request optional and proceeds without it, and no other board's manifest is substituted for it\" detail=\"tried={}\"",
                self.port,
                self.armed_at_secs,
                request.data_type,
                path.display()
            );
            report(&self.reporter, "source-boot-object-absent", &line);
            return None;
        }
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                let line = format!(
                    "{MUX_PREFIX} result=source-boot-object-unreadable port={} at={:.3}s type={:?} variant=\"{variant}\" prefix=\"{prefix}\" meaning=\"the global manifest the request names was located and could not be read, so the request fails by name rather than being answered with an empty transfer that would read as the tree shipping none\" detail=\"path={} {error}\"",
                    self.port,
                    self.armed_at_secs,
                    request.data_type,
                    path.display()
                );
                report(&self.reporter, "source-boot-object-unreadable", &line);
                return Some(Err(ProviderError::Io(error)));
            }
        };
        let line = format!(
            "{MUX_PREFIX} result=source-boot-object-served port={} at={:.3}s type={:?} variant=\"{variant}\" prefix=\"{prefix}\" board={board} optional={optional} bytes={} chunk={chunk_size} meaning=\"the guest's global manifest request was answered from the genuine file the request's own prefix, variant and board name, streamed in the chunk size it asked for\" detail=\"path={}\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            bytes.len(),
            path.display()
        );
        report(&self.reporter, "source-boot-object-served", &line);
        Some(Ok(StreamedObject::from_bytes(bytes, chunk_size)))
    }
}

pub struct RestoreAnswers {
    pub tickets: GlobalManifestProvider,
    pub firmware: Option<NorFirmwareProvider>,
    pub identities: BuildIdentityProvider,
    pub personalized: PersonalizedFirmwareProvider,
    pub source_boot_objects: SourceBootObjectProvider,
    pub fdr: FdrTrustProvider,
    pub port: u16,
    pub armed_at_secs: f64,
    pub reporter: SharedReporter,
}

impl RestoreAnswers {
    fn decline(&self, request: &DataRequest, held: &str) -> plist::Dictionary {
        let streamed = request.arguments.contains_key(KEY_DATA_CHUNK_SIZE);
        let line = format!(
            "{MUX_PREFIX} result=data-declined port={} at={:.3}s type={:?} async={} streamed={streamed} args=[{}] meaning=\"the guest asked for something this host holds nothing genuine for, so the reply is well formed and carries no payload; nothing was fabricated to fill it and the session continues, so the guest logs the key it did not find and fails at the step that needed it rather than on the host tearing the connection down. A request carrying {KEY_DATA_CHUNK_SIZE} is read through RestoreFileDataMessageStream and is answered with a zero length streamed completion, because an empty dictionary carries neither {KEY_FILE_DATA} nor {KEY_FILE_DATA_DONE} and that reader rejects it as a malformed FileData message; a request without it is read as a single reply and is answered with the empty dictionary whose absent key is the answer\" detail=\"{held}\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            request.asynchronous,
            describe_dictionary_entries(&request.arguments)
        );
        report(&self.reporter, "data-declined", &line);
        if streamed {
            streamed_done_message(true)
        } else {
            plist::Dictionary::new()
        }
    }

    fn answer_firmware_updater_personalization(
        &mut self,
        request: &DataRequest,
    ) -> plist::Dictionary {
        let updater = request
            .argument_string(KEY_MESSAGE_ARG_UPDATER_NAME)
            .unwrap_or("unknown");
        if updater != UPDATER_NAME_CRYPTEX1 {
            return self.decline_firmware_updater_personalization(request);
        }
        let manifest = match self.tickets.cryptex1_splat_manifest() {
            Ok(manifest) => manifest,
            Err(error) => {
                let line = format!(
                    "{MUX_PREFIX} result=splat-ticket-manifest-missing port={} at={:.3}s type={:?} updater={updater} meaning=\"the guest asked for the Cryptex1 splat ticket and this host could not resolve the board's genuine cryptex1 global manifest under any variant this restore declared, so the reply carries no ticket key and install_splat fails its presence check at 0x100034038 with FAILURE:2200; no ticket is invented to fill it\" detail=\"{error}\"",
                    self.port, self.armed_at_secs, request.data_type,
                );
                report(&self.reporter, "splat-ticket-manifest-missing", &line);
                return plist::Dictionary::new();
            }
        };
        let repersonalize = request
            .argument_bool("MessageForceRepersonalization")
            .unwrap_or(false);
        let device_generated = request.arguments.contains_key("DeviceGeneratedRequest")
            && request.arguments.contains_key("DeviceGeneratedTags");
        let digest = sha384(&manifest.bytes);
        let mut response = plist::Dictionary::new();
        response.insert(
            KEY_CRYPTEX1_TICKET.to_string(),
            plist::Value::Data(manifest.bytes.clone()),
        );
        let mut body = plist::Dictionary::new();
        body.insert(
            KEY_FIRMWARE_RESPONSE_DATA.to_string(),
            plist::Value::Dictionary(response),
        );
        let line = format!(
            "{MUX_PREFIX} result=splat-ticket-served port={} at={:.3}s type={:?} updater={updater} device_generated={device_generated} repersonalize={repersonalize} variant=\"{}\" bytes={} sha384={} boot_nonce={} signature=apple-intact key={KEY_CRYPTEX1_TICKET} meaning=\"install_splat's Cryptex1 ticket request was answered with the genuine Apple signed cryptex1 global manifest this IPSW ships for this board, byte for byte, under the libauthinstall key kAMAuthInstallTagCryptex1Img4Ticket, inside the reply's FirmwareResponseData dictionary, which is where 0x100034038 reads it; nothing was signed, re-signed, synthesised or rewritten here, and sha384 above is the digest of Apple's file as it sits in the tree\" detail=\"DEVIATION FROM A REAL DEVICE: the guest asked for a REPERSONALISED ticket bound to the Nonce it sent, and a real restore host answers it from Apple's TSS. This host does not use TSS and holds no signing key, so this is a STATIC GLOBAL manifest and not a TSS response, and boot_nonce=unstaged says it carries no Cryptex1 nonce. That is deliberate: ramrod_splat_write_personalized_ticket at 0x100066954 writes these exact bytes to <preboot>/<group>/cryptex1/current/apticket.<board>.<ecid>.im4m, and load_trust_cache_with_type type 0xd cryptex1.boot.os hands that file to the privileged monitor, which re-verifies its RSA-4096 PKCS1v15 SHA-384 signature over the MANB SET. Writing BNCH into MANP grows that SET and invalidates the shipped signature, so a stapled manifest is one no key can make valid. Nothing at restore time wants it: BNCH is read once in restored_external, at 0x100033c88, out of the AP root ticket at 0x100279218, which is the OS role's ticket and is still stapled. path={}\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            manifest.variant,
            manifest.bytes.len(),
            hex_digest(&digest),
            if manifest.nonce_staged {
                "staged"
            } else {
                "unstaged"
            },
            manifest.path.display(),
        );
        report(&self.reporter, "splat-ticket-served", &line);
        body
    }

    fn decline_firmware_updater_personalization(&self, request: &DataRequest) -> plist::Dictionary {
        let updater = request
            .argument_string(KEY_MESSAGE_ARG_UPDATER_NAME)
            .unwrap_or("unknown");
        let repersonalize = request
            .argument_bool("MessageForceRepersonalization")
            .unwrap_or(false);
        let device_generated = request.arguments.contains_key("DeviceGeneratedRequest")
            && request.arguments.contains_key("DeviceGeneratedTags");
        let line = format!(
            "{MUX_PREFIX} result=firmware-updater-personalization-unsigned port={} at={:.3}s type={:?} updater={updater} device_generated={device_generated} repersonalize={repersonalize} args=[{}] meaning=\"the guest is not asking for a firmware image this host has on disk; it built a DeviceGeneratedRequest, the on device half of a TSS personalisation, and is asking the host to return a {updater} object signed against the Nonce it just supplied. That signature is Apple's signing server's alone and no host that does not hold its key can produce it, and unlike Cryptex1 there is no genuine Apple artefact in this IPSW that answers it. The reply is the well formed empty one the guest reads as the object being absent, so the step fails on its own terms rather than on the host tearing the connection down\" detail=\"a genuine personalised {updater} object requires an Apple TSS signature over the device generated request; the host declines by name and fabricates none\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            describe_dictionary_entries(&request.arguments)
        );
        report(
            &self.reporter,
            "firmware-updater-personalization-unsigned",
            &line,
        );
        plist::Dictionary::new()
    }

    fn answer_recovery_os_local_policy(&self, request: &DataRequest) -> plist::Dictionary {
        let manifest = match self.tickets.recovery_os_manifest() {
            Ok(manifest) => manifest,
            Err(error) => return self.decline_recovery_os_local_policy(request, &error),
        };
        let image = match wrap_image4(&RECOVERY_OS_LOCAL_POLICY_IM4P, &manifest.bytes) {
            Ok(image) => image,
            Err(error) => return self.decline_recovery_os_local_policy(request, &error),
        };
        let line = format!(
            "{MUX_PREFIX} result=recovery-os-local-policy-global-signed port={} at={:.3}s type={:?} async={} variant=\"{}\" bytes={} payload_sha384={} manifest_sha384={} key={KEY_AP_LOCAL_POLICY} args=[{}] meaning=\"checkpoint 0x1616 macos_create_recovery_local_policy asked this host for a recoveryOS LocalPolicy. It is stitched here exactly as AMAuthInstallLocalPolicyStitchTicketData does it, IMG4 over the constant lpol IM4P and this board's genuine Apple signed recovery OS global manifest, which is the same file a RecoveryOSRootTicketData request is answered from. Nothing was signed, re-signed or synthesised\" detail=\"DEVIATION FROM A REAL DEVICE: the guest asked for a PERSONALISATION and this is GLOBAL SIGNING. AMAuthInstallApCreatePersonalizedResponse takes the global branch whenever the AP holds a global manifest and then discards the request, which is the state this host is in for every other object it serves, but it means the manifest carries no Ap,RecoveryOSPolicyNonceHash, no Ap,VolumeUUID and no Ap,LocalBoot, so the policy is NOT bound to the nonce the guest just proposed. Only Apple's signing server binds it. The step fails with AMRestoreErrorDomain code 6 either way, because 0x10001546c overwrites its own result with the constant 6, so the ONLY observable difference is the guest's printed line. EXPECT 'bootpolicy_store_recoveryos_policy() failed: 20'. libbootpolicy returns 20 when image4_decode_system_recoveryos_local_policy refuses the blob, and it will: that decoder runs Img4DecodePerformTrustEvaluation for object type lpol against three Apple Tatsu LocalPolicy anchors unconditionally, and a Secure Boot global manifest is neither an lpol manifest nor signed under that anchor. 20 is therefore the CONFIRMING reading, not a surprise: it proves the SEP nonce transaction opened, that get_proposed_recoveryos_policy_nonce_digest returned, that the reply reached the store call, and that the boundary is Apple's signature and nothing upstream of it. A different number means something upstream changed: 5 is a zero length blob, 6 is a decoded blob whose ronh tag is absent or does not equal the SEP's proposed digest, 4 is a write failure under the Preboot mount, and a bootpolicy_update_recoveryos_policy_nonce_begin or get_proposed failure would have fired before this host was asked at all\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            request.asynchronous,
            manifest.variant,
            image.len(),
            hex_digest(&RECOVERY_OS_LOCAL_POLICY_IM4P_SHA384),
            hex_digest(&sha384(&manifest.bytes)),
            describe_dictionary_entries(&request.arguments)
        );
        report(
            &self.reporter,
            "recovery-os-local-policy-global-signed",
            &line,
        );
        let mut reply = plist::Dictionary::new();
        reply.insert(KEY_AP_LOCAL_POLICY.to_string(), plist::Value::Data(image));
        reply
    }

    fn decline_recovery_os_local_policy(
        &self,
        request: &DataRequest,
        reason: &str,
    ) -> plist::Dictionary {
        let line = format!(
            "{MUX_PREFIX} result=recovery-os-local-policy-unsigned port={} at={:.3}s type={:?} async={} args=[{}] meaning=\"checkpoint 0x1616 macos_create_recovery_local_policy asked this host to personalise a recoveryOS LocalPolicy bound to the policy nonce digest it just proposed. A real restore host answers it from _handleRecoveryOSLocalPolicyRequest by way of AMAuthInstallBundlePersonalizeRecoveryOSLocalPolicy, which reaches Apple's signing server over the guest's own nonce; this host holds no signing key and could not even fall back to the global signing branch, so the reply carries no {KEY_AP_LOCAL_POLICY} and none is invented\" detail=\"TRUST BOUNDARY BLOCKER. The guest wanted one key, {KEY_AP_LOCAL_POLICY}, carrying a CFData it feeds to bootpolicy_store_recoveryos_policy. With this empty reply it prints nothing at all: it takes 0x10002b71c, fails the step with 0x2c and logs no line of its own, so this is the only record. What stopped the global signing branch: {reason}\"",
            self.port,
            self.armed_at_secs,
            request.data_type,
            request.asynchronous,
            describe_dictionary_entries(&request.arguments)
        );
        report(&self.reporter, "recovery-os-local-policy-unsigned", &line);
        plist::Dictionary::new()
    }
}

impl RestoreDataProvider for RestoreAnswers {
    fn supply(&mut self, request: &DataRequest) -> Result<plist::Dictionary, ProviderError> {
        let wire_name = request.data_type.wire_name();
        if wire_name == FDR_TRUST_DATA_TYPE || wire_name == FDR_MEMORY_COMMIT_DATA_TYPE {
            return self.fdr.supply(request);
        }
        if wire_name == NOR_DATA_TYPE {
            return match &mut self.firmware {
                Some(firmware) => firmware.supply(request),
                None => {
                    let line = format!(
                        "{MUX_PREFIX} result=nor-source-absent port={} at={:.3}s type={:?} args=[{}] meaning=\"the guest asked for the firmware payload and this run was given no firmware root to build it from. The reply is fetched once and drained key by key, so an empty dictionary here is a NULL RestoreSEPImageData the guest can never ask for again, which load_sep_os logs as no sep firmware and fails with error 0x33; refusing the request by name here, where the cause is known, rather than answering with an empty dictionary and letting the guest fail on its own terms\" detail=\"pass --asr-serve-firmware-root DIR\"",
                        self.port,
                        self.armed_at_secs,
                        request.data_type,
                        request
                            .arguments
                            .keys()
                            .map(String::as_str)
                            .collect::<Vec<_>>()
                            .join(",")
                    );
                    report(&self.reporter, "nor-source-absent", &line);
                    Err(ProviderError::Other(String::from(
                        "no --asr-serve-firmware-root was given, so the guest's NORData request cannot be answered and load_sep_os would fail on it unattributably",
                    )))
                }
            };
        }
        if matches!(
            request.data_type,
            DataType::BuildIdentityDict
                | DataType::BuildIdentityDictV2
                | DataType::RecoveryOSVersionData
        ) {
            let body = self.identities.supply(request)?;
            if let Some(variant) = self.identities.last_variant().map(str::to_string) {
                self.personalized.follow_variant(&variant);
            }
            return Ok(body);
        }
        if wire_name == PERSONALIZED_DATA_TYPE {
            return self.personalized.supply(request);
        }
        if wire_name == EAN_DATA_TYPE {
            return Ok(self.personalized.early_access_list(request));
        }
        if wire_name == FUD_DATA_TYPE {
            return Ok(self.personalized.fud_list(request));
        }
        if wire_name == FIRMWARE_UPDATER_DATA_TYPE || wire_name == FIRMWARE_UPDATER_DATA_V2_TYPE {
            return Ok(self.answer_firmware_updater_personalization(request));
        }
        if GlobalManifestProvider::classify(request).is_some() {
            return self.tickets.supply(request);
        }
        if request.data_type == DataType::RecoveryOSLocalPolicy {
            return Ok(self.answer_recovery_os_local_policy(request));
        }
        Ok(self.decline(
            request,
            "this host serves tickets from --asr-serve-global-manifests, firmware from --asr-serve-firmware-root, build identities from the BuildManifest and the FDR trust reply, and holds nothing for this type",
        ))
    }

    fn supply_streamed(
        &mut self,
        request: &DataRequest,
    ) -> Option<Result<StreamedObject, ProviderError>> {
        match self.source_boot_objects.supply_streamed(request) {
            Some(result) => Some(result),
            None => self.personalized.supply_streamed(request),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BuildIdentityProvider, COMPONENT_SYSTEM_VOLUME, COMPONENT_SYSTEM_VOLUME_CANONICAL_METADATA,
        EAN_DATA_TYPE, FDR_MEMORY_COMMIT_DATA_TYPE, FDR_TRUST_DATA_TYPE, FDR_TRUST_OBJECT_TAGS,
        FIRMWARE_UPDATER_DATA_TYPE, FUD_DATA_TYPE, FdrTrustDigest, FdrTrustProvider,
        GlobalManifestProvider, IDENTITY_MANIFEST_KEY, KEY_AP_LOCAL_POLICY,
        KEY_BOOTED_OS_FDR_TRUST_DATA, KEY_CRYPTEX1_TICKET, KEY_EAN_IMAGE_LIST,
        KEY_FDR_MEMORY_STORE_DATA, KEY_FDR_TRUST_DATA, KEY_FIRMWARE_RESPONSE_DATA,
        KEY_FUD_IMAGE_LIST, KEY_MESSAGE_ARG_UPDATER_NAME, KEY_RECOVERY_OS_VERSION_DATA,
        NorFirmwareProvider, PERSONALIZED_DATA_TYPE, PersonalizedFirmwareProvider,
        RECOVERY_OS_LOCAL_POLICY_IM4P, RECOVERY_OS_LOCAL_POLICY_IM4P_SHA384, RamrodTrace,
        RestoreAnswers, RestoreVariants, SourceBootObjectProvider, SplatComponent, SplatPlan,
        UPDATER_NAME_CRYPTEX1, describe_dictionary_entries, describe_plist_value, im4p_type_span,
        resolve_splat_components, wrap_image4,
    };
    use crate::crypto::{sha256, sha384};
    use crate::ramrod::{
        BOOT_NONCE_HASH_BYTES, BuildIdentity, Checkpoint, DataRequest, DataType,
        IMAGE_NAME_GLOBAL_MANIFEST, KEY_DATA_CHUNK_SIZE, KEY_GLOBAL_MANIFEST_OPTIONAL,
        KEY_GLOBAL_MANIFEST_PREFIX, KEY_IMAGE_LIST, KEY_IMAGE_NAME, KEY_IMAGE_TYPE, ProviderError,
        RestoreDataProvider, SessionObserver, StreamedObject, TRUST_OBJECT_KEY,
    };
    use crate::restore::{RestoreEvent, RestoreReporter, SharedReporter, StdoutReporter};
    use std::sync::Arc;

    struct CapturingReporter {
        lines: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl RestoreReporter for CapturingReporter {
        fn event(&mut self, event: RestoreEvent<'_>) {
            self.lines.lock().unwrap().push(event.line.to_string());
        }
    }

    fn capturing() -> (
        SharedReporter,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let reporter: SharedReporter =
            std::sync::Arc::new(std::sync::Mutex::new(CapturingReporter {
                lines: std::sync::Arc::clone(&lines),
            }));
        (reporter, lines)
    }

    fn reporter() -> SharedReporter {
        StdoutReporter::shared()
    }

    fn test_trust_object() -> Vec<u8> {
        vec![0x30, 0x06, 0x16, 0x04, b'r', b'v', b'o', b'k']
    }

    const TEST_INSTANCE: &str = "00008103-1122334455667788";

    fn test_trust_digest() -> FdrTrustDigest {
        FdrTrustDigest {
            digest: sha256(&test_trust_object()),
            element_index: 0,
            element_count: 1,
            trust_object: test_trust_object(),
            instance: Some(TEST_INSTANCE.to_string()),
        }
    }

    fn test_fdr_provider(reporter: &SharedReporter) -> FdrTrustProvider {
        FdrTrustProvider::new(Some(&test_trust_digest()), 62078, 0.0, reporter)
    }

    fn test_variants() -> RestoreVariants {
        RestoreVariants {
            install: "Customer Erase Install (IPSW)".to_string(),
            recovery_os: "macOS Customer".to_string(),
        }
    }

    fn identity_manifest() -> plist::Dictionary {
        let entry = |variant: &str, marker: i64| {
            let mut info = plist::Dictionary::new();
            info.insert("DeviceClass".into(), plist::Value::String("j274ap".into()));
            info.insert("Variant".into(), plist::Value::String(variant.into()));
            info.insert("BuildNumber".into(), plist::Value::String("25F80".into()));
            info.insert("BuildTrain".into(), plist::Value::String("CheerF".into()));
            info.insert(
                "ProductMarketingVersion".into(),
                plist::Value::String(format!("26.5.{marker}")),
            );
            let mut body = plist::Dictionary::new();
            body.insert("Info".into(), plist::Value::Dictionary(info));
            body.insert(
                "MarkerForTheTest".into(),
                plist::Value::Integer(marker.into()),
            );
            plist::Value::Dictionary(body)
        };
        let mut root = plist::Dictionary::new();
        root.insert(
            "BuildIdentities".into(),
            plist::Value::Array(vec![
                entry("Customer Erase Install (IPSW)", 1),
                entry("macOS Customer", 2),
                entry("Research Erase Install (IPSW)", 3),
            ]),
        );
        root
    }

    fn im4p_container(payload_type: &str, body: &[u8]) -> Vec<u8> {
        fn ia5(text: &str) -> Vec<u8> {
            let mut out = vec![0x16u8, u8::try_from(text.len()).unwrap()];
            out.extend_from_slice(text.as_bytes());
            out
        }
        let mut inner = ia5("IM4P");
        inner.extend(ia5(payload_type));
        inner.extend(ia5("1"));
        inner.push(0x04);
        inner.push(u8::try_from(body.len()).unwrap());
        inner.extend_from_slice(body);
        let mut out = vec![0x30u8, u8::try_from(inner.len()).unwrap()];
        out.extend(inner);
        out
    }

    #[test]
    fn the_im4p_type_span_is_the_second_string_of_the_container() {
        let container = im4p_container("dcpf", b"payload");
        let (at, len) = im4p_type_span(&container).expect("a well formed IM4P has a type span");
        assert_eq!(len, 4);
        assert_eq!(&container[at..at + len], b"dcpf");
        assert_eq!(im4p_type_span(&[]), None);
        assert_eq!(im4p_type_span(&[0x30, 0x83, 0x00]), None);
        assert_eq!(im4p_type_span(&[0x04, 0x02, 0x41, 0x42]), None);
        let mut not_im4p = im4p_container("dcpf", b"payload");
        not_im4p[4] = b'X';
        assert_eq!(im4p_type_span(&not_im4p), None);
        assert_eq!(im4p_type_span(&container[..at + len]), Some((at, len)));
        assert_eq!(im4p_type_span(&container[..at + len - 1]), None);
        assert_eq!(im4p_type_span(&container[..at - 1]), None);
    }

    #[test]
    fn retagging_changes_the_type_and_no_other_byte() {
        let shipped = im4p_container("dcpf", b"payload");
        let expected = im4p_container("dcp2", b"payload");
        assert_eq!(shipped.len(), expected.len());
        let (at, len) = im4p_type_span(&shipped).expect("a type span");
        let mut retagged = shipped.clone();
        retagged[at..at + len].copy_from_slice(b"dcp2");
        assert_eq!(retagged, expected);
        assert_eq!(
            shipped
                .iter()
                .zip(&retagged)
                .filter(|(left, right)| left != right)
                .count(),
            1
        );
    }

    #[test]
    fn the_recovery_os_version_reply_comes_out_of_the_recovery_identity() {
        let mut provider = test_identity_provider();
        let body = provider
            .supply(&data_request(DataType::RecoveryOSVersionData))
            .unwrap();
        let xml = body
            .get(KEY_RECOVERY_OS_VERSION_DATA)
            .and_then(plist::Value::as_data)
            .expect("the reply carries the version data under its own name");
        let version: plist::Dictionary = plist::from_bytes(xml).unwrap();
        assert_eq!(
            version.get("Variant").and_then(plist::Value::as_string),
            Some("macOS Customer"),
            "the install identity's variant would be the wrong build entirely"
        );
        assert_eq!(
            version.get("BuildNumber").and_then(plist::Value::as_string),
            Some("25F80")
        );
        assert_eq!(
            version.get("BuildTrain").and_then(plist::Value::as_string),
            Some("CheerF")
        );
        assert_eq!(
            version
                .get("ProductVersion")
                .and_then(plist::Value::as_string),
            Some("26.5.2")
        );
        assert!(!version.contains_key("ProductMarketingVersion"));
    }

    fn test_identity_provider() -> BuildIdentityProvider {
        BuildIdentityProvider::new(
            identity_manifest(),
            "J274AP".to_string(),
            "Customer Erase Install (IPSW)".to_string(),
            "macOS Customer".to_string(),
            Vec::new(),
            62078,
            0.0,
            &reporter(),
        )
    }

    fn test_personalized_provider() -> PersonalizedFirmwareProvider {
        PersonalizedFirmwareProvider::new(
            identity_manifest(),
            "J274AP".to_string(),
            "Customer Erase Install (IPSW)".to_string(),
            "macOS Customer".to_string(),
            None,
            None,
            None,
            62078,
            0.0,
            &reporter(),
        )
    }

    fn test_source_boot_object_provider(root: &std::path::Path) -> SourceBootObjectProvider {
        SourceBootObjectProvider::new(
            root.to_path_buf(),
            "Customer Erase Install (IPSW)".to_string(),
            "J274AP".to_string(),
            identity_manifest(),
            None,
            None,
            SplatPlan::default(),
            62078,
            0.0,
            &reporter(),
        )
    }

    fn data_request(data_type: DataType) -> DataRequest {
        DataRequest {
            data_type,
            data_port: None,
            arguments: plist::Dictionary::new(),
            asynchronous: false,
            async_context_uuid: None,
        }
    }

    fn data_request_with(data_type: DataType, arguments: Vec<(&str, plist::Value)>) -> DataRequest {
        let mut request = data_request(data_type);
        for (key, value) in arguments {
            request.arguments.insert(key.to_string(), value);
        }
        request
    }

    fn flagged_identity_manifest() -> plist::Dictionary {
        let component = |path: &str, flags: &[(&str, bool)]| {
            let mut info = plist::Dictionary::new();
            info.insert("Path".into(), plist::Value::String(path.into()));
            for (name, value) in flags {
                info.insert((*name).into(), plist::Value::Boolean(*value));
            }
            let mut body = plist::Dictionary::new();
            body.insert("Info".into(), plist::Value::Dictionary(info));
            plist::Value::Dictionary(body)
        };
        let identity = |variant: &str, components: Vec<(&str, plist::Value)>| {
            let mut info = plist::Dictionary::new();
            info.insert("DeviceClass".into(), plist::Value::String("j274ap".into()));
            info.insert("Variant".into(), plist::Value::String(variant.into()));
            let mut manifest = plist::Dictionary::new();
            for (name, value) in components {
                manifest.insert(name.into(), value);
            }
            let mut body = plist::Dictionary::new();
            body.insert("Info".into(), plist::Value::Dictionary(info));
            body.insert("Manifest".into(), plist::Value::Dictionary(manifest));
            plist::Value::Dictionary(body)
        };
        let mut root = plist::Dictionary::new();
        root.insert(
            "BuildIdentities".into(),
            plist::Value::Array(vec![
                identity(
                    "Customer Erase Install (IPSW)",
                    vec![
                        (
                            "Ap,TMU",
                            component("Firmware/tmu.im4p", &[("IsiBootEANFirmware", true)]),
                        ),
                        (
                            "Ap,CIO",
                            component("Firmware/cio.im4p", &[("IsiBootEANFirmware", true)]),
                        ),
                        (
                            "iBoot",
                            component("Firmware/iboot.im4p", &[("IsiBootEANFirmware", false)]),
                        ),
                        (
                            "Ap,AudioBootChime",
                            component(
                                "Firmware/chime.im4p",
                                &[("IsiBootNonEssentialFirmware", true)],
                            ),
                        ),
                        (
                            "GFX",
                            component("Firmware/agx.im4p", &[("IsFUDFirmware", true)]),
                        ),
                        (
                            "PMP",
                            component(
                                "Firmware/pmp.im4p",
                                &[("IsFUDFirmware", true), ("IsEarlyAccessFirmware", false)],
                            ),
                        ),
                    ],
                ),
                identity(
                    "macOS Customer",
                    vec![
                        (
                            "iBoot",
                            component("Firmware/iboot.im4p", &[("IsiBootEANFirmware", false)]),
                        ),
                        (
                            "SIO",
                            component("Firmware/sio.im4p", &[("IsFUDFirmware", true)]),
                        ),
                    ],
                ),
            ]),
        );
        root
    }

    fn flagged_personalized_provider() -> PersonalizedFirmwareProvider {
        PersonalizedFirmwareProvider::new(
            flagged_identity_manifest(),
            "J274AP".to_string(),
            "Customer Erase Install (IPSW)".to_string(),
            "macOS Customer".to_string(),
            None,
            None,
            None,
            62078,
            0.0,
            &reporter(),
        )
    }

    fn image_list_request(image_type: &str) -> DataRequest {
        data_request_with(
            DataType::Other(PERSONALIZED_DATA_TYPE.to_string()),
            vec![
                (KEY_IMAGE_LIST, plist::Value::Boolean(true)),
                (KEY_IMAGE_TYPE, plist::Value::String(image_type.to_string())),
            ],
        )
    }

    fn served_names(body: &plist::Dictionary) -> Vec<String> {
        body.get(KEY_IMAGE_LIST)
            .and_then(plist::Value::as_array)
            .expect("the list travels back under the key the request set")
            .iter()
            .map(|value| {
                value
                    .as_string()
                    .expect("every entry is a component name")
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn an_image_list_is_read_off_the_info_flag_the_request_names() {
        let mut provider = flagged_personalized_provider();
        let body = provider
            .supply(&image_list_request("IsiBootEANFirmware"))
            .unwrap();
        assert_eq!(served_names(&body), vec!["Ap,CIO", "Ap,TMU"]);
        let body = provider
            .supply(&image_list_request("IsiBootNonEssentialFirmware"))
            .unwrap();
        assert_eq!(served_names(&body), vec!["Ap,AudioBootChime"]);
    }

    #[test]
    fn an_identity_that_flags_nothing_is_answered_with_an_empty_list() {
        let mut provider = flagged_personalized_provider();
        let request = data_request_with(
            DataType::Other(PERSONALIZED_DATA_TYPE.to_string()),
            vec![
                (KEY_IMAGE_LIST, plist::Value::Boolean(true)),
                (
                    KEY_IMAGE_TYPE,
                    plist::Value::String("IsiBootEANFirmware".to_string()),
                ),
                (
                    crate::ramrod::message::KEY_VARIANT,
                    plist::Value::String("macOS Customer".to_string()),
                ),
            ],
        );
        let body = provider.supply(&request).unwrap();
        assert!(
            body.contains_key(KEY_IMAGE_LIST),
            "the key is present even when nothing is flagged"
        );
        assert!(served_names(&body).is_empty());
    }

    #[test]
    fn an_image_list_follows_the_identity_the_guest_was_handed() {
        let mut provider = flagged_personalized_provider();
        assert_eq!(
            served_names(
                &provider
                    .supply(&image_list_request("IsiBootEANFirmware"))
                    .unwrap()
            ),
            vec!["Ap,CIO", "Ap,TMU"]
        );
        provider.follow_variant("macOS Customer");
        assert!(
            served_names(
                &provider
                    .supply(&image_list_request("IsiBootEANFirmware"))
                    .unwrap()
            )
            .is_empty()
        );
    }

    #[test]
    fn a_named_variant_outranks_the_identity_that_was_handed_over() {
        let mut provider = flagged_personalized_provider();
        provider.follow_variant("macOS Customer");
        let mut request = image_list_request("IsiBootEANFirmware");
        request.arguments.insert(
            crate::ramrod::message::KEY_VARIANT.to_string(),
            plist::Value::String("Customer Erase Install (IPSW)".to_string()),
        );
        assert_eq!(
            served_names(&provider.supply(&request).unwrap()),
            vec!["Ap,CIO", "Ap,TMU"]
        );
    }

    #[test]
    fn the_identity_reply_carries_its_variant_across_to_the_image_list() {
        let dir = tempfile::tempdir().unwrap();
        manifests_tree(dir.path(), "j274ap", &[0x30, 0x02, 0x16, 0x00], &[9]);
        let mut answers = RestoreAnswers {
            tickets: GlobalManifestProvider::new(
                dir.path().to_path_buf(),
                test_variants(),
                "J274AP".to_string(),
                false,
                62078,
                0.0,
                None,
                None,
                None,
                &reporter(),
            ),
            firmware: None,
            identities: BuildIdentityProvider::new(
                flagged_identity_manifest(),
                "J274AP".to_string(),
                "Customer Erase Install (IPSW)".to_string(),
                "macOS Customer".to_string(),
                Vec::new(),
                62078,
                0.0,
                &reporter(),
            ),
            personalized: flagged_personalized_provider(),
            source_boot_objects: test_source_boot_object_provider(dir.path()),
            fdr: test_fdr_provider(&reporter()),
            port: 62078,
            armed_at_secs: 0.0,
            reporter: reporter(),
        };
        assert_eq!(
            served_names(
                &answers
                    .supply(&image_list_request("IsiBootEANFirmware"))
                    .unwrap()
            ),
            vec!["Ap,CIO", "Ap,TMU"]
        );
        let identity = data_request_with(
            DataType::BuildIdentityDict,
            vec![(
                crate::ramrod::message::KEY_VARIANT,
                plist::Value::String("macOS Customer".to_string()),
            )],
        );
        assert!(
            answers
                .supply(&identity)
                .unwrap()
                .contains_key(crate::ramrod::message::KEY_BUILD_IDENTITY_DICT)
        );
        assert!(
            served_names(
                &answers
                    .supply(&image_list_request("IsiBootEANFirmware"))
                    .unwrap()
            )
            .is_empty()
        );
    }

    #[test]
    fn an_image_list_request_without_an_image_type_is_answered_with_no_list() {
        let mut provider = flagged_personalized_provider();
        let request = data_request_with(
            DataType::Other(PERSONALIZED_DATA_TYPE.to_string()),
            vec![(KEY_IMAGE_LIST, plist::Value::Boolean(true))],
        );
        assert!(provider.supply(&request).unwrap().is_empty());
    }

    fn flagged_list_request(data_type: &str, list_key: &str) -> DataRequest {
        data_request_with(
            DataType::Other(data_type.to_string()),
            vec![(list_key, plist::Value::Boolean(true))],
        )
    }

    fn names_under(body: &plist::Dictionary, key: &str) -> Vec<String> {
        body.get(key)
            .and_then(plist::Value::as_array)
            .expect("the list travels back under the key the request set")
            .iter()
            .map(|value| {
                value
                    .as_string()
                    .expect("every entry is a component name")
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn the_ean_enumeration_is_answered_with_an_empty_array_when_nothing_is_flagged() {
        let mut provider = flagged_personalized_provider();
        let body =
            provider.early_access_list(&flagged_list_request(EAN_DATA_TYPE, KEY_EAN_IMAGE_LIST));
        assert!(
            body.contains_key(KEY_EAN_IMAGE_LIST),
            "a reply with no key is the NULL that fails update_ean"
        );
        assert!(names_under(&body, KEY_EAN_IMAGE_LIST).is_empty());
    }

    #[test]
    fn the_fud_enumeration_lists_the_components_the_identity_flags() {
        let mut provider = flagged_personalized_provider();
        let body = provider.fud_list(&flagged_list_request(FUD_DATA_TYPE, KEY_FUD_IMAGE_LIST));
        assert_eq!(names_under(&body, KEY_FUD_IMAGE_LIST), vec!["GFX", "PMP"]);
        let body =
            provider.early_access_list(&flagged_list_request(EAN_DATA_TYPE, KEY_EAN_IMAGE_LIST));
        assert!(names_under(&body, KEY_EAN_IMAGE_LIST).is_empty());
    }

    #[test]
    fn the_flagged_enumerations_follow_the_identity_the_guest_was_handed() {
        let mut provider = flagged_personalized_provider();
        assert_eq!(
            names_under(
                &provider.fud_list(&flagged_list_request(FUD_DATA_TYPE, KEY_FUD_IMAGE_LIST)),
                KEY_FUD_IMAGE_LIST
            ),
            vec!["GFX", "PMP"]
        );
        provider.follow_variant("macOS Customer");
        assert_eq!(
            names_under(
                &provider.fud_list(&flagged_list_request(FUD_DATA_TYPE, KEY_FUD_IMAGE_LIST)),
                KEY_FUD_IMAGE_LIST
            ),
            vec!["SIO"]
        );
    }

    #[test]
    fn a_flagged_enumeration_that_does_not_set_its_key_is_answered_with_no_list() {
        let mut provider = flagged_personalized_provider();
        let request = data_request_with(
            DataType::Other(FUD_DATA_TYPE.to_string()),
            vec![(KEY_IMAGE_NAME, plist::Value::String("GFX".to_string()))],
        );
        assert!(provider.fud_list(&request).is_empty());
    }

    #[test]
    fn the_router_answers_both_enumerations_and_reports_what_it_served() {
        let dir = tempfile::tempdir().unwrap();
        manifests_tree(dir.path(), "j274ap", &[0x30, 0x02, 0x16, 0x00], &[9]);
        let (reports, lines) = capturing();
        let mut answers = RestoreAnswers {
            tickets: GlobalManifestProvider::new(
                dir.path().to_path_buf(),
                test_variants(),
                "J274AP".to_string(),
                false,
                62078,
                0.0,
                None,
                None,
                None,
                &reporter(),
            ),
            firmware: None,
            identities: BuildIdentityProvider::new(
                flagged_identity_manifest(),
                "J274AP".to_string(),
                "Customer Erase Install (IPSW)".to_string(),
                "macOS Customer".to_string(),
                Vec::new(),
                62078,
                0.0,
                &reporter(),
            ),
            personalized: PersonalizedFirmwareProvider::new(
                flagged_identity_manifest(),
                "J274AP".to_string(),
                "Customer Erase Install (IPSW)".to_string(),
                "macOS Customer".to_string(),
                None,
                None,
                None,
                62078,
                0.0,
                &reports,
            ),
            source_boot_objects: test_source_boot_object_provider(dir.path()),
            fdr: test_fdr_provider(&reporter()),
            port: 62078,
            armed_at_secs: 0.0,
            reporter: reporter(),
        };
        let ean = answers
            .supply(&flagged_list_request(EAN_DATA_TYPE, KEY_EAN_IMAGE_LIST))
            .unwrap();
        assert!(names_under(&ean, KEY_EAN_IMAGE_LIST).is_empty());
        let fud = answers
            .supply(&flagged_list_request(FUD_DATA_TYPE, KEY_FUD_IMAGE_LIST))
            .unwrap();
        assert_eq!(names_under(&fud, KEY_FUD_IMAGE_LIST), vec!["GFX", "PMP"]);
        let lines = lines.lock().unwrap();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("result=ean-list-answered") && line.contains("images=0")),
            "the EAN answer is on the wire: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("result=fud-list-answered")
                    && line.contains("images=2")
                    && line.contains("names=[GFX,PMP]")),
            "the FUD answer names what it served: {lines:?}"
        );
    }

    fn global_manifest_request(prefix: &str, variant: &str, chunk: i64) -> DataRequest {
        data_request_with(
            DataType::SourceBootObjectV4,
            vec![
                (
                    KEY_GLOBAL_MANIFEST_PREFIX,
                    plist::Value::String(prefix.to_string()),
                ),
                (
                    crate::ramrod::message::KEY_VARIANT,
                    plist::Value::String(variant.to_string()),
                ),
                (
                    KEY_IMAGE_NAME,
                    plist::Value::String(IMAGE_NAME_GLOBAL_MANIFEST.to_string()),
                ),
                (KEY_GLOBAL_MANIFEST_OPTIONAL, plist::Value::Boolean(true)),
                (
                    crate::ramrod::KEY_DATA_CHUNK_SIZE,
                    plist::Value::Integer(chunk.into()),
                ),
            ],
        )
    }

    #[test]
    fn a_global_manifest_is_streamed_from_the_prefix_the_request_names() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("macOS Customer")
            .join("centauri")
            .join("centauri.j274ap.im4m");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, [0x41, 0x42, 0x43, 0x44]).unwrap();
        let mut provider = test_source_boot_object_provider(dir.path());
        let object = provider
            .supply_streamed(&global_manifest_request(
                "centauri/centauri",
                "macOS Customer",
                131_072,
            ))
            .expect("the request is claimed")
            .expect("the manifest is on disk");
        assert_eq!(streamed_bytes(&object), vec![0x41, 0x42, 0x43, 0x44]);
        assert_eq!(object.chunk_size, 131_072);
    }

    #[test]
    fn a_global_manifest_the_tree_does_not_ship_is_left_to_the_decline() {
        let dir = tempfile::tempdir().unwrap();
        let other = dir
            .path()
            .join("macOS Customer")
            .join("centauri")
            .join("centauri.j714cap.im4m");
        std::fs::create_dir_all(other.parent().unwrap()).unwrap();
        std::fs::write(&other, [0x41, 0x42]).unwrap();
        let mut provider = test_source_boot_object_provider(dir.path());
        assert!(
            provider
                .supply_streamed(&global_manifest_request(
                    "centauri/centauri",
                    "macOS Customer",
                    131_072,
                ))
                .is_none()
        );
    }

    #[test]
    fn an_unclaimed_source_boot_object_is_declined_by_the_router() {
        let dir = tempfile::tempdir().unwrap();
        manifests_tree(dir.path(), "j274ap", &[0x30, 0x02, 0x16, 0x00], &[9]);
        let mut answers = RestoreAnswers {
            tickets: GlobalManifestProvider::new(
                dir.path().to_path_buf(),
                test_variants(),
                "J274AP".to_string(),
                false,
                62078,
                0.0,
                None,
                None,
                None,
                &reporter(),
            ),
            firmware: None,
            identities: test_identity_provider(),
            personalized: test_personalized_provider(),
            source_boot_objects: test_source_boot_object_provider(dir.path()),
            fdr: test_fdr_provider(&reporter()),
            port: 62078,
            armed_at_secs: 0.0,
            reporter: reporter(),
        };
        let request = global_manifest_request("centauri/centauri", "macOS Customer", 131_072);
        assert!(answers.supply_streamed(&request).is_none());
        let body = answers.supply(&request).unwrap();
        assert_eq!(
            body.get(crate::ramrod::message::KEY_FILE_DATA_DONE)
                .and_then(plist::Value::as_boolean),
            Some(true)
        );
        assert_eq!(
            body.get(crate::ramrod::message::KEY_DATA_SIZE)
                .and_then(plist::Value::as_signed_integer),
            Some(0)
        );
        assert!(!body.contains_key(crate::ramrod::message::KEY_FILE_DATA));
    }

    #[test]
    fn a_global_manifest_prefix_that_escapes_the_root_is_not_claimed() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = test_source_boot_object_provider(dir.path());
        assert!(
            provider
                .supply_streamed(&global_manifest_request(
                    "../../etc/passwd",
                    "macOS Customer",
                    0
                ))
                .is_none()
        );
    }

    #[test]
    fn a_source_boot_object_naming_another_image_is_not_claimed() {
        let dir = tempfile::tempdir().unwrap();
        let (reporter, lines) = capturing();
        let mut provider = SourceBootObjectProvider::new(
            dir.path().to_path_buf(),
            "Customer Erase Install (IPSW)".to_string(),
            "J274AP".to_string(),
            identity_manifest(),
            None,
            None,
            SplatPlan::default(),
            62078,
            0.0,
            &reporter,
        );
        let request = data_request_with(
            DataType::SourceBootObjectV4,
            vec![
                (
                    KEY_GLOBAL_MANIFEST_PREFIX,
                    plist::Value::String("centauri/centauri".to_string()),
                ),
                (KEY_IMAGE_NAME, plist::Value::String("iBoot".to_string())),
            ],
        );
        let object = provider
            .supply_streamed(&request)
            .expect("the request is refused by name rather than left to the generic decline")
            .expect("the refusal is a transfer and not a session ending error");
        assert_eq!(
            object.len(),
            0,
            "no manifest may go out under an image name"
        );
        assert!(streamed_bytes(&object).is_empty());
        let lines = lines.lock().unwrap();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("result=source-component-refused")
                    && line.contains("component=iBoot")),
            "{lines:?}"
        );
    }

    fn manifests_tree(root: &std::path::Path, board: &str, os: &[u8], cryptex: &[u8]) {
        let os_path = root
            .join("macOS Customer")
            .join(format!("apticket.{board}.im4m"));
        std::fs::create_dir_all(os_path.parent().unwrap()).unwrap();
        std::fs::write(os_path, os).unwrap();
        let cryptex_path = root
            .join("cryptex1")
            .join("macOS Customer")
            .join(format!("apticket.{board}.im4m"));
        std::fs::create_dir_all(cryptex_path.parent().unwrap()).unwrap();
        std::fs::write(cryptex_path, cryptex).unwrap();
    }

    fn image4_element(magic: &str, tail: &[u8]) -> Vec<u8> {
        let mut body = vec![0x16u8, magic.len() as u8];
        body.extend_from_slice(magic.as_bytes());
        body.extend_from_slice(tail);
        let mut encoded = vec![0x30u8, body.len() as u8];
        encoded.extend_from_slice(&body);
        encoded
    }

    fn firmware_identity(root: &std::path::Path) -> BuildIdentity {
        let mut manifest = plist::Dictionary::new();
        for (name, flag, file) in [
            ("LLB", "IsFirmwarePayload", "LLB.j274.RELEASE.im4p"),
            (
                "RestoreSEP",
                "IsSecondaryFirmwarePayload",
                "sep-firmware.j274.RELEASE.im4p",
            ),
        ] {
            let relative = format!("Firmware/all_flash/{file}");
            let path = root.join(&relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(
                &path,
                image4_element("IM4P", &[0x16, 0x04, b'i', b'l', b'l', b'b']),
            )
            .unwrap();
            let mut info = plist::Dictionary::new();
            info.insert(flag.to_string(), plist::Value::Boolean(true));
            info.insert("Path".to_string(), plist::Value::String(relative));
            let mut entry = plist::Dictionary::new();
            entry.insert("Info".to_string(), plist::Value::Dictionary(info));
            manifest.insert(name.to_string(), plist::Value::Dictionary(entry));
        }
        BuildIdentity {
            index: 1,
            device_class: "j274ap".to_string(),
            variant: "Customer Erase Install (IPSW)".to_string(),
            info: plist::Dictionary::new(),
            components: Some(manifest),
        }
    }

    #[test]
    fn the_firmware_provider_answers_nor_data_with_the_slots_the_manifest_names() {
        let dir = tempfile::tempdir().unwrap();
        let board_manifest = image4_element("IM4M", &[0x02, 0x01, 0x00]);
        let mut provider = NorFirmwareProvider::prepare(
            &firmware_identity(dir.path()),
            dir.path().to_path_buf(),
            dir.path().join("apticket.j274ap.im4m"),
            &board_manifest,
            62078,
            0.0,
            &reporter(),
        );

        let mut request = data_request(DataType::Other("NORData".into()));
        request.arguments.insert(
            "FlashVersion1".to_string(),
            plist::Value::String("1".into()),
        );
        let body = provider.supply(&request).expect("the request is answered");
        assert!(
            body.get("RestoreSEPImageData")
                .and_then(plist::Value::as_data)
                .is_some()
        );
        assert!(
            body.get("LlbImageData")
                .and_then(plist::Value::as_data)
                .is_some()
        );
        assert!(body.get("NorImageData").is_none());
        assert!(body.get("SEPImageData").is_none());
    }

    #[test]
    fn a_firmware_request_with_no_firmware_source_is_refused_under_its_own_name() {
        let dir = tempfile::tempdir().unwrap();
        manifests_tree(dir.path(), "j274ap", &[0x30, 0x02, 0x16, 0x00], &[9]);
        let (trace, lines) = capturing();
        let mut answers = RestoreAnswers {
            tickets: GlobalManifestProvider::new(
                dir.path().to_path_buf(),
                test_variants(),
                "J274AP".to_string(),
                false,
                62078,
                0.0,
                None,
                None,
                None,
                &trace,
            ),
            firmware: None,
            identities: test_identity_provider(),
            personalized: test_personalized_provider(),
            source_boot_objects: test_source_boot_object_provider(dir.path()),
            fdr: test_fdr_provider(&trace),
            port: 62078,
            armed_at_secs: 0.0,
            reporter: Arc::clone(&trace),
        };
        let error = answers
            .supply(&data_request(DataType::Other("NORData".into())))
            .expect_err(
                "an empty dictionary here is a NULL RestoreSEPImageData the guest can never ask for again, so this must be a named host failure rather than a reply",
            );
        assert!(error.to_string().contains("--asr-serve-firmware-root"));
        let lines = lines.lock().unwrap();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("result=nor-source-absent") && line.contains("NORData")),
            "the refusal must name the type it refused: {lines:?}"
        );
    }

    #[test]
    fn the_fdr_trust_reply_carries_the_local_object_under_all_three_keys() {
        let mut provider = test_fdr_provider(&reporter());
        let body = provider
            .supply(&data_request(DataType::Other(
                FDR_TRUST_DATA_TYPE.to_string(),
            )))
            .expect("the FDR trust request is answered");
        assert_eq!(
            body.get(KEY_FDR_TRUST_DATA).and_then(plist::Value::as_data),
            Some(&test_trust_object()[..])
        );
        assert_eq!(
            body.get(KEY_BOOTED_OS_FDR_TRUST_DATA)
                .and_then(plist::Value::as_data),
            Some(&test_trust_object()[..])
        );
        let store = body
            .get(KEY_FDR_MEMORY_STORE_DATA)
            .and_then(plist::Value::as_dictionary)
            .expect("the memory store is a dictionary or the guest discards it");
        assert_eq!(
            store.get(TRUST_OBJECT_KEY).and_then(plist::Value::as_data),
            Some(&test_trust_object()[..])
        );
        assert_eq!(store.len(), 1);
        assert!(
            store
                .values()
                .all(|value| matches!(value, plist::Value::Data(_)))
        );
    }

    #[test]
    fn a_host_with_no_trust_object_serves_nothing_rather_than_empty_bytes() {
        let mut provider = FdrTrustProvider::new(None, 62078, 0.0, &reporter());
        let body = provider
            .supply(&data_request(DataType::Other(
                FDR_TRUST_DATA_TYPE.to_string(),
            )))
            .expect("a host holding no trust object still answers the request");
        assert!(body.is_empty());
        assert!(body.get(KEY_FDR_TRUST_DATA).is_none());
        assert!(body.get(KEY_BOOTED_OS_FDR_TRUST_DATA).is_none());
        assert!(body.get(KEY_FDR_MEMORY_STORE_DATA).is_none());
    }

    #[test]
    fn the_fdr_trust_line_says_what_is_served_and_what_still_decides_the_step() {
        let (reporter, lines) = capturing();
        let mut provider = test_fdr_provider(&reporter);
        provider
            .supply(&data_request(DataType::Other(
                FDR_TRUST_DATA_TYPE.to_string(),
            )))
            .expect("the FDR trust request is answered");
        let lines = lines.lock().unwrap();
        let line = lines
            .iter()
            .find(|line| line.contains("result=fdr-trust-served"))
            .expect("the reply is reported under its own name");
        assert!(line.contains(KEY_FDR_TRUST_DATA), "{line}");
        assert!(line.contains(KEY_BOOTED_OS_FDR_TRUST_DATA), "{line}");
        assert!(line.contains(KEY_FDR_MEMORY_STORE_DATA), "{line}");
        assert!(line.contains(TRUST_OBJECT_KEY), "{line}");
        assert!(line.contains("FDRMemoryStorePath"), "{line}");
        let sha256: String = sha256(&test_trust_object())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert!(line.contains(&sha256), "{line}");
        assert!(line.contains(FDR_TRUST_OBJECT_TAGS[0]), "{line}");
        assert!(line.contains(FDR_TRUST_OBJECT_TAGS[1]), "{line}");
        assert!(!line.contains("this reply carries none"), "{line}");
    }

    #[test]
    fn a_memory_commit_is_retained_verbatim_and_acknowledged() {
        let (reporter, lines) = capturing();
        let mut provider = test_fdr_provider(&reporter);
        let seal_key = format!("seal-{TEST_INSTANCE}");
        let sealing_manifest = vec![1u8, 2, 3, 4, 5];
        let mut store = plist::Dictionary::new();
        store.insert(
            seal_key.clone(),
            plist::Value::Data(sealing_manifest.clone()),
        );
        let mut request = data_request(DataType::Other(FDR_MEMORY_COMMIT_DATA_TYPE.to_string()));
        request.arguments.insert(
            KEY_FDR_MEMORY_STORE_DATA.to_string(),
            plist::Value::Dictionary(store),
        );

        let acknowledgement = provider
            .supply(&request)
            .expect("the commit is acknowledged rather than refused");
        assert!(!acknowledgement.is_empty());
        assert_eq!(
            acknowledgement
                .get(KEY_FDR_MEMORY_STORE_DATA)
                .and_then(plist::Value::as_dictionary)
                .and_then(|echoed| echoed.get(&seal_key))
                .and_then(plist::Value::as_data),
            Some(&sealing_manifest[..])
        );

        let body = provider
            .supply(&data_request(DataType::Other(
                FDR_TRUST_DATA_TYPE.to_string(),
            )))
            .expect("the FDR trust request is answered");
        let served = body
            .get(KEY_FDR_MEMORY_STORE_DATA)
            .and_then(plist::Value::as_dictionary)
            .expect("the memory store is a dictionary");
        assert_eq!(
            served.get(&seal_key).and_then(plist::Value::as_data),
            Some(&sealing_manifest[..])
        );
        assert_eq!(
            served.get(TRUST_OBJECT_KEY).and_then(plist::Value::as_data),
            Some(&test_trust_object()[..])
        );

        let lines = lines.lock().unwrap();
        let line = lines
            .iter()
            .find(|line| line.contains("result=fdr-memory-committed"))
            .expect("the commit is reported under its own name");
        assert!(line.contains(&seal_key), "{line}");
        assert!(
            line.contains(&format!("<data:{}bytes>", sealing_manifest.len())),
            "{line}"
        );
        assert!(line.contains("entries=1"), "{line}");
    }

    #[test]
    fn a_commit_with_no_readable_store_is_still_acknowledged() {
        let mut provider = test_fdr_provider(&reporter());
        let mut request = data_request(DataType::Other(FDR_MEMORY_COMMIT_DATA_TYPE.to_string()));
        request.arguments.insert(
            KEY_FDR_MEMORY_STORE_DATA.to_string(),
            plist::Value::String("not a store".to_string()),
        );
        let acknowledgement = provider
            .supply(&request)
            .expect("the commit is acknowledged rather than refused");
        assert!(!acknowledgement.is_empty());
        let body = provider
            .supply(&data_request(DataType::Other(
                FDR_TRUST_DATA_TYPE.to_string(),
            )))
            .expect("the FDR trust request is answered");
        let served = body
            .get(KEY_FDR_MEMORY_STORE_DATA)
            .and_then(plist::Value::as_dictionary)
            .expect("the memory store is a dictionary");
        assert_eq!(served.len(), 1);
        assert!(served.contains_key(TRUST_OBJECT_KEY));
    }

    #[test]
    fn an_fdr_trust_request_reaches_the_fdr_half_rather_than_the_ticket_provider() {
        let dir = tempfile::tempdir().unwrap();
        manifests_tree(dir.path(), "j274ap", &[0x30, 0x02, 0x16, 0x00], &[9]);
        let mut answers = RestoreAnswers {
            tickets: GlobalManifestProvider::new(
                dir.path().to_path_buf(),
                test_variants(),
                "J274AP".to_string(),
                false,
                62078,
                0.0,
                None,
                None,
                None,
                &reporter(),
            ),
            firmware: None,
            identities: test_identity_provider(),
            personalized: test_personalized_provider(),
            source_boot_objects: test_source_boot_object_provider(dir.path()),
            fdr: test_fdr_provider(&reporter()),
            port: 62078,
            armed_at_secs: 0.0,
            reporter: reporter(),
        };
        let body = answers
            .supply(&data_request(DataType::Other(
                FDR_TRUST_DATA_TYPE.to_string(),
            )))
            .expect("the FDR half answers rather than the ticket half refusing");
        assert!(body.contains_key(KEY_FDR_MEMORY_STORE_DATA));

        let mut commit = data_request(DataType::Other(FDR_MEMORY_COMMIT_DATA_TYPE.to_string()));
        commit.arguments.insert(
            KEY_FDR_MEMORY_STORE_DATA.to_string(),
            plist::Value::Dictionary(plist::Dictionary::new()),
        );
        let acknowledgement = answers
            .supply(&commit)
            .expect("the FDR half answers the commit");
        assert!(acknowledgement.contains_key(KEY_FDR_MEMORY_STORE_DATA));
    }

    #[test]
    fn a_ticket_request_still_reaches_the_ticket_half_when_firmware_is_wired_up() {
        let dir = tempfile::tempdir().unwrap();
        let os_bytes = vec![0x30u8, 0x82, 0x15, 0x49, 1, 2, 3, 4];
        manifests_tree(dir.path(), "j274ap", &os_bytes, &[9]);
        let firmware_root = tempfile::tempdir().unwrap();
        let board_manifest = image4_element("IM4M", &[0x02, 0x01, 0x00]);
        let mut answers = RestoreAnswers {
            tickets: GlobalManifestProvider::new(
                dir.path().to_path_buf(),
                test_variants(),
                "J274AP".to_string(),
                false,
                62078,
                0.0,
                None,
                None,
                None,
                &reporter(),
            ),
            firmware: Some(NorFirmwareProvider::prepare(
                &firmware_identity(firmware_root.path()),
                firmware_root.path().to_path_buf(),
                dir.path().join("apticket.j274ap.im4m"),
                &board_manifest,
                62078,
                0.0,
                &reporter(),
            )),
            identities: test_identity_provider(),
            personalized: test_personalized_provider(),
            source_boot_objects: test_source_boot_object_provider(dir.path()),
            fdr: test_fdr_provider(&reporter()),
            port: 62078,
            armed_at_secs: 0.0,
            reporter: reporter(),
        };
        let body = answers
            .supply(&data_request(DataType::RootTicket))
            .expect("the ticket half still answers");
        assert_eq!(
            body.get("RootTicketData").and_then(plist::Value::as_data),
            Some(&os_bytes[..])
        );
    }

    #[test]
    fn the_global_manifest_provider_answers_the_recovery_os_ticket_from_genuine_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let os_bytes = vec![0x30u8, 0x82, 0x15, 0x49, 1, 2, 3, 4, 5, 6, 7, 8];
        manifests_tree(dir.path(), "j274ap", &os_bytes, &[9, 9, 9]);

        let mut provider = GlobalManifestProvider::new(
            dir.path().to_path_buf(),
            test_variants(),
            "J274AP".to_string(),
            false,
            62078,
            0.0,
            None,
            None,
            None,
            &reporter(),
        );
        let body = provider
            .supply(&data_request(DataType::RecoveryOSRootTicketData))
            .expect("the recovery os ticket is answered from the genuine manifest");
        assert_eq!(
            body.get("RootTicketData").and_then(plist::Value::as_data),
            Some(&os_bytes[..])
        );
    }

    #[test]
    fn each_ticket_role_resolves_against_its_own_variant() {
        let dir = tempfile::tempdir().unwrap();
        let recovery_bytes = vec![0x30u8, 0x82, 0x15, 0x49, 1, 1, 1, 1];
        let install_bytes = vec![0x30u8, 0x82, 0x15, 0x49, 2, 2, 2, 2];
        manifests_tree(dir.path(), "j274ap", &recovery_bytes, &[9, 9, 9]);
        let install = dir
            .path()
            .join("Customer Erase Install (IPSW)")
            .join("apticket.j274ap.im4m");
        std::fs::create_dir_all(install.parent().unwrap()).unwrap();
        std::fs::write(&install, &install_bytes).unwrap();

        let mut provider = GlobalManifestProvider::new(
            dir.path().to_path_buf(),
            test_variants(),
            "J274AP".to_string(),
            false,
            62078,
            0.0,
            None,
            None,
            None,
            &reporter(),
        );
        let os = provider
            .supply(&data_request(DataType::RootTicket))
            .expect("the OS ticket is answered");
        assert_eq!(
            os.get("RootTicketData").and_then(plist::Value::as_data),
            Some(&install_bytes[..]),
            "RootTicket must come out of the install variant"
        );
        let recovery = provider
            .supply(&data_request(DataType::RecoveryOSRootTicketData))
            .expect("the recovery OS ticket is answered");
        assert_eq!(
            recovery
                .get("RootTicketData")
                .and_then(plist::Value::as_data),
            Some(&recovery_bytes[..]),
            "RecoveryOSRootTicketData must come out of the recovery variant"
        );
    }

    #[test]
    fn an_os_ticket_falls_back_when_the_install_variant_ships_no_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let recovery_bytes = vec![0x30u8, 0x82, 0x15, 0x49, 1, 1, 1, 1];
        manifests_tree(dir.path(), "j274ap", &recovery_bytes, &[9, 9, 9]);
        let centauri = dir
            .path()
            .join("Customer Erase Install (IPSW)")
            .join("centauri")
            .join("centauri.j274ap.im4m");
        std::fs::create_dir_all(centauri.parent().unwrap()).unwrap();
        std::fs::write(&centauri, [7, 7, 7, 7]).unwrap();

        let mut provider = GlobalManifestProvider::new(
            dir.path().to_path_buf(),
            test_variants(),
            "J274AP".to_string(),
            false,
            62078,
            0.0,
            None,
            None,
            None,
            &reporter(),
        );
        let os = provider
            .supply(&data_request(DataType::RootTicket))
            .expect("the OS ticket falls back to the recovery variant");
        assert_eq!(
            os.get("RootTicketData").and_then(plist::Value::as_data),
            Some(&recovery_bytes[..]),
            "the centauri file beside it must never be served as an AP ticket"
        );
    }

    #[test]
    fn the_corrupt_control_serves_different_bytes_of_the_same_length() {
        let dir = tempfile::tempdir().unwrap();
        let os_bytes: Vec<u8> = (0..512).map(|i| (i % 251) as u8).collect();
        manifests_tree(dir.path(), "j274ap", &os_bytes, &[9]);

        let mut genuine = GlobalManifestProvider::new(
            dir.path().to_path_buf(),
            test_variants(),
            "J274AP".to_string(),
            false,
            62078,
            0.0,
            None,
            None,
            None,
            &reporter(),
        );
        let mut corrupt = GlobalManifestProvider::new(
            dir.path().to_path_buf(),
            test_variants(),
            "J274AP".to_string(),
            true,
            62078,
            0.0,
            None,
            None,
            None,
            &reporter(),
        );
        let genuine_body = genuine
            .supply(&data_request(DataType::RecoveryOSRootTicketData))
            .unwrap();
        let corrupt_body = corrupt
            .supply(&data_request(DataType::RecoveryOSRootTicketData))
            .unwrap();
        let genuine_data = genuine_body
            .get("RootTicketData")
            .and_then(plist::Value::as_data)
            .unwrap();
        let corrupt_data = corrupt_body
            .get("RootTicketData")
            .and_then(plist::Value::as_data)
            .unwrap();
        assert_eq!(genuine_data.len(), corrupt_data.len());
        assert_ne!(genuine_data, corrupt_data);
    }

    #[test]
    fn a_ticket_with_no_genuine_manifest_fails_naming_itself() {
        let dir = tempfile::tempdir().unwrap();
        manifests_tree(dir.path(), "j274ap", &[1], &[2]);
        let mut provider = GlobalManifestProvider::new(
            dir.path().to_path_buf(),
            test_variants(),
            "J999AP".to_string(),
            false,
            62078,
            0.0,
            None,
            None,
            None,
            &reporter(),
        );
        let error = provider
            .supply(&data_request(DataType::RecoveryOSRootTicketData))
            .expect_err("a board with no manifest cannot be answered");
        let rendered = format!("{error}");
        assert!(rendered.contains("j999ap"), "{rendered}");
    }

    #[test]
    fn the_served_ticket_digest_is_the_one_the_machine_published() {
        let dir = tempfile::tempdir().unwrap();
        let manifest: Vec<u8> = (0..1024).map(|index| (index % 251) as u8).collect();
        manifests_tree(dir.path(), "j274ap", &manifest, &[9]);
        let staged = sha384(&manifest);

        let mut genuine = GlobalManifestProvider::new(
            dir.path().to_path_buf(),
            test_variants(),
            "J274AP".to_string(),
            false,
            62078,
            0.0,
            Some(staged),
            None,
            None,
            &reporter(),
        );
        let body = genuine
            .supply(&data_request(DataType::RootTicket))
            .expect("the root ticket is answered");
        let served = body
            .get("RootTicketData")
            .and_then(plist::Value::as_data)
            .expect("the ticket bytes are on the reply");
        assert_eq!(sha384(served), staged);

        let mut corrupt = GlobalManifestProvider::new(
            dir.path().to_path_buf(),
            test_variants(),
            "J274AP".to_string(),
            true,
            62078,
            0.0,
            Some(staged),
            None,
            None,
            &reporter(),
        );
        let corrupt_body = corrupt
            .supply(&data_request(DataType::RootTicket))
            .expect("the corrupt control still answers");
        let corrupt_served = corrupt_body
            .get("RootTicketData")
            .and_then(plist::Value::as_data)
            .unwrap();
        assert_ne!(sha384(corrupt_served), staged);
    }

    #[test]
    fn two_ticket_types_that_resolve_to_one_manifest_are_each_logged_once() {
        let dir = tempfile::tempdir().unwrap();
        manifests_tree(dir.path(), "j274ap", &[1, 2, 3, 4], &[9]);
        let mut provider = GlobalManifestProvider::new(
            dir.path().to_path_buf(),
            test_variants(),
            "J274AP".to_string(),
            false,
            62078,
            0.0,
            None,
            None,
            None,
            &reporter(),
        );
        provider
            .supply(&data_request(DataType::RecoveryOSRootTicketData))
            .unwrap();
        assert_eq!(provider.logged.len(), 1);
        provider
            .supply(&data_request(DataType::RootTicket))
            .unwrap();
        assert_eq!(provider.logged.len(), 2);
        assert!(
            provider
                .logged
                .contains("RecoveryOSRootTicketData:recovery-os:os")
        );
        assert!(provider.logged.contains("RootTicket:os:os"));
        provider
            .supply(&data_request(DataType::RootTicket))
            .unwrap();
        assert_eq!(provider.logged.len(), 2);
    }

    #[test]
    fn a_type_this_host_holds_nothing_for_is_declined_rather_than_ending_the_session() {
        let dir = tempfile::tempdir().unwrap();
        manifests_tree(dir.path(), "j274ap", &[0x30, 0x02, 0x16, 0x00], &[9]);
        let (reporter, lines) = capturing();
        let mut answers = RestoreAnswers {
            tickets: GlobalManifestProvider::new(
                dir.path().to_path_buf(),
                test_variants(),
                "J274AP".to_string(),
                false,
                62078,
                0.0,
                None,
                None,
                None,
                &reporter,
            ),
            firmware: None,
            identities: test_identity_provider(),
            personalized: test_personalized_provider(),
            source_boot_objects: test_source_boot_object_provider(dir.path()),
            fdr: test_fdr_provider(&reporter),
            port: 62078,
            armed_at_secs: 0.0,
            reporter: Arc::clone(&reporter),
        };
        for name in [
            "SourceBootObjectV4",
            "PersonalizedBootObjectV3",
            "BootabilityBundle",
            "RamdiskFWData",
            "FirmwareUpdaterDataV3",
            "RecoveryOSLocalPolicy",
        ] {
            let body = answers
                .supply(&data_request(DataType::from_wire(name)))
                .unwrap_or_else(|error| {
                    panic!("{name} ended the session instead of being declined: {error}")
                });
            assert!(body.is_empty(), "{name} was answered with fabricated keys");
        }
        let lines = lines.lock().unwrap();
        let declines: Vec<&String> = lines
            .iter()
            .filter(|line| line.contains("result=data-declined"))
            .collect();
        assert_eq!(declines.len(), 5, "{lines:?}");
        assert!(
            declines[0].contains("BootabilityBundle")
                || declines
                    .iter()
                    .any(|line| line.contains("BootabilityBundle"))
        );
        assert!(
            !declines
                .iter()
                .any(|line| line.contains("RecoveryOSLocalPolicy")),
            "{lines:?}"
        );
        let named: Vec<&String> = lines
            .iter()
            .filter(|line| line.contains("result=recovery-os-local-policy-unsigned"))
            .collect();
        assert_eq!(named.len(), 1, "{lines:?}");
        assert!(named[0].contains(KEY_AP_LOCAL_POLICY), "{named:?}");
    }

    #[test]
    fn the_local_policy_payload_digest_matches_the_reference_host() {
        assert_eq!(
            sha384(&RECOVERY_OS_LOCAL_POLICY_IM4P)[..],
            RECOVERY_OS_LOCAL_POLICY_IM4P_SHA384[..]
        );
        let image = wrap_image4(
            &RECOVERY_OS_LOCAL_POLICY_IM4P,
            &image4_element("IM4M", &[0x02, 0x01, 0x00]),
        )
        .expect("the constant payload is an IM4P and the stub manifest an IM4M");
        assert!(image.windows(4).any(|window| window == b"IMG4"));
        assert!(image.windows(4).any(|window| window == b"lpol"));
    }

    #[test]
    fn the_recovery_os_local_policy_is_stitched_from_the_recovery_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = image4_element("IM4M", &[0x02, 0x01, 0x2a]);
        manifests_tree(dir.path(), "j274ap", &manifest, &[9]);
        let (reporter, lines) = capturing();
        let mut answers = RestoreAnswers {
            tickets: GlobalManifestProvider::new(
                dir.path().to_path_buf(),
                test_variants(),
                "J274AP".to_string(),
                false,
                62078,
                0.0,
                None,
                None,
                None,
                &reporter,
            ),
            firmware: None,
            identities: test_identity_provider(),
            personalized: test_personalized_provider(),
            source_boot_objects: test_source_boot_object_provider(dir.path()),
            fdr: test_fdr_provider(&reporter),
            port: 62078,
            armed_at_secs: 0.0,
            reporter: Arc::clone(&reporter),
        };
        let body = answers
            .supply(&data_request(DataType::RecoveryOSLocalPolicy))
            .expect("the request is answered rather than ending the session");
        let served = match body.get(KEY_AP_LOCAL_POLICY) {
            Some(plist::Value::Data(bytes)) => bytes.clone(),
            other => panic!("the reply carries no {KEY_AP_LOCAL_POLICY} data: {other:?}"),
        };
        assert!(
            served
                .windows(manifest.len())
                .any(|window| window == manifest.as_slice()),
            "the board manifest is not in the stitched object verbatim"
        );
        assert!(
            served
                .windows(RECOVERY_OS_LOCAL_POLICY_IM4P.len())
                .any(|window| window == RECOVERY_OS_LOCAL_POLICY_IM4P)
        );
        let lines = lines.lock().unwrap();
        let named: Vec<&String> = lines
            .iter()
            .filter(|line| line.contains("result=recovery-os-local-policy-global-signed"))
            .collect();
        assert_eq!(named.len(), 1, "{lines:?}");
        assert!(
            named[0].contains("Ap,RecoveryOSPolicyNonceHash"),
            "{named:?}"
        );
        assert!(named[0].contains("GLOBAL SIGNING"), "{named:?}");
    }

    fn streamed_bytes(object: &StreamedObject) -> Vec<u8> {
        match &object.payload {
            crate::ramrod::StreamedPayload::Bytes(bytes) => bytes.clone(),
            crate::ramrod::StreamedPayload::File { path, .. } => std::fs::read(path).unwrap(),
        }
    }

    fn test_im4p(tag: &str, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        for text in ["IM4P", tag, "0"] {
            body.push(0x16);
            body.push(text.len() as u8);
            body.extend_from_slice(text.as_bytes());
        }
        body.push(0x04);
        body.push(payload.len() as u8);
        body.extend_from_slice(payload);
        let mut out = vec![0x30, body.len() as u8];
        out.extend_from_slice(&body);
        out
    }

    fn test_board_manifest() -> Vec<u8> {
        vec![0x30, 0x06, 0x16, 0x04, b'I', b'M', b'4', b'M']
    }

    fn seal_identity_manifest() -> plist::Dictionary {
        let component = |path: &str| {
            let mut info = plist::Dictionary::new();
            info.insert("Path".into(), plist::Value::String(path.into()));
            let mut entry = plist::Dictionary::new();
            entry.insert("Info".into(), plist::Value::Dictionary(info));
            plist::Value::Dictionary(entry)
        };
        let mut components = plist::Dictionary::new();
        components.insert(
            COMPONENT_SYSTEM_VOLUME.into(),
            component("Firmware/094-56453-088.dmg.aea.root_hash"),
        );
        components.insert(
            COMPONENT_SYSTEM_VOLUME_CANONICAL_METADATA.into(),
            component("Firmware/094-56453-088.dmg.aea.mtree"),
        );
        let mut info = plist::Dictionary::new();
        info.insert("DeviceClass".into(), plist::Value::String("j274ap".into()));
        info.insert(
            "Variant".into(),
            plist::Value::String("Customer Erase Install (IPSW)".into()),
        );
        let mut identity = plist::Dictionary::new();
        identity.insert("Info".into(), plist::Value::Dictionary(info));
        identity.insert(
            IDENTITY_MANIFEST_KEY.into(),
            plist::Value::Dictionary(components),
        );
        let mut root = plist::Dictionary::new();
        root.insert(
            "BuildIdentities".into(),
            plist::Value::Array(vec![plist::Value::Dictionary(identity)]),
        );
        root
    }

    #[test]
    fn the_seal_inputs_are_served_from_the_paths_the_identity_names() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("Firmware")).unwrap();
        let root_hash = test_im4p("isys", &[0xE6, 0x65, 0x08, 0x86]);
        let metadata = test_im4p("msys", &[0x70, 0x62, 0x7A, 0x65]);
        std::fs::write(
            dir.path().join("Firmware/094-56453-088.dmg.aea.root_hash"),
            &root_hash,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("Firmware/094-56453-088.dmg.aea.mtree"),
            &metadata,
        )
        .unwrap();
        let (reporter, lines) = capturing();
        let mut provider = PersonalizedFirmwareProvider::new(
            seal_identity_manifest(),
            "J274AP".to_string(),
            "Customer Erase Install (IPSW)".to_string(),
            "macOS Customer".to_string(),
            Some(dir.path().to_path_buf()),
            Some(test_board_manifest()),
            None,
            62078,
            0.0,
            &reporter,
        );
        for (data_type, payload) in [
            (DataType::SystemImageRootHash, &root_hash),
            (DataType::SystemImageCanonicalMetadata, &metadata),
        ] {
            let object = provider
                .supply_streamed(&data_request(data_type.clone()))
                .unwrap_or_else(|| panic!("{data_type} was left unclaimed"))
                .unwrap_or_else(|error| panic!("{data_type} failed: {error}"));
            let served = streamed_bytes(&object);
            assert!(
                served[..12].windows(4).any(|window| window == b"IMG4"),
                "{data_type} did not come back as an Image4"
            );
            assert!(
                served
                    .windows(payload.len())
                    .any(|window| window == payload.as_slice()),
                "{data_type} did not carry Apple's own payload verbatim"
            );
            assert!(
                served
                    .windows(test_board_manifest().len())
                    .any(|window| window == test_board_manifest()),
                "{data_type} was not wrapped with the board manifest"
            );
        }
        let lines = lines.lock().unwrap();
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.contains("result=system-volume-object-served"))
                .count(),
            2,
            "{lines:?}"
        );
    }

    #[test]
    fn the_seal_inputs_fall_through_to_the_decline_without_a_firmware_root() {
        let (reporter, lines) = capturing();
        let mut provider = PersonalizedFirmwareProvider::new(
            seal_identity_manifest(),
            "J274AP".to_string(),
            "Customer Erase Install (IPSW)".to_string(),
            "macOS Customer".to_string(),
            None,
            None,
            None,
            62078,
            0.0,
            &reporter,
        );
        for data_type in [
            DataType::SystemImageRootHash,
            DataType::SystemImageCanonicalMetadata,
        ] {
            assert!(
                provider
                    .supply_streamed(&data_request(data_type.clone()))
                    .is_none(),
                "{data_type} was claimed by a host that holds nothing for it"
            );
        }
        let lines = lines.lock().unwrap();
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.contains("result=system-volume-object-absent"))
                .count(),
            2,
            "{lines:?}"
        );
    }

    fn manifest_with_properties() -> Vec<u8> {
        fn der(identifier: &[u8], body: &[u8]) -> Vec<u8> {
            let mut out = identifier.to_vec();
            if body.len() < 0x80 {
                out.push(body.len() as u8);
            } else {
                out.push(0x81);
                out.push(body.len() as u8);
            }
            out.extend_from_slice(body);
            out
        }
        fn private_identifier(code: &str) -> Vec<u8> {
            let bytes = code.as_bytes();
            let mut value = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
            let mut groups = Vec::new();
            loop {
                groups.push((value & 0x7f) as u8);
                value >>= 7;
                if value == 0 {
                    break;
                }
            }
            groups.reverse();
            let mut identifier = vec![0xff];
            for (index, group) in groups.iter().enumerate() {
                if index + 1 == groups.len() {
                    identifier.push(*group);
                } else {
                    identifier.push(group | 0x80);
                }
            }
            identifier
        }
        let ia5 = |text: &str| der(&[0x16], text.as_bytes());
        let property = |code: &str, value: Vec<u8>| {
            let mut inner = ia5(code);
            inner.extend_from_slice(&value);
            der(&private_identifier(code), &der(&[0x30], &inner))
        };
        let block = |code: &str, properties: Vec<u8>| {
            let mut inner = ia5(code);
            inner.extend_from_slice(&der(&[0x31], &properties));
            der(&private_identifier(code), &der(&[0x30], &inner))
        };
        let properties = property("CHIP", der(&[0x02], &[0x81, 0x03]));
        let mut entries = block("MANP", properties);
        entries.extend_from_slice(&block("krnl", property("DGST", der(&[0x04], &[1u8; 48]))));
        let mut top = ia5("IM4M");
        top.extend_from_slice(&der(&[0x02], &[0x00]));
        top.extend_from_slice(&der(&[0x31], &block("MANB", entries)));
        top.extend_from_slice(&der(&[0x04], &[0xAA; 8]));
        der(&[0x30], &top)
    }

    fn splat_request(updater: &str) -> DataRequest {
        data_request_with(
            DataType::from_wire(FIRMWARE_UPDATER_DATA_TYPE),
            vec![
                (
                    KEY_MESSAGE_ARG_UPDATER_NAME,
                    plist::Value::String(updater.into()),
                ),
                (
                    "MessageArgType",
                    plist::Value::String(KEY_FIRMWARE_RESPONSE_DATA.into()),
                ),
                ("MessageForceRepersonalization", plist::Value::Boolean(true)),
                ("DataChunkSize", plist::Value::Integer(0x20000_i64.into())),
                (
                    "DeviceGeneratedRequest",
                    plist::Value::Dictionary(plist::Dictionary::new()),
                ),
                (
                    "DeviceGeneratedTags",
                    plist::Value::Dictionary(plist::Dictionary::new()),
                ),
            ],
        )
    }

    fn splat_answers(
        root: &std::path::Path,
        ap_nonce: Option<[u8; BOOT_NONCE_HASH_BYTES]>,
        reporter: &SharedReporter,
    ) -> RestoreAnswers {
        RestoreAnswers {
            tickets: GlobalManifestProvider::new(
                root.to_path_buf(),
                test_variants(),
                "J274AP".to_string(),
                false,
                62078,
                0.0,
                None,
                None,
                ap_nonce,
                reporter,
            ),
            firmware: None,
            identities: test_identity_provider(),
            personalized: test_personalized_provider(),
            source_boot_objects: test_source_boot_object_provider(root),
            fdr: test_fdr_provider(reporter),
            port: 62078,
            armed_at_secs: 0.0,
            reporter: Arc::clone(reporter),
        }
    }

    fn ticket_signing(objects: &[(&str, &[u8])]) -> Vec<u8> {
        fn der(identifier: &[u8], body: &[u8]) -> Vec<u8> {
            let mut out = identifier.to_vec();
            if body.len() < 0x80 {
                out.push(body.len() as u8);
            } else if body.len() <= 0xff {
                out.push(0x81);
                out.push(body.len() as u8);
            } else {
                out.push(0x82);
                out.push((body.len() >> 8) as u8);
                out.push((body.len() & 0xff) as u8);
            }
            out.extend_from_slice(body);
            out
        }
        fn private_identifier(code: &str) -> Vec<u8> {
            let bytes = code.as_bytes();
            let mut value = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
            let mut groups = Vec::new();
            loop {
                groups.push((value & 0x7f) as u8);
                value >>= 7;
                if value == 0 {
                    break;
                }
            }
            groups.reverse();
            let mut identifier = vec![0xff];
            for (index, group) in groups.iter().enumerate() {
                if index + 1 == groups.len() {
                    identifier.push(*group);
                } else {
                    identifier.push(group | 0x80);
                }
            }
            identifier
        }
        let ia5 = |text: &str| der(&[0x16], text.as_bytes());
        let property = |code: &str, value: Vec<u8>| {
            let mut inner = ia5(code);
            inner.extend_from_slice(&value);
            der(&private_identifier(code), &der(&[0x30], &inner))
        };
        let block = |code: &str, properties: Vec<u8>| {
            let mut inner = ia5(code);
            inner.extend_from_slice(&der(&[0x31], &properties));
            der(&private_identifier(code), &der(&[0x30], &inner))
        };
        let mut entries = block("MANP", property("CHIP", der(&[0x02], &[0x81, 0x03])));
        for (tag, digest) in objects {
            entries.extend_from_slice(&block(tag, property("DGST", der(&[0x04], digest))));
        }
        let mut top = ia5("IM4M");
        top.extend_from_slice(&der(&[0x02], &[0x00]));
        top.extend_from_slice(&der(&[0x31], &block("MANB", entries)));
        top.extend_from_slice(&der(&[0x04], &[0xAA; 8]));
        der(&[0x30], &top)
    }

    fn cryptex_identity_manifest(paths: &[(&str, &str)]) -> plist::Dictionary {
        let mut components = plist::Dictionary::new();
        for (name, path) in paths {
            let mut info = plist::Dictionary::new();
            info.insert("Path".into(), plist::Value::String((*path).into()));
            info.insert("HashMethod".into(), plist::Value::String("sha2-384".into()));
            let mut entry = plist::Dictionary::new();
            entry.insert("Info".into(), plist::Value::Dictionary(info));
            components.insert((*name).into(), plist::Value::Dictionary(entry));
        }
        let mut info = plist::Dictionary::new();
        info.insert("DeviceClass".into(), plist::Value::String("j274ap".into()));
        info.insert(
            "Variant".into(),
            plist::Value::String("macOS Customer".into()),
        );
        info.insert("ContentEncoding".into(), plist::Value::String("aea".into()));
        let mut identity = plist::Dictionary::new();
        identity.insert("Info".into(), plist::Value::Dictionary(info));
        identity.insert(
            IDENTITY_MANIFEST_KEY.into(),
            plist::Value::Dictionary(components),
        );
        let mut root = plist::Dictionary::new();
        root.insert(
            "BuildIdentities".into(),
            plist::Value::Array(vec![plist::Value::Dictionary(identity)]),
        );
        root
    }

    #[test]
    fn a_cryptex_member_is_held_only_when_it_matches_the_tickets_digest() {
        let dir = tempfile::tempdir().unwrap();
        let good = b"the payload this build describes".to_vec();
        let bad = b"a payload from some other build".to_vec();
        std::fs::write(dir.path().join("system.dmg"), &good).unwrap();
        std::fs::write(dir.path().join("app.dmg"), &bad).unwrap();
        let ticket = ticket_signing(&[("csos", &sha384(&good)), ("caos", &sha384(&good))]);
        let manifest = cryptex_identity_manifest(&[
            ("Cryptex1,SystemOS", "system.dmg"),
            ("Cryptex1,AppOS", "app.dmg"),
        ]);
        let (reporter, lines) = capturing();
        let plan = resolve_splat_components(
            &manifest,
            "J274AP",
            "macOS Customer",
            Some(&ticket),
            None,
            Some(&dir.path().to_path_buf()),
            62078,
            0.0,
            &reporter,
        );
        assert!(
            matches!(
                plan.components.get("Cryptex1,SystemOS"),
                Some(SplatComponent::Serve { verified: true, .. })
            ),
            "{:?}",
            plan.components.get("Cryptex1,SystemOS")
        );
        assert!(matches!(
            plan.components.get("Cryptex1,AppOS"),
            Some(SplatComponent::Omit { .. })
        ));
        assert_eq!(plan.omitted(), vec!["Cryptex1,AppOS".to_string()]);
        let lines = lines.lock().unwrap();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("result=splat-component-omitted")
                    && line.contains("component=Cryptex1,AppOS")
                    && line.contains("DEVIATION FROM A REAL RESTORE")),
            "{lines:?}"
        );
    }

    #[test]
    fn the_served_identity_names_only_the_members_the_host_can_serve() {
        let (reporter, lines) = capturing();
        let mut provider = BuildIdentityProvider::new(
            cryptex_identity_manifest(&[
                ("Cryptex1,SystemOS", "system.dmg"),
                ("Cryptex1,AppOS", "app.dmg"),
            ]),
            "J274AP".to_string(),
            "macOS Customer".to_string(),
            "macOS Customer".to_string(),
            vec!["Cryptex1,AppOS".to_string()],
            62078,
            0.0,
            &reporter,
        );
        let body = provider
            .supply(&data_request(DataType::BuildIdentityDict))
            .unwrap();
        let components = body
            .get(crate::ramrod::message::KEY_BUILD_IDENTITY_DICT)
            .and_then(plist::Value::as_dictionary)
            .and_then(|identity| identity.get(IDENTITY_MANIFEST_KEY))
            .and_then(plist::Value::as_dictionary)
            .expect("the identity carries its Manifest");
        assert!(components.contains_key("Cryptex1,SystemOS"));
        assert!(
            !components.contains_key("Cryptex1,AppOS"),
            "a member this host cannot serve must not be advertised"
        );
        let lines = lines.lock().unwrap();
        assert!(
            lines.iter().any(
                |line| line.contains("result=build-identity-components-dropped")
                    && line.contains("Cryptex1,AppOS")
            ),
            "{lines:?}"
        );
    }

    #[test]
    fn a_held_cryptex_member_is_streamed_from_the_file_it_resolved_to() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"cryptex system image bytes".to_vec();
        std::fs::write(dir.path().join("system.dmg"), &payload).unwrap();
        let ticket = ticket_signing(&[("csos", &sha384(&payload))]);
        let manifest = cryptex_identity_manifest(&[("Cryptex1,SystemOS", "system.dmg")]);
        let plan = resolve_splat_components(
            &manifest,
            "J274AP",
            "macOS Customer",
            Some(&ticket),
            None,
            Some(&dir.path().to_path_buf()),
            62078,
            0.0,
            &reporter(),
        );
        let (reporter, lines) = capturing();
        let mut provider = SourceBootObjectProvider::new(
            dir.path().to_path_buf(),
            "macOS Customer".to_string(),
            "J274AP".to_string(),
            manifest,
            None,
            Some(dir.path().to_path_buf()),
            plan,
            62078,
            0.0,
            &reporter,
        );
        let mut arguments = plist::Dictionary::new();
        arguments.insert(
            KEY_IMAGE_NAME.to_string(),
            plist::Value::String("Cryptex1,SystemOS".into()),
        );
        arguments.insert(
            KEY_DATA_CHUNK_SIZE.to_string(),
            plist::Value::Integer(131_072_i64.into()),
        );
        let object = provider
            .supply_streamed(&DataRequest {
                data_type: DataType::SourceBootObjectV4,
                data_port: None,
                arguments,
                asynchronous: false,
                async_context_uuid: None,
            })
            .expect("the request is claimed")
            .expect("the member is held");
        assert!(
            matches!(object.payload, crate::ramrod::StreamedPayload::File { .. }),
            "a payload this size class is streamed off disk, not held in memory"
        );
        assert_eq!(streamed_bytes(&object), payload);
        assert_eq!(object.chunk_size, 131_072);
        let lines = lines.lock().unwrap();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("result=source-component-served")
                    && line.contains("component=Cryptex1,SystemOS")
                    && line.contains("digest=ticket-verified")),
            "{lines:?}"
        );
    }

    #[test]
    fn the_cryptex1_personalization_request_is_answered_with_the_boards_own_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let cryptex = image4_element("IM4M", &[]);
        manifests_tree(dir.path(), "j274ap", &[0x30, 0x02, 0x16, 0x00], &cryptex);
        let (reporter, lines) = capturing();
        let mut answers = splat_answers(dir.path(), None, &reporter);
        let body = answers
            .supply(&splat_request(UPDATER_NAME_CRYPTEX1))
            .unwrap();
        let response = body
            .get(KEY_FIRMWARE_RESPONSE_DATA)
            .and_then(plist::Value::as_dictionary)
            .expect("the reply carries the personalisation response as a dictionary");
        assert_eq!(
            response
                .get(KEY_CRYPTEX1_TICKET)
                .and_then(plist::Value::as_data),
            Some(cryptex.as_slice()),
            "the ticket key must carry the manifest bytes verbatim"
        );
        assert_eq!(KEY_CRYPTEX1_TICKET, "Cryptex1,Ticket");
        let lines = lines.lock().unwrap();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("result=splat-ticket-served")
                    && line.contains("updater=Cryptex1")
                    && line.contains("device_generated=true")
                    && line.contains("repersonalize=true")
                    && line.contains("DEVIATION FROM A REAL DEVICE")
                    && line.contains("STATIC GLOBAL")),
            "{lines:?}"
        );
        assert!(
            !lines
                .iter()
                .any(|line| line.contains("result=data-declined")
                    && line.contains("FirmwareUpdaterData")),
            "the personalisation request must not fall through to the generic decline: {lines:?}"
        );
    }

    #[test]
    fn the_served_splat_ticket_is_apples_bytes_unmodified() {
        let dir = tempfile::tempdir().unwrap();
        let cryptex = manifest_with_properties();
        manifests_tree(dir.path(), "j274ap", &[0x30, 0x02, 0x16, 0x00], &cryptex);
        let nonce = [0x5Au8; BOOT_NONCE_HASH_BYTES];
        let (reporter, lines) = capturing();
        let mut answers = splat_answers(dir.path(), Some(nonce), &reporter);
        let body = answers
            .supply(&splat_request(UPDATER_NAME_CRYPTEX1))
            .unwrap();
        let served = body
            .get(KEY_FIRMWARE_RESPONSE_DATA)
            .and_then(plist::Value::as_dictionary)
            .and_then(|response| response.get(KEY_CRYPTEX1_TICKET))
            .and_then(plist::Value::as_data)
            .expect("the reply carries the ticket");
        assert_eq!(
            served,
            cryptex.as_slice(),
            "the grafted manifest must be Apple's file byte for byte"
        );
        assert_eq!(
            crate::ramrod::ticket::read_manifest(served)
                .unwrap()
                .boot_nonce_hash(),
            None,
            "no BNCH may be written into the manifest that is grafted and re-verified"
        );
        let stapled = crate::ramrod::ticket::set_boot_nonce_hash(&cryptex, &nonce)
            .expect("the fixture is rewritable, so an ungated staple would have landed");
        assert_ne!(
            stapled, cryptex,
            "the fixture must be one the staple actually changes"
        );
        let lines = lines.lock().unwrap();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("result=splat-ticket-served")
                    && line.contains("boot_nonce=unstaged")
                    && line.contains("signature=apple-intact")),
            "{lines:?}"
        );
    }

    #[test]
    fn only_the_ap_root_ticket_is_rewritten_and_the_cryptex_one_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let os = ticket_signing(&[("krnl", &[7u8; 48])]);
        let cryptex = manifest_with_properties();
        assert_ne!(os, cryptex);
        manifests_tree(dir.path(), "j274ap", &os, &cryptex);
        let nonce = [0x5Au8; BOOT_NONCE_HASH_BYTES];
        let mut provider = GlobalManifestProvider::new(
            dir.path().to_path_buf(),
            test_variants(),
            "J274AP".to_string(),
            false,
            62078,
            0.0,
            None,
            None,
            Some(nonce),
            &reporter(),
        );
        let mut cryptex_request = data_request(DataType::RootTicket);
        cryptex_request.arguments.insert(
            "ImageName".to_string(),
            plist::Value::String("Cryptex1,SystemOS".to_string()),
        );
        let served_cryptex = provider
            .supply(&cryptex_request)
            .unwrap()
            .get("RootTicketData")
            .and_then(plist::Value::as_data)
            .map(<[u8]>::to_vec)
            .expect("the cryptex ticket is answered");
        assert_eq!(
            served_cryptex, cryptex,
            "the cryptex manifest must go out as Apple signed it on this channel too"
        );

        let served_os = provider
            .supply(&data_request(DataType::RootTicket))
            .unwrap()
            .get("RootTicketData")
            .and_then(plist::Value::as_data)
            .map(<[u8]>::to_vec)
            .expect("the AP root ticket is answered");
        assert_eq!(
            crate::ramrod::ticket::read_manifest(&served_os)
                .unwrap()
                .boot_nonce_hash(),
            Some(nonce.as_slice()),
            "install_splat reads BNCH out of the AP root ticket, so that one keeps the staple"
        );
    }

    #[test]
    fn a_non_cryptex_updater_keeps_the_named_decline() {
        let dir = tempfile::tempdir().unwrap();
        manifests_tree(dir.path(), "j274ap", &[0x30, 0x02, 0x16, 0x00], &[9]);
        let (reporter, lines) = capturing();
        let mut answers = splat_answers(dir.path(), None, &reporter);
        let body = answers.supply(&splat_request("SE")).unwrap();
        assert!(
            body.is_empty(),
            "nothing is invented for an updater the host holds no file for"
        );
        let lines = lines.lock().unwrap();
        assert!(
            lines.iter().any(|line| line
                .contains("result=firmware-updater-personalization-unsigned")
                && line.contains("updater=SE")),
            "{lines:?}"
        );
        assert!(
            !lines
                .iter()
                .any(|line| line.contains("result=splat-ticket-served")),
            "no ticket may be served for an updater this host holds nothing for: {lines:?}"
        );
    }

    #[test]
    fn a_missing_cryptex_manifest_is_named_and_no_ticket_is_substituted() {
        let dir = tempfile::tempdir().unwrap();
        let os_path = dir
            .path()
            .join("macOS Customer")
            .join("apticket.j274ap.im4m");
        std::fs::create_dir_all(os_path.parent().unwrap()).unwrap();
        std::fs::write(os_path, [0x30, 0x02, 0x16, 0x00]).unwrap();
        let (reporter, lines) = capturing();
        let mut answers = splat_answers(dir.path(), None, &reporter);
        let body = answers
            .supply(&splat_request(UPDATER_NAME_CRYPTEX1))
            .unwrap();
        assert!(body.is_empty());
        let lines = lines.lock().unwrap();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("result=splat-ticket-manifest-missing")),
            "{lines:?}"
        );
    }

    #[test]
    fn a_firmware_request_with_no_firmware_source_ends_the_session_named_rather_than_declined() {
        let dir = tempfile::tempdir().unwrap();
        manifests_tree(dir.path(), "j274ap", &[0x30, 0x02, 0x16, 0x00], &[9]);
        let (reporter, lines) = capturing();
        let mut answers = RestoreAnswers {
            tickets: GlobalManifestProvider::new(
                dir.path().to_path_buf(),
                test_variants(),
                "J274AP".to_string(),
                false,
                62078,
                0.0,
                None,
                None,
                None,
                &reporter,
            ),
            firmware: None,
            identities: test_identity_provider(),
            personalized: test_personalized_provider(),
            source_boot_objects: test_source_boot_object_provider(dir.path()),
            fdr: test_fdr_provider(&reporter),
            port: 62078,
            armed_at_secs: 0.0,
            reporter: Arc::clone(&reporter),
        };
        answers
            .supply(&data_request(DataType::Other("NORData".into())))
            .expect_err(
                "the reply is fetched once and drained key by key, so an empty dictionary here is a NULL RestoreSEPImageData the guest can never ask for again",
            );
        let lines = lines.lock().unwrap();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("result=nor-source-absent"))
        );
        assert!(
            !lines
                .iter()
                .any(|line| line.contains("result=data-declined")),
            "this path no longer falls through to the ordinary decline: {lines:?}"
        );
    }

    #[test]
    fn a_ticket_that_cannot_be_resolved_still_ends_the_session() {
        let dir = tempfile::tempdir().unwrap();
        manifests_tree(dir.path(), "j274ap", &[1], &[2]);
        let mut answers = RestoreAnswers {
            tickets: GlobalManifestProvider::new(
                dir.path().to_path_buf(),
                test_variants(),
                "J999AP".to_string(),
                false,
                62078,
                0.0,
                None,
                None,
                None,
                &reporter(),
            ),
            firmware: None,
            identities: test_identity_provider(),
            personalized: test_personalized_provider(),
            source_boot_objects: test_source_boot_object_provider(dir.path()),
            fdr: test_fdr_provider(&reporter()),
            port: 62078,
            armed_at_secs: 0.0,
            reporter: reporter(),
        };
        assert!(
            answers
                .supply(&data_request(DataType::RecoveryOSRootTicketData))
                .is_err()
        );
    }

    #[test]
    fn a_build_identity_request_is_answered_with_the_manifest_s_own_entry() {
        let mut provider = test_identity_provider();
        let mut request = data_request(DataType::BuildIdentityDict);
        request.arguments.insert(
            "Variant".to_string(),
            plist::Value::String("macOS Customer".to_string()),
        );
        let body = provider.supply(&request).expect("the identity is answered");
        assert_eq!(
            body.get("Variant").and_then(plist::Value::as_string),
            Some("macOS Customer")
        );
        let identity = body
            .get("BuildIdentityDict")
            .and_then(plist::Value::as_dictionary)
            .expect("the entry itself is on the reply");
        assert_eq!(
            identity
                .get("MarkerForTheTest")
                .and_then(plist::Value::as_signed_integer),
            Some(2)
        );
    }

    #[test]
    fn a_build_identity_request_with_no_variant_uses_the_install_variant() {
        let mut provider = test_identity_provider();
        let body = provider
            .supply(&data_request(DataType::BuildIdentityDictV2))
            .expect("the identity is answered");
        assert_eq!(
            body.get("Variant").and_then(plist::Value::as_string),
            Some("Customer Erase Install (IPSW)")
        );
    }

    #[test]
    fn a_build_identity_request_for_an_unknown_variant_is_declined_not_substituted() {
        let mut provider = test_identity_provider();
        for variant in [
            "Customer Upgrade Install (IPSW)",
            "Research Erase Install (IPSW)",
        ] {
            let mut request = data_request(DataType::BuildIdentityDict);
            request.arguments.insert(
                "Variant".to_string(),
                plist::Value::String(variant.to_string()),
            );
            let body = provider
                .supply(&request)
                .expect("a decline is not a failure");
            assert!(
                body.is_empty(),
                "{variant} was answered with the wrong identity"
            );
        }
    }

    #[test]
    fn a_non_ticket_request_is_reported_by_name_not_served_manifest_bytes() {
        let dir = tempfile::tempdir().unwrap();
        manifests_tree(dir.path(), "j274ap", &[1, 2, 3], &[4]);
        let mut provider = GlobalManifestProvider::new(
            dir.path().to_path_buf(),
            test_variants(),
            "J274AP".to_string(),
            false,
            62078,
            0.0,
            None,
            None,
            None,
            &reporter(),
        );
        let error = provider
            .supply(&data_request(DataType::BuildIdentityDict))
            .expect_err("a non-ticket request is not answered from a manifest");
        assert!(matches!(error, ProviderError::Unsupported { .. }));
    }

    #[test]
    fn a_cryptex_argument_routes_to_the_cryptex_companion() {
        let dir = tempfile::tempdir().unwrap();
        let os = vec![10u8, 11, 12];
        let cryptex = vec![20u8, 21, 22, 23];
        manifests_tree(dir.path(), "j274ap", &os, &cryptex);
        let mut provider = GlobalManifestProvider::new(
            dir.path().to_path_buf(),
            test_variants(),
            "J274AP".to_string(),
            false,
            62078,
            0.0,
            None,
            None,
            None,
            &reporter(),
        );
        let mut request = data_request(DataType::RootTicket);
        request.arguments.insert(
            "ImageName".to_string(),
            plist::Value::String("Cryptex1,SystemOS".to_string()),
        );
        let body = provider.supply(&request).unwrap();
        assert_eq!(
            body.get("RootTicketData").and_then(plist::Value::as_data),
            Some(&cryptex[..])
        );
    }

    #[test]
    fn describe_plist_value_prints_a_length_for_data_rather_than_the_bytes() {
        let value = plist::Value::Data(vec![1, 2, 3, 4, 5]);
        assert_eq!(describe_plist_value(&value), "<data:5bytes>");
    }

    #[test]
    fn describe_plist_value_prints_scalars_as_their_own_text() {
        assert_eq!(
            describe_plist_value(&plist::Value::String("Cryptex1,SystemOS".to_string())),
            "Cryptex1,SystemOS"
        );
        assert_eq!(describe_plist_value(&plist::Value::Integer(3.into())), "3");
        assert_eq!(describe_plist_value(&plist::Value::Boolean(true)), "true");
    }

    #[test]
    fn describe_dictionary_entries_renders_every_key_and_value() {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "ImageName".to_string(),
            plist::Value::String("Cryptex1,SystemOS".to_string()),
        );
        dict.insert("SomeCount".to_string(), plist::Value::Integer(3.into()));
        assert_eq!(
            describe_dictionary_entries(&dict),
            "ImageName=Cryptex1,SystemOS,SomeCount=3"
        );
    }

    #[test]
    fn an_unanswered_request_names_its_own_argument_values_and_data_port() {
        let (reporter, lines) = capturing();
        let mut observer = RamrodTrace::new(62078, 0.0, reporter);
        let mut request = data_request(DataType::Other("SystemImageRootHash".to_string()));
        request.data_port = Some(9001);
        request.arguments.insert(
            "ImageName".to_string(),
            plist::Value::String("SystemVolume".to_string()),
        );
        observer.on_data_unanswered(
            &request,
            &ProviderError::Unsupported {
                data_type: "SystemImageRootHash".to_string(),
            },
        );
        let lines = lines.lock().unwrap();
        let line = lines
            .iter()
            .find(|line| line.contains("result=data-unanswered"))
            .expect("the refusal is reported under its own name");
        assert!(line.contains("SystemImageRootHash"), "{line}");
        assert!(line.contains("data_port=9001"), "{line}");
        assert!(line.contains("args=[ImageName=SystemVolume]"), "{line}");
        assert!(line.contains("last_operation=none"), "{line}");
        assert!(line.contains("checkpoints_seen=0"), "{line}");
        assert!(line.contains("begun=0 ended=0 open=0"), "{line}");
        assert!(line.contains("last_begun=none last_ended=none"), "{line}");
    }

    #[test]
    fn the_unanswered_line_carries_the_last_reported_operation_and_checkpoint_body() {
        let (reporter, lines) = capturing();
        let mut observer = RamrodTrace::new(62078, 0.0, reporter);
        observer.on_progress(Some(28), Some(0.5));
        let mut checkpoint_body = plist::Dictionary::new();
        checkpoint_body.insert(
            "UnverifiedStepKey".to_string(),
            plist::Value::Integer(1558.into()),
        );
        observer.on_checkpoint(
            &Checkpoint {
                id: Some(0x1616),
                name: Some("macos_create_recovery_local_policy"),
                result: None,
                complete: Some(false),
                has_error: false,
                has_warning: false,
                has_info: false,
            },
            &checkpoint_body,
        );
        let request = data_request(DataType::SourceBootObjectV5);
        observer.on_data_unanswered(
            &request,
            &ProviderError::Unsupported {
                data_type: "SourceBootObjectV5".to_string(),
            },
        );
        let lines = lines.lock().unwrap();
        let line = lines
            .iter()
            .find(|line| line.contains("result=data-unanswered"))
            .expect("the refusal is reported under its own name");
        assert!(line.contains("last_operation=28"), "{line}");
        assert!(line.contains("checkpoints_seen=1"), "{line}");
        assert!(line.contains("begun=1 ended=0 open=1"), "{line}");
        assert!(
            line.contains("last_begun=0x1616 macos_create_recovery_local_policy"),
            "{line}"
        );
        let checkpoint = lines
            .iter()
            .find(|line| line.contains("result=restore-checkpoint"))
            .expect("the checkpoint is reported under its own name");
        assert!(
            checkpoint.contains("detail=\"UnverifiedStepKey=1558\""),
            "{checkpoint}"
        );
    }
}
