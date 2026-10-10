use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::crypto::{P256_UNCOMPRESSED_BYTES, P256PrivateKey};

use crate::asr_server::producer::{
    AsrPhase, AsrProducerActivity, AsrProducerEvent, AsrProducerSink, AsrProducerWatchdogHandle,
    AsrProducerWatchdogPolicy, spawn_asr_producer_watchdog,
};
use crate::asr_server::{AsrServerConfig, PayloadObserver};
use crate::ramrod::{
    AsrBulkTransfer, BOOT_NONCE_HASH_BYTES, BootabilityBundleSource, BootabilityBundleTransfer,
    BootabilityRouter, DialPlan, HttpAssetAnswers, HttpAssetRouter, HttpAssetTransfer,
    PreparedAnswers, QueryKey, RestoreDataProvider, RestoreSummary, SystemClock,
    instance_identifier, load_build_manifest,
};
use crate::usbmux::{BulkTransport, is_device_gone, is_host_initiated_teardown, is_run_stopped};

use super::local_policy::{
    CurlSigningTransport, DeviceHardwareInfo, FirmwareUpdaterSigner, RecoveryOsLocalPolicySigner,
    SIGNING_ENVELOPE_VERSION_INFO, SIGNING_OPT_IN_FLAG, SIGNING_OPT_IN_KEY,
    SIGNING_SERVER_DEFAULT_BASE_URL, SigningEnvelope, firmware_updater_signer,
    signing_server_signer,
};
use super::mux::{ClaimedMuxTransport, bring_up_mux};
use super::options::{manifest_identity_count, resolve_restore_manifest};
use super::phases::{
    RestorePhaseError, RestorePreparationError, query_and_prepare_restore_session,
    start_prepared_restore,
};
use super::plan::{FDR_TRUST_NOT_AFTER, FDR_TRUST_NOT_BEFORE, RestorePlan, hex_digest};
use super::providers::{
    BuildIdentityProvider, FdrTrustProvider, GlobalManifestProvider, NorFirmwareProvider,
    PersonalizedFirmwareProvider, RamrodTrace, RestoreAnswers, RestoreVariants,
    SourceBootObjectProvider, board_manifest_for_firmware, resolve_splat_components,
};
use super::report::{ASR_SERVE_PREFIX, MUX_PREFIX, SharedReporter, lock, report};
use super::reverse_proxy;
use super::seal_report::{ARMED_IMAGE_SEAL_MEANING, classify_armed_image_seals};
use super::seal_server::{
    FDR_SEAL_PREFIX, FdrManifestSigner, LocalFdrManifestSigner, SIGNING_KEY_SOURCE_LEAF_SEED,
    SIGNING_KEY_SOURCE_SEP, SealServer, service_base_url,
};
use super::thread_class::{ThreadClass, set_current_thread_class};

struct ReporterProducerTrace {
    reporter: SharedReporter,
}

impl ReporterProducerTrace {
    fn new(reporter: SharedReporter) -> Self {
        Self { reporter }
    }
}

impl AsrProducerSink for ReporterProducerTrace {
    fn event(&self, event: AsrProducerEvent) {
        let result = event.result();
        let line = format!("{ASR_SERVE_PREFIX} {event}");
        report(&self.reporter, result, &line);
    }
}

pub struct PayloadProgress {
    total: u64,
    began: Instant,
    blocks: u64,
    bytes: u64,
    stop: Arc<AtomicBool>,
    reporter: SharedReporter,
    activity: Arc<AsrProducerActivity>,
    session_began: Instant,
    transfer_cancel: Option<Arc<AtomicBool>>,
    watchdog: Option<AsrProducerWatchdogHandle>,
    stopped_for: Option<crate::ramrod::DialCancellation>,
}

impl PayloadProgress {
    pub fn new(total: u64, stop: Arc<AtomicBool>, reporter: SharedReporter) -> Self {
        let activity = Arc::new(AsrProducerActivity::new());
        activity.set_total(total);
        Self {
            total,
            began: Instant::now(),
            blocks: 0,
            bytes: 0,
            stop,
            reporter,
            activity,
            session_began: Instant::now(),
            transfer_cancel: None,
            watchdog: None,
            stopped_for: None,
        }
    }

    #[must_use]
    pub fn on_session_clock(mut self, session_began: Instant) -> Self {
        self.session_began = session_began;
        self.activity
            .set_session_offset(session_began.elapsed().saturating_sub(self.began.elapsed()));
        self
    }

    pub fn with_transfer_cancel(mut self, cancel: Arc<AtomicBool>) -> Self {
        self.transfer_cancel = Some(cancel);
        self
    }

    fn start_watchdog(&mut self) {
        self.watchdog = Some(spawn_asr_producer_watchdog(
            Arc::clone(&self.activity),
            Arc::new(ReporterProducerTrace::new(Arc::clone(&self.reporter))),
            AsrProducerWatchdogPolicy::default(),
        ));
    }

    #[must_use]
    pub fn activity(&self) -> Arc<AsrProducerActivity> {
        Arc::clone(&self.activity)
    }
}

impl Clone for PayloadProgress {
    fn clone(&self) -> Self {
        let mut progress = Self::new(
            self.total,
            Arc::clone(&self.stop),
            Arc::clone(&self.reporter),
        )
        .on_session_clock(self.session_began);
        progress.transfer_cancel = self.transfer_cancel.clone();
        progress
    }
}

impl PayloadObserver for PayloadProgress {
    fn block_sent(&mut self, offset: u64, data_len: usize) {
        self.blocks += 1;
        self.bytes = offset + data_len as u64;
        self.activity.served_to(self.bytes, self.blocks);
        let elapsed = self.began.elapsed();
        lock(&self.reporter).payload_block(self.bytes, self.total, self.blocks, elapsed);
    }

    fn should_stop(&mut self) -> bool {
        let reason = if self.stop.load(Ordering::Acquire) {
            Some(crate::ramrod::DialCancellation::OperatorStopped)
        } else if self
            .transfer_cancel
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            Some(crate::ramrod::DialCancellation::TransferFailed)
        } else {
            None
        };
        if let Some(reason) = reason {
            self.stopped_for = Some(reason);
            true
        } else {
            false
        }
    }

    fn stop_error(&mut self) -> std::io::Error {
        match self.stopped_for {
            Some(reason) => std::io::Error::new(std::io::ErrorKind::ConnectionAborted, reason),
            None => std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "ASR payload stopped without a recorded cancellation reason",
            ),
        }
    }

    fn entered_phase(&mut self, phase: AsrPhase, _offset: u64) {
        self.activity.enter(phase);
    }

    fn serving_port(&mut self, port: u16, payload_size: u64) {
        self.total = payload_size;
        self.activity.set_port(port);
        self.activity.set_total(payload_size);
    }

    fn image_matched(
        &mut self,
        data_type: &str,
        port: u16,
        image: &std::path::Path,
        origin: &str,
        payload_size: u64,
    ) {
        let line = format!(
            "{ASR_SERVE_PREFIX} result=bulk-image-matched port={port} type={data_type} origin={origin} size={payload_size} image=\"{}\" meaning=\"the bulk transfer about to open on this port will stream this file for this DataType; origin says on whose authority, and two different types printing this same path with origin=default is one image answering both rather than either being resolved\" detail=\"\"",
            image.display()
        );
        report(&self.reporter, "bulk-image-matched", &line);
    }
}

fn report_armed_image_seal(reporter: &SharedReporter, port: u16, armed_at_secs: f64, path: &Path) {
    let mut probe = vec![0u8; 4096];
    let opened = std::fs::File::open(path).and_then(|mut file| {
        use std::io::Read;
        file.read_exact(&mut probe).map(|()| file)
    });
    let file = match opened {
        Ok(file) => file,
        Err(error) => {
            let line = format!(
                "{MUX_PREFIX} result=bulk-image-seal-unread port={port} at={armed_at_secs:.3}s image=\"{}\" meaning=\"{ARMED_IMAGE_SEAL_MEANING}\" detail=\"opening or reading block zero failed: {error}\"",
                path.display()
            );
            report(reporter, "bulk-image-seal-unread", &line);
            return;
        }
    };
    let container = match crate::apfs_image::probe_container(&probe) {
        Ok(container) => container,
        Err(error) => {
            let line = format!(
                "{MUX_PREFIX} result=bulk-image-seal-unread port={port} at={armed_at_secs:.3}s image=\"{}\" meaning=\"{ARMED_IMAGE_SEAL_MEANING}\" detail=\"not a bare APFS container: {error}\"",
                path.display()
            );
            report(reporter, "bulk-image-seal-unread", &line);
            return;
        }
    };
    let mut blocks = crate::apfs_verify::ReaderBlocks::new(file, 0, container.block_size);
    let seals = match crate::apfs_verify::read_container_seals(&mut blocks) {
        Ok(seals) => seals,
        Err(error) => {
            let line = format!(
                "{MUX_PREFIX} result=bulk-image-seal-unread port={port} at={armed_at_secs:.3}s image=\"{}\" meaning=\"{ARMED_IMAGE_SEAL_MEANING}\" detail=\"seal read failed: {error}\"",
                path.display()
            );
            report(reporter, "bulk-image-seal-unread", &line);
            return;
        }
    };
    let classified = classify_armed_image_seals(&seals);
    let sealed = classified.sealed_volume_count;
    let tokens = classified.container_tokens();
    let detail = classified.detail_line();
    let line = format!(
        "{MUX_PREFIX} result=bulk-image-seal port={port} at={armed_at_secs:.3}s image=\"{}\" block_size={} blocks={} xid={} volumes={} sealed={sealed} {tokens} meaning=\"{ARMED_IMAGE_SEAL_MEANING}\" detail=\"{detail}\"",
        path.display(),
        seals.block_size,
        seals.block_count,
        seals.xid,
        seals.volumes.len(),
    );
    report(reporter, "bulk-image-seal", &line);
}

pub enum RestoreOutcome {
    Ended {
        summary: Box<RestoreSummary>,
        bulk_transfers: usize,
    },
    Failed {
        stage: String,
        reason: String,
    },
}

#[derive(Clone)]
pub struct RestoreBootContext {
    pub ap_nonce: Option<[u8; BOOT_NONCE_HASH_BYTES]>,
    pub sep_nonce: Option<[u8; 20]>,
    pub sep_public_key: Option<[u8; P256_UNCOMPRESSED_BYTES]>,
    pub remote_digest_signing: bool,
    pub manifest_signer: Option<Arc<dyn FdrManifestSigner>>,
    pub local_test_signing_key: Option<P256PrivateKey>,
    pub metadata_unavailable: Option<String>,
    pub vm_local_signing_enabled: bool,
    pub skip_tcon_firmware: bool,
}

impl Default for RestoreBootContext {
    fn default() -> Self {
        Self {
            ap_nonce: None,
            sep_nonce: None,
            sep_public_key: None,
            remote_digest_signing: false,
            manifest_signer: None,
            local_test_signing_key: None,
            metadata_unavailable: None,
            vm_local_signing_enabled: true,
            skip_tcon_firmware: false,
        }
    }
}

impl std::fmt::Debug for RestoreBootContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RestoreBootContext")
            .field("metadata_unavailable", &self.metadata_unavailable)
            .field("vm_local_signing_enabled", &self.vm_local_signing_enabled)
            .field("skip_tcon_firmware", &self.skip_tcon_firmware)
            .field("ap_nonce", &self.ap_nonce)
            .field(
                "sep_public_key",
                &self.sep_public_key.as_ref().map(|bytes| hex_digest(bytes)),
            )
            .field("remote_digest_signing", &self.remote_digest_signing)
            .field("has_manifest_signer", &self.manifest_signer.is_some())
            .field(
                "has_local_test_signing_key",
                &self.local_test_signing_key.is_some(),
            )
            .finish()
    }
}

fn apply_skip_tcon_firmware(derived: &mut super::options::DerivedRestoreOptions, enabled: bool) {
    if enabled && !derived.is_macos {
        derived.options = std::mem::take(&mut derived.options)
            .with_value("SkipTCONFW", plist::Value::Boolean(true));
        if !derived.report.keys.iter().any(|key| key == "SkipTCONFW") {
            derived.report.keys.push("SkipTCONFW".to_string());
            derived.report.keys.sort();
        }
    }
}

fn reload_fdr_trust_material(directory: &Path) -> Result<crate::ramrod::FdrTrustMaterial, String> {
    crate::ramrod::FdrTrustMaterial::load_from_directory(directory)
        .map_err(|error| error.to_string())
}

fn validate_fdr_material_binding(
    material: &crate::ramrod::FdrTrustMaterial,
    expected: &super::plan::FdrTrustDigest,
) -> Result<(), String> {
    if material.digest() != expected.digest {
        return Err(format!(
            "fdr-material-digest-mismatch: reloaded={} bridged={}",
            hex_digest(&material.digest()),
            expected.hex()
        ));
    }
    if material.trust_object() != expected.trust_object.as_slice() {
        return Err("fdr-material-trust-object-mismatch: reloaded bytes differ from the bridged trust object".to_string());
    }
    Ok(())
}

fn stand_up_seal_server(
    plan: &RestorePlan,
    boot: &RestoreBootContext,
    hardware: &DeviceHardwareInfo,
    port: u16,
    armed_at_secs: f64,
    reporter: &SharedReporter,
) -> Result<Option<Arc<SealServer>>, String> {
    if !boot.vm_local_signing_enabled {
        report(
            reporter,
            "service-disabled",
            &format!(
                "{FDR_SEAL_PREFIX} result=service-disabled port={port} at={armed_at_secs:.3}s meaning=\"VM local signing disabled by the operator\""
            ),
        );
        return Ok(None);
    }
    let Some(directory) = plan.fdr_material_dir.as_ref() else {
        let line = format!(
            "{FDR_SEAL_PREFIX} result=service-unarmed port={port} at={armed_at_secs:.3}s material=none meaning=\"no local FDR service was armed; restore options retain the recovery image's service endpoints\" detail=\"no --fdr-material-dir was given, so there is nowhere to load or generate the FDR trust material from\"",
        );
        report(reporter, "service-unarmed", &line);
        if plan.fdr_trust_digest.is_some() {
            return Err("fdr-material-directory-missing: a bridged trust object requires its configured material directory".to_string());
        }
        return Ok(None);
    };
    let outcome = (|| {
        let (material, instance) = if let Some(expected) = &plan.fdr_trust_digest {
            let material = reload_fdr_trust_material(directory)?;
            validate_fdr_material_binding(&material, expected)?;
            let instance = expected.instance.clone().ok_or_else(|| {
                "fdr-instance-missing: bridged trust material has no device instance identifier"
                    .to_string()
            })?;
            (material, instance)
        } else {
            let identity = hardware.identity().map_err(|error| {
                format!("fdr-instance-unresolved: device hardware identity: {error}")
            })?;
            let material = crate::ramrod::FdrTrustMaterial::load_or_generate_portable(
                directory,
                FDR_TRUST_NOT_BEFORE,
                FDR_TRUST_NOT_AFTER,
            )
            .map_err(|error| {
                format!("fdr-material-unavailable: {}: {error}", directory.display())
            })?;
            (
                material,
                instance_identifier(identity.chip_id, identity.ecid),
            )
        };
        let signer: Arc<dyn FdrManifestSigner> = if boot.remote_digest_signing {
            let expected = boot.sep_public_key.ok_or_else(|| {
                String::from(
                    "the restore context requires remote MANB signing but named no SEP public key",
                )
            })?;
            let signer = boot.manifest_signer.clone().ok_or_else(|| {
                String::from(
                    "the restore context requires remote MANB signing but no remote signer was supplied",
                )
            })?;
            if signer.public_key() != expected {
                return Err(format!(
                    "the supplied remote MANB signer advertises {} but the restore context requires {}",
                    hex_digest(&signer.public_key()),
                    hex_digest(&expected)
                ));
            }
            signer
        } else if let Some(signer) = boot.manifest_signer.clone() {
            signer
        } else if let Some(key) = boot.local_test_signing_key {
            let source = if boot.sep_public_key == Some(key.public_uncompressed()) {
                SIGNING_KEY_SOURCE_SEP
            } else {
                SIGNING_KEY_SOURCE_LEAF_SEED
            };
            Arc::new(LocalFdrManifestSigner::new(key, source))
        } else {
            return Err(String::from(
                "no FDR MANB signer was supplied, so the offline sealing server cannot author manifests",
            ));
        };
        let server = SealServer::new(
            &material,
            directory,
            &instance,
            signer,
            FDR_TRUST_NOT_BEFORE,
            FDR_TRUST_NOT_AFTER,
            port,
            armed_at_secs,
            reporter,
        )
        .map_err(|error| error.to_string())?;
        Ok::<_, String>((server, instance))
    })();

    match outcome {
        Ok((server, instance)) => {
            let line = format!(
                "{FDR_SEAL_PREFIX} result=service-armed port={port} at={armed_at_secs:.3}s url={} instance={} leaf_bytes={} material={} trust_binding={} meaning=\"the local FDR certificate and sealing service is standing behind the reverse proxy, and the restore options route guest FDR requests to this service; the selected directory persists its signing authority and data records for this device\"",
                service_base_url(),
                instance,
                server.leaf_certificate().len(),
                directory.display(),
                if plan.fdr_trust_digest.is_some() {
                    "bridged"
                } else {
                    "stock-ticket"
                }
            );
            report(reporter, "service-armed", &line);
            let published = boot
                .sep_public_key
                .map_or_else(|| String::from("none"), |key| hex_digest(&key));
            let signing = hex_digest(&server.signing_public_key());
            let keys_match = if boot.sep_public_key.is_some() && signing == published {
                "yes"
            } else {
                "no"
            };
            let line = format!(
                "{FDR_SEAL_PREFIX} result=signing-key-bound port={port} at={armed_at_secs:.3}s source={} signing_key={signing} sep_published_key={published} keys_match={keys_match} meaning=\"this is the key every sealing manifest served during this run is signed with, and the device's Secure Enclave publishes the verification key through oskgp. keys_match=yes means they are one key and the guest's ECDSA verification is against the attached signer; keys_match=no means the manifest cannot verify no matter how well formed it is, because the guest verifies with the key its key store published and not with the certificate the restore service supplied\" detail=\"the guest fetches the verification key at signing version 2 through _AMFDRCryptoGetSikPub, called at 0xec14 in the restore ramdisk's libFDR.dylib, which reaches _AMFDRDeviceCopySikPub and _aks_system_key_get_public at 0x1c04, the AppleKeyStore path answered from the device's SEP key store. The point arrives raw, with no certificate and no chain, and goes straight into AMSupportEcDsaVerifySignature by way of _AMFDRDecodeEcdsaVerifySignature at 0x67e28. source={} means the key was taken from the live SEP device rather than derived a second time; source={} means no SEP key store was available, and then no key held by the service can satisfy that verification\"",
                server.signing_key_source(),
                SIGNING_KEY_SOURCE_SEP,
                SIGNING_KEY_SOURCE_LEAF_SEED
            );
            report(reporter, "signing-key-bound", &line);
            Ok(Some(Arc::new(server)))
        }
        Err(error) => {
            let line = format!(
                "{FDR_SEAL_PREFIX} result=service-unarmed port={port} at={armed_at_secs:.3}s material={} meaning=\"no local FDR service was armed; restore options retain the recovery image's service endpoints\" detail=\"{error}\"",
                directory.display()
            );
            report(reporter, "service-unarmed", &line);
            Err(format!("fdr-seal-preparation-failed: {error}"))
        }
    }
}

fn establish_host_thread_class(port: u16, armed_at_secs: f64, reporter: &SharedReporter) {
    let inherited = super::thread_class::current_thread_class();
    let (effective, corrected) = if inherited.competes_with_vcpu() {
        (set_current_thread_class(ThreadClass::Utility), true)
    } else {
        (inherited, false)
    };
    let topology = crate::topology::host_topology();
    let line = format!(
        "{MUX_PREFIX} result=host-thread-class port={port} at={armed_at_secs:.3}s inherited={inherited} effective={effective} corrected={corrected} vcpu_class=user-interactive competes_with_vcpu={} meaning=\"host CPU usage must never affect guest stability, so the class of the thread that owns this restore is read back off the thread and stated before it does any work; guest vCPU threads are raised to user-interactive when they are created, and this thread is the parent of the reverse proxy, the sealing server and every bulk transfer thread, all of which inherit its class, so one readback covers all of them; no means no thread this restore owns can take a performance core from a running vCPU, and a yes here is corrected to utility rather than only reported\" detail=\"logical_cpus={} performance_cpus={} efficiency_cpus={} topology={}; bulk payload reads are scoped lower still and report their own class on the splat-verify-cost line\"",
        if effective.competes_with_vcpu() {
            "yes"
        } else {
            "no"
        },
        topology.logical_cpus,
        topology.performance_cpus,
        topology.efficiency_cpus,
        if topology.measured {
            "measured"
        } else {
            "fallback"
        }
    );
    report(reporter, "host-thread-class", &line);
}

fn preflight_restore_manifest(
    plan: &RestorePlan,
    port: u16,
    armed_at_secs: f64,
    reporter: &SharedReporter,
) -> Result<(), RestoreOutcome> {
    let manifest_source = match resolve_restore_manifest(plan) {
        Ok(source) => source,
        Err(reason) => {
            let line = format!(
                "{MUX_PREFIX} result=no-restore-manifest port={port} at={armed_at_secs:.3}s meaning=\"no BuildManifest could be resolved, so no build identity can be chosen and no restore options can be derived; no device connection was attempted\" detail=\"{reason}\""
            );
            report(reporter, "no-restore-manifest", &line);
            return Err(RestoreOutcome::Failed {
                stage: "no-restore-manifest".to_string(),
                reason,
            });
        }
    };

    if let Err(error) = load_build_manifest(manifest_source.path()) {
        let reason = error.to_string();
        let line = format!(
            "{MUX_PREFIX} result=restore-manifest-unusable port={port} at={armed_at_secs:.3}s meaning=\"the BuildManifest was found but could not be parsed as a dictionary, so no device connection was attempted\" detail=\"{reason}\""
        );
        report(reporter, "restore-manifest-unusable", &line);
        return Err(RestoreOutcome::Failed {
            stage: "restore-manifest-unusable".to_string(),
            reason,
        });
    }

    Ok(())
}

fn initial_restore_images(plan: &RestorePlan, is_macos: bool) -> crate::ramrod::ImageSources {
    if is_macos {
        crate::ramrod::ImageSources::with_default(&plan.image)
    } else {
        crate::ramrod::ImageSources::default()
            .and_type(&crate::ramrod::DataType::SystemImageData, &plan.image)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_ramrod_restore_over_mux<T: BulkTransport + Send + 'static>(
    claimed: ClaimedMuxTransport<T>,
    boot: RestoreBootContext,
    plan: &RestorePlan,
    config: AsrServerConfig,
    image_size: u64,
    armed_at_secs: f64,
    stop: Arc<AtomicBool>,
    reporter: SharedReporter,
) -> RestoreOutcome {
    let port = plan.port;
    let began = Instant::now();
    let ap_nonce = boot.ap_nonce;
    crate::restore::report::rotate_mux_log();
    if let Some(reason) = &boot.metadata_unavailable {
        report(
            &reporter,
            "restore-metadata-unavailable",
            &format!(
                "{MUX_PREFIX} result=restore-metadata-unavailable port={port} detail=\"{reason}\" meaning=\"frozen boot metadata is unavailable; nonce, staged digest and VM signer have no supplied source\""
            ),
        );
    }
    if let Err(outcome) = preflight_restore_manifest(plan, port, armed_at_secs, &reporter) {
        return outcome;
    }
    establish_host_thread_class(port, armed_at_secs, &reporter);
    let claimed = match bring_up_mux(claimed, plan, armed_at_secs, &stop, &reporter) {
        Ok(up) => up,
        Err((stage, reason)) => {
            return RestoreOutcome::Failed {
                stage: stage.to_string(),
                reason,
            };
        }
    };
    let transfer_cancel = Arc::new(AtomicBool::new(false));
    let mut dialer = claimed
        .dialer()
        .clone()
        .with_transfer_cancel(Arc::clone(&transfer_cancel));
    let dial_plan = DialPlan::default().on_port(port).with_window(plan.window);
    let request_global_manifest = plan.global_manifests.is_some();
    let (identified, mut prepared) = match query_and_prepare_restore_session(
        &mut dialer,
        dial_plan,
        &mut SystemClock,
        plan,
        request_global_manifest,
    ) {
        Ok(identified) => identified,
        Err(RestorePhaseError::Identify(error)) => {
            let stage = match &error {
                crate::ramrod::RamrodError::Dial(_) => "identify-no-session",
                crate::ramrod::RamrodError::ClosedBeforeReply { .. } => "identify-closed",
                crate::ramrod::RamrodError::NotRestored { .. } => "identify-not-restored",
                _ => "identify-failed",
            };
            let line = format!(
                "{MUX_PREFIX} result={stage} port={port} at={armed_at_secs:.3}s elapsed={:.3}s meaning=\"the ramrod identify exchange did not complete; the host speaks first on this port and this is the first thing it says\" detail=\"{error}\"",
                began.elapsed().as_secs_f64()
            );
            report(&reporter, stage, &line);
            return RestoreOutcome::Failed {
                stage: stage.to_string(),
                reason: error.to_string(),
            };
        }
        Err(RestorePhaseError::Prepare(RestorePreparationError::ManifestResolution(reason))) => {
            let line = format!(
                "{MUX_PREFIX} result=no-restore-manifest port={port} at={armed_at_secs:.3}s meaning=\"no BuildManifest could be resolved, so no build identity can be chosen and no restore options can be derived; the restore is not started\" detail=\"{reason}\""
            );
            report(&reporter, "no-restore-manifest", &line);
            return RestoreOutcome::Failed {
                stage: "no-restore-manifest".to_string(),
                reason,
            };
        }
        Err(RestorePhaseError::Prepare(RestorePreparationError::ManifestLoad(error))) => {
            let line = format!(
                "{MUX_PREFIX} result=restore-manifest-unusable port={port} at={armed_at_secs:.3}s meaning=\"the BuildManifest was found but could not be turned into a dictionary; the restore is not started\" detail=\"{error}\""
            );
            report(&reporter, "restore-manifest-unusable", &line);
            return RestoreOutcome::Failed {
                stage: "restore-manifest-unusable".to_string(),
                reason: error,
            };
        }
        Err(RestorePhaseError::Prepare(RestorePreparationError::RestoreOptions(error))) => {
            let detail = error.detail();
            let line = format!(
                "{MUX_PREFIX} result={} port={port} at={armed_at_secs:.3}s elapsed={:.3}s meaning=\"{}\" detail=\"{}\"",
                error.label(),
                began.elapsed().as_secs_f64(),
                error.meaning(),
                detail
            );
            report(&reporter, error.label(), &line);
            return RestoreOutcome::Failed {
                stage: error.label().to_string(),
                reason: detail,
            };
        }
        Err(other) => {
            let line = format!(
                "{MUX_PREFIX} result=prepare-restore-failed port={port} at={armed_at_secs:.3}s elapsed={:.3}s meaning=\"restore preparation failed before StartRestore; the detail names the phase and nothing was sent to the guest\" detail=\"{other}\"",
                began.elapsed().as_secs_f64()
            );
            report(&reporter, "prepare-restore-failed", &line);
            return RestoreOutcome::Failed {
                stage: "prepare-restore-failed".to_string(),
                reason: other.to_string(),
            };
        }
    };
    let output_dialer = dialer.clone();
    let bulk_dialer = dialer.clone();
    let bundle_dialer = dialer.clone();
    let http_dialer = dialer.clone();
    let mut client = identified.client;
    let device = identified.device;
    let line = format!(
        "{MUX_PREFIX} result=identify-answered port={port} at={armed_at_secs:.3}s elapsed={:.3}s device={device:?} meaning=\"restored answered QueryType, so this really is the ramrod command channel\" detail=\"\"",
        began.elapsed().as_secs_f64()
    );
    report(&reporter, "identify-answered", &line);
    let device_hardware_info = query_device_hardware_info(
        &mut client,
        port,
        armed_at_secs,
        began.elapsed().as_secs_f64(),
        &reporter,
    );
    let sep_nonce = if !prepared.derived.is_macos {
        let answered = query_device_sep_nonce(&mut client, port, armed_at_secs, &reporter);
        if answered.is_none() && boot.sep_nonce.is_some() {
            report(
                &reporter,
                "sep-nonce-bridge",
                &format!(
                    "{MUX_PREFIX} result=sep-nonce-bridge port={port} at={armed_at_secs:.3}s bytes=20 meaning=\"restored did not answer SEPNonce; the bridge supplied the nonce generated by this guest's SEP ROM\""
                ),
            );
        }
        answered.or(boot.sep_nonce)
    } else {
        None
    };
    let line = format!(
        "{MUX_PREFIX} result=restore-manifest-loaded port={port} at={armed_at_secs:.3}s source={} identities={} meaning=\"the BuildManifest the restore options are derived from was read\" detail=\"path={}\"",
        prepared.manifest_source.label(),
        manifest_identity_count(&prepared.manifest),
        prepared.manifest_path.display()
    );
    report(&reporter, "restore-manifest-loaded", &line);
    let missing_assets = prepared
        .missing_required_assets()
        .into_iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    let line = format!(
        "{MUX_PREFIX} result=restore-assets-prepared port={port} at={armed_at_secs:.3}s elapsed={:.3}s required_assets={} missing_assets={} meaning=\"AppleUtils resolved the selected identity and enumerated the concrete restore assets before StartRestore, so any host side omission is visible before the guest is switched into restore\" detail=\"missing=[{}]\"",
        began.elapsed().as_secs_f64(),
        prepared
            .assets
            .iter()
            .filter(|asset| asset.required)
            .count(),
        missing_assets.len(),
        missing_assets.join(", ")
    );
    report(&reporter, "restore-assets-prepared", &line);
    let seal = match stand_up_seal_server(
        plan,
        &boot,
        &device_hardware_info,
        port,
        armed_at_secs,
        &reporter,
    ) {
        Ok(seal) => seal,
        Err(reason) => {
            report(
                &reporter,
                "fdr-seal-preparation-failed",
                &format!(
                    "{MUX_PREFIX} result=fdr-seal-preparation-failed port={port} at={armed_at_secs:.3}s detail={reason:?}"
                ),
            );
            return RestoreOutcome::Failed {
                stage: "fdr-seal-preparation-failed".to_string(),
                reason,
            };
        }
    };
    if seal.is_some() {
        prepared.derived = prepared.derived.with_local_fdr_service();
    } else {
        report(
            &reporter,
            "fdr-service-routing",
            &format!(
                "{FDR_SEAL_PREFIX} result=fdr-service-routing port={port} at={armed_at_secs:.3}s route=recovery-defaults meaning=\"the recovery image selects its FDR endpoints; no local service was armed\""
            ),
        );
    }
    apply_skip_tcon_firmware(&mut prepared.derived, boot.skip_tcon_firmware);
    let derived = prepared.derived.clone();
    let manifest = prepared.manifest.clone();
    let line = format!(
        "{MUX_PREFIX} result=identity-selected port={port} at={armed_at_secs:.3}s elapsed={:.3}s model={} behavior={} meaning=\"the build identities the restore options are derived from were chosen out of the manifest\" detail=\"install=#{} [{}] recovery={} [{}]\"",
        began.elapsed().as_secs_f64(),
        prepared.identity.hardware_model,
        derived.behavior,
        prepared.identity.install_index,
        prepared.identity.install_variant,
        prepared
            .identity
            .recovery_index
            .map_or_else(|| "undeclared".to_string(), |index| format!("#{index}")),
        prepared
            .identity
            .recovery_variant
            .as_deref()
            .unwrap_or("undeclared")
    );
    report(&reporter, "identity-selected", &line);
    let line = format!(
        "{MUX_PREFIX} result=restore-options-built port={port} at={armed_at_secs:.3}s elapsed={:.3}s uuid={} protocol_version={} meaning=\"the StartRestore options were derived from the manifest; sent lists every key on the wire, omitted names a key whose manifest source was absent, and withheld names a key deliberately not sent with the reason\" detail=\"{}\"",
        began.elapsed().as_secs_f64(),
        derived.session_uuid,
        match client.device_protocol_version() {
            Some(version) => version.to_string(),
            None => "none".to_string(),
        },
        derived.report
    );
    report(&reporter, "restore-options-built", &line);
    if !derived.is_macos {
        let line = format!(
            "{MUX_PREFIX} result=ticket-branch-armed port={port} at={armed_at_secs:.3}s elapsed={:.3}s branch=personalized-ap-preflight corrupt={} meaning=\"install and recovery AP tickets are requested from the signing server with this boot's nonce and the device's reported identity before StartRestore; root ticket requests use the corresponding signed response\" detail=\"\"",
            began.elapsed().as_secs_f64(),
            plan.corrupt_manifest
        );
        report(&reporter, "ticket-branch-armed", &line);
    } else if request_global_manifest {
        let line = format!(
            "{MUX_PREFIX} result=ticket-branch-armed port={port} at={armed_at_secs:.3}s elapsed={:.3}s branch=personalized-with-global-answers corrupt={} meaning=\"a global manifest source was given, so every ticket request is answered from the genuine board manifest; the guest's chooser at 0x10003b8d0 still logs 'Using personalized manifest' and that is expected, because copy_restore_options filters StartRestore through a 28 key whitelist that SelectMediumSecurityBootPolicy is not on and the key never reaches the chooser; the branch does not decide whether the ticket is accepted, the SHA-384 comparison against /chosen/boot-manifest-hash does\" detail=\"manifests={}\"",
            began.elapsed().as_secs_f64(),
            plan.corrupt_manifest,
            plan.global_manifests
                .as_ref()
                .map_or_else(|| "none".to_string(), |root| root.display().to_string())
        );
        report(&reporter, "ticket-branch-armed", &line);
    } else {
        let line = format!(
            "{MUX_PREFIX} result=ticket-branch-armed port={port} at={armed_at_secs:.3}s elapsed={:.3}s branch=personalized corrupt=false meaning=\"no global manifest source was given, so the guest stays on the personalized branch and any ticket request is reported by name rather than answered\" detail=\"\"",
            began.elapsed().as_secs_f64()
        );
        report(&reporter, "ticket-branch-armed", &line);
    }

    let personalized_tickets = if derived.is_macos {
        None
    } else {
        match prepare_mobile_ap_tickets(
            &manifest,
            &derived,
            &device_hardware_info,
            ap_nonce.as_ref(),
            sep_nonce.as_ref(),
            &CurlSigningTransport::default(),
            plan.fdr_trust_digest
                .as_ref()
                .map(|resolved| &resolved.digest),
            port,
            armed_at_secs,
            &reporter,
        ) {
            Ok(tickets) => Some(tickets),
            Err(reason) => {
                report(
                    &reporter,
                    "ap-ticket-preparation-failed",
                    &format!(
                        "{MUX_PREFIX} result=ap-ticket-preparation-failed port={port} at={armed_at_secs:.3}s detail={reason:?}"
                    ),
                );
                return RestoreOutcome::Failed {
                    stage: "ap-ticket-preparation-failed".to_string(),
                    reason,
                };
            }
        }
    };

    let stock_fdr_trust = if !derived.is_macos && plan.fdr_trust_digest.is_none() {
        let prepared = personalized_tickets
            .as_ref()
            .expect("mobile AP tickets prepared");
        let Some(ramdisk_path) = plan.restore_ramdisk.as_ref() else {
            return RestoreOutcome::Failed {
                stage: "stock-fdr-ramdisk-missing".to_string(),
                reason:
                    "RestoreRamDisk.Info.Path was not resolved from the selected build identity"
                        .to_string(),
            };
        };
        let result = std::fs::read(ramdisk_path)
            .map_err(|error| {
                format!(
                    "stock-fdr-ramdisk-unreadable: {}: {error}",
                    ramdisk_path.display()
                )
            })
            .and_then(|bytes| {
                super::plan::stock_fdr_trust_from_ramdisk_and_ticket(&bytes, &prepared.os_ticket)
            });
        match result {
            Ok(trust) => {
                report(
                    &reporter,
                    "stock-fdr-trust-selected",
                    &format!(
                        "{MUX_PREFIX} result=stock-fdr-trust-selected port={port} at={armed_at_secs:.3}s element={} of {} object_bytes={} sha256={} meaning=\"the restore ramdisk element whose SHA-256 matches the Apple signed OS AP ticket rfta was selected for FDRTrustData; the signed ticket remains unchanged\" detail=\"ramdisk={}\"",
                        trust.element_index,
                        trust.element_count,
                        trust.trust_object.len(),
                        trust.hex(),
                        ramdisk_path.display()
                    ),
                );
                Some(trust)
            }
            Err(reason) => {
                report(
                    &reporter,
                    "stock-fdr-trust-unresolved",
                    &format!(
                        "{MUX_PREFIX} result=stock-fdr-trust-unresolved port={port} at={armed_at_secs:.3}s detail={reason:?}"
                    ),
                );
                return RestoreOutcome::Failed {
                    stage: "stock-fdr-trust-unresolved".to_string(),
                    reason,
                };
            }
        }
    } else {
        None
    };

    match start_prepared_restore(&mut client, prepared) {
        Ok(()) => {}
        Err(RestorePhaseError::MissingRequiredAssets { missing }) => {
            let detail = missing
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let line = format!(
                "{MUX_PREFIX} result=restore-assets-missing port={port} at={armed_at_secs:.3}s elapsed={:.3}s meaning=\"StartRestore was withheld because the selected identity needs concrete files the host does not hold, and AppleUtils does not guess substitutes for them\" detail=\"{detail}\"",
                began.elapsed().as_secs_f64()
            );
            report(&reporter, "restore-assets-missing", &line);
            return RestoreOutcome::Failed {
                stage: "restore-assets-missing".to_string(),
                reason: detail,
            };
        }
        Err(RestorePhaseError::Start(error)) => {
            let line = format!(
                "{MUX_PREFIX} result=start-restore-failed port={port} at={armed_at_secs:.3}s elapsed={:.3}s meaning=\"StartRestore could not be sent; it is refused outright unless SupportedHostProtocols carries MuxSocket\" detail=\"{error}\"",
                began.elapsed().as_secs_f64()
            );
            report(&reporter, "start-restore-failed", &line);
            return RestoreOutcome::Failed {
                stage: "start-restore-failed".to_string(),
                reason: error.to_string(),
            };
        }
        Err(other) => {
            let line = format!(
                "{MUX_PREFIX} result=start-restore-failed port={port} at={armed_at_secs:.3}s elapsed={:.3}s meaning=\"StartRestore was not sent because the prepared session did not satisfy the restore start contract\" detail=\"{other}\"",
                began.elapsed().as_secs_f64()
            );
            report(&reporter, "start-restore-failed", &line);
            return RestoreOutcome::Failed {
                stage: "start-restore-failed".to_string(),
                reason: other.to_string(),
            };
        }
    }
    let line = format!(
        "{MUX_PREFIX} result=start-restore-sent port={port} at={armed_at_secs:.3}s elapsed={:.3}s meaning=\"StartRestore is away; the guest sends no acknowledgement for it, so the next line is whatever the guest asks for first\" detail=\"\"",
        began.elapsed().as_secs_f64()
    );
    report(&reporter, "start-restore-sent", &line);

    let progress = PayloadProgress::new(image_size, Arc::clone(&stop), Arc::clone(&reporter))
        .on_session_clock(began)
        .with_transfer_cancel(Arc::clone(&transfer_cancel));
    let mut images = initial_restore_images(plan, derived.is_macos);
    let mut armed_image_files: Vec<PathBuf> = vec![plan.image.clone()];
    for (data_type, named) in [
        (
            crate::ramrod::DataType::SystemImageData,
            plan.system_image.as_ref(),
        ),
        (
            crate::ramrod::DataType::RecoveryOSASRImage,
            plan.recovery_image.as_ref(),
        ),
    ] {
        if let Some(path) = named {
            images = images.and_type(&data_type, path);
            if !armed_image_files.iter().any(|armed| armed == path) {
                armed_image_files.push(path.clone());
            }
        }
    }
    let image_root = plan
        .image_root
        .clone()
        .or_else(|| plan.image.parent().map(std::path::Path::to_path_buf));
    if let Some(root) = &image_root {
        for data_type in crate::ramrod::bulk_image_types() {
            if images.names(&data_type) {
                continue;
            }
            let Some(entry) = crate::ramrod::bulk_image_entry(&data_type) else {
                continue;
            };
            let identity = if matches!(data_type, crate::ramrod::DataType::RecoveryOSASRImage)
                && !derived.is_macos
            {
                derived.recovery_identity.as_ref()
            } else {
                Some(&derived.install_identity)
            };
            let Some(identity) = identity else {
                report(
                    &reporter,
                    "bulk-image-unresolved",
                    &format!(
                        "{MUX_PREFIX} result=bulk-image-unresolved type={data_type} detail=\"install identity declares no recovery variant\""
                    ),
                );
                continue;
            };
            match crate::ramrod::resolve_bulk_image(&entry, identity, root) {
                Ok(resolved) => {
                    let line = format!(
                        "{MUX_PREFIX} result=bulk-image-resolved port={port} at={armed_at_secs:.3}s type={data_type} entry={} rule={} identity=#{} meaning=\"the BuildManifest component this request type maps to was found on disk, so the transfer streams the file the manifest names rather than whichever image the run happened to be given\" detail=\"manifest_path={} path={} root={}\"",
                        resolved.entry,
                        resolved.rule.label(),
                        resolved.identity_index,
                        resolved.manifest_path,
                        resolved.path.display(),
                        root.display()
                    );
                    report(&reporter, "bulk-image-resolved", &line);
                    if !armed_image_files
                        .iter()
                        .any(|armed| armed == &resolved.path)
                    {
                        armed_image_files.push(resolved.path.clone());
                    }
                    images = images.and_origin(
                        &data_type,
                        &resolved.path,
                        crate::ramrod::ImageOrigin::Manifest {
                            entry: resolved.entry.to_string(),
                            manifest_path: resolved.manifest_path.clone(),
                            rule: resolved.rule.label(),
                        },
                    );
                }
                Err(error) => {
                    let line = format!(
                        "{MUX_PREFIX} result=bulk-image-unresolved port={port} at={armed_at_secs:.3}s type={data_type} entry={} meaning=\"the BuildManifest component this request type maps to could not be found under the image root, so this type falls back to whatever else answers it; a type that takes no fallback will be declined by name when the guest asks and the session will carry on\" detail=\"fallback={} root={}: {error}\"",
                        entry.entry,
                        if entry.allows_default {
                            "the run's --asr-serve-image"
                        } else {
                            "none"
                        },
                        root.display()
                    );
                    report(&reporter, "bulk-image-unresolved", &line);
                }
            }
        }
    }
    let line = format!(
        "{MUX_PREFIX} result=bulk-images-armed port={port} at={armed_at_secs:.3}s system_image={} recovery_image={} meaning=\"which file answers which bulk DataType; a per-type file a run named wins over the manifest resolution, and the manifest resolution wins over the single default image, which answers only the types that permit one\" detail=\"default={} image_root={} system_image={} recovery_image={}\"",
        if plan.system_image.is_some() { "armed" } else { "absent" },
        if plan.recovery_image.is_some() { "armed" } else { "absent" },
        plan.image.display(),
        image_root
            .as_ref()
            .map_or_else(|| "none".to_string(), |root| root.display().to_string()),
        plan.system_image
            .as_ref()
            .map_or_else(|| "none: a SystemImageData request is answered from the manifest resolution or declined by name, never from the default".to_string(), |path| path.display().to_string()),
        plan.recovery_image
            .as_ref()
            .map_or_else(|| "none: a RecoveryOSASRImage request is answered from the manifest resolution, or from the default when that found nothing".to_string(), |path| path.display().to_string())
    );
    report(&reporter, "bulk-images-armed", &line);
    for image in &armed_image_files {
        report_armed_image_seal(&reporter, port, armed_at_secs, image);
    }
    let asr_bulk = AsrBulkTransfer::new(bulk_dialer, images, config, progress)
        .with_transfer_started(PayloadProgress::start_watchdog)
        .with_window(plan.window)
        .with_retry(plan.timeout, plan.retry);
    // Resolved now, not when the guest asks: that request arrives with the guest already blocked in `accept`.
    let bundle_roots: Vec<PathBuf> = [
        plan.bootability_bundle.clone(),
        plan.image_root.clone(),
        plan.image.parent().map(Path::to_path_buf),
        plan.firmware_root.clone(),
        plan.manifest
            .as_deref()
            .and_then(Path::parent)
            .map(Path::to_path_buf),
    ]
    .into_iter()
    .flatten()
    .collect();
    let bundle_source = match BootabilityBundleSource::discover(bundle_roots) {
        Ok(source) => {
            let members = source.members().unwrap_or_default();
            let line = format!(
                "{MUX_PREFIX} result=bootability-bundle-armed port={port} at={armed_at_secs:.3}s members={} meaning=\"the guest asks for this one inside preserve_source_boot_objects on a port it opens itself, and it is the only data type answered on neither the control connection nor an ASR session; this host connects in and pushes an uncompressed portable cpio archive, which is what the guest's extractor accepts once it has disabled libarchive for this type\" detail=\"root={} content={} trust_cache={}\"",
                members.len(),
                source.root().display(),
                source.content().display(),
                source.trust_cache().display()
            );
            report(&reporter, "bootability-bundle-armed", &line);
            Some(source)
        }
        Err(rejected) => {
            use std::fmt::Write as _;
            let mut searched = String::new();
            for (index, step) in rejected.iter().enumerate() {
                if index > 0 {
                    searched.push_str("; ");
                }
                let _ = write!(searched, "{}: {}", step.candidate.display(), step.error);
            }
            if searched.is_empty() {
                searched.push_str("nothing: this run named no image, no image root, no firmware root and no manifest");
            }
            let line = format!(
                "{MUX_PREFIX} result=bootability-bundle-unresolved port={port} at={armed_at_secs:.3}s candidates={} meaning=\"no bootability bundle was found under any root this run was given, so a BootabilityBundle request will be declined by name; the port the guest opens for it is still dialled and closed with no bytes on it, which is what lets the guest fail preserve_source_boot_objects on its own terms rather than wait in accept\" detail=\"{searched}\"",
                rejected.len()
            );
            report(&reporter, "bootability-bundle-unresolved", &line);
            None
        }
    };
    let bundle_bulk = BootabilityBundleTransfer::new(bundle_dialer, bundle_source)
        .with_window(plan.window)
        .with_retry(plan.timeout, plan.retry);
    // Routed on the wire type: the ASR service answers a client that speaks first, the bundle service pushes at a guest that says nothing, so crossing them leaves both sides waiting.
    let http_bulk =
        HttpAssetTransfer::new(http_dialer, Arc::clone(&stop), Arc::clone(&transfer_cancel))
            .with_window(plan.window)
            .with_retry(plan.timeout, plan.retry);
    let updater_output = crate::ramrod::UpdaterOutputTransfer::new(
        output_dialer,
        client.crash_log_directory().to_path_buf(),
    )
    .with_window(plan.window)
    .with_retry(plan.timeout, plan.retry)
    .with_cancellation(Arc::clone(&stop), Arc::clone(&transfer_cancel));
    let asr_bulk = crate::ramrod::UpdaterOutputRouter::new(updater_output, asr_bulk);
    let mut bulk = HttpAssetRouter::new(http_bulk, BootabilityRouter::new(bundle_bulk, asr_bulk));
    let ticket_root = plan
        .global_manifests
        .clone()
        .or_else(|| {
            plan.firmware_root.as_ref().map(|root| {
                let nested = root.join("Firmware/Manifests/restore");
                if nested.is_dir() {
                    nested
                } else {
                    root.clone()
                }
            })
        })
        .or_else(|| {
            personalized_tickets
                .as_ref()
                .map(|tickets| tickets.path().to_path_buf())
        });
    let provider: Box<dyn RestoreDataProvider> = match ticket_root {
        Some(root) => {
            // `AuthInstallVariant` is the identity being installed and `AuthInstallRecoveryOSVariant` the recovery OS; they are not interchangeable.
            let variants = RestoreVariants {
                install: derived.install_variant.clone(),
                recovery_os: derived.recovery_variant.clone(),
            };
            let tickets = GlobalManifestProvider::new(
                root.clone(),
                variants.clone(),
                derived.hardware_model.clone(),
                plan.corrupt_manifest,
                port,
                armed_at_secs,
                plan.staged_boot_manifest_sha384,
                plan.fdr_trust_digest.clone(),
                ap_nonce,
                &reporter,
            )
            .with_staged_boot_manifest(plan.staged_boot_manifest.clone());
            let tickets = if let Some(cache) = personalized_tickets.as_ref() {
                tickets.with_personalized_source(cache.path().to_path_buf())
            } else {
                tickets
            };
            let cryptex_ticket = tickets.cryptex1_ticket_bytes();
            // Prepared before start: the guest sends one NORData request and gets no second chance.
            let board_manifest = plan.firmware_root.as_ref().and_then(|_| {
                board_manifest_for_firmware(
                    personalized_tickets
                        .as_ref()
                        .map(|tickets| tickets.path())
                        .unwrap_or(root.as_path()),
                    &variants,
                    &derived.hardware_model,
                    plan.staged_boot_manifest.as_deref(),
                    plan.staged_boot_manifest_sha384,
                    plan.corrupt_manifest,
                    port,
                    armed_at_secs,
                    &reporter,
                )
            });
            // A missing board IM4M is refused rather than answered with a bare IM4P: AMAuthInstallApImg4DecodeRestoreInfo refuses one outright with error 99.
            let firmware = plan.firmware_root.as_ref().map(|firmware_root| {
                let (manifest_source, manifest_bytes) = match board_manifest.as_ref() {
                    Some(manifest) => (manifest.source.clone(), manifest.bytes.as_slice()),
                    None => ("unavailable".to_string(), &[][..]),
                };
                NorFirmwareProvider::prepare(
                    &derived.install_identity,
                    firmware_root.clone(),
                    manifest_source,
                    manifest_bytes,
                    port,
                    armed_at_secs,
                    &reporter,
                )
            });
            // A member advertised and then not delivered is fatal at `install_splat`, while one never advertised is skipped.
            let splat = resolve_splat_components(
                &manifest,
                &derived.hardware_model,
                if derived.is_macos {
                    derived
                        .recovery_variant
                        .as_deref()
                        .expect("macOS recovery variant")
                } else {
                    &derived.install_variant
                },
                cryptex_ticket.as_deref(),
                plan.firmware_root.as_ref(),
                image_root.as_ref(),
                port,
                armed_at_secs,
                &reporter,
            );
            Box::new(RestoreAnswers {
                tickets,
                firmware,
                identities: BuildIdentityProvider::new(
                    manifest.clone(),
                    derived.hardware_model.clone(),
                    derived.install_variant.clone(),
                    derived.recovery_variant.clone(),
                    splat.omitted(),
                    port,
                    armed_at_secs,
                    &reporter,
                ),
                personalized: PersonalizedFirmwareProvider::new(
                    manifest.clone(),
                    derived.hardware_model.clone(),
                    derived.install_variant.clone(),
                    derived.recovery_variant.clone(),
                    plan.firmware_root.clone(),
                    board_manifest
                        .as_ref()
                        .map(|manifest| manifest.bytes.clone()),
                    board_manifest
                        .as_ref()
                        .map(|manifest| manifest.source.clone()),
                    port,
                    armed_at_secs,
                    &reporter,
                ),
                source_boot_objects: SourceBootObjectProvider::new(
                    root.clone(),
                    derived.install_variant.clone(),
                    derived.hardware_model.clone(),
                    manifest.clone(),
                    plan.firmware_root.clone(),
                    image_root.clone(),
                    splat,
                    port,
                    armed_at_secs,
                    &reporter,
                )
                .with_personalized_source(
                    personalized_tickets
                        .as_ref()
                        .map(|tickets| tickets.path().to_path_buf()),
                ),
                fdr: FdrTrustProvider::new(
                    plan.fdr_trust_digest.as_ref().or(stock_fdr_trust.as_ref()),
                    port,
                    armed_at_secs,
                    &reporter,
                ),
                local_policy_signer: local_policy_signer_for_plan(
                    plan,
                    &derived.session_uuid,
                    port,
                    armed_at_secs,
                    &reporter,
                ),
                firmware_updater_signer: firmware_updater_signer_for_plan(
                    plan,
                    &derived.session_uuid,
                    port,
                    armed_at_secs,
                    &reporter,
                ),
                local_policy_census: super::local_policy::LocalPolicyCensus::default(),
                device_hardware_info,
                port,
                armed_at_secs,
                reporter: Arc::clone(&reporter),
            })
        }
        None => Box::new(PreparedAnswers::new()),
    };
    // Dialled here and held for the whole run: PurpleReverseProxy is launchd socket activated and can take longer to listen than libFDR's five second budget, and dropping the ctrl handle makes the daemon answer every later client with "not online".
    let mut proxy = reverse_proxy::spawn(
        dialer.link(),
        Arc::clone(&stop),
        Arc::clone(&reporter),
        armed_at_secs,
        seal,
    );

    let mut provider =
        HttpAssetAnswers::new(provider, Arc::clone(&stop), Arc::clone(&transfer_cancel));

    let mut observer = RamrodTrace::new(port, armed_at_secs, Arc::clone(&reporter));
    let outcome = match client.run_restore_with_cancellation(
        &mut provider,
        &mut bulk,
        &mut observer,
        Arc::clone(&transfer_cancel),
    ) {
        Ok(summary) => {
            let line = format!(
                "{MUX_PREFIX} result=restore-ended port={port} at={armed_at_secs:.3}s elapsed={:.3}s restore_outcome={} meaning=\"the guest stopped asking and closed the control connection\" detail=\"{summary:?}; final_status_acknowledged={}; guest_left_waiting={}; bulk_service_transfers={}; bootability_bundles_pushed={}\"",
                began.elapsed().as_secs_f64(),
                summary
                    .final_status
                    .as_ref()
                    .map_or("none", |status| status.outcome()),
                summary.final_status_acknowledged(),
                summary.guest_left_waiting(),
                bulk.fallback().fallback().fallback().transfers().len(),
                bulk.fallback().bundle().transfers().len()
            );
            report(&reporter, "restore-ended", &line);
            RestoreOutcome::Ended {
                summary: Box::new(summary),
                bulk_transfers: bulk.fallback().fallback().fallback().transfers().len(),
            }
        }
        Err(error) => {
            if is_host_initiated_teardown(&error.to_string()) {
                let line = format!(
                    "{MUX_PREFIX} result=host-timeout-teardown port={port} at={armed_at_secs:.3}s elapsed={:.3}s waiting_for=\"the guest's next message on the session that ended\" meaning=\"the host ended this session on its configured bounded ASR receive, which is the only clock the host ends a session on, and the guest did not fail; the restore-failed line that follows, the detach after it, and every guest-side message from here on including any CHECKPOINT FAILURE are consequences of the host end going away\" detail=\"the control session holds no bound at all and cannot produce this line; remove the ASR read bound or raise it if the guest was merely slow: {error}\"",
                    began.elapsed().as_secs_f64()
                );
                report(&reporter, "host-timeout-teardown", &line);
            } else if is_run_stopped(&error.to_string()) {
                let line = format!(
                    "{MUX_PREFIX} result=run-stopped-teardown port={port} at={armed_at_secs:.3}s elapsed={:.3}s meaning=\"the run was stopped, by an interrupt or a duration cap, while a session was waiting on the guest; the host stopped reading and the guest neither failed nor went away\" detail=\"nothing here is evidence about the restore: give the run longer if it was still making progress: {error}\"",
                    began.elapsed().as_secs_f64()
                );
                report(&reporter, "run-stopped-teardown", &line);
            } else if is_device_gone(&error.to_string()) {
                let line = format!(
                    "{MUX_PREFIX} result=guest-left-the-bus port={port} at={armed_at_secs:.3}s elapsed={:.3}s meaning=\"the guest's device-mode controller stopped being configured while a session was open, so the device went off the bus and the host did not end anything; this is the removal event a restore host gets from usbmux\" detail=\"look for what took the controller down, a guest-side halt of run-stop or a panic, rather than for a host bound: {error}\"",
                    began.elapsed().as_secs_f64()
                );
                report(&reporter, "guest-left-the-bus", &line);
            }
            let line = format!(
                "{MUX_PREFIX} result=restore-failed port={port} at={armed_at_secs:.3}s elapsed={:.3}s meaning=\"the restore session ended early; the detail names the stage, and where that stage is a read that timed out it names what was not received rather than who owed it\" detail=\"{error}; bulk_transfers={}; bootability_bundles_pushed={}\"",
                began.elapsed().as_secs_f64(),
                bulk.fallback().fallback().fallback().transfers().len(),
                bulk.fallback().bundle().transfers().len()
            );
            report(&reporter, "restore-failed", &line);
            RestoreOutcome::Failed {
                stage: "restore-failed".to_string(),
                reason: error.to_string(),
            }
        }
    };

    // Stopped before `detach_host` so the ctrl session closes while the device is still on the bus.
    proxy.stop();

    outcome
}

struct PreparedMobileTickets {
    cache: crate::scratch::ScratchDir,
    os_ticket: Vec<u8>,
}

impl PreparedMobileTickets {
    fn path(&self) -> &Path {
        self.cache.path()
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_mobile_ap_tickets(
    manifest: &plist::Dictionary,
    derived: &super::options::DerivedRestoreOptions,
    hardware: &DeviceHardwareInfo,
    ap_nonce: Option<&[u8; BOOT_NONCE_HASH_BYTES]>,
    sep_nonce: Option<&[u8; 20]>,
    transport: &dyn super::local_policy::SigningTransport,
    fdr_trust_digest: Option<&[u8; 32]>,
    port: u16,
    armed_at_secs: f64,
    reporter: &SharedReporter,
) -> Result<PreparedMobileTickets, String> {
    let hardware = match hardware {
        DeviceHardwareInfo::Answered(info) => info,
        DeviceHardwareInfo::Unanswered { detail } => {
            return Err(format!("AP ticket hardware identity unavailable: {detail}"));
        }
    };
    let nonce = ap_nonce.ok_or_else(|| {
        "AP ticket needs this boot's AP nonce; the bridge did not publish it".to_string()
    })?;
    let sep_nonce = sep_nonce.ok_or_else(|| {
        "AP ticket needs this boot's SEP nonce; restored did not publish it".to_string()
    })?;
    let envelope = SigningEnvelope::for_this_host(
        SIGNING_ENVELOPE_VERSION_INFO,
        Some(derived.session_uuid.clone()),
    )?;
    let cache = crate::scratch::ScratchDir::new("apple-utils-personalized-tickets-")
        .map_err(|error| format!("personalized ticket cache: {error}"))?;
    let mut os_ticket = None;
    for (role, variant) in [
        ("os", Some(derived.install_variant.as_str())),
        ("recovery-os", derived.recovery_variant.as_deref()),
    ] {
        let Some(variant) = variant else {
            continue;
        };
        let identity =
            crate::ramrod::raw_identity_for_variant(manifest, &derived.hardware_model, variant)
                .ok_or_else(|| {
                    format!(
                        "AP ticket identity unavailable: {} variant {variant:?}",
                        derived.hardware_model
                    )
                })?;
        report(
            reporter,
            "ap-ticket-requested",
            &format!(
                "{MUX_PREFIX} result=ap-ticket-requested port={port} at={armed_at_secs:.3}s role={role} variant={variant:?} nonce_bytes={} sep_nonce_bytes={} server={SIGNING_SERVER_DEFAULT_BASE_URL}",
                nonce.len(),
                sep_nonce.len()
            ),
        );
        let digest = if role == "os" { fdr_trust_digest } else { None };
        let signed = super::ap_ticket::request_ap_ticket_with_fdr_trust_digest(
            transport,
            &identity,
            hardware,
            nonce,
            Some(sep_nonce),
            &envelope,
            digest,
        )
        .map_err(|error| format!("{role} AP ticket for {variant:?}: {error}"))?;
        let path = cache_ap_ticket(
            cache.path(),
            variant,
            &derived.hardware_model,
            &signed.ticket,
        )?;
        if role == "os" {
            os_ticket = Some(signed.ticket.clone());
        }
        report(
            reporter,
            "ap-ticket-received",
            &format!(
                "{MUX_PREFIX} result=ap-ticket-received port={port} at={armed_at_secs:.3}s role={role} variant={variant:?} bytes={} sha384={} path={:?}",
                signed.ticket.len(),
                hex_digest(&crate::crypto::sha384(&signed.ticket)),
                path
            ),
        );
    }
    Ok(PreparedMobileTickets {
        cache,
        os_ticket: os_ticket.ok_or("install AP ticket was not prepared")?,
    })
}

fn cache_ap_ticket(
    root: &Path,
    variant: &str,
    model: &str,
    bytes: &[u8],
) -> Result<PathBuf, String> {
    let mut parts = Path::new(variant).components();
    if !matches!(parts.next(), Some(std::path::Component::Normal(_))) || parts.next().is_some() {
        return Err(format!(
            "AP ticket variant is not a single path component: {variant:?}"
        ));
    }
    let board = crate::ramrod::normalise_board(model);
    if board.is_empty()
        || !board
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(format!(
            "AP ticket hardware model cannot name a cache file: {model:?}"
        ));
    }
    let directory = root.join(variant);
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("AP ticket cache directory: {error}"))?;
    let path = directory.join(format!("apticket.{board}.im4m"));
    std::fs::write(&path, bytes).map_err(|error| format!("AP ticket cache write: {error}"))?;
    Ok(path)
}

// The device's own statement of its part, asked before StartRestore; a LocalPolicy request
// names it when the served root ticket is global.
fn query_device_hardware_info<T: std::io::Read + std::io::Write>(
    client: &mut crate::ramrod::RamrodClient<T>,
    port: u16,
    armed_at_secs: f64,
    elapsed_secs: f64,
    reporter: &SharedReporter,
) -> DeviceHardwareInfo {
    let info = match client.query_value(QueryKey::HardwareInfo) {
        Ok(plist::Value::Dictionary(info)) => DeviceHardwareInfo::Answered(info),
        Ok(other) => DeviceHardwareInfo::Unanswered {
            detail: format!(
                "the reply carried {} as {other:?} where restored sends a dictionary",
                QueryKey::HardwareInfo
            ),
        },
        Err(error) => DeviceHardwareInfo::Unanswered {
            detail: error.to_string(),
        },
    };
    let (result, meaning) = match &info {
        DeviceHardwareInfo::Answered(_) => (
            "hardware-info-answered",
            "restored stated the part it is: ChipID, BoardID, UniqueChipID, SecurityDomain and ProductionMode from /chosen, SecurityMode and the effective modes from MobileGestalt",
        ),
        DeviceHardwareInfo::Unanswered { .. } => (
            "hardware-info-unanswered",
            "restored did not state the part it is, so a LocalPolicy request over a global root ticket has no identity to name",
        ),
    };
    let line = format!(
        "{MUX_PREFIX} result={result} port={port} at={armed_at_secs:.3}s elapsed={elapsed_secs:.3}s {} meaning=\"{meaning}\" detail=\"\"",
        info.trace_fields()
    );
    report(reporter, result, &line);
    info
}

fn sep_nonce_from_value(value: plist::Value) -> Result<[u8; 20], String> {
    let bytes = value
        .as_data()
        .ok_or_else(|| format!("SEPNonce was {value:?}, expected data"))?;
    <[u8; 20]>::try_from(bytes)
        .map_err(|_| format!("SEPNonce was {} bytes, expected 20", bytes.len()))
}

fn query_device_sep_nonce<T: std::io::Read + std::io::Write>(
    client: &mut crate::ramrod::RamrodClient<T>,
    port: u16,
    armed_at_secs: f64,
    reporter: &SharedReporter,
) -> Option<[u8; 20]> {
    let result = client
        .query_value_named("SEPNonce")
        .map_err(|error| error.to_string())
        .and_then(sep_nonce_from_value);
    match result {
        Ok(nonce) => {
            report(
                reporter,
                "sep-nonce-answered",
                &format!(
                    "{MUX_PREFIX} result=sep-nonce-answered port={port} at={armed_at_secs:.3}s bytes={} meaning=\"restored reported the SEP nonce for this boot before ticket personalization\"",
                    nonce.len()
                ),
            );
            Some(nonce)
        }
        Err(reason) => {
            report(
                reporter,
                "sep-nonce-unanswered",
                &format!(
                    "{MUX_PREFIX} result=sep-nonce-unanswered port={port} at={armed_at_secs:.3}s meaning=\"no SEP nonce was available from restored, so an AP ticket cannot be personalized\" detail={reason:?}"
                ),
            );
            None
        }
    }
}

pub fn local_policy_signer_for_plan(
    plan: &RestorePlan,
    session_uuid: &str,
    port: u16,
    armed_at_secs: f64,
    reporter: &SharedReporter,
) -> Option<Arc<dyn RecoveryOsLocalPolicySigner>> {
    if !plan.sign_recovery_os_local_policy {
        let line = format!(
            "{MUX_PREFIX} result=recovery-os-local-policy-signing-not-armed port={port} at={armed_at_secs:.3}s flag={SIGNING_OPT_IN_FLAG} key={SIGNING_OPT_IN_KEY} meaning=\"LocalPolicy signing not armed\" detail=\"pass {SIGNING_OPT_IN_FLAG} or press {SIGNING_OPT_IN_KEY} before the restore starts; issuing posts ECID, chip and board to {SIGNING_SERVER_DEFAULT_BASE_URL}\""
        );
        report(
            reporter,
            "recovery-os-local-policy-signing-not-armed",
            &line,
        );
        return None;
    }
    match signing_server_signer(Some(session_uuid.to_string())) {
        Ok(signer) => {
            let line = format!(
                "{MUX_PREFIX} result=recovery-os-local-policy-signing-armed port={port} at={armed_at_secs:.3}s source={} base_url={SIGNING_SERVER_DEFAULT_BASE_URL} uuid={session_uuid} version_info={SIGNING_ENVELOPE_VERSION_INFO} meaning=\"LocalPolicy signing armed\" detail=\"a request that passes the identity gate is posted to {SIGNING_SERVER_DEFAULT_BASE_URL}; arming itself issues nothing\"",
                signer.source()
            );
            report(reporter, "recovery-os-local-policy-signing-armed", &line);
            Some(signer)
        }
        Err(error) => {
            let line = format!(
                "{MUX_PREFIX} result=recovery-os-local-policy-signing-not-armable port={port} at={armed_at_secs:.3}s flag={SIGNING_OPT_IN_FLAG} meaning=\"LocalPolicy signing armed but envelope unreadable\" detail=\"{error}\""
            );
            report(
                reporter,
                "recovery-os-local-policy-signing-not-armable",
                &line,
            );
            None
        }
    }
}

fn firmware_updater_signer_for_plan(
    plan: &RestorePlan,
    session_uuid: &str,
    port: u16,
    armed_at_secs: f64,
    reporter: &SharedReporter,
) -> Option<Arc<dyn FirmwareUpdaterSigner>> {
    if !plan.sign_recovery_os_local_policy {
        let line = format!(
            "{MUX_PREFIX} result=firmware-updater-signing-not-armed port={port} at={armed_at_secs:.3}s flag={SIGNING_OPT_IN_FLAG} key={SIGNING_OPT_IN_KEY}"
        );
        report(reporter, "firmware-updater-signing-not-armed", &line);
        return None;
    }
    match firmware_updater_signer(Some(session_uuid.to_string())) {
        Ok(signer) => {
            let line = format!(
                "{MUX_PREFIX} result=firmware-updater-signing-armed port={port} at={armed_at_secs:.3}s source={} base_url={SIGNING_SERVER_DEFAULT_BASE_URL}",
                signer.source(),
            );
            report(reporter, "firmware-updater-signing-armed", &line);
            Some(signer)
        }
        Err(error) => {
            let line = format!(
                "{MUX_PREFIX} result=firmware-updater-signing-not-armable port={port} at={armed_at_secs:.3}s detail=\"{error}\""
            );
            report(reporter, "firmware-updater-signing-not-armable", &line);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PayloadProgress, ReporterProducerTrace, RestoreBootContext, RestoreOutcome,
        SIGNING_OPT_IN_FLAG, SIGNING_OPT_IN_KEY, SIGNING_SERVER_DEFAULT_BASE_URL, cache_ap_ticket,
        local_policy_signer_for_plan, run_ramrod_restore_over_mux, sep_nonce_from_value,
    };
    use crate::asr_server::AsrServerConfig;
    use crate::asr_server::payload::PayloadObserver;
    use crate::asr_server::producer::{AsrPhase, AsrProducerEvent, AsrProducerSink};
    use crate::restore::RestorePlan;
    use crate::restore::local_policy::DeviceHardwareInfo;
    use crate::restore::mux::{ClaimedMuxTransport, ClaimedMuxTransportMetadata};
    use crate::restore::report::{RestoreEvent, RestoreReporter, SharedReporter};
    use crate::usbmux::{BulkTransport, MuxDialer, MuxLink, MuxVersion, SharedLink};
    use std::io;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    fn tcon_restore_options(macos: bool) -> crate::restore::options::DerivedRestoreOptions {
        use plist::{Dictionary, Value};
        let identity = |variant: &str| {
            let mut info = Dictionary::from_iter([
                (
                    "DeviceClass".to_string(),
                    Value::String("j620ap".to_string()),
                ),
                ("Variant".to_string(), Value::String(variant.to_string())),
                (
                    "RestoreBehavior".to_string(),
                    Value::String("Erase".to_string()),
                ),
                (
                    "MinimumSystemPartition".to_string(),
                    Value::Integer(11977.into()),
                ),
            ]);
            if macos {
                info.insert(
                    "MacOSVariant".to_string(),
                    Value::String("macOS Customer".to_string()),
                );
            } else if variant == "Customer Erase Install (IPSW)" {
                info.insert(
                    "RecoveryVariant".to_string(),
                    Value::String("Recovery Customer Install".to_string()),
                );
            }
            Value::Dictionary(Dictionary::from_iter([
                ("Info".to_string(), Value::Dictionary(info)),
                ("Manifest".to_string(), Value::Dictionary(Dictionary::new())),
            ]))
        };
        let manifest = Dictionary::from_iter([(
            "BuildIdentities".to_string(),
            Value::Array(vec![
                identity("Customer Erase Install (IPSW)"),
                identity(if macos {
                    "macOS Customer"
                } else {
                    "Recovery Customer Install"
                }),
            ]),
        )]);
        let device = crate::ramrod::DeviceType {
            service_type: "com.apple.mobile.restored".to_string(),
            protocol_version: Some(15),
            body: Dictionary::from_iter([(
                "HardwareModel".to_string(),
                Value::String("J620AP".to_string()),
            )]),
        };
        crate::restore::options::derive_restore_options(
            &manifest,
            &device,
            false,
            Some(crate::ramrod::RestoreBehavior::Erase),
        )
        .unwrap()
    }

    fn tcon_start_restore_wire(options: crate::ramrod::RestoreOptions) -> plist::Dictionary {
        let mut client = crate::ramrod::RamrodClient::new(std::io::Cursor::new(Vec::new()));
        client.start_restore(options).unwrap();
        let mut transport = client.into_inner();
        transport.set_position(0);
        let request = crate::ramrod::codec::read_message(&mut transport)
            .unwrap()
            .unwrap();
        let request = request.as_dictionary().unwrap();
        assert_eq!(request["Request"].as_string(), Some("StartRestore"));
        request["RestoreOptions"].as_dictionary().unwrap().clone()
    }

    #[test]
    fn mobile_skip_tcon_firmware_is_reported_and_sent_as_a_boolean() {
        let mut derived = tcon_restore_options(false);
        let boot = RestoreBootContext {
            skip_tcon_firmware: true,
            ..RestoreBootContext::default()
        };
        super::apply_skip_tcon_firmware(&mut derived, boot.skip_tcon_firmware);
        super::apply_skip_tcon_firmware(&mut derived, boot.skip_tcon_firmware);
        assert_eq!(
            derived
                .report
                .keys
                .iter()
                .filter(|key| key.as_str() == "SkipTCONFW")
                .count(),
            1
        );
        let body = tcon_start_restore_wire(derived.options);
        assert_eq!(body["SkipTCONFW"].as_boolean(), Some(true));
        assert_eq!(
            body["AuthInstallRecoveryOSVariant"].as_string(),
            Some("Recovery Customer Install")
        );
        assert_eq!(
            body["AuthInstallRestoreBehavior"].as_string(),
            Some("Erase")
        );
        assert_eq!(
            body["SupportedHostProtocols"].as_array().unwrap(),
            &vec![plist::Value::String("MuxSocket".to_string())]
        );
    }

    #[test]
    fn tcon_selection_preserves_existing_restore_options_for_both_identity_families() {
        for (macos, enabled) in [(false, false), (true, false), (true, true)] {
            let mut derived = tcon_restore_options(macos);
            assert_eq!(derived.is_macos, macos);
            super::apply_skip_tcon_firmware(&mut derived, enabled);
            let body = tcon_start_restore_wire(derived.options);
            assert_eq!(
                body["AuthInstallRestoreBehavior"].as_string(),
                Some("Erase")
            );
            assert_eq!(
                body["AuthInstallVariant"].as_string(),
                Some("Customer Erase Install (IPSW)")
            );
            assert_eq!(
                body["UUID"].as_string(),
                Some(derived.session_uuid.as_str())
            );
            assert_eq!(body["FlashNOR"].as_boolean(), Some(true));
        }
    }

    #[test]
    fn sep_nonce_query_value_preserves_the_device_bytes() {
        let nonce = [0x52; 20];
        assert_eq!(
            sep_nonce_from_value(plist::Value::Data(nonce.to_vec())).unwrap(),
            nonce
        );
    }

    #[derive(Default)]
    struct Recorder {
        events: Vec<(String, String)>,
    }

    impl RestoreReporter for Recorder {
        fn event(&mut self, event: RestoreEvent<'_>) {
            self.events
                .push((event.result.to_string(), event.line.to_string()));
        }
    }

    #[derive(Clone)]
    struct CountingTransport {
        calls: Arc<AtomicUsize>,
    }

    impl BulkTransport for CountingTransport {
        fn send(&mut self, _packet: &[u8]) -> io::Result<()> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn recv(&mut self, _timeout: Duration) -> io::Result<Option<Vec<u8>>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(None)
        }

        fn out_max_packet_size(&self) -> u16 {
            512
        }
    }

    fn reporter() -> (Arc<Mutex<Recorder>>, SharedReporter) {
        let recorded = Arc::new(Mutex::new(Recorder::default()));
        let reporter: SharedReporter = recorded.clone();
        (recorded, reporter)
    }

    fn claimed(calls: Arc<AtomicUsize>) -> ClaimedMuxTransport<CountingTransport> {
        let link = SharedLink::new(MuxLink::new(CountingTransport { calls }));
        ClaimedMuxTransport::new(
            MuxDialer::new(link),
            ClaimedMuxTransportMetadata {
                transport_kind: "loopback-test",
                interface: 0,
                device_to_host_endpoint: 0x81,
                host_to_device_endpoint: 0x01,
                host_to_device_max_packet_size: 512,
                version: MuxVersion::V2,
            },
        )
    }

    fn plan(image: PathBuf, manifest: Option<PathBuf>) -> RestorePlan {
        RestorePlan {
            image,
            system_image: None,
            recovery_image: None,
            image_root: None,
            manifest,
            behavior: None,
            port: 62078,
            timeout: Duration::from_millis(10),
            window: Duration::from_millis(10),
            retry: Duration::from_millis(1),
            read_poll: Duration::from_millis(1),
            asr_read_timeout: None,
            metadata: true,
            global_manifests: None,
            firmware_root: None,
            bootability_bundle: None,
            corrupt_manifest: false,
            staged_boot_manifest_sha384: None,
            staged_boot_manifest: None,
            fdr_trust_digest: None,
            restore_ramdisk: None,
            fdr_material_dir: None,
            sign_recovery_os_local_policy: false,
        }
    }

    fn run_preflight(plan: &RestorePlan, calls: Arc<AtomicUsize>) -> RestoreOutcome {
        let (_, reporter) = reporter();
        run_ramrod_restore_over_mux(
            claimed(calls),
            RestoreBootContext::default(),
            plan,
            AsrServerConfig::default(),
            0,
            0.0,
            Arc::new(AtomicBool::new(false)),
            reporter,
        )
    }

    #[test]
    fn mobile_recovery_bulk_request_records_a_named_missing_image_refusal() {
        use crate::ramrod::{BulkOutcome, BulkTransferService, DataRequest, DataType, GuestDialer};
        #[derive(Clone)]
        struct Dialer;
        impl GuestDialer for Dialer {
            type Stream = std::io::Cursor<Vec<u8>>;
            fn dial(&mut self, _port: u16, _timeout: Duration) -> io::Result<Self::Stream> {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "test device unavailable",
                ))
            }
        }
        let plan = plan(PathBuf::from("explicit-install.dmg"), None);
        let images = super::initial_restore_images(&plan, false);
        assert_eq!(
            images.resolve(&DataType::SystemImageData),
            Some(plan.image.as_path())
        );
        let mut bulk =
            crate::ramrod::AsrBulkTransfer::new(Dialer, images, AsrServerConfig::default(), ());
        let request = DataRequest {
            data_type: DataType::RecoveryOSASRImage,
            data_port: Some(9500),
            arguments: plist::Dictionary::new(),
            asynchronous: false,
            async_context_uuid: None,
        };
        match bulk.serve(9500, &request).unwrap() {
            BulkOutcome::Declined { reason } => assert!(reason.contains("RecoveryOSASRImage")),
            other => panic!("expected a named recovery image refusal, got {other:?}"),
        }
    }

    fn configured_material_plan() -> (tempfile::TempDir, RestorePlan) {
        let directory = tempfile::tempdir().unwrap();
        let material = crate::ramrod::FdrTrustMaterial::load_or_generate_portable(
            directory.path(),
            super::FDR_TRUST_NOT_BEFORE,
            super::FDR_TRUST_NOT_AFTER,
        )
        .unwrap();
        let mut plan = plan(PathBuf::from("explicit-image.dmg"), None);
        plan.fdr_material_dir = Some(directory.path().to_path_buf());
        plan.fdr_trust_digest = Some(crate::restore::plan::FdrTrustDigest {
            digest: material.digest(),
            trust_object: material.trust_object().to_vec(),
            element_index: 0,
            element_count: 1,
            instance: Some("configured-device-instance".to_string()),
        });
        (directory, plan)
    }

    fn unqueried_hardware() -> DeviceHardwareInfo {
        DeviceHardwareInfo::Unanswered {
            detail: "hardware query was not needed".to_string(),
        }
    }

    #[test]
    fn local_fdr_service_arms_for_stock_ticket_without_replacing_its_trust_object() {
        let directory = tempfile::tempdir().unwrap();
        let mut plan = plan(PathBuf::from("explicit-image.dmg"), None);
        plan.fdr_material_dir = Some(directory.path().join("device-material"));
        let key =
            crate::crypto::P256PrivateKey::derive(&[0x52; 32], b"test device signing identity");
        let boot = RestoreBootContext {
            sep_public_key: Some(key.public_uncompressed()),
            local_test_signing_key: Some(key),
            ..RestoreBootContext::default()
        };
        let mut info = plist::Dictionary::new();
        info.insert(
            "UniqueChipID".to_string(),
            plist::Value::Integer(0x1234_u64.into()),
        );
        info.insert("ChipID".to_string(), plist::Value::Integer(0x42_u64.into()));
        info.insert("BoardID".to_string(), plist::Value::Integer(1_u64.into()));
        info.insert(
            "SecurityDomain".to_string(),
            plist::Value::Integer(1_u64.into()),
        );
        info.insert("ProductionMode".to_string(), plist::Value::Boolean(true));
        info.insert("SecurityMode".to_string(), plist::Value::Boolean(true));
        let hardware = DeviceHardwareInfo::Answered(info);
        let (recorded, reporter) = reporter();
        let server = super::stand_up_seal_server(&plan, &boot, &hardware, 62078, 0.0, &reporter)
            .unwrap()
            .unwrap();
        assert_eq!(server.signing_public_key(), key.public_uncompressed());
        assert!(plan.fdr_trust_digest.is_none());
        assert!(
            recorded.lock().unwrap().events[0]
                .1
                .contains("trust_binding=stock-ticket")
        );
        assert!(plan.fdr_material_dir.as_ref().unwrap().is_dir());
    }

    #[test]
    fn seal_server_arms_with_the_exact_reloaded_material_and_device_key() {
        let (_directory, plan) = configured_material_plan();
        let expected = plan.fdr_trust_digest.as_ref().unwrap();
        let material =
            super::reload_fdr_trust_material(plan.fdr_material_dir.as_deref().unwrap()).unwrap();
        assert_eq!(material.digest(), expected.digest);
        assert_eq!(material.trust_object(), expected.trust_object.as_slice());
        let key =
            crate::crypto::P256PrivateKey::derive(&[0x51; 32], b"test device signing identity");
        let boot = RestoreBootContext {
            sep_public_key: Some(key.public_uncompressed()),
            local_test_signing_key: Some(key),
            ..RestoreBootContext::default()
        };
        let (recorded, reporter) = reporter();
        let server =
            super::stand_up_seal_server(&plan, &boot, &unqueried_hardware(), 62078, 0.0, &reporter)
                .unwrap()
                .unwrap();
        assert_eq!(server.signing_public_key(), key.public_uncompressed());
        assert_eq!(recorded.lock().unwrap().events[0].0, "service-armed");
    }

    #[test]
    fn seal_server_material_binding_failures_are_named() {
        let (_directory, plan) = configured_material_plan();
        for (digest_changed, refusal) in [
            (true, "fdr-material-digest-mismatch"),
            (false, "fdr-material-trust-object-mismatch"),
        ] {
            let mut mismatched = plan.clone();
            let expected = mismatched.fdr_trust_digest.as_mut().unwrap();
            if digest_changed {
                expected.digest[0] ^= 1;
            } else {
                expected.trust_object.push(0);
            }
            let (recorded, reporter) = reporter();
            let error = super::stand_up_seal_server(
                &mismatched,
                &RestoreBootContext::default(),
                &unqueried_hardware(),
                62078,
                0.0,
                &reporter,
            )
            .err()
            .expect("configured material binding must be verified before arming");
            assert!(error.contains(refusal), "{error}");
            assert_eq!(recorded.lock().unwrap().events[0].0, "service-unarmed");
        }
    }

    #[test]
    fn seal_server_invalid_configured_seed_returns_preparation_failure() {
        let (_directory, plan) = configured_material_plan();
        let seed = plan
            .fdr_material_dir
            .as_ref()
            .unwrap()
            .join(crate::ramrod::fdr_object::ROOT_CA_SEED_FILE_NAME);
        std::fs::write(seed, [1]).unwrap();
        let (_, reporter) = reporter();
        let error = super::stand_up_seal_server(
            &plan,
            &RestoreBootContext::default(),
            &unqueried_hardware(),
            62078,
            0.0,
            &reporter,
        )
        .err()
        .expect("invalid configured key must refuse preparation");
        assert!(error.contains("fdr-seal-preparation-failed"), "{error}");
        assert!(
            error.contains("fdr-material-root-key-unreadable"),
            "{error}"
        );
    }

    #[test]
    fn disabled_vm_signing_records_the_operator_policy() {
        let (recorded, reporter) = reporter();
        let boot = RestoreBootContext {
            vm_local_signing_enabled: false,
            ..RestoreBootContext::default()
        };
        let plan = plan(PathBuf::from("explicit-image.dmg"), None);
        let _seal =
            super::stand_up_seal_server(&plan, &boot, &unqueried_hardware(), 62078, 0.0, &reporter)
                .unwrap();
        let events = &recorded.lock().unwrap().events;
        assert_eq!(events[0].0, "service-disabled");
        assert!(events[0].1.contains("disabled by the operator"));
    }

    #[test]
    fn watchdog_events_use_the_injected_restore_reporter() {
        let (recorded, reporter) = reporter();
        let sink = ReporterProducerTrace::new(reporter);

        sink.event(AsrProducerEvent::ProducerClock {
            session_offset: Duration::from_secs(2),
        });

        let recorded = recorded.lock().expect("reporter lock");
        assert_eq!(recorded.events.len(), 1);
        assert_eq!(recorded.events[0].0, "producer-clock");
        assert!(
            recorded.events[0]
                .1
                .starts_with("[asr-serve] result=producer-clock")
        );
    }

    #[test]
    fn missing_or_malformed_manifest_performs_no_device_io() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let image = directory.path().join("restore.dmg");
        std::fs::write(&image, b"image").expect("write image");

        let missing_calls = Arc::new(AtomicUsize::new(0));
        let missing = run_preflight(&plan(image.clone(), None), Arc::clone(&missing_calls));
        assert!(matches!(
            missing,
            RestoreOutcome::Failed { ref stage, .. } if stage == "no-restore-manifest"
        ));
        assert_eq!(missing_calls.load(Ordering::Relaxed), 0);

        let manifest = directory.path().join("BuildManifest.plist");
        std::fs::write(&manifest, b"not a property list").expect("write malformed manifest");
        let malformed_calls = Arc::new(AtomicUsize::new(0));
        let malformed = run_preflight(&plan(image, Some(manifest)), Arc::clone(&malformed_calls));
        assert!(matches!(
            malformed,
            RestoreOutcome::Failed { ref stage, .. } if stage == "restore-manifest-unusable"
        ));
        assert_eq!(malformed_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn the_signing_service_is_armed_only_by_the_plan_the_operator_set() {
        let image = PathBuf::from("restore.dmg");

        let mut off = plan(image.clone(), None);
        off.sign_recovery_os_local_policy = false;
        let (off_recorded, off_reporter) = reporter();
        let off_signer =
            local_policy_signer_for_plan(&off, "SESSION-UUID", 62078, 0.0, &off_reporter);
        let off_events = off_recorded.lock().expect("reporter lock").events.clone();
        assert_eq!(off_events.len(), 1, "{off_events:?}");
        assert_eq!(
            off_events[0].0, "recovery-os-local-policy-signing-not-armed",
            "an unarmed run records why it will not issue the request: {off_events:?}"
        );
        assert!(
            off_events[0]
                .1
                .contains(&format!("flag={SIGNING_OPT_IN_FLAG}")),
            "the decline names the flag that would arm it: {off_events:?}"
        );
        assert!(
            off_events[0]
                .1
                .contains(&format!("key={SIGNING_OPT_IN_KEY}")),
            "the decline names the screen key that would arm it: {off_events:?}"
        );
        assert!(
            off_signer.is_none(),
            "an unarmed run carries the same absent service it always has"
        );

        let mut on = plan(image, None);
        on.sign_recovery_os_local_policy = true;
        let (on_recorded, on_reporter) = reporter();
        let on_signer = local_policy_signer_for_plan(&on, "SESSION-UUID", 62078, 0.0, &on_reporter)
            .expect("the operator armed the service, so the run carries one");
        assert_eq!(
            on_signer.source(),
            "curl",
            "the armed service issues over the transport this tree already uses"
        );
        let on_events = on_recorded.lock().expect("reporter lock").events.clone();
        assert_eq!(on_events.len(), 1, "{on_events:?}");
        assert_eq!(
            on_events[0].0, "recovery-os-local-policy-signing-armed",
            "{on_events:?}"
        );
        assert!(on_events[0].1.contains("source=curl"), "{on_events:?}");
        assert!(
            on_events[0].1.contains("uuid=SESSION-UUID"),
            "the arm carries the run's own session identifier, not one invented here: {on_events:?}"
        );
        assert!(
            on_events[0]
                .1
                .contains(&format!("base_url={SIGNING_SERVER_DEFAULT_BASE_URL}")),
            "the arm names where the request would go: {on_events:?}"
        );
    }
    #[test]
    fn personalized_ticket_cache_keeps_install_and_recovery_responses_distinct() {
        let cache = tempfile::tempdir().unwrap();
        let install = cache_ap_ticket(
            cache.path(),
            "Developer Erase Install (IPSW)",
            "J620AP",
            b"signed install response",
        )
        .unwrap();
        let recovery = cache_ap_ticket(
            cache.path(),
            "Recovery Customer Install",
            "J620AP",
            b"signed recovery response",
        )
        .unwrap();
        assert_eq!(std::fs::read(install).unwrap(), b"signed install response");
        assert_eq!(
            std::fs::read(recovery).unwrap(),
            b"signed recovery response"
        );
    }

    #[test]
    fn cloned_payload_progress_keeps_each_guest_port_and_phase_attributed() {
        let (_, reporter) = reporter();
        let session_began = Instant::now();
        let prototype = PayloadProgress::new(0, Arc::new(AtomicBool::new(false)), reporter)
            .on_session_clock(session_began);
        let mut recovery = prototype.clone();
        let mut system = prototype.clone();
        recovery.serving_port(9510, 4096);
        system.serving_port(9512, 8192);
        recovery.entered_phase(AsrPhase::AwaitingRequest, 0);
        system.entered_phase(AsrPhase::WritingPayload, 0);
        recovery.block_sent(0, 1024);
        system.block_sent(0, 2048);
        let recovery_sample = recovery.activity().sample();
        let system_sample = system.activity().sample();
        assert_eq!(
            (
                recovery_sample.port,
                recovery_sample.total,
                recovery_sample.offset,
                recovery_sample.blocks,
                recovery_sample.phase
            ),
            (9510, 4096, 1024, 1, AsrPhase::AwaitingRequest)
        );
        assert_eq!(
            (
                system_sample.port,
                system_sample.total,
                system_sample.offset,
                system_sample.blocks,
                system_sample.phase
            ),
            (9512, 8192, 2048, 1, AsrPhase::WritingPayload)
        );
        assert_eq!(recovery_sample.transitions, 1);
        assert_eq!(system_sample.transitions, 1);
    }

    #[test]
    fn payload_progress_retains_the_cancellation_reason_observed_after_a_block() {
        for reason in [
            crate::ramrod::DialCancellation::TransferFailed,
            crate::ramrod::DialCancellation::OperatorStopped,
        ] {
            let (_, reporter) = reporter();
            let stop = Arc::new(AtomicBool::new(false));
            let cancel = Arc::new(AtomicBool::new(false));
            let mut progress = PayloadProgress::new(4096, Arc::clone(&stop), reporter)
                .with_transfer_cancel(Arc::clone(&cancel));
            progress.serving_port(9632, 4096);
            progress.block_sent(0, 1024);
            cancel.store(true, Ordering::Release);
            if reason == crate::ramrod::DialCancellation::OperatorStopped {
                stop.store(true, Ordering::Release);
            }
            assert!(progress.should_stop());
            stop.store(false, Ordering::Release);
            cancel.store(false, Ordering::Release);
            let error = progress.stop_error();
            assert_eq!(
                crate::ramrod::DialCancellation::from_io_error(&error),
                Some(reason)
            );
            let sample = progress.activity().sample();
            assert_eq!(
                (sample.port, sample.offset, sample.blocks, sample.total),
                (9632, 1024, 1, 4096)
            );
        }
    }
}
