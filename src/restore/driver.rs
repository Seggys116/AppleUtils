use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::crypto::{P256_UNCOMPRESSED_BYTES, P256PrivateKey};

use crate::asr_server::producer::{
    AsrPhase, AsrProducerActivity, AsrProducerEvent, AsrProducerSink, AsrProducerWatchdogPolicy,
    spawn_asr_producer_watchdog,
};
use crate::asr_server::{AsrServerConfig, PayloadObserver};
use crate::ramrod::{
    AsrBulkTransfer, BOOT_NONCE_HASH_BYTES, BootabilityBundleSource, BootabilityBundleTransfer,
    BootabilityRouter, DialPlan, PreparedAnswers, RestoreDataProvider, RestoreSummary, SystemClock,
    load_build_manifest,
};
use crate::usbmux::{BulkTransport, is_device_gone, is_host_initiated_teardown, is_run_stopped};

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
        }
    }

    #[must_use]
    pub fn on_session_clock(self, session_began: Instant) -> Self {
        self.activity
            .set_session_offset(session_began.elapsed().saturating_sub(self.began.elapsed()));
        self
    }

    #[must_use]
    pub fn activity(&self) -> Arc<AsrProducerActivity> {
        Arc::clone(&self.activity)
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
        self.stop.load(Ordering::Relaxed)
    }

    fn entered_phase(&mut self, phase: AsrPhase, _offset: u64) {
        self.activity.enter(phase);
    }

    fn serving_port(&mut self, port: u16, payload_size: u64) {
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

#[derive(Clone, Default)]
pub struct RestoreBootContext {
    pub ap_nonce: Option<[u8; BOOT_NONCE_HASH_BYTES]>,
    pub sep_public_key: Option<[u8; P256_UNCOMPRESSED_BYTES]>,
    pub remote_digest_signing: bool,
    pub manifest_signer: Option<Arc<dyn FdrManifestSigner>>,
    pub local_test_signing_key: Option<P256PrivateKey>,
}

impl std::fmt::Debug for RestoreBootContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RestoreBootContext")
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

fn stand_up_seal_server(
    plan: &RestorePlan,
    boot: &RestoreBootContext,
    port: u16,
    armed_at_secs: f64,
    reporter: &SharedReporter,
) -> Option<Arc<SealServer>> {
    let Some(directory) = plan.fdr_material_dir.as_ref() else {
        let line = format!(
            "{FDR_SEAL_PREFIX} result=service-unarmed port={port} at={armed_at_secs:.3}s material=none meaning=\"the local restore service could not stand up its FDR certificate authority and sealing server, so a proxied FDR request is refused with its destination named exactly as it was before and fdr_recover fails on that; nothing is substituted for the material that could not be built\" detail=\"no --fdr-material-dir was given, so there is nowhere to load or generate the FDR trust material from\"",
        );
        report(reporter, "service-unarmed", &line);
        return None;
    };
    let instance = plan
        .fdr_trust_digest
        .as_ref()
        .and_then(|resolved| resolved.instance.clone());
    let outcome = crate::ramrod::FdrTrustMaterial::load_or_generate(
        directory,
        FDR_TRUST_NOT_BEFORE,
        FDR_TRUST_NOT_AFTER,
    )
    .map_err(|error| error.to_string())
    .and_then(|material| {
        let instance = instance.clone().ok_or_else(|| {
            String::from(
                "no FDR data instance identifier could be derived for this machine, and a sealing manifest names one",
            )
        })?;
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
        SealServer::new(
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
        .map_err(|error| error.to_string())
    });

    match outcome {
        Ok(server) => {
            let line = format!(
                "{FDR_SEAL_PREFIX} result=service-armed port={port} at={armed_at_secs:.3}s url={} instance={} leaf_bytes={} material={} meaning=\"the local offline FDR certificate authority and sealing server is standing behind the reverse proxy, and the restore options name this URL as FDRCAURL, FDRDataStoreURL and FDRSealingURL so the guest dials the local service instead of the apple.com defaults; the leaf is issued by the same root the trust object's trst element publishes, which is the anchor the guest verifies the chain against\" detail=\"the leaf's serial number persists beside the roots', and the key it certifies is this device's Secure Enclave identity key, so a manifest signed on one run is signed under the same key on the next; nothing here reaches the internet and nothing here disables a check. Which key is in force is on the signing-key-bound line that follows this one\"",
                service_base_url(),
                instance.as_deref().unwrap_or("none"),
                server.leaf_certificate().len(),
                directory.display()
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
            Some(Arc::new(server))
        }
        Err(error) => {
            let line = format!(
                "{FDR_SEAL_PREFIX} result=service-unarmed port={port} at={armed_at_secs:.3}s material={} meaning=\"the local restore service could not stand up its FDR certificate authority and sealing server, so a proxied FDR request is refused with its destination named exactly as it was before and fdr_recover fails on that; nothing is substituted for the material that could not be built\" detail=\"{error}\"",
                directory.display()
            );
            report(reporter, "service-unarmed", &line);
            None
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
    let mut dialer = claimed.dialer().clone();
    let dial_plan = DialPlan::default().on_port(port).with_window(plan.window);
    let request_global_manifest = plan.global_manifests.is_some();
    let (identified, prepared) = match query_and_prepare_restore_session(
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
    let bulk_dialer = dialer.clone();
    let bundle_dialer = dialer.clone();
    let mut client = identified.client;
    let device = identified.device;
    let line = format!(
        "{MUX_PREFIX} result=identify-answered port={port} at={armed_at_secs:.3}s elapsed={:.3}s device={device:?} meaning=\"restored answered QueryType, so this really is the ramrod command channel\" detail=\"\"",
        began.elapsed().as_secs_f64()
    );
    report(&reporter, "identify-answered", &line);
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
    let derived = prepared.derived.clone();
    let manifest = prepared.manifest.clone();
    let line = format!(
        "{MUX_PREFIX} result=identity-selected port={port} at={armed_at_secs:.3}s elapsed={:.3}s model={} behavior={} meaning=\"the build identities the restore options are derived from were chosen out of the manifest\" detail=\"install=#{} [{}] macos=#{} [{}]\"",
        began.elapsed().as_secs_f64(),
        prepared.identity.hardware_model,
        derived.behavior,
        prepared.identity.install_index,
        prepared.identity.install_variant,
        prepared.identity.macos_index,
        prepared.identity.macos_variant
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
    if request_global_manifest {
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
        .on_session_clock(began);
    let producer_activity = progress.activity();
    let mut images = crate::ramrod::ImageSources::with_default(&plan.image);
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
            match crate::ramrod::resolve_bulk_image(&entry, &derived.install_identity, root) {
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
    let mut bulk = BootabilityRouter::new(bundle_bulk, asr_bulk);
    let ticket_root = plan.global_manifests.clone().or_else(|| {
        plan.firmware_root.as_ref().map(|root| {
            let nested = root.join("Firmware/Manifests/restore");
            if nested.is_dir() {
                nested
            } else {
                root.clone()
            }
        })
    });
    let mut provider: Box<dyn RestoreDataProvider> = match ticket_root {
        Some(root) => {
            // `AuthInstallVariant` is the identity being installed and `AuthInstallRecoveryOSVariant` the recovery OS; they are not interchangeable.
            let variants = RestoreVariants {
                install: derived.install_variant.clone(),
                recovery_os: derived.macos_variant.clone(),
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
            );
            let cryptex_ticket = tickets.cryptex1_ticket_bytes();
            // Prepared before start: the guest sends one NORData request and gets no second chance.
            let board_manifest = plan.firmware_root.as_ref().and_then(|_| {
                board_manifest_for_firmware(
                    &root,
                    &variants,
                    &derived.hardware_model,
                    plan.corrupt_manifest,
                    port,
                    armed_at_secs,
                    &reporter,
                )
            });
            // A missing board IM4M is refused rather than answered with a bare IM4P: AMAuthInstallApImg4DecodeRestoreInfo refuses one outright with error 99.
            let firmware = plan.firmware_root.as_ref().map(|firmware_root| {
                let (manifest_path, manifest_bytes) = match board_manifest.as_ref() {
                    Some(manifest) => (manifest.path.clone(), manifest.bytes.as_slice()),
                    None => (firmware_root.join("apticket.im4m"), &[][..]),
                };
                NorFirmwareProvider::prepare(
                    &derived.install_identity,
                    firmware_root.clone(),
                    manifest_path,
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
                &derived.macos_variant,
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
                    derived.macos_variant.clone(),
                    splat.omitted(),
                    port,
                    armed_at_secs,
                    &reporter,
                ),
                personalized: PersonalizedFirmwareProvider::new(
                    manifest.clone(),
                    derived.hardware_model.clone(),
                    derived.install_variant.clone(),
                    derived.macos_variant.clone(),
                    plan.firmware_root.clone(),
                    board_manifest
                        .as_ref()
                        .map(|manifest| manifest.bytes.clone()),
                    board_manifest
                        .as_ref()
                        .map(|manifest| manifest.path.clone()),
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
                ),
                fdr: FdrTrustProvider::new(
                    plan.fdr_trust_digest.as_ref(),
                    port,
                    armed_at_secs,
                    &reporter,
                ),
                port,
                armed_at_secs,
                reporter: Arc::clone(&reporter),
            })
        }
        None => Box::new(PreparedAnswers::new()),
    };
    // Dialled here and held for the whole run: PurpleReverseProxy is launchd socket activated and can take longer to listen than libFDR's five second budget, and dropping the ctrl handle makes the daemon answer every later client with "not online".
    let seal = stand_up_seal_server(plan, &boot, port, armed_at_secs, &reporter);
    let mut proxy = reverse_proxy::spawn(
        dialer.link(),
        Arc::clone(&stop),
        Arc::clone(&reporter),
        armed_at_secs,
        seal,
    );

    let _producer_watchdog = spawn_asr_producer_watchdog(
        producer_activity,
        Arc::new(ReporterProducerTrace::new(Arc::clone(&reporter))),
        AsrProducerWatchdogPolicy::default(),
    );

    let mut observer = RamrodTrace::new(port, armed_at_secs, Arc::clone(&reporter));
    let outcome = match client.run_restore(&mut *provider, &mut bulk, &mut observer) {
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
                bulk.fallback().transfers().len(),
                bulk.bundle().transfers().len()
            );
            report(&reporter, "restore-ended", &line);
            RestoreOutcome::Ended {
                summary: Box::new(summary),
                bulk_transfers: bulk.fallback().transfers().len(),
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
                bulk.fallback().transfers().len(),
                bulk.bundle().transfers().len()
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

#[cfg(test)]
mod tests {
    use super::{
        ReporterProducerTrace, RestoreBootContext, RestoreOutcome, run_ramrod_restore_over_mux,
    };
    use crate::asr_server::AsrServerConfig;
    use crate::asr_server::producer::{AsrProducerEvent, AsrProducerSink};
    use crate::restore::RestorePlan;
    use crate::restore::mux::{ClaimedMuxTransport, ClaimedMuxTransportMetadata};
    use crate::restore::report::{RestoreEvent, RestoreReporter, SharedReporter};
    use crate::usbmux::{BulkTransport, MuxDialer, MuxLink, MuxVersion, SharedLink};
    use std::io;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

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
            fdr_trust_digest: None,
            fdr_material_dir: None,
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
}
