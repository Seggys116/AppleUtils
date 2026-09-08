use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use plist::Dictionary;

use crate::ramrod::client::{RamrodClient, connect_and_identify};
use crate::ramrod::dial::{Clock, DialPlan, GuestDialer};
use crate::ramrod::{
    BuildIdentity, DataType, DeviceType, RamrodError, RestoreOptions, bulk_image_entry,
    bulk_image_types, load_build_manifest, resolve_bulk_image,
};

use super::options::{
    DerivedRestoreOptions, ManifestSource, RestoreOptionsError, derive_restore_options,
    resolve_restore_manifest,
};
use super::plan::RestorePlan;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssetKind {
    BuildManifest,
    PrimaryImage,
    ImageRoot,
    BulkImage {
        data_type: String,
        component: String,
    },
    BootabilityBundle,
    GlobalManifestRoot,
    FirmwareRoot,
    FdrMaterialDirectory,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssetState {
    Present,
    Missing,
    NotRequested,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetCheck {
    pub path: PathBuf,
    pub state: AssetState,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetRequirement {
    pub kind: AssetKind,
    pub required: bool,
    pub check: AssetCheck,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedIdentitySummary {
    pub hardware_model: String,
    pub install_index: usize,
    pub install_variant: String,
    pub macos_index: usize,
    pub macos_variant: String,
}

#[derive(Debug)]
pub struct PreparedRestoreSession {
    pub manifest_source: ManifestSource,
    pub manifest_path: PathBuf,
    pub manifest: Dictionary,
    pub derived: DerivedRestoreOptions,
    pub identity: SelectedIdentitySummary,
    pub assets: Vec<AssetRequirement>,
}

pub struct IdentifiedRestoreSession<T> {
    pub client: RamrodClient<T>,
    pub device: DeviceType,
}

#[derive(Debug)]
pub enum RestorePreparationError {
    ManifestResolution(String),
    ManifestLoad(String),
    RestoreOptions(RestoreOptionsError),
}

impl std::fmt::Display for RestorePreparationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ManifestResolution(error) => formatter.write_str(error),
            Self::ManifestLoad(error) => formatter.write_str(error),
            Self::RestoreOptions(error) => formatter.write_str(&error.detail()),
        }
    }
}

impl std::error::Error for RestorePreparationError {}

#[derive(Debug)]
pub enum RestorePhaseError {
    Identify(RamrodError),
    Prepare(RestorePreparationError),
    MissingRequiredAssets { missing: Vec<PathBuf> },
    Start(RamrodError),
}

impl std::fmt::Display for RestorePhaseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Identify(error) | Self::Start(error) => formatter.write_str(&error.to_string()),
            Self::Prepare(error) => formatter.write_str(&error.to_string()),
            Self::MissingRequiredAssets { missing } => {
                let listed = missing
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(formatter, "required restore assets are missing: {listed}")
            }
        }
    }
}

impl std::error::Error for RestorePhaseError {}

fn path_check(path: PathBuf, required: bool, detail: impl Into<String>) -> AssetCheck {
    let state = if required {
        if path.exists() {
            AssetState::Present
        } else {
            AssetState::Missing
        }
    } else if path.exists() {
        AssetState::Present
    } else {
        AssetState::NotRequested
    };
    AssetCheck {
        path,
        state,
        detail: detail.into(),
    }
}

fn advisory_path_check(path: PathBuf, detail: impl Into<String>) -> AssetCheck {
    let state = if path.exists() {
        AssetState::Present
    } else {
        AssetState::Missing
    };
    AssetCheck {
        path,
        state,
        detail: detail.into(),
    }
}

fn image_root(plan: &RestorePlan) -> PathBuf {
    plan.image_root
        .clone()
        .or_else(|| plan.image.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn explicit_bulk_override<'a>(plan: &'a RestorePlan, data_type: &DataType) -> Option<&'a PathBuf> {
    match data_type {
        DataType::SystemImageData => plan.system_image.as_ref(),
        DataType::RecoveryOSASRImage => plan.recovery_image.as_ref(),
        _ => None,
    }
}

fn bulk_requirements(
    plan: &RestorePlan,
    root: &Path,
    identity: &BuildIdentity,
) -> Vec<AssetRequirement> {
    let mut requirements = Vec::new();
    for data_type in bulk_image_types() {
        let Some(entry) = bulk_image_entry(&data_type) else {
            continue;
        };
        if let Some(path) = explicit_bulk_override(plan, &data_type) {
            requirements.push(AssetRequirement {
                kind: AssetKind::BulkImage {
                    data_type: data_type.wire_name().to_string(),
                    component: entry.entry.to_string(),
                },
                required: true,
                check: path_check(
                    path.clone(),
                    true,
                    format!(
                        "resolved from {} via explicit {}",
                        entry.entry, entry.option
                    ),
                ),
            });
            continue;
        }
        match resolve_bulk_image(&entry, identity, root) {
            Ok(resolved) => {
                requirements.push(AssetRequirement {
                    kind: AssetKind::BulkImage {
                        data_type: data_type.wire_name().to_string(),
                        component: entry.entry.to_string(),
                    },
                    required: !entry.allows_default,
                    check: AssetCheck {
                        path: resolved.path,
                        state: AssetState::Present,
                        detail: format!(
                            "resolved from {} as {}",
                            entry.entry,
                            resolved.rule.label()
                        ),
                    },
                });
            }
            Err(error) => {
                let required =
                    !entry.allows_default && !matches!(data_type, DataType::SystemImageData);
                requirements.push(AssetRequirement {
                    kind: AssetKind::BulkImage {
                        data_type: data_type.wire_name().to_string(),
                        component: entry.entry.to_string(),
                    },
                    required,
                    check: AssetCheck {
                        path: root.to_path_buf(),
                        state: if entry.allows_default {
                            AssetState::NotRequested
                        } else {
                            AssetState::Missing
                        },
                        detail: error.to_string(),
                    },
                });
            }
        }
    }
    requirements
}

fn build_prepared_restore_session(
    plan: &RestorePlan,
    manifest_source: ManifestSource,
    manifest_path: PathBuf,
    manifest: Dictionary,
    derived: DerivedRestoreOptions,
    request_global_manifest: bool,
) -> PreparedRestoreSession {
    let root = image_root(plan);
    let mut assets = Vec::new();
    assets.push(AssetRequirement {
        kind: AssetKind::BuildManifest,
        required: true,
        check: AssetCheck {
            path: manifest_path.clone(),
            state: AssetState::Present,
            detail: manifest_source.label().to_string(),
        },
    });
    assets.push(AssetRequirement {
        kind: AssetKind::PrimaryImage,
        required: true,
        check: path_check(
            plan.image.clone(),
            true,
            "the restore image AppleUtils will arm before StartRestore",
        ),
    });
    assets.push(AssetRequirement {
        kind: AssetKind::ImageRoot,
        required: false,
        check: advisory_path_check(
            root.clone(),
            "the directory bulk image resolution runs under",
        ),
    });
    assets.extend(bulk_requirements(plan, &root, &derived.install_identity));

    if let Some(path) = &plan.bootability_bundle {
        assets.push(AssetRequirement {
            kind: AssetKind::BootabilityBundle,
            required: false,
            check: advisory_path_check(
                path.clone(),
                "the BootabilityBundle tree served over its dedicated port",
            ),
        });
    }
    if let Some(path) = &plan.global_manifests {
        assets.push(AssetRequirement {
            kind: AssetKind::GlobalManifestRoot,
            required: false,
            check: if request_global_manifest {
                advisory_path_check(
                    path.clone(),
                    "the extracted Firmware/Manifests/restore root for streamed global manifests",
                )
            } else {
                path_check(
                    path.clone(),
                    false,
                    "the extracted Firmware/Manifests/restore root for streamed global manifests",
                )
            },
        });
    }
    if let Some(path) = &plan.firmware_root {
        assets.push(AssetRequirement {
            kind: AssetKind::FirmwareRoot,
            required: false,
            check: advisory_path_check(
                path.clone(),
                "the extracted IPSW firmware tree for NORData and splat payloads",
            ),
        });
    }
    if let Some(path) = &plan.fdr_material_dir {
        assets.push(AssetRequirement {
            kind: AssetKind::FdrMaterialDirectory,
            required: false,
            check: advisory_path_check(
                path.clone(),
                "the persisted FDR trust material directory for certificate and sealing replies",
            ),
        });
    }

    let identity = SelectedIdentitySummary {
        hardware_model: derived.hardware_model.clone(),
        install_index: derived.install_index,
        install_variant: derived.install_variant.clone(),
        macos_index: derived.macos_index,
        macos_variant: derived.macos_variant.clone(),
    };

    PreparedRestoreSession {
        manifest_source,
        manifest_path,
        manifest,
        derived,
        identity,
        assets,
    }
}

pub fn prepare_restore_session(
    plan: &RestorePlan,
    device: &DeviceType,
) -> Result<PreparedRestoreSession, RestorePreparationError> {
    prepare_restore_session_with_branching(plan, device, false)
}

pub fn prepare_restore_session_with_branching(
    plan: &RestorePlan,
    device: &DeviceType,
    request_global_manifest: bool,
) -> Result<PreparedRestoreSession, RestorePreparationError> {
    let manifest_source =
        resolve_restore_manifest(plan).map_err(RestorePreparationError::ManifestResolution)?;
    let manifest_path = manifest_source.path().to_path_buf();
    let manifest = load_build_manifest(&manifest_path)
        .map_err(|error| RestorePreparationError::ManifestLoad(error.to_string()))?;
    let derived = derive_restore_options(&manifest, device, request_global_manifest, plan.behavior)
        .map_err(RestorePreparationError::RestoreOptions)?;
    Ok(build_prepared_restore_session(
        plan,
        manifest_source,
        manifest_path,
        manifest,
        derived,
        request_global_manifest,
    ))
}

impl PreparedRestoreSession {
    #[must_use]
    pub fn missing_required_assets(&self) -> Vec<PathBuf> {
        self.assets
            .iter()
            .filter(|asset| asset.required && asset.check.state != AssetState::Present)
            .map(|asset| asset.check.path.clone())
            .collect()
    }

    pub fn validate_required_assets(&self) -> Result<(), RestorePhaseError> {
        let missing = self.missing_required_assets();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(RestorePhaseError::MissingRequiredAssets { missing })
        }
    }

    pub fn into_restore_options(self) -> Result<RestoreOptions, RestorePhaseError> {
        self.validate_required_assets()?;
        Ok(self.derived.options)
    }
}

pub fn identify_restore_session<D, C>(
    dialer: &mut D,
    dial_plan: DialPlan,
    clock: &mut C,
) -> Result<IdentifiedRestoreSession<D::Stream>, RamrodError>
where
    D: GuestDialer,
    C: Clock,
{
    let (client, device) = connect_and_identify(dialer, dial_plan, clock)?;
    Ok(IdentifiedRestoreSession { client, device })
}

pub fn query_and_prepare_restore_session<D, C>(
    dialer: &mut D,
    dial_plan: DialPlan,
    clock: &mut C,
    plan: &RestorePlan,
    request_global_manifest: bool,
) -> Result<(IdentifiedRestoreSession<D::Stream>, PreparedRestoreSession), RestorePhaseError>
where
    D: GuestDialer,
    C: Clock,
{
    let identified =
        identify_restore_session(dialer, dial_plan, clock).map_err(RestorePhaseError::Identify)?;
    let prepared =
        prepare_restore_session_with_branching(plan, &identified.device, request_global_manifest)
            .map_err(RestorePhaseError::Prepare)?;
    Ok((identified, prepared))
}

pub fn start_prepared_restore<T>(
    client: &mut RamrodClient<T>,
    prepared: PreparedRestoreSession,
) -> Result<(), RestorePhaseError>
where
    T: Read + Write,
{
    let options = prepared.into_restore_options()?;
    client
        .start_restore(options)
        .map_err(RestorePhaseError::Start)
}

#[cfg(test)]
mod tests {
    use super::{
        AssetKind, AssetState, PreparedRestoreSession, prepare_restore_session,
        prepare_restore_session_with_branching,
    };
    use crate::ramrod::{DeviceType, RestoreBehavior};
    use crate::restore::RestorePlan;
    use plist::{Dictionary, Value};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    fn base_plan(image: PathBuf, manifest: Option<PathBuf>) -> RestorePlan {
        RestorePlan {
            image,
            system_image: None,
            recovery_image: None,
            image_root: None,
            manifest,
            behavior: None,
            port: 62078,
            timeout: Duration::from_secs(35),
            window: Duration::from_secs(600),
            retry: Duration::from_secs(5),
            read_poll: Duration::from_secs(30),
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

    fn manifest(model: &str) -> Value {
        Value::Dictionary(Dictionary::from_iter([(
            "BuildIdentities".to_string(),
            Value::Array(vec![
                build_identity(
                    model,
                    "macOS Customer",
                    "Erase",
                    "Customer Erase Install (IPSW)",
                ),
                build_identity(
                    model,
                    "Customer Erase Install (IPSW)",
                    "Erase",
                    "Customer Erase Install (IPSW)",
                ),
            ]),
        )]))
    }

    fn build_identity(model: &str, variant: &str, behavior: &str, install_variant: &str) -> Value {
        Value::Dictionary(Dictionary::from_iter([
            ("ApBoardID".to_string(), Value::String("0x00".to_string())),
            ("ApChipID".to_string(), Value::String("0x00".to_string())),
            (
                "Info".to_string(),
                Value::Dictionary(Dictionary::from_iter([
                    ("DeviceClass".to_string(), Value::String(model.to_string())),
                    ("Variant".to_string(), Value::String(variant.to_string())),
                    (
                        "RestoreBehavior".to_string(),
                        Value::String(behavior.to_string()),
                    ),
                ])),
            ),
            (
                "Manifest".to_string(),
                Value::Dictionary(Dictionary::from_iter([(
                    "OS".to_string(),
                    Value::Dictionary(Dictionary::from_iter([(
                        "Info".to_string(),
                        Value::Dictionary(Dictionary::from_iter([
                            (
                                "Path".to_string(),
                                Value::String("058-12345-001.dmg".to_string()),
                            ),
                            (
                                "ContentEncoding".to_string(),
                                Value::String("aea".to_string()),
                            ),
                        ])),
                    )])),
                )])),
            ),
            (
                "VariantContents".to_string(),
                Value::Dictionary(Dictionary::from_iter([(
                    "InstalledOSVariant".to_string(),
                    Value::String(install_variant.to_string()),
                )])),
            ),
        ]))
    }

    fn manifest_without_os_component(model: &str) -> Value {
        let mut install = match build_identity(
            model,
            "Customer Erase Install (IPSW)",
            "Erase",
            "Customer Erase Install (IPSW)",
        ) {
            Value::Dictionary(identity) => identity,
            _ => unreachable!("build_identity returns a dictionary"),
        };
        if let Some(Value::Dictionary(manifest)) = install.get_mut("Manifest") {
            manifest.remove("OS");
        }
        Value::Dictionary(Dictionary::from_iter([(
            "BuildIdentities".to_string(),
            Value::Array(vec![
                build_identity(
                    model,
                    "macOS Customer",
                    "Erase",
                    "Customer Erase Install (IPSW)",
                ),
                Value::Dictionary(install),
            ]),
        )]))
    }

    fn write_manifest(path: &Path, manifest: &Value) {
        let mut file = std::fs::File::create(path).expect("manifest file");
        manifest
            .to_writer_xml(&mut file)
            .expect("write manifest xml");
    }

    fn require_bulk_image(prepared: &PreparedRestoreSession, state: AssetState) -> bool {
        prepared.assets.iter().any(|asset| {
            matches!(
                asset.kind,
                AssetKind::BulkImage {
                    ref data_type,
                    ref component
                } if data_type == "RecoveryOSASRImage" && component == "OS"
            ) && asset.check.state == state
        })
    }

    fn bulk_image_asset<'a>(
        prepared: &'a PreparedRestoreSession,
        data_type: &str,
    ) -> &'a super::AssetRequirement {
        prepared
            .assets
            .iter()
            .find(|asset| {
                matches!(
                    asset.kind,
                    AssetKind::BulkImage {
                        data_type: ref asset_type,
                        ..
                    } if asset_type == data_type
                )
            })
            .expect("bulk image asset")
    }

    #[test]
    fn preparation_resolves_manifest_identity_and_assets_before_start_restore() {
        let directory = tempfile::tempdir().expect("tempdir");
        let image = directory.path().join("058-12345-001.dmg");
        let manifest_path = directory.path().join("BuildManifest.plist");
        let resolved = directory.path().join("OS__058-12345-001.dmg");
        std::fs::write(&image, b"image").expect("seed image");
        std::fs::write(&resolved, b"resolved image").expect("resolved image");
        write_manifest(&manifest_path, &manifest("J274AP"));

        let prepared = prepare_restore_session(
            &base_plan(image, Some(manifest_path)),
            &device_reporting("J274AP"),
        )
        .expect("preparation");

        assert_eq!(prepared.identity.hardware_model, "J274AP");
        assert_eq!(
            prepared.identity.install_variant,
            "Customer Erase Install (IPSW)"
        );
        assert!(
            prepared
                .assets
                .iter()
                .any(|asset| matches!(asset.kind, AssetKind::BuildManifest))
        );
        assert!(require_bulk_image(&prepared, AssetState::Present));
    }

    fn manifest_with_upgrade_and_erase(model: &str) -> Value {
        Value::Dictionary(Dictionary::from_iter([(
            "BuildIdentities".to_string(),
            Value::Array(vec![
                build_identity(
                    model,
                    "macOS Customer",
                    "Erase",
                    "Customer Erase Install (IPSW)",
                ),
                build_identity(
                    model,
                    "Customer Upgrade Install (IPSW)",
                    "Update",
                    "Customer Upgrade Install (IPSW)",
                ),
                build_identity(
                    model,
                    "Customer Erase Install (IPSW)",
                    "Erase",
                    "Customer Erase Install (IPSW)",
                ),
            ]),
        )]))
    }

    #[test]
    fn preparation_sends_erase_when_the_plan_names_erase() {
        let directory = tempfile::tempdir().expect("tempdir");
        let image = directory.path().join("058-12345-001.dmg");
        let manifest_path = directory.path().join("BuildManifest.plist");
        let resolved = directory.path().join("OS__058-12345-001.dmg");
        std::fs::write(&image, b"image").expect("seed image");
        std::fs::write(&resolved, b"resolved image").expect("resolved image");
        write_manifest(&manifest_path, &manifest_with_upgrade_and_erase("J274AP"));

        let mut plan = base_plan(image, Some(manifest_path));
        let upgraded =
            prepare_restore_session(&plan, &device_reporting("J274AP")).expect("upgrade default");
        assert_eq!(upgraded.derived.behavior, RestoreBehavior::Update);
        assert_eq!(
            upgraded.identity.install_variant,
            "Customer Upgrade Install (IPSW)"
        );

        plan.behavior = Some(RestoreBehavior::Erase);
        let erased =
            prepare_restore_session(&plan, &device_reporting("J274AP")).expect("erase pick");
        assert_eq!(erased.derived.behavior, RestoreBehavior::Erase);
        assert_eq!(
            erased.identity.install_variant,
            "Customer Erase Install (IPSW)"
        );
        let body = erased
            .derived
            .options
            .into_value()
            .expect("options")
            .as_dictionary()
            .cloned()
            .expect("dictionary");
        assert_eq!(
            body.get("AuthInstallVariant").and_then(Value::as_string),
            Some("Customer Erase Install (IPSW)")
        );
        assert_eq!(
            body.get("AuthInstallRestoreBehavior")
                .and_then(Value::as_string),
            Some("Erase")
        );
    }

    #[test]
    fn preparation_reports_missing_bulk_images_without_guessing_substitutes() {
        let directory = tempfile::tempdir().expect("tempdir");
        let image = directory.path().join("058-12345-001.dmg");
        let manifest_path = directory.path().join("BuildManifest.plist");
        write_manifest(&manifest_path, &manifest("J274AP"));

        let prepared = prepare_restore_session(
            &base_plan(image, Some(manifest_path)),
            &device_reporting("J274AP"),
        )
        .expect("preparation");

        assert!(prepared.assets.iter().any(|asset| {
            matches!(asset.kind, AssetKind::PrimaryImage)
                && asset.check.state == AssetState::Missing
        }));
        assert!(require_bulk_image(&prepared, AssetState::NotRequested));
    }

    #[test]
    fn preparation_marks_global_manifest_root_required_only_when_requested() {
        let directory = tempfile::tempdir().expect("tempdir");
        let image = directory.path().join("058-12345-001.dmg");
        let manifest_path = directory.path().join("BuildManifest.plist");
        let global = directory.path().join("Firmware/Manifests/restore");
        std::fs::write(&image, b"image").expect("seed image");
        write_manifest(&manifest_path, &manifest("J274AP"));

        let mut plan = base_plan(image, Some(manifest_path));
        plan.global_manifests = Some(global);

        let prepared =
            prepare_restore_session_with_branching(&plan, &device_reporting("J274AP"), false)
                .expect("preparation");
        assert!(prepared.assets.iter().any(|asset| {
            matches!(asset.kind, AssetKind::GlobalManifestRoot)
                && asset.check.state == AssetState::NotRequested
        }));
    }

    #[test]
    fn preparation_prefers_explicit_bulk_image_overrides_to_manifest_resolution() {
        let directory = tempfile::tempdir().expect("tempdir");
        let image = directory.path().join("058-12345-001.dmg");
        let manifest_path = directory.path().join("BuildManifest.plist");
        let manifest_resolved = directory.path().join("OS__058-12345-001.dmg");
        let explicit_system = directory.path().join("explicit-system.dmg");
        let explicit_recovery = directory.path().join("explicit-recovery.dmg");
        std::fs::write(&image, b"image").expect("seed image");
        std::fs::write(&manifest_resolved, b"manifest image").expect("manifest image");
        std::fs::write(&explicit_system, b"explicit system").expect("explicit system");
        std::fs::write(&explicit_recovery, b"explicit recovery").expect("explicit recovery");
        write_manifest(&manifest_path, &manifest("J274AP"));

        let mut plan = base_plan(image, Some(manifest_path));
        plan.system_image = Some(explicit_system.clone());
        plan.recovery_image = Some(explicit_recovery.clone());

        let prepared =
            prepare_restore_session(&plan, &device_reporting("J274AP")).expect("preparation");

        let system = bulk_image_asset(&prepared, "SystemImageData");
        assert_eq!(system.check.path, explicit_system);
        assert_eq!(system.check.state, AssetState::Present);
        let recovery = bulk_image_asset(&prepared, "RecoveryOSASRImage");
        assert_eq!(recovery.check.path, explicit_recovery);
        assert_eq!(recovery.check.state, AssetState::Present);
    }

    #[test]
    fn preparation_defers_missing_system_image_manifest_component_until_requested() {
        let directory = tempfile::tempdir().expect("tempdir");
        let image = directory.path().join("058-12345-001.dmg");
        let manifest_path = directory.path().join("BuildManifest.plist");
        std::fs::write(&image, b"image").expect("seed image");
        write_manifest(&manifest_path, &manifest_without_os_component("J274AP"));

        let prepared = prepare_restore_session(
            &base_plan(image, Some(manifest_path)),
            &device_reporting("J274AP"),
        )
        .expect("preparation");

        let system = bulk_image_asset(&prepared, "SystemImageData");
        assert_eq!(system.check.state, AssetState::Missing);
        assert!(!system.required);
        prepared
            .validate_required_assets()
            .expect("missing SystemImageData should not block StartRestore");
    }

    #[test]
    fn stale_bootability_and_provider_roots_do_not_block_preflight() {
        let directory = tempfile::tempdir().expect("tempdir");
        let image = directory.path().join("058-12345-001.dmg");
        let manifest_path = directory.path().join("BuildManifest.plist");
        let resolved = directory.path().join("OS__058-12345-001.dmg");
        std::fs::write(&image, b"image").expect("seed image");
        std::fs::write(&resolved, b"resolved image").expect("resolved image");
        write_manifest(&manifest_path, &manifest("J274AP"));

        let mut plan = base_plan(image, Some(manifest_path));
        plan.image_root = Some(directory.path().join("missing-image-root"));
        plan.bootability_bundle = Some(directory.path().join("missing-bundle"));
        plan.global_manifests = Some(directory.path().join("missing-global-manifests"));
        plan.firmware_root = Some(directory.path().join("missing-firmware-root"));
        plan.fdr_material_dir = Some(directory.path().join("missing-fdr-material"));

        let prepared =
            prepare_restore_session_with_branching(&plan, &device_reporting("J274AP"), true)
                .expect("preparation");

        assert!(prepared.assets.iter().any(|asset| {
            matches!(asset.kind, AssetKind::BootabilityBundle)
                && asset.check.state == AssetState::Missing
                && !asset.required
        }));
        assert!(prepared.assets.iter().any(|asset| {
            matches!(asset.kind, AssetKind::GlobalManifestRoot)
                && asset.check.state == AssetState::Missing
                && !asset.required
        }));
        assert!(prepared.assets.iter().any(|asset| {
            matches!(asset.kind, AssetKind::FirmwareRoot)
                && asset.check.state == AssetState::Missing
                && !asset.required
        }));
        assert!(prepared.assets.iter().any(|asset| {
            matches!(asset.kind, AssetKind::FdrMaterialDirectory)
                && asset.check.state == AssetState::Missing
                && !asset.required
        }));
        assert!(prepared.assets.iter().any(|asset| {
            matches!(asset.kind, AssetKind::ImageRoot)
                && asset.check.state == AssetState::Missing
                && !asset.required
        }));
        prepared
            .validate_required_assets()
            .expect("stale advisory roots should not block StartRestore");
    }
}
