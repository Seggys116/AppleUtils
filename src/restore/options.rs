use std::path::{Path, PathBuf};

use crate::ramrod::{
    BUILD_MANIFEST_FILE_NAME, BuildIdentity, DeviceType, IdentityError, OptionsReport,
    RestoreBehavior, RestoreOptions, generate_session_uuid, macos_restore_options,
    mobile_restore_options, select_install_identity, select_macos_identity,
    select_recovery_identity,
};

use super::plan::RestorePlan;
use super::seal_server::service_base_url;

pub const FDR_MEMORY_STORE_PATH_KEY: &str = "FDRMemoryStorePath";

pub const FDR_MEMORY_STORE_PATH: &str = "/private/var/tmp/appleutils-fdr-memory-store";

pub const FDR_CA_URL_KEY: &str = "FDRCAURL";

pub const FDR_DATA_STORE_URL_KEY: &str = "FDRDataStoreURL";

pub const FDR_SEALING_URL_KEY: &str = "FDRSealingURL";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestSource {
    Named(PathBuf),
    BesideImage(PathBuf),
}

impl ManifestSource {
    pub fn path(&self) -> &Path {
        match self {
            Self::Named(path) | Self::BesideImage(path) => path,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Named(_) => "flag",
            Self::BesideImage(_) => "beside-image",
        }
    }
}

pub fn resolve_restore_manifest(plan: &RestorePlan) -> Result<ManifestSource, String> {
    if let Some(named) = &plan.manifest {
        return Ok(ManifestSource::Named(named.clone()));
    }
    let beside = plan
        .image
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(BUILD_MANIFEST_FILE_NAME);
    if beside.is_file() {
        return Ok(ManifestSource::BesideImage(beside));
    }
    Err(format!(
        "--asr-serve-manifest was not given and no {BUILD_MANIFEST_FILE_NAME} sits beside the image at {}",
        beside.display()
    ))
}

pub fn manifest_identity_count(manifest: &plist::Dictionary) -> usize {
    manifest
        .get("BuildIdentities")
        .and_then(plist::Value::as_array)
        .map_or(0, Vec::len)
}

#[derive(Clone, Debug, PartialEq)]
pub struct DerivedRestoreOptions {
    pub options: RestoreOptions,
    pub report: OptionsReport,
    pub hardware_model: String,
    pub behavior: RestoreBehavior,
    pub install_index: usize,
    pub install_variant: String,
    pub recovery_index: Option<usize>,
    pub recovery_variant: Option<String>,
    pub is_macos: bool,
    pub session_uuid: String,
    pub install_identity: BuildIdentity,
    pub recovery_identity: Option<BuildIdentity>,
}

impl DerivedRestoreOptions {
    pub(crate) fn with_local_fdr_service(mut self) -> Self {
        let base = service_base_url();
        let keys = [FDR_CA_URL_KEY, FDR_DATA_STORE_URL_KEY, FDR_SEALING_URL_KEY];
        for key in keys {
            self.options = self
                .options
                .with_value(key, plist::Value::String(base.clone()));
            if !self.report.keys.iter().any(|sent| sent == key) {
                self.report.keys.push(key.to_string());
            }
        }
        self.report
            .withheld
            .retain(|(key, _)| !keys.contains(&key.as_str()));
        self.report.keys.sort();
        self
    }
}

#[derive(Debug)]
pub enum RestoreOptionsError {
    NoHardwareModel {
        reply_keys: Vec<String>,
    },
    NoMacosIdentity {
        hardware_model: String,
        identities: usize,
    },
    NoRecoveryIdentity {
        hardware_model: String,
        variant: String,
        error: IdentityError,
    },
    NoRestoreBehavior {
        hardware_model: String,
        identity_index: usize,
    },
    NoInstallIdentity {
        hardware_model: String,
        behavior: RestoreBehavior,
        error: IdentityError,
    },
    NoSessionUuid {
        error: std::io::Error,
    },
}

impl RestoreOptionsError {
    pub fn label(&self) -> &'static str {
        match self {
            Self::NoHardwareModel { .. } => "no-hardware-model",
            Self::NoMacosIdentity { .. } => "no-macos-identity",
            Self::NoRecoveryIdentity { .. } => "no-recovery-identity",
            Self::NoRestoreBehavior { .. } => "no-restore-behavior",
            Self::NoInstallIdentity { .. } => "no-install-identity",
            Self::NoSessionUuid { .. } => "no-session-uuid",
        }
    }

    pub fn meaning(&self) -> &'static str {
        match self {
            Self::NoHardwareModel { .. } => {
                "the QueryType reply carried no HardwareModel, so no build identity can be matched; the restore is not started"
            }
            Self::NoMacosIdentity { .. } => {
                "the manifest carries no macOS Customer identity for this model, so the macOS restore options do not apply and no substitute is sent; the restore is not started"
            }
            Self::NoRecoveryIdentity { .. } => {
                "the install identity names a recovery variant that cannot be matched for this model; the restore is not started"
            }
            Self::NoRestoreBehavior { .. } => {
                "the macOS identity carries no Info/RestoreBehavior, and erase versus update is not a host choice to invent; the restore is not started"
            }
            Self::NoInstallIdentity { .. } => {
                "no install identity matched, so the partition sizes and the padding have no source; the restore is not started"
            }
            Self::NoSessionUuid { .. } => {
                "the host entropy behind the session UUID could not be read, and a predictable one is not substituted; the restore is not started"
            }
        }
    }

    pub fn detail(&self) -> String {
        match self {
            Self::NoHardwareModel { reply_keys } => {
                format!("reply_keys=[{}]", reply_keys.join(","))
            }
            Self::NoMacosIdentity {
                hardware_model,
                identities,
            } => format!("model={hardware_model} identities={identities}"),
            Self::NoRecoveryIdentity {
                hardware_model,
                variant,
                error,
            } => {
                format!("model={hardware_model} recovery_variant={variant}: {error}")
            }
            Self::NoRestoreBehavior {
                hardware_model,
                identity_index,
            } => format!("model={hardware_model} macos_index={identity_index}"),
            Self::NoInstallIdentity {
                hardware_model,
                behavior,
                error,
            } => format!("model={hardware_model} behavior={behavior}: {error}"),
            Self::NoSessionUuid { error } => error.to_string(),
        }
    }
}

pub fn derive_restore_options(
    manifest: &plist::Dictionary,
    device: &DeviceType,
    request_global_manifest: bool,
    behavior: Option<RestoreBehavior>,
) -> Result<DerivedRestoreOptions, RestoreOptionsError> {
    let hardware_model = device
        .string("HardwareModel")
        .map(str::to_string)
        .ok_or_else(|| RestoreOptionsError::NoHardwareModel {
            reply_keys: device.body.keys().cloned().collect(),
        })?;
    let behavior = match behavior {
        Some(behavior) => behavior,
        None => crate::ramrod::install_behaviors_for_board(manifest, &hardware_model)
            .into_iter()
            .next()
            .ok_or_else(|| RestoreOptionsError::NoInstallIdentity {
                hardware_model: hardware_model.clone(),
                behavior: RestoreBehavior::Update,
                error: IdentityError::NoVariant {
                    hardware_model: hardware_model.clone(),
                    wanted: "Upgrade Install (IPSW) or Erase Install (IPSW)".into(),
                },
            })?,
    };
    let install =
        select_install_identity(manifest, &hardware_model, behavior).map_err(|error| {
            RestoreOptionsError::NoInstallIdentity {
                hardware_model: hardware_model.clone(),
                behavior,
                error,
            }
        })?;
    let behavior = install.restore_behavior().unwrap_or(behavior);
    let session_uuid =
        generate_session_uuid().map_err(|error| RestoreOptionsError::NoSessionUuid { error })?;
    let macos = select_macos_identity(manifest, &hardware_model);
    let is_macos = macos.is_some() || install.info_string("MacOSVariant").is_some();
    let recovery = if is_macos {
        Some(macos.ok_or_else(|| RestoreOptionsError::NoMacosIdentity {
            hardware_model: hardware_model.clone(),
            identities: manifest_identity_count(manifest),
        })?)
    } else if let Some(variant) = install.info_string("RecoveryVariant") {
        Some(
            select_recovery_identity(manifest, &hardware_model, variant).map_err(|error| {
                RestoreOptionsError::NoRecoveryIdentity {
                    hardware_model: hardware_model.clone(),
                    variant: variant.to_string(),
                    error,
                }
            })?,
        )
    } else {
        None
    };
    let (options, mut report) = if is_macos {
        macos_restore_options(
            &install,
            recovery.as_ref().expect("macOS recovery identity"),
            behavior,
            &session_uuid,
            request_global_manifest,
        )
    } else {
        mobile_restore_options(
            &install,
            recovery.as_ref(),
            behavior,
            &session_uuid,
            request_global_manifest,
        )
    };
    let options = options.with_value(
        FDR_MEMORY_STORE_PATH_KEY,
        plist::Value::String(FDR_MEMORY_STORE_PATH.to_string()),
    );
    report.keys.push(FDR_MEMORY_STORE_PATH_KEY.to_string());
    for key in [FDR_CA_URL_KEY, FDR_DATA_STORE_URL_KEY, FDR_SEALING_URL_KEY] {
        report.withheld.push((
            key.to_string(),
            "recovery image supplies the service endpoint",
        ));
    }
    report.keys.sort();
    Ok(DerivedRestoreOptions {
        options,
        report,
        hardware_model,
        behavior,
        install_index: install.index,
        install_variant: install.variant.clone(),
        recovery_index: recovery.as_ref().map(|identity| identity.index),
        recovery_variant: recovery.as_ref().map(|identity| identity.variant.clone()),
        is_macos,
        session_uuid,
        install_identity: install,
        recovery_identity: recovery,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        FDR_MEMORY_STORE_PATH, FDR_MEMORY_STORE_PATH_KEY, ManifestSource, RestoreOptionsError,
        derive_restore_options, manifest_identity_count, resolve_restore_manifest,
    };
    use crate::ramrod::{
        BUILD_MANIFEST_FILE_NAME, DeviceType, IdentityError, RestoreBehavior, RestoreOptions,
    };
    use crate::restore::RestorePlan;
    use std::path::PathBuf;
    use std::time::Duration;

    fn asr_serve_plan_for(image: PathBuf, manifest: Option<PathBuf>) -> RestorePlan {
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
            staged_boot_manifest: None,
            fdr_trust_digest: None,
            restore_ramdisk: None,
            fdr_material_dir: None,
            sign_recovery_os_local_policy: false,
        }
    }

    #[test]
    fn a_named_manifest_is_used_even_when_one_sits_beside_the_image() {
        let directory = tempfile::tempdir().unwrap();
        let beside = directory.path().join(BUILD_MANIFEST_FILE_NAME);
        std::fs::write(&beside, b"beside").unwrap();
        let named = directory.path().join("other-BuildManifest.plist");
        let plan = asr_serve_plan_for(directory.path().join("rosi.dmg"), Some(named.clone()));
        assert_eq!(
            resolve_restore_manifest(&plan),
            Ok(ManifestSource::Named(named))
        );
    }

    #[test]
    fn a_named_manifest_that_does_not_exist_is_still_the_one_reported() {
        let directory = tempfile::tempdir().unwrap();
        let named = directory.path().join("absent-BuildManifest.plist");
        let plan = asr_serve_plan_for(directory.path().join("rosi.dmg"), Some(named.clone()));
        let source = resolve_restore_manifest(&plan).expect("a named path resolves regardless");
        assert_eq!(source.path(), named);
        assert_eq!(source.label(), "flag");
    }

    #[test]
    fn an_unnamed_manifest_is_looked_for_beside_the_image() {
        let directory = tempfile::tempdir().unwrap();
        let beside = directory.path().join(BUILD_MANIFEST_FILE_NAME);
        std::fs::write(&beside, b"beside").unwrap();
        let plan = asr_serve_plan_for(directory.path().join("rosi.dmg"), None);
        let source = resolve_restore_manifest(&plan).expect("the sibling manifest resolves");
        assert_eq!(source.path(), beside);
        assert_eq!(source.label(), "beside-image");
    }

    #[test]
    fn no_manifest_anywhere_names_both_places_rather_than_falling_back() {
        let directory = tempfile::tempdir().unwrap();
        let plan = asr_serve_plan_for(directory.path().join("rosi.dmg"), None);
        let error = match resolve_restore_manifest(&plan) {
            Ok(source) => panic!("expected no manifest, got {source:?}"),
            Err(error) => error,
        };
        assert!(error.contains("--asr-serve-manifest"), "{error}");
        assert!(error.contains(BUILD_MANIFEST_FILE_NAME), "{error}");
        assert!(
            error.contains(&directory.path().display().to_string()),
            "{error}"
        );
    }

    #[test]
    fn a_directory_beside_the_image_is_not_mistaken_for_a_manifest() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join(BUILD_MANIFEST_FILE_NAME)).unwrap();
        let plan = asr_serve_plan_for(directory.path().join("rosi.dmg"), None);
        assert!(resolve_restore_manifest(&plan).is_err());
    }

    fn restore_manifest_for(model: &str) -> plist::Dictionary {
        let identity = |variant: &str| {
            let mut info = plist::Dictionary::new();
            info.insert("DeviceClass".into(), plist::Value::String(model.into()));
            info.insert("Variant".into(), plist::Value::String(variant.into()));
            info.insert(
                "MacOSVariant".into(),
                plist::Value::String("macOS Customer".into()),
            );
            info.insert(
                "MinimumSystemPartition".into(),
                plist::Value::Integer(11977.into()),
            );
            info.insert(
                "OSVarContentSize".into(),
                plist::Value::Integer(831_619_072.into()),
            );
            info.insert(
                "RestoreBehavior".into(),
                plist::Value::String("Erase".into()),
            );
            info.insert(
                "SystemPartitionPadding".into(),
                plist::Value::Dictionary(plist::Dictionary::new()),
            );
            let mut entry = plist::Dictionary::new();
            entry.insert("Info".into(), plist::Value::Dictionary(info));
            entry.insert(
                "Manifest".into(),
                plist::Value::Dictionary(plist::Dictionary::new()),
            );
            plist::Value::Dictionary(entry)
        };
        let mut root = plist::Dictionary::new();
        root.insert(
            "BuildIdentities".into(),
            plist::Value::Array(vec![
                identity("Customer Erase Install (IPSW)"),
                identity("macOS Customer"),
            ]),
        );
        root
    }

    fn device_reporting(model: Option<&str>) -> DeviceType {
        let mut body = plist::Dictionary::new();
        body.insert(
            "Type".into(),
            plist::Value::String("com.apple.mobile.restored".into()),
        );
        if let Some(model) = model {
            body.insert("HardwareModel".into(), plist::Value::String(model.into()));
        }
        DeviceType {
            service_type: "com.apple.mobile.restored".to_string(),
            protocol_version: Some(15),
            body,
        }
    }

    fn serialized_start_restore_options(options: RestoreOptions) -> plist::Dictionary {
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

    fn assert_image_fetch_capabilities(body: &plist::Dictionary) {
        let data = body["SupportedDataTypes"].as_dictionary().unwrap();
        assert_eq!(data["URLAsset"].as_boolean(), Some(true));
        assert_eq!(data["StreamedImageDecryptionKey"].as_boolean(), Some(false));
        assert_eq!(data["SystemImageData"].as_boolean(), Some(false));
        assert_eq!(data["RecoveryOSASRImage"].as_boolean(), Some(true));
        let asynchronous = body["SupportedAsyncDataTypes"].as_dictionary().unwrap();
        assert_eq!(asynchronous["URLAsset"].as_boolean(), Some(true));
        for name in [
            "StreamedImageDecryptionKey",
            "SystemImageData",
            "RecoveryOSASRImage",
        ] {
            assert_eq!(asynchronous[name].as_boolean(), Some(false), "{name}");
        }
        let messages = body["SupportedMessageTypes"].as_dictionary().unwrap();
        assert_eq!(messages["AsyncDataRequestMsg"].as_boolean(), Some(true));
        assert_eq!(messages["AsyncWait"].as_boolean(), Some(true));
        assert_eq!(
            body["SupportedHostProtocols"].as_array().unwrap(),
            &vec![plist::Value::String("MuxSocket".into())]
        );
    }

    #[test]
    fn the_options_are_derived_from_the_model_the_guest_reported() {
        for model in ["J274AP", "J413AP", "J714AP", "J815AP"] {
            let manifest = restore_manifest_for(&model.to_lowercase());
            let derived = match derive_restore_options(
                &manifest,
                &device_reporting(Some(model)),
                false,
                None,
            ) {
                Ok(derived) => derived,
                Err(error) => panic!("{model} did not derive: {}", error.detail()),
            };
            assert_eq!(derived.hardware_model, model);
            assert_eq!(derived.recovery_variant.as_deref(), Some("macOS Customer"));
            assert_eq!(derived.install_variant, "Customer Erase Install (IPSW)");
            assert_eq!(derived.behavior.wire_name(), "Erase");
            assert!(!derived.session_uuid.is_empty());
            let body = serialized_start_restore_options(derived.options);
            assert_eq!(
                body.get("AuthInstallRecoveryOSVariant")
                    .unwrap()
                    .as_string(),
                Some("macOS Customer")
            );
            assert_eq!(
                body.get("SystemPartitionSize").unwrap().as_signed_integer(),
                Some(11977)
            );
            assert_image_fetch_capabilities(&body);
            for key in ["SupportedDataTypes", "SupportedAsyncDataTypes"] {
                assert!(derived.report.keys.iter().any(|sent| sent == key), "{key}");
            }
            // Must stay present: absent makes cleanup_send_crash_logs dereference NULL in the guest.
            assert!(body.contains_key("SupportedMessageTypes"));
            assert_eq!(
                body.get(FDR_MEMORY_STORE_PATH_KEY)
                    .and_then(plist::Value::as_string),
                Some(FDR_MEMORY_STORE_PATH)
            );
            assert!(
                derived
                    .report
                    .keys
                    .iter()
                    .any(|key| key == FDR_MEMORY_STORE_PATH_KEY)
            );
            assert!(
                derived
                    .report
                    .keys
                    .windows(2)
                    .all(|pair| pair[0] <= pair[1]),
                "the reported key list is sorted"
            );
        }
    }

    #[test]
    fn the_memory_store_is_selected_and_no_check_weakening_option_travels_with_it() {
        let manifest = restore_manifest_for("j274ap");
        let derived =
            match derive_restore_options(&manifest, &device_reporting(Some("J274AP")), false, None)
            {
                Ok(derived) => derived,
                Err(error) => panic!("the options did not derive: {}", error.detail()),
            };
        let body = derived.options.into_value().unwrap();
        let body = body.as_dictionary().unwrap();
        assert!(body.contains_key(FDR_MEMORY_STORE_PATH_KEY));
        for forbidden in [
            "FDRIgnoreDevBoardFailures",
            "FDRSkipSealing",
            "AllowIncompleteData",
            "SealingManifestIsMinimal",
            "LocalSigning",
        ] {
            assert!(
                !body.contains_key(forbidden),
                "{forbidden} must never be sent"
            );
        }
    }

    #[test]
    fn a_guest_that_reports_no_model_is_named_rather_than_guessed_at() {
        let manifest = restore_manifest_for("j274ap");
        let error = match derive_restore_options(&manifest, &device_reporting(None), false, None) {
            Ok(_) => panic!("a reply with no HardwareModel must not derive options"),
            Err(error) => error,
        };
        assert_eq!(error.label(), "no-hardware-model");
        assert!(error.detail().contains("Type"), "{}", error.detail());
    }

    #[test]
    fn a_manifest_without_a_macos_identity_stops_the_restore_rather_than_shrinking_it() {
        let mut manifest = restore_manifest_for("j274ap");
        manifest
            .get_mut("BuildIdentities")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .pop();
        let error =
            match derive_restore_options(&manifest, &device_reporting(Some("J274AP")), false, None)
            {
                Ok(_) => panic!("a manifest with no macOS identity must not derive options"),
                Err(error) => error,
            };
        assert_eq!(error.label(), "no-macos-identity");
        assert!(error.detail().contains("J274AP"), "{}", error.detail());
    }

    #[test]
    fn a_model_the_manifest_does_not_carry_is_named_with_the_model() {
        let manifest = restore_manifest_for("j274ap");
        let error =
            match derive_restore_options(&manifest, &device_reporting(Some("J999AP")), false, None)
            {
                Ok(_) => panic!("a model the manifest does not carry must not derive options"),
                Err(error) => error,
            };
        assert_eq!(error.label(), "no-install-identity");
        assert!(error.detail().contains("J999AP"));
    }

    #[test]
    fn a_missing_restore_behaviour_field_still_selects_the_install_variant() {
        let mut manifest = restore_manifest_for("j274ap");
        for entry in manifest
            .get_mut("BuildIdentities")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .iter_mut()
        {
            entry
                .as_dictionary_mut()
                .unwrap()
                .get_mut("Info")
                .unwrap()
                .as_dictionary_mut()
                .unwrap()
                .remove("RestoreBehavior");
        }
        let derived =
            match derive_restore_options(&manifest, &device_reporting(Some("J274AP")), false, None)
            {
                Ok(derived) => derived,
                Err(error) => panic!("variant match must still select erase: {}", error.detail()),
            };
        assert_eq!(derived.behavior, RestoreBehavior::Erase);
        assert_eq!(derived.install_variant, "Customer Erase Install (IPSW)");
    }

    #[test]
    fn upgrade_is_the_default_when_both_install_identities_exist() {
        let mut manifest = restore_manifest_for("j274ap");
        let mut info = plist::Dictionary::new();
        info.insert("DeviceClass".into(), plist::Value::String("j274ap".into()));
        info.insert(
            "Variant".into(),
            plist::Value::String("Customer Upgrade Install (IPSW)".into()),
        );
        info.insert(
            "RestoreBehavior".into(),
            plist::Value::String("Update".into()),
        );
        info.insert(
            "MinimumSystemPartition".into(),
            plist::Value::Integer(11977.into()),
        );
        info.insert(
            "OSVarContentSize".into(),
            plist::Value::Integer(831_619_072.into()),
        );
        info.insert(
            "SystemPartitionPadding".into(),
            plist::Value::Dictionary(plist::Dictionary::new()),
        );
        let mut entry = plist::Dictionary::new();
        entry.insert("Info".into(), plist::Value::Dictionary(info));
        entry.insert(
            "Manifest".into(),
            plist::Value::Dictionary(plist::Dictionary::new()),
        );
        manifest
            .get_mut("BuildIdentities")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .insert(0, plist::Value::Dictionary(entry));

        let default =
            derive_restore_options(&manifest, &device_reporting(Some("J274AP")), false, None)
                .unwrap();
        assert_eq!(default.behavior, RestoreBehavior::Update);
        assert_eq!(default.install_variant, "Customer Upgrade Install (IPSW)");

        let erased = derive_restore_options(
            &manifest,
            &device_reporting(Some("J274AP")),
            false,
            Some(RestoreBehavior::Erase),
        )
        .unwrap();
        assert_eq!(erased.behavior, RestoreBehavior::Erase);
        assert_eq!(erased.install_variant, "Customer Erase Install (IPSW)");
    }

    fn mobile_manifest_for(model: &str) -> plist::Dictionary {
        let mut manifest = restore_manifest_for(model);
        let entries = manifest
            .get_mut("BuildIdentities")
            .unwrap()
            .as_array_mut()
            .unwrap();
        for entry in entries.iter_mut() {
            entry
                .as_dictionary_mut()
                .unwrap()
                .get_mut("Info")
                .unwrap()
                .as_dictionary_mut()
                .unwrap()
                .remove("MacOSVariant");
        }
        let info = entries[0]
            .as_dictionary_mut()
            .unwrap()
            .get_mut("Info")
            .unwrap()
            .as_dictionary_mut()
            .unwrap();
        info.insert(
            "RecoveryVariant".to_string(),
            plist::Value::String("Recovery Customer Install".to_string()),
        );
        info.insert(
            "ContentEncoding".to_string(),
            plist::Value::String("aea".to_string()),
        );
        entries[1]
            .as_dictionary_mut()
            .unwrap()
            .get_mut("Info")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert(
                "Variant".to_string(),
                plist::Value::String("Recovery Customer Install".to_string()),
            );
        manifest
    }

    #[test]
    fn mobile_options_follow_the_declared_recovery_identity() {
        let manifest = mobile_manifest_for("j620ap");
        let derived = derive_restore_options(
            &manifest,
            &device_reporting(Some("J620AP")),
            false,
            Some(RestoreBehavior::Erase),
        )
        .unwrap();
        assert_eq!(derived.install_index, 0);
        assert_eq!(derived.recovery_index, Some(1));
        assert_eq!(
            derived.recovery_variant.as_deref(),
            Some("Recovery Customer Install")
        );
        let session_uuid = derived.session_uuid.clone();
        let body = serialized_start_restore_options(derived.options);
        assert_image_fetch_capabilities(&body);
        assert_eq!(
            body["AuthInstallVariant"].as_string(),
            Some("Customer Erase Install (IPSW)")
        );
        assert_eq!(
            body["AuthInstallRestoreBehavior"].as_string(),
            Some("Erase")
        );
        assert_eq!(body["UUID"].as_string(), Some(session_uuid.as_str()));
        assert_eq!(
            body[FDR_MEMORY_STORE_PATH_KEY].as_string(),
            Some(FDR_MEMORY_STORE_PATH)
        );
        assert_eq!(body["CreateFilesystemPartitions"].as_boolean(), Some(true));
        assert_eq!(body["SystemImage"].as_boolean(), Some(true));
        assert!(body["SystemPartitionPadding"].as_dictionary().is_some());
        assert_eq!(
            body["AuthInstallRecoveryOSVariant"].as_string(),
            Some("Recovery Customer Install")
        );
        assert_eq!(
            body["SystemImageFormat"].as_string(),
            Some("AEAWrappedDiskImage")
        );
        assert_eq!(body["SystemImageType"].as_string(), Some("User"));
        assert_eq!(body["SystemPartitionSize"].as_signed_integer(), Some(11977));
    }

    #[test]
    fn recovery_service_defaults_are_reported_for_both_identity_families() {
        for (model, manifest) in [
            ("J620AP", mobile_manifest_for("j620ap")),
            ("J274AP", restore_manifest_for("j274ap")),
        ] {
            let derived = derive_restore_options(
                &manifest,
                &device_reporting(Some(model)),
                false,
                Some(RestoreBehavior::Erase),
            )
            .unwrap();
            for key in [
                super::FDR_CA_URL_KEY,
                super::FDR_DATA_STORE_URL_KEY,
                super::FDR_SEALING_URL_KEY,
            ] {
                assert!(
                    derived.report.withheld.iter().any(|(reported, reason)| {
                        reported == key && *reason == "recovery image supplies the service endpoint"
                    }),
                    "{model}: {key}"
                );
            }
            let body = serialized_start_restore_options(derived.options);
            assert_eq!(
                body[FDR_MEMORY_STORE_PATH_KEY].as_string(),
                Some(FDR_MEMORY_STORE_PATH)
            );
        }
    }

    #[test]
    fn an_armed_local_service_supplies_each_reported_endpoint() {
        for (model, manifest) in [
            ("J620AP", mobile_manifest_for("j620ap")),
            ("J274AP", restore_manifest_for("j274ap")),
        ] {
            let derived = derive_restore_options(
                &manifest,
                &device_reporting(Some(model)),
                false,
                Some(RestoreBehavior::Erase),
            )
            .unwrap()
            .with_local_fdr_service()
            .with_local_fdr_service();
            let body = serialized_start_restore_options(derived.options);
            let base = super::service_base_url();
            for key in [
                super::FDR_CA_URL_KEY,
                super::FDR_DATA_STORE_URL_KEY,
                super::FDR_SEALING_URL_KEY,
            ] {
                assert_eq!(body[key].as_string(), Some(base.as_str()));
                assert_eq!(
                    derived
                        .report
                        .keys
                        .iter()
                        .filter(|reported| *reported == key)
                        .count(),
                    1
                );
            }
            assert_eq!(
                body[FDR_MEMORY_STORE_PATH_KEY].as_string(),
                Some(FDR_MEMORY_STORE_PATH)
            );
        }
    }

    #[test]
    fn an_unresolved_declared_recovery_variant_is_refused_by_name() {
        let mut manifest = mobile_manifest_for("j620ap");
        let entries = manifest
            .get_mut("BuildIdentities")
            .unwrap()
            .as_array_mut()
            .unwrap();
        entries[0]
            .as_dictionary_mut()
            .unwrap()
            .get_mut("Info")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert(
                "RecoveryVariant".to_string(),
                plist::Value::String("Recovery Research Install".to_string()),
            );
        let error = derive_restore_options(
            &manifest,
            &device_reporting(Some("J620AP")),
            false,
            Some(RestoreBehavior::Erase),
        )
        .unwrap_err();
        assert_eq!(error.label(), "no-recovery-identity");
        assert!(error.detail().contains("Recovery Research Install"));
        assert!(error.detail().contains("J620AP"));
    }

    #[test]
    fn every_derivation_failure_has_its_own_label_and_meaning() {
        let failures = [
            RestoreOptionsError::NoHardwareModel { reply_keys: vec![] },
            RestoreOptionsError::NoMacosIdentity {
                hardware_model: "J274AP".into(),
                identities: 3,
            },
            RestoreOptionsError::NoRestoreBehavior {
                hardware_model: "J274AP".into(),
                identity_index: 113,
            },
            RestoreOptionsError::NoInstallIdentity {
                hardware_model: "J274AP".into(),
                behavior: RestoreBehavior::Erase,
                error: IdentityError::NoIdentities,
            },
            RestoreOptionsError::NoSessionUuid {
                error: std::io::Error::other("no entropy"),
            },
        ];
        let mut labels: Vec<&str> = failures.iter().map(RestoreOptionsError::label).collect();
        let count = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), count, "two failures share a label");
        for failure in &failures {
            assert!(failure.meaning().contains("the restore is not started"));
            assert!(!failure.label().is_empty());
        }
    }

    #[test]
    fn the_identity_count_reported_is_the_manifest_s_own() {
        let mut manifest = plist::Dictionary::new();
        assert_eq!(manifest_identity_count(&manifest), 0);
        manifest.insert(
            "BuildIdentities".to_string(),
            plist::Value::Array(vec![
                plist::Value::Dictionary(plist::Dictionary::new()),
                plist::Value::Dictionary(plist::Dictionary::new()),
            ]),
        );
        assert_eq!(manifest_identity_count(&manifest), 2);
    }
}
