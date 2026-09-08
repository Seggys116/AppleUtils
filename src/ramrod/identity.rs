use std::fmt;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use plist::{Dictionary, Integer, Value};

use super::message::RestoreOptions;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreBehavior {
    Erase,
    Update,
}

impl RestoreBehavior {
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Erase => "Erase",
            Self::Update => "Update",
        }
    }

    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "Erase" => Some(Self::Erase),
            "Update" => Some(Self::Update),
            _ => None,
        }
    }

    #[must_use]
    pub const fn install_variants(self) -> &'static [&'static str] {
        match self {
            Self::Erase => &["Erase Install (IPSW)"],
            Self::Update => &["Upgrade Install (IPSW)"],
        }
    }
}

impl fmt::Display for RestoreBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire_name())
    }
}

pub const MACOS_CUSTOMER_VARIANT: &str = "macOS Customer";

pub const RESEARCH_MARKER: &str = "Research";

#[derive(Clone, Debug, PartialEq)]
pub struct BuildIdentity {
    pub index: usize,
    pub device_class: String,
    pub variant: String,
    pub info: Dictionary,
    pub components: Option<Dictionary>,
}

impl BuildIdentity {
    #[must_use]
    pub fn info_integer(&self, key: &str) -> Option<i64> {
        match self.info.get(key)? {
            Value::Integer(value) => value.as_signed(),
            Value::String(text) => parse_manifest_integer(text),
            _ => None,
        }
    }

    #[must_use]
    pub fn info_string(&self, key: &str) -> Option<&str> {
        self.info.get(key)?.as_string()
    }

    #[must_use]
    pub fn info_dictionary(&self, key: &str) -> Option<&Dictionary> {
        self.info.get(key)?.as_dictionary()
    }

    #[must_use]
    pub fn restore_behavior(&self) -> Option<RestoreBehavior> {
        RestoreBehavior::from_wire(self.info_string("RestoreBehavior")?)
    }

    #[must_use]
    pub fn ships_component(&self, name: &str) -> Option<bool> {
        Some(self.components.as_ref()?.contains_key(name))
    }
}

pub const STOCKHOLM_COMPONENT: &str = "Stockholm";

fn parse_manifest_integer(text: &str) -> Option<i64> {
    let trimmed = text.trim();
    let (body, radix) = match trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        Some(rest) => (rest, 16),
        None => (trimmed, 10),
    };
    i64::from_str_radix(body, radix).ok()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityError {
    NoIdentities,
    NoDeviceClass {
        hardware_model: String,
    },
    NoVariant {
        hardware_model: String,
        wanted: String,
    },
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoIdentities => f.write_str("the manifest carries no BuildIdentities"),
            Self::NoDeviceClass { hardware_model } => write!(
                f,
                "no build identity has a DeviceClass matching {hardware_model}"
            ),
            Self::NoVariant {
                hardware_model,
                wanted,
            } => write!(
                f,
                "no build identity for {hardware_model} has a variant matching {wanted}"
            ),
        }
    }
}

impl std::error::Error for IdentityError {}

pub const BUILD_MANIFEST_FILE_NAME: &str = "BuildManifest.plist";

pub const RESTORE_PLIST_FILE_NAME: &str = "Restore.plist";

#[derive(Debug)]
pub enum ManifestError {
    Unreadable {
        path: PathBuf,
        error: std::io::Error,
    },
    Unparseable {
        path: PathBuf,
        error: plist::Error,
    },
    NotADictionary {
        path: PathBuf,
    },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { path, error } => {
                write!(f, "{} could not be read: {error}", path.display())
            }
            Self::Unparseable { path, error } => {
                write!(f, "{} is not a property list: {error}", path.display())
            }
            Self::NotADictionary { path } => write!(
                f,
                "{} parsed but its root is not a dictionary, so it is not a BuildManifest",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ManifestError {}

pub fn load_build_manifest(path: &Path) -> Result<Dictionary, ManifestError> {
    let bytes = std::fs::read(path).map_err(|error| ManifestError::Unreadable {
        path: path.to_path_buf(),
        error,
    })?;
    let value =
        Value::from_reader(Cursor::new(bytes)).map_err(|error| ManifestError::Unparseable {
            path: path.to_path_buf(),
            error,
        })?;
    match value {
        Value::Dictionary(manifest) => Ok(manifest),
        _ => Err(ManifestError::NotADictionary {
            path: path.to_path_buf(),
        }),
    }
}

pub const SESSION_UUID_ENTROPY_SOURCE: &str = "/dev/urandom";

pub fn generate_session_uuid() -> Result<String, std::io::Error> {
    let mut bytes = [0u8; 16];
    File::open(SESSION_UUID_ENTROPY_SOURCE)?.read_exact(&mut bytes)?;
    Ok(format_uuid_v4(bytes))
}

fn format_uuid_v4(mut bytes: [u8; 16]) -> String {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut text = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            text.push('-');
        }
        text.push(hex_digit(byte >> 4));
        text.push(hex_digit(byte & 0x0f));
    }
    text
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}

fn identities(manifest: &Dictionary) -> Result<&Vec<Value>, IdentityError> {
    manifest
        .get("BuildIdentities")
        .and_then(Value::as_array)
        .ok_or(IdentityError::NoIdentities)
}

#[must_use]
pub fn all_build_identities(manifest: &Dictionary) -> Vec<BuildIdentity> {
    let Ok(entries) = identities(manifest) else {
        return Vec::new();
    };
    (0..entries.len())
        .filter_map(|index| identity_at(entries, index))
        .collect()
}

fn identity_at(entries: &[Value], index: usize) -> Option<BuildIdentity> {
    let entry = entries.get(index)?.as_dictionary()?;
    let info = entry.get("Info")?.as_dictionary()?;
    Some(BuildIdentity {
        index,
        device_class: info.get("DeviceClass")?.as_string()?.to_string(),
        variant: info
            .get("Variant")
            .and_then(Value::as_string)
            .unwrap_or_default()
            .to_string(),
        info: info.clone(),
        components: entry
            .get("Manifest")
            .and_then(Value::as_dictionary)
            .cloned(),
    })
}

fn matching_device_class(entries: &[Value], hardware_model: &str) -> Vec<BuildIdentity> {
    (0..entries.len())
        .filter_map(|index| identity_at(entries, index))
        .filter(|identity| identity.device_class.eq_ignore_ascii_case(hardware_model))
        .collect()
}

fn pick_variant(
    candidates: &[BuildIdentity],
    wanted: &str,
    allow_substring: bool,
) -> Option<BuildIdentity> {
    let usable = |identity: &&BuildIdentity| !identity.variant.contains(RESEARCH_MARKER);
    if let Some(found) = candidates
        .iter()
        .filter(usable)
        .find(|identity| identity.variant == wanted)
    {
        return Some(found.clone());
    }
    if !allow_substring {
        return None;
    }
    candidates
        .iter()
        .filter(usable)
        .find(|identity| identity.variant.contains(wanted))
        .cloned()
}

#[must_use]
pub fn raw_identity_for_variant(
    manifest: &Dictionary,
    hardware_model: &str,
    variant: &str,
) -> Option<Dictionary> {
    if variant.contains(RESEARCH_MARKER) {
        return None;
    }
    let entries = identities(manifest).ok()?;
    entries.iter().find_map(|entry| {
        let body = entry.as_dictionary()?;
        let info = body.get("Info")?.as_dictionary()?;
        let device_class = info.get("DeviceClass")?.as_string()?;
        if !device_class.eq_ignore_ascii_case(hardware_model) {
            return None;
        }
        let found = info.get("Variant")?.as_string()?;
        (found == variant).then(|| body.clone())
    })
}

pub fn select_install_identity(
    manifest: &Dictionary,
    hardware_model: &str,
    behavior: RestoreBehavior,
) -> Result<BuildIdentity, IdentityError> {
    let entries = identities(manifest)?;
    let candidates = matching_device_class(entries, hardware_model);
    if candidates.is_empty() {
        return Err(IdentityError::NoDeviceClass {
            hardware_model: hardware_model.to_string(),
        });
    }
    for wanted in behavior.install_variants() {
        if let Some(found) = pick_variant(&candidates, wanted, true) {
            return Ok(found);
        }
    }
    Err(IdentityError::NoVariant {
        hardware_model: hardware_model.to_string(),
        wanted: behavior.install_variants().join(" or "),
    })
}

#[must_use]
pub fn install_behaviors_for_board(
    manifest: &Dictionary,
    hardware_model: &str,
) -> Vec<RestoreBehavior> {
    [RestoreBehavior::Update, RestoreBehavior::Erase]
        .into_iter()
        .filter(|&behavior| select_install_identity(manifest, hardware_model, behavior).is_ok())
        .collect()
}

#[must_use]
pub fn select_macos_identity(manifest: &Dictionary, hardware_model: &str) -> Option<BuildIdentity> {
    let entries = identities(manifest).ok()?;
    let candidates = matching_device_class(entries, hardware_model);
    pick_variant(&candidates, MACOS_CUSTOMER_VARIANT, false)
}

const BYTES_PER_MIB: i64 = 1024 * 1024;

#[must_use]
pub fn recovery_os_partition_size(identity: &BuildIdentity) -> Option<i64> {
    let bytes = identity.info_integer("OSVarContentSize")?;
    Some(bytes.div_euclid(BYTES_PER_MIB) + i64::from(bytes.rem_euclid(BYTES_PER_MIB) != 0))
}

pub const REQUIRED_MESSAGE_TYPES: &[&str] = &[
    "MsgType",
    "ProgressMsg",
    "StatusMsg",
    "DataRequestMsg",
    "PreviousRestoreLogMsg",
    "BBUpdateStatusMsg",
    "ProvisioningStatusMsg",
    "ProvisioningAck",
    "ProvisioningInfo",
    "ReceivedFinalStatusMsg",
];

pub const OPTIONAL_MESSAGE_TYPES: &[&str] = &[
    "CheckpointMsg",
    "FDRSubmit",
    "RestoredCrash",
    "AsyncDataRequestMsg",
    "AsyncWait",
    "RestoreAttestation",
    "CrashLog",
    "RestoreProtocol",
];

pub const ADVERTISED_OPTIONAL_MESSAGE_TYPES: &[&str] = &[
    "AsyncDataRequestMsg",
    "AsyncWait",
    "CheckpointMsg",
    "CrashLog",
];

pub const REQUIRED_DATA_TYPES: &[&str] = &[
    "DataType",
    "SystemImageData",
    "SystemImageRootHash",
    "SystemImageCanonicalMetadata",
    "ProvisioningData",
    "FDRTrustData",
    "FDRMemoryCommit",
    "NORData",
    "FUDData",
    "EANData",
    "RootData",
    "OverlayRootDataCount",
    "KernelCache",
    "RootTicket",
    "BuildIdentityDict",
    "BuildIdentityDictV2",
    "BasebandBootData",
    "BasebandStackData",
    "BasebandData",
    "DiagData",
    "BasebandUpdaterOutputData",
    "GrapeFWData",
    "HPMFWData",
    "SsoServiceTicket",
    "S3EOverride",
    "USBCOverride",
    "USBCFWData",
    "OpalFWData",
    "StockholmPostflight",
    "FirmwareUpdaterData",
    "FirmwareUpdaterDataV2",
    "FileData",
    "FileDataDone",
    "RecoveryOSOverlayRootDataCount",
    "SourceBootObjectV3",
    "SourceBootObjectV4",
    "RecoveryOSLocalPolicy",
    "PersonalizedBootObjectV3",
    "BootabilityBundle",
    "MessageUseStreamedImageFile",
];

pub const CENTAURI_REQUIRED_DATA_TYPE: &str = "SourceBootObjectV5";

pub const ASYNC_DATA_TYPES: &[&str] = &["BootabilityBundle", "StreamedImageDecryptionKey"];

#[must_use]
pub fn capability_dictionary(required: &[&str], optional: &[&str]) -> Value {
    let mut dictionary = Dictionary::new();
    for name in required {
        dictionary.insert((*name).to_string(), Value::Boolean(false));
    }
    for name in optional {
        dictionary.insert((*name).to_string(), Value::Boolean(true));
    }
    Value::Dictionary(dictionary)
}

const CAPABILITY_WITHHELD_REASON: &str =
    "absent-means-every-type-supported-so-declaring-can-only-remove-capability";

// A change that starts sending `SupportedAsyncDataTypes` must not carry `URLAsset` unless the host will dial back the port the guest then waits in `accept` on.
pub const ASYNC_TYPES_GRANTED_BY_THE_MESSAGE_TYPE_FALLBACK: &[&str] =
    &["SystemImageData", "RecoveryOSASRImage"];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OptionsReport {
    pub keys: Vec<String>,
    pub omitted: Vec<String>,
    pub withheld: Vec<(String, &'static str)>,
}

impl fmt::Display for OptionsReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "keys={} sent=[{}]", self.keys.len(), self.keys.join(","))?;
        if !self.omitted.is_empty() {
            write!(f, " omitted=[{}]", self.omitted.join(","))?;
        }
        for (key, reason) in &self.withheld {
            write!(f, " withheld={key}({reason})")?;
        }
        Ok(())
    }
}

#[must_use]
pub fn macos_restore_options(
    install: &BuildIdentity,
    macos: &BuildIdentity,
    behavior: RestoreBehavior,
    session_uuid: &str,
    request_global_manifest: bool,
) -> (RestoreOptions, OptionsReport) {
    let mut report = OptionsReport::default();
    let mut options = RestoreOptions::new();

    let set = |options: RestoreOptions, key: &str, value: Value, report: &mut OptionsReport| {
        report.keys.push(key.to_string());
        options.with_value(key, value)
    };

    options = set(
        options,
        "AutoBootDelay",
        Value::Integer(Integer::from(0)),
        &mut report,
    );
    options = set(
        options,
        "SupportedMessageTypes",
        capability_dictionary(REQUIRED_MESSAGE_TYPES, ADVERTISED_OPTIONAL_MESSAGE_TYPES),
        &mut report,
    );
    for key in ["SupportedDataTypes", "SupportedAsyncDataTypes"] {
        report
            .withheld
            .push((key.to_string(), CAPABILITY_WITHHELD_REASON));
    }
    options = set(options, "RootToInstall", Value::Boolean(false), &mut report);
    options = set(
        options,
        "UUID",
        Value::String(session_uuid.to_string()),
        &mut report,
    );
    options = set(
        options,
        "CreateFilesystemPartitions",
        Value::Boolean(true),
        &mut report,
    );
    options = set(options, "SystemImage", Value::Boolean(true), &mut report);
    match install.info_dictionary("SystemPartitionPadding") {
        Some(padding) => {
            options = set(
                options,
                "SystemPartitionPadding",
                Value::Dictionary(padding.clone()),
                &mut report,
            );
        }
        None => report.omitted.push("SystemPartitionPadding".to_string()),
    }

    for (key, value) in [
        ("AddSystemPartitionPadding", true),
        ("AllowUntetheredRestore", false),
        ("AuthInstallEnableSso", false),
        ("BasebandUpdaterOutputPath", true),
        ("DisableUserAuthentication", true),
        ("FitSystemPartitionToContent", true),
        ("FlashNOR", true),
        ("FormatForAPFS", true),
        ("FormatForLwVM", false),
        ("InstallDiags", false),
        ("InstallRecoveryOS", true),
        ("MacOSSwapPerformed", true),
        ("MacOSVariantPresent", true),
        ("RecoveryOSUnpack", true),
        ("SealSystemVolumeDuringRestore", true),
        ("SealedSystemVolumeAuthenticate", true),
        ("ShouldRestoreSystemImage", true),
        ("SkipPreflightPersonalization", false),
        // `FailWhenUCRTFails` stays unset: it turns these already-skipped retrievals into a restore-ending failure.
        ("SkipProductionUCRTRetrieval", true),
        ("SkipProductionDCRTRetrieval", true),
        ("UpdateBaseband", true),
        ("HostHasFixFor99053849", true),
        ("PersonalizedDuringPreflight", true),
    ] {
        options = set(options, key, Value::Boolean(value), &mut report);
    }
    options = set(
        options,
        "AuthInstallRecoveryOSVariant",
        Value::String(macos.variant.clone()),
        &mut report,
    );
    options = set(
        options,
        "AuthInstallVariant",
        Value::String(install.variant.clone()),
        &mut report,
    );
    options = set(
        options,
        "AuthInstallRestoreBehavior",
        Value::String(behavior.wire_name().to_string()),
        &mut report,
    );
    match install.ships_component(STOCKHOLM_COMPONENT) {
        Some(ships) => {
            options = set(
                options,
                "InstallStockholm",
                Value::Boolean(ships),
                &mut report,
            );
        }
        None => report.omitted.push("InstallStockholm".to_string()),
    }
    options = set(
        options,
        "MinimumBatteryVoltage",
        Value::Integer(Integer::from(0)),
        &mut report,
    );

    match install.info_integer("MinimumSystemPartition") {
        Some(size) => {
            options = set(
                options,
                "SystemPartitionSize",
                Value::Integer(Integer::from(size)),
                &mut report,
            );
        }
        None => report.omitted.push("SystemPartitionSize".to_string()),
    }
    match recovery_os_partition_size(macos) {
        Some(size) => {
            options = set(
                options,
                "recoveryOSPartitionSize",
                Value::Integer(Integer::from(size)),
                &mut report,
            );
        }
        None => report.omitted.push("recoveryOSPartitionSize".to_string()),
    }

    options = set(
        options,
        // Skipping `recovery_os_restore` is the only way past that step offline: its local-policy child needs a live Apple signing server.
        "RecoveryOSMacDFUFactoryInstall",
        Value::Boolean(true),
        &mut report,
    );

    if request_global_manifest {
        options = set(
            options,
            "SelectMediumSecurityBootPolicy",
            Value::Boolean(true),
            &mut report,
        );
    }

    report.keys.sort();
    (options, report)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_MINIMUM_SYSTEM_PARTITION: i64 = 11977;
    const REAL_OS_VAR_CONTENT_SIZE: i64 = 831_619_072;
    const REAL_RESTORE_BEHAVIOR: &str = "Erase";

    fn identity(device_class: &str, variant: &str) -> Value {
        let mut info = Dictionary::new();
        info.insert("DeviceClass".into(), Value::String(device_class.into()));
        info.insert("Variant".into(), Value::String(variant.into()));
        info.insert(
            "MinimumSystemPartition".into(),
            Value::Integer(Integer::from(REAL_MINIMUM_SYSTEM_PARTITION)),
        );
        info.insert(
            "OSVarContentSize".into(),
            Value::Integer(Integer::from(REAL_OS_VAR_CONTENT_SIZE)),
        );
        info.insert(
            "RestoreBehavior".into(),
            Value::String(REAL_RESTORE_BEHAVIOR.into()),
        );
        let mut padding = Dictionary::new();
        padding.insert("128".into(), Value::Integer(Integer::from(1)));
        info.insert("SystemPartitionPadding".into(), Value::Dictionary(padding));
        let mut entry = Dictionary::new();
        entry.insert("Info".into(), Value::Dictionary(info));
        let mut components = Dictionary::new();
        for name in ["KernelCache", "OS", "RestoreKernelCache"] {
            components.insert(name.into(), Value::Dictionary(Dictionary::new()));
        }
        entry.insert("Manifest".into(), Value::Dictionary(components));
        Value::Dictionary(entry)
    }

    fn manifest() -> Dictionary {
        let mut root = Dictionary::new();
        root.insert(
            "BuildIdentities".into(),
            Value::Array(vec![
                identity("j293ap", "Customer Erase Install (IPSW)"),
                identity("j274ap", "Customer Erase Install (IPSW)"),
                identity("j274ap", "Research Erase Install (IPSW)"),
                identity("j274ap", "Customer Upgrade Install (IPSW)"),
                identity("j274ap", "macOS Customer"),
            ]),
        );
        root
    }

    #[test]
    fn the_device_class_match_is_case_insensitive() {
        let found = select_install_identity(&manifest(), "J274AP", RestoreBehavior::Erase).unwrap();
        assert_eq!(found.device_class, "j274ap");
        assert_eq!(found.index, 1);
    }

    #[test]
    fn the_variant_match_allows_the_customer_prefix_real_manifests_use() {
        let found = select_install_identity(&manifest(), "J274AP", RestoreBehavior::Erase).unwrap();
        assert_eq!(found.variant, "Customer Erase Install (IPSW)");
        let upgrade =
            select_install_identity(&manifest(), "J274AP", RestoreBehavior::Update).unwrap();
        assert_eq!(upgrade.variant, "Customer Upgrade Install (IPSW)");
    }

    #[test]
    fn install_behaviours_list_upgrade_before_erase() {
        assert_eq!(
            install_behaviors_for_board(&manifest(), "J274AP"),
            vec![RestoreBehavior::Update, RestoreBehavior::Erase]
        );
        let mut erase_only = manifest();
        erase_only
            .get_mut("BuildIdentities")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .retain(|entry| {
                !entry
                    .as_dictionary()
                    .and_then(|body| body.get("Info"))
                    .and_then(Value::as_dictionary)
                    .and_then(|info| info.get("Variant"))
                    .and_then(Value::as_string)
                    .is_some_and(|variant| variant.contains("Upgrade"))
            });
        assert_eq!(
            install_behaviors_for_board(&erase_only, "J274AP"),
            vec![RestoreBehavior::Erase]
        );
    }

    #[test]
    fn a_research_variant_is_never_selected() {
        let found = select_install_identity(&manifest(), "J274AP", RestoreBehavior::Erase).unwrap();
        assert!(!found.variant.contains(RESEARCH_MARKER));
        assert_ne!(found.index, 2);
    }

    #[test]
    fn the_macos_lookup_is_exact_and_is_what_selects_the_macos_path() {
        let found = select_macos_identity(&manifest(), "J274AP").unwrap();
        assert_eq!(found.variant, MACOS_CUSTOMER_VARIANT);
        assert_eq!(found.index, 4);
        assert!(select_macos_identity(&manifest(), "j293ap").is_none());
    }

    #[test]
    fn an_unknown_model_is_named_rather_than_silently_falling_back() {
        assert_eq!(
            select_install_identity(&manifest(), "j999ap", RestoreBehavior::Erase),
            Err(IdentityError::NoDeviceClass {
                hardware_model: "j999ap".into()
            })
        );
    }

    #[test]
    fn manifest_integers_are_accepted_in_both_forms_the_manifest_mixes() {
        assert_eq!(parse_manifest_integer("4660"), Some(4660));
        assert_eq!(parse_manifest_integer("0x1234"), Some(0x1234));
        assert_eq!(parse_manifest_integer("0X1234"), Some(0x1234));
        assert_eq!(parse_manifest_integer(" 42 "), Some(42));
        assert_eq!(parse_manifest_integer("nonsense"), None);
    }

    #[test]
    fn the_restore_behaviour_comes_from_the_manifest_not_from_a_host_choice() {
        let found = select_macos_identity(&manifest(), "J274AP").unwrap();
        assert_eq!(found.restore_behavior(), Some(RestoreBehavior::Erase));
        assert_eq!(RestoreBehavior::Erase.wire_name(), REAL_RESTORE_BEHAVIOR);
    }

    #[test]
    fn the_recovery_partition_size_is_derived_and_rounds_up() {
        let macos = select_macos_identity(&manifest(), "J274AP").unwrap();
        assert_eq!(recovery_os_partition_size(&macos), Some(794));
        let bytes = REAL_OS_VAR_CONTENT_SIZE;
        assert!(794 * BYTES_PER_MIB >= bytes);
        assert!(793 * BYTES_PER_MIB < bytes);
    }

    #[test]
    fn the_macos_options_carry_every_key_and_name_what_they_left_out() {
        let install =
            select_install_identity(&manifest(), "J274AP", RestoreBehavior::Erase).unwrap();
        let macos = select_macos_identity(&manifest(), "J274AP").unwrap();
        let (options, report) =
            macos_restore_options(&install, &macos, RestoreBehavior::Erase, "test-uuid", false);
        assert!(report.omitted.is_empty(), "{report}");

        let value = options.into_value().expect("MuxSocket is still present");
        let body = value.as_dictionary().unwrap();
        assert!(body.contains_key("SupportedHostProtocols"));
        assert_eq!(
            body.get("SystemPartitionSize").unwrap().as_signed_integer(),
            Some(REAL_MINIMUM_SYSTEM_PARTITION)
        );
        assert_eq!(
            body.get("recoveryOSPartitionSize")
                .unwrap()
                .as_signed_integer(),
            Some(794)
        );
        assert_eq!(
            body.get("AuthInstallRestoreBehavior").unwrap().as_string(),
            Some("Erase")
        );
        assert_eq!(
            body.get("AuthInstallRecoveryOSVariant")
                .unwrap()
                .as_string(),
            Some(MACOS_CUSTOMER_VARIANT)
        );
        assert!(
            body.get("SystemPartitionPadding")
                .unwrap()
                .as_dictionary()
                .is_some()
        );
        assert_eq!(body.get("UUID").unwrap().as_string(), Some("test-uuid"));
        assert_eq!(
            body.get("AuthInstallVariant").unwrap().as_string(),
            Some("Customer Erase Install (IPSW)")
        );
        assert_eq!(
            body.get("CreateFilesystemPartitions")
                .and_then(Value::as_boolean),
            Some(true)
        );
        assert_eq!(
            body.get("InstallStockholm").unwrap().as_boolean(),
            Some(false)
        );
    }

    #[test]
    fn the_data_type_dictionaries_are_withheld_rather_than_sent_short() {
        let install =
            select_install_identity(&manifest(), "J274AP", RestoreBehavior::Erase).unwrap();
        let macos = select_macos_identity(&manifest(), "J274AP").unwrap();
        let (options, report) =
            macos_restore_options(&install, &macos, RestoreBehavior::Erase, "test-uuid", false);
        let withheld: Vec<&str> = report
            .withheld
            .iter()
            .map(|(key, _)| key.as_str())
            .collect();
        assert_eq!(
            withheld,
            vec!["SupportedDataTypes", "SupportedAsyncDataTypes"]
        );
        assert!(report.withheld.iter().all(|(_, reason)| !reason.is_empty()));
        let value = options.into_value().unwrap();
        let body = value.as_dictionary().unwrap();
        for (key, _) in &report.withheld {
            assert!(!body.contains_key(key), "{key} reached the wire");
            assert!(!report.keys.contains(key), "{key} was reported as sent");
        }
        let printed = report.to_string();
        assert!(
            printed.contains("withheld=SupportedDataTypes("),
            "{printed}"
        );
        assert!(!ASYNC_TYPES_GRANTED_BY_THE_MESSAGE_TYPE_FALLBACK.contains(&"URLAsset"));
        assert!(ADVERTISED_OPTIONAL_MESSAGE_TYPES.contains(&"AsyncDataRequestMsg"));
        for name in ASYNC_TYPES_GRANTED_BY_THE_MESSAGE_TYPE_FALLBACK {
            let data_type = crate::ramrod::message::DataType::from_wire(name);
            assert!(
                !matches!(data_type, crate::ramrod::message::DataType::Other(_)),
                "{name} is granted asynchronously and is not a type this host models"
            );
            assert!(
                crate::ramrod::images::bulk_image_entry(&data_type).is_some(),
                "{name} is granted asynchronously and no manifest entry answers it"
            );
        }
    }

    #[test]
    fn supported_message_types_is_sent_complete_and_carries_only_the_two_async_names() {
        let install =
            select_install_identity(&manifest(), "J274AP", RestoreBehavior::Erase).unwrap();
        let macos = select_macos_identity(&manifest(), "J274AP").unwrap();
        let (options, report) =
            macos_restore_options(&install, &macos, RestoreBehavior::Erase, "test-uuid", false);
        assert!(
            !report
                .withheld
                .iter()
                .any(|(key, _)| key == "SupportedMessageTypes"),
            "it is sent, so it cannot also be reported withheld"
        );
        assert!(report.keys.iter().any(|key| key == "SupportedMessageTypes"));
        let value = options.into_value().unwrap();
        let body = value.as_dictionary().unwrap();
        let sent = body
            .get("SupportedMessageTypes")
            .expect("SupportedMessageTypes never reached the wire")
            .as_dictionary()
            .expect("the guest reads it as a CFDictionary");
        assert_eq!(
            sent.len(),
            REQUIRED_MESSAGE_TYPES.len() + ADVERTISED_OPTIONAL_MESSAGE_TYPES.len()
        );
        for name in REQUIRED_MESSAGE_TYPES {
            assert_eq!(sent.get(name).unwrap().as_boolean(), Some(false), "{name}");
        }
        for name in ADVERTISED_OPTIONAL_MESSAGE_TYPES {
            assert_eq!(sent.get(name).unwrap().as_boolean(), Some(true), "{name}");
        }
        for name in ["AsyncDataRequestMsg", "AsyncWait"] {
            assert!(
                sent.contains_key(name),
                "{name} decides restore_system_image"
            );
        }
        for name in OPTIONAL_MESSAGE_TYPES {
            if ADVERTISED_OPTIONAL_MESSAGE_TYPES.contains(name) {
                continue;
            }
            assert!(!sent.contains_key(name), "{name} would switch a feature on");
        }
        for name in ["RestoreAttestation", "FDRSubmit", "RestoreProtocol"] {
            assert!(!sent.contains_key(name), "{name}");
        }
        assert!(sent.contains_key("CrashLog"), "CrashLog");
        assert!(sent.contains_key("CheckpointMsg"), "CheckpointMsg");
        assert!(body.contains_key("SupportedMessageTypes"));
    }

    #[test]
    fn the_guest_reference_dictionary_splits_eighteen_names_ten_to_eight() {
        assert_eq!(REQUIRED_MESSAGE_TYPES.len(), 10);
        assert_eq!(OPTIONAL_MESSAGE_TYPES.len(), 8);
        assert_eq!(
            REQUIRED_MESSAGE_TYPES.len() + OPTIONAL_MESSAGE_TYPES.len(),
            18
        );
        for name in OPTIONAL_MESSAGE_TYPES {
            assert!(
                !REQUIRED_MESSAGE_TYPES.contains(name),
                "{name} cannot be both"
            );
        }
        for name in ADVERTISED_OPTIONAL_MESSAGE_TYPES {
            assert!(
                OPTIONAL_MESSAGE_TYPES.contains(name),
                "{name} is not one of the guest's optional names"
            );
        }
        assert_eq!(ADVERTISED_OPTIONAL_MESSAGE_TYPES.len(), 4);
        assert!(ADVERTISED_OPTIONAL_MESSAGE_TYPES.contains(&"AsyncDataRequestMsg"));
        assert!(ADVERTISED_OPTIONAL_MESSAGE_TYPES.contains(&"AsyncWait"));
        assert!(ADVERTISED_OPTIONAL_MESSAGE_TYPES.contains(&"CheckpointMsg"));
        assert!(ADVERTISED_OPTIONAL_MESSAGE_TYPES.contains(&"CrashLog"));
        assert!(!ADVERTISED_OPTIONAL_MESSAGE_TYPES.contains(&"RestoreAttestation"));
    }

    #[test]
    fn a_capability_dictionary_carries_the_guest_s_own_polarity() {
        let value = capability_dictionary(REQUIRED_MESSAGE_TYPES, OPTIONAL_MESSAGE_TYPES);
        let body = value.as_dictionary().unwrap();
        assert_eq!(
            body.len(),
            REQUIRED_MESSAGE_TYPES.len() + OPTIONAL_MESSAGE_TYPES.len()
        );
        for name in REQUIRED_MESSAGE_TYPES {
            assert_eq!(body.get(name).unwrap().as_boolean(), Some(false), "{name}");
        }
        for name in OPTIONAL_MESSAGE_TYPES {
            assert_eq!(body.get(name).unwrap().as_boolean(), Some(true), "{name}");
        }
        assert!(!REQUIRED_DATA_TYPES.contains(&CENTAURI_REQUIRED_DATA_TYPE));
        let data = capability_dictionary(REQUIRED_DATA_TYPES, ASYNC_DATA_TYPES);
        assert_eq!(
            data.as_dictionary().unwrap().len(),
            REQUIRED_DATA_TYPES.len() + ASYNC_DATA_TYPES.len() - 1,
            "BootabilityBundle is in both lists and is one key"
        );
    }

    #[test]
    fn install_stockholm_follows_the_component_list_and_is_omitted_without_one() {
        let mut root = manifest();
        {
            let entries = root
                .get_mut("BuildIdentities")
                .unwrap()
                .as_array_mut()
                .unwrap();
            let components = entries[1]
                .as_dictionary_mut()
                .unwrap()
                .get_mut("Manifest")
                .unwrap()
                .as_dictionary_mut()
                .unwrap();
            components.insert(
                STOCKHOLM_COMPONENT.into(),
                Value::Dictionary(Dictionary::new()),
            );
        }
        let install = select_install_identity(&root, "J274AP", RestoreBehavior::Erase).unwrap();
        let macos = select_macos_identity(&root, "J274AP").unwrap();
        assert_eq!(install.ships_component(STOCKHOLM_COMPONENT), Some(true));
        let (options, report) =
            macos_restore_options(&install, &macos, RestoreBehavior::Erase, "u", false);
        assert!(!report.omitted.contains(&"InstallStockholm".to_string()));
        let value = options.into_value().unwrap();
        assert_eq!(
            value
                .as_dictionary()
                .unwrap()
                .get("InstallStockholm")
                .unwrap()
                .as_boolean(),
            Some(true)
        );

        let mut bare = manifest();
        for entry in bare
            .get_mut("BuildIdentities")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .iter_mut()
        {
            entry.as_dictionary_mut().unwrap().remove("Manifest");
        }
        let install = select_install_identity(&bare, "J274AP", RestoreBehavior::Erase).unwrap();
        let macos = select_macos_identity(&bare, "J274AP").unwrap();
        assert_eq!(install.ships_component(STOCKHOLM_COMPONENT), None);
        let (options, report) =
            macos_restore_options(&install, &macos, RestoreBehavior::Erase, "u", false);
        assert!(report.omitted.contains(&"InstallStockholm".to_string()));
        assert!(
            !options
                .into_value()
                .unwrap()
                .as_dictionary()
                .unwrap()
                .contains_key("InstallStockholm")
        );
    }

    #[test]
    fn none_of_the_ios_branch_keys_are_sent_on_the_macos_path() {
        let install =
            select_install_identity(&manifest(), "J274AP", RestoreBehavior::Erase).unwrap();
        let macos = select_macos_identity(&manifest(), "J274AP").unwrap();
        let (options, _) =
            macos_restore_options(&install, &macos, RestoreBehavior::Erase, "u", false);
        let value = options.into_value().unwrap();
        let body = value.as_dictionary().unwrap();
        for key in [
            "RestoreBundlePath",
            "SystemImageFormat",
            "BootImageType",
            "DFUFileType",
        ] {
            assert!(!body.contains_key(key), "{key} is an iOS branch key");
        }
        assert_eq!(
            body.get("PersonalizedDuringPreflight")
                .and_then(Value::as_boolean),
            Some(true)
        );
        assert_eq!(
            body.get("HostHasFixFor99053849")
                .and_then(Value::as_boolean),
            Some(true)
        );
    }

    #[test]
    fn the_global_manifest_flag_adds_the_selector_and_never_prefers_personalized() {
        let install =
            select_install_identity(&manifest(), "J274AP", RestoreBehavior::Erase).unwrap();
        let macos = select_macos_identity(&manifest(), "J274AP").unwrap();

        let (personalized, report) =
            macos_restore_options(&install, &macos, RestoreBehavior::Erase, "u", false);
        let personalized = personalized.into_value().unwrap();
        let personalized = personalized.as_dictionary().unwrap();
        assert!(!personalized.contains_key("SelectMediumSecurityBootPolicy"));
        assert!(
            !report
                .keys
                .contains(&"SelectMediumSecurityBootPolicy".to_string())
        );

        let (global, report) =
            macos_restore_options(&install, &macos, RestoreBehavior::Erase, "u", true);
        let global = global.into_value().unwrap();
        let global = global.as_dictionary().unwrap();
        assert_eq!(
            global
                .get("SelectMediumSecurityBootPolicy")
                .and_then(Value::as_boolean),
            Some(true)
        );
        assert!(!global.contains_key("PreferPersonalizedManifest"));
        assert!(
            report
                .keys
                .contains(&"SelectMediumSecurityBootPolicy".to_string())
        );
    }

    #[test]
    fn the_autoboot_delay_sent_matches_the_guests_default() {
        let install =
            select_install_identity(&manifest(), "J274AP", RestoreBehavior::Erase).unwrap();
        let macos = select_macos_identity(&manifest(), "J274AP").unwrap();
        let (options, report) =
            macos_restore_options(&install, &macos, RestoreBehavior::Erase, "u", false);

        assert!(report.keys.contains(&"AutoBootDelay".to_string()));
        assert_eq!(
            options.integer_value("AutoBootDelay"),
            Some(0),
            "AppleUtils sends the same delay the guest's own default would have used"
        );
    }

    #[test]
    fn a_session_uuid_is_version_four_and_the_right_shape() {
        let text = generate_session_uuid().expect("host entropy is readable");
        assert_eq!(text.len(), 36);
        let groups: Vec<&str> = text.split('-').collect();
        assert_eq!(
            groups.iter().map(|group| group.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(
            text.chars()
                .all(|c| c == '-' || c.is_ascii_digit() || ('A'..='F').contains(&c)),
            "{text} is not uppercase hexadecimal"
        );
        assert_eq!(groups[2].as_bytes()[0], b'4');
        assert!(matches!(groups[3].as_bytes()[0], b'8' | b'9' | b'A' | b'B'));
    }

    #[test]
    fn two_session_uuids_in_a_row_differ() {
        let first = generate_session_uuid().unwrap();
        let second = generate_session_uuid().unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn the_version_and_variant_bits_are_stamped_over_whatever_entropy_gave() {
        for raw in [[0x00u8; 16], [0xffu8; 16]] {
            let text = format_uuid_v4(raw);
            let groups: Vec<&str> = text.split('-').collect();
            assert_eq!(groups[2].as_bytes()[0], b'4', "{text}");
            assert!(
                matches!(groups[3].as_bytes()[0], b'8' | b'9' | b'A' | b'B'),
                "{text}"
            );
        }
    }

    #[test]
    fn a_manifest_that_is_not_there_is_named_rather_than_treated_as_empty() {
        let missing = std::path::Path::new("/nonexistent/restore-host/BuildManifest.plist");
        match load_build_manifest(missing) {
            Err(ManifestError::Unreadable { path, .. }) => assert_eq!(path, missing),
            other => panic!("expected an unreadable manifest, got {other:?}"),
        }
    }

    #[test]
    fn a_manifest_that_is_not_a_property_list_is_told_apart_from_a_missing_one() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(BUILD_MANIFEST_FILE_NAME);
        std::fs::write(&path, b"this is not a property list").unwrap();
        match load_build_manifest(&path) {
            Err(ManifestError::Unparseable { path: named, .. }) => assert_eq!(named, path),
            other => panic!("expected an unparseable manifest, got {other:?}"),
        }
    }

    #[test]
    fn a_property_list_that_is_not_a_dictionary_is_not_a_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(BUILD_MANIFEST_FILE_NAME);
        plist::to_file_xml(&path, &Value::Array(vec![Value::Boolean(true)])).unwrap();
        match load_build_manifest(&path) {
            Err(ManifestError::NotADictionary { path: named }) => assert_eq!(named, path),
            other => panic!("expected a non-dictionary manifest, got {other:?}"),
        }
    }

    #[test]
    fn a_written_manifest_round_trips_into_a_selectable_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(BUILD_MANIFEST_FILE_NAME);
        plist::to_file_xml(&path, &Value::Dictionary(manifest())).unwrap();
        let loaded = load_build_manifest(&path).unwrap();
        let macos = select_macos_identity(&loaded, "J274AP").unwrap();
        assert_eq!(macos.variant, MACOS_CUSTOMER_VARIANT);
        assert_eq!(macos.restore_behavior(), Some(RestoreBehavior::Erase));
    }

    #[test]
    fn a_manifest_missing_a_size_omits_the_key_rather_than_inventing_one() {
        let mut root = manifest();
        let entries = root
            .get_mut("BuildIdentities")
            .unwrap()
            .as_array_mut()
            .unwrap();
        for entry in entries.iter_mut() {
            let info = entry
                .as_dictionary_mut()
                .unwrap()
                .get_mut("Info")
                .unwrap()
                .as_dictionary_mut()
                .unwrap();
            info.remove("OSVarContentSize");
            info.remove("MinimumSystemPartition");
        }
        let install = select_install_identity(&root, "J274AP", RestoreBehavior::Erase).unwrap();
        let macos = select_macos_identity(&root, "J274AP").unwrap();
        let (options, report) =
            macos_restore_options(&install, &macos, RestoreBehavior::Erase, "u", false);
        assert!(report.omitted.contains(&"SystemPartitionSize".to_string()));
        assert!(
            report
                .omitted
                .contains(&"recoveryOSPartitionSize".to_string())
        );
        let value = options.into_value().unwrap();
        let body = value.as_dictionary().unwrap();
        assert!(!body.contains_key("SystemPartitionSize"));
        assert!(!body.contains_key("recoveryOSPartitionSize"));
    }
}
