use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use plist::{Dictionary, Integer, Value};

use super::message::{RestoreOptions, SystemImageFormat};

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

#[must_use]
pub fn installable_device_classes(manifest: &Dictionary) -> Vec<String> {
    let Ok(entries) = identities(manifest) else {
        return Vec::new();
    };
    let mut classes = BTreeSet::new();
    for entry in entries {
        let Some(info) = entry
            .as_dictionary()
            .and_then(|body| body.get("Info"))
            .and_then(Value::as_dictionary)
        else {
            continue;
        };
        let variant = info
            .get("Variant")
            .and_then(Value::as_string)
            .unwrap_or_default();
        if variant.contains(RESEARCH_MARKER) {
            continue;
        }
        let Some(class) = info
            .get("DeviceClass")
            .and_then(Value::as_string)
            .map(str::trim)
            .filter(|class| !class.is_empty())
        else {
            continue;
        };
        classes.insert(class.to_string());
    }
    classes.into_iter().collect()
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

pub fn select_recovery_identity(
    manifest: &Dictionary,
    hardware_model: &str,
    variant: &str,
) -> Result<BuildIdentity, IdentityError> {
    let entries = identities(manifest)?;
    let candidates = matching_device_class(entries, hardware_model);
    if candidates.is_empty() {
        return Err(IdentityError::NoDeviceClass {
            hardware_model: hardware_model.to_string(),
        });
    }
    pick_variant(&candidates, variant, false).ok_or_else(|| IdentityError::NoVariant {
        hardware_model: hardware_model.to_string(),
        wanted: variant.to_string(),
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
    "RootTicketData",
    "APTicket",
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
    CENTAURI_REQUIRED_DATA_TYPE,
    "PersonalizedBootObjectV3",
    "BootabilityBundle",
    "MessageUseStreamedImageFile",
    "StreamedImageDecryptionKey",
];

pub const CENTAURI_REQUIRED_DATA_TYPE: &str = "SourceBootObjectV5";

pub const ADVERTISED_OPTIONAL_DATA_TYPES: &[&str] = &[
    "PersonalizedData",
    "RecoveryOSASRImage",
    "RecoveryOSLocalPolicy",
    "RecoveryOSRootTicketData",
    "RecoveryOSVersionData",
    "URLAsset",
];

pub const ASYNC_DATA_TYPES: &[&str] = &[
    "BasebandData",
    "BootabilityBundle",
    "RecoveryOSASRImage",
    "StreamedImageDecryptionKey",
    "SystemImageData",
];

pub const ADVERTISED_OPTIONAL_ASYNC_DATA_TYPES: &[&str] = &["URLAsset"];

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

fn with_manifest_system_image_format(
    options: RestoreOptions,
    install: &BuildIdentity,
    report: &mut OptionsReport,
) -> RestoreOptions {
    match install.info_string("ContentEncoding") {
        Some("aea") => {
            report.keys.push("SystemImageFormat".to_string());
            options.with_system_image_format(SystemImageFormat::AeaWrappedDiskImage)
        }
        _ => {
            report.omitted.push("SystemImageFormat".to_string());
            options
        }
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
    options = set(
        options,
        "SupportedDataTypes",
        capability_dictionary(REQUIRED_DATA_TYPES, ADVERTISED_OPTIONAL_DATA_TYPES),
        &mut report,
    );
    options = set(
        options,
        "SupportedAsyncDataTypes",
        capability_dictionary(ASYNC_DATA_TYPES, ADVERTISED_OPTIONAL_ASYNC_DATA_TYPES),
        &mut report,
    );
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
    options = with_manifest_system_image_format(options, install, &mut report);
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

#[must_use]
pub fn mobile_restore_options(
    install: &BuildIdentity,
    recovery: Option<&BuildIdentity>,
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
    options = set(
        options,
        "SupportedDataTypes",
        capability_dictionary(REQUIRED_DATA_TYPES, ADVERTISED_OPTIONAL_DATA_TYPES),
        &mut report,
    );
    options = set(
        options,
        "SupportedAsyncDataTypes",
        capability_dictionary(ASYNC_DATA_TYPES, ADVERTISED_OPTIONAL_ASYNC_DATA_TYPES),
        &mut report,
    );
    for (key, value) in [
        ("BootImageType", "User"),
        ("DFUFileType", "RELEASE"),
        ("KernelCacheType", "Release"),
        ("NORImageType", "production"),
        ("SystemImageType", "User"),
        ("AuthInstallVariant", install.variant.as_str()),
        ("AuthInstallRestoreBehavior", behavior.wire_name()),
        ("UUID", session_uuid),
    ] {
        options = set(options, key, Value::String(value.to_string()), &mut report);
    }
    for (key, value) in [
        ("DataImage", false),
        ("FlashNOR", true),
        ("UpdateBaseband", true),
        ("InstallDiags", false),
        ("HostHasFixFor99053849", true),
        ("WaitForDeviceConnectionToFinishStateMachine", false),
        ("PersonalizedDuringPreflight", true),
        ("RootToInstall", false),
        ("CreateFilesystemPartitions", true),
        ("SystemImage", true),
    ] {
        options = set(options, key, Value::Boolean(value), &mut report);
    }
    for (source, key) in [
        ("SystemPartitionPadding", "SystemPartitionPadding"),
        ("MinimumSystemPartition", "SystemPartitionSize"),
    ] {
        match install.info.get(source) {
            Some(value) => options = set(options, key, value.clone(), &mut report),
            None => report.omitted.push(key.to_string()),
        }
    }
    options = with_manifest_system_image_format(options, install, &mut report);
    match install
        .components
        .as_ref()
        .and_then(|components| components.get("SEP"))
        .and_then(Value::as_dictionary)
        .and_then(|sep| sep.get("Info"))
        .and_then(Value::as_dictionary)
        .and_then(|info| info.get("RequiredCapacity"))
    {
        Some(capacity) => {
            options = set(
                options,
                "TZ0RequiredCapacity",
                capacity.clone(),
                &mut report,
            );
        }
        None => report.omitted.push("TZ0RequiredCapacity".to_string()),
    }
    report.omitted.extend([
        "FirmwareDirectory".to_string(),
        "RestoreBundlePath".to_string(),
    ]);
    match recovery {
        Some(identity) => {
            options = set(
                options,
                "InstallRecoveryOS",
                Value::Boolean(true),
                &mut report,
            );
            options = set(
                options,
                "AuthInstallRecoveryOSVariant",
                Value::String(identity.variant.clone()),
                &mut report,
            );
            report.omitted.extend([
                "RecoveryOSBundlePath".to_string(),
                "recoveryOSPartitionSize".to_string(),
                "recoveryOSMaxPartitionSize".to_string(),
            ]);
        }
        None => report.omitted.extend([
            "InstallRecoveryOS".to_string(),
            "AuthInstallRecoveryOSVariant".to_string(),
        ]),
    }
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

    fn serialized_start_restore_options(options: RestoreOptions) -> Dictionary {
        let mut client = crate::ramrod::RamrodClient::new(Cursor::new(Vec::new()));
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

    fn assert_restore_fetch_capabilities(body: &Dictionary, report: &OptionsReport) {
        let data = body["SupportedDataTypes"].as_dictionary().unwrap();
        for name in [
            "DataType",
            "SystemImageData",
            "SystemImageRootHash",
            "SystemImageCanonicalMetadata",
            "FDRTrustData",
            "FDRMemoryCommit",
            "BuildIdentityDict",
            "BuildIdentityDictV2",
            "RootTicket",
            "RootTicketData",
            "APTicket",
            "SourceBootObjectV3",
            "SourceBootObjectV4",
            "SourceBootObjectV5",
            "PersonalizedBootObjectV3",
            "BootabilityBundle",
            "StreamedImageDecryptionKey",
        ] {
            assert_eq!(data[name].as_boolean(), Some(false), "{name}");
        }
        for name in [
            "URLAsset",
            "PersonalizedData",
            "RecoveryOSASRImage",
            "RecoveryOSLocalPolicy",
            "RecoveryOSRootTicketData",
            "RecoveryOSVersionData",
        ] {
            assert_eq!(data[name].as_boolean(), Some(true), "{name}");
        }
        let asynchronous = body["SupportedAsyncDataTypes"].as_dictionary().unwrap();
        for name in [
            "BasebandData",
            "BootabilityBundle",
            "RecoveryOSASRImage",
            "StreamedImageDecryptionKey",
            "SystemImageData",
        ] {
            assert_eq!(asynchronous[name].as_boolean(), Some(false), "{name}");
        }
        assert_eq!(asynchronous["URLAsset"].as_boolean(), Some(true));
        let messages = body["SupportedMessageTypes"].as_dictionary().unwrap();
        for name in ["AsyncDataRequestMsg", "AsyncWait"] {
            assert_eq!(messages[name].as_boolean(), Some(true), "{name}");
        }
        assert_eq!(
            body["SupportedHostProtocols"].as_array().unwrap(),
            &vec![Value::String("MuxSocket".into())]
        );
        for key in ["SupportedDataTypes", "SupportedAsyncDataTypes"] {
            assert!(report.keys.iter().any(|sent| sent == key), "{key}");
            assert!(report.to_string().contains(key), "{key}");
        }
    }

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

    fn mobile_manifest() -> Dictionary {
        let mut install = identity("j617ap", "Developer Erase Install (IPSW)");
        let body = install.as_dictionary_mut().unwrap();
        let info = body.get_mut("Info").unwrap().as_dictionary_mut().unwrap();
        info.insert(
            "RecoveryVariant".into(),
            Value::String("Recovery Customer Install".into()),
        );
        info.insert("ContentEncoding".into(), Value::String("aea".into()));
        let mut sep_info = Dictionary::new();
        sep_info.insert("RequiredCapacity".into(), Value::String("0x800000".into()));
        let mut sep = Dictionary::new();
        sep.insert("Info".into(), Value::Dictionary(sep_info));
        body.get_mut("Manifest")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert("SEP".into(), Value::Dictionary(sep));
        let mut root = Dictionary::new();
        root.insert(
            "BuildIdentities".into(),
            Value::Array(vec![
                install,
                identity("j617ap", "Recovery Customer Install Extra"),
                identity("j618ap", "Recovery Customer Install"),
                identity("j617ap", "Recovery Customer Install"),
            ]),
        );
        root
    }

    #[test]
    fn declared_mobile_recovery_variant_selects_the_exact_identity() {
        let root = mobile_manifest();
        let install = select_install_identity(&root, "J617AP", RestoreBehavior::Erase).unwrap();
        let recovery = select_recovery_identity(
            &root,
            "J617AP",
            install.info_string("RecoveryVariant").unwrap(),
        )
        .unwrap();
        assert_eq!(recovery.index, 3);
        assert_eq!(recovery.device_class, "j617ap");
        assert_eq!(recovery.variant, "Recovery Customer Install");
    }

    #[test]
    fn recovery_selector_names_the_model_and_exact_variant_it_refuses() {
        let root = mobile_manifest();
        assert_eq!(
            select_recovery_identity(&root, "j617ap", "Recovery Customer"),
            Err(IdentityError::NoVariant {
                hardware_model: "j617ap".into(),
                wanted: "Recovery Customer".into(),
            })
        );
        assert_eq!(
            select_recovery_identity(&root, "j999ap", "Recovery Customer Install"),
            Err(IdentityError::NoDeviceClass {
                hardware_model: "j999ap".into(),
            })
        );
        assert_eq!(
            select_recovery_identity(&Dictionary::new(), "j617ap", "Recovery Customer Install"),
            Err(IdentityError::NoIdentities)
        );
    }

    #[test]
    fn mobile_options_carry_protocol_values_and_manifest_metadata() {
        let root = mobile_manifest();
        let install = select_install_identity(&root, "j617ap", RestoreBehavior::Erase).unwrap();
        let recovery = select_recovery_identity(
            &root,
            "j617ap",
            install.info_string("RecoveryVariant").unwrap(),
        )
        .unwrap();
        let (options, report) = mobile_restore_options(
            &install,
            Some(&recovery),
            RestoreBehavior::Erase,
            "mobile-session",
            true,
        );
        assert_eq!(
            options.system_image_format(),
            Some(SystemImageFormat::AeaWrappedDiskImage)
        );
        let body = serialized_start_restore_options(options);
        for (key, expected) in [
            ("BootImageType", "User"),
            ("DFUFileType", "RELEASE"),
            ("KernelCacheType", "Release"),
            ("NORImageType", "production"),
            ("SystemImageType", "User"),
            ("SystemImageFormat", "AEAWrappedDiskImage"),
            ("AuthInstallVariant", "Developer Erase Install (IPSW)"),
            ("AuthInstallRestoreBehavior", "Erase"),
            ("AuthInstallRecoveryOSVariant", "Recovery Customer Install"),
            ("TZ0RequiredCapacity", "0x800000"),
            ("UUID", "mobile-session"),
        ] {
            assert_eq!(body.get(key).unwrap().as_string(), Some(expected), "{key}");
        }
        for (key, expected) in [
            ("DataImage", false),
            ("FlashNOR", true),
            ("UpdateBaseband", true),
            ("InstallDiags", false),
            ("HostHasFixFor99053849", true),
            ("WaitForDeviceConnectionToFinishStateMachine", false),
            ("PersonalizedDuringPreflight", true),
            ("RootToInstall", false),
            ("CreateFilesystemPartitions", true),
            ("SystemImage", true),
            ("InstallRecoveryOS", true),
            ("SelectMediumSecurityBootPolicy", true),
        ] {
            assert_eq!(body.get(key).unwrap().as_boolean(), Some(expected), "{key}");
        }
        assert_eq!(
            body.get("AutoBootDelay").unwrap().as_signed_integer(),
            Some(0)
        );
        assert_eq!(
            body.get("SystemPartitionSize").unwrap().as_signed_integer(),
            Some(11977)
        );
        let padding = body
            .get("SystemPartitionPadding")
            .unwrap()
            .as_dictionary()
            .unwrap();
        assert_eq!(padding.get("128").unwrap().as_signed_integer(), Some(1));
        assert_eq!(
            body.get("SupportedHostProtocols")
                .unwrap()
                .as_array()
                .unwrap(),
            &vec![Value::String("MuxSocket".into())]
        );
        let messages = body
            .get("SupportedMessageTypes")
            .unwrap()
            .as_dictionary()
            .unwrap();
        assert_eq!(
            messages.get("DataRequestMsg").unwrap().as_boolean(),
            Some(false)
        );
        for name in [
            "AsyncDataRequestMsg",
            "AsyncWait",
            "CheckpointMsg",
            "CrashLog",
        ] {
            assert_eq!(
                messages.get(name).unwrap().as_boolean(),
                Some(true),
                "{name}"
            );
        }
        assert_restore_fetch_capabilities(&body, &report);
        assert!(
            report
                .omitted
                .contains(&"recoveryOSPartitionSize".to_string())
        );
        assert!(
            report
                .omitted
                .contains(&"recoveryOSMaxPartitionSize".to_string())
        );
    }

    #[test]
    fn mobile_options_report_undetermined_metadata_and_optional_recovery() {
        let root = mobile_manifest();
        let mut install = select_install_identity(&root, "j617ap", RestoreBehavior::Erase).unwrap();
        install.info.remove("ContentEncoding");
        install.info.remove("MinimumSystemPartition");
        install.info.remove("SystemPartitionPadding");
        install.components = None;
        let (options, report) = mobile_restore_options(
            &install,
            None,
            RestoreBehavior::Update,
            "update-session",
            false,
        );
        for key in [
            "SystemImageFormat",
            "SystemPartitionSize",
            "SystemPartitionPadding",
            "TZ0RequiredCapacity",
            "InstallRecoveryOS",
            "AuthInstallRecoveryOSVariant",
        ] {
            assert!(report.omitted.contains(&key.to_string()), "{key}");
        }
        let value = options.into_value().unwrap();
        let body = value.as_dictionary().unwrap();
        assert_eq!(
            body.get("AuthInstallRestoreBehavior").unwrap().as_string(),
            Some("Update")
        );
        assert_eq!(
            body.get("UUID").unwrap().as_string(),
            Some("update-session")
        );
        install.info.insert(
            "ContentEncoding".into(),
            Value::String("unrecognized".into()),
        );
        let (_, report) = mobile_restore_options(
            &install,
            None,
            RestoreBehavior::Update,
            "update-session",
            false,
        );
        assert!(report.omitted.contains(&"SystemImageFormat".to_string()));
    }

    #[test]
    fn mobile_options_preserve_partition_metadata_value_types() {
        let root = mobile_manifest();
        let mut install = select_install_identity(&root, "j617ap", RestoreBehavior::Erase).unwrap();
        install.info.insert(
            "MinimumSystemPartition".into(),
            Value::String("0x2ec9".into()),
        );
        let (options, _) = mobile_restore_options(
            &install,
            None,
            RestoreBehavior::Erase,
            "partition-session",
            false,
        );
        let value = options.into_value().unwrap();
        assert_eq!(
            value
                .as_dictionary()
                .unwrap()
                .get("SystemPartitionSize")
                .unwrap()
                .as_string(),
            Some("0x2ec9")
        );
    }

    #[test]
    fn installable_classes_skip_research() {
        let classes = installable_device_classes(&manifest());
        assert_eq!(classes, vec!["j274ap".to_string(), "j293ap".to_string()]);
    }

    #[test]
    fn installable_classes_include_ipados_boards() {
        let mut root = Dictionary::new();
        root.insert(
            "BuildIdentities".into(),
            Value::Array(vec![
                identity("j617ap", "Developer Erase Install (IPSW)"),
                identity("j617ap", "Developer Upgrade Install (IPSW)"),
                identity("j617ap", "Recovery Customer Install"),
                identity("j618ap", "Developer Erase Install (IPSW)"),
            ]),
        );
        let classes = installable_device_classes(&root);
        assert_eq!(classes, vec!["j617ap".to_string(), "j618ap".to_string()]);
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
        assert_eq!(report.omitted, vec!["SystemImageFormat"], "{report}");

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
    fn macos_start_restore_advertises_fetches_and_manifest_image_format() {
        let mut install =
            select_install_identity(&manifest(), "J274AP", RestoreBehavior::Erase).unwrap();
        install
            .info
            .insert("ContentEncoding".into(), Value::String("aea".into()));
        let macos = select_macos_identity(&manifest(), "J274AP").unwrap();
        let (options, report) =
            macos_restore_options(&install, &macos, RestoreBehavior::Erase, "test-uuid", false);
        let body = serialized_start_restore_options(options);
        assert_restore_fetch_capabilities(&body, &report);
        assert_eq!(
            body["SystemImageFormat"].as_string(),
            Some("AEAWrappedDiskImage")
        );
        assert!(report.keys.iter().any(|key| key == "SystemImageFormat"));
        assert_eq!(
            body["AuthInstallVariant"].as_string(),
            Some("Customer Erase Install (IPSW)")
        );
        assert_eq!(
            body["AuthInstallRecoveryOSVariant"].as_string(),
            Some("macOS Customer")
        );
        assert_eq!(
            body["AuthInstallRestoreBehavior"].as_string(),
            Some("Erase")
        );
        assert_eq!(body["UUID"].as_string(), Some("test-uuid"));
        assert_eq!(
            body["SystemPartitionSize"].as_signed_integer(),
            Some(REAL_MINIMUM_SYSTEM_PARTITION)
        );
        assert_eq!(
            body["recoveryOSPartitionSize"].as_signed_integer(),
            Some(794)
        );
        assert_eq!(
            body["SystemPartitionPadding"].as_dictionary().unwrap()["128"].as_signed_integer(),
            Some(1)
        );
        for key in [
            "CreateFilesystemPartitions",
            "SystemImage",
            "InstallRecoveryOS",
        ] {
            assert_eq!(body[key].as_boolean(), Some(true), "{key}");
        }
        for name in ["SystemImageData", "RecoveryOSASRImage"] {
            let data_type = crate::ramrod::message::DataType::from_wire(name);
            assert!(crate::ramrod::images::bulk_image_entry(&data_type).is_some());
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
        let data = capability_dictionary(REQUIRED_DATA_TYPES, ADVERTISED_OPTIONAL_DATA_TYPES);
        let data = data.as_dictionary().unwrap();
        for name in REQUIRED_DATA_TYPES {
            assert_eq!(data[name].as_boolean(), Some(false), "{name}");
        }
        for name in ADVERTISED_OPTIONAL_DATA_TYPES {
            assert_eq!(data[name].as_boolean(), Some(true), "{name}");
        }
        assert_eq!(data[CENTAURI_REQUIRED_DATA_TYPE].as_boolean(), Some(false));
        assert_eq!(data["BootabilityBundle"].as_boolean(), Some(false));
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
    fn macos_options_carry_the_restore_protocol_preflight_flags() {
        let install =
            select_install_identity(&manifest(), "J274AP", RestoreBehavior::Erase).unwrap();
        let macos = select_macos_identity(&manifest(), "J274AP").unwrap();
        let (options, _) =
            macos_restore_options(&install, &macos, RestoreBehavior::Erase, "u", false);
        let value = options.into_value().unwrap();
        let body = value.as_dictionary().unwrap();
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
