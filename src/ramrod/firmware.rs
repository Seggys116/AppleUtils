use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use plist::{Dictionary, Value};

use super::identity::BuildIdentity;
use crate::crypto::{sha256, sha384};

pub const KEY_NOR_IMAGE_DATA: &str = "NorImageData";
pub const KEY_LLB_IMAGE_DATA: &str = "LlbImageData";
pub const KEY_SEP_IMAGE_DATA: &str = "SEPImageData";
pub const KEY_SEP_PATCH_IMAGE_DATA: &str = "SEPPatchImageData";
pub const KEY_RESTORE_SEP_IMAGE_DATA: &str = "RestoreSEPImageData";

pub const ARGUMENT_FLASH_VERSION_1: &str = "FlashVersion1";

pub const INFO_IS_FIRMWARE_PAYLOAD: &str = "IsFirmwarePayload";
pub const INFO_IS_SECONDARY_FIRMWARE_PAYLOAD: &str = "IsSecondaryFirmwarePayload";
pub const INFO_PATH: &str = "Path";
pub const INFO_IMG4_PAYLOAD_TYPE: &str = "Img4PayloadType";
pub const INFO_HASH_METHOD: &str = "HashMethod";
pub const COMPONENT_DIGEST: &str = "Digest";

pub const COMPONENT_LLB: &str = "LLB";
pub const COMPONENT_SEP: &str = "SEP";
pub const COMPONENT_RESTORE_SEP: &str = "RestoreSEP";
pub const COMPONENT_SEP_STAGE1: &str = "SepStage1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NorSlot {
    Llb,
    Nor,
    Sep,
    RestoreSep,
    SepPatch,
}

impl NorSlot {
    #[must_use]
    pub const fn reply_key(self) -> Option<&'static str> {
        match self {
            Self::Llb => Some(KEY_LLB_IMAGE_DATA),
            Self::Nor => None,
            Self::Sep => Some(KEY_SEP_IMAGE_DATA),
            Self::RestoreSep => Some(KEY_RESTORE_SEP_IMAGE_DATA),
            Self::SepPatch => Some(KEY_SEP_PATCH_IMAGE_DATA),
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Llb => "llb",
            Self::Nor => "nor",
            Self::Sep => "sep",
            Self::RestoreSep => "restore-sep",
            Self::SepPatch => "sep-patch",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NorComponent {
    pub name: String,
    pub slot: NorSlot,
    pub path: String,
    pub payload_type: Option<String>,
    pub digest: Option<Vec<u8>>,
    pub hash_method: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NorPlan {
    pub components: Vec<NorComponent>,
    pub unclaimed_secondary: Vec<String>,
}

impl NorPlan {
    #[must_use]
    pub fn in_slot(&self, slot: NorSlot) -> Vec<&NorComponent> {
        self.components
            .iter()
            .filter(|component| component.slot == slot)
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }
}

// `FirmwareRootUnresolved` is large but is only ever built once, on a planning failure.
#[allow(clippy::result_large_err)]
pub fn plan_nor_payload(identity: &BuildIdentity) -> Result<NorPlan, NorPayloadError> {
    let components = identity
        .components
        .as_ref()
        .ok_or(NorPayloadError::NoManifest)?;
    let mut plan = NorPlan::default();
    for (name, entry) in components {
        let Some(info) = entry.as_dictionary().and_then(|entry| entry.get("Info")) else {
            continue;
        };
        let Some(info) = info.as_dictionary() else {
            continue;
        };
        let Some(slot) = slot_for(name, info, &mut plan.unclaimed_secondary) else {
            continue;
        };
        let path = info
            .get(INFO_PATH)
            .and_then(Value::as_string)
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .ok_or_else(|| NorPayloadError::ComponentPathMissing {
                component: name.clone(),
            })?;
        let payload_type = info
            .get(INFO_IMG4_PAYLOAD_TYPE)
            .and_then(Value::as_string)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let digest = entry
            .as_dictionary()
            .and_then(|entry| entry.get(COMPONENT_DIGEST))
            .and_then(Value::as_data)
            .filter(|digest| !digest.is_empty())
            .map(ToOwned::to_owned);
        let hash_method = info
            .get(INFO_HASH_METHOD)
            .and_then(Value::as_string)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        plan.components.push(NorComponent {
            name: name.clone(),
            slot,
            path: path.to_string(),
            payload_type,
            digest,
            hash_method,
        });
    }
    plan.components
        .sort_by(|left, right| (left.slot, &left.name).cmp(&(right.slot, &right.name)));
    plan.unclaimed_secondary.sort();
    Ok(plan)
}

fn slot_for(name: &str, info: &Dictionary, unclaimed: &mut Vec<String>) -> Option<NorSlot> {
    match name {
        COMPONENT_LLB => return Some(NorSlot::Llb),
        COMPONENT_RESTORE_SEP => return Some(NorSlot::RestoreSep),
        COMPONENT_SEP => return Some(NorSlot::Sep),
        COMPONENT_SEP_STAGE1 => return Some(NorSlot::SepPatch),
        _ => {}
    }
    if flag(info, INFO_IS_FIRMWARE_PAYLOAD) {
        return Some(NorSlot::Nor);
    }
    if flag(info, INFO_IS_SECONDARY_FIRMWARE_PAYLOAD) {
        unclaimed.push(name.to_string());
        return None;
    }
    None
}

fn flag(info: &Dictionary, key: &str) -> bool {
    info.get(key).and_then(Value::as_boolean).unwrap_or(false)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NorImage {
    pub name: String,
    pub slot: NorSlot,
    pub source: PathBuf,
    pub payload_bytes: usize,
    pub image_bytes: usize,
    pub image: Vec<u8>,
    pub served_type: Option<String>,
    pub retagged: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NorPayload {
    pub images: Vec<NorImage>,
    pub unclaimed_secondary: Vec<String>,
}

impl NorPayload {
    #[must_use]
    pub fn total_image_bytes(&self) -> usize {
        self.images.iter().map(|image| image.image_bytes).sum()
    }

    #[must_use]
    pub fn into_answer(self, flash_version_1: bool) -> Dictionary {
        self.answer(flash_version_1)
    }

    #[must_use]
    pub fn answer(&self, flash_version_1: bool) -> Dictionary {
        let mut body = Dictionary::new();
        let mut named = Dictionary::new();
        let mut ordered: Vec<Value> = Vec::new();
        for image in &self.images {
            match image.slot {
                NorSlot::Nor => {
                    if flash_version_1 {
                        named.insert(image.name.clone(), Value::Data(image.image.clone()));
                    } else {
                        ordered.push(Value::Data(image.image.clone()));
                    }
                }
                slot => {
                    if let Some(key) = slot.reply_key() {
                        body.insert(key.to_string(), Value::Data(image.image.clone()));
                    }
                }
            }
        }
        if flash_version_1 {
            if !named.is_empty() {
                body.insert(KEY_NOR_IMAGE_DATA.to_string(), Value::Dictionary(named));
            }
        } else if !ordered.is_empty() {
            body.insert(KEY_NOR_IMAGE_DATA.to_string(), Value::Array(ordered));
        }
        body
    }
}

// See the `#[allow]` on `plan_nor_payload`.
#[allow(clippy::result_large_err)]
pub fn validate_firmware_root(plan: &NorPlan, firmware_root: &Path) -> Result<(), NorPayloadError> {
    let mut missing = 0usize;
    let mut first: Option<&NorComponent> = None;
    for component in &plan.components {
        if firmware_root.join(&component.path).is_file() {
            continue;
        }
        missing += 1;
        if first.is_none() {
            first = Some(component);
        }
    }
    let Some(component) = first else {
        return Ok(());
    };
    let leading = component
        .path
        .split('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or_default();
    let doubled_segment = firmware_root
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .filter(|name| !leading.is_empty() && *name == leading)
        .map(str::to_string);
    Err(NorPayloadError::FirmwareRootUnresolved {
        root: firmware_root.to_path_buf(),
        component: component.name.clone(),
        component_path: component.path.clone(),
        joined: firmware_root.join(&component.path),
        missing,
        planned: plan.components.len(),
        doubled_segment,
    })
}

// See the `#[allow]` on `plan_nor_payload`.
#[allow(clippy::result_large_err)]
pub fn build_nor_payload(
    plan: &NorPlan,
    firmware_root: &Path,
    board_manifest: &[u8],
) -> Result<NorPayload, NorPayloadError> {
    if plan.is_empty() {
        return Err(NorPayloadError::NothingFlagged);
    }
    validate_firmware_root(plan, firmware_root)?;
    if board_manifest.is_empty() {
        return Err(NorPayloadError::NoBoardManifest);
    }
    check_container(board_manifest, "IM4M").map_err(|reason| {
        NorPayloadError::ManifestNotImage4 {
            bytes: board_manifest.len(),
            reason,
        }
    })?;
    let mut payload = NorPayload {
        images: Vec::with_capacity(plan.components.len()),
        unclaimed_secondary: plan.unclaimed_secondary.clone(),
    };
    for component in &plan.components {
        let source = firmware_root.join(&component.path);
        let bytes = std::fs::read(&source).map_err(|error| NorPayloadError::PayloadUnreadable {
            component: component.name.clone(),
            path: source.clone(),
            error,
        })?;
        let retag = retagged_payload(component, &bytes).map_err(|reason| {
            NorPayloadError::PayloadRetagRejected {
                component: component.name.clone(),
                path: source.clone(),
                reason,
            }
        })?;
        let retagged = retag.was_retagged();
        let served_type = component.payload_type.clone();
        let bytes = retag.into_bytes();
        let image = wrap_image4(&bytes, board_manifest).map_err(|reason| {
            NorPayloadError::PayloadNotImage4 {
                component: component.name.clone(),
                path: source.clone(),
                reason,
            }
        })?;
        payload.images.push(NorImage {
            name: component.name.clone(),
            slot: component.slot,
            source,
            payload_bytes: bytes.len(),
            image_bytes: image.len(),
            image,
            served_type,
            retagged,
        });
    }
    Ok(payload)
}

#[must_use]
pub fn wants_flash_version_1(arguments: &Dictionary) -> bool {
    arguments.contains_key(ARGUMENT_FLASH_VERSION_1)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RetagOutcome {
    NotApplicable(Vec<u8>),
    Retagged(Vec<u8>),
}

impl RetagOutcome {
    fn was_retagged(&self) -> bool {
        matches!(self, Self::Retagged(_))
    }

    fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::NotApplicable(bytes) | Self::Retagged(bytes) => bytes,
        }
    }
}

fn retagged_payload(component: &NorComponent, bytes: &[u8]) -> Result<RetagOutcome, String> {
    let Some(payload_type) = component.payload_type.as_deref() else {
        return Ok(RetagOutcome::NotApplicable(bytes.to_vec()));
    };
    let Some(expected) = component.digest.as_deref() else {
        return Ok(RetagOutcome::NotApplicable(bytes.to_vec()));
    };
    let retagged = retag_im4p_type(bytes, payload_type).ok_or_else(|| {
        format!(
            "Info/Img4PayloadType names {payload_type:?} and the shipped container's own Image4 payload type could not be located, or is a different length, so it cannot be retagged to it"
        )
    })?;
    let method = component
        .hash_method
        .clone()
        .unwrap_or_else(|| match expected.len() {
            48 => "sha2-384".to_string(),
            32 => "sha2-256".to_string(),
            other => format!(
                "no HashMethod is stated and the {other} byte Digest matches neither sha2-384 nor sha2-256"
            ),
        });
    let digest = payload_digest(&retagged, &method).ok_or_else(|| {
        format!(
            "HashMethod {method:?} is not sha2-384 or sha2-256, so the manifest Digest cannot be checked against the container retagged to {payload_type:?}"
        )
    })?;
    if digest.as_slice() == expected {
        Ok(RetagOutcome::Retagged(retagged))
    } else {
        Err(format!(
            "the container retagged to {payload_type:?} hashes to {} under {method}, which does not match the manifest Digest {}, so the retagged bytes are not this component's signed payload",
            hex_bytes(&digest),
            hex_bytes(expected)
        ))
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn retag_im4p_type(bytes: &[u8], payload_type: &str) -> Option<Vec<u8>> {
    let (type_at, type_len) = im4p_payload_type_span(bytes)?;
    if type_len != payload_type.len() {
        return None;
    }
    let mut retagged = bytes.to_vec();
    retagged[type_at..type_at + type_len].copy_from_slice(payload_type.as_bytes());
    Some(retagged)
}

fn im4p_payload_type_span(bytes: &[u8]) -> Option<(usize, usize)> {
    let (tag, contents) = der_first(bytes).ok()?;
    if tag != DER_SEQUENCE {
        return None;
    }
    let (magic_tag, magic) = der_first(contents).ok()?;
    if magic_tag != DER_IA5STRING || magic != b"IM4P" {
        return None;
    }
    let after_magic = contents.get(der_ia5string("IM4P").len()..)?;
    let (type_tag, type_bytes) = der_first(after_magic).ok()?;
    if type_tag != DER_IA5STRING {
        return None;
    }
    let type_at = subslice_offset(bytes, type_bytes)?;
    Some((type_at, type_bytes.len()))
}

fn subslice_offset(whole: &[u8], part: &[u8]) -> Option<usize> {
    let start = whole.as_ptr() as usize;
    let at = part.as_ptr() as usize;
    let offset = at.checked_sub(start)?;
    if offset.checked_add(part.len())? <= whole.len() {
        Some(offset)
    } else {
        None
    }
}

fn payload_digest(bytes: &[u8], method: &str) -> Option<Vec<u8>> {
    match method {
        "sha2-384" => Some(sha384(bytes).to_vec()),
        "sha2-256" => Some(sha256(bytes).to_vec()),
        _ => None,
    }
}

const DER_IA5STRING: u8 = 0x16;
const DER_SEQUENCE: u8 = 0x30;
const DER_CONTEXT_0: u8 = 0xA0;

pub fn wrap_image4(payload: &[u8], manifest: &[u8]) -> Result<Vec<u8>, String> {
    match container_magic(payload)? {
        magic if magic == "IMG4" => return Ok(payload.to_vec()),
        magic if magic == "IM4P" => {}
        other => {
            return Err(format!(
                "container magic is {other:?}, expected IM4P or IMG4"
            ));
        }
    }
    check_container(manifest, "IM4M")?;
    let mut body = der_ia5string("IMG4");
    body.extend_from_slice(payload);
    body.extend(der_element(DER_CONTEXT_0, manifest));
    Ok(der_element(DER_SEQUENCE, &body))
}

fn container_magic(bytes: &[u8]) -> Result<String, String> {
    let (tag, contents) = der_first(bytes)?;
    if tag != DER_SEQUENCE {
        return Err(format!(
            "outermost element has tag {tag:#04x}, expected a SEQUENCE"
        ));
    }
    let (magic_tag, magic) = der_first(contents)?;
    if magic_tag != DER_IA5STRING {
        return Err(format!(
            "first element inside the SEQUENCE has tag {magic_tag:#04x}, expected an IA5String"
        ));
    }
    std::str::from_utf8(magic)
        .map(str::to_string)
        .map_err(|error| format!("container magic is not text: {error}"))
}

fn check_container(bytes: &[u8], expected: &str) -> Result<(), String> {
    let magic = container_magic(bytes)?;
    if magic == expected {
        Ok(())
    } else {
        Err(format!(
            "container magic is {magic:?}, expected {expected:?}"
        ))
    }
}

fn der_first(bytes: &[u8]) -> Result<(u8, &[u8]), String> {
    let tag = *bytes
        .first()
        .ok_or_else(|| "empty DER element".to_string())?;
    let first_length = *bytes
        .get(1)
        .ok_or_else(|| "DER element ends before its length".to_string())?;
    let (length, header) = if first_length & 0x80 == 0 {
        (usize::from(first_length), 2usize)
    } else {
        let count = usize::from(first_length & 0x7F);
        if count == 0 || count > 4 {
            return Err(format!(
                "DER length uses {count} bytes, which is not a definite length this reader accepts"
            ));
        }
        let end = 2 + count;
        let digits = bytes
            .get(2..end)
            .ok_or_else(|| "DER element ends inside its length".to_string())?;
        let mut length = 0usize;
        for digit in digits {
            length = (length << 8) | usize::from(*digit);
        }
        (length, end)
    };
    bytes
        .get(header..header + length)
        .map(|contents| (tag, contents))
        .ok_or_else(|| {
            format!(
                "DER element announces {length} content bytes and only {} follow its header",
                bytes.len().saturating_sub(header)
            )
        })
}

fn der_element(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(contents.len() + 6);
    encoded.push(tag);
    let length = contents.len();
    if length < 0x80 {
        encoded.push(length as u8);
    } else {
        let digits = length.to_be_bytes();
        let first = digits
            .iter()
            .position(|digit| *digit != 0)
            .unwrap_or(digits.len() - 1);
        let significant = &digits[first..];
        encoded.push(0x80 | significant.len() as u8);
        encoded.extend_from_slice(significant);
    }
    encoded.extend_from_slice(contents);
    encoded
}

fn der_ia5string(text: &str) -> Vec<u8> {
    der_element(DER_IA5STRING, text.as_bytes())
}

#[derive(Debug)]
pub enum NorPayloadError {
    NoManifest,
    NothingFlagged,
    ComponentPathMissing {
        component: String,
    },
    FirmwareRootUnresolved {
        root: PathBuf,
        component: String,
        component_path: String,
        joined: PathBuf,
        missing: usize,
        planned: usize,
        doubled_segment: Option<String>,
    },
    PayloadUnreadable {
        component: String,
        path: PathBuf,
        error: io::Error,
    },
    PayloadRetagRejected {
        component: String,
        path: PathBuf,
        reason: String,
    },
    PayloadNotImage4 {
        component: String,
        path: PathBuf,
        reason: String,
    },
    NoBoardManifest,
    ManifestNotImage4 {
        bytes: usize,
        reason: String,
    },
}

impl fmt::Display for NorPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoManifest => f.write_str(
                "the chosen build identity carries no Manifest, so no firmware component can be resolved from it",
            ),
            Self::NothingFlagged => f.write_str(
                "the chosen build identity flags no IsFirmwarePayload or IsSecondaryFirmwarePayload component, so there is no firmware payload to serve",
            ),
            Self::ComponentPathMissing { component } => write!(
                f,
                "manifest component {component} is flagged as a firmware payload and carries no Info/Path"
            ),
            Self::FirmwareRootUnresolved {
                root,
                component,
                component_path,
                joined,
                missing,
                planned,
                doubled_segment,
            } => {
                write!(
                    f,
                    "the firmware root {} does not hold the components the chosen build identity names: {missing} of {planned} do not resolve under it. The first is {component}, whose Info/Path is {component_path} and which joined into {}. The root is expected to be the directory the IPSW's Firmware tree was extracted under, the parent of that tree, because every Info/Path already begins with the tree's own name",
                    root.display(),
                    joined.display()
                )?;
                if let Some(segment) = doubled_segment {
                    write!(
                        f,
                        ". The root's own last component is {segment} and so is the first segment of {component_path}, so the join doubles it as {segment}/{segment}: the root this tree wants is {}",
                        root.parent()
                            .filter(|parent| !parent.as_os_str().is_empty())
                            .map_or_else(
                                || "the directory it was extracted under".to_string(),
                                |parent| parent.display().to_string()
                            )
                    )?;
                }
                f.write_str(
                    ". Nothing is stripped here and no repaired root is tried, because a root this host corrects quietly is one that stays wrong on the next run",
                )
            }
            Self::PayloadUnreadable {
                component,
                path,
                error,
            } => write!(f, "{component} at {}: {error}", path.display()),
            Self::PayloadRetagRejected {
                component,
                path,
                reason,
            } => write!(
                f,
                "{component} at {}: shipped digest does not match the manifest, so the shipped bytes are not served under this component's name: {reason}",
                path.display()
            ),
            Self::PayloadNotImage4 {
                component,
                path,
                reason,
            } => write!(f, "{component} at {}: {reason}", path.display()),
            Self::NoBoardManifest => f.write_str(
                "no board manifest was resolved for this device, and every NOR component requires one to be wrapped into: a bare IM4P is not refused by the guest at parse time, it is accepted and silently stripped of the manifest that makes it verifiable, and AMAuthInstallApImg4DecodeRestoreInfo, which runs before that, refuses a bare IM4P outright with error 99",
            ),
            Self::ManifestNotImage4 { bytes, reason } => {
                write!(f, "the {bytes} byte board manifest is unusable: {reason}")
            }
        }
    }
}

impl std::error::Error for NorPayloadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PayloadUnreadable { error, .. } => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha384;

    fn im4p(tag: &str, payload: &[u8]) -> Vec<u8> {
        let mut body = der_ia5string("IM4P");
        body.extend(der_ia5string(tag));
        body.extend(der_ia5string("test payload"));
        body.extend(der_element(0x04, payload));
        der_element(DER_SEQUENCE, &body)
    }

    fn im4m() -> Vec<u8> {
        let mut body = der_ia5string("IM4M");
        body.extend(der_element(0x02, &[0x00]));
        der_element(DER_SEQUENCE, &body)
    }

    fn info(pairs: &[(&str, Value)]) -> Value {
        let mut info = Dictionary::new();
        for (key, value) in pairs {
            info.insert((*key).to_string(), value.clone());
        }
        let mut entry = Dictionary::new();
        entry.insert("Info".to_string(), Value::Dictionary(info));
        Value::Dictionary(entry)
    }

    fn identity(components: &[(&str, Value)]) -> BuildIdentity {
        let mut manifest = Dictionary::new();
        for (name, entry) in components {
            manifest.insert((*name).to_string(), entry.clone());
        }
        BuildIdentity {
            index: 1,
            device_class: "j274ap".to_string(),
            variant: "Customer Erase Install (IPSW)".to_string(),
            info: Dictionary::new(),
            components: Some(manifest),
        }
    }

    fn primary(path: &str) -> Value {
        info(&[
            (INFO_IS_FIRMWARE_PAYLOAD, Value::Boolean(true)),
            (INFO_PATH, Value::String(path.to_string())),
        ])
    }

    fn secondary(path: &str) -> Value {
        info(&[
            (INFO_IS_SECONDARY_FIRMWARE_PAYLOAD, Value::Boolean(true)),
            (INFO_PATH, Value::String(path.to_string())),
        ])
    }

    #[test]
    fn the_component_set_comes_from_the_flags_and_never_from_the_board() {
        let identity = identity(&[
            ("ANS", primary("Firmware/ansf.t8103.release.im4p")),
            (
                "DeviceTree",
                primary("Firmware/all_flash/DeviceTree.j274ap.im4p"),
            ),
            ("LLB", primary("Firmware/all_flash/LLB.j274.RELEASE.im4p")),
            (
                "iBoot",
                primary("Firmware/all_flash/iBoot.j274.RELEASE.im4p"),
            ),
            (
                "SEP",
                secondary("Firmware/all_flash/sep-firmware.j274.RELEASE.im4p"),
            ),
            (
                "RestoreSEP",
                secondary("Firmware/all_flash/sep-firmware.j274.RELEASE.im4p"),
            ),
            (
                "iBootData",
                info(&[
                    ("IsFUDFirmware", Value::Boolean(true)),
                    (
                        INFO_PATH,
                        Value::String("Firmware/all_flash/iBootData.j274.RELEASE.im4p".into()),
                    ),
                ]),
            ),
        ]);
        let plan = plan_nor_payload(&identity).expect("the plan is readable");
        assert_eq!(plan.components.len(), 6);
        assert_eq!(
            plan.in_slot(NorSlot::Nor)
                .iter()
                .map(|component| component.name.as_str())
                .collect::<Vec<_>>(),
            vec!["ANS", "DeviceTree", "iBoot"]
        );
        assert_eq!(plan.in_slot(NorSlot::Llb).len(), 1);
        assert_eq!(plan.in_slot(NorSlot::Sep).len(), 1);
        assert_eq!(plan.in_slot(NorSlot::RestoreSep).len(), 1);
        assert!(plan.in_slot(NorSlot::SepPatch).is_empty());
        assert!(plan.unclaimed_secondary.is_empty());
    }

    #[test]
    fn a_board_that_ships_sep_patches_gets_the_slot_and_one_that_does_not_has_no_key() {
        let with_patches = identity(&[
            ("LLB", primary("Firmware/all_flash/LLB.j575c.RELEASE.im4p")),
            (
                "SepStage1",
                secondary("Firmware/all_flash/sep-patches.j575c.im4p"),
            ),
        ]);
        let plan = plan_nor_payload(&with_patches).expect("the plan is readable");
        assert_eq!(plan.in_slot(NorSlot::SepPatch).len(), 1);

        let without = identity(&[("LLB", primary("Firmware/all_flash/LLB.j274.RELEASE.im4p"))]);
        let plan = plan_nor_payload(&without).expect("the plan is readable");
        assert!(plan.in_slot(NorSlot::SepPatch).is_empty());
    }

    #[test]
    fn a_secondary_payload_the_guest_has_no_reader_for_is_reported_not_swept_into_the_set() {
        let identity = identity(&[
            ("LLB", primary("Firmware/all_flash/LLB.j274.RELEASE.im4p")),
            ("SepStage2", secondary("Firmware/all_flash/sep-stage2.im4p")),
        ]);
        let plan = plan_nor_payload(&identity).expect("the plan is readable");
        assert_eq!(plan.components.len(), 1);
        assert_eq!(plan.unclaimed_secondary, vec!["SepStage2".to_string()]);
    }

    #[test]
    fn a_flagged_component_with_no_path_fails_the_plan_by_name() {
        let identity = identity(&[(
            "LLB",
            info(&[(INFO_IS_FIRMWARE_PAYLOAD, Value::Boolean(true))]),
        )]);
        match plan_nor_payload(&identity) {
            Err(NorPayloadError::ComponentPathMissing { component }) => {
                assert_eq!(component, "LLB")
            }
            other => panic!("expected a named refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_identity_with_no_manifest_is_not_read_as_an_empty_one() {
        let identity = BuildIdentity {
            index: 0,
            device_class: "j274ap".to_string(),
            variant: "Customer Erase Install (IPSW)".to_string(),
            info: Dictionary::new(),
            components: None,
        };
        assert!(matches!(
            plan_nor_payload(&identity),
            Err(NorPayloadError::NoManifest)
        ));
    }

    #[test]
    fn the_container_is_the_one_a_real_mac_holds_im4p_then_context_zero_manifest() {
        let payload = im4p("sepi", b"payload bytes");
        let manifest = im4m();
        let image = wrap_image4(&payload, &manifest).expect("the container is built");

        let (tag, contents) = der_first(&image).expect("the container parses");
        assert_eq!(tag, DER_SEQUENCE);
        let (magic_tag, magic) = der_first(contents).expect("the magic parses");
        assert_eq!(magic_tag, DER_IA5STRING);
        assert_eq!(magic, b"IMG4");

        let after_magic = &contents[der_ia5string("IMG4").len()..];
        let (payload_tag, _) = der_first(after_magic).expect("the payload parses");
        assert_eq!(payload_tag, DER_SEQUENCE);
        assert!(after_magic.starts_with(&payload));

        let after_payload = &after_magic[payload.len()..];
        let (manifest_tag, manifest_contents) =
            der_first(after_payload).expect("the manifest parses");
        assert_eq!(manifest_tag, DER_CONTEXT_0);
        assert_eq!(manifest_contents, &manifest[..]);
    }

    #[test]
    fn a_payload_that_is_already_a_container_is_not_wrapped_twice() {
        let payload = im4p("ibot", b"payload bytes");
        let manifest = im4m();
        let once = wrap_image4(&payload, &manifest).expect("the container is built");
        let twice = wrap_image4(&once, &manifest).expect("the container passes through");
        assert_eq!(once, twice);
    }

    #[test]
    fn a_manifest_that_is_not_an_im4m_is_refused_rather_than_wrapped() {
        let payload = im4p("ibot", b"payload bytes");
        let reason = wrap_image4(&payload, &payload).expect_err("a payload is not a manifest");
        assert!(reason.contains("IM4M"), "{reason}");
    }

    #[test]
    fn long_der_lengths_round_trip_through_the_encoder() {
        for length in [0usize, 1, 127, 128, 255, 256, 65535, 65536] {
            let contents = vec![0xA5u8; length];
            let encoded = der_element(DER_SEQUENCE, &contents);
            let (tag, decoded) = der_first(&encoded).expect("the element parses");
            assert_eq!(tag, DER_SEQUENCE);
            assert_eq!(decoded.len(), length);
        }
    }

    #[test]
    fn the_named_form_keys_the_primary_set_by_component_name() {
        let payload = NorPayload {
            images: vec![
                NorImage {
                    name: "iBoot".to_string(),
                    slot: NorSlot::Nor,
                    source: PathBuf::from("iBoot.im4p"),
                    payload_bytes: 4,
                    image_bytes: 4,
                    image: vec![1, 2, 3, 4],
                    served_type: None,
                    retagged: false,
                },
                NorImage {
                    name: "LLB".to_string(),
                    slot: NorSlot::Llb,
                    source: PathBuf::from("LLB.im4p"),
                    payload_bytes: 2,
                    image_bytes: 2,
                    image: vec![5, 6],
                    served_type: None,
                    retagged: false,
                },
                NorImage {
                    name: "RestoreSEP".to_string(),
                    slot: NorSlot::RestoreSep,
                    source: PathBuf::from("sep.im4p"),
                    payload_bytes: 3,
                    image_bytes: 3,
                    image: vec![7, 8, 9],
                    served_type: None,
                    retagged: false,
                },
            ],
            unclaimed_secondary: Vec::new(),
        };
        let body = payload.into_answer(true);
        assert_eq!(
            body.get(KEY_LLB_IMAGE_DATA).and_then(Value::as_data),
            Some(&[5u8, 6][..])
        );
        assert_eq!(
            body.get(KEY_RESTORE_SEP_IMAGE_DATA)
                .and_then(Value::as_data),
            Some(&[7u8, 8, 9][..])
        );
        let named = body
            .get(KEY_NOR_IMAGE_DATA)
            .and_then(Value::as_dictionary)
            .expect("the named form is a dictionary");
        assert_eq!(named.len(), 1);
        assert_eq!(
            named.get("iBoot").and_then(Value::as_data),
            Some(&[1u8, 2, 3, 4][..])
        );
        assert!(body.get(KEY_SEP_IMAGE_DATA).is_none());
        assert!(body.get(KEY_SEP_PATCH_IMAGE_DATA).is_none());
    }

    #[test]
    fn without_the_argument_the_primary_set_is_an_array_in_plan_order() {
        let payload = NorPayload {
            images: vec![
                NorImage {
                    name: "ANS".to_string(),
                    slot: NorSlot::Nor,
                    source: PathBuf::from("ans.im4p"),
                    payload_bytes: 1,
                    image_bytes: 1,
                    image: vec![1],
                    served_type: None,
                    retagged: false,
                },
                NorImage {
                    name: "iBoot".to_string(),
                    slot: NorSlot::Nor,
                    source: PathBuf::from("iboot.im4p"),
                    payload_bytes: 1,
                    image_bytes: 1,
                    image: vec![2],
                    served_type: None,
                    retagged: false,
                },
            ],
            unclaimed_secondary: Vec::new(),
        };
        let body = payload.into_answer(false);
        let ordered = body
            .get(KEY_NOR_IMAGE_DATA)
            .and_then(Value::as_array)
            .expect("the plain form is an array");
        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].as_data(), Some(&[1u8][..]));
        assert_eq!(ordered[1].as_data(), Some(&[2u8][..]));
    }

    #[test]
    fn the_argument_is_recognised_by_presence_the_way_the_guest_sends_it() {
        let mut arguments = Dictionary::new();
        assert!(!wants_flash_version_1(&arguments));
        arguments.insert(ARGUMENT_FLASH_VERSION_1.to_string(), Value::Boolean(true));
        assert!(wants_flash_version_1(&arguments));
    }

    #[test]
    fn a_component_whose_file_is_absent_fails_the_whole_payload_naming_it() {
        let identity = identity(&[("LLB", primary("Firmware/all_flash/LLB.j274.RELEASE.im4p"))]);
        let plan = plan_nor_payload(&identity).expect("the plan is readable");
        let root = std::env::temp_dir().join("ramrod-nor-payload-absent");
        match build_nor_payload(&plan, &root, &im4m()) {
            Err(NorPayloadError::FirmwareRootUnresolved {
                component, missing, ..
            }) => {
                assert_eq!(component, "LLB");
                assert_eq!(missing, 1);
            }
            other => panic!("expected a named refusal, got {other:?}"),
        }
    }

    fn extracted_firmware_tree(tree: &Path) {
        let all_flash = tree.join("all_flash");
        std::fs::create_dir_all(&all_flash).expect("the source tree is created");
        std::fs::write(
            all_flash.join("LLB.j274.RELEASE.im4p"),
            im4p("illb", b"llb payload"),
        )
        .expect("llb is written");
        std::fs::write(
            all_flash.join("sep-firmware.j274.RELEASE.im4p"),
            im4p("rsep", b"restore sep payload"),
        )
        .expect("sep is written");
    }

    fn firmware_identity() -> BuildIdentity {
        identity(&[
            ("LLB", primary("Firmware/all_flash/LLB.j274.RELEASE.im4p")),
            (
                "RestoreSEP",
                secondary("Firmware/all_flash/sep-firmware.j274.RELEASE.im4p"),
            ),
        ])
    }

    #[test]
    fn the_root_the_manifest_paths_resolve_against_is_the_parent_of_the_firmware_tree() {
        let extracted = tempfile::tempdir().expect("a temporary tree is made");
        extracted_firmware_tree(&extracted.path().join("Firmware"));
        let plan = plan_nor_payload(&firmware_identity()).expect("the plan is readable");
        validate_firmware_root(&plan, extracted.path())
            .expect("the directory the tree was extracted under resolves every component");
        let payload =
            build_nor_payload(&plan, extracted.path(), &im4m()).expect("the payload is built");
        assert_eq!(payload.images.len(), 2);
    }

    #[test]
    fn the_extracted_tree_passed_as_the_root_is_refused_and_the_doubled_segment_is_named() {
        let extracted = tempfile::tempdir().expect("a temporary tree is made");
        let tree = extracted.path().join("Firmware");
        extracted_firmware_tree(&tree);
        let plan = plan_nor_payload(&firmware_identity()).expect("the plan is readable");

        assert!(tree.join("all_flash/LLB.j274.RELEASE.im4p").is_file());
        assert!(extracted.path().join("Firmware").is_dir());

        let error = validate_firmware_root(&plan, &tree)
            .expect_err("the tree is not the root its own manifest paths resolve against");
        match &error {
            NorPayloadError::FirmwareRootUnresolved {
                root,
                component,
                joined,
                missing,
                planned,
                doubled_segment,
                ..
            } => {
                assert_eq!(root, &tree);
                assert_eq!(component, "LLB");
                assert_eq!(
                    joined,
                    &tree.join("Firmware/all_flash/LLB.j274.RELEASE.im4p")
                );
                assert_eq!((*missing, *planned), (2, 2));
                assert_eq!(doubled_segment.as_deref(), Some("Firmware"));
            }
            other => panic!("expected the root refusal, got {other:?}"),
        }
        let text = error.to_string();
        assert!(text.contains("Firmware/Firmware"), "{text}");
        assert!(
            text.contains(&extracted.path().display().to_string()),
            "{text}"
        );
        assert!(text.contains("parent of that tree"), "{text}");

        match build_nor_payload(&plan, &tree, &im4m()) {
            Err(NorPayloadError::FirmwareRootUnresolved { component, .. }) => {
                assert_eq!(component, "LLB")
            }
            other => panic!("expected the root refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_root_that_is_simply_wrong_is_refused_without_inventing_a_doubled_segment() {
        let elsewhere = tempfile::tempdir().expect("a temporary tree is made");
        std::fs::create_dir_all(elsewhere.path().join("Restore")).expect("a neighbour is created");
        let plan = plan_nor_payload(&firmware_identity()).expect("the plan is readable");
        let error = validate_firmware_root(&plan, elsewhere.path())
            .expect_err("a root that holds none of the components is refused");
        match &error {
            NorPayloadError::FirmwareRootUnresolved {
                component,
                missing,
                planned,
                doubled_segment,
                ..
            } => {
                assert_eq!(component, "LLB");
                assert_eq!((*missing, *planned), (2, 2));
                assert_eq!(doubled_segment.as_deref(), None);
            }
            other => panic!("expected the root refusal, got {other:?}"),
        }
        let text = error.to_string();
        assert!(
            text.contains("Firmware/all_flash/LLB.j274.RELEASE.im4p"),
            "{text}"
        );
        assert!(text.contains("parent of that tree"), "{text}");
        assert!(!text.contains("doubles it"), "{text}");
    }

    #[test]
    fn a_root_holding_only_part_of_the_set_is_refused_naming_what_is_short() {
        let extracted = tempfile::tempdir().expect("a temporary tree is made");
        let all_flash = extracted.path().join("Firmware").join("all_flash");
        std::fs::create_dir_all(&all_flash).expect("the source tree is created");
        std::fs::write(
            all_flash.join("LLB.j274.RELEASE.im4p"),
            im4p("illb", b"llb payload"),
        )
        .expect("llb is written");
        let plan = plan_nor_payload(&firmware_identity()).expect("the plan is readable");
        match validate_firmware_root(&plan, extracted.path()) {
            Err(NorPayloadError::FirmwareRootUnresolved {
                component,
                missing,
                planned,
                ..
            }) => {
                assert_eq!(component, "RestoreSEP");
                assert_eq!((missing, planned), (1, 2));
            }
            other => panic!("expected the root refusal, got {other:?}"),
        }
    }

    #[test]
    fn every_component_in_the_plan_is_built_from_its_own_file() {
        let root = std::env::temp_dir().join(format!(
            "ramrod-nor-payload-{}-{}",
            std::process::id(),
            "built"
        ));
        let all_flash = root.join("Firmware").join("all_flash");
        std::fs::create_dir_all(&all_flash).expect("the source tree is created");
        let llb = im4p("illb", b"llb payload");
        let sep = im4p("rsep", b"restore sep payload");
        std::fs::write(all_flash.join("LLB.j274.RELEASE.im4p"), &llb).expect("llb is written");
        std::fs::write(all_flash.join("sep-firmware.j274.RELEASE.im4p"), &sep)
            .expect("sep is written");

        let identity = identity(&[
            ("LLB", primary("Firmware/all_flash/LLB.j274.RELEASE.im4p")),
            (
                "RestoreSEP",
                secondary("Firmware/all_flash/sep-firmware.j274.RELEASE.im4p"),
            ),
        ]);
        let plan = plan_nor_payload(&identity).expect("the plan is readable");
        let manifest = im4m();
        let payload = build_nor_payload(&plan, &root, &manifest).expect("the payload is built");
        assert_eq!(payload.images.len(), 2);
        for image in &payload.images {
            assert!(image.image_bytes > image.payload_bytes);
            let (_, contents) = der_first(&image.image).expect("the container parses");
            let (_, magic) = der_first(contents).expect("the magic parses");
            assert_eq!(magic, b"IMG4");
        }
        assert!(payload.total_image_bytes() > llb.len() + sep.len());
    }

    #[test]
    fn restore_sep_is_planned_by_name_even_without_the_secondary_flag() {
        let identity = identity(&[(
            "RestoreSEP",
            info(&[(
                INFO_PATH,
                Value::String("Firmware/all_flash/sep-firmware.j274.RELEASE.im4p".into()),
            )]),
        )]);
        let plan = plan_nor_payload(&identity).expect("the plan is readable");
        assert_eq!(plan.in_slot(NorSlot::RestoreSep).len(), 1);
        assert!(plan.unclaimed_secondary.is_empty());
    }

    #[test]
    fn restore_sep_is_retagged_from_the_shipped_type_to_the_type_the_identity_signs() {
        let root = tempfile::tempdir().expect("a temporary tree is made");
        let all_flash = root.path().join("Firmware").join("all_flash");
        std::fs::create_dir_all(&all_flash).expect("the source tree is created");
        let shipped = im4p("sepi", b"sep firmware");
        let retagged = {
            let (at, len) = im4p_payload_type_span(&shipped).expect("the shipped file has a type");
            let mut bytes = shipped.clone();
            bytes[at..at + len].copy_from_slice(b"rsep");
            bytes
        };
        assert_ne!(shipped, retagged);
        std::fs::write(all_flash.join("sep-firmware.j274.RELEASE.im4p"), &shipped)
            .expect("sep is written");

        let digest = sha384(&retagged).to_vec();
        let identity = identity(&[(
            "RestoreSEP",
            restore_sep_entry(
                "Firmware/all_flash/sep-firmware.j274.RELEASE.im4p",
                "rsep",
                digest,
            ),
        )]);
        let plan = plan_nor_payload(&identity).expect("the plan is readable");
        let payload = build_nor_payload(&plan, root.path(), &im4m()).expect("the payload is built");
        assert_eq!(payload.images.len(), 1);
        assert_eq!(payload.images[0].slot, NorSlot::RestoreSep);

        let (_, contents) = der_first(&payload.images[0].image).expect("the container parses");
        let after_magic = &contents[der_ia5string("IMG4").len()..];
        assert!(
            after_magic.starts_with(&retagged),
            "RestoreSEPImageData must wrap the rsep container the identity signs, not the shipped sepi file"
        );
        assert!(
            !after_magic.starts_with(&shipped),
            "wrapping the shipped sepi file is what load_sep_os rejects"
        );
    }

    #[test]
    fn restore_sep_without_a_board_manifest_is_refused_rather_than_served_bare() {
        let root = tempfile::tempdir().expect("a temporary tree is made");
        let all_flash = root.path().join("Firmware").join("all_flash");
        std::fs::create_dir_all(&all_flash).expect("the source tree is created");
        let shipped = im4p("sepi", b"sep firmware");
        let retagged = {
            let (at, len) = im4p_payload_type_span(&shipped).expect("the shipped file has a type");
            let mut bytes = shipped.clone();
            bytes[at..at + len].copy_from_slice(b"rsep");
            bytes
        };
        std::fs::write(all_flash.join("sep-firmware.j274.RELEASE.im4p"), &shipped)
            .expect("sep is written");
        let identity = identity(&[(
            "RestoreSEP",
            restore_sep_entry(
                "Firmware/all_flash/sep-firmware.j274.RELEASE.im4p",
                "rsep",
                sha384(&retagged).to_vec(),
            ),
        )]);
        let plan = plan_nor_payload(&identity).expect("the plan is readable");
        match build_nor_payload(&plan, root.path(), &[]) {
            Err(NorPayloadError::NoBoardManifest) => {}
            other => panic!(
                "a bare IM4P is what AMAuthInstallApImg4DecodeRestoreInfo refuses with 99, so a missing board manifest must fail the build rather than serve one: {other:?}"
            ),
        }
    }

    #[test]
    fn a_shipped_digest_that_does_not_match_the_manifest_fails_the_build_rather_than_serving_the_shipped_bytes()
     {
        let root = tempfile::tempdir().expect("a temporary tree is made");
        let all_flash = root.path().join("Firmware").join("all_flash");
        std::fs::create_dir_all(&all_flash).expect("the source tree is created");
        let shipped = im4p("sepi", b"sep firmware");
        std::fs::write(all_flash.join("sep-firmware.j274.RELEASE.im4p"), &shipped)
            .expect("sep is written");

        let wrong_digest = sha384(b"not the retagged container").to_vec();
        let identity = identity(&[(
            "RestoreSEP",
            restore_sep_entry(
                "Firmware/all_flash/sep-firmware.j274.RELEASE.im4p",
                "rsep",
                wrong_digest,
            ),
        )]);
        let plan = plan_nor_payload(&identity).expect("the plan is readable");
        match build_nor_payload(&plan, root.path(), &im4m()) {
            Err(NorPayloadError::PayloadRetagRejected {
                component, reason, ..
            }) => {
                assert_eq!(component, "RestoreSEP");
                assert!(reason.contains("does not match"), "{reason}");
            }
            other => panic!(
                "a digest mismatch must fail the build rather than silently serve the shipped sepi bytes under RestoreSEPImageData: {other:?}"
            ),
        }
    }

    #[test]
    fn an_unknown_hash_method_fails_the_build_rather_than_serving_the_shipped_bytes() {
        let root = tempfile::tempdir().expect("a temporary tree is made");
        let all_flash = root.path().join("Firmware").join("all_flash");
        std::fs::create_dir_all(&all_flash).expect("the source tree is created");
        let shipped = im4p("sepi", b"sep firmware");
        std::fs::write(all_flash.join("sep-firmware.j274.RELEASE.im4p"), &shipped)
            .expect("sep is written");

        let mut info = Dictionary::new();
        info.insert(
            INFO_IS_SECONDARY_FIRMWARE_PAYLOAD.to_string(),
            Value::Boolean(true),
        );
        info.insert(
            INFO_PATH.to_string(),
            Value::String("Firmware/all_flash/sep-firmware.j274.RELEASE.im4p".to_string()),
        );
        info.insert(
            INFO_IMG4_PAYLOAD_TYPE.to_string(),
            Value::String("rsep".to_string()),
        );
        info.insert(
            INFO_HASH_METHOD.to_string(),
            Value::String("sha1".to_string()),
        );
        let mut entry = Dictionary::new();
        entry.insert("Info".to_string(), Value::Dictionary(info));
        entry.insert(COMPONENT_DIGEST.to_string(), Value::Data(vec![0u8; 20]));
        let identity = identity(&[("RestoreSEP", Value::Dictionary(entry))]);
        let plan = plan_nor_payload(&identity).expect("the plan is readable");
        match build_nor_payload(&plan, root.path(), &im4m()) {
            Err(NorPayloadError::PayloadRetagRejected {
                component, reason, ..
            }) => {
                assert_eq!(component, "RestoreSEP");
                assert!(reason.contains("sha1"), "{reason}");
            }
            other => panic!(
                "a HashMethod this host cannot compute must fail the build rather than silently serve the shipped bytes: {other:?}"
            ),
        }
    }

    fn restore_sep_entry(path: &str, payload_type: &str, digest: Vec<u8>) -> Value {
        let mut info = Dictionary::new();
        info.insert(
            INFO_IS_SECONDARY_FIRMWARE_PAYLOAD.to_string(),
            Value::Boolean(true),
        );
        info.insert(INFO_PATH.to_string(), Value::String(path.to_string()));
        info.insert(
            INFO_IMG4_PAYLOAD_TYPE.to_string(),
            Value::String(payload_type.to_string()),
        );
        let mut entry = Dictionary::new();
        entry.insert("Info".to_string(), Value::Dictionary(info));
        entry.insert(COMPONENT_DIGEST.to_string(), Value::Data(digest));
        Value::Dictionary(entry)
    }
}
