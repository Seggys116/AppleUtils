use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::apfs_image::{
    APFS_VOL_ROLE_PREBOOT, APFS_VOL_ROLE_SYSTEM, APPLE_APFS_TYPE_GUID,
    EFI_SYSTEM_PARTITION_TYPE_GUID, LINUX_FILESYSTEM_TYPE_GUID, parse_gpt,
};
use crate::apfs_read::{self, ApfsContainer, MountedVolume, VolumeChoice};

use crate::crypto::embedded_panic_crc32;

// Apple ANS exposes 4 KiB logical blocks independently of the image container.
const SECTOR: u32 = 4096;
const APFS_BLOCK: u32 = 4096;
const ALIGN: u64 = 1024 * 1024;
const GB: u64 = 1 << 30;
const MB: u64 = 1 << 20;

pub const SLIDER_MIN_GB: u32 = 8;
pub const SLIDER_MAX_GB: u32 = 512;
pub const SLIDER_DEFAULT_GB: u32 = 32;

pub const DEFAULT_INSTALLER_DATA_URL: &str =
    "https://github.com/AsahiLinux/asahi-installer-data/raw/prod/data/installer_data.json";

const QCOW_MAGIC: u32 = 0x5146_49FB;
const CLUSTER_BITS: u32 = 16;
const CLUSTER: u64 = 1 << CLUSTER_BITS;

static ZERO_CLUSTER: [u8; CLUSTER as usize] = [0u8; CLUSTER as usize];

fn zero_fill_needed(span: &mut [u8]) {
    let mut checked = 0usize;
    while checked < span.len() {
        let take = (span.len() - checked).min(ZERO_CLUSTER.len());
        if span[checked..checked + take] != ZERO_CLUSTER[..take] {
            span[checked..].fill(0);
            return;
        }
        checked += take;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpsError {
    Message(String),
    Io(String),
}

impl std::fmt::Display for OpsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(m) | Self::Io(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for OpsError {}

impl From<io::Error> for OpsError {
    fn from(err: io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

fn err(msg: impl Into<String>) -> OpsError {
    OpsError::Message(msg.into())
}

#[derive(Debug, Clone, Deserialize)]
pub struct InstallerData {
    pub os_list: Vec<OsEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsEntry {
    pub name: String,
    pub default_os_name: Option<String>,
    pub boot_object: Option<String>,
    pub next_object: Option<String>,
    pub package: Option<String>,
    #[serde(default)]
    pub supported_fw: Option<Vec<String>>,
    #[serde(default)]
    pub expert: bool,
    #[serde(default)]
    pub partitions: Vec<PartitionTemplate>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PartitionTemplate {
    pub name: String,
    #[serde(rename = "type")]
    pub part_type: Option<String>,
    pub size: Option<String>,
    pub image: Option<String>,
    pub source: Option<String>,
    #[serde(default)]
    pub copy_firmware: bool,
    #[serde(default)]
    pub copy_installer_data: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLatest {
    pub os_name: String,
    pub package_url: String,
    pub boot_object: String,
    pub next_object: String,
    pub root_image: String,
    pub kernel_image: String,
    pub supported_fw: Option<Vec<String>>,
    pub firmware_partitions: Vec<String>,
    pub installer_data_partitions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flavor {
    pub index: usize,
    pub name: String,
    pub default_os_name: String,
    pub package_url: String,
    pub expert: bool,
    pub slug: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirmwareRequirements {
    pub supported_fw: Option<Vec<String>>,
    pub firmware_partitions: Vec<String>,
    pub installer_data_partitions: Vec<String>,
}

impl From<&ResolvedLatest> for FirmwareRequirements {
    fn from(resolved: &ResolvedLatest) -> Self {
        Self {
            supported_fw: resolved.supported_fw.clone(),
            firmware_partitions: resolved.firmware_partitions.clone(),
            installer_data_partitions: resolved.installer_data_partitions.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifacts {
    pub kernel: Vec<u8>,
    pub m1n1: Vec<u8>,
    pub efi_files: Vec<(String, Vec<u8>)>,
    pub firmware_requirements: Option<FirmwareRequirements>,
    pub firmware: Option<crate::asahi_firmware::BoundFirmware>,
    pub installer_data: Option<crate::asahi_installer_data::InstallerDataTemplate>,
    pub m1n1_stage1: Vec<u8>,
    pub root_fs: Vec<u8>,
    pub root_path: Option<PathBuf>,
    pub boot_fs: Vec<u8>,
    pub boot_path: Option<PathBuf>,
}

impl Artifacts {
    pub fn memory(kernel: Vec<u8>, m1n1: Vec<u8>, root_fs: Vec<u8>) -> Self {
        Self {
            kernel,
            m1n1,
            efi_files: Vec::new(),
            firmware_requirements: None,
            firmware: None,
            installer_data: None,
            m1n1_stage1: Vec::new(),
            root_fs,
            root_path: None,
            boot_fs: Vec::new(),
            boot_path: None,
        }
    }

    pub fn validate_firmware(&self) -> Result<(), OpsError> {
        let Some(requirements) = &self.firmware_requirements else {
            return Ok(());
        };
        if requirements
            .installer_data_partitions
            .iter()
            .any(|partition| !partition.eq_ignore_ascii_case("EFI"))
        {
            return Err(err(
                "package requests installer data outside the EFI partition",
            ));
        }
        if !requirements.installer_data_partitions.is_empty() && self.installer_data.is_none() {
            return Err(err("Asahi package requires verified installer data"));
        }
        let required =
            requirements.supported_fw.is_some() || !requirements.firmware_partitions.is_empty();
        let Some(firmware) = &self.firmware else {
            return if required {
                Err(err(
                    "Asahi package requires a verified Apple OS firmware identity",
                ))
            } else {
                Ok(())
            };
        };
        crate::asahi_firmware::bind_restore_identity(
            firmware.selection.clone(),
            firmware.restore.clone(),
        )
        .map_err(err)?;
        if requirements
            .supported_fw
            .as_ref()
            .is_some_and(|versions| !versions.contains(&firmware.restore.product_version))
        {
            return Err(err(
                "selected Apple OS firmware is not supported by the Asahi package",
            ));
        }
        if requirements
            .firmware_partitions
            .iter()
            .any(|partition| !partition.eq_ignore_ascii_case("EFI"))
        {
            return Err(err(
                "package requests firmware placement outside the EFI partition",
            ));
        }
        if !requirements.firmware_partitions.is_empty()
            && !self
                .efi_files
                .iter()
                .any(|(name, bytes)| name.starts_with("vendorfw/") && !bytes.is_empty())
        {
            return Err(err(
                "Asahi package requires vendor firmware in the EFI partition",
            ));
        }
        Ok(())
    }

    fn validate_disk_firmware(&self) -> Result<(), OpsError> {
        self.validate_firmware()?;
        if let Some(firmware) = &self.firmware
            && self.installer_data.as_ref().is_none_or(|data| {
                !data.matches_firmware(firmware)
                    || data.preboot_files().is_empty()
                    || data.system_files().is_empty()
            })
        {
            return Err(err(
                "selected Apple OS firmware requires its on-disk restore bundle",
            ));
        }
        Ok(())
    }

    pub fn root_len(&self) -> Result<u64, OpsError> {
        payload_len(self.root_path.as_deref(), &self.root_fs)
    }

    pub fn boot_len(&self) -> Result<u64, OpsError> {
        payload_len(self.boot_path.as_deref(), &self.boot_fs)
    }
}

fn payload_len(path: Option<&Path>, bytes: &[u8]) -> Result<u64, OpsError> {
    if let Some(path) = path {
        Ok(std::fs::metadata(path)?.len())
    } else {
        Ok(bytes.len() as u64)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Latest,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscReport {
    pub path: String,
    pub virtual_size: u64,
    pub sector_size: u32,
    pub apfs_lba: u64,
    pub efi_lba: u64,
    pub boot_lba: u64,
    pub linux_lba: u64,
    pub efi_uuid: String,
}

pub fn parse_installer_data(json: &str) -> Result<InstallerData, OpsError> {
    serde_json::from_str(json).map_err(|e| err(format!("installer metadata: {e}")))
}

pub fn flavor_slug(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    for token in ["minimal", "server", "gnome", "xfce", "kde", "plasma"] {
        if lower.contains(token) {
            return token.to_string();
        }
    }
    let mut slug = String::new();
    for c in lower.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c);
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    slug.trim_matches('-').to_string()
}

pub fn list_flavors(data: &InstallerData) -> Vec<Flavor> {
    data.os_list
        .iter()
        .enumerate()
        .filter(|(_, os)| os.package.as_ref().is_some_and(|p| !p.is_empty()))
        .map(|(index, os)| Flavor {
            index,
            name: os.name.clone(),
            default_os_name: os
                .default_os_name
                .clone()
                .unwrap_or_else(|| os.name.clone()),
            package_url: os.package.clone().unwrap_or_default(),
            expert: os.expert,
            slug: flavor_slug(&os.name),
        })
        .collect()
}

pub fn list_installable_flavors(data: &InstallerData) -> Vec<Flavor> {
    list_flavors(data)
        .into_iter()
        .filter(|f| !f.expert)
        .collect()
}

fn resolve_from_entry(os: &OsEntry) -> Result<ResolvedLatest, OpsError> {
    let package_url = os
        .package
        .as_ref()
        .ok_or_else(|| err("missing package URL"))?
        .clone();
    if !package_url.contains("://") && package_url.is_empty() {
        return Err(err("package URL missing from installer metadata"));
    }
    let root_image = os
        .partitions
        .iter()
        .find(|p| p.image.as_deref() == Some("root.img") || p.name.eq_ignore_ascii_case("Root"))
        .and_then(|p| p.image.clone())
        .or_else(|| {
            os.partitions
                .iter()
                .rev()
                .find(|p| p.part_type.as_deref() == Some("Linux") && p.image.is_some())
                .and_then(|p| p.image.clone())
        })
        .unwrap_or_else(|| "root.img".into());
    let kernel_image = os
        .partitions
        .iter()
        .find(|p| p.image.as_deref() == Some("boot.img") || p.name.eq_ignore_ascii_case("Boot"))
        .and_then(|p| p.image.clone())
        .unwrap_or_else(|| "boot.img".into());
    Ok(ResolvedLatest {
        os_name: os
            .default_os_name
            .clone()
            .unwrap_or_else(|| os.name.clone()),
        package_url,
        boot_object: os.boot_object.clone().unwrap_or_else(|| "m1n1.bin".into()),
        next_object: os
            .next_object
            .clone()
            .unwrap_or_else(|| "m1n1/boot.bin".into()),
        root_image,
        kernel_image,
        supported_fw: os.supported_fw.clone(),
        firmware_partitions: os
            .partitions
            .iter()
            .filter(|partition| partition.copy_firmware)
            .map(|partition| partition.name.clone())
            .collect(),
        installer_data_partitions: os
            .partitions
            .iter()
            .filter(|partition| partition.copy_installer_data)
            .map(|partition| partition.name.clone())
            .collect(),
    })
}

pub fn resolve_latest(data: &InstallerData) -> Result<ResolvedLatest, OpsError> {
    let os = data
        .os_list
        .iter()
        .find(|os| !os.expert && os.package.as_ref().is_some_and(|p| !p.is_empty()))
        .ok_or_else(|| err("installer metadata names no installable OS package"))?;
    resolve_from_entry(os)
}

pub fn resolve_os(data: &InstallerData, query: &str) -> Result<ResolvedLatest, OpsError> {
    let q = query.trim();
    if q.is_empty() {
        return resolve_latest(data);
    }
    let q_lower = q.to_ascii_lowercase();
    let flavors = list_flavors(data);
    if flavors.is_empty() {
        return Err(err("installer metadata names no OS package"));
    }
    if let Some(hit) = flavors.iter().find(|f| f.slug == q_lower) {
        return resolve_from_entry(&data.os_list[hit.index]);
    }
    let named: Vec<&Flavor> = flavors
        .iter()
        .filter(|f| {
            f.name.eq_ignore_ascii_case(q)
                || f.default_os_name.eq_ignore_ascii_case(q)
                || f.name.to_ascii_lowercase().contains(&q_lower)
                || f.default_os_name.to_ascii_lowercase().contains(&q_lower)
        })
        .collect();
    match named.as_slice() {
        [one] => resolve_from_entry(&data.os_list[one.index]),
        [] => {
            let available = flavors
                .iter()
                .map(|f| format!("{} ({})", f.slug, f.name))
                .collect::<Vec<_>>()
                .join(", ");
            Err(err(format!(
                "no OS flavour matches {q:?}; available: {available}"
            )))
        }
        many => {
            if let Some(non_expert) = many.iter().find(|f| !f.expert) {
                return resolve_from_entry(&data.os_list[non_expert.index]);
            }
            resolve_from_entry(&data.os_list[many[0].index])
        }
    }
}

pub fn resolve_custom(data: &InstallerData) -> Result<ResolvedLatest, OpsError> {
    resolve_latest(data)
}

pub fn clamp_slider_gb(gb: u32) -> u32 {
    gb.clamp(SLIDER_MIN_GB, SLIDER_MAX_GB)
}

pub fn slider_gb_to_bytes(gb: u32) -> u64 {
    u64::from(clamp_slider_gb(gb)) * GB
}

pub fn min_disc_bytes() -> u64 {
    u64::from(SLIDER_MIN_GB) * GB
}

struct Layout {
    disc_size: u64,
    stub_lba: u64,
    stub_sectors: u64,
    efi_lba: u64,
    efi_sectors: u64,
    boot_lba: u64,
    boot_sectors: u64,
    linux_lba: u64,
    linux_sectors: u64,
    last_lba: u64,
}

fn align_up(v: u64, a: u64) -> u64 {
    v.div_ceil(a) * a
}

fn plan_layout(disc_size: u64, root_len: u64, boot_len: u64) -> Result<Layout, OpsError> {
    let last_lba = disc_size / u64::from(SECTOR);
    if last_lba < 64 {
        return Err(err("disc is too small for a GPT"));
    }
    let first = align_up(
        crate::apfs_image::gpt_first_usable_lba(SECTOR) * u64::from(SECTOR),
        ALIGN,
    ) / u64::from(SECTOR);
    let tail = crate::apfs_image::gpt_reserved_blocks(SECTOR);
    let usable_end = last_lba.saturating_sub(tail);
    if usable_end <= first {
        return Err(err("disc is too small for partitions"));
    }

    let large = disc_size >= 8 * GB;
    let stub_bytes = if large {
        2560 * MB
    } else {
        align_up((disc_size / 4).max(1024 * 1024), ALIGN)
    };
    let efi_bytes = if large { 512 * MB } else { ALIGN };
    let stub_sectors = stub_bytes / u64::from(SECTOR);
    let efi_sectors = efi_bytes / u64::from(SECTOR);
    let stub_lba = first;
    let efi_lba = stub_lba + stub_sectors;
    let boot_bytes = if boot_len == 0 {
        0
    } else {
        align_up(boot_len, ALIGN)
    };
    let boot_sectors = boot_bytes / u64::from(SECTOR);
    let boot_lba = efi_lba + efi_sectors;
    let linux_lba = boot_lba + boot_sectors;
    if linux_lba >= usable_end {
        return Err(err("disc is too small for APFS stub, EFI and Linux"));
    }
    let linux_sectors = usable_end - linux_lba;
    let linux_bytes = linux_sectors * u64::from(SECTOR);
    if linux_bytes < root_len.max(4 * 1024) {
        return Err(err(
            "Linux partition is smaller than the root filesystem image",
        ));
    }
    Ok(Layout {
        disc_size,
        stub_lba,
        stub_sectors,
        efi_lba,
        efi_sectors,
        boot_lba,
        boot_sectors,
        linux_lba,
        linux_sectors,
        last_lba: last_lba - 1,
    })
}

fn new_guid() -> Result<[u8; 16], OpsError> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    bytes[7] = (bytes[7] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(bytes)
}

fn apfs_uuid(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn guid_hyphen_lower(on_disk: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes(on_disk[0..4].try_into().unwrap());
    let d2 = u16::from_le_bytes(on_disk[4..6].try_into().unwrap());
    let d3 = u16::from_le_bytes(on_disk[6..8].try_into().unwrap());
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d1,
        d2,
        d3,
        on_disk[8],
        on_disk[9],
        on_disk[10],
        on_disk[11],
        on_disk[12],
        on_disk[13],
        on_disk[14],
        on_disk[15]
    )
}

fn utf16le_name(name: &str) -> [u8; 72] {
    let mut out = [0u8; 72];
    for (i, unit) in name.encode_utf16().take(36).enumerate() {
        let b = unit.to_le_bytes();
        out[i * 2] = b[0];
        out[i * 2 + 1] = b[1];
    }
    out
}

fn put_u32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(buf: &mut [u8], at: usize, v: u64) {
    buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

struct SparseImage {
    size: u64,
    ranges: BTreeMap<u64, Vec<u8>>,
}

impl SparseImage {
    fn new(size: u64) -> Self {
        Self {
            size,
            ranges: BTreeMap::new(),
        }
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let zero_cluster = [0u8; CLUSTER as usize];
        for (index, chunk) in data.chunks(CLUSTER as usize).enumerate() {
            if chunk != &zero_cluster[..chunk.len()] {
                self.ranges
                    .insert(offset + index as u64 * CLUSTER, chunk.to_vec());
            }
        }
    }

    fn to_qcow2_ranges(&self) -> Vec<(u64, Vec<u8>)> {
        self.ranges.iter().map(|(k, v)| (*k, v.clone())).collect()
    }
}

type GptPartitionSpec<'a> = ([u8; 16], [u8; 16], u64, u64, &'a str);

fn write_gpt(
    image: &mut SparseImage,
    layout: &Layout,
    disk_guid: [u8; 16],
    parts: &[GptPartitionSpec],
) {
    let bs = SECTOR as usize;
    let mut mbr = vec![0u8; bs];
    mbr[0x1BE] = 0x00;
    mbr[0x1BE + 1..0x1BE + 4].copy_from_slice(&[0, 2, 0]);
    mbr[0x1BE + 4] = 0xEE;
    mbr[0x1BE + 5..0x1BE + 8].copy_from_slice(&[0xff, 0xff, 0xff]);
    mbr[0x1BE + 8] = 1;
    let mbr_sectors = layout.last_lba.min(u64::from(u32::MAX)) as u32;
    mbr[0x1BE + 12..0x1BE + 16].copy_from_slice(&mbr_sectors.to_le_bytes());
    mbr[0x1FE] = 0x55;
    mbr[0x1FF] = 0xAA;
    image.write_at(0, &mbr);

    let mut array = vec![0u8; 128 * 128];
    for (i, (ty, uniq, first, last, name)) in parts.iter().enumerate() {
        let at = i * 128;
        array[at..at + 16].copy_from_slice(ty);
        array[at + 16..at + 32].copy_from_slice(uniq);
        array[at + 32..at + 40].copy_from_slice(&first.to_le_bytes());
        array[at + 40..at + 48].copy_from_slice(&last.to_le_bytes());
        array[at + 56..at + 128].copy_from_slice(&utf16le_name(name));
    }
    let array_crc = embedded_panic_crc32(&array);
    image.write_at(u64::from(SECTOR) * 2, &array);

    let write_header = |current: u64, alt: u64, part_lba: u64| {
        let mut h = vec![0u8; bs];
        h[0..8].copy_from_slice(b"EFI PART");
        put_u32(&mut h, 8, 0x0001_0000);
        put_u32(&mut h, 12, 92);
        put_u64(&mut h, 24, current);
        put_u64(&mut h, 32, alt);
        put_u64(&mut h, 40, crate::apfs_image::gpt_first_usable_lba(SECTOR));
        put_u64(
            &mut h,
            48,
            layout.last_lba - crate::apfs_image::gpt_reserved_blocks(SECTOR),
        );
        h[56..72].copy_from_slice(&disk_guid);
        put_u64(&mut h, 72, part_lba);
        put_u32(&mut h, 80, 128);
        put_u32(&mut h, 84, 128);
        put_u32(&mut h, 88, array_crc);
        let crc = embedded_panic_crc32(&h[..92]);
        put_u32(&mut h, 16, crc);
        h
    };

    let backup_header_lba = layout.last_lba;
    let backup_entries = layout.last_lba - (array.len() as u64).div_ceil(u64::from(SECTOR));
    image.write_at(u64::from(SECTOR), &write_header(1, backup_header_lba, 2));
    image.write_at(backup_entries * u64::from(SECTOR), &array);
    image.write_at(
        backup_header_lba * u64::from(SECTOR),
        &write_header(backup_header_lba, 1, backup_entries),
    );
}

pub fn validate_stage1(image: &[u8]) -> Result<(), OpsError> {
    if image.len() < 2048 || !contains_bytes(image, b"##m1n1_ver##") {
        return Err(err("stage one must be a complete m1n1 raw boot image"));
    }
    if contains_bytes(image, b"Chainloading files not supported in this build!") {
        return Err(err(
            "stage-one m1n1 was built without CHAINLOADING; use the installer boot/m1n1.bin, not EFI m1n1/boot.bin",
        ));
    }
    Ok(())
}

fn build_stage1(m1n1: &[u8], efi_uuid: &str, next_object: &str) -> Result<Vec<u8>, OpsError> {
    validate_stage1(m1n1)?;
    if next_object.is_empty()
        || next_object
            .bytes()
            .any(|b| b == 0 || b == b'\n' || b == b'\r')
    {
        return Err(err(
            "chainload destination must be a nonempty single-line path",
        ));
    }
    let mut out = m1n1.to_vec();
    out.extend_from_slice(format!("chosen.asahi,efi-system-partition={efi_uuid}\n").as_bytes());
    out.extend_from_slice(format!("chainload={efi_uuid};{next_object}\n").as_bytes());
    out.extend_from_slice(&[0; 4]);
    Ok(out)
}

pub fn fetch_installer_stage1() -> Result<Vec<u8>, OpsError> {
    let version = String::from_utf8(fetch_url("https://cdn.asahilinux.org/installer/latest")?)
        .map_err(|e| err(format!("installer version is not UTF-8: {e}")))?;
    let version = version.trim();
    if version.is_empty()
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err(err("installer version contains invalid characters"));
    }
    let archive = tempfile::NamedTempFile::new()?;
    fetch_url_to_file(
        &format!("https://cdn.asahilinux.org/installer/installer-{version}.tar.gz"),
        archive.path(),
    )?;
    read_installer_stage1(archive.path())
}

pub fn read_installer_stage1(archive: &Path) -> Result<Vec<u8>, OpsError> {
    let output = std::process::Command::new("tar")
        .arg("-xOf")
        .arg(archive)
        .arg("./boot/m1n1.bin")
        .output()?;
    if !output.status.success() {
        return Err(err(format!(
            "cannot read installer stage one: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    validate_stage1(&output.stdout)?;
    Ok(output.stdout)
}

fn fat_name_83(name: &str) -> [u8; 11] {
    let mut out = [b' '; 11];
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) => (s, e),
        None => (name, ""),
    };
    for (i, b) in stem.bytes().take(8).enumerate() {
        out[i] = b.to_ascii_uppercase();
    }
    for (i, b) in ext.bytes().take(3).enumerate() {
        out[8 + i] = b.to_ascii_uppercase();
    }
    out
}

fn qcow_refcount_shape(after_rc: u64, cluster: u64) -> (u64, u64) {
    let rc_per_block = cluster / 2;
    let mut rc_blocks = 1u64;
    let mut rc_table_clusters = 1u64;
    loop {
        let total = 1 + rc_table_clusters + rc_blocks + after_rc;
        let new_blocks = total.div_ceil(rc_per_block).max(1);
        let new_table = (new_blocks * 8).div_ceil(cluster).max(1);
        if new_blocks == rc_blocks && new_table == rc_table_clusters {
            return (rc_table_clusters, rc_blocks);
        }
        rc_blocks = new_blocks;
        rc_table_clusters = new_table;
    }
}

pub fn write_qcow2_image(
    path: &Path,
    virtual_size: u64,
    ranges: &[(u64, Vec<u8>)],
) -> Result<(), OpsError> {
    write_qcow2(path, virtual_size, ranges)
}

pub fn guest_write(path: &Path, offset: u64, data: &[u8]) -> Result<(), OpsError> {
    let mut img = Qcow2::open(path)?;
    img.write_at(offset, data)
}

fn write_qcow2(path: &Path, virtual_size: u64, ranges: &[(u64, Vec<u8>)]) -> Result<(), OpsError> {
    let cluster = CLUSTER;
    let virtual_size = align_up(virtual_size, cluster);
    let l2_entries = cluster / 8;
    let virtual_clusters = virtual_size / cluster;
    let l1_size = virtual_clusters.div_ceil(l2_entries);

    let mut clusters: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    for (offset, data) in ranges {
        let mut cursor = 0usize;
        while cursor < data.len() {
            let pos = offset + cursor as u64;
            let idx = pos / cluster;
            let within = (pos % cluster) as usize;
            let take = (cluster as usize - within).min(data.len() - cursor);
            let slot = clusters
                .entry(idx)
                .or_insert_with(|| vec![0u8; cluster as usize]);
            slot[within..within + take].copy_from_slice(&data[cursor..cursor + take]);
            cursor += take;
        }
    }
    clusters.retain(|_, v| v.iter().any(|b| *b != 0));

    let used_l2: BTreeMap<u64, ()> = clusters
        .keys()
        .map(|idx| idx / l2_entries)
        .map(|i| (i, ()))
        .collect();

    let l1_bytes = align_up(l1_size * 8, cluster);
    let l1_clusters = l1_bytes / cluster;
    let l2_count = used_l2.len() as u64;
    let data_count = clusters.len() as u64;
    let after_rc = l1_clusters + l2_count + data_count;
    let (rc_table_clusters, rc_blocks) = qcow_refcount_shape(after_rc, cluster);

    let mut host = 1u64;
    let refcount_table_offset = host * cluster;
    host += rc_table_clusters;
    let mut rc_block_offsets = Vec::with_capacity(rc_blocks as usize);
    for _ in 0..rc_blocks {
        rc_block_offsets.push(host * cluster);
        host += 1;
    }
    let l1_offset = host * cluster;
    host += l1_clusters;

    let mut l2_host: BTreeMap<u64, u64> = BTreeMap::new();
    for idx in used_l2.keys() {
        l2_host.insert(*idx, host * cluster);
        host += 1;
    }
    let mut data_host: BTreeMap<u64, u64> = BTreeMap::new();
    for idx in clusters.keys() {
        data_host.insert(*idx, host * cluster);
        host += 1;
    }
    let total_clusters = host;

    let mut file = File::create(path)?;
    let mut header = vec![0u8; cluster as usize];
    header[0..4].copy_from_slice(&QCOW_MAGIC.to_be_bytes());
    header[4..8].copy_from_slice(&3u32.to_be_bytes());
    header[20..24].copy_from_slice(&CLUSTER_BITS.to_be_bytes());
    header[24..32].copy_from_slice(&virtual_size.to_be_bytes());
    header[36..40].copy_from_slice(&(l1_size as u32).to_be_bytes());
    header[40..48].copy_from_slice(&l1_offset.to_be_bytes());
    header[48..56].copy_from_slice(&refcount_table_offset.to_be_bytes());
    header[56..60].copy_from_slice(&(rc_table_clusters as u32).to_be_bytes());
    header[72..80].copy_from_slice(&0u64.to_be_bytes());
    header[80..88].copy_from_slice(&0u64.to_be_bytes());
    header[88..96].copy_from_slice(&0u64.to_be_bytes());
    header[96..100].copy_from_slice(&4u32.to_be_bytes());
    header[100..104].copy_from_slice(&104u32.to_be_bytes());
    file.write_all(&header)?;

    let mut refcount_table = vec![0u8; (rc_table_clusters * cluster) as usize];
    for (i, off) in rc_block_offsets.iter().enumerate() {
        let at = i * 8;
        refcount_table[at..at + 8].copy_from_slice(&off.to_be_bytes());
    }
    file.write_all(&refcount_table)?;

    let mut remaining = total_clusters;
    let rc_per_block = cluster / 2;
    for _ in 0..rc_blocks {
        let mut block = vec![0u8; cluster as usize];
        let n = remaining.min(rc_per_block) as usize;
        for i in 0..n {
            let at = i * 2;
            block[at..at + 2].copy_from_slice(&1u16.to_be_bytes());
        }
        remaining = remaining.saturating_sub(n as u64);
        file.write_all(&block)?;
    }

    let mut l1 = vec![0u8; l1_bytes as usize];
    for (idx, host_off) in &l2_host {
        let at = (*idx as usize) * 8;
        let entry = host_off | (1u64 << 63);
        l1[at..at + 8].copy_from_slice(&entry.to_be_bytes());
    }
    file.write_all(&l1)?;

    for l1_idx in used_l2.keys() {
        let mut l2 = vec![0u8; cluster as usize];
        let base = l1_idx * l2_entries;
        for i in 0..l2_entries {
            let guest = base + i;
            if let Some(off) = data_host.get(&guest) {
                let entry = off | (1u64 << 63);
                let at = (i as usize) * 8;
                l2[at..at + 8].copy_from_slice(&entry.to_be_bytes());
            }
        }
        file.write_all(&l2)?;
    }

    for idx in clusters.keys() {
        file.write_all(clusters.get(idx).unwrap())?;
    }
    Ok(())
}

const QCOW_COPIED: u64 = 1u64 << 63;
const QCOW_COMPRESSED: u64 = 1u64 << 62;

pub trait ImageIo {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), OpsError>;
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), OpsError>;
}

struct Qcow2 {
    file: File,
    virtual_size: u64,
    cluster: u64,
    l1_offset: u64,
    l1: Vec<u64>,
    refcount_table_offset: u64,
    refcount_table_clusters: u32,
    refcount_order: u32,
    refcount_table: Vec<u64>,
    l2_cache: BTreeMap<usize, Vec<u64>>,
}

impl Qcow2 {
    fn open(path: &Path) -> Result<Self, OpsError> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .or_else(|_| std::fs::OpenOptions::new().read(true).open(path))?;
        let mut header = [0u8; 104];
        file.read_exact(&mut header[..72])?;
        let magic = u32::from_be_bytes(header[0..4].try_into().unwrap());
        if magic != QCOW_MAGIC {
            return Err(err("not a qcow2 image"));
        }
        let version = u32::from_be_bytes(header[4..8].try_into().unwrap());
        if version != 2 && version != 3 {
            return Err(err(format!("unsupported qcow2 version {version}")));
        }
        let mut refcount_order = 4u32;
        if version == 3 {
            file.read_exact(&mut header[72..104])?;
            let _header_length = u32::from_be_bytes(header[100..104].try_into().unwrap());
            let order = u32::from_be_bytes(header[96..100].try_into().unwrap());
            if order != 0 {
                refcount_order = order;
            }
        }
        if !(3..=6).contains(&refcount_order) {
            return Err(err(format!(
                "unsupported qcow2 refcount_order {refcount_order}"
            )));
        }
        let cluster_bits = u32::from_be_bytes(header[20..24].try_into().unwrap());
        let virtual_size = u64::from_be_bytes(header[24..32].try_into().unwrap());
        let l1_size = u32::from_be_bytes(header[36..40].try_into().unwrap());
        let l1_offset = u64::from_be_bytes(header[40..48].try_into().unwrap());
        let refcount_table_offset = u64::from_be_bytes(header[48..56].try_into().unwrap());
        let refcount_table_clusters = u32::from_be_bytes(header[56..60].try_into().unwrap());
        let cluster = 1u64 << cluster_bits;
        if refcount_table_offset == 0 || refcount_table_clusters == 0 {
            return Err(err("qcow2 header is missing a refcount table"));
        }
        let table_bytes = refcount_table_clusters as u64 * cluster;
        if table_bytes > 8 * MB {
            return Err(err("qcow2 refcount table is too large"));
        }
        file.seek(SeekFrom::Start(refcount_table_offset))?;
        let mut raw_table = vec![0u8; table_bytes as usize];
        file.read_exact(&mut raw_table)?;
        let refcount_table = raw_table
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_be_bytes(*c) & !0x1ff)
            .collect();
        file.seek(SeekFrom::Start(l1_offset))?;
        let mut raw = vec![0u8; l1_size as usize * 8];
        file.read_exact(&mut raw)?;
        let l1 = raw
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_be_bytes(*c) & !QCOW_COPIED)
            .collect();
        Ok(Self {
            file,
            virtual_size,
            cluster,
            l1_offset,
            l1,
            refcount_table_offset,
            refcount_table_clusters,
            refcount_order,
            refcount_table,
            l2_cache: BTreeMap::new(),
        })
    }

    fn l2_entries(&self) -> u64 {
        self.cluster / 8
    }

    fn refcount_entry_bytes(&self) -> u64 {
        1u64 << self.refcount_order.saturating_sub(3)
    }

    fn refcount_entries_per_block(&self) -> u64 {
        let bytes = self.refcount_entry_bytes();
        self.cluster.checked_div(bytes).unwrap_or(0)
    }

    fn extend_by_cluster(&mut self) -> Result<u64, OpsError> {
        let len = self.file.metadata()?.len();
        let off = align_up(len, self.cluster);
        self.file.set_len(off + self.cluster)?;
        Ok(off)
    }

    fn write_refcount_value(&mut self, offset: u64, count: u16) -> Result<(), OpsError> {
        let n = self.refcount_entry_bytes() as usize;
        if n == 2 {
            self.file.seek(SeekFrom::Start(offset))?;
            self.file.write_all(&count.to_be_bytes())?;
            return Ok(());
        }
        if n == 0 || n > 8 {
            return Err(err(format!(
                "unsupported qcow2 refcount_order {}",
                self.refcount_order
            )));
        }
        let be = (count as u64).to_be_bytes();
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&be[8 - n..])?;
        Ok(())
    }

    fn ensure_refcount_block(&mut self, block_index: u64) -> Result<u64, OpsError> {
        let Some(slot) = self.refcount_table.get(block_index as usize).copied() else {
            return Err(err(format!(
                "qcow2 refcount table ({} clusters) has no slot for block {block_index}",
                self.refcount_table_clusters
            )));
        };
        if slot != 0 {
            return Ok(slot);
        }
        let off = self.extend_by_cluster()?;
        let zeros = vec![0u8; self.cluster as usize];
        self.file.seek(SeekFrom::Start(off))?;
        self.file.write_all(&zeros)?;
        self.refcount_table[block_index as usize] = off;
        let table_at = self.refcount_table_offset + block_index * 8;
        self.file.seek(SeekFrom::Start(table_at))?;
        self.file.write_all(&off.to_be_bytes())?;
        self.set_cluster_refcount(off / self.cluster, 1)?;
        Ok(off)
    }

    fn set_cluster_refcount(&mut self, cluster_index: u64, count: u16) -> Result<(), OpsError> {
        let entries = self.refcount_entries_per_block();
        if entries == 0 {
            return Err(err("qcow2 refcount block has no entries"));
        }
        let block_index = cluster_index / entries;
        let entry_index = cluster_index % entries;
        let block_off = self.ensure_refcount_block(block_index)?;
        let at = block_off + entry_index * self.refcount_entry_bytes();
        self.write_refcount_value(at, count)
    }

    fn allocate_cluster(&mut self) -> Result<u64, OpsError> {
        let off = self.extend_by_cluster()?;
        self.set_cluster_refcount(off / self.cluster, 1)?;
        Ok(off)
    }

    #[cfg(test)]
    fn cluster_refcount(&mut self, cluster_index: u64) -> Result<u16, OpsError> {
        let entries = self.refcount_entries_per_block();
        if entries == 0 {
            return Ok(0);
        }
        let block_index = cluster_index / entries;
        let entry_index = cluster_index % entries;
        let Some(&block_off) = self.refcount_table.get(block_index as usize) else {
            return Ok(0);
        };
        if block_off == 0 {
            return Ok(0);
        }
        let n = self.refcount_entry_bytes() as usize;
        let at = block_off + entry_index * n as u64;
        let mut buf = [0u8; 8];
        if n == 0 || n > buf.len() {
            return Err(err(format!(
                "unsupported qcow2 refcount_order {}",
                self.refcount_order
            )));
        }
        self.file.seek(SeekFrom::Start(at))?;
        self.file.read_exact(&mut buf[..n])?;
        let mut padded = [0u8; 8];
        padded[8 - n..].copy_from_slice(&buf[..n]);
        Ok(u64::from_be_bytes(padded) as u16)
    }

    fn ensure_l2(&mut self, l1_idx: usize) -> Result<u64, OpsError> {
        if l1_idx >= self.l1.len() {
            return Err(err("guest offset is outside the qcow2 L1 table"));
        }
        if self.l1[l1_idx] != 0 {
            return Ok(self.l1[l1_idx]);
        }
        let l2 = self.allocate_cluster()?;
        let zeros = vec![0u8; self.cluster as usize];
        self.file.seek(SeekFrom::Start(l2))?;
        self.file.write_all(&zeros)?;
        self.l1[l1_idx] = l2;
        let entry = l2 | QCOW_COPIED;
        self.file
            .seek(SeekFrom::Start(self.l1_offset + (l1_idx as u64) * 8))?;
        self.file.write_all(&entry.to_be_bytes())?;
        self.l2_cache
            .insert(l1_idx, vec![0u64; self.l2_entries() as usize]);
        Ok(l2)
    }

    fn load_l2(&mut self, l1_idx: usize, l2_off: u64) -> Result<(), OpsError> {
        if self.l2_cache.contains_key(&l1_idx) {
            return Ok(());
        }
        let entries = self.l2_entries() as usize;
        let mut raw = vec![0u8; entries * 8];
        self.file.seek(SeekFrom::Start(l2_off))?;
        self.file.read_exact(&mut raw)?;
        let table = raw
            .as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| u64::from_be_bytes(*chunk))
            .collect();
        self.l2_cache.insert(l1_idx, table);
        Ok(())
    }

    fn host_cluster_for_write(&mut self, guest: u64) -> Result<u64, OpsError> {
        let l2_entries = self.l2_entries();
        let l1_idx = (guest / l2_entries) as usize;
        let l2_idx = (guest % l2_entries) as usize;
        let l2_off = self.ensure_l2(l1_idx)?;
        self.load_l2(l1_idx, l2_off)?;
        let raw_entry = self.l2_cache[&l1_idx][l2_idx];
        let host = raw_entry & !QCOW_COPIED & !QCOW_COMPRESSED;
        if host != 0 {
            return Ok(host);
        }
        let host = self.allocate_cluster()?;
        let zeros = vec![0u8; self.cluster as usize];
        self.file.seek(SeekFrom::Start(host))?;
        self.file.write_all(&zeros)?;
        let entry = host | QCOW_COPIED;
        self.file
            .seek(SeekFrom::Start(l2_off + l2_idx as u64 * 8))?;
        self.file.write_all(&entry.to_be_bytes())?;
        self.l2_cache.get_mut(&l1_idx).expect("just loaded")[l2_idx] = entry;
        Ok(host)
    }

    fn lookup_host(&mut self, guest: u64) -> Result<u64, OpsError> {
        let l2_entries = self.l2_entries();
        let l1_idx = (guest / l2_entries) as usize;
        let l2_idx = (guest % l2_entries) as usize;
        let Some(&l2_off) = self.l1.get(l1_idx) else {
            return Ok(0);
        };
        if l2_off == 0 {
            return Ok(0);
        }
        self.load_l2(l1_idx, l2_off)?;
        let raw_entry = self.l2_cache[&l1_idx][l2_idx];
        Ok(raw_entry & !QCOW_COPIED & !QCOW_COMPRESSED)
    }
}

impl ImageIo for Qcow2 {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), OpsError> {
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            if pos >= self.virtual_size {
                zero_fill_needed(&mut buf[done..]);
                break;
            }
            let guest = pos / self.cluster;
            let within = (pos % self.cluster) as usize;
            let first_take = (self.cluster as usize - within).min(buf.len() - done);
            let host = self.lookup_host(guest)?;

            let mut end = done + first_take;
            if host == 0 {
                let mut next_guest = guest + 1;
                while end < buf.len() && (offset + end as u64) < self.virtual_size {
                    if self.lookup_host(next_guest)? != 0 {
                        break;
                    }
                    end += (self.cluster as usize).min(buf.len() - end);
                    next_guest += 1;
                }
                zero_fill_needed(&mut buf[done..end]);
            } else {
                let mut next_guest = guest + 1;
                let mut expected_host = host + self.cluster;
                while end < buf.len() && (offset + end as u64) < self.virtual_size {
                    if self.lookup_host(next_guest)? != expected_host {
                        break;
                    }
                    end += (self.cluster as usize).min(buf.len() - end);
                    next_guest += 1;
                    expected_host += self.cluster;
                }
                self.file.seek(SeekFrom::Start(host + within as u64))?;
                self.file.read_exact(&mut buf[done..end])?;
            }
            done = end;
        }
        Ok(())
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), OpsError> {
        let mut done = 0usize;
        while done < data.len() {
            let pos = offset + done as u64;
            if pos >= self.virtual_size {
                return Err(err("write past the end of the qcow2 virtual disc"));
            }
            let guest = pos / self.cluster;
            let within = (pos % self.cluster) as usize;
            let first_take = (self.cluster as usize - within).min(data.len() - done);
            let host = self.host_cluster_for_write(guest)?;

            let mut end = done + first_take;
            let mut next_guest = guest + 1;
            let mut expected_host = host + self.cluster;
            while end < data.len() && (offset + end as u64) < self.virtual_size {
                if self.lookup_host(next_guest)? != expected_host {
                    break;
                }
                end += (self.cluster as usize).min(data.len() - end);
                next_guest += 1;
                expected_host += self.cluster;
            }
            self.file.seek(SeekFrom::Start(host + within as u64))?;
            self.file.write_all(&data[done..end])?;
            done = end;
        }
        Ok(())
    }
}

struct RawImage {
    file: File,
}

impl RawImage {
    fn open(path: &Path) -> Result<Self, OpsError> {
        Ok(Self {
            file: std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .or_else(|_| std::fs::OpenOptions::new().read(true).open(path))?,
        })
    }
}

impl ImageIo for RawImage {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), OpsError> {
        self.file.seek(SeekFrom::Start(offset))?;
        match self.file.read_exact(buf) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                buf.fill(0);
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), OpsError> {
        let end = offset + data.len() as u64;
        let len = self.file.metadata()?.len();
        if end > len {
            self.file.set_len(end)?;
        }
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(data)?;
        Ok(())
    }
}

fn open_image(path: &Path) -> Result<Box<dyn ImageIo>, OpsError> {
    if is_qcow2_path(path) {
        Ok(Box::new(Qcow2::open(path)?))
    } else {
        Ok(Box::new(RawImage::open(path)?))
    }
}

pub fn open_disc(path: &Path) -> Result<Box<dyn ImageIo>, OpsError> {
    open_image(path)
}

fn is_qcow2_path(path: &Path) -> bool {
    File::open(path)
        .ok()
        .and_then(|mut f| {
            let mut m = [0u8; 4];
            f.read_exact(&mut m).ok()?;
            Some(u32::from_be_bytes(m) == QCOW_MAGIC)
        })
        .unwrap_or(false)
}

pub fn qcow2_magic_is_present(path: &Path) -> bool {
    is_qcow2_path(path)
}

fn read_range(img: &mut dyn ImageIo, offset: u64, len: usize) -> Result<Vec<u8>, OpsError> {
    let mut buf = vec![0u8; len];
    img.read_at(offset, &mut buf)?;
    Ok(buf)
}

fn efi_payloads(
    artifacts: &Artifacts,
    next_object: &str,
    actual_vgid: Option<&str>,
) -> Result<Vec<(String, Vec<u8>)>, OpsError> {
    artifacts.validate_disk_firmware()?;
    let mut files = artifacts.efi_files.clone();
    if let Some(template) = &artifacts.installer_data {
        let vgid =
            actual_vgid.ok_or_else(|| err("installer data requires actual APFS volume group"))?;
        for (relative, bytes) in template.files_for_vgid(vgid).map_err(err)? {
            let name = format!("asahi/{relative}");
            files.retain(|(existing, _)| !existing.eq_ignore_ascii_case(&name));
            files.push((name, bytes));
        }
    }
    for (name, data) in [
        (next_object, &artifacts.m1n1),
        ("asahi/kernel", &artifacts.kernel),
    ] {
        if !data.is_empty() {
            files.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
            files.push((name.into(), data.clone()));
        }
    }
    if let Some(firmware) = &artifacts.firmware {
        let name = "asahi/firmware.json";
        let bytes = serde_json::to_vec_pretty(firmware).map_err(|error| err(error.to_string()))?;
        files.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
        files.push((name.into(), bytes));
    }
    Ok(files)
}

fn container_boot_vgid(container: &[u8]) -> Result<String, OpsError> {
    let mut source = crate::apfs_verify::SliceBlocks::new(container, APFS_BLOCK);
    let mut mounted = ApfsContainer::mount(
        &mut source,
        APFS_BLOCK,
        container.len() as u64 / u64::from(APFS_BLOCK),
    )
    .map_err(|e| err(e.to_string()))?;
    let volumes = mounted.volumes().map_err(|e| err(e.to_string()))?;
    let candidates = collect_picker_vgids(&mut mounted, &volumes);
    let preboot = mounted
        .open_volume_chosen(&VolumeChoice::Role(APFS_VOL_ROLE_PREBOOT))
        .map_err(|e| err(e.to_string()))?;
    let blessed = extract_volume_path(&mut mounted, &preboot, "/boot-volume")
        .and_then(|bytes| String::from_utf8(bytes).ok());
    resolve_boot_volume(blessed.as_deref(), None, &candidates)
}

fn compose_disk(
    artifacts: &Artifacts,
    disc_size: u64,
    next_object: &str,
    os_name: &str,
) -> Result<(SparseImage, DiscReport), OpsError> {
    artifacts.validate_disk_firmware()?;
    let layout = plan_layout(disc_size, artifacts.root_len()?, artifacts.boot_len()?)?;
    let disk_guid = new_guid()?;
    let apfs_guid = new_guid()?;
    let efi_guid = new_guid()?;
    let boot_guid = new_guid()?;
    let linux_guid = new_guid()?;
    let efi_uuid = guid_hyphen_lower(&efi_guid);
    let stage1 = build_stage1(&artifacts.m1n1_stage1, &efi_uuid, next_object)?;
    let stub_bytes = layout.stub_sectors * u64::from(SECTOR);
    let efi_bytes = layout.efi_sectors * u64::from(SECTOR);

    let apfs = crate::apfs_write::create_with_preboot_files(
        stub_bytes,
        os_name,
        &stage1,
        artifacts
            .installer_data
            .as_ref()
            .map(|data| data.system_version_bytes()),
        artifacts
            .installer_data
            .as_ref()
            .map(|data| data.preboot_files())
            .unwrap_or(&[]),
        artifacts
            .installer_data
            .as_ref()
            .map(|data| data.system_files())
            .unwrap_or(&[]),
    )
    .map_err(err)?;
    let actual_vgid = container_boot_vgid(&apfs)?;
    let fat = crate::fat32::create_efi(
        efi_bytes,
        SECTOR,
        u32::try_from(layout.efi_lba)
            .map_err(|_| err("EFI partition start exceeds FAT geometry limits"))?,
        &efi_payloads(artifacts, next_object, Some(&actual_vgid))?,
    )
    .map_err(err)?;

    let mut image = SparseImage::new(layout.disc_size);
    let mut parts = vec![
        (
            APPLE_APFS_TYPE_GUID,
            apfs_guid,
            layout.stub_lba,
            layout.stub_lba + layout.stub_sectors - 1,
            "Asahi Linux",
        ),
        (
            EFI_SYSTEM_PARTITION_TYPE_GUID,
            efi_guid,
            layout.efi_lba,
            layout.efi_lba + layout.efi_sectors - 1,
            "EFI",
        ),
    ];
    if layout.boot_sectors > 0 {
        parts.push((
            LINUX_FILESYSTEM_TYPE_GUID,
            boot_guid,
            layout.boot_lba,
            layout.boot_lba + layout.boot_sectors - 1,
            "Boot",
        ));
    }
    parts.push((
        LINUX_FILESYSTEM_TYPE_GUID,
        linux_guid,
        layout.linux_lba,
        layout.linux_lba + layout.linux_sectors - 1,
        "Linux",
    ));
    write_gpt(&mut image, &layout, disk_guid, &parts);
    image.write_at(layout.stub_lba * u64::from(SECTOR), &apfs);
    image.write_at(layout.efi_lba * u64::from(SECTOR), &fat);
    Ok((
        image,
        DiscReport {
            path: String::new(),
            virtual_size: layout.disc_size,
            sector_size: SECTOR,
            apfs_lba: layout.stub_lba,
            efi_lba: layout.efi_lba,
            boot_lba: layout.boot_lba,
            linux_lba: layout.linux_lba,
            efi_uuid,
        },
    ))
}

fn copy_file_payload(img: &mut dyn ImageIo, offset: u64, path: &Path) -> Result<(), OpsError> {
    copy_file_payload_progress(img, offset, path, |_, _| {})
}

fn copy_file_payload_progress(
    img: &mut dyn ImageIo,
    offset: u64,
    path: &Path,
    mut on_progress: impl FnMut(u64, u64),
) -> Result<(), OpsError> {
    const CHUNK: usize = 1024 * 1024;
    let total = std::fs::metadata(path)?.len();
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; CHUNK];
    let mut at = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        img.write_at(offset + at, &buf[..n])?;
        at += n as u64;
        on_progress(at, total);
    }
    Ok(())
}

fn write_root_at(
    img: &mut dyn ImageIo,
    offset: u64,
    artifacts: &Artifacts,
) -> Result<(), OpsError> {
    if let Some(path) = &artifacts.root_path {
        copy_file_payload(img, offset, path)
    } else {
        img.write_at(offset, &artifacts.root_fs)
    }
}

fn copy_payloads_into(
    path: &Path,
    report: &DiscReport,
    artifacts: &Artifacts,
) -> Result<(), OpsError> {
    copy_payloads_into_progress(path, report, artifacts, |_| {})
}

fn copy_payloads_into_progress(
    path: &Path,
    report: &DiscReport,
    artifacts: &Artifacts,
    mut on_progress: impl FnMut(f64),
) -> Result<(), OpsError> {
    let root_len = artifacts.root_len()?;
    let boot_len = artifacts.boot_len().unwrap_or(0);
    let total = root_len.saturating_add(boot_len).max(1);
    let mut done = 0u64;
    let mut img = open_image(path)?;
    if root_len > 0 {
        if let Some(root) = &artifacts.root_path {
            copy_file_payload_progress(
                &mut *img,
                report.linux_lba * u64::from(report.sector_size),
                root,
                |at, _| {
                    on_progress((done + at) as f64 / total as f64);
                },
            )?;
        } else {
            write_root_at(
                &mut *img,
                report.linux_lba * u64::from(report.sector_size),
                artifacts,
            )?;
        }
        done += root_len;
        on_progress(done as f64 / total as f64);
    }
    if let Some(boot) = &artifacts.boot_path
        && boot_len > 0
        && report.boot_lba != report.linux_lba
    {
        copy_file_payload_progress(
            &mut *img,
            report.boot_lba * u64::from(report.sector_size),
            boot,
            |at, _| {
                on_progress((done + at) as f64 / total as f64);
            },
        )?;
        done += boot_len;
        on_progress(done as f64 / total as f64);
    }
    if artifacts.boot_path.is_none() && !artifacts.boot_fs.is_empty() {
        img.write_at(
            report.boot_lba * u64::from(report.sector_size),
            &artifacts.boot_fs,
        )?;
    }
    Ok(())
}

pub fn create_qcow2_disc(
    path: &Path,
    artifacts: &Artifacts,
    disc_size: u64,
    next_object: &str,
    os_name: &str,
) -> Result<DiscReport, OpsError> {
    create_qcow2_disc_with_progress(path, artifacts, disc_size, next_object, os_name, |_| {})
}

pub fn create_qcow2_disc_with_progress(
    path: &Path,
    artifacts: &Artifacts,
    disc_size: u64,
    next_object: &str,
    os_name: &str,
    mut on_progress: impl FnMut(f64),
) -> Result<DiscReport, OpsError> {
    let size = disc_size.max(min_disc_bytes());
    on_progress(0.0);
    let (image, mut report) = compose_disk(artifacts, size, next_object, os_name)?;
    on_progress(0.06);
    write_qcow2(path, image.size, &image.to_qcow2_ranges())?;
    on_progress(0.12);
    copy_payloads_into_progress(path, &report, artifacts, |p| {
        on_progress(0.12 + 0.88 * p.clamp(0.0, 1.0));
    })?;
    on_progress(1.0);
    report.path = path.display().to_string();
    Ok(report)
}

pub fn install_raw_disc(
    path: &Path,
    artifacts: &Artifacts,
    disc_size: u64,
    next_object: &str,
    os_name: &str,
) -> Result<DiscReport, OpsError> {
    let size = disc_size.max(min_disc_bytes());
    let (image, mut report) = compose_disk(artifacts, size, next_object, os_name)?;
    let mut file = File::create(path)?;
    file.set_len(image.size)?;
    for (off, data) in image.to_qcow2_ranges() {
        file.seek(SeekFrom::Start(off))?;
        file.write_all(&data)?;
    }
    drop(file);
    copy_payloads_into(path, &report, artifacts)?;
    report.path = path.display().to_string();
    Ok(report)
}

fn detect_gpt(head: &[u8]) -> Result<crate::apfs_image::GptTable, OpsError> {
    let mut detected = None;
    for sector_size in [512, 4096] {
        if let Ok(table) = parse_gpt(head, sector_size) {
            if detected.is_some() {
                return Err(err("disc contains ambiguous GPT logical block sizes"));
            }
            detected = Some(table);
        }
    }
    detected.ok_or_else(|| err("disc has no valid 512-byte or 4096-byte GPT"))
}

pub fn read_efi_files(path: &Path, names: &[&str]) -> Result<Vec<Vec<u8>>, OpsError> {
    let mut image = open_image(path)?;
    let head = read_range(&mut *image, 0, 64 * 1024)?;
    let gpt = detect_gpt(&head)?;
    let partition = gpt
        .partitions
        .iter()
        .find(|p| p.is_efi())
        .ok_or_else(|| err("disc has no EFI partition"))?;
    let (start, end) = partition.byte_range(gpt.block_size);
    let bytes = read_range(
        &mut *image,
        start,
        usize::try_from(end - start).map_err(|_| err("EFI partition too large"))?,
    )?;
    if let [name] = names {
        crate::fat32::read_efi_file(&bytes, name)
            .map(|bytes| vec![bytes])
            .map_err(err)
    } else {
        crate::fat32::read_efi_files(&bytes, names).map_err(err)
    }
}

pub fn update_disc(path: &Path, artifacts: &Artifacts) -> Result<DiscReport, OpsError> {
    artifacts.validate_disk_firmware()?;
    validate_ans_geometry(path)?;
    validate_stage1(&artifacts.m1n1_stage1)?;
    let metadata = std::fs::metadata(path)?;
    if metadata.is_file() {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let staged = tempfile::NamedTempFile::new_in(parent)?;
        std::fs::copy(path, staged.path())?;
        let mut report = update_disc_contents(staged.path(), artifacts)?;
        validate_disc(staged.path())?;
        staged.as_file().sync_all()?;
        staged
            .persist(path)
            .map_err(|e| err(format!("cannot publish updated disc: {e}")))?;
        File::open(parent)?.sync_all()?;
        report.path = path.display().to_string();
        Ok(report)
    } else {
        update_disc_contents(path, artifacts)
    }
}

fn write_changed_blocks(
    img: &mut dyn ImageIo,
    offset: u64,
    old: &[u8],
    new: &[u8],
) -> Result<(), OpsError> {
    if old.len() != new.len() {
        return Err(err("partition update size mismatch"));
    }
    for (index, (before, after)) in old
        .chunks(CLUSTER as usize)
        .zip(new.chunks(CLUSTER as usize))
        .enumerate()
    {
        if before != after {
            img.write_at(offset + index as u64 * CLUSTER, after)?;
        }
    }
    Ok(())
}

fn update_disc_contents(path: &Path, artifacts: &Artifacts) -> Result<DiscReport, OpsError> {
    let old_stage1 = load_custom_boot_object(path, None)?;
    let (_, next_object) = chainload_target(&old_stage1)?;
    let mut img = open_image(path)?;
    let gpt_bytes = read_range(&mut *img, 0, 64 * 1024)?;
    let gpt = detect_gpt(&gpt_bytes)?;
    let apfs = gpt
        .partitions
        .iter()
        .find(|p| p.is_apple_apfs())
        .ok_or_else(|| err("disc has no Apple_APFS stub"))?;
    let efi = gpt
        .partitions
        .iter()
        .find(|p| p.is_efi())
        .ok_or_else(|| err("disc has no EFI partition"))?;
    let linux = gpt
        .partitions
        .iter()
        .rev()
        .find(|p| p.is_linux())
        .ok_or_else(|| err("disc has no Linux partition"))?;
    let boot = gpt
        .partitions
        .iter()
        .find(|p| p.is_linux() && p.first_lba != linux.first_lba);
    let (efi_start, efi_end) = efi.byte_range(gpt.block_size);
    let (linux_start, linux_end) = linux.byte_range(gpt.block_size);
    let (apfs_start, apfs_end) = apfs.byte_range(gpt.block_size);
    if artifacts.root_len()? > linux_end - linux_start {
        return Err(err("root filesystem is larger than the Linux partition"));
    }
    if artifacts.boot_len()? > 0 {
        let boot = boot.ok_or_else(|| err("disc has no separate boot partition"))?;
        let (start, end) = boot.byte_range(gpt.block_size);
        if artifacts.boot_len()? > end - start {
            return Err(err("boot image is larger than the boot partition"));
        }
    }
    let efi_uuid = guid_hyphen_lower(&efi.unique_guid);
    let stage1 = build_stage1(&artifacts.m1n1_stage1, &efi_uuid, next_object)?;
    let original_fat = read_range(
        &mut *img,
        efi_start,
        usize::try_from(efi_end - efi_start).map_err(|_| err("EFI partition too large"))?,
    )?;
    let container = read_range(
        &mut *img,
        apfs_start,
        usize::try_from(apfs_end - apfs_start).map_err(|_| err("APFS partition too large"))?,
    )?;
    let actual_vgid = container_boot_vgid(&container)?;
    let fat = crate::fat32::update_efi(
        &original_fat,
        &efi_payloads(artifacts, next_object, Some(&actual_vgid))?,
    )
    .map_err(err)?;
    let updated = crate::apfs_update::update_with_preboot_files(
        &container,
        &stage1,
        artifacts
            .installer_data
            .as_ref()
            .map(|data| data.system_version_bytes()),
        artifacts
            .installer_data
            .as_ref()
            .map(|data| data.preboot_files())
            .unwrap_or(&[]),
        artifacts
            .installer_data
            .as_ref()
            .map(|data| data.system_files())
            .unwrap_or(&[]),
    )
    .map_err(err)?;
    if updated.len() != container.len() {
        return Err(err("APFS update changed container size"));
    }
    write_changed_blocks(&mut *img, apfs_start, &container, &updated)?;
    write_changed_blocks(&mut *img, efi_start, &original_fat, &fat)?;
    if artifacts.root_len()? > 0 {
        write_root_at(&mut *img, linux_start, artifacts)?;
    }
    if let (Some(part), Some(file)) = (boot, artifacts.boot_path.as_ref()) {
        copy_file_payload(&mut *img, part.byte_range(gpt.block_size).0, file)?;
    } else if let Some(part) = boot
        && !artifacts.boot_fs.is_empty()
    {
        img.write_at(part.byte_range(gpt.block_size).0, &artifacts.boot_fs)?;
    }
    Ok(DiscReport {
        path: path.display().to_string(),
        virtual_size: linux_end,
        sector_size: gpt.block_size,
        apfs_lba: apfs.first_lba,
        efi_lba: efi.first_lba,
        boot_lba: boot.map(|p| p.first_lba).unwrap_or(linux.first_lba),
        linux_lba: linux.first_lba,
        efi_uuid,
    })
}

fn extract_volume_path(
    mounted: &mut ApfsContainer<'_>,
    volume: &MountedVolume,
    path: &str,
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    mounted.extract(volume, path, 0, None, &mut out).ok()?;
    Some(out)
}

fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn chainload_target(bytes: &[u8]) -> Result<(&str, &str), OpsError> {
    let line = bytes
        .split(|b| *b == b'\n')
        .rev()
        .find_map(|line| line.strip_prefix(b"chainload="))
        .ok_or_else(|| err("stage one has no configured chainload destination"))?;
    let line = std::str::from_utf8(line).map_err(|_| err("chainload destination is not UTF-8"))?;
    let (uuid, path) = line
        .split_once(';')
        .filter(|(uuid, path)| !uuid.is_empty() && !path.is_empty())
        .ok_or_else(|| err("configured chainload destination is invalid"))?;
    if line.bytes().any(|b| b == 0 || b == b'\r') {
        return Err(err(
            "configured chainload destination contains control bytes",
        ));
    }
    Ok((uuid, path))
}

fn contains_chainload(bytes: &[u8]) -> bool {
    chainload_target(bytes).is_ok()
}

fn picker_match(picker_vgids: &[String], want: &str) -> Option<String> {
    let want = want.trim();
    if want.is_empty() {
        return None;
    }
    picker_vgids
        .iter()
        .find(|g| g.trim().eq_ignore_ascii_case(want))
        .cloned()
}

pub fn resolve_boot_volume(
    blessed_vgid: Option<&str>,
    override_vgid: Option<&str>,
    picker_vgids: &[String],
) -> Result<String, OpsError> {
    if let Some(over) = override_vgid.map(str::trim).filter(|s| !s.is_empty()) {
        return picker_match(picker_vgids, over).ok_or_else(|| {
            err(format!(
                "Direct boot volume {over} is not a picker-visible SYSTEM volume group"
            ))
        });
    }
    if let Some(blessed) = blessed_vgid.map(str::trim).filter(|s| !s.is_empty()) {
        return picker_match(picker_vgids, blessed).ok_or_else(|| {
            err(format!(
                "blessed volume {blessed} is not a picker-visible SYSTEM volume group"
            ))
        });
    }
    Err(err(
        "Direct boot refuses without a blessed volume or an explicit boot-volume override",
    ))
}

struct PartitionBlocks<'a> {
    image: &'a mut dyn ImageIo,
    start: u64,
    length: u64,
    block_size: u32,
}

impl crate::apfs_verify::BlockSource for PartitionBlocks<'_> {
    fn read_block(
        &mut self,
        index: u64,
        into: &mut [u8],
    ) -> Result<(), crate::apfs_verify::VerifyError> {
        self.read_run(index, 1, into)
    }
    fn read_run(
        &mut self,
        index: u64,
        blocks: usize,
        into: &mut [u8],
    ) -> Result<(), crate::apfs_verify::VerifyError> {
        let bad = || crate::apfs_verify::VerifyError::BlockOutOfRange { index };
        let offset = index
            .checked_mul(u64::from(self.block_size))
            .ok_or_else(bad)?;
        if blocks.checked_mul(self.block_size as usize) != Some(into.len())
            || offset
                .checked_add(into.len() as u64)
                .is_none_or(|end| end > self.length)
        {
            return Err(bad());
        }
        self.image
            .read_at(self.start + offset, into)
            .map_err(|_| bad())
    }
}

fn partition_blocks(
    image: &mut dyn ImageIo,
    start: u64,
    end: u64,
) -> Result<(PartitionBlocks<'_>, u32, u64), OpsError> {
    let header = read_range(image, start, APFS_BLOCK as usize)?;
    let (block_size, block_count) =
        apfs_read::container_geometry_of(&header).map_err(|e| err(e.to_string()))?;
    let length = block_count
        .checked_mul(u64::from(block_size))
        .filter(|n| *n <= end - start)
        .ok_or_else(|| err("APFS geometry exceeds partition"))?;
    Ok((
        PartitionBlocks {
            image,
            start,
            length,
            block_size,
        },
        block_size,
        block_count,
    ))
}

fn collect_picker_vgids(
    mounted: &mut ApfsContainer<'_>,
    volumes: &[apfs_read::VolumeSummary],
) -> Vec<String> {
    let mut picker_vgids = Vec::new();
    for summary in volumes
        .iter()
        .filter(|summary| summary.role == APFS_VOL_ROLE_SYSTEM)
    {
        let Ok(vol) = mounted.open_volume_chosen(&VolumeChoice::Index(summary.index)) else {
            continue;
        };
        let plist = extract_volume_path(
            mounted,
            &vol,
            "/System/Library/CoreServices/SystemVersion.plist",
        );
        let launchd = extract_volume_path(mounted, &vol, "/sbin/launchd");
        if plist.as_ref().is_some_and(|bytes| !bytes.is_empty())
            && (launchd.is_some()
                || extract_volume_path(
                    mounted,
                    &vol,
                    "/Finish Installation.app/Contents/Resources/boot.bin",
                )
                .is_some_and(|b| !b.is_empty()))
        {
            picker_vgids.push(apfs_uuid(&summary.volume_group_id));
        }
    }
    picker_vgids
}

pub fn load_custom_boot_object(
    path: &Path,
    boot_volume: Option<&str>,
) -> Result<Vec<u8>, OpsError> {
    let mut img = open_image(path)?;
    let head = read_range(&mut *img, 0, 64 * 1024)?;
    let gpt = detect_gpt(&head)?;
    let apfs_part = gpt
        .partitions
        .iter()
        .find(|p| p.is_apple_apfs())
        .ok_or_else(|| err("no Apple_APFS partition"))?;
    let (start, end) = apfs_part.byte_range(gpt.block_size);
    let (mut source, block_size, block_count) = partition_blocks(&mut *img, start, end)?;
    let mut mounted = ApfsContainer::mount(&mut source, block_size, block_count)
        .map_err(|e| err(e.to_string()))?;
    let volumes = mounted.volumes().map_err(|e| err(e.to_string()))?;
    let picker_vgids = collect_picker_vgids(&mut mounted, &volumes);
    let preboot = mounted
        .open_volume_chosen(&VolumeChoice::Role(APFS_VOL_ROLE_PREBOOT))
        .map_err(|e| err(format!("APFS stub has no Preboot volume: {e}")))?;
    let blessed = extract_volume_path(&mut mounted, &preboot, "/boot-volume").and_then(|bytes| {
        let text = String::from_utf8_lossy(&bytes).trim().to_string();
        (!text.is_empty()).then_some(text)
    });
    let selected = resolve_boot_volume(blessed.as_deref(), boot_volume, &picker_vgids)?;
    extract_volume_path(&mut mounted, &preboot, &format!("/{selected}/boot.bin"))
        .filter(|bytes| !bytes.is_empty())
        .ok_or_else(|| {
            err(format!(
                "Preboot has no custom boot object for volume group {selected}"
            ))
        })
}

pub(crate) fn validate_installed_restore_bundle(
    path: &Path,
    bound: &crate::asahi_firmware::BoundFirmware,
) -> Result<bool, OpsError> {
    let mut img = open_image(path)?;
    let head = read_range(&mut *img, 0, 64 * 1024)?;
    let gpt = detect_gpt(&head)?;
    let apfs = gpt
        .partitions
        .iter()
        .find(|p| p.is_apple_apfs())
        .ok_or_else(|| err("no Apple_APFS partition"))?;
    let (start, end) = apfs.byte_range(gpt.block_size);
    let (mut source, block_size, block_count) = partition_blocks(&mut *img, start, end)?;
    let mut mounted = ApfsContainer::mount(&mut source, block_size, block_count)
        .map_err(|e| err(e.to_string()))?;
    let volumes = mounted.volumes().map_err(|e| err(e.to_string()))?;
    let candidates = collect_picker_vgids(&mut mounted, &volumes);
    let preboot = mounted
        .open_volume_chosen(&VolumeChoice::Role(APFS_VOL_ROLE_PREBOOT))
        .map_err(|e| err(e.to_string()))?;
    let blessed = extract_volume_path(&mut mounted, &preboot, "/boot-volume")
        .and_then(|bytes| String::from_utf8(bytes).ok());
    let selected = resolve_boot_volume(blessed.as_deref(), None, &candidates)?;
    let systems: Vec<_> = volumes
        .iter()
        .filter(|v| {
            v.role == APFS_VOL_ROLE_SYSTEM
                && apfs_uuid(&v.volume_group_id).eq_ignore_ascii_case(&selected)
        })
        .collect();
    let [system] = systems.as_slice() else {
        return Err(err("selected restore has no unique System volume"));
    };
    let system = mounted
        .open_volume_chosen(&VolumeChoice::Index(system.index))
        .map_err(|e| err(e.to_string()))?;
    let bootcaches = extract_volume_path(&mut mounted, &system, "/usr/standalone/bootcaches.plist")
        .ok_or_else(|| err("selected System lacks bootcaches metadata"))?;
    let bundle = crate::asahi_installer_data::restore_bundle_path(&bootcaches).map_err(err)?;
    let prefix = format!("/{selected}/{bundle}");
    let manifest = extract_volume_path(
        &mut mounted,
        &preboot,
        &format!("{prefix}/BuildManifest.plist"),
    )
    .ok_or_else(|| err("selected Preboot restore manifest is missing"))?;
    let manifest = plist::Value::from_reader(std::io::Cursor::new(manifest))
        .map_err(|e| err(e.to_string()))?;
    let manifest = manifest
        .as_dictionary()
        .ok_or_else(|| err("restore manifest is not a dictionary"))?;
    for (key, expected) in [
        ("ProductVersion", &bound.restore.product_version),
        ("ProductBuildVersion", &bound.restore.product_build),
    ] {
        if manifest.get(key).and_then(plist::Value::as_string) != Some(expected.as_str()) {
            return Err(err(format!(
                "Preboot {key} differs from installed firmware binding"
            )));
        }
    }
    for (volume, path) in [
        (
            &system,
            "/System/Library/CoreServices/SystemVersion.plist".to_owned(),
        ),
        (&preboot, format!("{prefix}/SystemVersion.plist")),
    ] {
        let bytes = extract_volume_path(&mut mounted, volume, &path)
            .ok_or_else(|| err(format!("selected restore metadata is missing: {path}")))?;
        let value = plist::Value::from_reader(std::io::Cursor::new(bytes))
            .map_err(|e| err(e.to_string()))?;
        let values = value
            .as_dictionary()
            .ok_or_else(|| err("selected SystemVersion is not a dictionary"))?;
        for (key, expected) in [
            ("ProductVersion", &bound.restore.product_version),
            ("ProductBuildVersion", &bound.restore.product_build),
        ] {
            if values.get(key).and_then(plist::Value::as_string) != Some(expected.as_str()) {
                return Err(err(format!(
                    "{path} {key} differs from installed firmware binding"
                )));
            }
        }
    }
    let (_, identity) =
        crate::asahi_firmware_archive::select_identity(manifest, &bound.selection).map_err(err)?;
    let components = identity
        .get("Manifest")
        .and_then(plist::Value::as_dictionary)
        .ok_or_else(|| err("restore identity lacks component manifest"))?;
    let temporary = tempfile::NamedTempFile::new()?;
    for (key, entry) in components {
        if !crate::asahi_firmware_archive::preboot_component(key) {
            continue;
        }
        let entry = entry
            .as_dictionary()
            .ok_or_else(|| err("invalid restore component"))?;
        let relative = entry
            .get("Info")
            .and_then(plist::Value::as_dictionary)
            .and_then(|v| v.get("Path"))
            .and_then(plist::Value::as_string)
            .ok_or_else(|| err("restore component lacks path"))?;
        crate::asahi_installer_data::relative_path(relative).map_err(err)?;
        let bytes = extract_volume_path(&mut mounted, &preboot, &format!("{prefix}/{relative}"))
            .ok_or_else(|| {
                err(format!(
                    "selected Preboot component {key} is missing: {relative}"
                ))
            })?;
        if bytes.is_empty() {
            return Err(err(format!("selected Preboot component {key} is empty")));
        }
        std::fs::write(temporary.path(), bytes)?;
        crate::asahi_firmware_archive::verify_digest(temporary.path(), entry).map_err(err)?;
    }
    let mut machine_provenance_verified = components.contains_key("SEP");
    if let Some(source) = extract_volume_path(
        &mut mounted,
        &preboot,
        &format!("{prefix}/SourceBuildManifest.plist"),
    ) {
        let digest: String = crate::crypto::sha256(&source)
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect();
        if digest != bound.restore.manifest_digest {
            return Err(err(
                "source BuildManifest digest differs from firmware binding",
            ));
        }
        let source = plist::Value::from_reader(std::io::Cursor::new(source))
            .map_err(|e| err(e.to_string()))?;
        let source = source
            .as_dictionary()
            .ok_or_else(|| err("source manifest is not a dictionary"))?;
        for key in ["ProductVersion", "ProductBuildVersion"] {
            if source.get(key) != manifest.get(key) {
                return Err(err("source manifest package differs from selected OS"));
            }
        }
        let (_, source_identity) =
            crate::asahi_firmware_archive::select_identity(source, &bound.selection)
                .map_err(err)?;
        if source_identity != identity {
            return Err(err(
                "source manifest OS identity differs from selected restore",
            ));
        }
        machine_provenance_verified = true;
        for (relative, entry) in
            crate::asahi_firmware_archive::machine_sep_candidates(source, &identity).map_err(err)?
        {
            let bytes =
                extract_volume_path(&mut mounted, &preboot, &format!("{prefix}/{relative}"))
                    .ok_or_else(|| err("machine SEP source payload is missing"))?;
            std::fs::write(temporary.path(), bytes)?;
            crate::asahi_firmware_archive::verify_digest(temporary.path(), &entry).map_err(err)?;
        }
    }
    let restored_bootcaches = extract_volume_path(
        &mut mounted,
        &preboot,
        &format!("{prefix}/usr/standalone/bootcaches.plist"),
    )
    .ok_or_else(|| err("restore bundle lacks bootcaches metadata"))?;
    if restored_bootcaches != bootcaches {
        return Err(err("System and Preboot bootcaches metadata differ"));
    }
    Ok(machine_provenance_verified)
}

pub fn inspect_created(path: &Path) -> Result<Inspected, OpsError> {
    let mut img = open_image(path)?;
    let head = read_range(&mut *img, 0, 64 * 1024)?;
    let gpt = detect_gpt(&head)?;
    let apfs_part = gpt
        .partitions
        .iter()
        .find(|p| p.is_apple_apfs())
        .ok_or_else(|| err("no Apple_APFS partition"))?;
    let efi = gpt.partitions.iter().find(|p| p.is_efi()).cloned();
    let linux = gpt.partitions.iter().rev().find(|p| p.is_linux()).cloned();
    let (start, end) = apfs_part.byte_range(gpt.block_size);
    let (mut source, block_size, block_count) = partition_blocks(&mut *img, start, end)?;
    let mut mounted = ApfsContainer::mount(&mut source, block_size, block_count)
        .map_err(|e| err(e.to_string()))?;
    let volumes = mounted.volumes().map_err(|e| err(e.to_string()))?;

    let mut snapshot_count = 0usize;
    let mut picker_visible = false;
    let mut system_version = None;
    let mut has_launchd = false;
    let mut finish_installation_boot = false;
    let mut system_vgids = Vec::new();
    let mut restore_paths = std::collections::BTreeMap::new();
    for summary in volumes
        .iter()
        .filter(|summary| summary.role == APFS_VOL_ROLE_SYSTEM)
    {
        let Ok(vol) = mounted.open_volume_chosen(&VolumeChoice::Index(summary.index)) else {
            continue;
        };
        if let Ok(snaps) = mounted.snapshots(&vol) {
            snapshot_count = snapshot_count.max(snaps.len());
        }
        if let Some(bytes) =
            extract_volume_path(&mut mounted, &vol, "/usr/standalone/bootcaches.plist")
        {
            restore_paths.insert(
                apfs_uuid(&summary.volume_group_id).to_ascii_lowercase(),
                crate::asahi_installer_data::restore_bundle_path(&bytes).map_err(err)?,
            );
        }
        let plist = extract_volume_path(
            &mut mounted,
            &vol,
            "/System/Library/CoreServices/SystemVersion.plist",
        );
        let launchd = extract_volume_path(&mut mounted, &vol, "/sbin/launchd");
        let has_finish_boot = extract_volume_path(
            &mut mounted,
            &vol,
            "/Finish Installation.app/Contents/Resources/boot.bin",
        )
        .is_some_and(|bytes| !bytes.is_empty());
        finish_installation_boot |= has_finish_boot;
        let has_plist = plist.as_ref().is_some_and(|bytes| !bytes.is_empty());
        if launchd.is_some() {
            has_launchd = true;
        }
        if has_plist && (launchd.is_some() || has_finish_boot) {
            picker_visible = true;
            system_vgids.push(apfs_uuid(&summary.volume_group_id));
        }
        if system_version.is_none()
            && let Some(bytes) = plist
        {
            system_version = Some(bytes);
        }
    }

    let mut blessed_vgid = String::new();
    let mut custom_boot_object = false;
    let mut chainload = false;
    let mut restore_bundle = false;
    if let Ok(preboot) = mounted.open_volume_chosen(&VolumeChoice::Role(APFS_VOL_ROLE_PREBOOT)) {
        if let Some(bytes) = extract_volume_path(&mut mounted, &preboot, "/boot-volume") {
            blessed_vgid = String::from_utf8_lossy(&bytes).trim().to_string();
        }
        let mut vgids = system_vgids;
        for summary in volumes.iter().filter(|s| s.role == APFS_VOL_ROLE_SYSTEM) {
            let id = apfs_uuid(&summary.volume_group_id);
            if !vgids.iter().any(|g| g.eq_ignore_ascii_case(&id)) {
                vgids.push(id);
            }
        }
        if !blessed_vgid.is_empty() && !vgids.iter().any(|g| g.eq_ignore_ascii_case(&blessed_vgid))
        {
            vgids.push(blessed_vgid.clone());
        }
        for vgid in &vgids {
            if let Some(obj) =
                extract_volume_path(&mut mounted, &preboot, &format!("/{vgid}/boot.bin"))
                && !obj.is_empty()
            {
                custom_boot_object = true;
                if contains_chainload(&obj) {
                    chainload = true;
                }
            }
            if extract_volume_path(
                &mut mounted,
                &preboot,
                &format!(
                    "/{vgid}/{}/SystemVersion.plist",
                    restore_paths
                        .get(&vgid.to_ascii_lowercase())
                        .map(String::as_str)
                        .unwrap_or("restore")
                ),
            )
            .is_some_and(|bytes| !bytes.is_empty())
            {
                restore_bundle = true;
            }
        }
    }
    drop(mounted);

    let efi_bytes = if let Some(p) = efi.as_ref() {
        let (s, e) = p.byte_range(gpt.block_size);
        Some(read_range(
            &mut *img,
            s,
            usize::try_from(e - s).map_err(|_| err("EFI partition too large to inspect"))?,
        )?)
    } else {
        None
    };
    let linux_prefix = if let Some(p) = linux.as_ref() {
        let (s, _) = p.byte_range(gpt.block_size);
        read_range(&mut *img, s, 128 * 1024)?
    } else {
        Vec::new()
    };
    let linux_fs = detect_linux_fs(&linux_prefix);
    Ok(Inspected {
        qcow2: is_qcow2_path(path),
        sector_size: gpt.block_size,
        has_apfs: true,
        has_efi: efi.is_some(),
        has_linux: linux.is_some(),
        volumes: volumes
            .iter()
            .map(|v| {
                (
                    v.name.clone(),
                    v.role,
                    v.volume_group_id,
                    v.declared_snapshots,
                )
            })
            .collect(),
        snapshot_count,
        chainload,
        efi_uuid: efi
            .as_ref()
            .map(|p| guid_hyphen_lower(&p.unique_guid))
            .unwrap_or_default(),
        kernel_on_efi: efi_bytes
            .as_ref()
            .map(|b| looks_like_efi_name(b, "KERNEL", &["asahi/kernel"]))
            .unwrap_or(false),
        m1n1_on_efi: efi_bytes
            .as_ref()
            .map(|b| {
                looks_like_efi_name(b, "BOOT.BIN", &["m1n1/boot.bin"]) || fat_contains(b, "BOOT")
            })
            .unwrap_or(false),
        linux_prefix,
        linux_fs,
        picker_visible,
        system_version,
        has_launchd,
        custom_boot_object,
        blessed_vgid,
        restore_bundle,
        finish_installation_boot,
    })
}

fn detect_linux_fs(prefix: &[u8]) -> String {
    if prefix.len() >= 0x43A {
        let magic = u16::from_le_bytes(prefix[0x438..0x43A].try_into().unwrap());
        if magic == 0xEF53 {
            return "ext4".into();
        }
    }
    if prefix.len() >= 0x10048 && &prefix[0x10040..0x10048] == b"_BHRfS_M" {
        return "btrfs".into();
    }
    if prefix.windows(4).any(|w| w == b"hsqs") {
        return "squashfs".into();
    }
    "data".into()
}

fn validate_ans_geometry(path: &Path) -> Result<(), OpsError> {
    let mut image = open_image(path)?;
    let head = read_range(&mut *image, 0, 64 * 1024)?;
    let gpt = detect_gpt(&head)?;
    if gpt.block_size != SECTOR {
        return Err(err(format!(
            "disc uses {}-byte GPT logical blocks, but Apple ANS requires {} bytes; regenerate the disc with the current Asahi generator",
            gpt.block_size, SECTOR
        )));
    }
    Ok(())
}

pub fn validate_disc(path: &Path) -> Result<Inspected, OpsError> {
    validate_ans_geometry(path)?;
    let mut image = open_image(path)?;
    let head = read_range(&mut *image, 0, 64 * 1024)?;
    let gpt = detect_gpt(&head)?;
    let efi = gpt
        .partitions
        .iter()
        .find(|p| p.is_efi())
        .ok_or_else(|| err("disc has no EFI partition"))?;
    let (efi_start, _) = efi.byte_range(gpt.block_size);
    let bpb = read_range(&mut *image, efi_start, 512)?;
    let sector_size = u16::from_le_bytes(bpb[11..13].try_into().unwrap());
    let hidden_sectors = u32::from_le_bytes(bpb[28..32].try_into().unwrap());
    if u32::from(sector_size) != gpt.block_size || u64::from(hidden_sectors) != efi.first_lba {
        return Err(err(
            "EFI filesystem geometry does not match the GPT; regenerate the disc",
        ));
    }
    if u16::from_le_bytes(bpb[17..19].try_into().unwrap()) != 0
        || u16::from_le_bytes(bpb[22..24].try_into().unwrap()) != 0
        || u32::from_le_bytes(bpb[36..40].try_into().unwrap()) == 0
    {
        return Err(err("EFI partition must contain FAT32; regenerate the disc"));
    }
    for partition in gpt.partitions.iter().filter(|p| p.is_apple_apfs()) {
        let (start, end) = partition.byte_range(gpt.block_size);
        let (mut source, _, _) = partition_blocks(&mut *image, start, end)?;
        crate::apfs_verify::verify_container(&mut source)
            .map_err(|e| err(format!("invalid APFS container: {e}")))?;
    }
    drop(image);
    let object = load_custom_boot_object(path, None)?;
    validate_stage1(&object)?;
    let (efi_uuid, next_object) = chainload_target(&object)?;
    let info = inspect_created(path)?;
    if !efi_uuid.eq_ignore_ascii_case(&info.efi_uuid) {
        return Err(err("stage one targets a different EFI partition"));
    }
    if read_efi_files(path, &[next_object])?
        .first()
        .is_none_or(|b| b.is_empty())
    {
        return Err(err("EFI chainload payload is empty"));
    }
    if !info.has_apfs || !info.has_efi || !info.has_linux {
        return Err(err("disc is missing APFS, EFI or Linux partitions"));
    }
    if !info.picker_visible {
        return Err(err(
            "stub is missing SystemVersion.plist and its boot payload",
        ));
    }
    if !info.custom_boot_object {
        return Err(err("Preboot has no custom iBoot boot object"));
    }
    if !info.chainload {
        return Err(err("custom boot object has no chainload="));
    }
    let blessed = info.blessed_vgid.trim();
    if blessed.is_empty() {
        return Err(err("bless/boot-volume is missing"));
    }
    let system_vgids: Vec<String> = info
        .volumes
        .iter()
        .filter(|(_, role, _, _)| *role == APFS_VOL_ROLE_SYSTEM)
        .map(|(_, _, vgid, _)| apfs_uuid(vgid))
        .collect();
    if !system_vgids
        .iter()
        .any(|vgid| vgid.eq_ignore_ascii_case(blessed))
    {
        return Err(err(format!(
            "bless/boot-volume {blessed} does not name the stub SYSTEM volume group"
        )));
    }
    if !info.restore_bundle {
        return Err(err("preserved restore bundle in preboot is missing"));
    }
    Ok(info)
}

pub fn parse_size_arg(s: &str) -> Result<u64, OpsError> {
    let t = s.trim().to_ascii_lowercase();
    let (num, mul) = if let Some(n) = t.strip_suffix("gb").or_else(|| t.strip_suffix('g')) {
        (n, GB)
    } else if let Some(n) = t.strip_suffix("mb").or_else(|| t.strip_suffix('m')) {
        (n, MB)
    } else if let Some(n) = t.strip_suffix("kb").or_else(|| t.strip_suffix('k')) {
        (n, 1024u64)
    } else {
        (t.as_str(), 1u64)
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| err(format!("invalid size {s}")))?;
    Ok(n.saturating_mul(mul))
}

impl Inspected {
    pub fn report(&self) -> String {
        let vols: Vec<String> = self
            .volumes
            .iter()
            .map(|(n, r, _, s)| format!("{n} role={r:#x} snaps={s}"))
            .collect();
        format!(
            "qcow2={}\nlogical_sector_size={}\napfs={}\nefi={}\nlinux={}\nlinux_fs={}\nsnapshots={}\nchainload={}\nefi_uuid={}\nvolumes={}\npicker_visible={}\ncustom_boot_object={}\nblessed_vgid={}\n",
            self.qcow2,
            self.sector_size,
            self.has_apfs,
            self.has_efi,
            self.has_linux,
            self.linux_fs,
            self.snapshot_count,
            self.chainload,
            self.efi_uuid,
            vols.join("; "),
            self.picker_visible,
            self.custom_boot_object,
            self.blessed_vgid,
        )
    }
}

fn fat_contains(fat: &[u8], name: &str) -> bool {
    let want = fat_name_83(name);
    fat.windows(11).any(|w| w == want)
}

fn looks_like_efi_name(fat: &[u8], name: &str, real_paths: &[&str]) -> bool {
    if real_paths
        .iter()
        .any(|path| crate::fat32::read_efi_file(fat, path).is_ok())
    {
        return true;
    }
    fat_contains(fat, name)
}

#[derive(Debug, Clone)]
pub struct Inspected {
    pub qcow2: bool,
    pub sector_size: u32,
    pub has_apfs: bool,
    pub has_efi: bool,
    pub has_linux: bool,
    pub volumes: Vec<(String, u16, [u8; 16], u64)>,
    pub snapshot_count: usize,
    pub chainload: bool,
    pub efi_uuid: String,
    pub kernel_on_efi: bool,
    pub m1n1_on_efi: bool,
    pub linux_prefix: Vec<u8>,
    pub linux_fs: String,
    pub picker_visible: bool,
    pub system_version: Option<Vec<u8>>,
    pub has_launchd: bool,
    pub custom_boot_object: bool,
    pub blessed_vgid: String,
    pub restore_bundle: bool,
    pub finish_installation_boot: bool,
}

pub fn fetch_url(url: &str) -> Result<Vec<u8>, OpsError> {
    let output = std::process::Command::new("curl")
        .args(["-fsSL", "--connect-timeout", "30", url])
        .output()
        .map_err(|e| err(format!("curl: {e}")))?;
    if !output.status.success() {
        return Err(err(format!(
            "curl failed for {url}: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(output.stdout)
}

pub fn fetch_url_to_file(url: &str, dest: &Path) -> Result<(), OpsError> {
    fetch_url_to_file_with_progress(url, dest, |_| {})
}

pub fn fetch_url_to_file_with_progress(
    url: &str,
    dest: &Path,
    mut on_progress: impl FnMut(Option<f64>),
) -> Result<(), OpsError> {
    on_progress(None);
    let cache_key = crate::asahi_cache::download_key(url);
    let cache = cache_key.as_ref().and_then(|_| crate::asahi_cache::root());
    let cache_key = cache_key.unwrap_or_default();
    if let Some(root) = &cache {
        on_progress(None);
        if crate::asahi_cache::restore(root, &cache_key, dest) {
            on_progress(Some(1.0));
            return Ok(());
        }
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let dest_s = dest
        .to_str()
        .ok_or_else(|| err("destination path is not valid UTF-8"))?;
    let validator = cache_key
        .strip_prefix(&format!("download:{url}:"))
        .map(|etag| format!("If-Match: {etag}"))
        .unwrap_or_default();
    let mut child = std::process::Command::new("curl")
        .args([
            "-fL",
            "--connect-timeout",
            "30",
            "--progress-bar",
            "--header",
            &validator,
            "-o",
            dest_s,
            url,
        ])
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .map_err(|e| err(format!("curl: {e}")))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| err("curl stderr was not captured"))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        match stderr.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if let Some(fraction) = parse_curl_progress(&buf) {
                    on_progress(Some(fraction));
                }
                if buf.len() > 8192 {
                    let keep = buf.len() - 4096;
                    buf.drain(..keep);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let status = child.wait()?;
    if !status.success() {
        let detail = String::from_utf8_lossy(&buf);
        let detail = detail.trim();
        return Err(err(if detail.is_empty() {
            format!("curl failed for {url}")
        } else {
            format!("curl failed for {url}: {detail}")
        }));
    }
    if let Some(root) = &cache {
        let _ = crate::asahi_cache::store(root, &cache_key, dest);
    }
    on_progress(Some(1.0));
    Ok(())
}

pub(crate) fn parse_curl_progress(buf: &[u8]) -> Option<f64> {
    let text = String::from_utf8_lossy(buf);
    let last = text.rsplit(['\r', '\n']).find(|line| line.contains('%'))?;
    let before = last.split('%').next()?;
    let token = before.split_whitespace().last()?;
    let value: f64 = token.parse().ok()?;
    if !(0.0..=100.0).contains(&value) {
        return None;
    }
    Some(value / 100.0)
}

pub fn load_artifacts_latest(
    data: &InstallerData,
    fetch: impl Fn(&str) -> Result<Vec<u8>, OpsError>,
) -> Result<Artifacts, OpsError> {
    load_artifacts_for_os(data, "", fetch)
}

pub fn load_artifacts_for_os(
    data: &InstallerData,
    os_query: &str,
    fetch: impl Fn(&str) -> Result<Vec<u8>, OpsError>,
) -> Result<Artifacts, OpsError> {
    let resolved = resolve_os(data, os_query)?;
    let package = fetch(&resolved.package_url)?;
    extract_package_artifacts(&package, &resolved)
}

pub fn load_artifacts_custom(
    data: &InstallerData,
    kernel: Vec<u8>,
    m1n1: Vec<u8>,
    fetch: impl Fn(&str) -> Result<Vec<u8>, OpsError>,
) -> Result<Artifacts, OpsError> {
    let mut artifacts = load_artifacts_for_os(data, "", fetch)?;
    artifacts.kernel = kernel;
    artifacts.m1n1 = m1n1;
    Ok(artifacts)
}

pub fn load_artifacts_from_package_file(
    data: &InstallerData,
    os_query: &str,
    package: &Path,
    workdir: &Path,
) -> Result<Artifacts, OpsError> {
    load_artifacts_from_package_file_parts(data, os_query, package, workdir, true)
}

pub fn load_artifacts_from_package_file_parts(
    data: &InstallerData,
    os_query: &str,
    package: &Path,
    workdir: &Path,
    include_root: bool,
) -> Result<Artifacts, OpsError> {
    load_artifacts_from_package_file_reporting(
        data,
        os_query,
        package,
        workdir,
        include_root,
        |_| {},
    )
}

pub fn load_artifacts_from_package_file_reporting(
    data: &InstallerData,
    os_query: &str,
    package: &Path,
    workdir: &Path,
    include_root: bool,
    on_progress: impl FnMut(f64),
) -> Result<Artifacts, OpsError> {
    let resolved = resolve_os(data, os_query)?;
    extract_package_from_path_parts(package, &resolved, workdir, include_root, on_progress)
}

fn extract_package_artifacts(
    package: &[u8],
    resolved: &ResolvedLatest,
) -> Result<Artifacts, OpsError> {
    let mut artifacts = extract_package_artifacts_unbound(package, resolved)?;
    artifacts.firmware_requirements = Some(FirmwareRequirements::from(resolved));
    Ok(artifacts)
}

fn extract_package_artifacts_unbound(
    package: &[u8],
    resolved: &ResolvedLatest,
) -> Result<Artifacts, OpsError> {
    if let Some(root) = zip_file(package, &resolved.root_image) {
        let kernel = zip_file(package, &resolved.kernel_image)
            .or_else(|| zip_file(package, "esp/m1n1/boot.bin"))
            .unwrap_or_default();
        let m1n1 = zip_file(package, "esp/m1n1/boot.bin")
            .or_else(|| zip_file(package, &resolved.boot_object))
            .unwrap_or_else(|| kernel.clone());
        let mut artifacts = Artifacts::memory(
            if kernel.is_empty() {
                m1n1.clone()
            } else {
                kernel
            },
            m1n1,
            root,
        );
        let archive = tempfile::NamedTempFile::new()?;
        std::fs::write(archive.path(), package)?;
        artifacts.efi_files = package_efi_files(archive.path(), &zip_list_file(archive.path())?)?;
        artifacts.boot_fs = zip_file(package, &resolved.kernel_image).unwrap_or_default();
        return Ok(artifacts);
    }
    Ok(Artifacts::memory(Vec::new(), Vec::new(), package.to_vec()))
}

pub fn extract_package_from_path(
    package: &Path,
    resolved: &ResolvedLatest,
    workdir: &Path,
) -> Result<Artifacts, OpsError> {
    extract_package_from_path_parts(package, resolved, workdir, true, |_| {})
}

fn extract_package_from_path_parts(
    package: &Path,
    resolved: &ResolvedLatest,
    workdir: &Path,
    include_root: bool,
    on_progress: impl FnMut(f64),
) -> Result<Artifacts, OpsError> {
    let mut artifacts = extract_package_from_path_parts_unbound(
        package,
        resolved,
        workdir,
        include_root,
        on_progress,
    )?;
    artifacts.firmware_requirements = Some(FirmwareRequirements::from(resolved));
    Ok(artifacts)
}

fn extract_package_from_path_parts_unbound(
    package: &Path,
    resolved: &ResolvedLatest,
    workdir: &Path,
    include_root: bool,
    mut on_progress: impl FnMut(f64),
) -> Result<Artifacts, OpsError> {
    std::fs::create_dir_all(workdir)?;
    let members = zip_list_file(package)?;
    if members.is_empty() {
        if !include_root {
            return Ok(Artifacts::memory(Vec::new(), Vec::new(), Vec::new()));
        }
        let dest = workdir.join("root.img");
        std::fs::copy(package, &dest)?;
        return Ok(Artifacts {
            kernel: Vec::new(),
            m1n1: Vec::new(),
            efi_files: Vec::new(),
            firmware_requirements: None,
            firmware: None,
            installer_data: None,
            m1n1_stage1: Vec::new(),
            root_fs: Vec::new(),
            root_path: Some(dest),
            boot_fs: Vec::new(),
            boot_path: None,
        });
    }
    let package_digest = crate::asahi_cache::digest(package).map_err(err)?;
    let extract_total = {
        let mut total = 0u64;
        if include_root {
            if let Some(m) = zip_find(&members, &resolved.root_image) {
                total += m.uncomp.max(1);
            }
            if zip_find(&members, &resolved.kernel_image).is_some()
                && let Some(m) = zip_find(&members, &resolved.kernel_image)
            {
                total += m.uncomp.max(1);
            }
        }
        total.max(1)
    };
    on_progress(0.0);
    let mut extracted = 0u64;
    let mut report = |n: u64| {
        extracted += n;
        on_progress((extracted as f64 / extract_total as f64).clamp(0.0, 1.0));
    };
    let root_path = if include_root {
        let root_dest = workdir.join("root.img");
        zip_extract_cached_progress(
            &package_digest,
            package,
            &members,
            &resolved.root_image,
            &root_dest,
            |n| {
                report(n);
            },
        )?;
        Some(root_dest)
    } else {
        None
    };
    const SMALL: u64 = 32 * MB;
    let m1n1 = zip_read_named_capped(package, &members, "esp/m1n1/boot.bin", SMALL)
        .or_else(|| zip_read_named_capped(package, &members, &resolved.boot_object, SMALL))
        .unwrap_or_default();
    let boot_dest = workdir.join("boot.img");
    let (kernel, boot_path) = if zip_find(&members, &resolved.kernel_image).is_some() {
        zip_extract_cached_progress(
            &package_digest,
            package,
            &members,
            &resolved.kernel_image,
            &boot_dest,
            |n| {
                report(n);
            },
        )?;
        let boot_len = std::fs::metadata(&boot_dest)?.len();
        if boot_len > SMALL {
            (Vec::new(), Some(boot_dest))
        } else {
            (std::fs::read(&boot_dest)?, Some(boot_dest))
        }
    } else {
        let kernel = zip_read_named_capped(package, &members, &resolved.kernel_image, SMALL)
            .or_else(|| zip_read_named_capped(package, &members, "esp/m1n1/boot.bin", SMALL))
            .unwrap_or_else(|| m1n1.clone());
        (kernel, None)
    };
    Ok(Artifacts {
        kernel,
        m1n1,
        efi_files: package_efi_files(package, &members)?,
        firmware_requirements: None,
        firmware: None,
        installer_data: None,
        m1n1_stage1: Vec::new(),
        root_fs: Vec::new(),
        root_path,
        boot_fs: Vec::new(),
        boot_path,
    })
}

fn package_efi_files(
    package: &Path,
    members: &[ZipMember],
) -> Result<Vec<(String, Vec<u8>)>, OpsError> {
    let mut files = Vec::new();
    for member in members {
        let Some(name) = member
            .name
            .strip_prefix("esp/")
            .filter(|name| !name.is_empty() && !name.ends_with('/'))
        else {
            continue;
        };
        if Path::new(name)
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err(err("EFI package contains an invalid path"));
        }
        let content = zip_read_named_capped(package, members, &member.name, 512 * MB)
            .ok_or_else(|| err(format!("cannot extract EFI file {}", member.name)))?;
        files.push((name.into(), content));
    }
    Ok(files)
}

pub(crate) struct ZipMember {
    pub(crate) name: String,
    method: u16,
    local_off: u64,
    comp: u64,
    pub(crate) uncomp: u64,
}

fn zip_name_matches(entry: &str, want: &str) -> bool {
    entry == want || entry.ends_with(want) || entry.rsplit(['/', '\\']).next() == Some(want)
}

pub(crate) fn zip_list_file(path: &Path) -> Result<Vec<ZipMember>, OpsError> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    if len < 22 {
        return Ok(Vec::new());
    }
    let scan = len.min((1 << 16) + 22);
    let start = len - scan;
    file.seek(SeekFrom::Start(start))?;
    let mut tail = vec![0u8; scan as usize];
    file.read_exact(&mut tail)?;
    let mut eocd = None;
    let mut i = tail.len().saturating_sub(22);
    loop {
        if tail[i..].starts_with(b"PK\x05\x06") {
            eocd = Some(i);
            break;
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    let Some(eocd) = eocd else {
        return zip_list_local_headers(path);
    };
    let mut cd_entries = u16::from_le_bytes(tail[eocd + 8..eocd + 10].try_into().unwrap()) as u64;
    let mut cd_size = u32::from_le_bytes(tail[eocd + 12..eocd + 16].try_into().unwrap()) as u64;
    let mut cd_off = u32::from_le_bytes(tail[eocd + 16..eocd + 20].try_into().unwrap()) as u64;
    if (cd_off == 0xFFFF_FFFF || cd_size == 0xFFFF_FFFF || cd_entries == 0xFFFF)
        && eocd >= 20
        && tail[eocd - 20..].starts_with(b"PK\x06\x07")
    {
        let zip64_eocd = u64::from_le_bytes(tail[eocd - 12..eocd - 4].try_into().unwrap());
        file.seek(SeekFrom::Start(zip64_eocd))?;
        let mut hdr = [0u8; 56];
        file.read_exact(&mut hdr)?;
        if &hdr[0..4] != b"PK\x06\x06" {
            return Err(err("zip64 end of central directory is malformed"));
        }
        cd_entries = u64::from_le_bytes(hdr[32..40].try_into().unwrap());
        cd_size = u64::from_le_bytes(hdr[40..48].try_into().unwrap());
        cd_off = u64::from_le_bytes(hdr[48..56].try_into().unwrap());
    }
    file.seek(SeekFrom::Start(cd_off))?;
    let mut cd = vec![0u8; cd_size as usize];
    file.read_exact(&mut cd)?;
    let mut members = Vec::new();
    let mut cursor = 0usize;
    while cursor + 46 <= cd.len() && (members.len() as u64) < cd_entries {
        if &cd[cursor..cursor + 4] != b"PK\x01\x02" {
            break;
        }
        let method = u16::from_le_bytes(cd[cursor + 10..cursor + 12].try_into().unwrap());
        let mut comp = u32::from_le_bytes(cd[cursor + 20..cursor + 24].try_into().unwrap()) as u64;
        let mut uncomp =
            u32::from_le_bytes(cd[cursor + 24..cursor + 28].try_into().unwrap()) as u64;
        let nlen = u16::from_le_bytes(cd[cursor + 28..cursor + 30].try_into().unwrap()) as usize;
        let elen = u16::from_le_bytes(cd[cursor + 30..cursor + 32].try_into().unwrap()) as usize;
        let clen = u16::from_le_bytes(cd[cursor + 32..cursor + 34].try_into().unwrap()) as usize;
        let mut local_off =
            u32::from_le_bytes(cd[cursor + 42..cursor + 46].try_into().unwrap()) as u64;
        let name_at = cursor + 46;
        if name_at + nlen > cd.len() {
            break;
        }
        let name = String::from_utf8_lossy(&cd[name_at..name_at + nlen]).into_owned();
        let extra_at = name_at + nlen;
        if extra_at + elen <= cd.len()
            && (comp == 0xFFFF_FFFF || uncomp == 0xFFFF_FFFF || local_off == 0xFFFF_FFFF)
        {
            let extra = &cd[extra_at..extra_at + elen];
            let mut e = 0usize;
            while e + 4 <= extra.len() {
                let tag = u16::from_le_bytes(extra[e..e + 2].try_into().unwrap());
                let sz = u16::from_le_bytes(extra[e + 2..e + 4].try_into().unwrap()) as usize;
                if e + 4 + sz > extra.len() {
                    break;
                }
                if tag == 0x0001 {
                    let mut z = 0usize;
                    let body = &extra[e + 4..e + 4 + sz];
                    // Zip64 order: original size first, present only when the 32-bit field was 0xFFFFFFFF.
                    let uncomp_field =
                        u32::from_le_bytes(cd[cursor + 24..cursor + 28].try_into().unwrap());
                    if uncomp_field == 0xFFFF_FFFF && z + 8 <= body.len() {
                        uncomp = u64::from_le_bytes(body[z..z + 8].try_into().unwrap());
                        z += 8;
                    }
                    if comp == 0xFFFF_FFFF && z + 8 <= body.len() {
                        comp = u64::from_le_bytes(body[z..z + 8].try_into().unwrap());
                        z += 8;
                    }
                    if local_off == 0xFFFF_FFFF && z + 8 <= body.len() {
                        local_off = u64::from_le_bytes(body[z..z + 8].try_into().unwrap());
                    }
                }
                e += 4 + sz;
            }
        }
        members.push(ZipMember {
            name,
            method,
            local_off,
            comp,
            uncomp: if uncomp == 0 { comp } else { uncomp },
        });
        cursor = extra_at + elen + clen;
    }
    if members.is_empty() {
        return zip_list_local_headers(path);
    }
    Ok(members)
}

fn zip_list_local_headers(path: &Path) -> Result<Vec<ZipMember>, OpsError> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let mut members = Vec::new();
    let mut off = 0u64;
    while off + 30 <= len {
        file.seek(SeekFrom::Start(off))?;
        let mut hdr = [0u8; 30];
        if file.read_exact(&mut hdr).is_err() {
            break;
        }
        if &hdr[0..4] != b"PK\x03\x04" {
            off += 1;
            continue;
        }
        let method = u16::from_le_bytes(hdr[8..10].try_into().unwrap());
        let comp = u32::from_le_bytes(hdr[18..22].try_into().unwrap()) as u64;
        let uncomp = u32::from_le_bytes(hdr[22..26].try_into().unwrap()) as u64;
        let nlen = u16::from_le_bytes(hdr[26..28].try_into().unwrap()) as u64;
        let elen = u16::from_le_bytes(hdr[28..30].try_into().unwrap()) as u64;
        let mut name = vec![0u8; nlen as usize];
        if file.read_exact(&mut name).is_err() {
            break;
        }
        members.push(ZipMember {
            name: String::from_utf8_lossy(&name).into_owned(),
            method,
            local_off: off,
            comp,
            uncomp: if uncomp == 0 { comp } else { uncomp },
        });
        off = off + 30 + nlen + elen + comp;
    }
    Ok(members)
}

fn zip_find<'a>(members: &'a [ZipMember], name: &str) -> Option<&'a ZipMember> {
    members.iter().find(|m| zip_name_matches(&m.name, name))
}

pub(crate) fn zip_open_payload(
    package: &Path,
    member: &ZipMember,
) -> Result<(File, u16, u64), OpsError> {
    let mut file = File::open(package)?;
    file.seek(SeekFrom::Start(member.local_off))?;
    let mut hdr = [0u8; 30];
    file.read_exact(&mut hdr)?;
    if &hdr[0..4] != b"PK\x03\x04" {
        return Err(err(format!("zip local header missing for {}", member.name)));
    }
    let nlen = u16::from_le_bytes(hdr[26..28].try_into().unwrap()) as u64;
    let elen = u16::from_le_bytes(hdr[28..30].try_into().unwrap()) as u64;
    file.seek(SeekFrom::Current(nlen as i64 + elen as i64))?;
    Ok((file, member.method, member.comp))
}

fn zip_extract_cached_progress(
    package_digest: &str,
    package: &Path,
    members: &[ZipMember],
    name: &str,
    dest: &Path,
    mut on_bytes: impl FnMut(u64),
) -> Result<(), OpsError> {
    let member = zip_find(members, name).ok_or_else(|| err(format!("zip has no {name}")))?;
    let cache = crate::asahi_cache::root();
    let key = format!("package:{package_digest}:{name}");
    if cache
        .as_ref()
        .is_some_and(|root| crate::asahi_cache::restore(root, &key, dest))
        && std::fs::metadata(dest)?.len() == member.uncomp
    {
        on_bytes(member.uncomp);
        return Ok(());
    }
    zip_extract_named_progress(package, members, name, dest, on_bytes)?;
    if std::fs::metadata(dest)?.len() != member.uncomp {
        return Err(err(format!("ZIP length mismatch for {name}")));
    }
    if let Some(root) = cache {
        let _ = crate::asahi_cache::store(&root, &key, dest);
    }
    Ok(())
}

fn zip_extract_named_progress(
    package: &Path,
    members: &[ZipMember],
    name: &str,
    dest: &Path,
    on_bytes: impl FnMut(u64),
) -> Result<(), OpsError> {
    let member = zip_find(members, name).ok_or_else(|| err(format!("zip has no {name}")))?;
    let (file, method, comp) = zip_open_payload(package, member)?;
    let mut limited = file.take(comp);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let out = File::create(dest)?;
    let mut counted = CountingWriter {
        inner: out,
        on_bytes,
    };
    match method {
        0 => {
            std::io::copy(&mut limited, &mut counted)?;
        }
        8 => {
            let mut decoder = flate2::read::DeflateDecoder::new(limited);
            std::io::copy(&mut decoder, &mut counted)?;
        }
        other => {
            return Err(err(format!(
                "zip method {other} is not supported for {name}"
            )));
        }
    }
    Ok(())
}

struct CountingWriter<W, F> {
    inner: W,
    on_bytes: F,
}

impl<W: Write, F: FnMut(u64)> Write for CountingWriter<W, F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        (self.on_bytes)(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn zip_read_named_capped(
    package: &Path,
    members: &[ZipMember],
    name: &str,
    cap: u64,
) -> Option<Vec<u8>> {
    let member = zip_find(members, name)?;
    if member.comp > cap {
        return None;
    }
    let (file, method, comp) = zip_open_payload(package, member).ok()?;
    let limited = file.take(comp);
    match method {
        0 => {
            let mut out = Vec::new();
            let mut reader = limited.take(cap);
            reader.read_to_end(&mut out).ok()?;
            Some(out)
        }
        8 => {
            let decoder = flate2::read::DeflateDecoder::new(limited);
            let mut out = Vec::new();
            let mut reader = decoder.take(cap);
            reader.read_to_end(&mut out).ok()?;
            Some(out)
        }
        _ => None,
    }
}

fn zip_file(zip: &[u8], name: &str) -> Option<Vec<u8>> {
    let name_b = name.as_bytes();
    let mut i = 0usize;
    while i + 30 < zip.len() {
        if zip[i..i + 4] != *b"PK\x03\x04" {
            i += 1;
            continue;
        }
        let method = u16::from_le_bytes(zip[i + 8..i + 10].try_into().ok()?);
        let comp = u32::from_le_bytes(zip[i + 18..i + 22].try_into().ok()?) as usize;
        let nlen = u16::from_le_bytes(zip[i + 26..i + 28].try_into().ok()?) as usize;
        let elen = u16::from_le_bytes(zip[i + 28..i + 30].try_into().ok()?) as usize;
        let name_at = i + 30;
        let data_at = name_at + nlen + elen;
        if name_at + nlen > zip.len() || data_at + comp > zip.len() {
            i += 1;
            continue;
        }
        let entry_name = &zip[name_at..name_at + nlen];
        let matches = entry_name == name_b
            || entry_name.ends_with(name_b)
            || std::str::from_utf8(entry_name)
                .ok()
                .is_some_and(|s| s.ends_with(name) || s == name);
        if matches {
            let payload = &zip[data_at..data_at + comp];
            return match method {
                0 => Some(payload.to_vec()),
                8 => inflate_raw(payload),
                _ => None,
            };
        }
        i = data_at + comp;
    }
    None
}

#[cfg(test)]
pub(crate) fn make_stored_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in files {
        let name_b = name.as_bytes();
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&[20, 0, 0, 0]);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name_b);
        out.extend_from_slice(data);
    }
    out
}

fn inflate_raw(payload: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::DeflateDecoder;
    let mut decoder = DeflateDecoder::new(payload);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apfs_image::{
        APFS_VOL_ROLE_DATA, APFS_VOL_ROLE_PREBOOT, APFS_VOL_ROLE_RECOVERY, APFS_VOL_ROLE_SYSTEM,
    };

    #[test]
    fn ans_gpt_uses_device_logical_blocks_and_valid_backup() {
        let layout = plan_layout(8 * GB, 4096, MB).unwrap();
        let mut image = SparseImage::new(layout.disc_size);
        write_gpt(
            &mut image,
            &layout,
            [1; 16],
            &[(
                APPLE_APFS_TYPE_GUID,
                [2; 16],
                layout.stub_lba,
                layout.stub_lba + layout.stub_sectors - 1,
                "APFS",
            )],
        );
        let mut head = vec![0; 64 * 1024];
        for (&offset, bytes) in &image.ranges {
            if offset < head.len() as u64 {
                head[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);
            }
        }
        let gpt = detect_gpt(&head).unwrap();
        assert_eq!(gpt.block_size, 4096);
        assert_eq!(&head[0x1bf..0x1c2], &[0, 2, 0]);
        assert_eq!(&head[0x1c3..0x1c6], &[0xff, 0xff, 0xff]);
        assert_eq!(
            u32::from_le_bytes(head[0x1ca..0x1ce].try_into().unwrap()),
            layout.last_lba as u32
        );
        let mut previous_end = 0;
        for (start, length) in [
            (layout.stub_lba, layout.stub_sectors),
            (layout.efi_lba, layout.efi_sectors),
            (layout.boot_lba, layout.boot_sectors),
            (layout.linux_lba, layout.linux_sectors),
        ] {
            assert_eq!(start * 4096 % ALIGN, 0);
            assert!(start >= previous_end);
            assert!(length > 0);
            previous_end = start + length;
        }
        assert!(previous_end <= layout.last_lba - 4);
        assert_eq!(gpt.partitions[0].byte_range(gpt.block_size).0, ALIGN);
        let backup = &image.ranges[&(layout.last_lba * 4096)];
        let entry_lba = u64::from_le_bytes(backup[72..80].try_into().unwrap());
        assert_eq!(entry_lba, layout.last_lba - 4);
        assert_eq!(image.ranges[&(entry_lba * 4096)].len(), 16384);
        let primary = &head[4096..8192];
        assert_eq!(u64::from_le_bytes(primary[40..48].try_into().unwrap()), 6);
        assert_eq!(
            u64::from_le_bytes(primary[48..56].try_into().unwrap()),
            entry_lba - 1
        );
        assert_eq!(
            u64::from_le_bytes(primary[32..40].try_into().unwrap()),
            layout.last_lba
        );
        assert_eq!(u64::from_le_bytes(backup[32..40].try_into().unwrap()), 1);
        assert_eq!(head[8192..24576], image.ranges[&(entry_lba * 4096)]);
        assert_eq!(
            u32::from_le_bytes(primary[88..92].try_into().unwrap()),
            embedded_panic_crc32(&head[8192..24576])
        );
        for header in [&head[4096..8192], backup.as_slice()] {
            let expected = u32::from_le_bytes(header[16..20].try_into().unwrap());
            let mut checked = header[..92].to_vec();
            checked[16..20].fill(0);
            assert_eq!(embedded_panic_crc32(&checked), expected);
        }
        let primary = head[4096..8192].to_vec();
        let entries = head[8192..24576].to_vec();
        head.fill(0);
        head[512..1024].copy_from_slice(&primary[..512]);
        head[1024..17408].copy_from_slice(&entries);
        let legacy = detect_gpt(&head).unwrap();
        assert_eq!(legacy.block_size, 512);
        assert_eq!(
            legacy.partitions[0].byte_range(512).0,
            layout.stub_lba * 512
        );
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &head).unwrap();
        for error in [
            validate_disc(file.path()).unwrap_err(),
            update_disc(
                file.path(),
                &Artifacts::memory(Vec::new(), Vec::new(), Vec::new()),
            )
            .unwrap_err(),
        ] {
            let message = error.to_string();
            assert!(message.contains("512-byte GPT"));
            assert!(message.contains("regenerate the disc"));
        }
        assert_eq!(std::fs::read(file.path()).unwrap(), head);
    }

    fn sample_metadata() -> &'static str {
        r#"{
            "os_list": [
                {
                    "name": "Fedora Asahi Remix Test",
                    "default_os_name": "Fedora Linux",
                    "boot_object": "m1n1.bin",
                    "next_object": "m1n1/boot.bin",
                    "package": "https://example.test/os/fedora-asahi-test.zip",
                    "partitions": [
                        {"name": "EFI", "type": "EFI", "size": "524288000B", "source": "esp"},
                        {"name": "Boot", "type": "Linux", "size": "1073741824B", "image": "boot.img"},
                        {"name": "Root", "type": "Linux", "size": "4096B", "image": "root.img"}
                    ]
                },
                {
                    "name": "Tethered boot",
                    "expert": true,
                    "boot_object": "m1n1.bin",
                    "partitions": []
                }
            ]
        }"#
    }

    fn stage1_fixture(tag: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 2048];
        bytes.extend_from_slice(b"##m1n1_ver##test\0chainload=\0");
        bytes.extend_from_slice(tag);
        bytes
    }

    #[test]
    fn efi_payloads_preserve_package_files_when_no_override_is_supplied() {
        let mut artifacts = Artifacts::memory(Vec::new(), Vec::new(), Vec::new());
        artifacts.efi_files = vec![
            ("m1n1/boot.bin".into(), b"stage2".to_vec()),
            ("asahi/kernel".into(), b"kernel".to_vec()),
        ];
        assert_eq!(
            efi_payloads(&artifacts, "m1n1/boot.bin", None).unwrap(),
            artifacts.efi_files
        );
    }

    #[test]
    fn stage_one_rejects_stage_two_without_chainloading() {
        let mut bytes = stage1_fixture(b"stage2");
        bytes.extend_from_slice(b"Chainloading files not supported in this build!");
        assert!(validate_stage1(&bytes).is_err());
        assert!(build_stage1(b"short", "uuid", "m1n1/boot.bin").is_err());
    }

    #[test]
    fn stage_one_configuration_is_terminated_and_keeps_code_intact() {
        let code = stage1_fixture(b"code");
        let object = build_stage1(&code, "uuid", "m1n1/boot.bin").unwrap();
        assert!(object.starts_with(&code));
        assert_eq!(
            chainload_target(&object).unwrap(),
            ("uuid", "m1n1/boot.bin")
        );
        assert!(chainload_target(&code).is_err());
        assert!(object.ends_with(b"chainload=uuid;m1n1/boot.bin\n\0\0\0\0"));
        assert!(build_stage1(&code, "uuid", "a\nb").is_err());
    }

    #[test]
    fn required_firmware_survives_resolution_and_refuses_unbound_disk_write() {
        let data = parse_installer_data(
            r#"{"os_list":[{
            "name":"Test OS","package":"https://example.test/os.zip",
            "supported_fw":["13.5"],"partitions":[{
                "name":"EFI","type":"EFI","copy_firmware":true,
                "copy_installer_data":true,"source":"esp"
            }]
        }]}"#,
        )
        .unwrap();
        let resolved = resolve_latest(&data).unwrap();
        let requirements = FirmwareRequirements::from(&resolved);
        assert_eq!(requirements.supported_fw, Some(vec!["13.5".into()]));
        assert_eq!(requirements.firmware_partitions, vec!["EFI"]);
        assert_eq!(requirements.installer_data_partitions, vec!["EFI"]);
        let mut payloads = artifacts(b"firmware-contract");
        payloads.firmware_requirements = Some(requirements);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("existing.qcow2");
        std::fs::write(&path, b"preserve existing disk").unwrap();
        let result = create_qcow2_disc(
            &path,
            &payloads,
            min_disc_bytes(),
            "m1n1/boot.bin",
            "Test OS",
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("verified installer data")
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"preserve existing disk");
        payloads
            .firmware_requirements
            .as_mut()
            .unwrap()
            .installer_data_partitions
            .clear();
        let result = create_qcow2_disc(
            &path,
            &payloads,
            min_disc_bytes(),
            "m1n1/boot.bin",
            "Test OS",
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("verified Apple OS firmware identity")
        );
        assert_eq!(std::fs::read(path).unwrap(), b"preserve existing disk");
    }

    fn artifacts(tag: &[u8]) -> Artifacts {
        let mut artifacts = Artifacts::memory(
            [b"KERN", tag].concat(),
            [b"M1N1", tag].concat(),
            [b"ROOT", tag, &[0u8; 64]].concat(),
        );
        artifacts.m1n1_stage1 = stage1_fixture(tag);
        artifacts
    }

    fn flavored_metadata() -> &'static str {
        r#"{
            "os_list": [
                {
                    "name": "Fedora Asahi Remix 44 (KDE Plasma)",
                    "default_os_name": "Fedora Linux",
                    "boot_object": "m1n1.bin",
                    "next_object": "m1n1/boot.bin",
                    "package": "https://example.test/os/fedora-kde.zip",
                    "partitions": [
                        {"name": "Root", "type": "Linux", "image": "root.img"},
                        {"name": "Boot", "type": "Linux", "image": "boot.img"}
                    ]
                },
                {
                    "name": "Fedora Asahi Remix 44 (GNOME)",
                    "default_os_name": "Fedora Linux",
                    "boot_object": "m1n1.bin",
                    "next_object": "m1n1/boot.bin",
                    "package": "https://example.test/os/fedora-gnome.zip",
                    "partitions": [
                        {"name": "Root", "type": "Linux", "image": "root.img"},
                        {"name": "Boot", "type": "Linux", "image": "boot.img"}
                    ]
                },
                {
                    "name": "Fedora Asahi Remix 44 Server",
                    "default_os_name": "Fedora Linux",
                    "boot_object": "m1n1.bin",
                    "next_object": "m1n1/boot.bin",
                    "package": "https://example.test/os/fedora-server.zip",
                    "partitions": [
                        {"name": "Root", "type": "Linux", "image": "root.img"},
                        {"name": "Boot", "type": "Linux", "image": "boot.img"}
                    ]
                },
                {
                    "name": "Fedora Asahi Remix 44 Minimal",
                    "default_os_name": "Fedora Linux",
                    "boot_object": "m1n1.bin",
                    "next_object": "m1n1/boot.bin",
                    "package": "https://example.test/os/fedora-minimal.zip",
                    "partitions": [
                        {"name": "Root", "type": "Linux", "image": "root.img"},
                        {"name": "Boot", "type": "Linux", "image": "boot.img"}
                    ]
                },
                {
                    "name": "UEFI environment only",
                    "expert": true,
                    "package": "https://example.test/os/uefi.zip",
                    "partitions": []
                }
            ]
        }"#
    }

    #[test]
    fn resolution_preserves_declared_firmware_requirements() {
        let data = parse_installer_data(
            r#"{"os_list":[{
            "name":"Test OS","package":"https://example.test/os.zip",
            "supported_fw":["13.5"],"partitions":[
                {"name":"EFI","copy_firmware":true,"copy_installer_data":true},
                {"name":"Root","image":"root.img"}
            ]
        }]}"#,
        )
        .unwrap();
        let resolved = resolve_latest(&data).unwrap();
        assert_eq!(resolved.supported_fw, Some(vec!["13.5".into()]));
        assert_eq!(resolved.firmware_partitions, vec!["EFI"]);
        assert_eq!(resolved.installer_data_partitions, vec!["EFI"]);
        let legacy = resolve_latest(&parse_installer_data(sample_metadata()).unwrap()).unwrap();
        assert_eq!(legacy.supported_fw, None);
        assert!(legacy.firmware_partitions.is_empty());
        assert!(legacy.installer_data_partitions.is_empty());
    }

    #[test]
    fn latest_resolution_reads_package_from_metadata_not_a_compiled_url() {
        let data = parse_installer_data(sample_metadata()).expect("parse");
        let latest = resolve_latest(&data).expect("latest");
        assert_eq!(
            latest.package_url,
            "https://example.test/os/fedora-asahi-test.zip"
        );
        assert_eq!(latest.root_image, "root.img");
        assert_eq!(latest.kernel_image, "boot.img");
        assert_eq!(latest.next_object, "m1n1/boot.bin");
        assert!(!latest.package_url.contains("asahilinux-fedora.b-cdn.net"));
        let custom = resolve_custom(&data).expect("custom still uses metadata for root FS");
        assert_eq!(custom.package_url, latest.package_url);
        assert_eq!(custom.root_image, "root.img");
    }

    #[test]
    fn flavours_are_selected_from_installer_metadata() {
        let data = parse_installer_data(flavored_metadata()).expect("parse");
        let installable = list_installable_flavors(&data);
        let slugs: Vec<&str> = installable.iter().map(|f| f.slug.as_str()).collect();
        assert_eq!(slugs, ["kde", "gnome", "server", "minimal"]);
        assert_eq!(
            resolve_latest(&data).unwrap().package_url,
            "https://example.test/os/fedora-kde.zip"
        );
        assert_eq!(
            resolve_os(&data, "minimal").unwrap().package_url,
            "https://example.test/os/fedora-minimal.zip"
        );
        assert_eq!(
            resolve_os(&data, "GNOME").unwrap().package_url,
            "https://example.test/os/fedora-gnome.zip"
        );
        assert_eq!(
            resolve_os(&data, "server").unwrap().package_url,
            "https://example.test/os/fedora-server.zip"
        );
        let kde = load_artifacts_for_os(&data, "kde", |url| {
            assert!(url.ends_with("fedora-kde.zip"));
            Ok(stored_zip(&[
                ("root.img", b"KDE-ROOT"),
                ("boot.img", b"KDE-BOOT"),
                ("esp/m1n1/boot.bin", b"KDE-M1N1"),
                ("esp/EFI/BOOT/BOOTAA64.EFI", b"GRUB"),
                ("esp/vendor/long filename.txt", b"asset"),
            ]))
        })
        .unwrap();
        assert_eq!(kde.root_fs, b"KDE-ROOT");
        assert_eq!(kde.kernel, b"KDE-BOOT");
        assert_eq!(kde.boot_fs, b"KDE-BOOT");
        assert!(
            kde.efi_files
                .contains(&("EFI/BOOT/BOOTAA64.EFI".into(), b"GRUB".to_vec()))
        );
        assert!(
            kde.efi_files
                .contains(&("vendor/long filename.txt".into(), b"asset".to_vec()))
        );
        let miss = resolve_os(&data, "xfce").unwrap_err();
        assert!(miss.to_string().contains("minimal"));
    }

    #[test]
    fn boot_only_package_update_streams_boot_image_without_extracting_root() {
        let dir = tempfile::tempdir().unwrap();
        let zip = dir.path().join("package.zip");
        let boot = vec![0x71; 33 * MB as usize];
        std::fs::write(
            &zip,
            deflated_zip(&[("boot.img", &boot), ("esp/m1n1/boot.bin", b"stage2")]),
        )
        .unwrap();
        let data = parse_installer_data(sample_metadata()).unwrap();
        let artifacts =
            load_artifacts_from_package_file_parts(&data, "", &zip, dir.path(), false).unwrap();
        assert!(artifacts.root_path.is_none());
        assert_eq!(artifacts.root_len().unwrap(), 0);
        assert_eq!(artifacts.boot_len().unwrap(), boot.len() as u64);
        assert_eq!(std::fs::read(artifacts.boot_path.unwrap()).unwrap(), boot);
        assert!(artifacts.kernel.is_empty());
        assert_eq!(artifacts.m1n1, b"stage2");
    }

    #[test]
    fn create_streams_a_file_backed_root_without_holding_it_in_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root.img");
        let mut body = b"ROOT-file".to_vec();
        body.extend_from_slice(&[0x5A; 200_000]);
        std::fs::write(&root, &body).unwrap();
        let arts = Artifacts {
            kernel: b"KERN-file".to_vec(),
            m1n1: b"M1N1-file".to_vec(),
            efi_files: Vec::new(),
            firmware_requirements: None,
            firmware: None,
            installer_data: None,
            m1n1_stage1: stage1_fixture(b"file"),
            root_fs: Vec::new(),
            root_path: Some(root),
            boot_fs: Vec::new(),
            boot_path: None,
        };
        assert_eq!(arts.root_fs.len(), 0);
        assert!(arts.root_len().unwrap() > 200_000);
        let path = dir.path().join("asahi.qcow2");
        create_qcow2_disc(&path, &arts, 8 * MB, "m1n1/boot.bin", "Asahi Linux").unwrap();
        let info = inspect_created(&path).unwrap();
        assert!(info.linux_prefix.starts_with(b"ROOT-file"));
        assert!(info.has_linux && info.chainload);
        let zip = dir.path().join("pkg.zip");
        std::fs::write(
            &zip,
            stored_zip(&[
                ("root.img", b"ZIP-ROOT-BYTES"),
                ("boot.img", b"ZIP-BOOT"),
                ("esp/m1n1/boot.bin", b"ZIP-M1N1"),
            ]),
        )
        .unwrap();
        let work = dir.path().join("work");
        let data = parse_installer_data(sample_metadata()).unwrap();
        let extracted = load_artifacts_from_package_file(&data, "", &zip, &work).unwrap();
        assert!(extracted.root_path.is_some());
        assert_eq!(extracted.root_fs.len(), 0);
        assert_eq!(
            std::fs::read(extracted.root_path.as_ref().unwrap()).unwrap(),
            b"ZIP-ROOT-BYTES"
        );
        assert_eq!(extracted.kernel, b"ZIP-BOOT");
        assert_eq!(extracted.m1n1, b"ZIP-M1N1");
    }

    #[test]
    fn create_disc_is_qcow2_with_apfs_efi_linux_and_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asahi.qcow2");
        let arts = artifacts(b"-create");
        create_qcow2_disc(&path, &arts, 8 * MB, "m1n1/boot.bin", "Asahi Linux").expect("create");
        assert!(qcow2_magic_is_present(&path));
        let info = inspect_created(&path).expect("inspect");
        assert!(info.qcow2);
        assert!(info.has_apfs && info.has_efi && info.has_linux);
        let roles: Vec<u16> = info.volumes.iter().map(|v| v.1).collect();
        assert!(roles.contains(&APFS_VOL_ROLE_SYSTEM));
        assert!(roles.contains(&APFS_VOL_ROLE_DATA));
        assert!(roles.contains(&APFS_VOL_ROLE_PREBOOT));
        assert!(roles.contains(&APFS_VOL_ROLE_RECOVERY));
        let sys = info
            .volumes
            .iter()
            .find(|v| v.1 == APFS_VOL_ROLE_SYSTEM)
            .unwrap();
        let data = info
            .volumes
            .iter()
            .find(|v| v.1 == APFS_VOL_ROLE_DATA)
            .unwrap();
        assert_eq!(sys.2, data.2);
        assert_ne!(sys.2, [0u8; 16]);
        assert!(info.custom_boot_object);
        assert!(info.chainload);
        assert!(
            info.efi_uuid
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == '-')
        );
        assert!(info.kernel_on_efi);
        assert!(info.m1n1_on_efi);
        assert!(info.linux_prefix.starts_with(b"ROOT-create"));
        assert!(info.picker_visible && info.custom_boot_object && info.chainload);
        let obj = load_custom_boot_object(&path, None).unwrap();
        assert!(contains_bytes(
            &obj,
            format!("chainload={};m1n1/boot.bin", info.efi_uuid).as_bytes()
        ));
        let raw = std::fs::read(&path).unwrap();
        assert!(raw.windows(arts.m1n1.len()).any(|w| w == arts.m1n1));
    }

    #[test]
    fn create_qcow2_emits_version_3_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asahi.qcow2");
        create_qcow2_disc(
            &path,
            &artifacts(b"-v3"),
            8 * MB,
            "m1n1/boot.bin",
            "Asahi Linux",
        )
        .unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(
            raw.len() >= CLUSTER as usize,
            "header occupies the first {}-byte cluster, got {} bytes",
            CLUSTER,
            raw.len()
        );
        assert_eq!(u32::from_be_bytes(raw[4..8].try_into().unwrap()), 3);
        assert_eq!(u64::from_be_bytes(raw[72..80].try_into().unwrap()), 0);
        assert_eq!(u64::from_be_bytes(raw[80..88].try_into().unwrap()), 0);
        assert_eq!(u64::from_be_bytes(raw[88..96].try_into().unwrap()), 0);
        assert_eq!(u32::from_be_bytes(raw[96..100].try_into().unwrap()), 4);
        assert_eq!(u32::from_be_bytes(raw[100..104].try_into().unwrap()), 104);

        let v2_path = dir.path().join("asahi-v2.qcow2");
        let mut v2 = raw.clone();
        v2[4..8].copy_from_slice(&2u32.to_be_bytes());
        std::fs::write(&v2_path, &v2).unwrap();
        let info = inspect_created(&v2_path).expect("Qcow2::open must still read version 2");
        assert!(info.qcow2 && info.has_apfs && info.has_efi && info.has_linux);
        let mut img = Qcow2::open(&v2_path).expect("open version 2");
        let mut gpt = [0u8; 8];
        img.read_at(u64::from(SECTOR), &mut gpt).unwrap();
        assert_eq!(&gpt, b"EFI PART");
    }

    #[test]
    fn update_replaces_kernel_and_m1n1_and_leaves_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asahi.qcow2");
        let mut original = artifacts(b"-old");
        original.boot_fs = vec![0x31; 4096];
        let installed =
            create_qcow2_disc(&path, &original, 8 * MB, "m1n1/boot.bin", "Asahi Linux").unwrap();
        let mut latest = artifacts(b"-newL");
        latest.boot_fs = vec![0x42; 8192];
        latest.root_fs.clear();
        latest.root_path = None;
        update_disc(&path, &latest).unwrap();
        let mut image = open_image(&path).unwrap();
        assert_eq!(
            read_range(
                &mut *image,
                installed.boot_lba * u64::from(SECTOR),
                latest.boot_fs.len()
            )
            .unwrap(),
            latest.boot_fs
        );
        drop(image);
        let files = read_efi_files(&path, &["asahi/kernel", "m1n1/boot.bin"]).unwrap();
        assert_eq!(files, vec![latest.kernel.clone(), latest.m1n1.clone()]);
        assert!(
            inspect_created(&path)
                .unwrap()
                .linux_prefix
                .starts_with(&original.root_fs)
        );
        let mut custom = artifacts(b"-cus!");
        custom.root_fs.clear();
        custom.m1n1_stage1.resize(64 * 1024, 0x55);
        update_disc(&path, &custom).unwrap();
        let files = read_efi_files(&path, &["asahi/kernel", "m1n1/boot.bin"]).unwrap();
        assert_eq!(files, vec![custom.kernel.clone(), custom.m1n1.clone()]);
        let object = load_custom_boot_object(&path, None).unwrap();
        assert!(object.starts_with(&custom.m1n1_stage1));
        assert!(
            inspect_created(&path)
                .unwrap()
                .linux_prefix
                .starts_with(&original.root_fs)
        );
        let before = std::fs::read(&path).unwrap();
        let root = dir.path().join("oversized-root.img");
        File::create(&root).unwrap().set_len(16 * GB).unwrap();
        custom.root_path = Some(root);
        assert!(
            update_disc(&path, &custom)
                .unwrap_err()
                .to_string()
                .contains("larger than")
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn update_with_a_root_payload_still_replaces_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asahi.qcow2");
        create_qcow2_disc(
            &path,
            &artifacts(b"-old"),
            8 * MB,
            "m1n1/boot.bin",
            "Asahi Linux",
        )
        .unwrap();
        update_disc(&path, &artifacts(b"-root")).unwrap();
        let info = inspect_created(&path).unwrap();
        assert!(info.linux_prefix.starts_with(b"ROOT-root"));
    }

    #[test]
    fn install_writes_layout_to_a_raw_destination() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asahi.img");
        let arts = artifacts(b"-inst");
        install_raw_disc(&path, &arts, 8 * MB, "m1n1/boot.bin", "Asahi Linux").unwrap();
        assert!(!qcow2_magic_is_present(&path));
        let info = inspect_created(&path).expect("inspect install");
        assert!(info.has_apfs && info.has_efi && info.has_linux);
        assert!(info.custom_boot_object);
        assert!(info.linux_prefix.starts_with(b"ROOT-inst"));
    }

    #[test]
    fn custom_artifacts_keep_user_kernel_and_m1n1_but_root_from_package() {
        let data = parse_installer_data(sample_metadata()).unwrap();
        let resolved = resolve_custom(&data).unwrap();
        assert_eq!(resolved.root_image, "root.img");
        let kernel = b"USERKERN".to_vec();
        let m1n1 = b"USERM1N1".to_vec();
        let zip = stored_zip(&[
            ("root.img", b"PKG-ROOT"),
            ("boot.img", b"PKG-BOOT"),
            ("esp/m1n1/boot.bin", b"PKG-M1N1"),
        ]);
        let arts = load_artifacts_custom(&data, kernel.clone(), m1n1.clone(), |_| Ok(zip.clone()))
            .unwrap();
        assert_eq!(arts.kernel, kernel);
        assert_eq!(arts.m1n1, m1n1);
        assert_eq!(arts.root_fs, b"PKG-ROOT");
    }

    #[test]
    fn update_disc_patches_qcow2_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asahi.qcow2");
        create_qcow2_disc(
            &path,
            &artifacts(b"-old"),
            8 * MB,
            "m1n1/boot.bin",
            "Asahi Linux",
        )
        .unwrap();
        let before = std::fs::metadata(&path).unwrap().len();
        let mut next = artifacts(b"-new!");
        next.root_fs.clear();
        next.root_path = None;
        update_disc(&path, &next).unwrap();
        let after = std::fs::metadata(&path).unwrap().len();
        assert!(
            after < 128 * MB,
            "in-place update must not materialise the full virtual disc, host size {after}"
        );
        assert!(
            after.abs_diff(before) < 32 * MB,
            "in-place update should not rewrite the qcow2 from scratch, {before} -> {after}"
        );
        let info = inspect_created(&path).unwrap();
        assert!(
            info.linux_prefix.starts_with(b"ROOT-old"),
            "update without a root payload must leave the installed root FS, got {:?}",
            String::from_utf8_lossy(&info.linux_prefix)
        );
        let host = std::fs::read(&path).unwrap();
        assert!(host.windows(b"KERN-new!".len()).any(|w| w == b"KERN-new!"));
        assert_eq!(
            read_efi_files(&path, &["asahi/kernel"]).unwrap(),
            vec![next.kernel.clone()]
        );
    }

    #[test]
    fn parse_size_arg_accepts_m_and_bytes() {
        assert_eq!(parse_size_arg("8M").unwrap(), 8 * MB);
        assert_eq!(parse_size_arg("8MB").unwrap(), 8 * MB);
        assert_eq!(parse_size_arg("8388608").unwrap(), 8 * MB);
    }

    #[test]
    fn parse_curl_progress_reads_percent_from_a_progress_bar() {
        assert_eq!(parse_curl_progress(b"####  45.0%"), Some(0.45));
        assert_eq!(
            parse_curl_progress(b"\r########  12.5%\r################  88.0%"),
            Some(0.88)
        );
        assert_eq!(parse_curl_progress(b"no numbers yet"), None);
        assert_eq!(
            parse_curl_progress(
                b"######################################################################## 100.0%"
            ),
            Some(1.0)
        );
    }

    #[test]
    fn zip_file_inflates_deflate_method_8_and_custom_still_uses_user_kernel() {
        let zip = deflated_zip(&[
            ("root.img", b"ROOT-deflated"),
            ("boot.img", b"PKG-BOOT"),
            ("esp/m1n1/boot.bin", b"PKG-M1N1"),
        ]);
        assert_eq!(
            zip_file(&zip, "root.img").as_deref(),
            Some(b"ROOT-deflated".as_slice())
        );
        let data = parse_installer_data(sample_metadata()).unwrap();
        let arts = load_artifacts_custom(&data, b"USERKERN".to_vec(), b"USERM1N1".to_vec(), |_| {
            Ok(zip.clone())
        })
        .unwrap();
        assert_eq!(arts.root_fs, b"ROOT-deflated");
        assert_eq!(arts.kernel, b"USERKERN");
        assert_eq!(arts.m1n1, b"USERM1N1");
        assert_ne!(arts.root_fs.as_slice(), zip.as_slice());
    }

    #[test]
    fn allocate_cluster_sets_refcount_to_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asahi.qcow2");
        let root = dir.path().join("root.img");
        std::fs::write(&root, vec![0x5A; 200_000]).unwrap();
        let arts = Artifacts {
            kernel: b"KERN".to_vec(),
            m1n1: b"M1N1".to_vec(),
            efi_files: Vec::new(),
            firmware_requirements: None,
            firmware: None,
            installer_data: None,
            m1n1_stage1: stage1_fixture(b"alloc"),
            root_fs: Vec::new(),
            root_path: Some(root),
            boot_fs: Vec::new(),
            boot_path: None,
        };
        create_qcow2_disc(&path, &arts, 8 * MB, "m1n1/boot.bin", "Asahi Linux").unwrap();
        let mut img = Qcow2::open(&path).unwrap();
        let l1 = img.l1.clone();
        let cluster = img.cluster;
        let l2_entries = img.l2_entries();
        let mut mapped = 0u64;
        for &l2_off in &l1 {
            if l2_off == 0 {
                continue;
            }
            assert_eq!(img.cluster_refcount(l2_off / cluster).unwrap(), 1);
            for i in 0..l2_entries {
                img.file.seek(SeekFrom::Start(l2_off + i * 8)).unwrap();
                let mut e = [0u8; 8];
                img.file.read_exact(&mut e).unwrap();
                let host = u64::from_be_bytes(e) & !QCOW_COPIED & !QCOW_COMPRESSED;
                if host == 0 {
                    continue;
                }
                mapped += 1;
                assert_eq!(
                    img.cluster_refcount(host / cluster).unwrap(),
                    1,
                    "host cluster {} must have refcount 1",
                    host / cluster
                );
            }
        }
        assert!(mapped > 0, "create must map at least one data cluster");

        let guest = 7 * MB;
        img.write_at(guest, b"NEWCLUSTER").unwrap();
        let host = img.lookup_host(guest / cluster).unwrap();
        assert_ne!(host, 0);
        assert_eq!(img.cluster_refcount(host / cluster).unwrap(), 1);
        drop(img);

        let mut img = Qcow2::open(&path).unwrap();
        img.write_at(guest + cluster, b"ANOTHER").unwrap();
        let host = img.lookup_host((guest + cluster) / cluster).unwrap();
        assert_eq!(img.cluster_refcount(host / cluster).unwrap(), 1);
    }

    #[test]
    fn qcow_refcounts_cover_a_fedora_sized_host_allocation() {
        let cluster = CLUSTER;
        let data = 14 * GB / cluster;
        let (table, blocks) = qcow_refcount_shape(data + 8, cluster);
        let total = 1 + table + blocks + data + 8;
        assert!(
            blocks * (cluster / 2) >= total,
            "refcount blocks {blocks} cannot cover {total} host clusters"
        );
        assert!(
            table * (cluster / 8) >= blocks,
            "refcount table clusters {table} cannot name {blocks} blocks"
        );
        assert!(blocks > 1);
    }

    #[test]
    fn update_replaces_a_multi_cluster_m1n1() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asahi.qcow2");
        create_qcow2_disc(
            &path,
            &artifacts(b"-old"),
            8 * MB,
            "m1n1/boot.bin",
            "Asahi Linux",
        )
        .unwrap();
        let mut next = artifacts(b"-big");
        next.m1n1 = vec![0x5A; 8192];
        next.kernel = vec![0xA5; 4096];
        update_disc(&path, &next).unwrap();
        let host = std::fs::read(&path).unwrap();
        assert!(
            host.windows(512).any(|w| w.iter().all(|b| *b == 0x5A)),
            "updated m1n1 clusters must land on the disc"
        );
        assert!(
            host.windows(512).any(|w| w.iter().all(|b| *b == 0xA5)),
            "updated kernel clusters must land on the disc"
        );
        assert!(host.iter().filter(|b| **b == 0x5A).count() >= 8192);
        assert!(host.iter().filter(|b| **b == 0xA5).count() >= 4096);
        assert_eq!(
            read_efi_files(&path, &["m1n1/boot.bin"]).unwrap(),
            vec![next.m1n1.clone()]
        );
    }

    #[test]
    fn created_stub_is_picker_visible_and_direct_boot_uses_bless() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asahi.qcow2");
        let arts = artifacts(b"-stub");
        create_qcow2_disc(&path, &arts, 8 * MB, "m1n1/boot.bin", "Asahi Linux").unwrap();
        let info = inspect_created(&path).expect("inspect");
        let sys = info
            .volumes
            .iter()
            .find(|v| v.1 == APFS_VOL_ROLE_SYSTEM)
            .unwrap();
        let vgid = apfs_uuid(&sys.2);
        let sv = info.system_version.as_ref().expect("SystemVersion.plist");
        let sv_text = String::from_utf8_lossy(sv);
        assert!(sv_text.contains("ProductName"), "{sv_text}");
        assert!(sv_text.contains("Asahi Linux"), "{sv_text}");
        assert!(!info.has_launchd);
        assert!(info.finish_installation_boot);
        assert!(info.picker_visible);
        assert!(info.custom_boot_object);
        assert!(info.restore_bundle);
        assert_eq!(info.blessed_vgid, vgid);
        assert!(info.chainload);
        assert!(info.m1n1_on_efi);

        let obj = load_custom_boot_object(&path, None).unwrap();
        assert!(obj.starts_with(&arts.m1n1_stage1));
        assert!(!obj.starts_with(&arts.m1n1));
        let chain = format!("chainload={};m1n1/boot.bin", info.efi_uuid);
        assert!(
            contains_bytes(&obj, chain.as_bytes()),
            "{}",
            String::from_utf8_lossy(&obj)
        );
        validate_disc(&path).expect("validate created disc");

        let mac = "00000000-0000-4000-8000-000000000001".to_string();
        let asahi = vgid.clone();
        assert!(resolve_boot_volume(None, None, std::slice::from_ref(&asahi)).is_err());
        assert!(resolve_boot_volume(None, None, &[mac.clone(), asahi.clone()]).is_err());
        assert_eq!(
            resolve_boot_volume(Some(&asahi), None, &[mac.clone(), asahi.clone()]).unwrap(),
            asahi
        );
        assert_eq!(
            resolve_boot_volume(Some(&asahi), Some(&mac), &[mac.clone(), asahi.clone()]).unwrap(),
            mac
        );

        let loaded = load_custom_boot_object(&path, None).unwrap();
        assert!(contains_chainload(&loaded));
        assert!(contains_bytes(&loaded, info.efi_uuid.as_bytes()));

        let miss = load_custom_boot_object(&path, Some("not-a-volume-group")).unwrap_err();
        let msg = miss.to_string().to_ascii_lowercase();
        assert!(
            !msg.contains("esp") && !msg.contains("efi") && !msg.contains("fallback"),
            "{msg}"
        );
    }

    #[test]
    fn inspect_extracts_a_custom_boot_object_larger_than_one_apfs_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asahi.qcow2");
        let mut arts = artifacts(b"-big1");
        arts.m1n1_stage1 = stage1_fixture(b"big");
        arts.m1n1_stage1.resize(8192, 0x11);
        create_qcow2_disc(&path, &arts, 8 * MB, "m1n1/boot.bin", "Asahi Linux").unwrap();
        let info = inspect_created(&path).unwrap();
        assert!(info.chainload && info.custom_boot_object && info.picker_visible);
        let obj = load_custom_boot_object(&path, None).unwrap();
        assert!(
            obj.len() > APFS_BLOCK as usize,
            "custom object must not be truncated to one APFS block, got {}",
            obj.len()
        );
        assert!(obj.starts_with(&arts.m1n1_stage1));
        assert!(contains_chainload(&obj));
        assert!(contains_bytes(&obj, info.efi_uuid.as_bytes()));
        validate_disc(&path).unwrap();
    }

    fn deflated_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::DeflateEncoder;
        let mut out = Vec::new();
        for (name, data) in files {
            let name_b = name.as_bytes();
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(data).unwrap();
            let comp = encoder.finish().unwrap();
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&[20, 0, 0, 0]);
            out.extend_from_slice(&8u16.to_le_bytes());
            out.extend_from_slice(&[0, 0, 0, 0]);
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(comp.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name_b);
            out.extend_from_slice(&comp);
        }
        out
    }

    fn stored_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in files {
            let name_b = name.as_bytes();
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&[20, 0, 0, 0]); // version, flags
            out.extend_from_slice(&0u16.to_le_bytes()); // stored
            out.extend_from_slice(&[0, 0, 0, 0]);
            out.extend_from_slice(&0u32.to_le_bytes()); // crc
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name_b);
            out.extend_from_slice(data);
        }
        out
    }
}
