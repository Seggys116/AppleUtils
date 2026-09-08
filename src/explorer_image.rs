use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use crate::apfs_image::{APFS_VOL_ROLE_SYSTEM, NX_MAGIC, SECTOR_BYTES, parse_gpt};
use crate::apfs_read::{
    ApfsContainer, ApfsReadError, DT_DIR, DT_LNK, DT_REG, VolumeChoice, container_geometry_of,
};
use crate::apfs_verify::{BlockSource, VerifyError};

const QCOW_MAGIC: u32 = 0x5146_49FB;
const QCOW_COPIED: u64 = 1u64 << 63;
const QCOW_COMPRESSED: u64 = 1u64 << 62;
const KOLY: &[u8; 4] = b"koly";
const MISH: &[u8; 4] = b"mish";
const UDIF_RAW: u32 = 0x0000_0001;
const UDIF_ZERO: u32 = 0x0000_0000;
const UDIF_IGNORE: u32 = 0x0000_0002;
const UDIF_ZLIB: u32 = 0x8000_0005;
const UDIF_TERM: u32 = 0xFFFF_FFFF;

const SYSTEM_VERSION_PATH: &str = "/System/Library/CoreServices/SystemVersion.plist";
const LAUNCHD_PATH: &str = "/sbin/launchd";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplorerError {
    Io(String),
    Format(String),
    Apfs(String),
}

impl std::fmt::Display for ExplorerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(m) | Self::Format(m) | Self::Apfs(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ExplorerError {}

impl From<io::Error> for ExplorerError {
    fn from(err: io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

impl From<ApfsReadError> for ExplorerError {
    fn from(err: ApfsReadError) -> Self {
        Self::Apfs(err.to_string())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendKind {
    Raw,
    Gpt,
    Qcow2,
    Dmg,
}

impl BackendKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Gpt => "gpt",
            Self::Qcow2 => "qcow2",
            Self::Dmg => "dmg",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Directory,
    File,
    Symlink,
    Other,
}

impl EntryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::File => "file",
            Self::Symlink => "symlink",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedEntry {
    pub name: String,
    pub kind: EntryKind,
    pub size: Option<u64>,
    pub symlink_target: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct VolumeInfo {
    pub name: String,
    pub role: String,
    pub sealed: bool,
    pub encrypted: bool,
    pub container_index: usize,
    pub partition_name: String,
    pub bootable: bool,
    pub volume_group_id: [u8; 16],
    pub system_version: Option<String>,
}

impl VolumeInfo {
    pub fn flag_label(&self) -> Option<&'static str> {
        if self.encrypted {
            Some("encrypted")
        } else if self.sealed {
            Some("sealed")
        } else if self.bootable {
            Some("bootable")
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplorerView {
    pub path: String,
    pub backend: BackendKind,
    pub volumes: Vec<VolumeInfo>,
    pub volume_index: usize,
    pub volume_cursor: usize,
    pub cwd: String,
    pub entries: Vec<ListedEntry>,
    pub cursor: usize,
    pub preview: Option<String>,
    pub error: Option<String>,
    pub message: Option<String>,
}

impl ExplorerView {
    pub fn volume_name(&self) -> &str {
        self.volumes
            .get(self.volume_index)
            .map(|volume| volume.name.as_str())
            .unwrap_or("")
    }

    pub fn volume(&self) -> Option<&VolumeInfo> {
        self.volumes.get(self.volume_index)
    }

    pub fn cursor_volume(&self) -> Option<&VolumeInfo> {
        self.volumes.get(self.volume_cursor)
    }
}

enum DiskBackend {
    Raw(File),
    Qcow2(Qcow2File),
    Udif(UdifFile),
}

impl DiskBackend {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), ExplorerError> {
        match self {
            Self::Raw(file) => {
                use std::io::Write;
                file.seek(SeekFrom::Start(offset))?;
                file.write_all(data)?;
                Ok(())
            }
            Self::Qcow2(qcow) => crate::asahi_ops::guest_write(&qcow.path, offset, data)
                .map_err(|e| ExplorerError::Io(e.to_string())),
            Self::Udif(_) => Err(ExplorerError::Format(
                "cannot insert into a UDIF/DMG; use a raw or qcow2 image".into(),
            )),
        }
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ExplorerError> {
        match self {
            Self::Raw(file) => {
                file.seek(SeekFrom::Start(offset))?;
                match file.read_exact(buf) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                        buf.fill(0);
                        Ok(())
                    }
                    Err(e) => Err(e.into()),
                }
            }
            Self::Qcow2(qcow) => qcow.read_at(offset, buf),
            Self::Udif(udif) => udif.read_at(offset, buf),
        }
    }
}

#[derive(Clone, Debug)]
struct ContainerLoc {
    offset: u64,
    block_size: u32,
    block_count: u64,
    partition_name: String,
}

pub struct OpenImage {
    backend: DiskBackend,
    kind: BackendKind,
    containers: Vec<ContainerLoc>,
    active: usize,
}

impl OpenImage {
    pub fn kind(&self) -> BackendKind {
        self.kind
    }

    pub fn block_size(&self) -> u32 {
        self.containers[self.active].block_size
    }

    pub fn block_count(&self) -> u64 {
        self.containers[self.active].block_count
    }

    fn read_container_block(&mut self, index: u64, into: &mut [u8]) -> Result<(), VerifyError> {
        let loc = &self.containers[self.active];
        let off = index
            .checked_mul(u64::from(loc.block_size))
            .and_then(|at| at.checked_add(loc.offset))
            .ok_or(VerifyError::BlockOutOfRange { index })?;
        self.backend
            .read_at(off, into)
            .map_err(|_| VerifyError::BlockOutOfRange { index })
    }

    fn write_container_block(&mut self, index: u64, data: &[u8]) -> Result<(), ExplorerError> {
        let loc = &self.containers[self.active];
        let off = index
            .checked_mul(u64::from(loc.block_size))
            .and_then(|at| at.checked_add(loc.offset))
            .ok_or_else(|| ExplorerError::Format("block address overflow".into()))?;
        self.backend.write_at(off, data)
    }
}

struct ImageBlocks<'a> {
    image: &'a mut OpenImage,
}

impl BlockSource for ImageBlocks<'_> {
    fn read_block(&mut self, index: u64, into: &mut [u8]) -> Result<(), VerifyError> {
        self.image.read_container_block(index, into)
    }
}

pub fn open_image(path: &Path) -> Result<OpenImage, ExplorerError> {
    open_image_mode(path, true)
}

fn open_image_mode(path: &Path, writable: bool) -> Result<OpenImage, ExplorerError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(writable)
        .open(path)
        .or_else(|_| File::open(path))?;
    let mut magic = [0u8; 8];
    let n = file.read(&mut magic)?;
    if n >= 4 && u32::from_be_bytes(magic[0..4].try_into().unwrap()) == QCOW_MAGIC {
        let mut qcow = Qcow2File::open(path)?;
        if qcow.version != 3 && qcow.version != 2 {
            return Err(ExplorerError::Format(format!(
                "unsupported qcow2 version {}",
                qcow.version
            )));
        }
        let containers = probe_all(|off, buf| qcow.read_at(off, buf))?;
        return Ok(OpenImage {
            backend: DiskBackend::Qcow2(qcow),
            kind: BackendKind::Qcow2,
            containers,
            active: 0,
        });
    }

    let len = file.metadata()?.len();
    if len >= 512 {
        file.seek(SeekFrom::Start(len - 512))?;
        let mut trail = [0u8; 512];
        file.read_exact(&mut trail)?;
        if trail[0..4] == *KOLY {
            let mut udif = UdifFile::open(path, &trail)?;
            let containers = probe_all(|off, buf| udif.read_at(off, buf))?;
            return Ok(OpenImage {
                backend: DiskBackend::Udif(udif),
                kind: BackendKind::Dmg,
                containers,
                active: 0,
            });
        }
    }

    file.seek(SeekFrom::Start(0))?;
    let mut raw = file;
    let containers = probe_all(|off, buf| {
        raw.seek(SeekFrom::Start(off))
            .map_err(ExplorerError::from)?;
        match raw.read_exact(buf) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                buf.fill(0);
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    })?;
    let kind = if containers.len() == 1 && containers[0].offset == 0 {
        BackendKind::Raw
    } else {
        BackendKind::Gpt
    };
    Ok(OpenImage {
        backend: DiskBackend::Raw(raw),
        kind,
        containers,
        active: 0,
    })
}

pub fn extract_selected_paths(
    image_path: &Path,
    volume_name: &str,
    paths: &[String],
) -> Result<tempfile::TempDir, ExplorerError> {
    extract_paths_at_container(image_path, volume_name, None, paths, false)
}

pub fn extract_paths_from_unique_volume(
    image_path: &Path,
    paths: &[String],
) -> Result<tempfile::TempDir, ExplorerError> {
    extract_unique_paths(image_path, paths, false)
}

pub fn extract_paths_with_link_metadata(
    image_path: &Path,
    paths: &[String],
) -> Result<tempfile::TempDir, ExplorerError> {
    extract_unique_paths(image_path, paths, true)
}

fn extract_unique_paths(
    image_path: &Path,
    paths: &[String],
    preserve_links: bool,
) -> Result<tempfile::TempDir, ExplorerError> {
    if paths.is_empty() {
        return Err(ExplorerError::Format("no extraction paths supplied".into()));
    }
    let mut image = open_image_mode(image_path, false)?;
    let volumes = collect_volumes(&mut image)?;
    let mut matches = Vec::new();
    for info in volumes {
        image.active = info.container_index;
        let block_size = image.block_size();
        let block_count = image.block_count();
        let mut blocks = ImageBlocks { image: &mut image };
        let mut apfs = ApfsContainer::mount(&mut blocks, block_size, block_count)?;
        let volume = apfs.open_volume_chosen(&VolumeChoice::Named(info.name.clone()))?;
        let mut supplies_all = true;
        for path in paths {
            match apfs.stat(&volume, path) {
                Ok(_) => {}
                Err(ApfsReadError::ComponentNotFound { .. }) => {
                    supplies_all = false;
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        if supplies_all {
            matches.push((info.name, info.container_index));
        }
    }
    if matches.len() != 1 {
        return Err(ExplorerError::Apfs(format!(
            "expected one volume supplying all requested paths, found {}",
            matches.len()
        )));
    }
    let (name, container) = matches.pop().unwrap();
    drop(image);
    extract_paths_at_container(image_path, &name, Some(container), paths, preserve_links)
}

fn extract_paths_at_container(
    image_path: &Path,
    volume_name: &str,
    container: Option<usize>,
    paths: &[String],
    preserve_links: bool,
) -> Result<tempfile::TempDir, ExplorerError> {
    let mut selected = BTreeSet::new();
    for path in paths {
        if !path.starts_with('/')
            || path == "/"
            || path.contains(['\\', '\0'])
            || path[1..]
                .split('/')
                .any(|part| portable_extraction_name(part).is_err())
        {
            return Err(ExplorerError::Format(format!(
                "unsafe extraction path {path:?}"
            )));
        }
        selected.insert(path.clone());
    }
    if selected.is_empty() {
        return Err(ExplorerError::Format("no extraction paths supplied".into()));
    }
    let mut image = open_image_mode(image_path, false)?;
    let volumes = collect_volumes(&mut image)?;
    let matching: Vec<_> = volumes
        .iter()
        .filter(|volume| {
            volume.name == volume_name
                && container.is_none_or(|index| index == volume.container_index)
        })
        .collect();
    if matching.len() != 1 {
        return Err(ExplorerError::Apfs(
            "volume selection is missing or ambiguous".into(),
        ));
    }
    image.active = matching[0].container_index;
    let block_size = image.block_size();
    let block_count = image.block_count();
    let mut blocks = ImageBlocks { image: &mut image };
    let mut apfs = ApfsContainer::mount(&mut blocks, block_size, block_count)?;
    let volume = apfs.open_volume_chosen(&VolumeChoice::Named(volume_name.into()))?;
    let output = tempfile::tempdir()?;
    let mut pending: Vec<_> = selected
        .iter()
        .filter(|path| {
            !selected
                .iter()
                .any(|parent| parent != *path && path.starts_with(&(parent.to_string() + "/")))
        })
        .map(|path| (path.clone(), path.clone(), BTreeSet::new(), false))
        .collect();
    let mut output_names = std::collections::BTreeMap::new();
    let mut links = std::collections::BTreeMap::new();
    while let Some((source, destination_path, mut ancestry, through_link)) = pending.pop() {
        if let Some(previous) =
            output_names.insert(destination_path.to_lowercase(), destination_path.clone())
            && previous != destination_path
        {
            return Err(ExplorerError::Format(
                "case-colliding extraction paths".into(),
            ));
        }
        let facts = match apfs.stat(&volume, &source) {
            Ok(facts) => facts,
            Err(ApfsReadError::ComponentNotFound { .. }) if preserve_links && through_link => {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let destination = output.path().join(&destination_path[1..]);
        if (facts.is_directory() || facts.is_symlink()) && !ancestry.insert(facts.file_id) {
            return Err(ExplorerError::Apfs("cyclic extraction topology".into()));
        }
        if facts.is_directory() {
            std::fs::create_dir_all(&destination)?;
            for entry in apfs.list_directory(&volume, &source)? {
                let name = portable_extraction_name(&entry.name)?;
                pending.push((
                    format!("{source}/{name}"),
                    format!("{destination_path}/{name}"),
                    ancestry.clone(),
                    through_link,
                ));
            }
        } else if facts.is_regular_file() {
            std::fs::create_dir_all(
                destination
                    .parent()
                    .ok_or_else(|| ExplorerError::Format("missing extraction parent".into()))?,
            )?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)?;
            apfs.extract(&volume, &source, 0, None, &mut file)?;
        } else if facts.is_symlink() {
            let target = apfs.read_symlink(&volume, &source)?;
            if preserve_links && !through_link {
                links.insert(destination_path.clone(), target.clone());
            }
            let resolved = confined_link_target(&source, &target)?;
            if !selected
                .iter()
                .any(|root| resolved == *root || resolved.starts_with(&(root.clone() + "/")))
            {
                return Err(ExplorerError::Format(format!(
                    "symlink {source} escapes selected paths"
                )));
            }
            pending.push((resolved, destination_path, ancestry, true));
        } else {
            return Err(ExplorerError::Format(format!(
                "unsupported extraction file type at {source}"
            )));
        }
    }
    if preserve_links {
        let data = serde_json::to_vec(&links).map_err(|e| ExplorerError::Format(e.to_string()))?;
        std::fs::write(output.path().join(".appleutils-symlinks.json"), data)?;
    }
    Ok(output)
}

fn portable_extraction_name(name: &str) -> Result<&str, ExplorerError> {
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'));
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.ends_with([' ', '.'])
        || reserved
        || name
            .chars()
            .any(|c| c.is_control() || "<>:\"/\\|?*".contains(c))
    {
        return Err(ExplorerError::Format(format!(
            "unrepresentable portable extraction name {name:?}"
        )));
    }
    Ok(name)
}

fn confined_link_target(source: &str, target: &str) -> Result<String, ExplorerError> {
    if target.is_empty() || target.contains(['\\', '\0']) {
        return Err(ExplorerError::Format(format!(
            "unsafe symlink target at {source}"
        )));
    }
    let mut parts: Vec<_> = if target.starts_with('/') {
        Vec::new()
    } else {
        let mut parent: Vec<_> = source[1..].split('/').collect();
        parent.pop();
        parent
    };
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(ExplorerError::Format("symlink escapes image root".into()));
                }
            }
            part => {
                portable_extraction_name(part)?;
                parts.push(part);
            }
        }
    }
    Ok(format!("/{}", parts.join("/")))
}

fn probe_all(
    mut read_at: impl FnMut(u64, &mut [u8]) -> Result<(), ExplorerError>,
) -> Result<Vec<ContainerLoc>, ExplorerError> {
    let mut found = Vec::new();
    let mut seen = BTreeSet::new();
    let mut push = |loc: ContainerLoc| {
        if seen.insert(loc.offset) {
            found.push(loc);
        }
    };

    let mut head = vec![0u8; 4096];
    read_at(0, &mut head)?;
    if u32::from_le_bytes(head[0x20..0x24].try_into().unwrap()) == NX_MAGIC {
        let (block_size, block_count) =
            container_geometry_of(&head).map_err(ExplorerError::from)?;
        push(ContainerLoc {
            offset: 0,
            block_size,
            block_count,
            partition_name: "container".into(),
        });
    }

    for gpt_block in [512u32, 4096] {
        let header_bytes = gpt_prefix_bytes(gpt_block);
        let mut prefix = vec![0u8; header_bytes];
        if read_at(0, &mut prefix).is_err() {
            continue;
        }
        let Ok(table) = parse_gpt(&prefix, gpt_block) else {
            continue;
        };
        for part in &table.partitions {
            let (start, _) = part.byte_range(gpt_block);
            let mut probe = vec![0u8; 4096];
            if read_at(start, &mut probe).is_err() {
                continue;
            }
            if u32::from_le_bytes(probe[0x20..0x24].try_into().unwrap()) != NX_MAGIC {
                continue;
            }
            let Ok((bs, bc)) = container_geometry_of(&probe) else {
                continue;
            };
            let partition_name = if part.name.trim().is_empty() {
                "APFS".into()
            } else {
                part.name.clone()
            };
            push(ContainerLoc {
                offset: start,
                block_size: bs,
                block_count: bc,
                partition_name,
            });
        }
    }

    if found.is_empty() {
        return Err(ExplorerError::Format(
            "no APFS container at byte 0 and no GPT partition probed as NXSB".into(),
        ));
    }
    Ok(found)
}

fn gpt_prefix_bytes(block_size: u32) -> usize {
    (2 * block_size as usize) + 128 * 128
}

fn entry_kind(entry_type: u16) -> EntryKind {
    match entry_type {
        t if t == DT_DIR => EntryKind::Directory,
        t if t == DT_REG => EntryKind::File,
        t if t == DT_LNK => EntryKind::Symlink,
        _ => EntryKind::Other,
    }
}

fn join_path(cwd: &str, name: &str) -> String {
    if cwd == "/" {
        format!("/{name}")
    } else {
        format!("{cwd}/{name}")
    }
}

fn list_entries(
    apfs: &mut ApfsContainer<'_>,
    volume_name: &str,
    cwd: &str,
) -> Result<Vec<ListedEntry>, ExplorerError> {
    let vol = apfs.open_volume_chosen(&VolumeChoice::Named(volume_name.to_string()))?;
    let raw = apfs.list_directory(&vol, cwd)?;
    let mut entries = Vec::with_capacity(raw.len());
    for item in raw {
        let kind = entry_kind(item.entry_type);
        let child = join_path(cwd, &item.name);
        let symlink_target = if kind == EntryKind::Symlink {
            apfs.read_symlink(&vol, &child).ok()
        } else {
            None
        };
        entries.push(ListedEntry {
            name: item.name,
            kind,
            size: item.size,
            symlink_target,
        });
    }
    entries.sort_by(|a, b| {
        kind_rank(a.kind).cmp(&kind_rank(b.kind)).then_with(|| {
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase())
        })
    });
    Ok(entries)
}

fn kind_rank(kind: EntryKind) -> u8 {
    match kind {
        EntryKind::Directory => 0,
        EntryKind::File => 1,
        EntryKind::Symlink => 2,
        EntryKind::Other => 3,
    }
}

fn volume_info_from_summary(
    apfs: &mut ApfsContainer<'_>,
    summary: &crate::apfs_read::VolumeSummary,
    container_index: usize,
    partition_name: &str,
) -> VolumeInfo {
    let role = crate::apfs_image::apfs_role_name(summary.role)
        .filter(|name| *name != "none")
        .unwrap_or("volume")
        .to_string();
    let is_system = role == "System" || summary.role == APFS_VOL_ROLE_SYSTEM;
    let picker_files = volume_is_picker_visible(apfs, &summary.name);
    VolumeInfo {
        name: summary.name.clone(),
        role,
        sealed: summary.sealed,
        encrypted: summary.encrypted,
        container_index,
        partition_name: partition_name.to_string(),
        bootable: is_system && picker_files,
        volume_group_id: summary.volume_group_id,
        system_version: extract_system_version(apfs, &summary.name),
    }
}

fn volume_is_picker_visible(apfs: &mut ApfsContainer<'_>, name: &str) -> bool {
    let Ok(vol) = apfs.open_volume_chosen(&VolumeChoice::Named(name.to_string())) else {
        return false;
    };
    path_is_regular_file(apfs, &vol, SYSTEM_VERSION_PATH)
        && (path_is_regular_file(apfs, &vol, LAUNCHD_PATH)
            || path_is_regular_file(
                apfs,
                &vol,
                "/Finish Installation.app/Contents/Resources/boot.bin",
            ))
}

fn path_is_regular_file(
    apfs: &mut ApfsContainer<'_>,
    vol: &crate::apfs_read::MountedVolume,
    path: &str,
) -> bool {
    match apfs.stat(vol, path) {
        Ok(facts) if facts.is_regular_file() => {
            let mut bytes = Vec::new();
            apfs.extract(vol, path, 0, None, &mut bytes).is_ok()
        }
        _ => false,
    }
}

fn extract_system_version(apfs: &mut ApfsContainer<'_>, name: &str) -> Option<String> {
    let vol = apfs
        .open_volume_chosen(&VolumeChoice::Named(name.to_string()))
        .ok()?;
    let mut bytes = Vec::new();
    apfs.extract(&vol, SYSTEM_VERSION_PATH, 0, None, &mut bytes)
        .ok()?;
    if bytes.is_empty() {
        return None;
    }
    parse_product_user_visible_version(&bytes)
}

fn parse_product_user_visible_version(bytes: &[u8]) -> Option<String> {
    if let Ok(value) = plist::Value::from_reader_xml(std::io::Cursor::new(bytes))
        && let Some(version) = value
            .as_dictionary()
            .and_then(|dict| dict.get("ProductUserVisibleVersion"))
            .and_then(plist::Value::as_string)
    {
        return Some(version.to_string());
    }
    let text = String::from_utf8_lossy(bytes);
    const KEY: &str = "ProductUserVisibleVersion";
    if let Some(idx) = text.find(KEY) {
        let after = &text[idx + KEY.len()..];
        if let Some(start) = after.find("<string>") {
            let rest = &after[start + 8..];
            if let Some(end) = rest.find("</string>") {
                let version = rest[..end].trim();
                if !version.is_empty() {
                    return Some(version.to_string());
                }
            }
        }
    }
    let snippet: String = text.chars().take(80).collect();
    let snippet = snippet.trim();
    if snippet.is_empty() {
        None
    } else {
        Some(snippet.to_string())
    }
}

fn collect_volumes(image: &mut OpenImage) -> Result<Vec<VolumeInfo>, ExplorerError> {
    let mut infos = Vec::new();
    let n = image.containers.len();
    for ci in 0..n {
        image.active = ci;
        let partition_name = image.containers[ci].partition_name.clone();
        let block_size = image.block_size();
        let block_count = image.block_count();
        let mut blocks = ImageBlocks { image };
        match ApfsContainer::mount(&mut blocks, block_size, block_count) {
            Ok(mut apfs) => match apfs.volumes() {
                Ok(volumes) => {
                    for summary in &volumes {
                        infos.push(volume_info_from_summary(
                            &mut apfs,
                            summary,
                            ci,
                            &partition_name,
                        ));
                    }
                }
                Err(_) => continue,
            },
            Err(_) => continue,
        }
    }
    if infos.is_empty() {
        return Err(ExplorerError::Apfs("the disc names no APFS volumes".into()));
    }
    Ok(infos)
}

pub fn load_view(
    path: &Path,
    cwd: &str,
    volume_index: usize,
) -> Result<ExplorerView, ExplorerError> {
    let mut image = open_image(path)?;
    let backend = image.kind;
    let infos = collect_volumes(&mut image)?;
    let volume_index = volume_index.min(infos.len() - 1);
    let chosen = infos[volume_index].clone();
    image.active = chosen.container_index;
    let block_size = image.block_size();
    let block_count = image.block_count();
    let mut blocks = ImageBlocks { image: &mut image };
    let mut apfs = ApfsContainer::mount(&mut blocks, block_size, block_count)?;
    let entries = list_entries(&mut apfs, &chosen.name, cwd)?;
    Ok(ExplorerView {
        path: path.display().to_string(),
        backend,
        volumes: infos,
        volume_index,
        volume_cursor: volume_index,
        cwd: cwd.to_string(),
        entries,
        cursor: 0,
        preview: None,
        error: None,
        message: None,
    })
}

pub fn export_entry(
    image: &Path,
    volume: &str,
    apfs_path: &str,
    dest: &Path,
) -> Result<std::path::PathBuf, ExplorerError> {
    let view = load_view(
        image,
        parent_of(apfs_path),
        volume_index_named(image, volume)?,
    )?;
    let name = name_of(apfs_path);
    let entry = view
        .entries
        .iter()
        .find(|e| e.name == name)
        .cloned()
        .ok_or_else(|| ExplorerError::Apfs(format!("{apfs_path} is not in the listing")))?;
    let out = if dest.is_dir() {
        dest.join(safe_name(&entry.name)?)
    } else {
        dest.to_path_buf()
    };
    export_one(image, volume, apfs_path, &entry, &out)?;
    Ok(out)
}

fn volume_index_named(image: &Path, volume: &str) -> Result<usize, ExplorerError> {
    let view = load_view(image, "/", 0)?;
    view.volumes
        .iter()
        .position(|v| v.name == volume)
        .ok_or_else(|| ExplorerError::Apfs(format!("no volume named {volume}")))
}

fn export_one(
    image: &Path,
    volume: &str,
    apfs_path: &str,
    entry: &ListedEntry,
    dest: &Path,
) -> Result<(), ExplorerError> {
    match entry.kind {
        EntryKind::Directory => {
            std::fs::create_dir_all(dest)?;
            let idx = volume_index_named(image, volume)?;
            let child_view = load_view(image, apfs_path, idx)?;
            for child in &child_view.entries {
                let child_apfs = join_path(apfs_path, &child.name);
                let child_dest = dest.join(safe_name(&child.name)?);
                export_one(image, volume, &child_apfs, child, &child_dest)?;
            }
        }
        EntryKind::Symlink => {
            let target = entry.symlink_target.as_deref().unwrap_or("");
            #[cfg(unix)]
            {
                let _ = std::fs::remove_file(dest);
                std::os::unix::fs::symlink(target, dest)?;
            }
            #[cfg(not(unix))]
            {
                std::fs::write(dest, target.as_bytes())?;
            }
        }
        EntryKind::File | EntryKind::Other => {
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let bytes = extract_bytes(image, volume, apfs_path)?;
            std::fs::write(dest, bytes)?;
        }
    }
    Ok(())
}

fn extract_bytes(image: &Path, volume: &str, apfs_path: &str) -> Result<Vec<u8>, ExplorerError> {
    let mut img = open_image(image)?;
    let infos = collect_volumes(&mut img)?;
    let chosen = infos
        .iter()
        .find(|v| v.name == volume)
        .cloned()
        .ok_or_else(|| ExplorerError::Apfs(format!("no volume named {volume}")))?;
    img.active = chosen.container_index;
    let block_size = img.block_size();
    let block_count = img.block_count();
    let mut blocks = ImageBlocks { image: &mut img };
    let mut apfs = ApfsContainer::mount(&mut blocks, block_size, block_count)?;
    let vol = apfs.open_volume_chosen(&VolumeChoice::Named(volume.to_string()))?;
    let mut bytes = Vec::new();
    apfs.extract(&vol, apfs_path, 0, None, &mut bytes)?;
    Ok(bytes)
}

fn safe_name(name: &str) -> Result<String, ExplorerError> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        return Err(ExplorerError::Format(format!("unsafe name {name:?}")));
    }
    Ok(name.to_string())
}

fn parent_of(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some(("", _)) | None => "/",
        Some(("/", _)) => "/",
        Some((parent, _)) => parent,
    }
}

fn name_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

pub fn insert_host_path(
    image: &Path,
    volume: &str,
    cwd: &str,
    host: &Path,
) -> Result<String, ExplorerError> {
    let meta = std::fs::symlink_metadata(host)?;
    if meta.file_type().is_dir() {
        let mut n = 0u32;
        for entry in std::fs::read_dir(host)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                insert_regular(image, volume, cwd, &entry.path())?;
                n += 1;
            }
        }
        return Ok(format!("inserted {n} files from {}", host.display()));
    }
    insert_regular(image, volume, cwd, host)
}

fn insert_regular(
    image: &Path,
    volume: &str,
    cwd: &str,
    host: &Path,
) -> Result<String, ExplorerError> {
    let name = host
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| ExplorerError::Format("host path has no file name".into()))?;
    let data = std::fs::read(host)?;
    let mut img = open_image(image)?;
    if img.kind == BackendKind::Dmg {
        return Err(ExplorerError::Format(
            "cannot insert into a UDIF/DMG; use a raw or qcow2 image".into(),
        ));
    }
    let infos = collect_volumes(&mut img)?;
    let chosen = infos
        .iter()
        .find(|v| v.name == volume)
        .cloned()
        .ok_or_else(|| ExplorerError::Apfs(format!("no volume named {volume}")))?;
    if chosen.sealed || chosen.encrypted {
        return Err(ExplorerError::Format(format!(
            "volume {} is sealed or encrypted and cannot be inserted into",
            chosen.name
        )));
    }
    img.active = chosen.container_index;
    let block_size = img.block_size();
    let block_count = img.block_count();
    let parent_id;
    let fs_tree_paddr;
    let apsb_paddr;
    {
        let mut blocks = ImageBlocks { image: &mut img };
        let mut apfs = ApfsContainer::mount(&mut blocks, block_size, block_count)?;
        let vol = apfs.open_volume_chosen(&VolumeChoice::Named(volume.to_string()))?;
        fs_tree_paddr = vol.fs_tree_paddr();
        apsb_paddr = vol.apsb_paddr();
        parent_id = if cwd == "/" {
            2
        } else {
            apfs.resolve(&vol, cwd)?.0
        };
    }
    struct Rw<'a> {
        img: &'a mut OpenImage,
    }
    impl crate::apfs_mutate::BlockRw for Rw<'_> {
        fn read_block(&mut self, index: u64, into: &mut [u8]) -> Result<(), String> {
            self.img
                .read_container_block(index, into)
                .map_err(|e| e.to_string())
        }
        fn write_block(&mut self, index: u64, data: &[u8]) -> Result<(), String> {
            self.img
                .write_container_block(index, data)
                .map_err(|e| e.to_string())
        }
    }
    crate::apfs_mutate::insert_regular_file(
        &mut Rw { img: &mut img },
        block_size,
        block_count,
        fs_tree_paddr,
        apsb_paddr,
        parent_id,
        name,
        &data,
    )
    .map_err(ExplorerError::Format)?;
    Ok(format!("inserted {name} ({} bytes)", data.len()))
}

pub fn preview_entry(
    path: &Path,
    volume_name: &str,
    cwd: &str,
    entry: &ListedEntry,
) -> Result<String, ExplorerError> {
    let child = join_path(cwd, &entry.name);
    let mut image = open_image(path)?;
    let infos = collect_volumes(&mut image)?;
    let Some(chosen) = infos.iter().find(|vol| vol.name == volume_name).cloned() else {
        return Err(ExplorerError::Apfs(format!(
            "no volume named {volume_name}"
        )));
    };
    image.active = chosen.container_index;
    let block_size = image.block_size();
    let block_count = image.block_count();
    let mut blocks = ImageBlocks { image: &mut image };
    let mut apfs = ApfsContainer::mount(&mut blocks, block_size, block_count)?;
    let vol = apfs.open_volume_chosen(&VolumeChoice::Named(chosen.name))?;
    match entry.kind {
        EntryKind::Symlink => {
            let target = apfs.read_symlink(&vol, &child)?;
            Ok(format!("symlink -> {target}"))
        }
        EntryKind::Directory => Ok("directory".into()),
        EntryKind::File | EntryKind::Other => {
            let mut bytes = Vec::new();
            apfs.extract(&vol, &child, 0, Some(4096), &mut bytes)?;
            if bytes
                .iter()
                .all(|b| *b >= 32 || *b == b'\n' || *b == b'\t' || *b == b'\r')
            {
                Ok(String::from_utf8_lossy(&bytes).into_owned())
            } else {
                Ok(format!("{} bytes", bytes.len()))
            }
        }
    }
}

pub fn dump_image(path: &Path) -> Result<String, ExplorerError> {
    let mut image = open_image(path)?;
    let backend = image.kind;
    let infos = collect_volumes(&mut image)?;
    let mut out = String::new();
    out.push_str(&format!("backend={}\n", backend.as_str()));
    if infos.is_empty() {
        out.push_str("volume=\n");
        return Ok(out);
    }
    for (index, vol) in infos.iter().enumerate() {
        out.push_str(&format!("volume[{index}]={}\n", vol.name));
        out.push_str(&format!("bootable[{index}]={}\n", vol.bootable));
    }
    let picker: Vec<&str> = infos
        .iter()
        .filter(|vol| vol.bootable)
        .map(|vol| vol.name.as_str())
        .collect();
    out.push_str(&format!("picker={}\n", picker.join(",")));
    let chosen = infos[0].clone();
    image.active = chosen.container_index;
    let block_size = image.block_size();
    let block_count = image.block_count();
    let mut blocks = ImageBlocks { image: &mut image };
    let mut apfs = ApfsContainer::mount(&mut blocks, block_size, block_count)?;
    dump_tree(&mut apfs, &chosen.name, "/", &mut out)?;
    Ok(out)
}

fn dump_tree(
    apfs: &mut ApfsContainer<'_>,
    volume_name: &str,
    cwd: &str,
    out: &mut String,
) -> Result<(), ExplorerError> {
    let entries = list_entries(apfs, volume_name, cwd)?;
    let vol = apfs.open_volume_chosen(&VolumeChoice::Named(volume_name.to_string()))?;
    for entry in &entries {
        let child = join_path(cwd, &entry.name);
        match entry.kind {
            EntryKind::Directory => {
                out.push_str(&format!("entry: {child}  kind=directory\n"));
            }
            EntryKind::File => {
                let size = entry.size.unwrap_or(0);
                out.push_str(&format!("entry: {child}  kind=file  size={size}\n"));
                let mut bytes = Vec::new();
                apfs.extract(&vol, &child, 0, None, &mut bytes)?;
                if bytes
                    .iter()
                    .all(|b| *b >= 32 || *b == b'\n' || *b == b'\t' || *b == b'\r')
                {
                    out.push_str(&format!("contents: {}\n", String::from_utf8_lossy(&bytes)));
                } else {
                    out.push_str(&format!(
                        "contents-hex: {}\n",
                        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
                    ));
                }
            }
            EntryKind::Symlink => {
                let target = entry
                    .symlink_target
                    .clone()
                    .unwrap_or_else(|| apfs.read_symlink(&vol, &child).unwrap_or_default());
                out.push_str(&format!("entry: {child}  kind=symlink  target={target}\n"));
            }
            EntryKind::Other => {
                out.push_str(&format!("entry: {child}  kind=other\n"));
            }
        }
    }
    for entry in &entries {
        if entry.kind == EntryKind::Directory {
            dump_tree(apfs, volume_name, &join_path(cwd, &entry.name), out)?;
        }
    }
    Ok(())
}

pub fn picker_volumes(view: &ExplorerView) -> Vec<&VolumeInfo> {
    view.volumes
        .iter()
        .filter(|volume| volume.bootable)
        .collect()
}

pub fn select_boot_volume<'a>(
    picker: &'a [VolumeInfo],
    blessed_vgid: Option<&[u8; 16]>,
    override_vgid: Option<&[u8; 16]>,
) -> Result<&'a VolumeInfo, ExplorerError> {
    let wanted = match override_vgid {
        Some(id) => id,
        None => match blessed_vgid {
            Some(id) => id,
            None => {
                return Err(ExplorerError::Apfs("Direct boot refused: no bless".into()));
            }
        },
    };
    picker
        .iter()
        .find(|volume| volume.bootable && &volume.volume_group_id == wanted)
        .ok_or_else(|| ExplorerError::Apfs("Direct boot refused: volume not picker-visible".into()))
}

struct Qcow2File {
    path: std::path::PathBuf,
    file: File,
    version: u32,
    virtual_size: u64,
    cluster: u64,
    l1: Vec<u64>,
}

impl Qcow2File {
    fn open(path: &Path) -> Result<Self, ExplorerError> {
        let mut file = File::open(path)?;
        let mut header = [0u8; 104];
        file.read_exact(&mut header[..72])?;
        let magic = u32::from_be_bytes(header[0..4].try_into().unwrap());
        if magic != QCOW_MAGIC {
            return Err(ExplorerError::Format("not a qcow2 image".into()));
        }
        let version = u32::from_be_bytes(header[4..8].try_into().unwrap());
        if version != 2 && version != 3 {
            return Err(ExplorerError::Format(format!(
                "unsupported qcow2 version {version}"
            )));
        }
        if version == 3 {
            file.read_exact(&mut header[72..104])?;
        }
        let cluster_bits = u32::from_be_bytes(header[20..24].try_into().unwrap());
        if !(9..=21).contains(&cluster_bits) {
            return Err(ExplorerError::Format(format!(
                "unsupported qcow2 cluster_bits {cluster_bits}"
            )));
        }
        let virtual_size = u64::from_be_bytes(header[24..32].try_into().unwrap());
        let l1_size = u32::from_be_bytes(header[36..40].try_into().unwrap());
        let l1_offset = u64::from_be_bytes(header[40..48].try_into().unwrap());
        let cluster = 1u64 << cluster_bits;
        file.seek(SeekFrom::Start(l1_offset))?;
        let mut raw = vec![0u8; l1_size as usize * 8];
        file.read_exact(&mut raw)?;
        let l1 = raw
            .chunks_exact(8)
            .map(|c| u64::from_be_bytes(c.try_into().unwrap()) & !QCOW_COPIED)
            .collect();
        Ok(Self {
            path: path.to_path_buf(),
            file,
            version,
            virtual_size,
            cluster,
            l1,
        })
    }

    fn lookup_host(&mut self, guest: u64) -> Result<u64, ExplorerError> {
        let l2_entries = self.cluster / 8;
        let l1_idx = (guest / l2_entries) as usize;
        let l2_idx = guest % l2_entries;
        let Some(&l2_off) = self.l1.get(l1_idx) else {
            return Ok(0);
        };
        if l2_off == 0 {
            return Ok(0);
        }
        self.file.seek(SeekFrom::Start(l2_off + l2_idx * 8))?;
        let mut e = [0u8; 8];
        self.file.read_exact(&mut e)?;
        let entry = u64::from_be_bytes(e);
        if entry & QCOW_COMPRESSED != 0 {
            return Err(ExplorerError::Format(
                "compressed qcow2 clusters are not used by this reader".into(),
            ));
        }
        Ok(entry & !QCOW_COPIED)
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ExplorerError> {
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            if pos >= self.virtual_size {
                buf[done..].fill(0);
                break;
            }
            let guest = pos / self.cluster;
            let within = (pos % self.cluster) as usize;
            let take = (self.cluster as usize - within).min(buf.len() - done);
            let host = self.lookup_host(guest)?;
            if host == 0 {
                buf[done..done + take].fill(0);
            } else {
                self.file.seek(SeekFrom::Start(host + within as u64))?;
                self.file.read_exact(&mut buf[done..done + take])?;
            }
            done += take;
        }
        Ok(())
    }
}

struct UdifRun {
    kind: u32,
    sector_start: u64,
    sector_count: u64,
    comp_offset: u64,
    comp_length: u64,
}

struct UdifFile {
    file: File,
    runs: Vec<UdifRun>,
    data_fork_offset: u64,
    decoded_run: Option<(u64, Vec<u8>)>,
}

impl UdifFile {
    fn open(path: &Path, koly: &[u8]) -> Result<Self, ExplorerError> {
        if koly.len() < 512 || koly[0..4] != *KOLY {
            return Err(ExplorerError::Format("missing UDIF koly trailer".into()));
        }
        let data_fork_offset = u64::from_be_bytes(koly[24..32].try_into().unwrap());
        let xml_offset = u64::from_be_bytes(koly[216..224].try_into().unwrap());
        let xml_length = u64::from_be_bytes(koly[224..232].try_into().unwrap());
        if xml_length == 0 || xml_length > 8 * 1024 * 1024 {
            return Err(ExplorerError::Format(
                "UDIF XML resource fork is unusable".into(),
            ));
        }
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(xml_offset))?;
        let mut xml = vec![0u8; xml_length as usize];
        file.read_exact(&mut xml)?;
        let mish = extract_blkx_mish(&xml)?;
        let mut runs = Vec::new();
        for table in mish {
            runs.extend(decode_mish_runs(&table)?);
        }
        runs.sort_by_key(|run| run.sector_start);
        for pair in runs.windows(2) {
            if pair[0].sector_start + pair[0].sector_count > pair[1].sector_start {
                return Err(ExplorerError::Format("UDIF block tables overlap".into()));
            }
        }
        let file_length = file.metadata()?.len();
        for run in &runs {
            if matches!(run.kind, UDIF_ZERO | UDIF_IGNORE) {
                continue;
            }
            if data_fork_offset
                .checked_add(run.comp_offset)
                .and_then(|offset| offset.checked_add(run.comp_length))
                .is_none_or(|end| end > file_length)
            {
                return Err(ExplorerError::Format(
                    "UDIF run extends beyond the image".into(),
                ));
            }
        }
        Ok(Self {
            file,
            runs,
            data_fork_offset,
            decoded_run: None,
        })
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ExplorerError> {
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let sector = pos / SECTOR_BYTES as u64;
            let within = (pos % SECTOR_BYTES as u64) as usize;
            let Some(run) = self
                .runs
                .iter()
                .find(|r| sector >= r.sector_start && sector < r.sector_start + r.sector_count)
                .cloned()
            else {
                let take = (SECTOR_BYTES - within).min(buf.len() - done);
                buf[done..done + take].fill(0);
                done += take;
                continue;
            };
            let take = (SECTOR_BYTES - within).min(buf.len() - done);
            match run.kind {
                UDIF_ZERO | UDIF_IGNORE => {
                    buf[done..done + take].fill(0);
                }
                UDIF_RAW => {
                    let sector_off = sector - run.sector_start;
                    let at = self.data_fork_offset
                        + run.comp_offset
                        + sector_off * SECTOR_BYTES as u64
                        + within as u64;
                    self.file.seek(SeekFrom::Start(at))?;
                    self.file.read_exact(&mut buf[done..done + take])?;
                }
                UDIF_ZLIB => {
                    if self
                        .decoded_run
                        .as_ref()
                        .is_none_or(|(start, _)| *start != run.sector_start)
                    {
                        self.decoded_run = Some((run.sector_start, self.read_zlib_run(&run)?));
                    }
                    let decoded = &self.decoded_run.as_ref().unwrap().1;
                    let at = (sector - run.sector_start) as usize * SECTOR_BYTES + within;
                    buf[done..done + take].copy_from_slice(&decoded[at..at + take]);
                }
                UDIF_TERM => {
                    buf[done..].fill(0);
                    break;
                }
                other => {
                    return Err(ExplorerError::Format(format!(
                        "unsupported UDIF blkx run type {other:#x}"
                    )));
                }
            }
            done += take;
        }
        Ok(())
    }

    fn read_zlib_run(&mut self, run: &UdifRun) -> Result<Vec<u8>, ExplorerError> {
        self.file
            .seek(SeekFrom::Start(self.data_fork_offset + run.comp_offset))?;
        let expected = run
            .sector_count
            .checked_mul(512)
            .filter(|size| *size <= 256 * 1024 * 1024)
            .ok_or_else(|| {
                ExplorerError::Format("UDIF compressed run exceeds decoding limit".into())
            })?;
        if run.comp_length > 256 * 1024 * 1024 {
            return Err(ExplorerError::Format(
                "UDIF compressed input exceeds decoding limit".into(),
            ));
        }
        let mut compressed = vec![0u8; run.comp_length as usize];
        self.file.read_exact(&mut compressed)?;
        let decoder = flate2::read::ZlibDecoder::new(&compressed[..]);
        let mut out = Vec::new();
        decoder
            .take(expected + 1)
            .read_to_end(&mut out)
            .map_err(|e| ExplorerError::Format(format!("UDIF zlib run did not decode: {e}")))?;
        if out.len() as u64 != expected {
            return Err(ExplorerError::Format(
                "UDIF decoded run length does not match its sectors".into(),
            ));
        }
        Ok(out)
    }
}

impl Clone for UdifRun {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind,
            sector_start: self.sector_start,
            sector_count: self.sector_count,
            comp_offset: self.comp_offset,
            comp_length: self.comp_length,
        }
    }
}

fn extract_blkx_mish(xml: &[u8]) -> Result<Vec<Vec<u8>>, ExplorerError> {
    match plist::Value::from_reader_xml(std::io::Cursor::new(xml)) {
        Ok(value) => mish_from_plist(&value),
        Err(_) => mish_from_xml_fallback(xml),
    }
}

fn mish_from_plist(value: &plist::Value) -> Result<Vec<Vec<u8>>, ExplorerError> {
    let dict = value
        .as_dictionary()
        .ok_or_else(|| ExplorerError::Format("UDIF plist is not a dict".into()))?;
    let fork = dict
        .get("resource-fork")
        .and_then(plist::Value::as_dictionary)
        .ok_or_else(|| ExplorerError::Format("UDIF plist has no resource-fork".into()))?;
    let blkx = fork
        .get("blkx")
        .and_then(plist::Value::as_array)
        .ok_or_else(|| ExplorerError::Format("UDIF plist has no blkx array".into()))?;
    let mut tables = Vec::new();
    for entry in blkx {
        if let Some(data) = entry
            .as_dictionary()
            .and_then(|d| d.get("Data"))
            .and_then(plist::Value::as_data)
            && data.starts_with(MISH)
        {
            tables.push(data.to_vec());
        }
    }
    if tables.is_empty() {
        return Err(ExplorerError::Format(
            "UDIF plist blkx entries carry no mish table".into(),
        ));
    }
    Ok(tables)
}

fn mish_from_xml_fallback(xml: &[u8]) -> Result<Vec<Vec<u8>>, ExplorerError> {
    let text = String::from_utf8_lossy(xml);
    let mut remaining = text.as_ref();
    let mut tables = Vec::new();
    while let Some(start) = remaining.find("<data>") {
        remaining = &remaining[start + 6..];
        let end = remaining
            .find("</data>")
            .ok_or_else(|| ExplorerError::Format("UDIF XML <data> is unclosed".into()))?;
        let b64: String = remaining[..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let decoded = base64_decode(&b64)?;
        if decoded.starts_with(MISH) {
            tables.push(decoded);
        }
        remaining = &remaining[end + 7..];
    }
    if tables.is_empty() {
        return Err(ExplorerError::Format(
            "UDIF XML carries no mish table".into(),
        ));
    }
    Ok(tables)
}

fn decode_mish_runs(mish: &[u8]) -> Result<Vec<UdifRun>, ExplorerError> {
    if mish.len() < 204 || mish[0..4] != *MISH {
        return Err(ExplorerError::Format(
            "blkx table is shorter than a mish header".into(),
        ));
    }
    let count = u32::from_be_bytes(mish[200..204].try_into().unwrap()) as usize;
    let need = count
        .checked_mul(40)
        .and_then(|n| n.checked_add(204))
        .ok_or_else(|| ExplorerError::Format("UDIF run count overflows".into()))?;
    let first_sector = u64::from_be_bytes(mish[8..16].try_into().unwrap());
    let table_sectors = u64::from_be_bytes(mish[16..24].try_into().unwrap());
    let data_offset = u64::from_be_bytes(mish[24..32].try_into().unwrap());
    if mish.len() < need {
        return Err(ExplorerError::Format(
            "blkx table is shorter than its run count".into(),
        ));
    }
    let mut runs = Vec::with_capacity(count);
    for i in 0..count {
        let at = 204 + i * 40;
        let kind = u32::from_be_bytes(mish[at..at + 4].try_into().unwrap());
        if kind == UDIF_TERM {
            break;
        }
        if kind == 0x7fff_fffe {
            continue;
        }
        let relative_sector = u64::from_be_bytes(mish[at + 8..at + 16].try_into().unwrap());
        let sector_count = u64::from_be_bytes(mish[at + 16..at + 24].try_into().unwrap());
        let relative_offset = u64::from_be_bytes(mish[at + 24..at + 32].try_into().unwrap());
        let comp_length = u64::from_be_bytes(mish[at + 32..at + 40].try_into().unwrap());
        let invalid =
            || ExplorerError::Format("UDIF run exceeds its table or address space".into());
        let end = relative_sector
            .checked_add(sector_count)
            .ok_or_else(invalid)?;
        if end > table_sectors {
            return Err(invalid());
        }
        first_sector
            .checked_add(end)
            .and_then(|end| end.checked_mul(512))
            .ok_or_else(invalid)?;
        let sector_start = first_sector
            .checked_add(relative_sector)
            .ok_or_else(invalid)?;
        let comp_offset = data_offset
            .checked_add(relative_offset)
            .ok_or_else(invalid)?;
        comp_offset.checked_add(comp_length).ok_or_else(invalid)?;
        if kind == UDIF_RAW && comp_length != sector_count.checked_mul(512).ok_or_else(invalid)? {
            return Err(ExplorerError::Format(
                "UDIF raw run length does not match its sectors".into(),
            ));
        }
        if sector_count != 0 {
            runs.push(UdifRun {
                kind,
                sector_start,
                sector_count,
                comp_offset,
                comp_length,
            });
        }
    }
    Ok(runs)
}

fn base64_decode(text: &str) -> Result<Vec<u8>, ExplorerError> {
    fn val(c: u8) -> Result<u8, ExplorerError> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(ExplorerError::Format("invalid base64 in UDIF plist".into())),
        }
    }
    let bytes: Vec<u8> = text.bytes().filter(|b| *b != b'=').collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let a = val(bytes[i])? as u32;
        let b = if i + 1 < bytes.len() {
            val(bytes[i + 1])? as u32
        } else {
            0
        };
        let c = if i + 2 < bytes.len() {
            val(bytes[i + 2])? as u32
        } else {
            0
        };
        let d = if i + 3 < bytes.len() {
            val(bytes[i + 3])? as u32
        } else {
            0
        };
        let n = (a << 18) | (b << 12) | (c << 6) | d;
        out.push((n >> 16) as u8);
        if i + 2 < bytes.len() {
            out.push((n >> 8) as u8);
        }
        if i + 3 < bytes.len() {
            out.push(n as u8);
        }
        i += 4;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apfs_fixture::{
        self, FIXTURE_DIR, FIXTURE_FILE, FIXTURE_FILE_BYTES, FIXTURE_NESTED, FIXTURE_SYMLINK,
        FIXTURE_SYMLINK_TARGET, FIXTURE_VOLUME, ImageWrap,
    };
    use crate::apfs_image::NX_MAGIC;
    use std::io::Write;

    fn udif_table(first: u64, data: u64) -> Vec<u8> {
        let mut bytes = vec![0; 244];
        bytes[..4].copy_from_slice(MISH);
        bytes[8..16].copy_from_slice(&first.to_be_bytes());
        bytes[16..24].copy_from_slice(&1u64.to_be_bytes());
        bytes[24..32].copy_from_slice(&data.to_be_bytes());
        bytes[200..204].copy_from_slice(&1u32.to_be_bytes());
        bytes[204..208].copy_from_slice(&UDIF_RAW.to_be_bytes());
        bytes[220..228].copy_from_slice(&1u64.to_be_bytes());
        bytes[236..244].copy_from_slice(&512u64.to_be_bytes());
        bytes
    }

    #[test]
    fn udif_multiple_tables_offsets_and_gaps() {
        let tables = [udif_table(0, 0), udif_table(2, 512)];
        let entries = tables
            .iter()
            .map(|table| {
                let mut entry = plist::Dictionary::new();
                entry.insert("Data".into(), plist::Value::Data(table.clone()));
                plist::Value::Dictionary(entry)
            })
            .collect();
        let mut fork = plist::Dictionary::new();
        fork.insert("blkx".into(), plist::Value::Array(entries));
        let mut root = plist::Dictionary::new();
        root.insert("resource-fork".into(), plist::Value::Dictionary(fork));
        let mut xml = Vec::new();
        plist::Value::Dictionary(root)
            .to_writer_xml(&mut xml)
            .unwrap();
        let mut trailer = [0; 512];
        trailer[..4].copy_from_slice(KOLY);
        trailer[24..32].copy_from_slice(&16u64.to_be_bytes());
        trailer[216..224].copy_from_slice(&1040u64.to_be_bytes());
        trailer[224..232].copy_from_slice(&(xml.len() as u64).to_be_bytes());
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&[0; 16]).unwrap();
        file.write_all(&[0x11; 512]).unwrap();
        file.write_all(&[0x22; 512]).unwrap();
        file.write_all(&xml).unwrap();
        file.write_all(&trailer).unwrap();
        let mut disk = UdifFile::open(file.path(), &trailer).unwrap();
        let mut output = [0xff; 1536];
        disk.read_at(0, &mut output).unwrap();
        assert_eq!(&output[..512], &[0x11; 512]);
        assert_eq!(&output[512..1024], &[0; 512]);
        assert_eq!(&output[1024..], &[0x22; 512]);
    }

    #[test]
    fn udif_zlib_reuses_exact_decoded_run() {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&[0x45; 1024]).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&compressed).unwrap();
        let run = UdifRun {
            kind: UDIF_ZLIB,
            sector_start: 0,
            sector_count: 2,
            comp_offset: 0,
            comp_length: compressed.len() as u64,
        };
        let mut disk = UdifFile {
            file: File::open(file.path()).unwrap(),
            runs: vec![run.clone()],
            data_fork_offset: 0,
            decoded_run: None,
        };
        let mut output = [0; 512];
        disk.read_at(0, &mut output).unwrap();
        assert_eq!(output, [0x45; 512]);
        file.as_file().set_len(0).unwrap();
        disk.read_at(512, &mut output).unwrap();
        assert_eq!(output, [0x45; 512]);
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&compressed).unwrap();
        let short = UdifRun {
            sector_count: 1,
            ..run
        };
        assert!(disk.read_zlib_run(&short).is_err());
    }

    #[test]
    fn udif_rejects_out_of_table_and_overflowing_runs() {
        let mut table = udif_table(0, 0);
        table[220..228].copy_from_slice(&2u64.to_be_bytes());
        assert!(decode_mish_runs(&table).is_err());
        assert!(decode_mish_runs(&udif_table(u64::MAX, 0)).is_err());
        assert!(decode_mish_runs(&udif_table(0, u64::MAX)).is_err());
    }

    fn assert_dump_walks_fixture(dump: &str, backend: &str) {
        assert!(dump.contains(&format!("backend={backend}")), "{dump}");
        assert!(
            dump.contains(&format!("volume[0]={FIXTURE_VOLUME}")),
            "{dump}"
        );
        assert!(dump.contains("bootable[0]=false"), "{dump}");
        assert!(
            dump.lines().any(|line| line == "picker="),
            "empty picker line missing in {dump}"
        );
        assert!(
            dump.contains(&format!("entry: /{FIXTURE_DIR}  kind=directory")),
            "{dump}"
        );
        assert!(
            dump.contains(&format!(
                "entry: /{FIXTURE_DIR}/{FIXTURE_NESTED}  kind=directory"
            )),
            "{dump}"
        );
        assert!(
            dump.contains(&format!("entry: /{FIXTURE_DIR}/{FIXTURE_FILE}  kind=file")),
            "{dump}"
        );
        assert!(
            dump.contains(&format!(
                "contents: {}",
                std::str::from_utf8(FIXTURE_FILE_BYTES).unwrap()
            )),
            "{dump}"
        );
        assert!(
            dump.contains(&format!(
                "entry: /{FIXTURE_DIR}/{FIXTURE_SYMLINK}  kind=symlink  target={FIXTURE_SYMLINK_TARGET}"
            )),
            "{dump}"
        );
    }

    #[test]
    fn gpt_qcow2_and_dmg_wraps_yield_the_same_walk() {
        let dir = tempfile::tempdir().unwrap();
        let gpt = dir.path().join("disk.img");
        let qcow = dir.path().join("disk.qcow2");
        let dmg = dir.path().join("disk.dmg");
        apfs_fixture::write_fixture(&gpt, ImageWrap::RawGpt).expect("gpt");
        apfs_fixture::write_fixture(&qcow, ImageWrap::Qcow2).expect("qcow2");
        apfs_fixture::write_fixture(&dmg, ImageWrap::Dmg).expect("dmg");

        let gpt_bytes = std::fs::read(&gpt).unwrap();
        assert_ne!(&gpt_bytes[0x20..0x24], &NX_MAGIC.to_le_bytes());

        let qcow_bytes = std::fs::read(&qcow).unwrap();
        assert_eq!(&qcow_bytes[0..4], &QCOW_MAGIC.to_be_bytes());
        assert_eq!(&qcow_bytes[4..8], &3u32.to_be_bytes());

        let dmg_bytes = std::fs::read(&dmg).unwrap();
        assert_ne!(&dmg_bytes[0x20..0x24], &NX_MAGIC.to_le_bytes());
        assert_eq!(
            &dmg_bytes[dmg_bytes.len() - 512..dmg_bytes.len() - 508],
            b"koly"
        );

        let gpt_dump = dump_image(&gpt).expect("dump gpt");
        let qcow_dump = dump_image(&qcow).expect("dump qcow2");
        let dmg_dump = dump_image(&dmg).expect("dump dmg");
        assert_dump_walks_fixture(&gpt_dump, "gpt");
        assert_dump_walks_fixture(&qcow_dump, "qcow2");
        assert_dump_walks_fixture(&dmg_dump, "dmg");

        let view = load_view(&gpt, "/", 0).expect("view");
        assert_eq!(view.volume_name(), FIXTURE_VOLUME);
        assert!(!view.volumes[0].bootable);
        assert!(picker_volumes(&view).is_empty());
        assert!(
            view.entries
                .iter()
                .any(|e| e.name == FIXTURE_DIR && e.kind == EntryKind::Directory)
        );
    }

    #[test]
    fn browse_view_names_sidebar_volumes_and_file_entries() {
        let dir = tempfile::tempdir().unwrap();
        let gpt = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&gpt, ImageWrap::RawGpt).unwrap();
        let view = load_view(&gpt, &format!("/{FIXTURE_DIR}"), 0).expect("docs listing");
        let names: Vec<&str> = view.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&FIXTURE_FILE));
        assert!(names.contains(&FIXTURE_SYMLINK));
        assert!(names.contains(&FIXTURE_NESTED));
        let link = view
            .entries
            .iter()
            .find(|e| e.name == FIXTURE_SYMLINK)
            .unwrap();
        assert_eq!(link.kind, EntryKind::Symlink);
        assert_eq!(link.symlink_target.as_deref(), Some(FIXTURE_SYMLINK_TARGET));
    }

    #[test]
    fn restore_ramdisk_qcow2_lists_iscpreboot_files_when_present() {
        let Ok(source) = std::env::var("APPLEUTILS_RAMDISK_QCOW2") else {
            return;
        };
        let path = std::path::Path::new(&source);
        if !path.exists() {
            return;
        }
        let view = load_view(path, "/", 0).expect("open ramdisk qcow2");
        let names: Vec<&str> = view.volumes.iter().map(|v| v.name.as_str()).collect();
        let idx = view
            .volumes
            .iter()
            .position(|v| v.name == "iSCPreboot")
            .unwrap_or(0);
        let view = load_view(path, "/", idx).expect("iSCPreboot");
        let entries: Vec<&str> = view.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(
            entries.contains(&"WiFi") || entries.contains(&"SFR"),
            "volumes={names:?} root={entries:?}"
        );
    }

    fn fake_volume(name: &str, bootable: bool, vgid: u8) -> VolumeInfo {
        VolumeInfo {
            name: name.into(),
            role: if bootable {
                "System".into()
            } else {
                "Data".into()
            },
            bootable,
            volume_group_id: [vgid; 16],
            ..VolumeInfo::default()
        }
    }

    fn assert_direct_boot_refused(err: ExplorerError, expect: &str) {
        let msg = err.to_string();
        assert!(msg.contains("Direct boot refused"), "{msg}");
        assert!(msg.contains(expect), "{msg}");
        assert!(!msg.contains("EFI"), "{msg}");
        assert!(!msg.contains("first system"), "{msg}");
        assert!(!msg.contains("using EFI"), "{msg}");
    }

    #[test]
    fn empty_direct_boot_is_refused() {
        let err = select_boot_volume(&[], None, None).unwrap_err();
        assert_direct_boot_refused(err, "no bless");
    }

    #[test]
    fn two_picker_volumes_without_bless_or_override_are_refused() {
        let volumes = [
            fake_volume("First", true, 1),
            fake_volume("Second", true, 2),
        ];
        let err = select_boot_volume(&volumes, None, None).unwrap_err();
        assert_direct_boot_refused(err, "no bless");
    }

    #[test]
    fn bless_selects_the_matching_picker_volume_not_the_first() {
        let volumes = [
            fake_volume("First", true, 1),
            fake_volume("Second", true, 2),
        ];
        let blessed = volumes[1].volume_group_id;
        let chosen = select_boot_volume(&volumes, Some(&blessed), None).expect("blessed");
        assert_eq!(chosen.name, "Second");
        assert_eq!(chosen.volume_group_id, [2u8; 16]);
    }

    #[test]
    fn override_vgid_beats_bless() {
        let volumes = [
            fake_volume("First", true, 1),
            fake_volume("Second", true, 2),
        ];
        let blessed = volumes[0].volume_group_id;
        let over = volumes[1].volume_group_id;
        let chosen = select_boot_volume(&volumes, Some(&blessed), Some(&over)).expect("override");
        assert_eq!(chosen.name, "Second");
    }

    #[test]
    fn non_bootable_volume_is_never_selected_even_when_vgid_matches_bless() {
        let volumes = [
            fake_volume("Data", false, 1),
            fake_volume("System", true, 2),
        ];
        let blessed = volumes[0].volume_group_id;
        let err = select_boot_volume(&volumes, Some(&blessed), None).unwrap_err();
        assert_direct_boot_refused(err, "not picker-visible");
    }

    #[test]
    fn asahi_stub_system_volume_is_picker_visible() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asahi.qcow2");
        let mut arts = crate::asahi_ops::Artifacts::memory(
            b"KERN-exp".to_vec(),
            b"M1N1-exp".to_vec(),
            [b"ROOT-exp".as_slice(), &[0u8; 64]].concat(),
        );
        arts.m1n1_stage1 = vec![0u8; 2048];
        arts.m1n1_stage1[..12].copy_from_slice(b"##m1n1_ver##");
        crate::asahi_ops::create_qcow2_disc(
            &path,
            &arts,
            8 * 1024 * 1024,
            "m1n1/boot.bin",
            "Asahi Linux",
        )
        .expect("create asahi qcow2");
        let view = load_view(&path, "/", 0).expect("load asahi");
        let system = view
            .volumes
            .iter()
            .find(|volume| volume.role == "System")
            .expect("System volume");
        assert!(
            system.bootable,
            "System volume must be picker-visible: {system:?}"
        );
        assert_eq!(system.name, "Asahi Linux");
        for volume in &view.volumes {
            if volume.role != "System" {
                assert!(
                    !volume.bootable,
                    "{} role={} must not be picker-visible",
                    volume.name, volume.role
                );
            }
        }
        let picker = picker_volumes(&view);
        assert_eq!(picker.len(), 1);
        assert_eq!(picker[0].name, "Asahi Linux");
        let dump = dump_image(&path).expect("dump asahi");
        assert!(dump.contains("picker=Asahi Linux"), "{dump}");
        let boot = extract_bytes(
            &path,
            &system.name,
            "/Finish Installation.app/Contents/Resources/boot.bin",
        )
        .expect("custom boot object on System volume");
        assert!(boot.starts_with(&arts.m1n1_stage1));
        let version = extract_bytes(
            &path,
            &system.name,
            "/System/Library/CoreServices/SystemVersion.plist",
        )
        .expect("system version plist");
        let metadata = plist::Value::from_reader(std::io::Cursor::new(version)).unwrap();
        assert_eq!(
            metadata
                .as_dictionary()
                .unwrap()
                .get("ProductName")
                .and_then(plist::Value::as_string),
            Some("Asahi Linux")
        );
        assert!(
            dump.contains("volume[") && dump.contains("Preboot") && dump.contains("Recovery"),
            "dump must still list every volume, not only bootable ones: {dump}"
        );
    }

    #[test]
    fn export_then_insert_round_trips_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        crate::apfs_fixture::write_fixture(&image, crate::apfs_fixture::ImageWrap::RawGpt).unwrap();
        let exported = dir.path().join("out");
        std::fs::create_dir_all(&exported).unwrap();
        let dest = export_entry(
            &image,
            crate::apfs_fixture::FIXTURE_VOLUME,
            &format!(
                "/{}/{}",
                crate::apfs_fixture::FIXTURE_DIR,
                crate::apfs_fixture::FIXTURE_FILE
            ),
            &exported,
        )
        .expect("export");
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            crate::apfs_fixture::FIXTURE_FILE_BYTES
        );

        let incoming = dir.path().join("fresh.txt");
        std::fs::write(&incoming, b"inserted-bytes").unwrap();
        insert_host_path(
            &image,
            crate::apfs_fixture::FIXTURE_VOLUME,
            &format!("/{}", crate::apfs_fixture::FIXTURE_DIR),
            &incoming,
        )
        .expect("insert");
        let listed = load_view(&image, &format!("/{}", crate::apfs_fixture::FIXTURE_DIR), 0)
            .expect("relist");
        assert!(
            listed.entries.iter().any(|e| e.name == "fresh.txt"),
            "{:?}",
            listed.entries
        );
        let bytes = extract_bytes(
            &image,
            crate::apfs_fixture::FIXTURE_VOLUME,
            &format!("/{}/fresh.txt", crate::apfs_fixture::FIXTURE_DIR),
        )
        .expect("read back");
        assert_eq!(bytes, b"inserted-bytes");
    }
}

#[cfg(test)]
mod scoped_extraction_tests {
    use super::*;
    #[test]
    fn unique_volume_selection_requires_every_requested_path() {
        use crate::apfs_fixture::*;
        let root = tempfile::tempdir().unwrap();
        let image = root.path().join("source.img");
        write_fixture(&image, ImageWrap::RawGpt).unwrap();
        let paths = vec![
            format!("/{FIXTURE_DIR}/{FIXTURE_FILE}"),
            format!("/{FIXTURE_DIR}/{FIXTURE_NESTED}"),
        ];
        let out = extract_paths_from_unique_volume(&image, &paths).unwrap();
        assert_eq!(
            std::fs::read(out.path().join(FIXTURE_DIR).join(FIXTURE_FILE)).unwrap(),
            FIXTURE_FILE_BYTES
        );
        assert!(
            extract_paths_from_unique_volume(&image, &[paths[0].clone(), "/missing".into()])
                .is_err()
        );
    }
    #[test]
    fn multiple_paths_export_from_portable_images_without_mutating_input() {
        use crate::apfs_fixture::*;
        let root = tempfile::tempdir().unwrap();
        for (name, wrap) in [
            ("raw", ImageWrap::RawGpt),
            ("qcow", ImageWrap::Qcow2),
            ("dmg", ImageWrap::Dmg),
        ] {
            let image = root.path().join(name);
            write_fixture(&image, wrap).unwrap();
            let before = std::fs::read(&image).unwrap();
            let output = extract_selected_paths(
                &image,
                FIXTURE_VOLUME,
                &[
                    format!("/{FIXTURE_DIR}"),
                    format!("/{FIXTURE_DIR}/{FIXTURE_FILE}"),
                ],
            )
            .unwrap();
            assert_eq!(
                std::fs::read(output.path().join(FIXTURE_DIR).join(FIXTURE_FILE)).unwrap(),
                FIXTURE_FILE_BYTES
            );
            assert_eq!(
                std::fs::read(output.path().join(FIXTURE_DIR).join(FIXTURE_SYMLINK)).unwrap(),
                FIXTURE_FILE_BYTES
            );
            assert_eq!(std::fs::read(&image).unwrap(), before);
        }
    }

    #[test]
    fn relative_links_are_preserved_and_escaping_targets_refused() {
        assert_eq!(
            confined_link_target("/usr/share/firmware/link", "../other/blob").unwrap(),
            "/usr/share/other/blob"
        );
        assert!(confined_link_target("/link", "../escape").is_err());
        assert_eq!(
            confined_link_target("/usr/link", "/usr/file").unwrap(),
            "/usr/file"
        );
        assert!(confined_link_target("/usr/link", "").is_err());
    }
    #[test]
    fn invalid_selection_is_refused_before_opening_image() {
        for path in [
            "relative",
            "/",
            "/a/../b",
            "/a//b",
            "/C:/escape",
            "/a/NUL",
            "/a/trailing.",
        ] {
            assert!(matches!(
                extract_selected_paths(
                    Path::new("/nonexistent-test-image"),
                    "System",
                    &[path.into()]
                ),
                Err(ExplorerError::Format(_))
            ));
        }
    }
}
