//! Exports files and `ipsw extract` components from an IPSW, decrypting AEA images and
//! decompressing IM4P payloads when `ipsw` is available. Output is built in a work folder inside
//! the output folder so each placement is a rename and no partial file appears at a final path.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::symlink;
use std::os::unix::process::CommandExt;
use std::path::{Component as PathPart, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::ipsw_catalog::IpswCatalog;
use crate::ipsw_tree::{EntryKind, IpswError, IpswTree, validate_link_target};
use crate::scratch::ScratchDir;

const BUILD_MANIFEST: &str = "BuildManifest.plist";
const MANIFEST_LIMIT: u64 = 64 * 1024 * 1024;
const WORK_PREFIX: &str = ".apple-utils-export-";
const AEA_SUFFIX: &str = ".aea";
const IM4P_SUFFIX: &str = ".im4p";
const CLI_MISSING: &str = "the ipsw command is not available";
const ENCRYPTED_IM4P: &str =
    "the payload is encrypted (it carries keybags), so it was kept as IM4P";
/// A DER tag plus the longest length encoding we accept (0x88 and eight bytes).
const TLV_HEADER_BYTES: u64 = 10;
const MAX_IM4P_PREFIX_ELEMENTS: usize = 16;
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const TERM_GRACE: Duration = Duration::from_secs(2);
const LOG_TAIL: u64 = 64 * 1024;
const SIGNATURE_BYTES: u64 = 16;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpswInfo {
    pub product_version: Option<String>,
    pub build: Option<String>,
    pub product_types: Vec<String>,
    pub catalog: IpswCatalog,
}

pub fn read_info(tree: &IpswTree) -> Result<IpswInfo, IpswError> {
    let bytes = tree.read_entry(BUILD_MANIFEST, MANIFEST_LIMIT)?;
    let value = plist::Value::from_reader(io::Cursor::new(bytes))
        .map_err(|error| IpswError::Corrupt(format!("{BUILD_MANIFEST} is not a plist: {error}")))?;
    let dict = value.as_dictionary().ok_or_else(|| {
        IpswError::Corrupt(format!(
            "{BUILD_MANIFEST} is not a property list dictionary"
        ))
    })?;
    let text = |key: &str| {
        dict.get(key)
            .and_then(plist::Value::as_string)
            .map(str::to_string)
    };
    let product_types = dict
        .get("SupportedProductTypes")
        .and_then(plist::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(plist::Value::as_string)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Ok(IpswInfo {
        product_version: text("ProductVersion"),
        build: text("ProductBuildVersion"),
        product_types,
        catalog: IpswCatalog::from_manifest(dict),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportOptions {
    pub decrypt_aea: bool,
    pub aea_key: Option<String>,
    pub decompress_im4p: bool,
    pub keep_originals: bool,
    pub preserve_paths: bool,
    pub overwrite: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            decrypt_aea: true,
            aea_key: None,
            decompress_im4p: true,
            keep_originals: false,
            preserve_paths: true,
            overwrite: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Component {
    Kernel,
    Dyld,
    DriverKit,
    DeviceTree,
    IBoot,
    Sep,
    Sptm,
    Exclave,
    SystemVersion,
    FcsKeys,
    Keybags,
}

impl Component {
    pub const ALL: [Component; 11] = [
        Self::Kernel,
        Self::Dyld,
        Self::DriverKit,
        Self::DeviceTree,
        Self::IBoot,
        Self::Sep,
        Self::Sptm,
        Self::Exclave,
        Self::SystemVersion,
        Self::FcsKeys,
        Self::Keybags,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Kernel => "Kernelcache",
            Self::Dyld => "dyld_shared_cache",
            Self::DriverKit => "DriverKit dyld cache",
            Self::DeviceTree => "DeviceTree",
            Self::IBoot => "iBoot",
            Self::Sep => "SEP firmware",
            Self::Sptm => "SPTM / TXM",
            Self::Exclave => "Exclave bundle",
            Self::SystemVersion => "SystemVersion",
            Self::FcsKeys => "AEA fcs-keys",
            Self::Keybags => "IM4P keybags",
        }
    }

    /// `ipsw extract` rejects `--device` for every other component.
    pub fn accepts_device(self) -> bool {
        matches!(
            self,
            Self::Kernel | Self::Dyld | Self::DriverKit | Self::FcsKeys
        )
    }

    pub fn flags(self) -> &'static [&'static str] {
        match self {
            Self::Kernel => &["--kernel"],
            Self::Dyld => &["--dyld"],
            Self::DriverKit => &["--dyld", "--driverkit"],
            Self::DeviceTree => &["--dtree"],
            Self::IBoot => &["--iboot"],
            Self::Sep => &["--sep"],
            Self::Sptm => &["--sptm"],
            Self::Exclave => &["--exclave"],
            Self::SystemVersion => &["--sys-ver"],
            Self::FcsKeys => &["--fcs-key"],
            Self::Keybags => &["--kbag"],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportRequest {
    pub files: Vec<String>,
    pub components: Vec<Component>,
    pub device: Option<String>,
    pub output: PathBuf,
    pub options: ExportOptions,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemAction {
    Copy,
    Link,
    Decrypt,
    Decompress,
    Component(Component),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportProgress {
    Started {
        total_items: usize,
        total_bytes: u64,
    },
    Item {
        index: usize,
        name: String,
        action: ItemAction,
    },
    Bytes {
        done: u64,
        total: u64,
    },
    Log(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Written {
        path: PathBuf,
    },
    Linked {
        path: PathBuf,
    },
    Decrypted {
        path: PathBuf,
        original: Option<PathBuf>,
    },
    Decompressed {
        path: PathBuf,
        original: Option<PathBuf>,
    },
    Kept {
        path: PathBuf,
        warning: String,
    },
    Skipped {
        reason: String,
    },
    Produced {
        paths: Vec<PathBuf>,
    },
    Failed {
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemReport {
    pub name: String,
    pub outcome: Outcome,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReportCounts {
    pub written: usize,
    pub linked: usize,
    pub decrypted: usize,
    pub decompressed: usize,
    pub kept: usize,
    pub skipped: usize,
    pub produced: usize,
    pub failed: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportReport {
    pub output: PathBuf,
    pub items: Vec<ItemReport>,
    pub cancelled: bool,
}

impl ExportReport {
    pub fn counts(&self) -> ReportCounts {
        let mut counts = ReportCounts::default();
        for item in &self.items {
            match &item.outcome {
                Outcome::Written { .. } => counts.written += 1,
                Outcome::Linked { .. } => counts.linked += 1,
                Outcome::Decrypted { .. } => counts.decrypted += 1,
                Outcome::Decompressed { .. } => counts.decompressed += 1,
                Outcome::Kept { .. } => counts.kept += 1,
                Outcome::Skipped { .. } => counts.skipped += 1,
                Outcome::Produced { paths } => counts.produced += paths.len(),
                Outcome::Failed { .. } => counts.failed += 1,
            }
        }
        counts
    }
}

pub fn is_aea_name(name: &str) -> bool {
    name.ends_with(AEA_SUFFIX)
}

pub fn looks_like_im4p_name(name: &str) -> bool {
    let base = name.rsplit('/').next().unwrap_or(name);
    base.to_ascii_lowercase().ends_with(IM4P_SUFFIX) || base.starts_with("kernelcache")
}

pub fn sniff_im4p(head: &[u8]) -> bool {
    if head.first() != Some(&0x30) {
        return false;
    }
    let Some(&length_byte) = head.get(1) else {
        return false;
    };
    let tag_at = match length_byte {
        0..=0x7f => 2,
        0x81..=0x84 => 2 + usize::from(length_byte - 0x80),
        _ => return false,
    };
    head.get(tag_at..tag_at + 6) == Some(&[0x16, 0x04, b'I', b'M', b'4', b'P'][..])
}

struct Im4pLayout {
    outer_end: u64,
    payload_end: u64,
}

fn der_length(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
    let first = *bytes.get(at)?;
    if first < 0x80 {
        return Some((u64::from(first), 1));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 8 {
        return None;
    }
    let raw = bytes.get(at + 1..at + 1 + count)?;
    let value = raw
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
    Some((value, 1 + count))
}

fn parse_im4p_layout(head: &[u8]) -> Option<Im4pLayout> {
    if head.first() != Some(&0x30) {
        return None;
    }
    let (outer_len, header) = der_length(head, 1)?;
    let mut at = 1 + header;
    let outer_end = at as u64 + outer_len;
    let (len, header) = der_length(head, at + 1)?;
    if head.get(at) != Some(&0x16)
        || head.get(at + 1 + header..at + 1 + header + 4)? != b"IM4P"
        || len != 4
    {
        return None;
    }
    at += 1 + header + 4;
    loop {
        let tag = *head.get(at)?;
        let (len, header) = der_length(head, at + 1)?;
        let end = (at + 1 + header) as u64 + len;
        match tag {
            0x16 => at = usize::try_from(end).ok()?,
            0x04 => {
                return Some(Im4pLayout {
                    outer_end,
                    payload_end: end,
                });
            }
            _ => return None,
        }
    }
}

/// A keybag (an OCTET STRING right after the payload) means the payload is encrypted. `None`
/// when the prefix is too short to say, since the payload can be huge.
pub fn im4p_is_encrypted(head: &[u8]) -> Option<bool> {
    let layout = parse_im4p_layout(head)?;
    if layout.payload_end >= layout.outer_end {
        return Some(false);
    }
    let next = *head.get(usize::try_from(layout.payload_end).ok()?)?;
    Some(next == 0x04)
}

fn read_tlv_header(file: &mut File, at: u64) -> io::Result<Option<(u8, u64, u64)>> {
    file.seek(SeekFrom::Start(at))?;
    let mut header = Vec::new();
    (&mut *file)
        .take(TLV_HEADER_BYTES)
        .read_to_end(&mut header)?;
    let Some(&tag) = header.first() else {
        return Ok(None);
    };
    Ok(der_length(&header, 1).map(|(len, size)| (tag, len, at + 1 + size as u64)))
}

/// Skips by seeking so only the byte after the payload is read; a non-IM4P is not encrypted.
fn im4p_file_is_encrypted(path: &Path) -> bool {
    let probe = || -> io::Result<bool> {
        let mut file = File::open(path)?;
        let Some((0x30, outer_len, content)) = read_tlv_header(&mut file, 0)? else {
            return Ok(false);
        };
        let outer_end = content.saturating_add(outer_len);
        let Some((0x16, 4, name_at)) = read_tlv_header(&mut file, content)? else {
            return Ok(false);
        };
        file.seek(SeekFrom::Start(name_at))?;
        let mut name = [0u8; 4];
        if file.read_exact(&mut name).is_err() || &name != b"IM4P" {
            return Ok(false);
        }
        let mut at = name_at + 4;
        for _ in 0..MAX_IM4P_PREFIX_ELEMENTS {
            let Some((tag, len, start)) = read_tlv_header(&mut file, at)? else {
                return Ok(false);
            };
            let end = start.saturating_add(len);
            match tag {
                0x16 => at = end,
                0x04 => {
                    if end >= outer_end {
                        return Ok(false);
                    }
                    file.seek(SeekFrom::Start(end))?;
                    let mut next = [0u8; 1];
                    return Ok(file.read(&mut next)? == 1 && next[0] == 0x04);
                }
                _ => return Ok(false),
            }
        }
        Ok(false)
    };
    probe().unwrap_or(false)
}

/// Names are compared case-folded, since the output may sit on a case-insensitive volume.
pub fn plan_destinations(
    files: &[String],
    options: &ExportOptions,
) -> Result<Vec<(String, PathBuf)>, String> {
    plan_destinations_with(files, options, true)
}

pub fn plan_destinations_with(
    files: &[String],
    options: &ExportOptions,
    transforms_available: bool,
) -> Result<Vec<(String, PathBuf)>, String> {
    let mut plan: Vec<(String, PathBuf)> = Vec::new();
    let mut seen = BTreeSet::new();
    for name in files {
        if !seen.insert(name.as_str()) {
            continue;
        }
        let relative = if options.preserve_paths {
            PathBuf::from(name)
        } else {
            PathBuf::from(name.rsplit('/').next().unwrap_or(name))
        };
        plan.push((name.clone(), relative));
    }
    let mut by_destination: BTreeMap<String, (PathBuf, Vec<&str>)> = BTreeMap::new();
    for (name, relative) in &plan {
        for destination in final_destinations(relative, name, options, transforms_available) {
            let slot = by_destination
                .entry(fold_path(&destination))
                .or_insert_with(|| (destination.clone(), Vec::new()));
            if !slot.1.contains(&name.as_str()) {
                slot.1.push(name);
            }
        }
    }
    let clashes: Vec<String> = by_destination
        .values()
        .filter(|(_, names)| names.len() > 1)
        .map(|(destination, names)| format!("{} ({})", destination.display(), names.join(", ")))
        .collect();
    if !clashes.is_empty() {
        return Err(format!(
            "these files would be written to the same place: {}",
            clashes.join("; ")
        ));
    }
    Ok(plan)
}

fn fold_path(path: &Path) -> String {
    path.to_string_lossy().to_lowercase()
}

fn final_destinations(
    relative: &Path,
    name: &str,
    options: &ExportOptions,
    transforms_available: bool,
) -> Vec<PathBuf> {
    let mut decoded = None;
    if transforms_available {
        if options.decrypt_aea {
            decoded = strip_name_suffix(relative, AEA_SUFFIX);
        }
        if decoded.is_none() && options.decompress_im4p && looks_like_im4p_name(name) {
            decoded = strip_name_suffix(relative, IM4P_SUFFIX);
        }
    }
    match decoded {
        Some(decoded) if options.keep_originals => vec![decoded, relative.to_path_buf()],
        Some(decoded) => vec![decoded],
        None => vec![relative.to_path_buf()],
    }
}

pub fn run_export(
    tree: &IpswTree,
    cli: Option<&Path>,
    request: &ExportRequest,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(ExportProgress),
) -> Result<ExportReport, IpswError> {
    let plan = plan_destinations_with(&request.files, &request.options, cli.is_some())
        .map_err(IpswError::Unsupported)?;
    let output = std::path::absolute(&request.output).map_err(io_error(format!(
        "could not resolve {}",
        request.output.display()
    )))?;
    fs::create_dir_all(&output)
        .map_err(io_error(format!("could not create {}", output.display())))?;
    let canonical = fs::canonicalize(&output)
        .map_err(io_error(format!("could not resolve {}", output.display())))?;
    let work = ScratchDir::new_in(&output, WORK_PREFIX)
        .map_err(io_error("could not create the export work folder"))?;
    let total_bytes: u64 = plan
        .iter()
        .filter_map(|(name, _)| tree.entry(name))
        .filter(|entry| entry.kind == EntryKind::File)
        .map(|entry| entry.size)
        .sum();
    let mut job = Job {
        tree,
        cli,
        cancel,
        progress,
        options: request.options.clone(),
        device: request
            .device
            .as_deref()
            .map(str::trim)
            .filter(|device| !device.is_empty())
            .map(str::to_string),
        output: output.clone(),
        canonical,
        work: work.path().to_path_buf(),
        serial: 0,
        placed: BTreeSet::new(),
        bytes_done: 0,
        total_bytes,
    };
    job.emit(ExportProgress::Started {
        total_items: plan.len() + request.components.len(),
        total_bytes,
    });
    let mut items = Vec::new();
    let cancelled = job.run_items(&plan, &request.components, &mut items);
    drop(job);
    drop(work);
    Ok(ExportReport {
        output,
        items,
        cancelled,
    })
}

enum ItemError {
    Cancelled,
    Interrupted(Outcome),
    Failed(String),
}

impl From<IpswError> for ItemError {
    fn from(error: IpswError) -> Self {
        match error {
            IpswError::Cancelled => Self::Cancelled,
            other => Self::Failed(other.to_string()),
        }
    }
}

fn failed(reason: impl Into<String>) -> ItemError {
    ItemError::Failed(reason.into())
}

fn io_error(context: impl Into<String>) -> impl FnOnce(io::Error) -> IpswError {
    let context = context.into();
    move |error| IpswError::Io { context, error }
}

fn io_failed(context: impl Into<String>) -> impl FnOnce(io::Error) -> ItemError {
    let context = context.into();
    move |error| ItemError::Failed(format!("{context}: {error}"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Transform {
    Aea,
    Im4p,
}

struct Job<'a> {
    tree: &'a IpswTree,
    cli: Option<&'a Path>,
    cancel: &'a AtomicBool,
    progress: &'a mut dyn FnMut(ExportProgress),
    options: ExportOptions,
    device: Option<String>,
    output: PathBuf,
    /// Symlinks resolved, for the containment check.
    canonical: PathBuf,
    work: PathBuf,
    serial: usize,
    placed: BTreeSet<String>,
    bytes_done: u64,
    total_bytes: u64,
}

impl Job<'_> {
    fn emit(&mut self, event: ExportProgress) {
        (self.progress)(event);
    }

    fn log(&mut self, line: String) {
        self.emit(ExportProgress::Log(line));
    }

    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    fn run_items(
        &mut self,
        plan: &[(String, PathBuf)],
        components: &[Component],
        items: &mut Vec<ItemReport>,
    ) -> bool {
        for (index, (name, relative)) in plan.iter().enumerate() {
            if self.cancelled() {
                return true;
            }
            match self.export_file(index, name, relative) {
                Ok(outcome) => self.record(items, name, outcome),
                Err(ItemError::Cancelled) => return true,
                Err(ItemError::Interrupted(outcome)) => {
                    self.record(items, name, outcome);
                    return true;
                }
                Err(ItemError::Failed(reason)) => {
                    self.record(items, name, Outcome::Failed { reason });
                }
            }
        }
        for (offset, component) in components.iter().enumerate() {
            if self.cancelled() {
                return true;
            }
            let label = component.label();
            self.emit(ExportProgress::Item {
                index: plan.len() + offset,
                name: label.to_string(),
                action: ItemAction::Component(*component),
            });
            match self.export_component(*component) {
                Ok(outcome) => self.record(items, label, outcome),
                Err(ItemError::Cancelled) => return true,
                Err(ItemError::Interrupted(outcome)) => {
                    self.record(items, label, outcome);
                    return true;
                }
                Err(ItemError::Failed(reason)) => {
                    self.record(items, label, Outcome::Failed { reason });
                }
            }
        }
        false
    }

    fn record(&mut self, items: &mut Vec<ItemReport>, name: &str, outcome: Outcome) {
        let line = match &outcome {
            Outcome::Decrypted { .. } => Some(format!("decrypted {name}")),
            Outcome::Decompressed { .. } => Some(format!("decompressed {name}")),
            Outcome::Kept { warning, .. } => Some(format!("kept {name}: {warning}")),
            Outcome::Skipped { reason } => Some(format!("skipped {name}: {reason}")),
            Outcome::Failed { reason } => Some(format!("failed {name}: {reason}")),
            Outcome::Produced { paths } => {
                Some(format!("produced {} file(s) from {name}", paths.len()))
            }
            Outcome::Written { .. } | Outcome::Linked { .. } => None,
        };
        if let Some(line) = line {
            self.log(line);
        }
        items.push(ItemReport {
            name: name.to_string(),
            outcome,
        });
    }

    fn item_dir(&mut self) -> Result<PathBuf, ItemError> {
        self.serial += 1;
        let dir = self.work.join(format!("item-{}", self.serial));
        fs::create_dir(&dir).map_err(io_failed("could not create a work folder"))?;
        Ok(dir)
    }

    fn exists(&self, relative: &Path) -> bool {
        fs::symlink_metadata(self.output.join(relative)).is_ok()
    }

    fn was_placed(&self, relative: &Path) -> bool {
        self.placed.contains(&fold_path(relative))
    }

    fn skip_if_present(&self, relatives: &[&Path]) -> Option<Outcome> {
        if let Some(relative) = relatives.iter().find(|relative| self.was_placed(relative)) {
            return Some(Outcome::Failed {
                reason: format!(
                    "{} was already written earlier in this run by another item",
                    relative.display()
                ),
            });
        }
        if self.options.overwrite {
            return None;
        }
        relatives
            .iter()
            .find(|relative| self.exists(relative))
            .map(|relative| Outcome::Skipped {
                reason: format!("{} already exists", relative.display()),
            })
    }

    fn export_file(
        &mut self,
        index: usize,
        name: &str,
        relative: &Path,
    ) -> Result<Outcome, ItemError> {
        let (kind, size) = match self.tree.entry(name) {
            Some(entry) => (entry.kind, entry.size),
            None => return Err(failed(format!("{name} is not in the archive"))),
        };
        let action = match kind {
            EntryKind::Symlink => ItemAction::Link,
            EntryKind::File if self.options.decrypt_aea && is_aea_name(name) => ItemAction::Decrypt,
            EntryKind::File if self.options.decompress_im4p && looks_like_im4p_name(name) => {
                ItemAction::Decompress
            }
            EntryKind::File => ItemAction::Copy,
        };
        self.emit(ExportProgress::Item {
            index,
            name: name.to_string(),
            action,
        });
        let outcome = match kind {
            EntryKind::Symlink => self.export_link(name, relative),
            EntryKind::File => self.export_regular(name, relative),
        };
        if kind == EntryKind::File {
            self.bytes_done += size;
            let (done, total) = (self.bytes_done, self.total_bytes);
            self.emit(ExportProgress::Bytes { done, total });
        }
        outcome
    }

    fn export_link(&mut self, name: &str, relative: &Path) -> Result<Outcome, ItemError> {
        if !self.options.preserve_paths {
            return Ok(Outcome::Skipped {
                reason: "symlinks are not exported when folders are dropped".into(),
            });
        }
        if let Some(skipped) = self.skip_if_present(&[relative]) {
            return Ok(skipped);
        }
        let target = self.tree.symlink_target(name)?;
        validate_link_target(name, &target)?;
        // Judge where the link would lead before anything is created or replaced.
        let destination = self.output.join(relative);
        self.ensure_parent(&destination)?;
        let parent = destination.parent().unwrap_or(&self.output);
        let real_parent = fs::canonicalize(parent)
            .map_err(io_failed(format!("could not resolve {}", parent.display())))?;
        if !link_stays_inside(&real_parent, &target, &self.canonical) {
            return Err(failed(format!(
                "{name} links to {target:?}, which leaves the output folder"
            )));
        }
        let dir = self.item_dir()?;
        let result = (|| {
            let staged = dir.join("link");
            symlink(&target, &staged)
                .map_err(io_failed(format!("could not create a link for {name}")))?;
            let path = self.place(&staged, relative)?;
            Ok(Outcome::Linked { path })
        })();
        let _ = fs::remove_dir_all(&dir);
        result
    }

    fn export_regular(&mut self, name: &str, relative: &Path) -> Result<Outcome, ItemError> {
        let aea_relative = if self.options.decrypt_aea {
            strip_name_suffix(relative, AEA_SUFFIX)
        } else {
            None
        };
        if !self.options.overwrite {
            // An IM4P name hint is not trusted: the content decides where that file lands.
            let hint = if aea_relative.is_some() && self.cli.is_some() {
                aea_relative.clone()
            } else if aea_relative.is_none()
                && self.options.decompress_im4p
                && looks_like_im4p_name(name)
            {
                None
            } else {
                Some(relative.to_path_buf())
            };
            if let Some(hint) = hint
                && let Some(skipped) = self.skip_if_present(&[hint.as_path()])
            {
                return Ok(skipped);
            }
        }
        let dir = self.item_dir()?;
        let result = self.export_regular_in(&dir, name, relative, aea_relative);
        let _ = fs::remove_dir_all(&dir);
        result
    }

    fn export_regular_in(
        &mut self,
        dir: &Path,
        name: &str,
        relative: &Path,
        aea_relative: Option<PathBuf>,
    ) -> Result<Outcome, ItemError> {
        let base = relative
            .file_name()
            .ok_or_else(|| failed(format!("{name} has no file name")))?
            .to_os_string();
        let in_dir = dir.join("in");
        let out_dir = dir.join("out");
        for folder in [&in_dir, &out_dir] {
            fs::create_dir(folder).map_err(io_failed("could not create a work folder"))?;
        }
        let input = in_dir.join(&base);
        self.extract(name, &input)?;

        let transform = if let Some(plain) = aea_relative {
            Some((Transform::Aea, plain))
        } else if self.options.decompress_im4p && sniff_file(&input) {
            Some((
                Transform::Im4p,
                decompressed_relative(relative, self.options.keep_originals),
            ))
        } else {
            None
        };
        let Some((transform, decoded)) = transform else {
            if let Some(skipped) = self.skip_if_present(&[relative]) {
                return Ok(skipped);
            }
            let path = self.place(&input, relative)?;
            return Ok(Outcome::Written { path });
        };
        // `ipsw img4 im4p extract` writes an encrypted payload out as is, so keep the IM4P.
        if transform == Transform::Im4p && im4p_file_is_encrypted(&input) {
            if let Some(skipped) = self.skip_if_present(&[relative]) {
                return Ok(skipped);
            }
            let path = self.place(&input, relative)?;
            return Ok(Outcome::Kept {
                path,
                warning: ENCRYPTED_IM4P.into(),
            });
        }
        let Some(cli) = self.cli else {
            if let Some(skipped) = self.skip_if_present(&[relative]) {
                return Ok(skipped);
            }
            let path = self.place(&input, relative)?;
            return Ok(Outcome::Kept {
                path,
                warning: CLI_MISSING.into(),
            });
        };

        let keep = self.options.keep_originals;
        let mut targets = vec![decoded.as_path()];
        if keep {
            targets.push(relative);
        }
        if let Some(skipped) = self.skip_if_present(&targets) {
            return Ok(skipped);
        }
        let produced = out_dir.join(decoded.file_name().unwrap_or_default());
        let args: Vec<OsString> = match transform {
            Transform::Aea => {
                let mut args: Vec<OsString> =
                    vec!["fw".into(), "aea".into(), input.clone().into_os_string()];
                args.push("-o".into());
                args.push(out_dir.clone().into_os_string());
                if let Some(key) = self
                    .options
                    .aea_key
                    .as_deref()
                    .map(str::trim)
                    .filter(|key| !key.is_empty())
                {
                    args.push("-b".into());
                    args.push(key.into());
                }
                args
            }
            Transform::Im4p => vec![
                "img4".into(),
                "im4p".into(),
                "extract".into(),
                "-o".into(),
                produced.clone().into_os_string(),
                input.clone().into_os_string(),
            ],
        };
        let ran = self.run_cli(cli, &args, dir).and_then(|()| {
            if fs::metadata(&produced).is_ok_and(|meta| meta.is_file()) {
                Ok(())
            } else {
                Err(failed("ipsw produced no output file"))
            }
        });
        match ran {
            Err(stop @ (ItemError::Cancelled | ItemError::Interrupted(_))) => Err(stop),
            Err(ItemError::Failed(warning)) => {
                if let Some(skipped) = self.skip_if_present(&[relative]) {
                    return Ok(skipped);
                }
                let path = self.place(&input, relative)?;
                Ok(Outcome::Kept { path, warning })
            }
            Ok(()) => {
                let path = self.place(&produced, &decoded)?;
                let original = if keep {
                    match self.place(&input, relative) {
                        Ok(original) => Some(original),
                        Err(error) => {
                            if let ItemError::Failed(reason) = error {
                                self.log(format!(
                                    "could not keep the original of {name}: {reason}"
                                ));
                            }
                            None
                        }
                    }
                } else {
                    None
                };
                Ok(match transform {
                    Transform::Aea => Outcome::Decrypted { path, original },
                    Transform::Im4p => Outcome::Decompressed { path, original },
                })
            }
        }
    }

    fn export_component(&mut self, component: Component) -> Result<Outcome, ItemError> {
        let Some(cli) = self.cli else {
            return Ok(Outcome::Failed {
                reason: CLI_MISSING.into(),
            });
        };
        let dir = self.item_dir()?;
        let result = self.export_component_in(cli, component, &dir);
        let _ = fs::remove_dir_all(&dir);
        result
    }

    /// Staging keeps a cancelled or failed run from leaving partial files in the output.
    fn export_component_in(
        &mut self,
        cli: &Path,
        component: Component,
        dir: &Path,
    ) -> Result<Outcome, ItemError> {
        let staging = dir.join("out");
        fs::create_dir(&staging).map_err(io_failed("could not create a work folder"))?;
        let mut args: Vec<OsString> = vec!["extract".into()];
        args.extend(component.flags().iter().map(OsString::from));
        if let Some(device) = self.device.clone() {
            if component.accepts_device() {
                args.push("--device".into());
                args.push(device.into());
            } else {
                self.log(format!(
                    "the device ({device}) does not apply to {}; ran without it",
                    component.label()
                ));
            }
        }
        args.push("-o".into());
        args.push(staging.clone().into_os_string());
        args.push(self.tree.archive_path().as_os_str().to_os_string());
        self.run_cli(cli, &args, dir)?;

        let mut files = Vec::new();
        collect_files(&staging, &staging, &mut files)
            .map_err(io_failed("could not list what ipsw produced"))?;
        files.sort();
        let label = component.label();
        let mut paths = Vec::new();
        let mut existing = Vec::new();
        let mut problems = Vec::new();
        for relative in files {
            if self.cancelled() {
                // Files already moved stay; say so rather than losing them from the report.
                return Err(if paths.is_empty() {
                    ItemError::Cancelled
                } else {
                    ItemError::Interrupted(Outcome::Produced { paths })
                });
            }
            if !self.options.overwrite && !self.was_placed(&relative) && self.exists(&relative) {
                self.log(format!(
                    "skipped {} from {label}: it already exists",
                    relative.display()
                ));
                existing.push(relative);
                continue;
            }
            match self.place(&staging.join(&relative), &relative) {
                Ok(path) => paths.push(path),
                Err(ItemError::Failed(reason)) => {
                    self.log(format!(
                        "could not place {} from {label}: {reason}",
                        relative.display()
                    ));
                    problems.push(reason);
                }
                Err(other) => return Err(other),
            }
        }
        if let Some(first) = problems.first() {
            return Ok(Outcome::Failed {
                reason: format!(
                    "{} of {} file(s) could not be placed ({first}); {} placed, {} already existed",
                    problems.len(),
                    problems.len() + paths.len() + existing.len(),
                    paths.len(),
                    existing.len()
                ),
            });
        }
        if paths.is_empty() && !existing.is_empty() {
            return Ok(Outcome::Skipped {
                reason: format!("all {} file(s) already exist", existing.len()),
            });
        }
        if !existing.is_empty() {
            self.log(format!(
                "{label}: {} file(s) were not replaced because they already exist",
                existing.len()
            ));
        }
        Ok(Outcome::Produced { paths })
    }

    fn extract(&mut self, name: &str, destination: &Path) -> Result<(), ItemError> {
        let tree = self.tree;
        let cancel = self.cancel;
        let (base, total) = (self.bytes_done, self.total_bytes);
        let progress = &mut *self.progress;
        tree.extract_file_cancellable(
            name,
            destination,
            &mut |done, _| {
                progress(ExportProgress::Bytes {
                    done: base + done,
                    total,
                });
            },
            cancel,
        )?;
        Ok(())
    }

    fn place(&mut self, source: &Path, relative: &Path) -> Result<PathBuf, ItemError> {
        let destination = self.output.join(relative);
        if self.was_placed(relative) {
            return Err(failed(format!(
                "{} was already written earlier in this run by another item",
                relative.display()
            )));
        }
        self.ensure_parent(&destination)?;
        match fs::symlink_metadata(&destination) {
            Ok(meta) if meta.is_dir() => {
                return Err(failed(format!(
                    "a folder already exists at {}",
                    relative.display()
                )));
            }
            Ok(_) if !self.options.overwrite => {
                return Err(failed(format!("{} already exists", relative.display())));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(io_failed(format!(
                    "could not inspect {}",
                    destination.display()
                ))(error));
            }
        }
        fs::rename(source, &destination).map_err(io_failed(format!(
            "could not place {}",
            destination.display()
        )))?;
        self.placed.insert(fold_path(relative));
        Ok(destination)
    }

    /// Each folder is checked as it is created; one resolving outside the output is refused.
    fn ensure_parent(&self, destination: &Path) -> Result<(), ItemError> {
        let Some(parent) = destination.parent() else {
            return Ok(());
        };
        let relative = parent
            .strip_prefix(&self.output)
            .map_err(|_| failed(format!("{} is outside the output folder", parent.display())))?;
        let mut current = self.output.clone();
        for component in relative.components() {
            let PathPart::Normal(part) = component else {
                return Err(failed(format!("{} is not a plain path", parent.display())));
            };
            if current == self.output && part.to_string_lossy().starts_with(WORK_PREFIX) {
                return Err(failed(format!(
                    "{} uses the name reserved for the export work folder",
                    part.to_string_lossy()
                )));
            }
            current.push(part);
            match fs::symlink_metadata(&current) {
                Ok(_) => {
                    let resolved = fs::canonicalize(&current).map_err(io_failed(format!(
                        "could not resolve {}",
                        current.display()
                    )))?;
                    if !resolved.starts_with(&self.canonical) || !resolved.is_dir() {
                        return Err(failed(format!(
                            "{} leaves the output folder",
                            current.display()
                        )));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    fs::create_dir(&current)
                        .map_err(io_failed(format!("could not create {}", current.display())))?;
                }
                Err(error) => {
                    return Err(io_failed(format!(
                        "could not inspect {}",
                        current.display()
                    ))(error));
                }
            }
        }
        Ok(())
    }

    fn run_cli(&self, cli: &Path, args: &[OsString], dir: &Path) -> Result<(), ItemError> {
        let stdout_path = dir.join("cli-stdout.log");
        let stderr_path = dir.join("cli-stderr.log");
        let stdout =
            File::create(&stdout_path).map_err(io_failed("could not create a log file"))?;
        let stderr =
            File::create(&stderr_path).map_err(io_failed("could not create a log file"))?;
        let child = Command::new(cli)
            .arg("--no-color")
            .args(args)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .process_group(0)
            .spawn()
            .map_err(io_failed(format!("could not run {}", cli.display())))?;
        let mut child = RunningChild {
            child,
            reaped: false,
        };
        let status = loop {
            match child.poll() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(error) => {
                    child.terminate();
                    return Err(io_failed("could not wait for ipsw")(error));
                }
            }
            if self.cancelled() {
                child.terminate();
                return Err(ItemError::Cancelled);
            }
            std::thread::sleep(POLL_INTERVAL);
        };
        if status.success() {
            return Ok(());
        }
        Err(ItemError::Failed(failure_message(
            &read_tail(&stdout_path),
            &read_tail(&stderr_path),
            status,
        )))
    }
}

/// Dropping it unreaped kills the group, so an early return or panic cannot leave `ipsw` running.
struct RunningChild {
    child: Child,
    reaped: bool,
}

impl RunningChild {
    fn group(&self) -> libc::pid_t {
        self.child.id() as libc::pid_t
    }

    fn signal_group(&self, signal: libc::c_int) {
        // SAFETY: kill takes no pointers. The negative pid addresses the child's own process
        // group, whose id cannot be reused while any member is alive; if none is left the call
        // fails with ESRCH, which is ignored.
        unsafe {
            libc::kill(-self.group(), signal);
        }
    }

    /// Once the leader is reaped, kills whatever it left in the group.
    fn poll(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        if status.is_some() {
            self.reaped = true;
            self.signal_group(libc::SIGKILL);
        }
        Ok(status)
    }

    fn terminate(&mut self) {
        if self.reaped {
            return;
        }
        self.signal_group(libc::SIGTERM);
        let deadline = Instant::now() + TERM_GRACE;
        while Instant::now() < deadline {
            // A leader that exits in time is followed by a SIGKILL to the rest of the group.
            if matches!(self.poll(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        self.signal_group(libc::SIGKILL);
        let _ = self.child.wait();
        self.reaped = true;
    }
}

impl Drop for RunningChild {
    fn drop(&mut self) {
        if !self.reaped {
            self.signal_group(libc::SIGKILL);
            let _ = self.child.wait();
            self.reaped = true;
        }
    }
}

fn read_tail(path: &Path) -> Vec<u8> {
    let read = || -> io::Result<Vec<u8>> {
        let mut file = File::open(path)?;
        let length = file.metadata()?.len();
        file.seek(SeekFrom::Start(length.saturating_sub(LOG_TAIL)))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    };
    read().unwrap_or_default()
}

fn failure_message(stdout: &[u8], stderr: &[u8], status: ExitStatus) -> String {
    let out = String::from_utf8_lossy(stdout);
    let err = String::from_utf8_lossy(stderr);
    let marked = out
        .lines()
        .chain(err.lines())
        .filter_map(|line| line.split_once('\u{2a2f}'))
        .map(|(_, message)| message.trim())
        .rfind(|message| !message.is_empty());
    if let Some(message) = marked {
        return message.to_string();
    }
    if let Some(line) = err
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
    {
        return line.to_string();
    }
    match status.code() {
        Some(code) => format!("exit {code}"),
        None => "killed by signal".to_string(),
    }
}

fn sniff_file(path: &Path) -> bool {
    let mut head = Vec::new();
    File::open(path)
        .and_then(|file| file.take(SIGNATURE_BYTES).read_to_end(&mut head))
        .is_ok()
        && sniff_im4p(&head)
}

/// A link step is replaced by where it leads, so a later `..` climbs from the real place.
fn link_stays_inside(parent: &Path, target: &str, root: &Path) -> bool {
    let mut resolved = parent.to_path_buf();
    for part in Path::new(target).components() {
        match part {
            PathPart::Normal(name) => {
                resolved.push(name);
                if fs::symlink_metadata(&resolved).is_ok_and(|meta| meta.file_type().is_symlink()) {
                    match fs::canonicalize(&resolved) {
                        Ok(real) => resolved = real,
                        Err(_) => return false,
                    }
                }
            }
            PathPart::CurDir => {}
            PathPart::ParentDir => {
                if !resolved.pop() {
                    return false;
                }
            }
            _ => return false,
        }
        if !resolved.starts_with(root) {
            return false;
        }
    }
    resolved.starts_with(root)
}

fn strip_name_suffix(relative: &Path, suffix: &str) -> Option<PathBuf> {
    let stem = relative
        .file_name()?
        .to_str()?
        .strip_suffix(suffix)
        .filter(|stem| !stem.is_empty())?;
    Some(relative.with_file_name(stem))
}

fn decompressed_relative(relative: &Path, keep_originals: bool) -> PathBuf {
    if let Some(stripped) = strip_name_suffix(relative, IM4P_SUFFIX) {
        return stripped;
    }
    if keep_originals {
        let mut name = relative.file_name().unwrap_or_default().to_os_string();
        name.push(".decompressed");
        return relative.with_file_name(name);
    }
    relative.to_path_buf()
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_files(root, &entry.path(), out)?;
        } else if file_type.is_file()
            && let Ok(relative) = entry.path().strip_prefix(root)
        {
            out.push(relative.to_path_buf());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipsw_fixture::{
        FixtureEntry, build_manifest_plist, fake_im4p, sample_entries, write_fake_cli, write_ipsw,
    };
    use std::os::unix::process::ExitStatusExt;

    struct Setup {
        _dir: tempfile::TempDir,
        root: PathBuf,
        tree: IpswTree,
        cli: PathBuf,
    }

    fn setup(entries: &[FixtureEntry]) -> Setup {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let bin = root.join("bin");
        fs::create_dir(&bin).unwrap();
        let cli = write_fake_cli(&bin).unwrap();
        let archive = root.join("test.ipsw");
        write_ipsw(&archive, entries).unwrap();
        let tree = IpswTree::open(&archive).unwrap();
        Setup {
            _dir: dir,
            root,
            tree,
            cli,
        }
    }

    fn request(setup: &Setup, files: &[&str]) -> ExportRequest {
        ExportRequest {
            files: files.iter().map(|name| name.to_string()).collect(),
            components: Vec::new(),
            device: None,
            output: setup.root.join("out"),
            options: ExportOptions::default(),
        }
    }

    fn run(setup: &Setup, request: &ExportRequest, with_cli: bool) -> ExportReport {
        let cancel = AtomicBool::new(false);
        run_export(
            &setup.tree,
            with_cli.then_some(setup.cli.as_path()),
            request,
            &cancel,
            &mut |_| {},
        )
        .unwrap()
    }

    fn no_work_dir_left(output: &Path) -> bool {
        fs::read_dir(output)
            .unwrap()
            .flatten()
            .all(|entry| !entry.file_name().to_string_lossy().starts_with(WORK_PREFIX))
    }

    #[test]
    fn im4p_sniffing_follows_the_der_header() {
        assert!(sniff_im4p(&fake_im4p(b"payload")));
        assert!(sniff_im4p(&[
            0x30, 0x10, 0x16, 0x04, b'I', b'M', b'4', b'P'
        ]));
        assert!(sniff_im4p(&[
            0x30, 0x82, 0x01, 0x00, 0x16, 0x04, b'I', b'M', b'4', b'P'
        ]));
        assert!(!sniff_im4p(b"AEA1PLAIN-SYSTEM-IMAGE"));
        assert!(!sniff_im4p(&[
            0x30, 0x85, 0, 0, 0, 0, 0, 0x16, 0x04, b'I', b'M', b'4', b'P'
        ]));
        assert!(!sniff_im4p(&[0x30]));
        assert!(!sniff_im4p(&[]));
    }

    #[test]
    fn name_hints() {
        assert!(is_aea_name("a/b.dmg.aea"));
        assert!(!is_aea_name("a/b.dmg"));
        assert!(looks_like_im4p_name("Firmware/dfu/iBEC.im4p"));
        assert!(looks_like_im4p_name("kernelcache.release.mac14j"));
        assert!(!looks_like_im4p_name("Firmware/notes.txt"));
    }

    #[test]
    fn flattening_reports_every_clash() {
        let options = ExportOptions {
            preserve_paths: false,
            ..ExportOptions::default()
        };
        let files: Vec<String> = ["a/x.bin", "b/x.bin", "c/y.bin", "d/y.bin", "e/z.bin"]
            .iter()
            .map(|name| name.to_string())
            .collect();
        let error = plan_destinations(&files, &options).unwrap_err();
        assert!(
            error.contains("x.bin") && error.contains("y.bin"),
            "{error}"
        );
        assert!(!error.contains("z.bin"), "{error}");
        let unique = plan_destinations(&files[..1], &options).unwrap();
        assert_eq!(
            unique,
            vec![("a/x.bin".to_string(), PathBuf::from("x.bin"))]
        );
        let kept = plan_destinations(&files, &ExportOptions::default()).unwrap();
        assert_eq!(kept[1].1, PathBuf::from("b/x.bin"));
    }

    #[test]
    fn failure_messages_prefer_the_marked_line() {
        let status = ExitStatus::from_raw(1 << 8);
        assert_eq!(
            failure_message(
                b"",
                "noise\n   \u{2a2f} failed to parse AEA: bad key\n".as_bytes(),
                status
            ),
            "failed to parse AEA: bad key"
        );
        assert_eq!(
            failure_message(b"", b"plain\nlast line\n", status),
            "last line"
        );
        assert_eq!(failure_message(b"", b"", status), "exit 1");
        assert_eq!(
            failure_message(b"", b"", ExitStatus::from_raw(9)),
            "killed by signal"
        );
    }

    #[test]
    fn reads_the_manifest() {
        let setup = setup(&sample_entries());
        let info = read_info(&setup.tree).unwrap();
        assert_eq!(info.product_version.as_deref(), Some("26.0"));
        assert_eq!(info.build.as_deref(), Some("25A1"));
        assert_eq!(info.product_types, vec!["Mac14,2", "Mac15,6"]);
        assert!(!build_manifest_plist().is_empty());
    }

    #[test]
    fn exports_with_decryption_decompression_and_links() {
        let setup = setup(&sample_entries());
        let files = [
            "090-12345-001.dmg.aea",
            "kernelcache.release.mac14j",
            "Firmware/dfu/iBEC.j414c.RELEASE.im4p",
            "Firmware/notes.txt",
            "Firmware/latest",
        ];
        let request = request(&setup, &files);
        let report = run(&setup, &request, true);
        let out = &request.output;
        assert!(!report.cancelled);
        assert_eq!(report.counts().failed, 0, "{:?}", report.items);
        assert_eq!(
            fs::read(out.join("090-12345-001.dmg")).unwrap(),
            b"PLAIN-SYSTEM-IMAGE"
        );
        assert!(!out.join("090-12345-001.dmg.aea").exists());
        assert_eq!(
            fs::read(out.join("kernelcache.release.mac14j")).unwrap(),
            b"KERNEL-PAYLOAD"
        );
        assert_eq!(
            fs::read(out.join("Firmware/dfu/iBEC.j414c.RELEASE")).unwrap(),
            b"IBEC-PAYLOAD"
        );
        assert_eq!(fs::read(out.join("Firmware/notes.txt")).unwrap(), b"hello");
        assert_eq!(
            fs::read_link(out.join("Firmware/latest")).unwrap(),
            Path::new("notes.txt")
        );
        let counts = report.counts();
        assert_eq!(
            (
                counts.decrypted,
                counts.decompressed,
                counts.written,
                counts.linked
            ),
            (1, 2, 1, 1)
        );
        assert!(no_work_dir_left(out));
    }

    #[test]
    fn keeps_originals_beside_the_transformed_files() {
        let setup = setup(&sample_entries());
        let mut request = request(
            &setup,
            &[
                "kernelcache.release.mac14j",
                "Firmware/all_flash/LLB.j414c.RELEASE.im4p",
            ],
        );
        request.options.keep_originals = true;
        let report = run(&setup, &request, true);
        let out = &request.output;
        assert_eq!(report.counts().decompressed, 2, "{:?}", report.items);
        assert_eq!(
            fs::read(out.join("kernelcache.release.mac14j.decompressed")).unwrap(),
            b"KERNEL-PAYLOAD"
        );
        assert_eq!(
            fs::read(out.join("kernelcache.release.mac14j")).unwrap(),
            fake_im4p(b"KERNEL-PAYLOAD")
        );
        assert_eq!(
            fs::read(out.join("Firmware/all_flash/LLB.j414c.RELEASE")).unwrap(),
            b"LLB-PAYLOAD"
        );
        assert_eq!(
            fs::read(out.join("Firmware/all_flash/LLB.j414c.RELEASE.im4p")).unwrap(),
            fake_im4p(b"LLB-PAYLOAD")
        );
    }

    #[test]
    fn a_failed_transform_keeps_the_original_with_the_tools_message() {
        let mut entries = sample_entries();
        entries.push(FixtureEntry::file("bad.dmg.aea", b"FAILxxxx".to_vec()));
        let setup = setup(&entries);
        let request = request(&setup, &["bad.dmg.aea"]);
        let report = run(&setup, &request, true);
        match &report.items[0].outcome {
            Outcome::Kept { path, warning } => {
                assert!(
                    warning.contains("failed to parse AEA: bad key"),
                    "{warning}"
                );
                assert_eq!(fs::read(path).unwrap(), b"FAILxxxx");
            }
            other => panic!("{other:?}"),
        }
        assert!(no_work_dir_left(&request.output));
    }

    #[test]
    fn without_the_cli_originals_are_kept_with_a_warning() {
        let setup = setup(&sample_entries());
        let request = request(&setup, &["090-12345-001.dmg.aea", "Firmware/notes.txt"]);
        let report = run(&setup, &request, false);
        assert!(matches!(report.items[0].outcome, Outcome::Kept { .. }));
        assert!(matches!(report.items[1].outcome, Outcome::Written { .. }));
        assert!(request.output.join("090-12345-001.dmg.aea").is_file());
    }

    #[test]
    fn the_key_reaches_the_cli() {
        let setup = setup(&sample_entries());
        let mut request = request(&setup, &["090-12345-001.dmg.aea"]);
        request.options.aea_key = Some("c2VjcmV0".into());
        run(&setup, &request, true);
        let log = fs::read_to_string(setup.cli.parent().unwrap().join("args.log")).unwrap();
        assert!(log.contains("-b c2VjcmV0"), "{log}");
    }

    #[test]
    fn existing_files_are_skipped_unless_overwriting() {
        let setup = setup(&sample_entries());
        let request = request(&setup, &["Firmware/notes.txt"]);
        let target = request.output.join("Firmware/notes.txt");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"mine").unwrap();
        let report = run(&setup, &request, true);
        assert!(matches!(report.items[0].outcome, Outcome::Skipped { .. }));
        assert_eq!(fs::read(&target).unwrap(), b"mine");

        let mut again = request.clone();
        again.options.overwrite = true;
        let report = run(&setup, &again, true);
        assert!(matches!(report.items[0].outcome, Outcome::Written { .. }));
        assert_eq!(fs::read(&target).unwrap(), b"hello");
    }

    #[test]
    fn placement_never_follows_a_link_out_of_the_output() {
        let setup = setup(&sample_entries());
        let request = request(&setup, &["Firmware/notes.txt"]);
        let outside = setup.root.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::create_dir_all(&request.output).unwrap();
        symlink(&outside, request.output.join("Firmware")).unwrap();
        let report = run(&setup, &request, true);
        assert!(matches!(report.items[0].outcome, Outcome::Failed { .. }));
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    }

    #[test]
    fn components_are_staged_then_placed() {
        let setup = setup(&sample_entries());
        let mut request = request(&setup, &[]);
        request.components = vec![Component::Kernel, Component::DeviceTree, Component::IBoot];
        request.device = Some("Mac15,6".into());
        let report = run(&setup, &request, true);
        let out = &request.output;
        match &report.items[0].outcome {
            Outcome::Produced { paths } => {
                assert_eq!(
                    paths,
                    &vec![out.join("25A1__Mac15,6/kernelcache.release.Mac15,6")]
                );
                assert_eq!(fs::read(&paths[0]).unwrap(), b"KERNEL-FROM-CLI");
            }
            other => panic!("{other:?}"),
        }
        match &report.items[1].outcome {
            Outcome::Failed { reason } => assert!(reason.contains("no files found"), "{reason}"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(report.items[2].outcome, Outcome::Produced { .. }));
        assert_eq!(report.counts().produced, 2);
        assert!(no_work_dir_left(out));
    }

    #[test]
    fn cancelling_a_running_tool_is_prompt_and_leaves_nothing() {
        let mut entries = sample_entries();
        entries.push(FixtureEntry::file("slow.dmg.aea", b"AEA1data".to_vec()));
        let setup = setup(&entries);
        let request = request(
            &setup,
            &["Firmware/notes.txt", "slow.dmg.aea", "Restore.plist"],
        );
        let cancel = AtomicBool::new(false);
        let started = Instant::now();
        let report = std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(400));
                cancel.store(true, Ordering::Relaxed);
            });
            run_export(
                &setup.tree,
                Some(setup.cli.as_path()),
                &request,
                &cancel,
                &mut |_| {},
            )
            .unwrap()
        });
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(report.cancelled);
        assert_eq!(report.items.len(), 1);
        assert!(request.output.join("Firmware/notes.txt").is_file());
        assert!(!request.output.join("slow.dmg").exists());
        assert!(!request.output.join("Restore.plist").exists());
        assert!(no_work_dir_left(&request.output));
    }

    #[test]
    fn an_abandoned_work_folder_is_reclaimed_by_the_next_export() {
        let setup = setup(&sample_entries());
        let request = request(&setup, &["Firmware/notes.txt"]);
        let stale = request.output.join(format!("{WORK_PREFIX}stale00"));
        fs::create_dir_all(&stale).unwrap();
        File::create(stale.join(".apple-utils-lock")).unwrap();
        fs::write(stale.join("half-written"), b"x").unwrap();
        run(&setup, &request, true);
        assert!(!stale.exists());
    }

    #[test]
    fn progress_starts_first_and_reports_items_and_bytes() {
        let setup = setup(&sample_entries());
        let request = request(&setup, &["Firmware/notes.txt", "Restore.plist"]);
        let cancel = AtomicBool::new(false);
        let mut events = Vec::new();
        run_export(&setup.tree, None, &request, &cancel, &mut |event| {
            events.push(event)
        })
        .unwrap();
        assert!(matches!(
            events[0],
            ExportProgress::Started { total_items: 2, .. }
        ));
        let items: Vec<usize> = events
            .iter()
            .filter_map(|event| match event {
                ExportProgress::Item { index, .. } => Some(*index),
                _ => None,
            })
            .collect();
        assert_eq!(items, vec![0, 1]);
        assert!(events.iter().any(|event| matches!(
            event,
            ExportProgress::Bytes { done, total } if done == total
        )));
    }

    #[test]
    fn a_clash_when_flattening_aborts_before_anything_is_written() {
        let setup = setup(&sample_entries());
        let mut request = request(
            &setup,
            &[
                "Firmware/Manifests/restore/info.plist",
                "Restore.plist",
                "BuildManifest.plist",
            ],
        );
        request.options.preserve_paths = false;
        request.files.push("Firmware/other/info.plist".into());
        let cancel = AtomicBool::new(false);
        let error = run_export(&setup.tree, None, &request, &cancel, &mut |_| {}).unwrap_err();
        assert!(matches!(error, IpswError::Unsupported(_)), "{error}");
        assert!(!request.output.exists());
    }

    #[test]
    fn read_info_fills_the_catalog_from_the_same_manifest() {
        let realistic = setup(&crate::ipsw_fixture::realistic_entries());
        let info = read_info(&realistic.tree).unwrap();
        assert_eq!(info.product_types, vec!["Mac14,3", "Mac14,5"]);
        assert_eq!(info.catalog.boards().len(), 2);
        let ramdisk = info.catalog.describe("090-12345-003.dmg").unwrap();
        assert_eq!(ramdisk.title, "Restore ramdisk");
        let plain = setup(&sample_entries());
        assert!(read_info(&plain.tree).unwrap().catalog.boards().is_empty());
    }

    #[test]
    fn the_device_is_passed_only_to_components_that_accept_it() {
        for component in Component::ALL {
            let expected = matches!(
                component,
                Component::Kernel | Component::Dyld | Component::DriverKit | Component::FcsKeys
            );
            assert_eq!(component.accepts_device(), expected, "{component:?}");
        }
        let setup = setup(&sample_entries());
        let mut request = request(&setup, &[]);
        request.components = vec![Component::Kernel, Component::DeviceTree, Component::Sep];
        request.device = Some("Mac15,6".into());
        let mut log = Vec::new();
        let cancel = AtomicBool::new(false);
        let report = run_export(
            &setup.tree,
            Some(setup.cli.as_path()),
            &request,
            &cancel,
            &mut |event| {
                if let ExportProgress::Log(line) = event {
                    log.push(line);
                }
            },
        )
        .unwrap();
        let args = fs::read_to_string(setup.cli.parent().unwrap().join("args.log")).unwrap();
        let line_with = |flag: &str| args.lines().find(|line| line.contains(flag)).unwrap();
        assert!(line_with("--kernel").contains("--device Mac15,6"), "{args}");
        assert!(!line_with("--dtree").contains("--device"), "{args}");
        assert!(!line_with("--sep").contains("--device"), "{args}");
        assert!(matches!(report.items[0].outcome, Outcome::Produced { .. }));
        match &report.items[1].outcome {
            Outcome::Failed { reason } => assert!(reason.contains("no files found"), "{reason}"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(report.items[2].outcome, Outcome::Produced { .. }));
        assert_eq!(
            log.iter()
                .filter(|line| line.contains("does not apply"))
                .count(),
            2,
            "{log:?}"
        );
    }

    #[test]
    fn the_fake_cli_rejects_device_with_components_that_do_not_take_it() {
        let setup = setup(&sample_entries());
        let out = setup.root.join("cli-out");
        fs::create_dir(&out).unwrap();
        for (flag, accepted) in [("--dtree", false), ("--sep", false), ("--kernel", true)] {
            let result = Command::new(&setup.cli)
                .args(["--no-color", "extract", flag, "--device", "Mac14,2", "-o"])
                .arg(&out)
                .arg(setup.tree.archive_path())
                .output()
                .unwrap();
            assert_eq!(result.status.success(), accepted, "{flag}");
            if !accepted {
                let stderr = String::from_utf8_lossy(&result.stderr);
                assert!(
                    stderr.contains("--device can only be used with"),
                    "{stderr}"
                );
            }
        }
    }

    #[test]
    fn keybags_mark_an_im4p_as_encrypted() {
        use crate::ipsw_fixture::{fake_im4p_der, fake_im4p_encrypted};
        let encrypted = fake_im4p_encrypted(b"SECRET");
        let plain = fake_im4p_der(b"SECRET", false);
        assert!(sniff_im4p(&encrypted) && sniff_im4p(&plain));
        assert_eq!(im4p_is_encrypted(&encrypted), Some(true));
        assert_eq!(im4p_is_encrypted(&plain), Some(false));
        assert_eq!(im4p_is_encrypted(&encrypted[..encrypted.len() - 6]), None);
        assert_eq!(im4p_is_encrypted(&encrypted[..10]), None);
        assert_eq!(im4p_is_encrypted(&fake_im4p(b"KERNEL-PAYLOAD")), None);
        assert_eq!(im4p_is_encrypted(b"AEA1PLAIN-SYSTEM-IMAGE"), None);
        assert_eq!(im4p_is_encrypted(&[]), None);
        let short = [
            0x30, 0x14, 0x16, 0x04, b'I', b'M', b'4', b'P', 0x16, 0x04, b's', b'e', b'p', b'i',
            0x16, 0x01, b'1', 0x04, 0x01, b'x', 0x04, 0x00,
        ];
        assert_eq!(im4p_is_encrypted(&short), Some(true));
    }

    #[test]
    fn a_huge_payload_is_judged_from_the_header_and_one_byte_after_it() {
        use crate::ipsw_fixture::{fake_im4p_der, fake_im4p_encrypted};
        let dir = tempfile::tempdir().unwrap();
        let payload = vec![0xAB; 1 << 20];
        let encrypted = dir.path().join("encrypted");
        let plain = dir.path().join("plain");
        fs::write(&encrypted, fake_im4p_encrypted(&payload)).unwrap();
        fs::write(&plain, fake_im4p_der(&payload, false)).unwrap();
        assert_eq!(
            im4p_is_encrypted(&fake_im4p_encrypted(&payload)[..64]),
            None
        );
        assert!(im4p_file_is_encrypted(&encrypted));
        assert!(!im4p_file_is_encrypted(&plain));
        assert!(!im4p_file_is_encrypted(&dir.path().join("missing")));
    }

    #[test]
    fn a_long_version_string_does_not_hide_the_keybag() {
        use crate::ipsw_fixture::fake_im4p_der_with_version;
        let version = vec![b'a'; 2000];
        let encrypted = fake_im4p_der_with_version(b"SECRET", &version, true);
        let plain = fake_im4p_der_with_version(b"SECRET", &version, false);
        assert!(sniff_im4p(&encrypted));
        assert_eq!(im4p_is_encrypted(&encrypted), Some(true));
        assert_eq!(im4p_is_encrypted(&plain), Some(false));
        assert_eq!(im4p_is_encrypted(&encrypted[..64]), None);
        let dir = tempfile::tempdir().unwrap();
        let encrypted_path = dir.path().join("encrypted");
        let plain_path = dir.path().join("plain");
        fs::write(&encrypted_path, &encrypted).unwrap();
        fs::write(&plain_path, &plain).unwrap();
        assert!(im4p_file_is_encrypted(&encrypted_path));
        assert!(!im4p_file_is_encrypted(&plain_path));
        let big = fake_im4p_der_with_version(&vec![0u8; 1 << 20], &vec![b'f'; 200_000], true);
        let big_path = dir.path().join("big");
        fs::write(&big_path, &big).unwrap();
        assert!(im4p_file_is_encrypted(&big_path));
    }

    #[test]
    fn an_encrypted_im4p_with_a_long_version_is_kept_end_to_end() {
        let image =
            crate::ipsw_fixture::fake_im4p_der_with_version(b"SECRET", &vec![b'0'; 2048], true);
        let entries = vec![
            FixtureEntry::file("BuildManifest.plist", build_manifest_plist()),
            FixtureEntry::file(
                "Firmware/all_flash/sep-firmware.j473.RELEASE.im4p",
                image.clone(),
            ),
        ];
        let setup = setup(&entries);
        let request = request(
            &setup,
            &["Firmware/all_flash/sep-firmware.j473.RELEASE.im4p"],
        );
        let report = run(&setup, &request, true);
        match &report.items[0].outcome {
            Outcome::Kept { path, warning } => {
                assert!(warning.contains("carries keybags"), "{warning}");
                assert_eq!(fs::read(path).unwrap(), image);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(report.counts().decompressed, 0);
        let args =
            fs::read_to_string(setup.cli.parent().unwrap().join("args.log")).unwrap_or_default();
        assert!(!args.contains("img4"), "{args}");
    }

    #[test]
    fn an_encrypted_im4p_is_kept_and_never_sent_to_the_tool() {
        let entries = vec![
            FixtureEntry::file("BuildManifest.plist", build_manifest_plist()),
            FixtureEntry::file(
                "Firmware/all_flash/sep-firmware.j473.RELEASE.im4p",
                crate::ipsw_fixture::fake_im4p_encrypted(b"SECRET"),
            ),
        ];
        let setup = setup(&entries);
        let request = request(
            &setup,
            &["Firmware/all_flash/sep-firmware.j473.RELEASE.im4p"],
        );
        for with_cli in [true, false] {
            let _ = fs::remove_dir_all(&request.output);
            let report = run(&setup, &request, with_cli);
            match &report.items[0].outcome {
                Outcome::Kept { path, warning } => {
                    assert_eq!(
                        warning,
                        "the payload is encrypted (it carries keybags), so it was kept as IM4P"
                    );
                    assert_eq!(
                        fs::read(path).unwrap(),
                        crate::ipsw_fixture::fake_im4p_encrypted(b"SECRET")
                    );
                    assert!(path.ends_with("sep-firmware.j473.RELEASE.im4p"));
                }
                other => panic!("{other:?}"),
            }
            assert_eq!(report.counts().decompressed, 0);
        }
        let args =
            fs::read_to_string(setup.cli.parent().unwrap().join("args.log")).unwrap_or_default();
        assert!(!args.contains("img4"), "{args}");
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn transformed_names_and_case_folding_are_planned_as_clashes() {
        let options = ExportOptions::default();
        for pair in [
            ["x.dmg.aea", "x.dmg"],
            ["Firmware/iBoot.im4p", "Firmware/iBoot"],
            ["a/Foo.bin", "a/foo.bin"],
        ] {
            let error = plan_destinations(&names(&pair), &options).unwrap_err();
            assert!(
                error.contains(pair[0]) && error.contains(pair[1]),
                "{error}"
            );
        }
        let flat = ExportOptions {
            preserve_paths: false,
            ..ExportOptions::default()
        };
        assert!(plan_destinations(&names(&["a/Foo", "b/foo"]), &flat).is_err());
        assert!(plan_destinations_with(&names(&["x.dmg.aea", "x.dmg"]), &options, false).is_ok());
        let keep = ExportOptions {
            keep_originals: true,
            ..ExportOptions::default()
        };
        assert!(plan_destinations(&names(&["x.dmg.aea", "y.dmg"]), &keep).is_ok());
        assert!(plan_destinations(&names(&["x.dmg.aea", "x.dmg.aea"]), &keep).is_ok());
    }

    #[test]
    fn a_collision_found_only_at_run_time_fails_instead_of_overwriting() {
        let entries = vec![
            FixtureEntry::file("BuildManifest.plist", build_manifest_plist()),
            FixtureEntry::file("dir/thing", fake_im4p(b"PAYLOAD")),
            FixtureEntry::file("dir/thing.decompressed", b"other".to_vec()),
        ];
        let setup = setup(&entries);
        let mut request = request(&setup, &["dir/thing", "dir/thing.decompressed"]);
        request.options.keep_originals = true;
        request.options.overwrite = true;
        let report = run(&setup, &request, true);
        assert!(matches!(
            report.items[0].outcome,
            Outcome::Decompressed { .. }
        ));
        match &report.items[1].outcome {
            Outcome::Failed { reason } => {
                assert!(reason.contains("earlier in this run"), "{reason}")
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            fs::read(request.output.join("dir/thing.decompressed")).unwrap(),
            b"PAYLOAD"
        );
    }

    #[test]
    fn links_are_judged_lexically_against_the_real_parent() {
        let root = Path::new("/out");
        assert!(link_stays_inside(Path::new("/out/a"), "../b", root));
        assert!(link_stays_inside(Path::new("/out/a"), "./c/d", root));
        assert!(!link_stays_inside(Path::new("/out/a"), "../../b", root));
        assert!(!link_stays_inside(Path::new("/out"), "../x", root));
        assert!(!link_stays_inside(
            Path::new("/out/a"),
            "x/../../../b",
            root
        ));
        assert!(!link_stays_inside(Path::new("/out"), "/etc", root));
    }

    #[test]
    fn a_target_through_an_earlier_link_is_followed_to_where_it_really_leads() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap().join("out");
        let deep = root.join("d1/d2/d3/d4");
        fs::create_dir_all(&deep).unwrap();
        symlink("../../../..", deep.join("up")).unwrap();
        symlink("up/../../..", deep.join("up2")).unwrap();
        assert!(link_stays_inside(&deep, "up", &root));
        assert!(link_stays_inside(&deep, "up/d1", &root));
        assert!(!link_stays_inside(&deep, "up/../../..", &root));
        assert!(!link_stays_inside(&deep, "up2/x", &root));
    }

    #[test]
    fn a_dangling_link_that_leaves_the_output_is_refused_before_anything_is_replaced() {
        let entries = vec![
            FixtureEntry::file("BuildManifest.plist", build_manifest_plist()),
            FixtureEntry::symlink("d/e", "../x"),
        ];
        let setup = setup(&entries);
        let mut request = request(&setup, &["d/e"]);
        request.options.overwrite = true;
        fs::create_dir_all(&request.output).unwrap();
        symlink(".", request.output.join("d")).unwrap();
        fs::write(request.output.join("e"), b"keep").unwrap();
        let report = run(&setup, &request, true);
        match &report.items[0].outcome {
            Outcome::Failed { reason } => assert!(reason.contains("leaves the output"), "{reason}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(fs::read(request.output.join("e")).unwrap(), b"keep");
    }

    #[test]
    fn a_failed_move_keeps_the_placed_files_in_the_report() {
        let setup = setup(&sample_entries());
        let mut request = request(&setup, &[]);
        request.components = vec![Component::DriverKit];
        request.options.overwrite = true;
        let blocked = request.output.join("25A1__Mac14,2/driverkit.bin");
        fs::create_dir_all(&blocked).unwrap();
        let mut log = Vec::new();
        let cancel = AtomicBool::new(false);
        let report = run_export(
            &setup.tree,
            Some(setup.cli.as_path()),
            &request,
            &cancel,
            &mut |event| {
                if let ExportProgress::Log(line) = event {
                    log.push(line);
                }
            },
        )
        .unwrap();
        match &report.items[0].outcome {
            Outcome::Failed { reason } => {
                assert!(
                    reason.contains("1 of 2") && reason.contains("1 placed"),
                    "{reason}"
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(request.output.join("25A1__Mac14,2/dyld.bin").is_file());
        assert!(
            log.iter().any(|line| line.contains("driverkit.bin")),
            "{log:?}"
        );
    }

    #[test]
    fn components_whose_files_all_exist_are_reported_as_skipped() {
        let setup = setup(&sample_entries());
        let mut request = request(&setup, &[]);
        request.components = vec![Component::Kernel];
        let first = run(&setup, &request, true);
        assert!(matches!(first.items[0].outcome, Outcome::Produced { .. }));
        let second = run(&setup, &request, true);
        match &second.items[0].outcome {
            Outcome::Skipped { reason } => assert!(reason.contains("already exist"), "{reason}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn leftovers_in_the_process_group_are_killed_after_the_leader_exits() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let script = format!(
            "(trap '' TERM; exec sleep 30) >/dev/null 2>&1 & echo $! > '{}'",
            pidfile.display()
        );
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let mut running = RunningChild {
            child,
            reaped: false,
        };
        while running.poll().unwrap().is_none() {
            std::thread::sleep(Duration::from_millis(10));
        }
        let pid: libc::pid_t = fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        // SAFETY: signal 0 only checks that the process exists.
        while unsafe { libc::kill(pid, 0) } == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_ne!(unsafe { libc::kill(pid, 0) }, 0, "the straggler survived");
    }
}
