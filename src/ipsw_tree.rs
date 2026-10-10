//! A lazy view of an IPSW: the archive's central directory is held in memory as a tree, and a file
//! is written to a private temp directory only when something asks for it. Nothing is unpacked
//! ahead of need, and the temp directory is removed when the stage is dropped.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use crate::scratch::ScratchDir;
use flate2::Crc;
use flate2::read::DeflateDecoder;

pub const IPSW_CLI_NAME: &str = "ipsw";

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const EOCD64_SIGNATURE: u32 = 0x0606_4b50;
const EOCD64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const EOCD_FIXED_LEN: usize = 22;
const EOCD64_LOCATOR_LEN: u64 = 20;
const EOCD64_FIXED_LEN: usize = 56;
const CENTRAL_FIXED_LEN: usize = 46;
const LOCAL_FIXED_LEN: usize = 30;
const MAX_COMMENT_LEN: u64 = 0xFFFF;
const MAX_CENTRAL_DIRECTORY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ENTRIES: u64 = 4_000_000;
const MAX_SYMLINK_TARGET: u64 = 4096;
const COPY_BUFFER: usize = 1024 * 1024;
const PROGRESS_STEP: u64 = 8 * 1024 * 1024;
const FLAG_ENCRYPTED: u16 = 0x0001;
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;
const UNIX_HOST: u8 = 3;
const MODE_TYPE_MASK: u32 = 0o170_000;
const MODE_SYMLINK: u32 = 0o120_000;
const MODE_DIRECTORY: u32 = 0o040_000;
const BUILD_MANIFEST: &str = "BuildManifest.plist";
const DECRYPT_WORK_DIR: &str = ".aea-work";
const AEA_SUFFIX: &str = ".aea";

#[derive(Debug)]
pub enum IpswError {
    Io { context: String, error: io::Error },
    NotAnArchive(String),
    Unsafe(String),
    Missing(String),
    Corrupt(String),
    Unsupported(String),
    NoCli,
    Cli(String),
}

impl fmt::Display for IpswError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { context, error } => write!(f, "{context}: {error}"),
            Self::NotAnArchive(reason) => write!(f, "not a usable IPSW: {reason}"),
            Self::Unsafe(reason) => write!(f, "unsafe IPSW entry: {reason}"),
            Self::Missing(name) => write!(f, "the IPSW has no entry named {name}"),
            Self::Corrupt(reason) => write!(f, "corrupt IPSW entry: {reason}"),
            Self::Unsupported(reason) => write!(f, "unsupported IPSW entry: {reason}"),
            Self::NoCli => write!(
                f,
                "the {IPSW_CLI_NAME} command is not installed, so encrypted (.aea) images cannot be decrypted"
            ),
            Self::Cli(reason) => write!(f, "{IPSW_CLI_NAME} failed: {reason}"),
        }
    }
}

impl std::error::Error for IpswError {}

fn io_error(context: impl Into<String>) -> impl FnOnce(io::Error) -> IpswError {
    let context = context.into();
    move |error| IpswError::Io { context, error }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Symlink,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpswEntry {
    pub kind: EntryKind,
    pub size: u64,
    compressed_size: u64,
    crc32: u32,
    method: u16,
    flags: u16,
    local_header_offset: u64,
    mode: u32,
}

/// The archive's file tree, read once from the central directory. File data stays on disk.
#[derive(Debug)]
pub struct IpswTree {
    archive: PathBuf,
    entries: BTreeMap<String, IpswEntry>,
    directories: BTreeSet<String>,
}

impl IpswTree {
    pub fn open(archive: &Path) -> Result<Self, IpswError> {
        let mut file = File::open(archive)
            .map_err(io_error(format!("could not open {}", archive.display())))?;
        let length = file
            .metadata()
            .map_err(io_error(format!("could not inspect {}", archive.display())))?
            .len();
        let directory = locate_central_directory(&mut file, length)?;
        let raw = read_at(&mut file, directory.offset, directory.size)
            .map_err(io_error("could not read the IPSW central directory"))?;
        let (entries, directories) = parse_central_directory(&raw, directory.count)?;
        Ok(Self {
            archive: archive.to_path_buf(),
            entries,
            directories,
        })
    }

    pub fn archive_path(&self) -> &Path {
        &self.archive
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entry(&self, name: &str) -> Option<&IpswEntry> {
        self.entries.get(name)
    }

    pub fn contains_file(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    pub fn is_directory(&self, name: &str) -> bool {
        self.directories.contains(name)
    }

    /// Immediate children of `directory` (`""` is the archive root), files and subdirectories.
    pub fn children(&self, directory: &str) -> Vec<(String, bool)> {
        let prefix = if directory.is_empty() {
            String::new()
        } else {
            format!("{directory}/")
        };
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for name in self.entries.keys().chain(self.directories.iter()) {
            let Some(rest) = name.strip_prefix(&prefix) else {
                continue;
            };
            if rest.is_empty() {
                continue;
            }
            let (child, is_directory) = match rest.split_once('/') {
                Some((child, _)) => (child, true),
                None => (rest, self.directories.contains(name)),
            };
            if seen.insert(child.to_string()) {
                out.push((child.to_string(), is_directory));
            }
        }
        out
    }

    /// Entry names equal to `prefix` or below it.
    pub fn names_under<'a>(&'a self, prefix: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        let below = format!("{prefix}/");
        self.entries
            .keys()
            .map(String::as_str)
            .filter(move |name| *name == prefix || name.starts_with(&below))
    }

    pub fn names_with_basename<'a>(
        &'a self,
        basename: &'a str,
    ) -> impl Iterator<Item = &'a str> + 'a {
        self.entries
            .keys()
            .map(String::as_str)
            .filter(move |name| name.rsplit('/').next() == Some(basename))
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    /// Streams one entry to `destination`, verifying its size and CRC-32. The write goes to a
    /// sibling partial file and is renamed into place only once it checks out.
    pub fn extract_file(
        &self,
        name: &str,
        destination: &Path,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<(), IpswError> {
        let entry = self
            .entries
            .get(name)
            .ok_or_else(|| IpswError::Missing(name.to_string()))?;
        if entry.kind != EntryKind::File {
            return Err(IpswError::Unsupported(format!(
                "{name} is not a regular file"
            )));
        }
        let mut reader = self.open_entry(name, entry)?;
        let partial = partial_path(destination);
        let outcome = (|| {
            let mut out = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode_private()
                .open(&partial)
                .map_err(io_error(format!("could not create {}", partial.display())))?;
            let mut crc = Crc::new();
            let mut buffer = vec![0u8; COPY_BUFFER];
            let mut written = 0u64;
            let mut reported = 0u64;
            loop {
                let read = reader
                    .read(&mut buffer)
                    .map_err(|error| IpswError::Corrupt(format!("{name}: {error}")))?;
                if read == 0 {
                    break;
                }
                if written + read as u64 > entry.size {
                    return Err(IpswError::Corrupt(format!(
                        "{name} is larger than the {} bytes the directory says",
                        entry.size
                    )));
                }
                crc.update(&buffer[..read]);
                out.write_all(&buffer[..read])
                    .map_err(io_error(format!("could not write {}", partial.display())))?;
                written += read as u64;
                if written - reported >= PROGRESS_STEP {
                    reported = written;
                    progress(written, entry.size);
                }
            }
            if written != entry.size {
                return Err(IpswError::Corrupt(format!(
                    "{name} is {written} bytes, the directory says {}",
                    entry.size
                )));
            }
            if crc.sum() != entry.crc32 {
                return Err(IpswError::Corrupt(format!(
                    "{name} failed its CRC-32 check"
                )));
            }
            out.flush()
                .map_err(io_error(format!("could not flush {}", partial.display())))?;
            drop(out);
            let permissions = if entry.mode & 0o111 != 0 {
                0o755
            } else {
                0o644
            };
            fs::set_permissions(&partial, fs::Permissions::from_mode(permissions)).map_err(
                io_error(format!(
                    "could not set permissions on {}",
                    partial.display()
                )),
            )?;
            fs::rename(&partial, destination).map_err(io_error(format!(
                "could not place {}",
                destination.display()
            )))?;
            progress(written, entry.size);
            Ok(())
        })();
        if outcome.is_err() {
            let _ = fs::remove_file(&partial);
        }
        outcome
    }

    /// The link target of a symlink entry.
    pub fn symlink_target(&self, name: &str) -> Result<String, IpswError> {
        let entry = self
            .entries
            .get(name)
            .ok_or_else(|| IpswError::Missing(name.to_string()))?;
        if entry.kind != EntryKind::Symlink {
            return Err(IpswError::Unsupported(format!("{name} is not a symlink")));
        }
        if entry.size > MAX_SYMLINK_TARGET {
            return Err(IpswError::Unsafe(format!(
                "{name} has an oversized link target"
            )));
        }
        let reader = self.open_entry(name, entry)?;
        let mut bytes = Vec::new();
        reader
            .take(MAX_SYMLINK_TARGET + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| IpswError::Corrupt(format!("{name}: {error}")))?;
        let mut crc = Crc::new();
        crc.update(&bytes);
        if bytes.len() as u64 != entry.size || crc.sum() != entry.crc32 {
            return Err(IpswError::Corrupt(format!(
                "{name} failed its integrity check"
            )));
        }
        String::from_utf8(bytes)
            .map_err(|_| IpswError::Unsafe(format!("{name} has a non-UTF-8 link target")))
    }

    fn open_entry(&self, name: &str, entry: &IpswEntry) -> Result<Box<dyn Read>, IpswError> {
        if entry.flags & FLAG_ENCRYPTED != 0 {
            return Err(IpswError::Unsupported(format!(
                "{name} is password protected"
            )));
        }
        let mut file = File::open(&self.archive).map_err(io_error(format!(
            "could not open {}",
            self.archive.display()
        )))?;
        let header = read_at(&mut file, entry.local_header_offset, LOCAL_FIXED_LEN as u64)
            .map_err(|_| IpswError::Corrupt(format!("{name} has no local header")))?;
        if u32_at(&header, 0) != LOCAL_SIGNATURE {
            return Err(IpswError::Corrupt(format!("{name} has a bad local header")));
        }
        let name_len = u64::from(u16_at(&header, 26));
        let extra_len = u64::from(u16_at(&header, 28));
        let data_offset = entry
            .local_header_offset
            .checked_add(LOCAL_FIXED_LEN as u64 + name_len + extra_len)
            .ok_or_else(|| IpswError::Corrupt(format!("{name} has an overflowing data offset")))?;
        file.seek(SeekFrom::Start(data_offset))
            .map_err(io_error("could not seek in the IPSW"))?;
        let bounded = file.take(entry.compressed_size);
        match entry.method {
            METHOD_STORED => Ok(Box::new(bounded)),
            METHOD_DEFLATE => Ok(Box::new(DeflateDecoder::new(io::BufReader::with_capacity(
                COPY_BUFFER,
                bounded,
            )))),
            other => Err(IpswError::Unsupported(format!(
                "{name} uses compression method {other}"
            ))),
        }
    }
}

trait PrivateMode {
    fn mode_private(&mut self) -> &mut Self;
}

impl PrivateMode for fs::OpenOptions {
    fn mode_private(&mut self) -> &mut Self {
        std::os::unix::fs::OpenOptionsExt::mode(self, 0o600)
    }
}

fn partial_path(destination: &Path) -> PathBuf {
    let mut name = destination
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".part");
    destination.with_file_name(name)
}

struct CentralDirectory {
    offset: u64,
    size: u64,
    count: u64,
}

fn read_at(file: &mut File, offset: u64, length: u64) -> io::Result<Vec<u8>> {
    let length = usize::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "read too large"))?;
    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0u8; length];
    file.read_exact(&mut buffer)?;
    Ok(buffer)
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(raw)
}

fn locate_central_directory(file: &mut File, length: u64) -> Result<CentralDirectory, IpswError> {
    let not_zip = |reason: &str| IpswError::NotAnArchive(reason.to_string());
    if length < EOCD_FIXED_LEN as u64 {
        return Err(not_zip("the file is too small to be a zip archive"));
    }
    let window = length.min(EOCD_FIXED_LEN as u64 + MAX_COMMENT_LEN);
    let window_start = length - window;
    let tail = read_at(file, window_start, window)
        .map_err(io_error("could not read the end of the IPSW"))?;
    let eocd_at = (0..=tail.len() - EOCD_FIXED_LEN)
        .rev()
        .find(|&at| {
            u32_at(&tail, at) == EOCD_SIGNATURE
                && at + EOCD_FIXED_LEN + usize::from(u16_at(&tail, at + 20)) == tail.len()
        })
        .ok_or_else(|| not_zip("no end-of-central-directory record"))?;
    let eocd_offset = window_start + eocd_at as u64;
    let entries = u64::from(u16_at(&tail, eocd_at + 10));
    let size = u64::from(u32_at(&tail, eocd_at + 12));
    let offset = u64::from(u32_at(&tail, eocd_at + 16));
    let needs_zip64 = entries == 0xFFFF || size == 0xFFFF_FFFF || offset == 0xFFFF_FFFF;
    if !needs_zip64 {
        return checked_directory(offset, size, entries, eocd_offset);
    }
    if eocd_offset < EOCD64_LOCATOR_LEN {
        return Err(not_zip("zip64 record is missing"));
    }
    let locator = read_at(file, eocd_offset - EOCD64_LOCATOR_LEN, EOCD64_LOCATOR_LEN)
        .map_err(io_error("could not read the zip64 locator"))?;
    if u32_at(&locator, 0) != EOCD64_LOCATOR_SIGNATURE {
        return Err(not_zip("zip64 locator is missing"));
    }
    let record_offset = u64_at(&locator, 8);
    if record_offset.saturating_add(EOCD64_FIXED_LEN as u64) > eocd_offset {
        return Err(not_zip("zip64 record is out of range"));
    }
    let record = read_at(file, record_offset, EOCD64_FIXED_LEN as u64)
        .map_err(io_error("could not read the zip64 record"))?;
    if u32_at(&record, 0) != EOCD64_SIGNATURE {
        return Err(not_zip("zip64 record is missing"));
    }
    checked_directory(
        u64_at(&record, 48),
        u64_at(&record, 40),
        u64_at(&record, 32),
        record_offset,
    )
}

fn checked_directory(
    offset: u64,
    size: u64,
    count: u64,
    end_of_directory: u64,
) -> Result<CentralDirectory, IpswError> {
    if size > MAX_CENTRAL_DIRECTORY_BYTES || count > MAX_ENTRIES {
        return Err(IpswError::NotAnArchive(
            "the central directory is implausibly large".into(),
        ));
    }
    if offset
        .checked_add(size)
        .is_none_or(|end| end > end_of_directory)
    {
        return Err(IpswError::NotAnArchive(
            "the central directory lies outside the archive".into(),
        ));
    }
    Ok(CentralDirectory {
        offset,
        size,
        count,
    })
}

fn parse_central_directory(
    raw: &[u8],
    count: u64,
) -> Result<(BTreeMap<String, IpswEntry>, BTreeSet<String>), IpswError> {
    let corrupt = |reason: &str| IpswError::NotAnArchive(reason.to_string());
    let mut entries = BTreeMap::new();
    let mut directories = BTreeSet::new();
    let mut at = 0usize;
    for _ in 0..count {
        if raw.len() < at + CENTRAL_FIXED_LEN || u32_at(raw, at) != CENTRAL_SIGNATURE {
            return Err(corrupt("a central directory record is damaged"));
        }
        let made_by_host = (u16_at(raw, at + 4) >> 8) as u8;
        let flags = u16_at(raw, at + 8);
        let method = u16_at(raw, at + 10);
        let crc32 = u32_at(raw, at + 16);
        let mut compressed = u64::from(u32_at(raw, at + 20));
        let mut size = u64::from(u32_at(raw, at + 24));
        let name_len = usize::from(u16_at(raw, at + 28));
        let extra_len = usize::from(u16_at(raw, at + 30));
        let comment_len = usize::from(u16_at(raw, at + 32));
        let external = u32_at(raw, at + 38);
        let mut offset = u64::from(u32_at(raw, at + 42));
        let name_at = at + CENTRAL_FIXED_LEN;
        let extra_at = name_at + name_len;
        let next = extra_at + extra_len + comment_len;
        if raw.len() < next {
            return Err(corrupt(
                "a central directory record runs past the directory",
            ));
        }
        let name_bytes = &raw[name_at..extra_at];
        let extra = &raw[extra_at..extra_at + extra_len];
        if size == 0xFFFF_FFFF || compressed == 0xFFFF_FFFF || offset == 0xFFFF_FFFF {
            apply_zip64_extra(extra, &mut size, &mut compressed, &mut offset)?;
        }
        at = next;

        let raw_name = std::str::from_utf8(name_bytes)
            .map_err(|_| IpswError::Unsafe("an entry name is not UTF-8".into()))?;
        let mode = if made_by_host == UNIX_HOST {
            external >> 16
        } else {
            0
        };
        let is_directory =
            raw_name.ends_with('/') || (mode & MODE_TYPE_MASK == MODE_DIRECTORY && mode != 0);
        if raw_name.starts_with("__MACOSX/") || raw_name == "__MACOSX" {
            continue;
        }
        let name = sanitize_name(raw_name)?;
        if is_directory {
            insert_directories(&mut directories, &name, true);
            continue;
        }
        let kind = if mode & MODE_TYPE_MASK == MODE_SYMLINK {
            EntryKind::Symlink
        } else {
            EntryKind::File
        };
        insert_directories(&mut directories, &name, false);
        let entry = IpswEntry {
            kind,
            size,
            compressed_size: compressed,
            crc32,
            method,
            flags,
            local_header_offset: offset,
            mode,
        };
        if entries.insert(name.clone(), entry).is_some() {
            return Err(IpswError::Unsafe(format!("{name} appears twice")));
        }
    }
    if let Some(clash) = entries.keys().find(|name| directories.contains(*name)) {
        return Err(IpswError::Unsafe(format!(
            "{clash} is both a file and a directory"
        )));
    }
    Ok((entries, directories))
}

fn apply_zip64_extra(
    extra: &[u8],
    size: &mut u64,
    compressed: &mut u64,
    offset: &mut u64,
) -> Result<(), IpswError> {
    let bad = || IpswError::NotAnArchive("a zip64 extra field is damaged".into());
    let mut at = 0usize;
    while at + 4 <= extra.len() {
        let id = u16_at(extra, at);
        let len = usize::from(u16_at(extra, at + 2));
        let body = extra.get(at + 4..at + 4 + len).ok_or_else(bad)?;
        at += 4 + len;
        if id != 0x0001 {
            continue;
        }
        let mut cursor = 0usize;
        for field in [&mut *size, &mut *compressed, &mut *offset] {
            if *field == 0xFFFF_FFFF {
                let value = body.get(cursor..cursor + 8).ok_or_else(bad)?;
                *field = u64_at(value, 0);
                cursor += 8;
            }
        }
        return Ok(());
    }
    Err(bad())
}

fn sanitize_name(raw: &str) -> Result<String, IpswError> {
    let trimmed = raw.trim_end_matches('/');
    if trimmed.is_empty()
        || trimmed.contains('\0')
        || trimmed.contains('\\')
        || trimmed.starts_with('/')
    {
        return Err(IpswError::Unsafe(format!("{raw:?}")));
    }
    for component in trimmed.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(IpswError::Unsafe(format!("{raw:?}")));
        }
    }
    Ok(trimmed.to_string())
}

fn insert_directories(directories: &mut BTreeSet<String>, name: &str, include_self: bool) {
    let mut end = 0usize;
    for (index, ch) in name.char_indices() {
        if ch == '/' {
            end = index;
            directories.insert(name[..end].to_string());
        }
    }
    let _ = end;
    if include_self {
        directories.insert(name.to_string());
    }
}

/// Locates the `ipsw` command-line tool: `PATH` first, then the usual package-manager prefixes.
pub fn find_ipsw_cli() -> Option<PathBuf> {
    let from_path = std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .unwrap_or_default();
    let fallbacks = ["/opt/homebrew/bin", "/usr/local/bin"].map(PathBuf::from);
    from_path
        .into_iter()
        .chain(fallbacks)
        .map(|dir| dir.join(IPSW_CLI_NAME))
        .find(|candidate| {
            fs::metadata(candidate)
                .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        })
}

/// The tree plus a private directory that files are pulled into on demand. Dropping the stage
/// removes every file it wrote.
pub struct IpswStage {
    tree: IpswTree,
    _guard: ScratchDir,
    root: PathBuf,
    staged: Mutex<BTreeSet<String>>,
    decrypted: Mutex<BTreeMap<String, String>>,
    cli: Option<PathBuf>,
}

impl fmt::Debug for IpswStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpswStage")
            .field("archive", &self.tree.archive)
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl IpswStage {
    pub fn open(archive: &Path) -> Result<Self, IpswError> {
        Self::open_with_cli(archive, find_ipsw_cli())
    }

    pub fn open_with_cli(archive: &Path, cli: Option<PathBuf>) -> Result<Self, IpswError> {
        let tree = IpswTree::open(archive)?;
        if !tree.contains_file(BUILD_MANIFEST) {
            return Err(IpswError::NotAnArchive(format!(
                "{BUILD_MANIFEST} is not at the top of the archive"
            )));
        }
        let root = ScratchDir::new("apple-utils-ipsw-")
            .map_err(io_error("could not create the IPSW staging directory"))?;
        let canonical_root = fs::canonicalize(root.path())
            .map_err(io_error("could not resolve the IPSW staging directory"))?;
        Ok(Self {
            tree,
            root: canonical_root,
            _guard: root,
            staged: Mutex::new(BTreeSet::new()),
            decrypted: Mutex::new(BTreeMap::new()),
            cli,
        })
    }

    pub fn tree(&self) -> &IpswTree {
        &self.tree
    }

    /// Directory that holds whatever has been staged so far, laid out like an extracted IPSW.
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn has_cli(&self) -> bool {
        self.cli.is_some()
    }

    pub fn staged_path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    pub fn is_staged(&self, name: &str) -> bool {
        self.staged.lock().expect("stage lock").contains(name)
    }

    pub fn stage(&self, name: &str) -> Result<PathBuf, IpswError> {
        self.stage_with_progress(name, &mut |_, _| {})
    }

    pub fn stage_with_progress(
        &self,
        name: &str,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<PathBuf, IpswError> {
        let destination = self.staged_path(name);
        let mut staged = self.staged.lock().expect("stage lock");
        if staged.contains(name) {
            return Ok(destination);
        }
        let entry = self
            .tree
            .entry(name)
            .ok_or_else(|| IpswError::Missing(name.to_string()))?;
        self.ensure_parent(&destination)?;
        match entry.kind {
            EntryKind::File => self.tree.extract_file(name, &destination, progress)?,
            EntryKind::Symlink => {
                let target = self.tree.symlink_target(name)?;
                validate_link_target(name, &target)?;
                symlink(&target, &destination).map_err(io_error(format!(
                    "could not create {}",
                    destination.display()
                )))?;
                if let Ok(resolved) = fs::canonicalize(&destination)
                    && !resolved.starts_with(&self.root)
                {
                    let _ = fs::remove_file(&destination);
                    return Err(IpswError::Unsafe(format!(
                        "{name} links to {target:?}, which leaves the staging directory"
                    )));
                }
            }
        }
        staged.insert(name.to_string());
        Ok(destination)
    }

    /// Creates the directories above `destination` one component at a time, refusing any that
    /// resolves, through a symlink or otherwise, to somewhere outside the staging root.
    fn ensure_parent(&self, destination: &Path) -> Result<(), IpswError> {
        let Some(parent) = destination.parent() else {
            return Ok(());
        };
        let relative = parent
            .strip_prefix(&self.root)
            .map_err(|_| IpswError::Unsafe(format!("{} is outside the stage", parent.display())))?;
        let mut current = self.root.clone();
        for component in relative.components() {
            let Component::Normal(part) = component else {
                return Err(IpswError::Unsafe(format!(
                    "{} is not a plain path",
                    parent.display()
                )));
            };
            current.push(part);
            match fs::symlink_metadata(&current) {
                Ok(_) => {
                    let resolved = fs::canonicalize(&current)
                        .map_err(io_error(format!("could not resolve {}", current.display())))?;
                    if !resolved.starts_with(&self.root) || !resolved.is_dir() {
                        return Err(IpswError::Unsafe(format!(
                            "{} leaves the staging directory",
                            current.display()
                        )));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    fs::create_dir(&current)
                        .map_err(io_error(format!("could not create {}", current.display())))?;
                }
                Err(error) => {
                    return Err(
                        io_error(format!("could not inspect {}", current.display()))(error),
                    );
                }
            }
        }
        Ok(())
    }

    /// Stages `prefix` and everything below it, returning how many entries were written.
    pub fn stage_tree(&self, prefix: &str) -> Result<usize, IpswError> {
        let names: Vec<String> = self.tree.names_under(prefix).map(str::to_string).collect();
        for name in &names {
            self.stage(name)?;
        }
        Ok(names.len())
    }

    /// Writes the plain disk image for an `.aea` entry by running `ipsw fw aea` on a temporary
    /// copy, then drops that copy. The result sits beside where the encrypted file would be,
    /// named without the `.aea` suffix.
    pub fn decrypt(&self, name: &str) -> Result<PathBuf, IpswError> {
        let plain_name = name
            .strip_suffix(AEA_SUFFIX)
            .filter(|plain| !plain.is_empty() && !plain.ends_with('/'))
            .ok_or_else(|| IpswError::Unsupported(format!("{name} is not an .aea file")))?
            .to_string();
        let destination = self.staged_path(&plain_name);
        if self
            .decrypted
            .lock()
            .expect("stage lock")
            .contains_key(name)
        {
            return Ok(destination);
        }
        let cli = self.cli.as_ref().ok_or(IpswError::NoCli)?;
        let entry = self
            .tree
            .entry(name)
            .ok_or_else(|| IpswError::Missing(name.to_string()))?;
        if entry.kind != EntryKind::File {
            return Err(IpswError::Unsupported(format!(
                "{name} is not a regular file"
            )));
        }
        let work = self.root.join(DECRYPT_WORK_DIR);
        let result = (|| {
            let input_dir = work.join("in");
            let output_dir = work.join("out");
            fs::create_dir_all(&input_dir)
                .and_then(|()| fs::create_dir_all(&output_dir))
                .map_err(io_error("could not create the decryption directory"))?;
            let base = name.rsplit('/').next().unwrap_or(name);
            let input = input_dir.join(base);
            self.tree.extract_file(name, &input, &mut |_, _| {})?;
            let output = Command::new(cli)
                .arg("--no-color")
                .args(["fw", "aea"])
                .arg(&input)
                .arg("-o")
                .arg(&output_dir)
                .output()
                .map_err(io_error(format!("could not run {}", cli.display())))?;
            if !output.status.success() {
                return Err(IpswError::Cli(format!(
                    "{} (exit {})",
                    String::from_utf8_lossy(&output.stderr).trim(),
                    output
                        .status
                        .code()
                        .map_or_else(|| "signal".into(), |c| c.to_string())
                )));
            }
            let plain_base = base.strip_suffix(AEA_SUFFIX).unwrap_or(base);
            let produced = output_dir.join(plain_base);
            if !fs::metadata(&produced).is_ok_and(|meta| meta.is_file() && meta.len() > 0) {
                return Err(IpswError::Cli(format!(
                    "no decrypted {plain_base} was produced for {name}"
                )));
            }
            fs::remove_file(&input).map_err(io_error("could not drop the encrypted copy"))?;
            self.ensure_parent(&destination)?;
            fs::rename(&produced, &destination).map_err(io_error(format!(
                "could not place {}",
                destination.display()
            )))?;
            Ok(())
        })();
        let _ = fs::remove_dir_all(&work);
        result?;
        self.decrypted
            .lock()
            .expect("stage lock")
            .insert(name.to_string(), plain_name);
        Ok(destination)
    }

    /// Removes one staged file so its disk space is returned once nothing else holds it. A later
    /// `stage` call writes it again.
    pub fn release(&self, name: &str) {
        let removed_plain = {
            let mut decrypted = self.decrypted.lock().expect("stage lock");
            decrypted.remove(name)
        };
        if let Some(plain) = removed_plain {
            let _ = fs::remove_file(self.staged_path(&plain));
        }
        let mut staged = self.staged.lock().expect("stage lock");
        if staged.remove(name) {
            let _ = fs::remove_file(self.staged_path(name));
        }
    }

    /// Removes everything staged but keeps the stage usable.
    pub fn release_all(&self) {
        let names: Vec<String> = {
            let staged = self.staged.lock().expect("stage lock");
            let decrypted = self.decrypted.lock().expect("stage lock");
            staged.iter().chain(decrypted.keys()).cloned().collect()
        };
        for name in names {
            self.release(&name);
        }
    }
}

fn validate_link_target(name: &str, target: &str) -> Result<(), IpswError> {
    let bad = || IpswError::Unsafe(format!("{name} links to {target:?}"));
    if target.is_empty() || target.contains('\0') || target.starts_with('/') {
        return Err(bad());
    }
    let mut depth = Path::new(name).components().count() as i64 - 1;
    for component in Path::new(target).components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir => depth -= 1,
            _ => return Err(bad()),
        }
        if depth < 0 {
            return Err(bad());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::DeflateEncoder;

    struct TestEntry {
        name: &'static str,
        data: Vec<u8>,
        deflate: bool,
        mode: u32,
    }

    fn file(name: &'static str, data: &[u8], deflate: bool) -> TestEntry {
        TestEntry {
            name,
            data: data.to_vec(),
            deflate,
            mode: 0o100_644,
        }
    }

    fn crc_of(data: &[u8]) -> u32 {
        let mut crc = Crc::new();
        crc.update(data);
        crc.sum()
    }

    /// A small zip writer so the reader is tested against bytes it did not produce.
    fn build_zip(entries: &[TestEntry], zip64: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for entry in entries {
            let (method, body) = if entry.deflate {
                let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(&entry.data).unwrap();
                (8u16, encoder.finish().unwrap())
            } else {
                (0u16, entry.data.clone())
            };
            let crc = crc_of(&entry.data);
            let offset = out.len() as u64;
            out.extend_from_slice(&LOCAL_SIGNATURE.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&(entry.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(entry.name.as_bytes());
            out.extend_from_slice(&body);

            let extra = if zip64 {
                let mut extra = Vec::new();
                extra.extend_from_slice(&1u16.to_le_bytes());
                extra.extend_from_slice(&24u16.to_le_bytes());
                extra.extend_from_slice(&(entry.data.len() as u64).to_le_bytes());
                extra.extend_from_slice(&(body.len() as u64).to_le_bytes());
                extra.extend_from_slice(&offset.to_le_bytes());
                extra
            } else {
                Vec::new()
            };
            let (size32, comp32, off32) = if zip64 {
                (0xFFFF_FFFFu32, 0xFFFF_FFFFu32, 0xFFFF_FFFFu32)
            } else {
                (entry.data.len() as u32, body.len() as u32, offset as u32)
            };
            central.extend_from_slice(&CENTRAL_SIGNATURE.to_le_bytes());
            central.extend_from_slice(&((u16::from(UNIX_HOST) << 8) | 20).to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&[0; 4]);
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&comp32.to_le_bytes());
            central.extend_from_slice(&size32.to_le_bytes());
            central.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
            central.extend_from_slice(&(extra.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&(entry.mode << 16).to_le_bytes());
            central.extend_from_slice(&off32.to_le_bytes());
            central.extend_from_slice(entry.name.as_bytes());
            central.extend_from_slice(&extra);
        }
        let central_offset = out.len() as u64;
        out.extend_from_slice(&central);
        if zip64 {
            let record_offset = out.len() as u64;
            out.extend_from_slice(&EOCD64_SIGNATURE.to_le_bytes());
            out.extend_from_slice(&44u64.to_le_bytes());
            out.extend_from_slice(&45u16.to_le_bytes());
            out.extend_from_slice(&45u16.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
            out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
            out.extend_from_slice(&(central.len() as u64).to_le_bytes());
            out.extend_from_slice(&central_offset.to_le_bytes());
            out.extend_from_slice(&EOCD64_LOCATOR_SIGNATURE.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&record_offset.to_le_bytes());
            out.extend_from_slice(&1u32.to_le_bytes());
        }
        out.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        let (count16, size32, off32) = if zip64 {
            (0xFFFFu16, 0xFFFF_FFFFu32, 0xFFFF_FFFFu32)
        } else {
            (
                entries.len() as u16,
                central.len() as u32,
                central_offset as u32,
            )
        };
        out.extend_from_slice(&count16.to_le_bytes());
        out.extend_from_slice(&count16.to_le_bytes());
        out.extend_from_slice(&size32.to_le_bytes());
        out.extend_from_slice(&off32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn write_zip(dir: &Path, entries: &[TestEntry], zip64: bool) -> PathBuf {
        let path = dir.join("test.ipsw");
        fs::write(&path, build_zip(entries, zip64)).unwrap();
        path
    }

    fn sample() -> Vec<TestEntry> {
        vec![
            file("BuildManifest.plist", b"<plist/>", false),
            file("Firmware/dfu/iBEC.im4p", &vec![7u8; 5000], true),
            file(
                "Firmware/Manifests/restore/a/manifest.plist",
                b"manifest",
                false,
            ),
            file("kernelcache.release.mac14j", &vec![3u8; 100_000], true),
        ]
    }

    #[test]
    fn indexes_the_tree_without_reading_file_data() {
        let dir = tempfile::tempdir().unwrap();
        for zip64 in [false, true] {
            let path = write_zip(dir.path(), &sample(), zip64);
            let tree = IpswTree::open(&path).unwrap();
            assert_eq!(tree.len(), 4);
            assert!(tree.is_directory("Firmware"));
            assert!(tree.is_directory("Firmware/Manifests/restore"));
            assert!(!tree.is_directory("BuildManifest.plist"));
            assert_eq!(
                tree.entry("kernelcache.release.mac14j").unwrap().size,
                100_000
            );
            let mut top = tree.children("");
            top.sort();
            assert_eq!(
                top,
                vec![
                    ("BuildManifest.plist".to_string(), false),
                    ("Firmware".to_string(), true),
                    ("kernelcache.release.mac14j".to_string(), false),
                ]
            );
            assert_eq!(tree.names_under("Firmware").count(), 2);
            assert_eq!(tree.names_with_basename("iBEC.im4p").count(), 1);
        }
    }

    #[test]
    fn stages_only_what_is_asked_for_and_verifies_content() {
        let dir = tempfile::tempdir().unwrap();
        for zip64 in [false, true] {
            let path = write_zip(dir.path(), &sample(), zip64);
            let stage = IpswStage::open_with_cli(&path, None).unwrap();
            assert!(!stage.staged_path("Firmware").exists());
            let staged = stage.stage("Firmware/dfu/iBEC.im4p").unwrap();
            assert_eq!(fs::read(&staged).unwrap(), vec![7u8; 5000]);
            assert!(!stage.staged_path("kernelcache.release.mac14j").exists());
            assert!(stage.is_staged("Firmware/dfu/iBEC.im4p"));
            assert_eq!(stage.stage("Firmware/dfu/iBEC.im4p").unwrap(), staged);
            assert_eq!(stage.stage_tree("Firmware").unwrap(), 2);
            assert!(
                stage
                    .staged_path("Firmware/Manifests/restore/a/manifest.plist")
                    .is_file()
            );
        }
    }

    #[test]
    fn release_returns_the_space_and_allows_restaging() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_zip(dir.path(), &sample(), false);
        let stage = IpswStage::open_with_cli(&path, None).unwrap();
        let staged = stage.stage("kernelcache.release.mac14j").unwrap();
        stage.release("kernelcache.release.mac14j");
        assert!(!staged.exists());
        assert!(!stage.is_staged("kernelcache.release.mac14j"));
        stage.stage("kernelcache.release.mac14j").unwrap();
        stage.release_all();
        assert!(!stage.staged_path("kernelcache.release.mac14j").exists());
    }

    #[test]
    fn dropping_the_stage_removes_its_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_zip(dir.path(), &sample(), false);
        let stage = IpswStage::open_with_cli(&path, None).unwrap();
        stage.stage_tree("Firmware").unwrap();
        let root = stage.root().to_path_buf();
        assert!(root.is_dir());
        drop(stage);
        assert!(!root.exists());
    }

    #[test]
    fn a_failed_crc_leaves_no_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_zip(dir.path(), &sample(), false);
        let mut bytes = fs::read(&path).unwrap();
        let at = bytes
            .windows(12)
            .position(|window| window == b"manifestPK\x03\x04")
            .unwrap();
        bytes[at] ^= 0xFF;
        fs::write(&path, &bytes).unwrap();
        let stage = IpswStage::open_with_cli(&path, None).unwrap();
        let name = "Firmware/Manifests/restore/a/manifest.plist";
        let error = stage.stage(name).unwrap_err();
        assert!(matches!(error, IpswError::Corrupt(_)), "{error}");
        assert!(!stage.staged_path(name).exists());
        assert!(!partial_path(&stage.staged_path(name)).exists());
        assert!(!stage.is_staged(name));
    }

    #[test]
    fn rejects_paths_that_climb_out_of_the_root() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["../escape", "a/../../b", "/abs", "a\\b"] {
            let entries = vec![TestEntry {
                name: Box::leak(name.to_string().into_boxed_str()),
                data: b"x".to_vec(),
                deflate: false,
                mode: 0o100_644,
            }];
            let path = write_zip(dir.path(), &entries, false);
            let error = IpswTree::open(&path).unwrap_err();
            assert!(matches!(error, IpswError::Unsafe(_)), "{name}: {error}");
        }
    }

    #[test]
    fn symlink_entries_become_links_that_stay_inside() {
        let dir = tempfile::tempdir().unwrap();
        let entries = vec![
            file("BuildManifest.plist", b"<plist/>", false),
            file("Bundle/Versions/A/Brain", b"binary", false),
            TestEntry {
                name: "Bundle/Versions/Current",
                data: b"A".to_vec(),
                deflate: false,
                mode: 0o120_755,
            },
            TestEntry {
                name: "Bundle/Evil",
                data: b"../../../outside".to_vec(),
                deflate: false,
                mode: 0o120_755,
            },
        ];
        let path = write_zip(dir.path(), &entries, false);
        let stage = IpswStage::open_with_cli(&path, None).unwrap();
        stage.stage("Bundle/Versions/A/Brain").unwrap();
        stage.stage("Bundle/Versions/Current").unwrap();
        let link = stage.staged_path("Bundle/Versions/Current");
        assert_eq!(fs::read_link(&link).unwrap(), Path::new("A"));
        assert_eq!(fs::read(link.join("Brain")).unwrap(), b"binary");
        assert!(matches!(
            stage.stage("Bundle/Evil").unwrap_err(),
            IpswError::Unsafe(_)
        ));
    }

    #[test]
    fn chained_links_cannot_lead_a_write_out_of_the_stage() {
        let dir = tempfile::tempdir().unwrap();
        let link = |name: &'static str, target: &'static str| TestEntry {
            name,
            data: target.as_bytes().to_vec(),
            deflate: false,
            mode: 0o120_755,
        };
        let entries = vec![
            file("BuildManifest.plist", b"<plist/>", false),
            link("d1/d2/d3/d4/up", "../../../.."),
            link("d1/d2/d3/d4/up2", "up/../../.."),
            link(
                "d1/d2/d3/d4/dangling",
                "up/../../apple-utils-escape-test-absent",
            ),
            link("Q", "d1/d2/d3/d4/dangling"),
            file("q/payload", b"x", false),
        ];
        let path = write_zip(dir.path(), &entries, false);
        let stage = IpswStage::open_with_cli(&path, None).unwrap();
        stage.stage("d1/d2/d3/d4/up").unwrap();
        assert!(matches!(
            stage.stage("d1/d2/d3/d4/up2").unwrap_err(),
            IpswError::Unsafe(_)
        ));
        assert!(!stage.staged_path("d1/d2/d3/d4/up2").exists());
        stage.stage("d1/d2/d3/d4/dangling").unwrap();
        stage.stage("Q").unwrap();
        if let Ok(placed) = stage.stage("q/payload") {
            assert!(fs::canonicalize(placed).unwrap().starts_with(stage.root()));
        }
        let outside = stage
            .root()
            .parent()
            .unwrap()
            .join("apple-utils-escape-test-absent");
        assert!(!outside.exists());
    }

    #[test]
    fn executable_bit_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let entries = vec![
            file("BuildManifest.plist", b"<plist/>", false),
            TestEntry {
                name: "tool",
                data: b"#!/bin/sh".to_vec(),
                deflate: false,
                mode: 0o100_755,
            },
        ];
        let path = write_zip(dir.path(), &entries, false);
        let stage = IpswStage::open_with_cli(&path, None).unwrap();
        let tool = stage.stage("tool").unwrap();
        assert_eq!(
            fs::metadata(tool).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn an_archive_without_a_build_manifest_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_zip(dir.path(), &[file("other.txt", b"x", false)], false);
        assert!(matches!(
            IpswStage::open_with_cli(&path, None).unwrap_err(),
            IpswError::NotAnArchive(_)
        ));
        let junk = dir.path().join("junk.ipsw");
        fs::write(&junk, vec![0u8; 4096]).unwrap();
        assert!(matches!(
            IpswTree::open(&junk).unwrap_err(),
            IpswError::NotAnArchive(_)
        ));
    }

    #[test]
    fn missing_entries_are_reported_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_zip(dir.path(), &sample(), false);
        let stage = IpswStage::open_with_cli(&path, None).unwrap();
        assert!(matches!(
            stage.stage("nope").unwrap_err(),
            IpswError::Missing(name) if name == "nope"
        ));
    }

    #[test]
    fn decrypting_without_the_cli_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let entries = vec![
            file("BuildManifest.plist", b"<plist/>", false),
            file("OS.dmg.aea", b"AEA1....", false),
        ];
        let path = write_zip(dir.path(), &entries, false);
        let stage = IpswStage::open_with_cli(&path, None).unwrap();
        assert!(matches!(
            stage.decrypt("OS.dmg.aea").unwrap_err(),
            IpswError::NoCli
        ));
        assert!(matches!(
            stage.decrypt("BuildManifest.plist").unwrap_err(),
            IpswError::Unsupported(_)
        ));
    }

    #[test]
    fn decryption_runs_the_cli_on_a_temp_copy_and_keeps_only_the_plain_image() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("fake-ipsw");
        // Mimics `ipsw --no-color fw aea IN -o OUT`: writes OUT/<IN without .aea>.
        fs::write(
            &fake,
            "#!/bin/sh\nin=\"$4\"\nout=\"$6\"\nb=$(basename \"$in\")\ncp \"$in\" \"$out/${b%.aea}\"\n",
        )
        .unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        let entries = vec![
            file("BuildManifest.plist", b"<plist/>", false),
            file("Sub/OS.dmg.aea", b"pretend-plain-image", false),
        ];
        let path = write_zip(dir.path(), &entries, false);
        let stage = IpswStage::open_with_cli(&path, Some(fake)).unwrap();
        let plain = stage.decrypt("Sub/OS.dmg.aea").unwrap();
        assert_eq!(plain, stage.staged_path("Sub/OS.dmg"));
        assert_eq!(fs::read(&plain).unwrap(), b"pretend-plain-image");
        assert!(!stage.staged_path("Sub/OS.dmg.aea").exists());
        assert!(!stage.root().join(DECRYPT_WORK_DIR).exists());
        assert_eq!(stage.decrypt("Sub/OS.dmg.aea").unwrap(), plain);
        stage.release("Sub/OS.dmg.aea");
        assert!(!plain.exists());
    }
}
