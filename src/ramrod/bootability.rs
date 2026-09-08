use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::bulk::{
    DEFAULT_DATA_PORT_ATTEMPT_TIMEOUT, DEFAULT_DATA_PORT_RETRY_INTERVAL, DEFAULT_DATA_PORT_WINDOW,
};
use super::cpio::{CpioError, CpioFileMeta, CpioWriter};
use super::dial::{Clock, DialPlan, GuestDialer, SystemClock, dial_until};
use super::message::{DataRequest, DataType};
use super::provider::{BulkOutcome, BulkTransferService, ProviderError};

pub const BOOTABILITY_BUNDLE_DATA_TYPE: &str = "BootabilityBundle";

pub const BUNDLE_ROOT_DIR: &str = "BootabilityBundle";

pub const BUNDLE_RESTORE_DIR: &str = "Restore";

pub const BUNDLE_CONTENT_DIR: &str = "Bootability";

pub const BUNDLE_FIRMWARE_DIR: &str = "Firmware";

pub const BUNDLE_TRUST_CACHE_SOURCE_NAME: &str = "Bootability.dmg.trustcache";

pub const BUNDLE_TRUST_CACHE_MEMBER_NAME: &str = "Bootability.trustcache";

pub const BUNDLE_MEMBER_UID: u32 = 0;

pub const BUNDLE_MEMBER_GID: u32 = 0;

#[must_use]
pub fn is_bootability_bundle(data_type: &DataType) -> bool {
    data_type.wire_name() == BOOTABILITY_BUNDLE_DATA_TYPE
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BundleMemberKind {
    Directory,
    RegularFile { size: u64 },
    Symlink { target: String },
}

impl BundleMemberKind {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::RegularFile { .. } => "file",
            Self::Symlink { .. } => "symlink",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleMember {
    pub relative: String,
    pub path: PathBuf,
    pub kind: BundleMemberKind,
    pub mode: u32,
    pub mtime: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BundleArchiveSummary {
    pub bytes: u64,
    pub members: u64,
    pub directories: u64,
    pub files: u64,
    pub symlinks: u64,
    pub content_bytes: u64,
}

#[derive(Debug)]
pub enum BootabilityError {
    RootMissing {
        root: PathBuf,
    },
    ContentMissing {
        root: PathBuf,
        looked_for: Vec<PathBuf>,
    },
    ContentEmpty {
        content: PathBuf,
    },
    TrustCacheMissing {
        looked_for: PathBuf,
    },
    NonUtf8Path {
        path: PathBuf,
    },
    UnsupportedMember {
        path: PathBuf,
    },
    Io {
        path: PathBuf,
        error: io::Error,
    },
    Archive(CpioError),
}

impl std::fmt::Display for BootabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RootMissing { root } => write!(
                f,
                "the bootability bundle root {} is not a directory",
                root.display()
            ),
            Self::ContentMissing { root, looked_for } => {
                write!(
                    f,
                    "{} holds no bootability content directory; looked for",
                    root.display()
                )?;
                for (index, candidate) in looked_for.iter().enumerate() {
                    let separator = if index == 0 { " " } else { ", " };
                    write!(f, "{separator}{}", candidate.display())?;
                }
                Ok(())
            }
            Self::ContentEmpty { content } => write!(
                f,
                "the bootability content directory {} is empty, so there is nothing to unpack",
                content.display()
            ),
            Self::TrustCacheMissing { looked_for } => write!(
                f,
                "the bootability trust cache {} is not a file; the reference host copies it into the archive as {BUNDLE_TRUST_CACHE_MEMBER_NAME} and fails the request when that copy fails, so a bundle without it is incomplete",
                looked_for.display()
            ),
            Self::NonUtf8Path { path } => write!(
                f,
                "the bootability member {} has a name that is not valid UTF-8 and cannot be named in a cpio header",
                path.display()
            ),
            Self::UnsupportedMember { path } => write!(
                f,
                "the bootability member {} is neither a directory, a regular file nor a symbolic link",
                path.display()
            ),
            Self::Io { path, error } => {
                write!(f, "reading {}: {error}", path.display())
            }
            Self::Archive(error) => write!(f, "writing the bootability archive: {error}"),
        }
    }
}

impl std::error::Error for BootabilityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { error, .. } => Some(error),
            Self::Archive(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CpioError> for BootabilityError {
    fn from(error: CpioError) -> Self {
        Self::Archive(error)
    }
}

#[derive(Clone, Debug)]
pub struct BootabilityBundleSource {
    root: PathBuf,
    content: PathBuf,
    trust_cache: PathBuf,
}

#[derive(Debug)]
pub struct BundleSearchStep {
    pub candidate: PathBuf,
    pub error: BootabilityError,
}

impl BootabilityBundleSource {
    pub fn resolve(root: &Path) -> Result<Self, BootabilityError> {
        if !root.is_dir() {
            return Err(BootabilityError::RootMissing {
                root: root.to_path_buf(),
            });
        }
        let nested = root.join(BUNDLE_RESTORE_DIR).join(BUNDLE_CONTENT_DIR);
        let beside = root.join(BUNDLE_CONTENT_DIR);
        let content = if nested.is_dir() {
            nested
        } else if beside.is_dir() {
            beside
        } else if root.file_name().and_then(|name| name.to_str()) == Some(BUNDLE_CONTENT_DIR) {
            root.to_path_buf()
        } else {
            return Err(BootabilityError::ContentMissing {
                root: root.to_path_buf(),
                looked_for: vec![nested, beside],
            });
        };
        let mut entries = fs::read_dir(&content).map_err(|error| BootabilityError::Io {
            path: content.clone(),
            error,
        })?;
        if entries.next().is_none() {
            return Err(BootabilityError::ContentEmpty { content });
        }
        let trust_cache = content
            .parent()
            .unwrap_or(Path::new(""))
            .join(BUNDLE_FIRMWARE_DIR)
            .join(BUNDLE_TRUST_CACHE_SOURCE_NAME);
        if !trust_cache.is_file() {
            return Err(BootabilityError::TrustCacheMissing {
                looked_for: trust_cache,
            });
        }
        let source = Self {
            root: root.to_path_buf(),
            content,
            trust_cache,
        };
        source.members()?;
        Ok(source)
    }

    pub fn discover<I>(roots: I) -> Result<Self, Vec<BundleSearchStep>>
    where
        I: IntoIterator<Item = PathBuf>,
    {
        let mut rejected: Vec<BundleSearchStep> = Vec::new();
        for root in roots {
            for candidate in [root.join(BUNDLE_ROOT_DIR), root] {
                if rejected.iter().any(|step| step.candidate == candidate) {
                    continue;
                }
                match Self::resolve(&candidate) {
                    Ok(source) => return Ok(source),
                    Err(error) => rejected.push(BundleSearchStep { candidate, error }),
                }
            }
        }
        Err(rejected)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn content(&self) -> &Path {
        &self.content
    }

    #[must_use]
    pub fn trust_cache(&self) -> &Path {
        &self.trust_cache
    }

    pub fn members(&self) -> Result<Vec<BundleMember>, BootabilityError> {
        let mut members = Vec::new();
        self.collect(&self.content, "", &mut members)?;
        Ok(members)
    }

    fn collect(
        &self,
        directory: &Path,
        prefix: &str,
        members: &mut Vec<BundleMember>,
    ) -> Result<(), BootabilityError> {
        let reader = fs::read_dir(directory).map_err(|error| BootabilityError::Io {
            path: directory.to_path_buf(),
            error,
        })?;
        let mut names = Vec::new();
        for entry in reader {
            let entry = entry.map_err(|error| BootabilityError::Io {
                path: directory.to_path_buf(),
                error,
            })?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| BootabilityError::NonUtf8Path { path: entry.path() })?;
            names.push(name);
        }
        let synthesised_trust_cache = prefix.is_empty()
            && !names
                .iter()
                .any(|name| name == BUNDLE_TRUST_CACHE_MEMBER_NAME);
        if synthesised_trust_cache {
            names.push(BUNDLE_TRUST_CACHE_MEMBER_NAME.to_string());
        }
        names.sort();
        for name in names {
            let path = if synthesised_trust_cache && name == BUNDLE_TRUST_CACHE_MEMBER_NAME {
                self.trust_cache.clone()
            } else {
                directory.join(&name)
            };
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let metadata = fs::symlink_metadata(&path).map_err(|error| BootabilityError::Io {
                path: path.clone(),
                error,
            })?;
            let mode = metadata.permissions().mode() & 0o7777;
            let mtime = modified_seconds(&metadata);
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                let target = fs::read_link(&path).map_err(|error| BootabilityError::Io {
                    path: path.clone(),
                    error,
                })?;
                let target = target
                    .to_str()
                    .ok_or_else(|| BootabilityError::NonUtf8Path { path: path.clone() })?
                    .to_string();
                members.push(BundleMember {
                    relative,
                    path,
                    kind: BundleMemberKind::Symlink { target },
                    mode,
                    mtime,
                });
            } else if file_type.is_dir() {
                members.push(BundleMember {
                    relative: relative.clone(),
                    path: path.clone(),
                    kind: BundleMemberKind::Directory,
                    mode,
                    mtime,
                });
                self.collect(&path, &relative, members)?;
            } else if file_type.is_file() {
                members.push(BundleMember {
                    relative,
                    path,
                    kind: BundleMemberKind::RegularFile {
                        size: metadata.len(),
                    },
                    mode,
                    mtime,
                });
            } else {
                return Err(BootabilityError::UnsupportedMember { path });
            }
        }
        Ok(())
    }

    pub fn write_archive<W: Write>(
        &self,
        out: W,
    ) -> Result<BundleArchiveSummary, BootabilityError> {
        let members = self.members()?;
        let mut writer = CpioWriter::new(out);
        let mut summary = BundleArchiveSummary::default();
        for member in &members {
            let meta = CpioFileMeta {
                mode: member.mode,
                uid: BUNDLE_MEMBER_UID,
                gid: BUNDLE_MEMBER_GID,
                mtime: member.mtime,
            };
            match &member.kind {
                BundleMemberKind::Directory => {
                    writer.write_directory(&member.relative, meta)?;
                    summary.directories += 1;
                }
                BundleMemberKind::Symlink { target } => {
                    writer.write_symlink(&member.relative, target, meta)?;
                    summary.symlinks += 1;
                }
                BundleMemberKind::RegularFile { size } => {
                    let mut file =
                        fs::File::open(&member.path).map_err(|error| BootabilityError::Io {
                            path: member.path.clone(),
                            error,
                        })?;
                    writer.write_file(&member.relative, *size, &mut file, meta)?;
                    summary.files += 1;
                    summary.content_bytes += size;
                }
            }
            summary.members += 1;
        }
        writer.finish()?;
        summary.bytes = writer.bytes_written();
        Ok(summary)
    }
}

fn modified_seconds(metadata: &fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |elapsed| elapsed.as_secs())
}

pub struct BootabilityBundleTransfer<D, C = SystemClock> {
    dialer: D,
    source: Option<BootabilityBundleSource>,
    clock: C,
    attempt_timeout: Duration,
    retry_interval: Duration,
    window: Duration,
    transfers: Vec<BundleArchiveSummary>,
}

impl<D> BootabilityBundleTransfer<D, SystemClock>
where
    D: GuestDialer,
{
    pub fn new(dialer: D, source: Option<BootabilityBundleSource>) -> Self {
        Self {
            dialer,
            source,
            clock: SystemClock,
            attempt_timeout: DEFAULT_DATA_PORT_ATTEMPT_TIMEOUT,
            retry_interval: DEFAULT_DATA_PORT_RETRY_INTERVAL,
            window: DEFAULT_DATA_PORT_WINDOW,
            transfers: Vec::new(),
        }
    }
}

impl<D, C> BootabilityBundleTransfer<D, C>
where
    D: GuestDialer,
    C: Clock,
{
    pub fn with_clock(dialer: D, source: Option<BootabilityBundleSource>, clock: C) -> Self {
        Self {
            dialer,
            source,
            clock,
            attempt_timeout: DEFAULT_DATA_PORT_ATTEMPT_TIMEOUT,
            retry_interval: DEFAULT_DATA_PORT_RETRY_INTERVAL,
            window: DEFAULT_DATA_PORT_WINDOW,
            transfers: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    #[must_use]
    pub fn with_retry(mut self, attempt_timeout: Duration, retry_interval: Duration) -> Self {
        self.attempt_timeout = attempt_timeout;
        self.retry_interval = retry_interval;
        self
    }

    #[must_use]
    pub fn source(&self) -> Option<&BootabilityBundleSource> {
        self.source.as_ref()
    }

    #[must_use]
    pub fn transfers(&self) -> &[BundleArchiveSummary] {
        &self.transfers
    }

    fn plan(&self, port: u16) -> DialPlan {
        DialPlan {
            port,
            attempt_timeout: self.attempt_timeout,
            retry_interval: self.retry_interval,
            window: self.window,
        }
    }
}

impl<D, C> BulkTransferService for BootabilityBundleTransfer<D, C>
where
    D: GuestDialer,
    C: Clock,
{
    fn serve(&mut self, port: u16, request: &DataRequest) -> Result<BulkOutcome, ProviderError> {
        if !is_bootability_bundle(&request.data_type) {
            let reason = format!(
                "the guest opened port {port} for a {} transfer and this service only answers {BOOTABILITY_BUNDLE_DATA_TYPE}",
                request.data_type
            );
            let plan = self.plan(port);
            return Ok(BulkOutcome::Declined {
                reason: match dial_until(&mut self.dialer, plan, &mut self.clock) {
                    Ok(_) => format!(
                        "{reason}; the port was connected and closed with no bytes on it, so the guest reads immediate EOF rather than waiting in accept"
                    ),
                    Err(error) => {
                        format!("{reason}; the port could not be connected either: {error}")
                    }
                },
            });
        }
        let Some(source) = self.source.clone() else {
            let reason = format!(
                "the guest opened port {port} for a {BOOTABILITY_BUNDLE_DATA_TYPE} transfer and no bundle was found under any root this run was given; the bootability-bundle-unresolved line names every directory that was tried and why each was turned down, and --asr-serve-bootability-bundle names one directly, being the IPSW's {BUNDLE_ROOT_DIR} directory whose {BUNDLE_RESTORE_DIR}/{BUNDLE_CONTENT_DIR} subtree and {BUNDLE_RESTORE_DIR}/{BUNDLE_FIRMWARE_DIR}/{BUNDLE_TRUST_CACHE_SOURCE_NAME} are what the guest unpacks"
            );
            let plan = self.plan(port);
            return Ok(BulkOutcome::Declined {
                reason: match dial_until(&mut self.dialer, plan, &mut self.clock) {
                    Ok(_) => format!(
                        "{reason}; the port was connected and closed with no bytes on it, so the guest reads immediate EOF rather than waiting in accept"
                    ),
                    Err(error) => {
                        format!("{reason}; the port could not be connected either: {error}")
                    }
                },
            });
        };

        let plan = self.plan(port);
        let mut outcome = dial_until(&mut self.dialer, plan, &mut self.clock).map_err(|error| {
            ProviderError::Other(format!(
                "the guest named port {port} for its {BOOTABILITY_BUNDLE_DATA_TYPE} request but never accepted: {error}"
            ))
        })?;

        let summary = source
            .write_archive(&mut outcome.stream)
            .map_err(|error| ProviderError::Other(format!("port {port}: {error}")))?;
        outcome.stream.flush().map_err(ProviderError::Io)?;

        self.transfers.push(summary);
        Ok(BulkOutcome::Served {
            bytes: summary.bytes,
            blocks: summary.members,
            initiates: 1,
            metadata_requests: 0,
            oob_requests: 0,
            oob_bytes: 0,
        })
    }
}

pub struct BootabilityRouter<B, F> {
    bundle: B,
    fallback: F,
}

impl<B, F> BootabilityRouter<B, F>
where
    B: BulkTransferService,
    F: BulkTransferService,
{
    pub fn new(bundle: B, fallback: F) -> Self {
        Self { bundle, fallback }
    }

    pub fn bundle(&self) -> &B {
        &self.bundle
    }

    pub fn fallback(&self) -> &F {
        &self.fallback
    }
}

impl<B, F> BulkTransferService for BootabilityRouter<B, F>
where
    B: BulkTransferService,
    F: BulkTransferService,
{
    fn serve(&mut self, port: u16, request: &DataRequest) -> Result<BulkOutcome, ProviderError> {
        if is_bootability_bundle(&request.data_type) {
            self.bundle.serve(port, request)
        } else {
            self.fallback.serve(port, request)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Read;
    use std::os::unix::fs::symlink;

    const ODC_MAGIC: &[u8] = b"070707";
    const ODC_HEADER_LEN: usize = 76;

    fn sample_bundle(root: &Path) -> PathBuf {
        let content = root.join(BUNDLE_RESTORE_DIR).join(BUNDLE_CONTENT_DIR);
        let versions = content.join("BootabilityBrain.framework/Versions/A");
        fs::create_dir_all(versions.join("Resources")).unwrap();
        fs::create_dir_all(content.join("System/Library/CoreServices")).unwrap();
        fs::write(versions.join("BootabilityBrain"), b"MACHO-BINARY").unwrap();
        fs::set_permissions(
            versions.join("BootabilityBrain"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(versions.join("Resources/Info.plist"), b"<plist/>").unwrap();
        fs::write(
            content.join("System/Library/CoreServices/RestoreVersion.plist"),
            b"<plist/>",
        )
        .unwrap();
        symlink(
            "A",
            content.join("BootabilityBrain.framework/Versions/Current"),
        )
        .unwrap();
        symlink(
            "Versions/Current/BootabilityBrain",
            content.join("BootabilityBrain.framework/BootabilityBrain"),
        )
        .unwrap();
        symlink(
            "Versions/Current/Resources",
            content.join("BootabilityBrain.framework/Resources"),
        )
        .unwrap();
        let firmware = root.join(BUNDLE_RESTORE_DIR).join(BUNDLE_FIRMWARE_DIR);
        fs::create_dir_all(&firmware).unwrap();
        fs::write(firmware.join(BUNDLE_TRUST_CACHE_SOURCE_NAME), b"TRUSTCACHE").unwrap();
        content
    }

    fn parse_odc(bytes: &[u8]) -> BTreeMap<String, (u32, Vec<u8>)> {
        let mut out = BTreeMap::new();
        let mut cursor = 0usize;
        loop {
            assert!(cursor + ODC_HEADER_LEN <= bytes.len(), "truncated header");
            let header = &bytes[cursor..cursor + ODC_HEADER_LEN];
            assert_eq!(&header[0..6], ODC_MAGIC, "every header carries the magic");
            let field = |start: usize, width: usize| -> u64 {
                let text = std::str::from_utf8(&header[start..start + width]).unwrap();
                u64::from_str_radix(text, 8).unwrap()
            };
            let mode = field(18, 6) as u32;
            let namesize = field(59, 6) as usize;
            let filesize = field(65, 11) as usize;
            cursor += ODC_HEADER_LEN;
            let name = std::str::from_utf8(&bytes[cursor..cursor + namesize - 1])
                .unwrap()
                .to_string();
            cursor += namesize;
            let body = bytes[cursor..cursor + filesize].to_vec();
            cursor += filesize;
            if name == "TRAILER!!!" {
                assert_eq!(cursor, bytes.len(), "nothing follows the trailer");
                return out;
            }
            out.insert(name, (mode, body));
        }
    }

    #[test]
    fn the_content_directory_is_found_from_the_bundle_root() {
        let dir = tempfile::tempdir().unwrap();
        let content = sample_bundle(dir.path());
        let source = BootabilityBundleSource::resolve(dir.path()).unwrap();
        assert_eq!(source.content(), content.as_path());
        assert_eq!(source.root(), dir.path());
    }

    #[test]
    fn the_content_directory_is_found_from_the_restore_directory_and_from_itself() {
        let dir = tempfile::tempdir().unwrap();
        let content = sample_bundle(dir.path());
        let from_restore =
            BootabilityBundleSource::resolve(&dir.path().join(BUNDLE_RESTORE_DIR)).unwrap();
        assert_eq!(from_restore.content(), content.as_path());
        let from_content = BootabilityBundleSource::resolve(&content).unwrap();
        assert_eq!(from_content.content(), content.as_path());
    }

    #[test]
    fn a_root_with_no_bootability_content_is_an_error_naming_where_it_looked() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("Firmware")).unwrap();
        let error = BootabilityBundleSource::resolve(dir.path()).unwrap_err();
        match &error {
            BootabilityError::ContentMissing { looked_for, .. } => {
                assert_eq!(looked_for.len(), 2);
                let rendered = error.to_string();
                assert!(rendered.contains(BUNDLE_CONTENT_DIR), "{rendered}");
                assert!(rendered.contains(BUNDLE_RESTORE_DIR), "{rendered}");
            }
            other => panic!("expected ContentMissing, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_content_directory_is_an_error_rather_than_an_archive_of_nothing() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(BUNDLE_RESTORE_DIR).join(BUNDLE_CONTENT_DIR)).unwrap();
        let error = BootabilityBundleSource::resolve(dir.path()).unwrap_err();
        assert!(
            matches!(error, BootabilityError::ContentEmpty { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn a_missing_root_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let error = BootabilityBundleSource::resolve(&dir.path().join("absent")).unwrap_err();
        assert!(
            matches!(error, BootabilityError::RootMissing { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn every_directory_precedes_what_is_inside_it() {
        let dir = tempfile::tempdir().unwrap();
        sample_bundle(dir.path());
        let source = BootabilityBundleSource::resolve(dir.path()).unwrap();
        let members = source.members().unwrap();
        let mut seen: Vec<&str> = Vec::new();
        for member in &members {
            if let Some((parent, _)) = member.relative.rsplit_once('/') {
                assert!(
                    seen.contains(&parent),
                    "{} arrived before its parent {parent}",
                    member.relative
                );
            }
            if matches!(member.kind, BundleMemberKind::Directory) {
                seen.push(&member.relative);
            }
        }
    }

    #[test]
    fn symbolic_links_are_archived_as_links_and_not_as_their_targets() {
        let dir = tempfile::tempdir().unwrap();
        sample_bundle(dir.path());
        let source = BootabilityBundleSource::resolve(dir.path()).unwrap();
        let members = source.members().unwrap();
        let link = members
            .iter()
            .find(|member| member.relative == "BootabilityBrain.framework/BootabilityBrain")
            .expect("the framework's top level binary link is a member");
        assert_eq!(
            link.kind,
            BundleMemberKind::Symlink {
                target: "Versions/Current/BootabilityBrain".to_string()
            }
        );
    }

    #[test]
    fn the_archive_is_portable_cpio_and_carries_every_member() {
        let dir = tempfile::tempdir().unwrap();
        sample_bundle(dir.path());
        let source = BootabilityBundleSource::resolve(dir.path()).unwrap();
        let mut archive = Vec::new();
        let summary = source.write_archive(&mut archive).unwrap();

        assert_eq!(&archive[0..6], ODC_MAGIC, "the guest sniffs this magic");
        let parsed = parse_odc(&archive);
        assert_eq!(parsed.len() as u64, summary.members);
        assert_eq!(summary.bytes, archive.len() as u64);
        assert_eq!(summary.files, 4);
        assert_eq!(summary.symlinks, 3);
        assert_eq!(summary.content_bytes, 12 + 8 + 8 + 10);

        let (mode, body) = parsed
            .get(BUNDLE_TRUST_CACHE_MEMBER_NAME)
            .expect("the trust cache is in the archive");
        assert_eq!(body, b"TRUSTCACHE");
        assert_eq!(mode & 0o170000, 0o100000, "regular file type bits");

        let (mode, body) = parsed
            .get("BootabilityBrain.framework/Versions/A/BootabilityBrain")
            .expect("the framework binary is in the archive");
        assert_eq!(body, b"MACHO-BINARY");
        assert_eq!(
            mode & 0o7777,
            0o755,
            "the executable bit has to survive, or the framework the guest unpacks will not run"
        );
        assert_eq!(mode & 0o170000, 0o100000, "regular file type bits");

        let (mode, body) = parsed
            .get("BootabilityBrain.framework/Versions/Current")
            .expect("the version link is in the archive");
        assert_eq!(
            body, b"A",
            "a link's body is its target, with no terminator"
        );
        assert_eq!(mode & 0o170000, 0o120000, "symbolic link type bits");

        let (mode, body) = parsed
            .get("BootabilityBrain.framework/Versions")
            .expect("the intermediate directory is in the archive");
        assert!(body.is_empty(), "a directory carries no data");
        assert_eq!(mode & 0o170000, 0o040000, "directory type bits");
    }

    #[test]
    fn the_archive_is_not_compressed() {
        let dir = tempfile::tempdir().unwrap();
        sample_bundle(dir.path());
        let source = BootabilityBundleSource::resolve(dir.path()).unwrap();
        let mut archive = Vec::new();
        source.write_archive(&mut archive).unwrap();
        assert_eq!(&archive[0..6], ODC_MAGIC);
        assert_ne!(&archive[0..2], b"\x1f\x8b", "not gzip");
        assert_ne!(&archive[0..4], b"YAA1", "not an Apple Archive");
        assert_ne!(&archive[0..2], b"PK", "not a zip");
    }

    #[test]
    fn two_archives_of_the_same_tree_are_identical() {
        let dir = tempfile::tempdir().unwrap();
        sample_bundle(dir.path());
        let source = BootabilityBundleSource::resolve(dir.path()).unwrap();
        let mut first = Vec::new();
        let mut second = Vec::new();
        source.write_archive(&mut first).unwrap();
        source.write_archive(&mut second).unwrap();
        assert_eq!(first, second);
    }

    struct RecordingDialer {
        ports: Vec<u16>,
        written: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        refuse: bool,
    }

    struct RecordingStream {
        written: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl Read for RecordingStream {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for RecordingStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl GuestDialer for RecordingDialer {
        type Stream = RecordingStream;

        fn dial(&mut self, port: u16, _timeout: Duration) -> io::Result<Self::Stream> {
            self.ports.push(port);
            if self.refuse {
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"));
            }
            Ok(RecordingStream {
                written: std::sync::Arc::clone(&self.written),
            })
        }
    }

    fn bundle_request(port: u16) -> DataRequest {
        DataRequest {
            data_type: DataType::from_wire(BOOTABILITY_BUNDLE_DATA_TYPE),
            data_port: Some(port),
            arguments: plist::Dictionary::new(),
            asynchronous: false,
            async_context_uuid: None,
        }
    }

    #[test]
    fn the_transfer_dials_the_port_the_guest_named_and_pushes_the_archive() {
        let dir = tempfile::tempdir().unwrap();
        sample_bundle(dir.path());
        let source = BootabilityBundleSource::resolve(dir.path()).unwrap();
        let written = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let dialer = RecordingDialer {
            ports: Vec::new(),
            written: std::sync::Arc::clone(&written),
            refuse: false,
        };
        let mut service = BootabilityBundleTransfer::new(dialer, Some(source));

        let outcome = service.serve(51234, &bundle_request(51234)).unwrap();
        match outcome {
            BulkOutcome::Served { bytes, blocks, .. } => {
                let pushed = written.lock().unwrap();
                assert_eq!(bytes, pushed.len() as u64);
                assert!(blocks > 0);
                assert_eq!(&pushed[0..6], ODC_MAGIC);
                let parsed = parse_odc(&pushed);
                assert!(parsed.contains_key("System/Library/CoreServices/RestoreVersion.plist"));
            }
            other => panic!("expected a served transfer, got {other:?}"),
        }
        assert_eq!(service.transfers().len(), 1);
    }

    #[test]
    fn a_run_with_no_bundle_declines_by_name_rather_than_ending_the_session() {
        let written = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let dialer = RecordingDialer {
            ports: Vec::new(),
            written: std::sync::Arc::clone(&written),
            refuse: false,
        };
        let mut service: BootabilityBundleTransfer<RecordingDialer> =
            BootabilityBundleTransfer::new(dialer, None);
        let outcome = service.serve(51234, &bundle_request(51234)).unwrap();
        match outcome {
            BulkOutcome::Declined { reason } => {
                assert!(reason.contains(BOOTABILITY_BUNDLE_DATA_TYPE), "{reason}");
                assert!(
                    reason.contains("--asr-serve-bootability-bundle"),
                    "{reason}"
                );
                assert!(reason.contains("immediate EOF"), "{reason}");
                assert!(reason.contains("bootability-bundle-unresolved"), "{reason}");
            }
            other => panic!("expected a decline, got {other:?}"),
        }
        assert!(written.lock().unwrap().is_empty());
    }

    #[test]
    fn a_type_this_service_does_not_own_is_declined_and_the_port_is_still_released() {
        let dir = tempfile::tempdir().unwrap();
        sample_bundle(dir.path());
        let source = BootabilityBundleSource::resolve(dir.path()).unwrap();
        let written = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let dialer = RecordingDialer {
            ports: Vec::new(),
            written: std::sync::Arc::clone(&written),
            refuse: false,
        };
        let mut service = BootabilityBundleTransfer::new(dialer, Some(source));
        let mut request = bundle_request(51234);
        request.data_type = DataType::RecoveryOSASRImage;
        let outcome = service.serve(51234, &request).unwrap();
        match outcome {
            BulkOutcome::Declined { ref reason } => {
                assert!(reason.contains("immediate EOF"), "{reason}");
            }
            other => panic!("expected a decline, got {other:?}"),
        }
        assert!(written.lock().unwrap().is_empty());
    }

    #[derive(Default)]
    struct CountingService {
        served: Vec<String>,
    }

    impl BulkTransferService for CountingService {
        fn serve(
            &mut self,
            _port: u16,
            request: &DataRequest,
        ) -> Result<BulkOutcome, ProviderError> {
            self.served.push(request.data_type.wire_name().to_string());
            Ok(BulkOutcome::Served {
                bytes: 1,
                blocks: 1,
                initiates: 1,
                metadata_requests: 0,
                oob_requests: 0,
                oob_bytes: 0,
            })
        }
    }

    #[test]
    fn the_router_sends_only_the_bundle_to_the_bundle_service() {
        let mut router =
            BootabilityRouter::new(CountingService::default(), CountingService::default());
        let mut asr = bundle_request(51234);
        asr.data_type = DataType::RecoveryOSASRImage;
        router.serve(51234, &bundle_request(51234)).unwrap();
        router.serve(51235, &asr).unwrap();
        router.serve(51236, &bundle_request(51236)).unwrap();
        assert_eq!(
            router.bundle().served,
            vec![
                BOOTABILITY_BUNDLE_DATA_TYPE.to_string(),
                BOOTABILITY_BUNDLE_DATA_TYPE.to_string()
            ]
        );
        assert_eq!(router.fallback().served, vec!["RecoveryOSASRImage"]);
    }

    #[test]
    fn a_port_that_is_never_accepted_is_a_failure_and_not_a_silent_success() {
        let dir = tempfile::tempdir().unwrap();
        sample_bundle(dir.path());
        let source = BootabilityBundleSource::resolve(dir.path()).unwrap();
        let written = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let dialer = RecordingDialer {
            ports: Vec::new(),
            written,
            refuse: true,
        };
        let mut service = BootabilityBundleTransfer::new(dialer, Some(source))
            .with_window(Duration::from_millis(0));
        let error = service.serve(51234, &bundle_request(51234)).unwrap_err();
        match error {
            ProviderError::Other(reason) => {
                assert!(reason.contains("51234"), "{reason}");
                assert!(reason.contains("never accepted"), "{reason}");
            }
            other => panic!("expected the dial failure, got {other:?}"),
        }
    }
}
