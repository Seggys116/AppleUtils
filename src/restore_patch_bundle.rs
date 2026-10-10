use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::apfs_read::{ApfsContainer, ApfsReadError, VolumeChoice, container_geometry_of};
use crate::apfs_verify::SliceBlocks;
use crate::crypto::sha256;
use crate::ramrod::der;

const RESTORED_EXTERNAL: &str = "/usr/local/bin/restored_external";
const USAGE: &str = "usage: apple-utils patch-restore --bundle PATH [--apply]";

pub fn run(args: &[String]) -> Result<String, String> {
    let mut bundle = None;
    let mut apply = false;
    let mut at = 0;
    while at < args.len() {
        match args[at].as_str() {
            "--bundle" if bundle.is_none() => {
                at += 1;
                bundle = Some(PathBuf::from(args.get(at).ok_or(USAGE)?));
            }
            "--apply" if !apply => apply = true,
            "--help" if args.len() == 1 => return Ok(format!("{USAGE}\n")),
            other => {
                return Err(format!(
                    "unrecognised or repeated argument {other:?}; {USAGE}"
                ));
            }
        }
        at += 1;
    }
    let bundle = bundle.ok_or(USAGE)?;
    run_bundle(&bundle, apply)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct DerField<'a> {
    tag: u8,
    encoded: &'a [u8],
    body: &'a [u8],
}

fn read_der<'a>(bytes: &'a [u8], at: &mut usize) -> Result<DerField<'a>, String> {
    let start = *at;
    let tag = *bytes.get(*at).ok_or("truncated IM4P DER tag")?;
    *at += 1;
    if tag & 0x1f == 0x1f {
        let mut first = true;
        loop {
            let digit = *bytes.get(*at).ok_or("truncated IM4P DER high tag")?;
            if first && digit & 0x7f == 0 {
                return Err("noncanonical IM4P DER high tag".into());
            }
            first = false;
            *at += 1;
            if digit & 0x80 == 0 {
                break;
            }
        }
    }
    let first = *bytes.get(*at).ok_or("truncated IM4P DER length")?;
    *at += 1;
    let length = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() {
            return Err("indefinite or overflowing IM4P DER length".into());
        }
        let end = at.checked_add(count).ok_or("overflowing IM4P DER length")?;
        let digits = bytes.get(*at..end).ok_or("truncated IM4P DER length")?;
        if digits[0] == 0 {
            return Err("noncanonical IM4P DER length".into());
        }
        let mut value = 0usize;
        for digit in digits {
            value = value
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*digit)))
                .ok_or("overflowing IM4P DER length")?;
        }
        if value < 128 {
            return Err("noncanonical IM4P DER long length".into());
        }
        *at = end;
        value
    };
    let end = at.checked_add(length).ok_or("overflowing IM4P DER body")?;
    let body = bytes.get(*at..end).ok_or("truncated IM4P DER body")?;
    *at = end;
    Ok(DerField {
        tag,
        encoded: &bytes[start..end],
        body,
    })
}

struct RestoreMedia<'a> {
    fields: Vec<DerField<'a>>,
}

impl<'a> RestoreMedia<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        let mut at = 0;
        let sequence = read_der(bytes, &mut at)?;
        if sequence.tag != der::IDENTIFIER_SEQUENCE || at != bytes.len() {
            return Err("restore media must be exactly one IM4P DER sequence".into());
        }
        let mut fields = Vec::new();
        at = 0;
        while at < sequence.body.len() {
            fields.push(read_der(sequence.body, &mut at)?);
        }
        if fields.len() < 4
            || fields[0].tag != der::IDENTIFIER_IA5_STRING
            || fields[0].body != b"IM4P"
            || fields[1].tag != der::IDENTIFIER_IA5_STRING
            || fields[1].body != b"rdsk"
            || fields[2].tag != der::IDENTIFIER_IA5_STRING
            || fields[3].tag != der::IDENTIFIER_OCTET_STRING
        {
            return Err("restore media must be an IM4P rdsk with an octet-string payload".into());
        }
        let payload = fields[3].body;
        let (block_size, block_count) = container_geometry_of(payload).map_err(|error| {
            format!("restore media payload is not raw uncompressed APFS: {error}")
        })?;
        let declared = u64::from(block_size)
            .checked_mul(block_count)
            .ok_or("restore media APFS geometry overflows")?;
        if declared > payload.len() as u64 {
            return Err(format!(
                "restore media APFS declares {declared} bytes but payload has {}",
                payload.len()
            ));
        }
        Ok(Self { fields })
    }

    fn payload(&self) -> &'a [u8] {
        self.fields[3].body
    }

    fn replace_payload(&self, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        for (index, field) in self.fields.iter().enumerate() {
            if index == 3 {
                body.extend_from_slice(&der::octet_string(payload));
            } else {
                body.extend_from_slice(field.encoded);
            }
        }
        der::sequence(&body)
    }
}

fn restored_external(image: &[u8]) -> Result<(VolumeChoice, String, Vec<u8>), String> {
    let (block_size, block_count) =
        container_geometry_of(image).map_err(|error| error.to_string())?;
    let mut blocks = SliceBlocks::new(image, block_size);
    let mut container = ApfsContainer::mount(&mut blocks, block_size, block_count)
        .map_err(|error| format!("mount restore media APFS: {error}"))?;
    let volumes = container
        .volumes()
        .map_err(|error| format!("enumerate restore media volumes: {error}"))?;
    let mut matches = Vec::new();
    let mut searched = Vec::new();
    for summary in volumes {
        searched.push(format!("{} (index {})", summary.name, summary.index));
        if summary.encrypted {
            return Err(format!(
                "cannot establish unique {RESTORED_EXTERNAL}: restore media volume {:?} is encrypted",
                summary.name
            ));
        }
        let choice = VolumeChoice::Index(summary.index);
        let volume = container
            .open_volume_chosen(&choice)
            .map_err(|error| error.to_string())?;
        let facts = match container.stat(&volume, RESTORED_EXTERNAL) {
            Ok(facts) => facts,
            Err(ApfsReadError::ComponentNotFound { .. }) => continue,
            Err(error) => {
                return Err(format!(
                    "inspect {RESTORED_EXTERNAL} in volume {:?}: {error}",
                    summary.name
                ));
            }
        };
        if !facts.is_regular_file() {
            return Err(format!(
                "{RESTORED_EXTERNAL} in volume {:?} must be a regular file, mode {:#o}",
                summary.name, facts.mode
            ));
        }
        let mut executable = Vec::new();
        container
            .extract(&volume, RESTORED_EXTERNAL, 0, None, &mut executable)
            .map_err(|error| {
                format!(
                    "extract {RESTORED_EXTERNAL} in volume {:?}: {error}",
                    summary.name
                )
            })?;
        if executable.len() as u64 != facts.readable_size() {
            return Err(format!(
                "{RESTORED_EXTERNAL} logical size mismatch in volume {:?}",
                summary.name
            ));
        }
        matches.push((choice, summary.name, executable));
    }
    if matches.len() != 1 {
        return Err(format!(
            "expected exactly one volume containing {RESTORED_EXTERNAL}, found {}; searched {}",
            matches.len(),
            searched.join(", ")
        ));
    }
    Ok(matches.remove(0))
}

fn configured_path(config: &Value, pointer: &str) -> Result<PathBuf, String> {
    let text = config
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("bundle config must name {pointer}"))?;
    let path = PathBuf::from(text);
    relative_components(&path)?;
    Ok(path)
}

fn relative_components(path: &Path) -> Result<Vec<&std::ffi::OsStr>, String> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(format!(
            "bundle path must be relative and nonempty: {}",
            path.display()
        ));
    }
    path.components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(format!(
                "bundle path contains traversal or a non-normal component: {}",
                path.display()
            )),
        })
        .collect()
}

fn staged_path(original: &Path, bytes: &[u8]) -> Result<PathBuf, String> {
    staged_path_for_hash(original, &sha256(bytes))
}

fn staged_path_for_hash(original: &Path, hash: &[u8; 32]) -> Result<PathBuf, String> {
    let stem = original
        .file_stem()
        .and_then(|name| name.to_str())
        .ok_or("configured bundle filename must be UTF-8")?;
    let extension = original
        .extension()
        .and_then(|extension| extension.to_str());
    let suffix = extension
        .map(|extension| format!(".{extension}"))
        .unwrap_or_default();
    Ok(original.with_file_name(format!("{stem}.skip-tcon-{}{suffix}", hex(hash))))
}

fn switched_config(original: &[u8], media: &Path, trustcache: &Path) -> Result<Vec<u8>, String> {
    let mut config: Value = serde_json::from_slice(original)
        .map_err(|error| format!("parse bundle config: {error}"))?;
    for (pointer, path) in [
        ("/sources/restoreMediaPath", media),
        ("/directBoot/restoreTrustcachePath", trustcache),
    ] {
        relative_components(path)?;
        let field = config
            .pointer_mut(pointer)
            .ok_or_else(|| format!("bundle config must name {pointer}"))?;
        if !field.is_string() {
            return Err(format!("bundle config {pointer} must be a string"));
        }
        *field = Value::String(
            path.to_str()
                .ok_or("staged bundle path must be UTF-8")?
                .to_owned(),
        );
    }
    let mut bytes = serde_json::to_vec_pretty(&config).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchReceipt {
    version: u32,
    config_sha256: [u8; 32],
    original_config_sha256: [u8; 32],
    original_media_sha256: [u8; 32],
    original_trustcache_sha256: [u8; 32],
    media_sha256: [u8; 32],
    trustcache_sha256: [u8; 32],
    executable_sha256: [u8; 32],
    old_cdhash: [u8; 20],
    new_cdhash: [u8; 20],
}

fn receipt_path(config: &[u8]) -> PathBuf {
    PathBuf::from(format!("restore-patch-{}.json", hex(&sha256(config))))
}

fn rollback_path(config_hash: &[u8; 32]) -> PathBuf {
    PathBuf::from(format!(
        "config.restore-patch-original-{}.json",
        hex(config_hash)
    ))
}

fn validate_receipt_config(
    receipt: &PatchReceipt,
    current: &[u8],
    original: &[u8],
    media: &Path,
    cache: &Path,
) -> Result<(PathBuf, PathBuf), String> {
    if receipt.version != 1 {
        return Err(format!(
            "unsupported restore patch receipt version {}",
            receipt.version
        ));
    }
    if sha256(current) != receipt.config_sha256
        || sha256(original) != receipt.original_config_sha256
    {
        return Err(
            "restore patch receipt config hashes do not match current and rollback configs".into(),
        );
    }
    let original_config: Value = serde_json::from_slice(original)
        .map_err(|error| format!("parse restore patch rollback config: {error}"))?;
    let original_media = configured_path(&original_config, "/sources/restoreMediaPath")?;
    let original_cache = configured_path(&original_config, "/directBoot/restoreTrustcachePath")?;
    if switched_config(original, media, cache)? != current {
        return Err("restore patch current config differs from the recorded transaction".into());
    }
    if staged_path_for_hash(&original_media, &receipt.media_sha256)? != media
        || staged_path_for_hash(&original_cache, &receipt.trustcache_sha256)? != cache
    {
        return Err("restore patch receipt does not identify the configured staged files".into());
    }
    Ok((original_media, original_cache))
}

#[cfg(unix)]
mod bundle_io {
    use std::ffi::{CString, OsStr};
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    use super::*;

    pub(super) struct Bundle {
        root: File,
    }

    fn io_error(action: &str, path: &Path, error: std::io::Error) -> String {
        format!("{action} {}: {error}", path.display())
    }

    fn name_cstring(name: &OsStr) -> Result<CString, String> {
        CString::new(name.as_bytes()).map_err(|_| "bundle path contains a NUL byte".into())
    }

    fn open_at(
        parent: &File,
        name: &OsStr,
        flags: i32,
        mode: libc::mode_t,
    ) -> std::io::Result<File> {
        let name = CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in bundle path")
        })?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode as libc::c_uint,
            )
        };
        if fd < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    #[cfg(target_os = "macos")]
    fn publish_at(parent: &File, temporary: &CString, final_name: &CString) -> std::io::Result<()> {
        let result = unsafe {
            libc::renameatx_np(
                parent.as_raw_fd(),
                temporary.as_ptr(),
                parent.as_raw_fd(),
                final_name.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(target_os = "linux")]
    fn publish_at(parent: &File, temporary: &CString, final_name: &CString) -> std::io::Result<()> {
        let result = unsafe {
            libc::renameat2(
                parent.as_raw_fd(),
                temporary.as_ptr(),
                parent.as_raw_fd(),
                final_name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn publish_at(parent: &File, temporary: &CString, final_name: &CString) -> std::io::Result<()> {
        let result = unsafe {
            libc::linkat(
                parent.as_raw_fd(),
                temporary.as_ptr(),
                parent.as_raw_fd(),
                final_name.as_ptr(),
                0,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let removed = unsafe { libc::unlinkat(parent.as_raw_fd(), temporary.as_ptr(), 0) };
        if removed == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn regular(file: &File, path: &Path) -> Result<(), String> {
        let metadata = file
            .metadata()
            .map_err(|error| io_error("inspect", path, error))?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(format!(
                "bundle file must be regular with a single link: {}",
                path.display()
            ));
        }
        Ok(())
    }

    impl Bundle {
        pub(super) fn open(path: &Path, apply: bool) -> Result<Self, String> {
            let absolute = if path.is_absolute() {
                path.to_owned()
            } else {
                std::env::current_dir()
                    .map_err(|error| error.to_string())?
                    .join(path)
            };
            let mut components = absolute.components();
            let root = components.next().ok_or("bundle path is empty")?;
            if root != Component::RootDir {
                return Err("bundle path must resolve to a filesystem root".into());
            }
            let mut directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(Path::new(root.as_os_str()))
                .map_err(|error| io_error("open bundle root", path, error))?;
            for component in components {
                let Component::Normal(name) = component else {
                    return Err(format!(
                        "bundle path contains traversal: {}",
                        path.display()
                    ));
                };
                directory = open_at(&directory, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
                    .map_err(|error| {
                        io_error("open bundle directory without symlinks", path, error)
                    })?;
            }
            if apply
                && unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
            {
                return Err(io_error(
                    "lock bundle for restore patch",
                    path,
                    std::io::Error::last_os_error(),
                ));
            }
            Ok(Self { root: directory })
        }

        fn parent(&self, path: &Path) -> Result<(File, CString), String> {
            let names = relative_components(path)?;
            let (last, parents) = names.split_last().ok_or("bundle filename is empty")?;
            let mut directory = self.root.try_clone().map_err(|error| error.to_string())?;
            for name in parents {
                directory = open_at(&directory, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
                    .map_err(|error| {
                        io_error("open bundle parent without symlinks", path, error)
                    })?;
            }
            Ok((directory, name_cstring(last)?))
        }

        pub(super) fn read_optional(&self, path: &Path) -> Result<Option<Vec<u8>>, String> {
            let (directory, name) = self.parent(path)?;
            let mut file = match open_at(
                &directory,
                OsStr::from_bytes(name.as_bytes()),
                libc::O_RDONLY | libc::O_NONBLOCK,
                0,
            ) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => {
                    return Err(io_error("open bundle file without symlinks", path, error));
                }
            };
            regular(&file, path)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .map_err(|error| io_error("read bundle file", path, error))?;
            Ok(Some(bytes))
        }

        pub(super) fn read(&self, path: &Path) -> Result<Vec<u8>, String> {
            self.read_optional(path)?
                .ok_or_else(|| format!("bundle file not found: {}", path.display()))
        }

        pub(super) fn recheck(&self, path: &Path, expected: &[u8]) -> Result<(), String> {
            self.recheck_hash(path, &sha256(expected))
        }

        pub(super) fn recheck_hash(&self, path: &Path, expected: &[u8; 32]) -> Result<(), String> {
            let (directory, name) = self.parent(path)?;
            let mut file = open_at(
                &directory,
                OsStr::from_bytes(name.as_bytes()),
                libc::O_RDONLY | libc::O_NONBLOCK,
                0,
            )
            .map_err(|error| io_error("reopen bundle file without symlinks", path, error))?;
            regular(&file, path)?;
            let mut hash = crate::crypto::Sha256::new();
            let mut buffer = [0; 65536];
            loop {
                let count = file
                    .read(&mut buffer)
                    .map_err(|error| io_error("hash bundle file", path, error))?;
                if count == 0 {
                    break;
                }
                hash.update(&buffer[..count]);
            }
            if &hash.finish() != expected {
                return Err(format!(
                    "bundle file changed while preparing restore patch: {}",
                    path.display()
                ));
            }
            Ok(())
        }

        pub(super) fn stage(&self, path: &Path, bytes: &[u8]) -> Result<(), String> {
            let (directory, name) = self.parent(path)?;
            let name_os = OsStr::from_bytes(name.as_bytes());
            let mut file = match open_at(&directory, name_os, libc::O_RDONLY | libc::O_NONBLOCK, 0)
            {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let (temporary, mut pending) = loop {
                        let mut nonce = [0u8; 16];
                        if unsafe { libc::getentropy(nonce.as_mut_ptr().cast(), nonce.len()) } != 0
                        {
                            return Err(io_error(
                                "generate staged bundle filename",
                                path,
                                std::io::Error::last_os_error(),
                            ));
                        }
                        let temporary = name_cstring(OsStr::new(&format!(
                            ".restore-patch-stage-{}",
                            hex(&nonce)
                        )))?;
                        match open_at(
                            &directory,
                            OsStr::from_bytes(temporary.as_bytes()),
                            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                            0o600,
                        ) {
                            Ok(file) => break (temporary, file),
                            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                                continue;
                            }
                            Err(error) => {
                                return Err(io_error(
                                    "create temporary staged bundle file",
                                    path,
                                    error,
                                ));
                            }
                        }
                    };
                    let write_result = pending
                        .write_all(bytes)
                        .and_then(|_| pending.sync_all())
                        .map_err(|error| {
                            io_error("write and sync temporary staged bundle file", path, error)
                        });
                    let publish_result = write_result.and_then(|_| {
                        match publish_at(&directory, &temporary, &name) {
                            Ok(()) => Ok(()),
                            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                                Ok(())
                            }
                            Err(error) => Err(io_error("publish staged bundle file", path, error)),
                        }
                    });
                    let cleanup =
                        unsafe { libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0) };
                    if cleanup != 0 {
                        let error = std::io::Error::last_os_error();
                        if error.kind() != std::io::ErrorKind::NotFound {
                            return Err(io_error(
                                "clean temporary staged bundle file",
                                path,
                                error,
                            ));
                        }
                    }
                    publish_result?;
                    open_at(&directory, name_os, libc::O_RDONLY | libc::O_NONBLOCK, 0).map_err(
                        |error| io_error("open published staged bundle file", path, error),
                    )?
                }
                Err(error) => return Err(io_error("open staged bundle file", path, error)),
            };
            regular(&file, path)?;
            use std::io::{Seek, SeekFrom};
            file.seek(SeekFrom::Start(0))
                .map_err(|error| io_error("rewind staged bundle file", path, error))?;
            let mut buffer = [0; 65536];
            let mut offset = 0usize;
            loop {
                let count = file
                    .read(&mut buffer)
                    .map_err(|error| io_error("verify staged bundle file", path, error))?;
                if count == 0 {
                    break;
                }
                let end = offset
                    .checked_add(count)
                    .ok_or("staged bundle file length overflows")?;
                if bytes.get(offset..end) != Some(&buffer[..count]) {
                    return Err(format!("staged bundle file collision: {}", path.display()));
                }
                offset = end;
            }
            if offset != bytes.len() {
                return Err(format!("staged bundle file collision: {}", path.display()));
            }
            file.sync_all()
                .map_err(|error| io_error("sync verified staged bundle file", path, error))?;
            directory
                .sync_all()
                .map_err(|error| io_error("sync staged bundle directory", path, error))?;
            Ok(())
        }

        pub(super) fn commit_config(
            &self,
            current: &[u8],
            original: &[u8],
            replacement: &[u8],
            sources: &[(&Path, &[u8; 32])],
        ) -> Result<PathBuf, String> {
            let rollback = rollback_path(&sha256(original));
            self.stage(&rollback, original)?;
            let temporary = PathBuf::from(format!(
                ".config.restore-patch-{}.tmp",
                hex(&sha256(replacement))
            ));
            self.stage(&temporary, replacement)?;
            for (path, hash) in sources {
                self.recheck_hash(path, hash)?;
            }
            self.recheck(&rollback, original)?;
            self.recheck(&temporary, replacement)?;
            self.recheck(Path::new("config.json"), current)?;
            let temporary_name = name_cstring(temporary.as_os_str())?;
            let config_name = name_cstring(OsStr::new("config.json"))?;
            if unsafe {
                libc::renameat(
                    self.root.as_raw_fd(),
                    temporary_name.as_ptr(),
                    self.root.as_raw_fd(),
                    config_name.as_ptr(),
                )
            } != 0
            {
                return Err(io_error(
                    "atomically switch bundle config",
                    Path::new("config.json"),
                    std::io::Error::last_os_error(),
                ));
            }
            self.root.sync_all().map_err(|error| {
                io_error(
                    "sync committed bundle config directory",
                    Path::new("config.json"),
                    error,
                )
            })?;
            self.recheck(Path::new("config.json"), replacement)?;
            Ok(rollback)
        }
    }
}

#[cfg(unix)]
struct VerifiedPatch {
    receipt: PatchReceipt,
    original_config: Vec<u8>,
    original_media: PathBuf,
    original_cache: PathBuf,
    output: String,
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn verify_applied_patch(
    bundle: &bundle_io::Bundle,
    path: &Path,
    config: &[u8],
    media_path: &Path,
    cache_path: &Path,
    media_bytes: &[u8],
    cache_bytes: &[u8],
    receipt_bytes: &[u8],
) -> Result<VerifiedPatch, String> {
    let receipt: PatchReceipt = serde_json::from_slice(receipt_bytes)
        .map_err(|error| format!("parse restore patch receipt: {error}"))?;
    let rollback = rollback_path(&receipt.original_config_sha256);
    let original_config = bundle.read(&rollback)?;
    let (original_media, original_cache) =
        validate_receipt_config(&receipt, config, &original_config, media_path, cache_path)?;
    if sha256(media_bytes) != receipt.media_sha256
        || sha256(cache_bytes) != receipt.trustcache_sha256
    {
        return Err(
            "restore patch receipt hashes do not match staged restore media and trustcache".into(),
        );
    }
    let media = RestoreMedia::parse(media_bytes)?;
    let (_, volume, executable) = restored_external(media.payload())?;
    if sha256(&executable) != receipt.executable_sha256 {
        return Err(format!(
            "restore patch receipt executable hash does not match {RESTORED_EXTERNAL}"
        ));
    }
    for (source, hash) in [
        (original_media.as_path(), &receipt.original_media_sha256),
        (
            original_cache.as_path(),
            &receipt.original_trustcache_sha256,
        ),
        (media_path, &receipt.media_sha256),
        (cache_path, &receipt.trustcache_sha256),
        (rollback.as_path(), &receipt.original_config_sha256),
        (Path::new("config.json"), &receipt.config_sha256),
    ] {
        bundle.recheck_hash(source, hash)?;
    }
    bundle.recheck(&receipt_path(config), receipt_bytes)?;
    let output = format!(
        "Verified restore patch already applied in bundle {}; no additional patch is needed.\nAPFS volume: {}\nOriginal CDHash: {}\nNew CDHash: {}\nStaged restore media: {}\nStaged restore trustcache: {}\nOriginal config: {}\nEnable Skip TCON firmware in AppleUtils before starting restore.\n",
        path.display(),
        volume,
        hex(&receipt.old_cdhash),
        hex(&receipt.new_cdhash),
        media_path.display(),
        cache_path.display(),
        rollback.display(),
    );
    Ok(VerifiedPatch {
        receipt,
        original_config,
        original_media,
        original_cache,
        output,
    })
}

#[cfg(unix)]
fn run_bundle(path: &Path, apply: bool) -> Result<String, String> {
    let bundle = bundle_io::Bundle::open(path, apply)?;
    let current_config = bundle.read(Path::new("config.json"))?;
    let config: Value = serde_json::from_slice(&current_config)
        .map_err(|error| format!("parse bundle config: {error}"))?;
    let current_media_path = configured_path(&config, "/sources/restoreMediaPath")?;
    let current_cache_path = configured_path(&config, "/directBoot/restoreTrustcachePath")?;
    let current_media = bundle.read(&current_media_path)?;
    let current_cache = bundle.read(&current_cache_path)?;
    let current_media_hash = sha256(&current_media);
    let current_cache_hash = sha256(&current_cache);
    let current_receipt_path = receipt_path(&current_config);
    let current_receipt_bytes = bundle.read_optional(&current_receipt_path)?;
    let installed = current_receipt_bytes
        .as_deref()
        .map(|bytes| {
            verify_applied_patch(
                &bundle,
                path,
                &current_config,
                &current_media_path,
                &current_cache_path,
                &current_media,
                &current_cache,
                bytes,
            )
        })
        .transpose()?;
    let (original_config, media_path, cache_path, original_media, original_cache) = match &installed
    {
        Some(verified) => {
            drop(current_media);
            drop(current_cache);
            let original_media = bundle.read(&verified.original_media)?;
            let original_cache = bundle.read(&verified.original_cache)?;
            if sha256(&original_media) != verified.receipt.original_media_sha256
                || sha256(&original_cache) != verified.receipt.original_trustcache_sha256
            {
                return Err(
                    "restore patch original media or trustcache changed after receipt verification"
                        .into(),
                );
            }
            (
                verified.original_config.clone(),
                verified.original_media.clone(),
                verified.original_cache.clone(),
                original_media,
                original_cache,
            )
        }
        None => (
            current_config.clone(),
            current_media_path.clone(),
            current_cache_path.clone(),
            current_media,
            current_cache,
        ),
    };
    let media = RestoreMedia::parse(&original_media)?;
    let (volume, volume_name, executable) = restored_external(media.payload())?;
    let prepared = crate::restore_patch::prepare_skip_tcon(&executable, &original_cache)?;
    if let Some(verified) = &installed {
        if prepared.old_cdhash != verified.receipt.old_cdhash {
            return Err(
                "restore patch receipt original CDHash does not match verified stock executable"
                    .into(),
            );
        }
        if sha256(&prepared.executable) == verified.receipt.executable_sha256
            && sha256(&prepared.trustcache_im4p) == verified.receipt.trustcache_sha256
            && prepared.new_cdhash == verified.receipt.new_cdhash
        {
            return verify_applied_patch(
                &bundle,
                path,
                &current_config,
                &current_media_path,
                &current_cache_path,
                &bundle.read(&current_media_path)?,
                &bundle.read(&current_cache_path)?,
                current_receipt_bytes
                    .as_deref()
                    .ok_or("verified restore patch receipt is missing")?,
            )
            .map(|verified| verified.output);
        }
    }
    let replacement_image = crate::apfs_replace::replace_file_in_container(
        media.payload(),
        volume,
        RESTORED_EXTERNAL,
        &sha256(&executable),
        &prepared.executable,
    )?;
    let replacement_media = media.replace_payload(&replacement_image);
    let staged_media = staged_path(&media_path, &replacement_media)?;
    let staged_cache = staged_path(&cache_path, &prepared.trustcache_im4p)?;
    if media_path == cache_path || staged_media == staged_cache {
        return Err("restore media and restore trustcache must name separate bundle files".into());
    }
    let replacement_config = switched_config(&original_config, &staged_media, &staged_cache)?;
    let receipt = PatchReceipt {
        version: 1,
        config_sha256: sha256(&replacement_config),
        original_config_sha256: sha256(&original_config),
        original_media_sha256: sha256(&original_media),
        original_trustcache_sha256: sha256(&original_cache),
        media_sha256: sha256(&replacement_media),
        trustcache_sha256: sha256(&prepared.trustcache_im4p),
        executable_sha256: sha256(&prepared.executable),
        old_cdhash: prepared.old_cdhash,
        new_cdhash: prepared.new_cdhash,
    };
    let receipt_bytes = serde_json::to_vec_pretty(&receipt).map_err(|error| error.to_string())?;
    let staged_receipt = receipt_path(&replacement_config);
    let staged_receipt_hash = sha256(&receipt_bytes);
    let mut output = format!(
        "{} restore patch for bundle {}\nAPFS volume: {}\nExecutable: {} ({} logical bytes)\nOriginal CDHash: {}\nNew CDHash: {}\nStaged restore media: {}\nStaged restore trustcache: {}\n",
        match (apply, installed.is_some()) {
            (true, true) => "Applying updated",
            (false, true) => "Dry-run updated",
            (true, false) => "Applying",
            (false, false) => "Dry-run",
        },
        path.display(),
        volume_name,
        RESTORED_EXTERNAL,
        executable.len(),
        hex(&prepared.old_cdhash),
        hex(&prepared.new_cdhash),
        staged_media.display(),
        staged_cache.display(),
    );
    let current_receipt_hash = current_receipt_bytes.as_ref().map(|bytes| sha256(bytes));
    let original_rollback = rollback_path(&receipt.original_config_sha256);
    let mut sources = vec![
        (media_path.as_path(), &receipt.original_media_sha256),
        (cache_path.as_path(), &receipt.original_trustcache_sha256),
        (current_media_path.as_path(), &current_media_hash),
        (current_cache_path.as_path(), &current_cache_hash),
    ];
    if let Some(hash) = &current_receipt_hash {
        sources.push((current_receipt_path.as_path(), hash));
        sources.push((original_rollback.as_path(), &receipt.original_config_sha256));
    }
    if apply {
        bundle.stage(&staged_media, &replacement_media)?;
        bundle.stage(&staged_cache, &prepared.trustcache_im4p)?;
        bundle.stage(&staged_receipt, &receipt_bytes)?;
        sources.extend([
            (staged_media.as_path(), &receipt.media_sha256),
            (staged_cache.as_path(), &receipt.trustcache_sha256),
            (staged_receipt.as_path(), &staged_receipt_hash),
        ]);
        let rollback = bundle.commit_config(
            &current_config,
            &original_config,
            &replacement_config,
            &sources,
        )?;
        output.push_str(&format!(
            "Committed config.json; original config: {}\nVerified receipt: {}\n",
            rollback.display(),
            staged_receipt.display()
        ));
    } else {
        for (source, hash) in sources {
            bundle.recheck_hash(source, hash)?;
        }
        bundle.recheck(Path::new("config.json"), &current_config)?;
        output.push_str("Pass --apply to stage these files and atomically switch config.json.\n");
    }
    output.push_str("Enable Skip TCON firmware in AppleUtils before starting restore.\n");
    Ok(output)
}

#[cfg(not(unix))]
fn run_bundle(_path: &Path, _apply: bool) -> Result<String, String> {
    Err("restore bundle patching requires Unix directory-relative opens and atomic rename".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apfs_payload(block_count: u64) -> Vec<u8> {
        let mut payload = vec![0; block_count as usize * 4096];
        payload[0x20..0x24].copy_from_slice(b"NXSB");
        payload[0x24..0x28].copy_from_slice(&4096u32.to_le_bytes());
        payload[0x28..0x30].copy_from_slice(&block_count.to_le_bytes());
        payload
    }

    #[test]
    fn im4p_replacement_preserves_description_type_and_optional_fields() {
        let original_payload = apfs_payload(1);
        let fields = [
            der::ia5_string("IM4P"),
            der::ia5_string("rdsk"),
            der::ia5_string("Recovery ramdisk"),
            der::octet_string(&original_payload),
            der::tlv(&[0xa1], &der::integer_u64(7)),
        ];
        let original = der::sequence(&fields.concat());
        let parsed = RestoreMedia::parse(&original).unwrap();
        let replacement_payload = apfs_payload(17);
        let replacement = parsed.replace_payload(&replacement_payload);
        let reparsed = RestoreMedia::parse(&replacement).unwrap();
        assert_eq!(reparsed.payload(), replacement_payload);
        assert_eq!(reparsed.fields.len(), fields.len());
        for index in [0, 1, 2, 4] {
            assert_eq!(reparsed.fields[index].encoded, fields[index]);
        }
        assert_eq!(
            replacement,
            der::sequence(
                &[
                    fields[0].clone(),
                    fields[1].clone(),
                    fields[2].clone(),
                    der::octet_string(&replacement_payload),
                    fields[4].clone(),
                ]
                .concat()
            )
        );
    }

    #[test]
    fn config_switch_preserves_recovery_cache_and_other_vm_settings() {
        let original = serde_json::to_vec(&serde_json::json!({
            "sources": { "restoreMediaPath": "media/restore.im4p", "diskPath": "target.qcow2" },
            "directBoot": {
                "restoreTrustcachePath": "firmware/restore.trustcache",
                "baseSystemTrustcachePath": "firmware/restore.trustcache",
                "bootSource": "restoreRamdisk"
            },
            "cpuCount": 8
        }))
        .unwrap();
        let bytes = switched_config(
            &original,
            Path::new("media/patched.im4p"),
            Path::new("firmware/patched.trustcache"),
        )
        .unwrap();
        let config: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            config,
            serde_json::json!({
                "sources": { "restoreMediaPath": "media/patched.im4p", "diskPath": "target.qcow2" },
                "directBoot": {
                    "restoreTrustcachePath": "firmware/patched.trustcache",
                    "baseSystemTrustcachePath": "firmware/restore.trustcache",
                    "bootSource": "restoreRamdisk"
                },
                "cpuCount": 8
            })
        );
    }

    #[test]
    fn staged_names_preserve_media_and_trustcache_extensions() {
        let media = staged_path(Path::new("media/restore.dmg"), b"replacement media").unwrap();
        let cache = staged_path(
            Path::new("firmware/restore.trustcache"),
            b"replacement cache",
        )
        .unwrap();
        assert_eq!(
            media,
            PathBuf::from(format!(
                "media/restore.skip-tcon-{}.dmg",
                hex(&sha256(b"replacement media"))
            ))
        );
        assert_eq!(
            cache,
            PathBuf::from(format!(
                "firmware/restore.skip-tcon-{}.trustcache",
                hex(&sha256(b"replacement cache"))
            ))
        );
        assert_eq!(media.extension().unwrap(), "dmg");
        assert_eq!(cache.extension().unwrap(), "trustcache");
    }

    #[test]
    fn receipt_binds_switched_config_to_original_paths_and_content_hashes() {
        let original = br#"{"sources":{"restoreMediaPath":"media/restore.dmg"},"directBoot":{"restoreTrustcachePath":"firmware/restore.trustcache","baseSystemTrustcachePath":"firmware/restore.trustcache"}}"#;
        let media = staged_path(Path::new("media/restore.dmg"), b"replacement media").unwrap();
        let cache = staged_path(
            Path::new("firmware/restore.trustcache"),
            b"replacement cache",
        )
        .unwrap();
        let config = switched_config(original, &media, &cache).unwrap();
        let receipt = PatchReceipt {
            version: 1,
            config_sha256: sha256(&config),
            original_config_sha256: sha256(original),
            original_media_sha256: sha256(b"original media"),
            original_trustcache_sha256: sha256(b"original cache"),
            media_sha256: sha256(b"replacement media"),
            trustcache_sha256: sha256(b"replacement cache"),
            executable_sha256: sha256(b"replacement executable"),
            old_cdhash: [0x11; 20],
            new_cdhash: [0x22; 20],
        };
        let encoded = serde_json::to_vec(&receipt).unwrap();
        let decoded: PatchReceipt = serde_json::from_slice(&encoded).unwrap();
        let (original_media, original_cache) =
            validate_receipt_config(&decoded, &config, original, &media, &cache).unwrap();
        assert_eq!(original_media, Path::new("media/restore.dmg"));
        assert_eq!(original_cache, Path::new("firmware/restore.trustcache"));
        assert_eq!(decoded.executable_sha256, sha256(b"replacement executable"));
        assert_eq!(decoded.old_cdhash, [0x11; 20]);
        assert_eq!(decoded.new_cdhash, [0x22; 20]);
        assert_eq!(
            receipt_path(&config),
            PathBuf::from(format!("restore-patch-{}.json", hex(&sha256(&config))))
        );
    }

    #[cfg(unix)]
    #[test]
    fn repeated_receipt_verification_checks_guest_executable_and_preserves_transaction() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("media")).unwrap();
        std::fs::create_dir(root.join("firmware")).unwrap();
        let executable = b"receipt test restored executable";
        let mut image = crate::apfs_write::create_with_preboot_files(
            64 * 1024 * 1024,
            "Recovery fixture",
            b"fixture stage one",
            None,
            &[],
            &[(
                "usr/local/bin/restored_external".to_owned(),
                executable.to_vec(),
            )],
        )
        .unwrap();
        let (block_size, block_count) = container_geometry_of(&image).unwrap();
        let checkpoint = {
            let mut blocks = SliceBlocks::new(&image, block_size);
            let container = ApfsContainer::mount(&mut blocks, block_size, block_count).unwrap();
            container.superblock_paddr()
        };
        // Publish the populated System volume as the fixture's single recovery volume.
        for paddr in [0, checkpoint] {
            let start = paddr as usize * block_size as usize;
            let superblock = &mut image[start..start + block_size as usize];
            let system_oid = superblock[0xC0..0xC8].to_vec();
            superblock[0xB8..0xD8].fill(0);
            superblock[0xB8..0xC0].copy_from_slice(&system_oid);
            crate::apfs_image::fletcher64_seal(superblock);
        }
        let (choice, name, extracted) = restored_external(&image).unwrap();
        assert_eq!(choice, VolumeChoice::Index(0));
        assert_eq!(name, "Recovery fixture");
        assert_eq!(extracted, executable);
        let media_bytes = der::sequence(
            &[
                der::ia5_string("IM4P"),
                der::ia5_string("rdsk"),
                der::ia5_string("Recovery fixture"),
                der::octet_string(&image),
            ]
            .concat(),
        );
        let original = br#"{"sources":{"restoreMediaPath":"media/restore.dmg"},"directBoot":{"restoreTrustcachePath":"firmware/restore.trustcache","baseSystemTrustcachePath":"firmware/restore.trustcache"}}"#;
        let media = staged_path(Path::new("media/restore.dmg"), &media_bytes).unwrap();
        let cache = staged_path(
            Path::new("firmware/restore.trustcache"),
            b"receipt test trustcache",
        )
        .unwrap();
        let config = switched_config(original, &media, &cache).unwrap();
        let receipt = PatchReceipt {
            version: 1,
            config_sha256: sha256(&config),
            original_config_sha256: sha256(original),
            original_media_sha256: sha256(b"original fixture media"),
            original_trustcache_sha256: sha256(b"original fixture cache"),
            media_sha256: sha256(&media_bytes),
            trustcache_sha256: sha256(b"receipt test trustcache"),
            executable_sha256: sha256(executable),
            old_cdhash: [0x11; 20],
            new_cdhash: [0x22; 20],
        };
        std::fs::write(root.join("config.json"), &config).unwrap();
        std::fs::write(
            root.join(rollback_path(&receipt.original_config_sha256)),
            original,
        )
        .unwrap();
        std::fs::write(root.join("media/restore.dmg"), b"original fixture media").unwrap();
        std::fs::write(
            root.join("firmware/restore.trustcache"),
            b"original fixture cache",
        )
        .unwrap();
        std::fs::write(root.join(&media), &media_bytes).unwrap();
        std::fs::write(root.join(&cache), b"receipt test trustcache").unwrap();
        std::fs::write(
            root.join(receipt_path(&config)),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        let bundle = bundle_io::Bundle::open(&root, true).unwrap();
        let receipt_bytes = bundle.read(&receipt_path(&config)).unwrap();
        let verify = || {
            verify_applied_patch(
                &bundle,
                &root,
                &config,
                &media,
                &cache,
                &media_bytes,
                b"receipt test trustcache",
                &receipt_bytes,
            )
            .unwrap()
        };
        let first = verify();
        let second = verify();
        assert_eq!(second.original_config, original);
        assert_eq!(second.original_media, Path::new("media/restore.dmg"));
        assert_eq!(
            second.original_cache,
            Path::new("firmware/restore.trustcache")
        );
        let first = first.output;
        let second = second.output;
        assert_eq!(first, second);
        assert!(second.starts_with("Verified restore patch already applied in bundle"));
        assert!(second.contains(&format!("Original CDHash: {}", hex(&receipt.old_cdhash))));
        assert!(second.contains(&format!("New CDHash: {}", hex(&receipt.new_cdhash))));
        assert_eq!(std::fs::read(root.join("config.json")).unwrap(), config);
        assert_eq!(std::fs::read(root.join(&media)).unwrap(), media_bytes);
        assert_eq!(
            std::fs::read(root.join(&cache)).unwrap(),
            b"receipt test trustcache"
        );
    }

    #[cfg(unix)]
    #[test]
    fn config_transaction_persists_verified_staging_and_exact_rollback() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("media")).unwrap();
        std::fs::create_dir(root.join("firmware")).unwrap();
        let original = br#"{"sources":{"restoreMediaPath":"media/restore.im4p"},"directBoot":{"restoreTrustcachePath":"firmware/restore.trustcache","baseSystemTrustcachePath":"firmware/restore.trustcache"},"memoryMiB":4096}"#;
        std::fs::write(root.join("config.json"), original).unwrap();
        std::fs::write(root.join("media/restore.im4p"), b"original media").unwrap();
        std::fs::write(root.join("firmware/restore.trustcache"), b"original cache").unwrap();
        let bundle = bundle_io::Bundle::open(&root, true).unwrap();
        let media = staged_path(Path::new("media/restore.im4p"), b"replacement media").unwrap();
        let cache = staged_path(
            Path::new("firmware/restore.trustcache"),
            b"replacement cache",
        )
        .unwrap();
        bundle.stage(&media, b"replacement media").unwrap();
        bundle.stage(&media, b"replacement media").unwrap();
        bundle.stage(&cache, b"replacement cache").unwrap();
        let config = switched_config(original, &media, &cache).unwrap();
        let rollback = bundle
            .commit_config(
                original,
                original,
                &config,
                &[
                    (Path::new("media/restore.im4p"), &sha256(b"original media")),
                    (
                        Path::new("firmware/restore.trustcache"),
                        &sha256(b"original cache"),
                    ),
                    (&media, &sha256(b"replacement media")),
                    (&cache, &sha256(b"replacement cache")),
                ],
            )
            .unwrap();
        assert_eq!(bundle.read(Path::new("config.json")).unwrap(), config);
        assert_eq!(bundle.read(&rollback).unwrap(), original);
        assert_eq!(bundle.read(&media).unwrap(), b"replacement media");
        assert_eq!(bundle.read(&cache).unwrap(), b"replacement cache");
        assert_eq!(
            bundle.read(Path::new("media/restore.im4p")).unwrap(),
            b"original media"
        );
        assert_eq!(
            bundle
                .read(Path::new("firmware/restore.trustcache"))
                .unwrap(),
            b"original cache"
        );
        let current: Value =
            serde_json::from_slice(&bundle.read(Path::new("config.json")).unwrap()).unwrap();
        assert_eq!(
            configured_path(&current, "/sources/restoreMediaPath").unwrap(),
            media
        );
        assert_eq!(
            configured_path(&current, "/directBoot/restoreTrustcachePath").unwrap(),
            cache
        );
        assert_eq!(
            current["directBoot"]["baseSystemTrustcachePath"],
            "firmware/restore.trustcache"
        );
    }

    #[cfg(unix)]
    #[test]
    fn updated_config_transaction_preserves_stock_rollback_and_both_generations() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("media")).unwrap();
        std::fs::create_dir(root.join("firmware")).unwrap();
        let original = br#"{"sources":{"restoreMediaPath":"media/restore.im4p","diskPath":"target.qcow2"},"directBoot":{"restoreTrustcachePath":"firmware/restore.trustcache","baseSystemTrustcachePath":"firmware/restore.trustcache"},"memoryMiB":4096}"#;
        std::fs::write(root.join("config.json"), original).unwrap();
        std::fs::write(root.join("media/restore.im4p"), b"stock media").unwrap();
        std::fs::write(root.join("firmware/restore.trustcache"), b"stock cache").unwrap();
        let bundle = bundle_io::Bundle::open(&root, true).unwrap();
        let first_media =
            staged_path(Path::new("media/restore.im4p"), b"first recipe media").unwrap();
        let first_cache = staged_path(
            Path::new("firmware/restore.trustcache"),
            b"first recipe cache",
        )
        .unwrap();
        let first_config = switched_config(original, &first_media, &first_cache).unwrap();
        let first_receipt = PatchReceipt {
            version: 1,
            config_sha256: sha256(&first_config),
            original_config_sha256: sha256(original),
            original_media_sha256: sha256(b"stock media"),
            original_trustcache_sha256: sha256(b"stock cache"),
            media_sha256: sha256(b"first recipe media"),
            trustcache_sha256: sha256(b"first recipe cache"),
            executable_sha256: sha256(b"first recipe executable"),
            old_cdhash: [0x11; 20],
            new_cdhash: [0x22; 20],
        };
        let first_receipt_bytes = serde_json::to_vec_pretty(&first_receipt).unwrap();
        let first_receipt_path = receipt_path(&first_config);
        bundle.stage(&first_media, b"first recipe media").unwrap();
        bundle.stage(&first_cache, b"first recipe cache").unwrap();
        bundle
            .stage(&first_receipt_path, &first_receipt_bytes)
            .unwrap();
        let rollback = bundle
            .commit_config(
                original,
                original,
                &first_config,
                &[
                    (
                        Path::new("media/restore.im4p"),
                        &first_receipt.original_media_sha256,
                    ),
                    (
                        Path::new("firmware/restore.trustcache"),
                        &first_receipt.original_trustcache_sha256,
                    ),
                    (&first_media, &first_receipt.media_sha256),
                    (&first_cache, &first_receipt.trustcache_sha256),
                    (&first_receipt_path, &sha256(&first_receipt_bytes)),
                ],
            )
            .unwrap();
        assert_eq!(bundle.read(Path::new("config.json")).unwrap(), first_config);
        assert_eq!(bundle.read(&rollback).unwrap(), original);
        assert_eq!(
            validate_receipt_config(
                &first_receipt,
                &first_config,
                original,
                &first_media,
                &first_cache
            )
            .unwrap(),
            (
                PathBuf::from("media/restore.im4p"),
                PathBuf::from("firmware/restore.trustcache")
            )
        );

        let updated_media =
            staged_path(Path::new("media/restore.im4p"), b"updated recipe media").unwrap();
        let updated_cache = staged_path(
            Path::new("firmware/restore.trustcache"),
            b"updated recipe cache",
        )
        .unwrap();
        let updated_config = switched_config(original, &updated_media, &updated_cache).unwrap();
        let updated_receipt = PatchReceipt {
            version: 1,
            config_sha256: sha256(&updated_config),
            original_config_sha256: first_receipt.original_config_sha256,
            original_media_sha256: first_receipt.original_media_sha256,
            original_trustcache_sha256: first_receipt.original_trustcache_sha256,
            media_sha256: sha256(b"updated recipe media"),
            trustcache_sha256: sha256(b"updated recipe cache"),
            executable_sha256: sha256(b"updated recipe executable"),
            old_cdhash: first_receipt.old_cdhash,
            new_cdhash: [0x33; 20],
        };
        let updated_receipt_bytes = serde_json::to_vec_pretty(&updated_receipt).unwrap();
        let updated_receipt_path = receipt_path(&updated_config);
        bundle
            .stage(&updated_media, b"updated recipe media")
            .unwrap();
        bundle
            .stage(&updated_cache, b"updated recipe cache")
            .unwrap();
        bundle
            .stage(&updated_receipt_path, &updated_receipt_bytes)
            .unwrap();
        let updated_rollback = bundle
            .commit_config(
                &first_config,
                original,
                &updated_config,
                &[
                    (
                        Path::new("media/restore.im4p"),
                        &updated_receipt.original_media_sha256,
                    ),
                    (
                        Path::new("firmware/restore.trustcache"),
                        &updated_receipt.original_trustcache_sha256,
                    ),
                    (&rollback, &updated_receipt.original_config_sha256),
                    (&first_media, &first_receipt.media_sha256),
                    (&first_cache, &first_receipt.trustcache_sha256),
                    (&first_receipt_path, &sha256(&first_receipt_bytes)),
                    (&updated_media, &updated_receipt.media_sha256),
                    (&updated_cache, &updated_receipt.trustcache_sha256),
                    (&updated_receipt_path, &sha256(&updated_receipt_bytes)),
                ],
            )
            .unwrap();
        assert_eq!(updated_rollback, rollback);
        assert_eq!(bundle.read(&updated_rollback).unwrap(), original);
        assert_eq!(
            bundle.read(Path::new("config.json")).unwrap(),
            updated_config
        );
        assert_eq!(
            validate_receipt_config(
                &updated_receipt,
                &updated_config,
                original,
                &updated_media,
                &updated_cache
            )
            .unwrap(),
            (
                PathBuf::from("media/restore.im4p"),
                PathBuf::from("firmware/restore.trustcache")
            )
        );
        for (path, bytes) in [
            (Path::new("media/restore.im4p"), b"stock media".as_slice()),
            (
                Path::new("firmware/restore.trustcache"),
                b"stock cache".as_slice(),
            ),
            (first_media.as_path(), b"first recipe media".as_slice()),
            (first_cache.as_path(), b"first recipe cache".as_slice()),
            (first_receipt_path.as_path(), first_receipt_bytes.as_slice()),
            (updated_media.as_path(), b"updated recipe media".as_slice()),
            (updated_cache.as_path(), b"updated recipe cache".as_slice()),
            (
                updated_receipt_path.as_path(),
                updated_receipt_bytes.as_slice(),
            ),
        ] {
            assert_eq!(bundle.read(path).unwrap(), bytes);
        }
        let current: Value =
            serde_json::from_slice(&bundle.read(Path::new("config.json")).unwrap()).unwrap();
        assert_eq!(current["sources"]["diskPath"], "target.qcow2");
        assert_eq!(
            current["directBoot"]["baseSystemTrustcachePath"],
            "firmware/restore.trustcache"
        );
        assert_eq!(current["memoryMiB"], 4096);
    }
}
