//! Scratch directories that do not outlive their process, however it ends.
//! A held advisory lock on a marker file tells the next run whether a directory is abandoned.

use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const OWNED_PREFIX: &str = "apple-utils-";
const HIDDEN_PREFIX: &str = ".apple-utils-";
const LOCK_NAME: &str = ".apple-utils-lock";
const PENDING_LOCK_NAME: &str = ".apple-utils-lock.pending";
/// A directory with no marker file predates this scheme; it is reclaimed once it has been idle
/// this long, so a directory another build is still filling is left alone.
const UNMARKED_IDLE: Duration = Duration::from_secs(60 * 60);

#[derive(Debug)]
pub struct ScratchDir {
    path: PathBuf,
    _lock: File,
}

impl ScratchDir {
    pub fn new(prefix: &str) -> io::Result<Self> {
        debug_assert!(prefix.starts_with(OWNED_PREFIX));
        static SWEPT: std::sync::Once = std::sync::Once::new();
        SWEPT.call_once(|| sweep_abandoned(OWNED_PREFIX));
        let path = tempfile::Builder::new().prefix(prefix).tempdir()?.keep();
        match lock_marker(&path, true) {
            Ok(Some(lock)) => Ok(Self { path, _lock: lock }),
            Ok(None) => {
                let _ = fs::remove_dir_all(&path);
                Err(io::Error::other("new scratch directory was already locked"))
            }
            Err(error) => {
                let _ = fs::remove_dir_all(&path);
                Err(error)
            }
        }
    }

    /// Created on the parent's filesystem so moving a finished file out of it is a rename.
    pub fn new_in(parent: &Path, prefix: &str) -> io::Result<Self> {
        debug_assert!(prefix.starts_with(OWNED_PREFIX) || prefix.starts_with(HIDDEN_PREFIX));
        sweep_abandoned_in(parent, prefix);
        let path = tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(parent)?
            .keep();
        match lock_marker(&path, true) {
            Ok(Some(lock)) => Ok(Self { path, _lock: lock }),
            Ok(None) => {
                let _ = fs::remove_dir_all(&path);
                Err(io::Error::other("new scratch directory was already locked"))
            }
            Err(error) => {
                let _ = fs::remove_dir_all(&path);
                Err(error)
            }
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// A new marker is locked under a temporary name, then renamed, so a concurrent sweep never
/// finds a marker that exists but is not yet locked.
fn lock_marker(directory: &Path, create: bool) -> io::Result<Option<File>> {
    let marker = directory.join(LOCK_NAME);
    let opened = if create {
        directory.join(PENDING_LOCK_NAME)
    } else {
        marker.clone()
    };
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(create)
        .open(&opened)?;
    // SAFETY: the descriptor is owned by `file`, which outlives the call.
    let status = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if status == 0 {
        if create {
            fs::rename(&opened, &marker)?;
        }
        return Ok(Some(file));
    }
    let error = io::Error::last_os_error();
    if create {
        let _ = fs::remove_file(&opened);
    }
    if error.kind() == io::ErrorKind::WouldBlock {
        Ok(None)
    } else {
        Err(error)
    }
}

pub fn sweep_abandoned(prefix: &str) {
    sweep_abandoned_in(&std::env::temp_dir(), prefix);
}

pub fn sweep_abandoned_in(dir: &Path, prefix: &str) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with(prefix) {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_dir() || meta.uid() != uid {
            continue;
        }
        match lock_marker(&path, false) {
            Ok(None) => {}
            Ok(Some(_held)) => {
                let _ = fs::remove_dir_all(&path);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let idle = meta
                    .modified()
                    .ok()
                    .and_then(|modified| SystemTime::now().duration_since(modified).ok());
                if idle.is_some_and(|idle| idle >= UNMARKED_IDLE) {
                    let _ = fs::remove_dir_all(&path);
                }
            }
            Err(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_removes_the_directory() {
        let dir = ScratchDir::new("apple-utils-scratch-test-drop-").unwrap();
        let path = dir.path().to_path_buf();
        fs::write(path.join("payload"), b"x").unwrap();
        drop(dir);
        assert!(!path.exists());
    }

    #[test]
    fn sweep_keeps_a_live_directory_and_reclaims_an_abandoned_one() {
        let prefix = "apple-utils-scratch-test-sweep-";
        let live = ScratchDir::new(prefix).unwrap();
        let abandoned = tempfile::Builder::new()
            .prefix(prefix)
            .tempdir()
            .unwrap()
            .keep();
        File::create(abandoned.join(LOCK_NAME)).unwrap();
        fs::write(abandoned.join("payload"), b"x").unwrap();

        sweep_abandoned(prefix);

        assert!(
            live.path().exists(),
            "a held directory must survive a sweep"
        );
        assert!(
            !abandoned.exists(),
            "an abandoned directory must be reclaimed"
        );
    }

    #[test]
    fn new_in_reclaims_abandoned_siblings_and_keeps_live_ones() {
        let parent = tempfile::tempdir().unwrap();
        let prefix = ".apple-utils-scratch-test-in-";
        let live = ScratchDir::new_in(parent.path(), prefix).unwrap();
        assert_eq!(live.path().parent().unwrap(), parent.path());
        let abandoned = parent.path().join(format!("{prefix}dead"));
        fs::create_dir(&abandoned).unwrap();
        File::create(abandoned.join(LOCK_NAME)).unwrap();
        let other = ScratchDir::new_in(parent.path(), prefix).unwrap();
        assert!(!abandoned.exists());
        assert!(live.path().exists());
        let path = other.path().to_path_buf();
        drop(other);
        assert!(!path.exists());
    }

    #[test]
    fn the_marker_appears_locked_and_without_a_pending_leftover() {
        let dir = ScratchDir::new("apple-utils-scratch-test-marker-").unwrap();
        assert!(dir.path().join(LOCK_NAME).is_file());
        assert!(!dir.path().join(PENDING_LOCK_NAME).exists());
        assert!(lock_marker(dir.path(), false).unwrap().is_none());
    }

    #[test]
    fn a_directory_still_awaiting_its_marker_survives_a_sweep() {
        let parent = tempfile::tempdir().unwrap();
        let prefix = ".apple-utils-scratch-test-pending-";
        let pending = parent.path().join(format!("{prefix}x"));
        fs::create_dir(&pending).unwrap();
        File::create(pending.join(PENDING_LOCK_NAME)).unwrap();
        sweep_abandoned_in(parent.path(), prefix);
        assert!(pending.exists());
    }

    #[test]
    fn sweep_leaves_a_recent_unmarked_directory() {
        let prefix = "apple-utils-scratch-test-unmarked-";
        let recent = tempfile::Builder::new()
            .prefix(prefix)
            .tempdir()
            .unwrap()
            .keep();
        sweep_abandoned(prefix);
        assert!(recent.exists());
        fs::remove_dir_all(&recent).unwrap();
    }
}
