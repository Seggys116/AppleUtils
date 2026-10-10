//! Scratch directories that do not outlive their process, however it ends.
//!
//! A plain `TempDir` is only removed by its destructor, which never runs when the process is
//! killed, loses its terminal, or exits while a worker thread still holds the directory. A
//! `ScratchDir` also keeps an advisory lock on a marker file for as long as the process lives;
//! the kernel drops that lock on any exit, so the next run can tell an abandoned directory from
//! one that is still in use and reclaim it.

use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const OWNED_PREFIX: &str = "apple-utils-";
const LOCK_NAME: &str = ".apple-utils-lock";
/// A directory with no marker file predates this scheme; it is reclaimed once it has been idle
/// this long, so a directory another build is still filling is left alone.
const UNMARKED_IDLE: Duration = Duration::from_secs(60 * 60);

#[derive(Debug)]
pub struct ScratchDir {
    path: PathBuf,
    _lock: File,
}

impl ScratchDir {
    /// Creates `<temp>/<prefix>XXXXXX`. The prefix must start with `apple-utils-`; the first
    /// call in a process also reclaims every abandoned directory with that prefix.
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

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Opens the marker and takes an exclusive lock. `Ok(None)` means another process holds it.
fn lock_marker(directory: &Path, create: bool) -> io::Result<Option<File>> {
    let marker = directory.join(LOCK_NAME);
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .open(marker)?;
    // SAFETY: the descriptor is owned by `file`, which outlives the call.
    let status = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if status == 0 {
        return Ok(Some(file));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        Ok(None)
    } else {
        Err(error)
    }
}

/// Removes every directory in the temp folder that starts with `prefix`, belongs to this user,
/// and is not held by a live process. Failures are ignored: a directory that cannot be removed
/// now is tried again on the next run.
pub fn sweep_abandoned(prefix: &str) {
    let Ok(entries) = fs::read_dir(std::env::temp_dir()) else {
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
            // Held by a live process, or unreadable: leave it.
            Ok(None) => {}
            // Unlocked marker: the owner is gone. The lock is held while removing.
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
        // An abandoned directory: marker present, nobody holding the lock.
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
