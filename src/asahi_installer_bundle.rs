use crate::asahi_firmware::CatalogProvenance;
use crate::crypto::Sha256;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

pub struct InstallerBundle {
    pub directory: tempfile::TempDir,
    pub stage1: Vec<u8>,
    pub policy: Vec<u8>,
    pub provenance: CatalogProvenance,
}

fn normalized(path: &Path) -> Result<PathBuf, String> {
    let mut result = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::Normal(name) => result.push(name),
            _ => return Err(format!("unsafe installer archive path {}", path.display())),
        }
    }
    Ok(result)
}
fn needed(path: &Path) -> bool {
    path == Path::new("main.py")
        || path == Path::new("boot/m1n1.bin")
        || path.starts_with("src")
        || path.starts_with("asahi_firmware")
}

impl InstallerBundle {
    pub fn open(archive: &Path, source_uri: &str, workdir: &Path) -> Result<Self, String> {
        if source_uri.trim().is_empty() {
            return Err("installer archive provenance is required".into());
        }
        let mut file = File::open(archive).map_err(|e| e.to_string())?;
        let before = file.metadata().map_err(|e| e.to_string())?;
        let mut hash = Sha256::new();
        let mut block = [0; 65536];
        loop {
            let n = file.read(&mut block).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            hash.update(&block[..n]);
        }
        let digest = hash
            .finish()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let directory = tempfile::Builder::new()
            .prefix("asahi-installer-")
            .tempdir_in(workdir)
            .map_err(|e| e.to_string())?;
        let mut archive_reader = tar::Archive::new(flate2::read::GzDecoder::new(&mut file));
        let mut seen = BTreeSet::new();
        for entry in archive_reader.entries().map_err(|e| e.to_string())? {
            let mut entry = entry.map_err(|e| e.to_string())?;
            let relative = normalized(&entry.path().map_err(|e| e.to_string())?)?;
            if !needed(&relative) {
                continue;
            }
            let kind = entry.header().entry_type();
            if kind.is_dir() {
                continue;
            }
            if !kind.is_file() {
                return Err(format!(
                    "installer tool input is not a regular file: {}",
                    relative.display()
                ));
            }
            if !seen.insert(relative.clone()) {
                return Err(format!("duplicate installer member {}", relative.display()));
            }
            let target = directory.path().join(relative);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let mut output = File::options()
                .write(true)
                .create_new(true)
                .open(target)
                .map_err(|e| e.to_string())?;
            let expected = entry.size();
            let copied = std::io::copy(&mut entry, &mut output).map_err(|e| e.to_string())?;
            if copied != expected {
                return Err("truncated installer archive member".into());
            }
        }
        drop(archive_reader);
        let after = file.metadata().map_err(|e| e.to_string())?;
        if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
            return Err("installer archive changed during verification".into());
        }
        let stage1 =
            std::fs::read(directory.path().join("boot/m1n1.bin")).map_err(|e| e.to_string())?;
        crate::asahi_ops::validate_stage1(&stage1).map_err(|e| e.to_string())?;
        let policies = ["main.py", "src/main.py"]
            .into_iter()
            .map(|name| directory.path().join(name))
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        if policies.len() != 1 {
            return Err("installer archive must contain one policy entry point".into());
        }
        let policy = std::fs::read(&policies[0]).map_err(|e| e.to_string())?;
        for member in [
            "asahi_firmware/__init__.py",
            "asahi_firmware/core.py",
            "asahi_firmware/cpio.py",
        ] {
            if !directory.path().join(member).is_file() {
                return Err(format!("installer archive lacks {member}"));
            }
        }
        Ok(Self {
            directory,
            stage1,
            policy,
            provenance: CatalogProvenance {
                source_uri: source_uri.into(),
                revision: digest,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn confines_installer_paths() {
        assert_eq!(
            normalized(Path::new("./src/main.py")).unwrap(),
            Path::new("src/main.py")
        );
        assert!(normalized(Path::new("../src/main.py")).is_err());
        assert!(normalized(Path::new("/src/main.py")).is_err());
        assert!(!needed(Path::new("unrelated/main.py")));
    }
    #[test]
    #[ignore = "requires ASAHI_INSTALLER_ARCHIVE containing the official installer"]
    fn opens_official_installer_as_one_bundle() {
        let directory = tempfile::tempdir().unwrap();
        let bundle = InstallerBundle::open(
            Path::new(&std::env::var("ASAHI_INSTALLER_ARCHIVE").unwrap()),
            "https://cdn.asahilinux.org/installer/installer-v0.9.1.tar.gz",
            directory.path(),
        )
        .unwrap();
        assert!(!bundle.stage1.is_empty());
        let policy = crate::asahi_firmware_catalog::read_installer_firmware_policy(
            &bundle.policy,
            "j274ap",
            0x8103,
            false,
            bundle.provenance,
        )
        .unwrap();
        assert!(!policy.catalog.is_empty());
    }
}
