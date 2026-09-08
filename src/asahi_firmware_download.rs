use crate::asahi_firmware::{BoundFirmware, select_firmware};
use crate::asahi_firmware_catalog::read_installer_firmware_policy;
use crate::asahi_installer_bundle::InstallerBundle;
use crate::asahi_ops::{self, FirmwareRequirements};
use std::path::{Path, PathBuf};

pub struct FirmwareArchiveInputs<'a> {
    pub board: &'a str,
    pub chip_id: u32,
    pub expert: bool,
    pub workdir: &'a Path,
    pub requirements: &'a FirmwareRequirements,
    pub installer_archive: Option<&'a Path>,
    pub installer_source_uri: Option<&'a str>,
    pub ipsw: Option<&'a Path>,
    pub repair_identity: Option<&'a BoundFirmware>,
}

pub struct ResolvedFirmwareArchives {
    pub directory: tempfile::TempDir,
    pub installer_archive: PathBuf,
    pub installer_source_uri: String,
    pub ipsw: PathBuf,
    pub restore_source_uri: String,
}

fn installer_url(version: &str) -> Result<String, String> {
    let version = version.trim();
    if version.is_empty()
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
    {
        return Err("official installer version contains invalid characters".into());
    }
    Ok(format!(
        "https://cdn.asahilinux.org/installer/installer-{version}.tar.gz"
    ))
}

fn local_file(path: &Path) -> Result<PathBuf, String> {
    let path = path
        .canonicalize()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if !path.is_file() {
        return Err(format!("archive is not a regular file: {}", path.display()));
    }
    Ok(path)
}

fn download(
    url: &str,
    destination: &Path,
    mut progress: impl FnMut(&str, Option<f64>),
) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err("remote firmware archive requires HTTPS".into());
    }
    let pending = destination.with_extension("partial");
    progress(url, Some(0.0));
    asahi_ops::fetch_url_to_file_with_progress(url, &pending, |value| progress(url, value))
        .map_err(|e| e.to_string())?;
    if std::fs::metadata(&pending)
        .map_err(|e| e.to_string())?
        .len()
        == 0
    {
        return Err(format!("downloaded archive is empty: {url}"));
    }
    std::fs::rename(&pending, destination).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn resolve_firmware_archives(
    inputs: &FirmwareArchiveInputs<'_>,
    mut progress: impl FnMut(&str, Option<f64>),
) -> Result<ResolvedFirmwareArchives, String> {
    let ipsw = local_file(inputs.ipsw.ok_or("select a local IPSW file before starting setup")?)?;
    let supported = if let Some(repair) = inputs.repair_identity {
        if inputs
            .requirements
            .supported_fw
            .as_ref()
            .is_some_and(|versions| !versions.contains(&repair.restore.product_version))
        {
            return Err("repair firmware is outside package compatibility policy".into());
        }
        Some(vec![repair.restore.product_version.clone()])
    } else {
        inputs.requirements.supported_fw.clone()
    };
    let archive_info = crate::asahi_firmware_archive::validate_archive_for_package(
        &ipsw, supported.as_deref(), Some((inputs.board, inputs.chip_id)),
    )?;
    std::fs::create_dir_all(inputs.workdir).map_err(|e| e.to_string())?;
    let directory = tempfile::Builder::new()
        .prefix("asahi-download-")
        .tempdir_in(inputs.workdir)
        .map_err(|e| e.to_string())?;
    let (installer_archive, installer_source_uri) = if let Some(local) = inputs.installer_archive {
        let path = local_file(local)?;
        let source = inputs
            .installer_source_uri
            .map(str::to_owned)
            .unwrap_or_else(|| path.display().to_string());
        (path, source)
    } else {
        if inputs.installer_source_uri.is_some() {
            return Err("--installer-source-uri requires a local --installer-archive".into());
        }
        let endpoint = "https://cdn.asahilinux.org/installer/latest";
        progress(endpoint, None);
        let version = String::from_utf8(asahi_ops::fetch_url(endpoint).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let url = installer_url(&version)?;
        let path = directory.path().join("installer.tar.gz");
        download(&url, &path, &mut progress)?;
        (path, url)
    };
    let installer =
        InstallerBundle::open(&installer_archive, &installer_source_uri, directory.path())?;
    let policy = read_installer_firmware_policy(
        &installer.policy,
        inputs.board,
        inputs.chip_id,
        inputs.expert,
        installer.provenance.clone(),
    )?;
    let selected_version = [archive_info.product_version];
    let selected = select_firmware(
        &policy.catalog,
        Some(&selected_version),
        &policy.target,
        &policy.provenance,
    ).map_err(|error| {
        let mut allowed = Vec::new();
        for entry in &policy.catalog {
            if supported.as_ref().is_some_and(|versions| !versions.contains(&entry.version)) { continue; }
            let version = [entry.version.clone()];
            if select_firmware(&policy.catalog, Some(&version), &policy.target, &policy.provenance).is_ok()
                && !allowed.contains(&entry.version) { allowed.push(entry.version.clone()); }
        }
        format!("IPSW macOS {} cannot be used for {}. Supported firmware for this target and package: {}. {error}",
            selected_version[0], inputs.board, if allowed.is_empty() { "none".into() } else { allowed.join(", ") })
    })?;
    let restore_source_uri = selected.entry.restore_url;
    Ok(ResolvedFirmwareArchives {
        directory,
        installer_archive,
        installer_source_uri,
        ipsw,
        restore_source_uri,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn official_version_cannot_escape_archive_url() {
        assert_eq!(
            installer_url(" v0.9.1\n").unwrap(),
            "https://cdn.asahilinux.org/installer/installer-v0.9.1.tar.gz"
        );
        for value in ["", "../other", "version?query", "a/b", "a b"] {
            assert!(installer_url(value).is_err());
        }
    }
    #[test]
    fn missing_ipsw_fails_before_progress_or_network() {
        let directory = tempfile::tempdir().unwrap();
        let work = directory.path().join("unused");
        let requirements = FirmwareRequirements {
            supported_fw: None, firmware_partitions: vec![], installer_data_partitions: vec![],
        };
        let inputs = FirmwareArchiveInputs {
            board: "testap", chip_id: 1, expert: false, workdir: &work,
            requirements: &requirements, installer_archive: None,
            installer_source_uri: None, ipsw: None, repair_identity: None,
        };
        let mut progressed = false;
        let result = resolve_firmware_archives(&inputs, |_, _| progressed = true);
        assert!(result.err().unwrap().contains("select a local IPSW"));
        assert!(!progressed);
        assert!(!work.exists());
    }

    #[test]
    fn local_inputs_require_real_files() {
        let directory = tempfile::tempdir().unwrap();
        assert!(local_file(directory.path()).is_err());
        assert!(local_file(&directory.path().join("absent")).is_err());
        let file = directory.path().join("restore.ipsw");
        std::fs::write(&file, b"fixture archive input").unwrap();
        assert_eq!(local_file(&file).unwrap(), file.canonicalize().unwrap());
    }
}
