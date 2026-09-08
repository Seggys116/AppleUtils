use crate::asahi_firmware::{BoundFirmware, select_firmware, validate_repair};
use crate::asahi_firmware_archive::{ComponentSelection, ExtractedFirmware, extract_firmware};
use crate::asahi_firmware_catalog::read_installer_firmware_policy;
use crate::asahi_installer_bundle::InstallerBundle;
use crate::asahi_ops::{Artifacts, FirmwareRequirements};
use crate::asahi_vendor_firmware::{
    VendorFirmwareInputs, VendorFirmwarePackage, build_vendor_firmware,
};
use plist::Value;
use std::path::{Component, Path};

pub struct ProvisioningInputs<'a> {
    pub board: &'a str,
    pub chip_id: u32,
    pub expert: bool,
    pub installer_archive: &'a Path,
    pub installer_source_uri: &'a str,
    pub ipsw: &'a Path,
    pub workdir: &'a Path,
    pub repair_identity: Option<&'a BoundFirmware>,
}

pub struct PreparedFirmware {
    pub installer: InstallerBundle,
    pub restore: ExtractedFirmware,
    pub fud_directory: tempfile::TempDir,
    requirements: FirmwareRequirements,
}

pub struct ProvisionedFirmware {
    pub prepared: PreparedFirmware,
    pub vendor: VendorFirmwarePackage,
}

fn leaf(value: &str) -> Result<&str, String> {
    if value.is_empty()
        || value.contains(['\\', ':', '\0'])
        || Path::new(value).components().count() != 1
        || !matches!(
            Path::new(value).components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err(format!("invalid firmware identity filename {value:?}"));
    }
    Ok(value)
}

fn fud_keys(identity: &plist::Dictionary) -> Result<Vec<String>, String> {
    let components = identity
        .get("Manifest")
        .and_then(Value::as_dictionary)
        .ok_or("missing component manifest")?;
    let mut keys = Vec::new();
    for (key, value) in components {
        let info = value
            .as_dictionary()
            .and_then(|v| v.get("Info"))
            .and_then(Value::as_dictionary)
            .ok_or_else(|| format!("missing component Info for {key}"))?;
        let flag = |name: &str| -> Result<bool, String> {
            match info.get(name) {
                Some(Value::Boolean(value)) => Ok(*value),
                None => Ok(false),
                _ => Err(format!("malformed {name} on {key}")),
            }
        };
        if flag("IsFUDFirmware")? && !flag("IsLoadedByiBoot")? && !flag("IsLoadedByiBootStage1")? {
            let path = info
                .get("Path")
                .and_then(Value::as_string)
                .ok_or("missing FUD path")?;
            if path.ends_with(".im4p") {
                leaf(key)?;
                keys.push(key.clone());
            }
        }
    }
    Ok(keys)
}

pub fn prepare_firmware(
    inputs: &ProvisioningInputs<'_>,
    requirements: &FirmwareRequirements,
) -> Result<PreparedFirmware, String> {
    if requirements
        .firmware_partitions
        .iter()
        .any(|name| !name.eq_ignore_ascii_case("EFI"))
    {
        return Err("unsupported firmware target partition".into());
    }
    let installer = InstallerBundle::open(
        inputs.installer_archive,
        inputs.installer_source_uri,
        inputs.workdir,
    )?;
    let policy = read_installer_firmware_policy(
        &installer.policy,
        inputs.board,
        inputs.chip_id,
        inputs.expert,
        installer.provenance.clone(),
    )?;
    let supported = if let Some(installed) = inputs.repair_identity {
        if requirements
            .supported_fw
            .as_ref()
            .is_some_and(|versions| !versions.contains(&installed.restore.product_version))
        {
            return Err("installed firmware is no longer supported by package".into());
        }
        Some(vec![installed.restore.product_version.clone()])
    } else {
        requirements.supported_fw.clone()
    };
    let archive_info = crate::asahi_firmware_archive::inspect_restore_archive(inputs.ipsw)?;
    crate::asahi_firmware::validate_supported_version(&archive_info.product_version, supported.as_deref())?;
    let selected_version = [archive_info.product_version];
    let selection = select_firmware(
        &policy.catalog,
        Some(&selected_version),
        &policy.target,
        &policy.provenance,
    )?;
    let restore = extract_firmware(
        inputs.ipsw,
        selection,
        inputs.workdir,
        ComponentSelection::BootAndVendorInputs,
    )?;
    if let Some(installed) = inputs.repair_identity {
        validate_repair(installed, &restore.bound)?;
    }
    let fud_directory = tempfile::Builder::new()
        .prefix("asahi-fud-")
        .tempdir_in(inputs.workdir)
        .map_err(|e| e.to_string())?;
    let device = leaf(
        inputs
            .board
            .strip_suffix("ap")
            .ok_or("restore device class must end in ap")?,
    )?;
    let device_root = fud_directory.path().join(device);
    std::fs::create_dir(&device_root).map_err(|e| e.to_string())?;
    for key in fud_keys(&restore.identity)? {
        let source = restore
            .extracted
            .get(&key)
            .ok_or_else(|| format!("selected FUD component was not extracted: {key}"))?;
        std::fs::copy(source, device_root.join(format!("{key}.im4p")))
            .map_err(|e| e.to_string())?;
    }
    Ok(PreparedFirmware {
        installer,
        restore,
        fud_directory,
        requirements: requirements.clone(),
    })
}

impl PreparedFirmware {
    pub fn recovery_image(&self) -> Result<&Path, String> {
        self.restore
            .extracted
            .get("BaseSystem")
            .map(|p| p.as_path())
            .ok_or("selected BaseSystem was not extracted".into())
    }

    pub fn provision_artifacts(
        self,
        artifacts: &mut Artifacts,
        recovery_root: &Path,
        target_calibration: Option<&Path>,
        requires_als_calibration: bool,
    ) -> Result<ProvisionedFirmware, String> {
        if artifacts.firmware_requirements.as_ref() != Some(&self.requirements) {
            return Err("artifact firmware requirements changed during provisioning".into());
        }
        let vendor = build_vendor_firmware(&VendorFirmwareInputs {
            installer_root: self.installer.directory.path(),
            installer_digest: &self.installer.provenance.revision,
            fud_directory: self.fud_directory.path(),
            kernelcache_im4p: self
                .restore
                .extracted
                .get("KernelCache")
                .ok_or("missing selected kernelcache")?,
            recovery_root,
            target_calibration,
            requires_als_calibration,
        })?;
        let backup = crate::asahi_installer_data::build_raw_firmware_backup(
            self.fud_directory.path(), recovery_root, target_calibration,
        )?;
        let installer_data = Some(crate::asahi_installer_data::build_installer_data_template(&self.restore, backup.path())?);
        let files = vendor
            .files
            .iter()
            .map(|file| {
                let bytes = std::fs::read(vendor.directory.path().join(&file.path))
                    .map_err(|e| e.to_string())?;
                Ok((format!("vendorfw/{}", file.path), bytes))
            })
            .collect::<Result<Vec<_>, String>>()?;
        attach_with_installer_data(
            artifacts,
            &self.restore.bound,
            &self.installer.stage1,
            files,
            installer_data,
        )?;
        Ok(ProvisionedFirmware {
            prepared: self,
            vendor,
        })
    }
}

#[cfg(test)]
fn attach(
    artifacts: &mut Artifacts,
    bound: &BoundFirmware,
    stage1: &[u8],
    files: Vec<(String, Vec<u8>)>,
) -> Result<(), String> {
    attach_with_installer_data(artifacts, bound, stage1, files, None)
}

fn attach_with_installer_data(
    artifacts: &mut Artifacts,
    bound: &BoundFirmware,
    stage1: &[u8],
    files: Vec<(String, Vec<u8>)>,
    installer_data: Option<crate::asahi_installer_data::InstallerDataTemplate>,
) -> Result<(), String> {
    for (name, bytes) in &files {
        if artifacts
            .efi_files
            .iter()
            .any(|(old, data)| old.eq_ignore_ascii_case(name) && data != bytes)
        {
            return Err(format!(
                "existing EFI file conflicts with selected firmware: {name}"
            ));
        }
    }
    for (old, _) in &artifacts.efi_files {
        if old.to_ascii_lowercase().starts_with("vendorfw/")
            && !files.iter().any(|(name, _)| name.eq_ignore_ascii_case(old))
        {
            return Err(format!(
                "existing vendor firmware is absent from selected package: {old}"
            ));
        }
    }
    let original_len = artifacts.efi_files.len();
    for (name, bytes) in files {
        if !artifacts
            .efi_files
            .iter()
            .any(|(old, _)| old.eq_ignore_ascii_case(&name))
        {
            artifacts.efi_files.push((name, bytes));
        }
    }
    let old_installer_data = std::mem::replace(&mut artifacts.installer_data, installer_data);
    let old_firmware = artifacts.firmware.replace(bound.clone());
    let old_stage1 = std::mem::replace(&mut artifacts.m1n1_stage1, stage1.to_vec());
    if let Err(error) = artifacts.validate_firmware() {
        artifacts.efi_files.truncate(original_len);
        artifacts.firmware = old_firmware;
        artifacts.installer_data = old_installer_data;
        artifacts.m1n1_stage1 = old_stage1;
        return Err(error.to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn attachment_commits_verified_identity_and_refuses_mixed_vendor_packages() {
        use crate::asahi_firmware::*;
        let bound = BoundFirmware {
            selection: SelectedFirmware {
                entry: FirmwareCatalogEntry {
                    version: "1".into(),
                    min_macos: "1".into(),
                    min_iboot: "1".into(),
                    min_sfr: "1".into(),
                    expert_only: false,
                    devices: None,
                    restore_url: "https://example.test/archive".into(),
                },
                board: "testap".into(),
                chip_id: 1,
                provenance: CatalogProvenance {
                    source_uri: "https://example.test/installer".into(),
                    revision: "test".into(),
                },
            },
            restore: RestoreIdentity {
                product_version: "1".into(),
                product_build: "test".into(),
                board: "testap".into(),
                chip_id: 1,
                identity: "test".into(),
                manifest_digest: "test".into(),
                archive_digest: "test".into(),
            },
        };
        let mut artifacts = Artifacts::memory(vec![], vec![], vec![]);
        artifacts.firmware_requirements = Some(FirmwareRequirements {
            supported_fw: Some(vec!["1".into()]),
            firmware_partitions: vec!["EFI".into()],
            installer_data_partitions: vec![],
        });
        attach(
            &mut artifacts,
            &bound,
            b"stage one",
            vec![("vendorfw/firmware.cpio".into(), b"package".to_vec())],
        )
        .unwrap();
        assert_eq!(artifacts.firmware.as_ref(), Some(&bound));
        assert_eq!(artifacts.m1n1_stage1, b"stage one");
        let before = artifacts.clone();
        assert!(
            attach(
                &mut artifacts,
                &bound,
                b"different",
                vec![("vendorfw/other".into(), vec![1])]
            )
            .is_err()
        );
        assert_eq!(artifacts, before);
        artifacts
            .firmware_requirements
            .as_mut()
            .unwrap()
            .supported_fw = Some(vec!["2".into()]);
        let before = artifacts.clone();
        assert!(
            attach(
                &mut artifacts,
                &bound,
                b"different",
                vec![("vendorfw/firmware.cpio".into(), b"package".to_vec())]
            )
            .is_err()
        );
        assert_eq!(artifacts, before);
    }
    #[test]
    fn fud_selection_preserves_official_boot_exclusion_and_container_filter() {
        let mut manifest = plist::Dictionary::new();
        for (key, boot, path) in [
            ("Touch", false, "firmware/a.im4p"),
            ("Boot", true, "firmware/b.im4p"),
            ("Raw", false, "firmware/c.bin"),
        ] {
            let mut info = plist::Dictionary::new();
            info.insert("IsFUDFirmware".into(), Value::Boolean(true));
            info.insert("IsLoadedByiBoot".into(), Value::Boolean(boot));
            info.insert("Path".into(), Value::String(path.into()));
            let mut entry = plist::Dictionary::new();
            entry.insert("Info".into(), Value::Dictionary(info));
            manifest.insert(key.into(), Value::Dictionary(entry));
        }
        let mut identity = plist::Dictionary::new();
        identity.insert("Manifest".into(), Value::Dictionary(manifest));
        assert_eq!(fud_keys(&identity).unwrap(), ["Touch"]);
        for value in ["../Touch", "a/b", "a\\b", "..", ""] {
            assert!(leaf(value).is_err());
        }
    }
}

pub struct RecoveryImageFiles {
    directory: tempfile::TempDir,
}

impl RecoveryImageFiles {
    pub fn extract(image: &Path) -> Result<Self, String> {
        let paths = vec!["/usr/share/firmware".into(), "/usr/sbin/appleh13camerad".into()];
        let cache = crate::asahi_cache::root();
        let directory = crate::asahi_recovery_cache::extract(cache.as_deref(), image, &paths, || {
            crate::explorer_image::extract_paths_with_link_metadata(image, &paths).map_err(|e| e.to_string())
        }).map_err(|e| format!("Failed to extract recovery firmware from IPSW BaseSystem {}: {e}", image.display()))?;
        Ok(Self { directory })
    }

    pub fn root(&self) -> &Path { self.directory.path() }
}

#[cfg(test)]
mod restore_integration_tests {
    use super::*;

    #[test]
    #[ignore = "requires official installer archive and selected IPSW; extracts selected RecoveryOS files"]
    fn packages_selected_restore_firmware() {
        let installer = std::path::PathBuf::from(std::env::var("ASAHI_INSTALLER_ARCHIVE").unwrap());
        let ipsw = std::path::PathBuf::from(std::env::var("ASAHI_RESTORE_ARCHIVE").unwrap());
        let requirements: FirmwareRequirements = serde_json::from_slice(
            &std::fs::read(std::env::var("ASAHI_FIRMWARE_REQUIREMENTS").unwrap()).unwrap()
        ).unwrap();
        let board = std::env::var("ASAHI_TARGET_BOARD").unwrap();
        let chip = std::env::var("ASAHI_TARGET_CHIP").unwrap();
        let chip_id = u32::from_str_radix(chip.trim_start_matches("0x"), 16).unwrap();
        let requires_als: bool = std::env::var("ASAHI_REQUIRES_ALS").unwrap().parse().unwrap();
        let calibration = std::env::var_os("ASAHI_TARGET_CALIBRATION").map(std::path::PathBuf::from);
        let workdir = tempfile::tempdir().unwrap();
        let inputs = ProvisioningInputs {
            board: &board, chip_id, expert: false, installer_archive: &installer,
            installer_source_uri: "https://alx.sh/installer", ipsw: &ipsw,
            workdir: workdir.path(), repair_identity: None,
        };
        let prepared = prepare_firmware(&inputs, &requirements).unwrap();
        eprintln!("selected restore {} {}", prepared.restore.bound.restore.product_version,
            prepared.restore.bound.restore.product_build);
        let mount = RecoveryImageFiles::extract(prepared.recovery_image().unwrap()).unwrap();
        let mut artifacts = Artifacts::memory(Vec::new(), Vec::new(), Vec::new());
        artifacts.firmware_requirements = Some(requirements);
        let provisioned = prepared.provision_artifacts(&mut artifacts, mount.root(),
            calibration.as_deref(), requires_als).unwrap();
        artifacts.validate_firmware().unwrap();
        for name in ["vendorfw/firmware.tar", "vendorfw/firmware.cpio", "vendorfw/manifest.txt"] {
            assert!(artifacts.efi_files.iter().any(|(path, bytes)| path == name && !bytes.is_empty()),
                "missing {name}");
        }
        assert!(!artifacts.installer_data.as_ref().unwrap().preboot_files().is_empty());
        assert!(provisioned.prepared.restore.directory.path().is_dir());
    }
}

#[cfg(test)]
mod recovery_error_tests {
    #[test]
    fn recovery_failure_identifies_source_image() {
        let root = tempfile::tempdir().unwrap();
        let image = root.path().join("BaseSystem.dmg");
        std::fs::write(&image, vec![0u8; 65536]).unwrap();
        let error = super::RecoveryImageFiles::extract(&image).err().unwrap();
        assert!(error.contains("IPSW BaseSystem"));
        assert!(error.contains("BaseSystem.dmg"));
        assert!(error.contains("APFS"));
    }
}
