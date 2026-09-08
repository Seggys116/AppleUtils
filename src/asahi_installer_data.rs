use crate::asahi_firmware_archive::ExtractedFirmware;
use plist::Value;
use std::io::Read;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallerDataTemplate {
    files: Vec<(String, Vec<u8>)>,
    stub_info: serde_json::Value,
    preboot_files: Vec<(String, Vec<u8>)>,
    system_files: Vec<(String, Vec<u8>)>,
    firmware: crate::asahi_firmware::BoundFirmware,
}
impl InstallerDataTemplate {
    pub fn files_for_vgid(&self, vgid: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
        validate_vgid(vgid)?;
        let mut info = self.stub_info.clone();
        info.as_object_mut()
            .ok_or("invalid stub info template")?
            .insert("vgid".into(), vgid.into());
        let mut files = self.files.clone();
        files.push((
            "stub_info.json".into(),
            serde_json::to_vec_pretty(&info).map_err(|e| e.to_string())?,
        ));
        Ok(files)
    }
    pub fn matches_firmware(&self, firmware: &crate::asahi_firmware::BoundFirmware) -> bool { &self.firmware == firmware }
    pub fn preboot_files(&self) -> &[(String, Vec<u8>)] { &self.preboot_files }
    pub fn system_files(&self) -> &[(String, Vec<u8>)] { &self.system_files }
    pub fn system_version_bytes(&self) -> &[u8] {
        &self
            .files
            .iter()
            .find(|(name, _)| name == "SystemVersion.plist")
            .expect("validated template SystemVersion")
            .1
    }
}

pub fn build_raw_firmware_backup(
    fud_directory: &Path,
    recovery_root: &Path,
    target_calibration: Option<&Path>,
) -> Result<tempfile::NamedTempFile, String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let output = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
    let request = serde_json::json!({"fud":fud_directory,"recovery":recovery_root,
        "calibration":target_calibration,"output":output.path()});
    let script = r#"
import sys,json,pathlib,tarfile
a=json.load(sys.stdin)
fud=pathlib.Path(a['fud']).resolve(strict=True)
recovery=pathlib.Path(a['recovery']).resolve(strict=True)
items=[(fud,'fud_firmware',fud),
    (recovery/'usr/share/firmware','firmware',recovery),
    (recovery/'usr/sbin/appleh13camerad','appleh13camerad',recovery)]
if a['calibration'] is not None:
    cal=pathlib.Path(a['calibration']).resolve(strict=True)
    items.append((cal/'apple','apple',cal))
    factory=cal/'com.apple.factorydata'
    if factory.exists(): items.append((factory,'com.apple.factorydata',cal))
links={}
link_file=recovery/'.appleutils-symlinks.json'
if link_file.exists():
    recorded=json.loads(link_file.read_text(encoding='utf-8'))
    if not isinstance(recorded,dict): raise ValueError('invalid recovery symlink metadata')
    for source,target in recorded.items():
        if not isinstance(source,str) or not isinstance(target,str) or not target or '\x00' in target:
            raise ValueError('invalid recovery symlink metadata')
        parts=source.split('/')
        if not source.startswith('/') or any(p in ('','.','..') for p in parts[1:]) or '\\' in source:
            raise ValueError('invalid recovery symlink path')
        if source.startswith('/usr/share/firmware/'):
            name='firmware/'+source[len('/usr/share/firmware/'):]
        elif source=='/usr/sbin/appleh13camerad':
            name='appleh13camerad'
        else: raise ValueError('recovery symlink is outside selected paths')
        links[name]=target

def recorded_link(name):
    return any(name==link or name.startswith(link+'/') for link in links)

def preserve(member):
    return None if recorded_link(member.name) else member

for path,name,root in items:
    for candidate in [path]+(list(path.rglob('*')) if path.is_dir() else []):
        archive_name=name+('/'+candidate.relative_to(path).as_posix() if candidate!=path else '')
        if not recorded_link(archive_name): candidate.resolve(strict=True).relative_to(root)
with tarfile.open(a['output'],'w:gz',dereference=False) as tar:
    for path,name,root in items:
        if path.exists() and not recorded_link(name): tar.add(path,arcname=name,filter=preserve)
        elif name not in links: raise FileNotFoundError(path)
    for name,target in sorted(links.items()):
        if any(name.startswith(parent+'/') for parent in links): continue
        member=tarfile.TarInfo(name)
        member.type=tarfile.SYMTYPE
        member.linkname=target
        member.mode=0o777
        tar.addfile(member)
"#;
    let mut child = Command::new("python3")
        .args(["-I", "-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let written = child
        .stdin
        .take()
        .ok_or("missing backup input")?
        .write_all(request.to_string().as_bytes());
    let result = child.wait_with_output().map_err(|e| e.to_string())?;
    written.map_err(|e| e.to_string())?;
    if !result.status.success() {
        return Err(format!(
            "raw firmware backup failed: {}",
            String::from_utf8_lossy(&result.stderr)
        ));
    }
    Ok(output)
}

fn metadata(bytes: &[u8]) -> Result<Value, String> {
    let value = Value::from_reader(std::io::Cursor::new(bytes)).map_err(|e| e.to_string())?;
    if value.as_dictionary().is_none() {
        return Err("installer metadata is not a dictionary".into());
    }
    Ok(value)
}

fn validate_version(value: &Value, version: &str, build: &str) -> Result<(), String> {
    let d = value.as_dictionary().ok_or("missing version dictionary")?;
    if d.get("ProductVersion").and_then(Value::as_string) != Some(version)
        || d.get("ProductBuildVersion").and_then(Value::as_string) != Some(build)
    {
        return Err("SystemVersion differs from selected restore identity".into());
    }
    Ok(())
}

fn validate_vgid(vgid: &str) -> Result<(), String> {
    if vgid.len() != 36
        || !vgid.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err("installer data requires the actual disk volume-group UUID".into());
    }
    Ok(())
}

pub(crate) fn relative_path(path: &str) -> Result<&str, String> {
    if path.is_empty() || path.contains(['\\', ':', '\0'])
        || path.split('/').any(|part| part.is_empty() || part == "." || part == "..") {
        return Err(format!("invalid restore bundle path {path:?}"));
    }
    Ok(path)
}

pub(crate) fn restore_bundle_path(bootcaches: &[u8]) -> Result<String, String> {
    let value = metadata(bootcaches)?;
    let path = value.as_dictionary().and_then(|d| d.get("bless2"))
        .and_then(Value::as_dictionary).and_then(|d| d.get("RestoreBundlePath"))
        .and_then(Value::as_string).ok_or("bootcaches lacks bless2 RestoreBundlePath")?;
    if path.starts_with('/') || path.contains(['\\', ':', '\0']) || path.split('/').any(|part| part.is_empty() || part == "..") {
        return Err(format!("invalid restore bundle path {path:?}"));
    }
    let normalized = path.split('/').filter(|part| *part != ".").collect::<Vec<_>>().join("/");
    relative_path(&normalized)?;
    Ok(normalized)
}

fn preboot_payloads(extracted: &ExtractedFirmware, manifest: &[u8], bootcaches: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let bundle = restore_bundle_path(bootcaches)?;
    let mut files = std::collections::BTreeMap::new();
    let mut insert = |relative: &str, bytes: Vec<u8>| -> Result<(), String> {
        relative_path(relative)?;
        let path = format!("{bundle}/{relative}");
        if let Some((old, _)) = files.iter().find(|(old, _): &(&String, &Vec<u8>)| old.eq_ignore_ascii_case(&path)) {
            return Err(format!("duplicate restore file {old}"));
        }
        files.insert(path, bytes);
        Ok(())
    };
    insert("BuildManifest.plist", manifest.to_vec())?;
    for name in ["SystemVersion.plist", "RestoreVersion.plist", "usr/standalone/bootcaches.plist"] {
        let path = extracted.metadata.get(name).ok_or_else(|| format!("missing restore metadata {name}"))?;
        insert(name, std::fs::read(path).map_err(|e| e.to_string())?)?;
    }
    let mut copied = std::collections::BTreeSet::new();
    for (key, relative) in &extracted.catalog {
        if !crate::asahi_firmware_archive::preboot_component(key) || !copied.insert(relative) { continue; }
        let path = extracted.extracted.get(key).ok_or_else(|| format!("missing selected restore component {key}"))?;
        insert(relative, std::fs::read(path).map_err(|e| e.to_string())?)?;
    }
    for (relative, path) in &extracted.preboot_supplemental {
        insert(relative, std::fs::read(path).map_err(|e| e.to_string())?)?;
    }
    Ok(files.into_iter().collect())
}

pub fn build_installer_data_template(
    extracted: &ExtractedFirmware,
    raw_firmware_backup: &Path,
) -> Result<InstallerDataTemplate, String> {
    let read_metadata = |name: &str| -> Result<Vec<u8>, String> {
        let path = extracted
            .metadata
            .get(name)
            .ok_or_else(|| format!("missing retained metadata {name}"))?;
        std::fs::read(path).map_err(|e| e.to_string())
    };
    let system_bytes = read_metadata("SystemVersion.plist")?;
    let system = metadata(&system_bytes)?;
    validate_version(
        &system,
        &extracted.bound.restore.product_version,
        &extracted.bound.restore.product_build,
    )?;
    let restore_bytes = read_metadata("RestoreVersion.plist")?;
    metadata(&restore_bytes)?;
    let mut manifest = metadata(
        &std::fs::read(extracted.directory.path().join("BuildManifest.plist"))
            .map_err(|e| e.to_string())?,
    )?;
    manifest.as_dictionary_mut().unwrap().insert(
        "BuildIdentities".into(),
        Value::Array(vec![Value::Dictionary(extracted.identity.clone())]),
    );
    let kernel = extracted
        .extracted
        .get("KernelCache")
        .ok_or("installer data requires selected KernelCache")?;
    let kernel_name = kernel
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("invalid kernelcache filename")?;
    if !kernel_name.starts_with("kernelcache.") {
        return Err("unsupported installer kernelcache filename".into());
    }
    let mut backup = std::fs::File::open(raw_firmware_backup).map_err(|e| e.to_string())?;
    let mut magic = [0; 2];
    backup.read_exact(&mut magic).map_err(|e| e.to_string())?;
    if magic != [0x1f, 0x8b] {
        return Err("raw firmware backup is not gzip".into());
    }
    let info = extracted
        .identity
        .get("Info")
        .and_then(Value::as_dictionary)
        .ok_or("selected identity lacks Info")?;
    let get = |key: &str| {
        info.get(key)
            .and_then(Value::as_string)
            .ok_or_else(|| format!("identity lacks {key}"))
    };
    let stub_info = serde_json::json!({"system_version":system,
        "manifest_info":{"build_number":get("BuildNumber")?,"variant":get("Variant")?,
        "device_class":get("DeviceClass")?,"board_id":extracted.identity.get("ApBoardID").ok_or("identity lacks board ID")?,
        "chip_id":extracted.identity.get("ApChipID").ok_or("identity lacks chip ID")?}});
    let mut manifest_bytes = Vec::new();
    manifest
        .to_writer_xml(&mut manifest_bytes)
        .map_err(|e| e.to_string())?;
    let bootcaches = read_metadata("usr/standalone/bootcaches.plist")?;
    let preboot_files = preboot_payloads(extracted, &manifest_bytes, &bootcaches)?;
    Ok(InstallerDataTemplate {
        firmware: extracted.bound.clone(),
        preboot_files,
        system_files: vec![("usr/standalone/bootcaches.plist".into(), bootcaches)],
        files: vec![
            ("BuildManifest.plist".into(), manifest_bytes),
            ("SystemVersion.plist".into(), system_bytes),
            ("RestoreVersion.plist".into(), restore_bytes),
            (
                kernel_name.into(),
                std::fs::read(kernel).map_err(|e| e.to_string())?,
            ),
            (
                "all_firmware.tar.gz".into(),
                std::fs::read(raw_firmware_backup).map_err(|e| e.to_string())?,
            ),
        ],
        stub_info,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture_bound() -> crate::asahi_firmware::BoundFirmware {
        serde_json::from_value(serde_json::json!({
            "selection": {"entry": {"version":"1","min_macos":"1","min_iboot":"1","min_sfr":"1","expert_only":false,"devices":null,"restore_url":"https://example.test/restore"}, "board":"testap","chip_id":1,"provenance":{"source_uri":"https://example.test/installer","revision":"test"}},
            "restore":{"product_version":"1","product_build":"test","board":"testap","chip_id":1,"identity":"test","manifest_digest":"test","archive_digest":"test"}
        })).unwrap()
    }

    #[test]
    fn restore_bundle_path_is_source_driven_and_confined() {
        let encode = |path: &str| {
            let value = Value::Dictionary([("bless2".to_owned(), Value::Dictionary([
                ("RestoreBundlePath".to_owned(), Value::String(path.into()))
            ].into_iter().collect()))].into_iter().collect());
            let mut bytes = Vec::new();
            value.to_writer_xml(&mut bytes).unwrap();
            bytes
        };
        assert_eq!(restore_bundle_path(&encode("custom/restore")).unwrap(), "custom/restore");
        assert_eq!(restore_bundle_path(&encode("./Restore")).unwrap(), "Restore");
        assert_eq!(restore_bundle_path(&encode("./custom/./restore")).unwrap(), "custom/restore");
        for path in ["/restore", "../restore", "a/../b", "a//b", "a\\b", "C:/restore", ""] {
            assert!(restore_bundle_path(&encode(path)).is_err(), "{path}");
        }
    }

    #[test]
    fn native_restore_payloads_preserve_selected_paths_and_skip_recovery_image() {
        use crate::asahi_firmware::*;
        let directory = tempfile::tempdir().unwrap();
        let bootcaches = br#"<?xml version="1.0"?><plist version="1.0"><dict><key>bless2</key><dict><key>RestoreBundlePath</key><string>source/restore</string></dict></dict></plist>"#;
        let mut metadata = std::collections::BTreeMap::new();
        for (name, bytes) in [("SystemVersion.plist", b"version".as_slice()), ("RestoreVersion.plist", b"restore".as_slice()), ("usr/standalone/bootcaches.plist", bootcaches.as_slice())] {
            let path = directory.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, bytes).unwrap();
            metadata.insert(name.into(), path);
        }
        let component = directory.path().join("component");
        std::fs::write(&component, b"original-firmware").unwrap();
        let bound = BoundFirmware {
            selection: SelectedFirmware {
                entry: FirmwareCatalogEntry { version: "1".into(), min_macos: "1".into(), min_iboot: "1".into(), min_sfr: "1".into(), expert_only: false, devices: None, restore_url: "https://example.test/restore".into() },
                board: "testap".into(), chip_id: 1,
                provenance: CatalogProvenance { source_uri: "https://example.test/installer".into(), revision: "test".into() },
            },
            restore: RestoreIdentity { product_version: "1".into(), product_build: "test".into(), board: "testap".into(), chip_id: 1, identity: "test".into(), manifest_digest: "test".into(), archive_digest: "test".into() },
        };
        let mut extracted = ExtractedFirmware {
            directory, bound, identity: plist::Dictionary::new(), metadata,
            catalog: [("DCP".into(), "Firmware/dcp.im4p".into()), ("BaseSystem".into(), "base.dmg".into())].into_iter().collect(),
            extracted: [("DCP".into(), component)].into_iter().collect(),
            preboot_supplemental: std::collections::BTreeMap::new(),
        };
        let files = preboot_payloads(&extracted, b"selected-manifest", bootcaches).unwrap();
        assert_eq!(files.iter().find(|(name, _)| name == "source/restore/Firmware/dcp.im4p").unwrap().1, b"original-firmware");
        assert!(files.iter().any(|(name, bytes)| name == "source/restore/BuildManifest.plist" && bytes == b"selected-manifest"));
        assert!(!files.iter().any(|(name, _)| name.ends_with("base.dmg")));
        extracted.catalog.insert("SEP".into(), "Firmware/sep.im4p".into());
        assert!(preboot_payloads(&extracted, b"manifest", bootcaches).unwrap_err().contains("missing selected restore component SEP"));
    }

    #[test]
    fn installed_restore_validation_detects_missing_and_stale_components() {
        use crate::asahi_firmware::*;
        let bound: BoundFirmware = fixture_bound();
        let system = br#"<?xml version="1.0"?><plist version="1.0"><dict><key>ProductName</key><string>Test</string><key>ProductVersion</key><string>1</string><key>ProductBuildVersion</key><string>test</string></dict></plist>"#.to_vec();
        let bootcaches = br#"<?xml version="1.0"?><plist version="1.0"><dict><key>bless2</key><dict><key>RestoreBundlePath</key><string>./Restore</string></dict></dict></plist>"#.to_vec();
        let mut manifest = plist::Value::from_reader(std::io::Cursor::new(br#"<?xml version="1.0"?><plist version="1.0"><dict><key>ProductVersion</key><string>1</string><key>ProductBuildVersion</key><string>test</string><key>BuildIdentities</key><array><dict><key>ApChipID</key><integer>1</integer><key>Info</key><dict><key>DeviceClass</key><string>testap</string><key>Variant</key><string>macOS Customer</string><key>RestoreBehavior</key><string>Erase</string></dict><key>Manifest</key><dict><key>DCP</key><dict><key>Info</key><dict><key>Path</key><string>Firmware/dcp.im4p</string></dict></dict></dict></dict></array></dict></plist>"#)).unwrap();
        manifest.as_dictionary_mut().unwrap().get_mut("BuildIdentities").unwrap().as_array_mut().unwrap()[0].as_dictionary_mut().unwrap().get_mut("Manifest").unwrap().as_dictionary_mut().unwrap().get_mut("DCP").unwrap().as_dictionary_mut().unwrap().insert("Digest".into(), Value::Data(crate::crypto::sha256(b"source-firmware").to_vec()));
        let mut manifest_bytes = Vec::new();
        manifest.to_writer_xml(&mut manifest_bytes).unwrap();
        let mut artifacts = crate::asahi_ops::Artifacts::memory(b"kernel".to_vec(), b"stage2".to_vec(), vec![0;4096]);
        artifacts.m1n1_stage1 = vec![0;2048];
        artifacts.m1n1_stage1.extend_from_slice(b"##m1n1_ver##test\0chainload=\0");
        artifacts.installer_data = Some(InstallerDataTemplate {
            firmware: bound.clone(),
            files: vec![("SystemVersion.plist".into(), system.clone())], stub_info: serde_json::json!({}),
            system_files: vec![("usr/standalone/bootcaches.plist".into(), bootcaches.clone())],
            preboot_files: vec![("Restore/SystemVersion.plist".into(), system.clone()), ("Restore/BuildManifest.plist".into(), manifest_bytes), ("Restore/usr/standalone/bootcaches.plist".into(), bootcaches), ("Restore/Firmware/dcp.im4p".into(), b"source-firmware".to_vec())],
        });
        let dir = tempfile::tempdir().unwrap();
        let disk = dir.path().join("disk.qcow2");
        crate::asahi_ops::create_qcow2_disc(&disk, &artifacts, 16*1024*1024, "m1n1/boot.bin", "Test").unwrap();
        assert!(!crate::asahi_ops::validate_installed_restore_bundle(&disk, &bound).unwrap());
        let legacy = dir.path().join("legacy.qcow2");
        let mut legacy_artifacts = artifacts.clone();
        legacy_artifacts.installer_data = None;
        crate::asahi_ops::create_qcow2_disc(&legacy, &legacy_artifacts, 16*1024*1024, "m1n1/boot.bin", "Test").unwrap();
        crate::asahi_ops::update_disc(&legacy, &artifacts).unwrap();
        crate::asahi_ops::validate_installed_restore_bundle(&legacy, &bound).unwrap();
        let mut other = bound.clone();
        other.restore.product_build = "different".into();
        artifacts.firmware = Some(other);
        assert!(crate::asahi_ops::create_qcow2_disc(&disk, &artifacts, 16*1024*1024, "m1n1/boot.bin", "Test").unwrap_err().to_string().contains("on-disk restore bundle"));
        crate::asahi_ops::validate_installed_restore_bundle(&disk, &bound).unwrap();
        artifacts.firmware = None;
        artifacts.installer_data.as_mut().unwrap().preboot_files.last_mut().unwrap().1 = b"stale-firmware".to_vec();
        crate::asahi_ops::update_disc(&disk, &artifacts).unwrap();
        assert!(crate::asahi_ops::validate_installed_restore_bundle(&disk, &bound).unwrap_err().to_string().contains("digest mismatch"));
        artifacts.installer_data.as_mut().unwrap().preboot_files.pop();
        let missing = dir.path().join("missing.qcow2");
        crate::asahi_ops::create_qcow2_disc(&missing, &artifacts, 16*1024*1024, "m1n1/boot.bin", "Test").unwrap();
        assert!(crate::asahi_ops::validate_installed_restore_bundle(&missing, &bound).unwrap_err().to_string().contains("component DCP is missing"));
        let template = artifacts.installer_data.as_mut().unwrap();
        let changed = String::from_utf8(system).unwrap().replace("<string>1</string>", "<string>2</string>").into_bytes();
        template.files[0].1 = changed.clone();
        template.preboot_files[0].1 = changed;
        let stale = dir.path().join("stale-version.qcow2");
        crate::asahi_ops::create_qcow2_disc(&stale, &artifacts, 16*1024*1024, "m1n1/boot.bin", "Test").unwrap();
        assert!(crate::asahi_ops::validate_installed_restore_bundle(&stale, &bound).unwrap_err().to_string().contains("SystemVersion.plist ProductVersion differs"));
    }

    #[test]
    fn fallback_archive_contains_selected_inputs_and_template_binds_real_vgid() {
        let root = tempfile::tempdir().unwrap();
        let fud = root.path().join("fud");
        let recovery = root.path().join("recovery");
        std::fs::create_dir_all(&fud).unwrap();
        std::fs::create_dir_all(recovery.join("usr/share/firmware")).unwrap();
        std::fs::create_dir_all(recovery.join("usr/sbin")).unwrap();
        std::fs::write(fud.join("target.im4p"), b"selected-fud").unwrap();
        std::fs::write(recovery.join("usr/share/firmware/target.bin"), b"selected-firmware").unwrap();
        std::fs::write(recovery.join("usr/sbin/appleh13camerad"), b"selected-camera").unwrap();
        let backup = build_raw_firmware_backup(&fud, &recovery, None).unwrap();
        let result = std::process::Command::new("tar").arg("-xOf").arg(backup.path())
            .arg("firmware/target.bin").output().unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout, b"selected-firmware");
        let template = InstallerDataTemplate { firmware: fixture_bound(), preboot_files: vec![], system_files: vec![], files: vec![("SystemVersion.plist".into(), b"source".to_vec())],
            stub_info: serde_json::json!({"manifest_info":{"build_number":"test"}}) };
        let vgid = "01234567-89ab-cdef-0123-456789abcdef";
        let files = template.files_for_vgid(vgid).unwrap();
        let info: serde_json::Value = serde_json::from_slice(&files.last().unwrap().1).unwrap();
        assert_eq!(info["vgid"], vgid);
        assert!(info.get("admin_users").is_none());
        assert!(template.stub_info.get("vgid").is_none());
    }

    #[test]
    fn fallback_archive_preserves_recorded_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let fud = root.path().join("fud");
        let recovery = root.path().join("recovery");
        let firmware = recovery.join("usr/share/firmware");
        std::fs::create_dir_all(&fud).unwrap();
        std::fs::create_dir_all(firmware.join("directory-link")).unwrap();
        std::fs::create_dir_all(recovery.join("usr/sbin")).unwrap();
        std::fs::write(recovery.join("usr/sbin/appleh13camerad"), b"camera").unwrap();
        std::fs::write(firmware.join("original"), b"firmware").unwrap();
        std::fs::write(firmware.join("valid"), b"firmware").unwrap();
        std::fs::write(firmware.join("directory-link/copied"), b"duplicate").unwrap();
        let metadata = serde_json::json!({
            "/usr/share/firmware/dangling": "missing.trx",
            "/usr/share/firmware/valid": "original",
            "/usr/share/firmware/directory-link": "original-directory"
        });
        std::fs::write(recovery.join(".appleutils-symlinks.json"), metadata.to_string()).unwrap();
        let backup = build_raw_firmware_backup(&fud, &recovery, None).unwrap();
        let reader = flate2::read::GzDecoder::new(std::fs::File::open(backup.path()).unwrap());
        let mut archive = tar::Archive::new(reader);
        let mut found = std::collections::BTreeMap::new();
        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            let name = entry.path().unwrap().to_string_lossy().into_owned();
            assert_ne!(name, "firmware/directory-link/copied");
            assert!(!name.contains(".appleutils-symlinks.json"));
            if entry.header().entry_type().is_symlink() {
                found.insert(name, entry.link_name().unwrap().unwrap().to_string_lossy().into_owned());
                assert_eq!(entry.size(), 0);
            }
        }
        assert_eq!(found.get("firmware/dangling").unwrap(), "missing.trx");
        assert_eq!(found.get("firmware/valid").unwrap(), "original");
        assert_eq!(found.get("firmware/directory-link").unwrap(), "original-directory");
        let invalid = serde_json::json!({"/usr/share/firmware/../escape": "missing"});
        std::fs::write(recovery.join(".appleutils-symlinks.json"), invalid.to_string()).unwrap();
        assert!(build_raw_firmware_backup(&fud, &recovery, None).unwrap_err().contains("invalid recovery symlink path"));
    }

    #[test]
    fn metadata_identity_and_vgid_are_required() {
        assert!(validate_vgid("unknown").is_err());
        assert!(validate_vgid("01234567-89ab-cdef-0123-456789abcdef").is_ok());
        assert!(metadata(b"not a plist").is_err());
        let value = Value::Dictionary(
            [
                ("ProductVersion".to_string(), Value::String("5".into())),
                (
                    "ProductBuildVersion".to_string(),
                    Value::String("B1".into()),
                ),
            ]
            .into_iter()
            .collect(),
        );
        validate_version(&value, "5", "B1").unwrap();
        assert!(validate_version(&value, "5", "B2").is_err());
        assert!(validate_version(&value, "6", "B1").is_err());
    }
}
