use crate::asahi_firmware::{
    BoundFirmware, RestoreIdentity, SelectedFirmware, bind_restore_identity,
};
use crate::asahi_ops::{ZipMember, zip_list_file, zip_open_payload};
use crate::crypto::{Sha256, Sha512};
use plist::{Dictionary, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

pub struct ExtractedFirmware {
    pub directory: tempfile::TempDir,
    pub bound: BoundFirmware,
    pub identity: Dictionary,
    pub catalog: BTreeMap<String, String>,
    pub extracted: BTreeMap<String, PathBuf>,
    pub metadata: BTreeMap<String, PathBuf>,
    pub preboot_supplemental: BTreeMap<String, PathBuf>,
}

pub enum ComponentSelection<'a> {
    Explicit(&'a [String]),
    BootAndVendorInputs,
}

fn requested_keys(
    components: &Dictionary,
    selection: ComponentSelection<'_>,
) -> Result<Vec<String>, String> {
    if let ComponentSelection::Explicit(keys) = selection {
        return Ok(keys.to_vec());
    }
    let required = ["iBoot", "DeviceTree", "KernelCache", "BaseSystem"];
    let mut selected: BTreeSet<String> = required.iter().map(|key| (*key).to_owned()).collect();
    for key in required {
        let entry = components
            .get(key)
            .and_then(Value::as_dictionary)
            .ok_or_else(|| format!("missing required boot/vendor component {key}"))?;
        let info = entry
            .get("Info")
            .and_then(Value::as_dictionary)
            .ok_or_else(|| format!("missing component Info for {key}"))?;
        safe_path(string(info, "Path")?)?;
    }
    for (key, value) in components {
        if !preboot_component(key) {
            continue;
        }
        let entry = value.as_dictionary().ok_or("malformed component")?;
        let info = entry.get("Info").and_then(Value::as_dictionary)
            .ok_or_else(|| format!("missing component Info for {key}"))?;
        safe_path(string(info, "Path")?)?;
        selected.insert(key.clone());
    }
    Ok(selected.into_iter().collect())
}

pub(crate) fn preboot_component(key: &str) -> bool {
    !matches!(key, "BaseSystem" | "OS" | "Ap,SystemVolumeCanonicalMetadata" | "RestoreRamDisk" | "RestoreTrustCache")
        && !key.starts_with("Cryptex")
}

pub(crate) fn machine_sep_candidates(manifest: &Dictionary, selected: &Dictionary) -> Result<Vec<(String, Dictionary)>, String> {
    let board = integer(selected.get("ApBoardID")).ok_or("selected identity lacks board ID")?;
    let chip = integer(selected.get("ApChipID")).ok_or("selected identity lacks chip ID")?;
    let device = selected.get("Info").and_then(Value::as_dictionary).and_then(|v| v.get("DeviceClass")).and_then(Value::as_string).ok_or("selected identity lacks device class")?;
    let mut candidates: Vec<(String, Dictionary)> = Vec::new();
    for identity in manifest.get("BuildIdentities").and_then(Value::as_array).ok_or("missing BuildIdentities")? {
        let identity = identity.as_dictionary().ok_or("malformed BuildIdentity")?;
        if integer(identity.get("ApBoardID")) != Some(board) || integer(identity.get("ApChipID")) != Some(chip)
            || identity.get("Info").and_then(Value::as_dictionary).and_then(|v| v.get("DeviceClass")).and_then(Value::as_string) != Some(device) { continue; }
        let Some(entry) = identity.get("Manifest").and_then(Value::as_dictionary).and_then(|v| v.get("SEP")) else { continue; };
        let entry = entry.as_dictionary().ok_or("malformed machine SEP component")?;
        let path = entry.get("Info").and_then(Value::as_dictionary).and_then(|v| v.get("Path")).and_then(Value::as_string).ok_or("machine SEP lacks path")?;
        safe_path(path)?;
        let digest = entry.get("Digest").and_then(Value::as_data).filter(|v| matches!(v.len(), 32 | 48)).ok_or("machine SEP lacks supported digest")?;
        if let Some((_, old)) = candidates.first() {
            if old.get("Digest").and_then(Value::as_data) != Some(digest) {
                return Err("conflicting machine SEP candidates for selected target".into());
            }
        }
        candidates.push((path.into(), entry.clone()));
    }
    Ok(candidates)
}

fn safe_path(name: &str) -> Result<&Path, String> {
    let path = Path::new(name);
    if name.is_empty()
        || name.contains(['\\', '\0', ':'])
        || name
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(format!("unsafe archive path {name:?}"));
    }
    Ok(path)
}
fn string<'a>(d: &'a Dictionary, key: &str) -> Result<&'a str, String> {
    d.get(key)
        .and_then(Value::as_string)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("missing manifest string {key}"))
}
fn integer(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::Integer(v) => v.as_unsigned(),
        Value::String(v) => v
            .strip_prefix("0x")
            .or_else(|| v.strip_prefix("0X"))
            .map(|s| u64::from_str_radix(s, 16).ok())
            .unwrap_or_else(|| v.parse().ok()),
        _ => None,
    }
}
pub(crate) fn select_identity(
    manifest: &Dictionary,
    selected: &SelectedFirmware,
) -> Result<(usize, Dictionary), String> {
    if string(manifest, "ProductVersion")? != selected.entry.version {
        return Err("archive ProductVersion differs from selected firmware".into());
    }
    let entries = manifest
        .get("BuildIdentities")
        .and_then(Value::as_array)
        .ok_or("missing BuildIdentities")?;
    let mut matches = Vec::new();
    for (index, value) in entries.iter().enumerate() {
        let Some(entry) = value.as_dictionary() else {
            return Err("malformed BuildIdentity".into());
        };
        let Some(info) = entry.get("Info").and_then(Value::as_dictionary) else {
            continue;
        };
        if info.get("DeviceClass").and_then(Value::as_string) == Some(selected.board.as_str())
            && integer(entry.get("ApChipID")) == Some(u64::from(selected.chip_id))
            && info.get("Variant").and_then(Value::as_string) == Some("macOS Customer")
            && info.get("RestoreBehavior").and_then(Value::as_string) == Some("Erase")
        {
            matches.push((index, entry.clone()));
        }
    }
    if matches.len() != 1 {
        return Err(format!(
            "expected one exact restore identity, found {}",
            matches.len()
        ));
    }
    Ok(matches.remove(0))
}
fn member<'a>(members: &'a [ZipMember], name: &str) -> Result<&'a ZipMember, String> {
    let mut found = members.iter().filter(|m| m.name == name);
    let result = found
        .next()
        .ok_or_else(|| format!("archive lacks exact member {name}"))?;
    if found.next().is_some() {
        return Err(format!("duplicate archive member {name}"));
    }
    Ok(result)
}
pub(crate) fn read_metadata_member(archive: &Path, name: &str) -> Result<Vec<u8>, String> {
    safe_path(name)?;
    let members = zip_list_file(archive).map_err(|e| e.to_string())?;
    let source = member(&members, name)?;
    if source.uncomp > 64 * 1024 * 1024 {
        return Err("installer metadata exceeds limit".into());
    }
    let mut bytes = Vec::new();
    reader(archive, source)?
        .take(source.uncomp + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 != source.uncomp {
        return Err("installer metadata ZIP length mismatch".into());
    }
    Ok(bytes)
}

fn reader(archive: &Path, member: &ZipMember) -> Result<Box<dyn Read>, String> {
    let (file, method, compressed) =
        zip_open_payload(archive, member).map_err(|e| e.to_string())?;
    let limited = file.take(compressed);
    match method {
        0 => Ok(Box::new(limited)),
        8 => Ok(Box::new(flate2::read::DeflateDecoder::new(limited))),
        _ => Err(format!("unsupported ZIP compression method {method}")),
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hash_file(path: &Path) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut sha256 = Sha256::new();
    let mut sha384 = Sha512::sha384();
    let mut buf = [0; 65536];
    loop {
        let n = file.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        sha256.update(&buf[..n]);
        sha384.update(&buf[..n]);
    }
    Ok((sha256.finish().to_vec(), sha384.finish()[..48].to_vec()))
}
pub(crate) fn verify_digest(path: &Path, entry: &Dictionary) -> Result<(), String> {
    let Some(value) = entry.get("Digest") else {
        return Ok(());
    };
    let expected = value
        .as_data()
        .filter(|v| !v.is_empty())
        .ok_or("malformed component Digest")?;
    let info = entry.get("Info").and_then(Value::as_dictionary);
    let method = info
        .and_then(|i| i.get("HashMethod"))
        .or_else(|| entry.get("HashMethod"));
    let width = match method.and_then(Value::as_string) {
        Some("sha2-256") => 32,
        Some("sha2-384") => 48,
        Some(other) => return Err(format!("unsupported manifest HashMethod {other}")),
        None if method.is_some() => return Err("malformed HashMethod".into()),
        None => expected.len(),
    };
    if width != expected.len() || !matches!(width, 32 | 48) {
        return Err("unsupported digest width".into());
    }
    let (sha256, sha384) = hash_file(path)?;
    if (if width == 32 { &sha256 } else { &sha384 }).as_slice() == expected {
        return Ok(());
    }
    if let Some(kind) = info
        .and_then(|i| i.get("Img4PayloadType"))
        .and_then(Value::as_string)
    {
        let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
        let retagged = crate::ramrod::firmware::retag_im4p_type(&bytes, kind)
            .ok_or("cannot verify manifest retagged IM4P digest")?;
        let actual = if width == 32 {
            crate::crypto::sha256(&retagged).to_vec()
        } else {
            crate::crypto::sha384(&retagged).to_vec()
        };
        if actual == expected {
            return Ok(());
        }
    }
    Err(format!("component digest mismatch: {}", path.display()))
}

pub fn extract_selected_firmware(
    archive: &Path,
    selection: SelectedFirmware,
    destination_parent: &Path,
    requested_components: &[String],
) -> Result<ExtractedFirmware, String> {
    extract_firmware(
        archive,
        selection,
        destination_parent,
        ComponentSelection::Explicit(requested_components),
    )
}

pub fn extract_firmware(
    archive: &Path,
    selection: SelectedFirmware,
    destination_parent: &Path,
    component_selection: ComponentSelection<'_>,
) -> Result<ExtractedFirmware, String> {
    let members = zip_list_file(archive).map_err(|e| e.to_string())?;
    let include_metadata = matches!(
        &component_selection,
        ComponentSelection::BootAndVendorInputs
    );
    let bytes = read_manifest_bytes(archive, &members)?;
    let manifest = Value::from_reader(std::io::Cursor::new(&bytes)).map_err(|e| e.to_string())?;
    let manifest = manifest
        .as_dictionary()
        .ok_or("BuildManifest is not a dictionary")?;
    let (index, identity) = select_identity(manifest, &selection)?;
    let components = identity
        .get("Manifest")
        .and_then(Value::as_dictionary)
        .ok_or("identity lacks Manifest")?;
    let requested_components = requested_keys(components, component_selection)?;
    let mut catalog = BTreeMap::new();
    for (key, value) in components {
        let entry = value.as_dictionary().ok_or("malformed component")?;
        if let Some(path) = entry
            .get("Info")
            .and_then(Value::as_dictionary)
            .and_then(|i| i.get("Path"))
        {
            let path = path.as_string().ok_or("malformed component path")?;
            safe_path(path)?;
            if path == "BuildManifest.plist" {
                return Err("component aliases BuildManifest".into());
            }
            catalog.insert(key.clone(), path.to_owned());
        }
    }
    let directory = tempfile::Builder::new()
        .prefix("restore-inputs-")
        .tempdir_in(destination_parent)
        .map_err(|e| e.to_string())?;
    let archive_digest = crate::asahi_cache::digest(archive)?;
    let cache = crate::asahi_cache::root();
    let mut extracted = BTreeMap::new();
    let mut written = BTreeSet::new();
    for key in &requested_components {
        let name = catalog
            .get(key)
            .ok_or_else(|| format!("identity lacks requested component path {key}"))?;
        let source = member(&members, name)?;
        let target = directory.path().join(safe_path(name)?);
        let mut restored = false;
        if written.insert(name.clone()) {
            std::fs::create_dir_all(target.parent().ok_or("missing target parent")?)
                .map_err(|e| e.to_string())?;
            let cache_key = format!("ipsw:{archive_digest}:{name}");
            restored = cache.as_ref().is_some_and(|root| crate::asahi_cache::restore(root, &cache_key, &target));
            if !restored {
                let mut output = File::options()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&target)
                    .map_err(|e| e.to_string())?;
                let n = std::io::copy(
                    &mut reader(archive, source)?
                        .take(source.uncomp.checked_add(1).ok_or("ZIP size overflow")?),
                    &mut output,
                )
                .map_err(|e| e.to_string())?;
                if n != source.uncomp {
                    return Err(format!("ZIP length mismatch for {name}"));
                }
                output.flush().map_err(|e| e.to_string())?;
            }
        }
        verify_digest(
            &target,
            components[key]
                .as_dictionary()
                .ok_or("malformed component")?,
        )?;
        if !restored && let Some(root) = &cache {
            let cache_key = format!("ipsw:{archive_digest}:{name}");
            let _ = crate::asahi_cache::store(root, &cache_key, &target);
        }
        extracted.insert(key.clone(), target);
    }
    std::fs::write(directory.path().join("BuildManifest.plist"), &bytes)
        .map_err(|e| e.to_string())?;
    let mut metadata_paths = BTreeMap::new();
    if include_metadata {
        for name in ["SystemVersion.plist", "RestoreVersion.plist", "usr/standalone/bootcaches.plist"] {
            let data = read_metadata_member(archive, name)?;
            let value =
                Value::from_reader(std::io::Cursor::new(&data)).map_err(|e| e.to_string())?;
            let fields = value
                .as_dictionary()
                .ok_or("installer metadata is not a dictionary")?;
            if name == "SystemVersion.plist"
                && (string(fields, "ProductVersion")? != string(manifest, "ProductVersion")?
                    || string(fields, "ProductBuildVersion")?
                        != string(manifest, "ProductBuildVersion")?)
            {
                return Err("SystemVersion differs from selected restore identity".into());
            }
            let path = directory.path().join(name);
            std::fs::create_dir_all(path.parent().ok_or("missing metadata parent")?).map_err(|e| e.to_string())?;
            std::fs::write(&path, data).map_err(|e| e.to_string())?;
            metadata_paths.insert(name.to_owned(), path);
        }
    }
    let mut preboot_supplemental = BTreeMap::new();
    if include_metadata {
        for (name, entry) in machine_sep_candidates(manifest, &identity)? {
            let source = member(&members, &name)?;
            let target = directory.path().join(safe_path(&name)?);
            std::fs::create_dir_all(target.parent().ok_or("missing SEP parent")?).map_err(|e| e.to_string())?;
            let cache_key = format!("ipsw:{archive_digest}:{name}");
            if !cache.as_ref().is_some_and(|root| crate::asahi_cache::restore(root, &cache_key, &target)) {
                let mut output = File::create(&target).map_err(|e| e.to_string())?;
                let n = std::io::copy(&mut reader(archive, source)?.take(source.uncomp.checked_add(1).ok_or("ZIP size overflow")?), &mut output).map_err(|e| e.to_string())?;
                if n != source.uncomp { return Err("machine SEP ZIP length mismatch".into()); }
                output.flush().map_err(|e| e.to_string())?;
            }
            verify_digest(&target, &entry)?;
            if let Some(root) = &cache { let _ = crate::asahi_cache::store(root, &cache_key, &target); }
            if !catalog.values().any(|path| path == &name) { preboot_supplemental.insert(name, target); }
        }
        let original = directory.path().join("SourceBuildManifest.plist");
        std::fs::write(&original, &bytes).map_err(|e| e.to_string())?;
        preboot_supplemental.insert("SourceBuildManifest.plist".into(), original);
    }

    if include_metadata {
        let variant = identity.get("Info").and_then(Value::as_dictionary)
            .and_then(|info| info.get("Variant")).and_then(Value::as_string)
            .ok_or("selected identity lacks variant")?;
        let manifest_prefix = format!("Firmware/Manifests/restore/{variant}/");
        for source in &members {
            if source.name.ends_with('/') { continue; }
            let relative = if let Some(path) = source.name.strip_prefix("BootabilityBundle/Restore/Bootability/") {
                Some(format!("Bootability/{path}"))
            } else if source.name == "BootabilityBundle/Restore/Firmware/Bootability.dmg.trustcache" {
                Some("Bootability/Bootability.trustcache".into())
            } else {
                source.name.strip_prefix(&manifest_prefix).map(str::to_owned)
            };
            let Some(relative) = relative else { continue; };
            safe_path(&relative)?;
            let target = directory.path().join(safe_path(&source.name)?);
            std::fs::create_dir_all(target.parent().ok_or("missing supplemental parent")?).map_err(|e| e.to_string())?;
            let cache_key = format!("ipsw:{archive_digest}:{}", source.name);
            if !cache.as_ref().is_some_and(|root| crate::asahi_cache::restore(root, &cache_key, &target)) {
                let mut output = File::create(&target).map_err(|e| e.to_string())?;
                let n = std::io::copy(&mut reader(archive, source)?.take(source.uncomp.checked_add(1).ok_or("ZIP size overflow")?), &mut output).map_err(|e| e.to_string())?;
                if n != source.uncomp { return Err(format!("ZIP length mismatch for {}", source.name)); }
                output.flush().map_err(|e| e.to_string())?;
                if let Some(root) = &cache { let _ = crate::asahi_cache::store(root, &cache_key, &target); }
            }
            if preboot_supplemental.insert(relative.clone(), target).is_some() {
                return Err(format!("duplicate Preboot supplemental path {relative}"));
            }
        }
        if !preboot_supplemental.contains_key("Bootability/Bootability.trustcache") {
            return Err("selected restore lacks Bootability trust cache".into());
        }
    }
    let restore = RestoreIdentity {
        product_version: string(manifest, "ProductVersion")?.to_owned(),
        product_build: string(manifest, "ProductBuildVersion")?.to_owned(),
        board: selection.board.clone(),
        chip_id: selection.chip_id,
        identity: format!("{index}:macOS Customer:Erase"),
        manifest_digest: hex(&crate::crypto::sha256(&bytes)),
        archive_digest,
    };
    Ok(ExtractedFirmware {
        directory,
        bound: bind_restore_identity(selection, restore)?,
        identity,
        catalog,
        extracted,
        metadata: metadata_paths,
        preboot_supplemental,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn selection() -> SelectedFirmware {
        use crate::asahi_firmware::{CatalogProvenance, FirmwareCatalogEntry};
        SelectedFirmware {
            board: "testap".into(),
            chip_id: 123,
            entry: FirmwareCatalogEntry {
                version: "1.2".into(),
                min_macos: "1".into(),
                min_iboot: "1".into(),
                min_sfr: "1".into(),
                expert_only: false,
                devices: None,
                restore_url: "https://example.test/firmware.ipsw".into(),
            },
            provenance: CatalogProvenance {
                source_uri: "https://example.test/catalog".into(),
                revision: "test".into(),
            },
        }
    }
    #[test]
    fn machine_sep_keeps_os_identity_and_rejects_conflicting_sources() {
        let identity = |path: Option<&str>, digest: u8, board: u64| {
            let mut components = Dictionary::new();
            if let Some(path) = path {
                components.insert("SEP".to_owned(), Value::Dictionary([
                    ("Digest".to_owned(), Value::Data(vec![digest;48])),
                    ("Info".to_owned(), Value::Dictionary([("Path".to_owned(), Value::String(path.into()))].into_iter().collect()))
                ].into_iter().collect()));
            }
            [
                ("ApBoardID".to_owned(), Value::Integer(board.into())),
                ("ApChipID".to_owned(), Value::Integer(0x8103u64.into())),
                ("Info".to_owned(), Value::Dictionary([("DeviceClass".to_owned(), Value::String("j274ap".into()))].into_iter().collect())),
                ("Manifest".to_owned(), Value::Dictionary(components))
            ].into_iter().collect::<Dictionary>()
        };
        let os = identity(None, 0, 1);
        let mut source = Dictionary::new();
        source.insert("BuildIdentities".to_owned(), Value::Array(vec![Value::Dictionary(os.clone()), Value::Dictionary(identity(Some("Firmware/all_flash/sep.im4p"), 7, 1)), Value::Dictionary(identity(Some("Firmware/all_flash/alias.im4p"), 7, 1)), Value::Dictionary(identity(Some("Firmware/all_flash/other.im4p"), 9, 2))]));
        let candidates = machine_sep_candidates(&source, &os).unwrap();
        assert_eq!(candidates.len(), 2);
        assert!(os["Manifest"].as_dictionary().unwrap().get("SEP").is_none());
        source.get_mut("BuildIdentities").unwrap().as_array_mut().unwrap().push(Value::Dictionary(identity(Some("Firmware/all_flash/conflict.im4p"), 8, 1)));
        assert!(machine_sep_candidates(&source, &os).unwrap_err().contains("conflicting"));
        assert!(machine_sep_candidates(&source, &identity(None,0,3)).unwrap().is_empty());
    }

    #[test]
    fn identity_rejects_wrong_version_board_and_ambiguity() {
        let mut info = Dictionary::new();
        for (key, value) in [
            ("DeviceClass", "testap"),
            ("Variant", "macOS Customer"),
            ("RestoreBehavior", "Erase"),
        ] {
            info.insert(key.into(), Value::String(value.into()));
        }
        let mut identity = Dictionary::new();
        identity.insert("Info".into(), Value::Dictionary(info));
        identity.insert("ApChipID".into(), Value::String("0x7b".into()));
        let mut manifest = Dictionary::new();
        manifest.insert("ProductVersion".into(), Value::String("1.2".into()));
        manifest.insert(
            "BuildIdentities".into(),
            Value::Array(vec![Value::Dictionary(identity.clone())]),
        );
        let selected = selection();
        assert!(select_identity(&manifest, &selected).is_ok());
        let mut wrong = selected.clone();
        wrong.board = "otherap".into();
        assert!(select_identity(&manifest, &wrong).is_err());
        wrong = selected.clone();
        wrong.entry.version = "2".into();
        assert!(select_identity(&manifest, &wrong).is_err());
        manifest.insert(
            "BuildIdentities".into(),
            Value::Array(vec![
                Value::Dictionary(identity.clone()),
                Value::Dictionary(identity),
            ]),
        );
        assert!(select_identity(&manifest, &selected).is_err());
    }
    fn stored_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut central = Vec::new();
        for (name, data) in files {
            let offset = bytes.len() as u32;
            let mut local = [0u8; 30];
            local[..4].copy_from_slice(b"PK\x03\x04");
            local[4..6].copy_from_slice(&20u16.to_le_bytes());
            local[18..22].copy_from_slice(&(data.len() as u32).to_le_bytes());
            local[22..26].copy_from_slice(&(data.len() as u32).to_le_bytes());
            local[26..28].copy_from_slice(&(name.len() as u16).to_le_bytes());
            bytes.extend(local);
            bytes.extend(name.as_bytes());
            bytes.extend(*data);
            let mut record = [0u8; 46];
            record[..4].copy_from_slice(b"PK\x01\x02");
            record[20..24].copy_from_slice(&(data.len() as u32).to_le_bytes());
            record[24..28].copy_from_slice(&(data.len() as u32).to_le_bytes());
            record[28..30].copy_from_slice(&(name.len() as u16).to_le_bytes());
            record[42..46].copy_from_slice(&offset.to_le_bytes());
            central.extend(record);
            central.extend(name.as_bytes());
        }
        let mut end = [0u8; 22];
        end[..4].copy_from_slice(b"PK\x05\x06");
        end[8..10].copy_from_slice(&(files.len() as u16).to_le_bytes());
        end[10..12].copy_from_slice(&(files.len() as u16).to_le_bytes());
        end[12..16].copy_from_slice(&(central.len() as u32).to_le_bytes());
        end[16..20].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        bytes.extend(central);
        bytes.extend(end);
        bytes
    }
    #[test]
    fn provisioning_preserves_machine_sep_source_and_rejects_corruption() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("source.ipsw");
        let mut components = Dictionary::new();
        for (key, path) in [("iBoot","iboot"),("DeviceTree","adt"),("KernelCache","kernelcache.test"),("BaseSystem","base")] {
            components.insert(key.into(), Value::Dictionary([("Info".to_owned(),Value::Dictionary([("Path".to_owned(),Value::String(path.into()))].into_iter().collect()))].into_iter().collect()));
        }
        let os: Dictionary = [("ApBoardID".to_owned(),Value::Integer(1u64.into())),("ApChipID".to_owned(),Value::Integer(123u64.into())),("Info".to_owned(),Value::Dictionary([("DeviceClass".to_owned(),Value::String("testap".into())),("Variant".to_owned(),Value::String("macOS Customer".into())),("RestoreBehavior".to_owned(),Value::String("Erase".into()))].into_iter().collect())),("Manifest".to_owned(),Value::Dictionary(components))].into_iter().collect();
        let mut machine = os.clone();
        machine.get_mut("Info").unwrap().as_dictionary_mut().unwrap().insert("Variant".into(),Value::String("Research".into()));
        machine.insert("Manifest".into(),Value::Dictionary([("SEP".to_owned(),Value::Dictionary([("Digest".to_owned(),Value::Data(crate::crypto::sha384(b"sep-original").to_vec())),("Info".to_owned(),Value::Dictionary([("Path".to_owned(),Value::String("Firmware/all_flash/sep.im4p".into()))].into_iter().collect()))].into_iter().collect()))].into_iter().collect()));
        let manifest=Value::Dictionary([("ProductVersion".to_owned(),Value::String("1.2".into())),("ProductBuildVersion".to_owned(),Value::String("test-build".into())),("BuildIdentities".to_owned(),Value::Array(vec![Value::Dictionary(os.clone()),Value::Dictionary(machine)]))].into_iter().collect());
        let mut xml=Vec::new(); manifest.to_writer_xml(&mut xml).unwrap();
        let version=br#"<plist version="1.0"><dict><key>ProductVersion</key><string>1.2</string><key>ProductBuildVersion</key><string>test-build</string></dict></plist>"#;
        let bootcaches=br#"<plist version="1.0"><dict><key>bless2</key><dict><key>RestoreBundlePath</key><string>./Restore</string></dict></dict></plist>"#;
        for payload in [b"sep-original".as_slice(), b"corrupt".as_slice()] {
            std::fs::write(&archive,stored_zip(&[("BuildManifest.plist",&xml),("SystemVersion.plist",version),("RestoreVersion.plist",version),("usr/standalone/bootcaches.plist",bootcaches),("iboot",b"iboot"),("adt",b"adt"),("kernelcache.test",b"kernel"),("base",b"base"),("Firmware/all_flash/sep.im4p",payload),("BootabilityBundle/Restore/Firmware/Bootability.dmg.trustcache",b"trust")])).unwrap();
            let result=extract_firmware(&archive,selection(),root.path(),ComponentSelection::BootAndVendorInputs);
            if payload==b"corrupt" { assert!(result.err().unwrap().contains("digest mismatch")); continue; }
            let extracted=result.unwrap();
            assert_eq!(extracted.identity,os);
            assert_eq!(std::fs::read(&extracted.preboot_supplemental["SourceBuildManifest.plist"]).unwrap(),xml);
            assert_eq!(std::fs::read(&extracted.preboot_supplemental["Firmware/all_flash/sep.im4p"]).unwrap(),payload);
        }
    }

    #[test]
    fn extracts_exact_member_and_rejects_duplicate_or_suffix_only_archive() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("test.ipsw");
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict>
        <key>ProductVersion</key><string>1.2</string><key>ProductBuildVersion</key><string>test-build</string>
        <key>BuildIdentities</key><array><dict><key>ApChipID</key><integer>123</integer>
        <key>Info</key><dict><key>DeviceClass</key><string>testap</string><key>Variant</key><string>macOS Customer</string><key>RestoreBehavior</key><string>Erase</string></dict>
        <key>Manifest</key><dict><key>iBoot</key><dict><key>Info</key><dict><key>Path</key><string>Firmware/iBoot.im4p</string></dict></dict></dict>
        </dict></array></dict></plist>"#;
        let payload = b"actual test payload";
        std::fs::write(
            &archive,
            stored_zip(&[
                ("BuildManifest.plist", xml),
                ("Firmware/iBoot.im4p", payload),
            ]),
        )
        .unwrap();
        let result =
            extract_selected_firmware(&archive, selection(), root.path(), &["iBoot".into()])
                .unwrap();
        assert_eq!(std::fs::read(&result.extracted["iBoot"]).unwrap(), payload);
        assert_eq!(result.bound.restore.product_build, "test-build");
        assert_eq!(
            result.bound.restore.archive_digest,
            hex(&crate::crypto::sha256(&std::fs::read(&archive).unwrap()))
        );
        for entries in [
            vec![
                ("BuildManifest.plist", xml.as_slice()),
                ("Other/Firmware/iBoot.im4p", payload.as_slice()),
            ],
            vec![
                ("BuildManifest.plist", xml.as_slice()),
                ("Firmware/iBoot.im4p", payload.as_slice()),
                ("Firmware/iBoot.im4p", payload.as_slice()),
            ],
        ] {
            std::fs::write(&archive, stored_zip(&entries)).unwrap();
            assert!(
                extract_selected_firmware(&archive, selection(), root.path(), &["iBoot".into()])
                    .is_err()
            );
        }
    }
    #[test]
    fn automatic_roles_include_boot_and_vendor_inputs_without_os_volume() {
        let mut components = Dictionary::new();
        for key in ["iBoot", "DeviceTree", "KernelCache", "BaseSystem"] {
            let mut info = Dictionary::new();
            info.insert("Path".into(), Value::String(format!("inputs/{key}")));
            let mut entry = Dictionary::new();
            entry.insert("Info".into(), Value::Dictionary(info));
            components.insert(key.into(), Value::Dictionary(entry));
        }
        for (key, flag, path) in [
            ("DCP", "IsLoadedByiBoot", "Firmware/dcp.im4p"),
            ("Multitouch", "IsFUDFirmware", "Firmware/mt.im4p"),
            ("NotIm4p", "IsFUDFirmware", "Firmware/raw.bin"),
            ("OS", "IsLoadedByiBoot", "os.dmg"),
        ] {
            let mut info = Dictionary::new();
            info.insert("Path".into(), Value::String(path.into()));
            info.insert(flag.into(), Value::Boolean(true));
            let mut entry = Dictionary::new();
            entry.insert("Info".into(), Value::Dictionary(info));
            components.insert(key.into(), Value::Dictionary(entry));
        }
        let keys = requested_keys(&components, ComponentSelection::BootAndVendorInputs).unwrap();
        assert_eq!(
            keys,
            [
                "BaseSystem",
                "DCP",
                "DeviceTree",
                "KernelCache",
                "Multitouch",
                "NotIm4p",
                "iBoot"
            ]
        );
        components.remove("BaseSystem");
        assert!(requested_keys(&components, ComponentSelection::BootAndVendorInputs).is_err());
        assert_eq!(
            requested_keys(&components, ComponentSelection::Explicit(&["DCP".into()])).unwrap(),
            ["DCP"]
        );
    }
    #[test]
    fn incompatible_ipsw_preflight_never_starts_downloads() {
        let manifest = br#"<?xml version="1.0"?><plist version="1.0"><dict>
        <key>ProductVersion</key><string>26.5.1</string>
        <key>ProductBuildVersion</key><string>Test</string>
        <key>BuildIdentities</key><array><dict>
        <key>ApChipID</key><integer>33027</integer><key>Info</key><dict>
        <key>DeviceClass</key><string>j274ap</string>
        <key>Variant</key><string>macOS Customer</string>
        <key>RestoreBehavior</key><string>Erase</string>
        </dict></dict></array></dict></plist>"#;
        let dir = tempfile::tempdir().unwrap();
        let ipsw = dir.path().join("input.ipsw");
        std::fs::write(&ipsw, stored_zip(&[("BuildManifest.plist", manifest)])).unwrap();
        let supported = vec!["13.5".to_string()];
        let error = validate_archive_for_package(&ipsw, Some(&supported), Some(("j274ap", 0x8103))).unwrap_err();
        assert!(error.contains("26.5.1") && error.contains("13.5"));
        let requirements = crate::asahi_ops::FirmwareRequirements {
            supported_fw: Some(supported), firmware_partitions: vec!["EFI".into()], installer_data_partitions: vec![],
        };
        let workdir = dir.path().join("must-not-create");
        let inputs = crate::asahi_firmware_download::FirmwareArchiveInputs {
            board: "j274ap", chip_id: 0x8103, expert: false, workdir: &workdir,
            requirements: &requirements, installer_archive: None, installer_source_uri: None,
            ipsw: Some(&ipsw), repair_identity: None,
        };
        let result = crate::asahi_firmware_download::resolve_firmware_archives(&inputs,
            |_, _| panic!("download progress must not start for an incompatible IPSW"));
        assert!(result.err().unwrap().contains("26.5.1"));
        assert!(!workdir.exists());
        assert!(validate_archive_for_package(&ipsw, Some(&["26.5.1".into()]), Some(("j274ap", 0x8103))).is_ok());
        assert!(validate_archive_for_package(&ipsw, None, Some(("wrongap", 0x8103))).is_err());
    }

    #[test]
    fn rejects_path_aliases_and_escape() {
        for value in ["../a", "/a", "a/../b", "a//b", "a/./b", "a\\b", "C:a", ""] {
            assert!(safe_path(value).is_err(), "{value}");
        }
        assert!(safe_path("Firmware/all_flash/iBoot.im4p").is_ok());
    }
    #[test]
    fn digest_verification_rejects_corruption_and_unknown_method() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("firmware");
        std::fs::write(&path, b"actual firmware").unwrap();
        let mut entry = Dictionary::new();
        entry.insert(
            "Digest".into(),
            Value::Data(crate::crypto::sha384(b"actual firmware").to_vec()),
        );
        assert!(verify_digest(&path, &entry).is_ok());
        std::fs::write(&path, b"corrupted firmware").unwrap();
        assert!(verify_digest(&path, &entry).is_err());
        entry.insert("HashMethod".into(), Value::String("unknown".into()));
        assert!(verify_digest(&path, &entry).is_err());
    }
}

fn read_manifest_bytes(archive: &Path, members: &[ZipMember]) -> Result<Vec<u8>, String> {
    let manifest_member = member(members, "BuildManifest.plist")?;
    if manifest_member.uncomp > 64 * 1024 * 1024 {
        return Err("BuildManifest exceeds metadata limit".into());
    }
    let mut bytes = Vec::new();
    reader(archive, manifest_member)?
        .take(manifest_member.uncomp + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 != manifest_member.uncomp {
        return Err("manifest ZIP length mismatch".into());
    }
    Ok(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreTarget {
    pub board: String,
    pub chip_id: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreArchiveInfo {
    pub product_version: String,
    pub product_build: String,
    pub identities: Vec<RestoreTarget>,
}

pub fn inspect_restore_archive(archive: &Path) -> Result<RestoreArchiveInfo, String> {
    let members = zip_list_file(archive).map_err(|e| e.to_string())?;
    let bytes = read_manifest_bytes(archive, &members)?;
    let value = Value::from_reader(std::io::Cursor::new(bytes)).map_err(|e| e.to_string())?;
    inspect_manifest(value.as_dictionary().ok_or("BuildManifest is not a dictionary")?)
}

fn inspect_manifest(manifest: &Dictionary) -> Result<RestoreArchiveInfo, String> {
    let mut identities = Vec::new();
    let mut seen = BTreeSet::new();
    for value in manifest.get("BuildIdentities").and_then(Value::as_array)
        .ok_or("missing BuildIdentities")? {
        let identity = value.as_dictionary().ok_or("malformed BuildIdentity")?;
        let info = identity.get("Info").and_then(Value::as_dictionary)
            .ok_or("missing BuildIdentity Info")?;
        if info.get("Variant").and_then(Value::as_string) != Some("macOS Customer")
            || info.get("RestoreBehavior").and_then(Value::as_string) != Some("Erase") {
            continue;
        }
        let board = string(info, "DeviceClass")?.to_owned();
        let chip_id = u32::try_from(integer(identity.get("ApChipID")).ok_or("missing ApChipID")?)
            .map_err(|_| "ApChipID exceeds target identifier width")?;
        if !seen.insert((board.clone(), chip_id)) {
            return Err(format!("ambiguous restore identity for {board}"));
        }
        identities.push(RestoreTarget { board, chip_id });
    }
    if identities.is_empty() { return Err("IPSW contains no macOS customer erase identities".into()); }
    Ok(RestoreArchiveInfo {
        product_version: string(manifest, "ProductVersion")?.into(),
        product_build: string(manifest, "ProductBuildVersion")?.into(),
        identities,
    })
}


pub fn validate_archive_for_package(
    archive: &Path, supported: Option<&[String]>, target: Option<(&str, u32)>,
) -> Result<RestoreArchiveInfo, String> {
    let info = inspect_restore_archive(archive)?;
    crate::asahi_firmware::validate_supported_version(&info.product_version, supported)?;
    if let Some((board, chip_id)) = target {
        if !info.identities.iter().any(|identity| identity.board == board && identity.chip_id == chip_id) {
            return Err(format!("IPSW macOS {} has no restore identity for {board} (chip {chip_id:#x}). Select an IPSW containing that target.", info.product_version));
        }
    }
    Ok(info)
}
