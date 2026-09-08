use std::collections::BTreeMap;
use std::path::{Component, Path};

fn inventory(root: &Path, relative: &Path, files: &mut BTreeMap<String, Option<String>>) -> Result<(), String> {
    for entry in std::fs::read_dir(root.join(relative)).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = relative.join(entry.file_name());
        let name = path.to_str().ok_or("cache path is not UTF-8")?.replace('\\', "/");
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        if kind.is_dir() {
            files.insert(name, None);
            inventory(root, &path, files)?;
        } else if kind.is_file() {
            files.insert(name, Some(crate::asahi_cache::digest(&entry.path())?));
        } else {
            return Err("recovery cache contains a non-regular entry".into());
        }
    }
    Ok(())
}

fn restore(entry: &Path) -> Result<tempfile::TempDir, String> {
    let expected: BTreeMap<String, Option<String>> = serde_json::from_slice(
        &std::fs::read(entry.join("inventory.json")).map_err(|e| e.to_string())?
    ).map_err(|e| e.to_string())?;
    let payload = entry.join("payload");
    let mut actual = BTreeMap::new();
    inventory(&payload, Path::new(""), &mut actual)?;
    if actual != expected { return Err("recovery cache content changed".into()); }
    let output = tempfile::tempdir().map_err(|e| e.to_string())?;
    for (name, digest) in expected {
        let path = Path::new(&name);
        if name.contains(['\\', ':']) || path.components().any(|c| !matches!(c, Component::Normal(_))) {
            return Err("invalid recovery cache path".into());
        }
        let destination = output.path().join(path);
        if let Some(digest) = digest {
            std::fs::create_dir_all(destination.parent().ok_or("missing parent")?).map_err(|e| e.to_string())?;
            std::fs::copy(payload.join(path), &destination).map_err(|e| e.to_string())?;
            if crate::asahi_cache::digest(&destination)? != digest { return Err("recovery cache copy changed".into()); }
        } else {
            std::fs::create_dir_all(destination).map_err(|e| e.to_string())?;
        }
    }
    Ok(output)
}

fn store(entry: &Path, source: &Path) -> Result<(), String> {
    let parent = entry.parent().ok_or("missing cache parent")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let pending = tempfile::Builder::new().prefix("pending-recovery-").tempdir_in(parent).map_err(|e| e.to_string())?;
    let mut files = BTreeMap::new();
    inventory(source, Path::new(""), &mut files)?;
    let payload = pending.path().join("payload");
    std::fs::create_dir(&payload).map_err(|e| e.to_string())?;
    for (name, digest) in &files {
        let destination = payload.join(name);
        if let Some(digest) = digest {
            std::fs::create_dir_all(destination.parent().ok_or("missing parent")?).map_err(|e| e.to_string())?;
            std::fs::copy(source.join(name), &destination).map_err(|e| e.to_string())?;
            if crate::asahi_cache::digest(&destination)? != *digest { return Err("recovery source changed".into()); }
        } else {
            std::fs::create_dir_all(destination).map_err(|e| e.to_string())?;
        }
    }
    std::fs::write(pending.path().join("inventory.json"), serde_json::to_vec(&files).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    if entry.exists() {
        let old = tempfile::Builder::new().prefix("replaced-recovery-").tempdir_in(parent).map_err(|e| e.to_string())?;
        std::fs::rename(entry, old.path().join("entry")).map_err(|e| e.to_string())?;
    }
    std::fs::rename(pending.path(), entry).map_err(|e| e.to_string())
}

pub fn extract(
    cache: Option<&Path>, image: &Path, paths: &[String],
    extract: impl FnOnce() -> Result<tempfile::TempDir, String>,
) -> Result<tempfile::TempDir, String> {
    let key = cache.map(|root| {
        let source = crate::asahi_cache::digest(image)?;
        let spec = serde_json::to_vec(&("recovery-files-v2", source, paths)).map_err(|e| e.to_string())?;
        let key: String = crate::crypto::sha256(&spec).iter().map(|b| format!("{b:02x}")).collect();
        Ok::<_, String>(root.join("recovery").join(key))
    }).transpose()?;
    if let Some(key) = &key {
        if let Ok(output) = restore(key) { return Ok(output); }
    }
    let output = extract()?;
    if let Some(key) = key { let _ = store(&key, output.path()); }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed_recovery_is_reused_but_changes_and_partial_entries_are_not() {
        let root = tempfile::tempdir().unwrap();
        let image = root.path().join("image");
        std::fs::write(&image, b"source").unwrap();
        let paths = vec!["/firmware".into()];
        let generate = || {
            let out = tempfile::tempdir().unwrap();
            std::fs::create_dir(out.path().join("empty")).unwrap();
            std::fs::write(out.path().join("firmware"), b"firmware").unwrap();
            Ok(out)
        };
        extract(Some(root.path()), &image, &paths, generate).unwrap();
        let out = extract(Some(root.path()), &image, &paths, || panic!("cache miss")).unwrap();
        assert_eq!(std::fs::read(out.path().join("firmware")).unwrap(), b"firmware");
        assert!(out.path().join("empty").is_dir());
        let entry = std::fs::read_dir(root.path().join("recovery")).unwrap().next().unwrap().unwrap().path();
        std::fs::write(entry.join("payload/firmware"), b"bad").unwrap();
        assert!(extract(Some(root.path()), &image, &paths, || Err("reextract".into())).is_err());
        std::fs::write(&image, b"different").unwrap();
        assert!(extract(Some(root.path()), &image, &paths, || Err("changed source".into())).is_err());
    }
}
