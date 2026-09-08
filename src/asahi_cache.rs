use std::io::Read;
use std::path::{Path, PathBuf};

pub fn digest(path: &Path) -> Result<String, String> {
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut hash = crate::crypto::Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hash
        .finish()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub fn root() -> Option<PathBuf> {
    std::env::var_os("APPLEUTILS_CACHE_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            if cfg!(target_os = "windows") {
                std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
            } else {
                std::env::var_os("XDG_CACHE_HOME")
                    .map(PathBuf::from)
                    .or_else(|| {
                        std::env::var_os("HOME").map(|home| {
                            PathBuf::from(home).join(if cfg!(target_os = "macos") {
                                "Library/Caches"
                            } else {
                                ".cache"
                            })
                        })
                    })
            }
            .map(|path| path.join("apple-utils").join("asahi-v1"))
        })
}

pub fn download_key(url: &str) -> Option<String> {
    if !url.starts_with("https://") {
        return None;
    }
    let output = std::process::Command::new("curl")
        .args(["-fsIL", "--connect-timeout", "10", "--max-time", "20", url])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let headers = String::from_utf8(output.stdout).ok()?;
    download_key_from_headers(url, &headers)
}

fn download_key_from_headers(url: &str, headers: &str) -> Option<String> {
    let final_headers = headers.trim().rsplit("\r\n\r\n").next()?;
    let etag = final_headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("etag").then(|| value.trim())
    })?;
    if etag.starts_with("W/") || !etag.starts_with('"') || !etag.ends_with('"') {
        return None;
    }
    Some(format!("download:{url}:{etag}"))
}

fn entry(root: &Path, key: &str) -> PathBuf {
    let key: String = crate::crypto::sha256(key.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    root.join(key)
}

pub fn restore(root: &Path, key: &str, destination: &Path) -> bool {
    let entry = entry(root, key);
    let source = entry.join("payload");
    let Ok(expected) = std::fs::read_to_string(entry.join("sha256")) else {
        return false;
    };
    if expected.len() != 64
        || !std::fs::symlink_metadata(&source).is_ok_and(|m| m.file_type().is_file())
    {
        return false;
    }
    if digest(&source).ok().as_deref() != Some(expected.as_str()) {
        return false;
    }
    let Some(parent) = destination.parent() else {
        return false;
    };
    let result = (|| -> Result<(), String> {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        std::fs::copy(&source, destination).map_err(|e| e.to_string())?;
        if digest(destination)? != expected {
            return Err("cache copy changed".into());
        }
        Ok(())
    })();
    result.is_ok()
}

pub fn store(root: &Path, key: &str, source: &Path) -> Result<(), String> {
    std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let temporary = tempfile::Builder::new()
        .prefix("pending-")
        .tempdir_in(root)
        .map_err(|e| e.to_string())?;
    let payload = temporary.path().join("payload");
    std::fs::copy(source, &payload).map_err(|e| e.to_string())?;
    let hash = digest(&payload)?;
    std::fs::write(temporary.path().join("sha256"), hash).map_err(|e| e.to_string())?;
    let target = entry(root, key);
    if target.exists() {
        let quarantine = tempfile::Builder::new()
            .prefix("replaced-")
            .tempdir_in(root)
            .map_err(|e| e.to_string())?;
        if std::fs::rename(&target, quarantine.path().join("entry")).is_err() {
            return Ok(());
        }
    }
    std::fs::rename(temporary.path(), target).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn download_validator_uses_only_final_strong_etag() {
        let url = "https://example.test/archive";
        let first = download_key_from_headers(
            url,
            "HTTP/1.1 302 Found\r\nETag: \"redirect\"\r\n\r\nHTTP/2 200\r\netag: \"body\"\r\n\r\n",
        )
        .unwrap();
        assert_eq!(first, format!("download:{url}:\"body\""));
        assert_ne!(
            Some(first),
            download_key_from_headers(url, "HTTP/2 200\r\nETag: \"changed\"\r\n\r\n")
        );
        assert!(download_key_from_headers(url, "HTTP/2 200\r\nETag: W/\"weak\"\r\n\r\n").is_none());
        assert!(download_key_from_headers(url, "HTTP/1.1 302 Found\r\nETag: \"redirect\"\r\n\r\nHTTP/2 200\r\nContent-Length: 12\r\n\r\n").is_none());
    }

    #[test]
    fn cache_validates_content_and_ignores_incomplete_entries() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("cache");
        let source = temp.path().join("source");
        let output = temp.path().join("output");
        std::fs::write(&source, b"completed content").unwrap();
        store(&root, "archive/member", &source).unwrap();
        assert!(restore(&root, "archive/member", &output));
        assert_eq!(std::fs::read(&output).unwrap(), b"completed content");
        assert!(!restore(&root, "different/member", &output));
        std::fs::write(entry(&root, "archive/member").join("payload"), b"corrupt").unwrap();
        assert!(!restore(&root, "archive/member", &output));
        store(&root, "archive/member", &source).unwrap();
        assert!(restore(&root, "archive/member", &output));
        std::fs::create_dir_all(entry(&root, "partial")).unwrap();
        std::fs::write(entry(&root, "partial").join("payload"), b"partial").unwrap();
        assert!(!restore(&root, "partial", &output));
    }
}
