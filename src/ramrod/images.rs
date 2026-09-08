use std::fmt;
use std::path::{Path, PathBuf};

use super::identity::BuildIdentity;
use super::message::DataType;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BulkImageEntry {
    pub entry: &'static str,
    pub option: &'static str,
    pub allows_default: bool,
}

#[must_use]
pub fn bulk_image_entry(data_type: &DataType) -> Option<BulkImageEntry> {
    match data_type {
        DataType::SystemImageData => Some(BulkImageEntry {
            entry: "OS",
            option: "--asr-serve-system-image",
            allows_default: false,
        }),
        DataType::RecoveryOSASRImage => Some(BulkImageEntry {
            entry: "OS",
            option: "--asr-serve-recovery-image",
            allows_default: true,
        }),
        _ => None,
    }
}

#[must_use]
pub fn bulk_image_types() -> Vec<DataType> {
    vec![DataType::SystemImageData, DataType::RecoveryOSASRImage]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageNameRule {
    ManifestPath,
    DecodedPath,
    PrefixedManifestPath,
    PrefixedDecodedPath,
}

impl ImageNameRule {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::ManifestPath => "manifest-path",
            Self::DecodedPath => "decoded-path",
            Self::PrefixedManifestPath => "prefixed-manifest-path",
            Self::PrefixedDecodedPath => "prefixed-decoded-path",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedBulkImage {
    pub entry: &'static str,
    pub identity_index: usize,
    pub manifest_path: String,
    pub path: PathBuf,
    pub rule: ImageNameRule,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BulkImageError {
    NoManifest {
        entry: &'static str,
        identity_index: usize,
    },
    EntryAbsent {
        entry: &'static str,
        identity_index: usize,
    },
    NoPath {
        entry: &'static str,
        identity_index: usize,
    },
    NotFound {
        entry: &'static str,
        manifest_path: String,
        tried: Vec<PathBuf>,
    },
}

impl fmt::Display for BulkImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoManifest {
                entry,
                identity_index,
            } => write!(
                f,
                "build identity #{identity_index} carries no Manifest, so it cannot be asked whether it ships {entry}"
            ),
            Self::EntryAbsent {
                entry,
                identity_index,
            } => write!(
                f,
                "build identity #{identity_index} ships no {entry} component"
            ),
            Self::NoPath {
                entry,
                identity_index,
            } => write!(
                f,
                "the {entry} component of build identity #{identity_index} names no Info/Path"
            ),
            Self::NotFound {
                entry,
                manifest_path,
                tried,
            } => write!(
                f,
                "the {entry} component names {manifest_path} and no spelling of it is a file: tried {}",
                tried
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

#[must_use]
pub fn image_candidates(
    root: &Path,
    entry: &str,
    manifest_path: &str,
    content_encoding: Option<&str>,
) -> Vec<(ImageNameRule, PathBuf)> {
    let relative = PathBuf::from(manifest_path.replace('\\', "/"));
    let Some(file_name) = relative.file_name().and_then(|name| name.to_str()) else {
        return Vec::new();
    };
    let directory = relative
        .parent()
        .map_or_else(PathBuf::new, Path::to_path_buf);
    let decoded = content_encoding
        .and_then(|encoding| file_name.strip_suffix(&format!(".{encoding}")))
        .unwrap_or(file_name);

    let decoded_differs = decoded != file_name;
    let (prefixed_decoded_rule, decoded_rule) = if decoded_differs {
        (
            ImageNameRule::PrefixedDecodedPath,
            ImageNameRule::DecodedPath,
        )
    } else {
        (
            ImageNameRule::PrefixedManifestPath,
            ImageNameRule::ManifestPath,
        )
    };

    let mut candidates = Vec::new();
    let mut push = |rule: ImageNameRule, name: String| {
        let path = root.join(&directory).join(name);
        if !candidates
            .iter()
            .any(|(_, existing): &(ImageNameRule, PathBuf)| *existing == path)
        {
            candidates.push((rule, path));
        }
    };
    push(prefixed_decoded_rule, format!("{entry}__{decoded}"));
    push(decoded_rule, decoded.to_string());
    push(
        ImageNameRule::PrefixedManifestPath,
        format!("{entry}__{file_name}"),
    );
    push(ImageNameRule::ManifestPath, file_name.to_string());
    candidates
}

pub fn resolve_bulk_image(
    entry: &BulkImageEntry,
    identity: &BuildIdentity,
    root: &Path,
) -> Result<ResolvedBulkImage, BulkImageError> {
    let components = identity
        .components
        .as_ref()
        .ok_or(BulkImageError::NoManifest {
            entry: entry.entry,
            identity_index: identity.index,
        })?;
    let component = components
        .get(entry.entry)
        .and_then(plist::Value::as_dictionary)
        .ok_or(BulkImageError::EntryAbsent {
            entry: entry.entry,
            identity_index: identity.index,
        })?;
    let manifest_path = component
        .get("Info")
        .and_then(plist::Value::as_dictionary)
        .and_then(|info| info.get("Path"))
        .and_then(plist::Value::as_string)
        .ok_or(BulkImageError::NoPath {
            entry: entry.entry,
            identity_index: identity.index,
        })?;

    let candidates = image_candidates(
        root,
        entry.entry,
        manifest_path,
        identity.info_string("ContentEncoding"),
    );
    for (rule, path) in &candidates {
        if path.is_file() {
            return Ok(ResolvedBulkImage {
                entry: entry.entry,
                identity_index: identity.index,
                manifest_path: manifest_path.to_string(),
                path: path.clone(),
                rule: *rule,
            });
        }
    }
    Err(BulkImageError::NotFound {
        entry: entry.entry,
        manifest_path: manifest_path.to_string(),
        tried: candidates.into_iter().map(|(_, path)| path).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use plist::{Dictionary, Value};

    fn identity_with(entry: &str, path: &str, content_encoding: Option<&str>) -> BuildIdentity {
        let mut info = Dictionary::new();
        info.insert("Path".to_string(), Value::String(path.to_string()));
        let mut component = Dictionary::new();
        component.insert("Info".to_string(), Value::Dictionary(info));
        let mut components = Dictionary::new();
        components.insert(entry.to_string(), Value::Dictionary(component));

        let mut identity_info = Dictionary::new();
        if let Some(encoding) = content_encoding {
            identity_info.insert(
                "ContentEncoding".to_string(),
                Value::String(encoding.to_string()),
            );
        }
        BuildIdentity {
            index: 7,
            device_class: "j274ap".to_string(),
            variant: "macOS Customer".to_string(),
            info: identity_info,
            components: Some(components),
        }
    }

    #[test]
    fn both_image_request_types_resolve_to_the_os_component() {
        let recovery = bulk_image_entry(&DataType::RecoveryOSASRImage).unwrap();
        assert_eq!(recovery.entry, "OS");
        assert!(recovery.allows_default);
        let system = bulk_image_entry(&DataType::SystemImageData).unwrap();
        assert_eq!(system.entry, "OS");
        assert!(!system.allows_default);
        assert!(bulk_image_entry(&DataType::RootTicket).is_none());
    }

    #[test]
    fn the_decoded_name_beats_the_encoded_one_the_manifest_wrote() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("094-56453-088.dmg.aea"), b"encoded").unwrap();
        std::fs::write(directory.path().join("OS__094-56453-088.dmg"), b"decoded").unwrap();
        let identity = identity_with("OS", "094-56453-088.dmg.aea", Some("aea"));
        let entry = bulk_image_entry(&DataType::RecoveryOSASRImage).unwrap();
        let resolved = resolve_bulk_image(&entry, &identity, directory.path()).unwrap();
        assert_eq!(
            resolved.path,
            directory.path().join("OS__094-56453-088.dmg")
        );
        assert_eq!(resolved.rule, ImageNameRule::PrefixedDecodedPath);
        assert_eq!(resolved.manifest_path, "094-56453-088.dmg.aea");
        assert_eq!(resolved.identity_index, 7);
    }

    #[test]
    fn an_untouched_tree_resolves_by_the_manifest_path_it_wrote() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(directory.path().join("Firmware")).unwrap();
        std::fs::write(directory.path().join("Firmware/094-56385-097.dmg"), b"os").unwrap();
        let identity = identity_with("OS", "Firmware/094-56385-097.dmg", None);
        let entry = bulk_image_entry(&DataType::SystemImageData).unwrap();
        let resolved = resolve_bulk_image(&entry, &identity, directory.path()).unwrap();
        assert_eq!(
            resolved.path,
            directory.path().join("Firmware/094-56385-097.dmg")
        );
        assert_eq!(resolved.rule, ImageNameRule::ManifestPath);
    }

    #[test]
    fn a_missing_file_names_every_spelling_that_was_tried() {
        let directory = tempfile::tempdir().unwrap();
        let identity = identity_with("OS", "094-56453-088.dmg.aea", Some("aea"));
        let entry = bulk_image_entry(&DataType::SystemImageData).unwrap();
        let error = resolve_bulk_image(&entry, &identity, directory.path()).unwrap_err();
        match error {
            BulkImageError::NotFound {
                entry,
                manifest_path,
                tried,
            } => {
                assert_eq!(entry, "OS");
                assert_eq!(manifest_path, "094-56453-088.dmg.aea");
                assert_eq!(tried.len(), 4);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_identity_that_ships_no_entry_says_so_rather_than_reporting_a_missing_file() {
        let directory = tempfile::tempdir().unwrap();
        let identity = identity_with("BaseSystem", "022-21678-093.dmg.aea", Some("aea"));
        let entry = bulk_image_entry(&DataType::RecoveryOSASRImage).unwrap();
        assert_eq!(
            resolve_bulk_image(&entry, &identity, directory.path()).unwrap_err(),
            BulkImageError::EntryAbsent {
                entry: "OS",
                identity_index: 7,
            }
        );
    }
}
