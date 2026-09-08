use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GlobalManifestKind {
    Os,
    Cryptex1,
    Centauri,
}

impl GlobalManifestKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Os => "os",
            Self::Cryptex1 => "cryptex1",
            Self::Centauri => "centauri",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestLayout {
    Apticket,
    Centauri,
}

impl ManifestLayout {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Apticket => "apticket",
            Self::Centauri => "centauri",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedGlobalManifest {
    pub path: PathBuf,
    pub layout: ManifestLayout,
    pub variant: String,
    pub skipped: Vec<String>,
}

impl ResolvedGlobalManifest {
    #[must_use]
    pub fn is_preferred_variant(&self) -> bool {
        self.skipped.is_empty()
    }
}

#[derive(Debug)]
pub enum GlobalManifestError {
    NotFound {
        board: String,
        variants: Vec<String>,
        kind: GlobalManifestKind,
        attempted: Vec<PathBuf>,
    },
    Unreadable {
        path: PathBuf,
        error: std::io::Error,
    },
    Empty {
        path: PathBuf,
    },
}

impl fmt::Display for GlobalManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound {
                board,
                variants,
                kind,
                attempted,
            } => {
                write!(
                    f,
                    "no {} global manifest for board {board} under variants [{}]; tried [",
                    kind.label(),
                    variants.join(", ")
                )?;
                for (index, path) in attempted.iter().enumerate() {
                    if index != 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", path.display())?;
                }
                write!(f, "]")
            }
            Self::Unreadable { path, error } => {
                write!(
                    f,
                    "global manifest at {} is unreadable: {error}",
                    path.display()
                )
            }
            Self::Empty { path } => {
                write!(f, "global manifest at {} is empty", path.display())
            }
        }
    }
}

impl std::error::Error for GlobalManifestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unreadable { error, .. } => Some(error),
            _ => None,
        }
    }
}

#[must_use]
pub fn normalise_board(hardware_model: &str) -> String {
    hardware_model.trim().to_ascii_lowercase()
}

fn candidate_path(
    root: &Path,
    variant: &str,
    board: &str,
    kind: GlobalManifestKind,
) -> (PathBuf, ManifestLayout) {
    match kind {
        GlobalManifestKind::Os => (
            root.join(variant).join(format!("apticket.{board}.im4m")),
            ManifestLayout::Apticket,
        ),
        GlobalManifestKind::Cryptex1 => (
            root.join("cryptex1")
                .join(variant)
                .join(format!("apticket.{board}.im4m")),
            ManifestLayout::Apticket,
        ),
        GlobalManifestKind::Centauri => (
            root.join(variant)
                .join("centauri")
                .join(format!("centauri.{board}.im4m")),
            ManifestLayout::Centauri,
        ),
    }
}

pub fn resolve_global_manifest(
    root: &Path,
    variant: &str,
    hardware_model: &str,
    kind: GlobalManifestKind,
) -> Result<ResolvedGlobalManifest, GlobalManifestError> {
    resolve_global_manifest_in_variants(root, std::slice::from_ref(&variant), hardware_model, kind)
}

pub fn resolve_global_manifest_in_variants(
    root: &Path,
    variants: &[&str],
    hardware_model: &str,
    kind: GlobalManifestKind,
) -> Result<ResolvedGlobalManifest, GlobalManifestError> {
    let board = normalise_board(hardware_model);
    let mut attempted = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    let mut tried: Vec<String> = Vec::new();
    for variant in variants {
        if tried.iter().any(|seen| seen == variant) {
            continue;
        }
        tried.push((*variant).to_string());
        let (path, layout) = candidate_path(root, variant, &board, kind);
        if path.is_file() {
            return Ok(ResolvedGlobalManifest {
                path,
                layout,
                variant: (*variant).to_string(),
                skipped,
            });
        }
        attempted.push(path);
        skipped.push((*variant).to_string());
    }
    Err(GlobalManifestError::NotFound {
        board,
        variants: tried,
        kind,
        attempted,
    })
}

pub fn load_global_manifest(
    resolved: &ResolvedGlobalManifest,
) -> Result<Vec<u8>, GlobalManifestError> {
    let bytes = std::fs::read(&resolved.path).map_err(|error| GlobalManifestError::Unreadable {
        path: resolved.path.clone(),
        error,
    })?;
    if bytes.is_empty() {
        return Err(GlobalManifestError::Empty {
            path: resolved.path.clone(),
        });
    }
    Ok(bytes)
}

const CORRUPTION_STRIDE: usize = 61;

const CORRUPTION_START: usize = 16;

#[must_use]
pub fn corrupt_manifest_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut corrupted = bytes.to_vec();
    let mut index = CORRUPTION_START;
    while index < corrupted.len() {
        corrupted[index] ^= 0x80;
        index += CORRUPTION_STRIDE;
    }
    corrupted
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_file(path: &Path, bytes: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn an_apticket_board_resolves_to_the_direct_layout() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let manifest = root.join("macOS Customer").join("apticket.j274ap.im4m");
        write_file(&manifest, &[1, 2, 3, 4]);

        let resolved =
            resolve_global_manifest(root, "macOS Customer", "J274AP", GlobalManifestKind::Os)
                .expect("the apticket layout resolves");
        assert_eq!(resolved.path, manifest);
        assert_eq!(resolved.layout, ManifestLayout::Apticket);
    }

    #[test]
    fn the_centauri_manifest_is_reachable_under_its_own_kind() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let manifest = root
            .join("macOS Customer")
            .join("centauri")
            .join("centauri.j714cap.im4m");
        write_file(&manifest, &[9, 9, 9, 9]);

        let resolved = resolve_global_manifest(
            root,
            "macOS Customer",
            "J714CAP",
            GlobalManifestKind::Centauri,
        )
        .expect("the centauri manifest resolves under the centauri kind");
        assert_eq!(resolved.path, manifest);
        assert_eq!(resolved.layout, ManifestLayout::Centauri);
    }

    #[test]
    fn a_centauri_manifest_is_never_served_as_an_ap_ticket() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_file(
            &root
                .join("macOS Customer")
                .join("centauri")
                .join("centauri.j714cap.im4m"),
            &[9, 9, 9, 9],
        );
        let error =
            resolve_global_manifest(root, "macOS Customer", "J714CAP", GlobalManifestKind::Os)
                .expect_err("the centauri file does not answer an AP ticket");
        let rendered = format!("{error}");
        assert!(rendered.contains("apticket.j714cap.im4m"), "{rendered}");
        assert!(!rendered.contains("centauri"), "{rendered}");
    }

    #[test]
    fn the_first_variant_that_ships_the_manifest_answers_and_the_rest_are_named() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let fallback = root.join("macOS Customer").join("apticket.j274ap.im4m");
        write_file(&fallback, &[1]);

        let resolved = resolve_global_manifest_in_variants(
            root,
            &["Customer Erase Install (IPSW)", "macOS Customer"],
            "J274AP",
            GlobalManifestKind::Os,
        )
        .expect("the fallback variant answers");
        assert_eq!(resolved.path, fallback);
        assert_eq!(resolved.variant, "macOS Customer");
        assert_eq!(resolved.skipped, vec!["Customer Erase Install (IPSW)"]);
        assert!(!resolved.is_preferred_variant());

        let preferred = root
            .join("Customer Erase Install (IPSW)")
            .join("apticket.j274ap.im4m");
        write_file(&preferred, &[2]);
        let resolved = resolve_global_manifest_in_variants(
            root,
            &["Customer Erase Install (IPSW)", "macOS Customer"],
            "J274AP",
            GlobalManifestKind::Os,
        )
        .expect("the preferred variant now answers");
        assert_eq!(resolved.path, preferred);
        assert_eq!(resolved.variant, "Customer Erase Install (IPSW)");
        assert!(resolved.skipped.is_empty());
        assert!(resolved.is_preferred_variant());
    }

    #[test]
    fn a_variant_repeated_by_the_caller_is_probed_once() {
        let dir = tempfile::tempdir().unwrap();
        let error = resolve_global_manifest_in_variants(
            dir.path(),
            &["macOS Customer", "macOS Customer"],
            "J999AP",
            GlobalManifestKind::Os,
        )
        .expect_err("no manifest ships for this board");
        match error {
            GlobalManifestError::NotFound {
                ref variants,
                ref attempted,
                ..
            } => {
                assert_eq!(variants.len(), 1);
                assert_eq!(attempted.len(), 1);
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn cryptex1_resolves_under_its_own_sibling_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let manifest = root
            .join("cryptex1")
            .join("macOS Customer")
            .join("apticket.j274ap.im4m");
        write_file(&manifest, &[7, 7]);

        let resolved = resolve_global_manifest(
            root,
            "macOS Customer",
            "J274AP",
            GlobalManifestKind::Cryptex1,
        )
        .expect("the cryptex1 companion resolves");
        assert_eq!(resolved.path, manifest);
    }

    #[test]
    fn a_missing_board_names_every_path_it_tried() {
        let dir = tempfile::tempdir().unwrap();
        let error = resolve_global_manifest_in_variants(
            dir.path(),
            &["Customer Erase Install (IPSW)", "macOS Customer"],
            "J999AP",
            GlobalManifestKind::Os,
        )
        .expect_err("a board with no manifest is an error");
        match error {
            GlobalManifestError::NotFound { ref attempted, .. } => {
                assert_eq!(attempted.len(), 2);
                let rendered = format!("{error}");
                assert!(
                    rendered.contains("Customer Erase Install (IPSW)"),
                    "{rendered}"
                );
                assert!(rendered.contains("macOS Customer"), "{rendered}");
                assert!(rendered.contains("apticket.j999ap.im4m"), "{rendered}");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_manifest_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let manifest = root.join("macOS Customer").join("apticket.j274ap.im4m");
        write_file(&manifest, &[]);
        let resolved =
            resolve_global_manifest(root, "macOS Customer", "J274AP", GlobalManifestKind::Os)
                .unwrap();
        assert!(matches!(
            load_global_manifest(&resolved),
            Err(GlobalManifestError::Empty { .. })
        ));
    }

    #[test]
    fn corruption_preserves_length_changes_bytes_and_spares_the_header() {
        let genuine: Vec<u8> = (0..4096).map(|index| (index % 251) as u8).collect();
        let corrupted = corrupt_manifest_bytes(&genuine);
        assert_eq!(corrupted.len(), genuine.len());
        assert_ne!(corrupted, genuine);
        assert_eq!(&corrupted[..CORRUPTION_START], &genuine[..CORRUPTION_START]);
        assert_ne!(corrupted[CORRUPTION_START], genuine[CORRUPTION_START]);
        let last_touched = ((genuine.len() - 1 - CORRUPTION_START) / CORRUPTION_STRIDE)
            * CORRUPTION_STRIDE
            + CORRUPTION_START;
        assert_ne!(corrupted[last_touched], genuine[last_touched]);
    }

    #[test]
    fn corruption_is_deterministic() {
        let genuine: Vec<u8> = (0..2048).map(|index| (index * 7 % 253) as u8).collect();
        assert_eq!(
            corrupt_manifest_bytes(&genuine),
            corrupt_manifest_bytes(&genuine)
        );
    }
}
