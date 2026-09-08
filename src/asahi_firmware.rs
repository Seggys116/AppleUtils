#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(Vec<u64>);

impl Version {
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = value.strip_prefix("iBoot-").unwrap_or(value);
        let mut parts = value
            .split(['.', ','])
            .map(|part| {
                part.parse::<u64>()
                    .map_err(|_| format!("invalid numeric firmware version: {value}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        while parts.last() == Some(&0) && parts.len() > 1 {
            parts.pop();
        }
        Ok(Self(parts))
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FirmwareCatalogEntry {
    pub version: String,
    pub min_macos: String,
    pub min_iboot: String,
    pub min_sfr: String,
    pub expert_only: bool,
    pub devices: Option<Vec<String>>,
    pub restore_url: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CatalogProvenance {
    pub source_uri: String,
    pub revision: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Prerequisites {
    PhysicalHost {
        macos: String,
        iboot: String,
        sfr: String,
    },
    VirtualTarget,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TargetConstraints {
    pub board: String,
    pub chip_id: u32,
    pub chip_min_version: String,
    pub device_min_version: String,
    pub expert: bool,
    pub prerequisites: Prerequisites,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SelectedFirmware {
    pub entry: FirmwareCatalogEntry,
    pub board: String,
    pub chip_id: u32,
    pub provenance: CatalogProvenance,
}

fn nonempty(value: &str, name: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("missing {name}"))
    } else {
        Ok(())
    }
}

pub fn select_firmware(
    catalog: &[FirmwareCatalogEntry],
    supported_fw: Option<&[String]>,
    target: &TargetConstraints,
    provenance: &CatalogProvenance,
) -> Result<SelectedFirmware, String> {
    nonempty(&target.board, "target board")?;
    nonempty(&provenance.source_uri, "catalog source")?;
    nonempty(&provenance.revision, "catalog revision")?;
    let minimum =
        Version::parse(&target.chip_min_version)?.max(Version::parse(&target.device_min_version)?);
    let host = match &target.prerequisites {
        Prerequisites::PhysicalHost { macos, iboot, sfr } => Some((
            Version::parse(macos)?,
            Version::parse(iboot)?,
            Version::parse(sfr)?,
        )),
        Prerequisites::VirtualTarget => None,
    };
    let mut selected = None;
    let mut seen = std::collections::HashSet::new();
    for entry in catalog {
        if !seen.insert(entry.version.as_str()) {
            return Err(format!("ambiguous catalog version {}", entry.version));
        }
        nonempty(&entry.restore_url, "restore source")?;
        let version = Version::parse(&entry.version)?;
        let requirements = (
            Version::parse(&entry.min_macos)?,
            Version::parse(&entry.min_iboot)?,
            Version::parse(&entry.min_sfr)?,
        );
        if version < minimum
            || supported_fw.is_some_and(|versions| !versions.contains(&entry.version))
            || entry
                .devices
                .as_ref()
                .is_some_and(|devices| !devices.contains(&target.board))
            || (entry.expert_only && !target.expert)
            || host.as_ref().is_some_and(|(macos, iboot, sfr)| {
                macos < &requirements.0 || iboot < &requirements.1 || sfr < &requirements.2
            })
        {
            continue;
        }
        selected = Some(entry.clone());
    }
    Ok(SelectedFirmware {
        entry: selected.ok_or("no official firmware satisfies package and target constraints")?,
        board: target.board.clone(),
        chip_id: target.chip_id,
        provenance: provenance.clone(),
    })
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RestoreIdentity {
    pub product_version: String,
    pub product_build: String,
    pub board: String,
    pub chip_id: u32,
    pub identity: String,
    pub manifest_digest: String,
    pub archive_digest: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BoundFirmware {
    pub selection: SelectedFirmware,
    pub restore: RestoreIdentity,
}

pub fn bind_restore_identity(
    selection: SelectedFirmware,
    restore: RestoreIdentity,
) -> Result<BoundFirmware, String> {
    if restore.product_version != selection.entry.version
        || restore.board != selection.board
        || restore.chip_id != selection.chip_id
    {
        return Err("restore identity does not match selected OS firmware and target".into());
    }
    for (value, name) in [
        (&restore.product_build, "restore build"),
        (&restore.identity, "restore identity"),
        (&restore.manifest_digest, "manifest digest"),
        (&restore.archive_digest, "archive digest"),
    ] {
        nonempty(value, name)?;
    }
    Ok(BoundFirmware { selection, restore })
}

pub fn validate_repair(installed: &BoundFirmware, candidate: &BoundFirmware) -> Result<(), String> {
    if installed.restore != candidate.restore
        || installed.selection.board != candidate.selection.board
        || installed.selection.chip_id != candidate.selection.chip_id
        || installed.selection.entry.version != candidate.selection.entry.version
    {
        return Err("repair firmware differs from the installed restore identity".into());
    }
    Ok(())
}

pub fn validate_supported_version(
    version: &str,
    supported: Option<&[String]>,
) -> Result<(), String> {
    if let Some(versions) = supported
        && !versions.iter().any(|v| v == version)
    {
        let allowed = if versions.is_empty() {
            "none".into()
        } else {
            versions.join(", ")
        };
        return Err(format!(
            "Selected IPSW: macOS {version}. Supported firmware versions: {allowed}. Select a matching IPSW."
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(version: &str) -> FirmwareCatalogEntry {
        FirmwareCatalogEntry {
            version: version.into(),
            min_macos: "2.0".into(),
            min_iboot: "iBoot-3.1".into(),
            min_sfr: "4.0,0".into(),
            expert_only: false,
            devices: None,
            restore_url: format!("https://example.test/{version}.ipsw"),
        }
    }
    fn target() -> TargetConstraints {
        TargetConstraints {
            board: "test-board".into(),
            chip_id: 99,
            chip_min_version: "1".into(),
            device_min_version: "1".into(),
            expert: false,
            prerequisites: Prerequisites::VirtualTarget,
        }
    }
    fn provenance() -> CatalogProvenance {
        CatalogProvenance {
            source_uri: "https://example.test/catalog".into(),
            revision: "test-revision".into(),
        }
    }
    #[test]
    fn respects_order_package_device_and_expert_filters() {
        let mut restricted = entry("7");
        restricted.devices = Some(vec!["another-board".into()]);
        let mut expert = entry("8");
        expert.expert_only = true;
        let catalog = [entry("6"), entry("5"), restricted, expert];
        let selected = select_firmware(&catalog, None, &target(), &provenance()).unwrap();
        assert_eq!(selected.entry.version, "5");
        assert_eq!(
            select_firmware(&catalog, Some(&["6".into()]), &target(), &provenance())
                .unwrap()
                .entry
                .version,
            "6"
        );
        assert!(select_firmware(&catalog, Some(&[]), &target(), &provenance()).is_err());
    }
    #[test]
    fn physical_prerequisites_are_not_fabricated_for_virtual_targets() {
        let mut t = target();
        t.prerequisites = Prerequisites::PhysicalHost {
            macos: "1".into(),
            iboot: "iBoot-3.1".into(),
            sfr: "4".into(),
        };
        assert!(select_firmware(&[entry("5")], None, &t, &provenance()).is_err());
        t.prerequisites = Prerequisites::VirtualTarget;
        assert!(select_firmware(&[entry("5")], None, &t, &provenance()).is_ok());
        assert!(select_firmware(&[entry("5"), entry("5")], None, &t, &provenance()).is_err());
    }
    #[test]
    fn binds_actual_identity_and_refuses_repair_mixing() {
        let selected = select_firmware(&[entry("5")], None, &target(), &provenance()).unwrap();
        let restore = RestoreIdentity {
            product_version: "5".into(),
            product_build: "A17".into(),
            board: "test-board".into(),
            chip_id: 99,
            identity: "Customer Erase Install".into(),
            manifest_digest: "manifest-digest".into(),
            archive_digest: "archive-digest".into(),
        };
        let bound = bind_restore_identity(selected.clone(), restore.clone()).unwrap();
        validate_repair(&bound, &bound).unwrap();
        let mut wrong = restore.clone();
        wrong.product_version = "6".into();
        assert!(bind_restore_identity(selected.clone(), wrong).is_err());
        let mut changed = restore;
        changed.product_build = "A18".into();
        let other = bind_restore_identity(selected, changed).unwrap();
        assert!(validate_repair(&bound, &other).is_err());
    }
}
