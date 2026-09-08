use crate::apfs_image::{APFS_VOL_ROLE_DATA, APFS_VOL_ROLE_PREBOOT, APFS_VOL_ROLE_SYSTEM};
use crate::apfs_verify::{ContainerSeals, VolumeSeal, VolumeSealReport, VolumeSnapshots};

pub(crate) const ARMED_IMAGE_SEAL_MEANING: &str = "the seal state of an armed image, read off the file itself before the transfer opens; this line never refuses a transfer. Unsealed SYSTEM is a note: sealing is guest apfs_sealvolume work and the host does not invent a hash tree. FDR rfta/ftap is a ticket trust object (apple_boot_trust path /System/Library/FDR/fdrtrustobject), not APFS snapshot blessing; missing com.apple.os.update-* is an APFS boot-finalisation fact and missing rfta is an FDR fact. An image that is not a bare APFS container reports why rather than being treated as unsealed";

const ZERO_VGID: [u8; 16] = [0u8; 16];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApsbField<T> {
    Known(T),
    // dead_code: constructed only by the test builders until the superblock reader grows a real "field absent" case; production code already handles it.
    #[allow(dead_code)]
    Unread,
}

impl<T> ApsbField<T> {
    fn known(self) -> Option<T> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unread => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArmedVolumeFacts {
    pub name: String,
    pub role: u16,
    pub sealed: bool,
    pub incompatible_features: u64,
    pub integrity_meta_oid: u64,
    pub seal: Option<VolumeSeal>,
    pub snapshots: VolumeSnapshots,
    pub root_to_xid: ApsbField<u64>,
    pub volume_group_id: ApsbField<[u8; 16]>,
}

impl ArmedVolumeFacts {
    fn from_report(volume: &VolumeSealReport) -> Self {
        let (root_to_xid, volume_group_id) = volume_apsb_extras(volume);
        Self {
            name: volume.name.clone(),
            role: volume.role,
            sealed: volume.sealed,
            incompatible_features: volume.incompatible_features,
            integrity_meta_oid: volume.integrity_meta_oid,
            seal: volume.seal.clone(),
            snapshots: volume.snapshots.clone(),
            root_to_xid,
            volume_group_id,
        }
    }

    #[cfg(test)]
    fn with_volume_group_id_unread(mut self) -> Self {
        self.volume_group_id = ApsbField::Unread;
        self
    }

    #[cfg(test)]
    fn with_root_to_xid_unread(mut self) -> Self {
        self.root_to_xid = ApsbField::Unread;
        self
    }
}

fn volume_apsb_extras(volume: &VolumeSealReport) -> (ApsbField<u64>, ApsbField<[u8; 16]>) {
    (
        ApsbField::Known(volume.root_to_xid),
        ApsbField::Known(volume.volume_group_id),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VolumeGroupToken {
    Paired,
    Mismatch,
    SystemUnpaired,
    NoData,
    NotApplicable,
    Unread,
}

impl VolumeGroupToken {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Paired => "paired",
            Self::Mismatch => "mismatch",
            Self::SystemUnpaired => "system-unpaired",
            Self::NoData => "no-data",
            Self::NotApplicable => "n/a",
            Self::Unread => "unread",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SystemSealToken {
    Sealed,
    Unsealed,
    FlagWithoutMeta,
    NotApplicable,
}

impl SystemSealToken {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Unsealed => "unsealed",
            Self::FlagWithoutMeta => "flag-without-meta",
            Self::NotApplicable => "n/a",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SystemSnapshotToken {
    Present,
    Missing,
    NotApplicable,
}

impl SystemSnapshotToken {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Missing => "missing",
            Self::NotApplicable => "n/a",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootToXidToken {
    Ok,
    Zero,
    Mismatch,
    NotApplicable,
    Unread,
}

impl RootToXidToken {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Zero => "zero",
            Self::Mismatch => "mismatch",
            Self::NotApplicable => "n/a",
            Self::Unread => "unread",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrebootToken {
    Present,
    Missing,
    NotApplicable,
}

impl PrebootToken {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Missing => "missing",
            Self::NotApplicable => "n/a",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArmedImageSealReport {
    pub volume_group: VolumeGroupToken,
    pub system_seal: SystemSealToken,
    pub system_snapshot: SystemSnapshotToken,
    pub root_to_xid: RootToXidToken,
    pub preboot: PrebootToken,
    pub sealed_volume_count: usize,
    pub volumes: Vec<String>,
}

impl ArmedImageSealReport {
    // dead_code: kept so the report-only contract stays callable and is not deleted as unused.
    #[allow(dead_code)]
    pub(crate) fn refuses_transfer(&self) -> bool {
        false
    }

    pub(crate) fn container_tokens(&self) -> String {
        format!(
            "volume_group={} system_seal={} system_snapshot={} root_to_xid={} preboot={}",
            self.volume_group.as_str(),
            self.system_seal.as_str(),
            self.system_snapshot.as_str(),
            self.root_to_xid.as_str(),
            self.preboot.as_str(),
        )
    }

    pub(crate) fn detail_line(&self) -> String {
        self.volumes.join(" | ")
    }
}

pub(crate) fn classify_armed_image_seals(seals: &ContainerSeals) -> ArmedImageSealReport {
    let facts: Vec<ArmedVolumeFacts> = seals
        .volumes
        .iter()
        .map(ArmedVolumeFacts::from_report)
        .collect();
    classify_armed_volumes(&facts)
}

fn classify_armed_volumes(volumes: &[ArmedVolumeFacts]) -> ArmedImageSealReport {
    let system = volumes
        .iter()
        .find(|volume| volume.role == APFS_VOL_ROLE_SYSTEM);
    let data = volumes
        .iter()
        .find(|volume| volume.role == APFS_VOL_ROLE_DATA);
    let has_preboot = volumes
        .iter()
        .any(|volume| volume.role == APFS_VOL_ROLE_PREBOOT);

    let volume_group = classify_volume_group(system, data);
    let system_seal = classify_system_seal(system);
    let (system_snapshot, named_xid) = classify_system_snapshot(system);
    let root_to_xid = classify_root_to_xid(system, named_xid);
    let preboot = classify_preboot(system.is_some(), has_preboot);

    ArmedImageSealReport {
        volume_group,
        system_seal,
        system_snapshot,
        root_to_xid,
        preboot,
        sealed_volume_count: volumes.iter().filter(|volume| volume.sealed).count(),
        volumes: volumes.iter().map(volume_detail_line).collect(),
    }
}

fn classify_volume_group(
    system: Option<&ArmedVolumeFacts>,
    data: Option<&ArmedVolumeFacts>,
) -> VolumeGroupToken {
    let Some(system) = system else {
        return VolumeGroupToken::NotApplicable;
    };
    match system.volume_group_id {
        ApsbField::Unread => {
            if data.is_none() {
                VolumeGroupToken::NoData
            } else {
                VolumeGroupToken::Unread
            }
        }
        ApsbField::Known(system_id) if system_id == ZERO_VGID => VolumeGroupToken::SystemUnpaired,
        ApsbField::Known(system_id) => match data.map(|volume| volume.volume_group_id) {
            None => VolumeGroupToken::NoData,
            Some(ApsbField::Unread) => VolumeGroupToken::Unread,
            Some(ApsbField::Known(data_id)) if data_id == system_id => VolumeGroupToken::Paired,
            Some(ApsbField::Known(_)) => VolumeGroupToken::Mismatch,
        },
    }
}

fn classify_system_seal(system: Option<&ArmedVolumeFacts>) -> SystemSealToken {
    let Some(system) = system else {
        return SystemSealToken::NotApplicable;
    };
    if !system.sealed {
        return SystemSealToken::Unsealed;
    }
    if system.seal.is_none() {
        SystemSealToken::FlagWithoutMeta
    } else {
        SystemSealToken::Sealed
    }
}

fn classify_system_snapshot(
    system: Option<&ArmedVolumeFacts>,
) -> (SystemSnapshotToken, Option<u64>) {
    let Some(system) = system else {
        return (SystemSnapshotToken::NotApplicable, None);
    };
    let expected = match &system.seal {
        Some(seal) => seal.root_snapshot_name(),
        None => match system.snapshots.root_snapshot_name() {
            Some(name) => name.to_string(),
            None => return (SystemSnapshotToken::Missing, None),
        },
    };
    let name_xid = system.snapshots.xid_for_name(&expected);
    let metadata_present = name_xid.is_some_and(|xid| {
        system
            .snapshots
            .snapshots
            .iter()
            .any(|snapshot| snapshot.xid == xid && snapshot.name == expected)
    });
    if name_xid.is_none() || !metadata_present {
        (SystemSnapshotToken::Missing, name_xid)
    } else {
        (SystemSnapshotToken::Present, name_xid)
    }
}

fn classify_root_to_xid(
    system: Option<&ArmedVolumeFacts>,
    named_xid: Option<u64>,
) -> RootToXidToken {
    let Some(system) = system else {
        return RootToXidToken::NotApplicable;
    };
    let Some(xid) = system.root_to_xid.known() else {
        return RootToXidToken::Unread;
    };
    if xid == 0 {
        return RootToXidToken::Zero;
    }
    match named_xid {
        Some(expected) if expected == xid => RootToXidToken::Ok,
        Some(_) => RootToXidToken::Mismatch,
        None => RootToXidToken::Mismatch,
    }
}

fn classify_preboot(has_system: bool, has_preboot: bool) -> PrebootToken {
    if !has_system {
        PrebootToken::NotApplicable
    } else if has_preboot {
        PrebootToken::Present
    } else {
        PrebootToken::Missing
    }
}

fn volume_detail_line(volume: &ArmedVolumeFacts) -> String {
    let seal = match &volume.seal {
        None => "seal=absent".to_string(),
        Some(seal) => format!(
            "seal={} hash={} broken={} snapshot={}",
            seal.hash_name,
            seal.root_hash_hex(),
            seal.broken,
            seal.root_snapshot_name()
        ),
    };
    let snapshot_names = volume
        .snapshots
        .snapshots
        .iter()
        .map(|snapshot| snapshot.name.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let snapshot_names = if snapshot_names.is_empty() {
        "-".to_string()
    } else {
        snapshot_names
    };
    format!(
        "name={:?} role={:#06x} sealed={} incompat={:#x} integrity_meta_oid={} snapshots={}/{}/{} names={} root_to_xid={} vgid={} {seal}",
        volume.name,
        volume.role,
        volume.sealed,
        volume.incompatible_features,
        volume.integrity_meta_oid,
        volume.snapshots.declared_count,
        volume.snapshots.snapshots.len(),
        volume.snapshots.names.len(),
        snapshot_names,
        format_root_to_xid_field(volume.root_to_xid),
        format_vgid_field(volume.volume_group_id),
    )
}

fn format_root_to_xid_field(field: ApsbField<u64>) -> String {
    match field {
        ApsbField::Unread => "unread".to_string(),
        ApsbField::Known(xid) => format!("{xid}"),
    }
}

fn format_vgid_field(field: ApsbField<[u8; 16]>) -> String {
    match field {
        ApsbField::Unread => "unread".to_string(),
        ApsbField::Known(id) if id == ZERO_VGID => "none".to_string(),
        ApsbField::Known(id) => {
            let mut hex = String::with_capacity(32);
            for byte in id {
                hex.push_str(&format!("{byte:02x}"));
            }
            hex
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apfs_image::APFS_VOL_ROLE_NONE;
    use crate::apfs_verify::{
        APFS_INCOMPAT_SEALED_VOLUME, ROOT_SNAPSHOT_PREFIX, SnapshotRecord, VolumeSeal,
    };

    fn seals_with(volumes: Vec<VolumeSealReport>) -> ContainerSeals {
        ContainerSeals {
            block_size: 4096,
            block_count: 64,
            uuid: [0; 16],
            xid: 1,
            superblock_paddr: 1,
            volumes,
        }
    }

    fn volume_report(
        name: &str,
        role: u16,
        sealed: bool,
        integrity_meta_oid: u64,
        seal: Option<VolumeSeal>,
        snapshots: VolumeSnapshots,
    ) -> VolumeSealReport {
        VolumeSealReport {
            oid: 1024,
            paddr: 8,
            fs_index: 0,
            name: name.to_string(),
            role,
            uuid: [0; 16],
            sealed,
            incompatible_features: if sealed {
                APFS_INCOMPAT_SEALED_VOLUME
            } else {
                0
            },
            integrity_meta_oid,
            seal,
            snapshots,
            root_to_xid: 0,
            volume_group_id: [0; 16],
        }
    }

    fn with_vgid(mut volume: VolumeSealReport, id: [u8; 16]) -> VolumeSealReport {
        volume.volume_group_id = id;
        volume
    }

    fn with_xid(mut volume: VolumeSealReport, xid: u64) -> VolumeSealReport {
        volume.root_to_xid = xid;
        volume
    }

    fn empty_snapshots() -> VolumeSnapshots {
        VolumeSnapshots::default()
    }

    fn snap(xid: u64, name: &str) -> SnapshotRecord {
        SnapshotRecord {
            xid,
            name: name.to_string(),
            flags: 0,
            sblock_oid: 0,
            extentref_tree_oid: 0,
            create_time: 0,
            change_time: 0,
            inum: 0,
        }
    }

    fn snapshots_with(xid: u64, name: &str) -> VolumeSnapshots {
        VolumeSnapshots {
            tree_paddr: 9,
            declared_count: 1,
            snapshots: vec![snap(xid, name)],
            names: vec![(name.to_string(), xid)],
        }
    }

    fn sample_seal(root_hash: Vec<u8>) -> VolumeSeal {
        VolumeSeal {
            oid: 7,
            paddr: 30,
            version: 2,
            flags: 0,
            broken: false,
            broken_xid: 0,
            hash_type: 1,
            hash_name: "sha256",
            root_hash_offset: 0x38,
            root_hash,
        }
    }

    fn none_role_volume() -> VolumeSealReport {
        volume_report(
            "Explorer",
            APFS_VOL_ROLE_NONE,
            false,
            0,
            None,
            empty_snapshots(),
        )
    }

    fn unsealed_system() -> VolumeSealReport {
        volume_report(
            "Macintosh HD",
            APFS_VOL_ROLE_SYSTEM,
            false,
            0,
            None,
            empty_snapshots(),
        )
    }

    fn data_volume() -> VolumeSealReport {
        volume_report(
            "Macintosh HD - Data",
            APFS_VOL_ROLE_DATA,
            false,
            0,
            None,
            empty_snapshots(),
        )
    }

    fn preboot_volume() -> VolumeSealReport {
        volume_report(
            "Preboot",
            APFS_VOL_ROLE_PREBOOT,
            false,
            0,
            None,
            empty_snapshots(),
        )
    }

    #[test]
    fn no_system_volume_is_not_a_boot_failure() {
        let report = classify_armed_image_seals(&seals_with(vec![none_role_volume()]));
        assert_eq!(report.volume_group.as_str(), "n/a");
        assert_eq!(report.system_seal.as_str(), "n/a");
        assert_eq!(report.system_snapshot.as_str(), "n/a");
        assert_eq!(report.root_to_xid.as_str(), "n/a");
        assert_eq!(report.preboot.as_str(), "n/a");
        assert!(!report.refuses_transfer());
        assert!(report.container_tokens().contains("volume_group=n/a"));
        assert!(
            report.volumes[0].contains("seal=absent"),
            "{}",
            report.volumes[0]
        );
    }

    #[test]
    fn unsealed_system_without_snapshots_is_a_note_not_a_refuse_transfer() {
        let report = classify_armed_image_seals(&seals_with(vec![unsealed_system()]));
        assert_eq!(report.system_seal.as_str(), "unsealed");
        assert_eq!(report.system_snapshot.as_str(), "missing");
        assert_eq!(report.root_to_xid.as_str(), "zero");
        assert_eq!(report.preboot.as_str(), "missing");
        assert!(!report.refuses_transfer());
        assert!(
            report.volumes[0].contains("seal=absent"),
            "{}",
            report.volumes[0]
        );
        assert!(
            !report.volumes[0].contains("hash="),
            "unsealed must not invent a seal hash: {}",
            report.volumes[0]
        );
    }

    #[test]
    fn system_without_data_is_no_data() {
        let report = classify_armed_image_seals(&seals_with(vec![with_vgid(
            unsealed_system(),
            [0x11u8; 16],
        )]));
        assert_eq!(report.volume_group.as_str(), "no-data");
        assert!(!report.refuses_transfer());
    }

    #[test]
    fn system_and_data_sharing_a_non_zero_vgid_are_paired() {
        let group = [0x11u8; 16];
        let report = classify_armed_image_seals(&seals_with(vec![
            with_vgid(unsealed_system(), group),
            with_vgid(data_volume(), group),
        ]));
        assert_eq!(report.volume_group.as_str(), "paired");
        assert!(!report.refuses_transfer());
        assert!(
            report.volumes[0].contains("vgid=11111111111111111111111111111111"),
            "{}",
            report.volumes[0]
        );
    }

    #[test]
    fn system_and_data_with_different_vgids_are_mismatch() {
        let report = classify_armed_image_seals(&seals_with(vec![
            with_vgid(unsealed_system(), [0x11u8; 16]),
            with_vgid(data_volume(), [0x22u8; 16]),
        ]));
        assert_eq!(report.volume_group.as_str(), "mismatch");
        assert!(!report.refuses_transfer());
    }

    #[test]
    fn system_with_zero_vgid_is_unpaired_even_when_data_exists() {
        let report = classify_armed_image_seals(&seals_with(vec![
            with_vgid(unsealed_system(), ZERO_VGID),
            with_vgid(data_volume(), [0x11u8; 16]),
        ]));
        assert_eq!(report.volume_group.as_str(), "system-unpaired");
    }

    #[test]
    fn system_with_zero_vgid_and_no_data_is_unpaired_not_no_data() {
        let report =
            classify_armed_image_seals(&seals_with(vec![with_vgid(unsealed_system(), ZERO_VGID)]));
        assert_eq!(report.volume_group.as_str(), "system-unpaired");
    }

    #[test]
    fn unread_vgid_with_system_and_data_stays_unread_not_zero() {
        let report = classify_armed_volumes(&[
            ArmedVolumeFacts::from_report(&unsealed_system()).with_volume_group_id_unread(),
            ArmedVolumeFacts::from_report(&data_volume()).with_volume_group_id_unread(),
        ]);
        assert_eq!(report.volume_group.as_str(), "unread");
        assert!(
            report
                .volumes
                .iter()
                .all(|line| line.contains("vgid=unread")),
            "{:?}",
            report.volumes
        );
    }

    #[test]
    fn named_snapshot_xid_disagreeing_with_root_to_xid_is_mismatch() {
        let name = format!("{ROOT_SNAPSHOT_PREFIX}DEADBEEF");
        let system = with_xid(
            volume_report(
                "Macintosh HD",
                APFS_VOL_ROLE_SYSTEM,
                false,
                0,
                None,
                snapshots_with(42, &name),
            ),
            7,
        );
        let report = classify_armed_image_seals(&seals_with(vec![system]));
        assert_eq!(report.system_snapshot.as_str(), "present");
        assert_eq!(report.root_to_xid.as_str(), "mismatch");
        assert!(!report.refuses_transfer());
    }

    #[test]
    fn matching_root_to_xid_is_ok() {
        let name = format!("{ROOT_SNAPSHOT_PREFIX}DEADBEEF");
        let system = with_xid(
            volume_report(
                "Macintosh HD",
                APFS_VOL_ROLE_SYSTEM,
                false,
                0,
                None,
                snapshots_with(42, &name),
            ),
            42,
        );
        let report = classify_armed_image_seals(&seals_with(vec![system]));
        assert_eq!(report.root_to_xid.as_str(), "ok");
    }

    #[test]
    fn zero_root_to_xid_is_zero_even_when_a_named_snapshot_exists() {
        let name = format!("{ROOT_SNAPSHOT_PREFIX}DEADBEEF");
        let system = volume_report(
            "Macintosh HD",
            APFS_VOL_ROLE_SYSTEM,
            false,
            0,
            None,
            snapshots_with(42, &name),
        );
        let report = classify_armed_image_seals(&seals_with(vec![system]));
        assert_eq!(report.root_to_xid.as_str(), "zero");
        assert_eq!(report.system_snapshot.as_str(), "present");
    }

    #[test]
    fn unread_root_to_xid_stays_unread_rather_than_zero() {
        let report = classify_armed_volumes(&[
            ArmedVolumeFacts::from_report(&unsealed_system()).with_root_to_xid_unread()
        ]);
        assert_eq!(report.root_to_xid.as_str(), "unread");
        assert!(
            report.volumes[0].contains("root_to_xid=unread"),
            "{}",
            report.volumes[0]
        );
    }

    #[test]
    fn sealed_volume_reports_the_real_hash_and_never_a_fabricated_one() {
        let hash = vec![
            0x82, 0x4C, 0xED, 0x64, 0xD9, 0xD5, 0x58, 0x85, 0x0E, 0xE4, 0x9C, 0x09, 0xB3, 0xD6,
            0xD2, 0x7B, 0xA3, 0x18, 0xCD, 0xA7, 0x0E, 0x9D, 0x49, 0xC7, 0xF6, 0x9B, 0x79, 0x76,
            0xE4, 0x8D, 0xF5, 0x4B,
        ];
        let seal = sample_seal(hash.clone());
        let expected_hex = seal.root_hash_hex();
        let system = volume_report(
            "Macintosh HD",
            APFS_VOL_ROLE_SYSTEM,
            true,
            7,
            Some(seal),
            empty_snapshots(),
        );
        let report = classify_armed_image_seals(&seals_with(vec![system, preboot_volume()]));
        assert_eq!(report.system_seal.as_str(), "sealed");
        assert_eq!(report.preboot.as_str(), "present");
        assert!(
            report.volumes[0].contains(&format!("hash={expected_hex}")),
            "{}",
            report.volumes[0]
        );
        assert!(
            !report.volumes[0].contains("seal=absent"),
            "{}",
            report.volumes[0]
        );
        assert_eq!(expected_hex.len(), 64);
        assert_ne!(expected_hex, "0".repeat(64));
    }

    #[test]
    fn sealed_flag_without_integrity_metadata_is_flag_without_meta() {
        let system = volume_report(
            "Macintosh HD",
            APFS_VOL_ROLE_SYSTEM,
            true,
            0,
            None,
            empty_snapshots(),
        );
        let report = classify_armed_image_seals(&seals_with(vec![system]));
        assert_eq!(report.system_seal.as_str(), "flag-without-meta");
        assert!(
            report.volumes[0].contains("seal=absent"),
            "{}",
            report.volumes[0]
        );
    }

    #[test]
    fn snapshot_name_without_matching_metadata_is_missing() {
        let name = format!("{ROOT_SNAPSHOT_PREFIX}DEADBEEF");
        let snapshots = VolumeSnapshots {
            tree_paddr: 9,
            declared_count: 1,
            snapshots: Vec::new(),
            names: vec![(name, 42)],
        };
        let system = volume_report(
            "Macintosh HD",
            APFS_VOL_ROLE_SYSTEM,
            false,
            0,
            None,
            snapshots,
        );
        let report = classify_armed_image_seals(&seals_with(vec![system]));
        assert_eq!(report.system_snapshot.as_str(), "missing");
    }

    #[test]
    fn meaning_separates_fdr_trust_objects_from_apfs_blessing() {
        assert!(ARMED_IMAGE_SEAL_MEANING.contains("rfta/ftap"));
        assert!(ARMED_IMAGE_SEAL_MEANING.contains("apple_boot_trust"));
        assert!(ARMED_IMAGE_SEAL_MEANING.contains("/System/Library/FDR/fdrtrustobject"));
        assert!(ARMED_IMAGE_SEAL_MEANING.contains("not APFS snapshot blessing"));
        assert!(ARMED_IMAGE_SEAL_MEANING.contains("com.apple.os.update-*"));
        assert!(ARMED_IMAGE_SEAL_MEANING.contains("apfs_sealvolume"));
        assert!(ARMED_IMAGE_SEAL_MEANING.contains("never refuses a transfer"));
        assert!(!ARMED_IMAGE_SEAL_MEANING.contains('"'));
    }
}
