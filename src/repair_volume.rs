use std::collections::BTreeSet;
use std::path::Path;

use crate::apfs_image::{
    APFS_INCOMPAT_SEALED_VOLUME, APFS_VOL_ROLE_DATA, APFS_VOL_ROLE_PREBOOT, APFS_VOL_ROLE_SYSTEM,
    NX_BLOCK_COUNT_OFFSET, NX_BLOCK_SIZE_OFFSET, NX_MAGIC, NX_MAGIC_OFFSET, NX_UUID_OFFSET,
    fletcher64_seal, parse_gpt,
};
use crate::apfs_verify::{
    APFS_MAGIC, BlockSource, ContainerSeals, OBJ_TYPE_MASK, ROOT_SNAPSHOT_PREFIX, SliceBlocks,
    TYPE_FS, VolumeSealReport, VolumeSnapshots, read_container_seals,
};
use crate::repair_ops::CheckStatus;

const APSB_INCOMPATIBLE_FEATURES_OFFSET: usize = 0x38;
const APSB_SNAP_META_TREE_OID_OFFSET: usize = 0x98;
const APSB_NUM_SNAPSHOTS_OFFSET: usize = 0xD8;
const APSB_ROOT_TO_XID_OFFSET: usize = 0x3C8;
const APSB_VOLUME_GROUP_OFFSET: usize = 0x3F0;
const APSB_INTEGRITY_META_OID_OFFSET: usize = 0x400;

const ZERO_VGID: [u8; 16] = [0u8; 16];

const OBJ_OID_OFFSET: usize = 0x08;
const OBJ_XID_OFFSET: usize = 0x10;
const OBJ_TYPE_OFFSET: usize = 0x18;
const APSB_FS_INDEX_OFFSET: usize = 0x24;
const APSB_UUID_OFFSET: usize = 0xF0;
const APSB_NAME_OFFSET: usize = 0x2C0;
const APSB_NAME_BYTES: usize = 0x100;
const APSB_ROLE_OFFSET: usize = 0x3C4;

const FALLBACK_VOL_APSB_PADDR: u64 = 21;

const GPT_PROBE_BYTES: usize = 64 * 1024;
const FALLBACK_SCAN_BLOCKS: u64 = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolumeFinding {
    pub id: String,
    pub status: CheckStatus,
    pub summary: String,
    pub detail: String,
    pub repairable: bool,
}

impl VolumeFinding {
    pub fn passed(&self) -> bool {
        self.status == CheckStatus::Pass
    }

    pub fn failed(&self) -> bool {
        self.status == CheckStatus::Fail
    }
}

pub fn inspect_seals(seals: &ContainerSeals) -> Vec<VolumeFinding> {
    let mut findings = Vec::new();
    findings.push(check_volume_group(seals));
    findings.push(check_preboot(seals));
    for volume in &seals.volumes {
        findings.push(check_snapshot_count(volume));
        findings.push(check_snapshot_names(volume));
        findings.push(check_volume_seal(volume));
        findings.push(check_blessing(volume));
        findings.push(check_root_to_xid(volume));
    }
    findings.sort_by(|left, right| left.id.cmp(&right.id));
    findings
}

pub fn inspect_source(source: &mut dyn BlockSource) -> Result<Vec<VolumeFinding>, String> {
    match seals_from_source(source) {
        Ok(seals) => Ok(inspect_seals(&seals)),
        Err(error) => Ok(vec![VolumeFinding {
            id: "volume-seals".to_string(),
            status: CheckStatus::Fail,
            summary: "failed to read volume seals".to_string(),
            detail: error,
            repairable: false,
        }]),
    }
}

pub fn inspect_image(path: &Path) -> Result<Vec<VolumeFinding>, String> {
    with_container(path, |container, block_size| {
        inspect_source(&mut SliceBlocks::new(container, block_size))
    })
}

pub fn apply_volume_repair(container: &mut [u8], block_size: u32, id: &str) -> Result<(), String> {
    if id == "volume-group" {
        return repair_volume_group(container, block_size);
    }
    if id == "preboot" {
        return Err("finding preboot is not repairable".into());
    }
    let (kind, paddr) = parse_volume_id(id)?;
    match kind {
        "snapshot-count" => repair_snapshot_count(container, block_size, paddr),
        "volume-seal" => repair_volume_seal_flag(container, block_size, paddr),
        "root-to-xid" => repair_root_to_xid(container, block_size, paddr),
        "snapshot-names" | "blessing" => Err(format!("finding {id} is not repairable")),
        _ => Err(format!("unrecognised repair id {id}")),
    }
}

pub fn apply_volume_repair_image(path: &Path, id: &str) -> Result<(), String> {
    with_container_mut(path, |container, block_size| {
        apply_volume_repair(container, block_size, id)
    })
}

pub fn inject_snapshot_count_fault(
    container: &mut [u8],
    block_size: u32,
    vol_paddr: u64,
) -> Result<(), String> {
    let block = volume_block_mut(container, block_size, vol_paddr)?;
    let declared = u64_at(block, APSB_NUM_SNAPSHOTS_OFFSET);
    let faulted = if declared == 0 { 7 } else { declared + 7 };
    put_u64(block, APSB_NUM_SNAPSHOTS_OFFSET, faulted);
    fletcher64_seal(block);
    Ok(())
}

pub fn inject_sealed_flag_fault(
    container: &mut [u8],
    block_size: u32,
    vol_paddr: u64,
) -> Result<(), String> {
    let block = volume_block_mut(container, block_size, vol_paddr)?;
    let features = u64_at(block, APSB_INCOMPATIBLE_FEATURES_OFFSET);
    put_u64(
        block,
        APSB_INCOMPATIBLE_FEATURES_OFFSET,
        features | APFS_INCOMPAT_SEALED_VOLUME,
    );
    fletcher64_seal(block);
    Ok(())
}

pub fn inject_snapshot_count_fault_image(path: &Path, vol_paddr: u64) -> Result<(), String> {
    with_container_mut(path, |container, block_size| {
        inject_snapshot_count_fault(container, block_size, vol_paddr)
    })
}

pub fn inject_sealed_flag_fault_image(path: &Path, vol_paddr: u64) -> Result<(), String> {
    with_container_mut(path, |container, block_size| {
        inject_sealed_flag_fault(container, block_size, vol_paddr)
    })
}

fn check_volume_group(seals: &ContainerSeals) -> VolumeFinding {
    let system = seals
        .volumes
        .iter()
        .find(|volume| volume.role == APFS_VOL_ROLE_SYSTEM);
    let data = seals
        .volumes
        .iter()
        .find(|volume| volume.role == APFS_VOL_ROLE_DATA);
    match (system, data) {
        (None, _) => VolumeFinding {
            id: "volume-group".to_string(),
            status: CheckStatus::NotApplicable,
            summary: "no system volume to pair".to_string(),
            detail: format!("volumes={}", seals.volumes.len()),
            repairable: false,
        },
        (Some(_), None) => VolumeFinding {
            id: "volume-group".to_string(),
            status: CheckStatus::Fail,
            summary: "system volume has no data-role volume to pair with".to_string(),
            detail: "SYSTEM is present, APFS_VOL_ROLE_DATA is absent".to_string(),
            repairable: false,
        },
        (Some(system), Some(data)) => {
            let ok = system.volume_group_id != ZERO_VGID
                && system.volume_group_id == data.volume_group_id;
            VolumeFinding {
                id: "volume-group".to_string(),
                status: if ok {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Fail
                },
                summary: if ok {
                    "system and data volumes share a volume group id".to_string()
                } else if system.volume_group_id == ZERO_VGID {
                    "system volume carries no apfs_volume_group_id".to_string()
                } else if data.volume_group_id == ZERO_VGID {
                    "data volume carries no apfs_volume_group_id".to_string()
                } else {
                    "system and data volume group ids disagree".to_string()
                },
                detail: format!(
                    "system={} data={}",
                    hex16(&system.volume_group_id),
                    hex16(&data.volume_group_id)
                ),
                repairable: !ok,
            }
        }
    }
}

fn check_preboot(seals: &ContainerSeals) -> VolumeFinding {
    let has_system = seals
        .volumes
        .iter()
        .any(|volume| volume.role == APFS_VOL_ROLE_SYSTEM);
    let has_preboot = seals
        .volumes
        .iter()
        .any(|volume| volume.role == APFS_VOL_ROLE_PREBOOT);
    if !has_system {
        return VolumeFinding {
            id: "preboot".to_string(),
            status: CheckStatus::NotApplicable,
            summary: "no system volume to require a preboot volume".to_string(),
            detail: format!("volumes={}", seals.volumes.len()),
            repairable: false,
        };
    }
    VolumeFinding {
        id: "preboot".to_string(),
        status: if has_preboot {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        summary: if has_preboot {
            "preboot-role volume is present".to_string()
        } else {
            "container has no preboot-role volume".to_string()
        },
        detail: if has_preboot {
            "role=Preboot".to_string()
        } else {
            "SYSTEM volume is present, APFS_VOL_ROLE_PREBOOT is absent".to_string()
        },
        repairable: false,
    }
}

pub(crate) fn named_root_snapshot_xid(snapshots: &VolumeSnapshots) -> Option<u64> {
    let name = snapshots.root_snapshot_name()?;
    let xid = snapshots.xid_for_name(name)?;
    snapshots
        .snapshots
        .iter()
        .any(|record| record.name == name && record.xid == xid)
        .then_some(xid)
}

pub(crate) fn check_root_to_xid(volume: &VolumeSealReport) -> VolumeFinding {
    let paddr = volume.paddr;
    let id = format!("root-to-xid:{paddr}");
    if volume.role != APFS_VOL_ROLE_SYSTEM {
        return VolumeFinding {
            id,
            status: CheckStatus::NotApplicable,
            summary: "volume is not a system volume".to_string(),
            detail: format!(
                "volume {} paddr {paddr}: apfs_root_to_xid={}",
                volume.name, volume.root_to_xid
            ),
            repairable: false,
        };
    }
    let Some(xid) = named_root_snapshot_xid(&volume.snapshots) else {
        return VolumeFinding {
            id,
            status: CheckStatus::NotApplicable,
            summary: "no named root snapshot to root the live volume at".to_string(),
            detail: format!(
                "volume {} paddr {paddr}: apfs_root_to_xid={}",
                volume.name, volume.root_to_xid
            ),
            repairable: false,
        };
    };
    let passed = volume.root_to_xid == xid;
    VolumeFinding {
        id,
        status: if passed {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        summary: if passed {
            format!("live volume is rooted at snapshot xid {xid}")
        } else if volume.root_to_xid == 0 {
            format!("live volume apfs_root_to_xid is 0 rather than snapshot xid {xid}")
        } else {
            format!(
                "live volume apfs_root_to_xid is {} rather than snapshot xid {xid}",
                volume.root_to_xid
            )
        },
        detail: format!(
            "volume {} paddr {paddr}: apfs_root_to_xid={} snapshot_xid={xid}",
            volume.name, volume.root_to_xid
        ),
        repairable: !passed,
    }
}

pub(crate) fn check_snapshot_count(volume: &VolumeSealReport) -> VolumeFinding {
    let paddr = volume.paddr;
    let declared = volume.snapshots.declared_count;
    let actual = volume.snapshots.snapshots.len() as u64;
    let passed = declared == actual;
    if passed && declared == 0 {
        let system = volume.role == APFS_VOL_ROLE_SYSTEM;
        return VolumeFinding {
            id: format!("snapshot-count:{paddr}"),
            status: if system {
                CheckStatus::Fail
            } else {
                CheckStatus::NotApplicable
            },
            summary: if system {
                "system volume has no snapshots".to_string()
            } else {
                "volume has no snapshots".to_string()
            },
            detail: format!(
                "volume {} paddr {paddr}: apfs_num_snapshots is 0, SNAP_METADATA holds 0",
                volume.name
            ),
            repairable: false,
        };
    }
    VolumeFinding {
        id: format!("snapshot-count:{paddr}"),
        status: if passed {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        summary: if passed {
            "declared snapshot count matches SNAP_METADATA records".to_string()
        } else {
            "declared snapshot count does not match SNAP_METADATA records".to_string()
        },
        detail: format!(
            "volume {} paddr {paddr}: apfs_num_snapshots is {declared}, SNAP_METADATA holds {actual}",
            volume.name
        ),
        repairable: !passed,
    }
}

pub(crate) fn check_snapshot_names(volume: &VolumeSealReport) -> VolumeFinding {
    let paddr = volume.paddr;
    let snapshots = &volume.snapshots;
    if snapshots.snapshots.is_empty() && snapshots.names.is_empty() {
        let system = volume.role == APFS_VOL_ROLE_SYSTEM;
        return VolumeFinding {
            id: format!("snapshot-names:{paddr}"),
            status: if system {
                CheckStatus::Fail
            } else {
                CheckStatus::NotApplicable
            },
            summary: if system {
                "system volume has no snapshot name index".to_string()
            } else {
                "no snapshot records to index".to_string()
            },
            detail: format!(
                "volume {} paddr {paddr}: both SNAP_METADATA and SNAP_NAME are empty",
                volume.name
            ),
            repairable: false,
        };
    }

    let mut mismatches = Vec::new();
    for record in &snapshots.snapshots {
        match snapshots.xid_for_name(&record.name) {
            Some(xid) if xid == record.xid => {}
            Some(xid) => mismatches.push(format!(
                "SNAP_METADATA {} xid {} has SNAP_NAME xid {xid}",
                record.name, record.xid
            )),
            None => mismatches.push(format!(
                "SNAP_METADATA {} xid {} has no SNAP_NAME record",
                record.name, record.xid
            )),
        }
    }
    for (name, xid) in &snapshots.names {
        let has_meta = snapshots
            .snapshots
            .iter()
            .any(|record| record.name == *name && record.xid == *xid);
        if !has_meta {
            mismatches.push(format!(
                "SNAP_NAME {name} xid {xid} has no SNAP_METADATA record"
            ));
        }
    }

    let passed = mismatches.is_empty();
    VolumeFinding {
        id: format!("snapshot-names:{paddr}"),
        status: if passed {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        summary: if passed {
            "SNAP_METADATA and SNAP_NAME records agree".to_string()
        } else {
            "SNAP_METADATA and SNAP_NAME records disagree".to_string()
        },
        detail: if passed {
            format!(
                "volume {} paddr {paddr}: {} snapshot(s) present in both indexes",
                volume.name,
                snapshots.snapshots.len()
            )
        } else {
            format!(
                "volume {} paddr {paddr}: {}",
                volume.name,
                mismatches.join("; ")
            )
        },
        repairable: false,
    }
}

fn check_volume_seal(volume: &VolumeSealReport) -> VolumeFinding {
    let paddr = volume.paddr;
    let flagged = volume.sealed || volume.incompatible_features & APFS_INCOMPAT_SEALED_VOLUME != 0;
    let has_meta = volume.integrity_meta_oid != 0;
    let id = format!("volume-seal:{paddr}");

    if let Some(seal) = &volume.seal
        && seal.broken
    {
        return VolumeFinding {
            id,
            status: CheckStatus::Fail,
            summary: "volume seal is recorded broken".to_string(),
            detail: format!(
                "volume {} paddr {paddr}: integrity metadata oid {} at paddr {} has APFS_SEAL_BROKEN (broken_xid {})",
                volume.name, seal.oid, seal.paddr, seal.broken_xid
            ),
            repairable: false,
        };
    }

    if flagged && !has_meta {
        return VolumeFinding {
            id,
            status: CheckStatus::Fail,
            summary: "sealed-volume flag is set without integrity metadata".to_string(),
            detail: format!(
                "volume {} paddr {paddr}: APFS_INCOMPAT_SEALED_VOLUME is set, apfs_integrity_meta_oid is 0",
                volume.name
            ),
            repairable: true,
        };
    }
    if has_meta && !flagged {
        return VolumeFinding {
            id,
            status: CheckStatus::Fail,
            summary: "integrity metadata is present without the sealed-volume flag".to_string(),
            detail: format!(
                "volume {} paddr {paddr}: apfs_integrity_meta_oid is {}, APFS_INCOMPAT_SEALED_VOLUME is clear",
                volume.name, volume.integrity_meta_oid
            ),
            repairable: true,
        };
    }

    VolumeFinding {
        id,
        status: if flagged {
            CheckStatus::Pass
        } else if volume.role == APFS_VOL_ROLE_SYSTEM {
            CheckStatus::Fail
        } else {
            CheckStatus::NotApplicable
        },
        summary: if flagged {
            "volume is sealed with integrity metadata".to_string()
        } else if volume.role == APFS_VOL_ROLE_SYSTEM {
            "system volume is not sealed".to_string()
        } else {
            "volume is not sealed".to_string()
        },
        detail: format!(
            "volume {} paddr {paddr}: sealed={flagged}, integrity_meta_oid={}",
            volume.name, volume.integrity_meta_oid
        ),
        repairable: false,
    }
}

fn check_blessing(volume: &VolumeSealReport) -> VolumeFinding {
    let paddr = volume.paddr;
    let id = format!("blessing:{paddr}");

    if let Some(seal) = &volume.seal {
        let name = seal.root_snapshot_name();
        if volume.snapshots.xid_for_name(&name).is_some() {
            return VolumeFinding {
                id,
                status: CheckStatus::Pass,
                summary: format!("root snapshot {name} is in the name index"),
                detail: format!(
                    "volume {} paddr {paddr}: name index resolves {name}",
                    volume.name
                ),
                repairable: false,
            };
        }
        return VolumeFinding {
            id,
            status: CheckStatus::Fail,
            summary: format!("sealed root snapshot {name} is not in the name index"),
            detail: format!(
                "volume {} paddr {paddr}: kernel lookup of {name} would fail",
                volume.name
            ),
            repairable: false,
        };
    }

    match volume.snapshots.root_snapshot_name() {
        None => VolumeFinding {
            id,
            status: if volume.role == APFS_VOL_ROLE_SYSTEM {
                CheckStatus::Fail
            } else {
                CheckStatus::NotApplicable
            },
            summary: if volume.role == APFS_VOL_ROLE_SYSTEM {
                "system volume has no blessed root snapshot".to_string()
            } else {
                "no sealed root snapshot to bless".to_string()
            },
            detail: format!(
                "volume {} paddr {paddr}: unsealed, no {ROOT_SNAPSHOT_PREFIX}* name records",
                volume.name
            ),
            repairable: false,
        },
        Some(name) => {
            let xid = volume.snapshots.xid_for_name(name);
            let meta_ok = xid.is_some_and(|xid| {
                volume
                    .snapshots
                    .snapshots
                    .iter()
                    .any(|record| record.name == name && record.xid == xid)
            });
            VolumeFinding {
                id,
                status: if meta_ok {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Fail
                },
                summary: if meta_ok {
                    format!("unsealed root snapshot {name} matches SNAP_METADATA")
                } else {
                    format!("unsealed root snapshot {name} has no SNAP_METADATA record")
                },
                detail: format!(
                    "volume {} paddr {paddr}: {ROOT_SNAPSHOT_PREFIX}* name {name} xid {xid:?}",
                    volume.name
                ),
                repairable: false,
            }
        }
    }
}

fn seals_from_source(source: &mut dyn BlockSource) -> Result<ContainerSeals, String> {
    match read_container_seals(source) {
        Ok(seals) => Ok(seals),
        Err(error) => match seals_from_apsb_fields(source) {
            Some(seals) if !seals.volumes.is_empty() => Ok(seals),
            _ => Err(error.to_string()),
        },
    }
}

fn seals_from_apsb_fields(source: &mut dyn BlockSource) -> Option<ContainerSeals> {
    let mut probe = vec![0u8; 4096];
    source.read_block(0, &mut probe).ok()?;
    if u32_at(&probe, NX_MAGIC_OFFSET) != NX_MAGIC {
        return None;
    }
    let block_size = u32_at(&probe, NX_BLOCK_SIZE_OFFSET);
    if !(512..=65536).contains(&block_size) || !block_size.is_power_of_two() {
        return None;
    }
    let block_count = u64_at(&probe, NX_BLOCK_COUNT_OFFSET);
    if block_count == 0 {
        return None;
    }

    let mut block0 = vec![0u8; block_size as usize];
    source.read_block(0, &mut block0).ok()?;

    let mut volumes = Vec::new();
    let mut seen = BTreeSet::new();
    let mut consider = |paddr: u64, volumes: &mut Vec<VolumeSealReport>| {
        if paddr >= block_count || !seen.insert(paddr) {
            return;
        }
        let mut block = vec![0u8; block_size as usize];
        if source.read_block(paddr, &mut block).is_err() {
            return;
        }
        if let Some(report) = volume_report_from_apsb(paddr, &block) {
            volumes.push(report);
        }
    };

    consider(FALLBACK_VOL_APSB_PADDR, &mut volumes);
    let scan_to = block_count.min(FALLBACK_SCAN_BLOCKS);
    for paddr in 0..scan_to {
        consider(paddr, &mut volumes);
    }
    volumes.sort_by_key(|volume| volume.paddr);

    let mut uuid = [0u8; 16];
    if block0.len() >= NX_UUID_OFFSET + 16 {
        uuid.copy_from_slice(&block0[NX_UUID_OFFSET..NX_UUID_OFFSET + 16]);
    }

    Some(ContainerSeals {
        block_size,
        block_count,
        uuid,
        xid: u64_at(&block0, OBJ_XID_OFFSET),
        superblock_paddr: 0,
        volumes,
    })
}

fn volume_report_from_apsb(paddr: u64, bytes: &[u8]) -> Option<VolumeSealReport> {
    if !looks_like_apsb(bytes) {
        return None;
    }
    let incompatible_features = u64_at(bytes, APSB_INCOMPATIBLE_FEATURES_OFFSET);
    let integrity_meta_oid = u64_at(bytes, APSB_INTEGRITY_META_OID_OFFSET);
    let snap_meta_tree_paddr = u64_at(bytes, APSB_SNAP_META_TREE_OID_OFFSET);
    let declared_count = u64_at(bytes, APSB_NUM_SNAPSHOTS_OFFSET);

    let name_end = bytes[APSB_NAME_OFFSET..APSB_NAME_OFFSET + APSB_NAME_BYTES]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(0);
    let name =
        String::from_utf8_lossy(&bytes[APSB_NAME_OFFSET..APSB_NAME_OFFSET + name_end]).into_owned();
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&bytes[APSB_UUID_OFFSET..APSB_UUID_OFFSET + 16]);
    let root_to_xid = u64_at(bytes, APSB_ROOT_TO_XID_OFFSET);
    let mut volume_group_id = [0u8; 16];
    volume_group_id
        .copy_from_slice(&bytes[APSB_VOLUME_GROUP_OFFSET..APSB_VOLUME_GROUP_OFFSET + 16]);

    Some(VolumeSealReport {
        oid: u64_at(bytes, OBJ_OID_OFFSET),
        paddr,
        fs_index: u32_at(bytes, APSB_FS_INDEX_OFFSET),
        name,
        role: u16_at(bytes, APSB_ROLE_OFFSET),
        uuid,
        sealed: incompatible_features & APFS_INCOMPAT_SEALED_VOLUME != 0,
        incompatible_features,
        integrity_meta_oid,
        seal: None,
        snapshots: VolumeSnapshots {
            tree_paddr: snap_meta_tree_paddr,
            declared_count,
            snapshots: Vec::new(),
            names: Vec::new(),
        },
        root_to_xid,
        volume_group_id,
    })
}

fn looks_like_apsb(bytes: &[u8]) -> bool {
    bytes.len() >= APSB_INTEGRITY_META_OID_OFFSET + 8
        && u32_at(bytes, NX_MAGIC_OFFSET) == APFS_MAGIC
        && u32_at(bytes, OBJ_TYPE_OFFSET) & OBJ_TYPE_MASK == TYPE_FS
}

fn repair_snapshot_count(container: &mut [u8], block_size: u32, paddr: u64) -> Result<(), String> {
    let actual = snapshot_metadata_count(container, block_size, paddr)?;
    let block = volume_block_mut(container, block_size, paddr)?;
    put_u64(block, APSB_NUM_SNAPSHOTS_OFFSET, actual);
    fletcher64_seal(block);
    Ok(())
}

fn repair_root_to_xid(container: &mut [u8], block_size: u32, paddr: u64) -> Result<(), String> {
    let Some(volume) = volume_from_container(container, block_size, paddr) else {
        return Err(format!(
            "root-to-xid:{paddr} cannot resolve a named root snapshot"
        ));
    };
    let Some(xid) = named_root_snapshot_xid(&volume.snapshots) else {
        return Err(format!(
            "root-to-xid:{paddr} has no named root snapshot to write"
        ));
    };
    let block = volume_block_mut(container, block_size, paddr)?;
    put_u64(block, APSB_ROOT_TO_XID_OFFSET, xid);
    fletcher64_seal(block);
    Ok(())
}

fn repair_volume_group(container: &mut [u8], block_size: u32) -> Result<(), String> {
    let (system, data) = {
        let mut source = crate::apfs_verify::SliceBlocks::new(container, block_size);
        let seals = seals_from_source(&mut source)?;
        let system = seals
            .volumes
            .iter()
            .find(|volume| volume.role == APFS_VOL_ROLE_SYSTEM)
            .cloned();
        let data = seals
            .volumes
            .iter()
            .find(|volume| volume.role == APFS_VOL_ROLE_DATA)
            .cloned();
        (system, data)
    };
    let (Some(system), Some(data)) = (system, data) else {
        return Err("volume-group is not repairable without both SYSTEM and DATA volumes".into());
    };
    let target = pick_group_id(
        &system.volume_group_id,
        &data.volume_group_id,
        &system.uuid,
        &data.uuid,
    );
    write_volume_group_id(container, block_size, system.paddr, &target)?;
    write_volume_group_id(container, block_size, data.paddr, &target)?;
    Ok(())
}

fn write_volume_group_id(
    container: &mut [u8],
    block_size: u32,
    paddr: u64,
    group: &[u8; 16],
) -> Result<(), String> {
    let block = volume_block_mut(container, block_size, paddr)?;
    block[APSB_VOLUME_GROUP_OFFSET..APSB_VOLUME_GROUP_OFFSET + 16].copy_from_slice(group);
    fletcher64_seal(block);
    Ok(())
}

fn pick_group_id(
    system_group: &[u8; 16],
    data_group: &[u8; 16],
    system_uuid: &[u8; 16],
    data_uuid: &[u8; 16],
) -> [u8; 16] {
    if *system_group != ZERO_VGID {
        *system_group
    } else if *data_group != ZERO_VGID {
        *data_group
    } else {
        mint_group_id(system_uuid, data_uuid)
    }
}

fn mint_group_id(system_uuid: &[u8; 16], data_uuid: &[u8; 16]) -> [u8; 16] {
    let mut input = [0u8; 32];
    if system_uuid <= data_uuid {
        input[..16].copy_from_slice(system_uuid);
        input[16..].copy_from_slice(data_uuid);
    } else {
        input[..16].copy_from_slice(data_uuid);
        input[16..].copy_from_slice(system_uuid);
    }
    let digest = crate::crypto::hash::sha256(&input);
    let mut group = [0u8; 16];
    group.copy_from_slice(&digest[..16]);
    group[6] = (group[6] & 0x0F) | 0x40;
    group[8] = (group[8] & 0x3F) | 0x80;
    group
}

fn hex16(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn repair_volume_seal_flag(
    container: &mut [u8],
    block_size: u32,
    paddr: u64,
) -> Result<(), String> {
    if let Some(volume) = volume_from_container(container, block_size, paddr)
        && volume.seal.as_ref().is_some_and(|seal| seal.broken)
    {
        return Err(format!(
            "volume-seal:{paddr} is recorded broken and is not repairable"
        ));
    }
    let block = volume_block_mut(container, block_size, paddr)?;
    let features = u64_at(block, APSB_INCOMPATIBLE_FEATURES_OFFSET);
    let flagged = features & APFS_INCOMPAT_SEALED_VOLUME != 0;
    let has_meta = u64_at(block, APSB_INTEGRITY_META_OID_OFFSET) != 0;
    let repaired = if flagged && !has_meta {
        features & !APFS_INCOMPAT_SEALED_VOLUME
    } else if has_meta && !flagged {
        features | APFS_INCOMPAT_SEALED_VOLUME
    } else {
        return Err(format!(
            "volume-seal:{paddr} is already consistent or not repairable"
        ));
    };
    put_u64(block, APSB_INCOMPATIBLE_FEATURES_OFFSET, repaired);
    fletcher64_seal(block);
    Ok(())
}

fn snapshot_metadata_count(container: &[u8], block_size: u32, paddr: u64) -> Result<u64, String> {
    if let Some(volume) = volume_from_container(container, block_size, paddr) {
        return Ok(volume.snapshots.snapshots.len() as u64);
    }
    let block = volume_block(container, block_size, paddr)?;
    let tree = u64_at(block, APSB_SNAP_META_TREE_OID_OFFSET);
    if tree == 0 {
        Ok(0)
    } else {
        Err(format!(
            "cannot recount snapshots for paddr {paddr}: snapshot tree is present but the seal walk failed"
        ))
    }
}

fn volume_from_container(
    container: &[u8],
    block_size: u32,
    paddr: u64,
) -> Option<VolumeSealReport> {
    let mut source = SliceBlocks::new(container, block_size);
    match seals_from_source(&mut source) {
        Ok(seals) => seals
            .volumes
            .into_iter()
            .find(|volume| volume.paddr == paddr),
        Err(_) => None,
    }
}

fn parse_volume_id(id: &str) -> Result<(&str, u64), String> {
    let (kind, rest) = id
        .split_once(':')
        .ok_or_else(|| format!("unrecognised repair id {id}"))?;
    if kind.is_empty() || rest.is_empty() {
        return Err(format!("unrecognised repair id {id}"));
    }
    let paddr = rest
        .parse::<u64>()
        .map_err(|_| format!("unrecognised repair id {id}"))?;
    Ok((kind, paddr))
}

struct ContainerLoc {
    offset: u64,
    block_size: u32,
    block_count: u64,
}

fn locate_apfs_container(
    mut read_at: impl FnMut(u64, &mut [u8]) -> Result<(), String>,
) -> Result<ContainerLoc, String> {
    let mut head = vec![0u8; GPT_PROBE_BYTES];
    read_at(0, &mut head)?;
    if let Some(loc) = loc_from_nxsb(&head, 0) {
        return Ok(loc);
    }
    for gpt_block in [512u32, 4096] {
        let Ok(table) = parse_gpt(&head, gpt_block) else {
            continue;
        };
        let Some(part) = table.partitions.iter().find(|part| part.is_apple_apfs()) else {
            continue;
        };
        let (start, _) = part.byte_range(gpt_block);
        let mut nxsb = vec![0u8; 4096];
        read_at(start, &mut nxsb)?;
        if let Some(loc) = loc_from_nxsb(&nxsb, start) {
            return Ok(loc);
        }
    }
    Err("no APFS container at byte 0 and no GPT Apple_APFS partition with NXSB".into())
}

fn loc_from_nxsb(block: &[u8], offset: u64) -> Option<ContainerLoc> {
    if block.len() < NX_BLOCK_COUNT_OFFSET + 8 {
        return None;
    }
    if u32_at(block, NX_MAGIC_OFFSET) != NX_MAGIC {
        return None;
    }
    let block_size = u32_at(block, NX_BLOCK_SIZE_OFFSET);
    let block_count = u64_at(block, NX_BLOCK_COUNT_OFFSET);
    if !(512..=65536).contains(&block_size) || !block_size.is_power_of_two() || block_count == 0 {
        return None;
    }
    Some(ContainerLoc {
        offset,
        block_size,
        block_count,
    })
}

fn container_len(loc: &ContainerLoc) -> Result<usize, String> {
    let bytes = loc
        .block_count
        .checked_mul(u64::from(loc.block_size))
        .ok_or_else(|| "APFS container size overflows".to_string())?;
    usize::try_from(bytes).map_err(|_| "APFS container does not fit in memory".to_string())
}

fn with_container<T>(
    path: &Path,
    body: impl FnOnce(&[u8], u32) -> Result<T, String>,
) -> Result<T, String> {
    let mut disc = crate::asahi_ops::open_disc(path).map_err(|e| e.to_string())?;
    let loc =
        locate_apfs_container(|offset, buf| disc.read_at(offset, buf).map_err(|e| e.to_string()))?;
    let len = container_len(&loc)?;
    let mut container = vec![0u8; len];
    disc.read_at(loc.offset, &mut container)
        .map_err(|e| e.to_string())?;
    body(&container, loc.block_size)
}

fn with_container_mut(
    path: &Path,
    body: impl FnOnce(&mut [u8], u32) -> Result<(), String>,
) -> Result<(), String> {
    let mut disc = crate::asahi_ops::open_disc(path).map_err(|e| e.to_string())?;
    let loc =
        locate_apfs_container(|offset, buf| disc.read_at(offset, buf).map_err(|e| e.to_string()))?;
    let len = container_len(&loc)?;
    let mut container = vec![0u8; len];
    disc.read_at(loc.offset, &mut container)
        .map_err(|e| e.to_string())?;
    body(&mut container, loc.block_size)?;
    disc.write_at(loc.offset, &container)
        .map_err(|e| e.to_string())
}

fn volume_block(container: &[u8], block_size: u32, paddr: u64) -> Result<&[u8], String> {
    let (at, end) = volume_block_range(container.len(), block_size, paddr)?;
    let block = &container[at..end];
    if !looks_like_apsb(block) {
        return Err(format!("block {paddr} is not a volume superblock"));
    }
    Ok(block)
}

fn volume_block_mut(
    container: &mut [u8],
    block_size: u32,
    paddr: u64,
) -> Result<&mut [u8], String> {
    let (at, end) = volume_block_range(container.len(), block_size, paddr)?;
    let block = &mut container[at..end];
    if !looks_like_apsb(block) {
        return Err(format!("block {paddr} is not a volume superblock"));
    }
    Ok(block)
}

fn volume_block_range(
    container_len: usize,
    block_size: u32,
    paddr: u64,
) -> Result<(usize, usize), String> {
    let block_size = block_size as usize;
    if block_size == 0 {
        return Err("block size is zero".into());
    }
    let at = paddr
        .checked_mul(block_size as u64)
        .and_then(|at| usize::try_from(at).ok())
        .ok_or_else(|| format!("volume paddr {paddr} overflows"))?;
    let end = at
        .checked_add(block_size)
        .ok_or_else(|| format!("volume paddr {paddr} overflows"))?;
    if end > container_len {
        return Err(format!(
            "volume superblock at paddr {paddr} is outside the container"
        ));
    }
    Ok((at, end))
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("u16 field"))
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("u32 field"))
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("u64 field"))
}

fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apfs_fixture::{ImageWrap, container_bytes, write_fixture};
    use crate::apfs_verify::{SnapshotRecord, VolumeSeal};

    const FIXTURE_VOL_APSB_PADDR: u64 = 21;
    const BLOCK_SIZE: u32 = 4096;

    fn write_gpt_image() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("disk.img");
        write_fixture(&path, ImageWrap::RawGpt).expect("write gpt fixture");
        (dir, path)
    }

    fn finding<'a>(findings: &'a [VolumeFinding], id: &str) -> &'a VolumeFinding {
        findings
            .iter()
            .find(|finding| finding.id == id)
            .unwrap_or_else(|| {
                panic!(
                    "missing finding {id} in {:?}",
                    findings
                        .iter()
                        .map(|finding| &finding.id)
                        .collect::<Vec<_>>()
                )
            })
    }

    fn assert_sorted(findings: &[VolumeFinding]) {
        assert!(
            findings.windows(2).all(|pair| pair[0].id <= pair[1].id),
            "findings are not sorted by id: {:?}",
            findings
                .iter()
                .map(|finding| &finding.id)
                .collect::<Vec<_>>()
        );
    }

    fn assert_clean_volume_checks(findings: &[VolumeFinding], paddr: u64) {
        assert!(!findings.is_empty(), "expected volume findings");
        assert_sorted(findings);
        for kind in [
            "snapshot-count",
            "snapshot-names",
            "volume-seal",
            "blessing",
            "root-to-xid",
        ] {
            let id = format!("{kind}:{paddr}");
            let item = finding(findings, &id);
            assert!(
                !item.failed(),
                "{id} failed: {} — {}",
                item.summary,
                item.detail
            );
            assert!(!item.repairable, "{id} was marked repairable");
        }
        for id in ["volume-group", "preboot"] {
            let item = finding(findings, id);
            assert!(
                !item.failed(),
                "{id} failed: {} — {}",
                item.summary,
                item.detail
            );
            assert!(!item.repairable, "{id} was marked repairable");
            assert_eq!(
                item.status,
                CheckStatus::NotApplicable,
                "{id} should be N/A on the explorer fixture"
            );
        }
    }

    fn empty_volume(
        paddr: u64,
        sealed: bool,
        integrity_meta_oid: u64,
        seal: Option<VolumeSeal>,
        snapshots: VolumeSnapshots,
    ) -> VolumeSealReport {
        VolumeSealReport {
            oid: 1024,
            paddr,
            fs_index: 0,
            name: "Explorer".into(),
            role: 0,
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

    fn seals_with(volumes: Vec<VolumeSealReport>) -> ContainerSeals {
        ContainerSeals {
            block_size: BLOCK_SIZE,
            block_count: 64,
            uuid: [0; 16],
            xid: 1,
            superblock_paddr: 1,
            volumes,
        }
    }

    fn sample_seal(broken: bool) -> VolumeSeal {
        VolumeSeal {
            oid: 7,
            paddr: 30,
            version: 2,
            flags: if broken { 1 } else { 0 },
            broken,
            broken_xid: if broken { 9 } else { 0 },
            hash_type: 1,
            hash_name: "sha256",
            root_hash_offset: 0x38,
            root_hash: vec![0xAB; 32],
        }
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

    #[test]
    fn clean_raw_gpt_fixture_passes_snapshot_seal_and_blessing_checks() {
        let (_dir, path) = write_gpt_image();
        let findings = inspect_image(&path).expect("inspect_image");
        assert_clean_volume_checks(&findings, FIXTURE_VOL_APSB_PADDR);
    }

    #[test]
    fn snapshot_count_fault_is_detected_and_repaired() {
        let (_dir, path) = write_gpt_image();
        inject_snapshot_count_fault_image(&path, FIXTURE_VOL_APSB_PADDR)
            .expect("inject snapshot count");
        let id = format!("snapshot-count:{FIXTURE_VOL_APSB_PADDR}");
        let before = inspect_image(&path).expect("inspect after inject");
        let count = finding(&before, &id);
        assert!(!count.passed(), "injected count should fail: {count:?}");
        assert!(count.repairable, "snapshot-count should be repairable");
        apply_volume_repair_image(&path, &id).expect("repair snapshot-count");
        let after = inspect_image(&path).expect("inspect after repair");
        assert_clean_volume_checks(&after, FIXTURE_VOL_APSB_PADDR);
    }

    #[test]
    fn sealed_flag_fault_is_detected_and_repaired() {
        let (_dir, path) = write_gpt_image();
        inject_sealed_flag_fault_image(&path, FIXTURE_VOL_APSB_PADDR).expect("inject sealed flag");
        let id = format!("volume-seal:{FIXTURE_VOL_APSB_PADDR}");
        let before = inspect_image(&path).expect("inspect after inject");
        let seal = finding(&before, &id);
        assert!(!seal.passed(), "injected sealed flag should fail: {seal:?}");
        assert!(seal.repairable, "flag-without-meta should be repairable");
        apply_volume_repair_image(&path, &id).expect("repair volume-seal");
        let after = inspect_image(&path).expect("inspect after repair");
        assert_clean_volume_checks(&after, FIXTURE_VOL_APSB_PADDR);
        let blessing = finding(&after, &format!("blessing:{FIXTURE_VOL_APSB_PADDR}"));
        assert!(!blessing.failed(), "blessing should not fail once unsealed");
        assert_eq!(blessing.status, CheckStatus::NotApplicable);
        assert_eq!(blessing.summary, "no sealed root snapshot to bless");
    }

    #[test]
    fn bare_container_slice_passes_inspect_seals_and_inspect_source() {
        let bytes = container_bytes();
        let mut source = SliceBlocks::new(&bytes, BLOCK_SIZE);
        let from_source = inspect_source(&mut source).expect("inspect_source");
        assert_clean_volume_checks(&from_source, FIXTURE_VOL_APSB_PADDR);

        let mut source = SliceBlocks::new(&bytes, BLOCK_SIZE);
        if let Ok(seals) = read_container_seals(&mut source) {
            let from_seals = inspect_seals(&seals);
            assert_eq!(from_seals, from_source);
            assert_clean_volume_checks(&from_seals, FIXTURE_VOL_APSB_PADDR);
        }
    }

    #[test]
    fn inspect_image_findings_are_stable_across_runs() {
        let (_dir, path) = write_gpt_image();
        let first = inspect_image(&path).expect("first inspect");
        let second = inspect_image(&path).expect("second inspect");
        assert_sorted(&first);
        assert_eq!(first, second);
        assert_clean_volume_checks(&first, FIXTURE_VOL_APSB_PADDR);
    }

    #[test]
    fn snapshot_count_mismatch_is_repairable() {
        let findings = inspect_seals(&seals_with(vec![empty_volume(
            21,
            false,
            0,
            None,
            VolumeSnapshots {
                tree_paddr: 0,
                declared_count: 7,
                snapshots: Vec::new(),
                names: Vec::new(),
            },
        )]));
        let item = finding(&findings, "snapshot-count:21");
        assert!(!item.passed());
        assert!(item.repairable);
    }

    #[test]
    fn snapshot_name_index_mismatch_is_not_repairable() {
        let findings = inspect_seals(&seals_with(vec![empty_volume(
            21,
            false,
            0,
            None,
            VolumeSnapshots {
                tree_paddr: 1,
                declared_count: 1,
                snapshots: vec![snap(3, "keep")],
                names: Vec::new(),
            },
        )]));
        let names = finding(&findings, "snapshot-names:21");
        assert!(!names.passed());
        assert!(!names.repairable);
        let count = finding(&findings, "snapshot-count:21");
        assert!(count.passed());
    }

    #[test]
    fn broken_seal_is_not_repairable() {
        let findings = inspect_seals(&seals_with(vec![empty_volume(
            21,
            true,
            7,
            Some(sample_seal(true)),
            VolumeSnapshots::default(),
        )]));
        let item = finding(&findings, "volume-seal:21");
        assert!(!item.passed());
        assert!(!item.repairable);
    }

    #[test]
    fn sealed_flag_without_integrity_meta_is_repairable() {
        let findings = inspect_seals(&seals_with(vec![empty_volume(
            21,
            true,
            0,
            None,
            VolumeSnapshots::default(),
        )]));
        let item = finding(&findings, "volume-seal:21");
        assert!(!item.passed());
        assert!(item.repairable);
        let blessing = finding(&findings, "blessing:21");
        assert_eq!(blessing.status, CheckStatus::NotApplicable);
        assert_eq!(blessing.summary, "no sealed root snapshot to bless");
    }

    #[test]
    fn system_volume_without_seal_or_snapshots_fails() {
        let mut volume = empty_volume(21, false, 0, None, VolumeSnapshots::default());
        volume.role = APFS_VOL_ROLE_SYSTEM;
        let findings = inspect_seals(&seals_with(vec![volume]));
        assert!(finding(&findings, "snapshot-count:21").failed());
        assert!(finding(&findings, "snapshot-names:21").failed());
        assert!(finding(&findings, "volume-seal:21").failed());
        assert!(finding(&findings, "blessing:21").failed());
        assert_eq!(
            finding(&findings, "blessing:21").summary,
            "system volume has no blessed root snapshot"
        );
        assert!(!finding(&findings, "snapshot-count:21").repairable);
        assert!(!finding(&findings, "snapshot-names:21").repairable);
        assert!(!finding(&findings, "volume-seal:21").repairable);
        assert!(!finding(&findings, "blessing:21").repairable);
        assert_eq!(
            finding(&findings, "root-to-xid:21").status,
            CheckStatus::NotApplicable
        );
        assert!(!finding(&findings, "root-to-xid:21").repairable);
        assert!(finding(&findings, "volume-group").failed());
        assert!(!finding(&findings, "volume-group").repairable);
        assert!(finding(&findings, "preboot").failed());
        assert!(!finding(&findings, "preboot").repairable);
    }

    #[test]
    fn system_named_snapshot_with_unset_root_to_xid_is_repairable() {
        let mut volume = empty_volume(
            21,
            false,
            0,
            None,
            VolumeSnapshots {
                tree_paddr: 1,
                declared_count: 1,
                snapshots: vec![snap(42, "com.apple.os.update-DEAD")],
                names: vec![("com.apple.os.update-DEAD".into(), 42)],
            },
        );
        volume.role = APFS_VOL_ROLE_SYSTEM;
        let findings = inspect_seals(&seals_with(vec![volume.clone()]));
        let item = finding(&findings, "root-to-xid:21");
        assert!(item.failed(), "{item:?}");
        assert!(item.repairable, "{item:?}");

        volume.root_to_xid = 42;
        let after = inspect_seals(&seals_with(vec![volume]));
        let item = finding(&after, "root-to-xid:21");
        assert!(item.passed(), "{item:?}");
        assert!(!item.repairable);
    }

    #[test]
    fn volume_group_pairing_shapes() {
        let mut system = empty_volume(21, false, 0, None, VolumeSnapshots::default());
        system.role = APFS_VOL_ROLE_SYSTEM;
        system.uuid = [0xAA; 16];
        let mut data = empty_volume(26, false, 0, None, VolumeSnapshots::default());
        data.role = APFS_VOL_ROLE_DATA;
        data.uuid = [0xBB; 16];

        let none = inspect_seals(&seals_with(vec![empty_volume(
            21,
            false,
            0,
            None,
            VolumeSnapshots::default(),
        )]));
        assert_eq!(
            finding(&none, "volume-group").status,
            CheckStatus::NotApplicable
        );
        assert_eq!(finding(&none, "preboot").status, CheckStatus::NotApplicable);

        let no_data = inspect_seals(&seals_with(vec![system.clone()]));
        assert!(finding(&no_data, "volume-group").failed());
        assert!(!finding(&no_data, "volume-group").repairable);

        let mut mismatched = system.clone();
        mismatched.volume_group_id = [0x11; 16];
        let mut data_other = data.clone();
        data_other.volume_group_id = [0x22; 16];
        let disagree = inspect_seals(&seals_with(vec![mismatched.clone(), data_other]));
        assert!(finding(&disagree, "volume-group").failed());
        assert!(finding(&disagree, "volume-group").repairable);

        data.volume_group_id = [0x11; 16];
        let agree = inspect_seals(&seals_with(vec![mismatched, data]));
        assert!(finding(&agree, "volume-group").passed());
    }

    #[test]
    fn integrity_meta_without_sealed_flag_is_repairable() {
        let findings = inspect_seals(&seals_with(vec![empty_volume(
            21,
            false,
            7,
            None,
            VolumeSnapshots::default(),
        )]));
        let item = finding(&findings, "volume-seal:21");
        assert!(!item.passed());
        assert!(item.repairable);
    }

    #[test]
    fn sealed_blessing_requires_the_root_snapshot_name() {
        let seal = sample_seal(false);
        let name = seal.root_snapshot_name();
        let missing = inspect_seals(&seals_with(vec![empty_volume(
            21,
            true,
            7,
            Some(seal.clone()),
            VolumeSnapshots::default(),
        )]));
        let blessing = finding(&missing, "blessing:21");
        assert!(!blessing.passed());
        assert!(!blessing.repairable);

        let present = inspect_seals(&seals_with(vec![empty_volume(
            21,
            true,
            7,
            Some(seal),
            VolumeSnapshots {
                tree_paddr: 1,
                declared_count: 1,
                snapshots: vec![snap(4, &name)],
                names: vec![(name.clone(), 4)],
            },
        )]));
        let blessing = finding(&present, "blessing:21");
        assert!(blessing.passed());
        let names = finding(&present, "snapshot-names:21");
        assert!(names.passed());
    }

    #[test]
    fn slice_snapshot_count_fault_round_trips_without_image_io() {
        let mut container = container_bytes();
        inject_snapshot_count_fault(&mut container, BLOCK_SIZE, FIXTURE_VOL_APSB_PADDR)
            .expect("inject");
        let before =
            inspect_source(&mut SliceBlocks::new(&container, BLOCK_SIZE)).expect("inspect");
        let id = format!("snapshot-count:{FIXTURE_VOL_APSB_PADDR}");
        let item = finding(&before, &id);
        assert!(!item.passed());
        assert!(item.repairable);
        apply_volume_repair(&mut container, BLOCK_SIZE, &id).expect("repair");
        let after = inspect_source(&mut SliceBlocks::new(&container, BLOCK_SIZE)).expect("inspect");
        assert_clean_volume_checks(&after, FIXTURE_VOL_APSB_PADDR);
    }

    #[test]
    fn slice_sealed_flag_fault_round_trips_without_image_io() {
        let mut container = container_bytes();
        inject_sealed_flag_fault(&mut container, BLOCK_SIZE, FIXTURE_VOL_APSB_PADDR)
            .expect("inject");
        let before =
            inspect_source(&mut SliceBlocks::new(&container, BLOCK_SIZE)).expect("inspect");
        let id = format!("volume-seal:{FIXTURE_VOL_APSB_PADDR}");
        let item = finding(&before, &id);
        assert!(!item.passed());
        assert!(item.repairable);
        apply_volume_repair(&mut container, BLOCK_SIZE, &id).expect("repair");
        let after = inspect_source(&mut SliceBlocks::new(&container, BLOCK_SIZE)).expect("inspect");
        assert_clean_volume_checks(&after, FIXTURE_VOL_APSB_PADDR);
    }
}
