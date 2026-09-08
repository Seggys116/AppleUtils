#[path = "asahi_firmware_verify.rs"]
mod asahi_firmware_verify;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::apfs_image::{
    APFS_INCOMPAT_SEALED_VOLUME, APFS_VOL_ROLE_DATA, APFS_VOL_ROLE_PREBOOT, APFS_VOL_ROLE_SYSTEM,
    NX_MAGIC, fletcher64_seal, fletcher64_valid, parse_gpt,
};
use crate::apfs_verify::{
    self, APFS_MAGIC, BlockSource, OBJ_TYPE_MASK, ROOT_SNAPSHOT_PREFIX, TYPE_BTREE,
    TYPE_BTREE_NODE, TYPE_FS, TYPE_NX_SUPERBLOCK, u16_at, u32_at, u64_at,
};
use crate::asahi_ops::{self, ImageIo};
use crate::repair_volume;

const TYPE_OMAP: u32 = 0x0B;
const TYPE_CHECKPOINT_MAP: u32 = 0x0C;
const J_SNAP_METADATA: u64 = 1;
const J_SNAP_NAME: u64 = 11;
const BTNODE_ROOT: u16 = 0x1;
const BTNODE_LEAF: u16 = 0x2;
const BTREE_INFO_BYTES: usize = 40;
const BTNODE_TOC_BASE: usize = 56;
const APSB_INCOMPAT_OFFSET: usize = 0x38;
const APSB_SNAP_TREE_OFFSET: usize = 0x98;
const APSB_NUM_SNAPSHOTS_OFFSET: usize = 0xD8;
const APSB_UUID_OFFSET: usize = 0xF0;
const APSB_ROLE_OFFSET: usize = 0x3C4;
const APSB_ROOT_TO_XID_OFFSET: usize = 0x3C8;
const APSB_VOLUME_GROUP_OFFSET: usize = 0x3F0;
const APSB_INTEGRITY_META_OFFSET: usize = 0x400;
const MAX_WALK: usize = 4096;
const ZERO_VGID: [u8; 16] = [0u8; 16];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Fail,
    NotApplicable,
}

impl CheckStatus {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::NotApplicable => "N/A",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub id: String,
    pub status: CheckStatus,
    pub summary: String,
    pub detail: String,
    pub repairable: bool,
}

impl Finding {
    pub fn passed(&self) -> bool {
        self.status == CheckStatus::Pass
    }

    pub fn failed(&self) -> bool {
        self.status == CheckStatus::Fail
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairPath {
    pub id: String,
    pub label: String,
    pub detail: String,
}

#[derive(Clone, Debug)]
pub struct SweepReport {
    pub path: String,
    pub backend: String,
    pub container_offset: u64,
    pub block_size: u32,
    pub block_count: u64,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug)]
pub struct ApplyReport {
    pub applied: Vec<String>,
    pub failed: Vec<(String, String)>,
    pub after: SweepReport,
}

struct Opened {
    disc: Box<dyn ImageIo>,
    backend: String,
    container_offset: u64,
    block_size: u32,
    block_count: u64,
}

struct DiscBlocks<'a> {
    disc: &'a mut dyn ImageIo,
    container_offset: u64,
    block_size: u32,
    block_count: u64,
}

impl BlockSource for DiscBlocks<'_> {
    fn read_block(&mut self, index: u64, into: &mut [u8]) -> Result<(), apfs_verify::VerifyError> {
        if index >= self.block_count {
            return Err(apfs_verify::VerifyError::BlockOutOfRange { index });
        }
        read_at(
            self.disc,
            self.container_offset,
            self.block_size,
            index,
            into,
        )
        .map_err(|_| apfs_verify::VerifyError::BlockOutOfRange { index })
    }
}

fn rigorous_volume_seal(opened: &mut Opened, paddr: u64) -> Option<apfs_verify::VolumeSealReport> {
    try_read_seals(opened)?
        .volumes
        .into_iter()
        .find(|volume| volume.paddr == paddr)
}

fn try_read_seals(opened: &mut Opened) -> Option<apfs_verify::ContainerSeals> {
    let mut blocks = DiscBlocks {
        disc: &mut *opened.disc,
        container_offset: opened.container_offset,
        block_size: opened.block_size,
        block_count: opened.block_count,
    };
    apfs_verify::read_container_seals(&mut blocks).ok()
}

fn read_at(
    disc: &mut dyn ImageIo,
    container_offset: u64,
    block_size: u32,
    paddr: u64,
    into: &mut [u8],
) -> Result<(), String> {
    let off = container_offset
        .checked_add(paddr.saturating_mul(u64::from(block_size)))
        .ok_or_else(|| format!("block {paddr} overflows"))?;
    disc.read_at(off, into).map_err(|e| e.to_string())
}

fn write_at(
    disc: &mut dyn ImageIo,
    container_offset: u64,
    block_size: u32,
    paddr: u64,
    data: &[u8],
) -> Result<(), String> {
    let off = container_offset
        .checked_add(paddr.saturating_mul(u64::from(block_size)))
        .ok_or_else(|| format!("block {paddr} overflows"))?;
    disc.write_at(off, data).map_err(|e| e.to_string())
}

// Both detection paths intentionally build an identical `Opened`.
#[allow(clippy::if_same_then_else)]
fn open_repair(path: &Path) -> Result<Opened, String> {
    let mut disc = asahi_ops::open_disc(path).map_err(|e| e.to_string())?;
    let qcow = asahi_ops::qcow2_magic_is_present(path);
    let mut head = vec![0u8; 4096];
    disc.read_at(0, &mut head).map_err(|e| e.to_string())?;

    if u32_at(&head, 0x20) == NX_MAGIC {
        let (block_size, block_count) = geometry_of(&head)?;
        return Ok(Opened {
            disc,
            backend: if qcow { "qcow2".into() } else { "raw".into() },
            container_offset: 0,
            block_size,
            block_count,
        });
    } else if fletcher64_valid(&head)
        && u32_at(&head, 0x18) & OBJ_TYPE_MASK == TYPE_NX_SUPERBLOCK
        && geometry_of(&head).is_ok()
    {
        let (block_size, block_count) = geometry_of(&head)?;
        return Ok(Opened {
            disc,
            backend: if qcow { "qcow2".into() } else { "raw".into() },
            container_offset: 0,
            block_size,
            block_count,
        });
    }

    for gpt_bs in [512u32, 4096] {
        let prefix_len = (2 * gpt_bs as usize) + 128 * 128;
        let mut prefix = vec![0u8; prefix_len];
        if disc.read_at(0, &mut prefix).is_err() {
            continue;
        }
        let Ok(table) = parse_gpt(&prefix, gpt_bs) else {
            continue;
        };
        let mut chosen = None;
        for part in &table.partitions {
            let (start, _) = part.byte_range(gpt_bs);
            let mut probe = vec![0u8; 4096];
            if disc.read_at(start, &mut probe).is_err() {
                continue;
            }
            let nx = u32_at(&probe, 0x20) == NX_MAGIC;
            if part.is_apple_apfs() || nx {
                chosen = Some((start, probe, nx));
                if nx {
                    break;
                }
            }
        }
        let Some((start, probe, nx)) = chosen else {
            continue;
        };
        let (block_size, block_count) = if nx {
            geometry_of(&probe)?
        } else {
            plausible_geometry(&probe)
        };
        return Ok(Opened {
            disc,
            backend: if qcow { "qcow2".into() } else { "gpt".into() },
            container_offset: start,
            block_size,
            block_count,
        });
    }

    Err("no APFS container at byte 0 and no GPT partition probed as NXSB".into())
}

fn geometry_of(block: &[u8]) -> Result<(u32, u64), String> {
    let block_size = u32_at(block, 0x24);
    let block_count = u64_at(block, 0x28);
    if !(512..=65536).contains(&block_size) || !block_size.is_power_of_two() {
        return Err(format!("unsupported APFS block size {block_size}"));
    }
    if block_count == 0 || block_count > (1 << 40) {
        return Err(format!("implausible APFS block count {block_count}"));
    }
    Ok((block_size, block_count))
}

fn plausible_geometry(block: &[u8]) -> (u32, u64) {
    let block_size = u32_at(block, 0x24);
    let block_count = u64_at(block, 0x28);
    if (512..=65536).contains(&block_size) && block_size.is_power_of_two() && block_count > 0 {
        (block_size, block_count)
    } else {
        (4096, 64)
    }
}

fn finding(
    id: impl Into<String>,
    passed: bool,
    summary: impl Into<String>,
    detail: impl Into<String>,
    repairable: bool,
) -> Finding {
    Finding {
        id: id.into(),
        status: if passed {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        summary: summary.into(),
        detail: detail.into(),
        repairable: repairable && !passed,
    }
}

fn skipped(
    id: impl Into<String>,
    summary: impl Into<String>,
    detail: impl Into<String>,
) -> Finding {
    Finding {
        id: id.into(),
        status: CheckStatus::NotApplicable,
        summary: summary.into(),
        detail: detail.into(),
        repairable: false,
    }
}

fn read_block(opened: &mut Opened, paddr: u64) -> Result<Vec<u8>, String> {
    let mut bytes = vec![0u8; opened.block_size as usize];
    read_at(
        &mut *opened.disc,
        opened.container_offset,
        opened.block_size,
        paddr,
        &mut bytes,
    )?;
    Ok(bytes)
}

fn looks_like_object(bytes: &[u8]) -> bool {
    if bytes.len() < 0x20 {
        return false;
    }
    let kind = u32_at(bytes, 0x18) & OBJ_TYPE_MASK;
    matches!(
        kind,
        TYPE_NX_SUPERBLOCK
            | TYPE_BTREE
            | TYPE_BTREE_NODE
            | TYPE_OMAP
            | TYPE_CHECKPOINT_MAP
            | TYPE_FS
    )
}

fn collect_omap_tree(opened: &mut Opened, root: u64) -> Result<Vec<(u64, u64, u64)>, String> {
    let block_size = opened.block_size as usize;
    let block_count = opened.block_count;
    let mut blocks = DiscBlocks {
        disc: opened.disc.as_mut(),
        container_offset: opened.container_offset,
        block_size: opened.block_size,
        block_count,
    };
    let mut verifier = apfs_verify::Verifier {
        source: &mut blocks,
        block_size,
        block_count,
        objects_checked: 0,
        in_use: Vec::new(),
    };
    verifier
        .collect_omap(root, "container object map tree")
        .map(|entries| {
            entries
                .into_iter()
                .map(|entry| (entry.oid, entry.xid, entry.paddr))
                .collect()
        })
        .map_err(|error| error.to_string())
}

type SnapshotMetadata = Vec<(u64, String)>;
type SnapshotNames = Vec<(String, u64)>;

struct SnapState {
    declared: u64,
    tree_paddr: u64,
    metadata: SnapshotMetadata,
    names: SnapshotNames,
    trustworthy: bool,
}

fn parse_snap_tree(bytes: &[u8], block_size: usize) -> Option<(SnapshotMetadata, SnapshotNames)> {
    let flags = u16_at(bytes, 0x20);
    if flags & BTNODE_LEAF == 0 {
        return None;
    }
    let nkeys = u32_at(bytes, 0x24) as usize;
    let toc_off = u16_at(bytes, 0x28) as usize;
    let toc_len = u16_at(bytes, 0x2A) as usize;
    let toc = BTNODE_TOC_BASE + toc_off;
    let key_base = toc + toc_len;
    let value_end = block_size
        - if flags & BTNODE_ROOT != 0 {
            BTREE_INFO_BYTES
        } else {
            0
        };
    let mut metadata = Vec::new();
    let mut names = Vec::new();
    if key_base > value_end || nkeys > 1024 {
        return None;
    }
    for index in 0..nkeys {
        let at = toc + index * 8;
        if at + 8 > bytes.len() {
            break;
        }
        let key_off = u16_at(bytes, at) as usize;
        let key_len = u16_at(bytes, at + 2) as usize;
        let value_off = u16_at(bytes, at + 4) as usize;
        let value_len = u16_at(bytes, at + 6) as usize;
        let key_at = key_base + key_off;
        if key_len < 8 || key_at + key_len > bytes.len() {
            continue;
        }
        let val_at = value_end.saturating_sub(value_off);
        if val_at >= bytes.len() {
            continue;
        }
        let header = u64_at(&bytes[key_at..], 0);
        let kind = header >> 60;
        let obj_id = header & 0x0FFF_FFFF_FFFF_FFFF;
        match kind {
            J_SNAP_METADATA => {
                if value_len < 0x32 || val_at + value_len > bytes.len() {
                    continue;
                }
                let name_len = u16_at(&bytes[val_at..], 0x30) as usize;
                if name_len == 0 || 0x32 + name_len > value_len {
                    continue;
                }
                let raw = &bytes[val_at + 0x32..val_at + 0x32 + name_len - 1];
                metadata.push((obj_id, String::from_utf8_lossy(raw).into_owned()));
            }
            J_SNAP_NAME => {
                if key_len < 10 || value_len < 8 || val_at + 8 > bytes.len() {
                    continue;
                }
                let name_len = u16_at(&bytes[key_at..], 8) as usize;
                if name_len == 0 || 10 + name_len > key_len {
                    continue;
                }
                let raw = &bytes[key_at + 10..key_at + 10 + name_len - 1];
                names.push((
                    String::from_utf8_lossy(raw).into_owned(),
                    u64_at(&bytes[val_at..], 0),
                ));
            }
            _ => {}
        }
    }
    Some((metadata, names))
}

fn volume_snap_state(opened: &mut Opened, apsb: &[u8]) -> SnapState {
    let declared = if apsb.len() >= APSB_NUM_SNAPSHOTS_OFFSET + 8 {
        u64_at(apsb, APSB_NUM_SNAPSHOTS_OFFSET)
    } else {
        0
    };
    let tree_paddr = if apsb.len() >= APSB_SNAP_TREE_OFFSET + 8 {
        u64_at(apsb, APSB_SNAP_TREE_OFFSET)
    } else {
        0
    };
    let mut metadata = Vec::new();
    let mut names = Vec::new();
    let mut trustworthy = true;
    if tree_paddr != 0 && tree_paddr < opened.block_count {
        match read_block(opened, tree_paddr) {
            Ok(tree) => match parse_snap_tree(&tree, opened.block_size as usize) {
                Some((m, n)) => {
                    metadata = m;
                    names = n;
                }
                None => trustworthy = false,
            },
            Err(_) => trustworthy = false,
        }
    }
    SnapState {
        declared,
        tree_paddr,
        metadata,
        names,
        trustworthy,
    }
}

fn volume_role(apsb: &[u8]) -> u16 {
    if apsb.len() >= APSB_ROLE_OFFSET + 2 {
        u16_at(apsb, APSB_ROLE_OFFSET)
    } else {
        0
    }
}

fn volume_uuid(apsb: &[u8]) -> [u8; 16] {
    let mut uuid = [0u8; 16];
    if apsb.len() >= APSB_UUID_OFFSET + 16 {
        uuid.copy_from_slice(&apsb[APSB_UUID_OFFSET..APSB_UUID_OFFSET + 16]);
    }
    uuid
}

fn volume_group_id(apsb: &[u8]) -> [u8; 16] {
    let mut vgid = [0u8; 16];
    if apsb.len() >= APSB_VOLUME_GROUP_OFFSET + 16 {
        vgid.copy_from_slice(&apsb[APSB_VOLUME_GROUP_OFFSET..APSB_VOLUME_GROUP_OFFSET + 16]);
    }
    vgid
}

fn volume_root_to_xid(apsb: &[u8]) -> u64 {
    if apsb.len() >= APSB_ROOT_TO_XID_OFFSET + 8 {
        u64_at(apsb, APSB_ROOT_TO_XID_OFFSET)
    } else {
        0
    }
}

fn expects_system_protection(role: u16) -> bool {
    role == APFS_VOL_ROLE_SYSTEM
}

fn hex16(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct VolIdentity {
    paddr: u64,
    role: u16,
    uuid: [u8; 16],
    vgid: [u8; 16],
}

fn identity_of(paddr: u64, apsb: &[u8]) -> VolIdentity {
    VolIdentity {
        paddr,
        role: volume_role(apsb),
        uuid: volume_uuid(apsb),
        vgid: volume_group_id(apsb),
    }
}

fn volume_group_finding(volumes: &[VolIdentity]) -> Finding {
    let system = volumes
        .iter()
        .find(|volume| volume.role == APFS_VOL_ROLE_SYSTEM);
    let data = volumes
        .iter()
        .find(|volume| volume.role == APFS_VOL_ROLE_DATA);
    match (system, data) {
        (None, _) => skipped(
            "volume-group",
            "no system volume to pair",
            format!("volumes={}", volumes.len()),
        ),
        (Some(system), None) => finding(
            "volume-group",
            false,
            "system volume has no data-role volume to pair with",
            format!(
                "SYSTEM paddr={} uuid={} is present, APFS_VOL_ROLE_DATA is absent",
                system.paddr,
                hex16(&system.uuid)
            ),
            false,
        ),
        (Some(system), Some(data)) => {
            let ok = system.vgid != ZERO_VGID && system.vgid == data.vgid;
            finding(
                "volume-group",
                ok,
                if ok {
                    "system and data volumes share a volume group id"
                } else if system.vgid == ZERO_VGID {
                    "system volume carries no apfs_volume_group_id"
                } else if data.vgid == ZERO_VGID {
                    "data volume carries no apfs_volume_group_id"
                } else {
                    "system and data volume group ids disagree"
                },
                format!(
                    "system_paddr={} system_uuid={} system={} data_paddr={} data_uuid={} data={}",
                    system.paddr,
                    hex16(&system.uuid),
                    hex16(&system.vgid),
                    data.paddr,
                    hex16(&data.uuid),
                    hex16(&data.vgid)
                ),
                true,
            )
        }
    }
}

fn preboot_finding(volumes: &[VolIdentity]) -> Finding {
    let has_system = volumes
        .iter()
        .any(|volume| volume.role == APFS_VOL_ROLE_SYSTEM);
    let has_preboot = volumes
        .iter()
        .any(|volume| volume.role == APFS_VOL_ROLE_PREBOOT);
    if !has_system {
        skipped(
            "preboot",
            "no system volume to require a preboot volume",
            format!("volumes={}", volumes.len()),
        )
    } else if has_preboot {
        finding(
            "preboot",
            true,
            "preboot-role volume is present",
            "role=Preboot",
            false,
        )
    } else {
        finding(
            "preboot",
            false,
            "container has no preboot-role volume",
            "SYSTEM volume is present, APFS_VOL_ROLE_PREBOOT is absent",
            false,
        )
    }
}

fn named_root_snapshot_xid(snap: &SnapState) -> Option<u64> {
    snap.names
        .iter()
        .filter(|(name, _)| name.starts_with(ROOT_SNAPSHOT_PREFIX))
        .filter(|(name, xid)| snap.metadata.iter().any(|(mx, mn)| mn == name && mx == xid))
        .max_by_key(|(_, xid)| *xid)
        .map(|(_, xid)| *xid)
}

fn unverifiable(id: impl Into<String>, snap: &SnapState, what: &str) -> Finding {
    Finding {
        id: id.into(),
        status: CheckStatus::Fail,
        summary: format!("{what} cannot be verified: snapshot metadata tree is not a single leaf"),
        detail: format!(
            "snapshot metadata tree at paddr={} is not a single b-tree leaf node; this \
             field-level repair check does not walk multi-node trees and refuses to guess {what}",
            snap.tree_paddr
        ),
        repairable: false,
    }
}

fn root_to_xid_finding(paddr: u64, role: u16, root_to_xid: u64, snap: &SnapState) -> Finding {
    if !expects_system_protection(role) {
        return skipped(
            format!("root-to-xid:{paddr}"),
            "volume is not a system volume",
            format!("root_to_xid={root_to_xid}"),
        );
    }
    if !snap.trustworthy {
        return unverifiable(format!("root-to-xid:{paddr}"), snap, "apfs_root_to_xid");
    }
    match named_root_snapshot_xid(snap) {
        None => skipped(
            format!("root-to-xid:{paddr}"),
            "no named root snapshot to root the live volume at",
            format!("root_to_xid={root_to_xid}"),
        ),
        Some(xid) if root_to_xid == xid => finding(
            format!("root-to-xid:{paddr}"),
            true,
            format!("live volume is rooted at snapshot xid {xid}"),
            format!("root_to_xid={root_to_xid}"),
            false,
        ),
        Some(xid) => finding(
            format!("root-to-xid:{paddr}"),
            false,
            if root_to_xid == 0 {
                format!("live volume apfs_root_to_xid is 0 rather than snapshot xid {xid}")
            } else {
                format!(
                    "live volume apfs_root_to_xid is {root_to_xid} rather than snapshot xid {xid}"
                )
            },
            format!("root_to_xid={root_to_xid} snapshot_xid={xid}"),
            true,
        ),
    }
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

fn volume_findings(paddr: u64, apsb: &[u8], snap: &SnapState) -> Vec<Finding> {
    let mut out = Vec::new();
    let role = volume_role(apsb);
    let system = expects_system_protection(role);
    let magic_ok = apsb.len() >= 0x24 && u32_at(apsb, 0x20) == APFS_MAGIC;
    out.push(finding(
        format!("volume-magic:{paddr}"),
        magic_ok,
        if magic_ok {
            "APFS volume superblock magic"
        } else {
            "volume superblock magic missing"
        },
        format!("block {paddr}"),
        true,
    ));

    if !snap.trustworthy {
        out.push(unverifiable(
            format!("snapshot-count:{paddr}"),
            snap,
            "apfs_num_snapshots",
        ));
    } else {
        volume_snapshot_count_finding(&mut out, paddr, system, snap);
    }

    if !snap.trustworthy {
        out.push(unverifiable(
            format!("snapshot-names:{paddr}"),
            snap,
            "the snapshot name index",
        ));
    } else {
        volume_snapshot_names_finding(&mut out, paddr, system, snap);
    }

    volume_seal_and_blessing_findings(&mut out, paddr, apsb, system, snap);

    out.push(root_to_xid_finding(
        paddr,
        role,
        volume_root_to_xid(apsb),
        snap,
    ));
    out
}

fn volume_snapshot_count_finding(
    out: &mut Vec<Finding>,
    paddr: u64,
    system: bool,
    snap: &SnapState,
) {
    let count_ok = snap.declared == snap.metadata.len() as u64;
    if count_ok && snap.declared == 0 && snap.metadata.is_empty() {
        if system {
            out.push(finding(
                format!("snapshot-count:{paddr}"),
                false,
                "system volume has no snapshots",
                format!("declared=0 tree=0 paddr={}", snap.tree_paddr),
                false,
            ));
        } else {
            out.push(skipped(
                format!("snapshot-count:{paddr}"),
                "volume has no snapshots",
                format!("declared=0 tree=0 paddr={}", snap.tree_paddr),
            ));
        }
    } else {
        out.push(finding(
            format!("snapshot-count:{paddr}"),
            count_ok,
            if count_ok {
                format!("snapshot count matches {} records", snap.declared)
            } else {
                format!(
                    "volume records {} snapshots, tree has {}",
                    snap.declared,
                    snap.metadata.len()
                )
            },
            format!(
                "declared={} tree={} paddr={}",
                snap.declared,
                snap.metadata.len(),
                snap.tree_paddr
            ),
            true,
        ));
    }
}

fn volume_snapshot_names_finding(
    out: &mut Vec<Finding>,
    paddr: u64,
    system: bool,
    snap: &SnapState,
) {
    let mut names_ok = true;
    for (xid, name) in &snap.metadata {
        if !snap.names.iter().any(|(n, x)| n == name && x == xid) {
            names_ok = false;
            break;
        }
    }
    for (name, xid) in &snap.names {
        if !snap.metadata.iter().any(|(x, n)| n == name && x == xid) {
            names_ok = false;
            break;
        }
    }
    if snap.metadata.is_empty() && snap.names.is_empty() {
        if system {
            out.push(finding(
                format!("snapshot-names:{paddr}"),
                false,
                "system volume has no snapshot name index",
                "metadata=0 names=0".to_string(),
                false,
            ));
        } else {
            out.push(skipped(
                format!("snapshot-names:{paddr}"),
                "no snapshot records to index",
                "metadata=0 names=0".to_string(),
            ));
        }
    } else {
        out.push(finding(
            format!("snapshot-names:{paddr}"),
            names_ok,
            if names_ok {
                "snapshot metadata and name index agree"
            } else {
                "snapshot metadata and name index disagree"
            },
            format!(
                "metadata={} names={}",
                snap.metadata.len(),
                snap.names.len()
            ),
            false,
        ));
    }
}

fn volume_seal_and_blessing_findings(
    out: &mut Vec<Finding>,
    paddr: u64,
    apsb: &[u8],
    system: bool,
    snap: &SnapState,
) {
    let incompat = if apsb.len() >= APSB_INCOMPAT_OFFSET + 8 {
        u64_at(apsb, APSB_INCOMPAT_OFFSET)
    } else {
        0
    };
    let sealed_flag = incompat & APFS_INCOMPAT_SEALED_VOLUME != 0;
    let integrity_oid = if apsb.len() >= APSB_INTEGRITY_META_OFFSET + 8 {
        u64_at(apsb, APSB_INTEGRITY_META_OFFSET)
    } else {
        0
    };
    let seal_ok = sealed_flag == (integrity_oid != 0);
    if seal_ok && !sealed_flag {
        if system {
            out.push(finding(
                format!("volume-seal:{paddr}"),
                false,
                "system volume is not sealed",
                format!("flag={sealed_flag} integrity_meta_oid={integrity_oid}"),
                false,
            ));
        } else {
            out.push(skipped(
                format!("volume-seal:{paddr}"),
                "volume is not sealed",
                format!("flag={sealed_flag} integrity_meta_oid={integrity_oid}"),
            ));
        }
    } else {
        out.push(finding(
            format!("volume-seal:{paddr}"),
            seal_ok,
            if seal_ok {
                "sealed flag and integrity metadata agree"
            } else if sealed_flag {
                "sealed flag is set without integrity metadata"
            } else {
                "integrity metadata present without sealed flag"
            },
            format!("flag={sealed_flag} integrity_meta_oid={integrity_oid}"),
            true,
        ));
    }

    if !snap.trustworthy {
        out.push(unverifiable(
            format!("blessing:{paddr}"),
            snap,
            "the blessed root snapshot",
        ));
        return;
    }

    let root_names: Vec<&str> = snap
        .names
        .iter()
        .filter(|(name, _)| name.starts_with(ROOT_SNAPSHOT_PREFIX))
        .map(|(name, _)| name.as_str())
        .collect();
    let blessing_ok = if !sealed_flag && root_names.is_empty() {
        true
    } else if sealed_flag && integrity_oid != 0 {
        !root_names.is_empty()
            && root_names.iter().all(|name| {
                snap.names
                    .iter()
                    .any(|(n, xid)| n == name && snap.metadata.iter().any(|(x, _)| x == xid))
            })
    } else {
        root_names.iter().all(|name| {
            snap.names
                .iter()
                .find(|(n, _)| n == name)
                .is_some_and(|(_, xid)| snap.metadata.iter().any(|(x, n)| n == *name && x == xid))
        })
    };
    if !sealed_flag && root_names.is_empty() {
        if system {
            out.push(finding(
                format!("blessing:{paddr}"),
                false,
                "system volume has no blessed root snapshot",
                "root_snapshots=0".to_string(),
                false,
            ));
        } else {
            out.push(skipped(
                format!("blessing:{paddr}"),
                "no sealed root snapshot to bless",
                "root_snapshots=0".to_string(),
            ));
        }
    } else {
        out.push(finding(
            format!("blessing:{paddr}"),
            blessing_ok,
            if blessing_ok {
                "boot snapshot blessing is consistent"
            } else {
                "blessed root snapshot is missing or inconsistent"
            },
            format!("root_snapshots={}", root_names.len()),
            false,
        ));
    }
}

fn custom_boot_pair(plist_bytes: &[u8], system_boot: &[u8], preboot_boot: &[u8]) -> bool {
    let Ok(plist::Value::Dictionary(info)) =
        plist::Value::from_reader(std::io::Cursor::new(plist_bytes))
    else {
        return false;
    };
    ["ProductName"].iter().all(|key| {
        info.get(key)
            .and_then(plist::Value::as_string)
            .is_some_and(|value| !value.is_empty())
    }) && !system_boot.is_empty()
        && system_boot == preboot_boot
}

fn custom_boot_groups(opened: &mut Opened) -> BTreeSet<[u8; 16]> {
    use crate::apfs_read::{ApfsContainer, MountedVolume, VolumeChoice};
    fn read(
        mounted: &mut ApfsContainer<'_>,
        volume: &MountedVolume,
        path: &str,
    ) -> Option<Vec<u8>> {
        let facts = mounted.stat(volume, path).ok()?;
        if !facts.is_regular_file() {
            return None;
        }
        let mut bytes = Vec::new();
        mounted
            .extract(volume, path, 0, Some(16 * 1024 * 1024 + 1), &mut bytes)
            .ok()?;
        (bytes.len() <= 16 * 1024 * 1024).then_some(bytes)
    }
    let mut groups = BTreeSet::new();
    let block_size = opened.block_size;
    let block_count = opened.block_count;
    let mut blocks = DiscBlocks {
        disc: opened.disc.as_mut(),
        container_offset: opened.container_offset,
        block_size,
        block_count,
    };
    let Ok(mut mounted) = ApfsContainer::mount(&mut blocks, block_size, block_count) else {
        return groups;
    };
    let Ok(volumes) = mounted.volumes() else {
        return groups;
    };
    let Ok(preboot) = mounted.open_volume_chosen(&VolumeChoice::Role(APFS_VOL_ROLE_PREBOOT)) else {
        return groups;
    };
    let Ok(preboot_entries) = mounted.list_directory(&preboot, "/") else {
        return groups;
    };
    for summary in volumes
        .iter()
        .filter(|volume| volume.role == APFS_VOL_ROLE_SYSTEM && !volume.sealed)
    {
        let group = summary.volume_group_id;
        if group == [0; 16] {
            continue;
        }
        let Ok(system) = mounted.open_volume_chosen(&VolumeChoice::Index(summary.index)) else {
            continue;
        };
        let hex: String = group.iter().map(|byte| format!("{byte:02X}")).collect();
        let id = format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        );
        let candidates: Vec<_> = preboot_entries
            .iter()
            .filter(|entry| entry.name.eq_ignore_ascii_case(&id))
            .collect();
        let [entry] = candidates.as_slice() else {
            continue;
        };
        let id = &entry.name;
        let Some(info) = read(
            &mut mounted,
            &system,
            "/System/Library/CoreServices/SystemVersion.plist",
        ) else {
            continue;
        };
        let Some(boot) = read(
            &mut mounted,
            &system,
            "/Finish Installation.app/Contents/Resources/boot.bin",
        ) else {
            continue;
        };
        let Some(copy) = read(&mut mounted, &preboot, &format!("/{id}/boot.bin")) else {
            continue;
        };
        if custom_boot_pair(&info, &boot, &copy) {
            groups.insert(group);
        }
    }
    groups
}

pub fn sweep(path: &Path) -> Result<SweepReport, String> {
    let mut opened = open_repair(path)?;
    let zero = read_block(&mut opened, 0)?;

    let mut findings = Vec::new();
    if let Some(finding) = asahi_firmware_verify::inspect(path) { findings.push(finding); }
    let structural = apfs_verify::verify_container(&mut DiscBlocks {
        disc: opened.disc.as_mut(),
        container_offset: opened.container_offset,
        block_size: opened.block_size,
        block_count: opened.block_count,
    });
    findings.push(finding(
        "container-structure",
        structural.is_ok(),
        if structural.is_ok() {
            "APFS container structures verified"
        } else {
            "APFS container structural verification failed"
        },
        match structural {
            Ok(container) => format!(
                "checkpoint xid={} at block {}; {} objects checked",
                container.xid, container.superblock_paddr, container.objects_checked
            ),
            Err(error) => error.to_string(),
        },
        false,
    ));
    let magic_ok = u32_at(&zero, 0x20) == NX_MAGIC;
    findings.push(finding(
        "container-magic",
        magic_ok,
        if magic_ok {
            "NXSB magic at container block 0"
        } else {
            "container superblock magic missing"
        },
        format!("observed={:#010x}", u32_at(&zero, 0x20)),
        true,
    ));
    let sum0 = fletcher64_valid(&zero);
    findings.push(finding(
        "checksum:0",
        sum0,
        if sum0 {
            "Fletcher-64 of container superblock 0"
        } else {
            "block 0 fails its Fletcher-64 check"
        },
        "container superblock copy",
        true,
    ));
    let geo_ok = geometry_of(&zero).is_ok();
    findings.push(finding(
        "container-geometry",
        geo_ok,
        if geo_ok {
            format!(
                "block size {} count {}",
                opened.block_size, opened.block_count
            )
        } else {
            "container geometry is unusable".into()
        },
        format!(
            "block_size={} block_count={}",
            u32_at(&zero, 0x24),
            u64_at(&zero, 0x28)
        ),
        false,
    ));

    let mut seen_checksum = BTreeSet::from([0u64]);
    let mut objects: BTreeSet<u64> = BTreeSet::from([0u64]);

    let descriptor_base = u64_at(&zero, 0x70);
    let descriptor_blocks = u32_at(&zero, 0x68) as u64;
    let mut checkpoint_ok = false;
    let mut best_xid = 0u64;
    let mut mounted = zero.clone();
    if descriptor_blocks > 0 && descriptor_blocks < 4096 {
        for slot in 0..descriptor_blocks {
            let paddr = descriptor_base + slot;
            if paddr >= opened.block_count {
                continue;
            }
            objects.insert(paddr);
            let Ok(bytes) = read_block(&mut opened, paddr) else {
                continue;
            };
            if looks_like_object(&bytes) && paddr != 0 {
                seen_checksum.insert(paddr);
                let ok = fletcher64_valid(&bytes);
                if !ok {
                    findings.push(finding(
                        format!("checksum:{paddr}"),
                        false,
                        format!("block {paddr} fails its Fletcher-64 check"),
                        "checkpoint descriptor object",
                        true,
                    ));
                }
            }
            if fletcher64_valid(&bytes)
                && u32_at(&bytes, 0x18) & OBJ_TYPE_MASK == TYPE_NX_SUPERBLOCK
                && u32_at(&bytes, 0x20) == NX_MAGIC
            {
                checkpoint_ok = true;
                let xid = u64_at(&bytes, 0x10);
                if xid >= best_xid {
                    best_xid = xid;
                    mounted = bytes;
                }
            }
        }
    }
    findings.push(finding(
        "checkpoint",
        checkpoint_ok,
        if checkpoint_ok {
            "checkpoint superblock present"
        } else {
            "no container superblock in the descriptor area"
        },
        format!("descriptor_base={descriptor_base} blocks={descriptor_blocks}"),
        false,
    ));

    let omap_paddr = u64_at(&mounted, 0xA0);
    let mut omap_ok = false;
    let mut omap_entries = Vec::new();
    if omap_paddr != 0 && omap_paddr < opened.block_count {
        objects.insert(omap_paddr);
        if let Ok(omap) = read_block(&mut opened, omap_paddr) {
            omap_ok = u32_at(&omap, 0x18) & OBJ_TYPE_MASK == TYPE_OMAP;
            if looks_like_object(&omap) {
                seen_checksum.insert(omap_paddr);
                if !fletcher64_valid(&omap) {
                    findings.push(finding(
                        format!("checksum:{omap_paddr}"),
                        false,
                        format!("block {omap_paddr} fails its Fletcher-64 check"),
                        "container object map",
                        true,
                    ));
                }
            }
            let tree = u64_at(&omap, 0x30);
            if tree != 0 && tree < opened.block_count {
                objects.insert(tree);
                if let Ok(node) = read_block(&mut opened, tree) {
                    if looks_like_object(&node) {
                        seen_checksum.insert(tree);
                        if !fletcher64_valid(&node) {
                            findings.push(finding(
                                format!("checksum:{tree}"),
                                false,
                                format!("block {tree} fails its Fletcher-64 check"),
                                "container object map tree",
                                true,
                            ));
                        }
                    }
                    omap_entries = collect_omap_tree(&mut opened, tree).unwrap_or_default();
                    for (_, _, paddr) in &omap_entries {
                        if *paddr != 0 && *paddr < opened.block_count {
                            objects.insert(*paddr);
                        }
                    }
                }
            }
        }
    }
    findings.push(finding(
        "object-map",
        omap_ok,
        if omap_ok {
            "container object map present"
        } else {
            "container object map missing"
        },
        format!("paddr={omap_paddr}"),
        false,
    ));

    let max_fs = u32_at(&mounted, 0xB4) as usize;
    let mut volumes = Vec::new();
    let xid = if best_xid == 0 {
        u64_at(&zero, 0x10)
    } else {
        best_xid
    };
    for index in 0..max_fs.min(100) {
        let oid = u64_at(&mounted, 0xB8 + index * 8);
        if oid == 0 {
            continue;
        }
        let paddr = omap_entries
            .iter()
            .filter(|(mapped, mapped_xid, _)| *mapped == oid && *mapped_xid <= xid)
            .max_by_key(|(_, mapped_xid, _)| *mapped_xid)
            .map(|(_, _, paddr)| *paddr);
        let Some(paddr) = paddr else {
            continue;
        };
        if paddr >= opened.block_count {
            continue;
        }
        objects.insert(paddr);
        let Ok(apsb) = read_block(&mut opened, paddr) else {
            continue;
        };
        if looks_like_object(&apsb) {
            seen_checksum.insert(paddr);
            if !fletcher64_valid(&apsb) {
                findings.push(finding(
                    format!("checksum:{paddr}"),
                    false,
                    format!("block {paddr} fails its Fletcher-64 check"),
                    "volume superblock",
                    true,
                ));
            }
        }
        volumes.push((paddr, apsb));
    }

    let custom_groups = custom_boot_groups(&mut opened);
    let mut volume_root_ok = false;
    let mut custom_boot_exempt: BTreeSet<u64> = BTreeSet::new();
    for (paddr, apsb) in &volumes {
        let snap = volume_snap_state(&mut opened, apsb);
        let mut checks = volume_findings(*paddr, apsb, &snap);
        if volume_role(apsb) == APFS_VOL_ROLE_SYSTEM
            && custom_groups.contains(&volume_group_id(apsb))
            && u64_at(apsb, APSB_INTEGRITY_META_OFFSET) == 0
        {
            custom_boot_exempt.insert(*paddr);
            for check in &mut checks {
                if check.id == format!("volume-seal:{paddr}") {
                    *check = skipped(
                        check.id.clone(),
                        "custom boot system does not require a macOS seal",
                        "System and Preboot carry matching custom boot objects and a valid system version plist",
                    );
                }
                if snap.declared == 0
                    && snap.metadata.is_empty()
                    && snap.names.is_empty()
                    && ["snapshot-count", "snapshot-names", "blessing"]
                        .iter()
                        .any(|kind| check.id == format!("{kind}:{paddr}"))
                {
                    *check = skipped(
                        check.id.clone(),
                        "custom boot system does not require a macOS root snapshot",
                        "Matching System and Preboot custom boot objects are present; no snapshot is declared",
                    );
                }
            }
        }
        findings.extend(checks);
        let fs_oid = if apsb.len() >= 0x90 {
            u64_at(apsb, 0x88)
        } else {
            0
        };
        if fs_oid != 0 {
            volume_root_ok = true;
        }
        if snap.tree_paddr != 0 {
            objects.insert(snap.tree_paddr);
        }
    }

    let identities: Vec<VolIdentity> = volumes
        .iter()
        .map(|(paddr, apsb)| identity_of(*paddr, apsb))
        .collect();
    findings.push(volume_group_finding(&identities));
    findings.push(preboot_finding(&identities));

    findings.push(finding(
        "volume-root",
        volume_root_ok,
        if volume_root_ok {
            "volume filesystem tree is named"
        } else {
            "no volume filesystem tree was found"
        },
        format!("volumes={}", volumes.len()),
        false,
    ));

    if let Some(seals) = try_read_seals(&mut opened) {
        for volume in &seals.volumes {
            if !custom_boot_exempt.contains(&volume.paddr) {
                for rigorous in [
                    repair_volume::check_snapshot_count(volume),
                    repair_volume::check_snapshot_names(volume),
                    repair_volume::check_root_to_xid(volume),
                ] {
                    findings.retain(|item| item.id != rigorous.id);
                    findings.push(Finding {
                        id: rigorous.id,
                        status: rigorous.status,
                        summary: rigorous.summary,
                        detail: rigorous.detail,
                        repairable: rigorous.repairable,
                    });
                }
            }
            if let Some(seal) = &volume.seal {
                if seal.broken {
                    let id = format!("volume-seal:{}", volume.paddr);
                    findings.retain(|item| item.id != id);
                    findings.push(finding(
                        id,
                        false,
                        "volume seal is recorded broken",
                        format!("broken_xid={}", seal.broken_xid),
                        false,
                    ));
                }
                let expected = seal.root_snapshot_name();
                let blessed = volume.snapshots.xid_for_name(&expected).is_some();
                let id = format!("blessing:{}", volume.paddr);
                findings.retain(|item| item.id != id);
                findings.push(finding(
                    id,
                    blessed,
                    if blessed {
                        "boot snapshot blessing matches the seal"
                    } else {
                        "blessed root snapshot does not match the seal"
                    },
                    expected,
                    false,
                ));
            }
        }
    }

    let mut by_id: BTreeMap<String, Finding> = BTreeMap::new();
    for item in findings {
        by_id.insert(item.id.clone(), item);
    }
    let mut findings: Vec<Finding> = by_id.into_values().collect();
    findings.sort_by(|a, b| a.id.cmp(&b.id));

    let _ = objects.len().min(MAX_WALK);
    let _ = seen_checksum.len();

    Ok(SweepReport {
        path: path.display().to_string(),
        backend: opened.backend,
        container_offset: opened.container_offset,
        block_size: opened.block_size,
        block_count: opened.block_count,
        findings,
    })
}

pub fn repair_paths(report: &SweepReport) -> Vec<RepairPath> {
    let mut paths = Vec::new();
    for finding in &report.findings {
        if !finding.failed() || !finding.repairable {
            continue;
        }
        let (label, detail) = if finding.id.starts_with("checksum:") {
            (
                format!(
                    "reseal Fletcher-64 on block {}",
                    finding.id.trim_start_matches("checksum:")
                ),
                "recompute the object checksum the verifier rejected".to_string(),
            )
        } else if finding.id.starts_with("volume-magic:") {
            (
                format!(
                    "restore APFS magic on volume superblock {}",
                    finding.id.trim_start_matches("volume-magic:")
                ),
                "write APSB magic and reseal the object".to_string(),
            )
        } else if finding.id == "container-magic" {
            (
                "restore NXSB magic on the container superblock".into(),
                "write NXSB magic and reseal".into(),
            )
        } else if finding.id.starts_with("snapshot-count:") {
            (
                format!(
                    "sync snapshot count on volume {}",
                    finding.id.trim_start_matches("snapshot-count:")
                ),
                "write apfs_num_snapshots to the number of SNAP_METADATA records".into(),
            )
        } else if finding.id.starts_with("volume-seal:") {
            (
                format!(
                    "reconcile sealed flag on volume {}",
                    finding.id.trim_start_matches("volume-seal:")
                ),
                "align APFS_INCOMPAT_SEALED_VOLUME with integrity metadata presence".into(),
            )
        } else if finding.id == "volume-group" {
            (
                "write a shared apfs_volume_group_id onto the system and data volumes".into(),
                "set both APSB volume group ids and reseal Fletcher-64".into(),
            )
        } else if finding.id.starts_with("root-to-xid:") {
            (
                format!(
                    "root the live volume at the named snapshot xid on {}",
                    finding.id.trim_start_matches("root-to-xid:")
                ),
                "write apfs_root_to_xid and reseal Fletcher-64".into(),
            )
        } else {
            (finding.summary.clone(), finding.detail.clone())
        };
        paths.push(RepairPath {
            id: finding.id.clone(),
            label,
            detail,
        });
    }
    paths.sort_by(|a, b| a.id.cmp(&b.id));
    paths
}

pub fn format_dump(report: &SweepReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("image={}\n", report.path));
    out.push_str(&format!("backend={}\n", report.backend));
    out.push_str(&format!("container_offset={}\n", report.container_offset));
    out.push_str(&format!("block_size={}\n", report.block_size));
    out.push_str(&format!("block_count={}\n", report.block_count));
    out.push_str("findings:\n");
    let mut findings = report.findings.clone();
    findings.sort_by(|a, b| a.id.cmp(&b.id));
    for item in &findings {
        out.push_str(&format!(
            "{:<4}  {}  {}\n",
            item.status.tag(),
            item.id,
            item.summary
        ));
        if item.failed() && !item.detail.is_empty() {
            out.push_str(&format!("      {}\n", item.detail));
        }
    }
    out.push_str("repairs:\n");
    for path in repair_paths(report) {
        out.push_str(&format!("{}  {}\n", path.id, path.label));
    }
    out
}

pub fn apply(path: &Path, ids: &[String]) -> Result<ApplyReport, String> {
    apply_with_progress(path, ids, |_, _| {})
}

pub fn apply_with_progress(
    path: &Path,
    ids: &[String],
    mut progress: impl FnMut(&str, f64),
) -> Result<ApplyReport, String> {
    progress("reading image", 0.05);
    let before = sweep(path)?;
    let targets: Vec<String> = if ids.iter().any(|id| id == "all") {
        repair_paths(&before).into_iter().map(|p| p.id).collect()
    } else {
        ids.to_vec()
    };
    let total = targets.len().max(1) as f64;
    progress("applying repairs", 0.12);
    let mut opened = open_repair(path)?;
    let mut applied = Vec::new();
    let mut failed = Vec::new();
    for (index, id) in targets.into_iter().enumerate() {
        let label = format!("applying {id}");
        progress(&label, 0.12 + 0.70 * (index as f64 / total));
        match apply_one(&mut opened, &id) {
            Ok(()) => applied.push(id),
            Err(err) => failed.push((id, err)),
        }
        progress("writing", 0.12 + 0.70 * ((index + 1) as f64 / total));
    }
    drop(opened);
    progress("verifying", 0.90);
    let after = sweep(path)?;
    progress("done", 1.0);
    Ok(ApplyReport {
        applied,
        failed,
        after,
    })
}

fn apply_one(opened: &mut Opened, id: &str) -> Result<(), String> {
    if let Some(paddr) = id.strip_prefix("checksum:") {
        let paddr: u64 = paddr.parse().map_err(|_| format!("bad repair id {id}"))?;
        let mut block = read_block(opened, paddr)?;
        fletcher64_seal(&mut block);
        write_at(
            &mut *opened.disc,
            opened.container_offset,
            opened.block_size,
            paddr,
            &block,
        )?;
        return Ok(());
    }
    if let Some(paddr) = id.strip_prefix("volume-magic:") {
        let paddr: u64 = paddr.parse().map_err(|_| format!("bad repair id {id}"))?;
        let mut block = read_block(opened, paddr)?;
        if block.len() >= 0x24 {
            block[0x20..0x24].copy_from_slice(&APFS_MAGIC.to_le_bytes());
        }
        fletcher64_seal(&mut block);
        write_at(
            &mut *opened.disc,
            opened.container_offset,
            opened.block_size,
            paddr,
            &block,
        )?;
        return Ok(());
    }
    if id == "container-magic" {
        let mut block = read_block(opened, 0)?;
        if block.len() >= 0x24 {
            block[0x20..0x24].copy_from_slice(&NX_MAGIC.to_le_bytes());
        }
        fletcher64_seal(&mut block);
        write_at(
            &mut *opened.disc,
            opened.container_offset,
            opened.block_size,
            0,
            &block,
        )?;
        return Ok(());
    }
    if let Some(paddr) = id.strip_prefix("snapshot-count:") {
        let paddr: u64 = paddr.parse().map_err(|_| format!("bad repair id {id}"))?;
        let mut block = read_block(opened, paddr)?;
        let count = if let Some(volume) = rigorous_volume_seal(opened, paddr) {
            volume.snapshots.snapshots.len() as u64
        } else {
            let snap = volume_snap_state(opened, &block);
            if !snap.trustworthy {
                return Err(format!(
                    "snapshot-count:{paddr} cannot be repaired: the snapshot metadata tree is \
                     not a single b-tree leaf, and the rigorous container walk could not read it"
                ));
            }
            snap.metadata.len() as u64
        };
        if block.len() >= APSB_NUM_SNAPSHOTS_OFFSET + 8 {
            block[APSB_NUM_SNAPSHOTS_OFFSET..APSB_NUM_SNAPSHOTS_OFFSET + 8]
                .copy_from_slice(&count.to_le_bytes());
        }
        fletcher64_seal(&mut block);
        write_at(
            &mut *opened.disc,
            opened.container_offset,
            opened.block_size,
            paddr,
            &block,
        )?;
        return Ok(());
    }
    if let Some(paddr) = id.strip_prefix("volume-seal:") {
        let paddr: u64 = paddr.parse().map_err(|_| format!("bad repair id {id}"))?;
        let mut block = read_block(opened, paddr)?;
        let integrity = if block.len() >= APSB_INTEGRITY_META_OFFSET + 8 {
            u64_at(&block, APSB_INTEGRITY_META_OFFSET)
        } else {
            0
        };
        if block.len() >= APSB_INCOMPAT_OFFSET + 8 {
            let mut incompat = u64_at(&block, APSB_INCOMPAT_OFFSET);
            if integrity == 0 {
                incompat &= !APFS_INCOMPAT_SEALED_VOLUME;
            } else {
                incompat |= APFS_INCOMPAT_SEALED_VOLUME;
            }
            block[APSB_INCOMPAT_OFFSET..APSB_INCOMPAT_OFFSET + 8]
                .copy_from_slice(&incompat.to_le_bytes());
        }
        fletcher64_seal(&mut block);
        write_at(
            &mut *opened.disc,
            opened.container_offset,
            opened.block_size,
            paddr,
            &block,
        )?;
        return Ok(());
    }
    if id == "volume-group" {
        return apply_volume_group(opened);
    }
    if let Some(paddr) = id.strip_prefix("root-to-xid:") {
        let paddr: u64 = paddr.parse().map_err(|_| format!("bad repair id {id}"))?;
        let mut block = read_block(opened, paddr)?;
        if volume_role(&block) != APFS_VOL_ROLE_SYSTEM {
            return Err(format!(
                "root-to-xid:{paddr} is only written on a SYSTEM volume"
            ));
        }
        let xid = if let Some(volume) = rigorous_volume_seal(opened, paddr) {
            let Some(xid) = repair_volume::named_root_snapshot_xid(&volume.snapshots) else {
                return Err(format!(
                    "root-to-xid:{paddr} has no named root snapshot to write"
                ));
            };
            xid
        } else {
            let snap = volume_snap_state(opened, &block);
            if !snap.trustworthy {
                return Err(format!(
                    "root-to-xid:{paddr} cannot be repaired: the snapshot metadata tree is not \
                     a single b-tree leaf, and the rigorous container walk could not read it"
                ));
            }
            let Some(xid) = named_root_snapshot_xid(&snap) else {
                return Err(format!(
                    "root-to-xid:{paddr} has no named root snapshot to write"
                ));
            };
            xid
        };
        if block.len() >= APSB_ROOT_TO_XID_OFFSET + 8 {
            block[APSB_ROOT_TO_XID_OFFSET..APSB_ROOT_TO_XID_OFFSET + 8]
                .copy_from_slice(&xid.to_le_bytes());
        }
        fletcher64_seal(&mut block);
        write_at(
            &mut *opened.disc,
            opened.container_offset,
            opened.block_size,
            paddr,
            &block,
        )?;
        return Ok(());
    }
    Err(format!("unknown repair id {id}"))
}

fn apply_volume_group(opened: &mut Opened) -> Result<(), String> {
    let volumes = listed_volumes(opened)?;
    let system = volumes.iter().find_map(|(paddr, apsb)| {
        (volume_role(apsb) == APFS_VOL_ROLE_SYSTEM)
            .then(|| (*paddr, volume_group_id(apsb), volume_uuid(apsb)))
    });
    let data = volumes.iter().find_map(|(paddr, apsb)| {
        (volume_role(apsb) == APFS_VOL_ROLE_DATA)
            .then(|| (*paddr, volume_group_id(apsb), volume_uuid(apsb)))
    });
    let (Some((system_paddr, system_vgid, system_uuid)), Some((data_paddr, data_vgid, data_uuid))) =
        (system, data)
    else {
        return Err("volume-group is not repairable without both SYSTEM and DATA volumes".into());
    };
    let target = pick_group_id(&system_vgid, &data_vgid, &system_uuid, &data_uuid);
    write_volume_group_id(opened, system_paddr, &target)?;
    write_volume_group_id(opened, data_paddr, &target)?;
    Ok(())
}

fn write_volume_group_id(opened: &mut Opened, paddr: u64, group: &[u8; 16]) -> Result<(), String> {
    let mut block = read_block(opened, paddr)?;
    if block.len() < APSB_VOLUME_GROUP_OFFSET + 16 {
        return Err(format!(
            "volume superblock {paddr} is too small for apfs_volume_group_id"
        ));
    }
    block[APSB_VOLUME_GROUP_OFFSET..APSB_VOLUME_GROUP_OFFSET + 16].copy_from_slice(group);
    fletcher64_seal(&mut block);
    write_at(
        &mut *opened.disc,
        opened.container_offset,
        opened.block_size,
        paddr,
        &block,
    )
}

fn listed_volumes(opened: &mut Opened) -> Result<Vec<(u64, Vec<u8>)>, String> {
    let zero = read_block(opened, 0)?;
    let descriptor_base = u64_at(&zero, 0x70);
    let descriptor_blocks = u32_at(&zero, 0x68) as u64;
    let mut best_xid = 0u64;
    let mut mounted = zero.clone();
    if descriptor_blocks > 0 && descriptor_blocks < 4096 {
        for slot in 0..descriptor_blocks {
            let paddr = descriptor_base + slot;
            if paddr >= opened.block_count {
                continue;
            }
            let Ok(bytes) = read_block(opened, paddr) else {
                continue;
            };
            if fletcher64_valid(&bytes)
                && u32_at(&bytes, 0x18) & OBJ_TYPE_MASK == TYPE_NX_SUPERBLOCK
                && u32_at(&bytes, 0x20) == NX_MAGIC
            {
                let xid = u64_at(&bytes, 0x10);
                if xid >= best_xid {
                    best_xid = xid;
                    mounted = bytes;
                }
            }
        }
    }
    let xid = if best_xid == 0 {
        u64_at(&zero, 0x10)
    } else {
        best_xid
    };
    let omap_paddr = u64_at(&mounted, 0xA0);
    let mut omap_entries = Vec::new();
    if omap_paddr != 0
        && omap_paddr < opened.block_count
        && let Ok(omap) = read_block(opened, omap_paddr)
    {
        let tree = u64_at(&omap, 0x30);
        if tree != 0 && tree < opened.block_count {
            omap_entries = collect_omap_tree(opened, tree)?;
        }
    }
    let max_fs = u32_at(&mounted, 0xB4) as usize;
    let mut volumes = Vec::new();
    for index in 0..max_fs.min(100) {
        let oid = u64_at(&mounted, 0xB8 + index * 8);
        if oid == 0 {
            continue;
        }
        let paddr = omap_entries
            .iter()
            .filter(|(mapped, mapped_xid, _)| *mapped == oid && *mapped_xid <= xid)
            .max_by_key(|(_, mapped_xid, _)| *mapped_xid)
            .map(|(_, _, paddr)| *paddr);
        let Some(paddr) = paddr else {
            continue;
        };
        if paddr >= opened.block_count {
            continue;
        }
        let Ok(apsb) = read_block(opened, paddr) else {
            continue;
        };
        volumes.push((paddr, apsb));
    }
    Ok(volumes)
}

pub fn inject_checksum_fault(path: &Path, paddr: u64) -> Result<(), String> {
    let mut opened = open_repair(path)?;
    let mut block = read_block(&mut opened, paddr)?;
    let at = 0x200.min(block.len().saturating_sub(1));
    block[at] ^= 0x01;
    write_at(
        &mut *opened.disc,
        opened.container_offset,
        opened.block_size,
        paddr,
        &block,
    )
}

pub fn inject_volume_magic_fault(path: &Path, paddr: u64) -> Result<(), String> {
    let mut opened = open_repair(path)?;
    let mut block = read_block(&mut opened, paddr)?;
    if block.len() >= 0x24 {
        block[0x20..0x24].copy_from_slice(&0u32.to_le_bytes());
    }
    fletcher64_seal(&mut block);
    write_at(
        &mut *opened.disc,
        opened.container_offset,
        opened.block_size,
        paddr,
        &block,
    )
}

pub fn inject_snapshot_count_fault(path: &Path, paddr: u64) -> Result<(), String> {
    let mut opened = open_repair(path)?;
    let mut block = read_block(&mut opened, paddr)?;
    if block.len() >= APSB_NUM_SNAPSHOTS_OFFSET + 8 {
        let declared = u64_at(&block, APSB_NUM_SNAPSHOTS_OFFSET);
        let next = if declared == 0 {
            7
        } else {
            declared.saturating_add(7)
        };
        block[APSB_NUM_SNAPSHOTS_OFFSET..APSB_NUM_SNAPSHOTS_OFFSET + 8]
            .copy_from_slice(&next.to_le_bytes());
    }
    fletcher64_seal(&mut block);
    write_at(
        &mut *opened.disc,
        opened.container_offset,
        opened.block_size,
        paddr,
        &block,
    )
}

pub fn inject_sealed_flag_fault(path: &Path, paddr: u64) -> Result<(), String> {
    let mut opened = open_repair(path)?;
    let mut block = read_block(&mut opened, paddr)?;
    if block.len() >= APSB_INCOMPAT_OFFSET + 8 {
        let incompat = u64_at(&block, APSB_INCOMPAT_OFFSET) | APFS_INCOMPAT_SEALED_VOLUME;
        block[APSB_INCOMPAT_OFFSET..APSB_INCOMPAT_OFFSET + 8]
            .copy_from_slice(&incompat.to_le_bytes());
    }
    fletcher64_seal(&mut block);
    write_at(
        &mut *opened.disc,
        opened.container_offset,
        opened.block_size,
        paddr,
        &block,
    )
}

pub fn inject_volume_role(path: &Path, paddr: u64, role: u16) -> Result<(), String> {
    let mut opened = open_repair(path)?;
    let mut block = read_block(&mut opened, paddr)?;
    if block.len() >= APSB_ROLE_OFFSET + 2 {
        block[APSB_ROLE_OFFSET..APSB_ROLE_OFFSET + 2].copy_from_slice(&role.to_le_bytes());
    }
    fletcher64_seal(&mut block);
    write_at(
        &mut *opened.disc,
        opened.container_offset,
        opened.block_size,
        paddr,
        &block,
    )
}

pub fn inject_volume_group_id(path: &Path, paddr: u64, vgid: [u8; 16]) -> Result<(), String> {
    let mut opened = open_repair(path)?;
    write_volume_group_id(&mut opened, paddr, &vgid)
}

pub fn inject_root_to_xid(path: &Path, paddr: u64, xid: u64) -> Result<(), String> {
    let mut opened = open_repair(path)?;
    let mut block = read_block(&mut opened, paddr)?;
    if block.len() >= APSB_ROOT_TO_XID_OFFSET + 8 {
        block[APSB_ROOT_TO_XID_OFFSET..APSB_ROOT_TO_XID_OFFSET + 8]
            .copy_from_slice(&xid.to_le_bytes());
    }
    fletcher64_seal(&mut block);
    write_at(
        &mut *opened.disc,
        opened.container_offset,
        opened.block_size,
        paddr,
        &block,
    )
}

#[cfg(test)]
fn dump_fails(dump: &str, id: &str) -> bool {
    dump.lines().any(|line| {
        let toks: Vec<&str> = line.split_whitespace().collect();
        toks.contains(&"FAIL") && toks.contains(&id)
    })
}

#[cfg(test)]
fn dump_passes(dump: &str, id: &str) -> bool {
    dump.lines().any(|line| {
        let toks: Vec<&str> = line.split_whitespace().collect();
        toks.contains(&"PASS") && toks.contains(&id)
    })
}

#[cfg(test)]
fn dump_na(dump: &str, id: &str) -> bool {
    dump.lines().any(|line| {
        let toks: Vec<&str> = line.split_whitespace().collect();
        toks.contains(&"N/A") && toks.contains(&id)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{
        APSB_NUM_SNAPSHOTS_OFFSET, APSB_ROLE_OFFSET, APSB_ROOT_TO_XID_OFFSET,
        APSB_SNAP_TREE_OFFSET, APSB_UUID_OFFSET, APSB_VOLUME_GROUP_OFFSET, BTNODE_LEAF,
        BTNODE_ROOT, BTNODE_TOC_BASE, BTREE_INFO_BYTES, J_SNAP_METADATA, J_SNAP_NAME, TYPE_OMAP,
        VolIdentity, ZERO_VGID, mint_group_id, open_repair, read_block, volume_group_finding,
        volume_group_id, volume_root_to_xid, volume_uuid, write_at,
    };
    use crate::apfs_fixture::{self, FIXTURE_VOL_APSB_PADDR, ImageWrap};
    use crate::apfs_image::{APFS_VOL_ROLE_DATA, APFS_VOL_ROLE_SYSTEM, fletcher64_seal};
    use crate::apfs_verify::{TYPE_BTREE, TYPE_FS};

    fn fail_ids(report: &SweepReport) -> Vec<&str> {
        report
            .findings
            .iter()
            .filter(|f| f.failed())
            .map(|f| f.id.as_str())
            .collect()
    }

    #[test]
    fn incomplete_raw_gpt_fixture_reports_structural_failure_and_dump_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        let report = sweep(&image).expect("sweep");
        assert_eq!(
            fail_ids(&report),
            ["container-structure"],
            "{:#?}",
            report.findings
        );
        assert_eq!(report.backend, "gpt");
        let first = format_dump(&report);
        let second = format_dump(&sweep(&image).unwrap());
        assert_eq!(first, second);
        assert!(first.contains("findings:"));
        assert!(first.contains("PASS"));
        assert!(dump_passes(&first, "container-magic"));
        assert!(dump_passes(&first, "checksum:0"));
        assert!(dump_passes(
            &first,
            &format!("volume-magic:{FIXTURE_VOL_APSB_PADDR}")
        ));
        assert!(
            dump_na(&first, &format!("snapshot-count:{FIXTURE_VOL_APSB_PADDR}")),
            "{first}"
        );
        assert!(
            dump_na(&first, &format!("volume-seal:{FIXTURE_VOL_APSB_PADDR}")),
            "{first}"
        );
        assert!(
            dump_na(&first, &format!("blessing:{FIXTURE_VOL_APSB_PADDR}")),
            "{first}"
        );
        assert!(
            dump_na(&first, &format!("snapshot-names:{FIXTURE_VOL_APSB_PADDR}")),
            "{first}"
        );
        assert!(dump_na(&first, "volume-group"), "{first}");
        assert!(dump_na(&first, "preboot"), "{first}");
        assert!(
            dump_na(&first, &format!("root-to-xid:{FIXTURE_VOL_APSB_PADDR}")),
            "{first}"
        );
    }

    #[test]
    fn custom_boot_seal_exemption_requires_valid_identity_and_matching_payloads() {
        let info = br#"<?xml version="1.0"?><plist version="1.0"><dict><key>ProductName</key><string>Custom OS</string><key>ProductVersion</key><string>1</string></dict></plist>"#;
        assert!(custom_boot_pair(info, b"boot object", b"boot object"));
        assert!(!custom_boot_pair(info, b"boot object", b"different object"));
        assert!(!custom_boot_pair(info, b"", b""));
        assert!(!custom_boot_pair(
            b"not a plist",
            b"boot object",
            b"boot object"
        ));
        assert!(!custom_boot_pair(
            b"<plist><dict/></plist>",
            b"boot object",
            b"boot object"
        ));
    }

    #[test]
    fn volume_checks_follow_newest_checkpoint_when_block_zero_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        let mut opened = open_repair(&image).unwrap();
        let mut zero = read_block(&mut opened, 0).unwrap();
        zero[0xA0..0xA8].fill(0);
        zero[0xB8..0xC0].fill(0);
        fletcher64_seal(&mut zero);
        write_at(
            opened.disc.as_mut(),
            opened.container_offset,
            opened.block_size,
            0,
            &zero,
        )
        .unwrap();
        let volumes = listed_volumes(&mut opened).unwrap();
        assert_eq!(volumes.len(), 1);
        assert_eq!(volumes[0].0, FIXTURE_VOL_APSB_PADDR);
        drop(opened);
        let report = sweep(&image).unwrap();
        assert!(report.findings.iter().any(|item| item.id
            == format!("volume-magic:{FIXTURE_VOL_APSB_PADDR}")
            && item.passed()));
    }

    #[test]
    fn repaired_superblock_type_does_not_hide_invalid_checkpoint_length() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();

        let mut opened = open_repair(&image).unwrap();
        for paddr in [0, 1] {
            let mut block = read_block(&mut opened, paddr).unwrap();
            block[0x18..0x1C].copy_from_slice(&0x4000_0001u32.to_le_bytes());
            fletcher64_seal(&mut block);
            write_at(
                opened.disc.as_mut(),
                opened.container_offset,
                opened.block_size,
                paddr,
                &block,
            )
            .unwrap();
        }
        drop(opened);
        let before = sweep(&image).unwrap();
        let structure = before
            .findings
            .iter()
            .find(|item| item.id == "container-structure")
            .unwrap();
        assert!(structure.failed());
        assert!(!structure.repairable);
        assert!(
            structure
                .detail
                .contains("container superblock object type")
        );

        let mut opened = open_repair(&image).unwrap();
        for paddr in [0, 1] {
            let mut block = read_block(&mut opened, paddr).unwrap();
            block[0x18..0x1C].copy_from_slice(&0x8000_0001u32.to_le_bytes());
            fletcher64_seal(&mut block);
            write_at(
                opened.disc.as_mut(),
                opened.container_offset,
                opened.block_size,
                paddr,
                &block,
            )
            .unwrap();
        }
        drop(opened);
        let after = sweep(&image).unwrap();
        let structure = after
            .findings
            .iter()
            .find(|item| item.id == "container-structure")
            .unwrap();
        assert!(structure.failed());
        assert!(
            structure.detail.contains("checkpoint descriptor")
                && structure.detail.contains("length"),
            "{}",
            structure.detail
        );
        assert!(!structure.repairable);
    }

    #[test]
    fn incomplete_qcow2_fixture_reports_structural_failure() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.qcow2");
        apfs_fixture::write_fixture(&image, ImageWrap::Qcow2).unwrap();
        let report = sweep(&image).expect("sweep qcow2");
        assert_eq!(report.backend, "qcow2");
        assert_eq!(
            fail_ids(&report),
            ["container-structure"],
            "{:#?}",
            report.findings
        );
    }

    #[test]
    fn mutated_raw_reports_injected_faults_and_subset_apply_leaves_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        inject_checksum_fault(&image, 0).unwrap();
        inject_volume_magic_fault(&image, FIXTURE_VOL_APSB_PADDR).unwrap();
        let dumped = format_dump(&sweep(&image).unwrap());
        assert!(dump_fails(&dumped, "checksum:0"), "{dumped}");
        assert!(
            dump_fails(&dumped, &format!("volume-magic:{FIXTURE_VOL_APSB_PADDR}")),
            "{dumped}"
        );

        apply(&image, &["checksum:0".into()]).unwrap();
        let after = format_dump(&sweep(&image).unwrap());
        assert!(!dump_fails(&after, "checksum:0"), "{after}");
        assert!(
            dump_fails(&after, &format!("volume-magic:{FIXTURE_VOL_APSB_PADDR}")),
            "{after}"
        );

        apply(&image, &["all".into()]).unwrap();
        let clean = sweep(&image).unwrap();
        assert_eq!(
            fail_ids(&clean),
            ["container-structure"],
            "{:#?}",
            clean.findings
        );
    }

    #[test]
    fn subset_apply_persists_on_qcow2() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.qcow2");
        apfs_fixture::write_fixture(&image, ImageWrap::Qcow2).unwrap();
        inject_checksum_fault(&image, 0).unwrap();
        inject_volume_magic_fault(&image, FIXTURE_VOL_APSB_PADDR).unwrap();
        apply(&image, &["checksum:0".into()]).unwrap();
        let after = format_dump(&sweep(&image).unwrap());
        assert!(!dump_fails(&after, "checksum:0"), "{after}");
        assert!(
            dump_fails(&after, &format!("volume-magic:{FIXTURE_VOL_APSB_PADDR}")),
            "{after}"
        );
        apply(&image, &["all".into()]).unwrap();
        assert_eq!(fail_ids(&sweep(&image).unwrap()), ["container-structure"]);
    }

    #[test]
    fn snapshot_count_and_sealed_flag_are_repairable() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        inject_snapshot_count_fault(&image, FIXTURE_VOL_APSB_PADDR).unwrap();
        inject_sealed_flag_fault(&image, FIXTURE_VOL_APSB_PADDR).unwrap();
        let dumped = format_dump(&sweep(&image).unwrap());
        let count_id = format!("snapshot-count:{FIXTURE_VOL_APSB_PADDR}");
        let seal_id = format!("volume-seal:{FIXTURE_VOL_APSB_PADDR}");
        assert!(dump_fails(&dumped, &count_id), "{dumped}");
        assert!(dump_fails(&dumped, &seal_id), "{dumped}");

        apply(&image, std::slice::from_ref(&count_id)).unwrap();
        let after_count = format_dump(&sweep(&image).unwrap());
        assert!(!dump_fails(&after_count, &count_id), "{after_count}");
        assert!(dump_fails(&after_count, &seal_id), "{after_count}");

        apply(&image, std::slice::from_ref(&seal_id)).unwrap();
        let after = format_dump(&sweep(&image).unwrap());
        assert!(!dump_fails(&after, &count_id), "{after}");
        assert!(!dump_fails(&after, &seal_id), "{after}");
        assert!(dump_na(&after, &seal_id), "{after}");
        assert!(dump_na(
            &after,
            &format!("blessing:{FIXTURE_VOL_APSB_PADDR}")
        ));
    }

    #[test]
    fn sealed_flag_without_meta_on_system_clears_flag_and_stays_unsealed() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        inject_volume_role(&image, FIXTURE_VOL_APSB_PADDR, APFS_VOL_ROLE_SYSTEM).unwrap();
        inject_sealed_flag_fault(&image, FIXTURE_VOL_APSB_PADDR).unwrap();
        let seal_id = format!("volume-seal:{FIXTURE_VOL_APSB_PADDR}");
        let before = sweep(&image).unwrap();
        let item = finding(&before, &seal_id);
        assert!(item.failed(), "{item:?}");
        assert!(item.repairable);
        apply(&image, std::slice::from_ref(&seal_id)).unwrap();
        let after = sweep(&image).unwrap();
        let item = finding(&after, &seal_id);
        assert!(item.failed(), "SYSTEM stays unsealed: {item:?}");
        assert!(!item.repairable, "must not invent a seal: {item:?}");
        assert!(!repair_paths(&after).iter().any(|path| path.id == seal_id));
    }

    fn finding<'a>(report: &'a SweepReport, id: &str) -> &'a Finding {
        report
            .findings
            .iter()
            .find(|item| item.id == id)
            .unwrap_or_else(|| {
                panic!(
                    "missing {id} in {:?}",
                    report
                        .findings
                        .iter()
                        .map(|item| item.id.as_str())
                        .collect::<Vec<_>>()
                )
            })
    }

    #[test]
    fn system_volume_unsealed_without_snapshots_fails_and_is_not_repairable() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        inject_volume_role(&image, FIXTURE_VOL_APSB_PADDR, APFS_VOL_ROLE_SYSTEM).unwrap();
        let report = sweep(&image).unwrap();
        for id in [
            format!("snapshot-count:{FIXTURE_VOL_APSB_PADDR}"),
            format!("snapshot-names:{FIXTURE_VOL_APSB_PADDR}"),
            format!("volume-seal:{FIXTURE_VOL_APSB_PADDR}"),
            format!("blessing:{FIXTURE_VOL_APSB_PADDR}"),
        ] {
            let item = finding(&report, &id);
            assert!(item.failed(), "{id}: {item:?}");
            assert!(!item.repairable, "{id} must not invent a seal or snapshot");
        }
        let paths = repair_paths(&report);
        assert!(
            !paths.iter().any(|path| path.id.starts_with("volume-seal:")),
            "unsealed SYSTEM without integrity metadata must not queue a seal write: {paths:?}"
        );
        let vg = finding(&report, "volume-group");
        assert!(vg.failed(), "{vg:?}");
        assert!(!vg.repairable);
        assert!(!paths.iter().any(|path| path.id == "volume-group"));
        let preboot = finding(&report, "preboot");
        assert!(preboot.failed(), "{preboot:?}");
        assert!(!preboot.repairable);
        assert_eq!(
            finding(&report, &format!("root-to-xid:{FIXTURE_VOL_APSB_PADDR}")).status,
            CheckStatus::NotApplicable
        );
    }

    #[test]
    fn volume_group_classification_shapes() {
        let none = volume_group_finding(&[VolIdentity {
            paddr: 21,
            role: 0,
            uuid: [1; 16],
            vgid: ZERO_VGID,
        }]);
        assert_eq!(none.status, CheckStatus::NotApplicable);
        assert!(!none.repairable);

        let no_data = volume_group_finding(&[VolIdentity {
            paddr: 21,
            role: APFS_VOL_ROLE_SYSTEM,
            uuid: [1; 16],
            vgid: [0x11; 16],
        }]);
        assert!(no_data.failed());
        assert!(!no_data.repairable);

        let zero = volume_group_finding(&[
            VolIdentity {
                paddr: 21,
                role: APFS_VOL_ROLE_SYSTEM,
                uuid: [1; 16],
                vgid: ZERO_VGID,
            },
            VolIdentity {
                paddr: 26,
                role: APFS_VOL_ROLE_DATA,
                uuid: [2; 16],
                vgid: ZERO_VGID,
            },
        ]);
        assert!(zero.failed());
        assert!(zero.repairable);

        let mismatch = volume_group_finding(&[
            VolIdentity {
                paddr: 21,
                role: APFS_VOL_ROLE_SYSTEM,
                uuid: [1; 16],
                vgid: [0x11; 16],
            },
            VolIdentity {
                paddr: 26,
                role: APFS_VOL_ROLE_DATA,
                uuid: [2; 16],
                vgid: [0x22; 16],
            },
        ]);
        assert!(mismatch.failed());
        assert!(mismatch.repairable);

        let agree = volume_group_finding(&[
            VolIdentity {
                paddr: 21,
                role: APFS_VOL_ROLE_SYSTEM,
                uuid: [1; 16],
                vgid: [0x11; 16],
            },
            VolIdentity {
                paddr: 26,
                role: APFS_VOL_ROLE_DATA,
                uuid: [2; 16],
                vgid: [0x11; 16],
            },
        ]);
        assert!(agree.passed());
        assert!(!agree.repairable);
    }

    #[test]
    fn system_without_data_volume_group_is_not_in_repair_paths() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        inject_volume_role(&image, FIXTURE_VOL_APSB_PADDR, APFS_VOL_ROLE_SYSTEM).unwrap();
        let report = sweep(&image).unwrap();
        let vg = finding(&report, "volume-group");
        assert!(vg.failed());
        assert!(!vg.repairable);
        assert!(
            !repair_paths(&report)
                .iter()
                .any(|path| path.id == "volume-group")
        );
    }

    const DATA_VOL_OID: u64 = 1025;
    const DATA_VOL_PADDR: u64 = 26;
    const OMAP_TREE_C: u64 = 18;
    const OBJ_PHYSICAL: u32 = 0x4000_0000;
    const OBJ_VIRTUAL: u32 = 0x0000_0000;

    fn put_u16(buf: &mut [u8], at: usize, value: u16) {
        buf[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(buf: &mut [u8], at: usize, value: u32) {
        buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(buf: &mut [u8], at: usize, value: u64) {
        buf[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn obj_stamp(block: &mut [u8], oid: u64, xid: u64, o_type: u32, subtype: u32) {
        put_u64(block, 8, oid);
        put_u64(block, 16, xid);
        put_u32(block, 24, o_type);
        put_u32(block, 28, subtype);
        fletcher64_seal(block);
    }

    fn btree_leaf(block_size: usize, records: &[(Vec<u8>, Vec<u8>)], root: bool) -> Vec<u8> {
        let mut block = vec![0u8; block_size];
        let mut flags = BTNODE_LEAF;
        if root {
            flags |= BTNODE_ROOT;
        }
        put_u16(&mut block, 0x20, flags);
        put_u16(&mut block, 0x22, 0);
        put_u32(&mut block, 0x24, records.len() as u32);
        let toc_len = (records.len() * 8) as u16;
        put_u16(&mut block, 0x28, 0);
        put_u16(&mut block, 0x2A, toc_len);
        let toc = BTNODE_TOC_BASE;
        let key_base = toc + toc_len as usize;
        let value_end = block_size - if root { BTREE_INFO_BYTES } else { 0 };
        let mut key_cursor = 0usize;
        let mut value_cursor = 0usize;
        for (index, (key, value)) in records.iter().enumerate() {
            let at = toc + index * 8;
            put_u16(&mut block, at, key_cursor as u16);
            put_u16(&mut block, at + 2, key.len() as u16);
            let value_offset = value_cursor + value.len();
            put_u16(&mut block, at + 4, value_offset as u16);
            put_u16(&mut block, at + 6, value.len() as u16);
            block[key_base + key_cursor..key_base + key_cursor + key.len()].copy_from_slice(key);
            key_cursor += key.len();
            let value_at = value_end - value_offset;
            block[value_at..value_at + value.len()].copy_from_slice(value);
            value_cursor = value_offset;
        }
        if root {
            let info = block_size - BTREE_INFO_BYTES;
            put_u32(&mut block, info + 4, TYPE_BTREE);
            put_u32(&mut block, info + 16, 4096);
        }
        block
    }

    fn omap_record(oid: u64, xid: u64, paddr: u64) -> (Vec<u8>, Vec<u8>) {
        let mut key = Vec::with_capacity(16);
        key.extend_from_slice(&oid.to_le_bytes());
        key.extend_from_slice(&xid.to_le_bytes());
        let mut val = vec![0u8; 16];
        put_u32(&mut val, 4, 4096);
        put_u64(&mut val, 8, paddr);
        (key, val)
    }

    fn install_data_sibling(path: &Path) -> (u64, [u8; 16], [u8; 16]) {
        let mut opened = open_repair(path).expect("open");
        let mut system = read_block(&mut opened, FIXTURE_VOL_APSB_PADDR).expect("system apsb");
        let system_uuid = volume_uuid(&system);
        system[APSB_ROLE_OFFSET..APSB_ROLE_OFFSET + 2]
            .copy_from_slice(&APFS_VOL_ROLE_SYSTEM.to_le_bytes());
        fletcher64_seal(&mut system);
        write_at(
            &mut *opened.disc,
            opened.container_offset,
            opened.block_size,
            FIXTURE_VOL_APSB_PADDR,
            &system,
        )
        .expect("write system");

        let mut data = system.clone();
        let data_uuid = [0xDAu8; 16];
        data[APSB_UUID_OFFSET..APSB_UUID_OFFSET + 16].copy_from_slice(&data_uuid);
        data[APSB_ROLE_OFFSET..APSB_ROLE_OFFSET + 2]
            .copy_from_slice(&APFS_VOL_ROLE_DATA.to_le_bytes());
        data[APSB_VOLUME_GROUP_OFFSET..APSB_VOLUME_GROUP_OFFSET + 16].fill(0);
        obj_stamp(&mut data, DATA_VOL_OID, 1, TYPE_FS | OBJ_VIRTUAL, 0);
        write_at(
            &mut *opened.disc,
            opened.container_offset,
            opened.block_size,
            DATA_VOL_PADDR,
            &data,
        )
        .expect("write data");

        let recs = vec![
            omap_record(1024, 1, FIXTURE_VOL_APSB_PADDR),
            omap_record(DATA_VOL_OID, 1, DATA_VOL_PADDR),
        ];
        let mut tree = btree_leaf(opened.block_size as usize, &recs, true);
        obj_stamp(
            &mut tree,
            OMAP_TREE_C,
            1,
            TYPE_BTREE | OBJ_PHYSICAL,
            TYPE_OMAP,
        );
        write_at(
            &mut *opened.disc,
            opened.container_offset,
            opened.block_size,
            OMAP_TREE_C,
            &tree,
        )
        .expect("write omap tree");

        for nx_paddr in [0u64, 1] {
            let mut nx = read_block(&mut opened, nx_paddr).expect("nxsb");
            nx[0xB4..0xB8].copy_from_slice(&2u32.to_le_bytes());
            nx[0xC0..0xC8].copy_from_slice(&DATA_VOL_OID.to_le_bytes());
            fletcher64_seal(&mut nx);
            write_at(
                &mut *opened.disc,
                opened.container_offset,
                opened.block_size,
                nx_paddr,
                &nx,
            )
            .expect("write nxsb");
        }
        (DATA_VOL_PADDR, system_uuid, data_uuid)
    }

    #[test]
    fn volume_group_mismatch_is_repaired_to_agreeing_ids() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        let (_data_paddr, system_uuid, data_uuid) = install_data_sibling(&image);
        inject_volume_group_id(&image, FIXTURE_VOL_APSB_PADDR, [0x11; 16]).unwrap();
        inject_volume_group_id(&image, DATA_VOL_PADDR, [0x22; 16]).unwrap();

        let before = sweep(&image).unwrap();
        let vg = finding(&before, "volume-group");
        assert!(vg.failed(), "{vg:?}");
        assert!(vg.repairable);
        assert!(
            repair_paths(&before)
                .iter()
                .any(|path| path.id == "volume-group")
        );

        apply(&image, &["volume-group".into()]).unwrap();
        let after = sweep(&image).unwrap();
        let vg = finding(&after, "volume-group");
        assert!(vg.passed(), "{vg:?} findings={:#?}", after.findings);

        let mut opened = open_repair(&image).unwrap();
        let system = read_block(&mut opened, FIXTURE_VOL_APSB_PADDR).unwrap();
        let data = read_block(&mut opened, DATA_VOL_PADDR).unwrap();
        let system_vgid = volume_group_id(&system);
        let data_vgid = volume_group_id(&data);
        assert_eq!(system_vgid, data_vgid);
        assert_ne!(system_vgid, ZERO_VGID);
        assert_eq!(system_vgid, [0x11; 16], "SYSTEM VGID wins on mismatch");
        let _ = (system_uuid, data_uuid);
    }

    #[test]
    fn volume_group_zero_ids_are_minted_from_volume_uuids() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        let (_data_paddr, system_uuid, data_uuid) = install_data_sibling(&image);
        inject_volume_group_id(&image, FIXTURE_VOL_APSB_PADDR, ZERO_VGID).unwrap();
        inject_volume_group_id(&image, DATA_VOL_PADDR, ZERO_VGID).unwrap();

        let before = sweep(&image).unwrap();
        assert!(finding(&before, "volume-group").failed());
        apply(&image, &["volume-group".into()]).unwrap();
        let after = sweep(&image).unwrap();
        assert!(finding(&after, "volume-group").passed());

        let expected = mint_group_id(&system_uuid, &data_uuid);
        let mut opened = open_repair(&image).unwrap();
        let system = read_block(&mut opened, FIXTURE_VOL_APSB_PADDR).unwrap();
        let data = read_block(&mut opened, DATA_VOL_PADDR).unwrap();
        assert_eq!(volume_group_id(&system), expected);
        assert_eq!(volume_group_id(&data), expected);
        assert_eq!(expected[6] & 0xF0, 0x40);
        assert_eq!(expected[8] & 0xC0, 0x80);
    }

    fn install_named_root_snapshot(path: &Path, name: &str, xid: u64) {
        const SNAP_TREE_PADDR: u64 = 27;
        let mut opened = open_repair(path).expect("open");
        let name_bytes = name.as_bytes();
        let name_len = (name_bytes.len() + 1) as u16;

        let mut meta_key = Vec::new();
        meta_key.extend_from_slice(&((J_SNAP_METADATA << 60) | xid).to_le_bytes());
        let mut meta_val = vec![0u8; 0x32 + name_bytes.len() + 1];
        put_u16(&mut meta_val, 0x30, name_len);
        meta_val[0x32..0x32 + name_bytes.len()].copy_from_slice(name_bytes);

        let mut name_key = Vec::new();
        name_key.extend_from_slice(&((J_SNAP_NAME << 60) | 0x0FFF_FFFF_FFFF_FFFF).to_le_bytes());
        name_key.extend_from_slice(&name_len.to_le_bytes());
        name_key.extend_from_slice(name_bytes);
        name_key.push(0);
        let mut name_val = vec![0u8; 8];
        put_u64(&mut name_val, 0, xid);

        let mut tree = btree_leaf(
            opened.block_size as usize,
            &[(meta_key, meta_val), (name_key, name_val)],
            true,
        );
        obj_stamp(
            &mut tree,
            SNAP_TREE_PADDR,
            1,
            TYPE_BTREE | OBJ_PHYSICAL,
            0x10,
        );
        write_at(
            &mut *opened.disc,
            opened.container_offset,
            opened.block_size,
            SNAP_TREE_PADDR,
            &tree,
        )
        .expect("write snap tree");

        let mut apsb = read_block(&mut opened, FIXTURE_VOL_APSB_PADDR).expect("apsb");
        apsb[APSB_SNAP_TREE_OFFSET..APSB_SNAP_TREE_OFFSET + 8]
            .copy_from_slice(&SNAP_TREE_PADDR.to_le_bytes());
        apsb[APSB_NUM_SNAPSHOTS_OFFSET..APSB_NUM_SNAPSHOTS_OFFSET + 8]
            .copy_from_slice(&1u64.to_le_bytes());
        apsb[APSB_ROOT_TO_XID_OFFSET..APSB_ROOT_TO_XID_OFFSET + 8]
            .copy_from_slice(&0u64.to_le_bytes());
        apsb[APSB_ROLE_OFFSET..APSB_ROLE_OFFSET + 2]
            .copy_from_slice(&APFS_VOL_ROLE_SYSTEM.to_le_bytes());
        fletcher64_seal(&mut apsb);
        write_at(
            &mut *opened.disc,
            opened.container_offset,
            opened.block_size,
            FIXTURE_VOL_APSB_PADDR,
            &apsb,
        )
        .expect("write apsb");
    }

    #[test]
    fn root_to_xid_zero_on_named_snapshot_is_repaired() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        install_named_root_snapshot(&image, "com.apple.os.update-DEAD", 42);

        let before = sweep(&image).unwrap();
        let id = format!("root-to-xid:{FIXTURE_VOL_APSB_PADDR}");
        let item = finding(&before, &id);
        assert!(item.failed(), "{item:?}");
        assert!(item.repairable);
        assert!(repair_paths(&before).iter().any(|path| path.id == id));

        apply(&image, std::slice::from_ref(&id)).unwrap();
        let after = sweep(&image).unwrap();
        let item = finding(&after, &id);
        assert!(item.passed(), "{item:?} dump=\n{}", format_dump(&after));

        let mut opened = open_repair(&image).unwrap();
        let apsb = read_block(&mut opened, FIXTURE_VOL_APSB_PADDR).unwrap();
        assert_eq!(volume_root_to_xid(&apsb), 42);
    }

    #[test]
    fn minted_group_id_stamps_rfc4122_version_and_variant() {
        let group = mint_group_id(&[0xAA; 16], &[0xBB; 16]);
        assert_eq!(group[6] & 0xF0, 0x40);
        assert_eq!(group[8] & 0xC0, 0x80);
        assert_eq!(mint_group_id(&[0xBB; 16], &[0xAA; 16]), group);
    }

    #[test]
    fn raw_container_with_corrupted_magic_is_still_openable_and_repairable() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        let mut bytes = apfs_fixture::container_bytes();
        bytes[0x20..0x24].fill(0);
        fletcher64_seal(&mut bytes[..4096]);
        std::fs::write(&image, &bytes).unwrap();

        let report = sweep(&image).expect("sweep must open a raw container with a bad magic");
        assert_eq!(report.backend, "raw");
        let item = finding(&report, "container-magic");
        assert!(item.failed(), "{item:?}");
        assert!(item.repairable, "{item:?}");

        apply(&image, &["container-magic".into()]).expect("apply container-magic");
        let after = sweep(&image).unwrap();
        assert!(finding(&after, "container-magic").passed());
    }

    #[test]
    fn multi_leaf_snapshot_tree_is_not_misread_as_empty() {
        const SNAP_TREE_PADDR: u64 = 27;
        const DECLARED_SNAPSHOTS: u64 = 3;

        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();

        let mut opened = open_repair(&image).expect("open");
        let mut tree = vec![0u8; opened.block_size as usize];
        tree[0x20..0x22].copy_from_slice(&BTNODE_ROOT.to_le_bytes());
        tree[0x22..0x24].copy_from_slice(&1u16.to_le_bytes());
        fletcher64_seal(&mut tree);
        write_at(
            &mut *opened.disc,
            opened.container_offset,
            opened.block_size,
            SNAP_TREE_PADDR,
            &tree,
        )
        .expect("write snap tree index node");

        let mut apsb = read_block(&mut opened, FIXTURE_VOL_APSB_PADDR).expect("apsb");
        apsb[APSB_SNAP_TREE_OFFSET..APSB_SNAP_TREE_OFFSET + 8]
            .copy_from_slice(&SNAP_TREE_PADDR.to_le_bytes());
        apsb[APSB_NUM_SNAPSHOTS_OFFSET..APSB_NUM_SNAPSHOTS_OFFSET + 8]
            .copy_from_slice(&DECLARED_SNAPSHOTS.to_le_bytes());
        apsb[APSB_ROLE_OFFSET..APSB_ROLE_OFFSET + 2]
            .copy_from_slice(&APFS_VOL_ROLE_SYSTEM.to_le_bytes());
        fletcher64_seal(&mut apsb);
        write_at(
            &mut *opened.disc,
            opened.container_offset,
            opened.block_size,
            FIXTURE_VOL_APSB_PADDR,
            &apsb,
        )
        .expect("write apsb");
        drop(opened);

        let count_id = format!("snapshot-count:{FIXTURE_VOL_APSB_PADDR}");
        let names_id = format!("snapshot-names:{FIXTURE_VOL_APSB_PADDR}");
        let root_id = format!("root-to-xid:{FIXTURE_VOL_APSB_PADDR}");

        let report = sweep(&image).unwrap();
        for id in [&count_id, &names_id, &root_id] {
            let item = finding(&report, id);
            assert!(item.failed(), "{id} must FAIL, not silently pass: {item:?}");
            assert!(
                !item.repairable,
                "{id} must not be offered as a repair when it cannot be verified: {item:?}"
            );
            assert!(
                item.detail.contains("not a single b-tree leaf")
                    || item.summary.contains("cannot be verified"),
                "{id} must say why it refuses to guess: {item:?}"
            );
        }
        let paths = repair_paths(&report);
        for id in [&count_id, &names_id, &root_id] {
            assert!(
                !paths.iter().any(|path| &path.id == id),
                "{id} must not appear in repair_paths: {paths:?}"
            );
        }

        let outcome = apply(&image, std::slice::from_ref(&count_id)).unwrap();
        assert!(
            outcome.applied.is_empty(),
            "snapshot-count must not be applied: {outcome:?}"
        );
        assert_eq!(outcome.failed.len(), 1);
        assert_eq!(outcome.failed[0].0, count_id);
        assert!(
            outcome.failed[0].1.contains("not a single b-tree leaf"),
            "{:?}",
            outcome.failed[0]
        );

        let mut opened = open_repair(&image).unwrap();
        let apsb = read_block(&mut opened, FIXTURE_VOL_APSB_PADDR).unwrap();
        assert_eq!(
            u64_at(&apsb, APSB_NUM_SNAPSHOTS_OFFSET),
            DECLARED_SNAPSHOTS,
            "a refused repair must not have touched apfs_num_snapshots"
        );
    }
}
