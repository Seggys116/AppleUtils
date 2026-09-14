//! Offline root-system-snapshot repair.
//!
//! XNU's `apfs_find_named_root_snapshot_xid` must resolve a named snapshot to a
//! non-zero xid even with unauthenticated root. This writes SNAP_METADATA and
//! SNAP_NAME records, a frozen volume superblock, and roots `apfs_root_to_xid`.

use std::cmp::Ordering;
use std::ops::Range;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::apfs_image::fletcher64_seal;
use crate::apfs_verify::{
    APFS_MAGIC, ContainerSeals, NX_MAGIC, OBJ_TYPE_MASK, OBJ_VIRTUAL, ROOT_SNAPSHOT_PREFIX,
    TYPE_BTREE, TYPE_FS, VolumeSealReport, read_container_seals, u16_at, u32_at, u64_at,
};
use crate::asahi_ops::ImageIo;
use crate::repair_writer::checkpoint::{self, CheckpointError, CheckpointPublish, EphemeralObject};
use crate::repair_writer::disc::{DiscError, RepairSession};
use crate::repair_writer::object::{
    self, OBJ_PHYS_BYTES, OID_OFFSET, ObjectWriteError, ReadModifyWriteError, SUBTYPE_OFFSET,
    TYPE_OFFSET, XID_OFFSET,
};
use crate::repair_writer::omap::{self, OmapError};
use crate::repair_writer::spaceman::{self, SpacemanError};

const APSB_SNAP_META_TREE_OID_OFFSET: usize = 0x98;
const APSB_NUM_SNAPSHOTS_OFFSET: usize = 0xD8;
const APSB_EXTENTREF_TREE_OID_OFFSET: usize = 0x90;
const APSB_MAGIC_OFFSET: usize = 0x20;
const APSB_ROOT_TO_XID_OFFSET: usize = 0x3C8;

const NX_SPACEMAN_OID_OFFSET: usize = 0x98;
const NX_OMAP_OID_OFFSET: usize = 0xA0;

const OM_TREE_TYPE_OFFSET: usize = 0x28;
const OM_TREE_OID_OFFSET: usize = 0x30;

const OBJ_PHYSICAL: u32 = 0x4000_0000;
const OBJ_STORAGE_MASK_HINT: u32 = 0xC000_0000;
const TYPE_OMAP: u32 = 0x0B;

const BTNODE_ROOT: u16 = 0x1;
const BTNODE_LEAF: u16 = 0x2;
const BTNODE_FIXED_KV_SIZE: u16 = 0x4;
const BTNODE_NOHEADER: u16 = 0x10;
const BTREE_INFO_BYTES: usize = 40;
const BTNODE_TOC_BASE: usize = 56;
const TOC_ENTRY_BYTES: usize = 8;

const BTN_FREE_SPACE_OFFSET: usize = OBJ_PHYS_BYTES + 0x0C;
const BTN_KEY_FREE_LIST_OFFSET: usize = OBJ_PHYS_BYTES + 0x10;
const BTN_VAL_FREE_LIST_OFFSET: usize = OBJ_PHYS_BYTES + 0x14;
const BTOFF_INVALID: u16 = 0xFFFF;

const BT_FLAGS_OFFSET: usize = 0x00;
const BT_NODE_SIZE_OFFSET: usize = 0x04;
const BT_KEY_SIZE_OFFSET: usize = 0x08;
const BT_VAL_SIZE_OFFSET: usize = 0x0C;
const BT_LONGEST_KEY_OFFSET: usize = 0x10;
const BT_LONGEST_VAL_OFFSET: usize = 0x14;
const BT_KEY_COUNT_OFFSET: usize = 0x18;
const BT_NODE_COUNT_OFFSET: usize = 0x20;

const BTREE_SEQUENTIAL_INSERT: u32 = 0x02;
const BTREE_PHYSICAL: u32 = 0x10;
const BTREE_KV_NONALIGNED: u32 = 0x40;

const TYPE_SNAP_META_TREE: u32 = 0x10;

const J_SNAP_METADATA: u64 = 1;
const J_SNAP_NAME: u64 = 11;

const OBJ_ID_MASK: u64 = 0x0FFF_FFFF_FFFF_FFFF;
const SNAP_NAME_OBJ_ID: u64 = OBJ_ID_MASK;

const SNAP_METADATA_VAL_HEADER_BYTES: usize = 0x32;
const SNAP_NAME_KEY_HEADER_BYTES: usize = 0x0A;

const SNAP_TREE_TOC_ENTRIES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotNameSource {
    AppleSealed,
    ExistingRootPrefixed,
    ChosenLabel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotOutcome {
    name: String,
    name_source: SnapshotNameSource,
    already_present: bool,
    written: bool,
    xid: u64,
    tree_paddr: u64,
    tree_created: bool,
    volume_paddr: u64,
    snapshot_superblock_paddr: u64,
    superblock_paddr: u64,
}

#[derive(Debug)]
enum SnapshotError {
    Disc(DiscError),
    Write(ObjectWriteError),
    Spaceman(SpacemanError),
    Checkpoint(CheckpointError),
    Omap(OmapError),
    Verify(String),
    Malformed(&'static str),
    Headerless,
    TreeNotSingleLeaf,
    TreeFull,
    DuplicateKey,
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disc(error) => write!(f, "disc error: {error}"),
            Self::Write(error) => write!(f, "{error}"),
            Self::Spaceman(error) => write!(f, "{error}"),
            Self::Checkpoint(error) => write!(f, "{error}"),
            Self::Omap(error) => write!(f, "{error}"),
            Self::Verify(error) => write!(f, "{error}"),
            Self::Malformed(reason) => write!(f, "malformed: {reason}"),
            Self::Headerless => write!(f, "snapshot metadata tree root is headerless"),
            Self::TreeNotSingleLeaf => write!(
                f,
                "the snapshot metadata tree is not a single node; splitting one is out of \
                 scope for this writer and no established format exists to guess at"
            ),
            Self::TreeFull => write!(
                f,
                "the snapshot metadata tree has no room for another record; splitting a node \
                 is out of scope for this writer and no established format exists to guess at"
            ),
            Self::DuplicateKey => write!(
                f,
                "a record with this key already exists in the snapshot metadata tree"
            ),
        }
    }
}

impl std::error::Error for SnapshotError {}

impl From<DiscError> for SnapshotError {
    fn from(error: DiscError) -> Self {
        Self::Disc(error)
    }
}

impl From<ObjectWriteError> for SnapshotError {
    fn from(error: ObjectWriteError) -> Self {
        Self::Write(error)
    }
}

impl From<SpacemanError> for SnapshotError {
    fn from(error: SpacemanError) -> Self {
        Self::Spaceman(error)
    }
}

impl From<CheckpointError> for SnapshotError {
    fn from(error: CheckpointError) -> Self {
        Self::Checkpoint(error)
    }
}

impl From<OmapError> for SnapshotError {
    fn from(error: OmapError) -> Self {
        Self::Omap(error)
    }
}

impl From<ReadModifyWriteError<SnapshotError>> for SnapshotError {
    fn from(error: ReadModifyWriteError<SnapshotError>) -> Self {
        match error {
            ReadModifyWriteError::Disc(error) => Self::Disc(error),
            ReadModifyWriteError::Mutation(error) => error,
        }
    }
}

fn chosen_label(volume_uuid: &[u8; 16], xid: u64) -> String {
    let mut hex = String::with_capacity(32);
    for byte in volume_uuid {
        hex.push_str(&format!("{byte:02X}"));
    }
    format!("{ROOT_SNAPSHOT_PREFIX}{hex}-{xid:X}")
}

struct NameChoice {
    name: String,
    source: SnapshotNameSource,
}

fn choose_name(volume: &VolumeSealReport, new_xid: u64) -> NameChoice {
    if let Some(seal) = &volume.seal {
        return NameChoice {
            name: seal.root_snapshot_name(),
            source: SnapshotNameSource::AppleSealed,
        };
    }
    if let Some(existing) = volume.snapshots.root_snapshot_name() {
        return NameChoice {
            name: existing.to_string(),
            source: SnapshotNameSource::ExistingRootPrefixed,
        };
    }
    NameChoice {
        name: chosen_label(&volume.uuid, new_xid),
        source: SnapshotNameSource::ChosenLabel,
    }
}

/// Create or root the `com.apple.os.update-*` snapshot XNU needs to mount a
/// system volume. Idempotent when the name already exists and `apfs_root_to_xid`
/// already names that snapshot.
pub fn apply_missing_root_snapshot(
    disc: &mut dyn ImageIo,
    container_offset: u64,
    block_size: u32,
    block_count: u64,
    volume_paddr: u64,
) -> Result<(), String> {
    let mut session = RepairSession::new(disc, container_offset, block_size, block_count);
    apply_on_session(&mut session, volume_paddr).map_err(|error| error.to_string())
}

fn apply_on_session(disc: &mut RepairSession<'_>, volume_paddr: u64) -> Result<(), SnapshotError> {
    let seals = read_seals(disc)?;
    let volume = find_volume(&seals, disc, volume_paddr)?;
    let ephemeral = checkpoint::collect_ephemeral_objects(disc, seals.superblock_paddr)?;
    let outcome = create_root_system_snapshot(disc, &seals, volume, &ephemeral)?;
    if outcome.already_present {
        return Ok(());
    }
    let after = read_seals(disc)?;
    let volume_after = after
        .volumes
        .iter()
        .find(|candidate| candidate.oid == volume.oid)
        .ok_or(SnapshotError::Malformed(
            "volume disappeared after the snapshot write",
        ))?;
    let name_xid = volume_after.snapshots.xid_for_name(&outcome.name);
    let metadata_present = name_xid.is_some_and(|xid| {
        volume_after
            .snapshots
            .snapshots
            .iter()
            .any(|snapshot| snapshot.xid == xid && snapshot.name == outcome.name)
    });
    if !metadata_present {
        return Err(SnapshotError::Verify(format!(
            "named snapshot {} is still missing after write",
            outcome.name
        )));
    }
    if volume_after.root_to_xid != outcome.xid {
        return Err(SnapshotError::Verify(format!(
            "apfs_root_to_xid is {:#x} after write, expected {:#x}",
            volume_after.root_to_xid, outcome.xid
        )));
    }
    Ok(())
}

fn read_seals(disc: &mut RepairSession<'_>) -> Result<ContainerSeals, SnapshotError> {
    read_container_seals(disc).map_err(|error| SnapshotError::Verify(error.to_string()))
}

fn find_volume<'a>(
    seals: &'a ContainerSeals,
    disc: &mut RepairSession<'_>,
    volume_paddr: u64,
) -> Result<&'a VolumeSealReport, SnapshotError> {
    if let Some(volume) = seals
        .volumes
        .iter()
        .find(|volume| volume.paddr == volume_paddr)
    {
        return Ok(volume);
    }
    let mut block = vec![0u8; disc.block_size() as usize];
    disc.read_block(volume_paddr, &mut block)?;
    let oid = u64_at(&block, OID_OFFSET);
    seals
        .volumes
        .iter()
        .find(|volume| volume.oid == oid)
        .ok_or(SnapshotError::Malformed(
            "no volume at the given physical address",
        ))
}

fn create_root_system_snapshot(
    disc: &mut RepairSession<'_>,
    container: &ContainerSeals,
    volume: &VolumeSealReport,
    ephemeral_objects: &[EphemeralObject],
) -> Result<SnapshotOutcome, SnapshotError> {
    let new_xid = container
        .xid
        .checked_add(1)
        .ok_or(SnapshotError::Malformed(
            "container transaction id would overflow",
        ))?;
    let choice = choose_name(volume, new_xid);

    let name_xid = volume.snapshots.xid_for_name(&choice.name);
    let metadata_present = name_xid.is_some_and(|xid| {
        volume
            .snapshots
            .snapshots
            .iter()
            .any(|snapshot| snapshot.xid == xid && snapshot.name == choice.name)
    });
    if let Some(xid) = name_xid
        && metadata_present
    {
        if volume.root_to_xid == xid {
            return Ok(SnapshotOutcome {
                name: choice.name,
                name_source: choice.source,
                already_present: true,
                written: false,
                xid,
                tree_paddr: volume.snapshots.tree_paddr,
                tree_created: false,
                volume_paddr: 0,
                snapshot_superblock_paddr: 0,
                superblock_paddr: 0,
            });
        }
        return root_live_volume_at_existing_snapshot(
            disc,
            container,
            volume,
            ephemeral_objects,
            choice.name,
            choice.source,
            xid,
        );
    }

    let block_size = disc.block_size() as usize;

    let mut volume_block = vec![0u8; block_size];
    disc.read_block(volume.paddr, &mut volume_block)?;
    if u64_at(&volume_block, OID_OFFSET) != volume.oid {
        return Err(SnapshotError::Malformed(
            "volume superblock at the given address does not carry the expected object id",
        ));
    }
    if u32_at(&volume_block, TYPE_OFFSET) & OBJ_TYPE_MASK != TYPE_FS
        || u32_at(&volume_block, TYPE_OFFSET) & OBJ_STORAGE_MASK_HINT != OBJ_VIRTUAL
    {
        return Err(SnapshotError::Malformed(
            "object at the given address is not a virtual volume superblock",
        ));
    }
    if u32_at(&volume_block, APSB_MAGIC_OFFSET) != APFS_MAGIC {
        return Err(SnapshotError::Malformed(
            "no APSB magic on the volume superblock",
        ));
    }
    let extentref_tree_oid = u64_at(&volume_block, APSB_EXTENTREF_TREE_OID_OFFSET);
    let existing_tree_paddr = u64_at(&volume_block, APSB_SNAP_META_TREE_OID_OFFSET);
    let current_snapshot_count = u64_at(&volume_block, APSB_NUM_SNAPSHOTS_OFFSET);

    let pointers = resolve_container_pointers(disc, container.superblock_paddr)?;
    let spaceman_paddr = find_ephemeral_paddr(ephemeral_objects, pointers.spaceman_oid)?;
    omap::ensure_upsertable(disc, pointers.omap_tree_root, volume.oid, new_xid)?;

    if existing_tree_paddr != 0 {
        let mut existing = vec![0u8; block_size];
        disc.read_block(existing_tree_paddr, &mut existing)?;
        let header = decode_variable_header(&existing)?;
        if (header.nkeys + 2) * TOC_ENTRY_BYTES > header.toc_len {
            return Err(SnapshotError::TreeFull);
        }
    }

    let frozen_volume_block = volume_block.clone();
    let mut private = spaceman::PrivateSpaceman::load(disc, spaceman_paddr)?;

    let (tree_paddr, tree_created) = if existing_tree_paddr == 0 {
        let allocated = private.allocate(new_xid)?;
        object::write_object(
            disc,
            allocated,
            allocated,
            new_xid,
            TYPE_BTREE | OBJ_PHYSICAL,
            TYPE_SNAP_META_TREE,
            &empty_leaf_body(block_size),
        )?;
        (allocated, true)
    } else {
        let allocated = private.allocate(new_xid)?;
        cow_physical(disc, existing_tree_paddr, allocated, new_xid)?;
        (allocated, false)
    };

    let snapshot_superblock_paddr = private.allocate(new_xid)?;
    write_snapshot_superblock(
        disc,
        snapshot_superblock_paddr,
        new_xid,
        &frozen_volume_block,
    )?;

    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    let (meta_key, meta_value) = snapshot_metadata_record(
        new_xid,
        &choice.name,
        snapshot_superblock_paddr,
        extentref_tree_oid,
        now_ns,
    );
    let (name_key, name_value) = snapshot_name_record(&choice.name, new_xid);

    object::read_modify_write::<SnapshotError>(disc, tree_paddr, |block| {
        insert_variable_entry(block, &meta_key, &meta_value)?;
        insert_variable_entry(block, &name_key, &name_value)?;
        block[XID_OFFSET..XID_OFFSET + 8].copy_from_slice(&new_xid.to_le_bytes());
        Ok(())
    })?;

    volume_block[XID_OFFSET..XID_OFFSET + 8].copy_from_slice(&new_xid.to_le_bytes());
    volume_block[APSB_SNAP_META_TREE_OID_OFFSET..APSB_SNAP_META_TREE_OID_OFFSET + 8]
        .copy_from_slice(&tree_paddr.to_le_bytes());
    let new_count = current_snapshot_count.saturating_add(1);
    volume_block[APSB_NUM_SNAPSHOTS_OFFSET..APSB_NUM_SNAPSHOTS_OFFSET + 8]
        .copy_from_slice(&new_count.to_le_bytes());
    volume_block[APSB_ROOT_TO_XID_OFFSET..APSB_ROOT_TO_XID_OFFSET + 8]
        .copy_from_slice(&new_xid.to_le_bytes());
    fletcher64_seal(&mut volume_block);

    let new_volume_paddr = private.allocate(new_xid)?;
    disc.write_block(new_volume_paddr, &volume_block)?;

    let new_omap_paddr = cow_omap_upsert(
        disc,
        &mut private,
        &pointers,
        volume.oid,
        new_xid,
        new_volume_paddr,
    )?;
    let appended = publish_transaction(
        disc,
        &mut private,
        container,
        ephemeral_objects,
        pointers.spaceman_oid,
        new_xid,
        new_omap_paddr,
    )?;

    Ok(SnapshotOutcome {
        name: choice.name,
        name_source: choice.source,
        already_present: false,
        written: true,
        xid: new_xid,
        tree_paddr,
        tree_created,
        volume_paddr: new_volume_paddr,
        snapshot_superblock_paddr,
        superblock_paddr: appended.superblock_paddr,
    })
}

fn root_live_volume_at_existing_snapshot(
    disc: &mut RepairSession<'_>,
    container: &ContainerSeals,
    volume: &VolumeSealReport,
    ephemeral_objects: &[EphemeralObject],
    name: String,
    name_source: SnapshotNameSource,
    snapshot_xid: u64,
) -> Result<SnapshotOutcome, SnapshotError> {
    let new_xid = container
        .xid
        .checked_add(1)
        .ok_or(SnapshotError::Malformed(
            "container transaction id would overflow",
        ))?;
    let mut volume_block = read_checked_volume_superblock(disc, volume)?;
    let current = u64_at(&volume_block, APSB_ROOT_TO_XID_OFFSET);
    if current == snapshot_xid {
        return Ok(SnapshotOutcome {
            name,
            name_source,
            already_present: true,
            written: false,
            xid: snapshot_xid,
            tree_paddr: volume.snapshots.tree_paddr,
            tree_created: false,
            volume_paddr: 0,
            snapshot_superblock_paddr: 0,
            superblock_paddr: 0,
        });
    }

    let pointers = resolve_container_pointers(disc, container.superblock_paddr)?;
    let spaceman_paddr = find_ephemeral_paddr(ephemeral_objects, pointers.spaceman_oid)?;
    omap::ensure_upsertable(disc, pointers.omap_tree_root, volume.oid, new_xid)?;

    volume_block[XID_OFFSET..XID_OFFSET + 8].copy_from_slice(&new_xid.to_le_bytes());
    volume_block[APSB_ROOT_TO_XID_OFFSET..APSB_ROOT_TO_XID_OFFSET + 8]
        .copy_from_slice(&snapshot_xid.to_le_bytes());
    fletcher64_seal(&mut volume_block);

    let mut private = spaceman::PrivateSpaceman::load(disc, spaceman_paddr)?;
    let new_volume_paddr = private.allocate(new_xid)?;
    disc.write_block(new_volume_paddr, &volume_block)?;

    let new_omap_paddr = cow_omap_upsert(
        disc,
        &mut private,
        &pointers,
        volume.oid,
        new_xid,
        new_volume_paddr,
    )?;
    let appended = publish_transaction(
        disc,
        &mut private,
        container,
        ephemeral_objects,
        pointers.spaceman_oid,
        new_xid,
        new_omap_paddr,
    )?;

    Ok(SnapshotOutcome {
        name,
        name_source,
        already_present: false,
        written: true,
        xid: snapshot_xid,
        tree_paddr: volume.snapshots.tree_paddr,
        tree_created: false,
        volume_paddr: new_volume_paddr,
        snapshot_superblock_paddr: 0,
        superblock_paddr: appended.superblock_paddr,
    })
}

fn read_checked_volume_superblock(
    disc: &mut RepairSession<'_>,
    volume: &VolumeSealReport,
) -> Result<Vec<u8>, SnapshotError> {
    let block_size = disc.block_size() as usize;
    let mut volume_block = vec![0u8; block_size];
    disc.read_block(volume.paddr, &mut volume_block)?;
    if u64_at(&volume_block, OID_OFFSET) != volume.oid {
        return Err(SnapshotError::Malformed(
            "volume superblock at the given address does not carry the expected object id",
        ));
    }
    if u32_at(&volume_block, TYPE_OFFSET) & OBJ_TYPE_MASK != TYPE_FS
        || u32_at(&volume_block, TYPE_OFFSET) & OBJ_STORAGE_MASK_HINT != OBJ_VIRTUAL
    {
        return Err(SnapshotError::Malformed(
            "object at the given address is not a virtual volume superblock",
        ));
    }
    if u32_at(&volume_block, APSB_MAGIC_OFFSET) != APFS_MAGIC {
        return Err(SnapshotError::Malformed(
            "no APSB magic on the volume superblock",
        ));
    }
    Ok(volume_block)
}

fn write_snapshot_superblock(
    disc: &mut RepairSession<'_>,
    paddr: u64,
    xid: u64,
    frozen_volume_block: &[u8],
) -> Result<(), SnapshotError> {
    let mut block = frozen_volume_block.to_vec();
    block[OID_OFFSET..OID_OFFSET + 8].copy_from_slice(&paddr.to_le_bytes());
    block[XID_OFFSET..XID_OFFSET + 8].copy_from_slice(&xid.to_le_bytes());
    block[TYPE_OFFSET..TYPE_OFFSET + 4].copy_from_slice(&(TYPE_FS | OBJ_PHYSICAL).to_le_bytes());
    block[SUBTYPE_OFFSET..SUBTYPE_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
    fletcher64_seal(&mut block);
    disc.write_block(paddr, &block)?;
    Ok(())
}

struct ContainerPointers {
    spaceman_oid: u64,
    omap_paddr: u64,
    omap_tree_root: u64,
}

fn cow_physical(
    disc: &mut RepairSession<'_>,
    src: u64,
    dst: u64,
    xid: u64,
) -> Result<(), SnapshotError> {
    let mut block = vec![0u8; disc.block_size() as usize];
    disc.read_block(src, &mut block)?;
    block[OID_OFFSET..OID_OFFSET + 8].copy_from_slice(&dst.to_le_bytes());
    block[XID_OFFSET..XID_OFFSET + 8].copy_from_slice(&xid.to_le_bytes());
    fletcher64_seal(&mut block);
    disc.write_block(dst, &block)?;
    Ok(())
}

fn cow_omap_upsert(
    disc: &mut RepairSession<'_>,
    private: &mut spaceman::PrivateSpaceman,
    pointers: &ContainerPointers,
    oid: u64,
    xid: u64,
    volume_paddr: u64,
) -> Result<u64, SnapshotError> {
    let new_tree = private.allocate(xid)?;
    cow_physical(disc, pointers.omap_tree_root, new_tree, xid)?;
    omap::upsert(disc, new_tree, oid, xid, volume_paddr, xid)?;
    let new_omap = private.allocate(xid)?;
    let mut omap_block = vec![0u8; disc.block_size() as usize];
    disc.read_block(pointers.omap_paddr, &mut omap_block)?;
    omap_block[OID_OFFSET..OID_OFFSET + 8].copy_from_slice(&new_omap.to_le_bytes());
    omap_block[XID_OFFSET..XID_OFFSET + 8].copy_from_slice(&xid.to_le_bytes());
    omap_block[OM_TREE_OID_OFFSET..OM_TREE_OID_OFFSET + 8].copy_from_slice(&new_tree.to_le_bytes());
    fletcher64_seal(&mut omap_block);
    disc.write_block(new_omap, &omap_block)?;
    Ok(new_omap)
}

fn publish_transaction(
    disc: &mut RepairSession<'_>,
    private: &mut spaceman::PrivateSpaceman,
    container: &ContainerSeals,
    ephemeral_objects: &[EphemeralObject],
    spaceman_oid: u64,
    new_xid: u64,
    new_omap_paddr: u64,
) -> Result<checkpoint::AppendedCheckpoint, SnapshotError> {
    let spaceman_body = private.materialize(disc, new_xid)?;
    let publish = CheckpointPublish {
        omap_oid: Some(new_omap_paddr),
        ephemeral_bodies: vec![(spaceman_oid, spaceman_body)],
    };
    Ok(checkpoint::append_with(
        disc,
        container.superblock_paddr,
        new_xid,
        ephemeral_objects,
        &publish,
    )?)
}

fn resolve_container_pointers(
    disc: &mut RepairSession<'_>,
    superblock_paddr: u64,
) -> Result<ContainerPointers, SnapshotError> {
    let block_size = disc.block_size() as usize;
    let mut sb = vec![0u8; block_size];
    disc.read_block(superblock_paddr, &mut sb)?;
    if u32_at(&sb, APSB_MAGIC_OFFSET) != NX_MAGIC {
        return Err(SnapshotError::Malformed(
            "no NXSB magic at the given container superblock address",
        ));
    }
    let spaceman_oid = u64_at(&sb, NX_SPACEMAN_OID_OFFSET);
    let omap_oid = u64_at(&sb, NX_OMAP_OID_OFFSET);

    let mut omap_block = vec![0u8; block_size];
    disc.read_block(omap_oid, &mut omap_block)?;
    if u64_at(&omap_block, OID_OFFSET) != omap_oid {
        return Err(SnapshotError::Malformed(
            "container object map is not self-addressed",
        ));
    }
    if u32_at(&omap_block, TYPE_OFFSET) & OBJ_TYPE_MASK != TYPE_OMAP {
        return Err(SnapshotError::Malformed(
            "container nx_omap_oid does not name an object map",
        ));
    }
    if u32_at(&omap_block, OM_TREE_TYPE_OFFSET) & OBJ_TYPE_MASK != TYPE_BTREE {
        return Err(SnapshotError::Malformed(
            "container object map's own tree type is not a b-tree",
        ));
    }
    let omap_tree_root = u64_at(&omap_block, OM_TREE_OID_OFFSET);
    Ok(ContainerPointers {
        spaceman_oid,
        omap_paddr: omap_oid,
        omap_tree_root,
    })
}

fn find_ephemeral_paddr(
    ephemeral_objects: &[EphemeralObject],
    oid: u64,
) -> Result<u64, SnapshotError> {
    ephemeral_objects
        .iter()
        .find(|entry| entry.oid == oid)
        .map(|entry| entry.paddr)
        .ok_or(SnapshotError::Malformed(
            "the space manager's oid is not in the given ephemeral object set",
        ))
}

fn snapshot_metadata_record(
    xid: u64,
    name: &str,
    sblock_oid: u64,
    extentref_tree_oid: u64,
    now_ns: u64,
) -> (Vec<u8>, Vec<u8>) {
    let key = ((J_SNAP_METADATA << 60) | xid).to_le_bytes().to_vec();
    let mut value = vec![0u8; SNAP_METADATA_VAL_HEADER_BYTES];
    value[0x00..0x08].copy_from_slice(&extentref_tree_oid.to_le_bytes());
    value[0x08..0x10].copy_from_slice(&sblock_oid.to_le_bytes());
    value[0x10..0x18].copy_from_slice(&now_ns.to_le_bytes());
    value[0x18..0x20].copy_from_slice(&now_ns.to_le_bytes());
    value[0x20..0x28].copy_from_slice(&0u64.to_le_bytes());
    value[0x28..0x2C].copy_from_slice(&(TYPE_BTREE | OBJ_PHYSICAL).to_le_bytes());
    value[0x2C..0x30].copy_from_slice(&0u32.to_le_bytes());
    let name_len = (name.len() + 1) as u16;
    value[0x30..0x32].copy_from_slice(&name_len.to_le_bytes());
    value.extend_from_slice(name.as_bytes());
    value.push(0);
    (key, value)
}

fn snapshot_name_record(name: &str, xid: u64) -> (Vec<u8>, Vec<u8>) {
    let mut key = ((J_SNAP_NAME << 60) | SNAP_NAME_OBJ_ID)
        .to_le_bytes()
        .to_vec();
    let name_len = (name.len() + 1) as u16;
    key.extend_from_slice(&name_len.to_le_bytes());
    key.extend_from_slice(name.as_bytes());
    key.push(0);
    (key, xid.to_le_bytes().to_vec())
}

struct VarHeader {
    nkeys: usize,
    toc: usize,
    toc_len: usize,
    key_base: usize,
    value_end: usize,
    free_off: usize,
    free_len: usize,
    info_at: usize,
}

impl VarHeader {
    fn data_area(&self) -> usize {
        self.value_end - self.key_base
    }
}

fn decode_variable_header(block: &[u8]) -> Result<VarHeader, SnapshotError> {
    let block_size = block.len();
    let flags = u16_at(block, OBJ_PHYS_BYTES);
    if flags & BTNODE_NOHEADER != 0 {
        return Err(SnapshotError::Headerless);
    }
    if flags & BTNODE_FIXED_KV_SIZE != 0 {
        return Err(SnapshotError::Malformed(
            "snapshot metadata tree root uses the fixed-size layout, not the variable one every \
             real named snapshot record needs",
        ));
    }
    if flags & (BTNODE_ROOT | BTNODE_LEAF) != (BTNODE_ROOT | BTNODE_LEAF) {
        return Err(SnapshotError::TreeNotSingleLeaf);
    }
    let nkeys = u32_at(block, OBJ_PHYS_BYTES + 0x04) as usize;
    let toc_off = u16_at(block, OBJ_PHYS_BYTES + 0x08) as usize;
    let toc_len = u16_at(block, OBJ_PHYS_BYTES + 0x0A) as usize;
    let toc = BTNODE_TOC_BASE + toc_off;
    let key_base = toc + toc_len;
    let value_end = block_size - BTREE_INFO_BYTES;
    if key_base > value_end || value_end > block_size {
        return Err(SnapshotError::Malformed(
            "table of contents leaves no room for keys and values",
        ));
    }
    if nkeys * TOC_ENTRY_BYTES > toc_len {
        return Err(SnapshotError::Malformed(
            "more keys than the table of contents holds",
        ));
    }
    if u16_at(block, BTN_KEY_FREE_LIST_OFFSET + 2) != 0
        || u16_at(block, BTN_VAL_FREE_LIST_OFFSET + 2) != 0
    {
        return Err(SnapshotError::Malformed(
            "snapshot metadata tree root carries freed key or value space this module does not \
             account for",
        ));
    }
    let free_off = u16_at(block, BTN_FREE_SPACE_OFFSET) as usize;
    let free_len = u16_at(block, BTN_FREE_SPACE_OFFSET + 2) as usize;
    Ok(VarHeader {
        nkeys,
        toc,
        toc_len,
        key_base,
        value_end,
        free_off,
        free_len,
        info_at: block_size - BTREE_INFO_BYTES,
    })
}

fn variable_entry_ranges(
    block: &[u8],
    header: &VarHeader,
    index: usize,
) -> Result<(Range<usize>, Range<usize>), SnapshotError> {
    let at = header.toc + index * TOC_ENTRY_BYTES;
    let key_off = u16_at(block, at) as usize;
    let key_len = u16_at(block, at + 2) as usize;
    let value_off = u16_at(block, at + 4) as usize;
    let value_len = u16_at(block, at + 6) as usize;
    let malformed = |reason: &'static str| SnapshotError::Malformed(reason);
    let key_at = header
        .key_base
        .checked_add(key_off)
        .filter(|end| end + key_len <= header.value_end)
        .ok_or_else(|| malformed("key runs past the value area"))?;
    let value_at = header
        .value_end
        .checked_sub(value_off)
        .filter(|at| *at >= header.key_base)
        .ok_or_else(|| malformed("value offset leaves the node"))?;
    let value_end = value_at
        .checked_add(value_len)
        .filter(|end| *end <= header.value_end)
        .ok_or_else(|| malformed("value runs past the end of the node"))?;
    Ok((key_at..key_at + key_len, value_at..value_end))
}

fn compare_records(a: &[u8], b: &[u8]) -> Ordering {
    let a_header = u64_at(a, 0);
    let b_header = u64_at(b, 0);
    match a_header.cmp(&b_header) {
        Ordering::Equal => tail_bytes(a, a_header >> 60).cmp(tail_bytes(b, b_header >> 60)),
        other => other,
    }
}

fn tail_bytes(key: &[u8], kind: u64) -> &[u8] {
    if kind == J_SNAP_NAME && key.len() >= SNAP_NAME_KEY_HEADER_BYTES {
        &key[SNAP_NAME_KEY_HEADER_BYTES..]
    } else {
        &[]
    }
}

fn insert_variable_entry(block: &mut [u8], key: &[u8], value: &[u8]) -> Result<(), SnapshotError> {
    let header = decode_variable_header(block)?;
    let key_size = key.len();
    let value_size = value.len();
    let data_area = header.data_area();

    let mut insert_at = header.nkeys;
    let mut key_high = 0usize;
    let mut value_high = 0usize;
    for index in 0..header.nkeys {
        let at = header.toc + index * TOC_ENTRY_BYTES;
        let key_off = u16_at(block, at) as usize;
        let key_len = u16_at(block, at + 2) as usize;
        let value_off = u16_at(block, at + 4) as usize;
        key_high = key_high.max(key_off + key_len);
        value_high = value_high.max(value_off);
        if insert_at == header.nkeys {
            let (key_range, _) = variable_entry_ranges(block, &header, index)?;
            match compare_records(&block[key_range], key) {
                Ordering::Equal => return Err(SnapshotError::DuplicateKey),
                Ordering::Greater => insert_at = index,
                Ordering::Less => {}
            }
        }
    }
    if key_high + value_high > data_area {
        return Err(SnapshotError::Malformed(
            "the node's keys and values already overlap",
        ));
    }
    if header.free_off > data_area
        || header.free_off + header.free_len > data_area
        || header.free_off < key_high
    {
        return Err(SnapshotError::Malformed(
            "the node's recorded free space contradicts its table of contents",
        ));
    }

    if (header.nkeys + 1) * TOC_ENTRY_BYTES > header.toc_len {
        return Err(SnapshotError::TreeFull);
    }
    let new_key_off = key_high;
    let new_value_off = value_high
        .checked_add(value_size)
        .ok_or(SnapshotError::TreeFull)?;
    let new_key_at = header.key_base + new_key_off;
    let new_value_at = header
        .value_end
        .checked_sub(new_value_off)
        .filter(|at| *at >= header.key_base)
        .ok_or(SnapshotError::TreeFull)?;
    if new_key_at + key_size > new_value_at {
        return Err(SnapshotError::TreeFull);
    }

    block[new_key_at..new_key_at + key_size].copy_from_slice(key);
    block[new_value_at..new_value_at + value_size].copy_from_slice(value);

    for index in (insert_at..header.nkeys).rev() {
        let at = header.toc + index * TOC_ENTRY_BYTES;
        let entry = block[at..at + TOC_ENTRY_BYTES].to_vec();
        let dest = header.toc + (index + 1) * TOC_ENTRY_BYTES;
        block[dest..dest + TOC_ENTRY_BYTES].copy_from_slice(&entry);
    }
    let at = header.toc + insert_at * TOC_ENTRY_BYTES;
    block[at..at + 2].copy_from_slice(&(new_key_off as u16).to_le_bytes());
    block[at + 2..at + 4].copy_from_slice(&(key_size as u16).to_le_bytes());
    block[at + 4..at + 6].copy_from_slice(&(new_value_off as u16).to_le_bytes());
    block[at + 6..at + 8].copy_from_slice(&(value_size as u16).to_le_bytes());

    let new_nkeys = (header.nkeys + 1) as u32;
    block[OBJ_PHYS_BYTES + 0x04..OBJ_PHYS_BYTES + 0x08].copy_from_slice(&new_nkeys.to_le_bytes());

    let used_keys = key_high + key_size;
    let used_values = value_high + value_size;
    write_free_space(block, used_keys, data_area - used_keys - used_values);
    record_entry_in_tree_info(block, header.info_at, key_size, value_size);
    Ok(())
}

fn write_free_space(block: &mut [u8], off: usize, len: usize) {
    block[BTN_FREE_SPACE_OFFSET..BTN_FREE_SPACE_OFFSET + 2]
        .copy_from_slice(&(off as u16).to_le_bytes());
    block[BTN_FREE_SPACE_OFFSET + 2..BTN_FREE_SPACE_OFFSET + 4]
        .copy_from_slice(&(len as u16).to_le_bytes());
}

fn record_entry_in_tree_info(block: &mut [u8], info_at: usize, key_size: usize, value_size: usize) {
    let flags = u32_at(block, info_at + BT_FLAGS_OFFSET);
    let charged = |size: usize| -> u32 {
        if flags & BTREE_KV_NONALIGNED != 0 {
            size as u32
        } else {
            (size as u32 + 7) & !7
        }
    };
    let longest_key = u32_at(block, info_at + BT_LONGEST_KEY_OFFSET).max(charged(key_size));
    let longest_val = u32_at(block, info_at + BT_LONGEST_VAL_OFFSET).max(charged(value_size));
    let key_count = u64_at(block, info_at + BT_KEY_COUNT_OFFSET).saturating_add(1);
    block[info_at + BT_LONGEST_KEY_OFFSET..info_at + BT_LONGEST_KEY_OFFSET + 4]
        .copy_from_slice(&longest_key.to_le_bytes());
    block[info_at + BT_LONGEST_VAL_OFFSET..info_at + BT_LONGEST_VAL_OFFSET + 4]
        .copy_from_slice(&longest_val.to_le_bytes());
    block[info_at + BT_KEY_COUNT_OFFSET..info_at + BT_KEY_COUNT_OFFSET + 8]
        .copy_from_slice(&key_count.to_le_bytes());
}

fn empty_leaf_body(block_size: usize) -> Vec<u8> {
    let mut body = vec![0u8; block_size - OBJ_PHYS_BYTES];
    let flags: u16 = BTNODE_ROOT | BTNODE_LEAF;
    body[0x00..0x02].copy_from_slice(&flags.to_le_bytes());
    body[0x02..0x04].copy_from_slice(&0u16.to_le_bytes());
    body[0x04..0x08].copy_from_slice(&0u32.to_le_bytes());
    body[0x08..0x0A].copy_from_slice(&0u16.to_le_bytes());
    let toc_len = SNAP_TREE_TOC_ENTRIES * TOC_ENTRY_BYTES;
    body[0x0A..0x0C].copy_from_slice(&(toc_len as u16).to_le_bytes());

    let data_area = block_size - BTNODE_TOC_BASE - toc_len - BTREE_INFO_BYTES;
    body[0x0C..0x0E].copy_from_slice(&0u16.to_le_bytes());
    body[0x0E..0x10].copy_from_slice(&(data_area as u16).to_le_bytes());
    body[0x10..0x12].copy_from_slice(&BTOFF_INVALID.to_le_bytes());
    body[0x12..0x14].copy_from_slice(&0u16.to_le_bytes());
    body[0x14..0x16].copy_from_slice(&BTOFF_INVALID.to_le_bytes());
    body[0x16..0x18].copy_from_slice(&0u16.to_le_bytes());

    let info_at = body.len() - BTREE_INFO_BYTES;
    let bt_flags = BTREE_SEQUENTIAL_INSERT | BTREE_PHYSICAL | BTREE_KV_NONALIGNED;
    body[info_at + BT_FLAGS_OFFSET..info_at + BT_FLAGS_OFFSET + 4]
        .copy_from_slice(&bt_flags.to_le_bytes());
    body[info_at + BT_NODE_SIZE_OFFSET..info_at + BT_NODE_SIZE_OFFSET + 4]
        .copy_from_slice(&(block_size as u32).to_le_bytes());
    body[info_at + BT_KEY_SIZE_OFFSET..info_at + BT_KEY_SIZE_OFFSET + 4]
        .copy_from_slice(&0u32.to_le_bytes());
    body[info_at + BT_VAL_SIZE_OFFSET..info_at + BT_VAL_SIZE_OFFSET + 4]
        .copy_from_slice(&0u32.to_le_bytes());
    body[info_at + BT_LONGEST_KEY_OFFSET..info_at + BT_LONGEST_KEY_OFFSET + 4]
        .copy_from_slice(&0u32.to_le_bytes());
    body[info_at + BT_LONGEST_VAL_OFFSET..info_at + BT_LONGEST_VAL_OFFSET + 4]
        .copy_from_slice(&0u32.to_le_bytes());
    body[info_at + BT_KEY_COUNT_OFFSET..info_at + BT_KEY_COUNT_OFFSET + 8]
        .copy_from_slice(&0u64.to_le_bytes());
    body[info_at + BT_NODE_COUNT_OFFSET..info_at + BT_NODE_COUNT_OFFSET + 8]
        .copy_from_slice(&1u64.to_le_bytes());
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apfs_verify::{SliceBlocks, read_container_seals};
    use crate::asahi_ops::{ImageIo, OpsError};
    use crate::repair_writer::disc::MemoryImage;
    use crate::repair_writer::object::test_support::{
        BLOCK_SIZE, INITIAL_XID, LAYOUT, OBJ_PHYSICAL, TYPE_BTREE, TYPE_OMAP as TS_TYPE_OMAP, open,
        session,
    };
    use crate::repair_writer::object::{self, OBJ_PHYS_BYTES};

    const TYPE_INTEGRITY_META: u32 = 0x1E;
    const IM_VERSION_OFFSET: usize = 0x20;
    const IM_HASH_TYPE_OFFSET: usize = 0x28;
    const IM_ROOT_HASH_OFFSET_OFFSET: usize = 0x2C;
    const IM_BROKEN_XID_OFFSET: usize = 0x30;
    const APSB_INTEGRITY_META_OID_OFFSET: usize = 0x400;
    const TYPE_FS_NUM: u32 = 0x0D;

    fn write_empty_fixed_omap_tree(disc: &mut RepairSession<'_>, paddr: u64) {
        const BTNODE_ROOT: u16 = 0x1;
        const BTNODE_LEAF: u16 = 0x2;
        const BTNODE_FIXED_KV_SIZE: u16 = 0x4;
        let block_size = disc.block_size() as usize;
        let mut body = vec![0u8; block_size - OBJ_PHYS_BYTES];
        let flags = BTNODE_ROOT | BTNODE_LEAF | BTNODE_FIXED_KV_SIZE;
        body[0x00..0x02].copy_from_slice(&flags.to_le_bytes());
        body[0x02..0x04].copy_from_slice(&0u16.to_le_bytes());
        body[0x04..0x08].copy_from_slice(&0u32.to_le_bytes());
        body[0x08..0x0A].copy_from_slice(&0u16.to_le_bytes());
        body[0x0A..0x0C].copy_from_slice(&64u16.to_le_bytes());
        object::write_object(
            disc,
            paddr,
            paddr,
            INITIAL_XID,
            TYPE_BTREE | OBJ_PHYSICAL,
            TS_TYPE_OMAP,
            &body,
        )
        .expect("write empty fixed omap tree");
    }

    fn write_empty_physical_tree(disc: &mut RepairSession<'_>, paddr: u64) {
        object::write_object(
            disc,
            paddr,
            paddr,
            INITIAL_XID,
            TYPE_BTREE | OBJ_PHYSICAL,
            TYPE_FS_NUM,
            &empty_leaf_body(disc.block_size() as usize),
        )
        .expect("write empty physical tree");
    }

    struct VolumeFixture {
        volume_oid: u64,
        volume_paddr: u64,
        snap_meta_paddr: u64,
    }

    fn build_unsealed_volume(disc: &mut RepairSession<'_>) -> VolumeFixture {
        build_volume(disc, false)
    }

    fn build_sealed_volume(disc: &mut RepairSession<'_>) -> VolumeFixture {
        build_volume(disc, true)
    }

    fn build_volume(disc: &mut RepairSession<'_>, sealed: bool) -> VolumeFixture {
        let volume_oid: u64 = 0x9000;
        let integrity_meta_oid: u64 = 0x9001;
        let fs_tree_oid: u64 = 0x9002;

        let vol_omap_tree_paddr = spaceman::allocate(disc, LAYOUT.spaceman, INITIAL_XID).unwrap();
        write_empty_fixed_omap_tree(disc, vol_omap_tree_paddr);
        let vol_omap_paddr = spaceman::allocate(disc, LAYOUT.spaceman, INITIAL_XID).unwrap();
        let mut vol_omap_body = vec![0u8; BLOCK_SIZE as usize - OBJ_PHYS_BYTES];
        vol_omap_body
            [OM_TREE_TYPE_OFFSET - OBJ_PHYS_BYTES..OM_TREE_TYPE_OFFSET - OBJ_PHYS_BYTES + 4]
            .copy_from_slice(&(TYPE_BTREE | OBJ_PHYSICAL).to_le_bytes());
        vol_omap_body[OM_TREE_OID_OFFSET - OBJ_PHYS_BYTES..OM_TREE_OID_OFFSET - OBJ_PHYS_BYTES + 8]
            .copy_from_slice(&vol_omap_tree_paddr.to_le_bytes());
        object::write_object(
            disc,
            vol_omap_paddr,
            vol_omap_paddr,
            INITIAL_XID,
            TS_TYPE_OMAP | OBJ_PHYSICAL,
            0,
            &vol_omap_body,
        )
        .expect("write volume omap");

        let extentref_paddr = spaceman::allocate(disc, LAYOUT.spaceman, INITIAL_XID).unwrap();
        write_empty_physical_tree(disc, extentref_paddr);
        omap::upsert(
            disc,
            vol_omap_tree_paddr,
            fs_tree_oid,
            INITIAL_XID,
            extentref_paddr,
            INITIAL_XID,
        )
        .expect("omap entry for fs tree");

        if sealed {
            let integrity_meta_paddr =
                spaceman::allocate(disc, LAYOUT.spaceman, INITIAL_XID).unwrap();
            let seal_hash = [0xABu8; 32];
            let mut im_body = vec![0u8; BLOCK_SIZE as usize - OBJ_PHYS_BYTES];
            im_body[IM_VERSION_OFFSET - OBJ_PHYS_BYTES..IM_VERSION_OFFSET - OBJ_PHYS_BYTES + 4]
                .copy_from_slice(&2u32.to_le_bytes());
            im_body[IM_HASH_TYPE_OFFSET - OBJ_PHYS_BYTES..IM_HASH_TYPE_OFFSET - OBJ_PHYS_BYTES + 4]
                .copy_from_slice(&1u32.to_le_bytes());
            let root_hash_offset: u32 = (IM_BROKEN_XID_OFFSET + 8) as u32;
            im_body[IM_ROOT_HASH_OFFSET_OFFSET - OBJ_PHYS_BYTES
                ..IM_ROOT_HASH_OFFSET_OFFSET - OBJ_PHYS_BYTES + 4]
                .copy_from_slice(&root_hash_offset.to_le_bytes());
            let hash_at = root_hash_offset as usize - OBJ_PHYS_BYTES;
            im_body[hash_at..hash_at + 32].copy_from_slice(&seal_hash);
            object::write_object(
                disc,
                integrity_meta_paddr,
                integrity_meta_oid,
                INITIAL_XID,
                TYPE_INTEGRITY_META | OBJ_VIRTUAL,
                0,
                &im_body,
            )
            .expect("write integrity metadata");
            omap::upsert(
                disc,
                vol_omap_tree_paddr,
                integrity_meta_oid,
                INITIAL_XID,
                integrity_meta_paddr,
                INITIAL_XID,
            )
            .expect("omap entry for integrity metadata");
        }

        let snap_meta_paddr = spaceman::allocate(disc, LAYOUT.spaceman, INITIAL_XID).unwrap();
        write_empty_physical_tree(disc, snap_meta_paddr);

        let volume_paddr = spaceman::allocate(disc, LAYOUT.spaceman, INITIAL_XID).unwrap();
        let mut vol_body = vec![0u8; BLOCK_SIZE as usize - OBJ_PHYS_BYTES];
        vol_body[APSB_MAGIC_OFFSET - OBJ_PHYS_BYTES..APSB_MAGIC_OFFSET - OBJ_PHYS_BYTES + 4]
            .copy_from_slice(&APFS_MAGIC.to_le_bytes());
        if sealed {
            vol_body[0x38 - OBJ_PHYS_BYTES..0x38 - OBJ_PHYS_BYTES + 8]
                .copy_from_slice(&0x20u64.to_le_bytes());
            vol_body[APSB_INTEGRITY_META_OID_OFFSET - OBJ_PHYS_BYTES
                ..APSB_INTEGRITY_META_OID_OFFSET - OBJ_PHYS_BYTES + 8]
                .copy_from_slice(&integrity_meta_oid.to_le_bytes());
        }
        vol_body[0x80 - OBJ_PHYS_BYTES..0x80 - OBJ_PHYS_BYTES + 8]
            .copy_from_slice(&vol_omap_paddr.to_le_bytes());
        vol_body[0x88 - OBJ_PHYS_BYTES..0x88 - OBJ_PHYS_BYTES + 8]
            .copy_from_slice(&fs_tree_oid.to_le_bytes());
        vol_body[APSB_EXTENTREF_TREE_OID_OFFSET - OBJ_PHYS_BYTES
            ..APSB_EXTENTREF_TREE_OID_OFFSET - OBJ_PHYS_BYTES + 8]
            .copy_from_slice(&extentref_paddr.to_le_bytes());
        vol_body[APSB_SNAP_META_TREE_OID_OFFSET - OBJ_PHYS_BYTES
            ..APSB_SNAP_META_TREE_OID_OFFSET - OBJ_PHYS_BYTES + 8]
            .copy_from_slice(&snap_meta_paddr.to_le_bytes());
        vol_body[0xF0 - OBJ_PHYS_BYTES..0x100 - OBJ_PHYS_BYTES].copy_from_slice(&[0x22u8; 16]);
        vol_body[0x2C0 - OBJ_PHYS_BYTES..0x2C0 - OBJ_PHYS_BYTES + 12]
            .copy_from_slice(b"Macintosh HD");
        object::write_object(
            disc,
            volume_paddr,
            volume_oid,
            INITIAL_XID,
            TYPE_FS | OBJ_VIRTUAL,
            0,
            &vol_body,
        )
        .expect("write volume superblock");

        omap::upsert(
            disc,
            LAYOUT.omap_tree_root,
            volume_oid,
            INITIAL_XID,
            volume_paddr,
            INITIAL_XID,
        )
        .expect("container omap entry for volume");
        object::read_modify_write::<std::convert::Infallible>(disc, LAYOUT.nxsb, |block| {
            block[0xB4..0xB8].copy_from_slice(&1u32.to_le_bytes());
            block[0xB8..0xC0].copy_from_slice(&volume_oid.to_le_bytes());
            Ok(())
        })
        .expect("wire volume into container superblock");

        VolumeFixture {
            volume_oid,
            volume_paddr,
            snap_meta_paddr,
        }
    }

    fn read_seals_bytes(bytes: &[u8]) -> ContainerSeals {
        let mut source = SliceBlocks::new(bytes, BLOCK_SIZE);
        read_container_seals(&mut source).expect("container seals resolve")
    }

    fn apply(
        image: &mut crate::repair_writer::disc::MemoryImage,
        volume_paddr: u64,
    ) -> Result<(), String> {
        apply_missing_root_snapshot(
            image,
            0,
            BLOCK_SIZE,
            crate::repair_writer::object::test_support::BLOCK_COUNT,
            volume_paddr,
        )
    }

    fn block_bytes(bytes: &[u8], paddr: u64) -> Vec<u8> {
        let at = paddr as usize * BLOCK_SIZE as usize;
        bytes[at..at + BLOCK_SIZE as usize].to_vec()
    }

    fn published_objects(bytes: &[u8], snap_meta_paddr: u64, volume_paddr: u64) -> Vec<Vec<u8>> {
        [
            LAYOUT.nxsb,
            LAYOUT.checkpoint_map,
            LAYOUT.reaper,
            LAYOUT.spaceman,
            LAYOUT.cib,
            LAYOUT.bitmap,
            LAYOUT.omap,
            LAYOUT.omap_tree_root,
            snap_meta_paddr,
            volume_paddr,
        ]
        .into_iter()
        .map(|paddr| block_bytes(bytes, paddr))
        .collect()
    }

    struct FailAfter<'a> {
        inner: &'a mut MemoryImage,
        remaining: usize,
    }

    impl ImageIo for FailAfter<'_> {
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), OpsError> {
            self.inner.read_at(offset, buf)
        }

        fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), OpsError> {
            if self.remaining == 0 {
                return Err(OpsError::Message("injected write failure".into()));
            }
            self.remaining -= 1;
            self.inner.write_at(offset, data)
        }
    }

    #[test]
    fn unsealed_volume_with_no_snapshot_gets_a_root_prefixed_name() {
        let mut image = open();
        let fixture = {
            let mut disc = session(&mut image);
            build_unsealed_volume(&mut disc)
        };
        apply(&mut image, fixture.volume_paddr).expect("apply snapshot");

        let seals = read_seals_bytes(&image.bytes);
        let volume = seals
            .volumes
            .iter()
            .find(|volume| volume.oid == fixture.volume_oid)
            .expect("volume present");
        let name = volume
            .snapshots
            .root_snapshot_name()
            .expect("root snapshot name");
        assert!(name.starts_with(ROOT_SNAPSHOT_PREFIX));
        assert_eq!(volume.snapshots.declared_count, 1);
        assert_eq!(volume.snapshots.snapshots.len(), 1);
        let snap = &volume.snapshots.snapshots[0];
        assert_eq!(snap.name, name);
        assert_eq!(volume.root_to_xid, snap.xid);
        assert_ne!(volume.root_to_xid, 0);
        assert_eq!(volume.snapshots.xid_for_name(name), Some(snap.xid));
        assert_eq!(snap.inum, 0);
        assert_eq!(snap.flags, 0);
    }

    #[test]
    fn applying_twice_is_idempotent() {
        let mut image = open();
        let fixture = {
            let mut disc = session(&mut image);
            build_unsealed_volume(&mut disc)
        };
        apply(&mut image, fixture.volume_paddr).expect("first apply");
        let after_first = image.bytes.clone();
        apply(&mut image, fixture.volume_paddr).expect("second apply");
        assert_eq!(
            after_first, image.bytes,
            "second apply must not write when the snapshot is already rooted"
        );

        let seals = read_seals_bytes(&image.bytes);
        let volume = seals
            .volumes
            .iter()
            .find(|volume| volume.oid == fixture.volume_oid)
            .expect("volume present");
        assert_eq!(volume.snapshots.declared_count, 1);
        assert_eq!(volume.snapshots.names.len(), 1);
    }

    #[test]
    fn existing_name_with_unset_root_to_xid_is_rooted_without_a_second_snapshot() {
        let mut image = open();
        let fixture = {
            let mut disc = session(&mut image);
            build_unsealed_volume(&mut disc)
        };
        apply(&mut image, fixture.volume_paddr).expect("first apply");

        let seals = read_seals_bytes(&image.bytes);
        let volume = seals
            .volumes
            .iter()
            .find(|v| v.oid == fixture.volume_oid)
            .expect("volume");
        let live_paddr = volume.paddr;
        let snap_xid = volume.root_to_xid;
        let name = volume.snapshots.root_snapshot_name().unwrap().to_string();
        {
            let mut disc = session(&mut image);
            let mut sb = vec![0u8; BLOCK_SIZE as usize];
            disc.read_block(live_paddr, &mut sb)
                .expect("read live volume");
            sb[APSB_ROOT_TO_XID_OFFSET..APSB_ROOT_TO_XID_OFFSET + 8]
                .copy_from_slice(&0u64.to_le_bytes());
            fletcher64_seal(&mut sb);
            disc.write_block(live_paddr, &sb)
                .expect("clear root_to_xid");
        }

        let seals_cleared = read_seals_bytes(&image.bytes);
        let volume_cleared = seals_cleared
            .volumes
            .iter()
            .find(|v| v.oid == fixture.volume_oid)
            .expect("volume");
        assert_eq!(volume_cleared.root_to_xid, 0);
        assert_eq!(volume_cleared.snapshots.xid_for_name(&name), Some(snap_xid));

        apply(&mut image, live_paddr).expect("root existing snapshot");

        let final_seals = read_seals_bytes(&image.bytes);
        let final_volume = final_seals
            .volumes
            .iter()
            .find(|v| v.oid == fixture.volume_oid)
            .expect("volume");
        assert_eq!(final_volume.root_to_xid, snap_xid);
        assert_eq!(final_volume.snapshots.declared_count, 1);
        assert_eq!(final_volume.snapshots.names.len(), 1);
    }

    #[test]
    fn non_leaf_container_omap_is_refused_and_the_disc_is_unchanged() {
        let mut image = open();
        let fixture = {
            let mut disc = session(&mut image);
            let fixture = build_unsealed_volume(&mut disc);
            object::read_modify_write::<std::convert::Infallible>(
                &mut disc,
                LAYOUT.omap_tree_root,
                |block| {
                    let flags: u16 = BTNODE_ROOT | BTNODE_FIXED_KV_SIZE;
                    block[OBJ_PHYS_BYTES..OBJ_PHYS_BYTES + 2].copy_from_slice(&flags.to_le_bytes());
                    Ok(())
                },
            )
            .expect("mark container omap as not a leaf");
            fixture
        };
        let before = image.bytes.clone();
        let error = apply(&mut image, fixture.volume_paddr).expect_err("must refuse");
        assert!(
            error.contains("not a leaf")
                || error.contains("index node")
                || error.contains("malformed"),
            "got {error}"
        );
        assert_eq!(before, image.bytes);
    }

    #[test]
    fn a_write_failure_after_preparing_objects_does_not_publish() {
        let mut image = open();
        let fixture = {
            let mut disc = session(&mut image);
            build_unsealed_volume(&mut disc)
        };
        let before = image.bytes.clone();
        let published = published_objects(&before, fixture.snap_meta_paddr, fixture.volume_paddr);
        let mut succeeded = false;
        for remaining in 0..64 {
            let mut attempt = MemoryImage {
                bytes: before.clone(),
            };
            let result = {
                let mut failing = FailAfter {
                    inner: &mut attempt,
                    remaining,
                };
                apply_missing_root_snapshot(
                    &mut failing,
                    0,
                    BLOCK_SIZE,
                    crate::repair_writer::object::test_support::BLOCK_COUNT,
                    fixture.volume_paddr,
                )
            };
            match result {
                Ok(()) => {
                    succeeded = true;
                    let seals = read_seals_bytes(&attempt.bytes);
                    let volume = seals
                        .volumes
                        .iter()
                        .find(|volume| volume.oid == fixture.volume_oid)
                        .expect("volume present");
                    assert_eq!(volume.snapshots.declared_count, 1);
                    assert_eq!(volume.snapshots.snapshots.len(), 1);
                    break;
                }
                Err(_) => {
                    assert_eq!(
                        published_objects(
                            &attempt.bytes,
                            fixture.snap_meta_paddr,
                            fixture.volume_paddr
                        ),
                        published
                    );
                }
            }
        }
        assert!(
            succeeded,
            "the leaf-omap path must still succeed when writes are allowed"
        );
    }

    #[test]
    fn tree_not_single_leaf_is_reported_and_the_disc_is_unchanged() {
        let mut image = open();
        let fixture = {
            let mut disc = session(&mut image);
            let fixture = build_unsealed_volume(&mut disc);
            object::read_modify_write::<std::convert::Infallible>(
                &mut disc,
                fixture.snap_meta_paddr,
                |block| {
                    let flags: u16 = BTNODE_ROOT;
                    block[OBJ_PHYS_BYTES..OBJ_PHYS_BYTES + 2].copy_from_slice(&flags.to_le_bytes());
                    Ok(())
                },
            )
            .expect("mark tree as not a leaf");
            fixture
        };
        let before = image.bytes.clone();
        let error = apply(&mut image, fixture.volume_paddr).expect_err("must refuse");
        assert!(
            error.contains("not a single node") || error.contains("TreeNotSingleLeaf"),
            "got {error}"
        );
        assert_eq!(before, image.bytes);
    }

    #[test]
    fn a_full_tree_is_reported_and_the_disc_is_unchanged() {
        let mut image = open();
        let fixture = {
            let mut disc = session(&mut image);
            let fixture = build_unsealed_volume(&mut disc);
            object::read_modify_write::<std::convert::Infallible>(
                &mut disc,
                fixture.snap_meta_paddr,
                |block| {
                    block[OBJ_PHYS_BYTES + 0x0A..OBJ_PHYS_BYTES + 0x0C]
                        .copy_from_slice(&8u16.to_le_bytes());
                    Ok(())
                },
            )
            .expect("shrink toc to one slot");
            fixture
        };
        let before = image.bytes.clone();
        let error = apply(&mut image, fixture.volume_paddr).expect_err("must refuse");
        assert!(
            error.contains("no room") || error.contains("TreeFull"),
            "got {error}"
        );
        assert_eq!(before, image.bytes);
    }

    #[test]
    fn sealed_volume_uses_apples_root_hash_name() {
        let mut image = open();
        let fixture = {
            let mut disc = session(&mut image);
            build_sealed_volume(&mut disc)
        };
        apply(&mut image, fixture.volume_paddr).expect("apply snapshot");
        let seals = read_seals_bytes(&image.bytes);
        let volume = seals
            .volumes
            .iter()
            .find(|volume| volume.oid == fixture.volume_oid)
            .expect("volume present");
        let expected = volume.seal.as_ref().expect("seal").root_snapshot_name();
        assert_eq!(
            volume.snapshots.root_snapshot_name(),
            Some(expected.as_str())
        );
        assert_eq!(volume.root_to_xid, volume.snapshots.snapshots[0].xid);
    }

    #[test]
    fn snapshot_name_key_pins_the_object_id_the_kernel_searches_for() {
        let name = "com.apple.os.update-919AAEAD952A4E4B8C0605740AF63C73";
        let (key, value) = snapshot_name_record(name, 0x2B0);
        assert_eq!(u64_at(&key, 0), 0xBFFF_FFFF_FFFF_FFFF);
        assert_eq!(key.len(), 10 + name.len() + 1);
        assert_eq!(u16_at(&key, 8) as usize, name.len() + 1);
        assert_eq!(&key[10..10 + name.len()], name.as_bytes());
        assert_eq!(*key.last().unwrap(), 0);
        assert_eq!(value, 0x2B0u64.to_le_bytes().to_vec());
    }

    #[test]
    fn a_fresh_snapshot_metadata_tree_carries_btree_info_a_mount_requires() {
        let mut block = vec![0u8; OBJ_PHYS_BYTES];
        block.extend_from_slice(&empty_leaf_body(BLOCK_SIZE as usize));
        assert_eq!(block.len(), BLOCK_SIZE as usize);
        let info_at = BLOCK_SIZE as usize - BTREE_INFO_BYTES;
        assert_eq!(
            u32_at(&block, info_at + BT_NODE_SIZE_OFFSET) as usize,
            BLOCK_SIZE as usize
        );
        assert_eq!(u64_at(&block, info_at + BT_NODE_COUNT_OFFSET), 1);
        assert_eq!(u16_at(&block, OBJ_PHYS_BYTES + 0x08), 0);
    }

    #[test]
    fn chosen_label_is_deterministic_and_starts_with_the_root_prefix() {
        let uuid = [0x11u8; 16];
        let a = chosen_label(&uuid, 42);
        let b = chosen_label(&uuid, 42);
        assert_eq!(a, b);
        assert!(a.starts_with(ROOT_SNAPSHOT_PREFIX));
        assert_ne!(a, chosen_label(&uuid, 43));
    }
}
