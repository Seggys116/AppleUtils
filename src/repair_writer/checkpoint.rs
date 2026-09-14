use crate::apfs_image::{NX_MAGIC, fletcher64_seal};
use crate::apfs_verify::{OBJ_TYPE_MASK, TYPE_NX_SUPERBLOCK, u32_at, u64_at};

use super::disc::{DiscError, RepairSession};
use super::object::{self, ObjectWriteError};

const NX_BLOCK_SIZE_OFFSET: usize = 0x24;
const NX_NEXT_XID_OFFSET: usize = 0x60;
const NX_OMAP_OID_OFFSET: usize = 0xA0;
const NX_XP_DESC_BLOCKS_OFFSET: usize = 0x68;
const NX_XP_DATA_BLOCKS_OFFSET: usize = 0x6C;
const NX_XP_DESC_BASE_OFFSET: usize = 0x70;
const NX_XP_DATA_BASE_OFFSET: usize = 0x78;
const NX_XP_DESC_NEXT_OFFSET: usize = 0x80;
const NX_XP_DATA_NEXT_OFFSET: usize = 0x84;
const NX_XP_DESC_INDEX_OFFSET: usize = 0x88;
const NX_XP_DESC_LEN_OFFSET: usize = 0x8C;
const NX_XP_DATA_INDEX_OFFSET: usize = 0x90;
const NX_XP_DATA_LEN_OFFSET: usize = 0x94;

const CPM_FLAGS_OFFSET: usize = 0x20;
const CPM_COUNT_OFFSET: usize = 0x24;
const CPM_ENTRIES_OFFSET: usize = 0x28;
const CPM_ENTRY_BYTES: usize = 40;
const CPM_FLAGS_VALUE: u32 = 1;

const OBJ_EPHEMERAL: u32 = 0x8000_0000;
const OBJ_PHYSICAL: u32 = 0x4000_0000;
const TYPE_CHECKPOINT_MAP: u32 = 0x0C;

#[cfg(test)]
const TYPE_NX_REAPER: u32 = 0x11;
#[cfg(test)]
const TYPE_SPACEMAN: u32 = 0x05;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EphemeralObject {
    pub oid: u64,
    pub o_type: u32,
    pub subtype: u32,
    pub paddr: u64,
}

#[derive(Debug, Clone)]
pub struct AppendedCheckpoint {
    pub superblock_paddr: u64,
    pub ephemeral_objects: Vec<EphemeralObject>,
}

#[derive(Debug)]
pub enum CheckpointError {
    Disc(DiscError),
    Write(ObjectWriteError),
    Malformed(&'static str),
    NotInPublishedCheckpoint { oid: u64 },
    MultiBlockEphemeralObject { oid: u64, size: u32 },
    RingFull,
}

impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disc(error) => write!(f, "disc error: {error}"),
            Self::Write(error) => write!(f, "{error}"),
            Self::Malformed(reason) => write!(f, "container superblock is malformed: {reason}"),
            Self::NotInPublishedCheckpoint { oid } => write!(
                f,
                "ephemeral object {oid} is not named by the currently published checkpoint, so \
                 its mapping size cannot be read; this writer republishes an existing ephemeral \
                 set, it does not place a new object"
            ),
            Self::MultiBlockEphemeralObject { oid, size } => write!(
                f,
                "ephemeral object {oid} occupies {size} bytes, more than one block; relocating a \
                 multi-block ephemeral object is out of scope for this writer"
            ),
            Self::RingFull => write!(
                f,
                "the checkpoint descriptor or data ring has no room for a new checkpoint without \
                 overwriting the one currently mounted"
            ),
        }
    }
}

impl std::error::Error for CheckpointError {}

impl From<DiscError> for CheckpointError {
    fn from(error: DiscError) -> Self {
        Self::Disc(error)
    }
}

impl From<ObjectWriteError> for CheckpointError {
    fn from(error: ObjectWriteError) -> Self {
        Self::Write(error)
    }
}

struct Geometry {
    block_size: u32,
    descriptor_base: u64,
    descriptor_blocks: u64,
    data_base: u64,
    data_blocks: u64,
    descriptor_index: u64,
    descriptor_len: u64,
    data_index: u64,
    data_len: u64,
}

fn read_geometry(superblock: &[u8]) -> Result<Geometry, CheckpointError> {
    let geometry = Geometry {
        block_size: u32_at(superblock, NX_BLOCK_SIZE_OFFSET),
        descriptor_base: u64_at(superblock, NX_XP_DESC_BASE_OFFSET),
        descriptor_blocks: u64::from(u32_at(superblock, NX_XP_DESC_BLOCKS_OFFSET)),
        data_base: u64_at(superblock, NX_XP_DATA_BASE_OFFSET),
        data_blocks: u64::from(u32_at(superblock, NX_XP_DATA_BLOCKS_OFFSET)),
        descriptor_index: u64::from(u32_at(superblock, NX_XP_DESC_INDEX_OFFSET)),
        descriptor_len: u64::from(u32_at(superblock, NX_XP_DESC_LEN_OFFSET)),
        data_index: u64::from(u32_at(superblock, NX_XP_DATA_INDEX_OFFSET)),
        data_len: u64::from(u32_at(superblock, NX_XP_DATA_LEN_OFFSET)),
    };
    if geometry.descriptor_blocks == 0 {
        return Err(CheckpointError::Malformed(
            "checkpoint descriptor ring has zero blocks",
        ));
    }
    if geometry.data_blocks == 0 {
        return Err(CheckpointError::Malformed(
            "checkpoint data ring has zero blocks",
        ));
    }
    if geometry.descriptor_len == 0 || geometry.descriptor_len > geometry.descriptor_blocks {
        return Err(CheckpointError::Malformed(
            "the published checkpoint's descriptor window does not fit the ring",
        ));
    }
    if geometry.data_len > geometry.data_blocks {
        return Err(CheckpointError::Malformed(
            "the published checkpoint's data window does not fit the ring",
        ));
    }
    Ok(geometry)
}

fn published_mapping_sizes(
    disc: &mut RepairSession<'_>,
    geometry: &Geometry,
) -> Result<Vec<(u64, u32)>, CheckpointError> {
    let block_size = disc.block_size() as usize;
    let mut sizes = Vec::new();
    for slot in 0..geometry.descriptor_len {
        let paddr = geometry.descriptor_base
            + (geometry.descriptor_index + slot) % geometry.descriptor_blocks;
        let mut block = vec![0u8; block_size];
        disc.read_block(paddr, &mut block)?;
        if u32_at(&block, object::TYPE_OFFSET) & OBJ_TYPE_MASK != TYPE_CHECKPOINT_MAP {
            continue;
        }
        let count = u32_at(&block, CPM_COUNT_OFFSET) as usize;
        let capacity = (block_size - CPM_ENTRIES_OFFSET) / CPM_ENTRY_BYTES;
        if count > capacity {
            return Err(CheckpointError::Malformed(
                "a published checkpoint mapping claims more entries than it can hold",
            ));
        }
        for index in 0..count {
            let at = CPM_ENTRIES_OFFSET + index * CPM_ENTRY_BYTES;
            sizes.push((u64_at(&block, at + 24), u32_at(&block, at + 8)));
        }
    }
    Ok(sizes)
}

/// Read the currently published checkpoint's ephemeral set, including each
/// object's on-disk `o_type`/`subtype`. Needed by snapshot repair so the
/// caller does not have to pass `verify_container`'s ephemeral list.
pub fn collect_ephemeral_objects(
    disc: &mut RepairSession<'_>,
    superblock_paddr: u64,
) -> Result<Vec<EphemeralObject>, CheckpointError> {
    let block_size = disc.block_size() as usize;
    let mut sb = vec![0u8; block_size];
    disc.read_block(superblock_paddr, &mut sb)?;
    if u32_at(&sb, 0x20) != NX_MAGIC {
        return Err(CheckpointError::Malformed(
            "no NXSB magic at the given superblock address",
        ));
    }
    let geometry = read_geometry(&sb)?;
    let mut objects = Vec::new();
    for slot in 0..geometry.descriptor_len {
        let paddr = geometry.descriptor_base
            + (geometry.descriptor_index + slot) % geometry.descriptor_blocks;
        let mut map = vec![0u8; block_size];
        disc.read_block(paddr, &mut map)?;
        if u32_at(&map, object::TYPE_OFFSET) & OBJ_TYPE_MASK != TYPE_CHECKPOINT_MAP {
            continue;
        }
        let count = u32_at(&map, CPM_COUNT_OFFSET) as usize;
        let capacity = (block_size - CPM_ENTRIES_OFFSET) / CPM_ENTRY_BYTES;
        if count > capacity {
            return Err(CheckpointError::Malformed(
                "a published checkpoint mapping claims more entries than it can hold",
            ));
        }
        for index in 0..count {
            let at = CPM_ENTRIES_OFFSET + index * CPM_ENTRY_BYTES;
            let o_type = u32_at(&map, at);
            let subtype = u32_at(&map, at + 4);
            let oid = u64_at(&map, at + 24);
            let mapped = u64_at(&map, at + 32);
            let mut object = vec![0u8; block_size];
            disc.read_block(mapped, &mut object)?;
            if u64_at(&object, object::OID_OFFSET) != oid
                || u32_at(&object, object::TYPE_OFFSET) != o_type
                || u32_at(&object, object::SUBTYPE_OFFSET) != subtype
            {
                return Err(CheckpointError::Malformed(
                    "an ephemeral object's own header disagrees with its checkpoint mapping",
                ));
            }
            objects.push(EphemeralObject {
                oid,
                o_type,
                subtype,
                paddr: mapped,
            });
        }
    }
    Ok(objects)
}

#[derive(Clone, Debug, Default)]
pub struct CheckpointPublish {
    pub omap_oid: Option<u64>,
    pub ephemeral_bodies: Vec<(u64, Vec<u8>)>,
}

pub fn append_checkpoint(
    disc: &mut RepairSession<'_>,
    old_superblock_paddr: u64,
    new_xid: u64,
    ephemeral_objects: &[EphemeralObject],
) -> Result<AppendedCheckpoint, CheckpointError> {
    append_with(
        disc,
        old_superblock_paddr,
        new_xid,
        ephemeral_objects,
        &CheckpointPublish::default(),
    )
}

pub fn append_with(
    disc: &mut RepairSession<'_>,
    old_superblock_paddr: u64,
    new_xid: u64,
    ephemeral_objects: &[EphemeralObject],
    publish: &CheckpointPublish,
) -> Result<AppendedCheckpoint, CheckpointError> {
    let block_size = disc.block_size();
    let mut old_sb = vec![0u8; block_size as usize];
    disc.read_block(old_superblock_paddr, &mut old_sb)?;

    if u32_at(&old_sb, 0x20) != NX_MAGIC {
        return Err(CheckpointError::Malformed(
            "no NXSB magic at the given superblock address",
        ));
    }
    let old_oid = u64_at(&old_sb, object::OID_OFFSET);
    let old_o_type = u32_at(&old_sb, object::TYPE_OFFSET);
    let old_subtype = u32_at(&old_sb, object::SUBTYPE_OFFSET);
    if old_o_type & OBJ_TYPE_MASK != TYPE_NX_SUPERBLOCK {
        return Err(CheckpointError::Malformed(
            "object at the given address is not a container superblock",
        ));
    }
    let geometry = read_geometry(&old_sb)?;
    if geometry.block_size != block_size {
        return Err(CheckpointError::Malformed(
            "the superblock's own block size disagrees with the disc's",
        ));
    }

    for entry in ephemeral_objects {
        if entry.paddr < geometry.data_base
            || entry.paddr >= geometry.data_base + geometry.data_blocks
        {
            return Err(CheckpointError::Malformed(
                "an ephemeral object's address falls outside the checkpoint data area",
            ));
        }
    }

    let published = published_mapping_sizes(disc, &geometry)?;
    let mut sizes = Vec::with_capacity(ephemeral_objects.len());
    for entry in ephemeral_objects {
        let size = published
            .iter()
            .find(|(oid, _)| *oid == entry.oid)
            .map(|(_, size)| *size)
            .ok_or(CheckpointError::NotInPublishedCheckpoint { oid: entry.oid })?;
        if size != block_size {
            return Err(CheckpointError::MultiBlockEphemeralObject {
                oid: entry.oid,
                size,
            });
        }
        sizes.push(size);
    }

    let mut bodies = Vec::with_capacity(ephemeral_objects.len());
    for entry in ephemeral_objects {
        let mut block = if let Some((_, body)) = publish
            .ephemeral_bodies
            .iter()
            .find(|(oid, _)| *oid == entry.oid)
        {
            if body.len() != block_size as usize {
                return Err(CheckpointError::Malformed(
                    "a replacement ephemeral body does not match the container block size",
                ));
            }
            body.clone()
        } else {
            let mut block = vec![0u8; block_size as usize];
            disc.read_block(entry.paddr, &mut block)?;
            block
        };
        if u64_at(&block, object::OID_OFFSET) != entry.oid
            || u32_at(&block, object::TYPE_OFFSET) != entry.o_type
            || u32_at(&block, object::SUBTYPE_OFFSET) != entry.subtype
        {
            return Err(CheckpointError::Malformed(
                "an ephemeral object's own header disagrees with the identity given for it",
            ));
        }
        block[object::XID_OFFSET..object::XID_OFFSET + 8].copy_from_slice(&new_xid.to_le_bytes());
        fletcher64_seal(&mut block);
        bodies.push(block);
    }

    let capacity_per_map = (block_size as usize - CPM_ENTRIES_OFFSET) / CPM_ENTRY_BYTES;
    let map_block_count = if ephemeral_objects.is_empty() {
        1
    } else {
        ephemeral_objects.len().div_ceil(capacity_per_map)
    } as u64;

    let descriptor_len = map_block_count + 1;
    if descriptor_len + geometry.descriptor_len > geometry.descriptor_blocks {
        return Err(CheckpointError::RingFull);
    }
    let new_descriptor_index =
        (geometry.descriptor_index + geometry.descriptor_len) % geometry.descriptor_blocks;
    let ring_slot = |offset: u64| -> u64 {
        geometry.descriptor_base + (new_descriptor_index + offset) % geometry.descriptor_blocks
    };

    let data_len = ephemeral_objects.len() as u64;
    if data_len + geometry.data_len > geometry.data_blocks {
        return Err(CheckpointError::RingFull);
    }
    let new_data_index = (geometry.data_index + geometry.data_len) % geometry.data_blocks;
    let data_slot = |offset: u64| -> u64 {
        geometry.data_base + (new_data_index + offset) % geometry.data_blocks
    };

    let mut relocated = Vec::with_capacity(ephemeral_objects.len());
    for (offset, (entry, body)) in ephemeral_objects.iter().zip(bodies.iter()).enumerate() {
        let paddr = data_slot(offset as u64);
        disc.write_block(paddr, body)?;
        relocated.push(EphemeralObject { paddr, ..*entry });
    }

    let mapped: Vec<(EphemeralObject, u32)> = relocated
        .iter()
        .copied()
        .zip(sizes.iter().copied())
        .collect();
    for (map_index, chunk) in mapped.chunks(capacity_per_map.max(1)).enumerate() {
        write_checkpoint_map(
            disc,
            ring_slot(map_index as u64),
            new_xid,
            chunk,
            block_size,
        )?;
    }
    if mapped.is_empty() {
        write_checkpoint_map(disc, ring_slot(0), new_xid, &[], block_size)?;
    }

    let new_superblock_paddr = ring_slot(map_block_count);
    let mut sb = old_sb.clone();
    put_u32(
        &mut sb,
        NX_XP_DESC_INDEX_OFFSET,
        new_descriptor_index as u32,
    );
    put_u32(&mut sb, NX_XP_DESC_LEN_OFFSET, descriptor_len as u32);
    put_u32(&mut sb, NX_XP_DATA_INDEX_OFFSET, new_data_index as u32);
    put_u32(&mut sb, NX_XP_DATA_LEN_OFFSET, data_len as u32);
    put_u32(
        &mut sb,
        NX_XP_DESC_NEXT_OFFSET,
        ((new_descriptor_index + descriptor_len) % geometry.descriptor_blocks) as u32,
    );
    put_u32(
        &mut sb,
        NX_XP_DATA_NEXT_OFFSET,
        ((new_data_index + data_len) % geometry.data_blocks) as u32,
    );
    put_u64(&mut sb, NX_NEXT_XID_OFFSET, new_xid.saturating_add(1));
    if let Some(omap_oid) = publish.omap_oid {
        put_u64(&mut sb, NX_OMAP_OID_OFFSET, omap_oid);
    }
    object::write_object(
        disc,
        new_superblock_paddr,
        old_oid,
        new_xid,
        old_o_type,
        old_subtype,
        &sb[object::OBJ_PHYS_BYTES..],
    )?;

    Ok(AppendedCheckpoint {
        superblock_paddr: new_superblock_paddr,
        ephemeral_objects: relocated,
    })
}

fn write_checkpoint_map(
    disc: &mut RepairSession<'_>,
    paddr: u64,
    xid: u64,
    objects: &[(EphemeralObject, u32)],
    block_size: u32,
) -> Result<(), CheckpointError> {
    let mut body = vec![0u8; block_size as usize - object::OBJ_PHYS_BYTES];
    put_u32(
        &mut body,
        CPM_FLAGS_OFFSET - object::OBJ_PHYS_BYTES,
        CPM_FLAGS_VALUE,
    );
    put_u32(
        &mut body,
        CPM_COUNT_OFFSET - object::OBJ_PHYS_BYTES,
        objects.len() as u32,
    );
    for (index, (entry, size)) in objects.iter().enumerate() {
        let at = (CPM_ENTRIES_OFFSET - object::OBJ_PHYS_BYTES) + index * CPM_ENTRY_BYTES;
        put_u32(&mut body, at, entry.o_type);
        put_u32(&mut body, at + 4, entry.subtype);
        put_u32(&mut body, at + 8, *size);
        put_u32(&mut body, at + 12, 0);
        put_u64(&mut body, at + 16, 0);
        put_u64(&mut body, at + 24, entry.oid);
        put_u64(&mut body, at + 32, entry.paddr);
    }
    object::write_object(
        disc,
        paddr,
        paddr,
        xid,
        TYPE_CHECKPOINT_MAP | OBJ_PHYSICAL,
        0,
        &body,
    )?;
    Ok(())
}

fn put_u32(body: &mut [u8], at: usize, value: u32) {
    body[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(body: &mut [u8], at: usize, value: u64) {
    body[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

pub const EPHEMERAL_STORAGE_CLASS: u32 = OBJ_EPHEMERAL;

#[cfg(test)]
pub(crate) mod kernel_checks {
    use super::*;

    const O_OID: usize = 0x08;
    const O_XID: usize = 0x10;
    const O_TYPE: usize = 0x18;
    const O_SUBTYPE: usize = 0x1C;
    const CPM_FLAG_LAST: u32 = 1;

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) enum LoadFailure {
        DescriptorWindowTooShort { descriptor_len: u32 },
        MappedAddress { oid: u64, wanted: u64, got: u64 },
        MappingSize { oid: u64, size: u32 },
        DataWindowOverflow { needed: u64, data_len: u64 },
        ObjectType { oid: u64, wanted: u32, got: u32 },
        ObjectSubtype { oid: u64, wanted: u32, got: u32 },
        ObjectOid { wanted: u64, got: u64 },
        ObjectXid { oid: u64, wanted: u64, got: u64 },
        MapBlockOid { wanted: u64, got: u64 },
        MapBlockType { wanted: u32, got: u32 },
        MapBlockSubtype { got: u32 },
        MapBlockXid { wanted: u64, got: u64 },
        MapBlockLastFlag { is_last: bool, flag: bool },
        MapBlockCount { count: u32, max: u32 },
    }

    fn read(bytes: &[u8], block_size: usize, paddr: u64) -> &[u8] {
        let start = paddr as usize * block_size;
        &bytes[start..start + block_size]
    }

    pub(crate) fn load_checkpoint_data(
        bytes: &[u8],
        block_size: usize,
        superblock_paddr: u64,
    ) -> Result<Vec<(u64, u64)>, LoadFailure> {
        let sb = read(bytes, block_size, superblock_paddr);
        let sb_xid = u64_at(sb, O_XID);
        let descriptor_base = u64_at(sb, NX_XP_DESC_BASE_OFFSET);
        let descriptor_blocks = u64::from(u32_at(sb, NX_XP_DESC_BLOCKS_OFFSET));
        let data_base = u64_at(sb, NX_XP_DATA_BASE_OFFSET);
        let data_blocks = u64::from(u32_at(sb, NX_XP_DATA_BLOCKS_OFFSET));
        let descriptor_index = u64::from(u32_at(sb, NX_XP_DESC_INDEX_OFFSET));
        let descriptor_len = u32_at(sb, NX_XP_DESC_LEN_OFFSET);
        let data_index = u64::from(u32_at(sb, NX_XP_DATA_INDEX_OFFSET));
        let data_len = u64::from(u32_at(sb, NX_XP_DATA_LEN_OFFSET));

        if descriptor_len < 2 {
            return Err(LoadFailure::DescriptorWindowTooShort { descriptor_len });
        }

        let mut cursor = data_index;
        let mut loaded = Vec::new();
        for slot in 0..u64::from(descriptor_len - 1) {
            let map_paddr = descriptor_base + (descriptor_index + slot) % descriptor_blocks;
            let map = read(bytes, block_size, map_paddr);
            let map_type = u32_at(map, O_TYPE);
            if map_type != TYPE_CHECKPOINT_MAP | OBJ_PHYSICAL {
                return Err(LoadFailure::MapBlockType {
                    wanted: TYPE_CHECKPOINT_MAP | OBJ_PHYSICAL,
                    got: map_type,
                });
            }
            let map_subtype = u32_at(map, O_SUBTYPE);
            if map_subtype != 0 {
                return Err(LoadFailure::MapBlockSubtype { got: map_subtype });
            }
            let map_xid = u64_at(map, O_XID);
            if map_xid != sb_xid {
                return Err(LoadFailure::MapBlockXid {
                    wanted: sb_xid,
                    got: map_xid,
                });
            }
            let map_oid = u64_at(map, O_OID);
            if map_oid != map_paddr {
                return Err(LoadFailure::MapBlockOid {
                    wanted: map_paddr,
                    got: map_oid,
                });
            }
            let is_last = slot == u64::from(descriptor_len - 1) - 1;
            let last_flag = u32_at(map, CPM_FLAGS_OFFSET) & CPM_FLAG_LAST != 0;
            if last_flag != is_last {
                return Err(LoadFailure::MapBlockLastFlag {
                    is_last,
                    flag: last_flag,
                });
            }
            let count_raw = u32_at(map, CPM_COUNT_OFFSET);
            let max_count = ((block_size - CPM_ENTRIES_OFFSET) / CPM_ENTRY_BYTES) as u32;
            if count_raw > max_count {
                return Err(LoadFailure::MapBlockCount {
                    count: count_raw,
                    max: max_count,
                });
            }
            let count = count_raw as usize;
            for index in 0..count {
                let at = CPM_ENTRIES_OFFSET + index * CPM_ENTRY_BYTES;
                let cpm_type = u32_at(map, at);
                let cpm_subtype = u32_at(map, at + 4);
                let cpm_size = u32_at(map, at + 8);
                let cpm_oid = u64_at(map, at + 24);
                let cpm_paddr = u64_at(map, at + 32);

                let wanted = data_base + cursor;
                if cpm_paddr != wanted {
                    return Err(LoadFailure::MappedAddress {
                        oid: cpm_oid,
                        wanted,
                        got: cpm_paddr,
                    });
                }
                if cpm_size == 0 || !(cpm_size as usize).is_multiple_of(block_size) {
                    return Err(LoadFailure::MappingSize {
                        oid: cpm_oid,
                        size: cpm_size,
                    });
                }
                let blocks = u64::from(cpm_size).div_ceil(block_size as u64);
                let offset = if cursor >= data_index {
                    cursor - data_index
                } else {
                    cursor + data_blocks - data_index
                };
                if offset >= data_len || offset + blocks > data_len {
                    return Err(LoadFailure::DataWindowOverflow {
                        needed: offset + blocks,
                        data_len,
                    });
                }

                let object = read(bytes, block_size, cpm_paddr);
                let got_type = u32_at(object, O_TYPE);
                if got_type != cpm_type {
                    return Err(LoadFailure::ObjectType {
                        oid: cpm_oid,
                        wanted: cpm_type,
                        got: got_type,
                    });
                }
                let got_subtype = u32_at(object, O_SUBTYPE);
                if got_subtype != cpm_subtype {
                    return Err(LoadFailure::ObjectSubtype {
                        oid: cpm_oid,
                        wanted: cpm_subtype,
                        got: got_subtype,
                    });
                }
                let got_oid = u64_at(object, O_OID);
                if got_oid != cpm_oid {
                    return Err(LoadFailure::ObjectOid {
                        wanted: cpm_oid,
                        got: got_oid,
                    });
                }
                let got_xid = u64_at(object, O_XID);
                if got_xid != sb_xid {
                    return Err(LoadFailure::ObjectXid {
                        oid: cpm_oid,
                        wanted: sb_xid,
                        got: got_xid,
                    });
                }

                loaded.push((cpm_oid, cpm_paddr));
                cursor = (cursor + blocks) % data_blocks;
            }
        }
        Ok(loaded)
    }

    pub(crate) fn best_loadable_checkpoint(bytes: &[u8], block_size: usize) -> Option<(u64, u64)> {
        let zero = read(bytes, block_size, 0);
        let descriptor_base = u64_at(zero, NX_XP_DESC_BASE_OFFSET);
        let descriptor_blocks = u64::from(u32_at(zero, NX_XP_DESC_BLOCKS_OFFSET));
        let mut best: Option<(u64, u64)> = None;
        for slot in 0..descriptor_blocks {
            let paddr = descriptor_base + slot;
            let block = read(bytes, block_size, paddr);
            if u32_at(block, O_TYPE) & OBJ_TYPE_MASK != TYPE_NX_SUPERBLOCK {
                continue;
            }
            if u32_at(block, 0x20) != NX_MAGIC {
                continue;
            }
            if load_checkpoint_data(bytes, block_size, paddr).is_err() {
                continue;
            }
            let xid = u64_at(block, O_XID);
            if best.is_none_or(|(best_xid, _)| xid > best_xid) {
                best = Some((xid, paddr));
            }
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::kernel_checks::{best_loadable_checkpoint, load_checkpoint_data};
    use super::*;
    use crate::repair_writer::object::test_support::{
        BLOCK_SIZE, INITIAL_XID, LAYOUT, REAPER_OID, SPACEMAN_OID, open, session, verify,
    };

    fn current_ephemeral_set() -> Vec<EphemeralObject> {
        vec![
            EphemeralObject {
                oid: REAPER_OID,
                o_type: TYPE_NX_REAPER | OBJ_EPHEMERAL,
                subtype: 0,
                paddr: LAYOUT.reaper,
            },
            EphemeralObject {
                oid: SPACEMAN_OID,
                o_type: TYPE_SPACEMAN | OBJ_EPHEMERAL,
                subtype: 0,
                paddr: LAYOUT.spaceman,
            },
        ]
    }

    fn kernel_load(bytes: &[u8], superblock_paddr: u64) -> Vec<(u64, u64)> {
        load_checkpoint_data(bytes, BLOCK_SIZE as usize, superblock_paddr)
            .expect("the kernel's own checkpoint loader accepts this checkpoint")
    }

    #[test]
    fn the_fixtures_own_published_checkpoint_loads_under_the_kernel_checks() {
        let image = open();
        let loaded = kernel_load(&image.bytes, LAYOUT.nxsb);
        assert_eq!(
            loaded,
            vec![(REAPER_OID, LAYOUT.reaper), (SPACEMAN_OID, LAYOUT.spaceman)]
        );
    }

    #[test]
    fn append_checkpoint_bumps_the_xid_and_still_verifies_clean() {
        let mut image = open();
        let before = verify(&image);
        let appended = {
            let mut disc = session(&mut image);
            append_checkpoint(
                &mut disc,
                LAYOUT.nxsb,
                INITIAL_XID + 1,
                &current_ephemeral_set(),
            )
            .expect("append checkpoint")
        };

        let after = verify(&image);
        assert_eq!(after.xid, INITIAL_XID + 1);
        assert_eq!(after.superblock_paddr, appended.superblock_paddr);
        assert_ne!(appended.superblock_paddr, before.superblock_paddr);
        assert_eq!(after.ephemeral.len(), before.ephemeral.len());
    }

    #[test]
    fn the_appended_checkpoint_loads_under_the_kernels_own_checks() {
        let mut image = open();
        let appended = {
            let mut disc = session(&mut image);
            append_checkpoint(
                &mut disc,
                LAYOUT.nxsb,
                INITIAL_XID + 1,
                &current_ephemeral_set(),
            )
            .expect("append checkpoint")
        };

        let loaded = kernel_load(&image.bytes, appended.superblock_paddr);
        let expected: Vec<(u64, u64)> = appended
            .ephemeral_objects
            .iter()
            .map(|entry| (entry.oid, entry.paddr))
            .collect();
        assert_eq!(loaded, expected);
        assert_eq!(
            best_loadable_checkpoint(&image.bytes, BLOCK_SIZE as usize),
            Some((INITIAL_XID + 1, appended.superblock_paddr))
        );
    }

    #[test]
    fn each_new_mapping_block_self_addresses() {
        let mut image = open();
        let appended = {
            let mut disc = session(&mut image);
            append_checkpoint(
                &mut disc,
                LAYOUT.nxsb,
                INITIAL_XID + 1,
                &current_ephemeral_set(),
            )
            .expect("append checkpoint")
        };

        let sb = &image.bytes[appended.superblock_paddr as usize * BLOCK_SIZE as usize..]
            [..BLOCK_SIZE as usize];
        let descriptor_base = u64_at(sb, NX_XP_DESC_BASE_OFFSET);
        let descriptor_blocks = u64::from(u32_at(sb, NX_XP_DESC_BLOCKS_OFFSET));
        let descriptor_index = u64::from(u32_at(sb, NX_XP_DESC_INDEX_OFFSET));
        let descriptor_len = u32_at(sb, NX_XP_DESC_LEN_OFFSET);
        for slot in 0..u64::from(descriptor_len - 1) {
            let map_paddr = descriptor_base + (descriptor_index + slot) % descriptor_blocks;
            let map =
                &image.bytes[map_paddr as usize * BLOCK_SIZE as usize..][..BLOCK_SIZE as usize];
            assert_eq!(
                u32_at(map, object::TYPE_OFFSET),
                TYPE_CHECKPOINT_MAP | OBJ_PHYSICAL
            );
            assert_eq!(u64_at(map, object::OID_OFFSET), map_paddr);
        }
        assert!(
            load_checkpoint_data(&image.bytes, BLOCK_SIZE as usize, appended.superblock_paddr)
                .is_ok()
        );
        assert_eq!(
            best_loadable_checkpoint(&image.bytes, BLOCK_SIZE as usize),
            Some((INITIAL_XID + 1, appended.superblock_paddr))
        );
    }

    #[test]
    fn every_ephemeral_object_is_relocated_and_restamped_with_the_new_xid() {
        let mut image = open();
        let appended = {
            let mut disc = session(&mut image);
            append_checkpoint(
                &mut disc,
                LAYOUT.nxsb,
                INITIAL_XID + 1,
                &current_ephemeral_set(),
            )
            .expect("append checkpoint")
        };

        for (before, after) in current_ephemeral_set()
            .iter()
            .zip(&appended.ephemeral_objects)
        {
            assert_ne!(before.paddr, after.paddr);
            let at = after.paddr as usize * BLOCK_SIZE as usize;
            let block = &image.bytes[at..at + BLOCK_SIZE as usize];
            assert_eq!(u64_at(block, object::XID_OFFSET), INITIAL_XID + 1);
            assert_eq!(u64_at(block, object::OID_OFFSET), before.oid);
            let old_at = before.paddr as usize * BLOCK_SIZE as usize;
            assert_eq!(
                u64_at(
                    &image.bytes[old_at..old_at + BLOCK_SIZE as usize],
                    object::XID_OFFSET
                ),
                INITIAL_XID
            );
        }
        assert!(load_checkpoint_data(&image.bytes, BLOCK_SIZE as usize, LAYOUT.nxsb).is_ok());
    }

    #[test]
    fn a_write_made_before_the_checkpoint_is_visible_after_it() {
        let mut image = open();
        let before = {
            {
                let mut disc = session(&mut image);
                crate::repair_writer::spaceman::allocate(
                    &mut disc,
                    LAYOUT.spaceman,
                    INITIAL_XID + 1,
                )
                .expect("allocate");
            }
            let before = verify(&image);
            let mut disc = session(&mut image);
            append_checkpoint(
                &mut disc,
                LAYOUT.nxsb,
                INITIAL_XID + 1,
                &current_ephemeral_set(),
            )
            .expect("append checkpoint");
            before
        };
        let after = verify(&image);
        assert_eq!(after.xid, INITIAL_XID + 1);
        assert_eq!(after.free_block_count, before.free_block_count);
    }

    #[test]
    fn repeated_checkpoints_keep_advancing_and_stay_loadable() {
        let mut image = open();
        let mut xid = INITIAL_XID;
        let mut superblock_paddr = LAYOUT.nxsb;
        let mut objects = current_ephemeral_set();
        {
            let mut disc = session(&mut image);
            for _ in 0..3 {
                xid += 1;
                let appended = append_checkpoint(&mut disc, superblock_paddr, xid, &objects)
                    .expect("append checkpoint");
                superblock_paddr = appended.superblock_paddr;
                objects = appended.ephemeral_objects;
            }
        }
        let after = verify(&image);
        assert_eq!(after.xid, xid);
        assert_eq!(after.superblock_paddr, superblock_paddr);
    }

    #[test]
    fn a_checkpoint_that_would_overwrite_the_mounted_one_is_refused() {
        let mut image = open();
        let mut disc = session(&mut image);
        let mut objects = current_ephemeral_set();
        objects.extend(current_ephemeral_set());
        objects.extend(current_ephemeral_set());
        objects.extend(current_ephemeral_set());
        let outcome = append_checkpoint(&mut disc, LAYOUT.nxsb, INITIAL_XID + 1, &objects);
        assert!(
            matches!(outcome, Err(CheckpointError::RingFull)),
            "got {outcome:?}"
        );
    }

    #[test]
    fn an_object_the_published_checkpoint_does_not_name_is_refused() {
        let mut image = open();
        let mut disc = session(&mut image);
        let mut objects = current_ephemeral_set();
        objects.push(EphemeralObject {
            oid: 0x9999,
            o_type: TYPE_SPACEMAN | OBJ_EPHEMERAL,
            subtype: 0,
            paddr: LAYOUT.spaceman,
        });
        let outcome = append_checkpoint(&mut disc, LAYOUT.nxsb, INITIAL_XID + 1, &objects);
        assert!(
            matches!(
                outcome,
                Err(CheckpointError::NotInPublishedCheckpoint { oid: 0x9999 })
            ),
            "got {outcome:?}"
        );
    }

    #[test]
    fn collect_ephemeral_objects_matches_the_published_set() {
        let mut image = open();
        let mut disc = session(&mut image);
        let collected = collect_ephemeral_objects(&mut disc, LAYOUT.nxsb).expect("collect");
        assert_eq!(collected, current_ephemeral_set());
    }
}
