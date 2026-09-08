use crate::apfs_image::{
    APFS_VOL_ROLE_PREBOOT, APFS_VOL_ROLE_SYSTEM, fletcher64_seal, fletcher64_valid,
};
use crate::apfs_verify::{
    BTreeNode, DrecKeyLayout, J_DIR_REC, J_FILE_EXTENT, J_INODE, OBJ_TYPE_MASK, Object,
    ROOT_DIR_INO_NUM, SliceBlocks, VerifiedContainer, VerifiedVolume, u16_at, u32_at, u64_at,
    verify_container,
};

const TYPE_SPACEMAN: u32 = 0x05;
const TYPE_SPACEMAN_CIB: u32 = 0x07;
const TYPE_CHECKPOINT_MAP: u32 = 0x0C;

const BTNODE_FIXED_KV_SIZE: u16 = 0x4;
const BTREE_INFO_BYTES: usize = 40;

const CHUNK_INFO_BYTES: usize = 32;
const CHECKPOINT_MAPPING_BYTES: usize = 40;

type LeafRecord = (Vec<u8>, Vec<u8>);

const J_OBJ_ID_MASK: u64 = 0x0FFF_FFFF_FFFF_FFFF;

const J_EXTENT: u64 = 2;
const J_SNAP_METADATA: u64 = 1;
const PHYS_EXT_LENGTH_MASK: u64 = 0x0FFF_FFFF_FFFF_FFFF;

fn put_u32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(buf: &mut [u8], at: usize, v: u64) {
    buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

// apfs_volume_group_id is straight hex over the bytes as stored, not a mixed-endian GUID encoding.
fn format_uuid(b: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-\
         {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

fn blocks_at(bytes: &[u8], block_size: u32, paddr: u64, count: usize) -> Result<&[u8], String> {
    let bs = block_size as usize;
    let start = usize::try_from(paddr)
        .ok()
        .and_then(|p| p.checked_mul(bs))
        .ok_or_else(|| format!("block address {paddr} overflowed"))?;
    let len = count.checked_mul(bs).ok_or("block span overflowed")?;
    let end = start.checked_add(len).ok_or("block span overflowed")?;
    bytes
        .get(start..end)
        .ok_or_else(|| format!("block {paddr} (+{count}) is outside the container"))
}

fn blocks_at_mut(
    bytes: &mut [u8],
    block_size: u32,
    paddr: u64,
    count: usize,
) -> Result<&mut [u8], String> {
    let bs = block_size as usize;
    let start = usize::try_from(paddr)
        .ok()
        .and_then(|p| p.checked_mul(bs))
        .ok_or_else(|| format!("block address {paddr} overflowed"))?;
    let len = count.checked_mul(bs).ok_or("block span overflowed")?;
    let end = start.checked_add(len).ok_or("block span overflowed")?;
    let total = bytes.len();
    bytes
        .get_mut(start..end)
        .ok_or_else(|| format!("block {paddr} (+{count}) is outside the container ({total} bytes)"))
}

fn block_at(bytes: &[u8], block_size: u32, paddr: u64) -> Result<&[u8], String> {
    blocks_at(bytes, block_size, paddr, 1)
}

fn block_at_mut(bytes: &mut [u8], block_size: u32, paddr: u64) -> Result<&mut [u8], String> {
    blocks_at_mut(bytes, block_size, paddr, 1)
}

fn zero_blocks(bytes: &mut [u8], block_size: u32, paddr: u64, blocks: u64) -> Result<(), String> {
    let count = usize::try_from(blocks).map_err(|_| "block count overflowed")?;
    blocks_at_mut(bytes, block_size, paddr, count)?.fill(0);
    Ok(())
}

fn write_stage1(
    bytes: &mut [u8],
    block_size: u32,
    paddr: u64,
    alloced: u64,
    data: &[u8],
) -> Result<(), String> {
    let count = usize::try_from(alloced / u64::from(block_size))
        .map_err(|_| "allocated block count overflowed")?;
    let region = blocks_at_mut(bytes, block_size, paddr, count)?;
    if data.len() > region.len() {
        return Err("stage-one content does not fit in its own allocated blocks".into());
    }
    region[..data.len()].copy_from_slice(data);
    region[data.len()..].fill(0);
    Ok(())
}

fn decode_tree_records(
    bytes: &[u8],
    block_size: u32,
    root: u64,
    mappings: Option<&std::collections::BTreeMap<u64, u64>>,
) -> Result<Vec<LeafRecord>, String> {
    let root_bytes = block_at(bytes, block_size, root)?;
    let info = block_size as usize - BTREE_INFO_BYTES;
    let fixed = (
        u32_at(root_bytes, info + 8) as usize,
        u32_at(root_bytes, info + 12) as usize,
    );
    let mut pending = vec![root];
    let mut visited = std::collections::BTreeSet::new();
    let mut records = Vec::new();
    while let Some(paddr) = pending.pop() {
        if !visited.insert(paddr) {
            return Err("APFS tree contains a cycle or duplicate child".into());
        }
        let block = block_at(bytes, block_size, paddr)?.to_vec();
        if !fletcher64_valid(&block) {
            return Err(format!("invalid APFS tree checksum at {paddr}"));
        }
        let fixed_node = u16_at(&block, 0x20) & BTNODE_FIXED_KV_SIZE != 0;
        let node = BTreeNode::decode(
            &Object {
                paddr,
                bytes: block,
            },
            block_size as usize,
        )
        .map_err(|e| e.to_string())?;
        let mut children = Vec::new();
        for index in 0..node.nkeys {
            let (key, value) = node.entry(index).map_err(|e| e.to_string())?;
            if node.is_leaf() {
                let (key, value) = if fixed_node {
                    (
                        key.get(..fixed.0).ok_or("short fixed APFS key")?,
                        value.get(..fixed.1).ok_or("short fixed APFS value")?,
                    )
                } else {
                    (key, value)
                };
                records.push((key.to_vec(), value.to_vec()));
            } else {
                if value.len() < 8 {
                    return Err("short APFS tree child".into());
                }
                let child = u64_at(value, 0);
                children.push(match mappings {
                    Some(map) => *map.get(&child).ok_or("unmapped APFS virtual child")?,
                    None => child,
                });
            }
        }
        pending.extend(children.into_iter().rev());
    }
    Ok(records)
}

fn decode_leaf_records(
    bytes: &[u8],
    block_size: u32,
    root: u64,
) -> Result<Vec<LeafRecord>, String> {
    decode_tree_records(bytes, block_size, root, None)
}

fn volume_mappings(
    bytes: &[u8],
    block_size: u32,
    apsb: &[u8],
) -> Result<std::collections::BTreeMap<u64, u64>, String> {
    let omap = block_at(bytes, block_size, u64_at(apsb, 0x80))?;
    let records = decode_leaf_records(bytes, block_size, u64_at(omap, 0x30))?;
    let mut map = std::collections::BTreeMap::new();
    for (key, value) in records {
        if key.len() < 16 || value.len() < 16 {
            return Err("short APFS object map entry".into());
        }
        map.insert(u64_at(&key, 0), u64_at(&value, 8));
    }
    Ok(map)
}

fn find_dir_child(
    records: &[(Vec<u8>, Vec<u8>)],
    parent: u64,
    name: &str,
    layout: DrecKeyLayout,
) -> Result<u64, String> {
    for (key, value) in records {
        if key.len() < 8 || u64_at(key, 0) >> 60 != J_DIR_REC {
            continue;
        }
        if u64_at(key, 0) & J_OBJ_ID_MASK != parent {
            continue;
        }
        let Some(name_len) = layout.name_length(key) else {
            continue;
        };
        if name_len == 0 {
            continue;
        }
        let start = layout.name_offset();
        let Some(end) = start.checked_add(name_len) else {
            continue;
        };
        if end > key.len() {
            continue;
        }
        if key[start..end - 1].eq_ignore_ascii_case(name.as_bytes()) {
            if value.len() < 8 {
                return Err(format!("{name:?}: directory record value is too short"));
            }
            return Ok(u64_at(value, 0));
        }
    }
    Err(format!("{name:?} was not found in the catalog"))
}

fn resolve_path(
    records: &[(Vec<u8>, Vec<u8>)],
    layout: DrecKeyLayout,
    path: &[&str],
) -> Result<u64, String> {
    let mut current = ROOT_DIR_INO_NUM;
    for name in path {
        current = find_dir_child(records, current, name, layout)?;
    }
    Ok(current)
}

struct FileLocation {
    file_id: u64,
    size: u64,
    alloced: u64,
    paddr: u64,
    inode_index: usize,
    extent_index: usize,
}

fn locate_file(
    records: &[(Vec<u8>, Vec<u8>)],
    layout: DrecKeyLayout,
    path: &[&str],
) -> Result<FileLocation, String> {
    let joined = path.join("/");
    let file_id = resolve_path(records, layout, path)?;

    let inode_index = records
        .iter()
        .position(|(key, _)| {
            key.len() >= 8
                && u64_at(key, 0) >> 60 == J_INODE
                && u64_at(key, 0) & J_OBJ_ID_MASK == file_id
        })
        .ok_or_else(|| format!("{joined}: no inode record for object id {file_id}"))?;
    let inode_value = &records[inode_index].1;
    if inode_value.len() != 0x8C {
        return Err(format!(
            "{joined}: inode record is {} bytes, not the 140-byte single-dstream form \
             apfs_write::create produces",
            inode_value.len()
        ));
    }
    if u16_at(inode_value, 0x5C) != 1
        || u16_at(inode_value, 0x5E) != 40
        || inode_value[0x60] != 8
        || u16_at(inode_value, 0x62) != 40
    {
        return Err(format!(
            "{joined}: inode record does not carry exactly one data-stream extended field"
        ));
    }
    let size = u64_at(inode_value, 0x64);
    let alloced = u64_at(inode_value, 0x6C);

    let mut extent_index = None;
    for (index, (key, _)) in records.iter().enumerate() {
        if key.len() >= 16
            && u64_at(key, 0) >> 60 == J_FILE_EXTENT
            && u64_at(key, 0) & J_OBJ_ID_MASK == file_id
        {
            if extent_index.is_some() {
                return Err(format!(
                    "{joined}: file has more than one extent; apfs_update only supports \
                     single-extent files"
                ));
            }
            extent_index = Some(index);
        }
    }
    let extent_index = extent_index
        .ok_or_else(|| format!("{joined}: no file-extent record for object id {file_id}"))?;
    let extent_value = &records[extent_index].1;
    if extent_value.len() != 24 {
        return Err(format!(
            "{joined}: file-extent value is {} bytes, not the 24-byte length+physical+crypto-id \
             form apfs_write::create produces",
            extent_value.len()
        ));
    }
    let paddr = u64_at(extent_value, 8);
    if u64_at(extent_value, 0) != alloced {
        return Err(format!(
            "{joined}: inode and file-extent records disagree about the file's allocated length"
        ));
    }

    Ok(FileLocation {
        file_id,
        size,
        alloced,
        paddr,
        inode_index,
        extent_index,
    })
}

fn read_file_bytes(
    bytes: &[u8],
    block_size: u32,
    records: &[(Vec<u8>, Vec<u8>)],
    layout: DrecKeyLayout,
    path: &[&str],
) -> Result<Vec<u8>, String> {
    let location = locate_file(records, layout, path)?;
    let blocks = usize::try_from(location.alloced / u64::from(block_size))
        .map_err(|_| "allocated block count overflowed")?;
    let region = blocks_at(bytes, block_size, location.paddr, blocks)?;
    let size = usize::try_from(location.size).map_err(|_| "logical size overflowed")?;
    if size > region.len() {
        return Err(format!(
            "{}: logical size exceeds its allocated blocks",
            path.join("/")
        ));
    }
    Ok(region[..size].to_vec())
}

fn phys_ext_key(phys_start: u64) -> Vec<u8> {
    ((J_EXTENT << 60) | phys_start).to_le_bytes().to_vec()
}

fn phys_ext_val(len_blocks: u64, owning_obj_id: u64, refcnt: i32) -> Vec<u8> {
    let mut value = vec![0u8; 20];
    let len_and_kind = len_blocks | (1u64 << 60);
    put_u64(&mut value, 0, len_and_kind);
    put_u64(&mut value, 8, owning_obj_id);
    value[16..20].copy_from_slice(&refcnt.to_le_bytes());
    value
}

struct Chunk {
    addr: u64,
    blocks: u32,
    free: u32,
    bitmap_addr: u64,
    bitmap: Option<Vec<u8>>,
    cib_index: usize,
    slot: usize,
    dirty: bool,
}

struct Cib {
    paddr: u64,
    bytes: Vec<u8>,
    dirty: bool,
}

struct SpacemanContext {
    paddr: u64,
    blocks: usize,
    bytes: Vec<u8>,
    blocks_per_chunk: u64,
    chunks: Vec<Chunk>,
    cibs: Vec<Cib>,
    free_delta: i64,
}

impl SpacemanContext {
    fn parse(
        bytes: &[u8],
        block_size: u32,
        spaceman_paddr: u64,
        spaceman_blocks: usize,
    ) -> Result<Self, String> {
        let sm = blocks_at(bytes, block_size, spaceman_paddr, spaceman_blocks)?.to_vec();
        if !fletcher64_valid(&sm) {
            return Err("space manager checksum is invalid".into());
        }
        if u32_at(&sm, 0x18) & OBJ_TYPE_MASK != TYPE_SPACEMAN {
            return Err(
                "checkpoint map's space manager mapping does not point at a space manager".into(),
            );
        }
        let blocks_per_chunk = u64::from(u32_at(&sm, 0x24));
        let chunk_count = u64_at(&sm, 0x38);
        let cib_count = u32_at(&sm, 0x40) as usize;
        let cab_count = u32_at(&sm, 0x44) as usize;
        if cab_count != 0 {
            return Err(
                "apfs_update does not support space managers large enough to need chunk-info \
                 address blocks"
                    .into(),
            );
        }
        let cib_addr_offset = u32_at(&sm, 0x50) as usize;

        let mut cibs = Vec::with_capacity(cib_count);
        let mut chunks = Vec::new();
        for cib_index in 0..cib_count {
            let cib_addr_at = cib_addr_offset + cib_index * 8;
            if cib_addr_at + 8 > sm.len() {
                return Err(
                    "space manager's chunk-info address array runs past its own object".into(),
                );
            }
            let cib_paddr = u64_at(&sm, cib_addr_at);
            let cib_bytes = block_at(bytes, block_size, cib_paddr)?.to_vec();
            if !fletcher64_valid(&cib_bytes) {
                return Err(format!(
                    "chunk-info block at {cib_paddr} has an invalid checksum"
                ));
            }
            if u32_at(&cib_bytes, 0x18) & OBJ_TYPE_MASK != TYPE_SPACEMAN_CIB {
                return Err(format!("block {cib_paddr} is not a chunk-info block"));
            }
            let n = u32_at(&cib_bytes, 0x24) as usize;
            for slot in 0..n {
                let at = 0x28 + slot * CHUNK_INFO_BYTES;
                if at + CHUNK_INFO_BYTES > cib_bytes.len() {
                    return Err(format!(
                        "chunk-info block at {cib_paddr} overflows its own block"
                    ));
                }
                let addr = u64_at(&cib_bytes, at + 8);
                let blocks = u32_at(&cib_bytes, at + 16);
                let free = u32_at(&cib_bytes, at + 20);
                let bitmap_addr = u64_at(&cib_bytes, at + 24);
                let bitmap = if bitmap_addr == 0 {
                    None
                } else {
                    Some(block_at(bytes, block_size, bitmap_addr)?.to_vec())
                };
                chunks.push(Chunk {
                    addr,
                    blocks,
                    free,
                    bitmap_addr,
                    bitmap,
                    cib_index,
                    slot,
                    dirty: false,
                });
            }
            cibs.push(Cib {
                paddr: cib_paddr,
                bytes: cib_bytes,
                dirty: false,
            });
        }
        if chunks.len() as u64 != chunk_count {
            return Err(
                "space manager's chunk-info blocks do not cover its own declared chunk count"
                    .into(),
            );
        }

        Ok(Self {
            paddr: spaceman_paddr,
            blocks: spaceman_blocks,
            bytes: sm,
            blocks_per_chunk,
            chunks,
            cibs,
            free_delta: 0,
        })
    }

    fn free_range(&mut self, paddr: u64, blocks: u64) -> Result<(), String> {
        let chunk_index = usize::try_from(paddr / self.blocks_per_chunk)
            .map_err(|_| "extent's chunk index overflowed")?;
        let chunk = self
            .chunks
            .get_mut(chunk_index)
            .ok_or("extent's chunk index is out of range")?;
        if paddr < chunk.addr {
            return Err("extent address precedes its own chunk".into());
        }
        let bit0 = paddr - chunk.addr;
        if bit0 + blocks > u64::from(chunk.blocks) {
            return Err(
                "extent crosses a chunk boundary; apfs_update does not support that".into(),
            );
        }
        let bitmap = chunk
            .bitmap
            .as_mut()
            .ok_or("chunk holding an allocated extent carries no allocation bitmap")?;
        for bit in bit0..bit0 + blocks {
            let byte = &mut bitmap[(bit >> 3) as usize];
            let mask = 1u8 << (bit & 7);
            if *byte & mask == 0 {
                return Err("freeing a block the space manager already shows free".into());
            }
            *byte &= !mask;
        }
        chunk.free += u32::try_from(blocks).map_err(|_| "block count overflowed")?;
        chunk.dirty = true;
        self.cibs[chunk.cib_index].dirty = true;
        self.free_delta += blocks as i64;
        Ok(())
    }

    fn alloc_range(&mut self, blocks: u64) -> Result<u64, String> {
        for chunk in &mut self.chunks {
            if u64::from(chunk.free) < blocks {
                continue;
            }
            let Some(bitmap) = chunk.bitmap.as_mut() else {
                continue;
            };
            let mut run = 0u64;
            let mut start = 0u64;
            let mut found = None;
            for bit in 0..u64::from(chunk.blocks) {
                let set = (bitmap[(bit >> 3) as usize] >> (bit & 7)) & 1 == 1;
                if set {
                    run = 0;
                } else {
                    if run == 0 {
                        start = bit;
                    }
                    run += 1;
                    if run == blocks {
                        found = Some(start);
                        break;
                    }
                }
            }
            let Some(start) = found else { continue };
            for bit in start..start + blocks {
                bitmap[(bit >> 3) as usize] |= 1 << (bit & 7);
            }
            chunk.free -= u32::try_from(blocks).map_err(|_| "block count overflowed")?;
            chunk.dirty = true;
            self.cibs[chunk.cib_index].dirty = true;
            self.free_delta -= blocks as i64;
            return Ok(chunk.addr + start);
        }
        Err(format!(
            "no {blocks}-block free run is available in any one chunk for apfs_update to place \
             the new content"
        ))
    }

    fn commit(mut self, bytes: &mut [u8], block_size: u32, new_xid: u64) -> Result<(), String> {
        for chunk in &self.chunks {
            if !chunk.dirty {
                continue;
            }
            if let Some(bitmap) = &chunk.bitmap {
                block_at_mut(bytes, block_size, chunk.bitmap_addr)?.copy_from_slice(bitmap);
            }
            let cib = &mut self.cibs[chunk.cib_index];
            let at = 0x28 + chunk.slot * CHUNK_INFO_BYTES;
            put_u64(&mut cib.bytes, at, new_xid); // ci_xid
            put_u32(&mut cib.bytes, at + 20, chunk.free);
        }
        for cib in &mut self.cibs {
            if !cib.dirty {
                continue;
            }
            put_u64(&mut cib.bytes, 0x10, new_xid); // o_xid
            fletcher64_seal(&mut cib.bytes);
            block_at_mut(bytes, block_size, cib.paddr)?.copy_from_slice(&cib.bytes);
        }
        if self.free_delta != 0 {
            let old_free = u64_at(&self.bytes, 0x48);
            let new_free = old_free as i64 + self.free_delta;
            let new_free = u64::try_from(new_free)
                .map_err(|_| "space manager free count would go negative")?;
            put_u64(&mut self.bytes, 0x48, new_free);
            put_u64(&mut self.bytes, 0x10, new_xid); // o_xid
            fletcher64_seal(&mut self.bytes);
            blocks_at_mut(bytes, block_size, self.paddr, self.blocks)?.copy_from_slice(&self.bytes);
        }
        Ok(())
    }
}

fn snapshot_protection(bytes: &[u8], block_size: u32, apsb: &[u8]) -> Result<Option<u64>, String> {
    let num_snapshots = u64_at(apsb, 0xD8);
    if num_snapshots == 0 {
        return Ok(None);
    }
    if num_snapshots != 1 {
        return Err(format!(
            "volume declares {num_snapshots} snapshots; apfs_update only supports the single \
             snapshot apfs_write::create takes"
        ));
    }
    let snap_meta_tree_paddr = u64_at(apsb, 0x98);
    let records = decode_leaf_records(bytes, block_size, snap_meta_tree_paddr)?;
    let mut found = None;
    for (key, value) in &records {
        if key.len() < 8 || u64_at(key, 0) >> 60 != J_SNAP_METADATA {
            continue;
        }
        if found.is_some() {
            return Err(
                "snapshot metadata tree carries more than one snapshot record; apfs_update only \
                 supports a single snapshot"
                    .into(),
            );
        }
        if value.len() < 8 {
            return Err("snapshot metadata value is too short".into());
        }
        found = Some(u64_at(value, 0x00));
    }
    let extentref_tree_paddr =
        found.ok_or("volume declares a snapshot but its metadata tree holds no record of one")?;
    if extentref_tree_paddr == 0 {
        return Err("snapshot metadata names no extent-reference tree of its own".into());
    }
    Ok(Some(extentref_tree_paddr))
}

fn is_snapshot_protected(
    bytes: &[u8],
    block_size: u32,
    snapshot_extentref_paddr: u64,
    paddr: u64,
) -> Result<bool, String> {
    let records = decode_leaf_records(bytes, block_size, snapshot_extentref_paddr)?;
    Ok(records.iter().any(|(key, _)| {
        key.len() >= 8
            && u64_at(key, 0) >> 60 == J_EXTENT
            && u64_at(key, 0) & J_OBJ_ID_MASK == paddr
    }))
}

fn ensure_file_records(
    records: &mut Vec<LeafRecord>,
    layout: DrecKeyLayout,
    path: &[&str],
    apsb: &mut [u8],
) -> Result<(), String> {
    use crate::apfs_write::{
        dir_inode_val, drec_key, drec_val, dstream_id_key, dstream_id_val, extent_key, extent_val,
        file_inode_val, inode_key, record_sort_key,
    };
    let mut parent = ROOT_DIR_INO_NUM;
    for (index, name) in path.iter().enumerate() {
        let last = index + 1 == path.len();
        if let Ok(child) = find_dir_child(records, parent, name, layout) {
            let inode = records
                .iter()
                .find(|(key, _)| key == &inode_key(child))
                .ok_or("directory child has no inode")?;
            let expected = if last { 0x8000 } else { 0x4000 };
            if u16_at(&inode.1, 0x50) & 0xf000 != expected {
                return Err(format!(
                    "{}: existing path has the wrong inode type",
                    path.join("/")
                ));
            }
            let record = records
                .iter_mut()
                .find(|(key, value)| {
                    key.len() >= 8
                        && u64_at(key, 0) >> 60 == J_DIR_REC
                        && u64_at(key, 0) & J_OBJ_ID_MASK == parent
                        && value.len() >= 8
                        && u64_at(value, 0) == child
                        && layout
                            .name_length(key)
                            .and_then(|len| len.checked_sub(1))
                            .and_then(|len| {
                                key.get(layout.name_offset()..layout.name_offset() + len)
                            })
                            .is_some_and(|stored| stored.eq_ignore_ascii_case(name.as_bytes()))
                })
                .ok_or("resolved directory record missing")?;
            record.0 = drec_key(parent, name)?;
            parent = child;
            continue;
        }
        let oid = u64_at(apsb, 0xB0);
        put_u64(apsb, 0xB0, oid.checked_add(1).ok_or("inode id overflow")?);
        let parent_inode = records
            .iter_mut()
            .find(|(key, _)| key == &inode_key(parent))
            .ok_or("parent inode missing")?;
        let count = u32_at(&parent_inode.1, 0x38)
            .checked_add(1)
            .ok_or("directory child count overflow")?;
        put_u32(&mut parent_inode.1, 0x38, count);
        records.push((
            drec_key(parent, name)?,
            drec_val(oid, if last { 8 } else { 4 }),
        ));
        if last {
            records.push((inode_key(oid), file_inode_val(parent, oid, 0, 0)));
            records.push((extent_key(oid), extent_val(0, 0)));
            records.push((dstream_id_key(oid), dstream_id_val(1)));
        } else {
            records.push((inode_key(oid), dir_inode_val(parent, oid, 0)));
        }
        parent = oid;
    }
    records.sort_by_key(|(key, _)| record_sort_key(key));
    Ok(())
}

struct UpdateTreeStore<'a> {
    bytes: &'a mut [u8],
    block_size: u32,
    sm: &'a mut SpacemanContext,
}

impl crate::apfs_write::TreeStore for UpdateTreeStore<'_> {
    fn block_size(&self) -> u32 {
        self.block_size
    }
    fn alloc(&mut self, blocks: u64) -> Result<u64, String> {
        self.sm.alloc_range(blocks)
    }
    fn write_blocks(&mut self, paddr: u64, data: &[u8]) -> Result<(), String> {
        if !data.len().is_multiple_of(self.block_size as usize) {
            return Err("unaligned APFS tree write".into());
        }
        blocks_at_mut(
            self.bytes,
            self.block_size,
            paddr,
            data.len() / self.block_size as usize,
        )?
        .copy_from_slice(data);
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn update_volume_files(
    bytes: &mut [u8],
    block_size: u32,
    sm: &mut SpacemanContext,
    apsb_paddr: u64,
    fs_tree_oid: u64,
    live_fs_tree_paddr: u64,
    layout: DrecKeyLayout,
    files: &[(Vec<&str>, &[u8])],
    new_xid: u64,
) -> Result<u64, String> {
    use crate::apfs_write::{TreeLayout, write_tree};
    let mut apsb = block_at(bytes, block_size, apsb_paddr)?.to_vec();
    let vol_omap_paddr = u64_at(&apsb, 0x80);
    let extentref_paddr = u64_at(&apsb, 0x90);
    let snapshot_extentref_paddr = snapshot_protection(bytes, block_size, &apsb)?;
    let mappings = volume_mappings(bytes, block_size, &apsb)?;
    let mut records = decode_tree_records(bytes, block_size, live_fs_tree_paddr, Some(&mappings))?;
    let mut extentref_records = decode_leaf_records(bytes, block_size, extentref_paddr)?;
    for (path, data) in files {
        ensure_file_records(&mut records, layout, path, &mut apsb)?;
        let location = locate_file(&records, layout, path)?;
        let protected = match snapshot_extentref_paddr {
            Some(paddr) if location.alloced != 0 => {
                is_snapshot_protected(bytes, block_size, paddr, location.paddr)?
            }
            _ => false,
        };
        let new_blocks = (data.len() as u64).div_ceil(u64::from(block_size)).max(1);
        let new_alloced = new_blocks * u64::from(block_size);
        let old_blocks = location.alloced / u64::from(block_size);
        let new_paddr = if !protected && old_blocks == new_blocks {
            location.paddr
        } else {
            if !protected && old_blocks != 0 {
                sm.free_range(location.paddr, old_blocks)?;
                zero_blocks(bytes, block_size, location.paddr, old_blocks)?;
            }
            sm.alloc_range(new_blocks)?
        };
        write_stage1(bytes, block_size, new_paddr, new_alloced, data)?;
        let inode = &mut records[location.inode_index].1;
        put_u64(inode, 0x64, data.len() as u64);
        put_u64(inode, 0x6C, new_alloced);
        put_u64(inode, 0x7C, data.len() as u64);
        let extent = &mut records[location.extent_index].1;
        put_u64(extent, 0, new_alloced);
        put_u64(extent, 8, new_paddr);
        extentref_records.retain(|(key, _)| {
            key.len() < 8
                || u64_at(key, 0) >> 60 != J_EXTENT
                || ![new_paddr, location.paddr].contains(&(u64_at(key, 0) & J_OBJ_ID_MASK))
        });
        extentref_records.push((
            phys_ext_key(new_paddr),
            phys_ext_val(new_blocks, location.file_id, 1),
        ));
    }
    extentref_records.sort_by_key(|(key, _)| u64_at(key, 0));
    let fs_alloc_count: u64 = extentref_records
        .iter()
        .map(|(_, value)| u64_at(value, 0) & PHYS_EXT_LENGTH_MASK)
        .sum();
    let omap_phys = block_at(bytes, block_size, vol_omap_paddr)?.to_vec();
    let old_omap_tree = u64_at(&omap_phys, 0x30);
    let mut omap_records = decode_leaf_records(bytes, block_size, old_omap_tree)?;
    let mut next_oid = u64_at(&apsb, 0xB0);
    let mut store = UpdateTreeStore {
        bytes,
        block_size,
        sm,
    };
    let (new_fs_tree_paddr, new_mappings) = write_tree(
        &mut store,
        records,
        TreeLayout {
            fixed: None,
            flags: 0x42,
            subtype: 0x0e,
        },
        new_xid,
        Some(fs_tree_oid),
        &mut next_oid,
    )?;
    for (oid, paddr) in new_mappings {
        omap_records.retain(|(key, _)| u64_at(key, 0) != oid || u64_at(key, 8) != new_xid);
        let mut key = oid.to_le_bytes().to_vec();
        key.extend_from_slice(&new_xid.to_le_bytes());
        let mut value = vec![0; 16];
        put_u32(&mut value, 4, block_size);
        put_u64(&mut value, 8, paddr);
        omap_records.push((key, value));
    }
    omap_records.sort_by_key(|(key, _)| (u64_at(key, 0), u64_at(key, 8)));
    let (new_omap_tree, _) = write_tree(
        &mut store,
        omap_records,
        TreeLayout {
            fixed: Some((16, 16)),
            flags: 0x12,
            subtype: 0x0b,
        },
        new_xid,
        None,
        &mut next_oid,
    )?;
    let (new_extentref, _) = write_tree(
        &mut store,
        extentref_records,
        TreeLayout {
            fixed: None,
            flags: 0x52,
            subtype: 0x0f,
        },
        new_xid,
        None,
        &mut next_oid,
    )?;
    let mut updated_omap = omap_phys;
    put_u64(&mut updated_omap, 0x30, new_omap_tree);
    put_u64(&mut updated_omap, 0x10, new_xid);
    fletcher64_seal(&mut updated_omap);
    block_at_mut(store.bytes, block_size, vol_omap_paddr)?.copy_from_slice(&updated_omap);
    put_u64(&mut apsb, 0x58, fs_alloc_count);
    put_u64(&mut apsb, 0x90, new_extentref);
    put_u64(&mut apsb, 0xB0, next_oid);
    fletcher64_seal(&mut apsb);
    block_at_mut(store.bytes, block_size, apsb_paddr)?.copy_from_slice(&apsb);
    Ok(new_fs_tree_paddr)
}

struct Mapping {
    paddr: u64,
    oid: u64,
    size: u32,
}

fn read_checkpoint_mappings(
    bytes: &[u8],
    block_size: u32,
    nxsb: &[u8],
) -> Result<(u64, Vec<Mapping>), String> {
    let desc_base = u64_at(nxsb, 0x70);
    let desc_blocks = u32_at(nxsb, 0x68) as u64;
    let index = u32_at(nxsb, 0x88) as u64;
    let len = u32_at(nxsb, 0x8C) as u64;
    if desc_blocks == 0 {
        return Err("mounted checkpoint's descriptor ring is empty".into());
    }
    if len != 2 {
        return Err(
            "apfs_update only supports a single checkpoint-map block per checkpoint, matching \
             apfs_write::create's own layout"
                .into(),
        );
    }
    let mut cpmap_paddr = None;
    for slot in 0..len {
        let paddr = desc_base + (index + slot) % desc_blocks;
        let block = block_at(bytes, block_size, paddr)?;
        if u32_at(block, 0x18) & OBJ_TYPE_MASK == TYPE_CHECKPOINT_MAP {
            cpmap_paddr = Some(paddr);
            break;
        }
    }
    let cpmap_paddr = cpmap_paddr.ok_or("mounted checkpoint carries no checkpoint map")?;
    let cpmap = block_at(bytes, block_size, cpmap_paddr)?.to_vec();
    if !fletcher64_valid(&cpmap) {
        return Err("checkpoint map checksum is invalid".into());
    }
    let count = u32_at(&cpmap, 0x24) as usize;
    let capacity = (block_size as usize - 0x28) / CHECKPOINT_MAPPING_BYTES;
    if count > capacity {
        return Err("checkpoint map claims more mappings than it can hold".into());
    }
    let mut mappings = Vec::with_capacity(count);
    for i in 0..count {
        let at = 0x28 + i * CHECKPOINT_MAPPING_BYTES;
        mappings.push(Mapping {
            oid: u64_at(&cpmap, at + 24),
            paddr: u64_at(&cpmap, at + 32),
            size: u32_at(&cpmap, at + 8),
        });
    }
    Ok((cpmap_paddr, mappings))
}

fn append_checkpoint(
    bytes: &mut [u8],
    block_size: u32,
    old_superblock_paddr: u64,
    new_xid: u64,
) -> Result<(), String> {
    let old_nxsb = block_at(bytes, block_size, old_superblock_paddr)?.to_vec();
    let (old_cpmap_paddr, _mappings) = read_checkpoint_mappings(bytes, block_size, &old_nxsb)?;
    let old_cpmap = block_at(bytes, block_size, old_cpmap_paddr)?.to_vec();

    let desc_base = u64_at(&old_nxsb, 0x70);
    let desc_blocks = u32_at(&old_nxsb, 0x68) as u64;
    let old_index = u32_at(&old_nxsb, 0x88) as u64;
    let old_len = u32_at(&old_nxsb, 0x8C) as u64;
    let new_len = old_len;
    let new_index = (old_index + old_len) % desc_blocks;
    if new_index == old_index {
        return Err("checkpoint descriptor ring has no room for a second checkpoint".into());
    }
    let new_next = (new_index + new_len) % desc_blocks;
    let new_cpmap_paddr = desc_base + new_index;
    let new_nxsb_paddr = desc_base + (new_index + 1) % desc_blocks;

    let mut new_cpmap = old_cpmap;
    put_u64(&mut new_cpmap, 0x08, new_cpmap_paddr); // o_oid: a checkpoint map's own physical address
    put_u64(&mut new_cpmap, 0x10, new_xid); // o_xid
    fletcher64_seal(&mut new_cpmap);

    let mut new_nxsb = old_nxsb;
    put_u64(&mut new_nxsb, 0x10, new_xid); // o_xid
    put_u64(&mut new_nxsb, 0x60, new_xid + 1); // nx_next_xid
    put_u32(&mut new_nxsb, 0x80, new_next as u32); // nx_xp_desc_next
    put_u32(&mut new_nxsb, 0x88, new_index as u32); // nx_xp_desc_index
    put_u32(&mut new_nxsb, 0x8C, new_len as u32); // nx_xp_desc_len
    fletcher64_seal(&mut new_nxsb);

    block_at_mut(bytes, block_size, new_cpmap_paddr)?.copy_from_slice(&new_cpmap);
    block_at_mut(bytes, block_size, new_nxsb_paddr)?.copy_from_slice(&new_nxsb);
    Ok(())
}

fn exactly_one_volume<'a>(
    container: &'a VerifiedContainer,
    role: u16,
    label: &str,
) -> Result<&'a VerifiedVolume, String> {
    let mut matches = container.volumes.iter().filter(|v| v.role & role != 0);
    let first = matches
        .next()
        .ok_or_else(|| format!("container has no {label} volume"))?;
    if matches.next().is_some() {
        return Err(format!("container has more than one {label} volume"));
    }
    Ok(first)
}

pub fn update(container: &[u8], stage1: &[u8]) -> Result<Vec<u8>, String> {
    update_with_system_version(container, stage1, None)
}

pub fn update_with_system_version(
    container: &[u8],
    stage1: &[u8],
    system_version: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    update_with_preboot_files(container, stage1, system_version, &[], &[])
}

pub fn update_with_preboot_files(
    container: &[u8],
    stage1: &[u8],
    system_version: Option<&[u8]>,
    preboot_files: &[(String, Vec<u8>)],
    system_files: &[(String, Vec<u8>)],
) -> Result<Vec<u8>, String> {
    crate::apfs_write::validate_preboot_files(preboot_files, system_version)?;
    crate::apfs_write::validate_system_files(system_files)?;
    if let Some(metadata) = system_version {
        crate::apfs_write::validate_system_version(metadata)?;
    }
    if stage1.is_empty() {
        return Err("Stage-one boot object is empty".into());
    }

    let (block_size, block_count) =
        crate::apfs_read::container_geometry_of(container).map_err(|e| e.to_string())?;
    if block_size != 4096 {
        return Err(format!(
            "apfs_update only supports 4096-byte blocks (container declares {block_size})"
        ));
    }
    let expected_len = block_count
        .checked_mul(u64::from(block_size))
        .ok_or("container geometry overflowed")?;
    if container.len() as u64 != expected_len {
        return Err(format!(
            "container is {} bytes, but its own geometry declares {expected_len}",
            container.len()
        ));
    }

    let before = {
        let mut blocks = SliceBlocks::new(container, block_size);
        verify_container(&mut blocks)
            .map_err(|e| format!("container fails verification before update: {e}"))?
    };

    let system = exactly_one_volume(&before, APFS_VOL_ROLE_SYSTEM, "System")?;
    let preboot = exactly_one_volume(&before, APFS_VOL_ROLE_PREBOOT, "Preboot")?;
    let system_paddr = system.paddr;
    let preboot_paddr = preboot.paddr;
    let system_fs_tree_oid = system.fs_tree_oid;
    let preboot_fs_tree_oid = preboot.fs_tree_oid;
    let system_fs_tree_paddr = system.fs_tree_paddr;
    let preboot_fs_tree_paddr = preboot.fs_tree_paddr;

    let mut bytes = container.to_vec();

    let system_apsb = block_at(&bytes, block_size, system_paddr)?.to_vec();
    let preboot_apsb = block_at(&bytes, block_size, preboot_paddr)?.to_vec();
    let group_bytes: [u8; 16] = system_apsb[0x3F0..0x400]
        .try_into()
        .map_err(|_| "System volume group id is malformed".to_string())?;
    let group = format_uuid(&group_bytes);
    let system_layout = DrecKeyLayout::of(u64_at(&system_apsb, 0x38));
    let preboot_layout = DrecKeyLayout::of(u64_at(&preboot_apsb, 0x38));

    let preboot_mappings = volume_mappings(&bytes, block_size, &preboot_apsb)?;
    let preboot_records = decode_tree_records(
        &bytes,
        block_size,
        preboot_fs_tree_paddr,
        Some(&preboot_mappings),
    )?;
    let selected = read_file_bytes(
        &bytes,
        block_size,
        &preboot_records,
        preboot_layout,
        &["boot-volume"],
    )
    .map_err(|e| format!("Preboot boot-volume: {e}"))?;
    let selected =
        String::from_utf8(selected).map_err(|_| "Preboot boot-volume is not UTF-8".to_string())?;
    if !selected.trim().eq_ignore_ascii_case(&group) {
        return Err("Preboot selection does not match the System volume group".into());
    }

    let system_path = [
        "Finish Installation.app",
        "Contents",
        "Resources",
        "boot.bin",
    ];
    let preboot_path = [group.as_str(), "boot.bin"];

    let nxsb = block_at(&bytes, block_size, before.superblock_paddr)?.to_vec();
    let (_, mappings) = read_checkpoint_mappings(&bytes, block_size, &nxsb)?;
    let spaceman_oid = u64_at(&nxsb, 0x98);
    let spaceman_mapping = mappings
        .iter()
        .find(|m| m.oid == spaceman_oid)
        .ok_or("checkpoint map does not name the space manager")?;
    let spaceman_size = spaceman_mapping.size;
    if spaceman_size == 0 || !u64::from(spaceman_size).is_multiple_of(u64::from(block_size)) {
        return Err(
            "space manager mapping size is not a positive multiple of the block size".into(),
        );
    }
    let spaceman_blocks = (spaceman_size / block_size) as usize;
    let mut sm =
        SpacemanContext::parse(&bytes, block_size, spaceman_mapping.paddr, spaceman_blocks)?;

    let new_xid = before.xid + 1;

    let mut system_payloads = vec![(system_path.to_vec(), stage1)];
    let mut preboot_payloads = vec![(preboot_path.to_vec(), stage1)];
    if let Some(metadata) = system_version {
        system_payloads.push((
            vec!["System", "Library", "CoreServices", "SystemVersion.plist"],
            metadata,
        ));
        for canonical in ["SystemVersion.plist", "restore/SystemVersion.plist"] {
            let mut parts = vec![group.as_str()];
            parts.extend(
                crate::apfs_write::preboot_metadata_path(preboot_files, canonical).split('/'),
            );
            preboot_payloads.push((parts, metadata));
        }
    }
    for (path, data) in system_files {
        system_payloads.push((path.split('/').collect(), data.as_slice()));
    }
    for (path, data) in preboot_files {
        if path.eq_ignore_ascii_case("SystemVersion.plist")
            || path.eq_ignore_ascii_case("restore/SystemVersion.plist")
        {
            continue;
        }
        let mut parts = vec![group.as_str()];
        parts.extend(path.split('/'));
        preboot_payloads.push((parts, data.as_slice()));
    }
    update_volume_files(
        &mut bytes,
        block_size,
        &mut sm,
        system_paddr,
        system_fs_tree_oid,
        system_fs_tree_paddr,
        system_layout,
        &system_payloads,
        new_xid,
    )?;
    update_volume_files(
        &mut bytes,
        block_size,
        &mut sm,
        preboot_paddr,
        preboot_fs_tree_oid,
        preboot_fs_tree_paddr,
        preboot_layout,
        &preboot_payloads,
        new_xid,
    )?;

    sm.commit(&mut bytes, block_size, new_xid)?;
    append_checkpoint(&mut bytes, block_size, before.superblock_paddr, new_xid)?;

    {
        let mut blocks = SliceBlocks::new(&bytes, block_size);
        verify_container(&mut blocks)
            .map_err(|e| format!("updated container fails verification: {e}"))?;
    }
    if bytes.len() != container.len() {
        return Err("internal: apfs_update changed the container's length".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apfs_read::{ApfsContainer, VolumeChoice};
    use crate::apfs_verify::SliceBlocks as VerifySliceBlocks;
    use crate::apfs_write::create;

    const OS_NAME: &str = "Test Linux";
    const CONTAINER_BYTES: u64 = 2560 * 1024 * 1024;

    fn read_whole(bytes: &[u8], path: &str, volume: &str) -> Vec<u8> {
        let block_count = bytes.len() as u64 / 4096;
        let mut blocks = VerifySliceBlocks::new(bytes, 4096);
        let mut mounted = ApfsContainer::mount(&mut blocks, 4096, block_count).expect("mount");
        let volume = mounted
            .open_volume_chosen(&VolumeChoice::Named(volume.to_string()))
            .unwrap_or_else(|e| panic!("open {volume:?}: {e}"));
        let mut out = Vec::new();
        mounted
            .extract(&volume, path, 0, None, &mut out)
            .unwrap_or_else(|e| panic!("extract {path:?}: {e}"));
        out
    }

    fn group_of(bytes: &[u8]) -> String {
        String::from_utf8(read_whole(bytes, "/boot-volume", "Preboot"))
            .unwrap()
            .trim()
            .to_string()
    }

    fn source_version(version: &str) -> Vec<u8> {
        let mut dictionary = plist::Dictionary::new();
        for (key, value) in [
            ("ProductName", "macOS"),
            ("ProductVersion", version),
            ("ProductBuildVersion", "fixture-build"),
            ("ProductUserVisibleVersion", version),
        ] {
            dictionary.insert(key.into(), plist::Value::String(value.into()));
        }
        let mut bytes = Vec::new();
        plist::Value::Dictionary(dictionary)
            .to_writer_xml(&mut bytes)
            .unwrap();
        bytes
    }

    #[test]
    fn preboot_payloads_insert_and_replace_multi_node_trees() {
        let original = create(CONTAINER_BYTES, OS_NAME, b"old boot").unwrap();
        let group = group_of(&original);
        let files: Vec<_> = (0..300)
            .map(|index| {
                (
                    format!("restore/Firmware/device{index}/payload.im4p"),
                    vec![index as u8; 4123],
                )
            })
            .collect();
        let system = vec![(
            "usr/standalone/bootcaches.plist".to_string(),
            b"bootcaches fixture".to_vec(),
        )];
        let updated =
            update_with_preboot_files(&original, b"new boot", None, &files, &system).unwrap();
        assert_eq!(group_of(&updated), group);
        for (path, data) in &files {
            assert_eq!(
                read_whole(&updated, &format!("/{group}/{path}"), "Preboot"),
                *data
            );
        }
        assert_eq!(
            read_whole(&updated, "/usr/standalone/bootcaches.plist", OS_NAME),
            system[0].1
        );
        let replacement = vec![(files[0].0.clone(), vec![55; 12000])];
        let twice =
            update_with_preboot_files(&updated, b"third boot", None, &replacement, &[]).unwrap();
        assert_eq!(
            read_whole(&twice, &format!("/{group}/{}", files[0].0), "Preboot"),
            replacement[0].1
        );
        assert_eq!(
            read_whole(&twice, &format!("/{group}/{}", files[299].0), "Preboot"),
            files[299].1
        );
        let mut blocks = VerifySliceBlocks::new(&twice, 4096);
        let mut mounted =
            ApfsContainer::mount(&mut blocks, 4096, twice.len() as u64 / 4096).unwrap();
        let volume = mounted
            .open_volume_chosen(&VolumeChoice::Named(OS_NAME.into()))
            .unwrap();
        let frozen = mounted
            .open_snapshot(&volume, &format!("{OS_NAME} install"))
            .unwrap();
        let mut boot = Vec::new();
        mounted
            .extract(
                &frozen,
                "/Finish Installation.app/Contents/Resources/boot.bin",
                0,
                None,
                &mut boot,
            )
            .unwrap();
        assert_eq!(boot, b"old boot");
    }

    #[test]
    fn preboot_payloads_reject_unsafe_and_colliding_names() {
        for names in [
            vec!["../escape"],
            vec!["/absolute"],
            vec!["restore//file"],
            vec!["boot.bin"],
            vec!["restore"],
            vec!["a", "A"],
            vec!["a", "a/b"],
            vec!["SystemVersion.plist"],
        ] {
            let files: Vec<_> = names
                .iter()
                .map(|name| (name.to_string(), vec![1]))
                .collect();
            assert!(update_with_preboot_files(&[], b"boot", None, &files, &[]).is_err());
            assert!(
                crate::apfs_write::create_with_preboot_files(
                    64 * 1024 * 1024,
                    OS_NAME,
                    b"boot",
                    None,
                    &files,
                    &[]
                )
                .is_err()
            );
        }
        let version = source_version("13.5");
        let files = vec![("restore/SystemVersion.plist".to_string(), version.clone())];
        let created = crate::apfs_write::create_with_preboot_files(
            CONTAINER_BYTES,
            OS_NAME,
            b"boot",
            Some(&version),
            &files,
            &[],
        )
        .unwrap();
        let group = group_of(&created);
        assert_eq!(
            read_whole(
                &created,
                &format!("/{group}/restore/SystemVersion.plist"),
                "Preboot"
            ),
            version
        );
    }

    #[test]
    fn preboot_payloads_preserve_source_restore_case_without_duplicate_directories() {
        let version = source_version("13.5");
        let files = vec![
            ("Restore/SystemVersion.plist".to_string(), version.clone()),
            ("Restore/Firmware/test.im4p".to_string(), vec![1, 2, 3]),
        ];
        let created = crate::apfs_write::create_with_preboot_files(
            CONTAINER_BYTES,
            OS_NAME,
            b"boot",
            Some(&version),
            &files,
            &[],
        )
        .unwrap();
        let group = group_of(&created);
        let mut blocks = VerifySliceBlocks::new(&created, 4096);
        let mut mounted =
            ApfsContainer::mount(&mut blocks, 4096, created.len() as u64 / 4096).unwrap();
        let volume = mounted
            .open_volume_chosen(&VolumeChoice::Named("Preboot".into()))
            .unwrap();
        let entries = mounted
            .list_directory(&volume, &format!("/{group}"))
            .unwrap();
        let names: Vec<_> = entries
            .iter()
            .filter(|entry| entry.name.eq_ignore_ascii_case("restore"))
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(names, vec!["Restore"]);
        drop(mounted);
        drop(created);
        let legacy = create(CONTAINER_BYTES, OS_NAME, b"boot").unwrap();
        let updated =
            update_with_preboot_files(&legacy, b"boot", Some(&version), &files, &[]).unwrap();
        let group = group_of(&updated);
        let mut blocks = VerifySliceBlocks::new(&updated, 4096);
        let mut mounted =
            ApfsContainer::mount(&mut blocks, 4096, updated.len() as u64 / 4096).unwrap();
        let volume = mounted
            .open_volume_chosen(&VolumeChoice::Named("Preboot".into()))
            .unwrap();
        let entries = mounted
            .list_directory(&volume, &format!("/{group}"))
            .unwrap();
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.name.eq_ignore_ascii_case("restore"))
                .count(),
            1
        );
        assert_eq!(
            read_whole(
                &updated,
                &format!("/{group}/Restore/Firmware/test.im4p"),
                "Preboot"
            ),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn selected_system_version_updates_all_live_copies_preserving_snapshot() {
        let old = source_version("13.5");
        let new = source_version("13.6");
        let original = crate::apfs_write::create_with_system_version(
            CONTAINER_BYTES,
            OS_NAME,
            b"original",
            Some(&old),
        )
        .unwrap();
        let group = group_of(&original);
        assert_eq!(
            read_whole(
                &original,
                "/System/Library/CoreServices/SystemVersion.plist",
                OS_NAME
            ),
            old
        );
        let updated = update_with_system_version(&original, b"replacement", Some(&new)).unwrap();
        assert_eq!(group_of(&updated), group);
        assert_eq!(
            read_whole(
                &updated,
                "/System/Library/CoreServices/SystemVersion.plist",
                OS_NAME
            ),
            new
        );
        for path in [
            format!("/{group}/SystemVersion.plist"),
            format!("/{group}/restore/SystemVersion.plist"),
        ] {
            assert_eq!(read_whole(&updated, &path, "Preboot"), new);
        }
        assert_eq!(
            read_whole(&updated, &format!("/{group}/boot.bin"), "Preboot"),
            b"replacement"
        );
        let mut blocks = VerifySliceBlocks::new(&updated, 4096);
        let mut mounted =
            ApfsContainer::mount(&mut blocks, 4096, updated.len() as u64 / 4096).unwrap();
        let system = mounted
            .open_volume_chosen(&VolumeChoice::Named(OS_NAME.into()))
            .unwrap();
        let frozen = mounted
            .open_snapshot(&system, &format!("{OS_NAME} install"))
            .unwrap();
        let mut metadata = Vec::new();
        mounted
            .extract(
                &frozen,
                "/System/Library/CoreServices/SystemVersion.plist",
                0,
                None,
                &mut metadata,
            )
            .unwrap();
        assert_eq!(metadata, old);
        let again = update_with_system_version(&updated, b"next", Some(&old)).unwrap();
        assert_eq!(
            read_whole(
                &again,
                "/System/Library/CoreServices/SystemVersion.plist",
                OS_NAME
            ),
            old
        );
    }

    #[test]
    fn selected_system_version_rejects_missing_identity_fields() {
        let malformed = b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict/></plist>";
        assert!(
            crate::apfs_write::create_with_system_version(
                16 * 1024 * 1024,
                OS_NAME,
                b"boot",
                Some(malformed)
            )
            .is_err()
        );
        assert!(update_with_system_version(&[], b"boot", Some(malformed)).is_err());
    }

    #[test]
    fn rejects_empty_stage1() {
        assert!(update(&[0u8; 4096], &[]).is_err());
    }

    #[test]
    fn replaces_both_copies_with_a_same_size_object() {
        let original = vec![0xA5u8; 200_003];
        let container = create(CONTAINER_BYTES, OS_NAME, &original).expect("create");
        let replacement = vec![0x5Au8; 200_003];
        let updated = update(&container, &replacement).expect("update");
        assert_eq!(updated.len(), container.len());

        let group = group_of(&updated);
        assert_eq!(
            read_whole(
                &updated,
                "/Finish Installation.app/Contents/Resources/boot.bin",
                OS_NAME
            ),
            replacement
        );
        assert_eq!(
            read_whole(&updated, &format!("/{group}/boot.bin"), "Preboot"),
            replacement
        );

        let mut blocks = VerifySliceBlocks::new(&updated, 4096);
        crate::apfs_verify::verify_container(&mut blocks).expect("verify_container");
    }

    #[test]
    fn replaces_both_copies_with_a_larger_object() {
        let original = vec![0x11u8; 4_096];
        let container = create(CONTAINER_BYTES, OS_NAME, &original).expect("create");
        let replacement = vec![0x22u8; 3_000_000];
        let updated = update(&container, &replacement).expect("update");
        assert_eq!(updated.len(), container.len());

        let group = group_of(&updated);
        assert_eq!(
            read_whole(
                &updated,
                "/Finish Installation.app/Contents/Resources/boot.bin",
                OS_NAME
            ),
            replacement
        );
        assert_eq!(
            read_whole(&updated, &format!("/{group}/boot.bin"), "Preboot"),
            replacement
        );

        let mut blocks = VerifySliceBlocks::new(&updated, 4096);
        crate::apfs_verify::verify_container(&mut blocks).expect("verify_container");
    }

    #[test]
    fn replaces_both_copies_with_a_smaller_object() {
        let original = vec![0x33u8; 3_000_000];
        let container = create(CONTAINER_BYTES, OS_NAME, &original).expect("create");
        let replacement = vec![0x44u8; 4_097];
        let updated = update(&container, &replacement).expect("update");
        assert_eq!(updated.len(), container.len());

        let group = group_of(&updated);
        assert_eq!(
            read_whole(
                &updated,
                "/Finish Installation.app/Contents/Resources/boot.bin",
                OS_NAME
            ),
            replacement
        );
        assert_eq!(
            read_whole(&updated, &format!("/{group}/boot.bin"), "Preboot"),
            replacement
        );

        let mut blocks = VerifySliceBlocks::new(&updated, 4096);
        crate::apfs_verify::verify_container(&mut blocks).expect("verify_container");
    }

    #[test]
    fn the_newest_checkpoint_wins_and_the_old_one_stays_valid() {
        let original = vec![0xAAu8; 1_000];
        let container = create(CONTAINER_BYTES, OS_NAME, &original).expect("create");
        let before = {
            let mut blocks = VerifySliceBlocks::new(&container, 4096);
            crate::apfs_verify::verify_container(&mut blocks).expect("verify before")
        };
        let replacement = vec![0xBBu8; 1_500];
        let updated = update(&container, &replacement).expect("update");
        let after = {
            let mut blocks = VerifySliceBlocks::new(&updated, 4096);
            crate::apfs_verify::verify_container(&mut blocks).expect("verify after")
        };
        assert!(after.xid > before.xid);
        assert_ne!(after.superblock_paddr, before.superblock_paddr);

        let old_nxsb = block_at(&container, 4096, before.superblock_paddr).unwrap();
        let old_nxsb_after = block_at(&updated, 4096, before.superblock_paddr).unwrap();
        assert_eq!(old_nxsb, old_nxsb_after);
        assert!(fletcher64_valid(old_nxsb_after));
    }

    #[test]
    fn can_be_applied_more_than_once() {
        let container = create(CONTAINER_BYTES, OS_NAME, &vec![0x01u8; 500]).expect("create");
        let once = update(&container, &vec![0x02u8; 9_000]).expect("first update");
        let twice = update(&once, &[0x03u8; 200]).expect("second update");
        assert_eq!(twice.len(), container.len());
        let group = group_of(&twice);
        assert_eq!(
            read_whole(
                &twice,
                "/Finish Installation.app/Contents/Resources/boot.bin",
                OS_NAME
            ),
            vec![0x03u8; 200]
        );
        assert_eq!(
            read_whole(&twice, &format!("/{group}/boot.bin"), "Preboot"),
            vec![0x03u8; 200]
        );
        let mut blocks = VerifySliceBlocks::new(&twice, 4096);
        crate::apfs_verify::verify_container(&mut blocks).expect("verify_container");
    }

    #[test]
    fn rejects_a_container_whose_preboot_selection_does_not_match() {
        let container = create(CONTAINER_BYTES, OS_NAME, &vec![0xAAu8; 500]).expect("create");
        let mut tampered = container.clone();
        let system_paddr = {
            let mut blocks = VerifySliceBlocks::new(&container, 4096);
            let verified = crate::apfs_verify::verify_container(&mut blocks).expect("verify");
            verified
                .volumes
                .iter()
                .find(|v| v.role & APFS_VOL_ROLE_SYSTEM != 0)
                .unwrap()
                .paddr
        };
        let at = system_paddr as usize * 4096 + 0x3F0;
        tampered[at] ^= 0xFF;
        crate::apfs_image::fletcher64_seal(
            &mut tampered[system_paddr as usize * 4096..system_paddr as usize * 4096 + 4096],
        );
        assert!(update(&tampered, &vec![0xBBu8; 500]).is_err());
    }

    #[test]
    fn the_system_snapshot_survives_an_update_byte_identically() {
        let original = vec![0x77u8; 3_000_000];
        let container = create(CONTAINER_BYTES, OS_NAME, &original).expect("create");
        let replacement = vec![0x88u8; 4_500_000];
        let updated = update(&container, &replacement).expect("update");

        let block_count = updated.len() as u64 / 4096;
        let mut blocks = VerifySliceBlocks::new(&updated, 4096);
        let mut mounted = ApfsContainer::mount(&mut blocks, 4096, block_count).expect("mount");
        let system = mounted
            .open_volume_chosen(&VolumeChoice::Named(OS_NAME.to_string()))
            .expect("open System");

        let snapshots = mounted.snapshots(&system).expect("snapshots");
        assert_eq!(snapshots.len(), 1, "{snapshots:?}");
        let snapshot_name = format!("{OS_NAME} install");
        assert_eq!(snapshots[0].name, snapshot_name);

        let frozen = mounted
            .open_snapshot(&system, &snapshot_name)
            .expect("open_snapshot");
        let mut frozen_content = Vec::new();
        mounted
            .extract(
                &frozen,
                "/Finish Installation.app/Contents/Resources/boot.bin",
                0,
                None,
                &mut frozen_content,
            )
            .expect("extract from the frozen snapshot");
        assert_eq!(
            frozen_content, original,
            "the snapshot must still read the original stage-one content, unchanged"
        );

        let mut live_content = Vec::new();
        mounted
            .extract(
                &system,
                "/Finish Installation.app/Contents/Resources/boot.bin",
                0,
                None,
                &mut live_content,
            )
            .expect("extract from the live volume");
        assert_eq!(
            live_content, replacement,
            "the live volume must read the replacement content"
        );
    }

    #[test]
    fn the_system_snapshot_survives_two_updates_in_a_row() {
        let original = vec![0x11u8; 500_000];
        let container = create(CONTAINER_BYTES, OS_NAME, &original).expect("create");
        let once = update(&container, &vec![0x22u8; 9_000_000]).expect("first update");
        let twice = update(&once, &[0x33u8; 123]).expect("second update");

        let block_count = twice.len() as u64 / 4096;
        let mut blocks = VerifySliceBlocks::new(&twice, 4096);
        let mut mounted = ApfsContainer::mount(&mut blocks, 4096, block_count).expect("mount");
        let system = mounted
            .open_volume_chosen(&VolumeChoice::Named(OS_NAME.to_string()))
            .expect("open System");
        let snapshot_name = format!("{OS_NAME} install");
        let frozen = mounted
            .open_snapshot(&system, &snapshot_name)
            .expect("open_snapshot");
        let mut frozen_content = Vec::new();
        mounted
            .extract(
                &frozen,
                "/Finish Installation.app/Contents/Resources/boot.bin",
                0,
                None,
                &mut frozen_content,
            )
            .expect("extract from the frozen snapshot");
        assert_eq!(frozen_content, original);
    }
}
