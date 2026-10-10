use std::collections::{BTreeMap, BTreeSet};

use crate::apfs_image::{fletcher64_seal, fletcher64_valid};
use crate::apfs_read::{ApfsContainer, VolumeChoice};
use crate::apfs_verify::{BTreeNode, Object, SliceBlocks, u16_at, u32_at, u64_at};
use crate::apfs_write::{TreeLayout, TreeStore, record_sort_key, write_tree};
use crate::asahi_ops::{ImageIo, OpsError};
use crate::repair_writer::checkpoint::{self, CheckpointPublish};
use crate::repair_writer::disc::RepairSession;

const ID_MASK: u64 = 0x0fff_ffff_ffff_ffff;
type Record = (Vec<u8>, Vec<u8>);

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn key_id(key: &[u8]) -> Result<(u64, u64), String> {
    if key.len() < 8 {
        return Err("file replacement: short catalog key".into());
    }
    let word = u64_at(key, 0);
    Ok((word & ID_MASK, word >> 60))
}
fn catalog_sort_key(key: &[u8], layout: crate::apfs_verify::DrecKeyLayout) -> (u64, u64, Vec<u8>) {
    if layout == crate::apfs_verify::DrecKeyLayout::Plain
        && key.len() >= 10
        && u64_at(key, 0) >> 60 == 9
    {
        let header = u64_at(key, 0);
        (header & ID_MASK, 9, key[10..].to_vec())
    } else {
        record_sort_key(key)
    }
}

fn block(image: &[u8], bs: u32, paddr: u64) -> Result<&[u8], String> {
    let at = paddr
        .checked_mul(u64::from(bs))
        .and_then(|at| usize::try_from(at).ok())
        .ok_or("APFS block offset overflow")?;
    image
        .get(
            at..at
                .checked_add(bs as usize)
                .ok_or("APFS block end overflow")?,
        )
        .ok_or_else(|| format!("APFS block {paddr} leaves the supplied container"))
}

struct Tree {
    records: Vec<Record>,
    nodes: Vec<(u64, u64)>,
    layout: TreeLayout,
}

fn read_tree(
    image: &[u8],
    bs: u32,
    root: u64,
    map: Option<&BTreeMap<u64, u64>>,
) -> Result<Tree, String> {
    let bytes = block(image, bs, root)?;
    let info = bs as usize - 40;
    let fixed = if u16_at(bytes, 0x20) & 4 != 0 {
        Some((
            u32_at(bytes, info + 8) as usize,
            u32_at(bytes, info + 12) as usize,
        ))
    } else {
        None
    };
    let layout = TreeLayout {
        fixed,
        flags: u32_at(bytes, info),
        subtype: u32_at(bytes, 0x1c),
    };
    let mut tree = Tree {
        records: Vec::new(),
        nodes: Vec::new(),
        layout,
    };
    let mut pending = vec![root];
    let mut seen = BTreeSet::new();
    while let Some(paddr) = pending.pop() {
        if !seen.insert(paddr) {
            return Err(format!("APFS tree repeats block {paddr}"));
        }
        let bytes = block(image, bs, paddr)?;
        if !fletcher64_valid(bytes) {
            return Err(format!("APFS tree checksum failed at block {paddr}"));
        }
        if u16_at(bytes, 0x20) & 0x10 != 0 {
            return Err("file replacement refuses a headerless catalog".into());
        }
        tree.nodes.push((u64_at(bytes, 8), paddr));
        let object = Object {
            paddr,
            bytes: bytes.to_vec(),
        };
        let node = BTreeNode::decode(&object, bs as usize).map_err(|e| e.to_string())?;
        let mut children = Vec::new();
        for index in 0..node.nkeys {
            let (key, value) = node.entry(index).map_err(|e| e.to_string())?;
            if node.is_leaf() {
                let (key, value) = if let Some((ks, vs)) = fixed {
                    (
                        key.get(..ks).ok_or("short fixed APFS key")?,
                        value.get(..vs).ok_or("short fixed APFS value")?,
                    )
                } else {
                    (key, value)
                };
                tree.records.push((key.to_vec(), value.to_vec()));
            } else {
                if value.len() < 8 {
                    return Err("short APFS child reference".into());
                }
                let child = u64_at(value, 0);
                children.push(match map {
                    Some(map) => *map
                        .get(&child)
                        .ok_or_else(|| format!("unmapped APFS catalog child {child}"))?,
                    None => child,
                });
            }
        }
        pending.extend(children.into_iter().rev());
    }
    Ok(tree)
}

fn mappings(records: &[Record], xid: u64) -> Result<BTreeMap<u64, u64>, String> {
    let mut versions = BTreeMap::new();
    for (key, value) in records {
        if key.len() != 16 || value.len() != 16 {
            return Err("short APFS object map record".into());
        }
        let (oid, version) = (u64_at(key, 0), u64_at(key, 8));
        if version <= xid && versions.get(&oid).is_none_or(|(old, _)| version > *old) {
            versions.insert(
                oid,
                (
                    version,
                    if u32_at(value, 0) & 1 == 0 {
                        Some(u64_at(value, 8))
                    } else {
                        None
                    },
                ),
            );
        }
    }
    Ok(versions
        .into_iter()
        .filter_map(|(oid, (_, paddr))| paddr.map(|paddr| (oid, paddr)))
        .collect())
}

fn omap_record(oid: u64, xid: u64, paddr: u64, bs: u32) -> Record {
    let mut key = oid.to_le_bytes().to_vec();
    key.extend_from_slice(&xid.to_le_bytes());
    let mut value = vec![0; 16];
    put32(&mut value, 4, bs);
    put64(&mut value, 8, paddr);
    (key, value)
}

struct Chunk {
    cib: usize,
    slot: usize,
    start: u64,
    count: u32,
    old_bitmap: u64,
    bitmap: Vec<u8>,
    dirty: bool,
}

struct Allocator {
    sm: Vec<u8>,
    cibs: Vec<(u64, Vec<u8>)>,
    chunks: Vec<Chunk>,
    ip_bitmap: Vec<u8>,
    old_ip_slot: u16,
    allocated: u64,
}

impl Allocator {
    fn load(image: &[u8], bs: u32, paddr: u64) -> Result<Self, String> {
        let sm = block(image, bs, paddr)?.to_vec();
        if !fletcher64_valid(&sm) {
            return Err("space manager checksum failed".into());
        }
        if u32_at(&sm, 0x44) != 0 {
            return Err("file replacement refuses indirect chunk addressing".into());
        }
        if u64_at(&sm, 0x60) != 0 {
            return Err("file replacement refuses Fusion allocation".into());
        }
        if u32_at(&sm, 0xa0) != 1 {
            return Err("file replacement refuses a multi-block internal-pool bitmap".into());
        }
        let at = u32_at(&sm, 0x148) as usize;
        if at + 2 > sm.len() {
            return Err("internal-pool bitmap index leaves the space manager".into());
        }
        let old_ip_slot = u16_at(&sm, at);
        let ip_bitmap = block(image, bs, u64_at(&sm, 0xa8) + u64::from(old_ip_slot))?.to_vec();
        if u64_at(&sm, 0x98) > u64::from(bs) * 8 {
            return Err("internal pool exceeds its bitmap".into());
        }
        let count = u32_at(&sm, 0x40) as usize;
        let at = u32_at(&sm, 0x50) as usize;
        if at
            .checked_add(count.checked_mul(8).ok_or("CIB count overflow")?)
            .is_none_or(|end| end > sm.len())
        {
            return Err("chunk address array leaves the space manager".into());
        }
        let mut cibs = Vec::new();
        let mut chunks = Vec::new();
        let mut covered = 0;
        let mut free = 0;
        for index in 0..count {
            let paddr = u64_at(&sm, at + index * 8);
            let bytes = block(image, bs, paddr)?.to_vec();
            if !fletcher64_valid(&bytes) {
                return Err(format!("CIB checksum failed at {paddr}"));
            }
            for slot in 0..u32_at(&bytes, 0x24) as usize {
                let at = 0x28 + slot * 32;
                if at + 32 > bytes.len() {
                    return Err("chunk record leaves its CIB".into());
                }
                let start = u64_at(&bytes, at + 8);
                let count = u32_at(&bytes, at + 16);
                if start != covered || u64::from(count) > u64::from(bs) * 8 {
                    return Err("malformed APFS chunk coverage".into());
                }
                covered += u64::from(count);
                let old_bitmap = u64_at(&bytes, at + 24);
                let bitmap = if old_bitmap == 0 {
                    vec![0; bs as usize]
                } else {
                    block(image, bs, old_bitmap)?.to_vec()
                };
                let counted = (0..count as usize)
                    .filter(|bit| bitmap[bit >> 3] & (1 << (bit & 7)) == 0)
                    .count() as u32;
                if counted != u32_at(&bytes, at + 20) {
                    return Err(format!(
                        "chunk {start} free count disagrees with its bitmap"
                    ));
                }
                free += u64::from(counted);
                chunks.push(Chunk {
                    cib: index,
                    slot,
                    start,
                    count,
                    old_bitmap,
                    bitmap,
                    dirty: false,
                });
            }
            cibs.push((paddr, bytes));
        }
        if covered != u64_at(&sm, 0x30) || free != u64_at(&sm, 0x48) {
            return Err("space manager allocation counts disagree with its chunks".into());
        }
        Ok(Self {
            sm,
            cibs,
            chunks,
            ip_bitmap,
            old_ip_slot,
            allocated: 0,
        })
    }

    fn allocate(&mut self, xid: u64) -> Result<u64, String> {
        for chunk in &mut self.chunks {
            if let Some(bit) =
                (0..chunk.count as usize).find(|bit| chunk.bitmap[bit >> 3] & (1 << (bit & 7)) == 0)
            {
                chunk.bitmap[bit >> 3] |= 1 << (bit & 7);
                chunk.dirty = true;
                let cib = &mut self.cibs[chunk.cib].1;
                let at = 0x28 + chunk.slot * 32;
                let free = u32_at(cib, at + 20)
                    .checked_sub(1)
                    .ok_or("chunk free count underflow")?;
                put64(cib, at, xid);
                put32(cib, at + 20, free);
                let free = u64_at(&self.sm, 0x48)
                    .checked_sub(1)
                    .ok_or("container free count underflow")?;
                put64(&mut self.sm, 0x48, free);
                self.allocated += 1;
                return Ok(chunk.start + bit as u64);
            }
        }
        Err("file replacement: no free main-device block".into())
    }

    fn allocate_ip(&mut self) -> Result<u64, String> {
        let count = u64_at(&self.sm, 0x98) as usize;
        let bit = (0..count)
            .find(|bit| self.ip_bitmap[bit >> 3] & (1 << (bit & 7)) == 0)
            .ok_or("file replacement: internal pool has no free metadata block")?;
        self.ip_bitmap[bit >> 3] |= 1 << (bit & 7);
        Ok(u64_at(&self.sm, 0xb0) + bit as u64)
    }

    fn materialize(
        &mut self,
        disc: &mut RepairSession<'_>,
        xid: u64,
    ) -> Result<Vec<(u64, u64)>, String> {
        let mut retired = Vec::new();
        let dirty_cibs: BTreeSet<usize> = self
            .chunks
            .iter()
            .filter(|chunk| chunk.dirty)
            .map(|chunk| chunk.cib)
            .collect();
        for index in 0..self.chunks.len() {
            if !self.chunks[index].dirty {
                continue;
            }
            let new_bitmap = self.allocate_ip()?;
            let chunk = &self.chunks[index];
            disc.write_block(new_bitmap, &chunk.bitmap)
                .map_err(|e| e.to_string())?;
            if chunk.old_bitmap != 0 {
                retired.push((chunk.old_bitmap, 1));
            }
            put64(
                &mut self.cibs[chunk.cib].1,
                0x28 + chunk.slot * 32 + 24,
                new_bitmap,
            );
        }
        for index in dirty_cibs {
            let new_cib = self.allocate_ip()?;
            let (old, bytes) = &mut self.cibs[index];
            retired.push((*old, 1));
            put64(bytes, 8, new_cib);
            put64(bytes, 16, xid);
            fletcher64_seal(bytes);
            disc.write_block(new_cib, bytes)
                .map_err(|e| e.to_string())?;
            let at = u32_at(&self.sm, 0x50) as usize + index * 8;
            put64(&mut self.sm, at, new_cib);
        }
        let slots = u32_at(&self.sm, 0xa4) as usize;
        let next_at = u32_at(&self.sm, 0x14c) as usize;
        let head = u16_at(&self.sm, 0x140) as usize;
        let tail = u16_at(&self.sm, 0x142) as usize;
        let index_at = u32_at(&self.sm, 0x148) as usize;
        let xid_at = u32_at(&self.sm, 0x144) as usize;
        if head >= slots
            || tail >= slots
            || next_at
                .checked_add(slots * 2)
                .is_none_or(|end| end > self.sm.len())
            || index_at + 2 > self.sm.len()
            || xid_at + 8 > self.sm.len()
            || head == self.old_ip_slot as usize
        {
            return Err("file replacement: invalid or exhausted internal-pool bitmap ring".into());
        }
        let next = u16_at(&self.sm, next_at + head * 2);
        if next == 0xffff {
            return Err("file replacement: internal-pool bitmap free ring exhausted".into());
        }
        disc.write_block(u64_at(&self.sm, 0xa8) + head as u64, &self.ip_bitmap)
            .map_err(|e| e.to_string())?;
        put16(&mut self.sm, 0x140, next);
        put16(&mut self.sm, next_at + head * 2, 0xffff);
        put16(&mut self.sm, next_at + tail * 2, self.old_ip_slot);
        put16(&mut self.sm, 0x142, self.old_ip_slot);
        put16(
            &mut self.sm,
            next_at + self.old_ip_slot as usize * 2,
            0xffff,
        );
        put16(&mut self.sm, index_at, head as u16);
        put64(&mut self.sm, xid_at, xid);
        Ok(retired)
    }
}

struct MemoryImage {
    bytes: Vec<u8>,
}
impl ImageIo for MemoryImage {
    fn read_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), OpsError> {
        let at = usize::try_from(offset)
            .map_err(|_| OpsError::Message("APFS read offset overflow".into()))?;
        let end = at
            .checked_add(out.len())
            .ok_or_else(|| OpsError::Message("APFS read end overflow".into()))?;
        out.copy_from_slice(
            self.bytes
                .get(at..end)
                .ok_or_else(|| OpsError::Message("APFS read leaves container".into()))?,
        );
        Ok(())
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), OpsError> {
        let at = usize::try_from(offset)
            .map_err(|_| OpsError::Message("APFS write offset overflow".into()))?;
        let end = at
            .checked_add(bytes.len())
            .ok_or_else(|| OpsError::Message("APFS write end overflow".into()))?;
        self.bytes
            .get_mut(at..end)
            .ok_or_else(|| OpsError::Message("APFS write leaves container".into()))?
            .copy_from_slice(bytes);
        Ok(())
    }
}

struct Store<'a, 'b> {
    disc: &'a mut RepairSession<'b>,
    allocator: &'a mut Allocator,
    xid: u64,
}
impl TreeStore for Store<'_, '_> {
    fn block_size(&self) -> u32 {
        self.disc.block_size()
    }
    fn alloc(&mut self, blocks: u64) -> Result<u64, String> {
        if blocks != 1 {
            return Err("APFS tree requested a contiguous multi-block allocation".into());
        }
        self.allocator.allocate(self.xid)
    }
    fn write_blocks(&mut self, paddr: u64, bytes: &[u8]) -> Result<(), String> {
        self.disc
            .write_block(paddr, bytes)
            .map_err(|e| e.to_string())
    }
}

struct LeafStore {
    bs: u32,
    body: Option<Vec<u8>>,
    allocated: bool,
}
impl TreeStore for LeafStore {
    fn block_size(&self) -> u32 {
        self.bs
    }
    fn alloc(&mut self, blocks: u64) -> Result<u64, String> {
        if blocks != 1 || self.allocated {
            return Err(
                "file replacement refuses a free queue requiring additional ephemeral nodes".into(),
            );
        }
        self.allocated = true;
        Ok(0)
    }
    fn write_blocks(&mut self, _: u64, bytes: &[u8]) -> Result<(), String> {
        self.body = Some(bytes.to_vec());
        Ok(())
    }
}

fn queue_body(
    image: &[u8],
    bs: u32,
    paddr: u64,
    additions: &[(u64, u64)],
    xid: u64,
) -> Result<(Vec<u8>, u64, u64), String> {
    let original = block(image, bs, paddr)?;
    let tree = read_tree(image, bs, paddr, None)?;
    if tree.nodes.len() != 1 || tree.layout.fixed != Some((16, 8)) {
        return Err("file replacement refuses a non-leaf deferred-free queue".into());
    }
    let mut ranges = Vec::new();
    for (key, value) in tree.records {
        if key.len() != 16 || value.len() != 8 {
            return Err("invalid deferred-free record".into());
        }
        ranges.push((u64_at(&key, 0), u64_at(&key, 8), u64_at(&value, 0).max(1)));
    }
    ranges.extend(
        additions
            .iter()
            .map(|&(paddr, blocks)| (xid, paddr, blocks)),
    );
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64, u64)> = Vec::new();
    for (xid, paddr, count) in ranges {
        if count == 0 {
            continue;
        }
        if let Some((last_xid, last_addr, last_count)) = merged.last_mut() {
            let end = last_addr
                .checked_add(*last_count)
                .ok_or("free queue range overflow")?;
            if *last_xid == xid && paddr == end {
                *last_count = last_count
                    .checked_add(count)
                    .ok_or("free queue count overflow")?;
                continue;
            }
            if *last_xid == xid && paddr < end {
                return Err("overlapping deferred-free ranges".into());
            }
        }
        merged.push((xid, paddr, count));
    }
    let count = merged.iter().try_fold(0u64, |sum, (_, _, count)| {
        sum.checked_add(*count).ok_or("free queue count overflow")
    })?;
    let oldest = merged.first().map_or(0, |entry| entry.0);
    let records = merged
        .into_iter()
        .map(|(xid, paddr, count)| {
            let mut key = xid.to_le_bytes().to_vec();
            key.extend_from_slice(&paddr.to_le_bytes());
            (key, count.to_le_bytes().to_vec())
        })
        .collect();
    let mut store = LeafStore {
        bs,
        body: None,
        allocated: false,
    };
    write_tree(&mut store, records, tree.layout, xid, None, &mut 0)?;
    let mut body = store
        .body
        .ok_or("deferred-free tree writer produced no root")?;
    body[8..32].copy_from_slice(&original[8..32]);
    put64(&mut body, 16, xid);
    fletcher64_seal(&mut body);
    Ok((body, count, oldest))
}

fn replace_inode_stream(
    inode: &[u8],
    private_id: u64,
    logical: u64,
    allocated: u64,
    remove_fork: bool,
) -> Result<Vec<u8>, String> {
    if inode.len() < 0x5c {
        return Err("short regular-file inode".into());
    }
    let mut fields = Vec::new();
    if inode.len() > 0x5c {
        if inode.len() < 0x60 {
            return Err("short inode extended-field header".into());
        }
        let count = u16_at(inode, 0x5c) as usize;
        let mut data_at = 0x60 + count * 4;
        if data_at > inode.len() {
            return Err("inode extended-field table leaves record".into());
        }
        for index in 0..count {
            let at = 0x60 + index * 4;
            let size = u16_at(inode, at + 2) as usize;
            let end = data_at
                .checked_add(size)
                .ok_or("inode field length overflow")?;
            let data = inode
                .get(data_at..end)
                .ok_or("inode extended field leaves record")?;
            if inode[at] != 8 {
                fields.push((inode[at..at + 4].to_vec(), data.to_vec()));
            }
            data_at += size.next_multiple_of(8);
        }
    }
    let mut stream = vec![0; 40];
    put64(&mut stream, 0, logical);
    put64(&mut stream, 8, allocated);
    put64(&mut stream, 24, logical);
    fields.push((vec![8, 0, 40, 0], stream));
    let mut out = inode[..0x5c].to_vec();
    put64(&mut out, 8, private_id);
    put32(&mut out, 0x44, u32_at(inode, 0x44) & !0x20);
    let mut flags = u64_at(inode, 0x30) & !0x40000;
    if remove_fork {
        flags = (flags & !0x4000) | 0x8000;
    }
    put64(&mut out, 0x30, flags);
    put64(&mut out, 0x54, 0);
    let used: usize = fields
        .iter()
        .map(|(_, data)| data.len().next_multiple_of(8))
        .sum();
    out.extend_from_slice(
        &u16::try_from(fields.len())
            .map_err(|_| "inode field count overflow")?
            .to_le_bytes(),
    );
    out.extend_from_slice(
        &u16::try_from(used)
            .map_err(|_| "inode field data overflow")?
            .to_le_bytes(),
    );
    for (entry, _) in &fields {
        out.extend_from_slice(entry);
    }
    for (_, data) in fields {
        out.extend_from_slice(&data);
        out.resize(out.len() + data.len().next_multiple_of(8) - data.len(), 0);
    }
    Ok(out)
}

fn detach_stream(
    records: &mut Vec<Record>,
    extrefs: &mut Vec<Record>,
    stream: u64,
    owner: u64,
    bs: u32,
    retained: bool,
) -> Result<Vec<(u64, u64)>, String> {
    let mut extents = Vec::new();
    for (key, value) in records.iter() {
        let (id, kind) = key_id(key)?;
        if id != stream {
            continue;
        }
        if kind == 6 && (value.len() != 4 || u32_at(value, 0) != 1) {
            return Err(format!("file replacement refuses shared stream {stream}"));
        }
        if kind != 8 {
            continue;
        }
        if key.len() != 16 || value.len() != 24 || u64_at(value, 16) != 0 {
            return Err(format!(
                "file replacement refuses encrypted or malformed stream {stream}"
            ));
        }
        let bytes = u64_at(value, 0) & ID_MASK;
        let paddr = u64_at(value, 8);
        if paddr == 0 {
            continue;
        }
        if !bytes.is_multiple_of(u64::from(bs)) {
            return Err("unaligned APFS file extent".into());
        }
        let blocks = bytes / u64::from(bs);
        let index = extrefs
            .iter()
            .position(|(key, _)| key.len() == 8 && u64_at(key, 0) & ID_MASK == paddr)
            .ok_or_else(|| {
                format!("stream {stream} extent {paddr} has no owned physical extent record")
            })?;
        let value = &extrefs[index].1;
        if value.len() != 20
            || u64_at(value, 0) & ID_MASK != blocks
            || u64_at(value, 8) != owner
            || u32_at(value, 16) != 1
        {
            return Err(format!(
                "file replacement refuses shared or split physical extent {paddr} of stream {stream}"
            ));
        }
        if !retained {
            extrefs.remove(index);
            extents.push((paddr, blocks));
        }
    }
    records.retain(|(key, _)| {
        key_id(key).is_ok_and(|(id, kind)| id != stream || (kind != 6 && kind != 8))
    });
    Ok(extents)
}

/// Replace one regular file in a raw, mutable APFS container using a new checkpoint.
pub fn replace_file_in_container(
    image: &[u8],
    volume: VolumeChoice,
    guest_path: &str,
    expected_old_sha256: &[u8; 32],
    replacement: &[u8],
) -> Result<Vec<u8>, String> {
    let (bs, block_count) =
        crate::apfs_read::container_geometry_of(image).map_err(|e| e.to_string())?;
    if image.len() as u64
        != u64::from(bs)
            .checked_mul(block_count)
            .ok_or("APFS container length overflow")?
    {
        return Err("file replacement requires exactly one raw APFS container".into());
    }
    let mut source = SliceBlocks::new(image, bs);
    crate::apfs_verify::verify_container(&mut source).map_err(|error| {
        format!("file replacement refuses an unverifiable source container: {error}")
    })?;
    let mut container =
        ApfsContainer::mount(&mut source, bs, block_count).map_err(|e| e.to_string())?;
    let mounted = container
        .open_volume_chosen(&volume)
        .map_err(|e| e.to_string())?;
    if mounted.sealed() {
        return Err(format!(
            "file replacement refuses sealed volume {:?}",
            mounted.name()
        ));
    }
    if mounted.encrypted() {
        return Err(format!(
            "file replacement refuses encrypted volume {:?}",
            mounted.name()
        ));
    }
    let facts = container
        .stat(&mounted, guest_path)
        .map_err(|e| e.to_string())?;
    if !facts.is_regular_file() {
        return Err(format!(
            "{guest_path}: file replacement requires a regular file"
        ));
    }
    let mut original = Vec::new();
    container
        .extract(&mounted, guest_path, 0, None, &mut original)
        .map_err(|e| e.to_string())?;
    if &crate::crypto::sha256(&original) != expected_old_sha256 {
        return Err(format!(
            "{guest_path}: logical SHA-256 does not match the expected original"
        ));
    }
    let sb_paddr = container.superblock_paddr();
    let old_xid = container.xid();
    let xid = old_xid
        .checked_add(1)
        .ok_or("APFS transaction ID overflow")?;
    let volume_oid = mounted.oid();
    let volume_paddr = mounted.apsb_paddr();
    let fs_root = mounted.fs_tree_paddr();
    drop(container);
    let sb = block(image, bs, sb_paddr)?;
    let mut apsb = block(image, bs, volume_paddr)?.to_vec();
    if u64_at(&apsb, 0x400) != 0 {
        return Err("file replacement refuses volume integrity metadata".into());
    }
    if u64_at(&apsb, 0x48) != 0 || u64_at(&apsb, 0x50) != 0 {
        return Err("file replacement refuses volume reservation or quota accounting".into());
    }
    if u64_at(&apsb, 0xa0) != 0 || u64_at(&apsb, 0xa8) != 0 {
        return Err("file replacement refuses a volume with pending snapshot reversion".into());
    }
    let retained = u64_at(&apsb, 0xd8) != 0;
    let vol_omap_paddr = u64_at(&apsb, 0x80);
    let vol_omap = block(image, bs, vol_omap_paddr)?;
    let mut vol_map_tree = read_tree(image, bs, u64_at(vol_omap, 0x30), None)?;
    let map = mappings(&vol_map_tree.records, old_xid)?;
    let mut catalog = read_tree(image, bs, fs_root, Some(&map))?;
    let extent_root = u64_at(&apsb, 0x90);
    let mut extrefs = read_tree(image, bs, extent_root, None)?;
    let inode_index = catalog
        .records
        .iter()
        .position(|(key, _)| key_id(key) == Ok((facts.file_id, 3)))
        .ok_or("resolved file inode is missing from its catalog")?;
    let inode = catalog.records[inode_index].1.clone();
    if facts.default_crypto_id.is_some_and(|id| id != 0) {
        return Err("file replacement refuses an encrypted file data stream".into());
    }
    if catalog
        .records
        .iter()
        .any(|(key, _)| key_id(key).is_ok_and(|(_, kind)| kind == 10))
        && replacement.len() != original.len()
    {
        return Err(
            "file replacement refuses a size change with directory-statistics accounting".into(),
        );
    }
    let remove_fork = matches!(facts.compression_type, Some(4 | 8));
    let mut removed_attrs = BTreeSet::new();
    let mut streams = BTreeSet::new();
    if facts.stream_size.is_some() {
        streams.insert(facts.private_id);
    }
    for (index, (key, value)) in catalog.records.iter().enumerate() {
        if key_id(key)? != (facts.file_id, 4) {
            continue;
        }
        if key.len() < 10 {
            return Err("short extended-attribute key".into());
        }
        let count = u16_at(key, 8) as usize;
        let name = key
            .get(10..10 + count.saturating_sub(1))
            .ok_or("extended-attribute name leaves key")?;
        if name != b"com.apple.decmpfs" && !(remove_fork && name == b"com.apple.ResourceFork") {
            continue;
        }
        if value.len() < 4 {
            return Err("short extended-attribute value".into());
        }
        if u16_at(value, 0) & 1 != 0 {
            if value.len() < 52 {
                return Err("short extended-attribute data stream".into());
            }
            streams.insert(u64_at(value, 4));
        }
        removed_attrs.insert(index);
    }
    let mut retired_data = Vec::new();
    for stream in &streams {
        let references = catalog
            .records
            .iter()
            .filter(|(key, value)| {
                if let Ok((_, kind)) = key_id(key) {
                    if kind == 3 {
                        return value.len() >= 16
                            && u64_at(value, 8) == *stream
                            && value.len() > 0x5c;
                    }
                    if kind == 4 {
                        return value.len() >= 52
                            && u16_at(value, 0) & 1 != 0
                            && u64_at(value, 4) == *stream;
                    }
                }
                false
            })
            .count();
        if references != 1 {
            return Err(format!(
                "file replacement refuses stream {stream} with {references} catalog owners"
            ));
        }
    }
    catalog.records = catalog
        .records
        .into_iter()
        .enumerate()
        .filter_map(|(index, record)| (!removed_attrs.contains(&index)).then_some(record))
        .collect();
    for stream in streams {
        retired_data.extend(detach_stream(
            &mut catalog.records,
            &mut extrefs.records,
            stream,
            facts.file_id,
            bs,
            retained,
        )?);
    }
    let private_id = u64_at(&apsb, 0xb0);
    let next_file_id = private_id
        .checked_add(1)
        .ok_or("APFS stream object ID overflow")?;
    if next_file_id > ID_MASK {
        return Err("APFS stream object ID exceeds catalog key range".into());
    }
    let mut next_metadata_oid = u64_at(sb, 0x58);
    let mut memory = MemoryImage {
        bytes: image.to_vec(),
    };
    let mut disc = RepairSession::new(&mut memory, 0, bs, block_count);
    let mut ephemeral =
        checkpoint::collect_ephemeral_objects(&mut disc, sb_paddr).map_err(|e| e.to_string())?;
    let spaceman_oid = u64_at(sb, 0x98);
    let spaceman_paddr = ephemeral
        .iter()
        .find(|entry| entry.oid == spaceman_oid)
        .ok_or("published checkpoint has no space manager")?
        .paddr;
    let mut allocator = Allocator::load(image, bs, spaceman_paddr)?;
    for entry in &ephemeral {
        let body = block(image, bs, entry.paddr)?;
        if u32_at(body, 0x18) & 0xffff == 5 && u32_at(body, 0xa0) != 1 {
            return Err("file replacement refuses a multi-block space manager bitmap".into());
        }
    }
    let old_head = u16_at(&allocator.sm, 0x140);
    let desc_base = u64_at(sb, 0x70);
    let desc_blocks = u32_at(sb, 0x68);
    if desc_blocks & 0x8000_0000 != 0 {
        return Err("file replacement refuses a tree-backed checkpoint descriptor area".into());
    }
    for slot in 0..u64::from(desc_blocks) {
        let candidate = block(image, bs, desc_base + slot)?;
        if !fletcher64_valid(candidate) || u32_at(candidate, 0x20) != crate::apfs_verify::NX_MAGIC {
            continue;
        }
        let objects = checkpoint::collect_ephemeral_objects(&mut disc, desc_base + slot)
            .map_err(|e| e.to_string())?;
        if let Some(entry) = objects
            .iter()
            .find(|entry| entry.oid == u64_at(candidate, 0x98))
        {
            let old_sm = block(image, bs, entry.paddr)?;
            let at = u32_at(old_sm, 0x148) as usize;
            if at + 2 > old_sm.len() {
                return Err(
                    "checkpoint internal-pool bitmap index leaves its space manager".into(),
                );
            }
            if u16_at(old_sm, at) == old_head {
                return Err("file replacement refuses reuse of an internal-pool bitmap still referenced by a checkpoint".into());
            }
        }
    }
    let mut store = Store {
        disc: &mut disc,
        allocator: &mut allocator,
        xid,
    };
    let allocated = (replacement.len() as u64)
        .div_ceil(u64::from(bs))
        .checked_mul(u64::from(bs))
        .ok_or("replacement allocated length overflow")?;
    let mut runs: Vec<(u64, u64, u64)> = Vec::new();
    for (index, data) in replacement.chunks(bs as usize).enumerate() {
        let paddr = store.alloc(1)?;
        let mut bytes = vec![0; bs as usize];
        bytes[..data.len()].copy_from_slice(data);
        store.write_blocks(paddr, &bytes)?;
        if let Some((_, start, blocks)) = runs.last_mut()
            && *start + *blocks == paddr
        {
            *blocks += 1;
        } else {
            runs.push((index as u64 * u64::from(bs), paddr, 1));
        }
    }
    let inode = replace_inode_stream(
        &inode,
        private_id,
        replacement.len() as u64,
        allocated,
        remove_fork,
    )?;
    let index = catalog
        .records
        .iter()
        .position(|(key, _)| key_id(key) == Ok((facts.file_id, 3)))
        .ok_or("replacement inode disappeared")?;
    catalog.records[index].1 = inode;
    catalog.records.push((
        crate::apfs_write::dstream_id_key(private_id),
        crate::apfs_write::dstream_id_val(1),
    ));
    for &(logical, paddr, blocks) in &runs {
        let mut key = ((8 << 60) | private_id).to_le_bytes().to_vec();
        key.extend_from_slice(&logical.to_le_bytes());
        catalog.records.push((
            key,
            crate::apfs_write::extent_val(blocks * u64::from(bs), paddr),
        ));
        let mut value = vec![0; 20];
        put64(&mut value, 0, (1 << 60) | blocks);
        put64(&mut value, 8, facts.file_id);
        put32(&mut value, 16, 1);
        extrefs
            .records
            .push((((2 << 60) | paddr).to_le_bytes().to_vec(), value));
    }
    catalog.records.sort_by_key(|(key, _)| {
        catalog_sort_key(
            key,
            crate::apfs_verify::DrecKeyLayout::of(u64_at(&apsb, 0x38)),
        )
    });
    extrefs.records.sort_by_key(|(key, _)| record_sort_key(key));
    let root_oid = u64_at(&apsb, 0x88);
    let (_, new_mappings) = write_tree(
        &mut store,
        catalog.records,
        catalog.layout,
        xid,
        Some(root_oid),
        &mut next_metadata_oid,
    )?;
    if !retained {
        let old_oids: BTreeSet<u64> = catalog.nodes.iter().map(|(oid, _)| *oid).collect();
        vol_map_tree
            .records
            .retain(|(key, _)| !old_oids.contains(&u64_at(key, 0)));
    }
    for (oid, paddr) in new_mappings {
        vol_map_tree.records.push(omap_record(oid, xid, paddr, bs));
    }
    vol_map_tree
        .records
        .sort_by_key(|(key, _)| (u64_at(key, 0), u64_at(key, 8)));
    let (new_vol_map_tree, _) = write_tree(
        &mut store,
        vol_map_tree.records,
        vol_map_tree.layout,
        xid,
        None,
        &mut next_metadata_oid,
    )?;
    let (new_extref, _) = write_tree(
        &mut store,
        extrefs.records,
        extrefs.layout,
        xid,
        None,
        &mut next_metadata_oid,
    )?;
    let new_vol_omap = store.alloc(1)?;
    let mut omap = vol_omap.to_vec();
    put64(&mut omap, 8, new_vol_omap);
    put64(&mut omap, 16, xid);
    put64(&mut omap, 0x30, new_vol_map_tree);
    fletcher64_seal(&mut omap);
    store.write_blocks(new_vol_omap, &omap)?;
    let new_apsb = store.alloc(1)?;
    let retired_data_count = retired_data.iter().try_fold(0u64, |sum, (_, count)| {
        sum.checked_add(*count)
            .ok_or("retired data block count overflow")
    })?;
    let mut volume_retired = retired_data;
    if !retained {
        volume_retired.extend(
            catalog
                .nodes
                .iter()
                .chain(&vol_map_tree.nodes)
                .chain(&extrefs.nodes)
                .map(|(_, paddr)| (*paddr, 1)),
        );
        volume_retired.push((vol_omap_paddr, 1));
    }
    volume_retired.push((volume_paddr, 1));
    let retired_count = volume_retired.iter().try_fold(0u64, |sum, (_, count)| {
        sum.checked_add(*count)
            .ok_or("retired volume block count overflow")
    })?;
    let volume_allocated = u64_at(&apsb, 0x58)
        .checked_add(store.allocator.allocated)
        .and_then(|count| count.checked_sub(retired_count))
        .ok_or("volume allocation count overflow or underflow")?;
    let total_allocated = u64_at(&apsb, 0xe0)
        .checked_add(allocated / u64::from(bs))
        .ok_or("volume total allocated block count overflow")?;
    let total_freed = u64_at(&apsb, 0xe8)
        .checked_add(retired_data_count)
        .ok_or("volume total freed block count overflow")?;
    put64(&mut apsb, 0xe0, total_allocated);
    put64(&mut apsb, 0xe8, total_freed);
    put64(&mut apsb, 0x58, volume_allocated);
    put64(&mut apsb, 0x80, new_vol_omap);
    put64(&mut apsb, 0x90, new_extref);
    put64(&mut apsb, 0xb0, next_file_id);
    put64(&mut apsb, 16, xid);
    fletcher64_seal(&mut apsb);
    store.write_blocks(new_apsb, &apsb)?;
    let container_omap_paddr = u64_at(sb, 0xa0);
    let container_omap = block(image, bs, container_omap_paddr)?;
    let mut container_tree = read_tree(image, bs, u64_at(container_omap, 0x30), None)?;
    container_tree
        .records
        .retain(|(key, _)| u64_at(key, 0) != volume_oid);
    container_tree
        .records
        .push(omap_record(volume_oid, xid, new_apsb, bs));
    container_tree
        .records
        .sort_by_key(|(key, _)| (u64_at(key, 0), u64_at(key, 8)));
    let (new_container_tree, _) = write_tree(
        &mut store,
        container_tree.records,
        container_tree.layout,
        xid,
        None,
        &mut next_metadata_oid,
    )?;
    let new_container_omap = store.alloc(1)?;
    let mut omap = container_omap.to_vec();
    put64(&mut omap, 8, new_container_omap);
    put64(&mut omap, 16, xid);
    put64(&mut omap, 0x30, new_container_tree);
    fletcher64_seal(&mut omap);
    store.write_blocks(new_container_omap, &omap)?;
    volume_retired.extend(container_tree.nodes.iter().map(|(_, paddr)| (*paddr, 1)));
    volume_retired.push((container_omap_paddr, 1));
    let retired_metadata = store.allocator.materialize(store.disc, xid)?;
    let ip_base = u64_at(&store.allocator.sm, 0xb0);
    let ip_end = ip_base
        .checked_add(u64_at(&store.allocator.sm, 0x98))
        .ok_or("internal pool extent overflow")?;
    let mut ip_retired = Vec::new();
    for (paddr, count) in retired_metadata {
        if paddr >= ip_base && paddr.checked_add(count).is_some_and(|end| end <= ip_end) {
            ip_retired.push((paddr, count));
        } else {
            volume_retired.push((paddr, count));
        }
    }
    let mut bodies = Vec::new();
    for (queue, retired) in [(0usize, ip_retired), (1usize, volume_retired)] {
        if retired.is_empty() {
            continue;
        }
        let at = 0xc8 + queue * 40;
        let oid = u64_at(&store.allocator.sm, at + 8);
        let (oid, body, count, oldest) = if oid == 0 {
            let new_oid = next_metadata_oid;
            next_metadata_oid = next_metadata_oid
                .checked_add(1)
                .ok_or("APFS ephemeral object ID overflow")?;
            if new_oid == 0 || ephemeral.iter().any(|entry| entry.oid == new_oid) {
                return Err("file replacement: container next object ID cannot name a new deferred-free queue".into());
            }
            let mut store = LeafStore {
                bs,
                body: None,
                allocated: false,
            };
            let mut records = Vec::new();
            let mut ranges = retired.clone();
            ranges.sort_unstable();
            let mut merged: Vec<(u64, u64)> = Vec::new();
            for (paddr, count) in ranges {
                if let Some((start, length)) = merged.last_mut()
                    && *start + *length == paddr
                {
                    *length += count;
                } else {
                    merged.push((paddr, count));
                }
            }
            let count = merged.iter().map(|(_, count)| *count).sum();
            for (paddr, count) in merged {
                let mut key = xid.to_le_bytes().to_vec();
                key.extend_from_slice(&paddr.to_le_bytes());
                records.push((key, count.to_le_bytes().to_vec()));
            }
            write_tree(
                &mut store,
                records,
                TreeLayout {
                    fixed: Some((16, 8)),
                    flags: 0x0e,
                    subtype: 9,
                },
                xid,
                None,
                &mut 0,
            )?;
            let mut body = store.body.ok_or("new deferred-free queue has no root")?;
            put64(&mut body, 8, new_oid);
            put32(&mut body, 0x18, 0x8000_0002);
            fletcher64_seal(&mut body);
            let data_blocks = u32_at(sb, 0x6c);
            if data_blocks == 0 {
                return Err("checkpoint data ring has no blocks".into());
            }
            let next_data = (u64::from(u32_at(sb, 0x90))
                + u64::from(u32_at(sb, 0x94))
                + ephemeral.len() as u64)
                % u64::from(data_blocks);
            ephemeral.push(checkpoint::EphemeralObject {
                oid: new_oid,
                o_type: 0x8000_0002,
                subtype: 9,
                paddr: u64_at(sb, 0x78) + next_data,
            });
            (new_oid, body, count, xid)
        } else {
            let paddr = ephemeral
                .iter()
                .find(|entry| entry.oid == oid)
                .ok_or_else(|| {
                    format!("file replacement: deferred-free queue {queue} is not published")
                })?
                .paddr;
            let (body, count, oldest) = queue_body(image, bs, paddr, &retired, xid)?;
            (oid, body, count, oldest)
        };
        put64(&mut store.allocator.sm, at + 8, oid);
        if u16_at(&store.allocator.sm, at + 24) == 0 {
            put16(&mut store.allocator.sm, at + 24, 1);
        }
        put64(&mut store.allocator.sm, at, count);
        put64(&mut store.allocator.sm, at + 16, oldest);
        bodies.push((oid, body));
    }
    bodies.push((spaceman_oid, store.allocator.sm.clone()));
    checkpoint::append_with(
        store.disc,
        sb_paddr,
        xid,
        &ephemeral,
        &CheckpointPublish {
            omap_oid: Some(new_container_omap),
            next_oid: Some(next_metadata_oid),
            ephemeral_bodies: bodies,
        },
    )
    .map_err(|e| e.to_string())?;
    let mut source = SliceBlocks::new(&memory.bytes, bs);
    crate::apfs_verify::verify_container(&mut source).map_err(|error| {
        format!("file replacement transaction failed allocation or metadata verification: {error}")
    })?;
    let mut container =
        ApfsContainer::mount(&mut source, bs, block_count).map_err(|e| e.to_string())?;
    let mounted = container
        .open_volume_chosen(&volume)
        .map_err(|e| e.to_string())?;
    let mut readback = Vec::new();
    container
        .extract(&mounted, guest_path, 0, None, &mut readback)
        .map_err(|e| e.to_string())?;
    if readback != replacement {
        return Err(format!(
            "{guest_path}: replacement logical readback differs from the supplied bytes"
        ));
    }
    drop(container);
    Ok(memory.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn resource_fork(logical: &[u8]) -> Vec<u8> {
        let chunks: Vec<Vec<u8>> = logical
            .chunks(65536)
            .map(|bytes| {
                let mut encoder =
                    flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(bytes).unwrap();
                encoder.finish().unwrap()
            })
            .collect();
        let mut entry = vec![0; 4 + chunks.len() * 8];
        put32(&mut entry, 0, chunks.len() as u32);
        for (index, chunk) in chunks.iter().enumerate() {
            let at = entry.len() as u32;
            put32(&mut entry, 4 + index * 8, at);
            put32(&mut entry, 8 + index * 8, chunk.len() as u32);
            entry.extend_from_slice(chunk);
        }
        let data_len = 4 + entry.len();
        let map_at = 256 + data_len;
        let mut fork = vec![0; map_at + 50];
        for (at, value) in [
            (0, 256u32),
            (4, map_at as u32),
            (8, data_len as u32),
            (12, 50),
        ] {
            fork[at..at + 4].copy_from_slice(&value.to_be_bytes());
        }
        fork[256..260].copy_from_slice(&(entry.len() as u32).to_be_bytes());
        fork[260..map_at].copy_from_slice(&entry);
        let header = fork[..16].to_vec();
        fork[map_at..map_at + 16].copy_from_slice(&header);
        fork[map_at + 24..map_at + 26].copy_from_slice(&28u16.to_be_bytes());
        fork[map_at + 26..map_at + 28].copy_from_slice(&50u16.to_be_bytes());
        fork[map_at + 30..map_at + 34].copy_from_slice(b"cmpf");
        fork[map_at + 36..map_at + 38].copy_from_slice(&10u16.to_be_bytes());
        fork[map_at + 38..map_at + 40].copy_from_slice(&1u16.to_be_bytes());
        fork[map_at + 40..map_at + 42].copy_from_slice(&0xffffu16.to_be_bytes());
        fork
    }

    fn fixture(logical: &[u8], snapshots: bool) -> Vec<u8> {
        let fork = resource_fork(logical);
        let mut files = vec![
            ("usr/local/bin/restored_external".into(), fork.clone()),
            ("usr/local/bin/neighbor".into(), b"neighbor bytes".to_vec()),
        ];
        for index in 0..1400 {
            files.push((
                format!("catalog/{index:04}{}", "n".repeat(190)),
                vec![index as u8],
            ));
        }
        let mut image = crate::apfs_write::create_with_preboot_files(
            64 * 1024 * 1024,
            "System",
            b"boot",
            None,
            &[],
            &files,
        )
        .unwrap();
        let (bs, blocks) = crate::apfs_read::container_geometry_of(&image).unwrap();
        let zero = block(&image, bs, 0).unwrap();
        let descriptor_base = u64_at(zero, 0x70);
        let descriptor_count = u64::from(u32_at(zero, 0x68));
        let checkpoint_paddr = descriptor_base
            + (u64::from(u32_at(zero, 0x88)) + u64::from(u32_at(zero, 0x8c)) - 1)
                % descriptor_count;
        let container_omap = block(&image, bs, u64_at(zero, 0xa0)).unwrap();
        let volume_map = read_tree(&image, bs, u64_at(container_omap, 0x30), None).unwrap();
        let system_oid = volume_map
            .records
            .iter()
            .find_map(|(key, value)| {
                let volume = block(&image, bs, u64_at(value, 8)).unwrap();
                (u16_at(volume, 0x3c4) == 1).then(|| u64_at(key, 0))
            })
            .unwrap();
        for paddr in [0, checkpoint_paddr] {
            let mut superblock = block(&image, bs, paddr).unwrap().to_vec();
            put64(&mut superblock, 0xb8, system_oid);
            for slot in 1..100 {
                put64(&mut superblock, 0xb8 + slot * 8, 0);
            }
            fletcher64_seal(&mut superblock);
            let at = paddr as usize * bs as usize;
            image[at..at + bs as usize].copy_from_slice(&superblock);
        }
        let mut source = SliceBlocks::new(&image, bs);
        let mut container = ApfsContainer::mount(&mut source, bs, blocks).unwrap();
        let volume = container
            .open_volume_chosen(&VolumeChoice::Role(1))
            .unwrap();
        let facts = container
            .stat(&volume, "/usr/local/bin/restored_external")
            .unwrap();
        let sb_addr = container.superblock_paddr();
        let apsb_addr = volume.apsb_paddr();
        let fs_addr = volume.fs_tree_paddr();
        drop(container);
        let sb = block(&image, bs, sb_addr).unwrap();
        let mut apsb = block(&image, bs, apsb_addr).unwrap().to_vec();
        let vol_omap_addr = u64_at(&apsb, 0x80);
        let mut vol_omap = block(&image, bs, vol_omap_addr).unwrap().to_vec();
        let mut omap = read_tree(&image, bs, u64_at(&vol_omap, 0x30), None).unwrap();
        let map = mappings(&omap.records, 1).unwrap();
        let mut catalog = read_tree(&image, bs, fs_addr, Some(&map)).unwrap();
        let mut next_metadata_oid = u64_at(sb, 0x58);
        let fork_id = u64_at(&apsb, 0xb0).max(
            next_metadata_oid
                .checked_add(catalog.records.len() as u64 + 1)
                .unwrap(),
        );
        let next_file_id = fork_id.checked_add(1).unwrap();
        let target = catalog
            .records
            .iter_mut()
            .find(|(key, _)| key_id(key) == Ok((facts.file_id, 3)))
            .unwrap();
        let alloced = u64_at(&target.1, 0x6c);
        let mut inode = target.1[..0x5c].to_vec();
        put64(&mut inode, 0x30, 0x44000);
        put32(&mut inode, 0x44, 0x20);
        put64(&mut inode, 0x54, logical.len() as u64);
        let name = b"restored_external\0";
        inode.extend_from_slice(&1u16.to_le_bytes());
        inode.extend_from_slice(&(name.len().next_multiple_of(8) as u16).to_le_bytes());
        inode.extend_from_slice(&[4, 2, name.len() as u8, 0]);
        inode.extend_from_slice(name);
        inode.resize(0x64 + name.len().next_multiple_of(8), 0);
        target.1 = inode;
        catalog
            .records
            .retain(|(key, _)| key_id(key) != Ok((facts.private_id, 6)));
        for (key, _) in &mut catalog.records {
            if key_id(key) == Ok((facts.private_id, 8)) {
                put64(key, 0, (8 << 60) | fork_id);
            }
        }
        let mut header = b"fpmc".to_vec();
        header.extend_from_slice(&4u32.to_le_bytes());
        header.extend_from_slice(&(logical.len() as u64).to_le_bytes());
        for (name, value) in [
            ("com.apple.decmpfs", {
                let mut v = vec![2, 0, 16, 0];
                v.extend_from_slice(&header);
                v
            }),
            ("com.apple.ResourceFork", {
                let mut v = vec![0; 52];
                put16(&mut v, 0, 1);
                put16(&mut v, 2, 48);
                put64(&mut v, 4, fork_id);
                put64(&mut v, 12, fork.len() as u64);
                put64(&mut v, 20, alloced);
                put64(&mut v, 36, fork.len() as u64);
                v
            }),
        ] {
            let mut key = ((4 << 60) | facts.file_id).to_le_bytes().to_vec();
            key.extend_from_slice(&((name.len() + 1) as u16).to_le_bytes());
            key.extend_from_slice(name.as_bytes());
            key.push(0);
            catalog.records.push((key, value));
        }
        catalog.records.sort_by_key(|(key, _)| {
            catalog_sort_key(
                key,
                crate::apfs_verify::DrecKeyLayout::of(u64_at(&apsb, 0x38)),
            )
        });
        let mut memory = MemoryImage {
            bytes: image.clone(),
        };
        let mut disc = RepairSession::new(&mut memory, 0, bs, blocks);
        let ephemeral = checkpoint::collect_ephemeral_objects(&mut disc, sb_addr).unwrap();
        let sm_addr = ephemeral
            .iter()
            .find(|entry| entry.oid == u64_at(sb, 0x98))
            .unwrap()
            .paddr;
        let mut allocator = Allocator::load(&image, bs, sm_addr).unwrap();
        let mut store = Store {
            disc: &mut disc,
            allocator: &mut allocator,
            xid: 1,
        };
        let (_, maps) = write_tree(
            &mut store,
            catalog.records,
            catalog.layout,
            1,
            Some(u64_at(&apsb, 0x88)),
            &mut next_metadata_oid,
        )
        .unwrap();
        let old_oids: BTreeSet<u64> = catalog.nodes.iter().map(|(oid, _)| *oid).collect();
        omap.records
            .retain(|(key, _)| !old_oids.contains(&u64_at(key, 0)));
        for (oid, paddr) in maps {
            omap.records.push(omap_record(oid, 1, paddr, bs));
        }
        omap.records
            .sort_by_key(|(key, _)| (u64_at(key, 0), u64_at(key, 8)));
        let (omap_root, _) = write_tree(
            &mut store,
            omap.records,
            omap.layout,
            1,
            None,
            &mut next_metadata_oid,
        )
        .unwrap();
        if !snapshots {
            put32(&mut vol_omap, 0x24, 0);
            put64(&mut vol_omap, 0x38, 0);
            put64(&mut vol_omap, 0x40, 0);
            let snapshot_root = u64_at(&apsb, 0x98);
            let snapshot_tree = read_tree(&image, bs, snapshot_root, None).unwrap();
            let mut leaf = LeafStore {
                bs,
                body: None,
                allocated: false,
            };
            write_tree(&mut leaf, Vec::new(), snapshot_tree.layout, 1, None, &mut 0).unwrap();
            let mut bytes = leaf.body.unwrap();
            bytes[8..32].copy_from_slice(&block(&image, bs, snapshot_root).unwrap()[8..32]);
            fletcher64_seal(&mut bytes);
            store.write_blocks(snapshot_root, &bytes).unwrap();
            put64(&mut apsb, 0xd8, 0);
        }
        put64(&mut vol_omap, 0x30, omap_root);
        fletcher64_seal(&mut vol_omap);
        store.write_blocks(vol_omap_addr, &vol_omap).unwrap();
        let extent_tree = read_tree(&image, bs, u64_at(&apsb, 0x90), None).unwrap();
        let snapshot_tree = read_tree(&image, bs, u64_at(&apsb, 0x98), None).unwrap();
        let data_blocks: u64 = extent_tree
            .records
            .iter()
            .map(|(_, value)| u64_at(value, 0) & ID_MASK)
            .sum();
        let mut owned_blocks = data_blocks
            + catalog.nodes.len() as u64
            + omap.nodes.len() as u64
            + extent_tree.nodes.len() as u64
            + snapshot_tree.nodes.len() as u64
            + 2;
        for (key, value) in &snapshot_tree.records {
            if key_id(key).unwrap().1 == 1 {
                owned_blocks += 1 + read_tree(&image, bs, u64_at(value, 0), None)
                    .unwrap()
                    .nodes
                    .len() as u64;
            }
        }
        let snapshot_omap = u64_at(&vol_omap, 0x38);
        if snapshot_omap != 0 {
            owned_blocks += read_tree(&image, bs, snapshot_omap, None)
                .unwrap()
                .nodes
                .len() as u64;
        }
        owned_blocks += store.allocator.allocated;
        put64(&mut apsb, 0xb0, next_file_id);
        put64(&mut apsb, 0x58, owned_blocks);
        put64(&mut apsb, 0xe0, data_blocks);
        put64(&mut apsb, 0xe8, 0);
        fletcher64_seal(&mut apsb);
        store.write_blocks(apsb_addr, &apsb).unwrap();
        for chunk in &store.allocator.chunks {
            if chunk.dirty {
                store
                    .disc
                    .write_block(chunk.old_bitmap, &chunk.bitmap)
                    .unwrap();
            }
        }
        for (paddr, bytes) in &store.allocator.cibs {
            let mut bytes = bytes.clone();
            fletcher64_seal(&mut bytes);
            store.disc.write_block(*paddr, &bytes).unwrap();
        }
        let mut sm = store.allocator.sm.clone();
        fletcher64_seal(&mut sm);
        store.disc.write_block(sm_addr, &sm).unwrap();
        for paddr in [0, sb_addr] {
            let mut superblock = block(&image, bs, paddr).unwrap().to_vec();
            put64(&mut superblock, 0xb8, system_oid);
            for slot in 1..100 {
                put64(&mut superblock, 0xb8 + slot * 8, 0);
            }
            put64(&mut superblock, 0x58, next_metadata_oid);
            fletcher64_seal(&mut superblock);
            store.write_blocks(paddr, &superblock).unwrap();
        }
        memory.bytes
    }

    fn assert_data_accounting_and_metadata_bound(
        image: &[u8],
        bs: u32,
        sb_paddr: u64,
        apsb_paddr: u64,
        fs_root: u64,
    ) -> u64 {
        let sb = block(image, bs, sb_paddr).unwrap();
        let apsb = block(image, bs, apsb_paddr).unwrap();
        let extrefs = read_tree(image, bs, u64_at(apsb, 0x90), None).unwrap();
        let data_blocks: u64 = extrefs
            .records
            .iter()
            .map(|(_, value)| u64_at(value, 0) & ID_MASK)
            .sum();
        assert_eq!(
            u64_at(apsb, 0xe0).checked_sub(u64_at(apsb, 0xe8)).unwrap(),
            data_blocks
        );
        let omap = block(image, bs, u64_at(apsb, 0x80)).unwrap();
        let omap_tree = read_tree(image, bs, u64_at(omap, 0x30), None).unwrap();
        let map = mappings(&omap_tree.records, u64_at(sb, 16)).unwrap();
        let catalog = read_tree(image, bs, fs_root, Some(&map)).unwrap();
        assert!(catalog.nodes.len() > 1);
        for (oid, _) in catalog.nodes {
            assert!(
                oid < u64_at(sb, 0x58),
                "catalog object {oid} fits the published container object ID bound"
            );
        }
        data_blocks
    }

    #[test]
    fn catalog_keys_follow_name_hash_and_numeric_order() {
        fn named_key(kind: u64, name: &str) -> Vec<u8> {
            let mut key = ((kind << 60) | 16).to_le_bytes().to_vec();
            key.extend_from_slice(&((name.len() + 1) as u16).to_le_bytes());
            key.extend_from_slice(name.as_bytes());
            key.push(0);
            key
        }
        let mut attributes = vec![
            named_key(4, "com.apple.decmpfs"),
            named_key(4, "com.apple.ResourceFork"),
        ];
        attributes.sort_by_key(|key| record_sort_key(key));
        assert_eq!(
            attributes,
            vec![
                named_key(4, "com.apple.ResourceFork"),
                named_key(4, "com.apple.decmpfs")
            ]
        );
        let mut offsets = Vec::new();
        for offset in [65536u64, 256] {
            let mut key = ((8u64 << 60) | 16).to_le_bytes().to_vec();
            key.extend_from_slice(&offset.to_le_bytes());
            offsets.push(key);
        }
        offsets.sort_by_key(|key| record_sort_key(key));
        assert_eq!(
            offsets.iter().map(|key| u64_at(key, 8)).collect::<Vec<_>>(),
            vec![256, 65536]
        );
        let mut directories = vec![named_key(9, "bb"), named_key(9, "aaa")];
        directories
            .sort_by_key(|key| catalog_sort_key(key, crate::apfs_verify::DrecKeyLayout::Plain));
        assert_eq!(directories, vec![named_key(9, "aaa"), named_key(9, "bb")]);
        let mut hashed = Vec::new();
        for name in ["bb", "aaa"] {
            let mut key = ((9u64 << 60) | 16).to_le_bytes().to_vec();
            key.extend_from_slice(&((7u32 << 10) | (name.len() as u32 + 1)).to_le_bytes());
            key.extend_from_slice(name.as_bytes());
            key.push(0);
            hashed.push(key);
        }
        hashed.sort_by_key(|key| record_sort_key(key));
        assert_eq!(
            hashed
                .iter()
                .map(|key| &key[12..key.len() - 1])
                .collect::<Vec<_>>(),
            vec![b"aaa".as_slice(), b"bb".as_slice()]
        );
    }

    #[test]
    fn compressed_catalog_replacement_preserves_neighbors_snapshot_and_allocation() {
        let original: Vec<u8> = (0..100_000u32).map(|index| (index % 251) as u8).collect();
        let replacement: Vec<u8> = (0..120_000u32).map(|index| (index % 239) as u8).collect();
        let image = fixture(&original, true);
        let (bs, blocks) = crate::apfs_read::container_geometry_of(&image).unwrap();
        let mut source = SliceBlocks::new(&image, bs);
        let verified_before = crate::apfs_verify::verify_container(&mut source).unwrap();
        let mut container = ApfsContainer::mount(&mut source, bs, blocks).unwrap();
        let volume = container
            .open_volume_chosen(&VolumeChoice::Role(1))
            .unwrap();
        assert!(u16_at(block(&image, bs, volume.fs_tree_paddr()).unwrap(), 0x22) >= 2);
        assert_eq!(
            container
                .stat(&volume, "/usr/local/bin/restored_external")
                .unwrap()
                .compression_type,
            Some(4)
        );
        let mut bytes = Vec::new();
        container
            .extract(
                &volume,
                "/usr/local/bin/restored_external",
                0,
                None,
                &mut bytes,
            )
            .unwrap();
        assert_eq!(bytes, original);
        let snapshot_name = container.snapshots(&volume).unwrap()[0].name.clone();
        let apsb = block(&image, bs, volume.apsb_paddr()).unwrap();
        let next_file_id = u64_at(apsb, 0xb0);
        let total_allocated = u64_at(apsb, 0xe0);
        let total_freed = u64_at(apsb, 0xe8);
        let next_metadata_oid = u64_at(
            block(&image, bs, container.superblock_paddr()).unwrap(),
            0x58,
        );
        assert!(next_file_id > next_metadata_oid);
        let old_data_blocks = assert_data_accounting_and_metadata_bound(
            &image,
            bs,
            container.superblock_paddr(),
            volume.apsb_paddr(),
            volume.fs_tree_paddr(),
        );
        drop(container);
        let updated = replace_file_in_container(
            &image,
            VolumeChoice::Role(1),
            "/usr/local/bin/restored_external",
            &crate::crypto::sha256(&original),
            &replacement,
        )
        .unwrap();
        let mut source = SliceBlocks::new(&updated, bs);
        let verified_after = crate::apfs_verify::verify_container(&mut source).unwrap();
        assert_eq!(verified_after.xid, verified_before.xid + 1);
        assert!(verified_after.free_block_count < verified_before.free_block_count);
        let mut container = ApfsContainer::mount(&mut source, bs, blocks).unwrap();
        let volume = container
            .open_volume_chosen(&VolumeChoice::Role(1))
            .unwrap();
        let facts = container
            .stat(&volume, "/usr/local/bin/restored_external")
            .unwrap();
        assert_eq!(facts.private_id, next_file_id);
        let apsb = block(&updated, bs, volume.apsb_paddr()).unwrap();
        let new_data_blocks = (replacement.len() as u64).div_ceil(u64::from(bs));
        assert_eq!(u64_at(apsb, 0xb0), next_file_id + 1);
        assert_eq!(u64_at(apsb, 0xe0), total_allocated + new_data_blocks);
        assert_eq!(u64_at(apsb, 0xe8), total_freed);
        let published_bound = u64_at(
            block(&updated, bs, container.superblock_paddr()).unwrap(),
            0x58,
        );
        assert!(published_bound > next_metadata_oid);
        for (oid, _, _) in &verified_after.ephemeral {
            assert!(*oid < published_bound);
        }
        assert_eq!(
            assert_data_accounting_and_metadata_bound(
                &updated,
                bs,
                container.superblock_paddr(),
                volume.apsb_paddr(),
                volume.fs_tree_paddr()
            ),
            old_data_blocks + new_data_blocks
        );
        assert!(facts.private_id > facts.file_id);
        assert_eq!(facts.stream_size, Some(replacement.len() as u64));
        assert_eq!(facts.mode, crate::apfs_read::S_IFREG | 0o644);
        let mut bytes = Vec::new();
        container
            .extract(
                &volume,
                "/usr/local/bin/restored_external",
                0,
                None,
                &mut bytes,
            )
            .unwrap();
        assert_eq!(bytes, replacement);
        let mut neighbor = Vec::new();
        container
            .extract(&volume, "/usr/local/bin/neighbor", 0, None, &mut neighbor)
            .unwrap();
        assert_eq!(neighbor, b"neighbor bytes");
        let snapshot = container.open_snapshot(&volume, &snapshot_name).unwrap();
        let mut bytes = Vec::new();
        container
            .extract(
                &snapshot,
                "/usr/local/bin/restored_external",
                0,
                None,
                &mut bytes,
            )
            .unwrap();
        assert_eq!(bytes, original);
        let mut neighbor = Vec::new();
        container
            .extract(&snapshot, "/usr/local/bin/neighbor", 0, None, &mut neighbor)
            .unwrap();
        assert_eq!(neighbor, b"neighbor bytes");
        for paddr in verified_before.blocks_in_use {
            assert_eq!(
                block(&updated, bs, paddr).unwrap(),
                block(&image, bs, paddr).unwrap(),
                "published source block {paddr} remains available to its checkpoint"
            );
        }
    }

    #[test]
    fn compressed_replacement_publishes_metadata_ids_and_data_lifetime_counters() {
        let original: Vec<u8> = (0..100_000u32).map(|index| (index % 251) as u8).collect();
        let replacement: Vec<u8> = (0..120_000u32).map(|index| (index % 239) as u8).collect();
        let image = fixture(&original, false);
        let (bs, blocks) = crate::apfs_read::container_geometry_of(&image).unwrap();
        let mut source = SliceBlocks::new(&image, bs);
        crate::apfs_verify::verify_container(&mut source).unwrap();
        let mut container = ApfsContainer::mount(&mut source, bs, blocks).unwrap();
        let volume = container
            .open_volume_chosen(&VolumeChoice::Role(1))
            .unwrap();
        let facts = container
            .stat(&volume, "/usr/local/bin/restored_external")
            .unwrap();
        assert_eq!(facts.compression_type, Some(4));
        let mut bytes = Vec::new();
        container
            .extract(
                &volume,
                "/usr/local/bin/restored_external",
                0,
                None,
                &mut bytes,
            )
            .unwrap();
        assert_eq!(bytes, original);
        let apsb = block(&image, bs, volume.apsb_paddr()).unwrap();
        let next_file_id = u64_at(apsb, 0xb0);
        let total_allocated = u64_at(apsb, 0xe0);
        let total_freed = u64_at(apsb, 0xe8);
        let next_metadata_oid = u64_at(
            block(&image, bs, container.superblock_paddr()).unwrap(),
            0x58,
        );
        assert!(next_file_id > next_metadata_oid);
        let old_data_blocks = assert_data_accounting_and_metadata_bound(
            &image,
            bs,
            container.superblock_paddr(),
            volume.apsb_paddr(),
            volume.fs_tree_paddr(),
        );
        let extrefs = read_tree(&image, bs, u64_at(apsb, 0x90), None).unwrap();
        let retired_data_blocks: u64 = extrefs
            .records
            .iter()
            .filter(|(_, value)| u64_at(value, 8) == facts.file_id)
            .map(|(_, value)| u64_at(value, 0) & ID_MASK)
            .sum();
        assert!(retired_data_blocks > 0);
        drop(container);
        let updated = replace_file_in_container(
            &image,
            VolumeChoice::Role(1),
            "/usr/local/bin/restored_external",
            &crate::crypto::sha256(&original),
            &replacement,
        )
        .unwrap();
        let mut source = SliceBlocks::new(&updated, bs);
        let verified = crate::apfs_verify::verify_container(&mut source).unwrap();
        let mut container = ApfsContainer::mount(&mut source, bs, blocks).unwrap();
        let volume = container
            .open_volume_chosen(&VolumeChoice::Role(1))
            .unwrap();
        let facts = container
            .stat(&volume, "/usr/local/bin/restored_external")
            .unwrap();
        assert_eq!(facts.private_id, next_file_id);
        let apsb = block(&updated, bs, volume.apsb_paddr()).unwrap();
        let new_data_blocks = (replacement.len() as u64).div_ceil(u64::from(bs));
        assert_eq!(u64_at(apsb, 0xb0), next_file_id + 1);
        assert_eq!(u64_at(apsb, 0xe0), total_allocated + new_data_blocks);
        assert_eq!(u64_at(apsb, 0xe8), total_freed + retired_data_blocks);
        let published_bound = u64_at(
            block(&updated, bs, container.superblock_paddr()).unwrap(),
            0x58,
        );
        assert!(published_bound > next_metadata_oid);
        for (oid, _, _) in &verified.ephemeral {
            assert!(*oid < published_bound);
        }
        assert_eq!(
            assert_data_accounting_and_metadata_bound(
                &updated,
                bs,
                container.superblock_paddr(),
                volume.apsb_paddr(),
                volume.fs_tree_paddr()
            ),
            old_data_blocks + new_data_blocks - retired_data_blocks
        );
        let mut bytes = Vec::new();
        container
            .extract(
                &volume,
                "/usr/local/bin/restored_external",
                0,
                None,
                &mut bytes,
            )
            .unwrap();
        assert_eq!(bytes, replacement);
        let mut neighbor = Vec::new();
        container
            .extract(&volume, "/usr/local/bin/neighbor", 0, None, &mut neighbor)
            .unwrap();
        assert_eq!(neighbor, b"neighbor bytes");
    }
}
