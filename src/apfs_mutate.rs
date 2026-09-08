use crate::apfs_image::fletcher64_seal;
use crate::apfs_verify::{BTreeNode, Object, u16_at, u32_at, u64_at};

const BTNODE_ROOT: u16 = 0x1;
const BTNODE_LEAF: u16 = 0x2;
const BTREE_INFO_BYTES: usize = 40;
const BTNODE_TOC_BASE: usize = 56;
const J_INODE: u64 = 3;
const J_XATTR: u64 = 4;
const J_SIBLING_LINK: u64 = 5;
const J_DSTREAM_ID: u64 = 6;
const J_FILE_EXTENT: u64 = 8;
const J_DIR_REC: u64 = 9;
const J_SNAP_NAME: u64 = 11;
const APSB_NUM_FILES_OFFSET: usize = 0xB8;
const APSB_NEXT_OBJ_ID_OFFSET: usize = 0xB0;
const S_IFREG: u16 = 0x8000;
const DT_REG: u16 = 8;
const INODE_XFIELDS_OFFSET: usize = 0x5C;
const INO_EXT_TYPE_DSTREAM: u8 = 8;
const DSTREAM_BYTES: usize = 40;
const J_OBJ_ID_MASK: u64 = 0x0FFF_FFFF_FFFF_FFFF;
const INODE_INTERNAL_FLAGS: u64 = 0x8000;

pub trait BlockRw {
    fn read_block(&mut self, index: u64, into: &mut [u8]) -> Result<(), String>;
    fn write_block(&mut self, index: u64, data: &[u8]) -> Result<(), String>;
}

#[allow(clippy::too_many_arguments)]
pub fn insert_regular_file(
    rw: &mut dyn BlockRw,
    block_size: u32,
    block_count: u64,
    fs_tree_paddr: u64,
    apsb_paddr: u64,
    parent_id: u64,
    name: &str,
    data: &[u8],
) -> Result<u64, String> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(format!("refusing to insert {name:?}"));
    }
    let bs = block_size as usize;
    let mut tree = vec![0u8; bs];
    rw.read_block(fs_tree_paddr, &mut tree)?;
    let flags = u16_at(&tree, 0x20);
    let level = u16_at(&tree, 0x22);
    if flags & BTNODE_LEAF == 0 || level != 0 {
        return Err(
            "insert needs a single-leaf filesystem catalog (this volume's tree is deeper)".into(),
        );
    }
    let object = Object {
        paddr: fs_tree_paddr,
        bytes: tree.clone(),
    };
    let node = BTreeNode::decode(&object, bs).map_err(|e| e.to_string())?;
    let mut records = Vec::new();
    for index in 0..node.nkeys {
        let (key, value) = node.entry(index).map_err(|e| e.to_string())?;
        records.push((key.to_vec(), value.to_vec()));
    }

    let hashed = records.iter().any(|(key, _)| drec_key_is_hashed(key));
    for (key, _) in &records {
        let kind = u64_at(key, 0) >> 60;
        if kind != J_DIR_REC {
            continue;
        }
        let oid = u64_at(key, 0) & J_OBJ_ID_MASK;
        if oid != parent_id {
            continue;
        }
        let (at, len) = if hashed {
            let n = (u32_at(key, 8) & 0x3FF) as usize;
            (12usize, n)
        } else {
            (10usize, u16_at(key, 8) as usize)
        };
        if len > 0 && at + len <= key.len() && &key[at..at + len - 1] == name.as_bytes() {
            return Err(format!("{name} already exists in this directory"));
        }
    }

    let mut max_oid = parent_id;
    for (key, _) in &records {
        let oid = u64_at(key, 0) & J_OBJ_ID_MASK;
        if oid > max_oid {
            max_oid = oid;
        }
    }
    let mut apsb = vec![0u8; bs];
    rw.read_block(apsb_paddr, &mut apsb)?;
    let next_obj_id = u64_at(&apsb, APSB_NEXT_OBJ_ID_OFFSET);
    let ino = (max_oid + 1).max(next_obj_id);
    let need = (data.len() as u64).div_ceil(u64::from(block_size)).max(1);
    let paddr = find_zero_run(rw, block_size, block_count, need)?;
    for i in 0..need {
        let mut block = vec![0u8; bs];
        let off = (i * u64::from(block_size)) as usize;
        let take = data.len().saturating_sub(off).min(bs);
        if take > 0 {
            block[..take].copy_from_slice(&data[off..off + take]);
        }
        rw.write_block(paddr + i, &block)?;
    }

    let alloced = need * u64::from(block_size);
    records.push((
        inode_key(ino),
        inode_val(parent_id, ino, data.len() as u64, alloced),
    ));
    records.push((extent_key(ino), extent_val(alloced, paddr)));
    records.push((drec_key(parent_id, name, hashed)?, drec_val(ino)));
    records.push((dstream_id_key(ino), dstream_id_val(1)));
    bump_nchildren(&mut records, parent_id);
    records.sort_by_key(|a| rec_order(&a.0));

    let mut rebuilt = btree_leaf(bs, &records, true)?;
    rebuilt[8..32].copy_from_slice(&tree[8..32]);
    fletcher64_seal(&mut rebuilt);
    rw.write_block(fs_tree_paddr, &rebuilt)?;

    let mut apsb = vec![0u8; bs];
    rw.read_block(apsb_paddr, &mut apsb)?;
    let num_files = u64_at(&apsb, APSB_NUM_FILES_OFFSET).saturating_add(1);
    apsb[APSB_NUM_FILES_OFFSET..APSB_NUM_FILES_OFFSET + 8]
        .copy_from_slice(&num_files.to_le_bytes());
    let next_obj_id = (ino + 1).max(u64_at(&apsb, APSB_NEXT_OBJ_ID_OFFSET));
    apsb[APSB_NEXT_OBJ_ID_OFFSET..APSB_NEXT_OBJ_ID_OFFSET + 8]
        .copy_from_slice(&next_obj_id.to_le_bytes());
    fletcher64_seal(&mut apsb);
    rw.write_block(apsb_paddr, &apsb)?;

    Ok(ino)
}

fn find_zero_run(
    rw: &mut dyn BlockRw,
    block_size: u32,
    block_count: u64,
    need: u64,
) -> Result<u64, String> {
    if need == 0 || need + 2 >= block_count {
        return Err("file does not fit in the container".into());
    }
    let bs = block_size as usize;
    let mut buf = vec![0u8; bs];
    let start_from = block_count.saturating_sub(need + 1);
    let search = start_from.min(4096);
    let mut paddr = start_from;
    let mut checked = 0u64;
    while paddr > 1 && checked < search {
        let mut ok = true;
        for i in 0..need {
            rw.read_block(paddr + i, &mut buf)?;
            if buf.iter().any(|b| *b != 0) {
                ok = false;
                break;
            }
        }
        if ok {
            return Ok(paddr);
        }
        paddr -= 1;
        checked += 1;
    }
    Err("no free zeroed blocks at the end of the container for insert".into())
}

fn drec_key_is_hashed(key: &[u8]) -> bool {
    if key.len() < 12 {
        return false;
    }
    let kind = u64_at(key, 0) >> 60;
    if kind != J_DIR_REC {
        return false;
    }
    let rest = key.len() - 8;
    let plain_len = u16_at(key, 8) as usize;
    let hashed_len = (u32_at(key, 8) & 0x3FF) as usize;
    rest == 4 + hashed_len && rest != 2 + plain_len
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum RecordTail {
    Number(u64),
    Named { prefix: u32, name: Vec<u8> },
    Bytes(Vec<u8>),
}

fn record_tail(kind: u64, key: &[u8]) -> RecordTail {
    match kind {
        J_DIR_REC if drec_key_is_hashed(key) && key.len() >= 12 => RecordTail::Named {
            prefix: u32_at(key, 8),
            name: key[12..].to_vec(),
        },
        J_DIR_REC if key.len() >= 10 => RecordTail::Named {
            prefix: 0,
            name: key[10..].to_vec(),
        },
        J_XATTR | J_SNAP_NAME if key.len() >= 10 => RecordTail::Named {
            prefix: 0,
            name: key[10..].to_vec(),
        },
        J_SIBLING_LINK | J_FILE_EXTENT if key.len() >= 16 => RecordTail::Number(u64_at(key, 8)),
        _ => RecordTail::Bytes(key.get(8.min(key.len())..).unwrap_or(&[]).to_vec()),
    }
}

fn rec_order(key: &[u8]) -> (u64, u64, RecordTail) {
    let header = u64_at(key, 0);
    let kind = header >> 60;
    (header & J_OBJ_ID_MASK, kind, record_tail(kind, key))
}

fn bump_nchildren(records: &mut [(Vec<u8>, Vec<u8>)], parent_id: u64) {
    for (key, value) in records.iter_mut() {
        let header = u64_at(key, 0);
        if header >> 60 != J_INODE || (header & J_OBJ_ID_MASK) != parent_id {
            continue;
        }
        if value.len() >= 0x3C {
            let n = u32::from_le_bytes(value[0x38..0x3C].try_into().unwrap()).saturating_add(1);
            value[0x38..0x3C].copy_from_slice(&n.to_le_bytes());
        }
        return;
    }
}

fn inode_key(oid: u64) -> Vec<u8> {
    ((J_INODE << 60) | oid).to_le_bytes().to_vec()
}

fn inode_val(parent: u64, oid: u64, size: u64, alloced: u64) -> Vec<u8> {
    let mut value = vec![0u8; INODE_XFIELDS_OFFSET];
    value[0..8].copy_from_slice(&parent.to_le_bytes());
    value[8..16].copy_from_slice(&oid.to_le_bytes()); // private_id
    value[0x30..0x38].copy_from_slice(&INODE_INTERNAL_FLAGS.to_le_bytes());
    value[0x38..0x3C].copy_from_slice(&1u32.to_le_bytes()); // nlink
    value[0x50..0x52].copy_from_slice(&(S_IFREG | 0o644).to_le_bytes());
    let mut dstream = vec![0u8; DSTREAM_BYTES];
    dstream[0..8].copy_from_slice(&size.to_le_bytes());
    dstream[8..16].copy_from_slice(&alloced.to_le_bytes());
    dstream[0x18..0x20].copy_from_slice(&size.to_le_bytes()); // total_bytes_written
    value.extend_from_slice(&1u16.to_le_bytes());
    value.extend_from_slice(&(DSTREAM_BYTES as u16).to_le_bytes());
    value.push(INO_EXT_TYPE_DSTREAM);
    value.push(0);
    value.extend_from_slice(&(DSTREAM_BYTES as u16).to_le_bytes());
    value.extend_from_slice(&dstream);
    value
}

fn crc32c_update(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    crc
}

fn name_hash(name: &str) -> Result<u32, String> {
    if !name.is_ascii() {
        return Err(format!(
            "{name:?} needs real Unicode case folding and NFD decomposition to hash correctly, \
             which this writer does not implement"
        ));
    }
    let folded = name.to_ascii_lowercase();
    let mut utf32le = Vec::with_capacity(folded.len() * 4);
    for ch in folded.chars() {
        utf32le.extend_from_slice(&(ch as u32).to_le_bytes());
    }
    let crc = crc32c_update(0xFFFF_FFFF, &utf32le);
    Ok(crc & 0x003F_FFFF)
}

fn drec_key(parent: u64, name: &str, hashed: bool) -> Result<Vec<u8>, String> {
    let mut key = ((J_DIR_REC << 60) | parent).to_le_bytes().to_vec();
    let nbytes = (name.len() + 1) as u32;
    if hashed {
        let hash = name_hash(name)?;
        let packed = (hash << 10) | nbytes;
        key.extend_from_slice(&packed.to_le_bytes());
    } else {
        key.extend_from_slice(&(nbytes as u16).to_le_bytes());
    }
    key.extend_from_slice(name.as_bytes());
    key.push(0);
    Ok(key)
}

fn drec_val(file_id: u64) -> Vec<u8> {
    let mut val = vec![0u8; 0x12];
    val[0..8].copy_from_slice(&file_id.to_le_bytes());
    val[0x10..0x12].copy_from_slice(&DT_REG.to_le_bytes());
    val
}

fn dstream_id_key(oid: u64) -> Vec<u8> {
    ((J_DSTREAM_ID << 60) | oid).to_le_bytes().to_vec()
}

fn dstream_id_val(refcnt: u32) -> Vec<u8> {
    refcnt.to_le_bytes().to_vec()
}

fn extent_key(oid: u64) -> Vec<u8> {
    let mut key = ((J_FILE_EXTENT << 60) | oid).to_le_bytes().to_vec();
    key.extend_from_slice(&0u64.to_le_bytes());
    key
}

fn extent_val(len: u64, phys: u64) -> Vec<u8> {
    let mut val = vec![0u8; 24];
    val[0..8].copy_from_slice(&len.max(1).to_le_bytes());
    val[8..16].copy_from_slice(&phys.to_le_bytes());
    val[16..24].copy_from_slice(&0u64.to_le_bytes());
    val
}

fn btree_leaf(
    block_size: usize,
    records: &[(Vec<u8>, Vec<u8>)],
    root: bool,
) -> Result<Vec<u8>, String> {
    let mut block = vec![0u8; block_size];
    let mut flags = BTNODE_LEAF;
    if root {
        flags |= BTNODE_ROOT;
    }
    block[0x20..0x22].copy_from_slice(&flags.to_le_bytes());
    let n = records.len() as u32;
    block[0x24..0x28].copy_from_slice(&n.to_le_bytes());
    let toc_len = (records.len() * 8) as u16;
    block[0x2A..0x2C].copy_from_slice(&toc_len.to_le_bytes());
    let toc = BTNODE_TOC_BASE;
    let key_base = toc + toc_len as usize;
    let value_end = block_size - if root { BTREE_INFO_BYTES } else { 0 };
    let mut key_cursor = 0usize;
    let mut value_cursor = 0usize;
    for (index, (key, value)) in records.iter().enumerate() {
        let at = toc + index * 8;
        block[at..at + 2].copy_from_slice(&(key_cursor as u16).to_le_bytes());
        block[at + 2..at + 4].copy_from_slice(&(key.len() as u16).to_le_bytes());
        let value_offset = value_cursor + value.len();
        block[at + 4..at + 6].copy_from_slice(&(value_offset as u16).to_le_bytes());
        block[at + 6..at + 8].copy_from_slice(&(value.len() as u16).to_le_bytes());
        let key_at = key_base + key_cursor;
        let val_at = value_end
            .checked_sub(value_offset)
            .ok_or_else(|| "catalog leaf is full; cannot insert".to_string())?;
        if key_at + key.len() > val_at {
            return Err("catalog leaf is full; cannot insert".into());
        }
        block[key_at..key_at + key.len()].copy_from_slice(key);
        block[val_at..val_at + value.len()].copy_from_slice(value);
        key_cursor += key.len();
        value_cursor = value_offset;
    }
    let free_len = value_end - key_base - key_cursor - value_cursor;
    block[0x2C..0x2E].copy_from_slice(&(key_cursor as u16).to_le_bytes());
    block[0x2E..0x30].copy_from_slice(&(free_len as u16).to_le_bytes());
    // The empty-free-list sentinel is 0xFFFF (BTOFF_INVALID), not 0.
    block[0x30..0x32].copy_from_slice(&0xFFFFu16.to_le_bytes());
    block[0x32..0x34].copy_from_slice(&0u16.to_le_bytes());
    block[0x34..0x36].copy_from_slice(&0xFFFFu16.to_le_bytes());
    block[0x36..0x38].copy_from_slice(&0u16.to_le_bytes());
    if root {
        let info = block_size - BTREE_INFO_BYTES;
        // BTREE_PHYSICAL is deliberately absent: a volume's filesystem tree is virtual, addressed through the volume object map.
        const BT_KV_NONALIGNED: u32 = 0x40;
        const BT_SEQUENTIAL_INSERT: u32 = 0x02;
        block[info..info + 4]
            .copy_from_slice(&(BT_KV_NONALIGNED | BT_SEQUENTIAL_INSERT).to_le_bytes());
        block[info + 4..info + 8].copy_from_slice(&(block_size as u32).to_le_bytes());
        block[info + 8..info + 12].copy_from_slice(&0u32.to_le_bytes());
        block[info + 12..info + 16].copy_from_slice(&0u32.to_le_bytes());
        let longest_key = records.iter().map(|(k, _)| k.len()).max().unwrap_or(0) as u32;
        let longest_val = records.iter().map(|(_, v)| v.len()).max().unwrap_or(0) as u32;
        block[info + 16..info + 20].copy_from_slice(&longest_key.to_le_bytes());
        block[info + 20..info + 24].copy_from_slice(&longest_val.to_le_bytes());
        block[info + 24..info + 32].copy_from_slice(&(records.len() as u64).to_le_bytes());
        block[info + 32..info + 40].copy_from_slice(&1u64.to_le_bytes());
    }
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apfs_read::{ApfsContainer, VolumeChoice};
    use crate::apfs_verify::{BlockSource, SliceBlocks, verify_container};

    fn clean_container() -> Vec<u8> {
        let stage1 = vec![0x42u8; 4096];
        crate::apfs_write::create(64 * 1024 * 1024, "T", &stage1).expect("apfs_write::create")
    }

    fn geometry(bytes: &[u8]) -> (u32, u64) {
        (u32_at(bytes, 0x24), u64_at(bytes, 0x28))
    }

    struct VecRw<'a> {
        bytes: &'a mut Vec<u8>,
        block_size: u32,
    }

    impl BlockRw for VecRw<'_> {
        fn read_block(&mut self, index: u64, into: &mut [u8]) -> Result<(), String> {
            let bs = self.block_size as usize;
            let at = (index as usize) * bs;
            let end = at + bs;
            if end > self.bytes.len() {
                return Err(format!("block {index} is outside the container"));
            }
            into.copy_from_slice(&self.bytes[at..end]);
            Ok(())
        }

        fn write_block(&mut self, index: u64, data: &[u8]) -> Result<(), String> {
            let bs = self.block_size as usize;
            let at = (index as usize) * bs;
            let end = at + bs;
            if end > self.bytes.len() {
                return Err(format!("block {index} is outside the container"));
            }
            self.bytes[at..end].copy_from_slice(data);
            Ok(())
        }
    }

    #[test]
    fn inserted_file_leaves_a_container_verify_container_still_accepts() {
        let mut bytes = clean_container();
        let (block_size, block_count) = geometry(&bytes);

        verify_container(&mut SliceBlocks::new(&bytes, block_size))
            .expect("container must verify clean before any insert");

        let (fs_tree_paddr, apsb_paddr) = {
            let mut source = SliceBlocks::new(&bytes, block_size);
            let mut mounted =
                ApfsContainer::mount(&mut source, block_size, block_count).expect("mount");
            let vol = mounted
                .open_volume_chosen(&VolumeChoice::Index(0))
                .expect("open the one volume");
            (vol.fs_tree_paddr(), vol.apsb_paddr())
        };

        let data = b"hello from insert_regular_file".to_vec();
        let ino = insert_regular_file(
            &mut VecRw {
                bytes: &mut bytes,
                block_size,
            },
            block_size,
            block_count,
            fs_tree_paddr,
            apsb_paddr,
            2, // root directory oid, the same convention explorer_image uses for "/"
            "inserted.txt",
            &data,
        )
        .expect("insert_regular_file");
        assert!(ino > 2);

        verify_container(&mut SliceBlocks::new(&bytes, block_size))
            .expect("container must still verify clean after insert_regular_file");

        let mut leaf = vec![0u8; block_size as usize];
        SliceBlocks::new(&bytes, block_size)
            .read_block(fs_tree_paddr, &mut leaf)
            .expect("read the rebuilt leaf back");
        let info = block_size as usize - BTREE_INFO_BYTES;
        let bt_flags = u32_at(&leaf, info);
        let bt_node_size = u32_at(&leaf, info + 4);
        let bt_key_count = u64_at(&leaf, info + 24);
        let bt_node_count = u64_at(&leaf, info + 32);
        assert_ne!(bt_flags, 0, "bt_flags must not be the invalid value 0");
        assert_eq!(
            bt_node_size, block_size,
            "bt_node_size must be the block size"
        );
        assert!(
            bt_key_count >= 1,
            "bt_key_count must count the records written"
        );
        assert_eq!(bt_node_count, 1, "a single leaf is one node");

        let mut source = SliceBlocks::new(&bytes, block_size);
        let mut mounted =
            ApfsContainer::mount(&mut source, block_size, block_count).expect("re-mount");
        let vol = mounted
            .open_volume_chosen(&VolumeChoice::Index(0))
            .expect("re-open the one volume");
        let mut out = Vec::new();
        mounted
            .extract(&vol, "/inserted.txt", 0, None, &mut out)
            .expect("extract the inserted file");
        assert_eq!(out, data);
    }
}
